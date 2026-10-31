/**
 * Secrets write-only contract: redact-on-read + sentinel keep-on-save.
 *
 * This module is the single implementation of the redaction/merge rules
 * for the dev mock (the only server stand-in in this repo). It is pure
 * JSON logic with no Node APIs, so vitest can import it directly. The
 * frontend (webui/src) must NEVER import it: the frontend renders what
 * the server returns and must not add a second, divergent scrub.
 *
 * Rules, mirroring the Go backend (carried for Go PR6 — the Go handler
 * MUST implement the same contract server-side):
 *
 * - Sentinel: exactly `<redacted>`, whole-value exact match after JSON
 *   parse. It is Go's `redact.Marker`
 *   (`go/internal/redact/value.go`, ref origin/feat/go-port @ 50a4cbc8).
 *   The sentinel is never persisted at a secret position (it restores
 *   the stored value or the save rejects); at a present non-secret
 *   position it is an ordinary literal value. It is never validated
 *   as a credential: merge precedes validation.
 * - Key set: the Go 37 secret keys, verbatim, matched lowercase-exact
 *   (no trim, no substring). New keys are added in Go first, then
 *   mirrored here — never frontend/mock-only. An unknown future key is
 *   protected only if its name is in this set, it sits in a header map,
 *   or it carries URL userinfo; anything else is caught by parse-time
 *   strictness on the Go side, not by widening this matcher.
 * - Header maps (`headers` / `extra_headers`, lowercase-exact): every
 *   value is redacted, whatever the header name. `custom_headers` is
 *   NOT a header map (pinned Go behaviour).
 * - URL userinfo: every other string value gets the Go userinfo scrub
 *   (regex ported verbatim: last `@` before the first `/`, `?`, or `#`
 *   after `://`). See redactURLUserinfo.
 * - BOUNDARY (Go parity, coordinator decision D2): this redactor does
 *   NOT strip `?token=` / fragment / Bearer secrets inside plain string
 *   values. Go's `Value` deliberately leaves those alone (only its
 *   error-string redactor strips them, with a different marker). A
 *   config string carrying `?token=...` is therefore displayed verbatim
 *   except for userinfo scrub. Any change to that boundary belongs in
 *   Go first; the mock must not invent a third scrub.
 * - Merge is structural (parsed JSON only), by path, never by value
 *   identity, in the order: guard -> parse -> merge -> validate merged
 *   -> write -> hash (the guard/parse/write/hash steps live in the
 *   mock store, configStore.ts). A sentinel at any path absent from
 *   stored rejects the whole save (R2, including renames); a sentinel
 *   at a present secret position keeps the stored value; a sentinel
 *   at a present non-secret position is an ordinary literal value.
 * - Type change: when the submitted value's JSON kind differs from
 *   the stored value's, the nested paths have no stored counterpart,
 *   so the subtree is adopted as new (R2): any exact sentinel inside
 *   it rejects. This closes the smuggle where a sentinel nested in a
 *   new-typed value would otherwise persist at a secret position.
 * - Multi-URL strings fail closed: a submitted string carrying a
 *   `<redacted>@` userinfo segment is rejected unless it is the
 *   untouched redacted view of the stored string or the single-span
 *   R6 splice; no per-span splicing is attempted.
 * - Array identity guard: a restore inside an object array element
 *   requires every identity key present in the stored element
 *   (`tag`, `type`, `username`, `name`, `address`, `port`) to be
 *   unchanged in the submitted element; with none present, the
 *   guard falls back to positional merge (documented residual).
 *   Before writing, the store asserts (findSentinelAtSecretPosition)
 *   that the merged document holds no sentinel at any secret/header
 *   position.
 * - No secret by value shape: a secret-looking string under a
 *   non-secret key is kept (except userinfo scrub). Value-shape
 *   heuristics (entropy, base64 length) are forbidden.
 */

/** The one sentinel for display and round-trip. Whole-value exact match only. */
export const REDACTED_SENTINEL = '<redacted>';

/**
 * The Go 37 secret keys, verbatim (lowercase).
 * Source: go/internal/redact/value.go:40-78 @ 50a4cbc8 (origin/feat/go-port).
 */
const SECRET_KEYS: ReadonlySet<string> = new Set([
  'access_key_secret',
  'account_key',
  'api_token',
  'auth',
  'auth_key',
  'auth_str',
  'authorization',
  'certificate',
  'client_certificate',
  'client_key',
  'client_key_password',
  'cookie',
  'key',
  'mac_key',
  'mca_key',
  'mca_key_password',
  'mesh_psk',
  'node_id',
  'obfs',
  'origin_ca_key',
  'password',
  'pre_shared_key',
  'private_key',
  'private_key_passphrase',
  'psk',
  'public_key',
  'secret',
  'security_token',
  'short_id',
  'static_key',
  'submission_key',
  'subscription_action_id',
  'token',
  'userkey',
  'uuid',
  'vm_id',
  'zone_token',
]);

/** Exact match after lowercasing only: no trim, no substring, no suffix/prefix. */
export function isSecretKey(key: string): boolean {
  return SECRET_KEYS.has(key.toLowerCase());
}

/** Header-map keys (lowercase-exact). Every value under one is redacted wholesale. */
function isHeaderMapKey(key: string): boolean {
  const lower = key.toLowerCase();
  return lower === 'headers' || lower === 'extra_headers';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Strip URL userinfo from every URL embedded in `s`, keeping scheme,
 * host, and the rest byte-identical. Port of Go's RedactURLUserinfo
 * (go/internal/redact/redact.go): `(?i)([a-z][a-z0-9+.-]*://)[^/\s?#]+@`.
 * The greedy run takes the LAST `@` before the first `/`, `?`, or `#`
 * after `://`, so a password containing `@` is handled, while a plain
 * email (no scheme), an `@` in a path/query, and an empty userinfo are
 * left unchanged. Idempotent.
 *
 * The whitespace class is spelled out explicitly as `[\t\n\f\r ]`:
 * that is Go RE2 `\s`. JavaScript `\s` would also match NBSP and
 * vertical tab, so a userinfo containing NBSP/VT would evade the
 * scrub in JS while Go scrubs it. The explicit class keeps the two
 * identical; a space or tab inside the userinfo still breaks the
 * match in both, leaving the string unchanged.
 */
const URL_USERINFO_PATTERN = String.raw`([a-z][a-z0-9+.-]*://)[^/?#\t\n\f\r ]+@`;

export function redactURLUserinfo(s: string): string {
  if (s === '') return s;
  return s.replace(new RegExp(URL_USERINFO_PATTERN, 'gi'), '$1<redacted>@');
}

function redactNode(value: unknown): unknown {
  if (typeof value === 'string') {
    return redactURLUserinfo(value);
  }
  if (Array.isArray(value)) {
    return value.map((element) => redactNode(element));
  }
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      if (isSecretKey(key)) {
        out[key] = REDACTED_SENTINEL;
      } else if (isHeaderMapKey(key)) {
        out[key] = redactHeaderValue(child);
      } else {
        out[key] = redactNode(child);
      }
    }
    return out;
  }
  return value;
}

/**
 * Redact one header-map value, mirroring Go's redactHeaders
 * (go/internal/redact/value.go) exactly: when the value is a map,
 * every header value is replaced wholesale with the marker (header
 * names survive); any non-map, non-nil value — string, number, bool,
 * object, or array — is replaced wholesale with the marker; nil
 * stays nil. A nested structure inside a header value is never
 * walked: the whole value becomes the marker.
 */
function redactHeaderValue(value: unknown): unknown {
  if (value === null) return null;
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      out[key] = REDACTED_SENTINEL;
    }
    return out;
  }
  return REDACTED_SENTINEL;
}

/**
 * Recursively redact a JSON-shaped value. Secret keys are replaced
 * wholesale whatever their type (string, object, array, number, bool,
 * or null -> sentinel); header maps wholesale per header name; every
 * other string gets URL-userinfo scrub only. The input is never
 * mutated; field order is preserved.
 */
export function redactValue(value: unknown): unknown {
  return redactNode(value);
}

/** Canonical serialisation of a stored config document (mock only). */
export function stringifyConfigDocument(doc: unknown): string {
  return JSON.stringify(doc, null, 2);
}

/** Rejection carrying the JSON path of the offending sentinel (path only, never a value). */
export class SentinelRejectionError extends Error {
  readonly path: string;

  constructor(path: string) {
    super('Redacted sentinel has no stored value to keep');
    this.name = 'SentinelRejectionError';
    this.path = path;
  }
}

/** Marker for "no stored value at this path" (distinct from stored null/undefined values). */
const ABSENT: unique symbol = Symbol('absent');

function joinPath(path: string, key: string): string {
  return path === '' ? key : `${path}.${key}`;
}

function deepClone(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((element) => deepClone(element));
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) out[key] = deepClone(child);
    return out;
  }
  return value;
}

/** JSON kind of a value: null, array, and object are distinct kinds; scalars use typeof. */
function jsonKind(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (isRecord(value)) return 'object';
  return typeof value;
}

interface MergeResult {
  merged: unknown;
  /** True when any keep (R1 restoration) happened inside this subtree. */
  restored: boolean;
}

/**
 * Adopt a brand-new subtree (no stored counterpart). An exact sentinel
 * anywhere in a new subtree rejects (R2, broad clause): a copied
 * redacted block must have real values typed in, and a renamed secret
 * key (R3) is a new path. Non-sentinel values are taken verbatim. The
 * result never aliases the input.
 */
function adoptNew(submitted: unknown, path: string): MergeResult {
  if (typeof submitted === 'string') {
    if (submitted === REDACTED_SENTINEL) {
      throw new SentinelRejectionError(path);
    }
    // A userinfo span that merely contains the sentinel is
    // rejected here too (same rule as the merge string
    // branch): it must never be stored verbatim.
    for (const span of userinfoSpans(submitted)) {
      if (span.userinfo !== REDACTED_SENTINEL && span.userinfo.includes(REDACTED_SENTINEL)) {
        throw new SentinelRejectionError(path);
      }
    }
  }
  if (Array.isArray(submitted)) {
    return {
      merged: submitted.map((element, index) => adoptNew(element, `${path}[${index}]`).merged),
      restored: false,
    };
  }
  if (isRecord(submitted)) {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(submitted)) {
      out[key] = adoptNew(child, joinPath(path, key)).merged;
    }
    return { merged: out, restored: false };
  }
  return { merged: deepClone(submitted), restored: false };
}

interface UserinfoSpan {
  /** Index of the first userinfo character (just after `://`). */
  start: number;
  /** Index of the `@` delimiting userinfo from host. */
  at: number;
  userinfo: string;
}

/** All URL-userinfo spans in `s`, per the Go userinfo regex (see URL_USERINFO_PATTERN). */
function userinfoSpans(s: string): UserinfoSpan[] {
  const re = new RegExp(URL_USERINFO_PATTERN, 'gi');
  const spans: UserinfoSpan[] = [];
  let match: RegExpExecArray | null;
  while ((match = re.exec(s)) !== null) {
    const start = match.index + match[1].length;
    const at = match.index + match[0].length - 1;
    spans.push({ start, at, userinfo: s.slice(start, at) });
  }
  return spans;
}

/**
 * R6 splice: the submitted string carries exactly one userinfo segment
 * whose value is the sentinel, and the stored string carries exactly
 * one userinfo segment. The submitted string IS the user's edit (host,
 * path, query, scheme — whatever differs is the edit); splice the
 * stored userinfo into it at the userinfo position. Returns null when
 * the shapes do not align (stored has zero or several URLs, submitted
 * has no userinfo segment, or the submitted userinfo is anything other
 * than exactly the sentinel) — then the submitted string is a new
 * literal, never restored. Multi-URL strings are not spliced: they
 * fall back to exact-redacted equality or a literal.
 */
function spliceUserinfo(stored: string, submitted: string): string | null {
  const storedSpans = userinfoSpans(stored);
  if (storedSpans.length !== 1) return null;
  const submittedSpans = userinfoSpans(submitted);
  if (submittedSpans.length !== 1) return null;
  const storedSpan = storedSpans[0];
  const submittedSpan = submittedSpans[0];
  if (submittedSpan.userinfo !== REDACTED_SENTINEL) return null;
  return (
    submitted.slice(0, submittedSpan.start) + storedSpan.userinfo + submitted.slice(submittedSpan.at)
  );
}

/** Structural equality for JSON-shaped values (key order ignored). Identity-key values are compared by content, not by reference: a freshly parsed submitted document never shares references with the stored one, so `!==` would reject every element whose identity value is an array or object (e.g. a WireGuard endpoint `address` list). */
function jsonDeepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((element, index) => jsonDeepEqual(element, b[index]));
  }
  if (isRecord(a) || isRecord(b)) {
    if (!isRecord(a) || !isRecord(b)) return false;
    const aKeys = Object.keys(a);
    const bKeys = Object.keys(b);
    if (aKeys.length !== bKeys.length) return false;
    return aKeys.every(
      (key) => Object.prototype.hasOwnProperty.call(b, key) && jsonDeepEqual(a[key], b[key]),
    );
  }
  return false;
}

/**
 * R4 identity guard: an array element whose merge restored a secret
 * must still be the same element. Every identity key present in the
 * stored element (`tag`, `type`, `username`, `name`, `address`,
 * `port`) must be present and unchanged in the submitted element;
 * a reorder/insert/delete that shifts a sentinel onto a different
 * element rejects instead of restoring the wrong secret. Keys
 * absent from the stored element impose no constraint. When the
 * stored element has none of these keys, there is nothing to check
 * and the guard falls back to positional merge (documented
 * residual: see SECRETS-CONTRACT.md).
 *
 * Non-object elements have no identity keys at all, so no check is
 * possible for them: restores inside them (e.g. a userinfo-redacted
 * string in a string array, kept via R6) are left to positional
 * merge. That is the real reason for the primitive fallback — not
 * that restores cannot arise there; they do, via R6.
 *
 * Carve-out: an `address` value carrying a URL-userinfo span is
 * governed by R6, not by identity. Its submitted form is the
 * redacted view (or an R6 host edit), so it cannot serve as an
 * identity assertion; comparing it raw would reject every
 * legitimate host edit. For such values the address comparison is
 * skipped and the element's identity rests on its other keys.
 */
function checkElementIdentity(
  storedElement: unknown,
  submittedElement: unknown,
  path: string,
): void {
  if (!isRecord(storedElement) || !isRecord(submittedElement)) return;
  for (const key of ['tag', 'type', 'username', 'name', 'address', 'port']) {
    if (!Object.prototype.hasOwnProperty.call(storedElement, key)) continue;
    const storedValue = storedElement[key];
    if (!Object.prototype.hasOwnProperty.call(submittedElement, key)) {
      throw new SentinelRejectionError(path);
    }
    const submittedValue = submittedElement[key];
    if (
      key === 'address' &&
      typeof storedValue === 'string' &&
      typeof submittedValue === 'string' &&
      (userinfoSpans(storedValue).length > 0 || userinfoSpans(submittedValue).length > 0)
    ) {
      continue;
    }
    if (!jsonDeepEqual(storedValue, submittedValue)) {
      throw new SentinelRejectionError(path);
    }
  }
}

function mergeNode(
  stored: unknown,
  submitted: unknown,
  path: string,
  secretPosition: boolean,
): MergeResult {
  // Exact sentinel string (whole-value match after parse only). A
  // sentinel at a path absent from stored rejects whatever the key
  // (R2/R3); at a present secret position it keeps the stored value
  // (R1); at a present non-secret position it is an ordinary literal.
  if (typeof submitted === 'string' && submitted === REDACTED_SENTINEL) {
    if (stored === ABSENT) throw new SentinelRejectionError(path);
    if (secretPosition) {
      return { merged: deepClone(stored), restored: true };
    }
    return { merged: REDACTED_SENTINEL, restored: false };
  }
  if (stored === ABSENT) return adoptNew(submitted, path);

  if (isRecord(stored) && isRecord(submitted)) {
    const out: Record<string, unknown> = {};
    let restored = false;
    // Keys absent from submitted are deleted (R9); keys only in
    // submitted are new (adoptNew rejects new sentinels).
    for (const [key, child] of Object.entries(submitted)) {
      // Inherited secretPosition is intentional and fail-closed: once
      // inside a secret-key subtree (e.g. the `obfs` object, whose
      // value is redacted wholesale), every nested position counts
      // as a secret position, so the stored subtree is kept or
      // rejected as a unit and never partially merged with a
      // sentinel nested inside it.
      const childSecret = secretPosition || isSecretKey(key) || isHeaderMapKey(key);
      const childStored: unknown = Object.prototype.hasOwnProperty.call(stored, key) ? stored[key] : ABSENT;
      const result = mergeNode(childStored, child, joinPath(path, key), childSecret);
      restored = restored || result.restored;
      out[key] = result.merged;
    }
    return { merged: out, restored };
  }

  if (Array.isArray(stored) && Array.isArray(submitted)) {
    const out: unknown[] = [];
    let restored = false;
    for (let index = 0; index < submitted.length; index++) {
      const elementPath = `${path}[${index}]`;
      if (index < stored.length) {
        const result = mergeNode(stored[index], submitted[index], elementPath, secretPosition);
        if (result.restored) checkElementIdentity(stored[index], submitted[index], elementPath);
        restored = restored || result.restored;
        out.push(result.merged);
      } else {
        out.push(adoptNew(submitted[index], elementPath).merged);
      }
    }
    return { merged: out, restored };
  }

  if (typeof stored === 'string' && typeof submitted === 'string') {
    if (submitted === stored) return { merged: stored, restored: false };
    // Untouched userinfo-redacted string -> keep stored verbatim (R6).
    // This IS a restore of the stored userinfo, so it marks restored:
    // the array identity guard must run for it (F2), or a swapped
    // element carrying only a userinfo secret would cross-attach.
    if (submitted === redactURLUserinfo(stored)) return { merged: stored, restored: true };
    // Multi-URL fail-closed (coordinator decision): a submitted
    // string carrying a `<redacted>@` userinfo segment is rejected
    // unless the stored and submitted strings each carry exactly
    // one userinfo span (the single-span splice below). The
    // untouched case is already handled above, so reaching here
    // with a sentinel segment means the string was edited; no
    // per-span splicing is attempted, and the sentinel segments
    // must never persist as literals.
    const storedSpans = userinfoSpans(stored);
    const submittedSpans = userinfoSpans(submitted);
    if (
      submittedSpans.some((span) => span.userinfo === REDACTED_SENTINEL) &&
      (storedSpans.length !== 1 || submittedSpans.length !== 1)
    ) {
      throw new SentinelRejectionError(path);
    }
    // A span that merely CONTAINS the sentinel (e.g.
    // "user:<redacted>") is neither the exact sentinel splice
    // nor a clean new literal: it could carry a live secret
    // pasted by mistake past the redaction boundary. Reject
    // it (mirrors Go merge.go).
    for (const span of submittedSpans) {
      if (span.userinfo !== REDACTED_SENTINEL && span.userinfo.includes(REDACTED_SENTINEL)) {
        throw new SentinelRejectionError(path);
      }
    }
    const spliced = spliceUserinfo(stored, submitted);
    // A splice restores the stored userinfo into the edited string,
    // so it marks restored for the array identity guard (F2).
    if (spliced !== null) return { merged: spliced, restored: true };
    // Tampered/removed userinfo, or any other edit: new literal (R6/R7).
    return { merged: submitted, restored: false };
  }

  // Type change or scalar edit: a submitted value whose JSON kind
  // differs from the stored value's has no stored counterpart for
  // its nested paths, so it is adopted as new (R2 semantics via
  // adoptNew): any exact sentinel nested inside it rejects instead
  // of persisting at a secret position. Same-kind scalar edits
  // reach here too (numbers, bools, null) and are taken verbatim.
  // Deletion/empty/null are distinct from keep (R9): they arrive
  // here, never in the sentinel branch.
  if (jsonKind(stored) !== jsonKind(submitted)) return adoptNew(submitted, path);
  return { merged: deepClone(submitted), restored: false };
}

/**
 * Merge a submitted (redacted, edited) document against the stored
 * document, per R1-R9. Throws SentinelRejectionError naming the JSON
 * path (only) when a sentinel appears where no stored value exists,
 * or when an array reorder moves a sentinel onto a different element.
 * Never mutates either input. A sentinel at a non-secret position is
 * returned as an ordinary literal value.
 */
export function mergeConfig(stored: unknown, submitted: unknown): unknown {
  return mergeNode(stored, submitted, '', false).merged;
}

/**
 * R8 assertion helper: find the first path in `doc` where the exact
 * sentinel string sits at a secret position — under a secret key, at
 * any depth inside a secret-key subtree, or anywhere inside a
 * header map (including the header-map value itself). Returns the
 * JSON path, or null when no such position holds the sentinel. A
 * sentinel at a present non-secret position is an ordinary literal
 * and is NOT reported: the assertion respects the non-secret-literal
 * case. The store calls this on the merged document before writing;
 * a non-null result means the merge let a sentinel through and the
 * save must be refused without writing.
 */
export function findSentinelAtSecretPosition(
  value: unknown,
  secretPosition = false,
  path = '',
): string | null {
  if (typeof value === 'string') {
    return value === REDACTED_SENTINEL && secretPosition ? path : null;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++) {
      const found = findSentinelAtSecretPosition(value[index], secretPosition, `${path}[${index}]`);
      if (found !== null) return found;
    }
    return null;
  }
  if (isRecord(value)) {
    for (const [key, child] of Object.entries(value)) {
      const childSecret = secretPosition || isSecretKey(key) || isHeaderMapKey(key);
      const found = findSentinelAtSecretPosition(child, childSecret, joinPath(path, key));
      if (found !== null) return found;
    }
  }
  return null;
}
