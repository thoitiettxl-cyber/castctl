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
 *   The sentinel is never persisted and never validated as a credential:
 *   merge precedes validation.
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
 */
export function redactURLUserinfo(s: string): string {
  if (s === '') return s;
  return s.replace(/([a-z][a-z0-9+.-]*:\/\/)[^/?#\s]+@/gi, '$1<redacted>@');
}

function redactNode(value: unknown, forceSecretStrings: boolean): unknown {
  if (typeof value === 'string') {
    return forceSecretStrings ? REDACTED_SENTINEL : redactURLUserinfo(value);
  }
  if (Array.isArray(value)) {
    return value.map((element) => redactNode(element, forceSecretStrings));
  }
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      if (isSecretKey(key)) {
        out[key] = REDACTED_SENTINEL;
      } else if (isHeaderMapKey(key)) {
        out[key] = redactHeaderValue(child);
      } else {
        out[key] = redactNode(child, forceSecretStrings);
      }
    }
    return out;
  }
  return value;
}

/**
 * Redact one header-map value: every value becomes the sentinel, header
 * names survive. A nil header map stays nil; a non-map value is replaced
 * wholesale, so a malformed headers value cannot leak.
 */
function redactHeaderValue(value: unknown): unknown {
  if (value === null) return null;
  if (Array.isArray(value)) return value.map((element) => redactNode(element, true));
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      out[key] = redactNode(child, true);
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
  return redactNode(value, false);
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
  if (typeof submitted === 'string' && submitted === REDACTED_SENTINEL) {
    throw new SentinelRejectionError(path);
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

/** All URL-userinfo spans in `s`, per the Go userinfo regex. */
function userinfoSpans(s: string): UserinfoSpan[] {
  const re = /([a-z][a-z0-9+.-]*:\/\/)[^/?#\s]+@/gi;
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

/**
 * R4 identity guard: an array element whose merge restored a secret
 * must still be the same element (same `tag`, and same `type` where
 * present). A reorder/insert/delete that shifts a sentinel onto a
 * different element rejects instead of restoring the wrong secret.
 * Non-object elements have no identity keys; sentinel restores inside
 * them do not arise from redacted views (secret keys redact wholesale),
 * so they are left to positional merge.
 */
function checkElementIdentity(
  storedElement: unknown,
  submittedElement: unknown,
  path: string,
): void {
  if (!isRecord(storedElement) || !isRecord(submittedElement)) return;
  for (const key of ['tag', 'type']) {
    const storedHas = Object.prototype.hasOwnProperty.call(storedElement, key);
    const submittedHas = Object.prototype.hasOwnProperty.call(submittedElement, key);
    if (storedHas !== submittedHas || storedElement[key] !== submittedElement[key]) {
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
    if (submitted === redactURLUserinfo(stored)) return { merged: stored, restored: false };
    const spliced = spliceUserinfo(stored, submitted);
    if (spliced !== null) return { merged: spliced, restored: false };
    // Tampered/removed userinfo, or any other edit: new literal (R6/R7).
    return { merged: submitted, restored: false };
  }

  // Type change or scalar edit: the submitted value is a new literal
  // (validate normally downstream). Deletion/empty/null are distinct
  // from keep (R9): they arrive here, never in the sentinel branch.
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
