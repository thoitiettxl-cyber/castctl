/**
 * Dev-mock config store (Node, Vite dev server only; never bundled).
 *
 * The mock owns mutable stored config bytes and enforces the
 * secrets-write-only contract on behalf of the future Go backend:
 * `sha256` is the SHA-256 of the stored file's raw bytes, `PUT`
 * compares `base_sha256` against the current stored hash (mismatch ->
 * 409 `config_changed`, no write), and saves merge the submitted
 * redacted text against the stored document (redact.ts) before
 * validating the merged document and writing it. The mock does NOT
 * canonicalise beyond the merge: it echoes the merged structure via a
 * JSON round-trip (Go-backend write canonicalisation is unpinned and
 * carried for Go PR6 — coordinator decision D4).
 *
 * The config editor edits the single-file portion only. The stored
 * legacy profile entry (legacyProfileEntryFixture) lives outside this
 * store and is never touched by config/DNS saves (coordinator
 * decision D3; the legacy-only backend case is unpinned/carried).
 */

import { deriveConfigSource } from './configSource.ts';
import {
  legacyProfileEntryFixture,
  profilesFixture,
  sha256Hex,
  storedConfigDocument,
} from './fixtures.ts';
import {
  findSentinelAtSecretPosition,
  mergeConfig,
  redactValue,
  SentinelRejectionError,
  stringifyConfigDocument,
} from './redact.ts';

export interface StoreError {
  status: number;
  type: string;
  /** Path-only / generic message. Never contains a submitted value. */
  message: string;
}

export type StoreResult<T> = { ok: true; data: T } | { ok: false; error: StoreError };

/** The mutable stored bytes. Re-parsed on every access; never aliased. */
let storedBytes: string = stringifyConfigDocument(storedConfigDocument);

function currentHash(): string {
  return sha256Hex(storedBytes);
}

function storedDocument(): Record<string, unknown> {
  return JSON.parse(storedBytes) as Record<string, unknown>;
}

/** Reset the store to the initial fixture bytes (tests only). */
export function resetConfigStore(): void {
  storedBytes = stringifyConfigDocument(storedConfigDocument);
}

/**
 * Structural validation of a merged document (mock only): the Go
 * `ParseSingleConfig` semantics apply when the backend lands. Returns
 * the offending JSON path, or null when structurally valid. Messages
 * built from the path never contain values.
 */
function findStructuralViolation(doc: unknown): string | null {
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return '';
  const record = doc as Record<string, unknown>;
  const topLevelKeys = ['default_profile', 'profiles', 'outbounds', 'endpoints', 'dns'];
  for (const key of Object.keys(record)) {
    if (!topLevelKeys.includes(key)) return key;
  }
  if (record.profiles !== undefined) {
    if (typeof record.profiles !== 'object' || record.profiles === null || Array.isArray(record.profiles)) {
      return 'profiles';
    }
    for (const [name, entry] of Object.entries(record.profiles as Record<string, unknown>)) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
        return `profiles.${name}`;
      }
      // Inline cookies are forbidden in config.json (Go ParseSingleConfig);
      // a `cookie` key inside a sing-box options object is legitimate and
      // is redacted by key, not rejected here.
      for (const forbidden of ['cookies', 'cookie']) {
        if (Object.prototype.hasOwnProperty.call(entry, forbidden)) {
          return `profiles.${name}.${forbidden}`;
        }
      }
    }
  }
  for (const key of ['outbounds', 'endpoints']) {
    if (record[key] !== undefined && !Array.isArray(record[key])) return key;
  }
  if (record.dns !== undefined && (typeof record.dns !== 'object' || record.dns === null || Array.isArray(record.dns))) {
    return 'dns';
  }
  return null;
}

function validationError(path: string): StoreError {
  return {
    status: 400,
    type: 'validation_failed',
    message: path === '' ? 'Invalid configuration' : `Invalid configuration at ${path}`,
  };
}

function conflictError(): StoreError {
  return {
    status: 409,
    type: 'config_changed',
    message: 'Configuration changed on disk; reload before saving',
  };
}

/** The staleness guard, evaluated before any body parsing or shape checks (R8 precedence: stale hash + invalid JSON is a 409, not a 400). Returns the conflict error, or null when the hash is current. */
function hashGuardError(baseSha256: unknown): StoreError | null {
  if (typeof baseSha256 !== 'string' || baseSha256 !== currentHash()) return conflictError();
  return null;
}

/** Rejection carrying the JSON path of a whitespace-padded key (path only, never a value). */
class WhitespaceKeyError extends Error {
  readonly path: string;

  constructor(path: string) {
    super('Object key has leading or trailing whitespace');
    this.name = 'WhitespaceKeyError';
    this.path = path;
  }
}

/**
 * Find the first object key with leading/trailing whitespace anywhere
 * in the submitted document, or null. This is a mock approximation
 * of Go strict parsing: a key such as `" password "` does not match
 * the secret-key set (lowercase-exact, no trim), so without this
 * check it would leak end-to-end in the mock. The Go backend's
 * strict parser rejects unknown fields and is the real control;
 * the mock rejects here, fail-closed, with a path-only error and
 * no write. Key matching itself stays lowercase-exact — this is a
 * validation rule, not a matcher change.
 */
function findWhitespaceKey(value: unknown, path: string): string | null {
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++) {
      const found = findWhitespaceKey(value[index], `${path}[${index}]`);
      if (found !== null) return found;
    }
    return null;
  }
  if (typeof value === 'object' && value !== null) {
    for (const [key, child] of Object.entries(value)) {
      const childPath = path === '' ? key : `${path}.${key}`;
      if (key !== key.trim()) return childPath;
      const found = findWhitespaceKey(child, childPath);
      if (found !== null) return found;
    }
  }
  return null;
}

function whitespaceError(path: string): StoreError {
  return {
    status: 400,
    type: 'validation_failed',
    message: `Invalid configuration at ${path}`,
  };
}

/** Guard -> parse -> merge -> validate merged -> write -> hash. Shared by PUT /config and PUT /dns. */
function saveMerged(
  baseSha256: unknown,
  merge: (stored: Record<string, unknown>) => unknown,
): StoreResult<{ sha256: string }> {
  const guard = hashGuardError(baseSha256);
  if (guard !== null) {
    return { ok: false, error: guard };
  }
  const stored = storedDocument();
  let merged: unknown;
  try {
    merged = merge(stored);
  } catch (err) {
    if (err instanceof SentinelRejectionError) {
      return {
        ok: false,
        error: {
          status: 400,
          type: 'validation_failed',
          message: `Redacted value at ${err.path} has no stored value; supply a real value or omit the field`,
        },
      };
    }
    if (err instanceof WhitespaceKeyError) {
      return { ok: false, error: whitespaceError(err.path) };
    }
    throw err;
  }
  const violation = findStructuralViolation(merged);
  if (violation !== null) return { ok: false, error: validationError(violation) };
  // R8 assertion (defence in depth: the merge must already exclude
  // sentinels from secret positions): refuse the write rather than
  // persist a sentinel at a secret/header position.
  const leakedSentinel = findSentinelAtSecretPosition(merged);
  if (leakedSentinel !== null) {
    return { ok: false, error: validationError(leakedSentinel) };
  }
  storedBytes = stringifyConfigDocument(merged);
  return { ok: true, data: { sha256: currentHash() } };
}

export function handleGetConfig(): { content: string; sha256: string; source: string } {
  return {
    content: stringifyConfigDocument(redactValue(storedDocument())),
    sha256: currentHash(),
    source: deriveConfigSource(profilesFixture.map((p) => p.source)),
  };
}

export function handlePutConfig(body: {
  content?: unknown;
  base_sha256?: unknown;
}): StoreResult<{ sha256: string }> {
  // Guard first: a stale hash is a 409 even when the body is invalid JSON.
  const guard = hashGuardError(body.base_sha256);
  if (guard !== null) {
    return { ok: false, error: guard };
  }
  if (typeof body.content !== 'string') {
    return { ok: false, error: validationError('') };
  }
  let submitted: unknown;
  try {
    submitted = JSON.parse(body.content) as unknown;
  } catch {
    return {
      ok: false,
      error: { status: 400, type: 'validation_failed', message: 'Invalid JSON in submitted config' },
    };
  }
  return saveMerged(body.base_sha256, (stored) => {
    const whitespacePath = findWhitespaceKey(submitted, '');
    if (whitespacePath !== null) throw new WhitespaceKeyError(whitespacePath);
    return mergeConfig(stored, submitted);
  });
}

export function handleValidateConfig(body: {
  content?: unknown;
}): { valid: boolean; errors: string[] } {
  if (typeof body.content !== 'string') return { valid: false, errors: ['Invalid JSON in submitted config'] };
  let submitted: unknown;
  try {
    submitted = JSON.parse(body.content) as unknown;
  } catch {
    return { valid: false, errors: ['Invalid JSON in submitted config'] };
  }
  const whitespacePath = findWhitespaceKey(submitted, '');
  if (whitespacePath !== null) {
    return { valid: false, errors: [whitespaceError(whitespacePath).message] };
  }
  let merged: unknown;
  try {
    merged = mergeConfig(storedDocument(), submitted);
  } catch (err) {
    if (err instanceof SentinelRejectionError) {
      return {
        valid: false,
        errors: [`Redacted value at ${err.path} has no stored value`],
      };
    }
    throw err;
  }
  const violation = findStructuralViolation(merged);
  if (violation !== null) {
    return { valid: false, errors: [validationError(violation).message] };
  }
  return { valid: true, errors: [] };
}

export function handleGetDns(): { dns: Record<string, unknown>; sha256: string } {
  const stored = storedDocument();
  const dns = stored.dns;
  return {
    dns: (redactValue(typeof dns === 'object' && dns !== null && !Array.isArray(dns) ? dns : {}) as Record<
      string,
      unknown
    >),
    sha256: currentHash(),
  };
}

export function handlePutDns(body: {
  dns?: unknown;
  base_sha256?: unknown;
}): StoreResult<{ sha256: string }> {
  // Guard first: a stale hash is a 409 even when the body is malformed.
  const guard = hashGuardError(body.base_sha256);
  if (guard !== null) {
    return { ok: false, error: guard };
  }
  if (typeof body.dns !== 'object' || body.dns === null || Array.isArray(body.dns)) {
    return { ok: false, error: validationError('dns') };
  }
  const submittedDns = body.dns;
  return saveMerged(body.base_sha256, (stored) => {
    const whitespacePath = findWhitespaceKey(submittedDns, '');
    if (whitespacePath !== null) throw new WhitespaceKeyError(whitespacePath);
    const storedDns = stored.dns;
    const storedSection =
      typeof storedDns === 'object' && storedDns !== null && !Array.isArray(storedDns)
        ? storedDns
        : {};
    return { ...stored, dns: mergeConfig(storedSection, submittedDns) };
  });
}

/** The legacy profile entry, untouched by config/DNS saves (D3). Exposed for the D3 pin test. */
export function snapshotLegacyProfileEntry(): unknown {
  return JSON.parse(JSON.stringify(legacyProfileEntryFixture)) as unknown;
}
