# Secrets write-only contract (web UI)

Secrets in `config.json` are **write-only**: the server never sends a
secret value to the browser, and the browser never persists config
content anywhere. This document states the contract the dev mock
implements (`dev-mocks/redact.ts`, `dev-mocks/configStore.ts`) and the
future Go backend **MUST** implement server-side (carried for Go PR6).
It lives inside `webui/` because it specifies this frontend/mock
surface; the later docs PR owns `docs/*`.

## Redact-on-read

- Every read that can carry config content returns the **redacted**
  view: `GET /config` (`content`), `GET /dns` (the `dns` slice),
  `GET /profiles/{name}` (`entry`), and the outbound/endpoint
  summaries (built from the redacted shape only).
- Redaction is recursive, by key — never by path allowlist, never by
  value shape:
  - The Go 37 secret keys, verbatim, matched lowercase-exact (no trim,
    no substring). Source: `go/internal/redact/value.go:40-78`
    (`origin/feat/go-port` @ `50a4cbc8`). New keys are added in Go
    first, then mirrored here — never mock-only.
  - `headers` / `extra_headers`: every value redacted, whatever the
    header name. `custom_headers` is NOT a header map.
  - Every other string value: URL-userinfo scrub only (Go regex
    semantics: last `@` before the first `/`, `?`, or `#` after
    `://`). Plain emails and userinfo-free URLs are untouched.
  - The sentinel is exactly `<redacted>` (Go's `redact.Marker`),
    whole-value exact match after JSON parse.
- Boundary (Go parity): `?token=` / fragment / Bearer secrets inside
  plain string values are displayed verbatim except for userinfo
  scrub. Go's structured redactor deliberately does not strip them.
  Any change belongs in Go first; the frontend/mock must not invent a
  third scrub.

## Sentinel keep-on-save

- `GET /config.sha256` is the lowercase hex SHA-256 of the stored
  file's raw bytes. `PUT /config {content, base_sha256}` compares
  `base_sha256` server-side; mismatch → `409 config_changed`, no
  write, no merge. On success the server merges, validates the merged
  document, writes atomically, and returns the hash of the bytes
  written. The client never computes the hash.
- Merge order: guard → parse → merge → validate merged → write →
  hash. The sentinel is never persisted and never validated as a
  credential.
- Merge rules (structural, parsed JSON only, by path):
  - Existing secret + sentinel → keep the stored value verbatim.
  - Sentinel at any path absent from stored (new field, new header
    name, new array element, rename/move) → reject the whole save:
    `400 validation_failed`, message names the JSON path only.
  - Arrays merge positionally; an element whose merge restored a
    secret must keep the same `tag`/`type`, else reject.
  - Header maps merge per header name. URL-userinfo strings splice
    the stored userinfo into the submitted string at the userinfo
    position. A tampered sentinel is an ordinary literal value.
  - Deletion, empty string, and `null` are distinct from keep.
  - On 409 the client reloads fresh redacted content and discards the
    failed edit, including any secret the user typed into it.

## DNS editor (contract change, D1)

`GET /dns` returns the redacted slice **with** the stored-file
`sha256`. `PUT /dns` accepts `{dns, base_sha256}`, enforces the same
409 guard, and merges per the rules above against the stored `dns`
section. This is a minimal extension of the previously frozen `dnsApi`
shapes; the Go backend must implement it the same way (Go PR6).

## Other surfaces

- Profile entries, diff modals (redacted base vs edited text),
  endpoint import preview, logs, and error/toast paths follow the
  same rules: error and rejection messages name paths only, never
  values; log messages are produced redacted server-side.
- Telegram stays write-only (empty token = unchanged); the token is
  never part of config content. Login cookies travel only through the
  login-import endpoint and are never written into config content.
- The config editor edits the single-file portion only. The stored
  legacy profile entry is untouched by config/DNS saves; backend
  behaviour for legacy-only layouts is unpinned/carried (Go PR6).
- The mock does not canonicalise beyond the merge (JSON round-trip
  of the merged structure). Go-backend write canonicalisation is
  unpinned/carried (Go PR6).

## Frontend discipline

- The frontend renders what the server returns. It must NOT add its
  own scrubber, sentinel handling, or hash computation: a second
  implementation would drift from the server contract.
- Never persist config content (redacted or not) to any browser
  storage, and never pass config content or API error bodies into
  confirmation messages or `console.*`.
