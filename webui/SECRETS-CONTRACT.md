# Secrets write-only contract (web UI)

Secrets in `config.json` are **write-only**: within the boundaries
stated in [Boundaries and known residuals](#boundaries-and-known-residuals),
the server never sends a secret value to the browser, and the browser
never persists config content anywhere. The boundaries are part of
the guarantee, not footnotes to it: an unknown future key, a
`?token=` / fragment / Bearer secret inside a plain string, and a
whitespace-padded key are each handled only as stated there. This
document states the contract the dev mock implements
(`dev-mocks/redact.ts`, `dev-mocks/configStore.ts`) and the future
Go backend **MUST** implement server-side (carried for Go PR6).
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
  - `headers` / `extra_headers`: every value redacted wholesale,
    whatever the header name. `custom_headers` is NOT a header map.
    A header value that is a map has every value replaced with the
    marker (names survive); any non-map, non-nil header value
    (string, number, bool, object, array) becomes the marker
    wholesale; nil stays nil. This mirrors Go's `redactHeaders`
    exactly.
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
  hash. The sentinel is never persisted at a secret position (it
  restores the stored value or the save rejects); at a present
  non-secret position it is an ordinary literal value. Before
  writing, the store asserts the merged document holds no sentinel
  at any secret/header position.
- Merge rules (structural, parsed JSON only, by path):
  - Existing secret + sentinel → keep the stored value verbatim.
  - Sentinel at any path absent from stored (new field, new header
    name, new array element, rename/move) → reject the whole save:
    `400 validation_failed`, message names the JSON path only.
  - A type change (the submitted value's JSON kind differs from the
    stored value's) adopts the subtree as new: any exact sentinel
    nested inside it rejects the whole save.
  - Arrays merge positionally; an element whose merge restored a
    secret must keep every identity key present in the stored
    element (`tag`, `type`, `username`, `name`, `address`, `port`)
    unchanged, else reject. An `address` carrying a URL-userinfo
    span is governed by the userinfo rule below, not by identity.
  - Header maps merge per header name. URL-userinfo strings splice
    the stored userinfo into the submitted string at the userinfo
    position (single-span case only). A tampered sentinel is an
    ordinary literal value.
  - A submitted string carrying a `<redacted>@` userinfo segment
    with anything other than exactly one userinfo span on each side
    (multi-URL strings, or a sentinel userinfo where the stored
    string has none) is rejected, unless it is the untouched
    redacted view of the stored string, which keeps the stored
    value. No per-span splicing is attempted.
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

## Boundaries and known residuals

These limits are part of the contract. Anything outside them is not
covered by the write-only guarantee as stated.

- **Unknown future keys (Go-set-first rule).** A key not in the Go
  37-key set is protected only if it sits in a header map or its
  value carries URL userinfo. Anything else relies on Go parse-time
  strictness: unknown fields in sing-box option objects are rejected
  by the parser, so an unredacted unknown secret field cannot be
  stored — but it also cannot be displayed, because display requires
  a parseable document. New keys are added in Go first, then
  mirrored in the mock — never mock-only, never by substring
  matching.
- **D2 parity boundary.** `?token=` / fragment / Bearer secrets
  inside plain string values are displayed verbatim except for
  userinfo scrub. Go's structured redactor deliberately does not
  strip them; any change belongs in Go first.
- **Whitespace-key strict-parse boundary.** A key with leading or
  trailing whitespace (e.g. `" password "`) does not match the
  secret-key set. The Go backend's strict parsing is the real
  control; the mock approximates it by rejecting any object key
  with leading/trailing whitespace anywhere in the submitted
  document (`400 validation_failed`, path only, no write). Key
  matching itself stays lowercase-exact.
- **Primitive string-array reorder (F2 residual).** A reorder of a
  string array (no identity keys exist on primitives) that shifts a
  userinfo-kept string onto a different position is
  indistinguishable from a host edit under the positional merge +
  R6 host-edit allowance, and is allowed. Identity protection for
  such arrays would require keys the elements do not have.
- **Identity-guard fallback (R-D residual).** When a restored array
  element's stored form has none of the identity keys (`tag`,
  `type`, `username`, `name`, `address`, `port`), the guard falls
  back to positional merge: a reorder there restores positionally
  and can cross-attach. Elements in the surveyed schema carry at
  least one identity key; a future keyless element type reopens
  this residual.
- **Sentinel literal at a non-secret position (R-A).** The text
  `<redacted>` at a present non-secret position is an ordinary
  literal value and may persist in the stored document. The
  write-only guarantee covers secret positions only; it was never
  a claim about the literal text everywhere.

## Frontend discipline

- The frontend renders what the server returns. It must NOT add its
  own scrubber, sentinel handling, or hash computation: a second
  implementation would drift from the server contract.
- Never persist config content (redacted or not) to any browser
  storage, and never pass config content or API error bodies into
  confirmation messages or `console.*`.
