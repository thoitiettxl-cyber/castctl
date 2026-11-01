# Security

Secrets in `config.json` are write-only: the server never sends a
secret value to the browser, and the browser never persists config
content anywhere. Reads return the redacted view, with the sentinel
`<redacted>` standing in for secret values; on save, the sentinel
keeps the stored value, guarded by the stored-file SHA-256 with a
409 on mismatch. Error and rejection messages name paths only,
never values. Secrets are never printed, logged, or committed.

The full contract is the [secrets write-only contract](../webui/SECRETS-CONTRACT.md).
The Go server implements the same redaction, sentinel
keep-on-save, and merge contract server-side (`internal/webui`).

## Loopback-only + token guidance

The web UI listens on loopback only (`127.0.0.1`, port `8317` by
default at runtime when the block has no `listen` key). The
`webui` block's `listen` key — the only listen source — is
validated loopback-only; a non-loopback address is a config
error, never a wider bind. Every `/api/v1` route requires a
Bearer token (the block's `token`, stored as a bcrypt hash:
plaintext is hashed and written back on serve startup and on
API saves, and logins are compared against the hash); the
token is never printed, logged, or returned. Reach the server
from another device through an SSH tunnel forwarding the
loopback port — never by binding a non-loopback address, and
never by exposing the Vite dev server.
