# Security

Secrets in `config.json` are write-only: the server never sends a
secret value to the browser, and the browser never persists config
content anywhere. Reads return the redacted view, with the sentinel
`<redacted>` standing in for secret values; on save, the sentinel
keeps the stored value, guarded by the stored-file SHA-256 with a
409 on mismatch. Error and rejection messages name paths only,
never values. Secrets are never printed, logged, or committed.

The full contract is the [secrets write-only contract](../webui/SECRETS-CONTRACT.md).
The Go server MUST implement the same redaction, sentinel
keep-on-save, and merge contract server-side (Go PR6).

## `--listen` + token + HTTPS/tunnel guidance

The web UI listens on localhost only by default (`127.0.0.1`, port
`8317` by default, configurable via `--port`). Non-loopback access
requires `--listen` and a token (`CASTCTL_WEBUI_KEY`). Use HTTPS or a
tunnel for non-loopback access.
