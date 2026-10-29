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
