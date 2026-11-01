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

## Plugins

Plugins are trusted, in-process, first-party only, with no
sandbox: a loaded plugin runs with the process's privileges
and must never be treated as untrusted input. A plugin
receives no secrets — no cookie paths, tokens, WireGuard
keys, or real proxy credentials — only a secret-stripped
outbound identity hash, ephemeral loopback-proxy
credentials, and its own config fragment (shown as
`<redacted>` wholesale). The only reverse callback is
`host.log`; `host.auth.*` is rejected absolutely. Plugin
network traffic goes through the core-owned per-session
loopback proxy, which injects the session cookie inside
core. See [Plugins](plugins.md). The framework is not wired
into the runtime in this PR: plugins load only through
`castctl plugin check` and tests.

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
