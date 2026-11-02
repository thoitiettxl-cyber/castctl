# Security

Secrets in `config.json` are write-only: the server never sends a
secret value to the browser, and the browser never persists config
content anywhere. Reads return the redacted view, with the sentinel
`<redacted>` standing in for secret values; on save, the sentinel
keeps the stored value, guarded by the stored-file SHA-256 with a
409 on mismatch. Error and rejection messages name paths only,
never values. Secrets are never printed, logged, or committed.

## Login credentials (`credentials` block)

The `credentials` block (login `username`/`password` per profile,
for the keeper's automatic headless re-login) follows the same
write-only contract, strengthened:

- Both `username` and `password` are secret keys in the
  redaction layer (`redact.secretKeys`, pinned by tests):
  every redacted view — CLI, web UI, logs, errors — renders
  `<redacted>`, and a `<redacted>` sentinel at either position
  is a secret position a save must never persist (the web UI's
  R8 assertion).
- The config file is mode 0600 and is saved atomically with
  no `.bak` or any other backup copy: a backup would be a
  second copy of plaintext secrets.
- Credentials are stored reversibly (form submission needs
  the plaintext) — never hashed, never sourced from env/argv,
  never written to a separate file, never passed to a plugin.
  The only read path is the keeper-internal accessor; no
  exported struct field carries a credential value.
- Credentials never appear in `auth status` output, keeper
  state files, audit records, logs, or Telegram notices
  (profile name only). A sentinel-leak test pins this at the
  command layer.
- A file edit that removes a credential entry is
  authoritative on the next keeper tick: credentials are
  re-read from disk per factory build and no live comparator
  caches them (unlike the webui token's live comparator —
  see the file-edit-removal limit in the web UI contract).

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

## Browser hardening (Design A)

Authentication stays stateless Bearer: no cookies, no CORS, no
remember-password. The no-CORS defence is the Origin allowlist:
mutating requests (`POST`/`PUT`/`PATCH`/`DELETE`) with an `Origin`
header from a non-loopback, non-same-host origin get a fixed 403;
an absent `Origin` (a non-browser client) is allowed, and
loopback/same-host origins are allowed. The check runs after
authentication, so a cross-origin request without a valid token
still gets 401, never a 403 that would confirm the route exists.
Middleware order is load-bearing and pinned: rate-limit → auth →
Origin → timeout.

Login attempts are rate-limited with a stdlib fixed-window
counter, in-memory and bounded: 5 failed token verifications per
5 minutes per remote address (configurable via
`webui.login_rate_limit`), then a fixed 429 with `Retry-After`.
A successful verification resets the counter. The store holds
at most 1024 addresses and the check fails closed at the cap:
when the store is full of unexpired entries, a request from an
address with no entry gets a fixed 429 (after pruning entries
whose window has expired), without being inserted — so a flood
of distinct addresses can never evict a limited address's entry
and reset its budget, and a newcomer's failures can never slip
past uncounted. The tradeoff is stated plainly: the 429 is
served before authentication, so a valid token presented from a
fresh address at a full cap is also 429 until an entry's window
expires and frees a slot, or the process restarts. The store is
per-process: a restart resets all budgets. The screencast WebSocket upgrade passes through the same limiter
(it carries no Bearer check and never feeds the counter), so an
over-limit address gets a 429 on the upgrade too until its
window expires; the WebSocket path is not exempted. API
responses carry `Cache-Control: no-store` and
`X-Content-Type-Options: nosniff`.

Session expiry is frontend-only: the browser discards the token
after `webui.session_idle_timeout` (default `12h`) without user
activity and requires re-login; a 401 from any call logs out
globally. Stated honestly: the server cannot revoke a Bearer, so
a stolen token stays valid until the configured token is
rotated — idle expiry bounds only an unattended browser tab.
