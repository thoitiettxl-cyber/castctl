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
- The config file is saved mode 0600, atomically, with
  no `.bak` or any other backup copy: a backup would be a
  second copy of plaintext secrets. (Save-side enforcement:
  loading does not refuse a world-readable file.)
- Credentials are stored reversibly (form submission needs
  the plaintext) — never hashed, never sourced from env/argv,
  never passed to a plugin. Castctl itself never writes the
  values to a separate file — but a headless re-login types
  them into a browser, and the browser keeps its own copies
  outside castctl's control:
  - Attach-first: the credentials are typed into the
    operator's own running Chrome, where Chrome may retain
    them via autofill, password-save prompts, and form
    history. Castctl cannot clear or audit that retention.
  - Launched browser: Chrome writes its own cookie store,
    history, and Login Data under the per-profile
    `chromium-profile/` dir (0700 directory; file modes are
    Chrome's, not castctl's). The dir persists by design
    (Chrome profile reuse across attempts) and castctl never
    rotates or deletes it, except that a failed launch or
    observation removes a dir that launch created. The
    operator removes it by deleting the directory. A launch
    whose Chrome binary is missing fails fast, before the
    dir or the proxy is created, and never waits past
    cancellation for a browser that failed to start.
  - Harvest reads all of the browser profile's cookies into
    memory briefly; only `muse.ai` / `auth.muse.ai` cookies
    are kept and persisted, the rest are dropped (count only).
  The only castctl read path is the keeper-internal accessor;
  values live in unexported config-entry fields, and the only
  value-carrying accessor returns the keeper-internal
  `LoginCredential` value (in memory only, cleared after use
  on a best-effort basis, never marshalled, logged, or handed
  to a plugin).
- Credentials never appear in `auth status` output, keeper
  state files, audit records, logs, or Telegram notices
  (profile name only). A sentinel-leak test pins this at the
  command layer, over CLI outputs, state files, redacted
  config views, log lines, and web UI API responses.
- A file edit that removes or rotates a credential entry is
  authoritative on the next re-login attempt: the keeper
  re-reads `config.json` from disk each time a re-login is
  attempted, so a running keeper picks the edit up without a
  restart. (Driver wiring is fixed at process start; only
  the values are re-read. Removing a credential does not
  invalidate cookies already harvested.)

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
