# Architecture

## Overview

castctl is a general content-pipeline control tool: content sources (first:
Muse) feed publishers (later: Facebook, TikTok, YouTube, via official APIs
first). One Go binary (CGO_ENABLED=1, GLIBC 2.17 baseline). All network traffic of a profile goes through
that profile's outbound (sing-box). The web UI is a single-file React app
embedded in the binary; see "Web UI" below.

Core + plugins: see "Core + plugins" below. The earlier layout
(`internal/source/muse`, `internal/publish/<platform>`) is superseded;
it is not the layout. Binary: `castctl`. Env vars: `CASTCTL_CONFIG`,
`CASTCTL_PROFILE`, `CASTCTL_WEBUI_KEY`.

Migration done: the `go/` tree moved to the castctl
root keeping only `go/` history, the Go module became
`github.com/thoitiettxl-cyber/castctl`, and the binary is `castctl`.
Deleting `go/` from muse-cli with a README pointer is a separate PR.

## Core + plugins

castctl is core + plugins, following CLIProxyAPI's plugin model exactly:
the same loader approach, ABI/contract style, plugins directory layout,
and store/install flow, adapted only for the per-profile proxy/cookies
handoff to plugins (never raw WireGuard keys). Plugins MUST send all
network traffic through the per-profile dialer that core provides, and
never dial directly, since without a sandbox they could otherwise bypass
the profile's outbound. CLIProxyAPI's config schema uses
`plugins.enabled` (global) and `plugins.configs.<id>.enabled`
(per-plugin); castctl follows the model exactly, adopting the same
toggles. The plugin toggles (`plugins.enabled` and
`plugins.configs.<id>.enabled`) are changed through the Management API
and the web UI.

Core is profiles, per-profile outbound (sing-box), the cookie/session
store and keeper, config, the web UI, and Telegram. Screencast login
stays in core. Each platform is a plugin: castctl-muse first, then
castctl-facebook, castctl-tiktok, and castctl-youtube.

Plugins are trusted and in-process, with no sandbox, exactly like
CLIProxyAPI, and only first-party CLIs (BQ1, closed). BQ2–BQ5 are
parked until just before plugin implementation, after the migration.
The red-team findings B1, B2, B3, and B4–B10 are parked.
The plugin design draft is rationale only: at implementation start it
is condensed to an implementable spec of under 20 KB mirroring
CLIProxyAPI, pointing to the draft for rationale. This docs change
does not condense it.

The upstream sources for the plugin model, the toggles, and what was
deliberately not taken are recorded in docs/provenance.md §2.

## Platforms

castctl is a general tool, not VM-only. Supported run targets: Linux only — linux/amd64 and linux/arm64 (Debian/server Linux host). No VM assumptions: no hard-coded paths,
no launcher, no agent-browser, no sandbox.

This supersedes the earlier five-target plan: release targets are
Linux only (above). The default build is dynamically linked
(`CGO_ENABLED=1`) on a GLIBC 2.17 baseline (manylinux2014); each
architecture also ships a `_no-plugin` static build
(`CGO_ENABLED=0`). The plugin loader is not implemented, so
neither build loads plugins. There are no Android, Windows, or
macOS builds. Release builds are produced by
`.github/workflows/release.yaml`, adapted from CLIProxyAPI's
release.yaml (see docs/provenance.md §2).

Config location: `--config`, then `CASTCTL_CONFIG`, then `XDG_CONFIG_HOME`, via `os.UserConfigDir` semantics. Directory fallback: when the `castctl` home does not exist but the pre-migration `muse-cli` home does, the old home is used with a one-line warning; nothing is moved or deleted (see README.md).

Screencast login: the browser dependency is optional and detected at
runtime (system Chromium or a configured path); with no browser, fall back
to `auth import` with a clear message. Plan for logging in from another device's web UI (e.g. a phone browser) against castctl's `--listen` server.

The web UI must work from a phone browser against castctl on another host
(`--listen` + token + HTTPS/tunnel guidance, see docs/security.md). Tests
must not depend on the developer VM's environment (hermetic: temp dirs,
fakes, no live hosts).

## Profile isolation (hard invariant)

Profiles must never interfere with each other through the sing-box
stack. This is a HARD invariant: a violation is a bug, and enforcement
is by test, not by convention. It applied in the `go/` tree in
muse-cli, on `feat/go-port`, pre-migration, and applies in castctl
now that the migration has landed, to every command,
the Telegram bot, the web UI, the session keeper, and the screencast
login flow.

1. **One outbound stack per profile.** Either one sing-box box instance
   per profile, or unique tags per profile, namespaced as
   `<profile>/<tag>`. Never share MUTABLE state between profiles:
   registries, outbound/endpoint managers, routers, DNS clients, and
   dialers are built per profile. Shared data across profiles must be
   immutable configuration only, proven read-only by test. Two profiles
   built concurrently must have independent lifecycles (start/stop of
   one never affects the other).

2. **Local inbounds are per profile and per session, with auth.** A
   local inbound created for the login browser (or any other local
   consumer) binds `127.0.0.1` on an OS-assigned port (`:0`), belongs to
   exactly one profile and one session, requires authentication with a
   random username/password generated for that session, and is closed
   when the session ends. Never a fixed port, never `0.0.0.0`, never
   shared across profiles or sessions, never without auth — so another
   profile or process cannot use it.

3. **Per-profile network state, no cross-profile routing.** The DNS
   cache/client, connection pools, TLS session cache, and cookie jar are
   all per profile. Profile A's traffic must NEVER leave through profile
   B's outbound. Required test: run two profiles concurrently through
   DIFFERENT outbounds backed by fake servers, and assert each egress
   hit only the right upstream (each fake records arrivals; profile A's
   requests appear only at fake A, B's only at fake B), with DNS and
   cookie-jar activity staying inside the owning profile. The TLS session
   cache is OFF by default; if it is ever enabled, it is per profile —
   a global cache must not exist.

4. **No shared WireGuard private key across profiles.** Two profiles
   may not share a WireGuard endpoint config with the same private key
   at the same time — including via a shared endpoint tag referenced by
   both profiles. Validate at config load: the load FAILS with exit 2
   and a clear error naming both profiles. Never print the key in the
   error, a log, or a fixture. Different keys, or a key used by a single
   profile, load normally.

5. **No environment proxy, no system proxy, ever.** No
   `ProxyFromEnvironment`, no reads of `HTTP_PROXY` / `HTTPS_PROXY` /
   `ALL_PROXY` / `NO_PROXY` anywhere in product code, no OS/system-proxy
   detection, and sing-box `SetSystemProxy` is `false` everywhere. A
   test must prove dialling is unaffected by hostile proxy environment
   variables. The only proxy a profile uses is the explicit `http`
   outbound in its own configuration, if any; `direct` stays truly
   direct.

Related invariants (already decided, restated here because this
section is the single reference): every network call of a profile
goes through that profile's one outbound dialer (fail closed, no
system-resolver fallback); cookies live in separate `0600` files, never
inline in `config.json`; secrets are never printed, logged, or
committed (see `docs/security.md`).

## Web UI

Source: `webui/` — a fork of the router-for-me/Cli-Proxy-API-Management-Center
frontend at `64b4f5aed19b8f791eb21eb9e785ea379ea05b44` (MIT; see
`webui/NOTICE` and the in-app About page). Kept: React + TypeScript + Vite
build, `vite-plugin-singlefile` output, theme/layout (including the mobile
off-canvas sidebar), shared UI components, i18next mechanism, CodeMirror
integration, diff-before-save pattern. Replaced: all pages, the API client
(fetch wrapper against castctl's own `/api/v1`), the auth store
(sessionStorage token), locale strings (English + Vietnamese), branding.

The committed `webui/dist/index.html` is the PRODUCTION build (mocks off).
The mock API layer (`webui/dev-mocks/`, `VITE_USE_MOCKS=true`) is dev-only
and never bundled. The screencast Login page is behind a build-time flag
(`VITE_ENABLE_SCREENCAST_LOGIN`, default off). Build/serve/mock
instructions: docs/development.md. Native-login bundle research (PARKED):
docs/research/native-login-bundle-analysis.md.

Secrets in config are write-only under the [secrets write-only contract](../webui/SECRETS-CONTRACT.md),
which the Go server MUST implement server-side (see docs/security.md).

The web UI fork's upstream commit, the measured file diff, and what
was kept, adapted, or removed are recorded in docs/provenance.md §3.
