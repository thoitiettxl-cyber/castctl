# Architecture

## Overview

castctl is a general content-pipeline control tool: content sources (first:
Muse) feed publishers (later: Facebook, TikTok, YouTube, via official APIs
first). One Go binary (CGO_ENABLED=1, GLIBC 2.17 baseline). All network traffic of a profile goes through
that profile's outbound (sing-box). The web UI is a single-file React app
embedded in the binary; see "Web UI" below.

Module layout (Go, after the migration from muse-cli): `internal/source/muse`,
`internal/publish/<platform>`, `internal/profile`, `internal/outbound`,
`internal/webui`. Binary: `castctl`. Env vars: `CASTCTL_CONFIG`,
`CASTCTL_PROFILE`, `CASTCTL_WEBUI_KEY`.

## Platforms

castctl is a general tool, not VM-only. Supported run targets: Linux only — linux/amd64 and linux/arm64 (Debian/server Linux host). No VM assumptions: no hard-coded paths,
no launcher, no agent-browser, no sandbox.

Config location: `--config`, then `CASTCTL_CONFIG`, then `XDG_CONFIG_HOME`, via `os.UserConfigDir` semantics.

Screencast login: the browser dependency is optional and detected at
runtime (system Chromium or a configured path); with no browser, fall back
to `auth import` with a clear message. Plan for logging in from another device's web UI (e.g. a phone browser) against castctl's `--listen` server.

The web UI must work from a phone browser against castctl on another host
(`--listen` + token + HTTPS/tunnel guidance, see docs/security.md). Tests
must not depend on the developer VM's environment (hermetic: temp dirs,
fakes, no live hosts).

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
