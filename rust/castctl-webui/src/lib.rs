// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Web UI HTTP server for the castctl Rust port (M6b):
//! loopback-only, bcrypt Bearer auth, the `/api/v1`
//! management API and the embedded frontend shell.
//!
//! Ported from Go `internal/webui` and
//! `internal/commands/webui.go` (head `c7b1d34`).
//! The module layout mirrors the Go files one-to-one:
//!
//! | Rust module | Go source |
//! |---|---|
//! | `server` | `server.go` (routes, middleware, auth) |
//! | `handlers` | `handlers.go` (status/profiles/outbounds/…) |
//! | `keeper_status` | `internal/keeper` (`ReadStatus`/`LoadState`) |
//! | `sections` | `sections.go` (keeper/webui settings) |
//! | `chats` | `chats.go` (ChatDeps seam + job store) |
//! | `logs` | `logs.go` (log gate + parseLogLine) |
//! | `plugins` | `plugins.go` |
//! | `endpoints` | `endpoints.go` (WireGuard conf import) |
//! | `screencast` | `screencast.go` (registry + WS; starter seam only) |
//! | `uidir` | `uidir.go` (custom UI directory) |
//! | `static_shell` | `server.go` serveShell + `webui/embed.go` |
//! | `store` | `store.go` (guarded save funnel) |
//! | `guarded` | `internal/profile/guard.go` (flock + atomic save) |
//! | `merge` | `merge.go` (sentinel merge R1–R9) |
//! | `ordered` | `ordered.go` (marshalOrdered) |
//! | `contain` | `contain.go` (path containment) |
//! | `ratelimit` | `ratelimit.go` |
//! | `origin` | `origin.go` + screencast CheckOrigin |
//! | `auth` | `internal/profile/webui_secret.go` + server auth |
//! | `config` | `internal/profile/webui.go` (typed block) |
//! | `contain` | `contain.go` (path containment) |
//! | `cookies` | `internal/gateway/cookies.go` (`ParseCookies`) |
//! | `validate` | `ParseSingleConfig` tail (keeper/tags/refs) |
//! | `redact` | `internal/redact/value.go` `Value` |
//! | `duration` | Go `time.ParseDuration` / `Duration.String` |
//! | `go_json` | Go `encoding/json` response rendering |
//! | `go_decode` | `decodeGeneric`/`decodeBody` trailing-data rules |
//! | `error` | API error vocabulary |
//!
//! Invariants (from `internal/webui/server.go`'s package
//! doc): loopback only; every `/api/v1` route + screencast
//! needs Bearer except `GET /api/v1/screencast/ws`
//! (single-use `?session=` token); the static shell is
//! unauthenticated; no cookies, no CORS headers, stateless
//! Bearer; the session idle timeout is FRONTEND-enforced
//! (the server only reports the effective value); the
//! middleware order is rate-limit → auth → Origin → timeout
//! (30s, WS excluded); the server never logs.

pub mod auth;
pub mod chats;
pub mod config;
pub mod contain;
pub mod cookies;
pub mod duration;
pub mod endpoints;
pub mod error;
pub mod go_decode;
pub mod go_json;
pub mod guarded;
pub mod handlers;
pub mod keeper_status;
pub mod logs;
pub mod merge;
pub mod ordered;
pub mod origin;
pub mod plugins;
pub mod ratelimit;
pub mod redact;
pub mod screencast;
pub mod sections;
pub mod server;
pub mod static_shell;
pub mod store;
pub mod uidir;
pub mod validate;

pub use server::{Deps, Server};
