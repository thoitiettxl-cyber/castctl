// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Command table, flag parsing, help/usage rendering, and exit
//! mapping ported from castctl's Go `internal/commands` (M2).
//!
//! Scope: the offline CLI surface (M2: global scan, per-command
//! parsing, dispatcher help/usage errors, config-location
//! resolution, and the `not ported yet` stub) plus the M4b
//! network path: the 13 read-only commands (`status`, `usage`,
//! `threads`, `history`, `files`, `feed`, `feed-status`,
//! `feed-prompt`, `goals`, `goal`, `ideas`, `idea`, `unread`)
//! through the gateway (`network`) over the per-profile runtime
//! (`runtime`), plus the M7a `wait` command (`wait`): the
//! subscribe-driven wait over the same runtime. M7b wires the
//! Phase A commands on top of the same path: session-*, stop,
//! seen, feed-react, idea-exec, approvals/approve/deny, invite,
//! redeem, wake, download, raw, plus `auto-approve` (config only,
//! no network). PR-2 wired `chat`, `send`, and `watch` (plus
//! `fs`). PR-3 wires `update` (`update`), `auth list` / `auth
//! status` / `auth import` (`auth`), and `history --download`
//! (`network::cmd_history`); `auth observe-login` stays the
//! fixed tag-off error (see PORTING.md §M7b.13).
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input. Every
//! public item cites its Go source at base `dev-rust` `85a8d5e`.

pub mod approvals;
pub mod auth;
pub mod autoapprove;
pub mod chat;
pub mod chat_texts;
pub mod fs;
pub mod help_texts;
pub mod network;
pub mod parser;
pub mod run;
pub mod runtime;
pub mod send;
pub mod table;
pub mod update;
pub mod wait;
pub mod watch;

pub use run::{Outcome, VERSION, run};
