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
//! (`runtime`). No network, gateway, browser, or migrate
//! execution is wired for any other command.
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input. Every
//! public item cites its Go source at base `dev-rust` `85a8d5e`.

pub mod help_texts;
pub mod network;
pub mod parser;
pub mod run;
pub mod runtime;
pub mod table;

pub use run::{Outcome, VERSION, run};
