// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Shared fake HTTP server for `castctl-transport` integration
//! tests (see `fake_server.rs`), plus the small route table
//! the RPC / env-proxy tests need (`routes.rs`).
//!
//! Split (M4b): the TLS test target includes only
//! `fake_server` (via `#[path]`), so `test_routes` —
//! unused there — does not trip `dead_code` under
//! `clippy -D warnings` in that target.

pub mod fake_server;
pub mod routes;

// Only `test_routes` is re-exported here: `FakeServer` /
// `Responder` / `RequestRecord` are imported through
// `common::fake_server` by each test target, because a
// re-export unused in one target trips `dead_code` under
// `clippy -D warnings` in that target (the TLS target
// does not include this module at all).
pub use routes::test_routes;
