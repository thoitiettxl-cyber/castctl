// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Shared fake servers for gateway integration tests.
//! Split so each test target includes only what it uses
//! (a target that pulls in an unused server trips
//! `dead_code` under `-D warnings`):
//! - `fake_server`: the canned-JSON gateway (real WS +
//!   real Noise + real protobuf).
//! - `bad_servers`: the garbage-handshake and blackhole
//!   servers (M4a negative tests).
//! - `raw_upgrade`: the raw 101 server (M4b literal-token
//!   tests — records the upgrade bytes verbatim, no URI
//!   parsing).

pub mod bad_servers;
pub mod fake_server;
pub mod raw_upgrade;

pub use bad_servers::{BadMsg2Server, BlackholeServer};
pub use fake_server::{FakeServer, Reply, canned_json};
pub use raw_upgrade::RawUpgradeServer;
