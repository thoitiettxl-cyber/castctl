// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `castctl-transport` (M3): transport glue for the castctl Rust
//! port. Protocols are NOT reimplemented here — `honk-outbound`
//! (GPL-3.0-only, pinned git rev in the workspace root) is the
//! engine, called as a dependency; this crate only maps castctl
//! config onto honk nodes, dials through them, and speaks
//! HTTP/JSON RPC over the resulting stream.
//!
//! Crate map (Go sources in each module's docs):
//!
//! | Module | Contents |
//! | `error` | Error taxonomy + allowlist summaries + exit codes |
//! | `routes` | Route table from `internal/proto/routes.json` |
//! | `config` | Sing-box outbound JSON → honk `Node` dispatch + TLS/REALITY |
//! | `dialer` | `Dialer` trait (the M3d seam), direct + honk dialers |
//! | `wireguard` | Userspace WireGuard dialer (M3d): boringtun + smoltcp tunnel |
//! | `http` | HTTP/1.1 client over a dialer (no proxy env, no redirects) |
//! | `retry` | Retry budget/ladder + safe-to-repeat (from `internal/conn`) |
//! | `rpc` | `call_json` HTTP-over-outbound RPC client |
//!
//! Invariants (each has a test; see PORTING.md §M3):
//! - No proxy environment variables are ever read in `src/`
//!   (grep check; the only proxy-env reader in Go is the
//!   explicit `internal/profile/envproxy.go` builder, which is a
//!   different path and is not ported here).
//! - Redirects are never followed.
//! - Retry follows the Go budget/ladder and safe set exactly.
//! - Errors carry allowlist summaries only — never body bytes,
//!   tokens, cookies or keys.
//! - No `unsafe` in this crate's code. The dependency tree
//!   (honk/boring/quinn) DOES contain `unsafe` and C code; see
//!   PORTING.md §M3 — the "no unsafe" rule covers castctl glue
//!   code only (plan decision D-M3-7), never the binary as a
//!   whole.
//! - No `unwrap()`/`expect()` on external input in non-test
//!   code (verified by grep: every hit is inside a `#[cfg(test)]`
//!   module, on a static fixture). The only `unsafe` blocks in
//!   the crate are the two env-mutation blocks in
//!   `tests/env_proxy.rs`, required because `set_var` /
//!   `remove_var` are `unsafe` in edition 2024, each with a
//!   `SAFETY` comment; there is no `unsafe` block in `src/`.

pub mod config;
pub mod dialer;
pub mod error;
pub mod http;
pub mod retry;
pub mod routes;
pub mod rpc;
pub mod tls;
pub mod wireguard;

pub use config::{Dispatch, TlsMode, dispatch_endpoint, dispatch_outbound};
pub use dialer::{BlockDialer, DIAL_TIMEOUT, DialTarget, Dialer, DirectDialer, HonkDialer};
pub use error::{BodySummary, TransportError};
pub use http::{HttpClient, HttpResponse, MAX_RESPONSE_BODY};
pub use retry::{RETRY_FOR, RETRY_PAUSE_INITIAL, RETRY_PAUSE_MAX, RetryPolicy};
pub use routes::{Route, RouteTable, Service};
pub use rpc::{DEFAULT_REQUEST_TIMEOUT, RpcClient};
pub use tls::{TLS_ALPN_HTTP1, tls_client_config};
pub use wireguard::{
    Prefix, WIREGUARD_DATA_OVERHEAD, WIREGUARD_DEFAULT_MTU, WIREGUARD_MIN_DATAGRAM,
    WireGuardConfig, WireGuardDialer, WireGuardPeerConfig, parse_wireguard_endpoint,
};
