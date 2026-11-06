// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `castctl-gateway` (M4a): WebSocket + Noise + protobuf gateway
//! client, ported from `internal/gateway` and `internal/conn`.
//!
//! Crate map (Go sources in each module's docs):
//!
//! | Module | Contents |
//! | `proto` | prost-generated types from `desc0.bin`/`desc1.bin` |
//! | `noise` | Noise XX handshake + transport via the `snow` crate |
//! | `framing` | `NoiseTransportFrame` chunking/reassembly (60000-byte pieces) |
//! | `gateway` | `Gateway`: WS reader loop, stream demux, `Request`/`CallJSON`/`Ping` |
//! | `shared` | `SharedConn`: retry-across-reconnect, heartbeat, stale probe, down notice |
//! | `dial` | WS dial + Noise handshake (`dial_gateway`, gateway-dial TLS rule at the call site) |
//!
//! Invariants (each has a test; see PORTING.md §M4a):
//! - No `unsafe` in this crate's code; no `unwrap()`/`expect()` on
//!   external input in runtime code (`build.rs` unwraps only the
//!   committed descriptor files `desc0.bin`/`desc1.bin` — a bad
//!   file fails the build, it never reaches runtime).
//! - Errors are `castctl_transport::TransportError` (same taxonomy
//!   and exit codes as Go `classifyError`); a gateway 3xx is
//!   `Gateway(status)` → exit 3, never `RedirectRefused`.
//! - No token, cookie or key is ever stored in an error, a log
//!   line, or a `Debug` rendering. `Debug` is hand-written wherever
//!   a struct could hold sensitive material.
//! - One Noise ciphertext = one WS binary message; plaintext is a
//!   `NoiseTransportFrame` chunked at 60000 bytes.

pub mod auth;
pub mod connector;
pub mod cookies;
pub mod dial;
pub mod framing;
pub mod gateway;
pub mod noise;
pub mod proto;
pub mod shared;
pub mod subscribe;
pub mod subscription;
pub mod summary;

pub use auth::{SessionInfo, fetch_access_token, fetch_hatch_token, fetch_session_info};
pub use connector::GatewayConnector;
pub use cookies::{CookieLoadError, load_cookies, parse_cookies};
pub use dial::dial_gateway_over_stream;
pub use dial::{GATEWAY_HOST, GATEWAY_ORIGIN, GATEWAY_USER_AGENT, default_ws_url, dial_gateway};
pub use framing::{
    MAX_PIECES_PER_GROUP, MAX_REASSEMBLED_SIZE, MAX_UNFINISHED_GROUPS, Reassembler,
    ReassemblyError, SEND_PIECE, marshal_transport_frame, new_chunk_id, split_pieces,
};
pub use gateway::{
    Body, DEFAULT_DOWNLOAD_TIMEOUT, DEFAULT_PING_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, Gateway,
    RequestOptions, WRITE_DEADLINE, uuid_v4,
};
pub use noise::{
    HANDSHAKE_TIMEOUT, InitiatorHandshake, MAX_NOISE_MESSAGE, NOISE_PARAMS, NoiseTransport,
    ResponderHandshake,
};
pub use shared::{
    CONNECT_TIMEOUT, Connector, DOWN_FAILS, DOWN_NOTICE, DownDecision, DownTracker, FAIL_SPACING,
    HEARTBEAT, HEARTBEAT_PING_TIMEOUT, HEARTBEAT_STOP_TIMEOUT, MAX_SUBSCRIBE_ATTEMPTS, RETRY_FOR,
    RETRY_PAUSE_INITIAL, RETRY_PAUSE_MAX, STALE_PING_TIMEOUT, SUBSCRIBE_RETRY_PAUSE, SharedConn,
    heartbeat_tick,
};
pub use subscribe::{
    CollectHandler, DEFAULT_SUBSCRIBE_IDLE_TIMEOUT, DEFAULT_SUBSCRIBE_MAX_RECORDS,
    DEFAULT_SUBSCRIBE_OVERALL_TIMEOUT, SUBSCRIBE_POLL_INTERVAL, SubscribeHandler, SubscribeOptions,
};
pub use subscription::{
    ActionIDStore, DEFAULT_SUBSCRIPTION_ACTION_ID, SUBSCRIPTION_ACTION_NAME, SUBSCRIPTION_PAGE,
    SubscriptionOptions, fetch_subscription, find_action_id, parse_rsc_result,
};
pub use summary::{Summary, summarize_body, summarize_parsed_body};
