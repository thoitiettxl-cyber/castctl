// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Retention roots: keep the transport+gateway closure linked into the
//! `castctl-full` binary under release+LTO.
//!
//! Why this file exists: a `main` that only calls `castctl_cli::run()`
//! never references any symbol from `castctl-transport` /
//! `castctl-gateway`, so dead-code elimination drops their code and the
//! binary would measure a shell-sized binary, not a full one. Each root
//! below is a REAL call to a minimal public constructor (no I/O), its
//! result passed through `std::hint::black_box` and dropped.
//!
//! The whole function runs ONLY behind the `PERF_KEEP_LINKED` env guard
//! in `main.rs` (never on the measured `--version` path): the roots
//! construct registries, a keypair, a runtime and a route table, which
//! would otherwise add artificial work (~0.1–1 ms) to startup. Go's
//! `--version` likewise links sing-box but constructs no outbound.
//! The guard itself is one env read (~µs); the branch cannot be proven
//! dead at compile time (`std::env::var` is runtime input), so LTO
//! must keep `keep_linked()` and its transitive callees in the binary
//! — verified by the size A/B + `nm` checks in README §1, not assumed.
//!
//! Dummy inputs (documented as dummy, never real credentials, never
//! dialled): the SOCKS JSON is copied from the transport crate's own
//! test (`rust/castctl-transport/src/config.rs`, test
//! `socks_maps_to_socks5_and_direct_block_wireguard`); the WireGuard
//! keys are deterministic dummy bytes (1..32 / 7×32, base64) — they
//! must be NON-zero because `WireGuardDialer::new` rejects an all-zero
//! key as "missing" (`wireguard.rs`, `new`). No root dials, binds,
//! resolves DNS, or reads a file at runtime (`RouteTable` parses
//! `include_str!`-embedded JSON, no runtime file read).

use std::hint::black_box;
use std::sync::Arc;

pub fn keep_linked() {
    // T1: honk-outbound core + 11-protocol registry. dispatch_outbound
    // builds a honk Node from JSON (pure); HonkDialer::new builds the
    // ProxyRegistry (pure; dial happens only on Dialer::dial, never here).
    let socks = serde_json::json!({
        "type": "socks",
        "server": "127.0.0.1",
        "server_port": 1080,
        "username": "u",
        "password": "p",
    });
    if let Ok(castctl_transport::Dispatch::Honk(node)) =
        castctl_transport::dispatch_outbound(&socks, None)
    {
        let _ = black_box(castctl_transport::HonkDialer::new(*node));
    }
    // T2: WireGuard config/validation + key parse. dispatch_endpoint
    // parses the endpoint JSON (strict base64 key decode) and builds a
    // WireGuardDialer; new() only validates + stores config (no UDP
    // bind, no spawn, no handshake — the tunnel lives in ensure_tunnel,
    // reachable only from Dialer::dial; see the nm table in README §1
    // for what this root does and does not retain).
    let wg = serde_json::json!({
        "type": "wireguard",
        "tag": "perf-keep",
        "address": ["10.2.0.2/32"],
        "private_key": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
        "peers": [{
            "address": "127.0.0.1",
            "port": 51820,
            "public_key": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
            "allowed_ips": ["0.0.0.0/0"],
        }],
    });
    let _ = black_box(castctl_transport::dispatch_endpoint(&wg, &[]));
    // T3: HTTP/RPC structs. DirectDialer is a unit struct (no-op);
    // HttpClient/RpcClient only wrap it; RouteTable parses embedded JSON.
    let dialer: Arc<dyn castctl_transport::Dialer> =
        Arc::new(castctl_transport::DirectDialer::new());
    let _ = black_box(castctl_transport::HttpClient::new(Arc::clone(&dialer)));
    if let Ok(routes) = castctl_transport::RouteTable::default_routes() {
        let _ = black_box(castctl_transport::RpcClient::new(
            Arc::clone(&dialer),
            castctl_transport::DialTarget::new("127.0.0.1", 1),
            routes,
        ));
    }
    // T4: gateway noise/framing/prost. InitiatorHandshake::new builds a
    // fresh snow keypair (pure CPU); msg1 writes the first Noise
    // message; Reassembler/split_pieces/marshal_transport_frame build
    // prost NoiseTransportFrame values (keeps prost + generated types);
    // decode_call_json decodes JSON; DownTracker is a plain struct;
    // default_ws_url/uuid_v4 are string builders.
    if let Ok(mut hs) = castctl_gateway::InitiatorHandshake::new() {
        let _ = black_box(hs.msg1());
    }
    let _ = black_box(castctl_gateway::Reassembler::new());
    let _ = black_box(castctl_gateway::split_pieces(b""));
    let _ = black_box(castctl_gateway::marshal_transport_frame(0, 0, 1, b""));
    let _ = black_box(castctl_gateway::Gateway::decode_call_json(b"{}"));
    let _ = black_box(castctl_gateway::DownTracker::new());
    let _ = black_box(castctl_gateway::default_ws_url(
        true,
        castctl_gateway::GATEWAY_HOST,
        "perf",
        "",
    ));
    let _ = black_box(castctl_gateway::uuid_v4());
    // T5: tokio runtime. Transport/gateway are async; without a runtime
    // root the runtime could be eliminated and rust-full would measure
    // short of M7 (the Go binary carries its scheduler). Build + drop:
    // the runtime is never run (no block_on, no spawn) and this whole
    // function only runs behind the env guard.
    let _ = black_box(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build(),
    );
    keep_linked_tier2();
}

/// Tier 2 — address roots, added ONLY because `nm` on the Tier-1-only
/// binary proved three subgraphs missing (see README §1): boringtun
/// (0 symbols), smoltcp (0 real code — the 2 hits were drop-glue type
/// names), hyper (0 symbols). Each root only takes the ADDRESS of a
/// public function; nothing is called, so no I/O can happen even with
/// the guard on. Taking the address forces the function to be emitted,
/// and its body pulls in the subgraph (WireGuardDialer::dial →
/// ensure_tunnel → boringtun Tunn::new + smoltcp Interface;
/// HttpClient::request → hyper client machinery).
///
/// Mechanism history (probe, 2026-11-05): plain address-taking +
/// `black_box` was PROVEN to be eliminated — a build with only that
/// produced a byte-identical size (16,272,088 B) and identical `nm`
/// counts (boringtun 0, hyper 0). So the addresses are kept in a
/// `#[used]` static instead: the static is retained by the linker and
/// its entries reference the functions, which pulls their object files
/// (and the subgraphs) into the binary. Measured outcome: the
/// WireGuardDialer::dial entry works (boringtun 0→98, smoltcp 2→185,
/// `ensure_tunnel` present in `nm`, +543,384 B unstripped). The
/// HttpClient::request entry does NOT retain hyper machinery (still 0
/// symbols): an async fn's address keeps only its constructor, not the
/// polled future that drives hyper — and polling it would require real
/// I/O, which no root may do. Hyper client machinery is therefore a
/// DISCLOSED gap (see README §1), not a retained subgraph.
/// Function addresses kept live so the linker retains the subgraphs
/// they point into. Raw pointers are not `Sync`, so they ride in a
/// wrapper whose `Sync` impl is sound: the entries are addresses of
/// immutable code, never mutated after initialisation.
struct KeepAddrs([*const (); 2]);
// SAFETY: entries are function addresses (immutable code); sharing
// references across threads is safe.
unsafe impl Sync for KeepAddrs {}

#[used]
static KEEP_TIER2: KeepAddrs = KeepAddrs([
    <castctl_transport::WireGuardDialer as castctl_transport::Dialer>::dial as *const (),
    castctl_transport::HttpClient::request as *const (),
]);

fn keep_linked_tier2() {
    // Read the field (not just the struct address): black_box the
    // address array itself, so the field counts as used and the
    // entries stay live. No call, no I/O.
    let _ = black_box(KEEP_TIER2.0);
}
