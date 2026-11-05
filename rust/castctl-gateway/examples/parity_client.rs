// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Rust parity client for the M4a cross-language gate: dial
//! one gateway server (the Go `gateway_server serve` mode),
//! call the methods given on the command line, print one line
//! per method: "<method>\t<compact JSON result>" — the same
//! format as the Go client's output, so the gate diffs them
//! byte-for-byte.
//!
//! Usage:
//!   cargo run -p castctl-gateway --example parity_client -- \
//!     "ws://127.0.0.1:PORT/v1/noise?vm_id=vm-test&auth_token=HT-FAKE" \
//!     connection.ping sessions.list chat.history feed.list goals.list
//!
//! The URL carries the literal `auth_token=<redacted>`
//! (mirroring Go `defaultWSURL`); no real token is ever in
//! it. `dial_gateway` percent-encodes the `<`/`>` for the
//! HTTP stack before dialing — the server decodes them back
//! to `<redacted>` — and the URL is never stored or logged.

use castctl_gateway::dial::dial_gateway;
use castctl_gateway::gateway::RequestOptions;
use castctl_transport::routes::RouteTable;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: parity_client <ws-url> <method> [method ...]");
        std::process::exit(2);
    }
    let url = &args[1];
    let methods = &args[2..];
    let routes = match RouteTable::default_routes() {
        Ok(r) => std::sync::Arc::new(r),
        Err(e) => {
            eprintln!("rust routes: {e}");
            std::process::exit(1);
        }
    };
    let gw = match dial_gateway(url, routes).await {
        Ok(gw) => gw,
        Err(e) => {
            eprintln!("rust dial: {e}");
            std::process::exit(1);
        }
    };
    for method in methods {
        match gw.call_json(method, RequestOptions::default()).await {
            Ok(out) => {
                let raw = serde_json::to_string(&out).unwrap_or_else(|_| "null".to_string());
                println!("{method}\t{raw}");
            }
            Err(e) => {
                eprintln!("rust call_json {method}: {e}");
                std::process::exit(1);
            }
        }
    }
}
