// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Env-proxy invariant test, in its OWN test binary.
//!
//! Why separate: setting process environment variables is
//! process-global, and Rust runs tests in one binary in parallel.
//! This file contains exactly ONE test, and no other test in
//! this binary touches the environment, so there is no race.
//! (Other test binaries are separate processes and cannot see
//! this process's env.)
//!
//! What it proves: with `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`
//! (upper- and lowercase) all pointing at a logging proxy
//! listener, an `RpcClient` over `DirectDialer` still reaches the
//! fake gateway server directly — the proxy listener receives
//! zero connections. The client has no proxy concept at all
//! (see `http.rs`); this test proves the negative at runtime,
//! complementing the grep check that `src/` never reads those
//! variables.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use castctl_transport::dialer::{DialTarget, DirectDialer};
use castctl_transport::rpc::RpcClient;
use common::{FakeServer, RequestRecord, Responder};

#[tokio::test]
async fn env_proxy_is_ignored() {
    let gateway = FakeServer::start(Arc::new(|_: &RequestRecord| {
        (
            200u16,
            vec![("content-type".to_string(), "application/json".to_string())],
            br#"{"ok":true,"result":{}}"#.to_vec(),
        )
    }) as Responder)
    .await;
    // Logging proxy listener: accepts and counts, then closes
    // without answering. If the client ever used the proxy env,
    // its request would land here and fail — the test would fail
    // twice over (gateway unreachable + proxy count > 0).
    let proxy_count = Arc::new(AtomicUsize::new(0));
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("INVARIANT: proxy listener binds");
    let proxy_port = proxy_listener
        .local_addr()
        .expect("INVARIANT: proxy addr")
        .port();
    let proxy_count_clone = Arc::clone(&proxy_count);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = proxy_listener.accept().await else {
                break;
            };
            proxy_count_clone.fetch_add(1, Ordering::SeqCst);
            drop(socket);
        }
    });
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");
    // SAFETY (edition 2024: set_var/remove_var are unsafe because
    // env mutation is process-global): this binary runs exactly
    // this one test, and nothing else in this process reads or
    // writes these variables concurrently. Values are restored
    // (removed) before the test returns.
    unsafe {
        std::env::set_var("HTTP_PROXY", &proxy_url);
        std::env::set_var("HTTPS_PROXY", &proxy_url);
        std::env::set_var("ALL_PROXY", &proxy_url);
        std::env::set_var("http_proxy", &proxy_url);
        std::env::set_var("https_proxy", &proxy_url);
        std::env::set_var("all_proxy", &proxy_url);
    }
    let result = RpcClient::new(
        Arc::new(DirectDialer::new()),
        DialTarget::new("127.0.0.1", gateway.port),
        common::test_routes(),
    )
    .with_timeout(Duration::from_secs(5))
    .call_json("fs.read", None, &[])
    .await;
    unsafe {
        std::env::remove_var("HTTP_PROXY");
        std::env::remove_var("HTTPS_PROXY");
        std::env::remove_var("ALL_PROXY");
        std::env::remove_var("http_proxy");
        std::env::remove_var("https_proxy");
        std::env::remove_var("all_proxy");
    }
    result.expect("request must succeed despite proxy env pointing at a dead proxy");
    assert_eq!(gateway.requests(), 1);
    // The recorded request proves the gateway — not the proxy —
    // served the exact request the client sent. (`fs.read` was
    // called with no params, so the body is empty.) This read
    // also keeps `RequestRecord`'s fields and `FakeServer`'s
    // `records` live in this test binary: nothing else here
    // reads them, and dead fields are a clippy error under
    // `-D warnings` with `--all-targets`.
    let record = gateway
        .records
        .lock()
        .expect("records lock")
        .last()
        .expect("one request recorded")
        .clone();
    assert_eq!(record.method, "POST");
    assert_eq!(record.path, "/fs/read");
    assert!(record.body.is_empty());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        proxy_count.load(Ordering::SeqCst),
        0,
        "proxy listener must receive zero connections"
    );
}
