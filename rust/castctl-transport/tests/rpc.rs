// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Integration tests for `RpcClient` against a fake HTTP server
//! (tokio, ephemeral loopback port): 200 / 4xx / 5xx, network
//! error retry, redirect refusal, token non-leakage, and the
//! GET-body-to-query + path-param behaviour of `call_json`.
//!
//! The env-proxy invariant has its own test binary
//! (`tests/env_proxy.rs`) because setting process env vars is
//! process-global: it must not share a process with tests that
//! could race it.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use castctl_transport::dialer::{DialTarget, Dialer, DirectDialer};
use castctl_transport::error::TransportError;
use castctl_transport::retry::RetryPolicy;
use castctl_transport::rpc::RpcClient;
use common::{FakeServer, Responder};

fn client_for(port: u16) -> RpcClient {
    RpcClient::new(
        Arc::new(DirectDialer::new()),
        DialTarget::new("127.0.0.1", port),
        common::test_routes(),
    )
    .with_timeout(Duration::from_secs(5))
    .with_retry_policy(RetryPolicy {
        budget: Duration::from_secs(5),
        pause_initial: Duration::from_millis(5),
        pause_max: Duration::from_millis(5),
    })
}

fn json_responder(status: u16, body: &'static str) -> Responder {
    let body = body.to_string();
    Arc::new(move |_| {
        (
            status,
            vec![("content-type".to_string(), "application/json".to_string())],
            body.clone().into_bytes(),
        )
    })
}

#[tokio::test]
async fn ok_true_returns_result_and_empty_body_returns_empty_map() {
    let server = FakeServer::start(json_responder(200, r#"{"ok":true,"result":{"a":1}}"#)).await;
    let value = client_for(server.port)
        .call_json("fs.read", Some(serde_json::json!({"path": "/x"})), &[])
        .await
        .expect("200 ok:true must succeed");
    assert_eq!(value, serde_json::json!({"a": 1}));
    assert_eq!(server.requests(), 1);

    let empty = FakeServer::start(json_responder(200, "")).await;
    let value = client_for(empty.port)
        .call_json("fs.read", Some(serde_json::json!({"path": "/x"})), &[])
        .await
        .expect("empty body must decode to {}");
    assert_eq!(value, serde_json::json!({}));
}

#[tokio::test]
async fn ok_false_and_non_json_are_gateway_errors_without_body_bytes() {
    let server =
        FakeServer::start(json_responder(200, r#"{"ok":false,"error":"bad_request"}"#)).await;
    let err = client_for(server.port)
        .call_json("fs.read", None, &[])
        .await
        .expect_err("ok:false must fail");
    assert!(matches!(err, TransportError::Gateway(_)));
    assert_eq!(err.exit_code(), 3);
    assert_eq!(server.requests(), 1, "gateway errors are never retried");

    let marker = "MARKER-NON-JSON-BODY-12345";
    let body = marker.to_string();
    let server2 = FakeServer::start(Arc::new(move |_| {
        (
            200,
            vec![("content-type".to_string(), "text/plain".to_string())],
            body.clone().into_bytes(),
        )
    }))
    .await;
    let err = client_for(server2.port)
        .call_json("fs.read", None, &[])
        .await
        .expect_err("non-JSON must fail");
    assert!(matches!(err, TransportError::Gateway(_)));
    assert!(!format!("{err}").contains(marker));
    assert!(!format!("{err:?}").contains(marker));
}

#[tokio::test]
async fn status_errors_map_to_gateway_exit_3_and_are_not_retried() {
    for status in [400u16, 401, 403, 404, 500, 502, 503] {
        let server = FakeServer::start(json_responder(
            status,
            r#"{"error":"some_server_error","detail":"should-not-leak"}"#,
        ))
        .await;
        let err = client_for(server.port)
            .call_json("fs.read", None, &[])
            .await
            .expect_err("non-2xx must fail");
        assert!(matches!(err, TransportError::Gateway(_)), "status {status}");
        assert_eq!(err.exit_code(), 3, "status {status}");
        assert_eq!(server.requests(), 1, "status {status} must not retry");
        assert!(!format!("{err}").contains("should-not-leak"));
    }
}

#[tokio::test]
async fn redirect_is_refused_and_second_server_gets_nothing() {
    let second = FakeServer::start(json_responder(200, r#"{"ok":true}"#)).await;
    let location = format!("http://127.0.0.1:{}/target", second.port);
    let first = FakeServer::start(Arc::new(move |_| {
        (
            302,
            vec![("location".to_string(), location.clone())],
            Vec::new(),
        )
    }))
    .await;
    let err = client_for(first.port)
        .call_json("fs.read", None, &[])
        .await
        .expect_err("redirect must be refused");
    assert!(matches!(err, TransportError::RedirectRefused { .. }));
    assert_eq!(first.requests(), 1);
    // No second request was ever issued, even though the client
    // knew the Location (Go noFollowRedirect invariant).
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(second.requests(), 0);
}

#[tokio::test]
async fn network_error_surfaces_connection_down() {
    // A refused connection surfaces as ConnectionDown (nothing
    // sent, retryable kind). The repeat-within-budget behaviour
    // itself is covered by `retry::run_with_retry` unit tests
    // with a counting closure; here the RPC layer only needs to
    // prove the error kind it produces from a real dial failure.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("INVARIANT: closed-port probe binds");
    let port = listener.local_addr().expect("INVARIANT: addr").port();
    drop(listener); // now refused
    let client = RpcClient::new(
        Arc::new(DirectDialer::new()),
        DialTarget::new("127.0.0.1", port),
        common::test_routes(),
    )
    .with_timeout(Duration::from_secs(2))
    .with_retry_policy(RetryPolicy {
        budget: Duration::from_millis(120),
        pause_initial: Duration::from_millis(10),
        pause_max: Duration::from_millis(10),
    });
    let err = client
        .call_json("fs.read", None, &[])
        .await
        .expect_err("refused connection must fail");
    assert!(matches!(err, TransportError::ConnectionDown { .. }));
    assert!(err.is_retryable_kind());
}

#[tokio::test]
async fn rpc_repeats_dial_failures_within_budget() {
    // Counting wrapper around the real DirectDialer, dialing a
    // closed port: the RPC layer must dial more than once for a
    // ConnectionDown (nothing sent) before the budget runs out,
    // for a safe method AND for an unsafe method (decide is a
    // POST write — ConnectionDown still repeats, because nothing
    // was sent; only ConnectionError is gated by safe).
    use honk_outbound::AsyncReadWrite;
    struct CountingDialer {
        inner: DirectDialer,
        count: Arc<AtomicUsize>,
    }
    impl Dialer for CountingDialer {
        fn dial(
            &self,
            target: &DialTarget,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Box<dyn AsyncReadWrite>, TransportError>>
                    + Send
                    + '_,
            >,
        > {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.inner.dial(target)
        }
    }
    for method in ["fs.read", "egress.approval.decide"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("INVARIANT: closed-port probe binds");
        let port = listener.local_addr().expect("INVARIANT: addr").port();
        drop(listener);
        let count = Arc::new(AtomicUsize::new(0));
        let client = RpcClient::new(
            Arc::new(CountingDialer {
                inner: DirectDialer::new(),
                count: Arc::clone(&count),
            }),
            DialTarget::new("127.0.0.1", port),
            common::test_routes(),
        )
        .with_timeout(Duration::from_secs(2))
        .with_retry_policy(RetryPolicy {
            budget: Duration::from_millis(150),
            pause_initial: Duration::from_millis(10),
            pause_max: Duration::from_millis(10),
        });
        let err = client
            .call_json(method, None, &[])
            .await
            .expect_err("refused connection must fail");
        assert!(
            matches!(err, TransportError::ConnectionDown { .. }),
            "{method}"
        );
        assert!(
            count.load(Ordering::SeqCst) >= 2,
            "{method}: dials = {} (must repeat ConnectionDown)",
            count.load(Ordering::SeqCst)
        );
    }
}

#[tokio::test]
async fn get_body_becomes_query_and_path_params_are_escaped() {
    let server = FakeServer::start(json_responder(200, r#"{"ok":true,"result":{}}"#)).await;
    let client = client_for(server.port);
    client
        .call_json(
            "chat.history",
            Some(serde_json::json!({"limit": 10, "flag": true})),
            &[],
        )
        .await
        .expect("GET call must succeed");
    let records = server.records.lock().expect("records lock");
    let record = records.last().expect("one request recorded");
    assert_eq!(record.method, "GET");
    assert!(
        record.path.starts_with("/chat/history?"),
        "path: {}",
        record.path
    );
    assert!(record.path.contains("limit=10"), "path: {}", record.path);
    assert!(record.path.contains("flag=True"), "path: {}", record.path);
    drop(records);

    let server2 = FakeServer::start(json_responder(200, r#"{"ok":true}"#)).await;
    let client2 = client_for(server2.port);
    client2
        .call_json(
            "chat.mark_seen",
            None,
            &[("thread_id".to_string(), "t/1".to_string())],
        )
        .await
        .expect("POST with path param must succeed");
    let records = server2.records.lock().expect("records lock");
    assert_eq!(records.last().expect("record").path, "/api/chat/t%2F1/seen");
}

#[tokio::test]
async fn token_in_request_body_never_appears_in_errors() {
    // Fake token shape only (never a real token): it travels in
    // the request body, and the server answers 500 with a body
    // that does NOT contain it. The error must not contain it
    // either — errors carry summaries, never body bytes.
    let fake_token = "FAKE-TOKEN-TEST-ONLY-1234567890abcdef";
    let server = FakeServer::start(json_responder(500, r#"{"error":"internal"}"#)).await;
    let err = client_for(server.port)
        .call_json(
            "fs.read",
            Some(serde_json::json!({"token": fake_token})),
            &[],
        )
        .await
        .expect_err("500 must fail");
    assert!(!format!("{err}").contains(fake_token));
    assert!(!format!("{err:?}").contains(fake_token));
    assert!(!err.log_summary().contains(fake_token));
    // The server DID receive the token in the body (the test
    // proves the token was actually in play, not absent).
    let records = server.records.lock().expect("records lock");
    let body = String::from_utf8_lossy(&records.last().expect("record").body);
    assert!(body.contains(fake_token));
}
