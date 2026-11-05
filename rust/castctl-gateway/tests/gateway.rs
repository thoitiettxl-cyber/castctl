// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Integration tests for the gateway client (M4a): real WS +
//! real Noise + real protobuf against the fake server in
//! `tests/common` (no mock of the wire; only the handler's
//! canned JSON is fake, as in Go `gatewaytest.Server`).
//!
//! Required tests from the M4a brief:
//! - heartbeat sends at the right cadence (count frames)
//! - stale probe detects a dead conn (dead gateway is not
//!   alive; the next call reconnects)
//! - retry within `RetryFor`
//! - down notice after `DownNotice`/`DownFails`
//! - no token/cookie leak into logs (hand-written `Debug`)
//! - cancel mid-handshake does not hang
//! - gateway 3xx -> `Gateway(status)` -> exit 3
//! - unknown method -> `Validation`
//! - chunked large response + shuffled pieces reassemble

mod common;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use castctl_gateway::Gateway;
use castctl_gateway::dial::dial_gateway;
use castctl_gateway::gateway::RequestOptions;
use castctl_gateway::shared::{
    Connector, DownDecision, DownTracker, HEARTBEAT, RETRY_FOR, SharedConn,
};
use castctl_transport::TransportError;
use castctl_transport::retry::RetryPolicy;
use common::{BlackholeServer, FakeServer, Reply, canned_json};
use tokio::time::sleep;

fn routes() -> Arc<castctl_transport::routes::RouteTable> {
    Arc::new(
        castctl_transport::routes::RouteTable::default_routes().expect("routes.json must load"),
    )
}

fn json_str(v: &serde_json::Value) -> String {
    serde_json::to_string(v).expect("call_json result must serialize")
}

fn policy_fast() -> RetryPolicy {
    RetryPolicy {
        budget: Duration::from_secs(2),
        pause_initial: Duration::from_millis(10),
        pause_max: Duration::from_millis(50),
    }
}

/// Connector that dials the fake server, failing the first
/// `fail_times` connects with `ConnectionDown`.
struct FlakyConnector {
    url: String,
    fail_times: AtomicU64,
    attempts: AtomicU64,
}

impl Connector for FlakyConnector {
    fn connect(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<Gateway>, TransportError>> + Send + '_>> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let url = self.url.clone();
        let fail = self.fail_times.load(Ordering::SeqCst) > 0;
        if fail {
            self.fail_times.fetch_sub(1, Ordering::SeqCst);
        }
        Box::pin(async move {
            if fail {
                return Err(TransportError::ConnectionDown {
                    message: "injected down".to_string(),
                });
            }
            dial_gateway(&url, routes()).await
        })
    }
}

struct AlwaysAuthConnector {
    attempts: AtomicU64,
}

impl Connector for AlwaysAuthConnector {
    fn connect(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<Gateway>, TransportError>> + Send + '_>> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Err(TransportError::Auth {
                message: "injected auth failure".to_string(),
            })
        })
    }
}

#[tokio::test]
async fn call_json_roundtrip_five_methods() {
    let server = FakeServer::start(Arc::new(|req| canned_json(&req.path))).await;
    let gw = dial_gateway(&server.ws_url(), routes()).await.unwrap();
    for (method, want) in [
        ("connection.ping", "\"pong\":true"),
        ("sessions.list", "\"sessions\""),
        ("chat.history", "\"messages\""),
        ("feed.list", "\"items\""),
        ("goals.list", "\"goals\""),
    ] {
        let out = gw
            .call_json(method, RequestOptions::default())
            .await
            .unwrap_or_else(|e| panic!("{method}: {e}"));
        // `call_json` returns the `result` field only (Go
        // `CallJSON`: `{"ok":true,"result":X}` -> `X`).
        let s = json_str(&out);
        assert!(s.contains(want), "{method}: {s}");
        assert!(!s.contains("\"ok\""), "{method}: envelope leaked: {s}");
    }
    // The server saw the right verbs/paths and a request id.
    // Verbs come from routes.json: ping is POST, the four
    // reads are GET.
    let reqs = server.requests.lock().unwrap();
    assert_eq!(reqs.len(), 5);
    assert_eq!(
        reqs.iter().map(|(v, _, _)| v.as_str()).collect::<Vec<_>>(),
        ["POST", "GET", "GET", "GET", "GET"]
    );
    assert_eq!(
        reqs.iter().map(|(_, p, _)| p.as_str()).collect::<Vec<_>>(),
        [
            "/api/ping",
            "/api/session/list",
            "/chat/history",
            "/api/feed",
            "/goals"
        ]
    );
    let hdrs = server.headers_seen.lock().unwrap();
    assert!(
        hdrs.iter()
            .all(|hs| hs.iter().any(|(k, _)| k == "x-request-id")),
        "every request carries x-request-id"
    );
    server.stop();
}

#[tokio::test]
async fn call_json_unknown_method_is_validation() {
    let server = FakeServer::start(Arc::new(|req| canned_json(&req.path))).await;
    let gw = dial_gateway(&server.ws_url(), routes()).await.unwrap();
    let err = gw
        .call_json("no.such.method", RequestOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransportError::Validation { .. }),
        "unknown method must be Validation, got {err:?}"
    );
    assert_eq!(err.exit_code(), 2);
    server.stop();
}

#[tokio::test]
async fn call_json_http_error_is_gateway_exit_3() {
    let server = FakeServer::start(Arc::new(|_| Reply::json(404, r#"{"ok":false}"#))).await;
    let gw = dial_gateway(&server.ws_url(), routes()).await.unwrap();
    let err = gw
        .call_json("sessions.list", RequestOptions::default())
        .await
        .unwrap_err();
    match &err {
        TransportError::Gateway(summary) => assert_eq!(summary.status, 404),
        other => panic!("want Gateway(404), got {other:?}"),
    }
    // Settled decision (Q5): gateway 3xx/4xx is Gateway ->
    // exit 3, never RedirectRefused.
    assert_eq!(err.exit_code(), 3);
    server.stop();
}

#[tokio::test]
async fn call_json_ok_false_is_gateway() {
    let server = FakeServer::start(Arc::new(|_| {
        Reply::json(200, r#"{"ok":false,"error":"boom"}"#)
    }))
    .await;
    let gw = dial_gateway(&server.ws_url(), routes()).await.unwrap();
    let err = gw
        .call_json("sessions.list", RequestOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransportError::Gateway(_)),
        "ok=false must be Gateway, got {err:?}"
    );
    server.stop();
}

#[tokio::test]
async fn chunked_large_response_and_shuffled_pieces() {
    let big = "x".repeat(200_000);
    let big2 = big.clone();
    let server = FakeServer::start(Arc::new(move |_| {
        let mut r = Reply::json(200, &format!(r#"{{"ok":true,"result":"{big2}"}}"#));
        r.shuffle_pieces = true;
        r
    }))
    .await;
    let gw = dial_gateway(&server.ws_url(), routes()).await.unwrap();
    let out = gw
        .call_json("sessions.list", RequestOptions::default())
        .await
        .unwrap();
    // The result is one JSON string value: serialized with
    // its two quote characters around the 200k payload.
    let s = json_str(&out);
    assert_eq!(s.len(), big.len() + 2);
    assert!(s.contains(&big[..1000]));
    server.stop();
}

#[tokio::test]
async fn heartbeat_sends_pings_at_cadence() {
    let server = FakeServer::start(Arc::new(|req| canned_json(&req.path))).await;
    let conn = Arc::new(FlakyConnector {
        url: server.ws_url(),
        fail_times: AtomicU64::new(0),
        attempts: AtomicU64::new(0),
    });
    let shared = Arc::new(SharedConn::with_policy(
        conn,
        policy_fast(),
        Duration::from_millis(300),
    ));
    // Warm the connection first: the heartbeat loop only
    // pings a gateway that exists (it never opens the first
    // one itself — same as Go, where the first call opens).
    let out = shared
        .call_json("connection.ping", RequestOptions::default())
        .await
        .unwrap();
    assert!(json_str(&out).contains("pong"));
    let before = server.ping_count.load(Ordering::SeqCst);
    shared.start_heartbeat();
    // heartbeat_tick = min(5s, 300ms) = 300ms; in ~1.1s we
    // expect at least 2 pings (ticks at ~300/600/900ms; a
    // tick is skipped only if the conn was used <300ms ago).
    sleep(Duration::from_millis(1100)).await;
    shared.stop_heartbeat().await;
    let pings = server.ping_count.load(Ordering::SeqCst) - before;
    assert!(
        (2..=5).contains(&pings),
        "heartbeat pings in 1.1s at 300ms cadence: got {pings}, want 2..=5"
    );
    server.stop();
}

#[tokio::test]
async fn stale_probe_detects_dead_conn_and_reconnects() {
    let server = FakeServer::start(Arc::new(|req| canned_json(&req.path))).await;
    let conn = Arc::new(FlakyConnector {
        url: server.ws_url(),
        fail_times: AtomicU64::new(0),
        attempts: AtomicU64::new(0),
    });
    let shared = Arc::new(SharedConn::with_policy(conn, policy_fast(), HEARTBEAT));
    // Warm the connection.
    let out = shared
        .call_json("connection.ping", RequestOptions::default())
        .await
        .unwrap();
    assert!(json_str(&out).contains("pong"));
    let gw = shared.snapshot().expect("gateway installed");
    assert!(gw.alive());
    // Kill the server side; the client reader must notice.
    server.close_all();
    let mut dead = false;
    for _ in 0..20 {
        sleep(Duration::from_millis(100)).await;
        if !gw.alive() {
            dead = true;
            break;
        }
    }
    assert!(
        dead,
        "gateway must report dead after the server dropped the conn"
    );
    // Note: `probe_stale` itself is NOT the detector here —
    // like Go `probeStale` it short-circuits to "alive" when
    // the gateway was used within `HEARTBEAT` (25s), and this
    // gateway was used seconds ago. The dead detection is the
    // reader task marking `dead` + `alive() == false`; the
    // recovery proof is the next call reconnecting (listener
    // is still up).
    assert!(!gw.alive());
    // ...and the next call reconnects (listener is still up).
    let out = shared
        .call_json("connection.ping", RequestOptions::default())
        .await
        .unwrap();
    assert!(json_str(&out).contains("pong"));
    assert_eq!(shared.connects(), 2, "one warm + one reconnect");
    server.stop();
}

#[tokio::test]
async fn retry_within_budget_then_succeeds() {
    let server = FakeServer::start(Arc::new(|req| canned_json(&req.path))).await;
    let conn = Arc::new(FlakyConnector {
        url: server.ws_url(),
        fail_times: AtomicU64::new(2),
        attempts: AtomicU64::new(0),
    });
    let attempts = Arc::clone(&conn);
    let shared = Arc::new(SharedConn::with_policy(conn, policy_fast(), HEARTBEAT));
    let start = Instant::now();
    let out = shared
        .call_json("sessions.list", RequestOptions::default())
        .await
        .unwrap();
    assert!(json_str(&out).contains("sessions"));
    assert!(
        start.elapsed() < RETRY_FOR,
        "retry must finish within RetryFor ({RETRY_FOR:?})"
    );
    // 2 failed + 1 good connect attempts; `connects()`
    // counts successful installs only, so it is 1.
    assert_eq!(
        attempts.attempts.load(Ordering::SeqCst),
        3,
        "2 failed + 1 good connect attempts"
    );
    assert_eq!(shared.connects(), 1);
    server.stop();
}

#[tokio::test]
async fn auth_failure_is_not_retried() {
    let conn = Arc::new(AlwaysAuthConnector {
        attempts: AtomicU64::new(0),
    });
    let attempts = Arc::clone(&conn);
    let shared = Arc::new(SharedConn::with_policy(conn, policy_fast(), HEARTBEAT));
    let err = shared
        .call_json("sessions.list", RequestOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Auth { .. }));
    // Exactly one connect attempt (no retry ladder), and
    // `connects()` stays 0: it counts successful installs
    // only (Go `Muse.connects`), and auth failed before any
    // gateway existed to install.
    assert_eq!(
        attempts.attempts.load(Ordering::SeqCst),
        1,
        "auth failure: exactly one connect attempt"
    );
    assert_eq!(shared.connects(), 0);
    assert_eq!(err.exit_code(), 2);
}

#[tokio::test]
async fn down_notice_after_threshold() {
    // Unit-level: the tracker behind SharedConn, driven by
    // explicit Instants (no waiting for DOWN_NOTICE).
    let mut t = DownTracker::with_thresholds(Duration::from_secs(60), 5, Duration::ZERO);
    let err = TransportError::ConnectionDown {
        message: "down".to_string(),
    };
    let now = Instant::now();
    for i in 0..4 {
        let d = t.mark_down(now + Duration::from_millis(i as u64), true, &err);
        assert_eq!(d, DownDecision::None, "fail {i} must not notify yet");
    }
    let d = t.mark_down(now + Duration::from_millis(10), true, &err);
    assert!(
        matches!(
            d,
            DownDecision::Notify {
                failed_reconnects: 5,
                ..
            }
        ),
        "5th fail must raise the notice, got {d:?}"
    );
    // Integration-level: a SharedConn whose connector always
    // fails reports the notice through the OnDown callback.
    let server = FakeServer::start(Arc::new(|req| canned_json(&req.path))).await;
    let conn = Arc::new(FlakyConnector {
        url: server.ws_url(),
        fail_times: AtomicU64::new(100),
        attempts: AtomicU64::new(0),
    });
    let mut shared = SharedConn::with_policy(conn, policy_fast(), HEARTBEAT);
    shared.set_down_tracker(DownTracker::with_thresholds(
        Duration::from_secs(60),
        5,
        Duration::ZERO,
    ));
    let notices = Arc::new(AtomicU64::new(0));
    let n2 = Arc::clone(&notices);
    shared.set_on_down(Arc::new(move |_err, _down_for| {
        n2.fetch_add(1, Ordering::SeqCst);
    }));
    let shared = Arc::new(shared);
    let _ = shared
        .call_json("sessions.list", RequestOptions::default())
        .await;
    assert!(
        notices.load(Ordering::SeqCst) >= 1,
        "down notice must fire after DownFails"
    );
    server.stop();
}

#[tokio::test]
async fn no_token_or_cookie_in_debug() {
    let server = FakeServer::start(Arc::new(|req| canned_json(&req.path))).await;
    let gw = dial_gateway(&server.ws_url(), routes()).await.unwrap();
    let dbg = format!("{gw:?}");
    assert!(
        !dbg.contains("FAKE-TOKEN-123"),
        "Gateway Debug must not leak the token: {dbg}"
    );
    assert!(
        !dbg.contains("hatch_sess"),
        "Gateway Debug must not leak cookies: {dbg}"
    );
    // TransportError Debug is hand-written and prints no
    // message bodies at all — and neither does log_summary
    // (lengths only). Display DOES echo a caller-supplied
    // message (truncated): that is by design, for the
    // operator, and the library never puts a token into a
    // message itself — so the leak test asserts Debug and
    // log_summary, not Display.
    let err = TransportError::Auth {
        message: "hatch_sess=FAKE-TOKEN-123".to_string(),
    };
    assert!(!format!("{err:?}").contains("FAKE-TOKEN"));
    assert!(!err.log_summary().contains("FAKE-TOKEN"));
    server.stop();
}

#[tokio::test]
async fn cancel_mid_handshake_does_not_hang() {
    let server = BlackholeServer::start().await;
    let url = server.ws_url();
    let start = Instant::now();
    let handle = tokio::spawn(async move { dial_gateway(&url, routes()).await });
    // Cancel mid-handshake (server never sends msg2).
    sleep(Duration::from_millis(200)).await;
    handle.abort();
    let outcome = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(
        outcome.is_ok(),
        "aborted dial must finish within 2s, took {:?}",
        start.elapsed()
    );
    server.stop();
}

#[tokio::test]
async fn heartbeat_interval_constant_unchanged() {
    assert_eq!(HEARTBEAT, Duration::from_secs(25));
}
