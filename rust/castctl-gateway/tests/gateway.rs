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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use castctl_gateway::Gateway;
use castctl_gateway::dial::{default_ws_url, dial_gateway};
use castctl_gateway::gateway::RequestOptions;
use castctl_gateway::shared::{
    Connector, DownDecision, DownTracker, HEARTBEAT, RETRY_FOR, SharedConn,
};
use castctl_transport::TransportError;
use castctl_transport::retry::RetryPolicy;
use castctl_transport::routes::{Route, Service};
use common::{BadMsg2Server, BlackholeServer, FakeServer, Reply, canned_json};
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
async fn dial_url_sends_redacted_literal_not_real_token() {
    // Boss decision 2026-11-05: mirror Go byte-for-byte. Go
    // `internal/gateway/connector.go:116` (`defaultWSURL`)
    // sends the literal `auth_token=<redacted>` — the quoted
    // hatch token is computed and silently discarded by
    // `Sprintf` (3 verbs, 4 args); `TestDefaultWSURL` pins
    // the literal, and the Go 0.9.0 production binary relays
    // real turns through that URL. The Rust URL must carry
    // the same literal and never the real token value. The
    // fake server records the raw upgrade request-target, so
    // this asserts on the wire URL, not on a helper.
    let server = FakeServer::start(Arc::new(|req| canned_json(&req.path))).await;
    let url = default_ws_url(
        false,
        &server.addr.to_string(),
        "vm-test",
        "REAL-TOKEN-SECRET-XYZ",
    );
    // String level: byte-for-byte the Go URL (raw literal).
    assert_eq!(
        url,
        format!(
            "ws://{}/v1/noise?vm_id=vm-test&auth_token=<redacted>",
            server.addr
        ),
        "default_ws_url must mirror Go defaultWSURL"
    );
    let gw = dial_gateway(&url, routes()).await.unwrap();
    // Clone the recorded target out and drop the lock guard
    // before any await (`gw.close().await` below).
    let target = {
        let targets = server.request_targets.lock().unwrap();
        assert_eq!(targets.len(), 1, "one WS upgrade, got {targets:?}");
        targets[0].clone()
    };
    // Wire level: `http::Uri` cannot represent `<`/`>` so
    // `dial_gateway` percent-encodes the literal on the wire;
    // the server decodes `%3C`/`%3E` back to `<redacted>`, the
    // same query value Go sends raw.
    assert!(
        target.contains("auth_token=%3Credacted%3E"),
        "dialed URL must carry the encoded Go literal, got {target}"
    );
    assert!(
        !target.contains("REAL-TOKEN-SECRET-XYZ"),
        "dialed URL must not carry the real token, got {target}"
    );
    assert!(
        target.contains("vm_id=vm-test"),
        "vm_id must survive: {target}"
    );
    // Decoded level: the decoded query value must be the
    // literal Go sends raw. No URL/query parser is a
    // dependency of this crate, so decode the two sequences
    // `dial_gateway` emits (`%3C`/`%3E`) on the extracted
    // value directly — a general URL parser is not needed
    // for this one value (fix loop 2, NB5).
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
    let token_value = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("auth_token="))
        .expect("auth_token present in the recorded target");
    let decoded = token_value.replace("%3C", "<").replace("%3E", ">");
    assert_eq!(
        decoded, "<redacted>",
        "decoded auth_token value must be the Go literal, got {decoded} (raw target {target})"
    );
    gw.close().await;
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
async fn call_json_redirect_is_gateway_exit_3() {
    // Explicit 3xx (not just the 404 case): Go
    // `calls.go:168-174` maps ANY non-2xx status to
    // `GatewayError(status)` → exit 3.
    let server = FakeServer::start(Arc::new(|_| Reply::json(301, r#"{"ok":true}"#))).await;
    let gw = dial_gateway(&server.ws_url(), routes()).await.unwrap();
    let err = gw
        .call_json("sessions.list", RequestOptions::default())
        .await
        .unwrap_err();
    match &err {
        TransportError::Gateway(summary) => assert_eq!(summary.status, 301),
        other => panic!("want Gateway(301), got {other:?}"),
    }
    assert_eq!(err.exit_code(), 3);
    server.stop();
}

#[tokio::test]
async fn call_json_non_json_body_is_gateway_exit_3() {
    // Non-JSON 200 body: `decode_call_json` maps it to
    // `Gateway(-1)` → exit 3.
    let server = FakeServer::start(Arc::new(|_| Reply::json(200, "this is not json"))).await;
    let gw = dial_gateway(&server.ws_url(), routes()).await.unwrap();
    let err = gw
        .call_json("sessions.list", RequestOptions::default())
        .await
        .unwrap_err();
    match &err {
        TransportError::Gateway(summary) => assert_eq!(summary.status, -1),
        other => panic!("want Gateway(-1), got {other:?}"),
    }
    assert_eq!(err.exit_code(), 3);
    server.stop();
}

#[tokio::test]
async fn call_json_reset_is_gateway_exit_3() {
    // A stream `Reset` mid-call maps to `Gateway(-1)` →
    // exit 3 (the `Reset` frame ends the stream with a
    // gateway error, it is not a connection failure).
    let server = FakeServer::start(Arc::new(|_| Reply {
        reset: Some((3, "boom".to_string())),
        ..Reply::json(200, "{}")
    }))
    .await;
    let gw = dial_gateway(&server.ws_url(), routes()).await.unwrap();
    let err = gw
        .call_json("sessions.list", RequestOptions::default())
        .await
        .unwrap_err();
    match &err {
        TransportError::Gateway(summary) => assert_eq!(summary.status, -1),
        other => panic!("want Gateway(-1), got {other:?}"),
    }
    assert_eq!(err.exit_code(), 3);
    server.stop();
}

#[tokio::test]
async fn request_timeout_is_timeout_exit_4() {
    // The server never answers: the call must fail with
    // `TimeoutError` (exit 4) at the 200ms deadline, not
    // hang and not a `ConnectionError`.
    let server = FakeServer::start(Arc::new(|_| Reply {
        never_reply: true,
        ..Reply::json(200, "{}")
    }))
    .await;
    let gw = dial_gateway(&server.ws_url(), routes()).await.unwrap();
    let err = gw
        .request(
            "sessions.list",
            RequestOptions {
                timeout: Duration::from_millis(200),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransportError::Timeout { .. }),
        "want Timeout, got {err:?}"
    );
    assert_eq!(err.exit_code(), 4);
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
    // Go `Live` (`conn.go:500-520`): replacing the dead
    // installed gateway counts one drop (and records the
    // outage + closes the old gateway).
    assert_eq!(
        shared.drops(),
        1,
        "replacing the dead installed gateway counts one drop"
    );
    server.stop();
}

#[tokio::test]
async fn live_open_failure_drops_dead_installed_gateway() {
    // Go `Live` (`conn.go:500-520` + open-error branch): a dead
    // installed gateway is detached BEFORE opening — the drop is
    // counted, the outage recorded with the dead error, and the
    // old gateway closed even when the reopen FAILS. Rust opens
    // first and installs after, so `live()` must do the same
    // detach on the open-error path (fix loop 2, F5/NB3).
    let server = FakeServer::start(Arc::new(|req| canned_json(&req.path))).await;
    let conn = Arc::new(FlakyConnector {
        url: server.ws_url(),
        fail_times: AtomicU64::new(0),
        attempts: AtomicU64::new(0),
    });
    let shared = Arc::new(SharedConn::with_policy(
        Arc::clone(&conn) as Arc<dyn Connector>,
        policy_fast(),
        HEARTBEAT,
    ));
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
    assert_eq!(shared.drops(), 0, "no drop counted yet");
    // The reopen now fails (one injected failure).
    conn.fail_times.store(1, Ordering::SeqCst);
    let err = shared.live().await.unwrap_err();
    assert!(
        matches!(err, TransportError::ConnectionDown { .. }),
        "live() must return the injected open failure, got {err}"
    );
    // The dead installed gateway is detached even though the
    // reopen failed: drop counted, slot cleared. (`close()`
    // rides the same helper call as the counted drop; a
    // missing close would leak the socket, observable only
    // via a live peer — same scope as PR1.)
    assert_eq!(
        shared.drops(),
        1,
        "failed reopen still counts the drop of the dead installed gateway"
    );
    assert!(
        shared.snapshot().is_none(),
        "slot must be cleared after the failed reopen"
    );
    server.stop();
}

#[tokio::test]
async fn probe_stale_or_uses_injectable_interval() {
    // Go `conn.go:445-452` `probeStale`: EITHER axis fresh
    // (last recv OR last use within `heartbeatInterval`)
    // means alive without a probe; only when BOTH are quiet
    // does it send a ping. The probe interval is the
    // SharedConn's injectable `heartbeat_interval` (300ms
    // here), not the 25s `HEARTBEAT` constant. This test
    // proves both branches: branch 1 (one axis fresh → no
    // ping) and branch 2 (both stale → exactly one ping).
    let interval = Duration::from_millis(300);
    let drop_pings = Arc::new(AtomicBool::new(false));
    let drop = Arc::clone(&drop_pings);
    let server = FakeServer::start(Arc::new(move |req| {
        if drop.load(Ordering::SeqCst) && req.path == "/api/ping" {
            Reply {
                never_reply: true,
                ..Reply::json(200, "{}")
            }
        } else {
            canned_json(&req.path)
        }
    }))
    .await;
    let conn = Arc::new(FlakyConnector {
        url: server.ws_url(),
        fail_times: AtomicU64::new(0),
        attempts: AtomicU64::new(0),
    });
    let shared = Arc::new(SharedConn::with_policy(conn, policy_fast(), interval));
    let out = shared
        .call_json("connection.ping", RequestOptions::default())
        .await
        .unwrap();
    assert!(json_str(&out).contains("pong"));
    let gw = shared.snapshot().expect("gateway installed");
    // Both axes stale (450ms > 300ms), then a dropped ping:
    // the send refreshes `last_used` only, `last_recv` stays
    // stale — exactly one axis fresh.
    sleep(Duration::from_millis(450)).await;
    drop_pings.store(true, Ordering::SeqCst);
    let err = gw.ping(Duration::from_millis(100)).await.unwrap_err();
    assert!(matches!(err, TransportError::Timeout { .. }));
    assert_eq!(err.exit_code(), 4);
    let before = server.ping_count.load(Ordering::SeqCst);
    // Branch 1: one axis fresh → alive, no probe ping sent.
    assert!(
        shared.probe_stale(&gw).await,
        "one axis fresh must be alive without a probe"
    );
    assert_eq!(
        server.ping_count.load(Ordering::SeqCst),
        before,
        "branch 1 must not send a ping"
    );
    // Both axes stale again; the probe must ping (and the
    // ping answers → alive).
    sleep(Duration::from_millis(450)).await;
    drop_pings.store(false, Ordering::SeqCst);
    assert!(
        shared.probe_stale(&gw).await,
        "both stale but ping answers must be alive"
    );
    assert_eq!(
        server.ping_count.load(Ordering::SeqCst),
        before + 1,
        "branch 2 must send exactly one probe ping"
    );
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
async fn unsafe_method_is_not_retried_on_connection_error() {
    // Handler: close the conn without answering for both
    // the unsafe write and the safe read — the in-flight
    // call fails with `ConnectionError` either way.
    let server = FakeServer::start(Arc::new(|req| {
        if req.path == "/chat/send" || req.path == "/api/session/list" {
            Reply {
                close_without_reply: true,
                ..Reply::json(200, "{}")
            }
        } else {
            canned_json(&req.path)
        }
    }))
    .await;
    let conn = Arc::new(FlakyConnector {
        url: server.ws_url(),
        fail_times: AtomicU64::new(0),
        attempts: AtomicU64::new(0),
    });
    let shared = Arc::new(SharedConn::with_policy(conn, policy_fast(), HEARTBEAT));
    let out = shared
        .call_json("connection.ping", RequestOptions::default())
        .await
        .unwrap();
    assert!(json_str(&out).contains("pong"));
    // Unsafe write (POST `chat.send`, not one of the 9 POST
    // reads): the `ConnectionError` must NOT be retried —
    // exactly one attempt reaches the server.
    let route = Route {
        method: "chat.send".to_string(),
        http: "POST".to_string(),
        path: "/chat/send".to_string(),
        service: Service::Daemon,
    };
    let err = shared
        .call_json(
            "chat.send",
            RequestOptions {
                route: Some(route),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransportError::ConnectionError { .. }),
        "want ConnectionError, got {err:?}"
    );
    let sends = server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, path, _)| path == "/chat/send")
        .count();
    assert_eq!(sends, 1, "unsafe method: exactly 1 attempt, got {sends}");
    // Sensitivity control: the same failure on a safe GET is
    // retried inside the 2s budget — the harness can observe
    // retries, so the 1 above is the safety rule, not a dead
    // retry path.
    let err = shared
        .call_json("sessions.list", RequestOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransportError::ConnectionError { .. }),
        "want ConnectionError, got {err:?}"
    );
    let lists = server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, path, _)| path == "/api/session/list")
        .count();
    assert!(
        lists > 1,
        "safe method must be retried, got {lists} attempts"
    );
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
        dbg.starts_with("Gateway { alive:"),
        "Gateway Debug shape is pinned: {dbg}"
    );
    assert!(
        !dbg.contains("auth_token"),
        "Gateway Debug must not name the token param: {dbg}"
    );
    assert!(
        !dbg.contains("FAKE-TOKEN-123"),
        "Gateway Debug must not leak the token: {dbg}"
    );
    assert!(
        !dbg.contains("hatch_sess"),
        "Gateway Debug must not leak cookies: {dbg}"
    );
    // SharedConn Debug prints counts only (the connector
    // owns credentials); same absence + shape pin.
    let shared = SharedConn::with_policy(
        Arc::new(FlakyConnector {
            url: server.ws_url(),
            fail_times: AtomicU64::new(0),
            attempts: AtomicU64::new(0),
        }),
        policy_fast(),
        HEARTBEAT,
    );
    let sdbg = format!("{shared:?}");
    assert!(
        sdbg.starts_with("SharedConn { connects:"),
        "SharedConn Debug shape is pinned: {sdbg}"
    );
    assert!(
        !sdbg.contains("auth_token")
            && !sdbg.contains("FAKE-TOKEN-123")
            && !sdbg.contains("hatch_sess"),
        "SharedConn Debug must not leak secrets: {sdbg}"
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
async fn dial_bad_msg2_is_connection_error() {
    // Truncated (5 bytes), empty (0 bytes) and oversized
    // (70000 bytes) msg2: the Noise handshake must fail
    // with `ConnectionError`, never hang or panic. A valid
    // XX msg2 with an empty payload is 48 bytes, so all
    // three are malformed by length alone.
    for (name, payload) in [
        ("truncated", vec![0xAA; 5]),
        ("empty", vec![]),
        ("oversized", vec![0xAA; 70_000]),
    ] {
        let server = BadMsg2Server::start(payload).await;
        let err = dial_gateway(&server.ws_url(), routes()).await.unwrap_err();
        assert!(
            matches!(err, TransportError::ConnectionError { .. }),
            "{name} msg2 must be ConnectionError, got {err:?}"
        );
        server.stop();
    }
}

#[tokio::test]
async fn heartbeat_interval_constant_unchanged() {
    assert_eq!(HEARTBEAT, Duration::from_secs(25));
}
