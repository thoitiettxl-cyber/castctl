// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Integration tests for the gateway connector + over-stream
//! dial (M4b): real WS + real Noise against the fake server
//! in `tests/common`, real HTTP/1.1 against the plain-HTTP
//! fake server in `tests/http_fake` — only the handlers'
//! replies are fake.

#[path = "common/fake_server.rs"]
mod fake_server;
mod http_fake;
#[path = "common/raw_upgrade.rs"]
mod raw_upgrade;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use castctl_gateway::connector::GatewayConnector;
use castctl_gateway::dial::dial_gateway_over_stream;
use castctl_gateway::gateway::RequestOptions;
use castctl_transport::{DialTarget, Dialer, DirectDialer, RouteTable, TransportError};
use fake_server::{FakeServer, canned_json};
use http_fake::{HttpFakeServer, HttpHandlerFn, HttpReply, HttpRequest};
use raw_upgrade::RawUpgradeServer;

fn routes() -> Arc<RouteTable> {
    Arc::new(RouteTable::default_routes().unwrap())
}

fn temp_cookies(name: &str, content: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("castctl-m4b-{name}-{}.txt", std::process::id()));
    std::fs::write(&path, content).unwrap();
    path
}

fn auth_message(err: &TransportError) -> Option<&str> {
    match err {
        TransportError::Auth { message } => Some(message),
        _ => None,
    }
}

fn conn_message(err: &TransportError) -> Option<&str> {
    match err {
        TransportError::ConnectionError { message } => Some(message),
        _ => None,
    }
}

#[tokio::test]
async fn connect_missing_cookies_is_auth() {
    let connector = GatewayConnector::new(Arc::new(DirectDialer::new()));
    let err = connector
        .connect("/nonexistent/cookies.txt", "")
        .await
        .unwrap_err();
    let m = auth_message(&err).unwrap();
    assert!(
        m.starts_with("no cookies at /nonexistent/cookies.txt: "),
        "{m}"
    );
    assert!(m.contains("gateway: read cookies file: "), "{m}");
}

#[tokio::test]
async fn connect_unparseable_cookies_is_auth() {
    let path = temp_cookies("unparseable", "garbage with no equals");
    let connector = GatewayConnector::new(Arc::new(DirectDialer::new()));
    let err = connector
        .connect(path.to_str().unwrap(), "")
        .await
        .unwrap_err();
    let want = format!("could not parse cookies file {}", path.display());
    assert_eq!(auth_message(&err), Some(want.as_str()));
    std::fs::remove_file(&path).unwrap();
}

#[tokio::test]
async fn connect_full_chain_over_fakes() {
    // Auth fake: session -> access token -> hatch token.
    let auth_server = HttpFakeServer::start(Arc::new(|req: &HttpRequest| {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/api/session") => HttpReply::text(
                200,
                "application/json",
                r#"{"vm_id": "vm-test", "status": "ok"}"#,
            ),
            ("POST", "/api/auth/check") => {
                HttpReply::text(200, "application/json", r#"{"access_token": "AT"}"#)
            }
            ("POST", "/api/hatch/token") => {
                assert_eq!(
                    std::str::from_utf8(&req.body).unwrap(),
                    r#"{"vmAddress":"wss://vm-test.metaaivm.com/","vmName":"vm-test"}"#
                );
                HttpReply::text(200, "application/json", r#"{"token": "HT"}"#)
            }
            _ => HttpReply::text(404, "text/plain", "not found"),
        }
    }) as HttpHandlerFn)
    .await;
    // WS fake: real Noise + protobuf, canned JSON per path.
    let ws_server = FakeServer::start(Arc::new(|req| canned_json(&req.path))).await;
    let ws_url = ws_server.ws_url();

    let cookies = temp_cookies(
        "full-chain",
        r#"{"cookies": {"hatch_sess": "S", "datr": "D"}}"#,
    );
    let connector = GatewayConnector::new(Arc::new(DirectDialer::new()))
        .with_secure(false)
        .with_auth_base(&auth_server.base_url())
        .with_ws_url(move |_vm_id, _hatch| ws_url.clone());
    let gw = connector
        .connect(cookies.to_str().unwrap(), "")
        .await
        .unwrap();
    // The auth chain discovered vm-test from /api/session
    // (no vm_id was given); the WS upgrade carried it. The
    // recorded target is the wire form (the literal token —
    // see the M4a dial test, which asserts the literal
    // token on the recorded target).
    // Clone the recorded targets out and drop the lock guard
    // before any await below.
    let target = {
        let targets = ws_server.request_targets.lock().unwrap();
        assert_eq!(targets.len(), 1);
        targets[0].clone()
    };
    assert!(target.contains("vm_id=vm-test"), "{target}");
    // The override URL is the fake server's own ws_url, which
    // carries the fake token FAKE-TOKEN-123 (not the literal —
    // the literal path is covered by the M4a dial test).
    assert!(target.contains("auth_token=FAKE-TOKEN-123"), "{target}");
    // The real hatch token from the fake auth chain ("HT")
    // must never reach the dialed URL.
    assert!(!target.contains("auth_token=HT"), "{target}");
    // The auth chain made exactly its 3 calls, with the
    // right headers: cookies on session, Bearer on hatch.
    let auth_reqs = {
        let reqs = auth_server.requests.lock().unwrap();
        assert_eq!(reqs.len(), 3);
        reqs.clone()
    };
    assert_eq!(auth_reqs[0].method, "GET");
    assert_eq!(auth_reqs[0].path, "/api/session");
    assert_eq!(auth_reqs[0].header("Cookie"), Some("hatch_sess=S; datr=D"));
    assert_eq!(auth_reqs[1].method, "POST");
    assert_eq!(auth_reqs[1].path, "/api/auth/check");
    assert_eq!(auth_reqs[2].method, "POST");
    assert_eq!(auth_reqs[2].path, "/api/hatch/token");
    assert_eq!(auth_reqs[2].header("Authorization"), Some("Bearer AT"));
    // The gateway is live: a real call round-trips.
    let out = gw
        .call_json("connection.ping", RequestOptions::default())
        .await
        .unwrap();
    let s = serde_json::to_string(&out).unwrap();
    assert!(s.contains("\"pong\":true"), "{s}");
    // The fake gateway saw exactly one ping, POST /api/ping,
    // carrying an x-request-id (the UA lives on the WS
    // upgrade, not on the ApplicationRequest — see the M4a
    // test, which asserts x-request-id only).
    assert_eq!(ws_server.ping_count.load(Ordering::SeqCst), 1);
    let reqs = ws_server.requests.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].0, "POST");
    assert_eq!(reqs[0].1, "/api/ping");
    drop(reqs);
    let hdrs = ws_server.headers_seen.lock().unwrap();
    assert!(hdrs[0].iter().any(|(k, _)| k == "x-request-id"), "{hdrs:?}");
    drop(hdrs);
    std::fs::remove_file(&cookies).unwrap();
    ws_server.stop();
    auth_server.stop();
}

#[tokio::test]
async fn dial_over_stream_plain_ws_ping() {
    let server = FakeServer::start(Arc::new(|req| canned_json(&req.path))).await;
    let target = DialTarget::new("127.0.0.1", server.addr.port());
    let stream = DirectDialer::new().dial(&target).await.unwrap();
    let gw = dial_gateway_over_stream(stream, &server.ws_url(), routes())
        .await
        .unwrap();
    let out = gw
        .call_json("connection.ping", RequestOptions::default())
        .await
        .unwrap();
    let s = serde_json::to_string(&out).unwrap();
    assert!(s.contains("\"pong\":true"), "{s}");
    server.stop();
}

/// The WS upgrade request-target carries the literal
/// `auth_token=<redacted>` Go sends — the live edge returns
/// 401 for the percent-encoded `%3Credacted%3E` form (M4b
/// live probe on cue, 2026-11-05), so the dial must NOT
/// encode it, even though `http::Uri` cannot represent `<>`.
/// The raw server records the request bytes verbatim (the
/// fake server's tungstenite handshake cannot parse a
/// literal `<>` target).
#[tokio::test]
async fn dial_over_stream_sends_literal_redacted_token() {
    let server = RawUpgradeServer::start().await;
    let url = format!(
        "ws://{}/v1/noise?vm_id=vm-test&auth_token=<redacted>",
        server.addr
    );
    let target = DialTarget::new("127.0.0.1", server.addr.port());
    let stream = DirectDialer::new().dial(&target).await.unwrap();
    let err = dial_gateway_over_stream(stream, &url, routes())
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransportError::ConnectionError { .. }),
        "dial must fail at the Noise step, not the upgrade: {err:?}"
    );
    assert!(
        server.sent_101(),
        "raw server must have answered 101 (upgrade well-formed)"
    );
    let head = server.request_head().expect("upgrade request recorded");
    let request_line = head.lines().next().unwrap_or("");
    assert!(
        request_line.contains("auth_token=<redacted>"),
        "upgrade target must carry the literal token, got: {request_line}"
    );
    assert!(
        !request_line.contains("%3Credacted%3E"),
        "upgrade target must NOT percent-encode the token, got: {request_line}"
    );
    server.stop();
}

/// T-B1 (fix loop 1): a non-101 upgrade response renders
/// Go's exact `handshakeFailureError` text
/// (`internal/gateway/handshake_log.go:41-46`):
/// `gateway: websocket handshake: status_code=502` — 45
/// chars, NOT the 47-char `gateway: websocket handshake
/// failed: status 502` this code rendered before the fix.
/// The dial fails at the upgrade step (no 101), so the
/// Noise step is never reached.
#[tokio::test]
async fn ws_upgrade_502_renders_go_45_chars() {
    let server = RawUpgradeServer::start_with_response(Some(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ))
    .await;
    let url = format!(
        "ws://{}/v1/noise?vm_id=vm-test&auth_token=<redacted>",
        server.addr
    );
    let target = DialTarget::new("127.0.0.1", server.addr.port());
    let stream = DirectDialer::new().dial(&target).await.unwrap();
    let err = dial_gateway_over_stream(stream, &url, routes())
        .await
        .unwrap_err();
    let m = conn_message(&err).expect("want ConnectionError");
    assert_eq!(
        m, "gateway: websocket handshake: status_code=502",
        "non-101 upgrade must match Go byte-for-byte"
    );
    assert_eq!(m.len(), 45, "Go renders 45 chars for a 502");
    assert!(!server.sent_101(), "server must not have sent 101");
    server.stop();
}

/// T-B1 (fix loop 1), no-status path: a response with no
/// parseable status renders Go's fixed 35-char
/// `gateway: websocket handshake failed`
/// (`handshake_log.go:49-51`), NOT the 28-char
/// `gateway: websocket dial failed` this code rendered
/// before the fix.
#[tokio::test]
async fn ws_upgrade_unparseable_status_renders_go_fixed_message() {
    let server = RawUpgradeServer::start_with_response(Some("GARBAGE\r\n\r\n")).await;
    let url = format!(
        "ws://{}/v1/noise?vm_id=vm-test&auth_token=<redacted>",
        server.addr
    );
    let target = DialTarget::new("127.0.0.1", server.addr.port());
    let stream = DirectDialer::new().dial(&target).await.unwrap();
    let err = dial_gateway_over_stream(stream, &url, routes())
        .await
        .unwrap_err();
    let m = conn_message(&err).expect("want ConnectionError");
    assert_eq!(
        m, "gateway: websocket handshake failed",
        "unparseable status must render Go's fixed message"
    );
    assert_eq!(m.len(), 35, "Go renders 35 chars with no status");
    server.stop();
}

/// T-B1 (fix loop 1), malformed-token path: Go's
/// `handshakeStatusToken` renders a token-shaped but
/// non-3-digit token as its length only
/// (`handshake_log.go:121-124`):
/// `gateway: websocket handshake: status_token_length=3`.
#[tokio::test]
async fn ws_upgrade_malformed_token_renders_length_only() {
    let server = RawUpgradeServer::start_with_response(Some(
        "HTTP/1.1 ABC Bad\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ))
    .await;
    let url = format!(
        "ws://{}/v1/noise?vm_id=vm-test&auth_token=<redacted>",
        server.addr
    );
    let target = DialTarget::new("127.0.0.1", server.addr.port());
    let stream = DirectDialer::new().dial(&target).await.unwrap();
    let err = dial_gateway_over_stream(stream, &url, routes())
        .await
        .unwrap_err();
    let m = conn_message(&err).expect("want ConnectionError");
    assert_eq!(
        m, "gateway: websocket handshake: status_token_length=3",
        "malformed token must render its length only, never its bytes"
    );
    server.stop();
}

#[tokio::test]
async fn dial_over_stream_wss_attempts_tls() {
    // A plain-HTTP responder: it answers any first flight
    // with a plaintext 400, so a TLS ClientHello fails the
    // handshake — proving the wss path really attempts TLS
    // instead of silently upgrading plain.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
        let _ = stream.shutdown().await;
    });
    let target = DialTarget::new("127.0.0.1", addr.port());
    let stream = DirectDialer::new().dial(&target).await.unwrap();
    let url = format!(
        "wss://127.0.0.1:{}/v1/noise?vm_id=x&auth_token=<redacted>",
        addr.port()
    );
    let err = dial_gateway_over_stream(stream, &url, routes())
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransportError::ConnectionError { .. }),
        "{err:?}"
    );
}
