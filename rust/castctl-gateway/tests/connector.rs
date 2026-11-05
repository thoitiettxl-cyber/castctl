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
use castctl_gateway::dial::{default_ws_url, dial_gateway_over_stream};
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

/// A server that RSTs the connection without reading it:
/// accept, then drop the stream immediately, so the
/// client's request bytes stay unread in the kernel
/// receive buffer and Linux RSTs the connection (closing
/// with unread data sends RST; reading first would give
/// a clean FIN and just re-exercise the EOF arm).
/// Lives here, not in `common/raw_upgrade.rs`, because
/// clippy's per-target dead-code check would fail the
/// targets that never construct it (fix loop 1 pattern).
/// (`TcpStream::set_linger` is unstable, issue #88494 —
/// the unread-data close is the stable way to force a
/// RST.) The accept loop runs until the test binary
/// exits; no stop handle is needed.
async fn start_reset_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            drop(stream);
        }
    });
    addr
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
    // recorded target is the wire form of the override URL
    // (a test fixture — see below, not Go's URL).
    // Clone the recorded targets out and drop the lock guard
    // before any await below.
    let target = {
        let targets = ws_server.request_targets.lock().unwrap();
        assert_eq!(targets.len(), 1);
        targets[0].clone()
    };
    assert!(target.contains("vm_id=vm-test"), "{target}");
    // The override URL is the fake server's own ws_url, which
    // carries the fixture token FAKE-TOKEN-123. The override
    // ignores the hatch token by construction, so the "HT"
    // from the fake auth chain must not appear — this pins
    // the fixture, not Go behaviour (Go's own URL carries
    // the real token, PORTING §M4c.7).
    assert!(target.contains("auth_token=FAKE-TOKEN-123"), "{target}");
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

/// The WS upgrade request-target is sent verbatim by the
/// hand-written upgrade: whatever `default_ws_url` built
/// (the quoted real token, PORTING §M4c.7) must arrive
/// byte-for-byte, with no re-encoding by an intermediate
/// URI parse. The raw server records the request bytes
/// verbatim. Fake token only.
#[tokio::test]
async fn dial_over_stream_sends_quoted_token_verbatim() {
    let server = RawUpgradeServer::start().await;
    const FAKE_TOKEN: &str = "FAKE+tok/en=1 2é";
    const QUOTED_TOKEN: &str = "FAKE%2Btok%2Fen%3D1%202%C3%A9";
    let url = default_ws_url(false, &server.addr.to_string(), "vm-test", FAKE_TOKEN);
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
    let err_text = format!("{err} {err:?}");
    assert!(
        !err_text.contains(FAKE_TOKEN),
        "dial error must not leak the raw token"
    );
    assert!(
        !err_text.contains(QUOTED_TOKEN),
        "dial error must not leak the quoted token"
    );
    let head = server.request_head().expect("upgrade request recorded");
    let request_line = head.lines().next().unwrap_or("");
    assert!(
        request_line.contains(QUOTED_TOKEN),
        "upgrade target must carry the quoted token verbatim"
    );
    assert!(
        !request_line.contains(FAKE_TOKEN),
        "upgrade target must not carry the raw token"
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
/// (`handshake_log.go:49-51`), NOT the 30-char
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

/// Fix loop 2 (B1): a 101 with a wrong
/// `Sec-WebSocket-Accept` renders Go's
/// `gateway: websocket handshake: status_code=101` —
/// gorilla returns the response non-nil on accept
/// mismatch (`client.go:394-405`), so
/// `handshakeStatusToken` takes the resp branch
/// (`handshake_log.go:103-107`). NOT the 30-char
/// `gateway: websocket dial failed`.
#[tokio::test]
async fn ws_upgrade_bad_accept_renders_go_status_code_101() {
    let server = RawUpgradeServer::start_with_response(Some(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n",
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
        m, "gateway: websocket handshake: status_code=101",
        "accept mismatch on a 101 must render Go's status_code=101"
    );
    assert_eq!(m.len(), 45, "Go renders 45 chars for a 101 accept mismatch");
    server.stop();
}

/// Fix loop 2 (B2): a server that closes without sending
/// any status line renders Go's fixed 35-char message —
/// gorilla's `ReadResponse` returns `(nil, nil, err)` on
/// EOF (`client.go:372-387`), so `handshakeStatusToken`
/// finds no malformed-status token and `ok=false`
/// (`handshake_log.go:49-51`).
#[tokio::test]
async fn ws_upgrade_eof_before_status_renders_go_fixed_message() {
    let server = RawUpgradeServer::start_with_response(Some("")).await;
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
        "EOF before any status line must render Go's fixed message"
    );
    assert_eq!(m.len(), 35, "Go renders 35 chars with no status");
    server.stop();
}

/// Fix loop 2 (B2): a server that RSTs the connection
/// before any status line renders the same fixed 35-char
/// message — the read fails (`client.go:372-387` returns
/// `(nil, nil, err)`), resp nil, no token. Which dial
/// arm fires (write / read / EOF) depends on RST timing,
/// but all three share the identical
/// `handshake_failed_error()` call, so the message
/// assertion pins the rendering either way.
#[tokio::test]
async fn ws_upgrade_reset_before_status_renders_go_fixed_message() {
    let addr = start_reset_server().await;
    let url = format!("ws://{addr}/v1/noise?vm_id=vm-test&auth_token=<redacted>");
    let target = DialTarget::new("127.0.0.1", addr.port());
    let stream = DirectDialer::new().dial(&target).await.unwrap();
    let err = dial_gateway_over_stream(stream, &url, routes())
        .await
        .unwrap_err();
    let m = conn_message(&err).expect("want ConnectionError");
    assert_eq!(
        m, "gateway: websocket handshake failed",
        "RST before any status line must render Go's fixed message"
    );
    assert_eq!(m.len(), 35, "Go renders 35 chars with no status");
}

/// Fix loop 2 (non-UTF-8 arm, status token): Go parses
/// the response as bytes (`net/http` `ReadResponse` +
/// `textproto` never validate UTF-8); a non-UTF-8 status
/// token fails `Atoi` → `malformed HTTP status code`
/// error → the regex-extracted token fails
/// `tokenShapeRe` (non-ASCII) → `ok=false` → the fixed
/// 35-char message (`handshake_log.go:103-130`).
#[tokio::test]
async fn ws_upgrade_non_utf8_status_token_renders_go_fixed_message() {
    let response: &[u8] = b"HTTP/1.1 \xff\xff\xff Bad\r\n\r\n";
    let server = RawUpgradeServer::start_with_response_bytes(Some(response)).await;
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
        "non-UTF-8 status token must render Go's fixed message"
    );
    assert_eq!(m.len(), 35, "Go renders 35 chars with no parseable token");
    server.stop();
}

/// Fix loop 2 (non-UTF-8 arm, header value): non-UTF-8
/// bytes in a header VALUE are valid obs-text
/// (`textproto` `validHeaderValueByte`,
/// `reader.go:733`), so the response still parses and
/// Go renders the status-based form — here
/// `status_code=502` for a 502, NOT the fixed message.
#[tokio::test]
async fn ws_upgrade_non_utf8_header_value_renders_go_status_code() {
    let response: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nX-Custom: \xff\xfe\r\n\r\n";
    let server = RawUpgradeServer::start_with_response_bytes(Some(response)).await;
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
        "non-UTF-8 in a header value must not hide the status"
    );
    assert_eq!(m.len(), 45, "Go renders 45 chars for a 502");
    server.stop();
}

/// Fix loop 2 (non-UTF-8 arm, header key): a header
/// KEY byte >= 0x80 fails `validHeaderFieldByte`, so
/// `canonicalMIMEHeaderKey` returns ok=false and
/// `ReadResponse` fails the whole response
/// (`textproto/reader.go:521-596`) → resp nil → the
/// fixed 35-char message, even with a valid 502 status
/// line (Go parses the whole head before returning it).
#[tokio::test]
async fn ws_upgrade_non_utf8_header_key_renders_go_fixed_message() {
    let response: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nX-\xff: v\r\n\r\n";
    let server = RawUpgradeServer::start_with_response_bytes(Some(response)).await;
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
        "non-UTF-8 in a header key must fail the whole response in Go"
    );
    assert_eq!(m.len(), 35, "Go renders 35 chars with no response");
    server.stop();
}

/// Fix loop 2 (non-UTF-8 arm, accept value): a 101
/// whose `Sec-WebSocket-Accept` value is non-UTF-8
/// cannot equal the computed key (ASCII base64), so
/// gorilla returns `(nil, resp, ErrBadHandshake)`
/// (`client.go:394-405`) → Go renders
/// `status_code=101`.
#[tokio::test]
async fn ws_upgrade_non_utf8_accept_value_renders_go_status_code_101() {
    let response: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \xff\xff\r\n\r\n";
    let server = RawUpgradeServer::start_with_response_bytes(Some(response)).await;
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
        m, "gateway: websocket handshake: status_code=101",
        "non-UTF-8 accept value must mismatch and render status_code=101"
    );
    assert_eq!(m.len(), 45, "Go renders 45 chars for a 101 accept mismatch");
    server.stop();
}

/// Fix loop 3 (ordering): Go's `ReadResponse`
/// returns a malformed-status error BEFORE parsing
/// headers (`response.go:170-186`) — a malformed
/// token + a malformed header renders the token
/// length form (`status_token_length=3`), never the
/// fixed message. Fix loop 2 deferred the status
/// error until after the header block validated,
/// which is true only for a valid code.
#[tokio::test]
async fn ws_upgrade_malformed_token_plus_bad_header_renders_go_status_token_length() {
    let server =
        RawUpgradeServer::start_with_response(Some("HTTP/1.1 ABC Bad\r\nBadHeader\r\n\r\n")).await;
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
        "malformed token must win over a malformed header in Go"
    );
    server.stop();
}

/// Fix loop 3 (proto): Go validates the proto with
/// `ParseHTTPVersion` (`response.go:186`) after the
/// status code and before the headers — `FOO 502`
/// renders the fixed 35-char message, not
/// `status_code=502`.
#[tokio::test]
async fn ws_upgrade_bad_proto_renders_go_fixed_message() {
    let server = RawUpgradeServer::start_with_response(Some("FOO 502 Bar\r\n\r\n")).await;
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
        "bad proto must render Go's fixed message"
    );
    assert_eq!(m.len(), 35, "Go renders 35 chars with no response");
    server.stop();
}

/// Fix loop 3 (first header line): Go's
/// `readMIMEHeader` rejects a header block whose
/// first line starts with SP/HTAB
/// (`textproto/reader.go:538-545`) → resp nil → the
/// fixed 35-char message, even with a valid 502
/// status line.
#[tokio::test]
async fn ws_upgrade_leading_space_first_header_renders_go_fixed_message() {
    let server = RawUpgradeServer::start_with_response(Some(
        "HTTP/1.1 502 Bad Gateway\r\n X-Custom: v\r\n\r\n",
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
        m, "gateway: websocket handshake failed",
        "leading-space first header line must fail the whole response in Go"
    );
    assert_eq!(m.len(), 35, "Go renders 35 chars with no response");
    server.stop();
}

/// Fix loop 3 (duplicate accept): Go consults
/// `resp.Header.Get("Sec-Websocket-Accept")`, which
/// returns the FIRST value — a 101 whose first
/// accept header is wrong and second is right
/// mismatches (`status_code=101`); Rust used to
/// accept if ANY accept header matched. The second
/// header must be the correctly derived key for the
/// client's nonce (random per dial), so a fixed
/// response cannot express this case — the server
/// below derives the key from the request.
#[tokio::test]
async fn ws_upgrade_duplicate_accept_first_wrong_renders_go_status_code_101() {
    let server = start_duplicate_accept_server().await;
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
        m, "gateway: websocket handshake: status_code=101",
        "only the first Sec-WebSocket-Accept counts in Go"
    );
    assert_eq!(m.len(), 45, "Go renders 45 chars for a 101 accept mismatch");
    server.stop();
}

/// A server answering 101 with a duplicated
/// `Sec-WebSocket-Accept`: first "wrong", second the
/// correctly derived key for the client's nonce. Lives
/// here, not in `common/raw_upgrade.rs`, because the
/// fixed-response harness cannot derive the key (random
/// per dial) and clippy's per-target dead-code check
/// fails targets that never construct a shared helper
/// (fix loop 1 pattern). The accept loop is stopped by
/// the test via `stop()`; the client side is bounded by
/// the 20 s `WS_UPGRADE_TIMEOUT` either way.
struct DuplicateAcceptServer {
    addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl DuplicateAcceptServer {
    fn stop(&self) {
        self.task.abort();
    }
}

async fn start_duplicate_accept_server() -> DuplicateAcceptServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let Ok(n) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 || buf.len() > 8192 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).position(|w| w == b"\r\n\r\n").is_some() {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&buf).into_owned();
                let Some(key) = text
                    .split("\r\n")
                    .find_map(|line| line.strip_prefix("Sec-WebSocket-Key:"))
                    .map(str::trim)
                else {
                    return;
                };
                let accept =
                    tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
                let resp = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    DuplicateAcceptServer { addr, task }
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
