// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Egress proxy tests, ported from
//! `internal/pluginhost/egress_test.go` (12 tests).
//!
//! Forward tests drive the proxy with hyper's http1
//! client (absolute-form URI, like Go's
//! `http.Transport{Proxy: ...}`); CONNECT tests use raw
//! TCP, like the Go tests. The fake upstream records
//! the last request it saw (method, URI, headers, body)
//! and returns a configurable response — the Rust
//! equivalent of `recordingRoundTripper`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use castctl_pluginhost::egress::{
    DialFn, DialStream, EgressProxy, UpstreamResponseFuture, UpstreamTransport,
};
use castctl_pluginhost::host::EgressProxyHandle;

/// The last request the fake upstream saw. `method`
/// and `body` are recorded for fidelity with Go's
/// `recordingRoundTripper` (which keeps the whole
/// request); no test reads them yet.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct RecordedRequest {
    method: http::Method,
    uri: String,
    headers: Vec<(String, String)>,
    body: Bytes,
}

/// Rust equivalent of `recordingRoundTripper`
/// (`egress_test.go:25-42`): records the last request,
/// answers 200 with `X-Upstream: yes` plus any
/// configured response headers.
struct FakeUpstream {
    last: Mutex<Option<RecordedRequest>>,
    body: Mutex<String>,
    response_headers: Mutex<Vec<(String, String)>>,
}

impl FakeUpstream {
    fn new(body: &str) -> Self {
        FakeUpstream {
            last: Mutex::new(None),
            body: Mutex::new(body.to_string()),
            response_headers: Mutex::new(Vec::new()),
        }
    }

    fn set_response_headers(&self, headers: Vec<(String, String)>) {
        *self.response_headers.lock().unwrap() = headers;
    }

    fn last(&self) -> Option<RecordedRequest> {
        self.last.lock().unwrap().clone()
    }

    fn last_header(&self, name: &str) -> String {
        let Some(last) = self.last() else {
            return String::new();
        };
        for (k, v) in &last.headers {
            if k.eq_ignore_ascii_case(name) {
                return v.clone();
            }
        }
        String::new()
    }
}

impl UpstreamTransport for FakeUpstream {
    fn round_trip(&self, req: Request<Full<Bytes>>) -> UpstreamResponseFuture<'_> {
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let bytes = body.collect().await.unwrap().to_bytes();
            let headers: Vec<(String, String)> = parts
                .headers
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            *self.last.lock().unwrap() = Some(RecordedRequest {
                method: parts.method.clone(),
                uri: parts.uri.to_string(),
                headers,
                body: bytes,
            });
            let mut builder = Response::builder().status(StatusCode::OK);
            for (k, v) in self.response_headers.lock().unwrap().iter() {
                builder = builder.header(k.as_str(), v.as_str());
            }
            let body_text = self.body.lock().unwrap().clone();
            Ok(builder
                .header("X-Upstream", "yes")
                .body(Full::new(Bytes::from(body_text)))
                .unwrap())
        })
    }
}

fn basic_auth(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{username}:{password}")
        )
    )
}

/// Drive one absolute-form GET through the proxy with
/// hyper's http1 client; returns (status, headers, body).
async fn proxy_get(
    proxy: &EgressProxy,
    target: &str,
    extra_headers: &[(&str, &str)],
    with_auth: bool,
) -> (StatusCode, http::HeaderMap, Bytes) {
    let stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut builder = http::Request::builder().method("GET").uri(target);
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    if with_auth {
        builder = builder.header(
            "Proxy-Authorization",
            basic_auth(proxy.username(), proxy.password()),
        );
    }
    let req = builder.body(Full::new(Bytes::new())).unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, parts.headers, bytes)
}

/// Open a raw CONNECT tunnel; returns the reader after
/// the status line + headers are drained.
async fn connect_tunnel(proxy: &EgressProxy, target: &str) -> BufReader<tokio::net::TcpStream> {
    let mut conn = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
    conn.write_all(
        format!(
            "CONNECT {target} HTTP/1.1\r\nProxy-Authorization: {}\r\nHost: {target}\r\n\r\n",
            basic_auth(proxy.username(), proxy.password())
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(
        line.contains("200"),
        "CONNECT status line = {line:?}, want 200"
    );
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line == "\r\n" {
            break;
        }
    }
    reader
}

/// A dial function returning one end of a duplex pipe
/// (the Rust equivalent of Go's `net.Pipe`).
fn pipe_dial(server_side: tokio::io::DuplexStream) -> DialFn {
    let slot = Arc::new(Mutex::new(Some(server_side)));
    Arc::new(move |addr: String| {
        let slot = Arc::clone(&slot);
        Box::pin(async move {
            let mut guard = slot.lock().unwrap();
            match guard.take() {
                Some(s) => Ok(Box::pin(s) as DialStream),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("dial called twice for {addr}"),
                )),
            }
        })
    })
}

#[tokio::test]
async fn auth_required() {
    let upstream = Arc::new(FakeUpstream::new("ok"));
    let proxy = EgressProxy::new(upstream.clone(), None, "session-cookie").unwrap();
    // No credentials.
    let (status, headers, _) = proxy_get(&proxy, "http://example.invalid/path", &[], false).await;
    assert_eq!(status, StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    assert_eq!(headers.get("Proxy-Authenticate").unwrap(), "Basic");
    // Wrong credentials (hand-set header; Go's client
    // re-adds it from the URL userinfo).
    let wrong = basic_auth("mallory", "wrong");
    let (status, headers, _) = proxy_get(
        &proxy,
        "http://example.invalid/path",
        &[("Proxy-Authorization", wrong.as_str())],
        false,
    )
    .await;
    assert_eq!(status, StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    assert_eq!(headers.get("Proxy-Authenticate").unwrap(), "Basic");
    assert!(
        upstream.last().is_none(),
        "upstream must not be reached without valid credentials"
    );
    proxy.close();
}

#[tokio::test]
async fn forwards_and_injects_cookie() {
    let upstream = Arc::new(FakeUpstream::new("upstream-ok"));
    let proxy = EgressProxy::new(upstream.clone(), None, "injected-cookie-value").unwrap();
    proxy.set_cookie_hosts(&["example.invalid".to_string()]);
    let (status, headers, body) = proxy_get(
        &proxy,
        "http://example.invalid/path?q=1",
        &[("Cookie", "plugin-cookie"), ("X-Custom", "keep-me")],
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, Bytes::from_static(b"upstream-ok"));
    assert_eq!(headers.get("X-Upstream").unwrap(), "yes");
    let last = upstream.last().expect("upstream not reached");
    assert_eq!(last.uri, "http://example.invalid/path?q=1");
    assert_eq!(upstream.last_header("Cookie"), "injected-cookie-value");
    assert_eq!(upstream.last_header("Proxy-Authorization"), "");
    assert_eq!(upstream.last_header("X-Custom"), "keep-me");
    proxy.close();
}

#[tokio::test]
async fn credentials_ephemeral_and_loopback() {
    let upstream = Arc::new(FakeUpstream::new(""));
    let a = EgressProxy::new(upstream.clone(), None, "").unwrap();
    let b = EgressProxy::new(upstream.clone(), None, "").unwrap();
    assert!(!a.username().is_empty() && !a.password().is_empty());
    assert!(!b.username().is_empty() && !b.password().is_empty());
    assert_ne!(a.username(), b.username());
    assert_ne!(a.password(), b.password());
    for p in [&a, &b] {
        assert!(
            p.url().starts_with("http://127.0.0.1:"),
            "proxy URL = {}, want loopback",
            p.url()
        );
    }
    a.close();
    b.close();
}

#[tokio::test]
async fn connect_without_dialer() {
    let upstream = Arc::new(FakeUpstream::new(""));
    let proxy = EgressProxy::new(upstream, None, "").unwrap();
    let mut conn = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
    conn.write_all(
        format!(
            "CONNECT example.invalid:443 HTTP/1.1\r\nProxy-Authorization: {}\r\nHost: example.invalid:443\r\n\r\n",
            basic_auth(proxy.username(), proxy.password())
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(
        line.contains("502"),
        "CONNECT status line = {line:?}, want 502 without a dialer"
    );
    proxy.close();
}

#[tokio::test]
async fn connect_tunnels() {
    let upstream = Arc::new(FakeUpstream::new(""));
    let (server_side, mut client_side) = tokio::io::duplex(1024);
    let dial = pipe_dial(server_side);
    let proxy = EgressProxy::new(upstream, Some(dial), "").unwrap();
    let mut reader = connect_tunnel(&proxy, "example.invalid:443").await;
    // Echo side: read 5 bytes, answer "pong!".
    tokio::spawn(async move {
        let mut buf = [0u8; 5];
        if client_side.read_exact(&mut buf).await.is_ok() {
            let _ = client_side.write_all(b"pong!").await;
        }
    });
    reader.get_mut().write_all(b"hello").await.unwrap();
    let mut got = [0u8; 5];
    reader.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"pong!");
    proxy.close();
}

#[tokio::test]
async fn close_aborts_tunnels() {
    let upstream = Arc::new(FakeUpstream::new(""));
    let (server_side, _client_side) = tokio::io::duplex(1024);
    let dial = pipe_dial(server_side);
    let proxy = EgressProxy::new(upstream, Some(dial), "").unwrap();
    let mut reader = connect_tunnel(&proxy, "example.invalid:443").await;
    proxy.close();
    // The tunnel must abort PROMPTLY on Close (connection
    // closed), not merely time out on the read deadline.
    let start = std::time::Instant::now();
    let res = tokio::time::timeout(Duration::from_secs(2), reader.read(&mut [0u8; 1])).await;
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(1500),
        "tunnel read after Close took {elapsed:?}"
    );
    match res {
        Ok(Ok(0)) => {} // EOF: tunnel aborted.
        Ok(Ok(_)) => panic!("tunnel read after Close succeeded, want EOF/closed"),
        Ok(Err(e)) => {
            assert_ne!(
                e.kind(),
                std::io::ErrorKind::TimedOut,
                "tunnel read timed out"
            );
        }
        Err(_) => panic!("tunnel read after Close timed out: Close did not abort the tunnel"),
    }
}

#[tokio::test]
async fn close_ignores_double_close() {
    // Close closes the listener explicitly AND via the
    // accept task; the end state (listener closed) is
    // what Close promises. The loop amplifies the race
    // window (CONNECT + immediate Close).
    for _ in 0..10 {
        let upstream = Arc::new(FakeUpstream::new(""));
        let (server_side, _client_side) = tokio::io::duplex(1024);
        let dial = pipe_dial(server_side);
        let proxy = EgressProxy::new(upstream, Some(dial), "").unwrap();
        let _reader = connect_tunnel(&proxy, "example.invalid:443").await;
        proxy.close();
        proxy.close();
    }
}

#[tokio::test]
async fn cookie_scope() {
    let upstream = Arc::new(FakeUpstream::new("ok"));
    let proxy = EgressProxy::new(upstream.clone(), None, "injected-cookie-value").unwrap();
    proxy.set_cookie_hosts(&["declared.invalid".to_string()]);
    let (_, _, _) = proxy_get(
        &proxy,
        "http://declared.invalid/a",
        &[("Cookie", "plugin-cookie")],
        true,
    )
    .await;
    assert_eq!(upstream.last_header("Cookie"), "injected-cookie-value");
    let (_, _, _) = proxy_get(
        &proxy,
        "http://other.invalid/b",
        &[("Cookie", "plugin-cookie")],
        true,
    )
    .await;
    assert_eq!(upstream.last_header("Cookie"), "");
    proxy.set_cookie_hosts(&[]);
    let (_, _, _) = proxy_get(&proxy, "http://declared.invalid/c", &[], true).await;
    assert_eq!(upstream.last_header("Cookie"), "");
    proxy.set_cookie_hosts(&[
        "not a host".to_string(),
        "EXAMPLE.INVALID:443".to_string(),
        "*.invalid".to_string(),
        "ok.invalid".to_string(),
    ]);
    let (_, _, _) = proxy_get(&proxy, "http://ok.invalid/d", &[], true).await;
    assert_eq!(upstream.last_header("Cookie"), "injected-cookie-value");
    proxy.close();
}

#[tokio::test]
async fn strips_set_cookie_and_hop_tokens() {
    let upstream = Arc::new(FakeUpstream::new("ok"));
    upstream.set_response_headers(vec![
        (
            "Set-Cookie".to_string(),
            "hatch_sess=SECRETVALUE; Path=/".to_string(),
        ),
        ("Connection".to_string(), "X-Hop".to_string()),
        ("X-Hop".to_string(), "hop-value".to_string()),
    ]);
    let proxy = EgressProxy::new(upstream.clone(), None, "").unwrap();
    let (status, headers, _) = proxy_get(
        &proxy,
        "http://example.invalid/path",
        &[
            ("Connection", "X-Req-Hop"),
            ("X-Req-Hop", "must-not-forward"),
        ],
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("Set-Cookie"), None);
    assert_eq!(headers.get("X-Hop"), None);
    assert_eq!(upstream.last_header("X-Req-Hop"), "");
    assert_eq!(upstream.last_header("Connection"), "");
    proxy.close();
}

#[tokio::test]
async fn connect_adds_no_cookie() {
    let upstream = Arc::new(FakeUpstream::new(""));
    let (server_side, mut client_side) = tokio::io::duplex(1024);
    let dial = pipe_dial(server_side);
    let proxy = EgressProxy::new(upstream, Some(dial), "injected-cookie-value").unwrap();
    proxy.set_cookie_hosts(&["example.invalid".to_string()]);
    let mut reader = connect_tunnel(&proxy, "example.invalid:443").await;
    let payload = b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n";
    reader.get_mut().write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    client_side.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload, "tunnel bytes must be verbatim");
    proxy.close();
}

#[tokio::test]
async fn close_refuses() {
    let upstream = Arc::new(FakeUpstream::new(""));
    let proxy = EgressProxy::new(upstream, None, "").unwrap();
    let addr = proxy.addr();
    proxy.close();
    let res = tokio::net::TcpStream::connect(addr).await;
    assert!(res.is_err(), "dial after Close succeeded, want refused");
}

#[tokio::test]
async fn duplicate_connection_headers() {
    // Hop-by-hop stripping must honour tokens named in
    // EVERY Connection header line, in both directions.
    // Raw TCP: hyper's client/server transports strip
    // hop-by-hop headers themselves, which would mask a
    // proxy stripping failure.
    let upstream = Arc::new(FakeUpstream::new("ok"));
    upstream.set_response_headers(vec![
        ("Connection".to_string(), "keep-alive".to_string()),
        ("Connection".to_string(), "X-Resp-Leak".to_string()),
        ("X-Resp-Leak".to_string(), "RESPLEAK".to_string()),
        (
            "Set-Cookie".to_string(),
            "hatch_sess=SECRETVALUE; Path=/".to_string(),
        ),
    ]);
    let proxy = EgressProxy::new(upstream.clone(), None, "").unwrap();
    let mut conn = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
    let raw = format!(
        "GET http://example.invalid/path HTTP/1.1\r\nHost: example.invalid\r\nProxy-Authorization: {}\r\nConnection: keep-alive\r\nConnection: X-Leak\r\nX-Leak: LEAKME\r\nX-Keep: yes\r\n\r\n",
        basic_auth(proxy.username(), proxy.password())
    );
    conn.write_all(raw.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(conn);
    let mut head_lines: Vec<String> = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        if line == "\r\n" {
            break;
        }
        head_lines.push(line);
    }
    for line in &head_lines {
        assert!(
            !line.contains("X-Resp-Leak") && !line.contains("RESPLEAK"),
            "response header leaked to plugin: {line:?} (headers {head_lines:?})"
        );
        assert!(
            !line.contains("Set-Cookie"),
            "Set-Cookie leaked to plugin: {line:?}"
        );
    }
    assert!(upstream.last().is_some(), "upstream not reached");
    assert_eq!(upstream.last_header("X-Leak"), "");
    assert_eq!(upstream.last_header("X-Keep"), "yes");
    assert_eq!(upstream.last_header("Proxy-Authorization"), "");
    proxy.close();
}
