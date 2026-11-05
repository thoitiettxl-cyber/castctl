// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Integration tests for `HttpClient::request_tls` (M4b)
//! against the shared plain-HTTP fake server (tokio,
//! ephemeral loopback port): TLS against a plain-HTTP server
//! must fail as `ConnectionDown` — proving the TLS handshake
//! is actually attempted — while the plain `request` against
//! the same server succeeds, proving the failure is the TLS
//! layer and not the dial.

#[path = "common/fake_server.rs"]
mod fake_server;

use std::sync::Arc;
use std::time::Duration;

use castctl_transport::dialer::{DialTarget, DirectDialer};
use castctl_transport::error::TransportError;
use castctl_transport::http::HttpClient;
use fake_server::{FakeServer, Responder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A minimal server that answers every connection with plain
/// HTTP bytes and then closes — exactly what a real plain-HTTP
/// server does to a TLS ClientHello (400 Bad Request). The
/// shared `FakeServer` cannot serve this role: it reads until
/// `\r\n\r\n`, which a binary ClientHello never contains, so
/// client and server would wait on each other until the
/// timeout. No request parsing happens here: the ClientHello
/// is binary and must never be parsed as HTTP.
struct PlainResponder {
    port: u16,
}

impl PlainResponder {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("INVARIANT: plain responder binds loopback");
        let port = listener
            .local_addr()
            .expect("INVARIANT: listener has addr")
            .port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    // Consume the first flight (the ClientHello),
                    // then answer with plain HTTP and close.
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { port }
    }
}

fn http_client() -> HttpClient {
    HttpClient::new(Arc::new(DirectDialer::new()))
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
async fn request_tls_against_plain_http_server_is_connection_down() {
    let server = FakeServer::start(json_responder(200, r#"{"ok":true}"#)).await;
    let client = http_client();
    let target = DialTarget::new("127.0.0.1", server.port);
    // The plain request succeeds against this server: the
    // failure below is the TLS layer, not the dial.
    let plain = client
        .request(
            http::Method::GET,
            &target,
            "/",
            &[],
            None,
            Duration::from_secs(5),
        )
        .await
        .expect("plain request must succeed against the fake server");
    assert_eq!(plain.status.as_u16(), 200);
    // The fake server recorded exactly that one request (this
    // also reads the record fields, so they are not dead code
    // in this target).
    assert_eq!(server.requests(), 1);
    {
        let records = server.records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].method, "GET");
        assert_eq!(records[0].path, "/");
        assert!(records[0].body.is_empty());
    }
    // The TLS attempt goes to a server that answers plain HTTP
    // to a ClientHello: rustls must fail the handshake, which
    // maps to ConnectionDown (nothing sent).
    let plain_server = PlainResponder::start().await;
    let tls_target = DialTarget::new("127.0.0.1", plain_server.port);
    let err = client
        .request_tls(
            http::Method::GET,
            &tls_target,
            "/",
            &[],
            None,
            Duration::from_secs(5),
        )
        .await
        .expect_err("TLS against a plain-HTTP server must fail");
    assert!(
        matches!(err, TransportError::ConnectionDown { .. }),
        "want ConnectionDown, got {err:?}"
    );
    assert_eq!(err.exit_code(), 1);
}

/// F3 (fix loop 1): a server that aborts mid-body pins the
/// `usage --json` transient (`error_length=36` in the first
/// M4b parity run, cause unpinned at the time): hyper's body
/// error is exactly `error reading a body from connection`
/// (36 chars, `hyper-1.12.0/src/error.rs:547`
/// `Kind::Body`), mapped to `ConnectionError` (exit 1) by
/// `http_over_stream` — a server-side reset mid-body, not a
/// client bug. The test must not hang: the request carries a
/// 5s timeout and the server closes after the partial body.
#[tokio::test]
async fn mid_body_abort_is_connection_error_36_chars() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        // Consume the request, then promise 100 body bytes,
        // send 10, and close — the body frame errors.
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf).await;
        let _ = socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n0123456789",
            )
            .await;
        let _ = socket.shutdown().await;
    });
    let client = http_client();
    let target = DialTarget::new("127.0.0.1", port);
    let err = client
        .request(
            http::Method::GET,
            &target,
            "/",
            &[],
            None,
            Duration::from_secs(5),
        )
        .await
        .expect_err("a mid-body abort must fail the request");
    let message = match &err {
        TransportError::ConnectionError { message } => message.clone(),
        other => panic!("want ConnectionError, got {other:?}"),
    };
    assert_eq!(
        message, "error reading a body from connection",
        "hyper's mid-body error text, pinned"
    );
    assert_eq!(message.len(), 36, "the transient's error_length=36");
    assert_eq!(err.exit_code(), 1);
}
