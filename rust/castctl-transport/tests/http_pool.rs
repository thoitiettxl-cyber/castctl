// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Connection-reuse, gzip and idle-retry tests for `HttpClient`
//! (2026-11-07: the pool, `Accept-Encoding: gzip` and the
//! streaming chunk scan that brought `usage` back to Go's wall
//! time — `rust/AGENT-CLI-SCOPE.md`).
//!
//! The server here is deliberately NOT `common::fake_server`: that
//! one answers exactly one request per connection and closes,
//! which cannot observe pooling. This one counts ACCEPTS (not
//! requests) and keeps the socket open for the next request unless
//! the test asks for a close.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use castctl_transport::dialer::{DialTarget, DirectDialer};
use castctl_transport::http::HttpClient;
use http::Method;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// How the fake server behaves for one test.
#[derive(Clone)]
struct Behaviour {
    /// Response body (already encoded as the test wants it).
    body: Vec<u8>,
    /// Extra response headers, e.g. `Content-Encoding: gzip`.
    response_headers: Vec<(String, String)>,
    /// Add `Connection: close` to every response.
    connection_close: bool,
    /// Close the socket right after the first response, WITHOUT
    /// saying so — the next request on the pooled socket finds a
    /// dead peer.
    close_after_first: bool,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self {
            body: b"ok".to_vec(),
            response_headers: Vec::new(),
            connection_close: false,
            close_after_first: false,
        }
    }
}

struct Server {
    port: u16,
    accepts: Arc<AtomicUsize>,
    /// Raw header block of every request served, in order.
    requests: Arc<Mutex<Vec<String>>>,
}

/// Start the keep-alive fake server. It answers `GET <any>` with
/// the configured behaviour and never inspects the path.
async fn start(behaviour: Behaviour) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("INVARIANT: loopback bind");
    let port = listener.local_addr().expect("INVARIANT: addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let accepts_task = Arc::clone(&accepts);
    let requests_task = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            accepts_task.fetch_add(1, Ordering::SeqCst);
            let behaviour = behaviour.clone();
            let requests = Arc::clone(&requests_task);
            tokio::spawn(async move {
                let mut socket = socket;
                let mut served = 0usize;
                loop {
                    let Some(head) = read_head(&mut socket).await else {
                        return;
                    };
                    requests
                        .lock()
                        .expect("INVARIANT: records lock")
                        .push(head.clone());
                    served += 1;
                    let mut resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n",
                        behaviour.body.len()
                    );
                    for (k, v) in &behaviour.response_headers {
                        resp.push_str(&format!("{k}: {v}\r\n"));
                    }
                    if behaviour.connection_close {
                        resp.push_str("Connection: close\r\n");
                    }
                    resp.push_str("\r\n");
                    let mut out = resp.into_bytes();
                    out.extend_from_slice(&behaviour.body);
                    if socket.write_all(&out).await.is_err() {
                        return;
                    }
                    let _ = socket.flush().await;
                    if behaviour.connection_close || (behaviour.close_after_first && served == 1) {
                        let _ = socket.shutdown().await;
                        return;
                    }
                }
            });
        }
    });
    Server {
        port,
        accepts,
        requests,
    }
}

/// Read one request head (`\r\n\r\n`-terminated) byte by byte, so
/// nothing of the next request on a keep-alive socket is consumed.
async fn read_head(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    while buf.len() < 65536 {
        match socket.read(&mut byte).await {
            Ok(0) => return None,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    return Some(String::from_utf8_lossy(&buf).into_owned());
                }
            }
            Err(_) => return None,
        }
    }
    None
}

fn client() -> HttpClient {
    HttpClient::new(Arc::new(DirectDialer::new()))
}

async fn get(client: &HttpClient, port: u16) -> castctl_transport::http::HttpResponse {
    client
        .request(
            Method::GET,
            &DialTarget::new("127.0.0.1", port),
            "/x",
            &[],
            None,
            Duration::from_secs(5),
        )
        .await
        .expect("request must succeed")
}

fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
}

#[tokio::test]
async fn pool_reuses_one_socket_for_two_requests() {
    let server = start(Behaviour::default()).await;
    let client = client();
    assert_eq!(
        get(&client, server.port).await.body,
        Bytes::from_static(b"ok")
    );
    assert_eq!(
        get(&client, server.port).await.body,
        Bytes::from_static(b"ok")
    );
    assert_eq!(
        server.requests.lock().unwrap().len(),
        2,
        "both requests must reach the server"
    );
    assert_eq!(
        server.accepts.load(Ordering::SeqCst),
        1,
        "the second request must ride the pooled socket, not a new one"
    );
}

#[tokio::test]
async fn connection_close_is_not_pooled() {
    let server = start(Behaviour {
        connection_close: true,
        ..Behaviour::default()
    })
    .await;
    let client = client();
    get(&client, server.port).await;
    get(&client, server.port).await;
    assert_eq!(
        server.accepts.load(Ordering::SeqCst),
        2,
        "a `Connection: close` reply must not be pooled"
    );
}

#[tokio::test]
async fn dead_idle_socket_is_retried_on_a_fresh_connection() {
    let server = start(Behaviour {
        close_after_first: true,
        ..Behaviour::default()
    })
    .await;
    let client = client();
    get(&client, server.port).await;
    // The server closed the socket silently; the pooled sender is
    // now dead. The request must still succeed, on a new socket.
    let second = get(&client, server.port).await;
    assert_eq!(second.body, Bytes::from_static(b"ok"));
    assert_eq!(
        server.requests.lock().unwrap().len(),
        2,
        "the retry must be the SAME request, not a duplicate"
    );
    assert_eq!(
        server.accepts.load(Ordering::SeqCst),
        2,
        "the retry needs a fresh connection"
    );
}

#[tokio::test]
async fn gzip_response_is_decoded_and_the_header_dropped() {
    let plain = b"hello gzip body".to_vec();
    let gz = gzip(&plain);
    let server = start(Behaviour {
        body: gz.clone(),
        response_headers: vec![("Content-Encoding".to_string(), "gzip".to_string())],
        ..Behaviour::default()
    })
    .await;
    let client = client();
    let resp = get(&client, server.port).await;
    assert_eq!(
        resp.body,
        Bytes::from(plain),
        "a gzip reply must be decoded for the caller"
    );
    assert!(
        resp.headers.get(http::header::CONTENT_ENCODING).is_none(),
        "Go's transport removes the header it decoded"
    );
    let head = server.requests.lock().unwrap()[0].clone();
    assert_eq!(
        header_value(&head, "accept-encoding").as_deref(),
        Some("gzip"),
        "the client must advertise gzip like Go's transport does"
    );
}

#[tokio::test]
async fn caller_accept_encoding_wins_and_body_stays_encoded() {
    let gz = gzip(b"leave me encoded");
    let server = start(Behaviour {
        body: gz.clone(),
        response_headers: vec![("Content-Encoding".to_string(), "gzip".to_string())],
        ..Behaviour::default()
    })
    .await;
    let client = client();
    let resp = client
        .request(
            Method::GET,
            &DialTarget::new("127.0.0.1", server.port),
            "/x",
            &[("Accept-Encoding".to_string(), "identity".to_string())],
            None,
            Duration::from_secs(5),
        )
        .await
        .expect("request must succeed");
    let head = server.requests.lock().unwrap()[0].clone();
    assert_eq!(
        header_value(&head, "accept-encoding").as_deref(),
        Some("identity"),
        "a caller-set Accept-Encoding must not be overridden"
    );
    assert_eq!(
        resp.body,
        Bytes::from(gz),
        "without our own gzip the body must pass through untouched"
    );
}

#[tokio::test]
async fn oversized_gzip_body_is_a_gateway_error() {
    // 17 MiB of zeros compresses to a few KiB: the cap must apply
    // AFTER decompression, or a bomb would sail past it.
    let big = vec![0u8; 17 * 1024 * 1024];
    let server = start(Behaviour {
        body: gzip(&big),
        response_headers: vec![("Content-Encoding".to_string(), "gzip".to_string())],
        ..Behaviour::default()
    })
    .await;
    let err = client()
        .request(
            Method::GET,
            &DialTarget::new("127.0.0.1", server.port),
            "/x",
            &[],
            None,
            Duration::from_secs(10),
        )
        .await
        .expect_err("a decompressed body over the cap must fail");
    assert!(
        matches!(err, castctl_transport::error::TransportError::Gateway(_)),
        "over-cap is a server-side Gateway error, got {err:?}"
    );
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).expect("INVARIANT: gzip write");
    enc.finish().expect("INVARIANT: gzip finish")
}
