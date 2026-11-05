// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Minimal raw WS-upgrade server for tests: reads the HTTP
//! upgrade request bytes, records them VERBATIM (no URI
//! parsing), answers 101 with a correct
//! `Sec-WebSocket-Accept`, then closes. It does NOT speak
//! Noise — a dial against it fails at the Noise handshake
//! step, which is exactly what the token-URL tests
//! expect (they assert on the upgrade bytes, not on a
//! round-trip).
//!
//! Why raw: the fake server's tungstenite handshake parses
//! the request-target with `http::Uri`, which rejects
//! `<`/`>` (`invalid uri character`), so it cannot accept
//! — or record — a literal `auth_token=<redacted>` upgrade
//! at all. The live edge accepts the literal (Go proves it;
//! M4b live probe on cue, 2026-11-05), so the wire
//! assertion needs a server that does not parse the target.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// A raw upgrade server. `request_head` holds the full
/// request header block (up to the blank line) of the first
/// connection, verbatim; `sent_101` is true once a 101 was
/// written (i.e. the request was well-formed enough to
/// answer). With `start_with_response`, the server answers
/// every connection with the given bytes verbatim instead
/// of a 101 (for handshake-failure tests: a 502, a
/// malformed status line, …); `sent_101` stays false and
/// the request head is still recorded.
/// `start_with_response_bytes` is the same with raw bytes
/// (for non-UTF-8 responses, which cannot be a `&str`).
pub struct RawUpgradeServer {
    pub addr: SocketAddr,
    request_head: Arc<Mutex<Option<String>>>,
    sent_101: Arc<Mutex<bool>>,
    accept_task: JoinHandle<()>,
}

impl RawUpgradeServer {
    pub async fn start() -> Self {
        Self::start_with_response(None).await
    }

    /// Start a server answering every connection with
    /// `response` verbatim (no 101, no accept derivation).
    /// `None` is the normal 101 behaviour of `start()`.
    pub async fn start_with_response(response: Option<&str>) -> Self {
        Self::start_with_response_bytes(response.map(str::as_bytes)).await
    }

    /// Like `start_with_response`, but the response is raw
    /// bytes — for non-UTF-8 handshake responses.
    pub async fn start_with_response_bytes(response: Option<&[u8]>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let request_head: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let sent_101: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let fixed2 = response.map(<[u8]>::to_vec);
        let head2 = Arc::clone(&request_head);
        let sent2 = Arc::clone(&sent_101);
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let head3 = Arc::clone(&head2);
                let sent3 = Arc::clone(&sent2);
                let fixed3 = fixed2.clone();
                tokio::spawn(async move {
                    serve_one(stream, head3, sent3, fixed3).await;
                });
            }
        });
        RawUpgradeServer {
            addr,
            request_head,
            sent_101,
            accept_task,
        }
    }

    /// The recorded request header block, if a connection arrived.
    pub fn request_head(&self) -> Option<String> {
        self.request_head.lock().unwrap().clone()
    }

    /// True once a 101 response was written.
    pub fn sent_101(&self) -> bool {
        *self.sent_101.lock().unwrap()
    }

    pub fn stop(&self) {
        self.accept_task.abort();
    }
}

async fn serve_one(
    mut stream: tokio::net::TcpStream,
    head: Arc<Mutex<Option<String>>>,
    sent_101: Arc<Mutex<bool>>,
    fixed_response: Option<Vec<u8>>,
) {
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
    *head.lock().unwrap() = Some(text.clone());
    if let Some(response) = fixed_response {
        let _ = stream.write_all(&response).await;
        let _ = stream.shutdown().await;
        return;
    }
    let key = text
        .split("\r\n")
        .find_map(|line| line.strip_prefix("Sec-WebSocket-Key:"))
        .map(str::trim);
    let Some(key) = key else {
        let _ = stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
        return;
    };
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    if stream.write_all(resp.as_bytes()).await.is_ok() {
        *sent_101.lock().unwrap() = true;
    }
    let _ = stream.shutdown().await;
}
