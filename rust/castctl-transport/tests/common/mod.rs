// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Shared fake HTTP server for `castctl-transport` integration
//! tests. This is test-only code (never shipped): a minimal
//! HTTP/1.1 server on an ephemeral loopback port that records
//! requests and answers from a caller-supplied responder.
//!
//! No token, cookie or key ever appears here: tests use the
//! literal fake marker `FAKE-TOKEN-TEST-ONLY` and assert it never
//! shows up in errors or logs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// One recorded request. Headers are parsed (for
/// `content-length`) but NOT stored: no test reads them, and
/// keeping a `headers` field nobody reads only invites a
/// future reader to assume request headers are asserted
/// somewhere. If a test ever needs them, add the field back
/// with a test that reads it.
#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

/// Responder: given a request, return (status, headers, body).
pub type Responder =
    Arc<dyn Fn(&RequestRecord) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + Sync>;

pub struct FakeServer {
    pub port: u16,
    pub count: Arc<AtomicUsize>,
    pub records: Arc<Mutex<Vec<RequestRecord>>>,
}

impl FakeServer {
    pub async fn start(responder: Responder) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("INVARIANT: fake server binds loopback");
        let port = listener
            .local_addr()
            .expect("INVARIANT: listener has addr")
            .port();
        let count = Arc::new(AtomicUsize::new(0));
        let records: Arc<Mutex<Vec<RequestRecord>>> = Arc::new(Mutex::new(Vec::new()));
        let count_clone = Arc::clone(&count);
        let records_clone = Arc::clone(&records);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let responder = Arc::clone(&responder);
                let count = Arc::clone(&count_clone);
                let records = Arc::clone(&records_clone);
                tokio::spawn(async move {
                    // Serve multiple requests on one connection
                    // (hyper reuses the connection within a call;
                    // M3 makes one call per connection, but the
                    // loop costs nothing and matches HTTP/1.1).
                    loop {
                        let mut buf = Vec::new();
                        let mut byte = [0u8; 1];
                        let mut header_end: Option<usize> = None;
                        // Read until \r\n\r\n (bounded: 64 KiB).
                        while buf.len() < 65536 {
                            match socket.read(&mut byte).await {
                                Ok(0) => return,
                                Ok(_) => {
                                    buf.push(byte[0]);
                                    if buf.ends_with(b"\r\n\r\n") {
                                        header_end = Some(buf.len());
                                        break;
                                    }
                                }
                                Err(_) => return,
                            }
                        }
                        let Some(header_len) = header_end else {
                            return;
                        };
                        let header_text = String::from_utf8_lossy(&buf[..header_len]).into_owned();
                        let mut lines = header_text.lines();
                        let request_line = lines.next().unwrap_or("").to_string();
                        let mut parts = request_line.split_whitespace();
                        let method = parts.next().unwrap_or("").to_string();
                        let path = parts.next().unwrap_or("").to_string();
                        let mut headers = HashMap::new();
                        for line in lines {
                            if let Some((k, v)) = line.split_once(':') {
                                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                            }
                        }
                        let content_length: usize = headers
                            .get("content-length")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        let mut body = Vec::new();
                        // Any bytes already read past the header
                        // belong to the body (we read byte-wise,
                        // so there are none — but keep the logic
                        // explicit for the next reader).
                        let _ = &mut body;
                        let mut remaining = content_length;
                        while remaining > 0 {
                            let mut chunk = vec![0u8; remaining.min(8192)];
                            match socket.read(&mut chunk).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    body.extend_from_slice(&chunk[..n]);
                                    remaining -= n;
                                }
                                Err(_) => return,
                            }
                        }
                        let record = RequestRecord { method, path, body };
                        count.fetch_add(1, Ordering::SeqCst);
                        records
                            .lock()
                            .expect("INVARIANT: records lock is not poisoned")
                            .push(record.clone());
                        let (status, resp_headers, resp_body) = responder(&record);
                        let reason = match status {
                            200 => "OK",
                            201 => "Created",
                            301 => "Moved Permanently",
                            302 => "Found",
                            400 => "Bad Request",
                            401 => "Unauthorized",
                            403 => "Forbidden",
                            404 => "Not Found",
                            500 => "Internal Server Error",
                            502 => "Bad Gateway",
                            503 => "Service Unavailable",
                            _ => "Status",
                        };
                        let mut response = format!("HTTP/1.1 {status} {reason}\r\n");
                        response.push_str(&format!("content-length: {}\r\n", resp_body.len()));
                        response.push_str("connection: close\r\n");
                        for (k, v) in &resp_headers {
                            response.push_str(&format!("{k}: {v}\r\n"));
                        }
                        response.push_str("\r\n");
                        if socket.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                        if socket.write_all(&resp_body).await.is_err() {
                            return;
                        }
                        let _ = socket.flush().await;
                        // `connection: close` was sent; close after
                        // one request to keep the harness simple.
                        return;
                    }
                });
            }
        });
        Self {
            port,
            count,
            records,
        }
    }

    pub fn requests(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

/// A route table with exactly the methods the RPC tests need,
/// in the `routes.json` shape (the real table is covered by the
/// unit tests in `routes.rs`).
pub fn test_routes() -> castctl_transport::RouteTable {
    castctl_transport::RouteTable::parse(
        r#"[{"method":"connection.ping","http":"GET","path":"/ping"},
            {"method":"chat.history","http":"GET","path":"/chat/history"},
            {"method":"chat.mark_seen","http":"POST","path":"/api/chat/{thread_id}/seen"},
            {"method":"egress.approval.decide","http":"POST","path":"/egress/decide"},
            {"method":"fs.read","http":"POST","path":"/fs/read"}]"#,
    )
    .expect("INVARIANT: test route table parses")
}
