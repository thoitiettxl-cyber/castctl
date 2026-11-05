// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Minimal plain-HTTP fake server for the gateway HTTPS
//! side-path tests (auth, subscription): one request per
//! connection, `Connection: close`, a handler-chosen reply
//! per request, every request recorded. Only the *handler* is
//! fake; the client speaks real HTTP/1.1 over a real socket
//! (via `HttpClient` + `DirectDialer`).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// One recorded HTTP request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// One handler-chosen HTTP reply.
#[derive(Debug, Clone)]
pub struct HttpReply {
    pub status: u16,
    /// `""` omits the Content-Type header.
    pub content_type: String,
    pub body: Vec<u8>,
}

impl HttpReply {
    pub fn text(status: u16, content_type: &str, body: &str) -> Self {
        HttpReply {
            status,
            content_type: content_type.to_string(),
            body: body.as_bytes().to_vec(),
        }
    }
}

pub type HttpHandlerFn = Arc<dyn Fn(&HttpRequest) -> HttpReply + Send + Sync>;

pub struct HttpFakeServer {
    pub addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<HttpRequest>>>,
    accept_task: JoinHandle<()>,
}

impl HttpFakeServer {
    pub async fn start(handler: HttpHandlerFn) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests2 = Arc::clone(&requests);
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let h = Arc::clone(&handler);
                let req = Arc::clone(&requests2);
                tokio::spawn(async move {
                    serve_conn(stream, h, req).await;
                });
            }
        });
        HttpFakeServer {
            addr,
            requests,
            accept_task,
        }
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn stop(self) {
        self.accept_task.abort();
    }
}

async fn serve_conn(
    stream: tokio::net::TcpStream,
    handler: HttpHandlerFn,
    requests: Arc<Mutex<Vec<HttpRequest>>>,
) {
    let mut reader = BufReader::new(stream);
    // Read the head (request line + headers) up to a 64 KiB cap.
    let mut head = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => {
                head.extend_from_slice(&buf[..n]);
                if head.len() > 65536 {
                    return;
                }
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let head_end = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(head.len());
    let head_text = String::from_utf8_lossy(&head[..head_end]);
    let mut lines = head_text.lines();
    let Some(request_line) = lines.next() else {
        return;
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().unwrap_or(0);
            }
            headers.push((k, v));
        }
    }
    // Body: bytes already read past the head, then the rest.
    let mut body: Vec<u8> = head[head_end..].to_vec();
    if body.len() < content_length {
        let mut rest = vec![0u8; content_length - body.len()];
        if reader.read_exact(&mut rest).await.is_ok() {
            body.extend_from_slice(&rest);
        }
    }
    body.truncate(content_length);
    let req = HttpRequest {
        method,
        path,
        headers,
        body,
    };
    let reply = handler(&req);
    requests.lock().unwrap().push(req);
    let mut out = Vec::new();
    out.extend_from_slice(
        format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status)).as_bytes(),
    );
    if !reply.content_type.is_empty() {
        out.extend_from_slice(format!("Content-Type: {}\r\n", reply.content_type).as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n", reply.body.len()).as_bytes());
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(&reply.body);
    let mut stream = reader.into_inner();
    let _ = stream.write_all(&out).await;
    let _ = stream.shutdown().await;
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Status",
    }
}
