// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Fake gateway server for integration tests: real WS +
//! real Noise (snow responder) + real protobuf framing —
//! no mock of the wire. The server answers `ApplicationRequest`
//! frames with a handler-chosen `ApplicationResponse` and
//! records every request it sees (verb, path, headers, body).
//!
//! Only the *handler* is fake (canned JSON per path), the
//! same role the Go `gatewaytest.Server` plays in the parity
//! gate. Tokens here are fake (`FAKE-TOKEN`) by construction.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use castctl_gateway::framing::{Reassembler, marshal_transport_frame, new_chunk_id, split_pieces};
use castctl_gateway::noise::ResponderHandshake;
use castctl_gateway::proto::{
    ApplicationRequest, ApplicationResponse, Header, NoiseTransportFrame, Reset, ServiceFrame,
    ServiceFrameKind, ServiceRequest, ServiceResponse,
};
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use tokio::net::TcpListener;
use tokio::task::{AbortHandle, JoinHandle};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};

/// What the fake server answers for one request.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: i32,
    pub body: Vec<u8>,
    pub end_body: bool,
    /// Close the connection right after answering.
    pub close_after: bool,
    /// Send the NoiseTransportFrame pieces in reverse order
    /// (reassembly must not depend on arrival order).
    pub shuffle_pieces: bool,
    /// Never answer this request at all (the client's call
    /// times out; the connection stays up).
    pub never_reply: bool,
    /// Close the connection without answering (the client's
    /// in-flight call fails with `ConnectionError`).
    pub close_without_reply: bool,
    /// Answer with a stream `Reset` instead of a `Response`
    /// (code, reason).
    pub reset: Option<(i32, String)>,
}

impl Reply {
    pub fn json(status: i32, body: &str) -> Self {
        Reply {
            status,
            body: body.as_bytes().to_vec(),
            end_body: true,
            close_after: false,
            shuffle_pieces: false,
            never_reply: false,
            close_without_reply: false,
            reset: None,
        }
    }
}

/// Handler: canned JSON per path (mirror of the Go parity
/// server's `{"ok":true,"result":{...}}` per method). Paths
/// are the REAL routes from `internal/proto/routes.json`
/// (not `/v1/...` guesses): connection.ping -> POST
/// `/api/ping`, sessions.list -> GET `/api/session/list`,
/// chat.history -> GET `/chat/history`, feed.list -> GET
/// `/api/feed`, goals.list -> GET `/goals`.
pub fn canned_json(path: &str) -> Reply {
    let body = match path {
        "/api/session/list" => r#"{"ok":true,"result":{"sessions":[{"id":"s1","title":"t1"}]}}"#,
        "/chat/history" => r#"{"ok":true,"result":{"messages":[{"role":"user","text":"hi"}]}}"#,
        "/api/feed" => r#"{"ok":true,"result":{"items":[{"id":"f1"}]}}"#,
        "/goals" => r#"{"ok":true,"result":{"goals":[{"id":"g1","title":"goal"}]}}"#,
        "/api/ping" => r#"{"ok":true,"result":{"pong":true}}"#,
        _ => r#"{"ok":true,"result":{}}"#,
    };
    Reply::json(200, body)
}

pub type HandlerFn = Arc<dyn Fn(&ApplicationRequest) -> Reply + Send + Sync>;

/// One recorded request: (verb, path, body).
pub type RequestRecord = (String, String, Vec<u8>);
/// One recorded request's headers: (key, value) pairs.
pub type HeaderRecord = Vec<(String, String)>;

pub struct FakeServer {
    pub addr: SocketAddr,
    /// Number of `connection.ping` requests received (any
    /// verb/path that maps to the ping route).
    pub ping_count: Arc<AtomicU64>,
    /// (verb, path, body) of every request, in arrival order.
    pub requests: Arc<Mutex<Vec<RequestRecord>>>,
    /// Headers of every request, in arrival order.
    pub headers_seen: Arc<Mutex<Vec<HeaderRecord>>>,
    /// Raw WS upgrade request-targets (`/v1/noise?...`), in
    /// connection order — lets tests assert on the URL the
    /// client actually dialed.
    pub request_targets: Arc<Mutex<Vec<String>>>,
    accept_task: JoinHandle<()>,
    conn_tasks: Arc<Mutex<Vec<AbortHandle>>>,
    listener: Arc<Mutex<Option<TcpListener>>>,
}

impl FakeServer {
    pub async fn start(handler: HandlerFn) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let listener = Arc::new(Mutex::new(Some(listener)));
        let ping_count = Arc::new(AtomicU64::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let headers_seen = Arc::new(Mutex::new(Vec::new()));
        let request_targets = Arc::new(Mutex::new(Vec::new()));
        let conn_tasks: Arc<Mutex<Vec<AbortHandle>>> = Arc::new(Mutex::new(Vec::new()));
        let listener2 = Arc::clone(&listener);
        let ping2 = Arc::clone(&ping_count);
        let req2 = Arc::clone(&requests);
        let hdr2 = Arc::clone(&headers_seen);
        let targets2 = Arc::clone(&request_targets);
        let conns2 = Arc::clone(&conn_tasks);
        let accept_task = tokio::spawn(async move {
            let listener = listener2.lock().unwrap().take().unwrap();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let h = Arc::clone(&handler);
                let ping = Arc::clone(&ping2);
                let req = Arc::clone(&req2);
                let hdr = Arc::clone(&hdr2);
                let targets = Arc::clone(&targets2);
                let task = tokio::spawn(async move {
                    serve_conn(stream, h, ping, req, hdr, targets).await;
                });
                conns2.lock().unwrap().push(task.abort_handle());
            }
        });
        FakeServer {
            addr,
            ping_count,
            requests,
            headers_seen,
            accept_task,
            conn_tasks,
            listener,
            request_targets,
        }
    }

    pub fn ws_url(&self) -> String {
        format!(
            "ws://{}/v1/noise?vm_id=vm-test&auth_token=FAKE-TOKEN-123",
            self.addr
        )
    }

    /// Drop every live connection (simulates a dead conn for
    /// the stale-probe test); the listener stays up.
    pub fn close_all(&self) {
        for h in self.conn_tasks.lock().unwrap().drain(..) {
            h.abort();
        }
    }

    pub fn stop(&self) {
        self.accept_task.abort();
        self.close_all();
        // Dropping the listener closes the port.
        let _ = self.listener.lock().unwrap().take();
    }
}

/// Records the raw WS upgrade request-target, then accepts
/// unchanged. A named `Callback` impl (not a closure): the
/// `ErrorResponse` in its return type is 136 bytes, and
/// clippy's `result_large_err` fires on a closure returning
/// it, while a trait-method implementation keeps the
/// signature the trait dictates.
struct RecordTarget {
    targets: Arc<Mutex<Vec<String>>>,
}

impl Callback for RecordTarget {
    fn on_request(self, req: &Request, resp: Response) -> Result<Response, ErrorResponse> {
        self.targets.lock().unwrap().push(req.uri().to_string());
        Ok(resp)
    }
}

async fn serve_conn(
    stream: tokio::net::TcpStream,
    handler: HandlerFn,
    ping_count: Arc<AtomicU64>,
    requests: Arc<Mutex<Vec<RequestRecord>>>,
    headers_seen: Arc<Mutex<Vec<HeaderRecord>>>,
    request_targets: Arc<Mutex<Vec<String>>>,
) {
    let targets = Arc::clone(&request_targets);
    let ws = match tokio_tungstenite::accept_hdr_async(stream, RecordTarget { targets }).await {
        Ok(ws) => ws,
        Err(_) => return,
    };
    let (mut write, mut read) = ws.split();
    // Noise handshake (responder): msg1 -> msg2 -> msg3.
    let mut hs = match ResponderHandshake::new() {
        Ok(hs) => hs,
        Err(_) => return,
    };
    let msg1 = match read.next().await {
        Some(Ok(WsMessage::Binary(b))) => b.to_vec(),
        _ => return,
    };
    if hs.read_msg1(&msg1).is_err() {
        return;
    }
    let msg2 = match hs.msg2() {
        Ok(m) => m,
        Err(_) => return,
    };
    if write.send(WsMessage::Binary(msg2.into())).await.is_err() {
        return;
    }
    let msg3 = match read.next().await {
        Some(Ok(WsMessage::Binary(b))) => b.to_vec(),
        _ => return,
    };
    if hs.read_msg3(&msg3).is_err() {
        return;
    }
    let transport = match hs.into_transport() {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut reasm = Reassembler::new();
    loop {
        let Some(msg) = read.next().await else {
            return;
        };
        let Ok(WsMessage::Binary(ct)) = msg else {
            continue;
        };
        let Ok(pt) = transport.decrypt(&ct) else {
            return;
        };
        let Ok(frame) = NoiseTransportFrame::decode(pt.as_slice()) else {
            return;
        };
        let Ok(Some(envelope)) = reasm.feed(&frame) else {
            return;
        };
        // Envelope is ASYMMETRIC (Go `gateway.go`
        // `sendEnvelope` vs `readFrame`, and
        // `gatewaytest/server.go` `serveWS`): the client sends
        // ServiceRequest{service, payload: ServiceFrame} and
        // the server answers ServiceResponse{payload:
        // ServiceFrame}. A symmetric guess here fails the
        // client's parse and drops the connection.
        let Ok(sr) = ServiceRequest::decode(envelope.as_slice()) else {
            return;
        };
        let Ok(sf) = ServiceFrame::decode(sr.payload.as_slice()) else {
            return;
        };
        let Some(ServiceFrameKind::Request(app_req)) = sf.kind else {
            continue;
        };
        if app_req.path == "/api/ping" {
            ping_count.fetch_add(1, Ordering::SeqCst);
        }
        requests.lock().unwrap().push((
            app_req.verb.clone(),
            app_req.path.clone(),
            app_req.body.clone(),
        ));
        headers_seen.lock().unwrap().push(
            app_req
                .headers
                .iter()
                .map(|h| (h.key.clone(), h.value.clone()))
                .collect(),
        );
        let reply = handler(&app_req);
        if reply.never_reply {
            continue;
        }
        if reply.close_without_reply {
            return;
        }
        let app_resp = ApplicationResponse {
            status: reply.status,
            headers: vec![Header {
                key: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: reply.body,
            end_body: reply.end_body,
        };
        let out_sf = match reply.reset {
            Some((code, reason)) => ServiceFrame {
                stream_id: sf.stream_id,
                kind: Some(ServiceFrameKind::Reset(Reset { code, reason })),
            },
            None => ServiceFrame {
                stream_id: sf.stream_id,
                kind: Some(ServiceFrameKind::Response(app_resp)),
            },
        };
        // Server -> client envelope: ServiceResponse,
        // NOT ServiceRequest (see the note above).
        let out_resp = ServiceResponse {
            payload: out_sf.encode_to_vec(),
        };
        let out_bytes = out_resp.encode_to_vec();
        let pieces = split_pieces(&out_bytes);
        let chunk_id = new_chunk_id();
        let total = pieces.len() as u32;
        let mut frames: Vec<Vec<u8>> = pieces
            .iter()
            .enumerate()
            .map(|(i, p)| marshal_transport_frame(chunk_id, i as u32, total, p))
            .collect();
        if reply.shuffle_pieces {
            frames.reverse();
        }
        for frame in frames {
            let Ok(ct) = transport.encrypt(&frame) else {
                return;
            };
            if write.send(WsMessage::Binary(ct.into())).await.is_err() {
                return;
            }
        }
        if reply.close_after {
            return;
        }
    }
}
