// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! One authenticated, multiplexed gateway connection (M4a).
//!
//! Go sources: `internal/gateway/gateway.go` (`Gateway`,
//! `newGateway`, `readLoop`, `readFrame`, `sendEnvelope`,
//! `writeWS`, `fail`), `internal/gateway/stream.go` (`open`,
//! `next`, `cancelStream`, `buildPath`, `resolveRoute`,
//! `LookupRoute`, `Alive`, `Dead`, `Close`, `Lease`),
//! `internal/gateway/calls.go` (`Request`, `CallJSON`, `Ping`,
//! `DownloadFile` route only — the download body itself is
//! `Request` with a synthetic route), `internal/gateway/phase.go`
//! (phases are NOT ported: they are metadata only in Go and
//! never change the error type, exit code, or retry decision).
//!
//! Shape: one reader task owns the WS read half + the Noise
//! transport + the reassembler; it decrypts and demultiplexes
//! frames into per-stream unbounded queues. Writers share the
//! WS write half behind a mutex and the Noise transport behind
//! its own mutex (`NoiseTransport`). `last_used` / `last_recv`
//! are updated on send / on every complete `ServiceFrame`
//! (Go updates `lastRecv` per frame in `readLoop`).
//!
//! The WS stream type is erased at construction: the gateway
//! holds a boxed `Stream` (read half) and a boxed `Sink`
//! (write half), so tests can feed it a plain-TCP
//! `WebSocketStream` while production passes the
//! `MaybeTlsStream` one from `dial.rs`.
//!
//! Deviations from Go, all deliberate:
//! - No `Phase`/`PhasedError`: Go documents phases as metadata
//!   only; nothing in this crate (or in `SharedConn` retry)
//!   reads them.
//! - `Dead` is the first fatal reader error as a
//!   `TransportError`, not Go's `classifyDeadLocked`
//!   (`ErrConnectionLost` with NotSent/Sent): the retry layer
//!   only distinguishes `ConnectionDown` (nothing sent —
//!   decided in `open`, before any byte is written) from
//!   `ConnectionError` (after send / mid-stream), and both
//!   are preserved exactly.
//! - `Close` waits at most 1s for the reader task (Go) but
//!   does not wait a further 2s for the write lock: dropping
//!   the sink halves is enough to unblock writers, and the
//!   task is detached (its `JoinHandle` is aborted after the
//!   1s bound) instead of leaking a lock wait.
//! - The reader treats a WS `Close` frame as a fatal
//!   `ConnectionError` ("gateway connection closed"); Go
//!   records the close code/reason for diagnostics but the
//!   error class is the same.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;

use futures_core::Stream;
use futures_sink::Sink;
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use serde_json::Value as JsonValue;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::dial::ws_error;
use crate::framing::{Reassembler, marshal_transport_frame, new_chunk_id, split_pieces};
use crate::noise::NoiseTransport;
use crate::proto::{
    ApplicationRequest, Header, Reset, ResetCode, ServiceFrame, ServiceFrameKind, ServiceRequest,
    ServiceResponse, ServiceType, service_type,
};
use crate::subscribe::{SubscribeHandler, SubscribeOptions};
use castctl_transport::error::{BodySummary, TransportError, validate_error_code};
use castctl_transport::routes::{Route, RouteTable, Service, build_path};

/// Bounds one WS write (Go `internal/gateway/gateway.go:23-25`
/// `WriteDeadline`).
pub const WRITE_DEADLINE: Duration = Duration::from_secs(15);

/// Default bound for one unary call when the caller passes no
/// timeout (Go `internal/gateway/calls.go:20`
/// `DefaultRequestTimeout`).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default bound for a download when the caller passes no
/// timeout (Go `internal/gateway/calls.go:24`
/// `DefaultDownloadTimeout`). Only the route/timeout are used
/// here; downloads ride `Request` (see `download_file`).
pub const DEFAULT_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// Default ping timeout (Go `internal/gateway/calls.go:215-224`:
/// `timeout <= 0` → 10s).
pub const DEFAULT_PING_TIMEOUT: Duration = Duration::from_secs(10);

/// One queued item for a stream: a frame, or a fatal error
/// delivered to a blocked caller (Go `stream.go` `queuedItem`).
/// No `Debug`: the frame may carry response bytes.
enum StreamItem {
    Frame(ServiceFrame),
    Err(TransportError),
}

/// What a request body can be (Go `internal/gateway/jsonutil.go`
/// `encodeBody`): `None` sends no body; `Bytes`/`Text` are sent
/// verbatim; `Json` is JSON-encoded. A `Json` float is never
/// produced by this crate's callers (Go forbids float64 bodies
/// unless they came in as `json.Number`); `serde_json::Value`
/// with the workspace `arbitrary_precision` feature keeps
/// numbers as literals.
#[derive(Clone, Default)]
pub enum Body {
    /// No body.
    #[default]
    None,
    /// Sent verbatim.
    Bytes(Vec<u8>),
    /// Sent verbatim.
    Text(String),
    /// JSON-encoded (object keys sort: `serde_json::Value`
    /// without `preserve_order` is a `BTreeMap`, as in Go's
    /// `json.Marshal` on a `map[string]any`).
    Json(JsonValue),
}

// Hand-written Debug: a body may carry request payload bytes,
// so Debug prints kind/length only, never the bytes.
impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Body::None => write!(f, "None"),
            Body::Bytes(b) => write!(f, "Bytes(len={})", b.len()),
            Body::Text(s) => write!(f, "Text(len={})", s.len()),
            Body::Json(_) => write!(f, "Json"),
        }
    }
}

impl Body {
    /// Encode exactly as Go `encodeBody`; an unencodable value
    /// is a caller-side `Validation` raised before anything is
    /// sent (Go `jsonutil.go:83-87`).
    pub fn encode(&self) -> Result<Option<Vec<u8>>, TransportError> {
        match self {
            Body::None => Ok(None),
            Body::Bytes(b) => Ok(Some(b.clone())),
            Body::Text(s) => Ok(Some(s.clone().into_bytes())),
            Body::Json(v) => {
                serde_json::to_vec(v)
                    .map(Some)
                    .map_err(|e| TransportError::Validation {
                        message: format!("encode body: {e}"),
                    })
            }
        }
    }
}

/// Options for one unary call (Go `internal/conn/gateway.go`
/// `RequestOptions`, minus `Deadline` — the absolute deadline
/// belongs to `SharedConn::retry_call`, not to the gateway).
#[derive(Clone, Default)]
pub struct RequestOptions {
    /// `{k}` path parameters.
    pub path_params: Vec<(String, String)>,
    /// Request body.
    pub body: Body,
    /// Query parameters (`None` values are dropped by the
    /// caller before building; a GET with a non-nil body and
    /// no query moves the body into the query string).
    pub query: Vec<(String, String)>,
    /// Per-call timeout; 0 means `DEFAULT_REQUEST_TIMEOUT`.
    pub timeout: Duration,
    /// Explicit route override (wins over the table lookup).
    pub route: Option<Route>,
}

// Hand-written Debug: counts/flags only — path params, query
// values and the body may carry caller data, so none of them
// is printed (the body prints kind/length only, via its own
// Debug; the route prints presence only, its path template
// never appears).
impl std::fmt::Debug for RequestOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestOptions")
            .field("path_params", &self.path_params.len())
            .field("body", &self.body)
            .field("query", &self.query.len())
            .field("timeout", &self.timeout)
            .field("route", &self.route.is_some())
            .finish()
    }
}

/// Render one scalar the way Python's `str()` does, for GET
/// body→query conversion (Go `internal/gateway/jsonutil.go`
/// `pythonStr`): strings as-is, bools `True`/`False`, numbers
/// decimal, null dropped by the caller.
fn python_str(v: &JsonValue) -> Option<String> {
    match v {
        JsonValue::Null => None,
        JsonValue::Bool(b) => Some(if *b {
            "True".to_string()
        } else {
            "False".to_string()
        }),
        JsonValue::Number(n) => Some(n.to_string()),
        JsonValue::String(s) => Some(s.clone()),
        JsonValue::Array(_) | JsonValue::Object(_) => None,
    }
}

/// A v4 UUID, from OS randomness (Go `stream.go` `uuidV4`).
/// Used for the `x-request-id` header on every request.
pub fn uuid_v4() -> String {
    let mut b: [u8; 16] = rand::random();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

type WsReadHalf =
    Pin<Box<dyn Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>> + Send>>;
type WsWriteHalf =
    Pin<Box<dyn Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error> + Send>>;

/// Generation counter for gateways (Go `gateway.go`
/// `gatewayGenerations`): bumped per gateway so a stale stream
/// queue item can never leak into a new connection. Fencing is
/// structural, not checked: each gateway owns its own stream
/// queues, and a reader that belongs to a closed gateway
/// simply stops delivering; `SharedConn` never bumps or
/// compares generations — on replacement it drops and closes
/// the old gateway (see `SharedConn::live`).
static GATEWAY_GENERATIONS: AtomicU64 = AtomicU64::new(0);

/// One authenticated, multiplexed gateway connection.
/// Safe for concurrent use: any number of tasks may run
/// requests on it at once (Go `gateway.go` `Gateway` doc).
pub struct Gateway {
    // Async mutex: the guard is held across `send().await`
    // in `write_ws`/`close`, and `std::sync::MutexGuard` is
    // `!Send`, which would make every caller future `!Send`.
    write_half: AsyncMutex<WsWriteHalf>,
    transport: Arc<NoiseTransport>,
    routes: Arc<RouteTable>,
    streams: Mutex<HashMap<i64, mpsc::UnboundedSender<StreamItem>>>,
    services: Mutex<HashMap<i64, ServiceType>>,
    next_stream: Mutex<i64>,
    closed: AtomicBool,
    dead: Mutex<Option<TransportError>>,
    last_used: Mutex<Instant>,
    last_recv: Mutex<Instant>,
    sent_any: AtomicBool,
    generation: u64,
    reader: Mutex<Option<JoinHandle<()>>>,
}

impl Gateway {
    /// Build a gateway over an established, Noise-handshaked
    /// WebSocket connection and start its single reader task
    /// (Go `newGateway`). The caller owns the handshake;
    /// `dial::dial_gateway` is the usual constructor.
    pub fn from_handshaked(
        read_half: WsReadHalf,
        write_half: WsWriteHalf,
        transport: Arc<NoiseTransport>,
        routes: Arc<RouteTable>,
    ) -> Arc<Self> {
        let now = Instant::now();
        let gw = Arc::new(Self {
            write_half: AsyncMutex::new(write_half),
            transport,
            routes,
            streams: Mutex::new(HashMap::new()),
            services: Mutex::new(HashMap::new()),
            next_stream: Mutex::new(1),
            closed: AtomicBool::new(false),
            dead: Mutex::new(None),
            last_used: Mutex::new(now),
            last_recv: Mutex::new(now),
            sent_any: AtomicBool::new(false),
            generation: GATEWAY_GENERATIONS.fetch_add(1, Ordering::SeqCst) + 1,
            reader: Mutex::new(None),
        });
        let reader_gw = Arc::clone(&gw);
        let handle = tokio::spawn(async move {
            reader_gw.read_loop(read_half).await;
        });
        if let Ok(mut slot) = gw.reader.lock() {
            *slot = Some(handle);
        }
        gw
    }

    /// Generation of this gateway (see `GATEWAY_GENERATIONS`).
    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn touch_used(&self) {
        if let Ok(mut t) = self.last_used.lock() {
            *t = Instant::now();
        }
    }

    fn touch_recv(&self) {
        if let Ok(mut t) = self.last_recv.lock() {
            *t = Instant::now();
        }
    }

    /// Whether the connection is up: not closed and no fatal
    /// reader error (Go `stream.go` `Alive`).
    pub fn alive(&self) -> bool {
        !self.closed.load(Ordering::SeqCst) && self.dead().is_none()
    }

    /// The fatal error that killed the reader, or `None` when
    /// healthy or closed cleanly (Go `stream.go` `Dead`).
    pub fn dead(&self) -> Option<TransportError> {
        self.dead.lock().ok().and_then(|d| d.clone())
    }

    /// Monotonic time of the last frame received (Go `LastRecv`).
    pub fn last_recv(&self) -> Instant {
        self.last_recv.lock().map(|t| *t).unwrap_or_else(|_| {
            // Lock poisoned: fall back to "just now" so a
            // poisoned clock can never report a stale gateway
            // as fresh, nor a fresh one as stale by a huge age.
            Instant::now()
        })
    }

    /// Monotonic time of the last send (Go `LastUsed`).
    pub fn last_used(&self) -> Instant {
        self.last_used
            .lock()
            .map(|t| *t)
            .unwrap_or_else(|_| Instant::now())
    }

    /// Route lookup (Go `stream.go` `LookupRoute`).
    pub fn lookup_route(&self, method: &str) -> Option<Route> {
        self.routes.lookup_route(method).cloned()
    }

    fn resolve_route(
        &self,
        method: &str,
        override_route: Option<&Route>,
    ) -> Result<Route, TransportError> {
        if let Some(r) = override_route {
            return Ok(r.clone());
        }
        self.lookup_route(method)
            .ok_or_else(|| TransportError::Validation {
                message: format!("unknown method: {method:?}"),
            })
    }

    fn is_down(&self) -> bool {
        !self.alive()
    }

    /// Record the first fatal reader error and deliver it to
    /// every live stream queue, so blocked callers wake with a
    /// `ConnectionError` instead of hanging until their
    /// deadline (Go `gateway.go` `fail`).
    fn fail(&self, err: TransportError) {
        let mut queues = Vec::new();
        if let Ok(mut dead) = self.dead.lock() {
            if !self.closed.load(Ordering::SeqCst) && dead.is_none() {
                *dead = Some(err.clone());
            }
            if let Ok(streams) = self.streams.lock() {
                queues = streams.values().cloned().collect();
            }
        }
        for q in queues {
            let _ = q.send(StreamItem::Err(err.clone()));
        }
    }

    /// Deliver a non-fatal reader error (a reassembly cap
    /// failure) to every currently open stream queue and leave
    /// the gateway alive (Go `deliverToOpenStreams`).
    fn deliver_to_open_streams(&self, err: TransportError) {
        let queues: Vec<_> = self
            .streams
            .lock()
            .map(|s| s.values().cloned().collect())
            .unwrap_or_default();
        for q in queues {
            let _ = q.send(StreamItem::Err(err.clone()));
        }
    }

    /// The single reader task (Go `readLoop` + `readFrame`):
    /// decrypt and demultiplex frames into per-stream queues
    /// until the connection closes or a fatal error arrives. A
    /// reassembly cap failure is NOT fatal: the offending
    /// group is already discarded, the error is delivered to
    /// the open streams, and the reader keeps reading.
    async fn read_loop(self: Arc<Self>, mut read_half: WsReadHalf) {
        let mut reassembler = Reassembler::new();
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return;
            }
            let msg = read_half.next().await;
            let data = match msg {
                Some(Ok(WsMessage::Binary(data))) => data,
                Some(Ok(WsMessage::Close(_))) => {
                    self.fail(TransportError::ConnectionError {
                        message: "gateway connection closed".to_string(),
                    });
                    return;
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => {
                    if self.closed.load(Ordering::SeqCst) {
                        return;
                    }
                    self.fail(ws_error(e));
                    return;
                }
                None => {
                    if self.closed.load(Ordering::SeqCst) {
                        return;
                    }
                    self.fail(TransportError::ConnectionError {
                        message: "gateway connection closed".to_string(),
                    });
                    return;
                }
            };
            let pt = match self.transport.decrypt(&data) {
                Ok(pt) => pt,
                Err(e) => {
                    self.fail(e);
                    return;
                }
            };
            let ntf = match crate::proto::NoiseTransportFrame::decode(pt.as_slice()) {
                Ok(ntf) => ntf,
                Err(_) => {
                    self.fail(TransportError::ConnectionError {
                        message: "gateway transport frame parse failed".to_string(),
                    });
                    return;
                }
            };
            let payload = match reassembler.feed(&ntf) {
                Ok(Some(payload)) => payload,
                Ok(None) => continue,
                Err(cap) => {
                    self.deliver_to_open_streams(cap.into_transport_error());
                    continue;
                }
            };
            let sr = match ServiceResponse::decode(payload.as_slice()) {
                Ok(sr) => sr,
                Err(_) => {
                    self.fail(TransportError::ConnectionError {
                        message: "gateway service response parse failed".to_string(),
                    });
                    return;
                }
            };
            let sf = match ServiceFrame::decode(sr.payload.as_slice()) {
                Ok(sf) => sf,
                Err(_) => {
                    self.fail(TransportError::ConnectionError {
                        message: "gateway service frame parse failed".to_string(),
                    });
                    return;
                }
            };
            self.touch_recv();
            let queue = self
                .streams
                .lock()
                .map(|s| s.get(&sf.stream_id).cloned())
                .unwrap_or(None);
            if let Some(q) = queue {
                let _ = q.send(StreamItem::Frame(sf));
            }
            // Untracked streams (track=false) are dropped here;
            // the reader still reads them off the wire, so the
            // connection stays healthy (Go `readLoop`).
        }
    }

    /// Send one binary WS message with a 15s deadline (Go
    /// `writeWS`). A deadline expiry is a send-timeout
    /// `ConnectionError`.
    async fn write_ws(&self, data: &[u8]) -> Result<(), TransportError> {
        let mut half = self.write_half.lock().await;
        let fut = half.send(WsMessage::Binary(data.to_vec().into()));
        match tokio::time::timeout(WRITE_DEADLINE, fut).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(ws_error(e)),
            Err(_) => Err(TransportError::ConnectionError {
                message: "gateway send timed out".to_string(),
            }),
        }
    }

    /// Wrap frame bytes in a `ServiceRequest`, split them into
    /// 60000-byte `NoiseTransportFrame` pieces sharing one
    /// chunk id, encrypt each piece, and write each ciphertext
    /// as one WS binary frame (Go `sendEnvelope`).
    async fn send_envelope(
        &self,
        service: ServiceType,
        frame_bytes: &[u8],
    ) -> Result<(), TransportError> {
        let outer = ServiceRequest {
            service: service as i32,
            payload: frame_bytes.to_vec(),
        };
        let outer_bytes = outer.encode_to_vec();
        let chunk_id = new_chunk_id();
        let pieces = split_pieces(&outer_bytes);
        for (idx, piece) in pieces.iter().enumerate() {
            let fr_bytes =
                marshal_transport_frame(chunk_id, idx as u32, pieces.len() as u32, piece);
            let ct =
                self.transport
                    .encrypt(&fr_bytes)
                    .map_err(|e| TransportError::ConnectionError {
                        message: format!("gateway encrypt failed: {}", e.log_summary()),
                    })?;
            if idx == 0 {
                // Mark the send BEFORE the first write (Go
                // `sendEnvelope`): the reader can classify a
                // death the moment the peer answers.
                self.sent_any.store(true, Ordering::SeqCst);
            }
            self.write_ws(&ct).await?;
        }
        Ok(())
    }

    fn forget(&self, sid: i64) {
        if let Ok(mut streams) = self.streams.lock() {
            streams.remove(&sid);
        }
        if let Ok(mut services) = self.services.lock() {
            services.remove(&sid);
        }
    }

    fn service_for(&self, sid: i64) -> Option<ServiceType> {
        self.services.lock().ok().and_then(|s| s.get(&sid).copied())
    }

    /// Forget a stream and, when the gateway is alive, send
    /// the CANCELLED reset (code 1) on its service. Send
    /// failures are swallowed (Go `cancelStream`).
    async fn cancel_stream(&self, sid: i64, service: ServiceType) {
        self.forget(sid);
        if !self.alive() {
            return;
        }
        let frame = ServiceFrame {
            stream_id: sid,
            kind: Some(ServiceFrameKind::Reset(Reset {
                code: ResetCode::Cancelled as i32,
                reason: String::new(),
            })),
        };
        let bytes = frame.encode_to_vec();
        let _ = self.send_envelope(service, &bytes).await;
    }

    /// Forget a stream and send its CANCELLED reset on the
    /// service stored at open time; an unknown stream id
    /// defaults to daemon (Go `cancelStreamFor`).
    pub async fn cancel_stream_for(&self, sid: i64) {
        let svc = self.service_for(sid).unwrap_or(ServiceType::ServiceDaemon);
        self.cancel_stream(sid, svc).await;
    }

    /// Start a stream (Go `stream.go` `open`): check the
    /// connection is up BEFORE building or sending anything,
    /// allocate the stream id, register the queue when tracked,
    /// and send the `ApplicationRequest` envelope. On send
    /// failure the stream is forgotten and the send error is
    /// returned. The receiver is handed to the caller: one
    /// `UnboundedReceiver` exists per tracked stream, and the
    /// request loop owns it until the stream ends.
    async fn open(
        &self,
        method: &str,
        path_params: &[(String, String)],
        body: Option<Vec<u8>>,
        query: &[(String, String)],
        route_override: Option<&Route>,
        track: bool,
    ) -> Result<(i64, Route, Option<mpsc::UnboundedReceiver<StreamItem>>), TransportError> {
        if self.is_down() {
            return Err(TransportError::ConnectionDown {
                message: "gateway connection is down".to_string(),
            });
        }
        let route = self.resolve_route(method, route_override)?;
        let mut headers = vec![Header {
            key: "x-request-id".to_string(),
            value: uuid_v4(),
        }];
        if let Some(raw) = &body
            && !raw.is_empty()
        {
            headers.push(Header {
                key: "content-type".to_string(),
                value: "application/json".to_string(),
            });
        }
        let req = ApplicationRequest {
            verb: route.http.clone(),
            path: build_path(&route.path, path_params, query),
            headers,
            body: body.unwrap_or_default(),
            end_body: true,
        };
        let (sid, service, rx) = {
            let mut next =
                self.next_stream
                    .lock()
                    .map_err(|_| TransportError::ConnectionError {
                        message: "gateway: stream lock poisoned".to_string(),
                    })?;
            let sid = *next;
            *next += 1;
            let service = service_type(route.service);
            let rx = if track {
                let (tx, rx) = mpsc::unbounded_channel::<StreamItem>();
                if let Ok(mut streams) = self.streams.lock() {
                    streams.insert(sid, tx);
                }
                Some(rx)
            } else {
                None
            };
            if let Ok(mut services) = self.services.lock() {
                services.insert(sid, service);
            }
            (sid, service, rx)
        };
        let frame = ServiceFrame {
            stream_id: sid,
            kind: Some(ServiceFrameKind::Request(req)),
        };
        let frame_bytes = frame.encode_to_vec();
        self.touch_used();
        if let Err(e) = self.send_envelope(service, &frame_bytes).await {
            self.forget(sid);
            return Err(e);
        }
        Ok((sid, route, rx))
    }

    /// Wait for the next frame on a stream (Go `stream.go`
    /// `next`). A dead gateway with no queued item is a
    /// `ConnectionError` before waiting; a queued fatal error
    /// is a `ConnectionError` wrapping it; a deadline expiry
    /// returns `Ok(None)` (the caller treats it as end-of-wait,
    /// as Go treats `errQueueEmpty`). Cancellation is by
    /// dropping the future (all awaits here are cancel-safe).
    async fn next(
        &self,
        sid: i64,
        rx: &mut mpsc::UnboundedReceiver<StreamItem>,
        timeout: Duration,
    ) -> Result<Option<ServiceFrame>, TransportError> {
        if self.dead().is_some() {
            // A queued item may still be waiting; drain it
            // first so a response that arrived with the fatal
            // error is not lost.
            match rx.try_recv() {
                Ok(StreamItem::Frame(frame)) => return Ok(Some(frame)),
                Ok(StreamItem::Err(err)) => {
                    return Err(TransportError::ConnectionError {
                        message: format!("gateway connection lost: {}", err.log_summary()),
                    });
                }
                Err(_) => {}
            }
            return Err(TransportError::ConnectionError {
                message: format!(
                    "gateway connection is down: {}",
                    self.dead().map(|d| d.log_summary()).unwrap_or_default()
                ),
            });
        }
        let _ = sid;
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(StreamItem::Frame(frame))) => Ok(Some(frame)),
            Ok(Some(StreamItem::Err(err))) => Err(TransportError::ConnectionError {
                message: format!("gateway connection lost: {}", err.log_summary()),
            }),
            Ok(None) => Err(TransportError::ConnectionError {
                message: "gateway connection closed".to_string(),
            }),
            Err(_) => Ok(None),
        }
    }

    /// Perform one unary call and return the raw response
    /// payload bytes (Go `calls.go` `Request`). It gathers
    /// `Response` (status + body chunks, `EndBody`) and
    /// `BodyChunk` frames until `end_body`; a reset is a
    /// `GatewayError(-1, ...)` carrying only the reset code
    /// and the reason's length, never the reason bytes;
    /// expiry with no status is a `TimeoutError`; a status
    /// outside 200–299 is a `GatewayError(status, ...)` —
    /// including 3xx (Q5: exit 3, never `RedirectRefused`).
    /// A stream that ended is forgotten; one that did not end
    /// is cancelled (CANCELLED reset on the route's service).
    /// A GET with a non-nil body and a nil query moves the
    /// body into the query string and sends no body.
    pub async fn request(
        &self,
        method: &str,
        opts: RequestOptions,
    ) -> Result<Vec<u8>, TransportError> {
        let route = self.resolve_route(method, opts.route.as_ref())?;
        let (mut body, mut query) = (opts.body, opts.query);
        if route.http.eq_ignore_ascii_case("get") && !matches!(body, Body::None) && query.is_empty()
        {
            // GET + body + no query: body becomes the query
            // string (Go `calls.go:83-89` `bodyToQuery`).
            let value = match &body {
                Body::Json(v) => v.clone(),
                _ => {
                    return Err(TransportError::Validation {
                        message: "GET body must be a map to convert to query".to_string(),
                    });
                }
            };
            let obj = value
                .as_object()
                .ok_or_else(|| TransportError::Validation {
                    message: "GET body must be a map to convert to query".to_string(),
                })?;
            let mut q = Vec::new();
            for (k, v) in obj {
                if let Some(s) = python_str(v) {
                    q.push((k.clone(), s));
                }
            }
            query = q;
            body = Body::None;
        }
        let raw = body.encode()?;
        let (sid, route, rx) = self
            .open(
                method,
                &opts.path_params,
                raw,
                &query,
                opts.route.as_ref(),
                true,
            )
            .await?;
        let mut rx = match rx {
            Some(rx) => rx,
            None => {
                // Tracked open always returns a receiver.
                self.forget(sid);
                return Err(TransportError::ConnectionError {
                    message: "gateway: tracked stream has no queue".to_string(),
                });
            }
        };
        let timeout = if opts.timeout.as_nanos() == 0 {
            DEFAULT_REQUEST_TIMEOUT
        } else {
            opts.timeout
        };
        let deadline = Instant::now() + timeout;
        let mut status: Option<i32> = None;
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut ended = false;
        let mut saw_frame = false;
        let mut loop_err: Option<TransportError> = None;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match self.next(sid, &mut rx, left).await {
                Ok(Some(frame)) => {
                    saw_frame = true;
                    match frame.kind {
                        Some(ServiceFrameKind::Response(resp)) => {
                            status = Some(resp.status);
                            if !resp.body.is_empty() {
                                chunks.push(resp.body);
                            }
                            if resp.end_body {
                                ended = true;
                            }
                        }
                        Some(ServiceFrameKind::BodyChunk(chunk)) => {
                            chunks.push(chunk.data);
                            if chunk.end_body {
                                ended = true;
                            }
                        }
                        Some(ServiceFrameKind::Reset(reset)) => {
                            ended = true;
                            loop_err = Some(TransportError::Gateway(BodySummary {
                                status: -1,
                                body_length: Some(reset.reason.len()),
                                content_type: None,
                                error_code: None,
                            }));
                        }
                        _ => {
                            // An inbound request frame (or no
                            // kind) is ignored, as Python's
                            // WhichOneof fall-through does.
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    loop_err = Some(e);
                    break;
                }
            }
            if ended {
                break;
            }
        }
        if ended {
            self.forget(sid);
        } else {
            self.cancel_stream(sid, service_type(route.service)).await;
        }
        let _ = saw_frame;
        if let Some(err) = loop_err {
            return Err(err);
        }
        let Some(status) = status else {
            return Err(TransportError::Timeout {
                message: format!("no response for {method}"),
            });
        };
        let mut payload = Vec::new();
        for c in chunks {
            payload.extend_from_slice(&c);
        }
        if !(200..300).contains(&status) {
            // 3xx included: Go `calls.go:168-174` maps ANY
            // non-2xx status to GatewayError(status) → exit 3.
            return Err(TransportError::Gateway(BodySummary {
                status,
                body_length: Some(payload.len()),
                content_type: None,
                error_code: None,
            }));
        }
        Ok(payload)
    }

    /// Decode one raw response the way Go `CallJSON` does
    /// (`calls.go:183-213`): empty body → `{}`; non-JSON →
    /// `GatewayError(-1)` (allowlist summary: body length
    /// only); `{"ok":false}` → `GatewayError(-1)` (only the
    /// `error` field, enum-gated, may be emitted); a `result`
    /// field wins; otherwise the whole decoded value.
    /// Numbers decode with `arbitrary_precision` (literals
    /// preserved, never float64) — the same guarantee as
    /// `castctl-transport` `rpc::decode_response`.
    pub fn decode_call_json(raw: &[u8]) -> Result<JsonValue, TransportError> {
        if raw.is_empty() {
            return Ok(JsonValue::Object(Default::default()));
        }
        let value: JsonValue = serde_json::from_slice(raw).map_err(|_| {
            TransportError::Gateway(BodySummary {
                status: -1,
                body_length: Some(raw.len()),
                content_type: None,
                error_code: None,
            })
        })?;
        if let Some(obj) = value.as_object() {
            if obj.get("ok").and_then(JsonValue::as_bool) == Some(false) {
                let code = obj
                    .get("error")
                    .and_then(JsonValue::as_str)
                    .and_then(validate_error_code);
                return Err(TransportError::Gateway(BodySummary {
                    status: -1,
                    body_length: Some(raw.len()),
                    content_type: None,
                    error_code: code,
                }));
            }
            if let Some(result) = obj.get("result") {
                return Ok(result.clone());
            }
        }
        Ok(value)
    }

    /// Perform one unary call and return the decoded JSON
    /// result (Go `calls.go` `CallJSON`).
    pub async fn call_json(
        &self,
        method: &str,
        opts: RequestOptions,
    ) -> Result<JsonValue, TransportError> {
        let raw = self.request(method, opts).await?;
        Self::decode_call_json(&raw)
    }

    /// Open a `chat.stream` (or any method) as an
    /// untracked stream and return its stream id (Go
    /// `stream.go` `open` with `track=false`). The
    /// caller never reads the stream's own frames — the
    /// turn is followed on `chat.history` instead — so
    /// no receiver is returned; cancel the stream with
    /// [`Gateway::cancel_stream_for`].
    ///
    /// FORCED ADDITION (M5b): `open` is private and no
    /// public stream API existed; the turn engine needs
    /// exactly this to deliver a message. See PORTING.md
    /// §M5b and the PR draft.
    pub async fn open_stream(
        &self,
        method: &str,
        body: Option<JsonValue>,
    ) -> Result<i64, TransportError> {
        let bytes = match body {
            Some(v) => Some(
                serde_json::to_vec(&v).map_err(|e| TransportError::Validation {
                    message: format!("gateway: stream body is not JSON: {e}"),
                })?,
            ),
            None => None,
        };
        let (sid, _, _) = self.open(method, &[], bytes, &[], None, false).await?;
        Ok(sid)
    }

    /// Open a subscription and return the raw NDJSON record
    /// bytes (Go `internal/gateway/calls.go:261-370`
    /// `SubscribeRaw`). Defaults `:266-276` (max 100, idle
    /// 10s, overall 120s); open + `OnOpen` `:278-283`;
    /// `ShouldStop` + `next` 500ms `:290-297`; frame kinds
    /// `:303-320`; line split + blank skip + `OnRecord`
    /// `:322-338`; ended→forget else cancel `:341-345`;
    /// trailing partial `:360-366`. The handler's
    /// `on_record` runs with each record the moment it
    /// arrives; a `true` return stops the subscription right
    /// there. `should_stop` is polled about every 500ms
    /// even while no records arrive. `on_open` runs once the
    /// subscription request is on the wire. Records are
    /// split on `\n`; blank lines are skipped; a trailing
    /// partial buffer is appended as one record (with an
    /// `on_record` call, whose return is ignored there)
    /// unless the subscription was halted. A subscription
    /// that ends is forgotten; one that is stopped is reset
    /// (the connection stays up). `ConnectionDown` is
    /// returned only when the stream never opened: once
    /// `on_open` has fired, connection loss surfaces as
    /// `ConnectionError` (that is what `next` returns).
    /// A loop error drops the gathered records and returns
    /// the error, exactly as Go returns `nil, err` — except
    /// Go also tags the phase (`PhaseSentNoReply` /
    /// `PhaseStreaming`, `:346-359`), which Rust does not
    /// carry (`TransportError` has no phase field).
    pub async fn subscribe_raw(
        &self,
        method: &str,
        opts: SubscribeOptions,
        handler: &mut dyn SubscribeHandler,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        use crate::subscribe::{
            DEFAULT_SUBSCRIBE_IDLE_TIMEOUT, DEFAULT_SUBSCRIBE_MAX_RECORDS,
            DEFAULT_SUBSCRIBE_OVERALL_TIMEOUT, SUBSCRIBE_POLL_INTERVAL, is_blank_bytes,
        };
        let max_records = if opts.max_records <= 0 {
            DEFAULT_SUBSCRIBE_MAX_RECORDS
        } else {
            opts.max_records
        };
        let idle_timeout = if opts.idle_timeout.as_nanos() == 0 {
            DEFAULT_SUBSCRIBE_IDLE_TIMEOUT
        } else {
            opts.idle_timeout
        };
        let overall_timeout = if opts.overall_timeout.as_nanos() == 0 {
            DEFAULT_SUBSCRIBE_OVERALL_TIMEOUT
        } else {
            opts.overall_timeout
        };
        let body = match opts.body {
            Some(v) => Some(
                serde_json::to_vec(&v).map_err(|e| TransportError::Validation {
                    message: format!("gateway: subscribe body is not JSON: {e}"),
                })?,
            ),
            None => None,
        };
        let (sid, _, rx) = self
            .open(
                method,
                &opts.path_params,
                body,
                &opts.query,
                opts.route.as_ref(),
                true,
            )
            .await?;
        let mut rx = match rx {
            Some(rx) => rx,
            None => {
                // Tracked open always returns a receiver.
                self.forget(sid);
                return Err(TransportError::ConnectionError {
                    message: "gateway: tracked stream has no queue".to_string(),
                });
            }
        };
        handler.on_open();
        let mut buf: Vec<u8> = Vec::new();
        let mut records: Vec<Vec<u8>> = Vec::new();
        let deadline = Instant::now() + overall_timeout;
        let mut idle_deadline = Instant::now() + idle_timeout;
        let mut halted = false;
        let mut ended = false;
        let mut saw_frame = false;
        let mut loop_err: Option<TransportError> = None;
        'outer: while !halted && Instant::now() < deadline && (records.len() as i64) < max_records {
            if handler.should_stop() {
                halted = true;
                break;
            }
            match self.next(sid, &mut rx, SUBSCRIBE_POLL_INTERVAL).await {
                Ok(Some(frame)) => {
                    saw_frame = true;
                    idle_deadline = Instant::now() + idle_timeout;
                    match frame.kind {
                        Some(ServiceFrameKind::Response(resp)) => {
                            if !resp.body.is_empty() {
                                buf.extend_from_slice(&resp.body);
                            }
                            if resp.end_body {
                                ended = true;
                                if buf.is_empty() {
                                    break 'outer;
                                }
                            }
                        }
                        Some(ServiceFrameKind::BodyChunk(chunk)) => {
                            buf.extend_from_slice(&chunk.data);
                            if chunk.end_body {
                                ended = true;
                            }
                        }
                        Some(ServiceFrameKind::Reset(_)) => {
                            // A reset ends the stream without
                            // splitting the buffered lines:
                            // the trailing-partial rule below
                            // still appends the whole buffer
                            // as one record, as Go does.
                            ended = true;
                            break 'outer;
                        }
                        _ => {
                            // Other kinds are ignored; the
                            // loop continues.
                        }
                    }
                    loop {
                        let Some(idx) = buf.iter().position(|b| *b == b'\n') else {
                            break;
                        };
                        let line: Vec<u8> = buf.drain(..=idx).collect();
                        let line = &line[..line.len() - 1];
                        if is_blank_bytes(line) {
                            continue;
                        }
                        let rec = line.to_vec();
                        records.push(rec.clone());
                        if handler.on_record(&rec).await {
                            halted = true;
                            break;
                        }
                        if (records.len() as i64) >= max_records {
                            break;
                        }
                    }
                    if ended {
                        break;
                    }
                }
                Ok(None) => {
                    // Queue empty for the poll interval (Go
                    // `errQueueEmpty`): idle bound decides.
                    if Instant::now() > idle_deadline {
                        break;
                    }
                }
                Err(e) => {
                    loop_err = Some(e);
                    break;
                }
            }
        }
        if ended {
            self.forget(sid);
        } else {
            self.cancel_stream(sid, ServiceType::ServiceDaemon).await;
        }
        // `saw_frame` decides Go's error phase (`calls.go:346-359`:
        // `PhaseSentNoReply` vs `PhaseStreaming`); Rust carries no
        // phase, so the flag is recorded and dropped here.
        let _ = saw_frame;
        if let Some(err) = loop_err {
            return Err(err);
        }
        if !halted && !is_blank_bytes(&buf) {
            let rec = buf.clone();
            records.push(rec.clone());
            handler.on_record(&rec).await;
        }
        Ok(records)
    }

    /// The web app's heartbeat: `connection.ping` with
    /// `{"presence":"away"}`, bounded by timeout (10s default
    /// when the timeout is zero) (Go `calls.go` `Ping`).
    pub async fn ping(&self, timeout: Duration) -> Result<JsonValue, TransportError> {
        let timeout = if timeout.as_nanos() == 0 {
            DEFAULT_PING_TIMEOUT
        } else {
            timeout
        };
        let mut body = serde_json::Map::new();
        body.insert(
            "presence".to_string(),
            JsonValue::String("away".to_string()),
        );
        self.call_json(
            "connection.ping",
            RequestOptions {
                body: Body::Json(JsonValue::Object(body)),
                timeout,
                ..Default::default()
            },
        )
        .await
    }

    /// Download a file: `GET /media/raw/…` on the synthetic
    /// route `media.raw` (NOT in routes.json), 300s default
    /// timeout (Go `calls.go` `DownloadFile`). `path` is the
    /// full `/media/raw/…` path (callers use
    /// `MediaPath`-equivalent resolution; this crate does not
    /// parse `sandbox://` refs).
    pub async fn download_file(
        &self,
        path: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, TransportError> {
        let timeout = if timeout.as_nanos() == 0 {
            DEFAULT_DOWNLOAD_TIMEOUT
        } else {
            timeout
        };
        let route = Route {
            method: "media.raw".to_string(),
            http: "GET".to_string(),
            path: path.to_string(),
            service: Service::Daemon,
        };
        self.request(
            "media.raw",
            RequestOptions {
                timeout,
                route: Some(route),
                ..Default::default()
            },
        )
        .await
    }

    /// Close the connection. Idempotent and safe to call
    /// concurrently with a blocked call: marks the gateway
    /// closed, delivers a `ConnectionError` to every live
    /// stream queue, closes the socket (which unblocks the
    /// reader promptly), and waits up to 1s for the reader
    /// task (Go `stream.go` `Close`).
    pub async fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let closed_err = TransportError::ConnectionError {
            message: "gateway connection closed".to_string(),
        };
        let queues: Vec<_> = self
            .streams
            .lock()
            .map(|s| s.values().cloned().collect())
            .unwrap_or_default();
        for q in queues {
            let _ = q.send(StreamItem::Err(closed_err.clone()));
        }
        // Close the write half: dropping the sink closes the
        // socket and unblocks the reader.
        {
            let mut half = self.write_half.lock().await;
            let _ = half.close().await;
        }
        let handle = self.reader.lock().ok().and_then(|mut h| h.take());
        if let Some(handle) = handle {
            let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
        }
    }
}

// Hand-written Debug: a gateway holds Noise key material (via
// the transport); the dial URL is never stored (see `dial.rs`),
// but Debug still prints only shape, never any peer text.
impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let streams = self.streams.lock().map(|s| s.len()).unwrap_or(0);
        write!(
            f,
            "Gateway {{ alive: {}, streams: {}, generation: {} }}",
            self.alive(),
            streams,
            self.generation
        )
    }
}
