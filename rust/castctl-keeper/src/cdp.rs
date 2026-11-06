// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! A minimal CDP client — the replacement for chromedp in
//! the keeper port.
//!
//! Design (from `research-ws-cdp.md` §6):
//! - `CdpClient` = one browser WebSocket session;
//!   `CdpSession` = one attached target session
//!   (`sessionId`).
//! - JSON-RPC id mapping via an atomic counter + pending
//!   oneshot map + a single reader task; events route by
//!   `sessionId`/`method` to per-session broadcast
//!   channels.
//! - Discovery is plain HTTP over a direct loopback
//!   connection (hyper http1, 5s timeout, body caps 64 KiB
//!   `/json/version` / 1 MiB `/json/list`).
//! - No self-reconnect: the tick/driver retries at a higher
//!   layer. A keepalive Ping runs every 30s.
//! - Bootstrap parity by default: the full chromedp enable
//!   set (see [`CdpSession::bootstrap`]), matching Go —
//!   the live probe decides whether a slimmer set is
//!   equivalent, not reasoning.
//!
//! [CHƯA KIỂM CHỨNG] whether tungstenite flushes Pong
//! replies for a read-only client (the keepalive Ping
//! only proves liveness when the peer answers).
//! (`flatten: true` for `Target.attachToTarget` and the
//! CDP handshake Origin requirement were closed by the
//! live probe, PORTING §M6a.9.)

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};

/// Errors from the CDP client. No cookie, token, or page
/// content is ever carried in an error.
#[derive(Debug, Clone)]
pub enum CdpError {
    /// The `chromedp` feature is off (Go `!with_chromedp`
    /// stub behaviour).
    Unavailable,
    /// I/O error (message only, no payload).
    Io(String),
    /// HTTP discovery error.
    Http(String),
    /// WebSocket error.
    Ws(String),
    /// A CDP error response (`code` + `message`).
    Protocol { code: i64, message: String },
    /// A call or dial exceeded its timeout.
    Timeout,
    /// The connection closed while a call was pending.
    Closed,
}

impl std::fmt::Display for CdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CdpError::Unavailable => write!(f, "CDP unavailable (chromedp feature off)"),
            CdpError::Io(m) => write!(f, "cdp io: {m}"),
            CdpError::Http(m) => write!(f, "cdp http: {m}"),
            CdpError::Ws(m) => write!(f, "cdp websocket: {m}"),
            CdpError::Protocol { code, message } => {
                write!(f, "cdp error {code}: {message}")
            }
            CdpError::Timeout => write!(f, "cdp timeout"),
            CdpError::Closed => write!(f, "cdp connection closed"),
        }
    }
}

impl std::error::Error for CdpError {}

impl From<CdpError> for crate::error::KeeperError {
    fn from(e: CdpError) -> Self {
        match e {
            CdpError::Unavailable => crate::error::KeeperError::ReexportUnavailable,
            other => crate::error::KeeperError::Cdp(other),
        }
    }
}

/// One entry of `/json/list`. Only `id`, `type` and
/// `url` are required: Go's `listTarget`
/// (`screencast.go:143-147`) decodes just those three,
/// and Chrome's `/json/list` omits `title` /
/// `description` / `webSocketDebuggerUrl` on some
/// target kinds (C-2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    pub id: String,
    #[serde(rename = "type")]
    pub target_type: String,
    #[serde(default)]
    pub title: String,
    pub url: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "webSocketDebuggerUrl", default)]
    pub web_socket_debugger_url: String,
    #[serde(rename = "devToolsFrontendUrl", default)]
    pub devtools_frontend_url: String,
}

/// One CDP event (`method` + `params`, optionally scoped to
/// a target session).
#[derive(Debug, Clone)]
pub struct CdpEvent {
    pub method: String,
    pub params: Value,
    pub session_id: Option<String>,
}

/// The `/json/version` response. `webSocketDebuggerUrl`
/// defaults to `""` when absent (Go's typed
/// `versionResponse` decodes only that field; a missing
/// one is the explicit "has no webSocketDebuggerUrl"
/// error, not a parse failure).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserVersionInfo {
    #[serde(rename = "Browser")]
    pub browser: String,
    #[serde(rename = "Protocol-Version")]
    pub protocol_version: String,
    #[serde(rename = "User-Agent")]
    pub user_agent: String,
    #[serde(rename = "V8-Version", default)]
    pub v8_version: String,
    #[serde(rename = "WebKit-Version", default)]
    pub webkit_version: String,
    #[serde(rename = "webSocketDebuggerUrl", default)]
    pub web_socket_debugger_url: String,
}

/// Dial timeout for the CDP WebSocket
/// (`export_cdp.go`: `remote.WithDialTimeout(10s)`).
pub const CDP_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Discovery HTTP timeout (`export_cdp.go`: 5s).
pub const CDP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Body cap for `/json/version` (64 KiB).
pub const VERSION_BODY_CAP: usize = 64 * 1024;
/// Body cap for `/json/list` (1 MiB).
pub const LIST_BODY_CAP: usize = 1024 * 1024;
/// Default per-call timeout. PROVENANCE: this constant
/// has NO Go counterpart — Go relies on the context
/// deadline (chromedp calls carry the caller's `ctx`);
/// the 30s bound is a Rust-side guard so a hung call
/// cannot block the tick forever (C-4).
pub const CDP_CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Keepalive Ping interval.
pub const CDP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// Explicit cap for one incoming CDP WebSocket message
/// (64 MiB). This is tungstenite 0.30.0's
/// `WebSocketConfig::default()` value, set explicitly
/// here so a tungstenite upgrade cannot change it
/// silently (safety NIT-8, review round 2). The cap is
/// enforced when tungstenite assembles a message
/// (`protocol/mod.rs`: `check_max_size`).
pub const CDP_WS_MAX_MESSAGE_SIZE: usize = 64 << 20;

/// Whether the raw URL carries userinfo: an `@` in the
/// AUTHORITY (before the first `/`). The `url` crate
/// cannot tell an empty username (`http://@host/`) from
/// none, but Go's `u.User != nil` rejects both.
fn has_userinfo(raw: &str) -> bool {
    let after_scheme = raw.split_once("://").map(|(_, r)| r).unwrap_or(raw);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    authority.contains('@')
}

/// The port written explicitly in an authority
/// (`host:port`), if any. The `url` crate drops a port
/// equal to the scheme default (`ws`/`http` -> 80) at
/// parse time (`Url::port()` -> `None`), while Go's
/// `u.Port()` returns the written digits (`"80"`).
/// An explicit default port still counts as present
/// (Go accepts it); a missing port must stay an error
/// (Go rejects it). Only the written digits are read —
/// never the scheme default — so a missing port cannot
/// be mistaken for an explicit one.
fn explicit_port(authority: &str) -> Option<u16> {
    // Userinfo is already rejected by the callers, but
    // never let it confuse the host/port split.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let port_str = if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: `[::1]:80` — the port follows
        // the closing bracket.
        rest.split(']').nth(1)?.strip_prefix(':')?
    } else {
        // IPv4/hostname: the port follows the last `:`.
        authority.rsplit_once(':')?.1
    };
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port_str.parse::<u16>().ok()
}

/// The shared loopback host/port check (Go
/// `validateLoopbackURL`, `export_cdp.go:391-418`):
/// loopback host (`net.ParseIP` + `IsLoopback`
/// semantics, `localhost` allowed) and a port in
/// 1..=65535. `authority` is the `host:port` text as
/// written (see `raw_authority`): it is only used to
/// tell an explicit default port (`:80`, dropped by
/// the `url` crate) from a missing port. Returns the
/// host (no brackets) and port.
fn check_loopback_host_port(url: &url::Url, authority: &str) -> Result<(String, u16), CdpError> {
    let host = url
        .host_str()
        .ok_or_else(|| CdpError::Http("browser URL has no host".to_string()))?;
    // `host_str()` keeps IPv6 brackets (`[::1]`);
    // strip them before the loopback check.
    let host = bare_host(host);
    let is_loopback =
        host.eq_ignore_ascii_case("localhost") || castctl_config::keeper::is_loopback_ip(host);
    if !is_loopback {
        return Err(CdpError::Http(format!(
            "browser URL host {host} is not loopback"
        )));
    }
    let port = match url.port() {
        Some(p) => p,
        // `url` drops a port equal to the scheme
        // default at parse time; Go's `u.Port()`
        // returns the written digits, so an explicit
        // `:80` still counts (Go accepts it) while a
        // missing port stays an error (Go rejects it).
        None => explicit_port(authority)
            .ok_or_else(|| CdpError::Http("browser URL has no port".to_string()))?,
    };
    if port == 0 {
        return Err(CdpError::Http("browser URL port out of range".to_string()));
    }
    Ok((host.to_string(), port))
}

/// The host without brackets: `url` 2.5 `host_str()`
/// KEEPS the brackets on an IPv6 literal (`[::1]`),
/// while Go's `u.Hostname()` strips them. Every
/// loopback/IP check and every render must go through
/// this first, or `[::1]` fails `is_loopback_ip` and
/// rendering double-brackets it (`[[::1]]`).
pub fn bare_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// The authority (`host:port`) exactly as written in
/// the input: the `url` crate NORMALIZES an IPv6 literal
/// (`::ffff:127.0.0.1` → `::ffff:7f00:1`) while Go's
/// `u.Hostname()` keeps the literal as written. The
/// discovery base is built from this, so the bytes Go
/// would send (including the `Host` header) are kept.
fn raw_authority(raw: &str) -> &str {
    let after_scheme = raw.split_once("://").map(|(_, r)| r).unwrap_or(raw);
    after_scheme.split('/').next().unwrap_or(after_scheme)
}

/// Validate a discovery base URL the way Go does
/// (`export_cdp.go`): `http` scheme, loopback host, port
/// 1–65535, no userinfo. Returns the normalised
/// `http://host:port` base — the host:port as written
/// (see `raw_authority`), with any path dropped.
pub fn validate_loopback_base(raw: &str) -> Result<String, CdpError> {
    let s = raw.trim();
    let url = url::Url::parse(s).map_err(|e| CdpError::Http(format!("bad browser URL: {e}")))?;
    if url.scheme() != "http" {
        return Err(CdpError::Http(format!(
            "browser URL scheme must be http, got {}",
            url.scheme()
        )));
    }
    if has_userinfo(s) {
        return Err(CdpError::Http(
            "browser URL must not contain userinfo".to_string(),
        ));
    }
    let (_host, _port) = check_loopback_host_port(&url, raw_authority(s))?;
    Ok(format!("http://{}", raw_authority(s)))
}

/// Validate a WebSocket URL the way Go does
/// (`export_cdp.go:391-418` `validateLoopbackURL`):
/// `ws` scheme, loopback host, port 1–65535, no
/// userinfo. `wss://` is rejected fail-closed (Go's
/// `DiscoverWebSocketURL` only ever returns `ws`). The
/// input is used as given (Go returns `raw` for a `ws`
/// input; callers trim before calling when Go trims).
pub fn validate_loopback_ws_url(raw: &str) -> Result<(), CdpError> {
    let url = url::Url::parse(raw).map_err(|e| CdpError::Http(format!("bad browser URL: {e}")))?;
    if url.scheme() != "ws" {
        return Err(CdpError::Http(format!(
            "browser URL scheme must be ws, got {}",
            url.scheme()
        )));
    }
    if has_userinfo(raw) {
        return Err(CdpError::Http(
            "browser URL must not contain userinfo".to_string(),
        ));
    }
    check_loopback_host_port(&url, raw_authority(raw))?;
    Ok(())
}

/// Resolve a keeper `browser` URL to the browser
/// WebSocket URL (Go `DiscoverWebSocketURL`,
/// `export_cdp.go:320-391`): a `ws://` URL is used as
/// given after loopback validation; an `http://` URL
/// goes through a typed GET of `/json/version`, and the
/// returned URL is validated the same way — a version
/// endpoint answering with a remote or non-WebSocket URL
/// is rejected fail-closed. Anything else is an error.
pub async fn discover_websocket_url(http_base: &str) -> Result<String, CdpError> {
    let s = http_base.trim();
    let url = url::Url::parse(s).map_err(|e| CdpError::Http(format!("bad browser URL: {e}")))?;
    match url.scheme() {
        "ws" => {
            validate_loopback_ws_url(s)?;
            Ok(s.to_string())
        }
        "http" => {
            let base = validate_loopback_base(s)?;
            let info: BrowserVersionInfo =
                discovery_get(&base, "/json/version", VERSION_BODY_CAP).await?;
            if info.web_socket_debugger_url.is_empty() {
                return Err(CdpError::Http(
                    "/json/version returned no webSocketDebuggerUrl".to_string(),
                ));
            }
            validate_loopback_ws_url(&info.web_socket_debugger_url)?;
            Ok(info.web_socket_debugger_url)
        }
        other => Err(CdpError::Http(format!(
            "browser URL scheme must be http or ws, got {other}"
        ))),
    }
}

/// GET `{base}/json/list` (5s, 1 MiB cap).
pub async fn list_targets(http_base: &str) -> Result<Vec<TargetInfo>, CdpError> {
    let base = validate_loopback_base(http_base)?;
    discovery_get(&base, "/json/list", LIST_BODY_CAP).await
}

/// GET `{base}/json/version` and return the parsed body.
pub async fn browser_version_info(http_base: &str) -> Result<BrowserVersionInfo, CdpError> {
    let base = validate_loopback_base(http_base)?;
    discovery_get(&base, "/json/version", VERSION_BODY_CAP).await
}

async fn discovery_get<T>(base: &str, path: &str, cap: usize) -> Result<T, CdpError>
where
    T: serde::de::DeserializeOwned,
{
    use http_body_util::BodyExt;
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;

    // The base is a validated loopback `http://host:port`
    // (see `validate_loopback_base`): parse host/port
    // without a URL crate (same shape as
    // `castctl-transport`'s HTTP client, which also drives
    // hyper http1 over a plain stream).
    let rest = base.strip_prefix("http://").unwrap_or(base);
    let hostport = match rest.split_once('/') {
        Some((hp, _)) => hp,
        None => rest,
    };
    // ONE 5s deadline for the whole call (Go
    // `http.Client.Timeout` is total, not per step — C-3).
    let deadline = tokio::time::Instant::now() + CDP_DISCOVERY_TIMEOUT;
    let remaining = || deadline.saturating_duration_since(tokio::time::Instant::now());
    let stream = tokio::time::timeout(remaining(), tokio::net::TcpStream::connect(hostport))
        .await
        .map_err(|_| CdpError::Timeout)?
        .map_err(|e| CdpError::Http(e.to_string()))?;
    let (mut sender, conn) =
        tokio::time::timeout(remaining(), http1::handshake(TokioIo::new(stream)))
            .await
            .map_err(|_| CdpError::Timeout)?
            .map_err(|e| CdpError::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    // Origin-form request-target + explicit Host: Chrome's
    // DevTools HTTP server answers 404 to absolute-form
    // targets (verified on cue 2026-11-06: curl
    // `--request-target http://127.0.0.1:9226/json/version`
    // -> 404, origin-form -> 200). Hyper sends the
    // absolute URI as the target when the request URI is
    // absolute, so the path goes in alone here.
    let req = http::Request::builder()
        .method(http::Method::GET)
        .uri(path)
        .header("Host", hostport)
        .header("Accept", "application/json")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|e| CdpError::Http(e.to_string()))?;
    let resp = tokio::time::timeout(remaining(), sender.send_request(req))
        .await
        .map_err(|_| CdpError::Timeout)?
        .map_err(|e| CdpError::Http(e.to_string()))?;
    // Go requires exactly 200 (`export_cdp.go`:
    // `resp.StatusCode != http.StatusOK`).
    if resp.status() != http::StatusCode::OK {
        return Err(CdpError::Http(format!("GET {path} -> {}", resp.status())));
    }
    let mut body = resp.into_body();
    let mut buf = Vec::new();
    loop {
        let frame = tokio::time::timeout(remaining(), body.frame())
            .await
            .map_err(|_| CdpError::Timeout)?
            .transpose()
            .map_err(|e| CdpError::Http(e.to_string()))?;
        let Some(chunk) = frame else {
            break;
        };
        if let Some(data) = chunk.data_ref() {
            if buf.len() + data.len() > cap {
                return Err(CdpError::Http(format!(
                    "GET {path} body exceeds {cap} bytes"
                )));
            }
            buf.extend_from_slice(data);
        }
    }
    // Go `json.Decoder.Decode` reads the FIRST value and
    // ignores trailing data; `serde_json::from_slice`
    // rejects trailing bytes.
    let mut values = serde_json::Deserializer::from_slice(&buf).into_iter::<T>();
    match values.next() {
        Some(Ok(v)) => Ok(v),
        Some(Err(e)) => Err(CdpError::Http(format!("GET {path}: {e}"))),
        None => Err(CdpError::Http(format!("GET {path}: empty body"))),
    }
}

// ---------------------------------------------------------------------------
// Client (feature-gated real implementation)
// ---------------------------------------------------------------------------

#[cfg(feature = "chromedp")]
mod real {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

    struct Outgoing {
        id: u64,
        session_id: Option<String>,
        method: String,
        params: Value,
        responder: oneshot::Sender<Result<Value, CdpError>>,
    }

    /// In-flight JSON-RPC calls by id: the reader task
    /// completes the matching oneshot when the response
    /// arrives.
    type PendingCalls = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, CdpError>>>>>;

    struct Shared {
        tx: mpsc::Sender<Outgoing>,
        next_id: AtomicU64,
        browser_events: broadcast::Sender<CdpEvent>,
        sessions: Arc<Mutex<HashMap<String, broadcast::Sender<CdpEvent>>>>,
    }

    /// One browser WebSocket session.
    pub struct CdpClient {
        shared: Arc<Shared>,
    }

    /// One attached target session.
    pub struct CdpSession {
        shared: Arc<Shared>,
        target_id: String,
        session_id: String,
        events: broadcast::Sender<CdpEvent>,
    }

    impl CdpClient {
        /// Dial the browser WebSocket URL (10s timeout,
        /// `export_cdp.go`). The URL is loopback-validated
        /// before dialing (F3): a remote or `wss://` URL
        /// is refused fail-closed here, not just in
        /// discovery.
        pub async fn connect(ws_url: &str) -> Result<Self, CdpError> {
            validate_loopback_ws_url(ws_url)?;
            // Explicit message cap (see
            // `CDP_WS_MAX_MESSAGE_SIZE`): identical to
            // `connect_async`'s defaults (`None, false`)
            // except the cap is spelled out instead of
            // inherited from tungstenite's default.
            // `WebSocketConfig` is `#[non_exhaustive]`,
            // so the cap is set with its builder method.
            let ws_config =
                WebSocketConfig::default().max_message_size(Some(CDP_WS_MAX_MESSAGE_SIZE));
            let (ws, _) = tokio::time::timeout(
                CDP_DIAL_TIMEOUT,
                tokio_tungstenite::connect_async_with_config(ws_url, Some(ws_config), false),
            )
            .await
            .map_err(|_| CdpError::Timeout)?
            .map_err(|e| CdpError::Ws(e.to_string()))?;
            let (mut write, read) = ws.split();
            let (tx, mut rx) = mpsc::channel::<Outgoing>(64);
            let (browser_tx, _) = broadcast::channel::<CdpEvent>(256);
            let shared = Arc::new(Shared {
                tx,
                next_id: AtomicU64::new(1),
                browser_events: browser_tx,
                sessions: Arc::new(Mutex::new(HashMap::new())),
            });
            let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));
            // Reader: route responses by id, events by
            // sessionId.
            {
                let pending = pending.clone();
                let browser_tx = shared.browser_events.clone();
                let sessions = shared.sessions.clone();
                tokio::spawn(async move {
                    let mut read = read;
                    while let Some(msg) = read.next().await {
                        let msg = match msg {
                            Ok(m) => m,
                            Err(_) => break,
                        };
                        let text = match msg {
                            Message::Text(t) => t.to_string(),
                            Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                            Message::Ping(_) | Message::Pong(_) | Message::Close(_) => continue,
                            Message::Frame(_) => continue,
                        };
                        let v: Value = match serde_json::from_str(&text) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        if let Some(id) = v.get("id").and_then(|i| i.as_u64()) {
                            let responder = pending.lock().await.remove(&id);
                            if let Some(tx) = responder {
                                let res = if let Some(err) = v.get("error") {
                                    Err(CdpError::Protocol {
                                        code: err
                                            .get("code")
                                            .and_then(|c| c.as_i64())
                                            .unwrap_or(-1),
                                        message: err
                                            .get("message")
                                            .and_then(|m| m.as_str())
                                            .unwrap_or("cdp error")
                                            .to_string(),
                                    })
                                } else {
                                    Ok(v.get("result").cloned().unwrap_or(Value::Null))
                                };
                                let _ = tx.send(res);
                            }
                            continue;
                        }
                        if let Some(method) = v.get("method").and_then(|m| m.as_str()) {
                            let ev = CdpEvent {
                                method: method.to_string(),
                                params: v.get("params").cloned().unwrap_or(Value::Null),
                                session_id: v
                                    .get("sessionId")
                                    .and_then(|s| s.as_str())
                                    .map(|s| s.to_string()),
                            };
                            match &ev.session_id {
                                Some(sid) => {
                                    let map = sessions.lock().await;
                                    if let Some(tx) = map.get(sid) {
                                        let _ = tx.send(ev);
                                    }
                                }
                                None => {
                                    let _ = browser_tx.send(ev);
                                }
                            }
                        }
                    }
                    // Stream ended: fail every pending call.
                    let mut map = pending.lock().await;
                    for (_, tx) in map.drain() {
                        let _ = tx.send(Err(CdpError::Closed));
                    }
                });
            }
            // Writer: serialise outgoing calls; keepalive
            // Ping every 30s.
            {
                let pending = pending.clone();
                tokio::spawn(async move {
                    let mut keepalive = tokio::time::interval(CDP_KEEPALIVE_INTERVAL);
                    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tokio::select! {
                            _ = keepalive.tick() => {
                                if write.send(Message::Ping(bytes::Bytes::new())).await.is_err() {
                                    break;
                                }
                            }
                            out = rx.recv() => {
                                let Some(out) = out else { break };
                                let mut msg = serde_json::json!({
                                    "id": out.id,
                                    "method": out.method,
                                    "params": out.params,
                                });
                                if let Some(sid) = &out.session_id {
                                    msg["sessionId"] = Value::String(sid.clone());
                                }
                                let text = match serde_json::to_string(&msg) {
                                    Ok(t) => t,
                                    Err(_) => {
                                        let _ = out.responder.send(Err(CdpError::Ws("cannot encode call".to_string())));
                                        continue;
                                    }
                                };
                                pending.lock().await.insert(out.id, out.responder);
                                if write.send(Message::Text(text.into())).await.is_err() {
                                    pending.lock().await.remove(&out.id);
                                    break;
                                }
                            }
                        }
                    }
                });
            }
            Ok(Self { shared })
        }

        /// Call a method on the browser session.
        pub async fn call(&self, method: &str, params: Value) -> Result<Value, CdpError> {
            self.call_inner(None, method, params).await
        }

        async fn call_inner(
            &self,
            session_id: Option<String>,
            method: &str,
            params: Value,
        ) -> Result<Value, CdpError> {
            let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = oneshot::channel();
            self.shared
                .tx
                .send(Outgoing {
                    id,
                    session_id,
                    method: method.to_string(),
                    params,
                    responder: tx,
                })
                .await
                .map_err(|_| CdpError::Closed)?;
            tokio::time::timeout(CDP_CALL_TIMEOUT, rx)
                .await
                .map_err(|_| CdpError::Timeout)?
                .map_err(|_| CdpError::Closed)?
        }

        /// `Browser.getVersion`.
        pub async fn version(&self) -> Result<Value, CdpError> {
            self.call("Browser.getVersion", Value::Object(Default::default()))
                .await
        }

        /// Attach to a target and return its session
        /// (`Target.attachToTarget`, `flatten: true` —
        /// [CHƯA KIỂM CHỨNG] on the wire here).
        pub async fn attach(&self, target_id: &str) -> Result<CdpSession, CdpError> {
            let res = self
                .call(
                    "Target.attachToTarget",
                    serde_json::json!({"targetId": target_id, "flatten": true}),
                )
                .await?;
            let session_id = res
                .get("sessionId")
                .and_then(|s| s.as_str())
                .ok_or_else(|| CdpError::Protocol {
                    code: -1,
                    message: "attachToTarget returned no sessionId".to_string(),
                })?
                .to_string();
            let (tx, _) = broadcast::channel::<CdpEvent>(256);
            self.shared
                .sessions
                .lock()
                .await
                .insert(session_id.clone(), tx.clone());
            Ok(CdpSession {
                shared: self.shared.clone(),
                target_id: target_id.to_string(),
                session_id,
                events: tx,
            })
        }

        /// Close a target (`Target.closeTarget`).
        /// Best-effort at the call site: the browser may
        /// already be gone.
        pub async fn close_target(&self, target_id: &str) -> Result<Value, CdpError> {
            self.call(
                "Target.closeTarget",
                serde_json::json!({"targetId": target_id}),
            )
            .await
        }

        /// Browser-level events (no `sessionId`).
        pub fn events(&self) -> broadcast::Receiver<CdpEvent> {
            self.shared.browser_events.subscribe()
        }
    }

    impl CdpSession {
        /// The target this session is attached to.
        pub fn target_id(&self) -> &str {
            &self.target_id
        }

        /// The CDP session id.
        pub fn session_id(&self) -> &str {
            &self.session_id
        }

        /// Call a method on this target session.
        pub async fn call(&self, method: &str, params: Value) -> Result<Value, CdpError> {
            let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = oneshot::channel();
            self.shared
                .tx
                .send(Outgoing {
                    id,
                    session_id: Some(self.session_id.clone()),
                    method: method.to_string(),
                    params,
                    responder: tx,
                })
                .await
                .map_err(|_| CdpError::Closed)?;
            tokio::time::timeout(CDP_CALL_TIMEOUT, rx)
                .await
                .map_err(|_| CdpError::Timeout)?
                .map_err(|_| CdpError::Closed)?
        }

        /// Events routed to this session.
        pub fn events(&self) -> broadcast::Receiver<CdpEvent> {
            self.events.subscribe()
        }

        /// The chromedp bootstrap enable set (wire order
        /// observed from chromedp v0.21.0, `research-ws-cdp.md`
        /// §3.2): `Runtime.enable`, then the constant
        /// `Runtime.evaluate("self")`, then Log, Network,
        /// Inspector, Page, DOM and CSS, `Target.setDiscoverTargets`,
        /// `Target.setAutoAttach`, `Page.setLifecycleEventsEnabled`,
        /// then the frame load (`Page.getFrameTree` with
        /// empty params, `chromedp.go` `newTarget`) and the
        /// document root (`DOM.getDocument` with empty
        /// params, `target.go` `documentUpdated`).
        pub async fn bootstrap(&self) -> Result<(), CdpError> {
            let empty = || Value::Object(Default::default());
            self.call("Runtime.enable", empty()).await?;
            // Liveness probe only: the result is discarded.
            // NEVER set `returnByValue: true` here: serialising
            // the window object fails with CDP -32000 ("Object
            // reference chain is too long") on every page, which
            // broke the whole bootstrap (and with it the keeper
            // CDP export, M7c fix loop 1 item 5). Without it
            // the call returns a reference and succeeds.
            self.call(
                "Runtime.evaluate",
                serde_json::json!({"expression": "self"}),
            )
            .await?;
            self.call("Log.enable", empty()).await?;
            self.call("Network.enable", empty()).await?;
            self.call("Inspector.enable", empty()).await?;
            self.call("Page.enable", empty()).await?;
            self.call("DOM.enable", empty()).await?;
            self.call("CSS.enable", empty()).await?;
            self.call(
                "Target.setDiscoverTargets",
                serde_json::json!({"discover": true}),
            )
            .await?;
            self.call(
                "Target.setAutoAttach",
                serde_json::json!({"autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true}),
            )
            .await?;
            self.call(
                "Page.setLifecycleEventsEnabled",
                serde_json::json!({"enabled": true}),
            )
            .await?;
            self.call("Page.getFrameTree", empty()).await?;
            self.call("DOM.getDocument", empty()).await?;
            Ok(())
        }

        /// Detach from the target.
        pub async fn detach(&self) -> Result<(), CdpError> {
            // Detach is a browser-session call.
            let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = oneshot::channel();
            let res = async {
                self.shared
                    .tx
                    .send(Outgoing {
                        id,
                        session_id: None,
                        method: "Target.detachFromTarget".to_string(),
                        params: serde_json::json!({"sessionId": self.session_id}),
                        responder: tx,
                    })
                    .await
                    .map_err(|_| CdpError::Closed)?;
                tokio::time::timeout(CDP_CALL_TIMEOUT, rx)
                    .await
                    .map_err(|_| CdpError::Timeout)?
                    .map_err(|_| CdpError::Closed)
            }
            .await;
            // The session leaves the router whether the
            // detach call succeeded or not (C-6): a failed
            // detach must not leave a stale route that
            // swallows later events for a recycled
            // session id.
            self.shared.sessions.lock().await.remove(&self.session_id);
            res.map(|_| ())
        }
    }
}

#[cfg(feature = "chromedp")]
pub use real::{CdpClient, CdpSession};

#[cfg(not(feature = "chromedp"))]
mod stub {
    use super::*;

    /// Stub client: every CDP operation refuses with the
    /// typed unavailable error (Go `!with_chromedp`).
    pub struct CdpClient;

    /// Stub session: never constructed.
    pub struct CdpSession;

    impl CdpClient {
        pub async fn connect(_ws_url: &str) -> Result<Self, CdpError> {
            Err(CdpError::Unavailable)
        }

        pub async fn call(&self, _method: &str, _params: Value) -> Result<Value, CdpError> {
            Err(CdpError::Unavailable)
        }

        pub async fn version(&self) -> Result<Value, CdpError> {
            Err(CdpError::Unavailable)
        }

        pub async fn attach(&self, _target_id: &str) -> Result<CdpSession, CdpError> {
            Err(CdpError::Unavailable)
        }

        pub async fn close_target(&self, _target_id: &str) -> Result<Value, CdpError> {
            Err(CdpError::Unavailable)
        }

        pub fn events(&self) -> broadcast::Receiver<CdpEvent> {
            let (_, rx) = broadcast::channel(1);
            rx
        }
    }

    impl CdpSession {
        pub fn target_id(&self) -> &str {
            ""
        }

        pub fn session_id(&self) -> &str {
            ""
        }

        pub async fn call(&self, _method: &str, _params: Value) -> Result<Value, CdpError> {
            Err(CdpError::Unavailable)
        }

        pub fn events(&self) -> broadcast::Receiver<CdpEvent> {
            let (_, rx) = broadcast::channel(1);
            rx
        }

        pub async fn bootstrap(&self) -> Result<(), CdpError> {
            Err(CdpError::Unavailable)
        }

        pub async fn detach(&self) -> Result<(), CdpError> {
            Err(CdpError::Unavailable)
        }
    }
}

#[cfg(not(feature = "chromedp"))]
pub use stub::{CdpClient, CdpSession};

/// `CDPAvailable` (Go `export_cdp.go` / stub): whether
/// this build can speak CDP at all.
pub const CDP_AVAILABLE: bool = cfg!(feature = "chromedp");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_loopback_base_rejects_non_loopback() {
        assert!(validate_loopback_base("http://127.0.0.1:9226").is_ok());
        assert!(validate_loopback_base("http://localhost:9226").is_ok());
        assert!(validate_loopback_base("http://example.com:9226").is_err());
        assert!(validate_loopback_base("https://127.0.0.1:9226").is_err());
        assert!(validate_loopback_base("http://127.0.0.1").is_err());
        assert!(validate_loopback_base("http://user@127.0.0.1:9226").is_err());
    }

    #[test]
    fn validate_loopback_go_parity_pins() {
        // F4: a "127." prefix is not loopback — the
        // suffix host must not pass, and `[::1]` must.
        assert!(validate_loopback_base("http://127.0.0.1.evil.com:9226").is_err());
        assert_eq!(
            validate_loopback_base("http://[::1]:9226").unwrap(),
            "http://[::1]:9226"
        );
        assert_eq!(
            validate_loopback_base("http://[::ffff:127.0.0.1]:9226").unwrap(),
            "http://[::ffff:127.0.0.1]:9226"
        );
        assert!(validate_loopback_base("http://[::ffff:192.168.0.1]:9226").is_err());
        // An empty username is still userinfo (Go
        // `u.User != nil`).
        assert!(validate_loopback_base("http://@127.0.0.1:9226").is_err());
        // F3: a direct ws URL is accepted only when it is
        // a loopback `ws://` URL; `wss://` and remote
        // hosts are refused fail-closed, before any dial.
        assert!(validate_loopback_ws_url("ws://127.0.0.1:9226/devtools/browser/abc").is_ok());
        assert!(validate_loopback_ws_url("ws://[::1]:9226/devtools/browser/abc").is_ok());
        assert!(validate_loopback_ws_url("wss://127.0.0.1:9226/devtools/browser/abc").is_err());
        assert!(validate_loopback_ws_url("ws://example.com:9226/devtools/browser/abc").is_err());
        assert!(validate_loopback_ws_url("ws://user@127.0.0.1:9226/devtools/browser/abc").is_err());
        assert!(validate_loopback_ws_url("ws://127.0.0.1/devtools/browser/abc").is_err());
        assert!(validate_loopback_ws_url("ws://127.0.0.1:0/devtools/browser/abc").is_err());
    }

    #[test]
    fn validate_loopback_default_port_is_explicit() {
        // N1 (review round 2): the `url` crate drops a
        // port equal to the scheme default at parse time
        // (`ws`/`http` -> 80), but Go's `u.Port()`
        // returns the written digits, so an explicit
        // `:80` still counts as a port (Go accepts it).
        // A missing port must stay an error (Go rejects
        // it). Probed against Go 1.26.8 `net/url` on cue
        // 2026-11-06: `ws://127.0.0.1:80/x` -> port
        // "80"; `ws://127.0.0.1/x` -> port "".
        assert!(validate_loopback_ws_url("ws://127.0.0.1:80/devtools/browser/abc").is_ok());
        assert!(validate_loopback_ws_url("ws://127.0.0.1:443/devtools/browser/abc").is_ok());
        assert!(validate_loopback_ws_url("ws://127.0.0.1:080/devtools/browser/abc").is_ok());
        assert!(validate_loopback_ws_url("ws://[::1]:80/devtools/browser/abc").is_ok());
        assert_eq!(
            validate_loopback_base("http://127.0.0.1:80").unwrap(),
            "http://127.0.0.1:80"
        );
        assert_eq!(
            validate_loopback_base("http://[::1]:80").unwrap(),
            "http://[::1]:80"
        );
        // No port at all is still an error (Go:
        // `u.Port() == ""`).
        assert!(validate_loopback_ws_url("ws://127.0.0.1/devtools/browser/abc").is_err());
        assert!(validate_loopback_base("http://127.0.0.1").is_err());
    }

    #[test]
    fn validate_loopback_uppercase_scheme_matches_go() {
        // Safety NIT-3 (review round 2) claimed Go
        // rejects an uppercase scheme — WRONG. Go's
        // `net/url.Parse` lowercases the scheme
        // (probed on cue 2026-11-06, go1.26.8:
        // `WS://127.0.0.1:9226/x` -> scheme "ws",
        // `HTTP://127.0.0.1:9226/` -> scheme "http"),
        // and the `url` crate does the same, so Rust
        // already matches Go here. No code change;
        // this pin locks the Go-parity behaviour so a
        // future "fix" does not break it.
        assert!(validate_loopback_ws_url("WS://127.0.0.1:9226/devtools/browser/abc").is_ok());
        assert!(validate_loopback_ws_url("Ws://127.0.0.1:9226/devtools/browser/abc").is_ok());
        assert_eq!(
            validate_loopback_base("HTTP://127.0.0.1:9226").unwrap(),
            "http://127.0.0.1:9226"
        );
    }

    #[test]
    #[cfg(feature = "chromedp")]
    fn ws_max_message_size_is_explicit_64mib() {
        // Safety NIT-8 (review round 2): the 64 MiB cap
        // used to come from tungstenite's default; the
        // connect path now sets it explicitly, so a
        // tungstenite upgrade cannot change it silently.
        // This pin fails if the library default ever
        // moves away from the value we rely on.
        use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
        assert_eq!(CDP_WS_MAX_MESSAGE_SIZE, 64 << 20);
        assert_eq!(
            WebSocketConfig::default().max_message_size,
            Some(CDP_WS_MAX_MESSAGE_SIZE)
        );
    }

    #[test]
    fn url_host_str_keeps_ipv6_brackets() {
        // Pins the `url` 2.5 behaviour `bare_host`
        // depends on: `host_str()` keeps the brackets
        // on an IPv6 literal, unlike Go's `u.Hostname()`.
        let u = url::Url::parse("http://[::1]:9226").unwrap();
        assert_eq!(u.host_str(), Some("[::1]"));
        assert_eq!(bare_host("[::1]"), "::1");
        assert_eq!(bare_host("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn target_info_optional_fields_default() {
        // C-2: Go decodes only id/type/url; the rest
        // default when absent.
        let raw = r#"[{"id":"ABC","type":"page","url":"about:blank"}]"#;
        let targets: Vec<TargetInfo> = serde_json::from_str(raw).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].title, "");
        assert_eq!(targets[0].web_socket_debugger_url, "");
    }

    #[test]
    fn target_info_parses_json_list_shape() {
        let raw = r#"[{"description":"","devtoolsFrontendUrl":"/devtools/inspector.html?ws=127.0.0.1:9226/devtools/page/ABC","id":"ABC","title":"","type":"page","url":"about:blank","webSocketDebuggerUrl":"ws://127.0.0.1:9226/devtools/page/ABC"}]"#;
        let targets: Vec<TargetInfo> = serde_json::from_str(raw).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].target_type, "page");
        assert_eq!(targets[0].url, "about:blank");
    }
}
