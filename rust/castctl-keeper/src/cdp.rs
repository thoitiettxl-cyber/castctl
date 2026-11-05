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
//! [CHƯA KIỂM CHỨNG] `flatten: true` for
//! `Target.attachToTarget` (chromedp uses it; not yet
//! proven on the wire here); the CDP handshake Origin
//! requirement; whether tungstenite flushes Pong replies
//! for a read-only client (the keepalive Ping only proves
//! liveness when the peer answers).

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

/// One entry of `/json/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    pub id: String,
    #[serde(rename = "type")]
    pub target_type: String,
    pub title: String,
    pub url: String,
    pub description: String,
    #[serde(rename = "webSocketDebuggerUrl")]
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

/// The `/json/version` response.
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
    #[serde(rename = "webSocketDebuggerUrl")]
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
/// Default per-call timeout.
pub const CDP_CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Keepalive Ping interval.
pub const CDP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Validate a discovery base URL the way Go does
/// (`export_cdp.go`): `http` scheme, loopback host, port
/// 1–65535, no userinfo. Returns the normalised
/// `http://host:port` base.
pub fn validate_loopback_base(raw: &str) -> Result<String, CdpError> {
    let url = url::Url::parse(raw).map_err(|e| CdpError::Http(format!("bad browser URL: {e}")))?;
    if url.scheme() != "http" {
        return Err(CdpError::Http(format!(
            "browser URL scheme must be http, got {}",
            url.scheme()
        )));
    }
    if url.username() != "" || url.password().is_some() {
        return Err(CdpError::Http(
            "browser URL must not contain userinfo".to_string(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| CdpError::Http("browser URL has no host".to_string()))?;
    let is_loopback =
        host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host.starts_with("127.");
    if !is_loopback {
        return Err(CdpError::Http(format!(
            "browser URL host {host} is not loopback"
        )));
    }
    let port = url
        .port()
        .ok_or_else(|| CdpError::Http("browser URL has no port".to_string()))?;
    if port == 0 {
        return Err(CdpError::Http("browser URL port out of range".to_string()));
    }
    Ok(format!("http://{host}:{port}"))
}

/// GET `{base}/json/version` (5s, 64 KiB cap) and return
/// the browser WebSocket URL (`export_cdp.go`).
pub async fn discover_websocket_url(http_base: &str) -> Result<String, CdpError> {
    let base = validate_loopback_base(http_base)?;
    let info: BrowserVersionInfo = discovery_get(&base, "/json/version", VERSION_BODY_CAP).await?;
    if info.web_socket_debugger_url.is_empty() {
        return Err(CdpError::Http(
            "/json/version returned no webSocketDebuggerUrl".to_string(),
        ));
    }
    Ok(info.web_socket_debugger_url)
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
    let stream = tokio::time::timeout(
        CDP_DISCOVERY_TIMEOUT,
        tokio::net::TcpStream::connect(hostport),
    )
    .await
    .map_err(|_| CdpError::Timeout)?
    .map_err(|e| CdpError::Http(e.to_string()))?;
    let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| CdpError::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("{base}{path}"))
        .header("Accept", "application/json")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|e| CdpError::Http(e.to_string()))?;
    let resp = tokio::time::timeout(CDP_DISCOVERY_TIMEOUT, sender.send_request(req))
        .await
        .map_err(|_| CdpError::Timeout)?
        .map_err(|e| CdpError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(CdpError::Http(format!("GET {path} -> {}", resp.status())));
    }
    let mut body = resp.into_body();
    let mut buf = Vec::new();
    loop {
        let frame = tokio::time::timeout(CDP_DISCOVERY_TIMEOUT, body.frame())
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
    serde_json::from_slice(&buf).map_err(|e| CdpError::Http(format!("GET {path}: {e}")))
}

// ---------------------------------------------------------------------------
// Client (feature-gated real implementation)
// ---------------------------------------------------------------------------

#[cfg(feature = "chromedp")]
mod real {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    struct Outgoing {
        id: u64,
        session_id: Option<String>,
        method: String,
        params: Value,
        responder: oneshot::Sender<Result<Value, CdpError>>,
    }

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
        /// `export_cdp.go`).
        pub async fn connect(ws_url: &str) -> Result<Self, CdpError> {
            let (ws, _) =
                tokio::time::timeout(CDP_DIAL_TIMEOUT, tokio_tungstenite::connect_async(ws_url))
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
            let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, CdpError>>>>> =
                Arc::new(Mutex::new(HashMap::new()));
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

        /// The chromedp bootstrap enable set
        /// (`export_cdp.go:49-57` + `research-ws-cdp.md`
        /// §3.2): Runtime, Log, Network, Inspector, Page,
        /// DOM and CSS on the target, `Target.setDiscoverTargets`
        /// + `Target.setAutoAttach`, `Page.setLifecycleEventsEnabled`,
        /// and the constant `Runtime.evaluate("self")`. The
        /// order matches the wire order chromedp emits.
        pub async fn bootstrap(&self) -> Result<(), CdpError> {
            let empty = || Value::Object(Default::default());
            self.call("Runtime.enable", empty()).await?;
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
            self.call(
                "Runtime.evaluate",
                serde_json::json!({"expression": "self", "returnByValue": true}),
            )
            .await?;
            Ok(())
        }

        /// Detach from the target.
        pub async fn detach(&self) -> Result<(), CdpError> {
            // Detach is a browser-session call.
            let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = oneshot::channel();
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
            let _ = tokio::time::timeout(CDP_CALL_TIMEOUT, rx)
                .await
                .map_err(|_| CdpError::Timeout)?
                .map_err(|_| CdpError::Closed)?;
            self.shared.sessions.lock().await.remove(&self.session_id);
            Ok(())
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
    fn target_info_parses_json_list_shape() {
        let raw = r#"[{"description":"","devtoolsFrontendUrl":"/devtools/inspector.html?ws=127.0.0.1:9226/devtools/page/ABC","id":"ABC","title":"","type":"page","url":"about:blank","webSocketDebuggerUrl":"ws://127.0.0.1:9226/devtools/page/ABC"}]"#;
        let targets: Vec<TargetInfo> = serde_json::from_str(raw).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].target_type, "page");
        assert_eq!(targets[0].url, "about:blank");
    }
}
