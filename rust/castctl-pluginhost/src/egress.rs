// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Per-session loopback egress proxy (BQ5).
//!
//! Go source: `internal/pluginhost/egress.go` (all of it).
//!
//! The proxy listens on 127.0.0.1 only, requires
//! ephemeral Basic credentials generated per proxy and
//! never equal to any real proxy credentials, forwards
//! absolute-form requests through a caller-supplied
//! upstream transport (in real wiring, the core-owned
//! client derived from the profile's outbound), and
//! injects the session Cookie header inside core for
//! declared hosts only, so the plugin never sees it.
//! Proxy use by plugins is by CONTRACT and code review
//! for first-party plugins, not an enforcement boundary:
//! an in-process native plugin can still dial, read the
//! environment, or read process memory. CONNECT tunneling
//! is served only when the caller supplies a dial
//! function, and returns 502 otherwise. This crate never
//! builds its own client for profile traffic; the
//! upstream transport and the dial function are injected
//! by the wiring that owns the profile.
//!
//! Timeouts: only `ReadHeaderTimeout` (10s) is set via
//! hyper's http1 builder. Go also sets `IdleTimeout`
//! (120s); hyper has no direct equivalent — recorded as
//! a minor note in PORTING.md (M6c). A Read/Write
//! timeout would abort slow-but-legitimate streaming
//! transfers; transfer timeouts belong to the
//! wiring-owned upstream transport and dial function.
//!
//! Rust adaptations (recorded in PORTING.md, M6c):
//!
//!   - tokio + hyper 1.8 + hyper-util 0.1.20,
//!     hand-rolled `Service` (no tower). The upstream
//!     is a `UpstreamTransport` trait (boxed future:
//!     `async fn` is not object-safe); the production
//!     impl (`HyperUpstream`) dials plain-HTTP upstreams
//!     via the hyper http1 handshake pattern from
//!     `castctl-transport/src/http.rs:292` — the
//!     hyper-util legacy client needs the
//!     `client-legacy` feature, which the workspace does
//!     not enable. HTTPS upstreams refuse (the Go
//!     wiring's upstream handles TLS via the profile
//!     outbound; the Rust wiring injects its own
//!     transport for that).
//!   - Request bodies are collected before the upstream
//!     call (Go streams them); no body limit is applied,
//!     matching Go's no-limit.
//!   - `Close` is synchronous (the `EgressProxyHandle`
//!     trait): it notifies the accept loop, aborts the
//!     tunnel tasks, aborts the accept task, and shuts
//!     the listener socket down with `shutdown(2)`
//!     (`libc::shutdown` — the established libc syscall
//!     wrapper pattern, as in `castctl-update`'s
//!     `flock`): tokio has no listener-close API, and
//!     the shutdown makes a dial after `Close` refuse
//!     deterministically on any runtime flavor.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper_util::rt::TokioIo;
use rand::RngCore;

use crate::error::PluginHostError;
use crate::host::EgressProxyHandle;
use crate::pluginabi::valid_cookie_host;

/// The upstream transport: one round trip. The request
/// carries a collected body; the response likewise.
/// Source: `http.RoundTripper` (`egress.go:56`).
pub trait UpstreamTransport: Send + Sync {
    /// Send `req` upstream and return the response.
    /// Any error becomes a 502 `"upstream error"` at
    /// the proxy.
    fn round_trip(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Full<Bytes>>, PluginHostError>> + Send + '_>>;
}

/// A dialed CONNECT target: any async byte stream.
/// Source: the `net.Conn` returned by the dial function
/// (`egress.go:57`).
pub type DialStream = Pin<Box<dyn tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin>>;

/// The CONNECT dial function: dial `addr` (a `host:port`
/// string) and return the target stream.
/// Source: `dial func(ctx, network, addr)` (`egress.go:57`).
pub type DialFn = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = std::io::Result<DialStream>> + Send>>
        + Send
        + Sync,
>;

/// Hop-by-hop headers, stripped in both directions.
/// Source: `hopByHopHeaders` (`egress.go:277-280`).
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "Connection",
    "Keep-Alive",
    "Proxy-Connection",
    "Proxy-Authorization",
    "Te",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
];

/// Strip hop-by-hop headers: read the `Connection`
/// tokens FIRST (deleting the `Connection` header first
/// would make the token list unreadable), iterate EVERY
/// `Connection` value, then delete the fixed list and
/// every named token.
/// Source: `stripHopByHop` (`egress.go:282-300`).
fn strip_hop_by_hop(headers: &mut http::HeaderMap) {
    let mut tokens: Vec<String> = Vec::new();
    for value in headers.get_all("Connection").iter() {
        if let Ok(s) = value.to_str() {
            for token in s.split(',') {
                let token = token.trim();
                if !token.is_empty() {
                    tokens.push(token.to_string());
                }
            }
        }
    }
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(*name);
    }
    for token in tokens {
        headers.remove(token);
    }
}

/// Constant-time byte comparison (xor fold; the `subtle`
/// crate is not in the lock). Length mismatch is false,
/// as in Go's `subtle.ConstantTimeCompare`.
/// Source: `authorized` (`egress.go:257-272`).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn random_credential() -> String {
    let mut raw = [0u8; 24];
    rand::rng().fill_bytes(&mut raw);
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        raw,
    )
}

struct Inner {
    upstream: Arc<dyn UpstreamTransport>,
    dial: Option<DialFn>,
    cookie: String,
    username: String,
    password: String,
    addr: SocketAddr,
    /// Hostnames the session cookie may be injected
    /// for. Empty means NO injection (fail-closed).
    cookie_hosts: RwLock<HashSet<String>>,
    tunnels: Mutex<HashMap<u64, tokio::task::AbortHandle>>,
    next_tunnel_id: AtomicU64,
    closed: AtomicBool,
    shutdown: tokio::sync::Notify,
    accept_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    listener_fd: std::os::unix::io::RawFd,
}

/// The per-session loopback HTTP proxy.
/// Source: `EgressProxy` (`egress.go:44-80`).
pub struct EgressProxy {
    inner: Arc<Inner>,
}

impl EgressProxy {
    /// Start a loopback proxy. `cookie` is injected as
    /// the `Cookie` header ONLY for hosts declared via
    /// `set_cookie_hosts`; with no declaration nothing
    /// is injected. An empty cookie injects nothing.
    /// Credentials live exactly as long as the proxy
    /// instance: `close` revokes them, and there is no
    /// rotation in v1. Must be called within a tokio
    /// runtime (the accept loop is spawned).
    /// Source: `NewEgressProxy` (`egress.go:99-133`).
    pub fn new(
        upstream: Arc<dyn UpstreamTransport>,
        dial: Option<DialFn>,
        cookie: &str,
    ) -> Result<EgressProxy, PluginHostError> {
        let username = random_credential();
        let password = random_credential();
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| {
            PluginHostError::failed(format!("listen egress proxy: {e}"))
        })?;
        let addr = std_listener.local_addr().map_err(|e| {
            PluginHostError::failed(format!("listen egress proxy: {e}"))
        })?;
        let listener = tokio::net::TcpListener::from_std(std_listener).map_err(|e| {
            PluginHostError::failed(format!("listen egress proxy: {e}"))
        })?;
        use std::os::unix::io::AsRawFd;
        let listener_fd = listener.as_raw_fd();
        let inner = Arc::new(Inner {
            upstream,
            dial,
            cookie: cookie.to_string(),
            username,
            password,
            addr,
            cookie_hosts: RwLock::new(HashSet::new()),
            tunnels: Mutex::new(HashMap::new()),
            next_tunnel_id: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            shutdown: tokio::sync::Notify::new(),
            accept_handle: Mutex::new(None),
            listener_fd,
        });
        let accept_inner = Arc::clone(&inner);
        let handle = tokio::spawn(async move {
            Self::accept_loop(accept_inner, listener).await;
        });
        *inner.accept_handle.lock().unwrap() = Some(handle);
        Ok(EgressProxy { inner })
    }

    async fn accept_loop(inner: Arc<Inner>, listener: tokio::net::TcpListener) {
        loop {
            let conn = tokio::select! {
                () = inner.shutdown.notified() => break,
                res = listener.accept() => match res {
                    Ok((stream, _)) => stream,
                    Err(_) => break,
                },
            };
            let io = TokioIo::new(conn);
            let service = ProxyService {
                inner: Arc::clone(&inner),
            };
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .header_read_timeout(std::time::Duration::from_secs(10))
                    .serve_connection(io, service)
                    .await;
            });
        }
    }

    /// The proxy URL plugins configure (loopback only).
    /// Source: `URL` (`egress.go:161-165`).
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.inner.addr)
    }

    /// The ephemeral username handed to the plugin.
    /// Source: `Username` (`egress.go:171`).
    #[must_use]
    pub fn username(&self) -> &str {
        &self.inner.username
    }

    /// The ephemeral password handed to the plugin.
    /// Source: `Password` (`egress.go:172`).
    #[must_use]
    pub fn password(&self) -> &str {
        &self.inner.password
    }

    /// The listener address (`host:port`).
    /// Source: `Addr` (`egress.go:175`).
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.inner.addr
    }

    /// Whether the proxy is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// Whether the session cookie may be injected for
    /// `host` (lowercased exact match).
    /// Source: `cookieAllowed` (`egress.go:150-154`).
    #[must_use]
    pub fn cookie_allowed(&self, host: &str) -> bool {
        let hosts = self.inner.cookie_hosts.read().unwrap();
        hosts.contains(&host.to_ascii_lowercase())
    }

    /// Stop the proxy. Credentials die with it. The
    /// listener socket is shut down directly as well as
    /// through the accept task: aborting the task alone
    /// leaves a scheduling window in which a dial could
    /// still complete. `Close` also aborts in-flight
    /// CONNECT tunnels by aborting their copy tasks
    /// (dropping both ends): hyper does NOT close
    /// hijacked connections, so without tunnel tracking
    /// revocation would block new connections only.
    /// Idempotent.
    /// Source: `Close` (`egress.go:185-219`).
    pub fn close_proxy(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.inner.shutdown.notify_waiters();
        // Abort live tunnels first: their copy tasks own
        // both ends, so aborting drops (closes) them.
        let handles: Vec<tokio::task::AbortHandle> = {
            let mut tunnels = self.inner.tunnels.lock().unwrap();
            tunnels.drain().map(|(_, h)| h).collect()
        };
        for h in handles {
            h.abort();
        }
        // Abort the accept loop (drops the listener) and
        // shut the listener socket down at the kernel
        // level so a dial racing task cleanup still
        // refuses deterministically.
        if let Some(handle) = self.inner.accept_handle.lock().unwrap().take() {
            handle.abort();
        }
        unsafe {
            libc::shutdown(self.inner.listener_fd, libc::SHUT_RDWR);
        }
    }
}

impl EgressProxyHandle for EgressProxy {
    /// Replace the declared cookie hosts (the plugin's
    /// registration `cookie_hosts`). Invalid entries are
    /// ignored; an empty list means no injection.
    /// Source: `SetCookieHosts` (`egress.go:136-148`).
    fn set_cookie_hosts(&self, hosts: &[String]) {
        let mut next = HashSet::new();
        for h in hosts {
            if valid_cookie_host(h) {
                next.insert(h.clone());
            }
        }
        *self.inner.cookie_hosts.write().unwrap() = next;
    }

    fn close(&self) {
        self.close_proxy();
    }

    fn is_closed(&self) -> bool {
        self.is_closed()
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        self.close_proxy();
    }
}

/// The hyper service fronting one `EgressProxy`.
#[derive(Clone)]
struct ProxyService {
    inner: Arc<Inner>,
}

impl ProxyService {
    fn authorized(&self, req: &Request<Incoming>) -> bool {
        // Proxy credentials arrive in
        // Proxy-Authorization, not Authorization.
        let Some(raw) = req.headers().get("Proxy-Authorization") else {
            return false;
        };
        let Ok(raw) = raw.to_str() else {
            return false;
        };
        let Some(b64) = raw.strip_prefix("Basic ") else {
            return false;
        };
        let Ok(decoded) = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            b64.trim(),
        ) else {
            return false;
        };
        let Ok(text) = std::str::from_utf8(&decoded) else {
            return false;
        };
        let Some((username, password)) = text.split_once(':') else {
            return false;
        };
        constant_time_eq(username.as_bytes(), self.inner.username.as_bytes())
            && constant_time_eq(password.as_bytes(), self.inner.password.as_bytes())
    }

    async fn handle(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        if !self.authorized(&req) {
            return Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header("Proxy-Authenticate", "Basic")
                .body(Full::new(Bytes::from_static(
                    b"proxy authentication required",
                )))
                .unwrap_or_else(|_| {
                    Response::new(Full::new(Bytes::from_static(b"proxy authentication required")))
                });
        }
        if req.method() == http::Method::CONNECT {
            return self.serve_connect(req).await;
        }
        self.serve_forward(req).await
    }

    async fn serve_forward(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        let uri = req.uri().clone();
        if uri.scheme().is_none() || uri.authority().is_none() {
            return plain_response(
                StatusCode::BAD_REQUEST,
                "proxy requires an absolute-form request URI",
            );
        }
        let (parts, body) = req.into_parts();
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return plain_response(StatusCode::BAD_GATEWAY, "upstream error"),
        };
        // URL userinfo in an absolute-form request is
        // never forwarded.
        let clean_uri = strip_userinfo(&uri);
        let mut upstream_req = Request::builder()
            .method(parts.method.clone())
            .uri(clean_uri)
            .version(parts.version);
        let headers = upstream_req.headers_mut().unwrap();
        *headers = parts.headers.clone();
        strip_hop_by_hop(headers);
        // The session cookie is injected inside core ONLY
        // for declared hosts, and always wins over
        // anything the plugin sent. For every other host
        // the plugin's Cookie header is removed.
        let host = uri
            .authority()
            .map(|a| a.host().to_string())
            .unwrap_or_default();
        if !self.inner.cookie.is_empty() && self.cookie_allowed(&host) {
            if let Ok(value) = http::HeaderValue::from_str(&self.inner.cookie) {
                headers.insert("Cookie", value);
            }
        } else {
            headers.remove("Cookie");
        }
        let upstream_req = upstream_req
            .body(Full::new(body_bytes))
            .unwrap_or_else(|_| Request::new(Full::new(Bytes::new())));
        let resp = match self.inner.upstream.round_trip(upstream_req).await {
            Ok(r) => r,
            Err(_) => return plain_response(StatusCode::BAD_GATEWAY, "upstream error"),
        };
        let (mut resp_parts, resp_body) = resp.into_parts();
        // Set-Cookie (and hop-by-hop headers) from the
        // upstream are never forwarded to the plugin.
        strip_hop_by_hop(&mut resp_parts.headers);
        resp_parts.headers.remove("Set-Cookie");
        let mut builder = Response::builder().status(resp_parts.status);
        for (name, value) in resp_parts.headers.iter() {
            builder = builder.header(name, value);
        }
        builder
            .body(resp_body)
            .unwrap_or_else(|_| plain_response(StatusCode::BAD_GATEWAY, "upstream error"))
    }

    /// Serve a raw CONNECT tunnel. The tunnel is
    /// OPAQUE: core neither injects the session cookie
    /// nor inspects anything inside the TLS stream.
    /// Source: `serveConnect` (`egress.go:343-398`).
    async fn serve_connect(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        let Some(dial) = self.inner.dial.clone() else {
            return plain_response(StatusCode::BAD_GATEWAY, "CONNECT not available");
        };
        let host = req
            .uri()
            .authority()
            .map(|a| a.as_str().to_string())
            .or_else(|| {
                req.headers()
                    .get("Host")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();
        let target = match dial(host).await {
            Ok(t) => t,
            Err(_) => return plain_response(StatusCode::BAD_GATEWAY, "dial error"),
        };
        let upgrade = hyper::upgrade::on(req);
        let inner = Arc::clone(&self.inner);
        let id = inner.next_tunnel_id.fetch_add(1, Ordering::SeqCst);
        let handle = tokio::spawn(async move {
            let mut upgraded = match upgrade.await {
                Ok(u) => u,
                Err(_) => {
                    drop(target);
                    return;
                }
            };
            // Track both tunnel ends so Close aborts the
            // tunnel. A tunnel that starts concurrently
            // with Close is shut down immediately.
            if inner.closed.load(Ordering::SeqCst) {
                drop(target);
                drop(upgraded);
                return;
            }
            let mut target = target;
            let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut target).await;
            let _ = inner.tunnels.lock().unwrap().remove(&id);
        });
        self.inner
            .tunnels
            .lock()
            .unwrap()
            .insert(id, handle.abort_handle());
        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
    }

    fn cookie_allowed(&self, host: &str) -> bool {
        let hosts = self.inner.cookie_hosts.read().unwrap();
        hosts.contains(&host.to_ascii_lowercase())
    }
}

impl Service<Request<Incoming>> for ProxyService {
    type Response = Response<Full<Bytes>>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { Ok(this.handle(req).await) })
    }
}

fn plain_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"error"))))
}

/// Rebuild `uri` without any userinfo in the authority.
fn strip_userinfo(uri: &http::Uri) -> http::Uri {
    let Some(authority) = uri.authority() else {
        return uri.clone();
    };
    let host_port = authority.as_str().rsplit('@').next().unwrap_or(authority.as_str());
    let mut builder = http::uri::Builder::new();
    if let Some(scheme) = uri.scheme() {
        builder = builder.scheme(scheme.clone());
    }
    builder = builder.authority(host_port);
    if let Some(pq) = uri.path_and_query() {
        builder = builder.path_and_query(pq.clone());
    }
    builder.build().unwrap_or_else(|_| uri.clone())
}

/// A plain-HTTP upstream via a fresh connection per
/// request (hyper http1 handshake, the
/// `castctl-transport/src/http.rs:292` pattern).
/// HTTPS upstreams refuse: the Go wiring's upstream
/// handles TLS via the profile outbound, and the Rust
/// wiring injects its own transport for that.
pub struct HyperUpstream;

impl UpstreamTransport for HyperUpstream {
    fn round_trip(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Full<Bytes>>, PluginHostError>> + Send + '_>>
    {
        Box::pin(async move {
            let uri = req.uri().clone();
            if uri.scheme_str() == Some("https") {
                return Err(PluginHostError::failed("upstream error"));
            }
            let authority = uri.authority().cloned().unwrap_or_default();
            let host = authority.host().to_string();
            let port = authority.port_u16().unwrap_or(80);
            let stream = tokio::net::TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|_| PluginHostError::failed("upstream error"))?;
            let io = TokioIo::new(stream);
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(io)
                .await
                .map_err(|_| PluginHostError::failed("upstream error"))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let resp = sender
                .send_request(req)
                .await
                .map_err(|_| PluginHostError::failed("upstream error"))?;
            let (parts, body) = resp.into_parts();
            let bytes = body
                .collect()
                .await
                .map_err(|_| PluginHostError::failed("upstream error"))?
                .to_bytes();
            Ok(Response::from_parts(parts, Full::new(bytes)))
        })
    }
}
