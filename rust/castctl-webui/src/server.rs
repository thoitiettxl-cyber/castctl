// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! HTTP server (`internal/webui/server.go`): routes,
//! pinned middleware order, auth, response envelopes,
//! and the hyper accept loop.
//!
//! Pinned middleware order (Design A): rate-limit → auth
//! → Origin → timeout (30s, buffered, WS excluded).
//! Every `/api/v1` route + screencast needs Bearer except
//! `GET /api/v1/screencast/ws` (single-use `?session=`
//! token, NOT Bearer). The static shell is unauthenticated.
//! No cookies, no CORS headers, stateless Bearer.
//!
//! Routing (chi semantics, reproduced by hand):
//! - Exact segment matching, case-sensitive; a known path
//!   with a wrong method → 405 envelope.
//! - An unknown `/api/v1/*` path (any method) runs the
//!   full middleware chain, then falls through to the 200
//!   shell — chi's mount fallthrough to the root NotFound
//!   handler. Unauthenticated unknown `/api/v1` still 401s.
//! - `GET /api/v1` (exact) falls through to the shell.
//! - Non-API paths: GET → shell / ui_dir; any other
//!   method (HEAD included — chi does not map HEAD to
//!   GET) → 405 envelope.
//! - HEAD is never routed as GET: a known API path +
//!   HEAD → 405, a non-API path + HEAD → 405, an unknown
//!   API path + HEAD → shell fallthrough. The response
//!   body is suppressed for HEAD (with the Content-Length
//!   the GET would have produced) by `render_resp` —
//!   Go net/http behaviour, not a routing rule.
//!
//! Response framing (Go net/http compat): Go buffers the
//! first 2048 bytes of a response; a body that fits is sent
//! with an automatic Content-Length, a larger body is sent
//! chunked with no Content-Length. Hyper's `Full` body
//! always carries a Content-Length, so bodies ≥ 2048 bytes
//! are sent as a single-chunk stream (chunked, no
//! Content-Length) unless the handler set an explicit
//! Content-Length (ui_dir assets always do).

use crate::auth::{parse_bearer_header, verify_token};
use crate::chats::ChatDeps;
use crate::config::{
    DEFAULT_LOGIN_RATE_LIMIT_ATTEMPTS, DEFAULT_LOGIN_RATE_LIMIT_WINDOW_NS, WebUIConfig,
    effective_login_rate_limit, effective_session_idle_timeout_ns,
};
use crate::error::ApiError;
use crate::go_json::encode_go_json_line;
use crate::origin::api_origin_allowed;
use crate::ratelimit::{RateLimiter, host_part, retry_after_seconds};
use crate::screencast::{ScreencastRegistry, ScreencastStarter};
use crate::static_shell::SHELL_BYTES;
use crate::store::{load_config, parse_loaded};
use crate::uidir::{check_ui_dir, serve_ui_dir};
use crate::validate::resolve_webui_from_config;
use bytes::Bytes;
use castctl_config::jsonvalue::{JsonValue, OrderedObject};
use futures_util::stream::once as stream_once;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response as HyperResponse, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::TcpListener;

/// API handler timeout: 30s (`apiHandlerTimeout`).
pub const API_TIMEOUT: Duration = Duration::from_secs(30);
/// `http.Server` ReadHeaderTimeout: 10s.
pub const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// `http.Server` IdleTimeout: 120s. Idle-BETWEEN-requests
/// only in Go — it never cuts a connection mid-request
/// and resets after every response. Hyper has no idle
/// knob; the per-request header read timeout (10s) is the
/// closest correct form, so idle keep-alive connections
/// are cut at 10s, not 120s (stricter, fail-closed —
/// recorded in PORTING §M6b.6; probe in §M6b.9).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Largest request body any route accepts (1 MiB cap).
pub const MAX_BODY_BYTES: usize = 1024 * 1024 + 1;
/// Go's net/http sniff buffer: bodies below this get an
/// automatic Content-Length; larger bodies go chunked.
pub const GO_SNIFF_BUFFER: usize = 2048;

/// One HTTP response: status + headers (in send order) +
/// body bytes. The dispatcher turns this into a hyper
/// response, applying Go's Content-Length/chunked rule.
#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// API response headers: `Content-Type: application/json`,
/// `Cache-Control: no-store`,
/// `X-Content-Type-Options: nosniff` (Design A).
pub fn api_headers() -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Cache-Control".to_string(), "no-store".to_string()),
        ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
    ]
}

/// Shell response headers: `Content-Type: text/html;
/// charset=utf-8` + no-store + nosniff.
pub fn shell_headers() -> Vec<(String, String)> {
    vec![
        (
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        ),
        ("Cache-Control".to_string(), "no-store".to_string()),
        ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
    ]
}

/// `writeEnvelope`: success envelope `{data: ...}` with
/// API headers. `data` must already be in Go emission
/// order (struct declaration order or sorted map keys).
pub fn envelope_resp(status: u16, data: JsonValue) -> Resp {
    let mut envelope = OrderedObject::new();
    envelope.set("data".to_string(), data);
    Resp {
        status,
        headers: api_headers(),
        body: encode_go_json_line(&JsonValue::Object(envelope)).into_bytes(),
    }
}

/// `writeError`: error envelope `{error: {type, message}}`
/// with API headers. The inner map renders sorted
/// (`message` before `type`), as Go's
/// `map[string]string` does.
pub fn error_resp(status: u16, typ: &str, msg: &str) -> Resp {
    let mut inner = OrderedObject::new();
    inner.set("message".to_string(), JsonValue::Str(msg.to_string()));
    inner.set("type".to_string(), JsonValue::Str(typ.to_string()));
    let mut envelope = OrderedObject::new();
    envelope.set("error".to_string(), JsonValue::Object(inner));
    Resp {
        status,
        headers: api_headers(),
        body: encode_go_json_line(&JsonValue::Object(envelope)).into_bytes(),
    }
}

/// `writeAPIError`: an [`ApiError`] renders as its
/// envelope; anything else is the fixed 500.
pub fn api_error_resp(err: &ApiError) -> Resp {
    error_resp(err.status, err.typ, &err.msg)
}

/// Fixed 404 `not_found` / `not found` (ui_dir refusals).
pub fn not_found_resp() -> Resp {
    error_resp(404, "not_found", "not found")
}

/// Fixed 405 `method_not_allowed` / `method not allowed`.
pub fn method_not_allowed_resp() -> Resp {
    error_resp(405, "method_not_allowed", "method not allowed")
}

/// Fixed 401 `unauthorized` / `invalid or missing token`.
pub fn unauthorized_resp() -> Resp {
    error_resp(401, "unauthorized", "invalid or missing token")
}

/// Fixed 403 `forbidden` / `cross-origin request rejected`.
pub fn forbidden_resp() -> Resp {
    error_resp(403, "forbidden", "cross-origin request rejected")
}

/// Fixed 429 `rate_limited` / `too many failed login
/// attempts` with `Retry-After` = window seconds.
pub fn rate_limited_resp(window: Duration) -> Resp {
    let mut resp = error_resp(429, "rate_limited", "too many failed login attempts");
    resp.headers
        .push(("Retry-After".to_string(), retry_after_seconds(window)));
    resp
}

/// Fixed 503 `timeout` / `request timed out`.
pub fn timeout_resp() -> Resp {
    error_resp(503, "timeout", "request timed out")
}

/// Fixed 500 `internal_error` / `internal error`.
pub fn internal_resp() -> Resp {
    error_resp(500, "internal_error", "internal error")
}

/// The shell response (embedded bytes, shell headers).
pub fn shell_resp() -> Resp {
    Resp {
        status: 200,
        headers: shell_headers(),
        body: SHELL_BYTES.to_vec(),
    }
}

/// Screencast availability seam
/// (`ScreencastAvailability` in Go): reports whether a
/// screencast session can start for a profile. In this
/// build the seam is implemented over the config file
/// (keeper entry with a browser URL); a nil seam means
/// unavailable.
pub type ScreencastAvailability = Arc<dyn Fn(&str) -> (bool, String) + Send + Sync>;

/// Cookie import seam (`Deps.ImportCookies` in Go):
/// validates and writes cookies for a profile through the
/// locked writer path; returns whether a `.bak` backup was
/// made. `None` means cookie import is unavailable (the
/// handler reports it explicitly).
pub type ImportCookies = Arc<dyn Fn(&str, &str) -> Result<bool, String> + Send + Sync>;

/// Cookie restore seam (`Deps.RestoreCookies` in Go).
/// `None` means unavailable.
pub type RestoreCookies = Arc<dyn Fn(&str) -> Result<bool, String> + Send + Sync>;

/// `Deps` wires one Server (`internal/webui/server.go`
/// `Deps`). `TokenHash` is the stored bcrypt hash at
/// startup; the live comparator starts there and is
/// refreshed after every successful guarded save.
pub struct Deps {
    pub config_dir: PathBuf,
    pub version: String,
    pub listen_addr: String,
    pub token_hash: String,
    pub has_token: bool,
    pub bundle_sha256: String,
    pub ui_dir: Option<String>,
    pub cookies_files: Vec<String>,
    pub import_cookies: Option<ImportCookies>,
    pub restore_cookies: Option<RestoreCookies>,
    pub screencast_available: Option<ScreencastAvailability>,
    pub screencast_starter: Option<ScreencastStarter>,
    pub chats: Option<Arc<ChatDeps>>,
}

/// Server construction failure: a configuration error
/// (exit 2) or an operational one (exit 1). `UIDirError`
/// maps to exit 2.
#[derive(Debug, Clone)]
pub enum NewServerError {
    Config(String),
    UIDir(String),
}

impl std::fmt::Display for NewServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NewServerError::Config(m) | NewServerError::UIDir(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for NewServerError {}

/// One web UI HTTP server.
pub struct Server {
    pub deps: Deps,
    token_hash: RwLock<String>,
    rate_limiter: Mutex<RateLimiter>,
    pub sessions: ScreencastRegistry,
    pub job_store: crate::chats::ChatJobStore,
    shutdown: tokio::sync::Notify,
}

impl Server {
    /// `New`: fails closed when no token is configured or
    /// the frontend shell is missing; with `ui_dir` set,
    /// the on-disk root must additionally be a directory
    /// holding a regular `index.html` and must not overlap
    /// the config directory. A present-but-broken root
    /// fails here, never by falling back to the embedded
    /// frontend.
    pub fn new(deps: Deps) -> Result<Arc<Self>, NewServerError> {
        if deps.config_dir.as_os_str().is_empty() {
            return Err(NewServerError::Config(
                "webui: config directory is required".to_string(),
            ));
        }
        if !deps.has_token || deps.token_hash.is_empty() {
            return Err(NewServerError::Config(
                "webui: no token configured".to_string(),
            ));
        }
        if let Some(ui_dir) = &deps.ui_dir {
            check_ui_dir(&deps.config_dir, ui_dir, &deps.cookies_files)
                .map_err(|e| NewServerError::UIDir(e.0))?;
        }
        Ok(Arc::new(Server {
            token_hash: RwLock::new(deps.token_hash.clone()),
            rate_limiter: Mutex::new(RateLimiter::new()),
            sessions: ScreencastRegistry::new(),
            job_store: crate::chats::ChatJobStore::new(),
            shutdown: tokio::sync::Notify::new(),
            deps,
        }))
    }

    /// Signal the accept loop to stop (SIGINT path): the
    /// listener stops accepting and in-flight connections
    /// drain for up to 5s (Go's `http.Server.Shutdown`).
    pub fn request_shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    /// The live Bearer comparator (read under a read lock).
    pub fn token_hash(&self) -> String {
        self.token_hash
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// `authorized`: the `Authorization` header must start
    /// exactly with `"Bearer "`, the presented token must
    /// be non-empty and contain no space/tab/CR/LF, and
    /// bcrypt must verify it against the live hash. Every
    /// failure is the same fixed 401.
    pub fn authorized(&self, auth_header: Option<&str>) -> bool {
        let Some(header) = auth_header else {
            return false;
        };
        let Some(presented) = parse_bearer_header(header) else {
            return false;
        };
        let hash = self.token_hash();
        verify_token(presented, &hash)
    }

    /// `refreshTokenHash`: refresh the live comparator
    /// from the saved document after a successful guarded
    /// save. Runs only after Save succeeds. A save whose
    /// document carries no token clears the comparator —
    /// but only when the stored document carried one
    /// (`had_token`); when it never carried one, the
    /// comparator came from startup Deps and is untouched.
    pub fn refresh_token_hash(&self, webui_token: Option<String>, had_token: bool) {
        let hash = webui_token.unwrap_or_default();
        if hash.is_empty() && !had_token {
            return;
        }
        if let Ok(mut guard) = self.token_hash.write() {
            *guard = hash;
        }
    }

    /// `currentWebUIConfig`: the stored `webui` block, or
    /// `None` when the block is absent or the stored config
    /// cannot be loaded or parsed. Callers apply the
    /// documented defaults to a nil result.
    pub fn current_webui_config(&self) -> Option<WebUIConfig> {
        let load = load_config(&self.deps.config_dir).ok()?;
        if !load.state.found {
            return None;
        }
        let (cfg, _) = parse_loaded(&load, &self.deps.config_dir).ok()?;
        resolve_webui_from_config(&cfg).ok().flatten()
    }

    /// `loginLimits`: the effective rate-limit pair from
    /// the currently stored config (defaults on any load
    /// or parse failure).
    pub fn login_limits(&self) -> (i64, Duration) {
        match self.current_webui_config() {
            Some(cfg) => {
                let (attempts, window_ns) = effective_login_rate_limit(&cfg);
                (attempts, Duration::from_nanos(window_ns.max(0) as u64))
            }
            None => (
                DEFAULT_LOGIN_RATE_LIMIT_ATTEMPTS,
                Duration::from_nanos(DEFAULT_LOGIN_RATE_LIMIT_WINDOW_NS.max(0) as u64),
            ),
        }
    }

    /// Effective session idle timeout in seconds (for
    /// `/status`): the effective `webui.session_idle_timeout`
    /// (12h default), via the current config.
    pub fn session_idle_timeout_seconds(&self) -> i64 {
        match self.current_webui_config() {
            Some(cfg) => effective_session_idle_timeout_ns(&cfg) / 1_000_000_000,
            None => 12 * 60 * 60,
        }
    }

    /// `configPath`: `<configDir>/config.json`.
    pub fn config_path(&self) -> String {
        format!("{}/config.json", self.deps.config_dir.to_string_lossy())
    }

    /// Bundle SHA-256: the on-disk index.html hash when
    /// `ui_dir` is active, else the embedded hash. (The
    /// command layer supplies the on-disk hash in
    /// `deps.bundle_sha256`; the embedded hash is the
    /// fallback — here the deps value is authoritative,
    /// matching Go's `BundleSHA256` field.)
    pub fn bundle_sha256(&self) -> String {
        self.deps.bundle_sha256.clone()
    }

    /// Bind the listen socket without serving yet, so the
    /// caller can print the startup line only after the
    /// bind succeeds (Go's `net.Listen` before the startup
    /// line in `cmdWebUIServe`).
    pub async fn bind(listen_addr: &str) -> std::io::Result<TcpListener> {
        TcpListener::bind(listen_addr).await
    }

    /// Serve forever on `listen_addr` (already validated
    /// loopback-only by the command layer). Binds the
    /// socket, then accepts connections; each connection
    /// runs `http1` with a 10s header-read timeout and a
    /// 120s idle timeout approximation. Returns on bind
    /// failure or on a fatal accept error.
    pub async fn serve(self: &Arc<Self>, listen_addr: &str) -> std::io::Result<()> {
        let listener = Self::bind(listen_addr).await?;
        self.serve_on(listener).await
    }

    /// Serve on an already-bound listener. The accept loop
    /// stops on [`Server::request_shutdown`]; in-flight
    /// connections then drain for up to 5s before the
    /// remainder are aborted (Go's 5s graceful shutdown).
    pub async fn serve_on(self: &Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        let mut joins: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                res = listener.accept() => {
                    let (stream, peer) = res?;
                    let server = Arc::clone(self);
                    joins.spawn(async move {
                        let io = TokioIo::new(stream);
                        let service = service_fn(move |req| {
                            let server = Arc::clone(&server);
                            async move { server.handle_hyper(req, peer).await }
                        });
                        let conn = http1::Builder::new()
                            .header_read_timeout(READ_HEADER_TIMEOUT)
                            .timer(hyper_util::rt::TokioTimer::new())
                            .serve_connection(io, service);
                        // No lifetime cap: Go's
                        // `http.Server.IdleTimeout` (120s) is
                        // idle-BETWEEN-requests only — it never
                        // cuts a connection mid-request and
                        // resets after every response. The
                        // previous code wrapped the whole
                        // connection in `timeout(IDLE_TIMEOUT,
                        // conn)`, a lifetime cap from accept
                        // that killed connections at 120s even
                        // mid-request. Hyper has no idle knob;
                        // the per-request header read timeout
                        // (10s) also bounds the wait for the
                        // next request's headers on a keep-alive
                        // connection, so it is the closest
                        // correct form. Residual: idle
                        // keep-alive connections are cut at
                        // 10s, not 120s — stricter
                        // (fail-closed); see PORTING §M6b.6
                        // and the probe in §M6b.9. A live WS
                        // is unaffected either way: the
                        // upgraded socket is detached from
                        // this connection.
                        let _ = conn.await;
                    });
                }
                _ = self.shutdown.notified() => break,
            }
            while joins.try_join_next().is_some() {}
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), joins.join_all()).await;
        Ok(())
    }

    /// Hyper entry point: validate the path, read the body
    /// only when the route needs one (capped at 1 MiB +
    /// 1), dispatch, and render the [`Resp`] with Go's
    /// Content-Length/chunked rule. A WS upgrade is
    /// detected here and handed to the screencast module
    /// before any body is read.
    async fn handle_hyper(
        self: &Arc<Self>,
        req: Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<HyperResponse<RespBody>, hyper::Error> {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let path_raw = uri.path().to_string();
        // The WS upgrade is a chi route: it matches the RAW
        // path, so an encoded `/screencast%2fws` is NOT an
        // upgrade (it falls through to the shell instead).
        let is_ws_upgrade = method == Method::GET
            && path_raw == "/api/v1/screencast/ws"
            && req
                .headers()
                .get("upgrade")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false);
        if is_ws_upgrade {
            // Go's `recoverer` wraps the whole router,
            // including the WS handler: a panic is the
            // fixed 500, never a dropped connection.
            use futures_util::FutureExt;
            return match std::panic::AssertUnwindSafe(self.handle_ws_upgrade(req, peer))
                .catch_unwind()
                .await
            {
                Ok(r) => r,
                Err(_) => Ok(render_resp(&Method::GET, internal_resp())),
            };
        }
        let headers = req.headers().clone();
        // Invalid escape: Go's stdlib 400s before any
        // handler — and before any body is read. The
        // stdlib body is the status text (`400 Bad
        // Request`); Content-Length is absent and the
        // connection closes, which hyper cannot emit —
        // recorded as a residual in PORTING §M6b.6.
        let path_decoded = match percent_decode_path(&path_raw) {
            Some(p) => p,
            None => {
                return Ok(render_resp(
                    &method,
                    Resp {
                        status: 400,
                        headers: vec![(
                            "Content-Type".to_string(),
                            "text/plain; charset=utf-8".to_string(),
                        )],
                        body: b"400 Bad Request".to_vec(),
                    },
                ));
            }
        };
        // Body policy (Go parity): only handlers that
        // decode a body read one — `route_reads_body`
        // mirrors Go's `decodeBody`/`bodyJSON` call sites
        // exactly. A 405, an unknown path, a 501 stub and
        // every GET never touch the body: the request is
        // dropped unread (hyper closes the connection after
        // the response, as Go does for unread bodies). A
        // body read is capped at `MAX_BODY_BYTES` (1 MiB +
        // 1, the largest Go per-handler cap) WHILE reading,
        // so an over-cap body is the fixed 400 before
        // dispatch — and before auth. The per-handler caps
        // (64 KiB / 1 MiB) still apply at decode time.
        let body: Vec<u8> = if crate::handlers::route_reads_body(&method, &path_raw) {
            match read_capped_body(req).await {
                Ok(b) => b,
                Err(_) => {
                    return Ok(render_resp(
                        &method,
                        api_error_resp(&crate::error::err_validation(
                            "invalid JSON in request body",
                        )),
                    ));
                }
            }
        } else {
            Vec::new()
        };
        let resp = with_recover(
            self.dispatch(&method, &path_raw, &path_decoded, &uri, &headers, peer, &body),
        )
        .await;
        Ok(render_resp(&method, resp))
    }

    /// Route + middleware dispatch. Routing uses the RAW
    /// (still percent-encoded) request path: chi routes on
    /// `r.URL.RawPath`, so `%2F` never splits a segment
    /// and an encoded static segment never matches
    /// (`/api/v1/%73tatus` is no route; `/profiles/a%2Fb`
    /// is one param, not two segments). `path_decoded` is
    /// Go's `r.URL.Path` (validated by `handle_hyper` —
    /// an invalid escape never reaches here); it is used
    /// only for the ui_dir filesystem path and for the WS
    /// suffix check in `dispatch_api` (Go's `requireAuth`
    /// tests the decoded suffix).
    async fn dispatch(
        self: &Arc<Self>,
        method: &Method,
        path_raw: &str,
        path_decoded: &str,
        uri: &hyper::Uri,
        headers: &hyper::HeaderMap,
        peer: SocketAddr,
        body: &[u8],
    ) -> Resp {
        // The mount prefix is matched on the RAW path: an
        // encoded prefix (`/api%2fv1/...`) matches no mount
        // and falls through to the shell unauthenticated.
        let is_api = path_raw == "/api/v1" || path_raw.starts_with("/api/v1/");
        if is_api {
            return self
                .dispatch_api(method, path_raw, path_decoded, uri, headers, peer, body)
                .await;
        }
        // Non-API: GET → shell; anything else → 405.
        // HEAD is NOT mapped to GET (chi has no GetHead
        // opt-in installed; Go's own uidir_test pins HEAD
        // → 405 for static paths).
        if *method != Method::GET {
            return method_not_allowed_resp();
        }
        self.serve_static(&path_decoded, method)
    }

    /// The `/api/v1` pipeline: rate-limit → auth → Origin
    /// → timeout → route. Runs for every path under the
    /// mount, including unknown ones (they fall through to
    /// the shell after the middleware). `path` is the raw
    /// path (routing); `path_decoded` is Go's `r.URL.Path`
    /// (WS suffix check + shell fallthrough).
    async fn dispatch_api(
        self: &Arc<Self>,
        method: &Method,
        path: &str,
        path_decoded: &str,
        uri: &hyper::Uri,
        headers: &hyper::HeaderMap,
        peer: SocketAddr,
        body: &[u8],
    ) -> Resp {
        let (attempts, window) = self.login_limits();
        let client_key = host_part(&peer.to_string()).to_string();
        {
            let mut limiter = self.rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
            if limiter.exceeded(&client_key, attempts.max(0) as u32, window) {
                return rate_limited_resp(window);
            }
        }
        // The WS path skips Bearer auth (Go's requireAuth
        // tests the DECODED `r.URL.Path` suffix, so an
        // encoded `/screencast%2fws` also skips auth — but
        // it then matches no route and falls through to
        // the shell, exactly as in Go).
        let is_ws = path_decoded.ends_with("/screencast/ws");
        if !is_ws {
            let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
            if !self.authorized(auth) {
                {
                    let mut limiter = self.rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
                    limiter.record_failure(&client_key, window);
                }
                return unauthorized_resp();
            }
            {
                let mut limiter = self.rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
                limiter.record_success(&client_key);
            }
        }
        // Origin: mutating methods only. An empty Origin
        // header is allowed by Go's requireSameOrigin
        // short-circuit (origin == "" → next), so it is
        // treated as absent here; api_origin_allowed
        // itself still rejects "" (Go's allowedOrigin("")
        // == false) and must not change.
        if matches!(
            method,
            &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE
        ) {
            let origin = headers
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .filter(|s| !s.is_empty());
            let host = headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !api_origin_allowed(origin, host) {
                return forbidden_resp();
            }
        }
        // Timeout: 30s, WS excluded. HEAD flows as an
        // ordinary unregistered method: a known path
        // answers 405 from the route table, an unknown
        // path falls through to the shell.
        let fut = self.route_api(method, path, path_decoded, uri, headers, peer, body);
        if is_ws {
            fut.await
        } else {
            match tokio::time::timeout(API_TIMEOUT, fut).await {
                Ok(resp) => resp,
                Err(_) => timeout_resp(),
            }
        }
        // HEAD is handled uniformly in render_resp (headers
        // kept, body stripped, Content-Length preserved).
    }

    /// Route one authenticated `/api/v1` request to its
    /// handler. A known path with a wrong method is a 405;
    /// an unknown path falls through to the shell. `path`
    /// is the RAW path (chi routes on RawPath — a trailing
    /// slash is a different path, e.g. `/api/v1/status/`
    /// matches no route and falls through); `path_decoded`
    /// is Go's `r.URL.Path`, passed to the shell
    /// fallthrough so the ui_dir filesystem lookup sees
    /// the decoded path.
    async fn route_api(
        self: &Arc<Self>,
        method: &Method,
        path: &str,
        path_decoded: &str,
        uri: &hyper::Uri,
        headers: &hyper::HeaderMap,
        peer: SocketAddr,
        body: &[u8],
    ) -> Resp {
        match crate::handlers::route(self, method, path, uri, headers, peer, body).await {
            crate::handlers::RouteOutcome::Handled(resp) => resp,
            crate::handlers::RouteOutcome::MethodNotAllowed => method_not_allowed_resp(),
            crate::handlers::RouteOutcome::Fallthrough => {
                self.serve_static(path_decoded, method)
            }
        }
    }

    /// The unauthenticated static shell (embedded, or the
    /// on-disk root when `ui_dir` is set). `method` is the
    /// original request method: non-API routing admits
    /// only GET, but API fallthrough can reach here with
    /// any method (HEAD included — unknown API path). The
    /// ui_dir lookup treats HEAD as GET (Go's serveUIDir
    /// does not branch on method); the HEAD body itself is
    /// suppressed by `render_resp`.
    pub fn serve_static(&self, path: &str, method: &Method) -> Resp {
        match &self.deps.ui_dir {
            None => shell_resp(),
            Some(ui_dir) => {
                let method_str = if method == Method::HEAD {
                    "GET"
                } else {
                    method.as_str()
                };
                serve_ui_dir(&self.deps.config_dir, ui_dir, method_str, path)
            }
        }
    }

    /// The screencast WS upgrade path (called before any
    /// body is read). Rate-limit applies (the upgrade
    /// passes through the outermost middleware); auth is
    /// the single-use `?session=` token, checked inside
    /// the WS handler.
    async fn handle_ws_upgrade(
        self: &Arc<Self>,
        req: Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<HyperResponse<RespBody>, hyper::Error> {
        let (attempts, window) = self.login_limits();
        let client_key = host_part(&peer.to_string()).to_string();
        {
            let mut limiter = self.rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
            if limiter.exceeded(&client_key, attempts.max(0) as u32, window) {
                let resp = rate_limited_resp(window);
                return Ok(render_resp(&Method::GET, resp));
            }
        }
        crate::screencast::handle_ws_upgrade(self, req, peer).await
    }
}

/// Decode a raw request path the way Go's `net/http`
/// decodes `r.URL.Path`: `%XX` sequences become bytes
/// (a `+` stays a `+` in paths); an invalid escape is an
/// error. The result is lossy UTF-8 for routing.
pub fn percent_decode_path(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = hex_val(bytes[i + 1])?;
            let lo = hex_val(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Why a capped body read failed: over the cap, or a
/// transport error mid-body. Both map to the same fixed
/// 400 at the call site (Go's `decodeBody` also reports
/// any read/decode failure as the fixed validation
/// error).
enum BodyRead {
    OverCap,
    Transport,
}

/// Run a response future under Go's `recoverer`
/// (`server.go:523`): a handler panic becomes the fixed
/// 500 `internal_error`, never a dropped connection (Go
/// writes the envelope and keeps serving). No reachable
/// trigger exists on the current request path (the only
/// request-path `expect` is the `log_gate` invariant in
/// `logs.rs`, and the WS starter + chat-send future
/// already guard themselves) — this is defence in depth,
/// matching Go's root-router recoverer.
async fn with_recover<Fut>(fut: Fut) -> Resp
where
    Fut: std::future::Future<Output = Resp>,
{
    use futures_util::FutureExt;
    match std::panic::AssertUnwindSafe(fut).catch_unwind().await {
        Ok(resp) => resp,
        Err(_) => internal_resp(),
    }
}

/// Read a request body frame by frame, stopping at
/// `MAX_BODY_BYTES` (1 MiB + 1) WITHOUT allocating past
/// it — Go's `http.MaxBytesReader` equivalent at the
/// transport edge. Returns the bytes when the whole body
/// fits, or an error (over-cap or transport) otherwise.
/// Trailers are ignored, as Go's decoder ignores them.
async fn read_capped_body(req: Request<Incoming>) -> Result<Vec<u8>, BodyRead> {
    let mut body = req.into_body();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| BodyRead::Transport)?;
        if let Ok(data) = frame.into_data() {
            if buf.len() + data.len() > MAX_BODY_BYTES {
                return Err(BodyRead::OverCap);
            }
            buf.extend_from_slice(&data);
        }
    }
    Ok(buf)
}

/// The hyper body type for responses.
pub type RespBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// Render a [`Resp`] as a hyper response, applying Go's
/// Content-Length/chunked rule: an explicit Content-Length
/// header is honoured as-is; otherwise bodies below the
/// 2048-byte sniff buffer get an automatic Content-Length
/// (hyper's `Full`), and larger bodies go chunked
/// (a single-chunk stream, no Content-Length). HEAD
/// responses keep the headers (with the Content-Length the
/// GET would have produced) and send an empty body.
/// This is NOT a HEAD→GET routing mapping — routing is
/// decided before this point (HEAD reaches a 405 or a
/// shell fallthrough); it reproduces Go net/http's HEAD
/// body suppression, so it is kept deliberately (fix loop
/// 1, R2): deleting it would send a body on HEAD
/// responses.
pub fn render_resp(method: &Method, resp: Resp) -> HyperResponse<RespBody> {
    let mut builder = HyperResponse::builder()
        .status(StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    let has_explicit_len = resp
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
    for (k, v) in &resp.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let body_bytes = Bytes::from(resp.body);
    if method == Method::HEAD {
        if !has_explicit_len {
            builder = builder.header("Content-Length", body_bytes.len().to_string());
        }
        return builder
            .body(Empty::<Bytes>::new().map_err(|e| match e {}).boxed())
            .expect("HEAD response builds");
    }
    if has_explicit_len || body_bytes.len() < GO_SNIFF_BUFFER {
        builder
            .body(Full::new(body_bytes).map_err(|e| match e {}).boxed())
            .expect("Full response builds")
    } else {
        let stream =
            stream_once(async move { Ok::<_, hyper::Error>(http_body::Frame::data(body_bytes)) });
        builder
            .body(StreamBody::new(stream).boxed())
            .expect("stream response builds")
    }
}

/// Decode a request body with a size cap into a generic
/// [`JsonValue`], preserving number literals and key
/// order. Mirrors Go's `bodyJSON`: over-cap, invalid JSON,
/// or trailing garbage → fixed 400 `validation_failed` /
/// `invalid JSON in request body`. A trailing VALID second
/// JSON value is tolerated, exactly as Go's second
/// `Decode` allows (see `go_decode`).
pub fn decode_body_json(body: &[u8], max_bytes: usize) -> Result<JsonValue, ApiError> {
    if body.len() > max_bytes {
        return Err(crate::error::err_validation("invalid JSON in request body"));
    }
    crate::go_decode::decode_body_value(body)
}

/// Decode a request body into a typed shape via a
/// field-extraction closure: the body is decoded as a
/// generic [`JsonValue`], the top level must be an object,
/// and unknown fields are rejected
/// (`DisallowUnknownFields` in Go's `decodeBody`).
///
/// Go matches struct fields case-INSENSITIVELY, and
/// case-variant duplicates collapse last-wins
/// (`{"content":"a","Content":"b"}` decodes as `"b"`).
/// The object is therefore folded by ASCII-lowercase key
/// before the allow-list check and the extractor: the
/// first position is kept, the last value wins (Go's
/// duplicate-key rule, applied case-insensitively).
pub fn decode_body_typed<F, T>(
    body: &[u8],
    max_bytes: usize,
    allowed: &[&str],
    extract: F,
) -> Result<T, ApiError>
where
    F: FnOnce(&castctl_config::jsonvalue::OrderedObject) -> Result<T, ApiError>,
{
    let value = decode_body_json(body, max_bytes)?;
    let JsonValue::Object(obj) = &value else {
        return Err(crate::error::err_validation("invalid JSON in request body"));
    };
    let obj = fold_case_keys(obj);
    for key in obj.keys() {
        if !allowed
            .iter()
            .any(|a| a.eq_ignore_ascii_case(key.as_str()))
        {
            return Err(crate::error::err_validation("invalid JSON in request body"));
        }
    }
    extract(&obj)
}

/// Fold an object's keys by ASCII-lowercase: the first
/// position is kept, the last value wins. Used only for
/// typed request bodies (Go struct decoding); stored
/// documents keep their exact keys.
fn fold_case_keys(obj: &castctl_config::jsonvalue::OrderedObject) -> OrderedObject {
    let mut out = OrderedObject::new();
    // Lowercase key -> first-seen original key.
    let mut first_keys: Vec<(String, String)> = Vec::new();
    for (k, v) in obj.iter() {
        let lower = k.to_ascii_lowercase();
        match first_keys.iter().find(|(l, _)| *l == lower) {
            Some((_, first)) => {
                let first = first.clone();
                out.set(first, v.clone());
            }
            None => {
                first_keys.push((lower, k.clone()));
                out.set(k.clone(), v.clone());
            }
        }
    }
    out
}

/// Extract a required string field, or a validation error
/// naming the field. `None` when the key is absent.
pub fn req_string(
    obj: &castctl_config::jsonvalue::OrderedObject,
    key: &str,
) -> Result<Option<String>, ApiError> {
    match obj.get(key) {
        None => Ok(None),
        Some(JsonValue::Str(s)) => Ok(Some(s.clone())),
        Some(_) => Err(crate::error::err_validation(format!(
            "{key} must be a string"
        ))),
    }
}

/// Extract an optional boolean field.
pub fn req_bool(
    obj: &castctl_config::jsonvalue::OrderedObject,
    key: &str,
) -> Result<Option<bool>, ApiError> {
    match obj.get(key) {
        None => Ok(None),
        Some(JsonValue::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(crate::error::err_validation(format!(
            "{key} must be a boolean"
        ))),
    }
}

/// The 64 KiB body cap (`decodeBody` for profile
/// create/patch/rename/delete, telegram PUT, webui-settings
/// PUT, chats start/send/op).
pub const BODY_CAP_64K: usize = 64 * 1024;
/// The 1 MiB body cap (login import, outbound/endpoint
/// create/patch/validate, config PUT/validate, DNS,
/// keeper-settings PUT, endpoint import).
pub const BODY_CAP_1M: usize = 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hyper_uri_path_keeps_raw_encoding() {
        // R3 probe (not an assumption): hyper's `Uri::path`
        // returns the request-target path verbatim — no
        // percent-decoding. Routing on this value reproduces
        // chi's RawPath behaviour; decoding it first would
        // let `%2F` split segments.
        let uri: hyper::Uri = "/api/v1/profiles/a%2Fb".parse().unwrap();
        assert_eq!(uri.path(), "/api/v1/profiles/a%2Fb");
        let uri: hyper::Uri = "/api/v1/%73tatus".parse().unwrap();
        assert_eq!(uri.path(), "/api/v1/%73tatus");
        let uri: hyper::Uri = "/api%2fv1/status".parse().unwrap();
        assert_eq!(uri.path(), "/api%2fv1/status");
        let uri: hyper::Uri = "/api/v1/status".parse().unwrap();
        assert_eq!(uri.path(), "/api/v1/status");
    }

    #[test]
    fn route_reads_body_table() {
        // R4 classifier: exactly the Go handlers that call
        // decodeBody/bodyJSON read a body; every other
        // route (GETs, 501 test stubs, restore, set-default,
        // screencast start, DELETE outbound/endpoint) never
        // does — Go returns 405/shell without reading.
        use hyper::Method;
        let yes = [
            (Method::POST, "/api/v1/profiles"),
            (Method::PATCH, "/api/v1/profiles/main"),
            (Method::DELETE, "/api/v1/profiles/main"),
            (Method::POST, "/api/v1/profiles/main/rename"),
            (Method::POST, "/api/v1/profiles/main/login/import"),
            (Method::POST, "/api/v1/outbounds"),
            (Method::POST, "/api/v1/outbounds/validate"),
            (Method::PATCH, "/api/v1/outbounds/tag"),
            (Method::POST, "/api/v1/endpoints"),
            (Method::POST, "/api/v1/endpoints/import"),
            (Method::PATCH, "/api/v1/endpoints/tag"),
            (Method::PUT, "/api/v1/config"),
            (Method::POST, "/api/v1/config/validate"),
            (Method::PUT, "/api/v1/dns"),
            (Method::PUT, "/api/v1/settings/telegram"),
            (Method::PUT, "/api/v1/settings/keeper"),
            (Method::PUT, "/api/v1/settings/webui"),
            (Method::POST, "/api/v1/chats/main"),
            (Method::POST, "/api/v1/chats/main/sess/send"),
            (Method::POST, "/api/v1/chats/main/sess/op"),
        ];
        for (m, p) in yes {
            assert!(
                crate::handlers::route_reads_body(&m, p),
                "{m} {p} must read a body"
            );
        }
        let no = [
            (Method::GET, "/api/v1/status"),
            (Method::GET, "/api/v1/profiles"),
            (Method::GET, "/api/v1/profiles/main"),
            (Method::DELETE, "/api/v1/outbounds/tag"),
            (Method::DELETE, "/api/v1/endpoints/tag"),
            (Method::POST, "/api/v1/profiles/main/test"),
            (Method::POST, "/api/v1/outbounds/tag/test"),
            (Method::POST, "/api/v1/profiles/main/login/restore"),
            (Method::POST, "/api/v1/profiles/main/set-default"),
            (Method::POST, "/api/v1/screencast/main/start"),
            (Method::POST, "/api/v1/status"),
            (Method::POST, "/api/v1/nope"),
            (Method::GET, "/api/v1/screencast/ws"),
            (Method::PUT, "/api/v1/status"),
        ];
        for (m, p) in no {
            assert!(
                !crate::handlers::route_reads_body(&m, p),
                "{m} {p} must NOT read a body"
            );
        }
    }
    /// Minimal valid config for the live-server tests: the
    /// webui block allows 100 failed attempts so the tests
    /// never trip the limiter.
    const LIVE_FIXTURE: &str = r#"{
  "default_profile": "muse01",
  "profiles": {
    "muse01": {
      "cookies_file": "profiles/muse01/cookies.txt",
      "outbound": "proxy-eu",
      "fingerprint": "chrome"
    }
  },
  "outbounds": [
    {"type": "trojan", "tag": "proxy-eu", "server": "203.0.113.10", "server_port": 443, "password": "SECRET-TROJAN"}
  ],
  "dns": {"servers": [{"tag": "dns1", "type": "tcp", "server": "127.0.0.1", "server_port": 5353}], "final": "dns1"},
  "webui": {"listen": "127.0.0.1:18318", "token": "plain-token", "login_rate_limit": {"attempts": 100, "window": "5m"}}
}"#;

    fn live_server(dir: &std::path::Path) -> Arc<Server> {
        let token_hash = crate::auth::hash_token("plain-token").expect("hash test token");
        Server::new(Deps {
            config_dir: dir.to_path_buf(),
            version: "0.9.0".to_string(),
            listen_addr: "127.0.0.1:0".to_string(),
            token_hash,
            has_token: <redacted>
            bundle_sha256: crate::static_shell::bundle_sha256(),
            ui_dir: None,
            cookies_files: Vec::new(),
            import_cookies: None,
            restore_cookies: None,
            screencast_available: None,
            screencast_starter: None,
            chats: None,
        })
        .expect("test server builds")
    }

    /// One raw HTTP request over a fresh TCP connection;
    /// returns the full response head + body as text.
    /// The write may break early (the server can 400/405
    /// while the client is still sending) — write errors
    /// are ignored, the response is what is asserted.
    async fn raw_request(port: u16, method: &str, path: &str, body_len: usize) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer plain-token\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
        );
        let _ = stream.write_all(head.as_bytes()).await;
        let chunk = vec![b'x'; 65536];
        let mut remaining = body_len;
        while remaining > 0 {
            let n = remaining.min(chunk.len());
            if stream.write_all(&chunk[..n]).await.is_err() {
                break;
            }
            remaining -= n;
        }
        let mut resp = Vec::new();
        let _ = stream.read_to_end(&mut resp).await;
        String::from_utf8_lossy(&resp).into_owned()
    }

    async fn live_server_case(method: &str, path: &str, body_len: usize) -> String {
        // Unique scratch dir per call: cargo runs the
        // live-server tests in parallel.
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "m6b-server-live-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.json"), LIVE_FIXTURE).unwrap();
        let server = live_server(&dir);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let srv = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let _ = srv.serve_on(listener).await;
        });
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            raw_request(port, method, path, body_len),
        )
        .await
        .expect("request completes");
        server.request_shutdown();
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
        resp
    }

    #[tokio::test]
    async fn over_cap_body_to_unknown_api_path_is_400() {
        // R4 fail-before: with the cap wired, a 2 MiB body
        // to an unknown API path is the fixed 400 BEFORE
        // dispatch. With the cap removed (MAX_BODY_BYTES
        // neutered huge), the body is read whole, dispatch
        // falls through to the shell, and this test goes
        // RED with 200 — that is the proof the cap, not
        // the per-handler decode cap, is doing the work.
        let resp = live_server_case("POST", "/api/v1/nope", 2 * 1024 * 1024).await;
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert!(resp.contains("invalid JSON in request body"), "{resp}");
    }

    #[tokio::test]
    async fn over_cap_body_to_wrong_method_is_405() {
        // Routing precedes any body read: a 2 MiB body to
        // a known path with the wrong method is a 405, not
        // a 400 — Go never reads the body for a 405.
        let resp = live_server_case("POST", "/api/v1/status", 2 * 1024 * 1024).await;
        assert!(resp.starts_with("HTTP/1.1 405"), "{resp}");
    }

    #[tokio::test]
    async fn body_on_get_is_ignored() {
        // GET routes never read a body: a 2 MiB body on a
        // GET is ignored and the request succeeds.
        let resp = live_server_case("GET", "/api/v1/status", 2 * 1024 * 1024).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    }

    #[tokio::test]
    async fn recoverer_maps_panic_to_fixed_500() {
        // M2: Go's root-router recoverer turns any handler
        // panic into the fixed 500 envelope.
        let resp = with_recover(async { panic!("boom") }).await;
        assert_eq!(resp.status, 500);
        let body = String::from_utf8(resp.body).unwrap();
        assert!(body.contains("internal_error"), "{body}");
    }

    #[tokio::test]
    async fn recoverer_passes_through_ok() {
        let resp = with_recover(async { envelope_resp(200, JsonValue::Number("1".to_string())) }).await;
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn decode_body_typed_is_case_insensitive() {
        // F-C4: Go's DisallowUnknownFields matches struct
        // fields case-insensitively.
        let body = br#"{"Content": "x", "BASE_SHA256": "abc"}"#;
        let out = decode_body_typed(body, BODY_CAP_64K, &["content", "base_sha256"], |obj| {
            req_string(obj, "content")
        })
        .expect("case variants accepted");
        assert_eq!(out, Some("x".to_string()));
        // Case-variant duplicates collapse last-wins.
        let body = br#"{"content": "a", "Content": "b"}"#;
        let out = decode_body_typed(body, BODY_CAP_64K, &["content"], |obj| {
            req_string(obj, "content")
        })
        .expect("duplicates collapse");
        assert_eq!(out, Some("b".to_string()));
        // Unknown fields are still rejected, any case.
        let body = br#"{"content": "a", "BOGUS": 1}"#;
        assert!(
            decode_body_typed(body, BODY_CAP_64K, &["content"], |obj| {
                req_string(obj, "content")
            })
            .is_err()
        );
    }

}
