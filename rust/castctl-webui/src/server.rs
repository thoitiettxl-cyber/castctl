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
/// recorded in PORTING §M6b.6; probe in §M6b.9). (Fix
/// loop 2: the old `IDLE_TIMEOUT` const is deleted — it
/// described a removed wrapper, not a live mechanism.)
/// Go `http.Server` default `MaxHeaderBytes`: 1 MiB.
/// `http.Server` in `internal/commands/webui.go:232-236`
/// sets no `MaxHeaderBytes`, so the stdlib default
/// (1 MiB) applies; hyper's read buffer defaults to
/// ~400 KiB, so the knob is set explicitly (fix loop 2,
/// B3). A head past this → hyper's automatic 431, the
/// same status Go sends.
pub const MAX_HEAD_BYTES: usize = 1024 * 1024;
/// Maximum header count: Go has NO count limit, only the
/// 1 MiB head-bytes cap. Hyper's knob cannot express
/// "no limit" for free: it allocates the header slot
/// array per request and writes it, so the exact
/// byte-cap-equivalent value (262,144 = 1 MiB / 4 B
/// minimal header line) costs ~14 MB of touched memory
/// on EVERY request — measured by proof 11 (VmHWM delta
/// +18,904 KiB wired at 262,144 vs +4,624 KiB in fix
/// loop 1 at the 100 default). 10,000 headers is the
/// chosen bound: it covers ~50 KB+ of minimal header
/// lines, far beyond any real client (browsers send
/// ~15-30), at ~560 KB touched per request. Residual,
/// recorded: a request with >10,000 headers inside
/// 1 MiB gets hyper's automatic 431 where Go accepts —
/// fail-closed, pathological input only.
pub const MAX_HEADERS: usize = 10_000;
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
/// attempts` with `Retry-After` = window seconds. Go sets
/// Retry-After BEFORE writeError's headers in code, but
/// net/http serializes headers sorted by key, so the wire
/// order is Cache-Control, Content-Type, Retry-After,
/// X-Content-Type-Options — `render_resp` sorts every
/// response, so the insertion position here is inert.
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
    /// runs `http1` with a 10s header-read timeout only
    /// (no idle timeout — hyper has no idle knob; see
    /// PORTING §M6b.6). Returns on bind failure or on a
    /// fatal accept error.
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
                            .max_headers(MAX_HEADERS)
                            .max_buf_size(MAX_HEAD_BYTES)
                            .timer(hyper_util::rt::TokioTimer::new())
                            .serve_connection(io, service);
                        // No lifetime cap: Go's
                        // `http.Server.IdleTimeout` (120s) is
                        // idle-BETWEEN-requests only — it never
                        // cuts a connection mid-request and
                        // resets after every response. The
                        // previous code wrapped the whole
                        // connection in a 120s `timeout`, a
                        // lifetime cap from accept that killed
                        // connections at 120s even mid-request.
                        // Hyper has no idle knob; the
                        // per-request header read timeout
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
                        //
                        // Framing knobs (fix loop 2, B3): Go's
                        // head cap is 1 MiB with no header-count
                        // limit (`MaxHeaderBytes` default); the
                        // byte knob is set exactly, the count
                        // knob to 10,000 (the exact equivalent
                        // 262,144 costs ~14 MB touched per
                        // request — measured, see MAX_HEADERS).
                        // Residuals hyper cannot express:
                        // `Transfer-Encoding` other than chunked
                        // is a hyper parse error (automatic 400,
                        // no response body) where Go answers
                        // 501, and a request URI over 65534
                        // bytes is hyper's automatic 414 where
                        // Go has no URI cap — both recorded in
                        // PORTING §M6b.6.
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

    /// Hyper entry point: validate the path, run the
    /// middleware gates on headers, read the body only
    /// when the route needs one (capped at 1 MiB + 1,
    /// inside the 30s API timeout), dispatch, and render
    /// the [`Resp`] with Go's Content-Length/chunked rule.
    /// A WS upgrade is detected here and handed to the
    /// screencast module before any body is read.
    ///
    /// Panic cover (fix loop 2, safety N-3): Go's root
    /// `recoverer` wraps the whole router, including
    /// response rendering, so this outer `catch_unwind`
    /// covers everything `with_recover` (dispatch only)
    /// does not — the body read and `render_resp`. No
    /// reachable trigger exists: `render_resp`'s three
    /// `.expect()`s fire only on an invalid status or
    /// header value, and every value it sees is a fixed
    /// string, a numeric, or base64 (`http` 1.3.1
    /// `Builder::header` records invalid values as
    /// builder errors instead of panicking) — verified
    /// against the crate source, not assumed. If one
    /// ever fired, the fallback renders the fixed 500
    /// envelope (status 500, fixed headers), which
    /// cannot fail the same way.
    async fn handle_hyper(
        self: &Arc<Self>,
        req: Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<HyperResponse<RespBody>, hyper::Error> {
        let method = req.method().clone();
        use futures_util::FutureExt;
        match std::panic::AssertUnwindSafe(self.handle_hyper_inner(req, peer))
            .catch_unwind()
            .await
        {
            Ok(r) => r,
            Err(_) => Ok(render_resp(&method, internal_resp())),
        }
    }

    async fn handle_hyper_inner(
        self: &Arc<Self>,
        req: Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<HyperResponse<RespBody>, hyper::Error> {
        let (parts, body) = req.into_parts();
        let method = parts.method.clone();
        let uri = parts.uri.clone();
        let path_raw = uri.path().to_string();
        // The WS upgrade is a chi route: it matches the RAW
        // path, so an encoded `/screencast%2fws` is NOT an
        // upgrade (it falls through to the shell instead).
        let is_ws_upgrade = method == Method::GET
            && path_raw == "/api/v1/screencast/ws"
            && parts
                .headers
                .get("upgrade")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false);
        if is_ws_upgrade {
            // Go's `recoverer` wraps the whole router,
            // including the WS handler: a panic is the
            // fixed 500, never a dropped connection.
            use futures_util::FutureExt;
            let req = Request::from_parts(parts, body);
            return match std::panic::AssertUnwindSafe(self.handle_ws_upgrade(req, peer))
                .catch_unwind()
                .await
            {
                Ok(r) => r,
                Err(_) => Ok(render_resp(&Method::GET, internal_resp())),
            };
        }
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
        // Body policy (Go parity, fix loop 2, B1): the body
        // is NOT read here. The middleware gates
        // (rate-limit → auth → Origin) run first, on
        // headers alone, inside `dispatch_api`; the capped
        // body read happens there, after the gates and
        // inside the 30s API timeout — exactly Go's order
        // (middleware in `server.go:258-276`, body read
        // inside the handler via `MaxBytesReader`,
        // `server.go:642-643`). The old pre-dispatch read
        // answered 400 to an over-cap body before auth ever
        // ran (Go: 401/429/403); it also never fed the
        // rate limiter. The cap itself is unchanged
        // (1 MiB + 1, `read_capped_body`); only the order
        // moved. A 405, an unknown path, a 501 stub and
        // every GET never touch the body: the request
        // stream is dropped unread (hyper closes the
        // connection after the response, as Go does for
        // unread bodies).
        let headers = parts.headers.clone();
        let resp = with_recover(self.dispatch(
            &method,
            &path_raw,
            &path_decoded,
            &uri,
            &headers,
            peer,
            body,
        ))
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
    // Arity mirrors Go's handler signature (method, raw +
    // decoded path, uri, headers, peer, body); precedent:
    // castctl-telegram's #[allow]s on the same lint.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch(
        self: &Arc<Self>,
        method: &Method,
        path_raw: &str,
        path_decoded: &str,
        uri: &hyper::Uri,
        headers: &hyper::HeaderMap,
        peer: SocketAddr,
        body: Incoming,
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
        // → 405 for static paths). The body stream is
        // dropped unread on every non-API path: Go's
        // static handler never reads a body either.
        drop(body);
        if *method != Method::GET {
            return method_not_allowed_resp();
        }
        self.serve_static(path_decoded, method)
    }

    /// The `/api/v1` pipeline: rate-limit → auth → Origin
    /// → timeout → route. Runs for every path under the
    /// mount, including unknown ones (they fall through to
    /// the shell after the middleware). `path` is the raw
    /// path (routing); `path_decoded` is Go's `r.URL.Path`
    /// (WS suffix check + shell fallthrough). The body
    /// stream arrives unread: it is read (capped) only
    /// after the gates, inside the timeout — see below.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_api(
        self: &Arc<Self>,
        method: &Method,
        path: &str,
        path_decoded: &str,
        uri: &hyper::Uri,
        headers: &hyper::HeaderMap,
        peer: SocketAddr,
        body: Incoming,
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
        // Body + route under the 30s API timeout (fix
        // loop 2, B1/B2): Go's `apiTimeout` wraps the
        // handler INCLUDING `decodeBody`
        // (`server.go:436-470`, `apiHandlerTimeout` 30s),
        // so the capped body read runs here — after the
        // gates above, inside the same budget as the
        // handler. A slow-drip body (or a lying
        // Content-Length) is therefore cut at 30s with
        // the same 503 `timeout` envelope; before this
        // fix the pre-dispatch read had no timeout at all
        // (hyper's header-read timeout disarms once the
        // head parses). HEAD flows as an ordinary
        // unregistered method: a known path answers 405
        // from the route table, an unknown path falls
        // through to the shell.
        let reads_body = crate::handlers::route_reads_body(method, path);
        let fut = async {
            let body_bytes: Vec<u8> = if reads_body {
                match read_capped_body(body).await {
                    Ok(b) => b,
                    Err(_) => {
                        return api_error_resp(&crate::error::err_validation(
                            "invalid JSON in request body",
                        ));
                    }
                }
            } else {
                Vec::new()
            };
            self.route_api(method, path, path_decoded, uri, headers, peer, &body_bytes)
                .await
        };
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
    #[allow(clippy::too_many_arguments)]
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
            crate::handlers::RouteOutcome::Fallthrough => self.serve_static(path_decoded, method),
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
/// Called from `dispatch_api` AFTER the middleware gates
/// and inside the 30s API timeout (fix loop 2, B1/B2):
/// the caller owns the timeout, this function owns only
/// the cap.
async fn read_capped_body(mut body: Incoming) -> Result<Vec<u8>, BodyRead> {
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
    // Go's net/http serializes response headers SORTED by
    // key (Header.writeSubset), regardless of the order
    // the handler set them: writeError sets Content-Type,
    // Cache-Control, X-Content-Type-Options (server.go)
    // and the rate limiter sets Retry-After before that,
    // yet the 429 goes out as Cache-Control, Content-Type,
    // Retry-After, X-Content-Type-Options (parity run 3).
    // hyper preserves insertion order, so sort here — the
    // single funnel every Resp passes through.
    let mut resp = resp;
    resp.headers.sort_by_key(|(k, _)| k.to_ascii_lowercase());
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
        // Go net/http HEAD semantics: the body is
        // suppressed, but the Content-Length the GET
        // would have produced is kept ONLY when the
        // body fits the 2048-byte sniff buffer (a small
        // envelope answers HEAD with `Content-Length:
        // 71`; the 964333-byte shell answers HEAD with
        // NO Content-Length — measured live, fix loop 2
        // N3). An explicit Content-Length (ui_dir assets)
        // is always kept.
        if !has_explicit_len && body_bytes.len() < GO_SNIFF_BUFFER {
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
        if !allowed.iter().any(|a| a.eq_ignore_ascii_case(key.as_str())) {
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
    // Keys are normalized to ASCII-lowercase: Go struct
    // decoding matches field names case-insensitively, and
    // the typed extractors below look up lowercase names
    // ("content", "base_sha256"). `OrderedObject::set`
    // replaces in place, so the first position is kept and
    // the last value wins (Go: later duplicate wins).
    let mut out = OrderedObject::new();
    for (k, v) in obj.iter() {
        out.set(k.to_ascii_lowercase(), v.clone());
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

    /// Same fixture with a 1-attempt limiter, so one
    /// failed login trips the rate limit (fix loop 2:
    /// the over-cap → 429 pin needs a tripped limiter
    /// without 100 bcrypt verifies).
    const LIVE_FIXTURE_STRICT: &str = r#"{
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
  "webui": {"listen": "127.0.0.1:18318", "token": "plain-token", "login_rate_limit": {"attempts": 1, "window": "5m"}}
}"#;

    fn live_server(dir: &std::path::Path) -> Arc<Server> {
        let token_hash = crate::auth::hash_token("plain-token").expect("hash test token");
        Server::new(Deps {
            config_dir: dir.to_path_buf(),
            version: "0.9.0".to_string(),
            listen_addr: "127.0.0.1:0".to_string(),
            token_hash,
            has_token: true,
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
    /// `auth`: `Some("plain-token")` sends the valid
    /// Bearer token, `Some(other)` sends that token,
    /// `None` sends no Authorization header at all.
    /// `extra`: additional head lines (e.g. Origin).
    async fn raw_request_full(
        port: u16,
        method: &str,
        path: &str,
        body_len: usize,
        auth: Option<&str>,
        extra: &[(&str, &str)],
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n");
        if let Some(token) = auth {
            head.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        for (k, v) in extra {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
        ));
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

    async fn raw_request(port: u16, method: &str, path: &str, body_len: usize) -> String {
        raw_request_full(port, method, path, body_len, Some("plain-token"), &[]).await
    }

    /// Start a live server on a scratch dir + port;
    /// returns `(server, port, task, dir)`. The caller
    /// shuts it down (`request_shutdown` + abort) and
    /// removes the dir.
    async fn start_live_server(
        fixture: &str,
    ) -> (
        Arc<Server>,
        u16,
        tokio::task::JoinHandle<()>,
        std::path::PathBuf,
    ) {
        // Unique scratch dir per call: cargo runs the
        // live-server tests in parallel.
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("m6b-server-live-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.json"), fixture).unwrap();
        let server = live_server(&dir);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let srv = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let _ = srv.serve_on(listener).await;
        });
        (server, port, handle, dir)
    }

    async fn live_server_case(method: &str, path: &str, body_len: usize) -> String {
        let (server, port, handle, dir) = start_live_server(LIVE_FIXTURE).await;
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

    async fn live_server_case_full(
        fixture: &str,
        method: &str,
        path: &str,
        body_len: usize,
        auth: Option<&str>,
        extra: &[(&str, &str)],
    ) -> String {
        let (server, port, handle, dir) = start_live_server(fixture).await;
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            raw_request_full(port, method, path, body_len, auth, extra),
        )
        .await
        .expect("request completes");
        server.request_shutdown();
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
        resp
    }

    #[tokio::test]
    async fn head_shell_has_no_content_length() {
        // Fix loop 2, N3 (measured live): Go answers a
        // HEAD on the 964333-byte shell with NO
        // Content-Length; the old code always sent the
        // explicit `964333`.
        let resp = live_server_case("HEAD", "/api/v1/nope", 0).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(
            !resp.to_ascii_lowercase().contains("content-length"),
            "{resp}"
        );
    }

    #[tokio::test]
    async fn head_small_envelope_keeps_content_length() {
        // Fix loop 2, N3 (measured live): Go answers a
        // HEAD on a small envelope (405, 71-byte body)
        // WITH `Content-Length: 71` — the sniff-buffer
        // rule applies to HEAD too.
        let resp = live_server_case("HEAD", "/api/v1/status", 0).await;
        assert!(resp.starts_with("HTTP/1.1 405"), "{resp}");
        assert!(
            resp.to_ascii_lowercase().contains("content-length: 71"),
            "{resp}"
        );
    }

    #[tokio::test]
    async fn over_cap_body_to_unknown_api_path_falls_through() {
        // R4, corrected: an unknown API path never reads a
        // body (`route_reads_body` is false), so a 2 MiB
        // body falls through to the shell 200 — exactly as
        // Go does (Go never reads the body for an unknown
        // path either). The earlier version of this test
        // asserted 400 on a false premise (that unknown
        // paths read the body first); the pre-dispatch cap
        // changes MEMORY, not status, for these paths, and
        // is proven by the RSS proof in §M6b.9, not here.
        let resp = live_server_case("POST", "/api/v1/nope", 2 * 1024 * 1024).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    }

    #[tokio::test]
    async fn over_cap_body_to_body_route_is_400() {
        // R4: a 2 MiB body to a body-taking route with a
        // valid token is the fixed 400 — after the gates,
        // not before them (fix loop 2, B1: the gates run
        // on headers first; only an authenticated,
        // same-origin caller reaches the capped read).
        // (Neutering MAX_BODY_BYTES leaves this 400 in
        // place via the per-handler 1 MiB cap, so this
        // test pins the outcome, not the pre-dispatch cap
        // itself — the cap is proven by the RSS proof in
        // §M6b.9.)
        let resp = live_server_case("POST", "/api/v1/config/validate", 2 * 1024 * 1024).await;
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert!(resp.contains("invalid JSON in request body"), "{resp}");
    }

    #[tokio::test]
    async fn over_cap_body_without_token_is_401() {
        // Fix loop 2, B1: the gates run before the body
        // read, so an unauthenticated over-cap POST is
        // Go's 401, not the 400 the old pre-dispatch read
        // answered — and the attempt feeds the limiter's
        // failure counter exactly as an under-cap 401
        // does.
        let resp = live_server_case_full(
            LIVE_FIXTURE,
            "POST",
            "/api/v1/config/validate",
            2 * 1024 * 1024,
            None,
            &[],
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 401"), "{resp}");
    }

    #[tokio::test]
    async fn over_cap_body_with_bad_origin_is_403() {
        // Fix loop 2, B1: same ordering for Origin — a
        // valid token + cross-origin over-cap POST is
        // Go's 403, not 400.
        let resp = live_server_case_full(
            LIVE_FIXTURE,
            "POST",
            "/api/v1/config/validate",
            2 * 1024 * 1024,
            Some("plain-token"),
            &[("Origin", "https://evil.example")],
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    }

    #[tokio::test]
    async fn over_cap_body_when_rate_limited_is_429() {
        // Fix loop 2, B1: a rate-limited client sending
        // an over-cap body is Go's 429 — the limiter is
        // consulted before any body byte is read. The
        // strict fixture trips after one failed login.
        let (server, port, handle, dir) = start_live_server(LIVE_FIXTURE_STRICT).await;
        let bad =
            raw_request_full(port, "GET", "/api/v1/status", 0, Some("wrong-token"), &[]).await;
        assert!(bad.starts_with("HTTP/1.1 401"), "{bad}");
        let resp = raw_request_full(
            port,
            "POST",
            "/api/v1/config/validate",
            2 * 1024 * 1024,
            None,
            &[],
        )
        .await;
        server.request_shutdown();
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(resp.starts_with("HTTP/1.1 429"), "{resp}");
    }

    #[tokio::test]
    async fn slow_drip_body_times_out_at_30s() {
        // Fix loop 2, B2: a body that drips 1 KiB and
        // then stalls is cut at the 30s API timeout with
        // Go's 503 `timeout` envelope — not held forever.
        // Real-time wait (31s): a paused-clock variant
        // was tried and REJECTED — under
        // `tokio::time::pause`, `advance(31s)` makes
        // hyper close the connection with an empty
        // response (measured: 0 bytes), while the same
        // code in real time delivers the 503. The paused
        // clock is not a faithful probe of hyper's timer
        // interaction, so this test pays the 31s.
        let (server, port, handle, dir) = start_live_server(LIVE_FIXTURE).await;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let head = "POST /api/v1/config/validate HTTP/1.1\r\n\
            Host: 127.0.0.1\r\n\
            Authorization: Bearer plain-token\r\n\
            Content-Type: application/json\r\n\
            Content-Length: 65536\r\n\
            Connection: close\r\n\r\n";
        stream.write_all(head.as_bytes()).await.expect("head");
        // Valid-but-incomplete JSON prefix (an unterminated
        // string): the read must block on the missing rest,
        // not fail fast on content — Go's decoder fails a
        // garbage prefix at once (parity run 1: Go 400 in
        // 0.1s), which proves nothing about the timeout.
        let mut prefix = b"{\"content\": \"".to_vec();
        prefix.extend(std::iter::repeat_n(b'a', 1011));
        debug_assert_eq!(prefix.len(), 1024);
        stream.write_all(&prefix).await.expect("first KiB");
        // No more bytes: the server must 503 at 30s.
        let mut resp = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(45),
            stream.read_to_end(&mut resp),
        )
        .await;
        server.request_shutdown();
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
        let text = String::from_utf8_lossy(&resp).into_owned();
        assert!(text.starts_with("HTTP/1.1 503"), "{text}");
        assert!(text.contains("request timed out"), "{text}");
    }

    #[tokio::test]
    async fn many_headers_are_accepted() {
        // Fix loop 2, B3: Go has no header-count limit
        // (only the 1 MiB head cap); 101 headers must not
        // 431 — the old hyper default (100) did.
        let mut extra: Vec<(String, String)> = Vec::new();
        for i in 0..101 {
            extra.push((format!("X-Test-{i}"), "v".to_string()));
        }
        let extra_refs: Vec<(&str, &str)> = extra
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let (server, port, handle, dir) = start_live_server(LIVE_FIXTURE).await;
        let resp = raw_request_full(
            port,
            "GET",
            "/api/v1/status",
            0,
            Some("plain-token"),
            &extra_refs,
        )
        .await;
        server.request_shutdown();
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    }

    #[tokio::test]
    async fn more_than_max_headers_is_431() {
        // Fix loop 2, B3 (recorded residual): MAX_HEADERS
        // is 10,000, not Go's unbounded count — a request
        // with 10,001 headers gets hyper's automatic 431
        // where Go accepts. Fail-closed, pathological
        // input only; pinned so the boundary is explicit.
        let mut extra: Vec<(String, String)> = Vec::new();
        for i in 0..10_001 {
            extra.push((format!("X-Test-{i}"), "v".to_string()));
        }
        let extra_refs: Vec<(&str, &str)> = extra
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let (server, port, handle, dir) = start_live_server(LIVE_FIXTURE).await;
        let resp = raw_request_full(
            port,
            "GET",
            "/api/v1/status",
            0,
            Some("plain-token"),
            &extra_refs,
        )
        .await;
        server.request_shutdown();
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(resp.starts_with("HTTP/1.1 431"), "{resp}");
    }

    #[tokio::test]
    async fn huge_single_header_is_accepted() {
        // Fix loop 2, B3: a single 500 KiB header is
        // inside Go's 1 MiB head cap; the old hyper
        // default read buffer (~400 KiB) 431'd it.
        let big = "a".repeat(500 * 1024);
        let resp = live_server_case_full(
            LIVE_FIXTURE,
            "GET",
            "/api/v1/status",
            0,
            Some("plain-token"),
            &[("X-Big", &big)],
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    }

    #[tokio::test]
    async fn transfer_encoding_gzip_is_hyper_400() {
        // Fix loop 2, B3 (TE half): hyper rejects a
        // non-chunked Transfer-Encoding at parse time
        // with its automatic 400 — the service never sees
        // the request, so Go's 501 cannot be emitted at
        // this layer. Pinned as the recorded residual
        // (PORTING §M6b.6), not as a match.
        let (server, port, handle, dir) = start_live_server(LIVE_FIXTURE).await;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let head = "POST /api/v1/config/validate HTTP/1.1\r\n\
            Host: 127.0.0.1\r\n\
            Authorization: Bearer plain-token\r\n\
            Transfer-Encoding: gzip\r\n\
            Content-Length: 5\r\n\
            Connection: close\r\n\r\nhello";
        stream.write_all(head.as_bytes()).await.expect("head");
        let mut resp = Vec::new();
        let _ = stream.read_to_end(&mut resp).await;
        server.request_shutdown();
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
        let text = String::from_utf8_lossy(&resp).into_owned();
        assert!(text.starts_with("HTTP/1.1 400"), "{text}");
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
        let resp =
            with_recover(async { envelope_resp(200, JsonValue::Number("1".to_string())) }).await;
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
