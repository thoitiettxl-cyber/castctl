// SPDX-License-Identifier: GPL-3.0-only
// Screencast relay: the web UI front-end for
// keeper.LoginSession, over the frozen keeper.Transport
// boundary. Port of Go internal/webui/screencast.go.
//
// This package sends no CDP calls of its own and imports
// no chromedp package: the runner (attach to the user's
// Chrome) lives in internal/keeper behind the
// with_chromedp tag, reached through the injected
// ScreencastStarter. Without the tag, the starter seam is
// nil and the page and the API say unavailable.
//
// Session auth: POST /screencast/{profile}/start (Bearer)
// mints a single-use opaque session token (crypto/rand,
// 5-minute TTL, in-memory only, never logged). The
// WebSocket validates that token from its query string —
// a browser WebSocket cannot set an Authorization header,
// and a Bearer token must never be put in a query string.
// At most one live session per profile.
//
// M6b status ("chưa nối"): the Rust build has no chromedp
// build tag and no keeper crate yet, so the starter seam is
// ALWAYS nil. Start mints a token but the WebSocket then
// 503s after consume — matching Go's nil-starter branch
// order. Availability follows the with_chromedp Go branch
// (the cue Go binary is built WITH chromedp): a keeper
// entry with a browser URL for the profile means
// available, anything else names the missing entry.

use crate::error::{ApiError, err_validation};
use crate::go_json::encode_go_json;
use crate::origin::ws_origin_allowed;
use crate::server::{Resp, envelope_resp, error_resp};
use crate::store::{ConfigLoad, parse_loaded};
use base64::Engine as _;
use castctl_config::jsonvalue::{JsonValue, OrderedObject};
use http_body_util::BodyExt;
use rand::Rng as _;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const SCREENCAST_SESSION_TTL: Duration = Duration::from_secs(5 * 60);
pub const MAX_SCREENCAST_INPUT: usize = 64;
/// The keeper login timeout (15m) bounding one WS session.
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// `LoginOutcome` (keeper/login.go): the closed set of
/// session outcomes. Runners report done/cancelled/failed;
/// the core adds timeout for its own deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginOutcome {
    Done,
    Saved,
    Cancelled,
    Timeout,
    Failed,
}

impl LoginOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            LoginOutcome::Done => "done",
            LoginOutcome::Saved => "saved",
            LoginOutcome::Cancelled => "cancelled",
            LoginOutcome::Timeout => "timeout",
            LoginOutcome::Failed => "failed",
        }
    }
}

/// `LoginResult` (keeper/login.go): the session's terminal
/// report. `earliest_expiry` is an RFC3339 string when set.
#[derive(Debug, Clone)]
pub struct LoginResult {
    pub outcome: LoginOutcome,
    pub cookies_saved: bool,
    pub saved_names: Vec<String>,
    pub earliest_expiry: Option<String>,
}

impl LoginResult {
    pub fn failed() -> Self {
        LoginResult {
            outcome: LoginOutcome::Failed,
            cookies_saved: false,
            saved_names: Vec::new(),
            earliest_expiry: None,
        }
    }

    /// The terminal report map (sorted keys, as Go's
    /// `map[string]any` renders): type/result, outcome,
    /// cookies_saved, saved_names, earliest_expiry?.
    pub fn to_json(&self) -> JsonValue {
        let mut obj = OrderedObject::new();
        obj.set("cookies_saved", JsonValue::Bool(self.cookies_saved));
        if let Some(exp) = &self.earliest_expiry {
            obj.set("earliest_expiry", JsonValue::Str(exp.clone()));
        }
        obj.set("outcome", JsonValue::Str(self.outcome.as_str().to_string()));
        obj.set(
            "saved_names",
            JsonValue::Array(
                self.saved_names
                    .iter()
                    .map(|n| JsonValue::Str(n.clone()))
                    .collect(),
            ),
        );
        obj.set("type", JsonValue::Str("result".to_string()));
        JsonValue::Object(obj)
    }
}

/// `SessionPhase` (keeper/transport.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    Loading,
    Ready,
    LoggedInDetected,
    Done,
    Failed,
    Cancelled,
}

impl SessionPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionPhase::Loading => "loading",
            SessionPhase::Ready => "ready",
            SessionPhase::LoggedInDetected => "logged_in_detected",
            SessionPhase::Done => "done",
            SessionPhase::Failed => "failed",
            SessionPhase::Cancelled => "cancelled",
        }
    }
}

/// `Frame` (keeper/transport.go): one screencast JPEG
/// frame. Data is the raw JPEG bytes; SessionID is the
/// CDP frame number, used only for the ack.
#[derive(Debug, Clone)]
pub struct Frame {
    pub data: Vec<u8>,
    pub session_id: i64,
    pub width: i32,
    pub height: i32,
}

impl Frame {
    /// The frame message (sorted keys, as Go's
    /// `map[string]any` renders): data (base64 JPEG),
    /// height, type, width.
    pub fn to_json(&self) -> JsonValue {
        let mut obj = OrderedObject::new();
        obj.set(
            "data",
            JsonValue::Str(base64::engine::general_purpose::STANDARD.encode(&self.data)),
        );
        obj.set("height", JsonValue::Number(self.height.to_string()));
        obj.set("type", JsonValue::Str("frame".to_string()));
        obj.set("width", JsonValue::Number(self.width.to_string()));
        JsonValue::Object(obj)
    }
}

/// `InputKind` (keeper/transport.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Mouse,
    Key,
    Text,
    Done,
    Cancel,
}

impl InputKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            InputKind::Mouse => "mouse",
            InputKind::Key => "key",
            InputKind::Text => "text",
            InputKind::Done => "done",
            InputKind::Cancel => "cancel",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "mouse" => Some(InputKind::Mouse),
            "key" => Some(InputKind::Key),
            "text" => Some(InputKind::Text),
            "done" => Some(InputKind::Done),
            "cancel" => Some(InputKind::Cancel),
            _ => None,
        }
    }
}

/// `InputEvent` (keeper/transport.go). Modifiers is the
/// CDP bitmask (Alt=1, Ctrl=2, Meta=4, Shift=8). No event
/// carries a secret.
#[derive(Debug, Clone, PartialEq)]
pub struct InputEvent {
    pub kind: InputKind,
    pub mouse_type: String,
    pub button: String,
    pub x: f64,
    pub y: f64,
    pub click_count: i64,
    pub delta_x: f64,
    pub delta_y: f64,
    pub key_type: String,
    pub key: String,
    pub text: String,
    pub modifiers: i64,
}

/// The client's input message shape. Unknown fields are
/// ignored; kind and type vocabularies are allowlisted
/// before any event reaches the runner.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct WsInputMessage {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub mouse_type: String,
    #[serde(default)]
    pub button: String,
    #[serde(default)]
    pub x: f64,
    #[serde(default)]
    pub y: f64,
    #[serde(default)]
    pub click_count: i64,
    #[serde(default)]
    pub delta_x: f64,
    #[serde(default)]
    pub delta_y: f64,
    #[serde(default)]
    pub key_type: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub modifiers: i64,
}

/// `validateWSInput` (Go screencast.go): allowlists the
/// kind/type vocabularies and the numeric bounds. Anything
/// invalid is dropped silently by the caller.
pub fn validate_ws_input(msg: &WsInputMessage) -> Option<InputEvent> {
    match InputKind::from_name(&msg.kind)? {
        InputKind::Mouse => {
            if !matches!(
                msg.mouse_type.as_str(),
                "mousePressed" | "mouseReleased" | "mouseMoved" | "mouseWheel"
            ) {
                return None;
            }
            if !matches!(
                msg.button.as_str(),
                "left" | "middle" | "right" | "back" | "forward" | "none" | ""
            ) {
                return None;
            }
            if !(0..=3).contains(&msg.click_count) {
                return None;
            }
            if !(0..=15).contains(&msg.modifiers) {
                return None;
            }
            Some(InputEvent {
                kind: InputKind::Mouse,
                mouse_type: msg.mouse_type.clone(),
                button: msg.button.clone(),
                x: msg.x,
                y: msg.y,
                click_count: msg.click_count,
                delta_x: msg.delta_x,
                delta_y: msg.delta_y,
                key_type: String::new(),
                key: String::new(),
                text: String::new(),
                modifiers: msg.modifiers,
            })
        }
        InputKind::Key => {
            if !matches!(
                msg.key_type.as_str(),
                "keyDown" | "keyUp" | "rawKeyDown" | "char"
            ) {
                return None;
            }
            if msg.key.len() > 64 {
                return None;
            }
            // Key-event Text shares the Text-kind 1024
            // bound: an uncapped Text would reach the
            // keeper dispatch path verbatim.
            if msg.text.len() > 1024 {
                return None;
            }
            if !(0..=15).contains(&msg.modifiers) {
                return None;
            }
            Some(InputEvent {
                kind: InputKind::Key,
                mouse_type: String::new(),
                button: String::new(),
                x: 0.0,
                y: 0.0,
                click_count: 0,
                delta_x: 0.0,
                delta_y: 0.0,
                key_type: msg.key_type.clone(),
                key: msg.key.clone(),
                text: msg.text.clone(),
                modifiers: msg.modifiers,
            })
        }
        InputKind::Text => {
            if msg.text.is_empty() || msg.text.len() > 1024 {
                return None;
            }
            Some(InputEvent {
                kind: InputKind::Text,
                mouse_type: String::new(),
                button: String::new(),
                x: 0.0,
                y: 0.0,
                click_count: 0,
                delta_x: 0.0,
                delta_y: 0.0,
                key_type: String::new(),
                key: String::new(),
                text: msg.text.clone(),
                modifiers: 0,
            })
        }
        InputKind::Done => Some(InputEvent {
            kind: InputKind::Done,
            mouse_type: String::new(),
            button: String::new(),
            x: 0.0,
            y: 0.0,
            click_count: 0,
            delta_x: 0.0,
            delta_y: 0.0,
            key_type: String::new(),
            key: String::new(),
            text: String::new(),
            modifiers: 0,
        }),
        InputKind::Cancel => Some(InputEvent {
            kind: InputKind::Cancel,
            mouse_type: String::new(),
            button: String::new(),
            x: 0.0,
            y: 0.0,
            click_count: 0,
            delta_x: 0.0,
            delta_y: 0.0,
            key_type: String::new(),
            key: String::new(),
            text: String::new(),
            modifiers: 0,
        }),
    }
}

/// A phase notice (sorted keys, as Go's `map[string]any`
/// renders): detail, phase, type.
pub fn phase_message(phase: SessionPhase, detail: &str) -> String {
    let mut obj = OrderedObject::new();
    obj.set("detail", JsonValue::Str(detail.to_string()));
    obj.set("phase", JsonValue::Str(phase.as_str().to_string()));
    obj.set("type", JsonValue::Str("phase".to_string()));
    encode_go_json(&JsonValue::Object(obj))
}

// --- session registry -----------------------------------------

struct ScreencastSession {
    profile: String,
    expires_at: Instant,
    live: bool,
    consumed: bool,
}

struct RegistryInner {
    sessions: HashMap<String, ScreencastSession>,
    by_profile: HashMap<String, String>,
}

/// `sessionRegistry` (Go screencast.go): mints, consumes,
/// and tracks screencast sessions. A token is consumed on
/// first WebSocket connect; an expired or unknown token is
/// a 401 before upgrade.
pub struct ScreencastRegistry {
    inner: Mutex<RegistryInner>,
}

#[derive(Debug)]
pub enum MintError {
    Busy,
    Random,
}

#[derive(Debug)]
pub enum ConsumeError {
    Unknown,
    Busy,
}

impl ScreencastRegistry {
    pub fn new() -> Self {
        ScreencastRegistry {
            inner: Mutex::new(RegistryInner {
                sessions: HashMap::new(),
                by_profile: HashMap::new(),
            }),
        }
    }

    pub fn mint(&self, profile_name: &str) -> Result<String, MintError> {
        let mut raw = [0u8; 32];
        rand::rng().fill_bytes(&mut raw);
        let token = hex_encode(&raw);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        // Prune expired unconsumed tokens (bounded map; the
        // live check below is what enforces one session per
        // profile).
        inner
            .sessions
            .retain(|_, sess| sess.live || now <= sess.expires_at);
        if let Some(existing) = inner.by_profile.get(profile_name)
            && let Some(sess) = inner.sessions.get(existing)
            && sess.live
        {
            return Err(MintError::Busy);
        }
        inner.sessions.insert(
            token.clone(),
            ScreencastSession {
                profile: profile_name.to_string(),
                expires_at: now + SCREENCAST_SESSION_TTL,
                live: false,
                consumed: false,
            },
        );
        Ok(token)
    }

    /// Consume validates and single-use consumes a token,
    /// marking its session live. Returns the profile name.
    pub fn consume(&self, token: &str) -> Result<String, ConsumeError> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        // Validate first, under a short borrow: the busy
        // check below reads `by_profile` off the same map,
        // so the session borrow must end before it.
        let profile = {
            let sess = inner.sessions.get_mut(token).ok_or(ConsumeError::Unknown)?;
            if sess.consumed {
                // Single-use: a replayed token is unknown,
                // even while its session is live (the busy
                // branch below is for a DIFFERENT token for
                // the same profile).
                return Err(ConsumeError::Unknown);
            }
            if now > sess.expires_at {
                // Expired: drop it so a later mint is not
                // blocked by a stale byProfile entry.
                let _ = inner.sessions.remove(token);
                return Err(ConsumeError::Unknown);
            }
            sess.profile.clone()
        };
        // Busy check BEFORE marking consumed: a token
        // presented while another session is live must stay
        // consumable after the live session ends; burning
        // it here would strand the operator with an
        // "unknown session" error.
        if let Some(existing) = inner.by_profile.get(&profile).cloned()
            && let Some(other) = inner.sessions.get(&existing)
            && other.live
        {
            return Err(ConsumeError::Busy);
        }
        let sess = inner.sessions.get_mut(token).ok_or(ConsumeError::Unknown)?;
        sess.consumed = true;
        // Kept in the map while live: mint()'s busy check
        // reads it through byProfile. release() removes
        // both entries.
        sess.live = true;
        inner.by_profile.insert(profile.clone(), token.to_string());
        Ok(profile)
    }

    pub fn release(&self, profile_name: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(token) = inner.by_profile.remove(profile_name) {
            inner.sessions.remove(&token);
        }
    }
}

impl Default for ScreencastRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn hex_encode(raw: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len() * 2);
    for b in raw {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// --- availability + handlers ----------------------------------

fn no_keeper_entry_msg(profile_name: &str) -> String {
    format!(
        "no keeper entry for profile \"{}\": add a \"keeper\" entry with a browser URL (see docs/config.md)",
        profile_name
    )
}

/// `webuiScreencastAvailable` (Go internal/commands/webui.go,
/// with_chromedp branch — the cue Go binary is built WITH
/// chromedp): a keeper entry naming the profile with a
/// browser URL means available; anything else names the
/// missing entry. A config that cannot be loaded/parsed is
/// an error (the status/start handlers render it as a 400
/// with the safe message).
pub fn screencast_availability(
    config_dir: &Path,
    load: &ConfigLoad,
    profile_name: &str,
) -> Result<(bool, String), ApiError> {
    if !load.state.found {
        return Ok((false, "no config file".to_string()));
    }
    let (cfg, _) = parse_loaded(load, config_dir)?;
    let entries = match &cfg.keeper_raw {
        None => {
            return Ok((false, no_keeper_entry_msg(profile_name)));
        }
        Some(raw) => crate::validate::parse_keeper_block(raw)
            .map_err(|e| err_validation(crate::error::safe_message_str(&e.to_string())))?,
    };
    for entry in &entries {
        if entry.profile == profile_name && !entry.browser.is_empty() {
            return Ok((true, String::new()));
        }
    }
    Ok((false, no_keeper_entry_msg(profile_name)))
}

/// GET /screencast/status: `?profile=` or the default
/// profile. Response map (sorted keys): available,
/// profile, reason.
pub fn handle_screencast_status(
    config_dir: &Path,
    load: &ConfigLoad,
    query: &[(String, String)],
) -> Result<Resp, ApiError> {
    let mut profile_name = crate::logs::query_value(query, "profile").unwrap_or_default();
    if profile_name.is_empty()
        && load.state.found
        && let Ok((cfg, _)) = parse_loaded(load, config_dir)
    {
        profile_name = cfg.default_profile.clone();
    }
    let (available, reason) = screencast_availability(config_dir, load, &profile_name)?;
    let mut map = OrderedObject::new();
    map.set("available", JsonValue::Bool(available));
    map.set("profile", JsonValue::Str(profile_name));
    map.set("reason", JsonValue::Str(reason));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

/// POST /screencast/{profile}/start (Bearer): mint a
/// single-use token. Availability error → 400;
/// unavailable → 503; nil starter (always, in M6b) →
/// 503; busy → 409; success `{session_id, ws_url}`.
pub fn handle_screencast_start(
    config_dir: &Path,
    registry: &ScreencastRegistry,
    load: &ConfigLoad,
    profile_name: &str,
    starter_present: bool,
) -> Resp {
    let (available, reason) = match screencast_availability(config_dir, load, profile_name) {
        Ok(v) => v,
        Err(e) => return crate::server::api_error_resp(&e),
    };
    if !available {
        return error_resp(503, "screencast_unavailable", &reason);
    }
    if !starter_present {
        return error_resp(
            503,
            "screencast_unavailable",
            "screencast unavailable in this build (rebuild with -tags with_chromedp)",
        );
    }
    match registry.mint(profile_name) {
        Ok(token) => {
            let mut map = OrderedObject::new();
            map.set("session_id", JsonValue::Str(token.clone()));
            map.set(
                "ws_url",
                JsonValue::Str(format!("/api/v1/screencast/ws?session={}", token)),
            );
            envelope_resp(200, JsonValue::Object(map))
        }
        Err(MintError::Busy) => error_resp(
            409,
            "screencast_busy",
            "a screencast session is already live for this profile",
        ),
        Err(MintError::Random) => error_resp(500, "internal_error", "internal error"),
    }
}

/// The WS origin check (`wsUpgrader.CheckOrigin`, Go
/// screencast.go): no Origin → allowed; else the origin
/// host must be loopback or the request host itself
/// (WITH port — unlike the API check, which strips it).
pub fn ws_check_origin(origin: Option<&str>, request_host: &str) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    if origin.is_empty() {
        return true;
    }
    ws_origin_allowed(Some(origin), request_host)
}

/// GET /screencast/ws, pre-upgrade half: validate the
/// `?session=` token (missing → 401; consume failure →
/// 401, or 409 when busy) and the nil-starter gate (503,
/// checked AFTER consume — the token is burned first).
/// Returns Ok(profile) when the upgrade may proceed, or
/// the error response to send. The caller releases the
/// profile when the session ends.
pub fn ws_pre_upgrade(
    registry: &ScreencastRegistry,
    session: &str,
    starter_present: bool,
) -> Result<String, Resp> {
    if session.is_empty() {
        return Err(error_resp(401, "unauthorized", "invalid or missing token"));
    }
    let profile_name = match registry.consume(session) {
        Ok(p) => p,
        Err(ConsumeError::Busy) => {
            return Err(error_resp(
                409,
                "screencast_busy",
                "a screencast session is already live for this profile",
            ));
        }
        Err(ConsumeError::Unknown) => {
            return Err(error_resp(401, "unauthorized", "invalid or missing token"));
        }
    };
    if !starter_present {
        registry.release(&profile_name);
        return Err(error_resp(
            503,
            "screencast_unavailable",
            "screencast unavailable in this build (rebuild with -tags with_chromedp)",
        ));
    }
    Ok(profile_name)
}

/// The starter seam type: `Some` starter runs one login
/// session over the WS transport. M6b: always `None`
/// ("chưa nối" — depends on M6a keeper/Chrome).
/// The signature mirrors Go's `ScreencastStarter`:
/// `(ctx, profile, token, transport) -> LoginResult`.
/// It is a plain function pointer type for now; the async
/// runner wiring lands with the keeper port.
pub type ScreencastStarter = std::sync::Arc<dyn Fn(&str, &str) -> LoginResult + Send + Sync>;

/// Render the terminal report for a finished session
/// (Go handleScreencastWS): outcome enum only, plus
/// value-free metadata. No error text leaves the handler.
pub fn terminal_report(result: &LoginResult) -> String {
    encode_go_json(&result.to_json())
}

/// The plain-HTTP `GET /api/v1/screencast/ws` path (a
/// request WITHOUT the `Upgrade: websocket` header reaches
/// the route table instead of the upgrade path): Go runs
/// the same pre-upgrade checks, so a missing/unknown
/// session still 401s and a nil starter still 503s. When
/// a starter IS present this returns the same 503 — the
/// transport runner lands with the keeper port (M6a); the
/// branch is unreachable in M6b (the CLI wires no
/// starter).
pub fn handle_screencast_ws_http(
    registry: &ScreencastRegistry,
    session: &str,
    starter_present: bool,
) -> Resp {
    match ws_pre_upgrade(registry, session, starter_present) {
        Ok(profile) => {
            // The session was consumed by ws_pre_upgrade;
            // the plain-HTTP path has no socket to run it
            // on, so release the profile before answering
            // 503 — otherwise the profile stays Busy and
            // every later mint/upgrade for it fails (F-D6 /
            // safety M-1). Latent in M6b (starter always
            // None, so this arm is unreachable), but it
            // must not ship as a strand.
            registry.release(&profile);
            error_resp(
                503,
                "screencast_unavailable",
                "screencast unavailable in this build (rebuild with -tags with_chromedp)",
            )
        }
        Err(resp) => resp,
    }
}

/// The WebSocket upgrade path (`handleScreencastWS` in Go),
/// called by `server::handle_ws_upgrade` after the
/// rate-limit check. Order mirrors Go exactly: session
/// token first (missing → 401, unknown → 401, busy →
/// 409), then the nil-starter gate (503, AFTER consume —
/// the token is burned first), then the origin check
/// inside the upgrade, then the starter with the 15-minute
/// timeout and the terminal report.
///
/// In M6b the starter is always `None`, so the upgrade
/// itself is unreachable from the CLI: `ws_pre_upgrade`
/// returns the 503 before any handshake bytes are written.
/// The upgrade half below exists so a future starter
/// wiring has the full path: RFC 6455 handshake
/// (`Sec-WebSocket-Accept`), the origin check at upgrade
/// time, the starter run, the terminal report, and the
/// session release when the socket closes.

/// Gorilla `Upgrader.returnError` bytes (no custom
/// `Error` set on Go's upgrader): `Sec-WebSocket-Version:
/// 13` + `http.Error` (plain-text status text + "\n").
fn ws_handshake_error(status: u16, body: &[u8]) -> Resp {
    Resp {
        status,
        headers: vec![
            ("Sec-WebSocket-Version".to_string(), "13".to_string()),
            (
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            ),
            (
                "X-Content-Type-Options".to_string(),
                "nosniff".to_string(),
            ),
        ],
        body: body.to_vec(),
    }
}

pub async fn handle_ws_upgrade(
    server: &std::sync::Arc<crate::server::Server>,
    mut req: hyper::Request<hyper::body::Incoming>,
    _peer: std::net::SocketAddr,
) -> Result<hyper::Response<crate::server::RespBody>, hyper::Error> {
    use base64::Engine as _;
    use futures_util::SinkExt;
    use sha1::Digest as _;

    let query = crate::logs::parse_query(req.uri().query().unwrap_or(""));
    let session = crate::logs::query_value(&query, "session").unwrap_or_default();
    let starter_present = server.deps.screencast_starter.is_some();
    let profile = match ws_pre_upgrade(&server.sessions, &session, starter_present) {
        Ok(p) => p,
        Err(resp) => return Ok(crate::server::render_resp(&hyper::Method::GET, resp)),
    };
    // Origin is checked at upgrade time in Go (the
    // gorilla upgrader's CheckOrigin): a disallowed origin
    // gets a 403 plain-text `Forbidden\n` (gorilla
    // returnError: Sec-WebSocket-Version: 13 +
    // http.Error), NOT a silent close and NOT the JSON
    // envelope. The branch is unreachable in M6b (starter
    // is None), so the difference is unobservable; see
    // PORTING.md §M6b.
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !ws_check_origin(origin.as_deref(), &host) {
        server.sessions.release(&profile);
        return Ok(crate::server::render_resp(
            &hyper::Method::GET,
            ws_handshake_error(403, b"Forbidden\n"),
        ));
    }
    let key = match req.headers().get("sec-websocket-key") {
        Some(v) => match v.to_str() {
            Ok(k) => k.to_string(),
            Err(_) => {
                server.sessions.release(&profile);
                return Ok(crate::server::render_resp(
                    &hyper::Method::GET,
                    ws_handshake_error(400, b"Bad Request\n"),
                ));
            }
        },
        None => {
            server.sessions.release(&profile);
            return Ok(crate::server::render_resp(
                &hyper::Method::GET,
                ws_handshake_error(400, b"Bad Request\n"),
            ));
        }
    };
    let accept = {
        let mut hasher = sha1::Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    };
    let upgrade = hyper::upgrade::on(&mut req);
    let (_parts, _body) = req.into_parts();
    let response = hyper::Response::builder()
        .status(hyper::StatusCode::SWITCHING_PROTOCOLS)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", accept)
        .body(
            http_body_util::Empty::<bytes::Bytes>::new()
                .map_err(|e| match e {})
                .boxed(),
        )
        .expect("101 response builds");
    let server2 = std::sync::Arc::clone(server);
    let token = session.clone();
    tokio::spawn(async move {
        let upgraded = match upgrade.await {
            Ok(u) => u,
            Err(_) => {
                server2.sessions.release(&profile);
                return;
            }
        };
        let io = hyper_util::rt::TokioIo::new(upgraded);
        let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            io,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;
        // The starter is sync (no transport parameter yet —
        // the transport runner lands with M6a): run it, then
        // send the terminal report and close. A starter
        // failure is a failed outcome, never a crash.
        let starter = server2
            .deps
            .screencast_starter
            .as_ref()
            .expect("starter present (checked above)")
            .clone();
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| starter(&profile, &token)))
                .unwrap_or_else(|_| LoginResult::failed());
        let report = terminal_report(&result);
        let _ = ws
            .send(tokio_tungstenite::tungstenite::Message::Text(report.into()))
            .await;
        let _ = ws.close(None).await;
        server2.sessions.release(&profile);
    });
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn plain_http_ws_releases_session() {
        // F-D6: with a starter present, a plain-HTTP GET
        // to /screencast/ws consumed the session and
        // returned 503 without releasing it — the profile
        // stayed Busy forever. A second mint must succeed.
        let r = ScreencastRegistry::new();
        let tok = r.mint("muse01").unwrap();
        let resp = handle_screencast_ws_http(&r, &tok, true);
        assert_eq!(resp.status, 503);
        assert!(r.mint("muse01").is_ok());
    }

    #[test]
    fn registry_mint_consume_release() {
        let r = ScreencastRegistry::new();
        let tok = r.mint("muse01").unwrap();
        assert_eq!(tok.len(), 64);
        assert!(tok.chars().all(|c| c.is_ascii_hexdigit()));
        // Consume once: ok.
        assert_eq!(r.consume(&tok).unwrap(), "muse01");
        // Replay: unknown.
        assert!(matches!(r.consume(&tok), Err(ConsumeError::Unknown)));
        // Mint while live: busy.
        assert!(matches!(r.mint("muse01"), Err(MintError::Busy)));
        // A different profile is unaffected.
        let tok2 = r.mint("other").unwrap();
        assert_eq!(r.consume(&tok2).unwrap(), "other");
        // Release frees the profile.
        r.release("muse01");
        assert!(r.mint("muse01").is_ok());
    }

    #[test]
    fn registry_busy_token_stays_consumable() {
        let r = ScreencastRegistry::new();
        let tok_live = r.mint("muse01").unwrap();
        // Minted while the first token is only reserved
        // (not live yet): mint refuses only a LIVE
        // session, so a second token exists to test the
        // consume-time busy rule.
        let tok2 = r.mint("muse01").unwrap();
        r.consume(&tok_live).unwrap();
        // A second token for the same profile: consume
        // refuses busy WITHOUT burning it.
        assert!(matches!(r.consume(&tok2), Err(ConsumeError::Busy)));
        // After the live session ends, the second token
        // still consumes.
        r.release("muse01");
        assert_eq!(r.consume(&tok2).unwrap(), "muse01");
    }

    #[test]
    fn validate_ws_input_allowlists() {
        let mut m = WsInputMessage {
            kind: "mouse".to_string(),
            mouse_type: "mousePressed".to_string(),
            button: "left".to_string(),
            click_count: 1,
            ..Default::default()
        };
        let ev = validate_ws_input(&m).unwrap();
        assert_eq!(ev.kind, InputKind::Mouse);
        m.mouse_type = "teleport".to_string();
        assert!(validate_ws_input(&m).is_none());
        m.mouse_type = "mouseMoved".to_string();
        m.click_count = 4;
        assert!(validate_ws_input(&m).is_none());
        m.click_count = 0;
        m.kind = "key".to_string();
        m.key_type = "keyDown".to_string();
        m.key = "a".to_string();
        assert!(validate_ws_input(&m).is_some());
        m.key = "x".repeat(65);
        assert!(validate_ws_input(&m).is_none());
        m.key = "a".to_string();
        m.kind = "text".to_string();
        m.text = String::new();
        assert!(validate_ws_input(&m).is_none());
        m.text = "hi".to_string();
        assert!(validate_ws_input(&m).is_some());
        m.kind = "done".to_string();
        assert!(validate_ws_input(&m).is_some());
        m.kind = "bogus".to_string();
        assert!(validate_ws_input(&m).is_none());
    }

    #[test]
    fn frame_message_shape() {
        let f = Frame {
            data: vec![0xff, 0xd8, 0xff],
            session_id: 7,
            width: 800,
            height: 600,
        };
        let rendered = encode_go_json(&f.to_json());
        assert!(rendered.contains("\"type\":\"frame\""));
        assert!(rendered.contains("\"data\":\"/9j/\""));
        assert!(rendered.contains("\"width\":800"));
    }

    #[test]
    fn availability_no_keeper_entry() {
        let dir = std::env::temp_dir();
        let load = ConfigLoad {
            raw: b"{\"profiles\":{}}".to_vec(),
            hash: String::new(),
            state: crate::guarded::ConfigState {
                found: true,
                exists: true,
                sha256: String::new(),
                raw: b"{\"profiles\":{}}".to_vec(),
                base_dir: dir.clone(),
            },
        };
        let (avail, reason) = screencast_availability(&dir, &load, "muse01").unwrap();
        assert!(!avail);
        assert!(reason.contains("no keeper entry for profile \"muse01\""));
    }
}
