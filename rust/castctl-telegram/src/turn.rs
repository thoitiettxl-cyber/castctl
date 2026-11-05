// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The turn engine: one text turn per chat, streaming
//! bubble edits, two-way media, and the resume-follow
//! after a manual approval decision.
//!
//! Go sources: `internal/commands/telegram_turn.go`
//! (runner, bubble editor, delivery, media),
//! `internal/commands/wait.go` (`deliverSend`,
//! `executeWait`, `callHistoryEvents`),
//! `internal/deliver/stop.go` (`StopTurn`),
//! `internal/gateway/media.go` (`MediaPath`),
//! `internal/telegram/files.go` (`SendFile`,
//! `DocName`), `internal/telegram/text.go`
//! (`SplitText`, `NeedsDocument`).
//!
//! [DEVIATION — no live subscribe] There is no
//! `chat.subscribe` implementation anywhere in the Rust
//! workspace (M3 did not port `SubscribeRaw`), so the
//! follow in [`TurnRunner::wait_follow`] polls
//! `chat.history` every second instead of consuming the
//! subscribe NDJSON stream. The state machine it feeds
//! ([`crate::wait::Waiter`]) and the preview it feeds
//! ([`crate::preview::StreamPreview`]) are faithful
//! ports; bubble updates therefore arrive at poll
//! cadence rather than push cadence, but the final text
//! still comes from a history re-read, as in Go. See
//! PORTING.md §M5b deviation 1.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::sync::Notify;

use crate::approvals::{Approval, choose_auto_decision};
use crate::claims::{ClaimManager, NotifyPending};
use crate::error::BotError;
use crate::files::{InboxMedia, download_media, inbox_name, send_file};
use crate::preview::StreamPreview;
use crate::registry::{CallbackRegistry, approval_markup};
use crate::send::{HtmlMode, InlineKeyboardButton, InlineKeyboardMarkup, SendOptions, Sender};
use crate::state::TelegramStateStore;
use crate::wait::{
    ApproveError, ApproveOutcome, ApprovedRecord, Reply, WaitApprover, WaitKind, Waiter,
    event_name, history_seq, is_self_referential, needs_input_reason, outcome_of, replies_after,
    seq_of, user_ack,
};
use castctl_gateway::{Body, Gateway, RequestOptions, SharedConn};
use castctl_shared::{
    JsonValue as SharedJson, Resource, event_resources, file_rows, from_serde, local_name,
};
use castctl_tg_files::UPLOAD_LIMIT;
use castctl_tg_text::{button_text, needs_document, split_text};
use castctl_transport::TransportError;

/// Turn timeout: 6h.
/// Source: `internal/commands/telegram_turn.go:84`
/// (`telegramTurnTimeout`).
pub const TURN_TIMEOUT: Duration = Duration::from_secs(6 * 60 * 60);
/// Delivery-ack timeout: 30s.
/// Source: `internal/commands/telegram_turn.go:175`
/// (`ackTimeout` default).
pub const ACK_TIMEOUT: Duration = Duration::from_secs(30);
/// Resume slot wait: 5s.
/// Source: `internal/commands/telegram_turn.go:297`
/// (`resumeSlotWait`).
pub const RESUME_SLOT_WAIT: Duration = Duration::from_secs(5);
/// Resume slot poll: 10ms.
/// Source: `internal/commands/telegram_turn.go:335,357`.
pub const RESUME_POLL: Duration = Duration::from_millis(10);
/// Streaming edit throttle: 1s.
/// Source: `internal/commands/telegram_turn.go:683`
/// (ticker) and `:704` (`maybeEdit`).
pub const EDIT_THROTTLE: Duration = Duration::from_secs(1);
/// Detached final-edit timeout: 15s.
/// Source: `internal/commands/telegram_turn.go:755`
/// (`editFinal`).
pub const EDIT_FINAL_TIMEOUT: Duration = Duration::from_secs(15);
/// Delivery-ack poll interval: 100ms.
/// Source: `internal/commands/wait.go:932`.
pub const ACK_POLL: Duration = Duration::from_millis(100);
/// Bound on CONTINUOUS swallowable history errors in
/// the follow poll: after this long with no successful
/// history read, the turn fails with the last history
/// error instead of polling silently to the 6h turn
/// timeout. Grounded in Go, not invented: 30s is both
/// the ack deadline (`internal/commands/
/// telegram_turn.go:175`) and the Runner's
/// `ReconnectBudget` — the duration Go tolerates a
/// storm of failed resubscribes before escalating to a
/// bounded state check (`internal/wait/runner.go:30-31`,
/// `noteFailure`). Go's push stream can recover on the
/// next resubscribe; the Rust history poll cannot, so
/// at the same 30s boundary the poll fails the turn
/// (error text to the user, slot released) instead of
/// escalating to a state check it does not have. See
/// PORTING.md §M5b deviation 17.
pub const FOLLOW_HISTORY_ERROR_BUDGET: Duration = Duration::from_secs(30);
/// Document preview: first 1500 runes.
/// Source: `internal/commands/telegram_turn.go:879-880`.
pub const DOCUMENT_PREVIEW_RUNES: usize = 1500;
/// Max files delivered per turn: 6.
/// Source: `internal/commands/telegram_turn.go:909`.
pub const MAX_FILES_PER_TURN: usize = 6;
/// Turn-media history windows, tried in order.
/// Source: `internal/commands/telegram_turn.go:901`.
pub const TURN_MEDIA_HISTORY_LIMITS: [i64; 3] = [200, 500, 1000];
/// Busy reply for a second turn in the same chat.
/// Source: `internal/commands/telegram_turn.go:278`.
pub const BUSY_REPLY: &str = "⏳ Muse is already working in this chat. Use /stop to interrupt it.";
/// Bubble text while sending.
/// Source: `internal/commands/telegram_turn.go:483`.
pub const SENDING_BUBBLE: &str = "⏳ Sending to Muse…";
/// Bubble text while resuming.
/// Source: `internal/commands/telegram_turn.go:555`.
pub const CONTINUING_BUBBLE: &str = "⏳ Muse is continuing…";
/// No-delivery-ack bubble text.
/// Source: `internal/commands/telegram_turn.go:505-506`.
pub const NO_ACK_TEXT: &str =
    "⚠️ Muse did not confirm delivery within 30 s. Check /history before sending again.";

/// Render a turn failure for the bubble using fixed
/// templates by error class only: no error text, and
/// therefore no server body, ever reaches a chat message.
/// Source: `internal/commands/telegram_turn.go:624-636`
/// (`turnErrorText`).
#[must_use]
pub fn turn_error_text(err: &BotError, stopped: bool) -> String {
    if is_auth_error(err) {
        return "🔑 muse.ai login expired. Re-export cookies with `castctl auth export` and restart the bot."
            .to_string();
    }
    if stopped || matches!(err, BotError::Cancelled) {
        return "⏹ Stopped.".to_string();
    }
    "⚠️ Could not reach Muse (gateway error). Try again.".to_string()
}

/// Whether `err` is a gateway auth failure
/// (`*conn.AuthError`). The handler's copy in
/// `commands.rs` matches the same single variant;
/// the duplication is deliberate (that helper is
/// private to the handler module).
/// Source: `internal/commands/telegram_commands.go`
/// (`isAuthError`, deferred NIT N10).
#[must_use]
pub fn is_auth_error(err: &BotError) -> bool {
    matches!(err, BotError::Transport(TransportError::Auth { .. }))
}

/// Whether a media failure is fatal: only an auth error
/// or a cancelled context. A Telegram 401 on a media send
/// is a notice, not fatal.
/// Source: `internal/commands/telegram_turn.go:1315-1322`
/// (`isMediaFatal`).
#[must_use]
pub fn is_media_fatal(err: &BotError) -> bool {
    is_auth_error(err) || matches!(err, BotError::Cancelled)
}

/// Whether a history-read error is swallowable in a
/// poll: only gateway/timeout classes.
/// Source: `internal/commands/wait.go:816-823`
/// (`swallowableHistoryError`).
#[must_use]
pub fn swallowable_history_error(err: &BotError) -> bool {
    matches!(
        err,
        BotError::Transport(TransportError::Gateway(_) | TransportError::Timeout { .. })
    )
}

/// Classify a media failure for the failure notice.
/// Source: `internal/commands/telegram_turn.go:1341-1375`
/// (`mediaFailureClass`).
#[must_use]
pub fn media_failure_class(err: &BotError) -> String {
    match err {
        BotError::Api { code, .. } => match code {
            429 => "too many requests".to_string(),
            400 => "bad request".to_string(),
            403 => "forbidden".to_string(),
            401 => "unauthorized".to_string(),
            404 => "not found".to_string(),
            409 => "conflict".to_string(),
            _ => "error".to_string(),
        },
        BotError::Transport(TransportError::Auth { .. }) => "auth failed".to_string(),
        BotError::Transport(
            TransportError::Gateway(_) | TransportError::ConnectionError { .. },
        ) => err.summary(),
        _ => "error".to_string(),
    }
}

/// Truncate a failure class to 200 runes for the notice.
/// Source: `internal/commands/telegram_turn.go:1377-1380`.
fn truncate_class(class: &str) -> String {
    class.chars().take(200).collect()
}

/// The too-big notice for one file. Size is whole MiB
/// (`bytes>>20`). The name is HTML-escaped: Go uses
/// `telegram.EscapeText` here
/// (`internal/commands/telegram_turn.go:1324-1330`).
#[must_use]
pub fn too_big_notice(name: &str, bytes: i64) -> String {
    format!(
        "📎 <b>{}</b> is {} MB, too big for Telegram. Get it with castctl download.",
        castctl_tg_text::escape_text(name),
        bytes >> 20
    )
}

/// The per-file failure notice.
/// Source: `internal/commands/telegram_turn.go:1377-1380`.
#[must_use]
pub fn media_failure_notice(name: &str, verb: &str, err: &BotError) -> String {
    format!(
        "📎 <b>{}</b> could not be {verb} ({}).",
        castctl_tg_text::escape_text(name),
        truncate_class(&media_failure_class(err))
    )
}

/// First 1500 runes, right-trimmed, plus the
/// "(full reply attached)" tail.
/// Source: `internal/commands/telegram_turn.go:879-880`
/// (`documentPreview`).
#[must_use]
pub fn document_preview(text: &str) -> String {
    let head: String = text.chars().take(DOCUMENT_PREVIEW_RUNES).collect();
    let head = head.trim_end().to_string();
    format!("{head}\n\n… (full reply attached)")
}

/// The watermark cap for a turn: the greatest seq this
/// turn delivered (its own user message, or a later
/// reply), so a later turn's events already in the
/// history window are never skipped.
/// Source: `internal/commands/telegram_turn.go:615-622`
/// (`deliveredTopSeq`).
#[must_use]
pub fn delivered_top_seq(user_seq: i64, res: &WaitResult) -> i64 {
    let mut top = user_seq;
    for reply in &res.replies {
        if reply.seq > top {
            top = reply.seq;
        }
    }
    top
}

/// Resolve a sandbox media reference to its
/// `/media/raw/…` download path.
/// Source: `internal/gateway/media.go:47-91`
/// (`MediaPath`, `mediaRefString`).
pub fn media_path(path: &str, variants: Option<&SharedJson>) -> Result<String, TransportError> {
    // `variants.original` wins over `path` whenever it
    // is non-empty (`media.go:80-91`).
    let mut refstr = String::new();
    if let Some(SharedJson::Object(map)) = variants
        && let Some(SharedJson::Str(original)) = map.get("original")
        && !original.is_empty()
    {
        refstr = original.clone();
    }
    if refstr.is_empty() {
        refstr = path.to_string();
    }
    if refstr.is_empty() {
        return Err(TransportError::Validation {
            message: format!("bad sandbox path: ref_length={}", refstr.len()),
        });
    }
    let mut rel: &str = &refstr;
    let owned;
    if let Some(rest) = rel.strip_prefix("sandbox://") {
        rel = rest;
    } else if rel.starts_with("http://") || rel.starts_with("https://") {
        owned = http_escaped_path(rel).ok_or_else(|| TransportError::Validation {
            message: format!("bad sandbox path: ref_length={}", refstr.len()),
        })?;
        rel = &owned;
    }
    let rel = rel.trim_start_matches('/');
    let rel = rel.strip_prefix("media/raw/").unwrap_or(rel);
    // `url.PathUnescape` (`media.go:67-69`): unquote only
    // when the whole string unquotes; on any bad escape
    // keep the original string.
    let unquoted = percent_decode(rel).unwrap_or_else(|| rel.to_string());
    if unquoted.is_empty() || unquoted.split('/').any(|seg| seg == "..") {
        return Err(TransportError::Validation {
            message: format!("bad sandbox path: ref_length={}", refstr.len()),
        });
    }
    Ok(format!("/media/raw/{}", quote_python(&unquoted)))
}

/// The escaped path of an http(s) URL, Go `url.Parse` +
/// `EscapedPath` (`media.go:56-63`): the query/fragment
/// are dropped; any bad `%` escape fails the parse.
/// (Verified against Go's `net/url` by probe, see
/// PORTING §M5b.) The returned path is still
/// percent-encoded; the caller's unquote + re-quote
/// normalizes it exactly like Go's `PathUnescape` +
/// `quotePython` pair.
fn http_escaped_path(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let path_start = after_scheme.find('/').unwrap_or(after_scheme.len());
    let path_and_rest = &after_scheme[path_start..];
    let path = path_and_rest.split(['?', '#']).next().unwrap_or("");
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || hex_val(bytes[i + 1]).is_none()
                || hex_val(bytes[i + 2]).is_none()
            {
                return None;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    Some(path.to_string())
}

/// Percent-decode `%XX` sequences, Go's
/// `url.PathUnescape`: `None` when ANY escape is bad
/// (the caller then keeps the original string).
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let (h, l) = (hex_val(bytes[i + 1])?, hex_val(bytes[i + 2])?);
            out.push(h * 16 + l);
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

/// Hand-rolled `urllib.parse.quote(safe="/")`:
/// unreserved + `/` pass through, everything else is
/// `%XX` (uppercase hex).
/// Source: `internal/gateway/media.go` (`quotePython`).
fn quote_python(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Resolve a turn-media resource to its download ref:
/// `variants` (original) first, else the bare path.
/// Source: `internal/commands/telegram_turn.go:1302`
/// (`downloadRef`).
#[must_use]
pub fn download_ref(res: &Resource) -> String {
    if let Some(SharedJson::Object(map)) = &res.variants
        && let Some(SharedJson::Str(original)) = map.get("original")
        && !original.is_empty()
    {
        return original.clone();
    }
    res.path.clone()
}

/// The reply document name: `.md` when the text
/// contains a fenced block or a Markdown heading /
/// bold run, else `.txt`; the stem is sanitised
/// (`[^A-Za-z0-9._-]+` → `-`, `-` trimmed from both
/// ends, capped at 40 runes).
/// Source: `internal/telegram/files.go:125-138`
/// (`DocName`).
#[must_use]
pub fn doc_name(stem: &str, text: &str) -> String {
    let md = text.contains("```")
        || text.lines().any(|line| {
            let hashes = line.chars().take_while(|c| *c == '#').count();
            (1..=6).contains(&hashes) && line.chars().nth(hashes) == Some(' ')
                || line.contains("**")
        });
    let ext = if md { ".md" } else { ".txt" };
    let mut clean: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    clean = clean.trim_matches('-').to_string();
    let capped: String = clean.chars().take(40).collect();
    format!("{capped}{ext}")
}

/// One turn's wait outcome, mirroring Go's
/// `wait.Result` fields the delivery reads.
/// Source: `internal/wait/waiter.go` (`Result`).
#[derive(Debug, Clone, Default)]
pub struct WaitResult {
    /// Decided kind.
    pub kind: WaitKind,
    /// Outcome string (`done` / `needs_input` /
    /// `needs_approval` / `failed` / `timeout`).
    pub outcome: String,
    /// Terminal status string (done/failed), or "".
    pub status: String,
    /// Boundary seq the wait started after.
    pub after_seq: i64,
    /// Final reply text (last reply's text).
    pub final_text: String,
    /// Final replies in seq order.
    pub replies: Vec<Reply>,
    /// The final history read failed.
    pub final_read_failed: bool,
    /// Human note (e.g. timeout detail).
    pub note: String,
    /// Pending approvals (kind approval only).
    pub approvals: Vec<Approval>,
    /// Input reason for the last reply, or "".
    pub needs_input_reason: String,
    /// Question text for the last reply, or "".
    pub question: String,
    /// Process exit code for the kind.
    pub exit_code: i32,
    /// Node id that ran the turn ("" when unknown).
    pub node_id: String,
    /// Auto-approved records.
    pub auto_approved: Vec<ApprovedRecord>,
    /// Auto-approve errors.
    pub auto_approve_errors: Vec<ApproveError>,
}

/// The gateway surface a turn needs. Two impls exist:
/// [`SharedGatewayPort`] (production, over the shared
/// connection) and [`DirectGatewayPort`] (tests / E2E,
/// over one `Gateway`).
pub trait GatewayPort: Send + Sync {
    /// `chat.history` events (the `chat_events` list),
    /// oldest first, in the thread when given.
    fn history(
        &self,
        limit: i64,
        thread: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Value>, BotError>> + Send + '_>>;

    /// Open `chat.stream` (tracked = false: nobody reads
    /// the stream's own frames; the turn is followed on
    /// history). Returns the stream id, used only for
    /// cancel.
    fn open_stream(
        &self,
        body: Value,
    ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>>;

    /// One unary gateway call.
    fn call_json(
        &self,
        method: &str,
        opts: RequestOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Value, BotError>> + Send + '_>>;

    /// Download `/media/raw/…` bytes.
    fn download_file(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, BotError>> + Send + '_>>;

    /// Write one file to System Files (`fs.write`,
    /// overwrite=false, create_parent=true).
    fn write_file(
        &self,
        path: &str,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>>;

    /// Whether the gateway's route table knows `method`
    /// (the `/raw` route check lives in the service).
    fn has_route(
        &self,
        method: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, BotError>> + Send + '_>>;
}

/// Production port over the shared connection.
/// Source: `internal/commands/telegram_turn.go`
/// (gateway lease held for the whole turn).
pub struct SharedGatewayPort {
    conn: Arc<SharedConn>,
}

impl SharedGatewayPort {
    #[must_use]
    pub fn new(conn: Arc<SharedConn>) -> Self {
        Self { conn }
    }
}

impl GatewayPort for SharedGatewayPort {
    fn history(
        &self,
        limit: i64,
        thread: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Value>, BotError>> + Send + '_>> {
        let conn = Arc::clone(&self.conn);
        let thread = thread.to_string();
        Box::pin(async move {
            let mut body = json!({ "limit": limit });
            if !thread.is_empty() {
                body["session_id"] = Value::String(thread);
            }
            let v = conn
                .call_json(
                    "chat.history",
                    RequestOptions {
                        body: Body::Json(body),
                        ..Default::default()
                    },
                )
                .await?;
            let Some(obj) = v.as_object() else {
                return Err(BotError::Validation(
                    "gateway: chat.history result is not an object".to_string(),
                ));
            };
            let events = obj
                .get("chat_events")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            Ok(events)
        })
    }

    fn open_stream(
        &self,
        body: Value,
    ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>> {
        let conn = Arc::clone(&self.conn);
        Box::pin(async move {
            let gw = conn.live().await?;
            let sid = gw.open_stream("chat.stream", Some(body)).await?;
            Ok(sid)
        })
    }

    fn call_json(
        &self,
        method: &str,
        opts: RequestOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Value, BotError>> + Send + '_>> {
        let conn = Arc::clone(&self.conn);
        let method = method.to_string();
        Box::pin(async move { conn.call_json(&method, opts).await.map_err(BotError::from) })
    }

    fn download_file(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, BotError>> + Send + '_>> {
        let conn = Arc::clone(&self.conn);
        let path = path.to_string();
        Box::pin(async move {
            let gw = conn.live().await?;
            gw.download_file(&path, Duration::ZERO)
                .await
                .map_err(BotError::from)
        })
    }

    fn write_file(
        &self,
        path: &str,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        let conn = Arc::clone(&self.conn);
        let path = path.to_string();
        let data = data.to_vec();
        Box::pin(async move {
            let body = json!({
                "path": path,
                "overwrite": false,
                "append": false,
                "create_parent": true,
                "data_base64": base64_encode(&data),
            });
            conn.call_json(
                "fs.write",
                RequestOptions {
                    body: Body::Json(body),
                    ..Default::default()
                },
            )
            .await?;
            Ok(())
        })
    }

    fn has_route(
        &self,
        method: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, BotError>> + Send + '_>> {
        let conn = Arc::clone(&self.conn);
        let method = method.to_string();
        Box::pin(async move {
            let gw = conn.live().await?;
            Ok(gw.lookup_route(&method).is_some())
        })
    }
}

/// Production port over one direct `Gateway`
/// (tests / E2E, as in
/// `castctl-gateway/examples/parity_client.rs`).
pub struct DirectGatewayPort {
    gw: Arc<Gateway>,
}

impl DirectGatewayPort {
    #[must_use]
    pub fn new(gw: Arc<Gateway>) -> Self {
        Self { gw }
    }
}

impl GatewayPort for DirectGatewayPort {
    fn history(
        &self,
        limit: i64,
        thread: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Value>, BotError>> + Send + '_>> {
        let gw = Arc::clone(&self.gw);
        let thread = thread.to_string();
        Box::pin(async move {
            let mut body = json!({ "limit": limit });
            if !thread.is_empty() {
                body["session_id"] = Value::String(thread);
            }
            let v = gw
                .call_json(
                    "chat.history",
                    RequestOptions {
                        body: Body::Json(body),
                        ..Default::default()
                    },
                )
                .await
                .map_err(BotError::from)?;
            let Some(obj) = v.as_object() else {
                return Err(BotError::Validation(
                    "gateway: chat.history result is not an object".to_string(),
                ));
            };
            Ok(obj
                .get("chat_events")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default())
        })
    }

    fn open_stream(
        &self,
        body: Value,
    ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>> {
        let gw = Arc::clone(&self.gw);
        Box::pin(async move {
            gw.open_stream("chat.stream", Some(body))
                .await
                .map_err(BotError::from)
        })
    }

    fn call_json(
        &self,
        method: &str,
        opts: RequestOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Value, BotError>> + Send + '_>> {
        let gw = Arc::clone(&self.gw);
        let method = method.to_string();
        Box::pin(async move { gw.call_json(&method, opts).await.map_err(BotError::from) })
    }

    fn download_file(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, BotError>> + Send + '_>> {
        let gw = Arc::clone(&self.gw);
        let path = path.to_string();
        Box::pin(async move {
            gw.download_file(&path, Duration::ZERO)
                .await
                .map_err(BotError::from)
        })
    }

    fn write_file(
        &self,
        path: &str,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        let gw = Arc::clone(&self.gw);
        let path = path.to_string();
        let data = data.to_vec();
        Box::pin(async move {
            let body = json!({
                "path": path,
                "overwrite": false,
                "append": false,
                "create_parent": true,
                "data_base64": base64_encode(&data),
            });
            gw.call_json(
                "fs.write",
                RequestOptions {
                    body: Body::Json(body),
                    ..Default::default()
                },
            )
            .await
            .map_err(BotError::from)?;
            Ok(())
        })
    }

    fn has_route(
        &self,
        method: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, BotError>> + Send + '_>> {
        let gw = Arc::clone(&self.gw);
        let method = method.to_string();
        Box::pin(async move { Ok(gw.lookup_route(&method).is_some()) })
    }
}

/// Base64 (standard alphabet, padded), for `fs.write`
/// bodies. Implemented locally: no base64 crate is in
/// the workspace dependency set.
/// Source: `internal/gateway/fsclient.go:548`
/// (`fsclient.WriteFile`).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// The Telegram send surface a turn needs. The
/// production impl wraps a [`BotApi`] through
/// [`Sender`]; tests record calls instead.
pub trait BotSink: Send + Sync {
    /// Send text (split at 3800 runes); returns the last
    /// message id.
    fn send(
        &self,
        chat_id: i64,
        text: &str,
        opts: SendOptions,
    ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>>;

    /// Edit with the HTML-then-plain fallback.
    fn edit(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
        mode: HtmlMode,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>>;

    /// Edit, swallowing ALL errors.
    fn edit_plain(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// Delete a message.
    fn delete(
        &self,
        chat_id: i64,
        message_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>>;

    /// Send a file (kind from name/mime/size, caption
    /// truncated at 1024 runes, 400-only fallback).
    fn send_file(
        &self,
        chat_id: i64,
        name: &str,
        data: &[u8],
        mime: &str,
        caption: &str,
        opts: &SendOptions,
    ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>>;
}

/// Production sink over one [`BotApi`].
pub struct SenderSink {
    api: Arc<crate::api::BotApi>,
}

impl SenderSink {
    #[must_use]
    pub fn new(api: Arc<crate::api::BotApi>) -> Self {
        Self { api }
    }
}

impl BotSink for SenderSink {
    fn send(
        &self,
        chat_id: i64,
        text: &str,
        opts: SendOptions,
    ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>> {
        let api = Arc::clone(&self.api);
        let text = text.to_string();
        Box::pin(async move { Sender::new(&api).send(chat_id, &text, opts).await })
    }

    fn edit(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
        mode: HtmlMode,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        let api = Arc::clone(&self.api);
        let text = text.to_string();
        Box::pin(async move {
            Sender::new(&api)
                .edit(chat_id, message_id, &text, mode, markup)
                .await
        })
    }

    fn edit_plain(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let api = Arc::clone(&self.api);
        let text = text.to_string();
        Box::pin(async move {
            Sender::new(&api)
                .edit_plain(chat_id, message_id, &text, markup)
                .await;
        })
    }

    fn delete(
        &self,
        chat_id: i64,
        message_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        let api = Arc::clone(&self.api);
        Box::pin(async move { Sender::new(&api).delete(chat_id, message_id).await })
    }

    fn send_file(
        &self,
        chat_id: i64,
        name: &str,
        data: &[u8],
        mime: &str,
        caption: &str,
        opts: &SendOptions,
    ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>> {
        let api = Arc::clone(&self.api);
        let name = name.to_string();
        let data = data.to_vec();
        let mime = mime.to_string();
        let caption = caption.to_string();
        let opts = opts.clone();
        Box::pin(
            async move { send_file(&api, chat_id, &name, &data, &mime, &caption, &opts).await },
        )
    }
}

/// The bubble editor: at most one edit per second, only
/// when the preview changed and the rendered text differs,
/// under one lock so the final edit can never be
/// overwritten by a streaming edit. Only the loop task
/// performs edits: the runner signals through a
/// non-blocking notify and never touches the network, so
/// a slow or 429-throttled edit cannot stall event
/// consumption.
/// Source: `internal/commands/telegram_turn.go:638-760`
/// (`bubbleEditor`).
pub struct BubbleEditor {
    inner: Arc<EditorInner>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

struct EditorInner {
    sink: Arc<dyn BotSink>,
    chat_id: i64,
    message_id: i64,
    preview: Arc<StreamPreview>,
    signal: Notify,
    stop: Notify,
    /// Stop flag: the authority for loop exit.
    /// `notify_waiters` only wakes tasks already
    /// waiting, so a `finish()` that runs before this
    /// task first polls would otherwise be lost and the
    /// loop would wait forever (hang observed in the
    /// `edit_final` test, 2026-11-06).
    stopped: AtomicBool,
    finished: AtomicBool,
    /// Last rendered text (Go's `shown string`); an edit
    /// is skipped when the render equals it.
    shown: Mutex<String>,
    last_edit: Mutex<Option<Instant>>,
}

impl BubbleEditor {
    /// Start the loop task. Edits happen only when the
    /// preview is dirty and the rendered text differs
    /// from what is shown (Go `maybeEdit`); the loop
    /// forces an attempt every second and on every
    /// signal.
    #[must_use]
    pub fn start(
        sink: Arc<dyn BotSink>,
        chat_id: i64,
        message_id: i64,
        preview: Arc<StreamPreview>,
    ) -> Self {
        let inner = Arc::new(EditorInner {
            sink,
            chat_id,
            message_id,
            preview,
            signal: Notify::new(),
            stop: Notify::new(),
            stopped: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            shown: Mutex::new(String::new()),
            last_edit: Mutex::new(None),
        });
        let task_inner = Arc::clone(&inner);
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(EDIT_THROTTLE);
            ticker.tick().await;
            loop {
                if task_inner.stopped.load(Ordering::SeqCst) {
                    break;
                }
                tokio::select! {
                    () = task_inner.stop.notified() => break,
                    () = task_inner.signal.notified() => {
                        maybe_edit(&task_inner).await;
                    }
                    _ = ticker.tick() => {
                        maybe_edit(&task_inner).await;
                    }
                }
            }
        });
        Self {
            inner,
            handle: Some(handle),
        }
    }

    /// Signal the loop that a new event arrived.
    pub fn signal(&self) {
        self.inner.signal.notify_one();
    }

    /// Feed one event to the preview and signal the loop.
    pub fn feed(&self, ev: &Value) {
        self.inner.preview.feed(ev);
        self.signal();
    }

    /// Stop the loop, join it, then land one last partial
    /// edit when deltas arrived after the last streaming
    /// edit, so streamed text is not lost when the final
    /// edit follows immediately after. Idempotent: safe
    /// to call twice (the deferred call in the runner and
    /// the explicit call before delivery — and
    /// `edit_final` calls it first, too).
    /// Source: `internal/commands/telegram_turn.go:730-745`
    /// (`finish`).
    pub async fn finish(&mut self) {
        if self.inner.finished.swap(true, Ordering::SeqCst) {
            return;
        }
        self.inner.stopped.store(true, Ordering::SeqCst);
        self.inner.stop.notify_waiters();
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
        let (text, dirty) = self.inner.preview.render_and_clear(Instant::now());
        let shown = self
            .inner
            .shown
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();
        if !dirty || text == shown {
            return;
        }
        if let Ok(mut s) = self.inner.shown.lock() {
            *s = text.clone();
        }
        self.inner
            .sink
            .edit_plain(self.inner.chat_id, self.inner.message_id, &text, None)
            .await;
    }

    /// The detached final edit: `finish()` first, then a
    /// 15s-timeout edit in Markdown mode with the plain
    /// fallback; on any error, send the text as a new
    /// message instead. Never returns an error.
    /// Source: `internal/commands/telegram_turn.go:755-767`
    /// (`editFinal`).
    pub async fn edit_final(&mut self, text: &str, markup: Option<InlineKeyboardMarkup>) {
        self.finish().await;
        let sink = Arc::clone(&self.inner.sink);
        let chat_id = self.inner.chat_id;
        let message_id = self.inner.message_id;
        let text = text.to_string();
        let markup2 = markup.clone();
        let edited = tokio::time::timeout(
            EDIT_FINAL_TIMEOUT,
            sink.edit(chat_id, message_id, &text, HtmlMode::Markdown, markup),
        )
        .await;
        match edited {
            Ok(Ok(())) => {}
            _ => {
                let _ = sink
                    .send(
                        chat_id,
                        &text,
                        SendOptions {
                            mode: HtmlMode::Markdown,
                            markup: markup2,
                            ..Default::default()
                        },
                    )
                    .await;
            }
        }
    }
}

/// One streaming-edit attempt. The throttle is checked
/// BEFORE rendering (a throttled attempt leaves the
/// dirty flag set for the next attempt); an edit is
/// skipped when nothing changed or the rendered text
/// equals what is already shown; `shown`/`last_edit`
/// are written BEFORE the network call (a failed edit
/// counts as shown and throttled).
/// Source: `internal/commands/telegram_turn.go:699-728`
/// (`maybeEdit`).
async fn maybe_edit(inner: &Arc<EditorInner>) {
    if inner.finished.load(Ordering::SeqCst) {
        return;
    }
    let last = *inner.last_edit.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(last) = last
        && Instant::now().duration_since(last) < EDIT_THROTTLE
    {
        return;
    }
    let (text, dirty) = inner.preview.render_and_clear(Instant::now());
    let shown = inner.shown.lock().map(|s| s.clone()).unwrap_or_default();
    if !dirty || text == shown {
        return;
    }
    // Written BEFORE the network call.
    if let Ok(mut s) = inner.shown.lock() {
        *s = text.clone();
    }
    if let Ok(mut l) = inner.last_edit.lock() {
        *l = Some(Instant::now());
    }
    inner
        .sink
        .edit_plain(inner.chat_id, inner.message_id, &text, None)
        .await;
}

/// The wait approver over the claim manager: fresh
/// approvals are auto-decided through
/// `ClaimManager::approve_forever` (which owns the
/// claim protocol and `RecordDecided`).
///
/// [DEVIATION] `approve_forever` swallows per-id decide
/// errors (it only returns the decided ids), so
/// `WaitResult.auto_approve_errors` is always empty
/// from this approver; the outcome notes therefore
/// never carry an auto-approve error line. The
/// decisions themselves are still correct. See
/// PORTING.md §M5b deviation 8.
pub struct ClaimApprover {
    claims: Arc<ClaimManager>,
    auto_approve: bool,
    auto_allow_once: bool,
}

impl ClaimApprover {
    #[must_use]
    pub fn new(claims: Arc<ClaimManager>, auto_approve: bool, auto_allow_once: bool) -> Self {
        Self {
            claims,
            auto_approve,
            auto_allow_once,
        }
    }
}

impl WaitApprover for ClaimApprover {
    fn approve(
        &self,
        fresh: &[Approval],
    ) -> Pin<Box<dyn Future<Output = ApproveOutcome> + Send + '_>> {
        let claims = Arc::clone(&self.claims);
        let fresh = fresh.to_vec();
        let auto_approve = self.auto_approve;
        let auto_allow_once = self.auto_allow_once;
        Box::pin(async move {
            let decided = claims
                .approve_forever(&fresh, auto_approve, auto_allow_once)
                .await;
            let mut out = ApproveOutcome::default();
            for a in &fresh {
                if decided.contains(&a.id) {
                    out.handled.push(a.id.clone());
                    if let Some(decision) = choose_auto_decision(a, auto_approve, auto_allow_once) {
                        out.approved.push(ApprovedRecord {
                            approval_id: a.id.clone(),
                            title: a.title.clone(),
                            kind: a.kind.clone(),
                            scope: a.scope.clone(),
                            decision: decision.to_string(),
                        });
                    }
                }
            }
            out
        })
    }
}

/// One delivered segment: reply text, or one media file.
/// Source: `internal/commands/telegram_turn.go:1081`
/// (`buildTurnSegments`).
#[derive(Debug, Clone)]
pub enum TurnSegment {
    /// Reply text (already coalesced).
    Text(String),
    /// One media resource with its history seq.
    Media {
        /// History seq of the carrying event.
        seq: i64,
        /// Resolved resource.
        resource: Resource,
    },
}

/// The turn runner: at most one turn per chat, a spawn
/// gate for shutdown, a stop registry, and the
/// resume-follow stale guard. The runner owns the
/// active-turn set; `Bot::begin_turn`/`end_turn` are a
/// second set the core never marks (see PORTING.md
/// §M5b deviation 2) — the runner's set drives every
/// M5b decision.
/// Source: `internal/commands/telegram_turn.go:240-460`.
pub struct TurnRunner {
    port: Arc<dyn GatewayPort>,
    sink: Arc<dyn BotSink>,
    api: Arc<crate::api::BotApi>,
    state: Arc<TelegramStateStore>,
    registry: Arc<CallbackRegistry>,
    claims: Arc<ClaimManager>,
    profile_name: String,
    /// Profile node id, sent in the `chat.stream` body
    /// (Go `deliverSend`: `prof.NodeID`).
    node_id: String,
    block_auto_approve: bool,
    block_auto_allow_once: bool,
    active: Mutex<HashSet<i64>>,
    stops: Mutex<HashMap<i64, Arc<TurnStop>>>,
    resumed: Mutex<HashMap<(i64, String), i64>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    stopping: AtomicBool,
    /// Bound on continuous swallowable history errors
    /// in `wait_follow` (see
    /// [`FOLLOW_HISTORY_ERROR_BUDGET`]), in millis;
    /// tests override it to keep the dead-gateway test
    /// fast.
    follow_error_budget_ms: std::sync::atomic::AtomicU64,
}

/// Drop guard for one chat's turn slot: clears the slot
/// when the spawned turn task ends for ANY reason,
/// including a panic unwinding through it. Go defers
/// `clearActive` through a panic
/// (`telegram_turn.go:187-197,281-284`).
struct TurnSlotGuard {
    runner: Arc<TurnRunner>,
    chat_id: i64,
}

impl TurnSlotGuard {
    fn new(runner: Arc<TurnRunner>, chat_id: i64) -> Self {
        Self { runner, chat_id }
    }
}

impl Drop for TurnSlotGuard {
    fn drop(&mut self) {
        self.runner.clear_active(self.chat_id);
    }
}

/// The per-turn stop entry: a flag the turn reads for
/// its error text, and a notify the wait loop watches.
pub struct TurnStop {
    /// Set by `stop_turn`.
    pub stopped: AtomicBool,
    /// Notified by `stop_turn`.
    pub notify: Notify,
}

impl TurnRunner {
    /// Build a runner. `block_auto_approve` /
    /// `block_auto_allow_once` are the handler-config
    /// defaults the state store overrides per chat.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        port: Arc<dyn GatewayPort>,
        sink: Arc<dyn BotSink>,
        api: Arc<crate::api::BotApi>,
        state: Arc<TelegramStateStore>,
        registry: Arc<CallbackRegistry>,
        claims: Arc<ClaimManager>,
        profile_name: String,
        node_id: String,
        block_auto_approve: bool,
        block_auto_allow_once: bool,
    ) -> Self {
        Self {
            port,
            sink,
            api,
            state,
            registry,
            claims,
            profile_name,
            node_id,
            block_auto_approve,
            block_auto_allow_once,
            active: Mutex::new(HashSet::new()),
            stops: Mutex::new(HashMap::new()),
            resumed: Mutex::new(HashMap::new()),
            tasks: Mutex::new(Vec::new()),
            stopping: AtomicBool::new(false),
            follow_error_budget_ms: std::sync::atomic::AtomicU64::new(
                FOLLOW_HISTORY_ERROR_BUDGET.as_millis() as u64,
            ),
        }
    }

    /// Override the follow-poll history-error budget
    /// (tests only; production uses
    /// [`FOLLOW_HISTORY_ERROR_BUDGET`]).
    #[cfg(test)]
    fn set_follow_error_budget(&self, budget: Duration) {
        self.follow_error_budget_ms
            .store(budget.as_millis() as u64, Ordering::SeqCst);
    }

    /// The follow-poll history-error budget.
    fn follow_error_budget(&self) -> Duration {
        Duration::from_millis(self.follow_error_budget_ms.load(Ordering::SeqCst))
    }

    /// Whether `chat_id` has an active turn (runner set).
    #[must_use]
    pub fn has_active_turn(&self, chat_id: i64) -> bool {
        self.active
            .lock()
            .map(|a| a.contains(&chat_id))
            .unwrap_or(false)
    }

    /// Whether any chat has an active turn.
    #[must_use]
    pub fn any_active_turn(&self) -> bool {
        self.active.lock().map(|a| !a.is_empty()).unwrap_or(false)
    }

    /// Effective toggles for `chat_id`.
    fn toggles(&self, chat_id: i64) -> (bool, bool) {
        let t = self
            .state
            .toggles(self.block_auto_approve, self.block_auto_allow_once);
        let _ = chat_id;
        (t.auto_approve, t.auto_allow_once)
    }

    /// Start a text turn in its own task and return
    /// immediately, so the dispatcher's per-chat worker
    /// stays free for /stop. A second message while one
    /// is active gets the busy reply.
    /// Source: `internal/commands/telegram_turn.go:262-295`
    /// (`startTurn`).
    pub async fn start_turn(self: &Arc<Self>, chat_id: i64, text: String) {
        if self.stopping.load(Ordering::SeqCst) {
            return;
        }
        // Go `startTurn` (`telegram_turn.go:271-280`)
        // holds ONE lock for the busy check and the slot
        // insert: a single critical section, no await
        // inside (a `std::sync::MutexGuard` is not
        // `Send`), so two concurrent starts cannot both
        // pass the check.
        let busy = {
            let mut active = self.active.lock().expect("active lock");
            if active.contains(&chat_id) {
                true
            } else {
                active.insert(chat_id);
                false
            }
        };
        if busy {
            let _ = self
                .sink
                .send(
                    chat_id,
                    BUSY_REPLY,
                    SendOptions {
                        mode: HtmlMode::Plain,
                        ..Default::default()
                    },
                )
                .await;
            return;
        }
        let this = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let _guard = TurnSlotGuard::new(Arc::clone(&this), chat_id);
            let stopped = this.run_text_turn(chat_id, &text).await;
            let _ = stopped;
        });
        self.push_task(handle);
    }

    /// Record a spawned turn task, dropping finished
    /// handles first so the vec does not grow without
    /// bound over the bot's lifetime (Red N4; the
    /// `decided` set is already capped at 1024, and
    /// `notified`/`resumed` intentionally match Go,
    /// which never prunes them either — see PORTING).
    fn push_task(&self, handle: tokio::task::JoinHandle<()>) {
        let mut tasks = self.tasks.lock().expect("tasks lock");
        tasks.retain(|h| !h.is_finished());
        tasks.push(handle);
    }

    /// Schedule a resume-follow under the same
    /// one-turn-per-chat guard, waiting at most 5s for
    /// the slot (the deciding turn is usually still in
    /// teardown). Drops: `slot-wait-expired` and
    /// `stale-resume` (with the user notice),
    /// `shutdown-cancelled` (log only, no notice).
    /// Source: `internal/commands/telegram_turn.go:316-396`
    /// (`startResume`).
    pub async fn start_resume(
        self: &Arc<Self>,
        chat_id: i64,
        session_id: String,
        title: String,
        after_seq: i64,
    ) {
        if self.stopping.load(Ordering::SeqCst) {
            return;
        }
        let this = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let deadline = Instant::now() + RESUME_SLOT_WAIT;
            loop {
                {
                    let mut active = this.active.lock().expect("active lock");
                    if !active.contains(&chat_id) {
                        active.insert(chat_id);
                        break;
                    }
                }
                // Go `startResume`
                // (`telegram_turn.go:327-332`): the deferred
                // `clearActive` runs only when `acquired`
                // is true. This branch never acquired the
                // slot, so it must NOT clear the running
                // turn's slot.
                if this.stopping.load(Ordering::SeqCst) {
                    return;
                }
                if Instant::now() > deadline {
                    this.drop_resume(chat_id, "slot-wait-expired").await;
                    return;
                }
                tokio::time::sleep(RESUME_POLL).await;
            }
            // The slot is ours from here: the guard clears
            // it on every exit path, including a panic.
            let _guard = TurnSlotGuard::new(Arc::clone(&this), chat_id);
            // [DEVIATION] Go checks the bot core's second
            // active set (`HasActiveTurn`) here; in Rust
            // there is only the runner's set, and the slot
            // was just acquired, so that check collapses
            // into the slot wait above. See PORTING.md §M5b
            // deviation 2.
            let stale = {
                let resumed = this.resumed.lock().expect("resumed lock");
                resumed
                    .get(&(chat_id, session_id.clone()))
                    .is_some_and(|last| after_seq <= *last)
            };
            if stale {
                this.drop_resume(chat_id, "stale-resume").await;
                return;
            }
            this.run_resume(chat_id, &session_id, &title, after_seq)
                .await;
        });
        self.push_task(handle);
    }

    async fn drop_resume(&self, chat_id: i64, reason: &str) {
        let _ = self
            .sink
            .send(
                chat_id,
                &format!("⚠️ Follow dropped ({reason}). Send a message to continue."),
                SendOptions {
                    silent: true,
                    ..Default::default()
                },
            )
            .await;
    }

    fn clear_active(&self, chat_id: i64) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(&chat_id);
        }
    }

    /// Join in-flight turns (shutdown): mark stopping so
    /// no new turn starts, signal every registered stop,
    /// then wait for every spawned task. Go `Wait`
    /// (`telegram_turn.go:240-249`) is bounded because
    /// shutdown cancels the turn ctx; signalling here is
    /// the Rust equivalent — without it a turn polling
    /// history to the 6h deadline hangs shutdown forever.
    /// Source: `internal/commands/telegram_turn.go:240-249`
    /// (`Wait`).
    pub async fn wait_turns(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Ok(stops) = self.stops.lock() {
            for entry in stops.values() {
                entry.stopped.store(true, Ordering::SeqCst);
                entry.notify.notify_waiters();
            }
        }
        let handles = {
            let mut tasks = self.tasks.lock().expect("tasks lock");
            std::mem::take(&mut *tasks)
        };
        for h in handles {
            let _ = h.await;
        }
    }

    /// Cancel the chat's active turn (if any) and ask the
    /// server to cancel it (`chat.cancel` for the chat's
    /// current session). Reports whether the server said
    /// anything was running.
    /// Source: `internal/commands/telegram_turn.go:431-460`
    /// (`stopTurn`) and `internal/deliver/stop.go:26-34`.
    pub async fn stop_turn(&self, chat_id: i64) -> Result<bool, BotError> {
        if let Ok(stops) = self.stops.lock()
            && let Some(entry) = stops.get(&chat_id)
        {
            entry.stopped.store(true, Ordering::SeqCst);
            entry.notify.notify_waiters();
        }
        let scope = self.state.chat(chat_id).session_id;
        let mut body = json!({});
        if !scope.is_empty() {
            body["session_id"] = Value::String(scope);
        }
        let res = self
            .port
            .call_json(
                "chat.cancel",
                RequestOptions {
                    body: Body::Json(body),
                    ..Default::default()
                },
            )
            .await?;
        let cancelled = res
            .get("cancelled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(cancelled)
    }

    /// One text turn for a plain message (or a
    /// question-button value, sent as ordinary user
    /// text). Errors are rendered into the bubble and
    /// `Ok` is returned: a failed turn must not stop the
    /// poll loop.
    /// Source: `internal/commands/telegram_turn.go:465-538`
    /// (`runTextTurn`).
    async fn run_text_turn(self: &Arc<Self>, chat_id: i64, text: &str) -> Result<(), BotError> {
        let entry = self.state.chat(chat_id);
        let scope = entry.session_id.clone();
        let title = if entry.title.is_empty() {
            "main chat".to_string()
        } else {
            entry.title.clone()
        };
        let stop = Arc::new(TurnStop {
            stopped: AtomicBool::new(false),
            notify: Notify::new(),
        });
        {
            let mut stops = self.stops.lock().expect("stops lock");
            stops.insert(chat_id, Arc::clone(&stop));
        }
        self.signal_if_stopping(&stop);
        let preview = Arc::new(StreamPreview::new(Instant::now()));
        let bubble_id = match self
            .sink
            .send(
                chat_id,
                SENDING_BUBBLE,
                SendOptions {
                    mode: HtmlMode::Plain,
                    ..Default::default()
                },
            )
            .await
        {
            Ok(id) => id,
            Err(e) => {
                // Bubble failure aborts the turn: without a
                // bubble there is nowhere to stream to.
                self.unregister_stop(chat_id, &stop);
                return Err(e);
            }
        };
        let mut editor = BubbleEditor::start(
            Arc::clone(&self.sink),
            chat_id,
            bubble_id,
            Arc::clone(&preview),
        );
        let user_seq = match self.deliver_send(chat_id, &scope, text, &stop).await {
            Ok(seq) => seq,
            Err(e) => {
                let stopped = stop.stopped.load(Ordering::SeqCst);
                editor.edit_final(&turn_error_text(&e, stopped), None).await;
                editor.finish().await;
                self.unregister_stop(chat_id, &stop);
                return Ok(());
            }
        };
        let Some(user_seq) = user_seq else {
            editor.edit_final(NO_ACK_TEXT, None).await;
            editor.finish().await;
            self.unregister_stop(chat_id, &stop);
            return Ok(());
        };
        let (auto_approve, auto_allow_once) = self.toggles(chat_id);
        let res = match self
            .wait_follow(
                chat_id,
                &scope,
                user_seq,
                TURN_TIMEOUT,
                &preview,
                &mut editor,
                auto_approve,
                auto_allow_once,
                &stop,
            )
            .await
        {
            Ok(res) => res,
            Err(e) => {
                let stopped = stop.stopped.load(Ordering::SeqCst);
                editor.edit_final(&turn_error_text(&e, stopped), None).await;
                editor.finish().await;
                self.unregister_stop(chat_id, &stop);
                return Ok(());
            }
        };
        // The final reply owns the bubble from here: stop
        // streaming edits before delivering.
        editor.finish().await;
        let stopped = stop.stopped.load(Ordering::SeqCst);
        if let Err(e) = self
            .deliver_final(chat_id, bubble_id, &scope, &title, user_seq, &res, stopped)
            .await
        {
            // Go returns the `deliverFinal` error without
            // `editFinal` (`telegram_turn.go:529-532`), but
            // the spawned turn task drops that `Err` and
            // the user would see nothing: report the error
            // text in the bubble first, then propagate.
            let stopped = stop.stopped.load(Ordering::SeqCst);
            editor.edit_final(&turn_error_text(&e, stopped), None).await;
            editor.finish().await;
            self.unregister_stop(chat_id, &stop);
            return Err(e);
        }
        self.unregister_stop(chat_id, &stop);
        // Advance the watermark only after delivery
        // succeeded, capped at the last seq delivered.
        let top = delivered_top_seq(user_seq, &res);
        if top > 0 {
            let _ = self.state.set_watermark(&scope, top);
        }
        Ok(())
    }

    /// Follow a turn after a manual approval decision,
    /// with no new delivery. The bubble says Muse is
    /// continuing; the wait follows from `after_seq`.
    /// Source: `internal/commands/telegram_turn.go:547-606`
    /// (`runResume`).
    async fn run_resume(
        self: &Arc<Self>,
        chat_id: i64,
        session_id: &str,
        title: &str,
        after_seq: i64,
    ) {
        let title = if title.is_empty() {
            "main chat".to_string()
        } else {
            title.to_string()
        };
        let stop = Arc::new(TurnStop {
            stopped: AtomicBool::new(false),
            notify: Notify::new(),
        });
        {
            let mut stops = self.stops.lock().expect("stops lock");
            stops.insert(chat_id, Arc::clone(&stop));
        }
        self.signal_if_stopping(&stop);
        let preview = Arc::new(StreamPreview::new(Instant::now()));
        let bubble_id = match self
            .sink
            .send(
                chat_id,
                CONTINUING_BUBBLE,
                SendOptions {
                    mode: HtmlMode::Plain,
                    ..Default::default()
                },
            )
            .await
        {
            Ok(id) => id,
            Err(_) => {
                self.unregister_stop(chat_id, &stop);
                return;
            }
        };
        let mut editor = BubbleEditor::start(
            Arc::clone(&self.sink),
            chat_id,
            bubble_id,
            Arc::clone(&preview),
        );
        let (auto_approve, auto_allow_once) = self.toggles(chat_id);
        let res = match self
            .wait_follow(
                chat_id,
                session_id,
                after_seq,
                TURN_TIMEOUT,
                &preview,
                &mut editor,
                auto_approve,
                auto_allow_once,
                &stop,
            )
            .await
        {
            Ok(res) => res,
            Err(e) => {
                let stopped = stop.stopped.load(Ordering::SeqCst);
                editor.edit_final(&turn_error_text(&e, stopped), None).await;
                editor.finish().await;
                self.unregister_stop(chat_id, &stop);
                return;
            }
        };
        // The follow reached its wait: record the seq so a
        // stale re-tap of another button from the same turn
        // cannot re-fire this follow. A failed follow
        // records nothing, so it stays retryable.
        {
            let mut resumed = self.resumed.lock().expect("resumed lock");
            resumed.insert((chat_id, session_id.to_string()), after_seq);
        }
        editor.finish().await;
        let stopped = stop.stopped.load(Ordering::SeqCst);
        match self
            .deliver_final(
                chat_id, bubble_id, session_id, &title, after_seq, &res, stopped,
            )
            .await
        {
            Ok(()) => {
                let top = delivered_top_seq(after_seq, &res);
                if top > 0 {
                    let _ = self.state.set_watermark(session_id, top);
                }
            }
            // Same rule as `run_text_turn`: a delivery
            // failure must reach the user as an error text
            // in the bubble, not vanish silently.
            Err(e) => {
                let stopped = stop.stopped.load(Ordering::SeqCst);
                editor.edit_final(&turn_error_text(&e, stopped), None).await;
                editor.finish().await;
            }
        }
        self.unregister_stop(chat_id, &stop);
    }

    fn unregister_stop(&self, chat_id: i64, entry: &Arc<TurnStop>) {
        if let Ok(mut stops) = self.stops.lock()
            && let Some(cur) = stops.get(&chat_id)
            && Arc::ptr_eq(cur, entry)
        {
            stops.remove(&chat_id);
        }
    }

    /// Signal `entry` when shutdown is already in
    /// progress: a turn registered after `wait_turns`
    /// signalled the map must still stop promptly
    /// instead of polling to the 6h deadline.
    fn signal_if_stopping(&self, entry: &Arc<TurnStop>) {
        if self.stopping.load(Ordering::SeqCst) {
            entry.stopped.store(true, Ordering::SeqCst);
            entry.notify.notify_waiters();
        }
    }

    /// Send the user's text via `chat.stream`, then poll
    /// history until the user's message is acked (or the
    /// 30s ack timeout). Returns the user seq, or `None`
    /// when delivery was never confirmed.
    /// Source: `internal/commands/wait.go:862-948`
    /// (`deliverSend`).
    async fn deliver_send(
        &self,
        _chat_id: i64,
        scope: &str,
        text: &str,
        stop: &Arc<TurnStop>,
    ) -> Result<Option<i64>, BotError> {
        let baseline_events = self.port.history(1, scope).await?;
        let baseline = baseline_events
            .iter()
            .filter_map(history_seq)
            .max()
            .unwrap_or(0);
        let baseline20 = self.port.history(20, scope).await?;
        let baseline = baseline20
            .iter()
            .filter_map(history_seq)
            .max()
            .unwrap_or(baseline);
        let mut body = json!({
            "items": [{"type": "text", "text": text}],
            "node_id": self.node_id,
            "capabilities": {},
        });
        if !scope.is_empty() {
            body["session_id"] = Value::String(scope.to_string());
        }
        self.port.open_stream(body).await?;
        let deadline = Instant::now() + ACK_TIMEOUT;
        loop {
            if stop.stopped.load(Ordering::SeqCst) {
                return Err(BotError::Cancelled);
            }
            let events = match self.port.history(10, scope).await {
                Ok(events) => events,
                Err(e) => {
                    // Go `deliverSend`
                    // (`internal/commands/wait.go:920-929`):
                    // a swallowable history error keeps
                    // polling to the deadline; only a
                    // non-swallowable error fails the send.
                    if swallowable_history_error(&e) {
                        if Instant::now() >= deadline {
                            return Ok(None);
                        }
                        tokio::time::sleep(ACK_POLL).await;
                        continue;
                    }
                    return Err(e);
                }
            };
            if let Some(seq) = user_ack(&events, baseline, Some(text)) {
                return Ok(Some(seq));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            tokio::time::sleep(ACK_POLL).await;
        }
    }

    /// Follow a turn to its end by polling `chat.history`
    /// every second (see the module-level deviation note:
    /// no `chat.subscribe` exists in Rust yet). New events
    /// feed the preview and the waiter in seq order; the
    /// approver auto-decides fresh approvals; on a decided
    /// outcome a final history read (2 attempts) collects
    /// the replies, with the settle / replayed-failed /
    /// lag-window endgame.
    /// Source: `internal/commands/wait.go:240-450`
    /// (`executeWait` / `Runner.finish`).
    #[allow(clippy::too_many_arguments)]
    async fn wait_follow(
        &self,
        chat_id: i64,
        scope: &str,
        after_seq: i64,
        timeout: Duration,
        preview: &Arc<StreamPreview>,
        editor: &mut BubbleEditor,
        auto_approve: bool,
        auto_allow_once: bool,
        stop: &Arc<TurnStop>,
    ) -> Result<WaitResult, BotError> {
        let mut waiter = Waiter::new(scope);
        waiter.set_boundary(after_seq, false, false);
        let approver = ClaimApprover::new(Arc::clone(&self.claims), auto_approve, auto_allow_once);
        let deadline = Instant::now() + timeout;
        let mut last_seen: i64 = after_seq;
        let mut outcome: Option<crate::wait::Outcome> = None;
        // Consecutive swallowable history errors: the
        // poll has no resubscribe to recover on (deviation
        // 1), so a dead gateway must end the turn instead
        // of polling silently to the 6h deadline. See
        // `FOLLOW_HISTORY_ERROR_BUDGET` and PORTING §M5b
        // deviation 17 for the bound's Go anchors.
        let mut first_error_at: Option<Instant> = None;
        let mut consecutive_errors: u32 = 0;
        loop {
            if stop.stopped.load(Ordering::SeqCst) {
                return Err(BotError::Cancelled);
            }
            let events = match self.port.history(200, scope).await {
                Ok(events) => {
                    first_error_at = None;
                    consecutive_errors = 0;
                    events
                }
                Err(e) => {
                    // History errors are swallowable only for
                    // gateway/timeout classes (Go's ack-poll
                    // rule, `internal/commands/wait.go:932`);
                    // anything else ends the turn.
                    if !swallowable_history_error(&e) {
                        return Err(e);
                    }
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    let first = *first_error_at.get_or_insert_with(Instant::now);
                    if first.elapsed() >= self.follow_error_budget() {
                        return Err(e);
                    }
                    // Go's resubscribe backoff
                    // (`internal/wait/runner.go:426-435`):
                    // base 1s, doubling with the shift capped
                    // at 5 (max 32s). The sleep watches the
                    // stop notify so /stop stays prompt.
                    let shift = consecutive_errors.saturating_sub(1).min(5);
                    let pause = Duration::from_secs(1u64 << shift);
                    if stop.stopped.load(Ordering::SeqCst) {
                        return Err(BotError::Cancelled);
                    }
                    tokio::select! {
                        () = tokio::time::sleep(pause) => {}
                        () = stop.notify.notified() => {
                            return Err(BotError::Cancelled);
                        }
                    }
                    continue;
                }
            };
            let mut fresh: Vec<Value> = events
                .iter()
                .filter(|ev| seq_of(ev) > last_seen)
                .cloned()
                .collect();
            fresh.sort_by_key(seq_of);
            for ev in &fresh {
                last_seen = last_seen.max(seq_of(ev));
                preview.feed(ev);
                editor.signal();
                // Approvals events also notify the chat (the
                // turn engine is `notify_pending`'s first
                // caller).
                if event_name(ev).starts_with("approvals")
                    && let Some(pend) = approvals_pending(ev)
                {
                    let items: Vec<Approval> = pend
                        .iter()
                        .map(crate::approvals::describe_approval)
                        .collect();
                    if !items.is_empty() {
                        let ctx = NotifyPending {
                            api: &self.api,
                            registry: &self.registry,
                            claims: &self.claims,
                            auto_approve,
                            auto_allow_once,
                            any_active_turn: true,
                            chat_id,
                            items: &items,
                        };
                        crate::claims::notify_pending(&ctx).await;
                    }
                }
                if let Some(o) = waiter.feed(ev, Some(&approver)).await {
                    outcome = Some(o);
                    break;
                }
            }
            if outcome.is_some() || Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        // Final history read (2 attempts), then the
        // endgame: settle a suspect terminal, accept a
        // replayed failure, lag window for a done outcome
        // with zero replies, fail-closed timeout.
        let mut events: Vec<Value> = Vec::new();
        let mut final_read_failed = false;
        for _ in 0..2 {
            match self.port.history(200, scope).await {
                Ok(ev) => {
                    events = ev;
                    break;
                }
                Err(_) => {
                    final_read_failed = true;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        let replies = replies_after(&events, after_seq, None);
        let mut kind = match &outcome {
            Some(o) => o.kind,
            None => WaitKind::Timeout,
        };
        let mut detail = outcome
            .as_ref()
            .map(|o| o.detail.clone())
            .unwrap_or_default();
        let mut approvals = outcome
            .as_ref()
            .map(|o| o.approvals.clone())
            .unwrap_or_default();
        if outcome.is_none() {
            // Last-chance replayed-failed proof.
            let latest_user = events
                .iter()
                .filter(|ev| ev.get("event_name").and_then(Value::as_str) == Some("message.user"))
                .filter_map(history_seq)
                .max();
            if let Some(o) = waiter.accept_replayed_failed(latest_user) {
                kind = o.kind;
                detail = o.detail;
            }
        }
        if kind == WaitKind::Done && replies.is_empty() {
            // Lag window: one more read after a second.
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Ok(ev) = self.port.history(200, scope).await {
                events = ev;
            }
        }
        let replies = replies_after(&events, after_seq, None);
        if matches!(kind, WaitKind::Done | WaitKind::Failed)
            && let Some(o) = waiter.settle(&replies)
        {
            kind = o.kind;
            detail = o.detail;
        }
        if kind == WaitKind::Timeout {
            detail = waiter.status().unwrap_or("").to_string();
        }
        if kind == WaitKind::Approval {
            approvals = outcome
                .as_ref()
                .map(|o| o.approvals.clone())
                .unwrap_or_default();
        }
        let final_text = replies.last().map(|r| r.text.clone()).unwrap_or_default();
        let needs_input_reason = replies
            .last()
            .map(|r| needs_input_reason(&r.text))
            .unwrap_or_default();
        let question = replies.last().map(|r| r.text.clone()).unwrap_or_default();
        let outcome_str = outcome_of(kind, &replies);
        let exit_code = crate::wait::exit_code(kind, &replies);
        Ok(WaitResult {
            kind,
            outcome: outcome_str.to_string(),
            status: detail,
            after_seq,
            final_text,
            replies,
            final_read_failed,
            note: String::new(),
            approvals,
            needs_input_reason,
            question,
            exit_code,
            node_id: String::new(),
            auto_approved: waiter.approved_records().to_vec(),
            auto_approve_errors: waiter.approve_errors().to_vec(),
        })
    }

    /// Deliver the final reply: media first when the turn
    /// produced any, else text only. Returns `Err` only
    /// when delivery itself failed (the caller then skips
    /// the watermark).
    /// Source: `internal/commands/telegram_turn.go:793-824`
    /// (`deliverFinal`).
    /// The arity mirrors Go's `deliverFinal` signature.
    #[allow(clippy::too_many_arguments)]
    async fn deliver_final(
        &self,
        chat_id: i64,
        bubble_id: i64,
        scope: &str,
        title: &str,
        user_seq: i64,
        res: &WaitResult,
        stopped: bool,
    ) -> Result<(), BotError> {
        let mut final_text = res.final_text.clone();
        if final_text.is_empty() {
            final_text = res
                .replies
                .iter()
                .map(|r| r.text.trim())
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
                .join("\n\n");
        }
        let notes = outcome_notes(res, stopped);
        let markup = final_markup(&self.registry, res, scope, title, Some(user_seq));
        if self
            .deliver_media_turn(chat_id, bubble_id, scope, user_seq, res, &notes, &markup)
            .await?
        {
            return Ok(());
        }
        // Text-only path.
        let text = if final_text.is_empty() && notes.is_empty() {
            if res.outcome == "done" || res.outcome == "needs_input" {
                "(no reply text)".to_string()
            } else {
                "(done)".to_string()
            }
        } else if final_text.is_empty() {
            notes.join("\n\n")
        } else if notes.is_empty() {
            final_text.clone()
        } else {
            format!("{final_text}\n\n{}", notes.join("\n\n"))
        };
        self.deliver_text_segment(chat_id, bubble_id, &text, true, true, markup)
            .await
    }

    /// Deliver one text segment: the first piece edits the
    /// bubble (error → send new), later pieces are sent;
    /// a long reply becomes a document instead.
    /// Source: `internal/commands/telegram_turn.go:826-874`
    /// (`deliverTextSegment`).
    async fn deliver_text_segment(
        &self,
        chat_id: i64,
        bubble_id: i64,
        text: &str,
        first: bool,
        last: bool,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Result<(), BotError> {
        if first && needs_document(text) {
            let preview = document_preview(text);
            if self
                .sink
                .edit(chat_id, bubble_id, &preview, HtmlMode::Plain, None)
                .await
                .is_err()
            {
                let _ = self
                    .sink
                    .send(
                        chat_id,
                        &preview,
                        SendOptions {
                            mode: HtmlMode::Plain,
                            ..Default::default()
                        },
                    )
                    .await;
            }
            let name = doc_name("muse-reply", text);
            let err = self
                .sink
                .send_file(
                    chat_id,
                    &name,
                    text.as_bytes(),
                    "",
                    "Muse's full reply",
                    &SendOptions {
                        markup: if last { markup } else { None },
                        ..Default::default()
                    },
                )
                .await;
            return err.map(|_| ());
        }
        if !first && needs_document(text) {
            let name = doc_name("muse-reply", text);
            return self
                .sink
                .send_file(
                    chat_id,
                    &name,
                    text.as_bytes(),
                    "",
                    "Muse's full reply",
                    &SendOptions {
                        markup: if last { markup } else { None },
                        ..Default::default()
                    },
                )
                .await
                .map(|_| ());
        }
        let pieces = split_text(text);
        let n = pieces.len();
        for (i, piece) in pieces.iter().enumerate() {
            let is_last_piece = last && i + 1 == n;
            if first && i == 0 {
                if self
                    .sink
                    .edit(
                        chat_id,
                        bubble_id,
                        piece,
                        HtmlMode::Plain,
                        if is_last_piece { markup.clone() } else { None },
                    )
                    .await
                    .is_err()
                {
                    self.sink
                        .send(
                            chat_id,
                            piece,
                            SendOptions {
                                mode: HtmlMode::Plain,
                                markup: if is_last_piece { markup.clone() } else { None },
                                ..Default::default()
                            },
                        )
                        .await?;
                }
            } else {
                self.sink
                    .send(
                        chat_id,
                        piece,
                        SendOptions {
                            mode: HtmlMode::Plain,
                            markup: if is_last_piece { markup.clone() } else { None },
                            ..Default::default()
                        },
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Collect this turn's media from history, widening
    /// the window until the oldest event is at or before
    /// the user's message.
    /// Source: `internal/commands/telegram_turn.go:934-1080`
    /// (`collectTurnMedia`).
    async fn collect_turn_media(
        &self,
        scope: &str,
        user_seq: i64,
        upto: Option<i64>,
    ) -> Result<Vec<(i64, Resource)>, BotError> {
        let mut out: Vec<(i64, Resource)> = Vec::new();
        let mut seen_event: HashSet<(i64, String)> = HashSet::new();
        let mut seen_path: HashSet<String> = HashSet::new();
        for limit in TURN_MEDIA_HISTORY_LIMITS {
            let events = self.port.history(limit, scope).await?;
            let mut sorted = events.clone();
            sorted.sort_by_key(seq_of);
            let oldest = sorted.iter().filter_map(history_seq).min();
            let mut rows: Vec<(i64, Resource)> = Vec::new();
            for ev in &sorted {
                let seq = seq_of(ev);
                if seq <= user_seq || upto.is_some_and(|u| seq > u) {
                    continue;
                }
                if ev.get("event_name").and_then(Value::as_str) != Some("message.assistant") {
                    continue;
                }
                if payload_status(ev) != Some("completed".to_string()) {
                    continue;
                }
                if is_self_referential(ev) {
                    continue;
                }
                let mid = first_truthy_id(ev);
                if !seen_event.insert((seq, mid)) {
                    continue;
                }
                for res in event_resources(&from_serde(ev)) {
                    if seen_path.insert(res.path.clone()) {
                        rows.push((seq, res));
                    }
                }
            }
            out.extend(rows);
            if oldest.is_some_and(|o| o <= user_seq) {
                break;
            }
        }
        out.sort_by_key(|(seq, _)| *seq);
        Ok(out)
    }

    /// Deliver the turn's media segments. Returns `Ok(true)`
    /// when at least one media segment was delivered (the
    /// caller then skips the text path), `Ok(false)` when
    /// there was no media at all.
    /// Source: `internal/commands/telegram_turn.go:1128-1242`
    /// (`deliverMediaTurn`, `buildTurnSegments`).
    /// The arity mirrors Go's `deliverMediaTurn` signature.
    #[allow(clippy::too_many_arguments)]
    async fn deliver_media_turn(
        &self,
        chat_id: i64,
        bubble_id: i64,
        scope: &str,
        user_seq: i64,
        res: &WaitResult,
        notes: &[String],
        markup: &Option<InlineKeyboardMarkup>,
    ) -> Result<bool, BotError> {
        // Go `deliverMediaTurn`
        // (`telegram_turn.go:1133-1143`): a history-read
        // failure is `errMediaUnavailable` (unless
        // auth/cancel) and the caller falls back to the
        // text-only path — the turn does not fail. The
        // collect is capped at `deliveredTopSeq`
        // (`telegram_turn.go:1133`, filter at `:960`).
        let media = match self
            .collect_turn_media(scope, user_seq, Some(delivered_top_seq(user_seq, res)))
            .await
        {
            Ok(media) => media,
            Err(e) => {
                if is_media_fatal(&e) {
                    return Err(e);
                }
                return Ok(false);
            }
        };
        if media.is_empty() {
            return Ok(false);
        }
        // Cap 6 is counted AFTER path-dedupe, BEFORE the
        // sent-media claim — Go counts the same way, so a
        // file already sent in an earlier turn still
        // consumes one of the 6 slots here (deviation vs
        // Python, which filters already-sent first; see
        // `docs/provenance.md`).
        let excess = media.len().saturating_sub(MAX_FILES_PER_TURN);
        let mut notes = notes.to_vec();
        if excess > 0 {
            notes.push(format!("📎 {excess} more file(s): see /files"));
        }
        // Go truncates the send list to the cap here
        // (`telegram_turn.go:1155`: `items =
        // items[:maxFilesPerTurn]`); the note above is the
        // only trace of the rest. (Found by the cap-6
        // edge-case test, 2026-11-06: the first version
        // of this function sent all 7.)
        let media: &[(i64, castctl_shared::Resource)] = if media.len() > MAX_FILES_PER_TURN {
            &media[..MAX_FILES_PER_TURN]
        } else {
            &media
        };
        let segments = build_turn_segments(res, media, &notes);
        let n = segments.len();
        let mut first_text_done = false;
        let mut media_first = true;
        for (i, seg) in segments.iter().enumerate() {
            let is_last = i + 1 == n;
            match seg {
                TurnSegment::Text(text) => {
                    media_first = false;
                    let m = if is_last { markup.clone() } else { None };
                    self.deliver_text_segment(
                        chat_id,
                        bubble_id,
                        text,
                        !first_text_done,
                        is_last,
                        m,
                    )
                    .await?;
                    first_text_done = true;
                }
                TurnSegment::Media { seq: _, resource } => {
                    if media_first && i == 0 {
                        // Media-first turn: delete the bubble
                        // best-effort.
                        let _ = self.sink.delete(chat_id, bubble_id).await;
                    }
                    self.deliver_media_item(chat_id, scope, resource).await?;
                }
            }
        }
        // Notes/buttons with no trailing text segment get a
        // tail message.
        if matches!(segments.last(), Some(TurnSegment::Media { .. }))
            && (!notes.is_empty() || markup.is_some())
        {
            let tail = if notes.is_empty() {
                "⬆️".to_string()
            } else {
                notes.join("\n\n")
            };
            self.sink
                .send(
                    chat_id,
                    &tail,
                    SendOptions {
                        markup: markup.clone(),
                        ..Default::default()
                    },
                )
                .await?;
        }
        Ok(true)
    }

    /// Deliver one media file: claim sent-media BEFORE
    /// downloading (a claim-save failure only warns; an
    /// already-claimed file is silently skipped); the
    /// pre-download size gate keeps the claim on
    /// too-big; a download/send failure releases it.
    /// Source: `internal/commands/telegram_turn.go:1243-1330`
    /// (`deliverMediaItem`).
    async fn deliver_media_item(
        &self,
        chat_id: i64,
        scope: &str,
        res: &Resource,
    ) -> Result<(), BotError> {
        // Go computes the name from the resource path
        // first (`LocalName(res.Path)`) and a bad path
        // surfaces inside the download as a per-file
        // failure — a notice, not a fatal error
        // (`telegram_turn.go:1243-1330`).
        let path = match media_path(&res.path, res.variants.as_ref()) {
            Ok(path) => path,
            Err(e) => {
                let name = local_name(&res.path, "");
                let _ = self
                    .sink
                    .send(
                        chat_id,
                        &media_failure_notice(&name, "fetched", &BotError::Transport(e)),
                        SendOptions::default(),
                    )
                    .await;
                return Ok(());
            }
        };
        let name = local_name(&path, "");
        let key = crate::state::sent_media_key(&self.profile_name, chat_id, scope, &path);
        if self.state.sent_media_claimed(&key) {
            return Ok(());
        }
        let _ = self.state.claim_sent_media(&key);
        let byte_len = res.byte_len.unwrap_or(0);
        if byte_len > UPLOAD_LIMIT {
            let _ = self
                .sink
                .send(
                    chat_id,
                    &too_big_notice(&name, byte_len),
                    SendOptions {
                        mode: HtmlMode::Html,
                        ..Default::default()
                    },
                )
                .await;
            return Ok(());
        }
        let data = match self.port.download_file(&path).await {
            Ok(data) => data,
            Err(e) => {
                let _ = self.state.release_sent_media(&key);
                if is_media_fatal(&e) {
                    return Err(e);
                }
                let _ = self
                    .sink
                    .send(
                        chat_id,
                        &media_failure_notice(&name, "fetched", &e),
                        SendOptions::default(),
                    )
                    .await;
                return Ok(());
            }
        };
        if (data.len() as i64) > UPLOAD_LIMIT {
            let _ = self
                .sink
                .send(
                    chat_id,
                    &too_big_notice(&name, data.len() as i64),
                    SendOptions {
                        mode: HtmlMode::Html,
                        ..Default::default()
                    },
                )
                .await;
            return Ok(());
        }
        let caption = match &res.label {
            Some(label) if !label.trim().is_empty() && label.trim() != name => {
                label.trim().to_string()
            }
            _ => String::new(),
        };
        let mime = res.mime.clone().unwrap_or_default();
        if let Err(e) = self
            .sink
            .send_file(
                chat_id,
                &name,
                &data,
                &mime,
                &caption,
                &SendOptions::default(),
            )
            .await
        {
            let _ = self.state.release_sent_media(&key);
            if is_media_fatal(&e) {
                return Err(e);
            }
            let _ = self
                .sink
                .send(
                    chat_id,
                    &media_failure_notice(&name, "sent", &e),
                    SendOptions::default(),
                )
                .await;
        }
        Ok(())
    }
}

/// Extract the pending list from an approvals event
/// (same rule as the waiter's: only `approvals*`
/// events; `pending_approvals` preferred, empty does
/// not fall back).
fn approvals_pending(ev: &Value) -> Option<Vec<Value>> {
    if !event_name(ev).starts_with("approvals") {
        return None;
    }
    let p = ev.get("payload").and_then(Value::as_object)?;
    let pend = match p.get("pending_approvals") {
        Some(v) if !v.is_null() => Some(v),
        _ => p.get("pending"),
    };
    pend.and_then(Value::as_array).cloned()
}

fn payload_status(ev: &Value) -> Option<String> {
    ev.get("payload")
        .and_then(|p| p.get("status"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn first_truthy_id(ev: &Value) -> String {
    for v in [
        ev.get("payload").and_then(|p| p.get("message_id")),
        ev.get("message_id"),
    ] {
        if let Some(s) = v.and_then(Value::as_str)
            && !s.is_empty()
        {
            return s.to_string();
        }
    }
    String::new()
}

/// Outcome notes appended after the final text, in
/// Python's order: auto-approved lines, needs-input,
/// needs-approval, failed/stopped, timeout, auto-approve
/// errors.
/// Source: `internal/commands/telegram_turn.go:1391-1426`
/// (`outcomeNotes`).
#[must_use]
pub fn outcome_notes(res: &WaitResult, stopped: bool) -> Vec<String> {
    let mut notes: Vec<String> = Vec::new();
    for a in &res.auto_approved {
        let decision = if a.decision == "allow_always" {
            "always"
        } else {
            "once"
        };
        let mut line = format!("✅ auto-approved ({decision}): {}", a.title);
        if !a.kind.is_empty() || !a.scope.is_empty() {
            line.push_str(&format!(" [{} {}]", a.kind, a.scope));
        }
        notes.push(line);
    }
    match res.outcome.as_str() {
        "needs_input" => {
            notes.push("❓ Muse is asking…".to_string());
        }
        "needs_approval" => {
            for a in &res.approvals {
                notes.push(format!("🔐 Approval: {}: {}", a.title, a.question));
            }
        }
        "failed" => {
            if stopped {
                notes.push("⏹ Stopped.".to_string());
            } else if res.status.is_empty() {
                notes.push("⚠️ Muse's turn ended.".to_string());
            } else {
                notes.push(format!("⚠️ Muse's turn ended: {}", res.status));
            }
        }
        "timeout" => {
            notes.push("⌛ Still running after 6h…".to_string());
        }
        _ => {}
    }
    for e in &res.auto_approve_errors {
        notes.push(format!(
            "⚠️ could not auto-approve {}: {}",
            e.approval_id, e.summary
        ));
    }
    notes
}

/// The final inline keyboard: question buttons for
/// `needs_input`, one row per approval for
/// `needs_approval`, else none.
/// Source: `internal/commands/telegram_turn.go:1441-1483`
/// (`finalMarkup`).
#[must_use]
pub fn final_markup(
    registry: &CallbackRegistry,
    res: &WaitResult,
    scope: &str,
    title: &str,
    after_seq: Option<i64>,
) -> Option<InlineKeyboardMarkup> {
    match res.outcome.as_str() {
        "needs_input" => {
            let last = res.replies.last()?;
            let options = question_options(last);
            if options.is_empty() {
                return None;
            }
            let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
            for (label, value) in options {
                let token = registry.register(crate::registry::CallbackEntry {
                    action: "answer".to_string(),
                    answer: value,
                    ..Default::default()
                });
                rows.push(vec![InlineKeyboardButton::new(
                    &button_text(&label),
                    &token,
                )]);
            }
            Some(InlineKeyboardMarkup {
                inline_keyboard: rows,
            })
        }
        "needs_approval" => {
            let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
            for a in &res.approvals {
                let m = approval_markup(registry, a, scope, title, after_seq);
                rows.extend(m.inline_keyboard);
            }
            if rows.is_empty() {
                None
            } else {
                Some(InlineKeyboardMarkup {
                    inline_keyboard: rows,
                })
            }
        }
        _ => None,
    }
}

/// Question options for the last reply, in Go's order:
/// (1) first widget with non-empty options, max 10;
/// (2) a numbered/bulleted list of 2–8 items from the
/// last 12 non-blank lines; (3) generic Yes/No/Go ahead.
/// Each option is `(label, value)`: the button shows the
/// label, the callback answers the value.
/// Source: `internal/commands/telegram_turn.go:1500+`
/// (`questionOptions`, `widgetOptions`, `listOptions`).
#[must_use]
pub fn question_options(reply: &Reply) -> Vec<(String, String)> {
    for w in &reply.widgets {
        let opts = widget_options(w);
        if !opts.is_empty() {
            return opts;
        }
    }
    if let Some(opts) = list_options(&reply.text) {
        return opts;
    }
    vec![
        ("👍 Yes".to_string(), "Yes".to_string()),
        ("👎 No".to_string(), "No".to_string()),
        ("▶️ Go ahead".to_string(), "Go ahead".to_string()),
    ]
}

/// Widget options: a dict's label is its first
/// non-empty label/text/title/value, its value its
/// first non-empty value/label/text/title; a plain
/// string is both; nil yields `"None"`.
/// Source: `internal/commands/telegram_turn.go:1532-1591`
/// (`widgetOptions`, `optionLabel`, `optionValue`).
fn widget_options(w: &crate::wait::Widget) -> Vec<(String, String)> {
    let Some(arr) = w.options.as_array() else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = Vec::new();
    // Go `widgetOptions` (`telegram_turn.go:1532-1548`):
    // empty labels are skipped BEFORE the 10-cap is
    // counted, so the loop breaks only once 10 options
    // have been collected.
    for item in arr.iter() {
        if out.len() >= 10 {
            break;
        }
        let label = option_label(item);
        if label.is_empty() {
            continue;
        }
        out.push((label, option_value(item)));
    }
    out
}

/// Go `pythonFloat` (`telegram_turn.go:1618-1637`):
/// `strconv.FormatFloat(f, 'g', -1, 64)` — the shortest
/// digits that round-trip — with `.0` appended when the
/// result has no `.`, `e`, or `E`. Rust's `{}` display
/// is the same shortest round-trip in the normal range;
/// outside it Go switches to scientific form with an
/// explicit `e+XX`/`e-XX` exponent, which `{}` never
/// produces, so that range is formatted by hand.
fn python_float(f: f64) -> String {
    if f.is_nan() {
        return "nan".to_string();
    }
    if f.is_infinite() {
        return if f > 0.0 {
            "inf".to_string()
        } else {
            "-inf".to_string()
        };
    }
    if f != 0.0 && (f.abs() >= 1e21 || f.abs() < 1e-4) {
        // Go 'g' with precision -1 uses %e for these
        // magnitudes: shortest digits, exponent with a
        // sign and at least two digits.
        let s = format!("{f:e}");
        let (mantissa, exp) = s.split_once('e').unwrap_or((&s, "0"));
        let mantissa = mantissa.trim_end_matches('0').trim_end_matches('.');
        let exp: i32 = exp.parse().unwrap_or(0);
        return format!("{mantissa}e{exp:+03}");
    }
    let s = format!("{f}");
    if s.contains('.') || s.contains('e') || s.contains('E') {
        s
    } else {
        format!("{s}.0")
    }
}

fn option_label(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Object(m) => first_widget_string(m, &["label", "text", "title", "value"]),
        Value::Null => "None".to_string(),
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(f) = n.as_f64() {
                python_float(f)
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

fn option_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Object(m) => first_widget_string(m, &["value", "label", "text", "title"]),
        Value::Null => "None".to_string(),
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(f) = n.as_f64() {
                python_float(f)
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

fn first_widget_string(m: &serde_json::Map<String, Value>, keys: &[&str]) -> String {
    for k in keys {
        if let Some(s) = m.get(*k).and_then(Value::as_str)
            && !s.is_empty()
        {
            return s.to_string();
        }
    }
    String::new()
}

/// A list of 2–8 items from the last 12 non-blank
/// lines. A non-item line after items started resets
/// the list — unless it ends with `?`.
/// Source: `internal/commands/telegram_turn.go:1663-1689`
/// (`listOptions`).
fn list_options(text: &str) -> Option<Vec<(String, String)>> {
    let mut tail: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if tail.len() > 12 {
        tail = tail[tail.len() - 12..].to_vec();
    }
    let mut found: Vec<String> = Vec::new();
    for ln in &tail {
        if let Some(item) = parse_list_item(ln) {
            found.push(item);
        } else if !found.is_empty() && !ln.trim().ends_with('?') {
            found.clear();
        }
    }
    if (2..=8).contains(&found.len()) {
        Some(found.into_iter().map(|f| (f.clone(), f)).collect())
    } else {
        None
    }
}

/// Extract a list item per Python `_OPT_RE`: optional
/// leading whitespace, then a marker — 1–2 digits or
/// one A–H letter, optionally `(`-prefixed, followed
/// by `.` or `)`; or a `-`, `•`, `*` bullet — then
/// REQUIRED whitespace, then 1–80 runes after
/// stripping `[*_``]` and re-trimming.
/// Source: `internal/commands/telegram_turn.go:1697-1748`
/// (`parseListItem`, `parseListItemRest`).
fn parse_list_item(line: &str) -> Option<String> {
    let runes: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < runes.len() && runes[i].is_whitespace() {
        i += 1;
    }
    if i >= runes.len() {
        return None;
    }
    let rest = &runes[i..];
    if matches!(rest[0], '-' | '•' | '*') {
        return parse_list_item_rest(&rest[1..]);
    }
    let mut j = 0;
    if rest[0] == '(' {
        j = 1;
    }
    let start = j;
    if j < rest.len() && rest[j].is_ascii_digit() {
        while j < rest.len() && j - start < 2 && rest[j].is_ascii_digit() {
            j += 1;
        }
    } else if j < rest.len()
        && ((('A'..='H').contains(&rest[j])) || (('a'..='h').contains(&rest[j])))
    {
        j += 1;
    } else {
        return None;
    }
    if j >= rest.len() || !matches!(rest[j], '.' | ')') {
        return None;
    }
    parse_list_item_rest(&rest[j + 1..])
}

fn parse_list_item_rest(after: &[char]) -> Option<String> {
    if after.is_empty() || !after[0].is_whitespace() {
        return None;
    }
    let mut k = 0;
    while k < after.len() && after[k].is_whitespace() {
        k += 1;
    }
    let item: String = after[k..]
        .iter()
        .filter(|c| !matches!(c, '*' | '_' | '`'))
        .collect();
    let item = item.trim().to_string();
    let n = item.chars().count();
    if (1..=80).contains(&n) {
        Some(item)
    } else {
        None
    }
}

/// Merge reply texts and media by seq: text before media
/// at the same seq, consecutive texts coalesced with
/// `"\n\n"`, notes on the last text segment.
/// Source: `internal/commands/telegram_turn.go:1081-1127`
/// (`buildTurnSegments`).
#[must_use]
pub fn build_turn_segments(
    res: &WaitResult,
    media: &[(i64, Resource)],
    notes: &[String],
) -> Vec<TurnSegment> {
    let mut items: Vec<(i64, u8, TurnSegment)> = Vec::new();
    for r in &res.replies {
        if !r.text.trim().is_empty() {
            items.push((r.seq, 0, TurnSegment::Text(r.text.clone())));
        }
    }
    for (seq, resource) in media {
        items.push((
            *seq,
            1,
            TurnSegment::Media {
                seq: *seq,
                resource: resource.clone(),
            },
        ));
    }
    items.sort_by_key(|(seq, order, _)| (*seq, *order));
    let mut segments: Vec<TurnSegment> = Vec::new();
    for (_, _, seg) in items {
        match seg {
            TurnSegment::Text(t) => {
                if let Some(TurnSegment::Text(prev)) = segments.last_mut() {
                    prev.push_str("\n\n");
                    prev.push_str(&t);
                } else {
                    segments.push(TurnSegment::Text(t));
                }
            }
            TurnSegment::Media { .. } => segments.push(seg),
        }
    }
    if !notes.is_empty()
        && let Some(TurnSegment::Text(last)) = segments.last_mut()
    {
        last.push_str("\n\n");
        last.push_str(&notes.join("\n\n"));
    }
    segments
}

/// One inbound Telegram attachment: download it, write it
/// to System Files under `telegram-inbox/`, and return the
/// turn text that tells Muse about it.
/// Source: `internal/commands/telegram_commands.go:758-803`
/// (`inboundMedia`) and `internal/telegram/inbound.go`.
pub async fn inbound_media_text(
    api: &crate::api::BotApi,
    port: &dyn GatewayPort,
    media: &InboxMedia,
    caption: &str,
) -> Result<String, BotError> {
    let data = download_media(api, media).await.map_err(|e| {
        // The too-large branch keys on the exact
        // validation literal from `files.rs`
        // (`"file exceeds the 20 MiB download limit"`);
        // that module owns the literal.
        if let BotError::Validation(msg) = &e
            && msg == "file exceeds the 20 MiB download limit"
        {
            return BotError::Validation(
                "⚠️ That file is too big for Telegram to fetch (20 MB limit).".to_string(),
            );
        }
        e
    })?;
    let at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let name = inbox_name(&media.name, at_unix);
    let rel = format!("telegram-inbox/{name}");
    port.write_file(&rel, &data).await.map_err(|e| {
        if is_auth_error(&e) {
            BotError::Validation("🔑 muse.ai login expired. Use /login.".to_string())
        } else {
            BotError::Validation(format!("⚠️ Upload to System Files failed: {}", e.summary()))
        }
    })?;
    let mime_suffix = match &media.mime_type {
        Some(m) if !m.is_empty() => format!(", {m}"),
        _ => String::new(),
    };
    let note = format!(
        "[Telegram attachment saved in your System Files at {rel} ({} bytes{mime_suffix})]",
        data.len()
    );
    if caption.trim().is_empty() {
        Ok(format!("I sent you a file from Telegram. {note}"))
    } else {
        Ok(format!("{caption}\n\n{note}"))
    }
}

/// The `/files` rows for a turn's history window, in
/// HISTORY order (oldest first, last 40) — the handler
/// reverses/dedupes/caps at 12.
pub fn files_list_rows(events: &[Value]) -> Vec<crate::router::SharedFileRow> {
    let shared: Vec<SharedJson> = events.iter().map(from_serde).collect();
    file_rows(&shared)
        .into_iter()
        .map(|r| crate::router::SharedFileRow {
            path: r.path,
            size: r.byte_len,
            mime: r.mime,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wait::Widget;
    use serde_json::json;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn turn_error_text_literals() {
        let auth = BotError::Transport(TransportError::Auth {
            message: "x".to_string(),
        });
        assert_eq!(
            turn_error_text(&auth, false),
            "🔑 muse.ai login expired. Re-export cookies with `castctl auth export` and restart the bot."
        );
        assert_eq!(turn_error_text(&BotError::Cancelled, false), "⏹ Stopped.");
        assert_eq!(
            turn_error_text(&BotError::Validation("v".to_string()), true),
            "⏹ Stopped."
        );
        assert_eq!(
            turn_error_text(&BotError::Validation("v".to_string()), false),
            "⚠️ Could not reach Muse (gateway error). Try again."
        );
    }

    #[test]
    fn media_path_literals() {
        assert_eq!(
            media_path("sandbox://a/b.png", None).unwrap(),
            "/media/raw/a/b.png"
        );
        assert_eq!(
            media_path(
                "",
                Some(&from_serde(&json!({"original": "sandbox://x/y.mp4"})))
            )
            .unwrap(),
            "/media/raw/x/y.mp4"
        );
        assert_eq!(
            media_path("media/raw/a%20b.png", None).unwrap(),
            "/media/raw/a%20b.png"
        );
        assert!(media_path("sandbox://a/../b.png", None).is_err());
        assert!(media_path("", None).is_err());
        // Go `MediaPath` (`internal/gateway/media.go:47-91`):
        // a leading "/" is trimmed before the
        // `media/raw/` strip; `sandbox://` + `media/raw/`
        // strips once; http(s) URLs contribute only their
        // escaped path (query/fragment dropped).
        assert_eq!(media_path("/a/b.png", None).unwrap(), "/media/raw/a/b.png");
        assert_eq!(
            media_path("/media/raw/a.png", None).unwrap(),
            "/media/raw/a.png"
        );
        assert_eq!(
            media_path("sandbox://media/raw/a.png", None).unwrap(),
            "/media/raw/a.png"
        );
        assert_eq!(
            media_path("https://host/media/raw/a%20b.png", None).unwrap(),
            "/media/raw/a%20b.png"
        );
        assert_eq!(
            media_path("http://host/x/y.png?z=1#frag", None).unwrap(),
            "/media/raw/x/y.png"
        );
        // `variants.original` wins over a non-empty path
        // (Go `mediaRefString`, `media.go:80-91`, via
        // `downloadRef`, `telegram_turn.go:1302-1310`).
        assert_eq!(
            media_path(
                "sandbox://a/b.png",
                Some(&from_serde(&json!({"original": "sandbox://x/y.mp4"})))
            )
            .unwrap(),
            "/media/raw/x/y.mp4"
        );
        // A `..` segment reached only after unquoting is
        // still rejected; an invalid escape in an http URL
        // fails the parse (`url.Parse`, probe-verified).
        assert!(media_path("sandbox://a/%2e%2e/b.png", None).is_err());
        assert!(media_path("https://host/a%zz.png", None).is_err());
        // A raw space in an http URL parses fine
        // (probe-verified): `EscapedPath` already quotes
        // it, so the media path keeps `%20`.
        assert_eq!(
            media_path("https://host/a b.png", None).unwrap(),
            "/media/raw/a%20b.png"
        );
        // `PathUnescape` fails on ANY bad escape
        // (probe-verified), so Go keeps the whole
        // original string and re-quotes it — `%20` stays
        // escaped as `%2520`.
        assert_eq!(
            media_path("sandbox://a%20b%zz.png", None).unwrap(),
            "/media/raw/a%2520b%25zz.png"
        );
    }

    #[test]
    fn download_ref_prefers_variants_original() {
        let res = castctl_shared::Resource {
            path: "sandbox://a/b.png".to_string(),
            kind: "image".to_string(),
            mime: None,
            byte_len: None,
            label: None,
            variants: Some(from_serde(&json!({"original": "sandbox://x/y.mp4"}))),
        };
        assert_eq!(download_ref(&res), "sandbox://x/y.mp4");
        let bare = castctl_shared::Resource {
            variants: None,
            ..res.clone()
        };
        assert_eq!(download_ref(&bare), "sandbox://a/b.png");
    }

    #[test]
    fn doc_name_literals() {
        assert_eq!(doc_name("muse-reply", "plain text"), "muse-reply.txt");
        assert_eq!(
            doc_name("muse-reply", "a\n```rust\nx\n```"),
            "muse-reply.md"
        );
        assert_eq!(doc_name("muse-reply", "# Title\nbody"), "muse-reply.md");
        assert_eq!(doc_name("muse-reply", "has **bold**"), "muse-reply.md");
        assert_eq!(doc_name("a/b c!", "x"), "a-b-c.txt");
    }

    #[test]
    fn document_preview_truncates_at_1500_runes() {
        let text = "x".repeat(1501);
        let p = document_preview(&text);
        assert!(p.ends_with("… (full reply attached)"));
        assert_eq!(
            p.chars().count(),
            1500 + "\n\n… (full reply attached)".chars().count()
        );
    }

    #[test]
    fn base64_encode_literals() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn media_failure_class_literals() {
        let api = |code: i32| BotError::Api {
            code,
            description: "x".to_string(),
            retry_after: None,
        };
        assert_eq!(media_failure_class(&api(429)), "too many requests");
        assert_eq!(media_failure_class(&api(400)), "bad request");
        assert_eq!(media_failure_class(&api(403)), "forbidden");
        assert_eq!(media_failure_class(&api(401)), "unauthorized");
        assert_eq!(media_failure_class(&api(404)), "not found");
        assert_eq!(media_failure_class(&api(409)), "conflict");
        assert_eq!(
            media_failure_class(&BotError::Transport(TransportError::Auth {
                message: "x".to_string()
            })),
            "auth failed"
        );
        assert_eq!(media_failure_class(&BotError::Cancelled), "error");
    }

    #[test]
    fn too_big_and_failure_notices() {
        assert_eq!(
            too_big_notice("a.png", 49 * 1024 * 1024 + 1),
            "📎 <b>a.png</b> is 49 MB, too big for Telegram. Get it with castctl download."
        );
        // Go escapes the filename (`telegram.EscapeText`,
        // `telegram_turn.go:1324-1330,1377-1380`): a name
        // carrying markup must not break the HTML notice.
        assert_eq!(
            too_big_notice("a<b>&.png", 49 * 1024 * 1024 + 1),
            "📎 <b>a&lt;b&gt;&amp;.png</b> is 49 MB, too big for Telegram. Get it with castctl download."
        );
        let e = BotError::Api {
            code: 429,
            description: "x".to_string(),
            retry_after: None,
        };
        assert_eq!(
            media_failure_notice("a.png", "fetched", &e),
            "📎 <b>a.png</b> could not be fetched (too many requests)."
        );
        assert_eq!(
            media_failure_notice("a<b>&.png", "fetched", &e),
            "📎 <b>a&lt;b&gt;&amp;.png</b> could not be fetched (too many requests)."
        );
    }

    #[test]
    fn outcome_notes_order() {
        let res = WaitResult {
            outcome: "needs_approval".to_string(),
            auto_approved: vec![ApprovedRecord {
                approval_id: "a1".to_string(),
                title: "Run shell".to_string(),
                kind: "shell".to_string(),
                scope: "all".to_string(),
                decision: "allow_always".to_string(),
            }],
            approvals: vec![Approval {
                title: "Write file".to_string(),
                question: "Allow write?".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let notes = outcome_notes(&res, false);
        assert_eq!(notes[0], "✅ auto-approved (always): Run shell [shell all]");
        assert_eq!(notes[1], "🔐 Approval: Write file: Allow write?");
    }

    #[test]
    fn question_options_generic_fallback() {
        let reply = Reply {
            seq: 1,
            message_id: "m".to_string(),
            text: "hello".to_string(),
            widgets: Vec::new(),
            media: false,
            agent_id: String::new(),
            root_agent_id: String::new(),
        };
        assert_eq!(
            question_options(&reply),
            vec![
                ("👍 Yes".to_string(), "Yes".to_string()),
                ("👎 No".to_string(), "No".to_string()),
                ("▶️ Go ahead".to_string(), "Go ahead".to_string()),
            ]
        );
        let listed = Reply {
            text: "Pick one:\n1. Alpha\n2. Beta\n3. Gamma".to_string(),
            ..reply.clone()
        };
        assert_eq!(
            question_options(&listed),
            vec![
                ("Alpha".to_string(), "Alpha".to_string()),
                ("Beta".to_string(), "Beta".to_string()),
                ("Gamma".to_string(), "Gamma".to_string()),
            ]
        );
        let widgeted = Reply {
            widgets: vec![Widget {
                id: json!(1),
                kind: "choice".to_string(),
                text: None,
                options: json!(["Red", "Blue"]),
            }],
            ..reply.clone()
        };
        assert_eq!(
            question_options(&widgeted),
            vec![
                ("Red".to_string(), "Red".to_string()),
                ("Blue".to_string(), "Blue".to_string()),
            ]
        );
        // A non-item line after items started resets the
        // list — unless it ends with "?".
        let broken = Reply {
            text: "1. Alpha\nsome prose\n2. Beta".to_string(),
            ..reply.clone()
        };
        assert_eq!(
            question_options(&broken),
            vec![
                ("👍 Yes".to_string(), "Yes".to_string()),
                ("👎 No".to_string(), "No".to_string()),
                ("▶️ Go ahead".to_string(), "Go ahead".to_string()),
            ]
        );
        // "(A)" letter markers and "•" bullets parse.
        let letters = Reply {
            text: "(A) First\n(B) Second".to_string(),
            ..reply.clone()
        };
        assert_eq!(
            question_options(&letters),
            vec![
                ("First".to_string(), "First".to_string()),
                ("Second".to_string(), "Second".to_string()),
            ]
        );
    }

    #[test]
    fn widget_options_filters_empty_before_cap() {
        // Go `widgetOptions` (`telegram_turn.go:1532-1548`):
        // empty labels are skipped BEFORE the 10-cap is
        // counted, so 1 empty + 10 valid options yield 10.
        let mut opts = vec![json!({"label": ""})];
        for i in 1..=10 {
            opts.push(json!({"label": format!("o{i}")}));
        }
        let reply = Reply {
            seq: 1,
            message_id: "m".to_string(),
            text: "hello".to_string(),
            widgets: vec![Widget {
                id: json!(1),
                kind: "choice".to_string(),
                text: None,
                options: Value::Array(opts),
            }],
            media: false,
            agent_id: String::new(),
            root_agent_id: String::new(),
        };
        let got = question_options(&reply);
        assert_eq!(got.len(), 10, "empty labels must not consume cap slots");
        assert_eq!(got[0], ("o1".to_string(), "o1".to_string()));
        assert_eq!(got[9], ("o10".to_string(), "o10".to_string()));
    }

    #[test]
    fn widget_options_floats_use_python_repr() {
        // Go `pythonFloat` (`telegram_turn.go:1618-1637`):
        // shortest round-trip digits, `.0` kept for
        // integral values — never `{:.1}`.
        let reply = Reply {
            seq: 1,
            message_id: "m".to_string(),
            text: "hello".to_string(),
            widgets: vec![Widget {
                id: json!(1),
                kind: "choice".to_string(),
                text: None,
                options: json!([123.456, 42.0]),
            }],
            media: false,
            agent_id: String::new(),
            root_agent_id: String::new(),
        };
        assert_eq!(
            question_options(&reply),
            vec![
                ("123.456".to_string(), "123.456".to_string()),
                ("42.0".to_string(), "42.0".to_string()),
            ]
        );
        assert_eq!(python_float(123.456), "123.456");
        assert_eq!(python_float(42.0), "42.0");
        assert_eq!(python_float(1.0), "1.0");
        assert_eq!(python_float(0.5), "0.5");
    }

    #[test]
    fn build_turn_segments_merges_by_seq() {
        let res = WaitResult {
            replies: vec![
                Reply {
                    seq: 11,
                    message_id: "m1".to_string(),
                    text: "first".to_string(),
                    widgets: Vec::new(),
                    media: false,
                    agent_id: String::new(),
                    root_agent_id: String::new(),
                },
                Reply {
                    seq: 12,
                    message_id: "m2".to_string(),
                    text: "second".to_string(),
                    widgets: Vec::new(),
                    media: false,
                    agent_id: String::new(),
                    root_agent_id: String::new(),
                },
            ],
            ..Default::default()
        };
        let media = vec![(
            11,
            Resource {
                path: "sandbox://a.png".to_string(),
                kind: "image".to_string(),
                mime: Some("image/png".to_string()),
                byte_len: Some(10),
                label: None,
                variants: None,
            },
        )];
        let segs = build_turn_segments(&res, &media, &["note".to_string()]);
        assert_eq!(segs.len(), 3);
        assert!(matches!(&segs[0], TurnSegment::Text(t) if t == "first"));
        assert!(matches!(&segs[1], TurnSegment::Media { .. }));
        assert!(matches!(&segs[2], TurnSegment::Text(t) if t == "second\n\nnote"));
    }

    /// A sink that records every call, for editor tests.
    pub struct RecordingSink {
        pub calls: StdMutex<Vec<String>>,
        pub fail_edit: AtomicBool,
        pub fail_send: AtomicBool,
        /// Fail `send` from this (0-based) send call
        /// onward; default `usize::MAX` never fails. Lets
        /// a test keep the opening bubble send working
        /// while the delivery sends fail.
        pub fail_send_after: AtomicUsize,
        send_count: AtomicUsize,
    }

    impl RecordingSink {
        pub fn new() -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
                fail_edit: AtomicBool::new(false),
                fail_send: AtomicBool::new(false),
                fail_send_after: AtomicUsize::new(usize::MAX),
                send_count: AtomicUsize::new(0),
            }
        }

        pub fn edit_count(&self) -> usize {
            self.calls
                .lock()
                .map(|c| c.iter().filter(|s| s.starts_with("edit:")).count())
                .unwrap_or(0)
        }
    }

    impl BotSink for RecordingSink {
        fn send(
            &self,
            _chat_id: i64,
            text: &str,
            _opts: SendOptions,
        ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>> {
            let text = text.to_string();
            let calls = &self.calls;
            let fail = self.fail_send.load(Ordering::SeqCst)
                || self.send_count.fetch_add(1, Ordering::SeqCst)
                    >= self.fail_send_after.load(Ordering::SeqCst);
            Box::pin(async move {
                calls
                    .lock()
                    .map(|mut c| c.push(format!("send:{text}")))
                    .ok();
                if fail {
                    Err(BotError::Validation("boom".to_string()))
                } else {
                    Ok(99)
                }
            })
        }

        fn edit(
            &self,
            _chat_id: i64,
            _message_id: i64,
            text: &str,
            _mode: HtmlMode,
            _markup: Option<InlineKeyboardMarkup>,
        ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
            let text = text.to_string();
            let calls = &self.calls;
            let fail = self.fail_edit.load(Ordering::SeqCst);
            Box::pin(async move {
                calls
                    .lock()
                    .map(|mut c| c.push(format!("edit:{text}")))
                    .ok();
                if fail {
                    Err(BotError::Validation("boom".to_string()))
                } else {
                    Ok(())
                }
            })
        }

        fn edit_plain(
            &self,
            _chat_id: i64,
            _message_id: i64,
            text: &str,
            _markup: Option<InlineKeyboardMarkup>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let text = text.to_string();
            let calls = &self.calls;
            Box::pin(async move {
                calls
                    .lock()
                    .map(|mut c| c.push(format!("edit:{text}")))
                    .ok();
            })
        }

        fn delete(
            &self,
            _chat_id: i64,
            _message_id: i64,
        ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
            Box::pin(async move { Ok(()) })
        }

        fn send_file(
            &self,
            _chat_id: i64,
            name: &str,
            data: &[u8],
            _mime: &str,
            _caption: &str,
            _opts: &SendOptions,
        ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>> {
            let name = name.to_string();
            let len = data.len();
            let calls = &self.calls;
            Box::pin(async move {
                calls
                    .lock()
                    .map(|mut c| c.push(format!("send_file:{name}:{len}")))
                    .ok();
                Ok(100)
            })
        }
    }

    impl RecordingSink {
        /// Number of `send_file` calls recorded.
        pub fn send_file_count(&self) -> usize {
            self.calls
                .lock()
                .map(|c| c.iter().filter(|s| s.starts_with("send_file:")).count())
                .unwrap_or(0)
        }

        /// Names sent via `send_file`, in call order.
        pub fn send_file_names(&self) -> Vec<String> {
            self.calls
                .lock()
                .map(|c| {
                    c.iter()
                        .filter_map(|s| {
                            s.strip_prefix("send_file:")
                                .and_then(|r| r.rsplit_once(':'))
                                .map(|(name, _)| name.to_string())
                        })
                        .collect()
                })
                .unwrap_or_default()
        }
    }

    #[tokio::test]
    async fn editor_throttles_to_one_edit_per_second() {
        let sink = Arc::new(RecordingSink::new());
        let preview = Arc::new(StreamPreview::new(Instant::now()));
        let mut editor = BubbleEditor::start(sink.clone(), 1, 7, Arc::clone(&preview));
        // Three rapid feeds: the loop must edit at most
        // twice (first edit + one after the 1s tick).
        for i in 0..3 {
            preview.feed(
                &json!({"event": "delta.text_append", "payload": {"text": format!("chunk{i} ")}}),
            );
            editor.signal();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(1200)).await;
        editor.finish().await;
        let n = sink.edit_count();
        // Exactly 2: the first signal edits at once, the
        // next signals are throttled (dirty stays set),
        // the 1s tick lands the second edit, and finish
        // finds nothing new to show.
        assert_eq!(n, 2, "streaming throttle is 1 edit/s, got {n} edits");
        // Finish is idempotent: a second call edits nothing.
        let before = sink.edit_count();
        editor.finish().await;
        assert_eq!(sink.edit_count(), before);
    }

    /// A scripted port for media tests: history is a
    /// fixed script (every limit returns the same events),
    /// downloads come from a path-keyed map.
    struct TestPort {
        history_script: Vec<Value>,
        files: std::collections::HashMap<String, Vec<u8>>,
    }

    impl GatewayPort for TestPort {
        fn history(
            &self,
            _limit: i64,
            _thread: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Value>, BotError>> + Send + '_>> {
            let script = self.history_script.clone();
            Box::pin(async move { Ok(script) })
        }

        fn open_stream(
            &self,
            _body: Value,
        ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>> {
            Box::pin(async move { Ok(1) })
        }

        fn call_json(
            &self,
            _method: &str,
            _opts: RequestOptions,
        ) -> Pin<Box<dyn Future<Output = Result<Value, BotError>> + Send + '_>> {
            Box::pin(async move { Ok(json!({})) })
        }

        fn download_file(
            &self,
            path: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, BotError>> + Send + '_>> {
            let data = self.files.get(path).cloned().unwrap_or_default();
            Box::pin(async move { Ok(data) })
        }

        fn write_file(
            &self,
            _path: &str,
            _data: &[u8],
        ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
            Box::pin(async move { Ok(()) })
        }

        fn has_route(
            &self,
            _method: &str,
        ) -> Pin<Box<dyn Future<Output = Result<bool, BotError>> + Send + '_>> {
            Box::pin(async move { Ok(true) })
        }
    }

    /// A port whose history answers come from a queue;
    /// when the queue is exhausted the last answer
    /// repeats. Lets tests script transient failures and
    /// evolving histories (ack poll, follow poll).
    struct QueuePort {
        queue: StdMutex<std::collections::VecDeque<Result<Vec<Value>, BotError>>>,
        last: StdMutex<Result<Vec<Value>, BotError>>,
        files: std::collections::HashMap<String, Vec<u8>>,
    }

    impl QueuePort {
        fn new(steps: Vec<Result<Vec<Value>, BotError>>) -> Self {
            Self {
                queue: StdMutex::new(steps.into()),
                last: StdMutex::new(Ok(Vec::new())),
                files: std::collections::HashMap::new(),
            }
        }

        fn with_files(mut self, files: std::collections::HashMap<String, Vec<u8>>) -> Self {
            self.files = files;
            self
        }

        fn gateway_error() -> BotError {
            BotError::Transport(TransportError::Gateway(castctl_transport::BodySummary {
                status: 502,
                body_length: None,
                content_type: None,
                error_code: None,
            }))
        }

        fn timeout_error() -> BotError {
            BotError::Transport(TransportError::Timeout {
                message: "deadline".to_string(),
            })
        }
    }

    impl GatewayPort for QueuePort {
        fn history(
            &self,
            _limit: i64,
            _thread: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Value>, BotError>> + Send + '_>> {
            let step = {
                let mut q = self.queue.lock().expect("queue lock");
                match q.pop_front() {
                    Some(step) => {
                        if let Ok(mut l) = self.last.lock() {
                            *l = step.clone();
                        }
                        step
                    }
                    None => self
                        .last
                        .lock()
                        .map(|l| l.clone())
                        .unwrap_or_else(|e| e.into_inner().clone()),
                }
            };
            Box::pin(async move { step })
        }

        fn open_stream(
            &self,
            _body: Value,
        ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>> {
            Box::pin(async move { Ok(1) })
        }

        fn call_json(
            &self,
            _method: &str,
            _opts: RequestOptions,
        ) -> Pin<Box<dyn Future<Output = Result<Value, BotError>> + Send + '_>> {
            Box::pin(async move { Ok(json!({})) })
        }

        fn download_file(
            &self,
            path: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, BotError>> + Send + '_>> {
            let data = self.files.get(path).cloned().unwrap_or_default();
            Box::pin(async move { Ok(data) })
        }

        fn write_file(
            &self,
            _path: &str,
            _data: &[u8],
        ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
            Box::pin(async move { Ok(()) })
        }

        fn has_route(
            &self,
            _method: &str,
        ) -> Pin<Box<dyn Future<Output = Result<bool, BotError>> + Send + '_>> {
            Box::pin(async move { Ok(true) })
        }
    }

    /// A port whose history panics: the turn task must
    /// still release its slot (Go's `recoverTurnPanic` +
    /// defers, `telegram_turn.go:187-197,281-284`).
    struct PanicPort;

    impl GatewayPort for PanicPort {
        fn history(
            &self,
            _limit: i64,
            _thread: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Value>, BotError>> + Send + '_>> {
            Box::pin(async move { panic!("test port panics on history") })
        }

        fn open_stream(
            &self,
            _body: Value,
        ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>> {
            Box::pin(async move { Ok(1) })
        }

        fn call_json(
            &self,
            _method: &str,
            _opts: RequestOptions,
        ) -> Pin<Box<dyn Future<Output = Result<Value, BotError>> + Send + '_>> {
            Box::pin(async move { Ok(json!({})) })
        }

        fn download_file(
            &self,
            _path: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, BotError>> + Send + '_>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn write_file(
            &self,
            _path: &str,
            _data: &[u8],
        ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
            Box::pin(async move { Ok(()) })
        }

        fn has_route(
            &self,
            _method: &str,
        ) -> Pin<Box<dyn Future<Output = Result<bool, BotError>> + Send + '_>> {
            Box::pin(async move { Ok(true) })
        }
    }

    /// Build a runner over any scripted port + recording
    /// sink, for turn tests. The BotApi is never called
    /// on this path (only the port and the sink are);
    /// the state file is a temp file, removed by the
    /// caller.
    fn runner_with(
        tag: &str,
        port: Arc<dyn GatewayPort>,
        sink: Arc<RecordingSink>,
    ) -> (Arc<TurnRunner>, Arc<crate::state::TelegramStateStore>) {
        let api = Arc::new(crate::api::BotApi::new(
            Arc::new(castctl_transport::DirectDialer::new()) as Arc<dyn castctl_transport::Dialer>,
            crate::api::BotApiConfig::plaintext(
                "123456:FAKE-TOKEN-TEST-ONLY-AAAA".to_string(),
                castctl_transport::DialTarget::new("127.0.0.1", 1),
            ),
        ));
        let path =
            std::env::temp_dir().join(format!("m5b-media-test-{}-{tag}.json", std::process::id()));
        let state = Arc::new(crate::state::TelegramStateStore::load(path).expect("state load"));
        let registry = Arc::new(crate::registry::CallbackRegistry::new());
        let decider: Arc<dyn crate::claims::Decider> =
            Arc::new(crate::services::GatewayDecider::new(port.clone()));
        let claims = Arc::new(crate::claims::ClaimManager::new(
            decider,
            Duration::from_secs(15),
        ));
        let runner = Arc::new(TurnRunner::new(
            port,
            sink,
            api,
            Arc::clone(&state),
            registry,
            claims,
            "no1".to_string(),
            "node-test".to_string(),
            false,
            false,
        ));
        (runner, state)
    }

    /// Build a runner over a scripted port + recording
    /// sink, for media/claim tests. The BotApi is never
    /// called on this path (only the port and the sink
    /// are); the state file is a temp file, removed by
    /// the caller.
    fn media_runner(
        tag: &str,
        port: Arc<TestPort>,
        sink: Arc<RecordingSink>,
    ) -> (Arc<TurnRunner>, Arc<crate::state::TelegramStateStore>) {
        runner_with(tag, port, sink)
    }

    /// One user message event, for ack scripts.
    fn user_event(seq: i64, text: &str) -> Value {
        json!({
            "seq": seq,
            "event_name": "message.user",
            "payload": {"display_text": text, "content": text}
        })
    }

    /// One `task.status` event, for follow scripts.
    fn task_event(seq: i64, status: &str) -> Value {
        json!({
            "seq": seq,
            "event_name": "task.status",
            "payload": {"status": status, "root_agent_id": "root1", "agent_id": "root1"}
        })
    }

    /// One completed assistant event carrying plain
    /// reply text, for follow scripts.
    fn assistant_text_event(seq: i64, text: &str) -> Value {
        json!({
            "seq": seq,
            "event_name": "message.assistant",
            "payload": {"status": "completed", "display_text": text, "message_id": format!("m{seq}"), "data": {}}
        })
    }

    /// One completed assistant event carrying one media
    /// file, for `collect_turn_media` scripts.
    fn media_event(seq: i64, mid: &str, path: &str, byte_len: i64) -> Value {
        json!({
            "seq": seq,
            "event_name": "message.assistant",
            "payload": {
                "status": "completed",
                "display_text": "reply",
                "message_id": mid,
                "data": {"images": [{"path": path, "mime": "image/png", "byte_len": byte_len, "label": mid}]}
            }
        })
    }

    #[tokio::test]
    async fn deliver_media_item_too_big_keeps_claim_sends_notice() {
        let sink = Arc::new(RecordingSink::new());
        let port = Arc::new(TestPort {
            history_script: Vec::new(),
            files: std::collections::HashMap::new(),
        });
        let (runner, state) = media_runner("too-big", Arc::clone(&port), Arc::clone(&sink));
        let res = castctl_shared::Resource {
            path: "sandbox://big.png".to_string(),
            kind: "image".to_string(),
            mime: Some("image/png".to_string()),
            byte_len: Some(UPLOAD_LIMIT + 1),
            label: None,
            variants: None,
        };
        runner.deliver_media_item(111, "", &res).await.unwrap();
        // Pre-check gate: 49 MiB + 1 byte, no download, no
        // send — only the exact too-big notice, and the
        // claim is KEPT (a retry must not re-send).
        assert_eq!(sink.send_file_count(), 0);
        let calls = sink.calls.lock().unwrap().clone();
        assert!(
            calls.iter().any(|c| c
                == "send:📎 <b>big.png</b> is 49 MB, too big for Telegram. Get it with castctl download."),
            "too-big notice missing; calls: {calls:?}"
        );
        let key = crate::state::sent_media_key("no1", 111, "", "/media/raw/big.png");
        assert!(
            state.sent_media_claimed(&key),
            "claim must be kept on too-big"
        );
        // Second delivery of the same file is a silent
        // skip (already claimed), not a second notice.
        let before = sink.calls.lock().unwrap().len();
        runner.deliver_media_item(111, "", &res).await.unwrap();
        assert_eq!(sink.calls.lock().unwrap().len(), before);
    }

    #[tokio::test]
    async fn deliver_media_item_at_limit_sends() {
        let sink = Arc::new(RecordingSink::new());
        let mut files = std::collections::HashMap::new();
        files.insert("/media/raw/at-limit.png".to_string(), b"PNG!".to_vec());
        let port = Arc::new(TestPort {
            history_script: Vec::new(),
            files,
        });
        let (runner, _state) = media_runner("at-limit", Arc::clone(&port), Arc::clone(&sink));
        let res = castctl_shared::Resource {
            path: "sandbox://at-limit.png".to_string(),
            kind: "image".to_string(),
            mime: Some("image/png".to_string()),
            byte_len: Some(UPLOAD_LIMIT),
            label: None,
            variants: None,
        };
        runner.deliver_media_item(111, "", &res).await.unwrap();
        assert_eq!(sink.send_file_count(), 1);
        assert_eq!(sink.send_file_names(), vec!["at-limit.png".to_string()]);
    }

    #[tokio::test]
    async fn deliver_media_turn_caps_at_six_with_note() {
        let sink = Arc::new(RecordingSink::new());
        let mut files = std::collections::HashMap::new();
        let mut script = Vec::new();
        for i in 1..=7 {
            let path = format!("sandbox://f{i}.png");
            files.insert(format!("/media/raw/f{i}.png"), b"PNG!".to_vec());
            script.push(media_event((i * 10) as i64, &format!("m{i}"), &path, 4));
        }
        let port = Arc::new(TestPort {
            history_script: script,
            files,
        });
        let (runner, _state) = media_runner("cap-six", Arc::clone(&port), Arc::clone(&sink));
        // Go's cap is `deliveredTopSeq(userSeq, res)`
        // (`telegram_turn.go:1133`): with no reply the cap
        // is `userSeq` itself and no media passes, so the
        // covering reply (empty text: no text segment) is
        // part of the fixture.
        let res = WaitResult {
            replies: vec![Reply {
                seq: 100,
                message_id: "m100".to_string(),
                text: String::new(),
                widgets: Vec::new(),
                media: false,
                agent_id: String::new(),
                root_agent_id: String::new(),
            }],
            ..Default::default()
        };
        let delivered = runner
            .deliver_media_turn(111, 7, "", 0, &res, &[], &None)
            .await
            .unwrap();
        assert!(delivered);
        // Go truncates to 6 (`telegram_turn.go:1155`);
        // the 7th file is only the excess note.
        assert_eq!(sink.send_file_count(), 6);
        assert_eq!(
            sink.send_file_names(),
            vec!["f1.png", "f2.png", "f3.png", "f4.png", "f5.png", "f6.png"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
        let calls = sink.calls.lock().unwrap().clone();
        assert!(
            calls
                .iter()
                .any(|c| c == "send:📎 1 more file(s): see /files"),
            "cap-6 excess note missing; calls: {calls:?}"
        );
    }

    #[tokio::test]
    async fn second_turn_same_chat_gets_busy_reply() {
        let sink = Arc::new(RecordingSink::new());
        let port = Arc::new(TestPort {
            history_script: vec![media_event(10, "m1", "sandbox://f1.png", 4)],
            files: std::collections::HashMap::new(),
        });
        let (runner, _state) = media_runner("busy", Arc::clone(&port), Arc::clone(&sink));
        runner.start_turn(111, "one".to_string()).await;
        runner.start_turn(111, "two".to_string()).await;
        // The second start is refused synchronously with
        // the exact Go busy reply; no queue exists.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let calls = sink.calls.lock().unwrap().clone();
        assert!(
            calls.iter().any(|c| c == &format!("send:{BUSY_REPLY}")),
            "busy reply missing; calls: {calls:?}"
        );
        // The first turn is still in its ack poll (the
        // script has no user event); stop it instead of
        // waiting out the 30s ack timeout.
        let _ = runner.stop_turn(111).await;
        runner.wait_turns().await;
    }

    #[tokio::test]
    async fn finish_before_loop_starts_returns_promptly() {
        let sink = Arc::new(RecordingSink::new());
        let preview = Arc::new(StreamPreview::new(Instant::now()));
        let mut editor = BubbleEditor::start(sink.clone(), 1, 7, preview);
        // No yield before finish: the loop task has not
        // run yet, so a notify-only stop would be lost
        // and finish would hang forever (regression:
        // `edit_final_falls_back_to_send_on_error` hung
        // >60s on 2026-11-06).
        tokio::time::timeout(Duration::from_secs(5), editor.finish())
            .await
            .expect("finish must not hang when the loop never ran");
    }

    #[tokio::test]
    async fn edit_final_falls_back_to_send_on_error() {
        let sink = Arc::new(RecordingSink::new());
        sink.fail_edit.store(true, Ordering::SeqCst);
        let preview = Arc::new(StreamPreview::new(Instant::now()));
        let mut editor = BubbleEditor::start(sink.clone(), 1, 7, preview);
        editor.edit_final("final text", None).await;
        let calls = sink.calls.lock().unwrap().clone();
        assert!(
            calls.iter().any(|c| c == "send:final text"),
            "edit failure must fall back to send, calls={calls:?}"
        );
    }

    /// Poll `has_active_turn` until the slot frees, or
    /// `timeout` elapses.
    async fn wait_until_slot_free(
        runner: &Arc<TurnRunner>,
        chat_id: i64,
        timeout: Duration,
    ) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if !runner.has_active_turn(chat_id) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    fn busy_reply_count(sink: &Arc<RecordingSink>) -> usize {
        sink.calls
            .lock()
            .map(|c| {
                c.iter()
                    .filter(|s| *s == &format!("send:{BUSY_REPLY}"))
                    .count()
            })
            .unwrap_or(0)
    }

    fn gateway_error() -> BotError {
        QueuePort::gateway_error()
    }

    #[tokio::test]
    async fn deliver_send_swallows_transient_history_errors() {
        // Go `deliverSend` (`internal/commands/wait.go:920-929`):
        // a Gateway/Timeout error in the ack poll is
        // swallowed and the poll continues to the 30s
        // deadline; only a non-swallowable error fails.
        let sink = Arc::new(RecordingSink::new());
        let port = Arc::new(QueuePort::new(vec![
            Ok(vec![user_event(5, "old")]),
            Ok(vec![user_event(5, "old")]),
            Err(QueuePort::gateway_error()),
            Err(QueuePort::timeout_error()),
            Ok(vec![user_event(6, "hello")]),
        ]));
        let (runner, _state) = runner_with("ack-swallow", port, Arc::clone(&sink));
        let stop = Arc::new(TurnStop {
            stopped: AtomicBool::new(false),
            notify: Notify::new(),
        });
        let seq = runner.deliver_send(111, "", "hello", &stop).await;
        assert_eq!(seq.unwrap(), Some(6));
    }

    #[tokio::test]
    async fn deliver_send_non_swallowable_history_error_fails() {
        let sink = Arc::new(RecordingSink::new());
        let port = Arc::new(QueuePort::new(vec![
            Ok(vec![user_event(5, "old")]),
            Ok(vec![user_event(5, "old")]),
            Err(BotError::Validation("boom".to_string())),
        ]));
        let (runner, _state) = runner_with("ack-fatal", port, Arc::clone(&sink));
        let stop = Arc::new(TurnStop {
            stopped: AtomicBool::new(false),
            notify: Notify::new(),
        });
        assert!(runner.deliver_send(111, "", "hello", &stop).await.is_err());
    }

    #[tokio::test]
    async fn deliver_media_turn_uses_delivered_top_seq_cap() {
        // Go `deliverMediaTurn` (`telegram_turn.go:1133`):
        // `collectTurnMedia` is capped at
        // `deliveredTopSeq(userSeq, res)` — media from an
        // event after the last delivered reply is NOT this
        // turn's media: not sent, not claimed.
        let sink = Arc::new(RecordingSink::new());
        let mut files = std::collections::HashMap::new();
        files.insert("/media/raw/f10.png".to_string(), b"PNG!".to_vec());
        files.insert("/media/raw/f20.png".to_string(), b"PNG!".to_vec());
        let port = Arc::new(
            QueuePort::new(vec![Ok(vec![
                media_event(10, "m10", "sandbox://f10.png", 4),
                media_event(20, "m20", "sandbox://f20.png", 4),
            ])])
            .with_files(files),
        );
        let (runner, state) = runner_with("upto", port, Arc::clone(&sink));
        let res = WaitResult {
            replies: vec![Reply {
                seq: 15,
                message_id: "m15".to_string(),
                text: "reply15".to_string(),
                widgets: Vec::new(),
                media: false,
                agent_id: String::new(),
                root_agent_id: String::new(),
            }],
            ..Default::default()
        };
        let delivered = runner
            .deliver_media_turn(111, 7, "", 0, &res, &[], &None)
            .await
            .unwrap();
        assert!(delivered);
        assert_eq!(sink.send_file_names(), vec!["f10.png".to_string()]);
        let key20 = crate::state::sent_media_key("no1", 111, "", "/media/raw/f20.png");
        assert!(
            !state.sent_media_claimed(&key20),
            "media past the delivered top seq must not be claimed"
        );
    }

    #[tokio::test]
    async fn deliver_media_turn_history_error_falls_back_to_text_only() {
        // Go `deliverMediaTurn` (`telegram_turn.go:1133-1143`):
        // a history-read failure is `errMediaUnavailable`
        // (unless auth/cancel) and the caller falls back
        // to the text-only path — the turn does not fail.
        let sink = Arc::new(RecordingSink::new());
        let port = Arc::new(QueuePort::new(vec![Err(gateway_error())]));
        let (runner, _state) = runner_with("media-hist-err", port, Arc::clone(&sink));
        let res = WaitResult {
            ..Default::default()
        };
        let delivered = runner
            .deliver_media_turn(111, 7, "", 0, &res, &[], &None)
            .await
            .unwrap();
        assert!(!delivered, "history error must fall back, not fail");
    }

    #[tokio::test]
    async fn deliver_final_history_error_falls_back_to_text_only() {
        let sink = Arc::new(RecordingSink::new());
        let port = Arc::new(QueuePort::new(vec![Err(gateway_error())]));
        let (runner, _state) = runner_with("final-hist-err", port, Arc::clone(&sink));
        let mut res = WaitResult {
            ..Default::default()
        };
        res.final_text = "hello".to_string();
        res.outcome = "done".to_string();
        runner
            .deliver_final(111, 7, "", "main chat", 0, &res, false)
            .await
            .unwrap();
        let calls = sink.calls.lock().unwrap().clone();
        assert!(
            calls.iter().any(|c| c == "edit:hello"),
            "text-only fallback must deliver the reply, calls={calls:?}"
        );
    }

    #[tokio::test]
    async fn deliver_media_item_bad_path_is_notice_not_fatal() {
        // Go `deliverMediaItem` (`telegram_turn.go:1243-1330`):
        // a per-file failure is a notice and the turn
        // continues with the next file; only a fatal
        // (auth/cancel) failure returns an error.
        let sink = Arc::new(RecordingSink::new());
        let mut files = std::collections::HashMap::new();
        files.insert("/media/raw/good.png".to_string(), b"PNG!".to_vec());
        let port = Arc::new(
            QueuePort::new(vec![Ok(vec![
                media_event(10, "m10", "sandbox://a/../b.png", 4),
                media_event(11, "m11", "sandbox://good.png", 4),
            ])])
            .with_files(files),
        );
        let (runner, _state) = runner_with("bad-path", port, Arc::clone(&sink));
        // Covering reply (empty text: no text segment):
        // Go's cap is `deliveredTopSeq(userSeq, res)`, so
        // without it no media passes the filter.
        let res = WaitResult {
            replies: vec![Reply {
                seq: 20,
                message_id: "m20".to_string(),
                text: String::new(),
                widgets: Vec::new(),
                media: false,
                agent_id: String::new(),
                root_agent_id: String::new(),
            }],
            ..Default::default()
        };
        let delivered = runner
            .deliver_media_turn(111, 7, "", 0, &res, &[], &None)
            .await
            .unwrap();
        assert!(delivered);
        assert_eq!(sink.send_file_count(), 1);
        assert_eq!(sink.send_file_names(), vec!["good.png".to_string()]);
        let calls = sink.calls.lock().unwrap().clone();
        assert!(
            calls
                .iter()
                .any(|c| c == "send:📎 <b>b.png</b> could not be fetched (error)."),
            "bad-path file must become a notice, calls={calls:?}"
        );
    }

    #[tokio::test]
    async fn dead_gateway_follow_fails_bounded_and_releases_slot() {
        // A gateway that stays dead after the ack must end
        // the turn with an error text within the follow
        // history-error budget — never a silent poll to
        // the 6h turn timeout — and the slot must be free
        // for the next turn (no busy reply for it).
        let sink = Arc::new(RecordingSink::new());
        let port = Arc::new(QueuePort::new(vec![
            Ok(vec![user_event(5, "old")]),
            Ok(vec![user_event(5, "old")]),
            Ok(vec![user_event(6, "hi")]),
            Err(gateway_error()),
        ]));
        let (runner, _state) = runner_with("dead-gw", port, Arc::clone(&sink));
        runner.set_follow_error_budget(Duration::from_millis(300));
        runner.start_turn(111, "hi".to_string()).await;
        assert!(
            wait_until_slot_free(&runner, 111, Duration::from_secs(8)).await,
            "dead-gateway turn must end within the error budget"
        );
        let calls = sink.calls.lock().unwrap().clone();
        assert!(
            calls
                .iter()
                .any(|c| c == "edit:⚠️ Could not reach Muse (gateway error). Try again."),
            "turn must report the gateway error to the user, calls={calls:?}"
        );
        // The next turn on the same chat is not busy: the
        // slot was released (its baseline read fails, so
        // it reports the error instead of queueing).
        runner.start_turn(111, "hi2".to_string()).await;
        assert!(
            wait_until_slot_free(&runner, 111, Duration::from_secs(8)).await,
            "second turn must also finish"
        );
        assert_eq!(
            busy_reply_count(&sink),
            0,
            "no turn after a dead gateway may get a busy reply"
        );
        // Timeout-guarded: on the pre-fix code the first
        // turn never ends, so an unguarded join would hang
        // the suite past the assertions above.
        let _ = tokio::time::timeout(Duration::from_secs(5), runner.wait_turns()).await;
    }

    #[tokio::test]
    async fn concurrent_start_turn_same_chat_runs_only_one() {
        // Go `startTurn` (`telegram_turn.go:271-280`):
        // the busy check and the slot insert hold ONE
        // lock. Two concurrent starts for one chat run
        // exactly one turn; the other gets the busy reply.
        let sink = Arc::new(RecordingSink::new());
        let port = Arc::new(TestPort {
            history_script: vec![media_event(10, "m1", "sandbox://f1.png", 4)],
            files: std::collections::HashMap::new(),
        });
        let (runner, _state) = media_runner("concurrent", Arc::clone(&port), Arc::clone(&sink));
        let r1 = Arc::clone(&runner);
        let r2 = Arc::clone(&runner);
        let (_r1, _r2) = tokio::join!(
            tokio::spawn(async move { r1.start_turn(111, "one".to_string()).await }),
            tokio::spawn(async move { r2.start_turn(111, "two".to_string()).await }),
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            busy_reply_count(&sink),
            1,
            "exactly one of two concurrent starts gets the busy reply"
        );
        let _ = runner.stop_turn(111).await;
        runner.wait_turns().await;
    }

    #[tokio::test]
    async fn start_turn_panic_releases_slot() {
        // Go defers `clearActive` through a panic
        // (`telegram_turn.go:187-197,281-284`): a turn
        // that panics must not leak its slot.
        let sink = Arc::new(RecordingSink::new());
        let port = Arc::new(PanicPort);
        let (runner, _state) = runner_with("panic-slot", port, Arc::clone(&sink));
        runner.start_turn(111, "one".to_string()).await;
        assert!(
            wait_until_slot_free(&runner, 111, Duration::from_secs(5)).await,
            "panicked turn must release its slot"
        );
        // A later start on the same chat is not busy
        // (it panics again on its own history read, but
        // the busy reply is the wrong answer).
        runner.start_turn(111, "two".to_string()).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            busy_reply_count(&sink),
            0,
            "slot must be free after a panic"
        );
        runner.wait_turns().await;
    }

    #[tokio::test]
    async fn wait_turns_signals_stops_so_shutdown_does_not_hang() {
        // Go `Wait` (`telegram_turn.go:240-249`): the join
        // is bounded because shutdown cancels the turn
        // ctx. `wait_turns` must signal every registered
        // stop before joining, or a turn in its 6h follow
        // hangs shutdown forever.
        let sink = Arc::new(RecordingSink::new());
        let port = Arc::new(TestPort {
            history_script: Vec::new(),
            files: std::collections::HashMap::new(),
        });
        let (runner, _state) = media_runner("wait-shutdown", Arc::clone(&port), Arc::clone(&sink));
        runner.start_turn(111, "one".to_string()).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(runner.has_active_turn(111));
        tokio::time::timeout(Duration::from_secs(5), runner.wait_turns())
            .await
            .expect("wait_turns must return promptly on shutdown");
    }

    #[tokio::test]
    async fn start_resume_does_not_clear_slot_it_never_acquired() {
        // Go `startResume` (`telegram_turn.go:327-332`):
        // the deferred `clearActive` runs only when
        // `acquired` is true. A resume that is still
        // waiting for the slot when shutdown begins must
        // not clear the running turn's slot.
        let sink = Arc::new(RecordingSink::new());
        let port = Arc::new(TestPort {
            history_script: Vec::new(),
            files: std::collections::HashMap::new(),
        });
        let (runner, _state) = media_runner("resume-guard", Arc::clone(&port), Arc::clone(&sink));
        runner.start_turn(111, "one".to_string()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(runner.has_active_turn(111));
        // Start the resume WHILE stopping is still false,
        // so its task is really waiting for the slot; flip
        // stopping only after it is waiting. (Setting
        // stopping first makes `start_resume` return at
        // its entry check and the test vacuous.)
        runner
            .start_resume(111, "s".to_string(), "t".to_string(), 1)
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        runner.stopping.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            runner.has_active_turn(111),
            "resume must not clear a slot it never acquired"
        );
        let _ = runner.stop_turn(111).await;
        runner.wait_turns().await;
    }

    #[tokio::test]
    async fn run_text_turn_deliver_error_still_reports_error_text() {
        // A `deliver_final` failure must reach the user as
        // an error text in the bubble, not vanish when the
        // spawned turn task drops its `Err`.
        let sink = Arc::new(RecordingSink::new());
        sink.fail_edit.store(true, Ordering::SeqCst);
        // Fail sends from the 2nd send onward: the
        // opening bubble send (1st) must succeed, or the
        // turn aborts before delivery. The final-text
        // edit fails (fail_edit) and its send fallback
        // fails (2nd send) — that is the delivery error
        // under test.
        sink.fail_send_after.store(1, Ordering::SeqCst);
        let full = vec![
            user_event(6, "hi"),
            task_event(7, "running"),
            task_event(8, "completed"),
            assistant_text_event(9, "Hello"),
        ];
        let port = Arc::new(QueuePort::new(vec![
            Ok(vec![user_event(5, "old")]),
            Ok(vec![user_event(5, "old")]),
            Ok(full.clone()),
        ]));
        let (runner, _state) = runner_with("deliver-err", port, Arc::clone(&sink));
        runner.start_turn(111, "hi".to_string()).await;
        assert!(
            wait_until_slot_free(&runner, 111, Duration::from_secs(10)).await,
            "turn must finish"
        );
        let calls = sink.calls.lock().unwrap().clone();
        assert!(
            calls
                .iter()
                .any(|c| c == "edit:⚠️ Could not reach Muse (gateway error). Try again."),
            "deliver failure must be reported in the bubble, calls={calls:?}"
        );
        runner.wait_turns().await;
    }
}
