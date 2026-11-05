// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Bot API calls over the outbound.
//!
//! Go sources: `internal/telegram/bot.go:316-352`
//! (`BoundClient`), `:62-74` (timeouts), `:1507-1546`
//! (`sleepOrDone`, `retryCall`), `:1635-1660`
//! (`sendMessageCall`), `:1786-1816` (`SetCommands`),
//! `internal/telegram/files.go:169-264` (`SendFile`,
//! `sendFileKind`), `internal/telegram/inbound.go:172-221`
//! (`DownloadMedia`).
//!
//! The Go bot uses the go-telegram/bot library, which hides
//! the HTTP layer. This port hand-rolls the loop on
//! `castctl-transport` (`HttpClient::request` for plaintext
//! tests, `tls::TlsHttpClient` for production HTTPS — see
//! `tls.rs` for why the TLS path lives here). It does NOT use
//! `RpcClient::call_json`: that client's route table is the
//! gateway's (258 entries from `internal/proto/routes.json`)
//! and its envelope decoding is the gateway's, not the Bot
//! API's (`{"ok":true,"result":[...]}` vs gateway envelopes).
//!
//! Security invariant: the token travels only in the request
//! path (`/bot<token>/<method>`), exactly as the Bot API
//! requires; the path is never logged, never interpolated
//! into an error, never stored. Redirects are refused by the
//! HTTP layer, so a token-bearing path is never re-sent to a
//! second host.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use castctl_transport::{DialTarget, Dialer, HttpClient, TransportError};
use serde_json::Value;

use crate::error::BotError;
use crate::send::InlineKeyboardMarkup;
use crate::tls::{TlsHttpClient, telegram_api_target};
use crate::types::Update;

/// Long-poll `timeout` parameter sent to `getUpdates`
/// (seconds). Go `PollTimeout = 26s`
/// (`internal/telegram/bot.go:62-67`) — the library sends
/// pollTimeout−1s, so 26s here sends exactly 25s (Python
/// polls `getUpdates` with `timeout=25`,
/// `src/muse_cli/tgbot.py:2438-2439`).
pub const POLL_TIMEOUT_SECS: u64 = 25;

/// Client timeout for poll calls. Must exceed the poll
/// timeout or the client aborts every long poll early.
/// Source: `internal/telegram/bot.go:69-74`
/// (`ClientTimeout = 40s`; Python 40s HTTP timeout,
/// `src/muse_cli/tgapi.py:84-86`).
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(40);

/// Client timeout for file uploads/downloads.
/// Source: `internal/telegram/files.go:41-44` (120s; Python
/// `_post(method, 120, ...)`, `src/muse_cli/tgapi.py:139`).
pub const UPLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum `retry_after` (seconds) the 429 rule honours.
/// Source: `internal/telegram/bot.go:1527-1546` (`retryCall`).
pub const MAX_RETRY_AFTER_SECS: i64 = 60;

/// Maximum 429 retries per call (initial attempt + 2).
/// Source: `internal/telegram/bot.go:1527-1546`.
pub const MAX_429_RETRIES: usize = 2;

/// Extra pause added to `retry_after` between 429 retries.
/// Source: `internal/telegram/bot.go:1527-1546`
/// (`retry_after + 0.5s`).
pub const RETRY_AFTER_PAD: Duration = Duration::from_millis(500);

/// Bot API host path prefix for file downloads.
/// Source: `internal/telegram/inbound.go:172-221`
/// (`DownloadMedia` GETs the file URL from `getFile`).
pub const FILE_DOWNLOAD_PREFIX: &str = "/file/bot";

/// Configuration for [`BotApi`]. There is no direct Go type
/// counterpart: Go spreads these across `Settings`
/// (`internal/telegram/bot.go:191-274`) and the two library
/// instances built in `New` (`:358-481`).
///
/// Hand-written `Debug`: the token renders as `[redacted]`
/// (same pattern as [`BotApi`]; fix loop 1, safety B2 —
/// the derived `Debug` used to print the token verbatim).
#[derive(Clone)]
pub struct BotApiConfig {
    /// Bot token (shape-checked by the caller, never logged).
    /// Source: `internal/telegram/bot.go:63-65` (`botTokenShape`).
    pub token: String,
    /// Bot API target. Production is `api.telegram.org:443`;
    /// tests pass the fake server's target.
    /// Source: `internal/telegram/bot.go:191-274`
    /// (`Settings.ServerURL`; empty = library default).
    pub target: DialTarget,
    /// Whether to speak TLS (production) or plaintext (tests
    /// against a local fake server). There is no Go
    /// counterpart: Go always speaks TLS; the plaintext path
    /// exists only so the fake-server tests can run without a
    /// TLS stack.
    pub use_tls: bool,
    /// Per-attempt timeout for poll calls (default
    /// [`CLIENT_TIMEOUT`]).
    pub client_timeout: Duration,
    /// Per-attempt timeout for upload/download calls (default
    /// [`UPLOAD_TIMEOUT`]).
    pub upload_timeout: Duration,
}

impl std::fmt::Debug for BotApiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BotApiConfig")
            .field("token", &"[redacted]")
            .field("target", &self.target)
            .field("use_tls", &self.use_tls)
            .field("client_timeout", &self.client_timeout)
            .field("upload_timeout", &self.upload_timeout)
            .finish_non_exhaustive()
    }
}

/// Shutdown signal shared with a [`BotApi`] so 429 retry
/// sleeps can be cancelled instead of blocking shutdown
/// for up to 60.5s (fix loop 1, tech B6 / red N7). Go's
/// `sleepOrDone` (`internal/telegram/bot.go:1507-1546`)
/// respects `ctx` cancellation on every retry path; this
/// is the Rust equivalent. `Bot::new` installs the bot's
/// own signal; a client without one sleeps plainly
/// (standalone/handler tests).
pub struct ShutdownSignal {
    flag: AtomicBool,
    notify: tokio::sync::Notify,
}

impl ShutdownSignal {
    /// New unset signal.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            flag: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        })
    }

    /// Fire the signal (idempotent).
    pub fn request(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Whether the signal has fired.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Wait for the signal. The waiter is registered
    /// (`enable()`) BEFORE the flag is re-checked, so a
    /// request between the check and the wait cannot be
    /// lost.
    pub async fn wait(&self) {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        let _ = notified.as_mut().enable();
        if self.flag.load(Ordering::SeqCst) {
            return;
        }
        notified.await;
    }
}

impl BotApiConfig {
    /// Production config: TLS to `api.telegram.org:443`.
    #[must_use]
    pub fn production(token: String) -> Self {
        Self {
            token,
            target: telegram_api_target(),
            use_tls: true,
            client_timeout: CLIENT_TIMEOUT,
            upload_timeout: UPLOAD_TIMEOUT,
        }
    }

    /// Test config: plaintext to a fake server target.
    #[must_use]
    pub fn plaintext(token: String, target: DialTarget) -> Self {
        Self {
            token,
            target,
            use_tls: false,
            client_timeout: CLIENT_TIMEOUT,
            upload_timeout: UPLOAD_TIMEOUT,
        }
    }
}

/// One Bot API client bound to a profile outbound.
///
/// Hand-written `Debug`: the token renders as `[redacted]`
/// (pattern: `TelegramConfig`,
/// `castctl-config/src/telegram.rs:37-51`).
pub struct BotApi {
    token: String,
    target: DialTarget,
    plain: Option<HttpClient>,
    tls: Option<TlsHttpClient>,
    client_timeout: Duration,
    upload_timeout: Duration,
    shutdown: Mutex<Option<Arc<ShutdownSignal>>>,
}

impl std::fmt::Debug for BotApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BotApi")
            .field("token", &"[redacted]")
            .field("target", &self.target)
            .field("use_tls", &self.tls.is_some())
            .field("client_timeout", &self.client_timeout)
            .field("upload_timeout", &self.upload_timeout)
            .finish_non_exhaustive()
    }
}

impl BotApi {
    /// Build a client over `dialer` from `config`.
    /// No direct Go function counterpart: Go's `New`
    /// (`internal/telegram/bot.go:358-481`) builds the two
    /// library instances around a supplied `*http.Client`;
    /// this constructor is the Rust-side equivalent of
    /// binding a dialer to the Bot API base URL.
    #[must_use]
    pub fn new(dialer: Arc<dyn Dialer>, config: BotApiConfig) -> Self {
        if config.use_tls {
            Self {
                token: config.token,
                target: config.target,
                plain: None,
                tls: Some(TlsHttpClient::new(dialer)),
                client_timeout: config.client_timeout,
                upload_timeout: config.upload_timeout,
                shutdown: Mutex::new(None),
            }
        } else {
            Self {
                token: config.token,
                target: config.target,
                plain: Some(HttpClient::new(dialer)),
                tls: None,
                client_timeout: config.client_timeout,
                upload_timeout: config.upload_timeout,
                shutdown: Mutex::new(None),
            }
        }
    }

    /// Install the shutdown signal for 429 retry sleeps
    /// (see [`ShutdownSignal`]). `Bot::new` calls this
    /// with the bot's signal; without it, retry sleeps
    /// are plain `tokio::time::sleep`s.
    pub fn set_shutdown_signal(&self, signal: Arc<ShutdownSignal>) {
        *self.shutdown.lock().expect("shutdown lock") = Some(signal);
    }

    /// Sleep `dur` unless the shutdown signal fires
    /// first. Returns `false` when cancelled (the caller
    /// returns `BotError::Cancelled`, mirroring Go's
    /// `retryCall` returning `ctx.Err()`).
    async fn sleep_or_shutdown(&self, dur: Duration) -> bool {
        let Some(signal) = self.shutdown.lock().expect("shutdown lock").clone() else {
            tokio::time::sleep(dur).await;
            return true;
        };
        tokio::select! {
            () = signal.wait() => false,
            () = tokio::time::sleep(dur) => true,
        }
    }

    /// The token, for redaction/summary callers only. Never
    /// log the return value. No direct Go function
    /// counterpart: Go reads `b.token` directly.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The Bot API target this client talks to.
    #[must_use]
    pub fn target(&self) -> &DialTarget {
        &self.target
    }

    fn method_path(&self, method: &str) -> String {
        format!("/bot{}/{}", self.token, method)
    }

    async fn post_json(
        &self,
        path: &str,
        body: Bytes,
        timeout: Duration,
        max_body: Option<usize>,
    ) -> Result<castctl_transport::HttpResponse, TransportError> {
        let headers = [("Content-Type".to_string(), "application/json".to_string())];
        match (&self.plain, &self.tls) {
            (Some(plain), None) => {
                plain
                    .request(
                        http::Method::POST,
                        &self.target,
                        path,
                        &headers,
                        Some(body),
                        timeout,
                    )
                    .await
            }
            (None, Some(tls)) => {
                if let Some(cap) = max_body {
                    tls.request_with_body_cap(
                        http::Method::POST,
                        &self.target,
                        path,
                        &headers,
                        Some(body),
                        timeout,
                        cap,
                    )
                    .await
                } else {
                    tls.request(
                        http::Method::POST,
                        &self.target,
                        path,
                        &headers,
                        Some(body),
                        timeout,
                    )
                    .await
                }
            }
            _ => Err(TransportError::Validation {
                message: "bot api client has no transport".to_string(),
            }),
        }
    }

    async fn get_path(
        &self,
        path: &str,
        timeout: Duration,
        max_body: Option<usize>,
    ) -> Result<castctl_transport::HttpResponse, TransportError> {
        match (&self.plain, &self.tls) {
            (Some(plain), None) => {
                plain
                    .request(http::Method::GET, &self.target, path, &[], None, timeout)
                    .await
            }
            (None, Some(tls)) => {
                if let Some(cap) = max_body {
                    tls.request_with_body_cap(
                        http::Method::GET,
                        &self.target,
                        path,
                        &[],
                        None,
                        timeout,
                        cap,
                    )
                    .await
                } else {
                    tls.request(http::Method::GET, &self.target, path, &[], None, timeout)
                        .await
                }
            }
            _ => Err(TransportError::Validation {
                message: "bot api client has no transport".to_string(),
            }),
        }
    }

    /// Decode one Bot API envelope into its `result`, or the
    /// `Api` error it carries. The body bytes are never copied
    /// into the error; `description` is held, never printed
    /// (see `error.rs`). An undecodable body on a 5xx status
    /// maps to the 5xx `Api` error (the status is
    /// authoritative, so the poll loop takes the 5xx ladder
    /// instead of spinning at 1 req/s — fix loop 1, red N1;
    /// a [DEVIATION] from Go, whose library reports a
    /// response decode failure there — see PORTING §M5a.3).
    /// Any other undecodable body is `ResponseDecode`.
    fn decode_envelope(
        status: http::StatusCode,
        headers: &http::HeaderMap,
        body: &[u8],
    ) -> Result<Value, BotError> {
        let value: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => {
                if status.is_server_error() {
                    return Err(BotError::Api {
                        code: status.as_u16() as i32,
                        description: String::new(),
                        retry_after: None,
                    });
                }
                return Err(BotError::ResponseDecode);
            }
        };
        let ok = value.get("ok").and_then(Value::as_bool).unwrap_or(false);
        if ok {
            return Ok(value.get("result").cloned().unwrap_or(Value::Null));
        }
        let code = value
            .get("error_code")
            .and_then(Value::as_i64)
            .unwrap_or(status.as_u16() as i64);
        let description = value
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut retry_after = value
            .get("parameters")
            .and_then(|p| p.get("retry_after"))
            .and_then(Value::as_i64);
        if retry_after.is_none() {
            retry_after = headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<i64>().ok());
        }
        Err(BotError::Api {
            code: i32::try_from(code).unwrap_or(0),
            description,
            retry_after,
        })
    }

    /// One Bot API call with Go's 429 retry rule.
    /// Source: `internal/telegram/bot.go:1527-1546`
    /// (`retryCall`): retry ONLY HTTP 429 with `retry_after`
    /// present, 1..=60, at most 2 retries, sleeping
    /// `retry_after + 0.5s` between attempts.
    ///
    /// Cancellation: the retry sleep respects the shutdown
    /// signal installed by [`BotApi::set_shutdown_signal`]
    /// (Go `sleepOrDone`); a cancelled sleep returns
    /// `BotError::Cancelled` instead of waiting out up to
    /// 60.5s. Dropping the future cancels the sleep too.
    pub async fn call_json(&self, method: &str, params: Value) -> Result<Value, BotError> {
        self.call_json_timeout(method, params, self.client_timeout)
            .await
    }

    /// [`BotApi::call_json`] with an explicit per-attempt timeout.
    /// No direct Go function counterpart: Go's `retryCall`
    /// wraps a closure whose timeout is the client timeout;
    /// the upload path (120s) needs the override.
    pub async fn call_json_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, BotError> {
        let path = self.method_path(method);
        let body = Bytes::from(
            serde_json::to_vec(&params)
                .map_err(|_| BotError::Validation("request encode failure".to_string()))?,
        );
        for attempt in 0..=MAX_429_RETRIES {
            let resp = self.post_json(&path, body.clone(), timeout, None).await?;
            let result = Self::decode_envelope(resp.status, &resp.headers, &resp.body);
            match result {
                Ok(value) => return Ok(value),
                Err(ref e @ BotError::Api { code: 429, .. }) => {
                    let retry_after = e.retry_after().unwrap_or(0);
                    if (1..=MAX_RETRY_AFTER_SECS).contains(&retry_after)
                        && attempt < MAX_429_RETRIES
                    {
                        if !self
                            .sleep_or_shutdown(
                                Duration::from_secs(u64::try_from(retry_after).unwrap_or(0))
                                    + RETRY_AFTER_PAD,
                            )
                            .await
                        {
                            return Err(BotError::Cancelled);
                        }
                        continue;
                    }
                    return Err(result.unwrap_err());
                }
                Err(e) => return Err(e),
            }
        }
        Err(BotError::Validation(
            "retry loop ended without a result".to_string(),
        ))
    }

    /// `getUpdates` with the long-poll timeout parameter.
    /// Source: `internal/telegram/bot.go:445-479` (the poll
    /// instance: `WithAllowedUpdates{message, callback_query}`,
    /// `WithInitialOffset`); the `timeout` parameter is
    /// pollTimeout−1s per the library, i.e. 25s here
    /// (`POLL_TIMEOUT_SECS`).
    ///
    /// Decode mirrors the pinned Bot API library
    /// (`go-telegram/bot v1.27.1-.../get_updates.go`,
    /// `decodeUpdate` — fix loop 3, red R6), NOT a
    /// whole-array unmarshal: the envelope decodes to
    /// raw items, then each item decodes on its own, "so
    /// a single undecodable update does not reject the
    /// whole batch". A missing `result` (`null`) is an
    /// empty batch, not an error; a `result` that is not
    /// an array is a response decode failure (the whole
    /// batch fails, as in Go — the library's unmarshal
    /// into `[]json.RawMessage` fails there too); ABSENT
    /// or `null` fields zero-fill via `null_as_default`
    /// on `types.rs` and the item proceeds. A bare `null`
    /// array element decodes to a zero `Update` (Go: a
    /// null element is a zero value), never fails the
    /// batch. A WRONG-TYPE field fails only that item:
    /// its `update_id` is read best-effort — readable,
    /// the item is pushed as a skipped zero `Update`
    /// carrying that id (the run loop advances the poll
    /// offset past it and the allowlist drops it by
    /// sender 0, exactly Go's skip-and-advance);
    /// unreadable (wrong-type id, float id, non-object
    /// element, missing id), it becomes a zero `Update`
    /// (Go's `offsetStuck` case: offset unchanged, the
    /// batch is re-requested at the long-poll cadence)
    /// — and decoding CONTINUES with the rest of the
    /// batch instead of returning `Err(UpdateDecode)`.
    /// (The old doc here claimed a wrong-type field
    /// fails the whole batch "as in Go" — that claim
    /// was FALSE; the library decodes per item. Fix
    /// loop 3 corrects the record; do not reintroduce
    /// the old claim.)
    pub async fn get_updates(&self, offset: i64) -> Result<Vec<Update>, BotError> {
        let mut params = serde_json::json!({
            "timeout": POLL_TIMEOUT_SECS,
            "allowed_updates": ["message", "callback_query"],
        });
        if offset > 0 {
            params["offset"] = serde_json::json!(offset);
        }
        let result = self.call_json("getUpdates", params).await?;
        if result.is_null() {
            return Ok(Vec::new());
        }
        let Some(items) = result.as_array() else {
            return Err(BotError::ResponseDecode);
        };
        let mut updates = Vec::with_capacity(items.len());
        for item in items {
            if item.is_null() {
                updates.push(Update::default());
                continue;
            }
            match serde_json::from_value(item.clone()) {
                Ok(update) => updates.push(update),
                Err(_) => {
                    // Mirror the pinned library's
                    // `decodeUpdate` (fix loop 3, red R6):
                    // a single undecodable item must not
                    // reject the whole batch. Read its id
                    // best-effort; a readable id is pushed
                    // as a skipped zero `Update` carrying
                    // it (the run loop advances the offset
                    // past it), an unreadable id becomes a
                    // zero `Update` (Go's `offsetStuck`
                    // case). Either way, keep decoding the
                    // rest of the batch.
                    let id = item.get("update_id").and_then(Value::as_i64).unwrap_or(0);
                    updates.push(Update {
                        update_id: id,
                        ..Default::default()
                    });
                }
            }
        }
        Ok(updates)
    }

    /// `getMe` (one call; Go performs it at construction with
    /// no `SkipGetMe`, `internal/telegram/bot.go:358-481`).
    pub async fn get_me(&self) -> Result<Value, BotError> {
        self.call_json("getMe", serde_json::json!({})).await
    }

    /// `sendMessage` with a pre-built parameter object;
    /// returns the sent `message_id`.
    /// Source: `internal/telegram/bot.go:1635-1660`
    /// (`sendMessageCall`).
    pub async fn send_message_params(&self, params: Value) -> Result<i64, BotError> {
        let result = self.call_json("sendMessage", params).await?;
        let message_id = result
            .get("message_id")
            .and_then(Value::as_i64)
            .ok_or_else(|| {
                BotError::Validation("telegram: sendMessage returned no message".to_string())
            })?;
        Ok(message_id)
    }

    /// `editMessageText` with a pre-built parameter object.
    /// A JSON `true` result (inline messages) is success.
    /// Source: `internal/telegram/bot.go:1662-1699` (`Edit`).
    pub async fn edit_message_text_params(&self, params: Value) -> Result<(), BotError> {
        let _ = self.call_json("editMessageText", params).await?;
        Ok(())
    }

    /// `editMessageReplyMarkup` with an empty keyboard
    /// (clear buttons).
    /// Source: `internal/telegram/bot.go:1819-1846`
    /// (`ClearMarkup` / `clearMarkup`).
    pub async fn clear_markup(&self, chat_id: i64, message_id: i64) -> Result<(), BotError> {
        let params = serde_json::json!({
            "chat_id": chat_id,
            "message_id": message_id,
            "reply_markup": {"inline_keyboard": []},
        });
        let _ = self.call_json("editMessageReplyMarkup", params).await?;
        Ok(())
    }

    /// `deleteMessage`.
    /// Source: `internal/telegram/bot.go:1738-1745` (`Delete`).
    pub async fn delete_message(&self, chat_id: i64, message_id: i64) -> Result<(), BotError> {
        let params = serde_json::json!({
            "chat_id": chat_id,
            "message_id": message_id,
        });
        let _ = self.call_json("deleteMessage", params).await?;
        Ok(())
    }

    /// `answerCallbackQuery`.
    /// Source: `internal/telegram/bot.go:1726-1736` (`answer`).
    pub async fn answer_callback_query(
        &self,
        callback_query_id: &str,
        text: &str,
    ) -> Result<(), BotError> {
        let mut params = serde_json::json!({
            "callback_query_id": callback_query_id,
        });
        if !text.is_empty() {
            params["text"] = serde_json::json!(text);
        }
        let _ = self.call_json("answerCallbackQuery", params).await?;
        Ok(())
    }

    /// `setMyCommands` (default scope + default language).
    /// Validation happens in `send.rs`/`commands.rs` BEFORE
    /// any request; this method only performs the call.
    /// Source: `internal/telegram/bot.go:1786-1816`
    /// (`SetCommands`).
    pub async fn set_my_commands(&self, commands: &[(String, String)]) -> Result<(), BotError> {
        let list: Vec<Value> = commands
            .iter()
            .map(|(name, description)| {
                serde_json::json!({"command": name, "description": description})
            })
            .collect();
        let params = serde_json::json!({"commands": list});
        let _ = self.call_json("setMyCommands", params).await?;
        Ok(())
    }

    /// `getMyCommands` (default scope, default language).
    /// Used by the live check and by tests; Go has no direct
    /// caller (the menu is verified live via `getMyCommands`
    /// in CASTCTL-CONTEXT.md).
    pub async fn get_my_commands(&self) -> Result<Value, BotError> {
        self.call_json("getMyCommands", serde_json::json!({})).await
    }

    /// Multipart file upload (`sendDocument` / `sendPhoto` /
    /// `sendVideo` / `sendAudio`). A FRESH multipart body is
    /// built per retry attempt (the body bytes are consumed
    /// building the request; reusing one would upload an
    /// empty part on retry). `markup` is attached to every
    /// method, as Go's `sendFileKind` does
    /// (`files.go:192-264`) — the old code dropped it
    /// (fix loop 1, tech N6). The 429 retry sleep respects
    /// the shutdown signal (see [`BotApi::call_json`]).
    /// Source: `internal/telegram/files.go:192-264`
    /// (`sendFileKind`). The arity mirrors Go's
    /// `sendFileKind` signature; bundling the fields
    /// would only move the same list into a struct.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_file_multipart(
        &self,
        method: &str,
        chat_id: i64,
        filename: &str,
        data: &[u8],
        caption: &str,
        reply_to: i64,
        silent: bool,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Result<i64, BotError> {
        let path = self.method_path(method);
        let boundary = "----castctl-telegram-form-boundary-7d3a9f2e";
        // The multipart part name is the method's file field
        // (`sendDocument` → `document`, `sendPhoto` → `photo`,
        // `sendVideo` → `video`, `sendAudio` → `audio`).
        let part_name = match method {
            "sendPhoto" => "photo",
            "sendVideo" => "video",
            "sendAudio" => "audio",
            _ => "document",
        };
        for attempt in 0..=MAX_429_RETRIES {
            let body = multipart_body(
                boundary,
                part_name,
                chat_id,
                filename,
                data,
                caption,
                reply_to,
                silent,
                markup.as_ref(),
            );
            let headers = [(
                "Content-Type".to_string(),
                format!("multipart/form-data; boundary={boundary}"),
            )];
            let resp = match (&self.plain, &self.tls) {
                (Some(plain), None) => {
                    plain
                        .request(
                            http::Method::POST,
                            &self.target,
                            &path,
                            &headers,
                            Some(body),
                            self.upload_timeout,
                        )
                        .await?
                }
                (None, Some(tls)) => {
                    tls.request(
                        http::Method::POST,
                        &self.target,
                        &path,
                        &headers,
                        Some(body),
                        self.upload_timeout,
                    )
                    .await?
                }
                _ => {
                    return Err(BotError::Validation(
                        "bot api client has no transport".to_string(),
                    ));
                }
            };
            let result = Self::decode_envelope(resp.status, &resp.headers, &resp.body);
            match result {
                Ok(value) => {
                    let message_id =
                        value
                            .get("message_id")
                            .and_then(Value::as_i64)
                            .ok_or_else(|| {
                                BotError::Validation(
                                    "telegram: send file returned no message".to_string(),
                                )
                            })?;
                    return Ok(message_id);
                }
                Err(ref e @ BotError::Api { code: 429, .. }) => {
                    let retry_after = e.retry_after().unwrap_or(0);
                    if (1..=MAX_RETRY_AFTER_SECS).contains(&retry_after)
                        && attempt < MAX_429_RETRIES
                    {
                        if !self
                            .sleep_or_shutdown(
                                Duration::from_secs(u64::try_from(retry_after).unwrap_or(0))
                                    + RETRY_AFTER_PAD,
                            )
                            .await
                        {
                            return Err(BotError::Cancelled);
                        }
                        continue;
                    }
                    return Err(result.unwrap_err());
                }
                Err(e) => return Err(e),
            }
        }
        Err(BotError::Validation(
            "retry loop ended without a result".to_string(),
        ))
    }

    /// `getFile`: returns the server `file_path`.
    /// Source: `internal/telegram/inbound.go:172-221`
    /// (`DownloadMedia` calls `getFile` via the poll instance).
    pub async fn get_file_path(&self, file_id: &str) -> Result<String, BotError> {
        let result = self
            .call_json("getFile", serde_json::json!({"file_id": file_id}))
            .await?;
        let path = result
            .get("file_path")
            .and_then(Value::as_str)
            .ok_or_else(|| BotError::Validation("getFile returned no file_path".to_string()))?;
        if path.is_empty() {
            return Err(BotError::Validation(
                "getFile returned an empty file_path".to_string(),
            ));
        }
        Ok(path.to_string())
    }

    /// GET a file by its server path. The URL contains the
    /// token: it is never logged, never interpolated into an
    /// error, never stored (see `files.rs`).
    /// Source: `internal/telegram/inbound.go:172-221`.
    /// `max_body` is the post-download gate cap (limit + 1);
    /// the TLS path honours it exactly, the plaintext path
    /// caps at the transport's 16 MiB (tests only).
    ///
    /// Deliberate: this GET has NO 429 retry — a 429 fails
    /// fast (fix loop 2, red NIT 6). Go's `DownloadMedia`
    /// performs exactly one `client.Do` and returns a plain
    /// error on any non-200 (`inbound.go:172-221`); the
    /// `getFile` call before it uses the normal `call_json`
    /// 429 retry shared by all Bot API calls.
    pub async fn download_file_bytes(
        &self,
        file_path: &str,
        max_body: usize,
    ) -> Result<Bytes, BotError> {
        let path = format!(
            "{FILE_DOWNLOAD_PREFIX}/{token}/{file_path}",
            token = self.token
        );
        let resp = self
            .get_path(&path, self.upload_timeout, Some(max_body))
            .await?;
        if !resp.status.is_success() {
            // Non-200 carries only the status code, never a body.
            // Source: `internal/telegram/inbound.go:172-221`.
            return Err(BotError::Api {
                code: resp.status.as_u16() as i32,
                description: String::new(),
                retry_after: None,
            });
        }
        Ok(resp.body)
    }
}

/// Build one multipart/form-data body for a file upload.
/// Fields mirror Go `sendFileKind`
/// (`internal/telegram/files.go:192-264`): `chat_id`,
/// `caption` (plain, no `parse_mode`), `disable_notification`
/// when silent, `reply_parameters` when replying,
/// `reply_markup` when a keyboard is attached, then the
/// file part. The file part Content-Type is
/// `application/octet-stream` — Go's deviation (the library
/// always writes the stdlib multipart default; Python sets
/// it from the filename, `src/muse_cli/tgapi.py:161-172`).
/// The arity mirrors `sendFileKind`'s fields; see the
/// `#[allow]` on `send_file_multipart`.
#[allow(clippy::too_many_arguments)]
fn multipart_body(
    boundary: &str,
    part_name: &str,
    chat_id: i64,
    filename: &str,
    data: &[u8],
    caption: &str,
    reply_to: i64,
    silent: bool,
    markup: Option<&InlineKeyboardMarkup>,
) -> Bytes {
    let mut out = Vec::with_capacity(data.len() + 512);
    let field = |out: &mut Vec<u8>, name: &str, value: &str| {
        out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        out.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    };
    field(&mut out, "chat_id", &chat_id.to_string());
    if !caption.is_empty() {
        field(&mut out, "caption", caption);
    }
    if silent {
        field(&mut out, "disable_notification", "true");
    }
    if reply_to != 0 {
        let reply = serde_json::json!({"message_id": reply_to}).to_string();
        field(&mut out, "reply_parameters", &reply);
    }
    if let Some(markup) = markup {
        field(&mut out, "reply_markup", &markup.to_json().to_string());
    }
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{part_name}\"; filename=\"{filename}\"\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Bytes::from(out)
}
