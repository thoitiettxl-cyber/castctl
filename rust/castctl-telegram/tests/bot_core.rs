// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Integration tests for `castctl-telegram` against a fake
//! Bot API server on `127.0.0.1:0` (plaintext, via
//! `DirectDialer`).
//!
//! The fake server follows the `castctl-transport`
//! `tests/common` FakeServer pattern (raw `TcpListener`,
//! one request per connection, caller-supplied responder)
//! — written here in this crate, not imported from M4b.
//!
//! The token used everywhere is the literal fake marker
//! `123456:FAKE-TOKEN-TEST-ONLY-AAAA` (valid shape per
//! `castctl-config::valid_telegram_token_shape`); no real
//! Telegram traffic ever leaves the loopback interface and
//! no real message is ever sent.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use castctl_telegram::BotError;
use castctl_telegram::claims::{ClaimManager, Decider};
use castctl_telegram::router::{
    BotServices, DownloadedFile, FsOutcome, IdeaCard, NewChatOutcome, SessionOp, SessionRow,
    SharedFileRow,
};
use castctl_telegram::state::TelegramStateStore;
use castctl_telegram::types::MessageContext;
use castctl_telegram::{
    Approval, Bot, BotApi, BotApiConfig, BotSettings, COMMAND_HELP_TEXT, COMMAND_MENU,
    CallbackEntry, CallbackQuery, CallbackRegistry, ChatEntry, CommandHandler,
    CommandHandlerConfig, HtmlMode, InboxMedia, InlineKeyboardButton, InlineKeyboardMarkup,
    SendOptions, Sender,
};
use castctl_transport::{DialTarget, Dialer, DirectDialer};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Fake token (valid shape, never real).
const FAKE_TOKEN: &str = "123456:FAKE-TOKEN-TEST-ONLY-AAAA";

/// Allowed user id in most tests.
const ALLOWED_UID: i64 = 111;
/// Owner user id in most tests.
const OWNER_UID: i64 = 999;
/// Stranger user id (never allowed).
const STRANGER_UID: i64 = 555;

// ----------------------------------------------------------------
// Fake Bot API server
// ----------------------------------------------------------------

/// One recorded request (headers are parsed for
/// `content-length` but not stored; the path is parsed
/// for the method but not stored).
#[derive(Debug, Clone)]
struct RequestRecord {
    method: String,
    body: Vec<u8>,
}

impl RequestRecord {
    /// Decoded JSON body (empty object when unparseable).
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

/// Shared fake-server behaviour: queued updates, forced
/// 429/500 failures, and a message-id counter.
struct FakeBehavior {
    updates: Mutex<VecDeque<Value>>,
    /// Full `getUpdates` envelopes, served verbatim one
    /// per poll (fix loop 1, red R3/R4 tests): each entry
    /// is the whole response body, e.g. `{"ok": true,
    /// "result": [...]}` or `{"ok": true}` (no result).
    raw_envelopes: Mutex<VecDeque<Value>>,
    fail_429: Mutex<HashMap<String, (u32, i64)>>,
    fail_500: Mutex<HashMap<String, u32>>,
    /// 500 responses with an EMPTY body (fix loop 1, red
    /// N1): the client must still take the 5xx ladder,
    /// not fail the decode.
    fail_500_empty: Mutex<HashMap<String, u32>>,
    /// 400 "can't parse entities" for `sendMessage` /
    /// `editMessageText` calls carrying `parse_mode:
    /// "HTML"` (fix loop 1, tech B5 tests).
    fail_parse_html: Mutex<HashMap<String, u32>>,
    next_message_id: AtomicI64,
}

impl FakeBehavior {
    fn new() -> Self {
        Self {
            updates: Mutex::new(VecDeque::new()),
            raw_envelopes: Mutex::new(VecDeque::new()),
            fail_429: Mutex::new(HashMap::new()),
            fail_500: Mutex::new(HashMap::new()),
            fail_500_empty: Mutex::new(HashMap::new()),
            fail_parse_html: Mutex::new(HashMap::new()),
            next_message_id: AtomicI64::new(1),
        }
    }

    fn queue_update(&self, update: Value) {
        self.updates
            .lock()
            .expect("behavior lock")
            .push_back(update);
    }

    fn queue_raw_envelope(&self, envelope: Value) {
        self.raw_envelopes
            .lock()
            .expect("behavior lock")
            .push_back(envelope);
    }

    fn fail_429(&self, method: &str, times: u32, retry_after: i64) {
        self.fail_429
            .lock()
            .expect("behavior lock")
            .insert(method.to_string(), (times, retry_after));
    }

    fn fail_500(&self, method: &str, times: u32) {
        self.fail_500
            .lock()
            .expect("behavior lock")
            .insert(method.to_string(), times);
    }

    fn fail_500_empty(&self, method: &str, times: u32) {
        self.fail_500_empty
            .lock()
            .expect("behavior lock")
            .insert(method.to_string(), times);
    }

    fn fail_parse_html(&self, method: &str, times: u32) {
        self.fail_parse_html
            .lock()
            .expect("behavior lock")
            .insert(method.to_string(), times);
    }

    /// Answer one recorded request: (status, body).
    fn respond(&self, rec: &RequestRecord) -> (u16, Vec<u8>) {
        let method = rec.method.clone();
        if let Some((remaining, retry_after)) = self
            .fail_429
            .lock()
            .expect("behavior lock")
            .get_mut(&method)
            && *remaining > 0
        {
            *remaining -= 1;
            let body = serde_json::json!({
                "ok": false,
                "error_code": 429,
                "description": "Too Many Requests: retry after 1",
                "parameters": {"retry_after": *retry_after},
            });
            return (429, serde_json::to_vec(&body).expect("json"));
        }
        if let Some(remaining) = self
            .fail_500_empty
            .lock()
            .expect("behavior lock")
            .get_mut(&method)
            && *remaining > 0
        {
            *remaining -= 1;
            return (500, Vec::new());
        }
        if let Some(remaining) = self
            .fail_500
            .lock()
            .expect("behavior lock")
            .get_mut(&method)
            && *remaining > 0
        {
            *remaining -= 1;
            let body = serde_json::json!({
                "ok": false,
                "error_code": 500,
                "description": "Internal Server Error",
            });
            return (500, serde_json::to_vec(&body).expect("json"));
        }
        let ok = |result: Value| -> (u16, Vec<u8>) {
            let body = serde_json::json!({"ok": true, "result": result});
            (200, serde_json::to_vec(&body).expect("json"))
        };
        // 400 "can't parse entities" for HTML attempts
        // (Markdown-fallback tests): only when the call
        // carries parse_mode "HTML".
        let parse_fails = |rec: &RequestRecord| -> bool {
            let is_html = rec.json().get("parse_mode").and_then(Value::as_str) == Some("HTML");
            if !is_html {
                return false;
            }
            self.fail_parse_html
                .lock()
                .expect("behavior lock")
                .get_mut(&method)
                .is_some_and(|remaining| {
                    if *remaining > 0 {
                        *remaining -= 1;
                        true
                    } else {
                        false
                    }
                })
        };
        let parse_error = || -> (u16, Vec<u8>) {
            let body = serde_json::json!({
                "ok": false,
                "error_code": 400,
                "description": "Bad Request: can't parse entities: Character '>' is reserved and must be escaped with the preceding '\\'",
            });
            (400, serde_json::to_vec(&body).expect("json"))
        };
        match method.as_str() {
            "getMe" => ok(serde_json::json!({
                "id": 1, "is_bot": true, "first_name": "Test", "username": "testbot",
            })),
            "getUpdates" => {
                // A queued raw envelope wins over the
                // update queue: served verbatim, one per
                // poll, with no offset filtering.
                if let Some(envelope) = self
                    .raw_envelopes
                    .lock()
                    .expect("behavior lock")
                    .pop_front()
                {
                    return (200, serde_json::to_vec(&envelope).expect("json"));
                }
                let offset = rec
                    .json()
                    .get("offset")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                let mut queue = self.updates.lock().expect("behavior lock");
                let mut batch = Vec::new();
                while let Some(front) = queue.front() {
                    let id = front.get("update_id").and_then(Value::as_i64).unwrap_or(0);
                    if id < offset {
                        queue.pop_front();
                        continue;
                    }
                    batch.push(queue.pop_front().expect("front checked"));
                }
                ok(Value::Array(batch))
            }
            "sendMessage" => {
                if parse_fails(rec) {
                    return parse_error();
                }
                let mid = self.next_message_id.fetch_add(1, Ordering::SeqCst);
                let chat_id = rec
                    .json()
                    .get("chat_id")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                ok(serde_json::json!({
                    "message_id": mid,
                    "chat": {"id": chat_id, "type": "private"},
                    "date": 0, "text": "",
                }))
            }
            "editMessageText" => {
                if parse_fails(rec) {
                    return parse_error();
                }
                ok(Value::Bool(true))
            }
            "getMyCommands" => ok(Value::Array(vec![])),
            "getFile" => ok(serde_json::json!({
                "file_id": "f1", "file_path": "x/y", "file_size": 4,
            })),
            // Multipart uploads return a message object,
            // like sendMessage (the body is multipart, not
            // JSON, so `chat_id` reads as 0 here — the
            // tests only assert the message id + body).
            "sendDocument" | "sendPhoto" | "sendVideo" | "sendAudio" => {
                let mid = self.next_message_id.fetch_add(1, Ordering::SeqCst);
                ok(serde_json::json!({
                    "message_id": mid,
                    "chat": {"id": 0, "type": "private"},
                    "date": 0, "text": "",
                }))
            }
            _ => ok(Value::Bool(true)),
        }
    }
}

struct FakeServer {
    port: u16,
    records: Arc<Mutex<Vec<RequestRecord>>>,
    behavior: Arc<FakeBehavior>,
}

impl FakeServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("INVARIANT: fake server binds loopback");
        let port = listener.local_addr().expect("listener addr").port();
        let records: Arc<Mutex<Vec<RequestRecord>>> = Arc::new(Mutex::new(Vec::new()));
        let behavior = Arc::new(FakeBehavior::new());
        let records_clone = Arc::clone(&records);
        let behavior_clone = Arc::clone(&behavior);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let records = Arc::clone(&records_clone);
                let behavior = Arc::clone(&behavior_clone);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut byte = [0u8; 1];
                    let mut header_end: Option<usize> = None;
                    while buf.len() < 65536 {
                        match socket.read(&mut byte).await {
                            Ok(0) => return,
                            Ok(_) => {
                                buf.push(byte[0]);
                                if buf.ends_with(b"\r\n\r\n") {
                                    header_end = Some(buf.len());
                                    break;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                    let Some(header_len) = header_end else {
                        return;
                    };
                    let header_text = String::from_utf8_lossy(&buf[..header_len]).into_owned();
                    let mut lines = header_text.lines();
                    let request_line = lines.next().unwrap_or("").to_string();
                    let mut parts = request_line.split_whitespace();
                    let _http_method = parts.next().unwrap_or("").to_string();
                    let path = parts.next().unwrap_or("").to_string();
                    let mut headers = HashMap::new();
                    for line in lines {
                        if let Some((k, v)) = line.split_once(':') {
                            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                        }
                    }
                    let content_length: usize = headers
                        .get("content-length")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let mut body = Vec::new();
                    let mut remaining = content_length;
                    while remaining > 0 {
                        let mut chunk = vec![0u8; remaining.min(8192)];
                        match socket.read(&mut chunk).await {
                            Ok(0) => break,
                            Ok(n) => {
                                body.extend_from_slice(&chunk[..n]);
                                remaining -= n;
                            }
                            Err(_) => return,
                        }
                    }
                    let method = path.rsplit('/').next().unwrap_or("").to_string();
                    let rec = RequestRecord { method, body };
                    let (status, resp_body) = behavior.respond(&rec);
                    if rec.method == "getUpdates"
                        && resp_body.as_slice() == b"{\"ok\":true,\"result\":[]}"
                    {
                        // Empty poll: pace the loop like a
                        // long-poll (10ms). Without this a
                        // running Bot re-polls with zero
                        // delay and spins the executor at
                        // thousands of polls/sec; under a
                        // full parallel run that starved a
                        // sibling test past its 10s wait
                        // (offset test flaked 2/3 full runs,
                        // passed alone in 0.03s). Production
                        // polls long-poll up to POLL_TIMEOUT,
                        // so the pacing models reality.
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    records.lock().expect("records lock").push(rec);
                    let resp = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        resp_body.len()
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    let _ = socket.write_all(&resp_body).await;
                    let _ = socket.flush().await;
                });
            }
        });
        Self {
            port,
            records,
            behavior,
        }
    }

    /// Requests to `method` so far.
    fn count_method(&self, method: &str) -> usize {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .filter(|r| r.method == method)
            .count()
    }

    /// Text of the last `sendMessage` request (`text` param).
    fn last_send_text(&self) -> Option<String> {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .rev()
            .find(|r| r.method == "sendMessage")
            .and_then(|r| r.json().get("text")?.as_str().map(str::to_string))
    }

    /// All `sendMessage` texts so far, in order.
    fn send_texts(&self) -> Vec<String> {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .filter(|r| r.method == "sendMessage")
            .filter_map(|r| r.json().get("text")?.as_str().map(str::to_string))
            .collect()
    }

    /// All `answerCallbackQuery` texts so far, in order
    /// (empty string when the call carried no text).
    fn answer_texts(&self) -> Vec<String> {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .filter(|r| r.method == "answerCallbackQuery")
            .map(|r| {
                r.json()
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            })
            .collect()
    }

    /// Raw body of the last request to `method`, as text
    /// (for multipart assertions: the body is not JSON).
    fn last_request_body(&self, method: &str) -> Option<String> {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .rev()
            .find(|r| r.method == method)
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
    }

    /// `text` params of all requests to `method` so far,
    /// in order.
    fn request_texts(&self, method: &str) -> Vec<String> {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .filter(|r| r.method == method)
            .filter_map(|r| r.json().get("text")?.as_str().map(str::to_string))
            .collect()
    }

    /// `parse_mode` params of all requests to `method` so
    /// far, in order (`None` when the call carried none).
    fn request_parse_modes(&self, method: &str) -> Vec<Option<String>> {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .filter(|r| r.method == method)
            .map(|r| {
                r.json()
                    .get("parse_mode")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect()
    }

    /// `offset` params of all `getUpdates` requests so far,
    /// in order.
    fn get_updates_offsets(&self) -> Vec<i64> {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .filter(|r| r.method == "getUpdates")
            .map(|r| r.json().get("offset").and_then(Value::as_i64).unwrap_or(0))
            .collect()
    }
}

// ----------------------------------------------------------------
// Fake services (the M5b/M4b seam, with call recording)
// ----------------------------------------------------------------

struct FakeServicesInner {
    calls: Vec<String>,
    sessions: Vec<SessionRow>,
    new_chat: NewChatOutcome,
    status: String,
    history: String,
    unread: String,
    feed: String,
    goals: String,
    goal: String,
    usage: String,
    wake: String,
    ideas: Vec<IdeaCard>,
    files: Vec<SharedFileRow>,
    approvals: Vec<Approval>,
    fs_outcome: Option<FsOutcome>,
    update: String,
    raw: String,
    save_cookies: String,
    /// When true, `save_login_cookies` fails (fix loop 1,
    /// safety N6 test).
    save_cookies_err: bool,
    downloaded: DownloadedFile,
    stop_result: bool,
}

impl Default for FakeServicesInner {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            sessions: Vec::new(),
            new_chat: NewChatOutcome {
                session_id: String::new(),
                title: String::new(),
                reply: String::new(),
            },
            status: String::new(),
            history: String::new(),
            unread: String::new(),
            feed: String::new(),
            goals: String::new(),
            goal: String::new(),
            usage: String::new(),
            wake: String::new(),
            ideas: Vec::new(),
            files: Vec::new(),
            approvals: Vec::new(),
            fs_outcome: None,
            update: String::new(),
            raw: String::new(),
            save_cookies: String::new(),
            save_cookies_err: false,
            downloaded: DownloadedFile {
                name: String::new(),
                data: Vec::new(),
                mime: None,
            },
            stop_result: false,
        }
    }
}

struct FakeServices {
    inner: Mutex<FakeServicesInner>,
}

impl Default for FakeServices {
    fn default() -> Self {
        Self {
            inner: Mutex::new(FakeServicesInner {
                status: "status ok".to_string(),
                history: "history".to_string(),
                unread: "{}".to_string(),
                feed: "feed".to_string(),
                goals: "goals".to_string(),
                goal: "{}".to_string(),
                usage: "usage".to_string(),
                wake: "wake".to_string(),
                update: "update ok".to_string(),
                raw: "{}".to_string(),
                save_cookies: "✅ Cookies saved and working (VM <code>v1</code>).".to_string(),
                downloaded: DownloadedFile {
                    name: "f.txt".to_string(),
                    data: vec![1, 2, 3],
                    mime: None,
                },
                fs_outcome: Some(FsOutcome::Text("fs ok".to_string())),
                ..FakeServicesInner::default()
            }),
        }
    }
}

impl FakeServices {
    fn new() -> Self {
        Self::default()
    }

    fn record(&self, call: String) {
        self.inner.lock().expect("services lock").calls.push(call);
    }

    fn get<T>(&self, f: impl FnOnce(&FakeServicesInner) -> T) -> T {
        f(&self.inner.lock().expect("services lock"))
    }

    fn calls(&self) -> Vec<String> {
        self.get(|i| i.calls.clone())
    }

    fn has_call(&self, prefix: &str) -> bool {
        self.calls().iter().any(|c| c.starts_with(prefix))
    }

    fn call_count(&self, prefix: &str) -> usize {
        self.calls()
            .iter()
            .filter(|c| c.starts_with(prefix))
            .count()
    }

    fn set_save_cookies_fail(&self, fail: bool) {
        self.inner.lock().expect("services lock").save_cookies_err = fail;
    }
}

impl BotServices for FakeServices {
    fn start_turn(
        &self,
        chat_id: i64,
        text: String,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.record(format!("start_turn:{chat_id}:{text}"));
        Box::pin(async move {})
    }

    fn stop_turn(
        &self,
        chat_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, BotError>> + Send + '_>> {
        self.record(format!("stop_turn:{chat_id}"));
        let r = self.get(|i| i.stop_result);
        Box::pin(async move { Ok(r) })
    }

    fn wait_turns(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {})
    }

    fn resume_turn(
        &self,
        chat_id: i64,
        session_id: &str,
        title: &str,
        after_seq: i64,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.record(format!(
            "resume_turn:{chat_id}:{session_id}:{title}:{after_seq}"
        ));
        Box::pin(async move {})
    }

    fn list_sessions(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SessionRow>, BotError>> + Send + '_>> {
        self.record("list_sessions".to_string());
        let rows = self.get(|i| i.sessions.clone());
        Box::pin(async move { Ok(rows) })
    }

    fn status_text(
        &self,
        chat_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record(format!("status_text:{chat_id}"));
        let t = self.get(|i| i.status.clone());
        Box::pin(async move { Ok(t) })
    }

    fn new_chat(
        &self,
        chat_id: i64,
        title: &str,
    ) -> Pin<Box<dyn Future<Output = Result<NewChatOutcome, BotError>> + Send + '_>> {
        self.record(format!("new_chat:{chat_id}:{title}"));
        let o = self.get(|i| i.new_chat.clone());
        Box::pin(async move { Ok(o) })
    }

    fn history_text(
        &self,
        chat_id: i64,
        n: usize,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record(format!("history_text:{chat_id}:{n}"));
        let t = self.get(|i| i.history.clone());
        Box::pin(async move { Ok(t) })
    }

    fn unread_text(
        &self,
        chat_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record(format!("unread_text:{chat_id}"));
        let t = self.get(|i| i.unread.clone());
        Box::pin(async move { Ok(t) })
    }

    fn rename_chat(
        &self,
        chat_id: i64,
        title: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        self.record(format!("rename_chat:{chat_id}:{title}"));
        Box::pin(async move { Ok(()) })
    }

    fn session_op(
        &self,
        chat_id: i64,
        session_id: &str,
        op: SessionOp,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        self.record(format!("session_op:{chat_id}:{session_id}:{op:?}"));
        Box::pin(async move { Ok(()) })
    }

    fn delete_chat(
        &self,
        chat_id: i64,
        session_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        self.record(format!("delete_chat:{chat_id}:{session_id}"));
        Box::pin(async move { Ok(()) })
    }

    fn pending_approvals(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Approval>, BotError>> + Send + '_>> {
        self.record("pending_approvals".to_string());
        let rows = self.get(|i| i.approvals.clone());
        Box::pin(async move { Ok(rows) })
    }

    fn decide_approval(
        &self,
        approval_id: &str,
        decision: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        self.record(format!("decide_approval:{approval_id}:{decision}"));
        Box::pin(async move { Ok(()) })
    }

    fn files_list(
        &self,
        chat_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SharedFileRow>, BotError>> + Send + '_>> {
        self.record(format!("files_list:{chat_id}"));
        let rows = self.get(|i| i.files.clone());
        Box::pin(async move { Ok(rows) })
    }

    fn download_file(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<DownloadedFile, BotError>> + Send + '_>> {
        self.record(format!("download_file:{path}"));
        let f = self.get(|i| i.downloaded.clone());
        Box::pin(async move { Ok(f) })
    }

    fn feed_text(
        &self,
        limit: usize,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record(format!("feed_text:{limit}"));
        let t = self.get(|i| i.feed.clone());
        Box::pin(async move { Ok(t) })
    }

    fn goals_text(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record("goals_text".to_string());
        let t = self.get(|i| i.goals.clone());
        Box::pin(async move { Ok(t) })
    }

    fn goal_text(
        &self,
        id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record(format!("goal_text:{id}"));
        let t = self.get(|i| i.goal.clone());
        Box::pin(async move { Ok(t) })
    }

    fn ideas_list(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IdeaCard>, BotError>> + Send + '_>> {
        self.record("ideas_list".to_string());
        let rows = self.get(|i| i.ideas.clone());
        Box::pin(async move { Ok(rows) })
    }

    fn execute_idea(
        &self,
        card_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record(format!("execute_idea:{card_id}"));
        Box::pin(async move { Ok("executed".to_string()) })
    }

    fn usage_text(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record("usage_text".to_string());
        let t = self.get(|i| i.usage.clone());
        Box::pin(async move { Ok(t) })
    }

    fn wake(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record("wake".to_string());
        let t = self.get(|i| i.wake.clone());
        Box::pin(async move { Ok(t) })
    }

    fn fs_run(
        &self,
        chat_id: i64,
        arg: &str,
    ) -> Pin<Box<dyn Future<Output = Result<FsOutcome, BotError>> + Send + '_>> {
        self.record(format!("fs_run:{chat_id}:{arg}"));
        let o = self.get(|i| i.fs_outcome.clone().expect("fs outcome set"));
        Box::pin(async move { Ok(o) })
    }

    fn fs_delete(
        &self,
        path: &str,
        recursive: bool,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record(format!("fs_delete:{path}:{recursive}"));
        let path = path.to_string();
        Box::pin(async move { Ok(format!("🗑 Deleted {path}")) })
    }

    fn update_check(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record("update_check".to_string());
        let t = self.get(|i| i.update.clone());
        Box::pin(async move { Ok(t) })
    }

    fn raw_call(
        &self,
        method: &str,
        params_json: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record(format!("raw_call:{method}:{params_json}"));
        let t = self.get(|i| i.raw.clone());
        Box::pin(async move { Ok(t) })
    }

    fn save_login_cookies(
        &self,
        chat_id: i64,
        user_id: i64,
        cookies_text: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record(format!("save_login_cookies:{chat_id}:{user_id}"));
        let _ = cookies_text;
        let (fail, t) = self.get(|i| (i.save_cookies_err, i.save_cookies.clone()));
        Box::pin(async move {
            if fail {
                Err(BotError::Validation("simulated save failure".to_string()))
            } else {
                Ok(t)
            }
        })
    }

    fn inbound_media(
        &self,
        chat_id: i64,
        media: castctl_telegram::InboxMedia,
        caption: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        self.record(format!("inbound_media:{chat_id}:{}:{caption}", media.kind));
        Box::pin(async move { Ok(()) })
    }
}

/// Test decider: always succeeds.
struct OkDecider;

impl Decider for OkDecider {
    fn decide(
        &self,
        _approval_id: &str,
        _decision: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        Box::pin(async move { Ok(()) })
    }
}

// ----------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------

fn test_api(port: u16) -> Arc<BotApi> {
    Arc::new(BotApi::new(
        Arc::new(DirectDialer::new()) as Arc<dyn Dialer>,
        BotApiConfig::plaintext(FAKE_TOKEN.to_string(), DialTarget::new("127.0.0.1", port)),
    ))
}

fn test_claims() -> Arc<ClaimManager> {
    Arc::new(ClaimManager::new(
        Arc::new(OkDecider),
        Duration::from_secs(15),
    ))
}

fn test_config(owner_set: bool) -> CommandHandlerConfig {
    test_config_with_cookies(owner_set, PathBuf::new(), String::new())
}

fn test_config_with_cookies(
    owner_set: bool,
    cookies_file: PathBuf,
    vm_id: String,
) -> CommandHandlerConfig {
    CommandHandlerConfig {
        profile_name: "no1".to_string(),
        owner_id: OWNER_UID,
        owner_id_set: owner_set,
        block_auto_approve: false,
        block_auto_allow_once: false,
        cookies_file,
        vm_id,
    }
}

fn test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "castctl-telegram-test-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("test dir");
    dir
}

fn test_state(name: &str) -> (Arc<TelegramStateStore>, PathBuf) {
    let dir = test_dir(name);
    let path = dir.join("telegram-state.json");
    let store = TelegramStateStore::load(path.clone()).expect("state load");
    (Arc::new(store), dir)
}

fn msg_update(id: i64, chat_id: i64, uid: i64, text: &str) -> Value {
    serde_json::json!({
        "update_id": id,
        "message": {
            "message_id": id,
            "from": {"id": uid, "is_bot": false, "first_name": "T"},
            "chat": {"id": chat_id, "type": "private"},
            "date": 0,
            "text": text,
        },
    })
}

async fn wait_until<F>(timeout: Duration, mut cond: F)
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while !cond() {
        if start.elapsed() > timeout {
            panic!("condition not met within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn make_bot(
    server: &FakeServer,
    state: Arc<TelegramStateStore>,
    services: Arc<FakeServices>,
    allowed: Vec<i64>,
    owner_set: bool,
) -> Arc<Bot> {
    Bot::new(
        test_api(server.port),
        state,
        Arc::new(CallbackRegistry::new()),
        test_claims(),
        services as Arc<dyn BotServices>,
        test_config(owner_set),
        BotSettings {
            allowed_user_ids: allowed,
            backoff_ladder: vec![Duration::from_millis(50)],
        },
    )
    .await
    .expect("bot construction (getMe)")
}

fn make_handler(
    server: &FakeServer,
    state: Arc<TelegramStateStore>,
    services: Arc<FakeServices>,
) -> CommandHandler {
    make_handler_with_config(server, state, services, test_config(true))
}

fn make_handler_with_config(
    server: &FakeServer,
    state: Arc<TelegramStateStore>,
    services: Arc<FakeServices>,
    config: CommandHandlerConfig,
) -> CommandHandler {
    CommandHandler::new(
        test_api(server.port),
        state,
        Arc::new(CallbackRegistry::new()),
        test_claims(),
        services as Arc<dyn BotServices>,
        config,
    )
}

fn mc(chat_id: i64, uid: i64, text: &str) -> MessageContext {
    MessageContext {
        chat_id,
        user_id: uid,
        text: text.to_string(),
        message_id: 1,
        media: None,
        caption: String::new(),
        is_document: false,
    }
}

// ----------------------------------------------------------------
// (a) Routing table: all 30 commands route; unknown replies
// ----------------------------------------------------------------

#[tokio::test]
async fn routing_table_all_30() {
    let server = FakeServer::start().await;
    let services = Arc::new(FakeServices::new());
    let (state, _dir) = test_state("routing");
    // Side-chat mapping for the commands that need one.
    state
        .set_chat(
            100,
            ChatEntry {
                session_id: "s1".to_string(),
                title: "Side".to_string(),
            },
        )
        .expect("set chat");
    let handler = make_handler(&server, Arc::clone(&state), Arc::clone(&services));

    // (name, arg, expected service-call prefix or send text)
    let cases: &[(&str, &str, &str)] = &[
        ("start", "", "send:👋 Connected"),
        ("help", "", "send:<b>Muse on Telegram</b>"),
        ("stop", "", "call:stop_turn:100"),
        ("status", "", "call:status_text:100"),
        ("chats", "", "call:list_sessions"),
        ("main", "", "send:💬 Now in: <b>main chat</b>"),
        ("new", "Title", "call:new_chat:100:Title"),
        ("history", "5", "call:history_text:100:5"),
        ("unread", "", "call:unread_text:100"),
        ("rename", "New", "call:rename_chat:100:New"),
        ("pin", "", "call:session_op:100:s1:Pin"),
        ("unpin", "", "call:session_op:100:s1:Unpin"),
        ("archive", "", "call:session_op:100:s1:Archive"),
        ("unarchive", "", "call:session_op:100:s1:Unarchive"),
        ("delete", "", "send:Delete side chat <b>Side</b> for good?"),
        ("approvals", "", "call:pending_approvals"),
        ("autoapprove", "", "send:Auto-approve is <b>off</b>"),
        ("watch", "", "send:👀 Watch is <b>off</b>."),
        ("files", "", "call:files_list:100"),
        ("feed", "", "call:feed_text:10"),
        ("goals", "", "call:goals_text"),
        ("goal", "g1", "call:goal_text:g1"),
        ("ideas", "", "call:ideas_list"),
        ("usage", "", "call:usage_text"),
        ("wake", "", "call:wake"),
        ("fs", "ls /", "call:fs_run:100:ls /"),
        ("profile", "", "send:Serving profile: <b>no1</b>."),
        ("update", "", "call:update_check"),
        ("login", "", "send:🔑 Send the muse.ai cookies now"),
        ("raw", "chat.list", "call:raw_call:chat.list:"),
    ];
    assert_eq!(cases.len(), 30, "all 30 commands must be covered");
    for (name, arg, expect) in cases {
        // `/main` and `/archive` reset the mapping; restore
        // the side-chat mapping before every case.
        state
            .set_chat(
                100,
                ChatEntry {
                    session_id: "s1".to_string(),
                    title: "Side".to_string(),
                },
            )
            .expect("set chat");
        let before_sends = server.send_texts().len();
        let before_calls = services.calls().len();
        handler
            .dispatch_message(mc(100, OWNER_UID, format!("/{name} {arg}").trim_end()))
            .await
            .expect("dispatch");
        if let Some(prefix) = expect.strip_prefix("call:") {
            assert!(
                services.calls()[before_calls..]
                    .iter()
                    .any(|c| c.starts_with(prefix)),
                "/{name}: expected service call starting with {prefix:?}, got {:?}",
                &services.calls()[before_calls..]
            );
        } else if let Some(prefix) = expect.strip_prefix("send:") {
            let sends = server.send_texts();
            assert!(
                sends[before_sends..].iter().any(|t| t.starts_with(prefix)),
                "/{name}: expected send starting with {prefix:?}, got {:?}",
                &sends[before_sends..]
            );
        } else {
            panic!("bad expectation {expect}");
        }
    }
    // Unknown name replies `Unknown command`; invalid name
    // (digits) is escaped the same way.
    handler
        .dispatch_message(mc(100, OWNER_UID, "/bogus arg"))
        .await
        .expect("dispatch");
    assert_eq!(
        server.last_send_text().as_deref(),
        Some("Unknown command /bogus. /help lists them.")
    );
    handler
        .dispatch_message(mc(100, OWNER_UID, "/123abc"))
        .await
        .expect("dispatch");
    assert_eq!(
        server.last_send_text().as_deref(),
        Some("Unknown command /123abc. /help lists them.")
    );
    // `@botname` suffix and upper-case names still route.
    handler
        .dispatch_message(mc(100, OWNER_UID, "/HELP@testbot"))
        .await
        .expect("dispatch");
    assert_eq!(server.last_send_text().as_deref(), Some(COMMAND_HELP_TEXT));
}

// ----------------------------------------------------------------
// (b) Offset persistence across restart
// ----------------------------------------------------------------

#[tokio::test]
async fn offset_persists_across_restart() {
    let server = FakeServer::start().await;
    let dir = test_dir("offset");
    let path = dir.join("telegram-state.json");
    let services = Arc::new(FakeServices::new());
    server
        .behavior
        .queue_update(msg_update(10, 100, ALLOWED_UID, "hello"));
    server
        .behavior
        .queue_update(msg_update(11, 100, ALLOWED_UID, "hello again"));
    let state = Arc::new(TelegramStateStore::load(path.clone()).expect("state load"));
    let bot = make_bot(
        &server,
        Arc::clone(&state),
        Arc::clone(&services),
        vec![ALLOWED_UID],
        true,
    )
    .await;
    let run = tokio::spawn({
        let bot = Arc::clone(&bot);
        async move { bot.run().await }
    });
    // 10s, not 5s: under a full parallel run (8 cores,
    // ~20 hot poll loops + the lib suite) this test once
    // starved past 5s with zero turns, then passed alone
    // in 0.03s — the wait is a scheduling margin, not a
    // behaviour bound (fix loop 1 flake-hardening).
    wait_until(Duration::from_secs(10), || {
        services.call_count("start_turn") >= 2
    })
    .await;
    bot.request_shutdown();
    run.await.expect("run task").expect("run ok");
    assert_eq!(state.offset(), 11, "state offset after first run");

    // Restart: the server offers 11 again and 12; only 12
    // may be handled (offset 11+1 = 12).
    server
        .behavior
        .queue_update(msg_update(11, 100, ALLOWED_UID, "hello again"));
    server
        .behavior
        .queue_update(msg_update(12, 100, ALLOWED_UID, "third"));
    let state2 = Arc::new(TelegramStateStore::load(path.clone()).expect("state reload"));
    assert_eq!(state2.offset(), 11, "reloaded offset");
    let bot2 = make_bot(
        &server,
        Arc::clone(&state2),
        Arc::clone(&services),
        vec![ALLOWED_UID],
        true,
    )
    .await;
    let run2 = tokio::spawn({
        let bot = Arc::clone(&bot2);
        async move { bot.run().await }
    });
    wait_until(Duration::from_secs(10), || {
        services.call_count("start_turn") >= 3
    })
    .await;
    bot2.request_shutdown();
    run2.await.expect("run task").expect("run ok");
    assert_eq!(state2.offset(), 12, "state offset after restart run");
    assert_eq!(
        services.call_count("start_turn"),
        3,
        "update 11 must not be handled twice"
    );
}

// ----------------------------------------------------------------
// (c) Duplicate update in one batch handled once
// ----------------------------------------------------------------

#[tokio::test]
async fn duplicate_update_handled_once() {
    let server = FakeServer::start().await;
    let (state, _dir) = test_state("dup");
    let services = Arc::new(FakeServices::new());
    let dup = msg_update(5, 100, ALLOWED_UID, "hello");
    server.behavior.queue_update(dup.clone());
    server.behavior.queue_update(dup);
    let bot = make_bot(
        &server,
        state,
        Arc::clone(&services),
        vec![ALLOWED_UID],
        true,
    )
    .await;
    let run = tokio::spawn({
        let bot = Arc::clone(&bot);
        async move { bot.run().await }
    });
    wait_until(Duration::from_secs(5), || {
        services.call_count("start_turn") >= 1
    })
    .await;
    // Give the poll loop time to see the duplicate too.
    tokio::time::sleep(Duration::from_millis(300)).await;
    bot.request_shutdown();
    run.await.expect("run task").expect("run ok");
    assert_eq!(
        services.call_count("start_turn"),
        1,
        "same update_id twice in one batch = one turn"
    );
}

// ----------------------------------------------------------------
// (d) 429 backoff: max 2 retries, retry_after + 0.5s sleeps
// ----------------------------------------------------------------

#[tokio::test]
async fn backoff_429_retries_twice_then_succeeds() {
    let server = FakeServer::start().await;
    server.behavior.fail_429("sendMessage", 2, 1);
    let services = Arc::new(FakeServices::new());
    let (state, _dir) = test_state("backoff");
    let handler = make_handler(&server, state, services);
    let start = Instant::now();
    handler
        .dispatch_message(mc(100, OWNER_UID, "/help"))
        .await
        .expect("dispatch");
    let elapsed = start.elapsed();
    assert_eq!(
        server.count_method("sendMessage"),
        3,
        "initial attempt + 2 retries"
    );
    assert!(
        elapsed >= Duration::from_millis(3000),
        "two (1s + 0.5s) sleeps expected, got {elapsed:?}"
    );
    assert_eq!(
        server.last_send_text().as_deref(),
        Some(COMMAND_HELP_TEXT),
        "the third attempt succeeds"
    );
}

// ----------------------------------------------------------------
// (d2) 5xx backoff in the poll loop: 2×500 then success
// ----------------------------------------------------------------

#[tokio::test]
async fn backoff_5xx_poll_loop_retries() {
    let server = FakeServer::start().await;
    server.behavior.fail_500("getUpdates", 2);
    let (state, _dir) = test_state("backoff5xx");
    let services = Arc::new(FakeServices::new());
    server
        .behavior
        .queue_update(msg_update(30, 100, ALLOWED_UID, "hello"));
    let bot = make_bot(
        &server,
        state,
        Arc::clone(&services),
        vec![ALLOWED_UID],
        true,
    )
    .await;
    let run = tokio::spawn({
        let bot = Arc::clone(&bot);
        async move { bot.run().await }
    });
    wait_until(Duration::from_secs(5), || {
        services.call_count("start_turn") >= 1
    })
    .await;
    bot.request_shutdown();
    run.await.expect("run task").expect("run ok");
    // Without the retry the update would never arrive
    // (the two 500s must be retried, then the third poll
    // succeeds). The count is >= 3, not == 3: the loop
    // keeps polling empty batches until shutdown lands.
    assert!(
        server.count_method("getUpdates") >= 3,
        "2×500 retried, then success"
    );
    assert_eq!(
        services.call_count("start_turn"),
        1,
        "the update is handled exactly once"
    );
}

// ----------------------------------------------------------------
// (e) Stranger rejection: owner / allowed / stranger
// ----------------------------------------------------------------

#[tokio::test]
async fn stranger_rejection_three_cases() {
    let server = FakeServer::start().await;
    let (state, _dir) = test_state("stranger");
    let services = Arc::new(FakeServices::new());
    // Owner admitted everywhere (owner command works).
    server
        .behavior
        .queue_update(msg_update(20, 100, OWNER_UID, "/profile"));
    // Allowed non-owner: owner command refused with the
    // fixed sentence, admitted elsewhere (/help works).
    server
        .behavior
        .queue_update(msg_update(21, 101, ALLOWED_UID, "/profile"));
    server
        .behavior
        .queue_update(msg_update(22, 101, ALLOWED_UID, "/help"));
    // Stranger: dropped silently (no reply, no state change).
    server
        .behavior
        .queue_update(msg_update(23, 102, STRANGER_UID, "hello"));
    server
        .behavior
        .queue_update(msg_update(24, 102, STRANGER_UID, "/profile"));
    let bot = make_bot(
        &server,
        Arc::clone(&state),
        Arc::clone(&services),
        vec![ALLOWED_UID],
        true,
    )
    .await;
    let run = tokio::spawn({
        let bot = Arc::clone(&bot);
        async move { bot.run().await }
    });
    wait_until(Duration::from_secs(5), || {
        server
            .send_texts()
            .iter()
            .any(|t| t.starts_with("Serving profile:"))
            && server.send_texts().len() >= 3
    })
    .await;
    // Let the stranger updates arrive and be dropped.
    tokio::time::sleep(Duration::from_millis(300)).await;
    bot.request_shutdown();
    run.await.expect("run task").expect("run ok");

    let sends = server.send_texts();
    assert_eq!(
        sends
            .iter()
            .filter(|t| t.starts_with("Serving profile:"))
            .count(),
        1,
        "only the owner ran /profile, got {sends:?}"
    );
    assert!(
        sends
            .iter()
            .any(|t| t == "Only the owner can use that command."),
        "allowed non-owner gets the fixed refusal, got {sends:?}"
    );
    assert!(
        sends.iter().any(|t| t == COMMAND_HELP_TEXT),
        "allowed non-owner is admitted to /help"
    );
    assert!(
        !services.has_call("start_turn"),
        "stranger 'hello' must never start a turn"
    );
    assert_eq!(
        sends.len(),
        3,
        "exactly three replies (profile + refusal + help); stranger silent, got {sends:?}"
    );
    // The stranger updates never advanced the state offset:
    // last accepted id is 22.
    assert_eq!(state.offset(), 22, "stranger updates do not advance offset");
}

// ----------------------------------------------------------------
// (f) /help byte-identical (integration: the sent text)
// ----------------------------------------------------------------

#[tokio::test]
async fn help_text_sent_byte_identical() {
    let server = FakeServer::start().await;
    let services = Arc::new(FakeServices::new());
    let (state, _dir) = test_state("help");
    let handler = make_handler(&server, state, services);
    handler
        .dispatch_message(mc(100, OWNER_UID, "/help"))
        .await
        .expect("dispatch");
    assert_eq!(server.last_send_text().as_deref(), Some(COMMAND_HELP_TEXT));
    // The constant itself is pinned to Go verbatim by the
    // unit test in commands.rs (`help_text_matches_go_verbatim`).
    assert!(COMMAND_MENU.len() == 30, "menu has 30 entries");
}

// ----------------------------------------------------------------
// (g) Token never appears in Debug / Display / summaries
// ----------------------------------------------------------------

#[test]
fn token_never_in_debug_or_display() {
    let api = BotApi::new(
        Arc::new(DirectDialer::new()) as Arc<dyn Dialer>,
        BotApiConfig::plaintext(FAKE_TOKEN.to_string(), DialTarget::new("127.0.0.1", 1)),
    );
    assert!(
        !format!("{api:?}").contains(FAKE_TOKEN),
        "BotApi Debug must redact the token"
    );
    let err = BotError::Api {
        code: 429,
        description: FAKE_TOKEN.to_string(),
        retry_after: Some(5),
    };
    assert!(
        !err.to_string().contains(FAKE_TOKEN),
        "BotError Display must never print the Api description"
    );
    assert!(
        !err.summary().contains(FAKE_TOKEN),
        "BotError summary must be fixed-vocabulary only"
    );
    let cfg = BotApiConfig::plaintext(FAKE_TOKEN.to_string(), DialTarget::new("127.0.0.1", 1));
    assert!(
        !format!("{cfg:?}").contains(FAKE_TOKEN),
        "BotApiConfig Debug must redact the token (fix loop 1, safety B2)"
    );
    let settings = BotSettings {
        allowed_user_ids: vec![ALLOWED_UID],
        backoff_ladder: vec![],
    };
    assert!(
        !format!("{settings:?}").contains(FAKE_TOKEN),
        "BotSettings Debug carries no token"
    );
}

// ----------------------------------------------------------------
// (h) SetCommands validation: zero API calls on failure
// ----------------------------------------------------------------

#[tokio::test]
async fn set_commands_validation_zero_calls() {
    let server = FakeServer::start().await;
    let (state, _dir) = test_state("setcmd");
    let services = Arc::new(FakeServices::new());
    let bot = make_bot(&server, state, services, vec![ALLOWED_UID], true).await;
    // Construction called getMe exactly once.
    assert_eq!(server.count_method("getMe"), 1);
    assert_eq!(server.count_method("setMyCommands"), 0);

    // Bad name (space + upper case).
    let bad = vec![("Bad Name".to_string(), "x".to_string())];
    assert!(bot.set_commands(&bad).await.is_err());
    // Duplicate name.
    let dup = vec![
        ("help".to_string(), "a".to_string()),
        ("help".to_string(), "b".to_string()),
    ];
    assert!(bot.set_commands(&dup).await.is_err());
    // Overlong description (257 runes).
    let long = vec![("help".to_string(), "x".repeat(257))];
    assert!(bot.set_commands(&long).await.is_err());
    // Empty description.
    let empty = vec![("help".to_string(), String::new())];
    assert!(bot.set_commands(&empty).await.is_err());
    assert_eq!(
        server.count_method("setMyCommands"),
        0,
        "validation failures must make zero API calls"
    );

    // A valid menu goes through exactly once.
    bot.set_menu_commands().await.expect("valid menu");
    assert_eq!(server.count_method("setMyCommands"), 1);
}

// ----------------------------------------------------------------
// Fix loop 1: malformed updates (red R3), offset overflow
// (red R4), 5xx empty body (red N1), 429 cancellation
// (tech B6), Markdown fallback (tech B5), /profile local
// (tech B9), raced decide tap (red N6), send_file markup
// (tech N6), download_media fast error (tech N14),
// /login save failure (safety N6), double start (tech N9)
// ----------------------------------------------------------------

/// Malformed shapes in one batch must not poison the loop
/// (fix loop 1, red R3): absent fields decode to Go's
/// zero values, good updates in the same batch are still
/// handled, and the loop progresses past a failed batch.
#[tokio::test]
async fn malformed_updates_do_not_poison_the_loop() {
    let server = FakeServer::start().await;
    let (state, _dir) = test_state("malformed");
    let services = Arc::new(FakeServices::new());
    // Batch 1: message missing `chat`, a good update, a
    // callback missing `from`, an update missing
    // `update_id`.
    let no_chat = serde_json::json!({"update_id": 1, "message": {
        "message_id": 1,
        "from": {"id": ALLOWED_UID, "is_bot": false, "first_name": "T"},
        "date": 0, "text": "no chat",
    }});
    let good = msg_update(2, 100, ALLOWED_UID, "good");
    let no_from = serde_json::json!({"update_id": 3, "callback_query": {
        "id": "q1",
        "message": {"message_id": 5, "from": {"id": ALLOWED_UID, "is_bot": false, "first_name": "T"}, "chat": {"id": 100, "type": "private"}, "date": 0, "text": "x"},
        "data": "c:abcdefgh",
    }});
    let no_id = serde_json::json!({"message": {
        "message_id": 9,
        "from": {"id": ALLOWED_UID, "is_bot": false, "first_name": "T"},
        "chat": {"id": 100, "type": "private"},
        "date": 0, "text": "no id",
    }});
    server.behavior.queue_raw_envelope(
        serde_json::json!({"ok": true, "result": [no_chat, good, no_from, no_id]}),
    );
    // Batch 2: `result` not an array → the whole batch
    // fails (Go parity: wrong-type fails the decode), but
    // the loop continues.
    server
        .behavior
        .queue_raw_envelope(serde_json::json!({"ok": true, "result": "not-an-array"}));
    // Batch 3: `ok: true` with no `result` → empty batch.
    server
        .behavior
        .queue_raw_envelope(serde_json::json!({"ok": true}));
    // Batch 4: a good update after the malformed ones.
    server.behavior.queue_raw_envelope(serde_json::json!({
        "ok": true, "result": [msg_update(5, 100, ALLOWED_UID, "after")],
    }));
    // Batch 5: a wrong-TYPE item is SKIPPED per item
    // (fix loop 3, red R6 — mirrors the pinned
    // library's `decodeUpdate`); the good item in the
    // same batch is still handled, and the offset
    // advances past the poison (its id is unreadable,
    // so the offset advances via the good item).
    let bad_type = serde_json::json!({"update_id": "six", "message": {
        "message_id": 6,
        "from": {"id": ALLOWED_UID, "is_bot": false, "first_name": "T"},
        "chat": {"id": 100, "type": "private"},
        "date": 0, "text": "bad",
    }});
    server.behavior.queue_raw_envelope(serde_json::json!({
        "ok": true,
        "result": [bad_type, msg_update(7, 100, ALLOWED_UID, "lost")],
    }));
    // Batch 6: the loop still progresses after the failed batch.
    server.behavior.queue_raw_envelope(serde_json::json!({
        "ok": true, "result": [msg_update(8, 100, ALLOWED_UID, "last")],
    }));
    let bot = make_bot(
        &server,
        Arc::clone(&state),
        Arc::clone(&services),
        vec![ALLOWED_UID],
        true,
    )
    .await;
    let run = tokio::spawn({
        let bot = Arc::clone(&bot);
        async move { bot.run().await }
    });
    wait_until(Duration::from_secs(10), || {
        services.call_count("start_turn") >= 6
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    bot.request_shutdown();
    run.await.expect("run task").expect("run ok");
    // Handled: "no chat" (chat 0), "good", "no id",
    // "after", "lost" (the good item in the wrong-type
    // batch — skipped poison, not a failed batch),
    // "last" = 6 turns. The callback missing `from`
    // (uid 0) was dropped; the wrong-type item itself
    // (unreadable id) became a zero update, dropped by
    // the allowlist.
    assert_eq!(services.call_count("start_turn"), 6);
    assert!(
        services.calls().iter().any(|c| c.contains("lost")),
        "the good item in a wrong-type batch IS handled, got {:?}",
        services.calls()
    );
    assert_eq!(
        state.offset(),
        8,
        "offset advances past the malformed batches"
    );
}

/// A wrong-TYPE item is SKIPPED per item and the
/// offset advances past it (fix loop 3, red R6):
/// mirrors the pinned Bot API library's `decodeUpdate`
/// (`go-telegram/bot v1.27.1-.../get_updates.go` —
/// "decodes one update on its own, so a single
/// undecodable update does not reject the whole batch").
/// A readable id advances the offset past the poison
/// even though the item itself is not delivered; an
/// unreadable id (wrong-type id, non-object element,
/// float id — Go's head-ID read fails on all of them)
/// becomes a zero `Update`, dropped by the allowlist
/// with the offset unchanged (Go's `offsetStuck` case),
/// and the REST of the batch is still delivered.
#[tokio::test]
async fn wrong_type_items_are_skipped_like_go() {
    let server = FakeServer::start().await;
    let (state, _dir) = test_state("wrong-type-skip");
    let services = Arc::new(FakeServices::new());
    // Batch 1: readable id (5), wrong-type nested field
    // (`chat` is a string, not an object) + a good update.
    let bad_chat = serde_json::json!({"update_id": 5, "message": {
        "message_id": 1,
        "from": {"id": ALLOWED_UID, "is_bot": false, "first_name": "T"},
        "chat": "oops",
        "date": 0, "text": "bad",
    }});
    server.behavior.queue_raw_envelope(serde_json::json!({
        "ok": true,
        "result": [bad_chat, msg_update(6, 100, ALLOWED_UID, "good")],
    }));
    // Batch 2: a non-object element, a float `update_id`
    // (5.5 — unreadable as i64), and a good update.
    let float_id = serde_json::json!({"update_id": 5.5, "message": {
        "message_id": 2,
        "from": {"id": ALLOWED_UID, "is_bot": false, "first_name": "T"},
        "chat": {"id": 100, "type": "private"},
        "date": 0, "text": "float",
    }});
    server.behavior.queue_raw_envelope(serde_json::json!({
        "ok": true,
        "result": ["junk", float_id, msg_update(7, 100, ALLOWED_UID, "after")],
    }));
    let bot = make_bot(
        &server,
        Arc::clone(&state),
        Arc::clone(&services),
        vec![ALLOWED_UID],
        true,
    )
    .await;
    let run = tokio::spawn({
        let bot = Arc::clone(&bot);
        async move { bot.run().await }
    });
    wait_until(Duration::from_secs(10), || {
        services.call_count("start_turn") >= 2
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    bot.request_shutdown();
    run.await.expect("run task").expect("run ok");
    // Handled: "good" (id 6) and "after" (id 7) = 2
    // turns. The poison items were skipped, never
    // delivered: "bad" (id 5, skipped, offset advanced
    // past it), "junk" and "float" (unreadable ids,
    // zero updates, dropped).
    assert_eq!(services.call_count("start_turn"), 2);
    assert!(
        services.calls().iter().any(|c| c.contains("good")),
        "good update after a readable-id poison is handled, got {:?}",
        services.calls()
    );
    assert!(
        services.calls().iter().any(|c| c.contains("after")),
        "good update after unreadable-id poisons is handled, got {:?}",
        services.calls()
    );
    assert_eq!(
        state.offset(),
        7,
        "offset advances past both poison batches"
    );
}

/// Explicit JSON `null` fields must not poison the loop
/// (fix loop 2, red R5): `null` decodes to Go's zero
/// value, the good updates in the same batch are still
/// handled, and the loop progresses. Covers every null
/// shape — `chat: null`, `update_id: null`, callback
/// `from: null`, `chat.id` / `chat.type: null`, a bare
/// `null` array element — plus a follow-up good batch.
#[tokio::test]
async fn null_fields_do_not_poison_the_loop() {
    let server = FakeServer::start().await;
    let (state, _dir) = test_state("null-fields");
    let services = Arc::new(FakeServices::new());
    // Batch 1: every null shape at once, with good
    // updates interleaved.
    let null_chat = serde_json::json!({"update_id": 1, "message": {
        "message_id": 1,
        "from": {"id": ALLOWED_UID, "is_bot": false, "first_name": "T"},
        "chat": null, "date": 0, "text": "null chat",
    }});
    let good = msg_update(2, 100, ALLOWED_UID, "good");
    let null_from = serde_json::json!({"update_id": 3, "callback_query": {
        "id": "q1", "from": null,
        "message": {"message_id": 5, "from": {"id": ALLOWED_UID, "is_bot": false, "first_name": "T"}, "chat": {"id": 100, "type": "private"}, "date": 0, "text": "x"},
        "data": "c:abcdefgh",
    }});
    let null_id = serde_json::json!({"update_id": null, "message": {
        "message_id": 9,
        "from": {"id": ALLOWED_UID, "is_bot": false, "first_name": "T"},
        "chat": {"id": 100, "type": "private"},
        "date": 0, "text": "null id",
    }});
    let null_chat_id = serde_json::json!({"update_id": 5, "message": {
        "message_id": 1,
        "from": {"id": ALLOWED_UID, "is_bot": false, "first_name": "T"},
        "chat": {"id": null, "type": null},
        "date": 0, "text": "null chat id",
    }});
    server
        .behavior
        .queue_raw_envelope(serde_json::json!({"ok": true, "result": [
            null_chat, good, null_from, null_id, serde_json::Value::Null, null_chat_id,
        ]}));
    // Batch 2: a good update after the null batch.
    server.behavior.queue_raw_envelope(serde_json::json!({
        "ok": true, "result": [msg_update(6, 100, ALLOWED_UID, "after")],
    }));
    let bot = make_bot(
        &server,
        Arc::clone(&state),
        Arc::clone(&services),
        vec![ALLOWED_UID],
        true,
    )
    .await;
    let run = tokio::spawn({
        let bot = Arc::clone(&bot);
        async move { bot.run().await }
    });
    wait_until(Duration::from_secs(10), || {
        services.call_count("start_turn") >= 5
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    bot.request_shutdown();
    run.await.expect("run task").expect("run ok");
    // Handled: "null chat" (chat 0), "good", "null id"
    // (update_id 0), "null chat id" (chat 0), "after" = 5
    // turns. The callback with `from: null` (uid 0) and
    // the bare `null` element (zero update, uid 0) were
    // dropped by the allowlist.
    assert_eq!(services.call_count("start_turn"), 5);
    assert_eq!(state.offset(), 6, "offset advances past the null batch");
}

/// `update_id` extremes must not wrap the offset (fix
/// loop 1, red R4): `i64::MAX` saturates, 0 / -1 /
/// `i64::MIN` are handled, and a restart polls with
/// offset `i64::MAX` without replaying anything.
#[tokio::test]
async fn offset_overflow_max_update_id() {
    let server = FakeServer::start().await;
    let (state, dir) = test_state("overflow");
    let services = Arc::new(FakeServices::new());
    server.behavior.queue_raw_envelope(serde_json::json!({
        "ok": true,
        "result": [
            msg_update(i64::MAX, 100, ALLOWED_UID, "max"),
            msg_update(0, 100, ALLOWED_UID, "zero"),
            msg_update(-1, 100, ALLOWED_UID, "minus one"),
            msg_update(i64::MIN, 100, ALLOWED_UID, "min"),
        ],
    }));
    let bot = make_bot(
        &server,
        Arc::clone(&state),
        Arc::clone(&services),
        vec![ALLOWED_UID],
        true,
    )
    .await;
    let run = tokio::spawn({
        let bot = Arc::clone(&bot);
        async move { bot.run().await }
    });
    wait_until(Duration::from_secs(5), || {
        services.call_count("start_turn") >= 4
    })
    .await;
    bot.request_shutdown();
    run.await.expect("run task").expect("run ok");
    assert_eq!(
        state.offset(),
        i64::MAX,
        "offset saturates at MAX, never wraps"
    );

    // Restart from the same state file: the next poll asks
    // with offset MAX and nothing is replayed.
    let polls_before = server.count_method("getUpdates");
    let path = dir.join("telegram-state.json");
    let state2 = Arc::new(TelegramStateStore::load(path).expect("state reload"));
    assert_eq!(state2.offset(), i64::MAX);
    let bot2 = make_bot(
        &server,
        Arc::clone(&state2),
        Arc::clone(&services),
        vec![ALLOWED_UID],
        true,
    )
    .await;
    let run2 = tokio::spawn({
        let bot = Arc::clone(&bot2);
        async move { bot.run().await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    bot2.request_shutdown();
    run2.await.expect("run task").expect("run ok");
    let new_offsets = &server.get_updates_offsets()[polls_before..];
    assert!(
        !new_offsets.is_empty() && new_offsets.iter().all(|o| *o == i64::MAX),
        "restart polls with offset MAX, got {new_offsets:?}"
    );
    assert_eq!(
        services.call_count("start_turn"),
        4,
        "no update is replayed after restart"
    );
}

/// A 5xx with an EMPTY (non-JSON) body still takes the
/// 5xx backoff ladder (fix loop 1, red N1).
#[tokio::test]
async fn backoff_5xx_empty_body_retries() {
    let server = FakeServer::start().await;
    server.behavior.fail_500_empty("getUpdates", 2);
    let (state, _dir) = test_state("backoff5xxempty");
    let services = Arc::new(FakeServices::new());
    server
        .behavior
        .queue_update(msg_update(40, 100, ALLOWED_UID, "hello"));
    let bot = make_bot(
        &server,
        state,
        Arc::clone(&services),
        vec![ALLOWED_UID],
        true,
    )
    .await;
    let run = tokio::spawn({
        let bot = Arc::clone(&bot);
        async move { bot.run().await }
    });
    wait_until(Duration::from_secs(5), || {
        services.call_count("start_turn") >= 1
    })
    .await;
    bot.request_shutdown();
    run.await.expect("run task").expect("run ok");
    assert!(
        server.count_method("getUpdates") >= 3,
        "2x500-empty retried, then success"
    );
    assert_eq!(
        services.call_count("start_turn"),
        1,
        "the update is handled exactly once"
    );
}

/// A 429 retry sleep on the handler path is cancelled by
/// shutdown (fix loop 1, tech B6): one attempt, no 60s
/// wait, `Cancelled` out.
#[tokio::test]
async fn handler_429_sleep_cancelled_by_shutdown() {
    let server = FakeServer::start().await;
    server.behavior.fail_429("sendMessage", 1, 60);
    let api = test_api(server.port);
    let signal = castctl_telegram::api::ShutdownSignal::new();
    api.set_shutdown_signal(Arc::clone(&signal));
    let start = Instant::now();
    let task = tokio::spawn({
        let api = Arc::clone(&api);
        async move {
            api.send_message_params(serde_json::json!({"chat_id": 100, "text": "hi"}))
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    signal.request();
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("must not hang on the 60s sleep")
        .expect("join");
    assert!(
        matches!(result, Err(BotError::Cancelled)),
        "expected Cancelled, got {result:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(5));
    assert_eq!(
        server.count_method("sendMessage"),
        1,
        "no retry after the cancel"
    );
}

/// A 429 retry sleep on the poll path is cancelled by
/// shutdown (fix loop 1, tech B6): the run returns
/// promptly instead of sleeping 60s.
#[tokio::test]
async fn poll_429_sleep_cancelled_by_shutdown() {
    let server = FakeServer::start().await;
    server.behavior.fail_429("getUpdates", 1, 60);
    let (state, _dir) = test_state("poll429");
    let services = Arc::new(FakeServices::new());
    let bot = make_bot(&server, state, services, vec![ALLOWED_UID], true).await;
    let start = Instant::now();
    let run = tokio::spawn({
        let bot = Arc::clone(&bot);
        async move { bot.run().await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    bot.request_shutdown();
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("run must return promptly, not sleep 60s")
        .expect("join")
        .expect("run ok");
    assert!(start.elapsed() < Duration::from_secs(5));
    assert_eq!(
        server.count_method("getUpdates"),
        1,
        "one poll, no retry after the cancel"
    );
}

/// A second `run()` returns "telegram: bot already
/// started" (fix loop 1, tech N9).
#[tokio::test]
async fn double_start_returns_already_started() {
    let server = FakeServer::start().await;
    let (state, _dir) = test_state("doublestart");
    let services = Arc::new(FakeServices::new());
    let bot = make_bot(&server, state, services, vec![ALLOWED_UID], true).await;
    let run = tokio::spawn({
        let bot = Arc::clone(&bot);
        async move { bot.run().await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let err = bot.run().await.expect_err("second run must fail");
    assert!(
        err.to_string().contains("telegram: bot already started"),
        "{err}"
    );
    bot.request_shutdown();
    run.await.expect("join").expect("first run ok");
}

/// Markdown fallback sends the ORIGINAL markdown text
/// (fix loop 1, tech B5); HTML fallback strips tags; an
/// over-limit Markdown body is truncated to 4096 runes
/// without losing its markdown.
#[tokio::test]
async fn markdown_fallback_keeps_original_text() {
    let server = FakeServer::start().await;
    let api = test_api(server.port);
    let sender = Sender::new(&api);
    // Markdown: HTML attempt fails once; the fallback must
    // be the original "**bold** and more", with no parse_mode.
    server.behavior.fail_parse_html("sendMessage", 1);
    sender
        .send_md(100, "**bold** and more", SendOptions::default())
        .await
        .expect("send_md");
    assert_eq!(server.count_method("sendMessage"), 2);
    assert_eq!(
        server.request_parse_modes("sendMessage"),
        vec![Some("HTML".to_string()), None],
        "first attempt HTML, fallback plain"
    );
    assert_eq!(
        server
            .request_texts("sendMessage")
            .last()
            .map(String::as_str),
        Some("**bold** and more"),
        "Markdown fallback keeps the original text"
    );
    // HTML: the fallback strips tags.
    server.behavior.fail_parse_html("sendMessage", 1);
    sender
        .send(100, "<b>bold</b>", SendOptions::default())
        .await
        .expect("send html");
    assert_eq!(
        server.last_send_text().as_deref(),
        Some("bold"),
        "HTML fallback strips tags"
    );
    // Over-limit Markdown via `send_one` (no splitting):
    // the HTML attempt is skipped and the original is
    // truncated to 4096 runes.
    let long = format!("**bold**{}", "x".repeat(5000));
    let before = server.count_method("sendMessage");
    sender
        .send_one(
            100,
            &long,
            SendOptions {
                mode: HtmlMode::Markdown,
                ..SendOptions::default()
            },
        )
        .await
        .expect("send long md");
    assert_eq!(server.count_method("sendMessage"), before + 1);
    let last = server.last_send_text().expect("last text");
    assert_eq!(last.chars().count(), 4096);
    assert!(
        last.starts_with("**bold**"),
        "truncated original keeps its markdown"
    );
    // Edit fallback, same rule.
    server.behavior.fail_parse_html("editMessageText", 1);
    sender
        .edit(100, 5, "**bold**", HtmlMode::Markdown, None)
        .await
        .expect("edit md");
    assert_eq!(server.count_method("editMessageText"), 2);
    assert_eq!(
        server
            .request_texts("editMessageText")
            .last()
            .map(String::as_str),
        Some("**bold**"),
        "edit fallback keeps the original markdown"
    );
}

/// `/profile` is local (fix loop 1, tech B9): cookies
/// present + VM id from the config, no service call.
#[tokio::test]
async fn profile_local_reports_cookies_and_vm() {
    let server = FakeServer::start().await;
    let dir = test_dir("profile");
    let cookies = dir.join("cookies.txt");
    std::fs::write(&cookies, "hatch_sess=x").expect("write cookies");
    let services = Arc::new(FakeServices::new());
    let (state, _dir) = test_state("profile-state");
    let handler = make_handler_with_config(
        &server,
        Arc::clone(&state),
        Arc::clone(&services),
        test_config_with_cookies(true, cookies, "vm-9".to_string()),
    );
    handler
        .dispatch_message(mc(100, OWNER_UID, "/profile"))
        .await
        .expect("dispatch");
    assert_eq!(
        server.last_send_text().as_deref(),
        Some(
            "Serving profile: <b>no1</b> (VM <code>vm-9</code>).\nCookies: present.\nProfile switching is not available from chat; edit the telegram block's profile and restart the bot."
        )
    );
    // Missing cookies + no VM id: same local path.
    let handler2 = make_handler(&server, state, Arc::clone(&services));
    handler2
        .dispatch_message(mc(100, OWNER_UID, "/profile"))
        .await
        .expect("dispatch");
    assert_eq!(
        server.last_send_text().as_deref(),
        Some(
            "Serving profile: <b>no1</b>.\nCookies: missing.\nProfile switching is not available from chat; edit the telegram block's profile and restart the bot."
        )
    );
}

/// Two concurrent taps on one decide button answer
/// exactly once each — one empty, one "expired" (fix
/// loop 1, red N6) — and the confirm is sent once.
#[tokio::test]
async fn raced_decide_tap_answers_once_each() {
    let server = FakeServer::start().await;
    let services = Arc::new(FakeServices::new());
    let (state, _dir) = test_state("racedecide");
    let registry = Arc::new(CallbackRegistry::new());
    let handler = Arc::new(CommandHandler::new(
        test_api(server.port),
        state,
        Arc::clone(&registry),
        test_claims(),
        services as Arc<dyn BotServices>,
        test_config(true),
    ));
    let data = registry.register(CallbackEntry {
        action: "decide".to_string(),
        approval_id: "ap1".to_string(),
        decision: "allow_always".to_string(),
        ..CallbackEntry::default()
    });
    let cb: CallbackQuery = serde_json::from_value(serde_json::json!({
        "id": "q1",
        "from": {"id": OWNER_UID, "is_bot": false, "first_name": "O"},
        "data": data,
        "message": {"message_id": 7, "from": {"id": OWNER_UID, "is_bot": false, "first_name": "O"}, "chat": {"id": 100, "type": "private"}, "date": 0, "text": "x"},
    }))
    .expect("callback parses");
    let (r1, r2) = tokio::join!(handler.handle_callback(&cb), handler.handle_callback(&cb));
    r1.expect("first tap");
    r2.expect("second tap");
    assert_eq!(
        server.count_method("answerCallbackQuery"),
        2,
        "exactly two answers, one per tap"
    );
    let mut answers = server.answer_texts();
    answers.sort();
    assert_eq!(
        answers,
        vec![
            "".to_string(),
            "This button expired; run the command again.".to_string()
        ],
        "one empty answer, one expired — never two of either"
    );
    assert_eq!(
        server
            .send_texts()
            .iter()
            .filter(|t| t.contains("Always allowed"))
            .count(),
        1,
        "the confirm is sent once"
    );
}

/// `send_file` keeps `opts.markup` through to the
/// multipart body (fix loop 1, tech N6).
#[tokio::test]
async fn send_file_keeps_markup_in_multipart() {
    let server = FakeServer::start().await;
    let api = test_api(server.port);
    let markup = InlineKeyboardMarkup {
        inline_keyboard: vec![vec![InlineKeyboardButton::new("Tap me", "c:abcdefgh")]],
    };
    castctl_telegram::files::send_file(
        &api,
        100,
        "doc.txt",
        b"hello",
        "",
        "cap",
        &SendOptions {
            markup: Some(markup),
            ..SendOptions::default()
        },
    )
    .await
    .expect("send_file");
    assert_eq!(server.count_method("sendDocument"), 1);
    let body = server
        .last_request_body("sendDocument")
        .expect("sendDocument recorded");
    assert!(
        body.contains("reply_markup"),
        "multipart must carry reply_markup, got {body}"
    );
    assert!(
        body.contains("c:abcdefgh"),
        "multipart must carry the callback data, got {body}"
    );
}

/// `download_media` fast-errors on an empty `file_id`
/// before any `getFile` call (fix loop 1, tech N14).
#[tokio::test]
async fn download_media_empty_file_id_fast_errors() {
    let server = FakeServer::start().await;
    let api = test_api(server.port);
    let media = InboxMedia {
        file_id: String::new(),
        name: "x".to_string(),
        mime_type: None,
        size: None,
        kind: "document".to_string(),
    };
    let err = castctl_telegram::files::download_media(&api, &media)
        .await
        .expect_err("empty file_id must fail");
    assert!(
        err.to_string().contains("telegram: no file to download"),
        "{err}"
    );
    assert_eq!(
        server.count_method("getFile"),
        0,
        "no getFile call before the fast error"
    );
}

/// A `/login` save failure gets Go's fixed sentence (fix
/// loop 1, safety N6).
#[tokio::test]
async fn login_save_failure_fixed_sentence() {
    let server = FakeServer::start().await;
    let services = Arc::new(FakeServices::new());
    services.set_save_cookies_fail(true);
    let (state, _dir) = test_state("loginfail");
    let handler = make_handler(&server, state, services);
    handler
        .dispatch_message(mc(100, OWNER_UID, "/login"))
        .await
        .expect("login");
    handler
        .dispatch_message(mc(100, OWNER_UID, "hatch_sess=abc; other=def"))
        .await
        .expect("cookies");
    assert_eq!(
        server.last_send_text().as_deref(),
        Some("⚠️ Could not save the cookies; nothing changed. /login to retry.")
    );
}
