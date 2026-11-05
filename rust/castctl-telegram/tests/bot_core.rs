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
    CallbackRegistry, ChatEntry, CommandHandler, CommandHandlerConfig,
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
    fail_429: Mutex<HashMap<String, (u32, i64)>>,
    fail_500: Mutex<HashMap<String, u32>>,
    next_message_id: AtomicI64,
}

impl FakeBehavior {
    fn new() -> Self {
        Self {
            updates: Mutex::new(VecDeque::new()),
            fail_429: Mutex::new(HashMap::new()),
            fail_500: Mutex::new(HashMap::new()),
            next_message_id: AtomicI64::new(1),
        }
    }

    fn queue_update(&self, update: Value) {
        self.updates
            .lock()
            .expect("behavior lock")
            .push_back(update);
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
        match method.as_str() {
            "getMe" => ok(serde_json::json!({
                "id": 1, "is_bot": true, "first_name": "Test", "username": "testbot",
            })),
            "getUpdates" => {
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
            "getMyCommands" => ok(Value::Array(vec![])),
            "getFile" => ok(serde_json::json!({
                "file_id": "f1", "file_path": "x/y", "file_size": 4,
            })),
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
    profile: String,
    update: String,
    raw: String,
    save_cookies: String,
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
            profile: String::new(),
            update: String::new(),
            raw: String::new(),
            save_cookies: String::new(),
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
                profile: "Serving profile: <b>no1</b>.".to_string(),
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

    fn profile_text(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        self.record("profile_text".to_string());
        let t = self.get(|i| i.profile.clone());
        Box::pin(async move { Ok(t) })
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
        let t = self.get(|i| i.save_cookies.clone());
        Box::pin(async move { Ok(t) })
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
    CommandHandlerConfig {
        profile_name: "no1".to_string(),
        owner_id: OWNER_UID,
        owner_id_set: owner_set,
        block_auto_approve: false,
        block_auto_allow_once: false,
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
    CommandHandler::new(
        test_api(server.port),
        state,
        Arc::new(CallbackRegistry::new()),
        test_claims(),
        services as Arc<dyn BotServices>,
        test_config(true),
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
        ("profile", "", "call:profile_text"),
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
    wait_until(Duration::from_secs(5), || {
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
    wait_until(Duration::from_secs(5), || {
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
        services.has_call("profile_text") && server.send_texts().len() >= 3
    })
    .await;
    // Let the stranger updates arrive and be dropped.
    tokio::time::sleep(Duration::from_millis(300)).await;
    bot.request_shutdown();
    run.await.expect("run task").expect("run ok");

    assert_eq!(
        services.call_count("profile_text"),
        1,
        "only the owner ran /profile"
    );
    let sends = server.send_texts();
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
        !err.summary(FAKE_TOKEN).contains(FAKE_TOKEN),
        "BotError summary must be fixed-vocabulary only"
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
