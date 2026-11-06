// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! M7c item 4: Telegram bot driven through the REAL `Bot::run`
//! poll loop (not the CLI — `castctl-rs telegram run` is still
//! a stub at dev-rust `e7a97d7`, `castctl-cli/src/run.rs:1014`;
//! this is library-level evidence, labelled as such in the
//! M7c report, never claimed as CLI parity).
//!
//! Fake Bot API server (loopback, plaintext; merged fake:
//! `turn_e2e.rs` Red-N2 edits + `/file/` download, plus
//! `bot_core.rs` `getUpdates` queue + 10 ms empty-poll
//! pacing) + the REAL Go gateway
//! (`rust/parity/gateway_server serve-e2e`).
//!
//! Env-gated: runs only when `M7C_E2E=1` and
//! `M7C_E2E_GATEWAY_ADDR` names the running Go server.
//! Otherwise the test returns early (skipped, not failed).
//!
//! The token used everywhere is the literal fake marker
//! `123456:FAKE-TOKEN-TEST-ONLY-AAAA`; no real Telegram
//! traffic ever leaves the loopback interface and no real
//! message is ever sent. The Go server's stderr log
//! (`E2E ...` lines: decide, fs.write, media, SUMMARY) is
//! the verbatim trace for the report.
//!
//! Phases, in order (one test, the Go script is shared
//! state, so phases must not run in parallel):
//!   1. `Bot::new` (getMe once) + `set_commands` (once,
//!      30-entry menu) + `Bot::run` poll loop.
//!   2. text turn via an enqueued message update: streaming
//!      edits (partial text first, full text last) + final
//!      reply + media sent (`sendPhoto` e2e.png).
//!   3. auto-approve decide of scripted approval `a1`
//!      (toggles on): exactly one decide RPC.
//!   4. button decide: a registered `decide` button for
//!      `appr-1` (`allow_once`, resume triple s1/t/42)
//!      tapped once via an enqueued `callback_query`
//!      update, then tapped a second time: exactly one
//!      confirm, exactly one `answerCallbackQuery` per tap
//!      (first empty, second expired), exactly one
//!      `editMessageReplyMarkup`, no second decide RPC.
//!   5. inbound media via an enqueued photo update:
//!      `getFile` + file download + follow turn.
//!   6. clean shutdown: `request_shutdown`, `run()`
//!      returns `Ok(())`.
//!
//! Owner identity: sender = owner = allowlisted user 111
//! (one identity satisfies both the allowlist gate and the
//! owner gate for the decide path; cf. `bot_core.rs`
//! `OWNER_UID` precedent). This differs from the R3 recipe
//! draft (`owner_id: 0, owner_id_set: false`), which left
//! the decide sender-gate uncertain.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use castctl_gateway::dial::dial_gateway;
use castctl_telegram::api::BotApi;
use castctl_telegram::api::BotApiConfig;
use castctl_telegram::bot::{Bot, BotSettings};
use castctl_telegram::claims::{ClaimManager, Decider};
use castctl_telegram::commands::CommandHandlerConfig;
use castctl_telegram::registry::{CallbackEntry, CallbackRegistry};
use castctl_telegram::router::{BotServices, COMMAND_MENU};
use castctl_telegram::services::{GatewayBotServices, GatewayDecider};
use castctl_telegram::state::TelegramStateStore;
use castctl_telegram::turn::{DirectGatewayPort, SenderSink, TurnRunner};
use castctl_transport::routes::RouteTable;
use castctl_transport::{DialTarget, Dialer, DirectDialer};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Fake token (valid shape, never real).
const FAKE_TOKEN: &str = "123456:FAKE-TOKEN-TEST-ONLY-AAAA";

/// One recorded Bot API request.
#[derive(Debug, Clone)]
struct RequestRecord {
    method: String,
    body: Vec<u8>,
}

impl RequestRecord {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

struct FakeBotApi {
    port: u16,
    records: Arc<Mutex<Vec<RequestRecord>>>,
    updates: Arc<Mutex<VecDeque<Value>>>,
}

impl FakeBotApi {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fake Bot API binds loopback");
        let port = listener.local_addr().expect("listener addr").port();
        let records: Arc<Mutex<Vec<RequestRecord>>> = Arc::new(Mutex::new(Vec::new()));
        let updates: Arc<Mutex<VecDeque<Value>>> = Arc::new(Mutex::new(VecDeque::new()));
        let records_clone = Arc::clone(&records);
        let updates_clone = Arc::clone(&updates);
        let counter = Arc::new(AtomicI64::new(1));
        let counter_clone = Arc::clone(&counter);
        let last_edit: Arc<Mutex<HashMap<(String, String), String>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let last_edit_clone = Arc::clone(&last_edit);
        let edit_429_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let edit_429_clone = Arc::clone(&edit_429_done);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let records = Arc::clone(&records_clone);
                let updates = Arc::clone(&updates_clone);
                let counter = Arc::clone(&counter_clone);
                let last_edit = Arc::clone(&last_edit_clone);
                let edit_429_done = Arc::clone(&edit_429_clone);
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
                    let http_method = parts.next().unwrap_or("").to_string();
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
                    // File download: GET /file/bot<token>/... —
                    // raw bytes, not a JSON envelope.
                    if http_method == "GET" && path.starts_with("/file/bot") {
                        let file_bytes = b"FAKE".to_vec();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            file_bytes.len()
                        );
                        records.lock().expect("records lock").push(RequestRecord {
                            method: "file-download".to_string(),
                            body: path.into_bytes(),
                        });
                        let _ = socket.write_all(resp.as_bytes()).await;
                        let _ = socket.write_all(&file_bytes).await;
                        let _ = socket.flush().await;
                        return;
                    }
                    let method = path.rsplit('/').next().unwrap_or("").to_string();
                    let rec = RequestRecord {
                        method: method.clone(),
                        body: body.clone(),
                    };
                    let ok = |result: Value| -> (u16, Vec<u8>) {
                        let body = serde_json::json!({"ok": true, "result": result});
                        (200, serde_json::to_vec(&body).expect("json"))
                    };
                    let (status, resp_body) = match method.as_str() {
                        "getMe" => ok(serde_json::json!({
                            "id": 1, "is_bot": true, "first_name": "Test", "username": "testbot",
                        })),
                        "getUpdates" => {
                            // Drain the queue under the lock,
                            // then release it BEFORE the
                            // pacing sleep: holding a
                            // std MutexGuard across an
                            // await makes the future !Send.
                            let batch = {
                                let offset = serde_json::from_slice::<Value>(&body)
                                    .ok()
                                    .and_then(|v| v.get("offset").and_then(Value::as_i64))
                                    .unwrap_or(0);
                                let mut queue = updates.lock().expect("updates lock");
                                let mut batch = Vec::new();
                                while let Some(front) = queue.front() {
                                    let id =
                                        front.get("update_id").and_then(Value::as_i64).unwrap_or(0);
                                    if id < offset {
                                        queue.pop_front();
                                        continue;
                                    }
                                    batch.push(queue.pop_front().expect("front checked"));
                                }
                                batch
                            };
                            if batch.is_empty() {
                                // Pace empty polls like a
                                // long-poll (bot_core.rs
                                // precedent): without this
                                // a running Bot re-polls
                                // with zero delay and spins.
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                            ok(Value::Array(batch))
                        }
                        "sendMessage" => {
                            let mid = counter.fetch_add(1, Ordering::SeqCst);
                            ok(serde_json::json!({
                                "message_id": mid,
                                "chat": {"id": 0, "type": "private"},
                                "date": 0, "text": "",
                            }))
                        }
                        "getFile" => ok(serde_json::json!({
                            "file_id": "f1", "file_path": "inbox/photo.jpg", "file_size": 4,
                        })),
                        "sendDocument" | "sendPhoto" | "sendVideo" | "sendAudio" => {
                            let mid = counter.fetch_add(1, Ordering::SeqCst);
                            ok(serde_json::json!({
                                "message_id": mid,
                                "chat": {"id": 0, "type": "private"},
                                "date": 0, "text": "",
                            }))
                        }
                        // Red N2 (turn_e2e.rs): the first edit
                        // ever is a 429 with retry_after 1
                        // (client retry must recover); an
                        // edit identical to the last edit of
                        // the same (chat, message) is a 400
                        // "message is not modified" (client
                        // must swallow it).
                        "editMessageText" => {
                            let body_json: Value =
                                serde_json::from_slice(&body).unwrap_or(Value::Null);
                            let chat_id = body_json
                                .get("chat_id")
                                .map(|v| v.to_string())
                                .unwrap_or_default();
                            let message_id = body_json
                                .get("message_id")
                                .map(|v| v.to_string())
                                .unwrap_or_default();
                            let text = body_json
                                .get("text")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            if !edit_429_done.swap(true, Ordering::SeqCst) {
                                let err_body = serde_json::json!({
                                    "ok": false, "error_code": 429,
                                    "description": "Too Many Requests: retry after 1",
                                    "parameters": {"retry_after": 1},
                                });
                                (429, serde_json::to_vec(&err_body).expect("json"))
                            } else {
                                let mut seen = last_edit.lock().expect("last edit lock");
                                match seen.get(&(chat_id.clone(), message_id.clone())) {
                                    Some(prev) if *prev == text => {
                                        let err_body = serde_json::json!({
                                            "ok": false, "error_code": 400,
                                            "description": "Bad Request: message is not modified",
                                        });
                                        (400, serde_json::to_vec(&err_body).expect("json"))
                                    }
                                    _ => {
                                        seen.insert((chat_id, message_id), text);
                                        ok(Value::Bool(true))
                                    }
                                }
                            }
                        }
                        _ => ok(Value::Bool(true)),
                    };
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
            updates,
        }
    }

    fn queue_update(&self, update: Value) {
        self.updates.lock().expect("updates lock").push_back(update);
    }

    fn count_method(&self, method: &str) -> usize {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .filter(|r| r.method == method)
            .count()
    }

    fn request_texts(&self, method: &str) -> Vec<String> {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .filter(|r| r.method == method)
            .filter_map(|r| r.json().get("text")?.as_str().map(str::to_string))
            .collect()
    }

    /// All `answerCallbackQuery` texts so far, in order
    /// (empty string when the call carried no text field —
    /// the client omits it for an empty answer; cf.
    /// `bot_core.rs` `answer_texts`).
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

    fn request_bodies(&self, method: &str) -> Vec<String> {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .filter(|r| r.method == method)
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .collect()
    }

    /// Texts of `sendMessage` calls targeting one chat.
    fn send_texts_for_chat(&self, chat_id: i64) -> Vec<String> {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .filter(|r| r.method == "sendMessage")
            .filter_map(|r| {
                let v = r.json();
                if v.get("chat_id").and_then(Value::as_i64) != Some(chat_id) {
                    return None;
                }
                v.get("text")?.as_str().map(str::to_string)
            })
            .collect()
    }

    /// Texts of `editMessageText` calls targeting one chat
    /// (the resume turn edits chat 500; the media follow
    /// turn edits chat 111 — same text, different chats).
    fn edit_texts_for_chat(&self, chat_id: i64) -> Vec<String> {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .filter(|r| r.method == "editMessageText")
            .filter_map(|r| {
                let v = r.json();
                if v.get("chat_id").and_then(Value::as_i64) != Some(chat_id) {
                    return None;
                }
                v.get("text")?.as_str().map(str::to_string)
            })
            .collect()
    }
}

/// Wait until `cond` holds or the deadline passes.
async fn wait_until<F>(deadline: Instant, mut cond: F) -> bool
where
    F: FnMut() -> bool,
{
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    cond()
}

fn msg_update(id: i64, chat_id: i64, uid: i64, text: &str) -> Value {
    serde_json::json!({
        "update_id": id,
        "message": {
            "message_id": id,
            "from": {"id": uid, "is_bot": false, "first_name": "T"},
            "chat": {"id": chat_id, "type": "private"},
            "date": 1700000000,
            "text": text,
        },
    })
}

#[tokio::test]
async fn m7c_bot_run_e2e() {
    if std::env::var("M7C_E2E").as_deref() != Ok("1") {
        eprintln!("M7C_E2E != 1: skipping M7c bot E2E (needs gateway_server serve-e2e)");
        return;
    }
    let gw_addr = match std::env::var("M7C_E2E_GATEWAY_ADDR") {
        Ok(a) => a,
        Err(_) => {
            eprintln!("M7C_E2E_GATEWAY_ADDR unset: skipping M7c bot E2E");
            return;
        }
    };
    let fake = FakeBotApi::start().await;
    let api = Arc::new(BotApi::new(
        Arc::new(DirectDialer::new()) as Arc<dyn Dialer>,
        BotApiConfig::plaintext(
            FAKE_TOKEN.to_string(),
            DialTarget::new("127.0.0.1", fake.port),
        ),
    ));
    let url = format!("ws://{gw_addr}/v1/noise?vm_id=vm-test&auth_token=FAKE");
    let routes = Arc::new(RouteTable::default_routes().expect("routes"));
    let gw = dial_gateway(&url, routes).await.expect("dial Go gateway");
    let port: Arc<dyn castctl_telegram::turn::GatewayPort> = Arc::new(DirectGatewayPort::new(gw));
    let state_path =
        std::env::temp_dir().join(format!("m7c-bot-state-{}.json", std::process::id()));
    let state = Arc::new(TelegramStateStore::load(state_path.clone()).expect("state load"));
    state.set_toggles(true, false).expect("set toggles");
    let registry = Arc::new(CallbackRegistry::new());
    let decider: Arc<dyn Decider> = Arc::new(GatewayDecider::new(Arc::clone(&port)));
    let claims = Arc::new(ClaimManager::new(decider, Duration::from_secs(15)));
    let sink = Arc::new(SenderSink::new(Arc::clone(&api)));
    let runner = Arc::new(TurnRunner::new(
        Arc::clone(&port),
        sink,
        Arc::clone(&api),
        Arc::clone(&state),
        Arc::clone(&registry),
        Arc::clone(&claims),
        "no1".to_string(),
        "node-e2e".to_string(),
        false,
        false,
    ));
    let services = GatewayBotServices::new(
        Arc::clone(&port),
        Arc::clone(&api),
        Arc::clone(&state),
        Arc::clone(&registry),
        Arc::clone(&claims),
        Arc::clone(&runner),
    );
    let bot = Bot::new(
        Arc::clone(&api),
        Arc::clone(&state),
        Arc::clone(&registry),
        Arc::clone(&claims),
        Arc::new(services) as Arc<dyn BotServices>,
        CommandHandlerConfig {
            profile_name: "no1".to_string(),
            owner_id: 111,
            owner_id_set: true,
            block_auto_approve: true,
            block_auto_allow_once: false,
            cookies_file: std::path::PathBuf::new(),
            vm_id: "vm-test".to_string(),
        },
        BotSettings {
            allowed_user_ids: vec![111],
            backoff_ladder: vec![Duration::from_millis(50)],
        },
    )
    .await
    .expect("Bot::new (getMe)");
    assert_eq!(
        fake.count_method("getMe"),
        1,
        "getMe must be called exactly once"
    );
    let menu: Vec<(String, String)> = COMMAND_MENU
        .iter()
        .map(|e| (e.name.to_string(), e.description.to_string()))
        .collect();
    assert_eq!(menu.len(), 30, "COMMAND_MENU must have 30 entries");
    bot.set_commands(&menu).await.expect("setMyCommands");
    assert_eq!(
        fake.count_method("setMyCommands"),
        1,
        "setMyCommands must be called exactly once"
    );

    let bot_run = Arc::clone(&bot);
    let run_handle = tokio::spawn(async move { bot_run.run().await });

    // Phase 2: text turn via an enqueued message update.
    fake.queue_update(msg_update(1, 111, 111, "hello muse"));
    let done = wait_until(Instant::now() + Duration::from_secs(30), || {
        fake.request_texts("editMessageText")
            .iter()
            .any(|t| t.contains("Hello from Muse"))
    })
    .await;
    assert!(
        done,
        "turn 1 never delivered 'Hello from Muse'; edits so far: {:?}",
        fake.request_texts("editMessageText")
    );
    let edits = fake.request_texts("editMessageText");
    assert!(
        edits.len() >= 2,
        "expected >=2 streaming edits, got {}: {edits:?}",
        edits.len()
    );
    assert!(
        edits
            .iter()
            .any(|t| t.contains("Hel") && !t.contains("Hello from Muse")),
        "no partial streaming edit observed; edits: {edits:?}"
    );
    assert!(
        fake.count_method("sendPhoto") >= 1,
        "turn 1 sent no media (sendPhoto)"
    );
    assert!(
        fake.request_bodies("sendPhoto")
            .iter()
            .any(|b| b.contains("e2e.png")),
        "sendPhoto body has no e2e.png filename"
    );
    // Phase 3: auto-approve decide of scripted approval a1.
    assert!(
        claims.is_decided("a1"),
        "approval a1 was never decided (auto-approve did not run)"
    );

    // Phase 4: button decide (appr-1, allow_once, resume s1/t/42).
    let data = registry.register(CallbackEntry {
        action: "decide".to_string(),
        approval_id: "appr-1".to_string(),
        decision: "allow_once".to_string(),
        session_id: "s1".to_string(),
        title: "t".to_string(),
        after_seq: Some(42),
        ..CallbackEntry::default()
    });
    assert!(data.starts_with("c:"), "callback data must be a c: token");
    let cb_update = |id: i64| {
        serde_json::json!({
            "update_id": id,
            "callback_query": {
                "id": "cq-1",
                "from": {"id": 111, "is_bot": false, "first_name": "T"},
                "data": data,
                "message": {
                    "message_id": 100,
                    "from": {"id": 1, "is_bot": true, "first_name": "Test"},
                    "chat": {"id": 500, "type": "private"},
                    "date": 1700000000,
                    "text": "approve?",
                },
            },
        })
    };
    fake.queue_update(cb_update(60));
    let decided = wait_until(Instant::now() + Duration::from_secs(30), || {
        claims.is_decided("appr-1")
    })
    .await;
    assert!(decided, "button decide never decided appr-1");
    assert_eq!(
        fake.count_method("answerCallbackQuery"),
        1,
        "exactly one answerCallbackQuery for the first tap"
    );
    assert_eq!(
        fake.answer_texts(),
        vec![String::new()],
        "first tap answer must carry empty text"
    );
    assert!(
        fake.request_texts("sendMessage")
            .iter()
            .any(|t| t.contains("Allowed once") && t.contains("appr-1")),
        "no 'Allowed once' confirm for appr-1; sends: {:?}",
        fake.request_texts("sendMessage")
    );
    assert_eq!(
        fake.count_method("editMessageReplyMarkup"),
        1,
        "buttons must be cleared exactly once"
    );
    // Second identical tap: single-flight — no second decide,
    // no second confirm; the tap answers "expired".
    fake.queue_update(cb_update(61));
    let expired = wait_until(Instant::now() + Duration::from_secs(30), || {
        fake.count_method("answerCallbackQuery") >= 2
    })
    .await;
    assert!(expired, "second tap was never answered");
    assert_eq!(
        fake.count_method("answerCallbackQuery"),
        2,
        "exactly two answers total (one per tap)"
    );
    let mut answers = fake.answer_texts();
    answers.sort();
    assert_eq!(
        answers,
        vec![
            String::new(),
            "This button expired; run the command again.".to_string()
        ],
        "one empty answer, one expired — never two of either"
    );
    assert_eq!(
        fake.request_texts("sendMessage")
            .iter()
            .filter(|t| t.contains("Allowed once") && t.contains("appr-1"))
            .count(),
        1,
        "the confirm must be sent exactly once (single-flight)"
    );
    assert_eq!(
        fake.count_method("editMessageReplyMarkup"),
        1,
        "buttons must be cleared exactly once even after the second tap"
    );

    // The decide above carries a resume triple (s1/t/42):
    // the runner starts a resume turn on chat 500. A resume
    // re-reads history after `after_seq` — it opens NO new
    // stream — and its first visible act is the
    // "Muse is continuing…" bubble on chat 500. The scripted
    // gateway log puts the completed assistant message at
    // seq 40, i.e. NOT after 42, so the follow correctly
    // delivers nothing more: assert the bubble (resume ran),
    // not a final edit (none is due at this after_seq).
    let resumed = wait_until(Instant::now() + Duration::from_secs(30), || {
        fake.send_texts_for_chat(500)
            .iter()
            .any(|t| t.contains("Muse is continuing"))
    })
    .await;
    assert!(
        resumed,
        "resume turn never started on chat 500; sends to 500: {:?}",
        fake.send_texts_for_chat(500)
    );
    eprintln!("M7C resume turn on chat 500 started (continuing bubble sent)");

    // Phase 5: inbound media via an enqueued photo update.
    let edits_before = fake.count_method("editMessageText");
    fake.queue_update(serde_json::json!({
        "update_id": 70,
        "message": {
            "message_id": 70,
            "from": {"id": 111, "is_bot": false, "first_name": "T"},
            "chat": {"id": 111, "type": "private"},
            "date": 1700000000,
            "photo": [{"file_id": "f1", "file_unique_id": "u1", "width": 10, "height": 10, "file_size": 4}],
            "caption": "",
        },
    }));
    let media_done = wait_until(Instant::now() + Duration::from_secs(30), || {
        fake.count_method("editMessageText") > edits_before
            && fake
                .edit_texts_for_chat(111)
                .iter()
                .any(|t| t.contains("Hello from Muse"))
    })
    .await;
    assert_eq!(fake.count_method("getFile"), 1, "no getFile call");
    assert_eq!(
        fake.count_method("file-download"),
        1,
        "no file download call"
    );
    assert!(media_done, "inbound follow turn never delivered");

    // Phase 6: clean shutdown.
    bot.request_shutdown();
    let run_result = tokio::time::timeout(Duration::from_secs(30), run_handle)
        .await
        .expect("run() did not return after shutdown")
        .expect("run task panicked");
    assert!(
        run_result.is_ok(),
        "run() must return Ok(()): {run_result:?}"
    );
    let _ = std::fs::remove_file(&state_path);
}
