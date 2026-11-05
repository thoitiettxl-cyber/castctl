// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Offline end-to-end test for the M5b turn engine:
//! fake Bot API server (loopback, plaintext) + the REAL
//! Go gateway (`rust/parity/gateway_server serve-e2e`).
//!
//! Env-gated: runs only when `M5B_E2E=1` and
//! `M5B_E2E_GATEWAY_ADDR` names the running Go server
//! (e.g. `127.0.0.1:PORT` from its `READY addr=` line).
//! Otherwise the test returns early (skipped, not failed).
//!
//! The token used everywhere is the literal fake marker
//! `123456:FAKE-TOKEN-TEST-ONLY-AAAA`; no real Telegram
//! traffic ever leaves the loopback interface and no real
//! message is ever sent. The Go server's stderr log
//! (`E2E ...` lines: decide, fs.write, media) is the
//! verbatim trace for the report; this test asserts the
//! Rust-side observations (edit counts/texts, sendPhoto,
//! `claims.is_decided`, getFile + file download).
//!
//! One test, sequential phases (the Go script is shared
//! state, so phases must not run in parallel):
//!   1. text turn: streaming edits (partial text first,
//!      full text last) + final reply + media sent.
//!   2. inbound media: getFile + file download +
//!      `telegram-inbox/` write + follow turn.
//!   3. two parallel turns on different chats.
//!
//! The approval decide is exercised through auto-approve
//! (state toggles on): the scripted approvals event is
//! auto-decided via `egress.approval.decide`, exactly one
//! RPC; the button path (`cb_decide`) is covered by the
//! M5a `bot_core.rs` callback tests, not here.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use castctl_gateway::dial::dial_gateway;
use castctl_telegram::api::BotApi;
use castctl_telegram::api::BotApiConfig;
use castctl_telegram::claims::{ClaimManager, Decider};
use castctl_telegram::files::InboxMedia;
use castctl_telegram::registry::CallbackRegistry;
use castctl_telegram::router::BotServices;
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
    next_message_id: AtomicI64,
}

impl FakeBotApi {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fake Bot API binds loopback");
        let port = listener.local_addr().expect("listener addr").port();
        let records: Arc<Mutex<Vec<RequestRecord>>> = Arc::new(Mutex::new(Vec::new()));
        let records_clone = Arc::clone(&records);
        let next_message_id = AtomicI64::new(1);
        let counter = Arc::new(AtomicI64::new(1));
        let counter_clone = Arc::clone(&counter);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let records = Arc::clone(&records_clone);
                let counter = Arc::clone(&counter_clone);
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
            next_message_id,
        }
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

    fn request_bodies(&self, method: &str) -> Vec<String> {
        self.records
            .lock()
            .expect("records lock")
            .iter()
            .filter(|r| r.method == method)
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
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

#[tokio::test]
async fn m5b_offline_turn_e2e() {
    if std::env::var("M5B_E2E").as_deref() != Ok("1") {
        eprintln!("M5B_E2E != 1: skipping offline turn E2E (needs gateway_server serve-e2e)");
        return;
    }
    let gw_addr = match std::env::var("M5B_E2E_GATEWAY_ADDR") {
        Ok(a) => a,
        Err(_) => {
            eprintln!("M5B_E2E_GATEWAY_ADDR unset: skipping offline turn E2E");
            return;
        }
    };
    let bot = FakeBotApi::start().await;
    let api = Arc::new(BotApi::new(
        Arc::new(DirectDialer::new()) as Arc<dyn Dialer>,
        BotApiConfig::plaintext(
            FAKE_TOKEN.to_string(),
            DialTarget::new("127.0.0.1", bot.port),
        ),
    ));
    let url = format!("ws://{gw_addr}/v1/noise?vm_id=vm-test&auth_token=FAKE");
    let routes = Arc::new(RouteTable::default_routes().expect("routes"));
    let gw = dial_gateway(&url, routes).await.expect("dial Go gateway");
    let port: Arc<dyn castctl_telegram::turn::GatewayPort> = Arc::new(DirectGatewayPort::new(gw));
    let state_path =
        std::env::temp_dir().join(format!("m5b-e2e-state-{}.json", std::process::id()));
    let state = Arc::new(TelegramStateStore::load(state_path.clone()).expect("state load"));
    state.set_toggles(true, false).expect("set toggles");
    let registry = Arc::new(CallbackRegistry::new());
    let decider: Arc<dyn Decider> = Arc::new(GatewayDecider::new(Arc::clone(&port)));
    let claims = Arc::new(ClaimManager::new(
        decider,
        std::time::Duration::from_secs(15),
    ));
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

    // Phase 1: one text turn.
    services.start_turn(111, "hello muse".to_string()).await;
    let done = wait_until(Instant::now() + Duration::from_secs(30), || {
        bot.request_texts("editMessageText")
            .iter()
            .any(|t| t.contains("Hello from Muse"))
    })
    .await;
    assert!(
        done,
        "turn 1 never delivered 'Hello from Muse'; edits so far: {:?}",
        bot.request_texts("editMessageText")
    );
    let edits = bot.request_texts("editMessageText");
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
        bot.count_method("sendPhoto") >= 1,
        "turn 1 sent no media (sendPhoto)"
    );
    assert!(
        bot.request_bodies("sendPhoto")
            .iter()
            .any(|b| b.contains("e2e.png")),
        "sendPhoto body has no e2e.png filename"
    );
    assert!(
        claims.is_decided("a1"),
        "approval a1 was never decided (auto-approve did not run)"
    );

    // Phase 2: one inbound media message.
    let media = InboxMedia {
        file_id: "f1".to_string(),
        name: "photo.jpg".to_string(),
        mime_type: Some("image/jpeg".to_string()),
        size: Some(4),
        kind: "photo".to_string(),
    };
    let edits_before = bot.count_method("editMessageText");
    services
        .inbound_media(111, media, "")
        .await
        .expect("inbound media");
    assert_eq!(bot.count_method("getFile"), 1, "no getFile call");
    assert_eq!(
        bot.count_method("file-download"),
        1,
        "no file download call"
    );
    let done2 = wait_until(Instant::now() + Duration::from_secs(30), || {
        bot.count_method("editMessageText") > edits_before
            && bot
                .request_texts("editMessageText")
                .iter()
                .any(|t| t.contains("Hello from Muse"))
    })
    .await;
    assert!(done2, "inbound follow turn never delivered");

    // Phase 3: two parallel turns on different chats.
    // Fresh chats (not 111): chat 111's phase-2 turn
    // releases its slot only after its final edit lands,
    // so reusing it here would race the busy reply
    // instead of proving parallelism (observed in the
    // first E2E run: only 3 streams, "parallel one"
    // never opened one).
    let finals_before = bot
        .request_texts("editMessageText")
        .iter()
        .filter(|t| t.contains("Hello from Muse"))
        .count();
    let s1 = &services;
    let s2 = &services;
    tokio::join!(
        s1.start_turn(333, "parallel one".to_string()),
        s2.start_turn(444, "parallel two".to_string()),
    );
    let done3 = wait_until(Instant::now() + Duration::from_secs(30), || {
        bot.request_texts("editMessageText")
            .iter()
            .filter(|t| t.contains("Hello from Muse"))
            .count()
            >= finals_before + 2
    })
    .await;
    assert!(done3, "parallel turns never delivered (both final edits)");
    runner.wait_turns().await;
    let _ = std::fs::remove_file(&state_path);
    let _ = bot.next_message_id;
}
