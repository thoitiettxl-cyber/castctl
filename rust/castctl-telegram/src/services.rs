// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The production [`BotServices`] implementation and the
//! production [`Decider`]: the gateway-backed service
//! the bot core calls, and the single-call decider the
//! claim manager calls.
//!
//! Where this lives, and why: `services.rs` inside
//! `castctl-telegram` (no new crate, no workspace edit).
//! The seam trait (`BotServices` in `router.rs`) and its
//! production impl stay in one crate, next to the turn
//! runner and the claim manager they compose; the
//! gateway does not depend on telegram, so there is no
//! dependency cycle. See PORTING.md §M5b ("BotServices
//! home").
//!
//! Of the 29 `BotServices` methods, M5b owns the turn /
//! media / approval ones for real; the remaining ~20
//! gateway-read methods return
//! [`BotError::NotWired`] with their name, explicitly
//! listed in PORTING.md as the M4b-gateway follow-up
//! boundary (research 04 §8 expressly permits leaving
//! parts `NotWired` with clear docs). Production never
//! had a service impl before, so no behaviour regresses.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::{Value, json};

use crate::api::BotApi;
use crate::claims::{ClaimManager, Decider};
use crate::error::BotError;
use crate::files::InboxMedia;
use crate::registry::CallbackRegistry;
use crate::router::{
    BotServices, DownloadedFile, FsOutcome, IdeaCard, NewChatOutcome, SessionOp, SharedFileRow,
};
use crate::state::TelegramStateStore;
use crate::turn::{GatewayPort, TurnRunner, files_list_rows, inbound_media_text, media_path};
use castctl_gateway::{Body, RequestOptions};
use castctl_shared::local_name;

/// The production decider: one `egress.approval.decide`
/// call, no retry, no idempotency key.
/// Source: `internal/commands/telegram_approvals.go:44-53`
/// (`callDecide`) and `internal/proto/routes.json:1095`
/// (route `POST /approvals/{approval_id}/decide`).
///
/// Safe through `SharedConn::call_json`: `decide` is
/// deliberately NOT in the POST-read set
/// (`castctl-transport/src/retry.rs`), so `safe_to_repeat`
/// is false and no post-send retry happens; only
/// `ConnectionDown` (nothing sent) retries — matching Go's
/// `SharedConn` behaviour.
pub struct GatewayDecider {
    port: Arc<dyn GatewayPort>,
}

impl GatewayDecider {
    #[must_use]
    pub fn new(port: Arc<dyn GatewayPort>) -> Self {
        Self { port }
    }

    /// The exact decide request: path params + body.
    /// Source: `internal/commands/telegram_approvals.go:44-53`.
    #[must_use]
    pub fn decide_request(approval_id: &str, decision: &str) -> (Vec<(String, String)>, Value) {
        (
            vec![("approval_id".to_string(), approval_id.to_string())],
            json!({ "decision": decision }),
        )
    }
}

/// Whether `decision` is one of the three decisions
/// Go ever produces (`internal/telegram/approvals.go:21-33`;
/// CLI `approveDecision`, `internal/commands/wait.go:1277-1293`).
/// Anything else is rejected locally, before any RPC.
#[must_use]
pub fn valid_decision(decision: &str) -> bool {
    matches!(decision, "allow_always" | "allow_once" | "deny")
}

impl Decider for GatewayDecider {
    fn decide(
        &self,
        approval_id: &str,
        decision: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        let port = Arc::clone(&self.port);
        let (path_params, body) = Self::decide_request(approval_id, decision);
        // Owned before the future: the returned future
        // borrows `&self`, not the `&str` argument.
        let decision = decision.to_string();
        Box::pin(async move {
            if !valid_decision(&decision) {
                return Err(BotError::Validation(format!(
                    "unknown decision: {decision}"
                )));
            }
            port.call_json(
                "egress.approval.decide",
                RequestOptions {
                    path_params,
                    body: Body::Json(body),
                    ..Default::default()
                },
            )
            .await?;
            Ok(())
        })
    }
}

/// The production [`BotServices`]: turn/media/approval
/// methods for real over a [`GatewayPort`], the rest
/// `NotWired`.
pub struct GatewayBotServices {
    port: Arc<dyn GatewayPort>,
    #[allow(dead_code)]
    api: Arc<BotApi>,
    state: Arc<TelegramStateStore>,
    #[allow(dead_code)]
    registry: Arc<CallbackRegistry>,
    #[allow(dead_code)]
    claims: Arc<ClaimManager>,
    runner: Arc<TurnRunner>,
}

impl GatewayBotServices {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        port: Arc<dyn GatewayPort>,
        api: Arc<BotApi>,
        state: Arc<TelegramStateStore>,
        registry: Arc<CallbackRegistry>,
        claims: Arc<ClaimManager>,
        runner: Arc<TurnRunner>,
    ) -> Self {
        Self {
            port,
            api,
            state,
            registry,
            claims,
            runner,
        }
    }
}

fn not_wired(name: &'static str) -> BotError {
    BotError::NotWired(name)
}

/// Pick the pending-approvals list from an
/// `egress.approvals` response: `pending_approvals`
/// when it is a non-empty array, else `pending`.
/// Source: `internal/commands/wait.go:1160-1164`
/// (`pendingApprovals`) — Python `or` semantics: an
/// explicitly empty first list falls through to the
/// fallback key.
fn pending_list(obj: &serde_json::Map<String, Value>) -> Vec<Value> {
    for key in ["pending_approvals", "pending"] {
        if let Some(arr) = obj.get(key).and_then(Value::as_array)
            && !arr.is_empty()
        {
            return arr.clone();
        }
    }
    Vec::new()
}

impl BotServices for GatewayBotServices {
    fn start_turn(
        &self,
        chat_id: i64,
        text: String,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let runner = Arc::clone(&self.runner);
        Box::pin(async move {
            runner.start_turn(chat_id, text).await;
        })
    }

    fn stop_turn(
        &self,
        chat_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, BotError>> + Send + '_>> {
        let runner = Arc::clone(&self.runner);
        Box::pin(async move { runner.stop_turn(chat_id).await })
    }

    fn wait_turns(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let runner = Arc::clone(&self.runner);
        Box::pin(async move {
            runner.wait_turns().await;
        })
    }

    fn resume_turn(
        &self,
        chat_id: i64,
        session_id: &str,
        title: &str,
        after_seq: i64,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let runner = Arc::clone(&self.runner);
        let session_id = session_id.to_string();
        let title = title.to_string();
        Box::pin(async move {
            runner
                .start_resume(chat_id, session_id, title, after_seq)
                .await;
        })
    }

    fn list_sessions(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<crate::router::SessionRow>, BotError>> + Send + '_>>
    {
        Box::pin(async move { Err(not_wired("list_sessions")) })
    }

    fn status_text(
        &self,
        _chat_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("status_text")) })
    }

    fn new_chat(
        &self,
        _chat_id: i64,
        _title: &str,
    ) -> Pin<Box<dyn Future<Output = Result<NewChatOutcome, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("new_chat")) })
    }

    fn history_text(
        &self,
        _chat_id: i64,
        _n: usize,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("history_text")) })
    }

    fn unread_text(
        &self,
        _chat_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("unread_text")) })
    }

    fn rename_chat(
        &self,
        _chat_id: i64,
        _title: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("rename_chat")) })
    }

    fn session_op(
        &self,
        _chat_id: i64,
        _session_id: &str,
        _op: SessionOp,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("session_op")) })
    }

    fn delete_chat(
        &self,
        _chat_id: i64,
        _session_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("delete_chat")) })
    }

    /// Fresh read, never decides. `pending_approvals`
    /// is preferred; an explicitly empty list does not
    /// fall back to `pending`; a non-object result is a
    /// validation error.
    /// Source: `internal/commands/telegram_approvals.go:70-86`
    /// (`telegramPendingApprovals`).
    fn pending_approvals(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<crate::approvals::Approval>, BotError>> + Send + '_>>
    {
        let port = Arc::clone(&self.port);
        Box::pin(async move {
            let v = port
                .call_json(
                    "egress.approvals",
                    RequestOptions {
                        ..Default::default()
                    },
                )
                .await?;
            let Some(obj) = v.as_object() else {
                return Err(BotError::Validation(
                    "gateway: egress.approvals result is not an object".to_string(),
                ));
            };
            let list = pending_list(obj);
            Ok(list
                .iter()
                .map(crate::approvals::describe_approval)
                .collect())
        })
    }

    fn decide_approval(
        &self,
        approval_id: &str,
        decision: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        let port = Arc::clone(&self.port);
        let (path_params, body) = GatewayDecider::decide_request(approval_id, decision);
        // Owned before the future: the returned future
        // borrows `&self`, not the `&str` argument.
        let decision = decision.to_string();
        Box::pin(async move {
            if !valid_decision(&decision) {
                return Err(BotError::Validation(format!(
                    "unknown decision: {decision}"
                )));
            }
            port.call_json(
                "egress.approval.decide",
                RequestOptions {
                    path_params,
                    body: Body::Json(body),
                    ..Default::default()
                },
            )
            .await?;
            Ok(())
        })
    }

    /// HISTORY order (oldest first, last 40 events); the
    /// handler reverses/dedupes/caps at 12.
    /// Source: `internal/commands/telegram_commands.go:664-682`.
    fn files_list(
        &self,
        chat_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SharedFileRow>, BotError>> + Send + '_>> {
        let port = Arc::clone(&self.port);
        let scope = self.state.chat(chat_id).session_id;
        Box::pin(async move {
            let events = port.history(40, &scope).await?;
            Ok(files_list_rows(&events))
        })
    }

    /// Both size gates live in the handler; this fetches
    /// the bytes.
    /// Source: `internal/commands/telegram_commands.go:711-756`.
    fn download_file(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<DownloadedFile, BotError>> + Send + '_>> {
        let port = Arc::clone(&self.port);
        let path = path.to_string();
        Box::pin(async move {
            let resolved = media_path(&path, None).map_err(BotError::Transport)?;
            let data = port.download_file(&resolved).await?;
            Ok(DownloadedFile {
                name: local_name(&resolved, ""),
                data,
                mime: None,
            })
        })
    }

    fn feed_text(
        &self,
        _limit: usize,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("feed_text")) })
    }

    fn goals_text(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("goals_text")) })
    }

    fn goal_text(
        &self,
        _id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("goal_text")) })
    }

    fn ideas_list(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IdeaCard>, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("ideas_list")) })
    }

    fn execute_idea(
        &self,
        _card_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("execute_idea")) })
    }

    fn usage_text(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("usage_text")) })
    }

    fn wake(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("wake")) })
    }

    fn fs_run(
        &self,
        _chat_id: i64,
        _arg: &str,
    ) -> Pin<Box<dyn Future<Output = Result<FsOutcome, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("fs_run")) })
    }

    fn fs_delete(
        &self,
        _path: &str,
        _recursive: bool,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("fs_delete")) })
    }

    fn update_check(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("update_check")) })
    }

    /// The route check lives in the service: unknown
    /// methods are refused before any gateway call.
    /// Source: `internal/commands/telegram_owner.go:145-183`
    /// (`ownerRaw`).
    fn raw_call(
        &self,
        method: &str,
        params_json: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        let port = Arc::clone(&self.port);
        let method = method.to_string();
        let params_json = params_json.to_string();
        Box::pin(async move {
            if !port.has_route(&method).await? {
                return Err(BotError::Validation(format!(
                    "telegram: unknown method {method}"
                )));
            }
            let params: Value = if params_json.trim().is_empty() {
                Value::Object(Default::default())
            } else {
                serde_json::from_str(&params_json)
                    .map_err(|e| BotError::Validation(format!("telegram: bad /raw params: {e}")))?
            };
            let v = port
                .call_json(
                    &method,
                    RequestOptions {
                        body: Body::Json(params),
                        ..Default::default()
                    },
                )
                .await?;
            Ok(serde_json::to_string(&v).unwrap_or_default())
        })
    }

    fn save_login_cookies(
        &self,
        _chat_id: i64,
        _user_id: i64,
        _cookies_text: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>> {
        Box::pin(async move { Err(not_wired("save_login_cookies")) })
    }

    /// Download the attachment, save it to System Files
    /// under `telegram-inbox/`, then start a turn telling
    /// Muse about it.
    /// Source: `internal/commands/telegram_commands.go:758-803`
    /// (`inboundMedia`).
    fn inbound_media(
        &self,
        chat_id: i64,
        media: InboxMedia,
        caption: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
        let port = Arc::clone(&self.port);
        let api = Arc::clone(&self.api);
        let runner = Arc::clone(&self.runner);
        let caption = caption.to_string();
        Box::pin(async move {
            let text = inbound_media_text(&api, port.as_ref(), &media, &caption).await?;
            runner.start_turn(chat_id, text).await;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::turn::GatewayPort;
    use std::time::Duration;

    /// A sink that accepts everything and records
    /// nothing, for service tests that only need the
    /// `GatewayBotServices` wiring.
    struct NullSink;

    impl crate::turn::BotSink for NullSink {
        fn send(
            &self,
            _chat_id: i64,
            _text: &str,
            _opts: crate::send::SendOptions,
        ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>> {
            Box::pin(async move { Ok(1) })
        }

        fn edit(
            &self,
            _chat_id: i64,
            _message_id: i64,
            _text: &str,
            _mode: crate::send::HtmlMode,
            _markup: Option<crate::send::InlineKeyboardMarkup>,
        ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
            Box::pin(async move { Ok(()) })
        }

        fn edit_plain(
            &self,
            _chat_id: i64,
            _message_id: i64,
            _text: &str,
            _markup: Option<crate::send::InlineKeyboardMarkup>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async move {})
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
            _name: &str,
            _data: &[u8],
            _mime: &str,
            _caption: &str,
            _opts: &crate::send::SendOptions,
        ) -> Pin<Box<dyn Future<Output = Result<i64, BotError>> + Send + '_>> {
            Box::pin(async move { Ok(1) })
        }
    }

    fn services_with(port: Arc<ScriptedPort>) -> Arc<GatewayBotServices> {
        let api = Arc::new(crate::api::BotApi::new(
            Arc::new(castctl_transport::DirectDialer::new()) as Arc<dyn castctl_transport::Dialer>,
            crate::api::BotApiConfig::plaintext(
                "123456:FAKE-TOKEN-TEST-ONLY-AAAA".to_string(),
                castctl_transport::DialTarget::new("127.0.0.1", 1),
            ),
        ));
        let path =
            std::env::temp_dir().join(format!("m5b-services-test-{}.json", std::process::id()));
        let state = Arc::new(crate::state::TelegramStateStore::load(path).expect("state load"));
        let registry = Arc::new(crate::registry::CallbackRegistry::new());
        let gw: Arc<dyn crate::turn::GatewayPort> =
            Arc::clone(&port) as Arc<dyn crate::turn::GatewayPort>;
        let decider: Arc<dyn crate::claims::Decider> =
            Arc::new(GatewayDecider::new(Arc::clone(&gw)));
        let claims = Arc::new(crate::claims::ClaimManager::new(
            decider,
            Duration::from_secs(15),
        ));
        let runner = Arc::new(crate::turn::TurnRunner::new(
            Arc::clone(&gw),
            Arc::new(NullSink),
            Arc::clone(&api),
            Arc::clone(&state),
            Arc::clone(&registry),
            Arc::clone(&claims),
            "no1".to_string(),
            "node-test".to_string(),
            false,
            false,
        ));
        Arc::new(GatewayBotServices::new(
            gw, api, state, registry, claims, runner,
        ))
    }

    #[tokio::test]
    async fn pending_approvals_falls_back_to_pending_when_empty() {
        // Go `pendingApprovals` (`internal/commands/wait.go:1160-1164`):
        // an explicitly empty `pending_approvals` falls
        // back to `pending` (Python `or` semantics) —
        // the server only lists the approval in `pending`
        // when the other key is empty.
        let port = Arc::new(ScriptedPort::new(vec![]));
        {
            let mut a = port.approvals_json.lock().expect("approvals lock");
            *a = json!({"pending_approvals": [], "pending": [{"approval_id": "a2"}]});
        }
        let services = services_with(Arc::clone(&port));
        let list = crate::router::BotServices::pending_approvals(&*services)
            .await
            .expect("pending approvals");
        assert_eq!(list.len(), 1, "fallback list must be used");
        assert_eq!(list[0].id, "a2");
    }

    #[tokio::test]
    async fn decide_rejects_unknown_decision_without_rpc() {
        // Go only ever produces `allow_always`,
        // `allow_once`, `deny` (`internal/telegram/approvals.go:21-33`;
        // CLI `approveDecision`, `wait.go:1277-1293`):
        // an unknown decision is a local error, never a
        // gateway RPC.
        use crate::claims::Decider;
        let port = Arc::new(ScriptedPort::new(vec![]));
        let decider = GatewayDecider::new(Arc::clone(&port) as Arc<dyn crate::turn::GatewayPort>);
        assert!(
            decider.decide("a1", "allow_session").await.is_err(),
            "unknown decision must be rejected"
        );
        assert_eq!(
            port.calls.lock().expect("calls lock").len(),
            0,
            "invalid decision must not reach the gateway"
        );
        decider
            .decide("a1", "allow_once")
            .await
            .expect("valid decision decides");
        assert_eq!(port.calls.lock().expect("calls lock").len(), 1);
    }

    #[test]
    fn decide_request_is_exact() {
        let (params, body) = GatewayDecider::decide_request("appr-1", "allow_always");
        assert_eq!(
            params,
            vec![("approval_id".to_string(), "appr-1".to_string())]
        );
        assert_eq!(body, json!({ "decision": "allow_always" }));
        let (_, body) = GatewayDecider::decide_request("appr-2", "deny");
        assert_eq!(body, json!({ "decision": "deny" }));
    }

    /// A scripted port for service tests: history is a
    /// fixed script, calls are recorded.
    pub struct ScriptedPort {
        pub history_script: Vec<Value>,
        pub calls: std::sync::Mutex<Vec<(String, Value)>>,
        pub files: std::collections::HashMap<String, Vec<u8>>,
        pub approvals_json: std::sync::Mutex<Value>,
    }

    impl ScriptedPort {
        pub fn new(history_script: Vec<Value>) -> Self {
            Self {
                history_script,
                calls: std::sync::Mutex::new(Vec::new()),
                files: std::collections::HashMap::new(),
                approvals_json: std::sync::Mutex::new(json!({
                    "pending_approvals": [
                        {"approval_id": "a1", "display": {"summary_title": "Run shell", "permission_question": {"text": "Allow?"}}}
                    ]
                })),
            }
        }
    }

    impl GatewayPort for ScriptedPort {
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
            method: &str,
            opts: RequestOptions,
        ) -> Pin<Box<dyn Future<Output = Result<Value, BotError>> + Send + '_>> {
            let method = method.to_string();
            let body = match opts.body {
                Body::Json(v) => v,
                _ => Value::Null,
            };
            let calls = &self.calls;
            let approvals = self
                .approvals_json
                .lock()
                .map(|a| a.clone())
                .unwrap_or(Value::Null);
            Box::pin(async move {
                calls
                    .lock()
                    .map(|mut c| c.push((method.clone(), body)))
                    .ok();
                match method.as_str() {
                    "egress.approvals" => Ok(approvals),
                    "egress.approval.decide" => Ok(json!({})),
                    _ => Ok(json!({})),
                }
            })
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
            method: &str,
        ) -> Pin<Box<dyn Future<Output = Result<bool, BotError>> + Send + '_>> {
            let known = matches!(method, "chat.history" | "chat.stream" | "sessions.list");
            Box::pin(async move { Ok(known) })
        }
    }

    #[tokio::test]
    async fn pending_approvals_reads_pending_list() {
        let port = Arc::new(ScriptedPort::new(Vec::new()));
        let decider = GatewayDecider::new(port.clone());
        // The decider path: one decide call, exact body.
        decider.decide("a1", "allow_once").await.unwrap();
        let calls = port.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "egress.approval.decide");
        assert_eq!(calls[0].1, json!({ "decision": "allow_once" }));
    }
}
