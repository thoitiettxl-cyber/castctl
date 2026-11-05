// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Command handler: routing, gates, full handlers, seam
//! dispatch, callbacks.
//!
//! Go sources: `internal/commands/telegram_commands.go`
//! (`dispatch`, `runCommand`, `start`, `help`, `stop`,
//! `status`, `showChats`, `main`, `newChat`, `history`,
//! `unread`, `rename`, `sessionOpCmd`, `archive`,
//! `deletePrompt`, `watch`, `files`, `downloadFile`,
//! `inboundMedia`, `handleCallback`),
//! `internal/commands/telegram_approvals.go`
//! (`approvals`, `autoApprove`),
//! `internal/commands/telegram_read.go` (`feed`, `goals`,
//! `goal`, `ideas`, `usage`, `wake`, `ideaExec`),
//! `internal/commands/telegram_fs.go` (`fs`, `replyLong`,
//! `fsRm`),
//! `internal/commands/telegram_owner.go` (`ownerProfile`,
//! `ownerUpdate`, `ownerLogin`, `takeAwaitingCookies`,
//! `ownerRaw`),
//! `internal/telegram/bot.go:1230-1484` (`onCallback`,
//! `cbDecide`, `cbApproveAll`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use castctl_tg_text::{CHUNK_SIZE, escape_text};
use serde_json::Value;

use crate::api::BotApi;
use crate::approvals::approval_text;
use crate::claims::ClaimManager;
use crate::error::BotError;
use crate::files::{TOO_BIG_DOWNLOAD_REFUSAL, download_media, exceeds_upload_limit, send_file};
use crate::registry::{CallbackEntry, CallbackRegistry, approval_markup, approve_all_markup};
use crate::router::{
    BotServices, FsOutcome, NewChatOutcome, OWNER_ONLY_SENTENCE, SessionOp, is_owner_command,
    is_valid_command_name, parse_command,
};
use crate::send::{HtmlMode, InlineKeyboardButton, InlineKeyboardMarkup, SendOptions, Sender};
use crate::state::{ChatEntry, EffectiveToggles, TelegramStateStore};
use crate::types::{CallbackQuery, MessageContext};

/// `/help` text, byte-identical to Go.
/// Source: `internal/commands/telegram_commands.go:40-64`
/// (`telegramBotHelpText` — "Python's HELP verbatim",
/// `src/muse_cli/tgbot.py:98-115`).
pub const COMMAND_HELP_TEXT: &str = "<b>Muse on Telegram</b>\nType anything to talk to Muse in the current conversation. Send a photo or file to put it in Muse's System Files (<code>telegram-inbox/</code>) and tell Muse about it.\n\n<b>Conversation</b>\n/chats open another chat · /main · /new [title]\n/history [N] · /unread · /stop\n/rename &lt;title&gt; · /pin · /unpin · /archive · /unarchive · /delete\n\n<b>Muse</b>\n/status · /approvals · /autoapprove on|off · /watch on|off\n/files · /feed · /goals · /goal &lt;id&gt; · /ideas · /usage · /wake\n\n<b>System Files</b>\n/fs ls [path] · /fs tree [path] [depth] · /fs cat &lt;path&gt; · /fs get &lt;path&gt;\n/fs find &lt;name&gt; · /fs stat &lt;path&gt; · /fs mkdir &lt;path&gt; · /fs mv &lt;src&gt; &lt;dst&gt; · /fs rm [-r] &lt;path&gt;\n\n<b>Admin</b>\n/profile · /login (new cookies) · /update · /raw &lt;method&gt; [json]";

/// `/raw` usage line (Python's usage line verbatim).
/// Source: `internal/commands/telegram_owner.go:135-138`
/// (`rawUsage`).
pub const RAW_USAGE: &str = "Usage: /raw &lt;method&gt; [json body]; path params go in <code>{\\\"_params\\\": {...}}</code>";

/// `/fs` usage line (Python's usage line verbatim, incl.
/// literal `&lt;/&gt;` entities, sent as HTML).
/// Source: `internal/commands/telegram_fs.go:48-50`
/// (`fsUsage`).
pub const FS_USAGE: &str = "Usage: /fs ls [path] · tree [path] [depth] · cat|get|stat &lt;path&gt; · find &lt;name&gt; · mkdir &lt;path&gt; · mv &lt;src&gt; &lt;dst&gt; [-f] · rm [-r] &lt;path&gt;";

/// Chat-picker page size.
/// Source: `internal/commands/telegram_commands.go:486`
/// (`chatsPageSize = 8`).
pub const CHATS_PAGE_SIZE: usize = 8;

/// `/files` list cap (after dedupe).
/// Source: `internal/commands/telegram_commands.go:681-682`
/// (12 rows, not 6 — the brief's "cap 6" matches nothing
/// in the code).
pub const FILES_LIST_CAP: usize = 12;

/// `/goal` document threshold (runes).
/// Source: `internal/commands/telegram_read.go:129`
/// (`goal`: body >3000 runes → head send + `goal.json`).
pub const GOAL_DOCUMENT_THRESHOLD: usize = 3000;

/// `/login` cookies document cap.
/// Source: `internal/commands/telegram_owner.go:244-247`
/// (1 MiB).
pub const LOGIN_COOKIES_LIMIT: i64 = 1 << 20;

/// Whether an error is an auth error (login-expired path).
/// Source: `internal/commands/telegram_commands.go:138-151`
/// (`dispatch` maps `*conn.AuthError` to the login-expired
/// sentence).
#[must_use]
pub fn is_auth_error(e: &BotError) -> bool {
    matches!(
        e,
        BotError::Transport(castctl_transport::TransportError::Auth { .. })
    )
}

/// Static handler configuration (from the telegram block +
/// the profile). No direct Go type counterpart: Go spreads
/// these across `telegramCmdHandler`
/// (`internal/commands/telegram_commands.go`) and the
/// `telegram.go` startup wiring.
#[derive(Debug, Clone)]
pub struct CommandHandlerConfig {
    /// Linked profile name.
    pub profile_name: String,
    /// Owner user id (0 when unconfigured).
    pub owner_id: i64,
    /// Whether `owner_id` was configured.
    pub owner_id_set: bool,
    /// Block `auto_approve` value (state file wins after
    /// the first runtime toggle).
    pub block_auto_approve: bool,
    /// Block `auto_allow_once` value.
    pub block_auto_allow_once: bool,
}

/// The command handler: routing + gates + full handlers.
/// Source: `internal/commands/telegram_commands.go`
/// (`telegramCmdHandler`).
pub struct CommandHandler {
    api: Arc<BotApi>,
    state: Arc<TelegramStateStore>,
    registry: Arc<CallbackRegistry>,
    claims: Arc<ClaimManager>,
    services: Arc<dyn BotServices>,
    config: CommandHandlerConfig,
    awaiting_cookies: Mutex<HashMap<i64, i64>>,
}

impl std::fmt::Debug for CommandHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandHandler")
            .field("api", &self.api)
            .field("profile_name", &self.config.profile_name)
            .field("owner_id", &self.config.owner_id)
            .field("owner_id_set", &self.config.owner_id_set)
            .finish_non_exhaustive()
    }
}

impl CommandHandler {
    /// Build a handler. The caller owns the `BotApi`,
    /// state store, registry, claims manager, and services.
    #[must_use]
    pub fn new(
        api: Arc<BotApi>,
        state: Arc<TelegramStateStore>,
        registry: Arc<CallbackRegistry>,
        claims: Arc<ClaimManager>,
        services: Arc<dyn BotServices>,
        config: CommandHandlerConfig,
    ) -> Self {
        Self {
            api,
            state,
            registry,
            claims,
            services,
            config,
            awaiting_cookies: Mutex::new(HashMap::new()),
        }
    }

    fn sender(&self) -> Sender<'_> {
        Sender::new(&self.api)
    }

    /// Whether `uid` is the configured owner. With no
    /// owner configured every uid is refused.
    /// Source: `internal/commands/telegram_owner.go:77-81`
    /// (`isOwner`).
    #[must_use]
    pub fn is_owner(&self, uid: i64) -> bool {
        self.config.owner_id_set && uid == self.config.owner_id
    }

    /// Effective toggles (block values overlaid with the
    /// state file's non-nil values).
    #[must_use]
    pub fn effective_toggles(&self) -> EffectiveToggles {
        self.state.toggles(
            self.config.block_auto_approve,
            self.config.block_auto_allow_once,
        )
    }

    /// The callback registry (button actions register here).
    #[must_use]
    pub fn registry(&self) -> &Arc<CallbackRegistry> {
        &self.registry
    }

    /// The claims manager (decide single-flight + auto-log).
    #[must_use]
    pub fn claims(&self) -> &Arc<ClaimManager> {
        &self.claims
    }

    /// Route one message: "/name args" to the command
    /// table, a cookie-awaiting answer to the cookie
    /// handler, a message with media to the inbound-media
    /// path, anything else with non-blank text to a turn.
    /// Source: `internal/commands/telegram_commands.go:119-153`
    /// (`dispatch`).
    pub async fn dispatch_message(&self, mc: MessageContext) -> Result<(), BotError> {
        let text = mc.text.clone();
        if text.starts_with('/') {
            let (name, arg) = parse_command(&text).unwrap_or_default();
            let result = self.run_command(&mc, &name, &arg).await;
            if let Err(e) = result {
                if is_auth_error(&e) {
                    let _ = self
                        .sender()
                        .send(
                            mc.chat_id,
                            "🔑 muse.ai login expired. Re-export cookies with `castctl auth export` and restart the bot.",
                            SendOptions {
                                mode: HtmlMode::Plain,
                                ..SendOptions::default()
                            },
                        )
                        .await;
                    return Ok(());
                }
                let _ = self
                    .sender()
                    .send(
                        mc.chat_id,
                        &format!("⚠️ Could not run /{name} (gateway error)."),
                        SendOptions {
                            mode: HtmlMode::Plain,
                            ..SendOptions::default()
                        },
                    )
                    .await;
                return Ok(());
            }
            return Ok(());
        }
        if self.take_awaiting_cookies(&mc).await? {
            return Ok(());
        }
        if let Some(media) = &mc.media {
            let media = media.clone();
            let caption = mc.caption.clone();
            return self
                .services
                .inbound_media(mc.chat_id, media, &caption)
                .await;
        }
        if text.trim().is_empty() {
            return Ok(());
        }
        self.services.start_turn(mc.chat_id, text).await;
        Ok(())
    }

    /// Run one command by name.
    /// Source: `internal/commands/telegram_commands.go:154-235`
    /// (`runCommand`).
    pub async fn run_command(
        &self,
        mc: &MessageContext,
        name: &str,
        arg: &str,
    ) -> Result<(), BotError> {
        let chat_id = mc.chat_id;
        if !is_valid_command_name(name) {
            let _ = self
                .sender()
                .send(
                    chat_id,
                    &format!("Unknown command /{}. /help lists them.", escape_text(name)),
                    SendOptions::default(),
                )
                .await;
            return Ok(());
        }
        // Owner gate runs before the handler and before
        // dispatch's error mapping, so a refusal never
        // touches the gateway or the updater.
        // Source: `internal/commands/telegram_commands.go:160-167`.
        if is_owner_command(name) && !self.is_owner(mc.user_id) {
            let _ = self
                .sender()
                .send(
                    chat_id,
                    OWNER_ONLY_SENTENCE,
                    SendOptions {
                        mode: HtmlMode::Plain,
                        ..SendOptions::default()
                    },
                )
                .await;
            return Ok(());
        }
        match name {
            "start" => self.start(chat_id).await,
            "help" => self.help(chat_id).await,
            "stop" => self.stop(chat_id).await,
            "status" => self.status(chat_id).await,
            "chats" => self.show_chats(chat_id, 0, 0).await,
            "main" => self.main(chat_id).await,
            "new" => self.new_chat(chat_id, arg).await,
            "history" => self.history(chat_id, arg).await,
            "unread" => self.unread(chat_id).await,
            "rename" => self.rename(chat_id, arg).await,
            "pin" => {
                self.session_op_cmd(chat_id, SessionOp::Pin, "📌 Pinned.")
                    .await
            }
            "unpin" => {
                self.session_op_cmd(chat_id, SessionOp::Unpin, "Unpinned.")
                    .await
            }
            "archive" => self.archive(chat_id).await,
            "unarchive" => {
                self.session_op_cmd(chat_id, SessionOp::Unarchive, "📤 Unarchived.")
                    .await
            }
            "delete" => self.delete_prompt(chat_id).await,
            "approvals" => self.approvals(chat_id).await,
            "autoapprove" => self.auto_approve(chat_id, arg).await,
            "watch" => self.watch(chat_id, arg).await,
            "files" => self.files(chat_id).await,
            "feed" => self.feed(chat_id, arg).await,
            "goals" => self.goals(chat_id).await,
            "goal" => self.goal(chat_id, arg).await,
            "ideas" => self.ideas(chat_id).await,
            "usage" => self.usage(chat_id).await,
            "wake" => self.wake(chat_id).await,
            "fs" => self.fs(chat_id, arg).await,
            "profile" => self.owner_profile(chat_id).await,
            "update" => self.owner_update(chat_id).await,
            "login" => self.owner_login(mc).await,
            "raw" => self.owner_raw(chat_id, arg).await,
            _ => {
                let _ = self
                    .sender()
                    .send(
                        chat_id,
                        &format!("Unknown command /{name}. /help lists them."),
                        SendOptions::default(),
                    )
                    .await;
                Ok(())
            }
        }
    }

    /// `/start` reply.
    /// Source: `internal/commands/telegram_commands.go:237-240`.
    async fn start(&self, chat_id: i64) -> Result<(), BotError> {
        let _ = self
            .sender()
            .send(
                chat_id,
                &format!(
                    "👋 Connected to Muse (profile <code>{}</code>). Type a message to talk to Muse; /help lists commands.",
                    escape_text(&self.config.profile_name)
                ),
                SendOptions::default(),
            )
            .await?;
        Ok(())
    }

    /// `/help`: sends `telegramBotHelpText` verbatim.
    /// Source: `internal/commands/telegram_commands.go:242-244`.
    async fn help(&self, chat_id: i64) -> Result<(), BotError> {
        let _ = self
            .sender()
            .send(chat_id, COMMAND_HELP_TEXT, SendOptions::default())
            .await?;
        Ok(())
    }

    /// `/stop`: cancels the chat's active turn.
    /// Source: `internal/commands/telegram_commands.go:253-272`.
    async fn stop(&self, chat_id: i64) -> Result<(), BotError> {
        let cancelled = self.services.stop_turn(chat_id).await?;
        let text = if cancelled {
            "⏹ Stopped Muse's turn."
        } else {
            "⏹ Stop sent; Muse reported nothing running."
        };
        let _ = self
            .sender()
            .send(chat_id, text, SendOptions::default())
            .await?;
        Ok(())
    }

    /// `/status` (seam: sessions + unread + identity + probe).
    /// Source: `internal/commands/telegram_commands.go:274`.
    async fn status(&self, chat_id: i64) -> Result<(), BotError> {
        let text = self.services.status_text(chat_id).await?;
        let _ = self
            .sender()
            .send(chat_id, &text, SendOptions::default())
            .await?;
        Ok(())
    }

    /// Render the chat picker.
    /// Source: `internal/commands/telegram_commands.go:488-536`
    /// (`showChats`).
    async fn show_chats(&self, chat_id: i64, message_id: i64, page: usize) -> Result<(), BotError> {
        let rows = self.services.list_sessions().await?;
        let mapping = self.state.chat(chat_id);
        let cur = mapping.session_id.clone();
        let pages = rows.len().div_ceil(CHATS_PAGE_SIZE).max(1);
        let page = page.min(pages - 1);
        let mut main_label = "💬 main chat".to_string();
        if cur.is_empty() {
            main_label += " ✓";
        }
        let mut btns: Vec<Vec<InlineKeyboardButton>> = vec![vec![InlineKeyboardButton::new(
            &main_label,
            &self.registry.register(CallbackEntry {
                action: "open".to_string(),
                title: "main chat".to_string(),
                ..CallbackEntry::default()
            }),
        )]];
        let start = page * CHATS_PAGE_SIZE;
        let end = ((page + 1) * CHATS_PAGE_SIZE).min(rows.len());
        for r in &rows[start..end] {
            let mut label = String::new();
            if r.pinned {
                label += "📌 ";
            }
            label += if r.title.is_empty() {
                "untitled"
            } else {
                &r.title
            };
            if r.session_id == cur && !cur.is_empty() {
                label += " ✓";
            }
            btns.push(vec![InlineKeyboardButton::new(
                &label,
                &self.registry.register(CallbackEntry {
                    action: "open".to_string(),
                    session_id: r.session_id.clone(),
                    title: if r.title.is_empty() {
                        "untitled".to_string()
                    } else {
                        r.title.clone()
                    },
                    ..CallbackEntry::default()
                }),
            )]);
        }
        let mut nav: Vec<InlineKeyboardButton> = Vec::new();
        if page > 0 {
            nav.push(InlineKeyboardButton::new(
                "◀ Prev",
                &self.registry.register(CallbackEntry {
                    action: "chats_page".to_string(),
                    page: page as i64 - 1,
                    ..CallbackEntry::default()
                }),
            ));
        }
        if page < pages - 1 {
            nav.push(InlineKeyboardButton::new(
                "Next ▶",
                &self.registry.register(CallbackEntry {
                    action: "chats_page".to_string(),
                    page: page as i64 + 1,
                    ..CallbackEntry::default()
                }),
            ));
        }
        if !nav.is_empty() {
            btns.push(nav);
        }
        let text = format!(
            "Your chats ({} side chats, page {}/{}). Tap one to open it.",
            rows.len(),
            page + 1,
            pages
        );
        let markup = InlineKeyboardMarkup {
            inline_keyboard: btns,
        };
        if message_id != 0 {
            self.sender()
                .edit(chat_id, message_id, &text, HtmlMode::Plain, Some(markup))
                .await?;
        } else {
            let _ = self
                .sender()
                .send(
                    chat_id,
                    &text,
                    SendOptions {
                        markup: Some(markup),
                        mode: HtmlMode::Plain,
                        ..SendOptions::default()
                    },
                )
                .await?;
        }
        Ok(())
    }

    /// `/main`: switch back to the main chat.
    /// Source: `internal/commands/telegram_commands.go:537-547`.
    async fn main(&self, chat_id: i64) -> Result<(), BotError> {
        self.state.set_chat(
            chat_id,
            ChatEntry {
                session_id: String::new(),
                title: "main chat".to_string(),
            },
        )?;
        let _ = self
            .sender()
            .send(
                chat_id,
                "💬 Now in: <b>main chat</b>",
                SendOptions::default(),
            )
            .await?;
        Ok(())
    }

    /// `/new` (seam: `deliver.SessionStart`).
    /// Source: `internal/commands/telegram_commands.go:549-594`.
    async fn new_chat(&self, chat_id: i64, arg: &str) -> Result<(), BotError> {
        let outcome: NewChatOutcome = self.services.new_chat(chat_id, arg).await?;
        if outcome.session_id.is_empty() {
            let _ = self
                .sender()
                .send(chat_id, &outcome.reply, SendOptions::default())
                .await?;
            return Ok(());
        }
        self.state.set_chat(
            chat_id,
            ChatEntry {
                session_id: outcome.session_id,
                title: outcome.title,
            },
        )?;
        let _ = self
            .sender()
            .send(chat_id, &outcome.reply, SendOptions::default())
            .await?;
        Ok(())
    }

    /// `/history`: N = all-digits arg else 10, clamped
    /// [1, 50]; output plain (never parsed as HTML).
    /// Source: `internal/commands/telegram_commands.go:595-612`.
    async fn history(&self, chat_id: i64, arg: &str) -> Result<(), BotError> {
        let n = parse_history_n(arg);
        let text = self.services.history_text(chat_id, n).await?;
        let _ = self
            .sender()
            .send(
                chat_id,
                &text,
                SendOptions {
                    mode: HtmlMode::Plain,
                    ..SendOptions::default()
                },
            )
            .await?;
        Ok(())
    }

    /// `/unread` (seam: raw `chat.unread_count` JSON in
    /// `<pre>`, truncated to 3500 runes).
    /// Source: `internal/commands/telegram_commands.go:832`.
    async fn unread(&self, chat_id: i64) -> Result<(), BotError> {
        let body = self.services.unread_text(chat_id).await?;
        let trunc: String = body.chars().take(3500).collect();
        let text = format!("<pre>{}</pre>", escape_text(&trunc));
        let _ = self
            .sender()
            .send(chat_id, &text, SendOptions::default())
            .await?;
        Ok(())
    }

    /// The current side-chat mapping, or the fixed
    /// side-chat-only sentence when in the main chat.
    /// Source: `internal/commands/telegram_commands.go:853-861`
    /// (`currentThread`).
    async fn current_thread(&self, chat_id: i64) -> Result<Option<ChatEntry>, BotError> {
        let mapping = self.state.chat(chat_id);
        if mapping.session_id.is_empty() {
            let _ = self
                .sender()
                .send(
                    chat_id,
                    "That works on side chats. Open one with /chats or make one with /new.",
                    SendOptions {
                        mode: HtmlMode::Plain,
                        ..SendOptions::default()
                    },
                )
                .await?;
            return Ok(None);
        }
        Ok(Some(mapping))
    }

    /// `/rename` (seam: gateway op, then stored title update).
    /// Source: `internal/commands/telegram_commands.go:869-890`.
    async fn rename(&self, chat_id: i64, arg: &str) -> Result<(), BotError> {
        let title = arg.trim();
        if title.is_empty() {
            let _ = self
                .sender()
                .send(
                    chat_id,
                    "Usage: /rename &lt;new title&gt;",
                    SendOptions::default(),
                )
                .await?;
            return Ok(());
        }
        let Some(mapping) = self.current_thread(chat_id).await? else {
            return Ok(());
        };
        self.services.rename_chat(chat_id, title).await?;
        self.state.set_chat(
            chat_id,
            ChatEntry {
                session_id: mapping.session_id,
                title: title.to_string(),
            },
        )?;
        let _ = self
            .sender()
            .send(
                chat_id,
                &format!("✏️ Renamed to <b>{}</b>.", escape_text(title)),
                SendOptions::default(),
            )
            .await?;
        Ok(())
    }

    /// `/pin` / `/unpin` / `/unarchive` (seam).
    /// Source: `internal/commands/telegram_commands.go:891-905`
    /// (`sessionOpCmd`).
    async fn session_op_cmd(
        &self,
        chat_id: i64,
        op: SessionOp,
        reply: &str,
    ) -> Result<(), BotError> {
        let Some(mapping) = self.current_thread(chat_id).await? else {
            return Ok(());
        };
        self.services
            .session_op(chat_id, &mapping.session_id, op)
            .await?;
        let _ = self
            .sender()
            .send(
                chat_id,
                reply,
                SendOptions {
                    mode: HtmlMode::Plain,
                    ..SendOptions::default()
                },
            )
            .await?;
        Ok(())
    }

    /// `/archive` (seam + mapping reset to main).
    /// Source: `internal/commands/telegram_commands.go:906-929`.
    async fn archive(&self, chat_id: i64) -> Result<(), BotError> {
        let Some(mapping) = self.current_thread(chat_id).await? else {
            return Ok(());
        };
        self.services
            .session_op(chat_id, &mapping.session_id, SessionOp::Archive)
            .await?;
        self.state.set_chat(
            chat_id,
            ChatEntry {
                session_id: String::new(),
                title: "main chat".to_string(),
            },
        )?;
        let _ = self
            .sender()
            .send(
                chat_id,
                "🗄 Archived. Back in the main chat.",
                SendOptions {
                    mode: HtmlMode::Plain,
                    ..SendOptions::default()
                },
            )
            .await?;
        Ok(())
    }

    /// `/delete` prompt (no owner gate — documented
    /// asymmetry, Python parity, Boss-approved 2026-11-01).
    /// Source: `internal/commands/telegram_commands.go:930-951`
    /// (`deletePrompt`).
    async fn delete_prompt(&self, chat_id: i64) -> Result<(), BotError> {
        let Some(mapping) = self.current_thread(chat_id).await? else {
            return Ok(());
        };
        let markup = InlineKeyboardMarkup {
            inline_keyboard: vec![vec![
                InlineKeyboardButton::new(
                    "🗑 Yes, delete",
                    &self.registry.register(CallbackEntry {
                        action: "delete".to_string(),
                        session_id: mapping.session_id.clone(),
                        ..CallbackEntry::default()
                    }),
                ),
                InlineKeyboardButton::new(
                    "Cancel",
                    &self.registry.register(CallbackEntry {
                        action: "noop".to_string(),
                        ..CallbackEntry::default()
                    }),
                ),
            ]],
        };
        let _ = self
            .sender()
            .send(
                chat_id,
                &format!(
                    "Delete side chat <b>{}</b> for good?",
                    escape_text(&mapping.title)
                ),
                SendOptions {
                    markup: Some(markup),
                    ..SendOptions::default()
                },
            )
            .await?;
        Ok(())
    }

    /// `/approvals` (seam: fresh `egress.approvals` read).
    /// Source: `internal/commands/telegram_approvals.go:131-168`.
    async fn approvals(&self, chat_id: i64) -> Result<(), BotError> {
        let pend = match self.services.pending_approvals().await {
            Ok(pend) => pend,
            Err(_) => {
                let _ = self
                    .sender()
                    .send(
                        chat_id,
                        "⚠️ Could not list approvals (gateway error).",
                        SendOptions {
                            mode: HtmlMode::Plain,
                            ..SendOptions::default()
                        },
                    )
                    .await?;
                return Ok(());
            }
        };
        let toggles = self.effective_toggles();
        if pend.is_empty() {
            let text = if toggles.auto_approve {
                "No pending approvals. Auto-approve is on (always)."
            } else {
                "No pending approvals. Auto-approve is off."
            };
            let _ = self
                .sender()
                .send(
                    chat_id,
                    text,
                    SendOptions {
                        mode: HtmlMode::Plain,
                        ..SendOptions::default()
                    },
                )
                .await?;
            return Ok(());
        }
        for d in &pend {
            let markup = approval_markup(&self.registry, d, "", "", None);
            let _ = self
                .sender()
                .send(
                    chat_id,
                    &approval_text(d),
                    SendOptions {
                        markup: Some(markup),
                        ..SendOptions::default()
                    },
                )
                .await?;
        }
        if pend.len() > 1 {
            let _ = self
                .sender()
                .send(
                    chat_id,
                    "Or decide them all:",
                    SendOptions {
                        markup: Some(approve_all_markup(&self.registry)),
                        ..SendOptions::default()
                    },
                )
                .await?;
        }
        Ok(())
    }

    /// `/autoapprove` (state file only — never rewrites
    /// `config.json`).
    /// Source: `internal/commands/telegram_approvals.go:169-226`.
    async fn auto_approve(&self, chat_id: i64, arg: &str) -> Result<(), BotError> {
        let a = arg.trim().to_lowercase();
        let parts: Vec<&str> = a.split_whitespace().collect();
        if !parts.is_empty() && parts[0] == "once" {
            if parts.len() > 2 {
                return self
                    .send_text(chat_id, "Usage: /autoapprove once on|off|status")
                    .await;
            }
            if parts.len() == 1 || parts[1] == "status" {
                // Report only.
            } else if parts[1] == "on" || parts[1] == "off" {
                let toggles = self.effective_toggles();
                let _ = self
                    .state
                    .set_toggles(toggles.auto_approve, parts[1] == "on");
            } else {
                return self
                    .send_text(chat_id, "Usage: /autoapprove once on|off|status")
                    .await;
            }
            let toggles = self.effective_toggles();
            let fallback = if toggles.auto_allow_once {
                "are decided with allow_once when auto-approve is on."
            } else {
                "are left for a human (exit 4 / needs_approval)."
            };
            let text = format!(
                "Auto-allow-once is <b>{}</b>: approvals with no forever option {} Auto-approve is <b>{}</b>.",
                on_off(toggles.auto_allow_once),
                fallback,
                on_off(toggles.auto_approve)
            );
            return self.send_text(chat_id, &text).await;
        }
        if a == "on" || a == "always" || a == "off" {
            let toggles = self.effective_toggles();
            let _ = self.state.set_toggles(a != "off", toggles.auto_allow_once);
        } else if !a.is_empty() && a != "status" {
            return self
                .send_text(chat_id, "Usage: /autoapprove on|off|status")
                .await;
        }
        let toggles = self.effective_toggles();
        if toggles.auto_approve {
            let mut text = "✅ Auto-approve is <b>on</b>: every approval gets Muse's forever choice (allow_always), so Muse never blocks.".to_string();
            if toggles.auto_allow_once {
                text += " Approvals with no forever option fall back to allow_once.";
            }
            return self.send_text(chat_id, &text).await;
        }
        self.send_text(
            chat_id,
            "Auto-approve is <b>off</b>: approvals come here with buttons.",
        )
        .await
    }

    /// `/watch` (state-file flag only; forwarding itself is
    /// NOT implemented — roadmap step 5b).
    /// Source: `internal/commands/telegram_commands.go:952-976`.
    async fn watch(&self, chat_id: i64, arg: &str) -> Result<(), BotError> {
        let a = arg.trim().to_lowercase();
        if a == "on" || a == "off" {
            let _ = self.state.set_watch(a == "on");
        }
        let toggles = self.effective_toggles();
        let text = if toggles.watch {
            "👀 Watch is <b>on</b>: the flag is stored; live event forwarding lands in step 5b."
        } else {
            "👀 Watch is <b>off</b>."
        };
        let _ = self
            .sender()
            .send(chat_id, text, SendOptions::default())
            .await?;
        Ok(())
    }

    /// `/files` (seam: last 40 history events → rows,
    /// reversed, deduped by path, capped at 12).
    /// Source: `internal/commands/telegram_commands.go:664-709`.
    async fn files(&self, chat_id: i64) -> Result<(), BotError> {
        let rows = self.services.files_list(chat_id).await?;
        let mut seen = std::collections::HashSet::new();
        let mut deduped: Vec<&crate::router::SharedFileRow> = Vec::new();
        for row in rows.iter().rev() {
            if seen.insert(row.path.clone()) {
                deduped.push(row);
            }
        }
        if deduped.len() > FILES_LIST_CAP {
            deduped.truncate(FILES_LIST_CAP);
        }
        if deduped.is_empty() {
            let _ = self
                .sender()
                .send(
                    chat_id,
                    "No files in recent messages here.",
                    SendOptions {
                        mode: HtmlMode::Plain,
                        ..SendOptions::default()
                    },
                )
                .await?;
            return Ok(());
        }
        let mut btns: Vec<Vec<InlineKeyboardButton>> = Vec::new();
        for row in deduped {
            let name = dl_file_name(&row.path);
            let label = format!("📥 {}", truncate_runes(&name, 50));
            btns.push(vec![InlineKeyboardButton::new(
                &label,
                &self.registry.register(CallbackEntry {
                    action: "dl".to_string(),
                    resource_path: row.path.clone(),
                    resource_size: row.size,
                    resource_mime: row.mime.clone(),
                    ..CallbackEntry::default()
                }),
            )]);
        }
        let markup = InlineKeyboardMarkup {
            inline_keyboard: btns,
        };
        let _ = self
            .sender()
            .send(
                chat_id,
                "Recent files (newest first). Tap one to get it:",
                SendOptions {
                    markup: Some(markup),
                    mode: HtmlMode::Plain,
                    ..SendOptions::default()
                },
            )
            .await?;
        Ok(())
    }

    /// `/feed` (seam; limit sanitised: digits-only else 10;
    /// 0/negative → 10).
    /// Source: `internal/commands/telegram_read.go:47-59`.
    async fn feed(&self, chat_id: i64, arg: &str) -> Result<(), BotError> {
        let limit = parse_feed_limit(arg);
        let text = self.services.feed_text(limit).await?;
        let _ = self
            .sender()
            .send(chat_id, &text, SendOptions::default())
            .await?;
        Ok(())
    }

    /// `/goals` (seam).
    /// Source: `internal/commands/telegram_read.go:87`.
    async fn goals(&self, chat_id: i64) -> Result<(), BotError> {
        let text = self.services.goals_text().await?;
        let _ = self
            .sender()
            .send(chat_id, &text, SendOptions::default())
            .await?;
        Ok(())
    }

    /// `/goal` (seam: blank arg → usage; body >3000 runes →
    /// head send + `goal.json` document, else head + `<pre>`).
    /// Source: `internal/commands/telegram_read.go:129-168`.
    async fn goal(&self, chat_id: i64, arg: &str) -> Result<(), BotError> {
        let id = arg.trim();
        if id.is_empty() {
            let _ = self
                .sender()
                .send(
                    chat_id,
                    "Usage: /goal &lt;id&gt; (ids from /goals)",
                    SendOptions::default(),
                )
                .await?;
            return Ok(());
        }
        let body = self.services.goal_text(id).await?;
        let head = goal_head(&body);
        if body.chars().count() > GOAL_DOCUMENT_THRESHOLD {
            let send_text = if head.is_empty() {
                "Goal:".to_string()
            } else {
                head
            };
            let _ = self
                .sender()
                .send(chat_id, &send_text, SendOptions::default())
                .await?;
            let _ = send_file(
                &self.api,
                chat_id,
                "goal.json",
                body.as_bytes(),
                "",
                "",
                &SendOptions::default(),
            )
            .await?;
            return Ok(());
        }
        let text = format!("{}<pre>{}</pre>", head, escape_text(&body));
        let _ = self
            .sender()
            .send(chat_id, &text, SendOptions::default())
            .await?;
        Ok(())
    }

    /// `/ideas` (seam: first 15 cards, one silent send each,
    /// plus a `▶️ Execute` button carrying the RAW title).
    /// Source: `internal/commands/telegram_read.go:193-228`.
    async fn ideas(&self, chat_id: i64) -> Result<(), BotError> {
        let rows = self.services.ideas_list().await?;
        if rows.is_empty() {
            let _ = self
                .sender()
                .send(
                    chat_id,
                    "No idea cards right now.",
                    SendOptions {
                        mode: HtmlMode::Plain,
                        ..SendOptions::default()
                    },
                )
                .await?;
            return Ok(());
        }
        for r in rows.iter().take(15) {
            let display_title = if r.title.is_empty() {
                "(untitled)".to_string()
            } else {
                r.title.clone()
            };
            let mut text = format!("💡 <b>{}</b>", escape_text(&display_title));
            if let Some(section) = &r.section
                && !section.is_empty()
            {
                text += &format!("\n<i>{}</i>", escape_text(section));
            }
            let markup = InlineKeyboardMarkup {
                inline_keyboard: vec![vec![InlineKeyboardButton::new(
                    "▶️ Execute",
                    &self.registry.register(CallbackEntry {
                        action: "idea_exec".to_string(),
                        idea_id: r.id.clone(),
                        title: r.title.clone(),
                        ..CallbackEntry::default()
                    }),
                )]],
            };
            let _ = self
                .sender()
                .send(
                    chat_id,
                    &text,
                    SendOptions {
                        markup: Some(markup),
                        silent: true,
                        ..SendOptions::default()
                    },
                )
                .await?;
        }
        Ok(())
    }

    /// `/usage` (seam).
    /// Source: `internal/commands/telegram_read.go:270`.
    async fn usage(&self, chat_id: i64) -> Result<(), BotError> {
        let text = self.services.usage_text().await?;
        let _ = self
            .sender()
            .send(chat_id, &text, SendOptions::default())
            .await?;
        Ok(())
    }

    /// `/wake` (seam).
    /// Source: `internal/commands/telegram_read.go:296`.
    async fn wake(&self, chat_id: i64) -> Result<(), BotError> {
        let text = self.services.wake().await?;
        let _ = self
            .sender()
            .send(chat_id, &text, SendOptions::default())
            .await?;
        Ok(())
    }

    /// `/fs` (seam: the service runs the op; the handler
    /// renders text / file / rm-confirm).
    /// Source: `internal/commands/telegram_fs.go:146-374`.
    async fn fs(&self, chat_id: i64, arg: &str) -> Result<(), BotError> {
        match self.services.fs_run(chat_id, arg).await? {
            FsOutcome::Text(text) => {
                let _ = self
                    .sender()
                    .send(chat_id, &text, SendOptions::default())
                    .await?;
                Ok(())
            }
            FsOutcome::File {
                name,
                data,
                caption,
            } => {
                let _ = send_file(
                    &self.api,
                    chat_id,
                    &name,
                    &data,
                    "",
                    &caption,
                    &SendOptions::default(),
                )
                .await?;
                Ok(())
            }
            FsOutcome::ConfirmDelete { path, recursive } => {
                let what = if recursive {
                    " and everything in it"
                } else {
                    ""
                };
                let markup = InlineKeyboardMarkup {
                    inline_keyboard: vec![vec![
                        InlineKeyboardButton::new(
                            "🗑 Yes, delete",
                            &self.registry.register(CallbackEntry {
                                action: "fs_rm".to_string(),
                                fs_path: path.clone(),
                                fs_recursive: recursive,
                                ..CallbackEntry::default()
                            }),
                        ),
                        InlineKeyboardButton::new(
                            "Cancel",
                            &self.registry.register(CallbackEntry {
                                action: "noop".to_string(),
                                ..CallbackEntry::default()
                            }),
                        ),
                    ]],
                };
                let _ = self
                    .sender()
                    .send(
                        chat_id,
                        &format!("Delete <code>/{}</code>{}?", escape_text(&path), what),
                        SendOptions {
                            markup: Some(markup),
                            ..SendOptions::default()
                        },
                    )
                    .await?;
                Ok(())
            }
        }
    }

    /// `/profile` (seam; Go is display-only, no gateway call).
    /// Source: `internal/commands/telegram_owner.go:87`.
    async fn owner_profile(&self, chat_id: i64) -> Result<(), BotError> {
        let text = self.services.profile_text().await?;
        let _ = self
            .sender()
            .send(chat_id, &text, SendOptions::default())
            .await?;
        Ok(())
    }

    /// `/update` (seam: dry-run check only).
    /// Source: `internal/commands/telegram_owner.go:107`.
    async fn owner_update(&self, chat_id: i64) -> Result<(), BotError> {
        let text = self.services.update_check().await?;
        let _ = self
            .sender()
            .send(chat_id, &text, SendOptions::default())
            .await?;
        Ok(())
    }

    /// `/login`: arm the awaiting-cookies state (in-memory
    /// only, lost on restart) and send the instruction.
    /// Source: `internal/commands/telegram_owner.go:252-266`.
    async fn owner_login(&self, mc: &MessageContext) -> Result<(), BotError> {
        self.awaiting_cookies
            .lock()
            .expect("awaiting lock")
            .insert(mc.chat_id, mc.user_id);
        let _ = self
            .sender()
            .send(
                mc.chat_id,
                "🔑 Send the muse.ai cookies now: the <code>cookies.txt</code> file from <code>castctl auth export</code>, or one line like <code>hatch_sess=…; other=…</code>. I delete your message after reading it. They replace the profile's <code>cookies.txt</code> (the old one is kept as <code>.bak</code>). This waiting state is kept in memory only and is lost if the bot restarts.",
                SendOptions::default(),
            )
            .await?;
        Ok(())
    }

    /// `/raw` (seam: route check + gateway call in the
    /// service; reply via `reply_long` as `<method>.json`).
    /// Source: `internal/commands/telegram_owner.go:145-183`.
    async fn owner_raw(&self, chat_id: i64, arg: &str) -> Result<(), BotError> {
        let (method, rest) = match arg.split_once(' ') {
            Some((m, r)) => (m.trim(), r.trim()),
            None => (arg.trim(), ""),
        };
        if method.is_empty() {
            let _ = self
                .sender()
                .send(chat_id, RAW_USAGE, SendOptions::default())
                .await?;
            return Ok(());
        }
        let body = self.services.raw_call(method, rest).await?;
        self.reply_long(chat_id, &body, &format!("{method}.json"), true)
            .await
    }

    /// `replyLong`: text >3800 runes → ONE document named
    /// stem (`.txt` appended when no dot), captioned
    /// `{name} ({n} chars)`; shorter + `pre` → one `<pre>`
    /// send; shorter, no pre → plain send.
    /// Source: `internal/commands/telegram_fs.go:123-144`.
    async fn reply_long(
        &self,
        chat_id: i64,
        text: &str,
        stem: &str,
        pre: bool,
    ) -> Result<(), BotError> {
        let mut name = stem.to_string();
        if !name.contains('.') {
            name += ".txt";
        }
        let n = text.chars().count();
        if n > CHUNK_SIZE {
            let _ = send_file(
                &self.api,
                chat_id,
                &name,
                text.as_bytes(),
                "",
                &format!("{name} ({n} chars)"),
                &SendOptions::default(),
            )
            .await?;
            return Ok(());
        }
        if pre {
            let _ = self
                .sender()
                .send(
                    chat_id,
                    &format!("<pre>{}</pre>", escape_text(text)),
                    SendOptions::default(),
                )
                .await?;
            return Ok(());
        }
        let _ = self
            .sender()
            .send(
                chat_id,
                text,
                SendOptions {
                    mode: HtmlMode::Plain,
                    ..SendOptions::default()
                },
            )
            .await?;
        Ok(())
    }

    /// Consume `mc` as the awaited cookie answer. Only a
    /// document or non-blank text from the arming user
    /// consumes; commands are handled before this runs, and
    /// photos fall through to the inbox untouched.
    /// Source: `internal/commands/telegram_owner.go:295-371`
    /// (`takeAwaitingCookies`).
    async fn take_awaiting_cookies(&self, mc: &MessageContext) -> Result<bool, BotError> {
        let armed = {
            let mut guard = self.awaiting_cookies.lock().expect("awaiting lock");
            match guard.get(&mc.chat_id) {
                Some(&uid) if uid == mc.user_id => {
                    let is_document = mc.media.as_ref().is_some_and(|m| m.kind == "document");
                    let has_text = !mc.text.trim().is_empty();
                    if is_document || has_text {
                        guard.remove(&mc.chat_id);
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            }
        };
        if !armed {
            return Ok(false);
        }
        // The message is deleted BEFORE validating (must not
        // linger on any path; delete error swallowed).
        let _ = self.api.delete_message(mc.chat_id, mc.message_id).await;
        let mut cookies_text: Option<String> = None;
        if let Some(media) = &mc.media
            && media.kind == "document"
        {
            if let Some(size) = media.size
                && size > LOGIN_COOKIES_LIMIT
            {
                return self
                    .send_text(mc.chat_id, "⚠️ That cookies file is too big (1 MiB limit).")
                    .await
                    .map(|()| true);
            }
            let data = download_media(&self.api, media).await?;
            if data.len() as i64 > LOGIN_COOKIES_LIMIT {
                return self
                    .send_text(mc.chat_id, "⚠️ That cookies file is too big (1 MiB limit).")
                    .await
                    .map(|()| true);
            }
            cookies_text = Some(String::from_utf8_lossy(&data).into_owned());
        }
        let text = cookies_text.unwrap_or_else(|| mc.text.clone());
        if !text.contains("hatch_sess") {
            return self
                .send_text(
                    mc.chat_id,
                    "⚠️ No hatch_sess cookie in that, so nothing changed. /login to retry.",
                )
                .await
                .map(|()| true);
        }
        let reply = self
            .services
            .save_login_cookies(mc.chat_id, mc.user_id, &text)
            .await?;
        let _ = self
            .sender()
            .send(mc.chat_id, &reply, SendOptions::default())
            .await?;
        Ok(true)
    }

    /// Handle one callback query: answer FIRST, then
    /// dispatch. Unknown registry entry → answer text
    /// `This button expired; run the command again.`
    /// Source: `internal/telegram/bot.go:1230-1303`
    /// (`onCallback`).
    pub async fn handle_callback(&self, cb: &CallbackQuery) -> Result<(), BotError> {
        let (chat_id, message_id) = match &cb.message {
            Some(m) => (m.chat.id, m.message_id),
            None => (cb.from.id, 0),
        };
        let Some(data) = cb.data.clone() else {
            let _ = self
                .sender()
                .answer(&cb.id, "This button expired; run the command again.")
                .await;
            return Ok(());
        };
        let Some(entry) = self.registry.lookup(&data) else {
            let _ = self
                .sender()
                .answer(&cb.id, "This button expired; run the command again.")
                .await;
            return Ok(());
        };
        // Answer first (empty text for a live button).
        let _ = self.sender().answer(&cb.id, "").await;
        match entry.action.as_str() {
            "decide" | "approve_all" => {
                // Consume-before-RPC: first tap wins; a
                // double-tap gets "expired".
                let Some(entry) = self.registry.consume(&data) else {
                    let _ = self
                        .sender()
                        .answer(&cb.id, "This button expired; run the command again.")
                        .await;
                    return Ok(());
                };
                let result = if entry.action == "decide" {
                    self.cb_decide(chat_id, message_id, &entry).await
                } else {
                    self.cb_approve_all(chat_id).await
                };
                if let Err(e) = result {
                    self.callback_warning(chat_id, &e).await;
                }
                Ok(())
            }
            "profile" => Ok(()), // Defensive drop: no profile action is ever registered.
            action => {
                let handled = self
                    .handle_callback_action(chat_id, message_id, &entry, action)
                    .await;
                match handled {
                    Ok(true) => Ok(()),
                    Ok(false) => Ok(()), // Unknown action: debug log only (no logger here).
                    Err(e) => {
                        self.callback_warning(chat_id, &e).await;
                        Ok(())
                    }
                }
            }
        }
    }

    /// The `decide` button: single-flight decide, confirm
    /// label + `<code>approval_id</code>`, silent send;
    /// confirm BEFORE clearing buttons; resume only when
    /// the button carries `AfterSeq`.
    /// Source: `internal/telegram/bot.go:1398-1447`
    /// (`cbDecide`).
    async fn cb_decide(
        &self,
        chat_id: i64,
        message_id: i64,
        entry: &CallbackEntry,
    ) -> Result<(), BotError> {
        let decided = self
            .claims
            .decide_once(&entry.approval_id, &entry.decision)
            .await?;
        if !decided {
            // Already decided elsewhere: clear the buttons
            // and return without a second confirm or resume.
            if message_id != 0 {
                let _ = self.sender().clear_markup(chat_id, message_id).await;
            }
            return Ok(());
        }
        let label = match entry.decision.as_str() {
            "allow_always" => "✅ Always allowed",
            "allow_once" => "✅ Allowed once",
            _ => "❌ Denied",
        };
        let _ = self
            .sender()
            .send(
                chat_id,
                &format!("{label}: <code>{}</code>", escape_text(&entry.approval_id)),
                SendOptions {
                    silent: true,
                    ..SendOptions::default()
                },
            )
            .await?;
        if message_id != 0 {
            let _ = self.sender().clear_markup(chat_id, message_id).await;
        }
        if let Some(after_seq) = entry.after_seq {
            self.services
                .resume_turn(chat_id, &entry.session_id, &entry.title, after_seq)
                .await;
        }
        Ok(())
    }

    /// The `approve_all` button: re-read pending, decide
    /// every forever-offering approval with `allow_always`,
    /// report titles joined `, ` or `nothing pending`.
    /// Source: `internal/telegram/bot.go:1448-1484`
    /// (`cbApproveAll`).
    async fn cb_approve_all(&self, chat_id: i64) -> Result<(), BotError> {
        let pend = self.services.pending_approvals().await?;
        let mut done: Vec<String> = Vec::new();
        for d in &pend {
            if !crate::approvals::offers_forever(d) {
                continue;
            }
            let decided = self.claims.decide_once(&d.id, "allow_always").await?;
            if !decided {
                continue;
            }
            done.push(if d.title.is_empty() {
                d.id.clone()
            } else {
                d.title.clone()
            });
        }
        let joined = if done.is_empty() {
            "nothing pending".to_string()
        } else {
            escape_text(&done.join(", "))
        };
        let _ = self
            .sender()
            .send(
                chat_id,
                &format!("✅ Always allowed: {joined}"),
                SendOptions::default(),
            )
            .await?;
        Ok(())
    }

    /// Callback actions the bot core does not own:
    /// `answer`, `open`, `chats_page`, `dl`, `delete`,
    /// `noop`, `idea_exec`, `fs_rm`.
    /// Source: `internal/commands/telegram_commands.go:977-1023`
    /// (`handleCallback`).
    async fn handle_callback_action(
        &self,
        chat_id: i64,
        message_id: i64,
        entry: &CallbackEntry,
        action: &str,
    ) -> Result<bool, BotError> {
        match action {
            "answer" => {
                if message_id != 0 {
                    let _ = self.sender().clear_markup(chat_id, message_id).await;
                }
                let _ = self
                    .sender()
                    .send(
                        chat_id,
                        &format!("➡️ {}", entry.answer),
                        SendOptions {
                            silent: true,
                            mode: HtmlMode::Plain,
                            ..SendOptions::default()
                        },
                    )
                    .await?;
                self.services
                    .start_turn(chat_id, entry.answer.clone())
                    .await;
                Ok(true)
            }
            "open" => {
                self.state.set_chat(
                    chat_id,
                    ChatEntry {
                        session_id: entry.session_id.clone(),
                        title: entry.title.clone(),
                    },
                )?;
                let _ = self
                    .sender()
                    .send(
                        chat_id,
                        &format!("💬 Now in: <b>{}</b>", escape_text(&entry.title)),
                        SendOptions::default(),
                    )
                    .await?;
                self.history(chat_id, "3").await?;
                Ok(true)
            }
            "chats_page" => {
                let page = entry.page.max(0) as usize;
                self.show_chats(chat_id, message_id, page).await?;
                Ok(true)
            }
            "dl" => {
                self.download_file(chat_id, entry).await?;
                Ok(true)
            }
            "delete" => {
                self.services
                    .delete_chat(chat_id, &entry.session_id)
                    .await?;
                let mapping = self.state.chat(chat_id);
                if mapping.session_id == entry.session_id {
                    let _ = self.state.set_chat(
                        chat_id,
                        ChatEntry {
                            session_id: String::new(),
                            title: "main chat".to_string(),
                        },
                    );
                }
                if message_id != 0 {
                    self.sender()
                        .edit(
                            chat_id,
                            message_id,
                            "🗑 Deleted. Back in the main chat.",
                            HtmlMode::Plain,
                            None,
                        )
                        .await?;
                }
                Ok(true)
            }
            "noop" => {
                if message_id != 0 {
                    self.sender()
                        .edit(chat_id, message_id, "Cancelled.", HtmlMode::Plain, None)
                        .await?;
                }
                Ok(true)
            }
            "idea_exec" => {
                match self.services.execute_idea(&entry.idea_id).await {
                    Ok(_) => {}
                    Err(e) if is_auth_error(&e) => {
                        let _ = self
                            .sender()
                            .send(
                                chat_id,
                                "🔑 muse.ai login expired. Use /login.",
                                SendOptions {
                                    mode: HtmlMode::Plain,
                                    ..SendOptions::default()
                                },
                            )
                            .await?;
                        return Ok(true);
                    }
                    Err(e) => return Err(e),
                }
                let title = if entry.title.is_empty() {
                    entry.idea_id.clone()
                } else {
                    entry.title.clone()
                };
                let _ = self
                    .sender()
                    .send(
                        chat_id,
                        &format!(
                            "▶️ Muse is working on: <b>{}</b>. Replies arrive here when they land.",
                            escape_text(&title)
                        ),
                        SendOptions::default(),
                    )
                    .await?;
                Ok(true)
            }
            "fs_rm" => {
                match self
                    .services
                    .fs_delete(&entry.fs_path, entry.fs_recursive)
                    .await
                {
                    Ok(reply) => {
                        if message_id != 0 {
                            // Edit passes no markup, so the
                            // Yes/Cancel buttons STAY.
                            self.sender()
                                .edit(chat_id, message_id, &reply, HtmlMode::Plain, None)
                                .await?;
                        }
                        Ok(true)
                    }
                    Err(e) if is_auth_error(&e) => {
                        let _ = self
                            .sender()
                            .send(
                                chat_id,
                                "🔑 muse.ai login expired. Use /login.",
                                SendOptions {
                                    mode: HtmlMode::Plain,
                                    ..SendOptions::default()
                                },
                            )
                            .await?;
                        Ok(true)
                    }
                    Err(e) => Err(e),
                }
            }
            _ => Ok(false),
        }
    }

    /// Serve one download-button tap: refuse oversize files
    /// (both gates), otherwise download and send with
    /// `SendFile`.
    /// Source: `internal/commands/telegram_commands.go:711-756`
    /// (`downloadFile`).
    async fn download_file(&self, chat_id: i64, entry: &CallbackEntry) -> Result<(), BotError> {
        if let Some(size) = entry.resource_size
            && exceeds_upload_limit(size)
        {
            self.send_text(chat_id, TOO_BIG_DOWNLOAD_REFUSAL).await?;
            return Ok(());
        }
        let downloaded = self.services.download_file(&entry.resource_path).await?;
        if exceeds_upload_limit(downloaded.data.len() as i64) {
            self.send_text(chat_id, TOO_BIG_DOWNLOAD_REFUSAL).await?;
            return Ok(());
        }
        let mime = downloaded.mime.as_deref().unwrap_or("");
        let _ = send_file(
            &self.api,
            chat_id,
            &downloaded.name,
            &downloaded.data,
            mime,
            "",
            &SendOptions::default(),
        )
        .await?;
        Ok(())
    }

    /// Chat warning for a callback-handler error:
    /// `⚠️ <summarizeError, truncated to 600 runes,
    /// HTML-escaped>`.
    /// Source: `internal/telegram/bot.go:1295-1302`.
    async fn callback_warning(&self, chat_id: i64, e: &BotError) {
        let summary = e.summary(self.api.token());
        let trunc: String = summary.chars().take(600).collect();
        let _ = self
            .sender()
            .send(
                chat_id,
                &format!("⚠️ {}", escape_text(&trunc)),
                SendOptions::default(),
            )
            .await;
    }

    /// Send one HTML-mode message (command reports carry
    /// `<b>` markup, pre-escaped where they interpolate
    /// state; no user or server text is interpolated).
    /// Source: `internal/commands/telegram_approvals.go:228-232`
    /// (`sendText`).
    async fn send_text(&self, chat_id: i64, text: &str) -> Result<(), BotError> {
        let _ = self
            .sender()
            .send(chat_id, text, SendOptions::default())
            .await?;
        Ok(())
    }
}

/// `on` / `off` for a toggle.
/// Source: `internal/commands/telegram_approvals.go:222-226`
/// (`onOff`).
fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

/// `/history` N: all-digits arg else 10, clamped [1, 50].
/// Source: `internal/commands/telegram_commands.go:595-612`.
fn parse_history_n(arg: &str) -> usize {
    let trimmed = arg.trim();
    let n: usize = if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit()) {
        trimmed.parse().unwrap_or(10)
    } else {
        10
    };
    n.clamp(1, 50)
}

/// `/feed` limit: digits-only else 10; 0/negative → 10.
/// Source: `internal/commands/telegram_read.go:47-57`
/// (`parseFeedLimit`).
fn parse_feed_limit(arg: &str) -> usize {
    let trimmed = arg.trim();
    if trimmed.is_empty() || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return 10;
    }
    match trimmed.parse::<i64>() {
        Ok(n) if n > 0 => n as usize,
        _ => 10,
    }
}

/// Base name of a path (Go `dlFileName` / `path.Base`).
/// No direct Go function counterpart in the bot core file
/// list; `dlFileName` is used by `files` /
/// `downloadFile` (`internal/commands/telegram_commands.go:664-756`).
fn dl_file_name(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    if base.is_empty() {
        path.to_string()
    } else {
        base.to_string()
    }
}

/// Truncate to at most `n` runes.
/// Source: `internal/telegram/bot.go:1485-1492`
/// (`truncateRunes`).
fn truncate_runes(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect()
    }
}

/// `/goal` head line from the raw `goals.get` JSON body:
/// `🎯 <b>title</b> [status]` + optional subtitle/
/// description line. Empty when the body has no goal map.
/// Source: `internal/commands/telegram_read.go:129-168`.
fn goal_head(body: &str) -> String {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return String::new();
    };
    let g = match value.get("goal") {
        Some(inner) if inner.is_object() => inner,
        _ => &value,
    };
    if !g.is_object() {
        return String::new();
    }
    let title = g.get("title").and_then(Value::as_str).unwrap_or("");
    let status = g.get("status").and_then(Value::as_str).unwrap_or("");
    let mut head = format!(
        "🎯 <b>{}</b> [{}]\n",
        escape_text(title),
        escape_text(status)
    );
    let sub = g
        .get("subtitle")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            g.get("description")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("");
    if !sub.is_empty() {
        head += &format!("{}\n", escape_text(sub));
    }
    head
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_text_matches_go_verbatim() {
        // Copied from internal/commands/telegram_commands.go:40-64
        // (telegramBotHelpText) at main 1396697.
        let go = "<b>Muse on Telegram</b>\nType anything to talk to Muse in the current conversation. Send a photo or file to put it in Muse's System Files (<code>telegram-inbox/</code>) and tell Muse about it.\n\n<b>Conversation</b>\n/chats open another chat · /main · /new [title]\n/history [N] · /unread · /stop\n/rename &lt;title&gt; · /pin · /unpin · /archive · /unarchive · /delete\n\n<b>Muse</b>\n/status · /approvals · /autoapprove on|off · /watch on|off\n/files · /feed · /goals · /goal &lt;id&gt; · /ideas · /usage · /wake\n\n<b>System Files</b>\n/fs ls [path] · /fs tree [path] [depth] · /fs cat &lt;path&gt; · /fs get &lt;path&gt;\n/fs find &lt;name&gt; · /fs stat &lt;path&gt; · /fs mkdir &lt;path&gt; · /fs mv &lt;src&gt; &lt;dst&gt; · /fs rm [-r] &lt;path&gt;\n\n<b>Admin</b>\n/profile · /login (new cookies) · /update · /raw &lt;method&gt; [json]";
        assert_eq!(COMMAND_HELP_TEXT, go);
    }

    #[test]
    fn parse_history_n_rules() {
        assert_eq!(parse_history_n(""), 10);
        assert_eq!(parse_history_n("abc"), 10);
        assert_eq!(parse_history_n("0"), 1);
        assert_eq!(parse_history_n("51"), 50);
        assert_eq!(parse_history_n("25"), 25);
    }

    #[test]
    fn parse_feed_limit_rules() {
        assert_eq!(parse_feed_limit(""), 10);
        assert_eq!(parse_feed_limit("abc"), 10);
        assert_eq!(parse_feed_limit("0"), 10);
        assert_eq!(parse_feed_limit("5"), 5);
    }

    #[test]
    fn goal_head_renders_title_status_subtitle() {
        let body = r#"{"goal": {"title": "Ship it", "status": "active", "subtitle": "soon"}}"#;
        assert_eq!(goal_head(body), "🎯 <b>Ship it</b> [active]\nsoon\n");
        assert_eq!(goal_head("not json"), "");
    }

    #[test]
    fn dl_file_name_is_base() {
        assert_eq!(dl_file_name("/a/b/c.txt"), "c.txt");
        assert_eq!(dl_file_name("plain"), "plain");
    }
}
