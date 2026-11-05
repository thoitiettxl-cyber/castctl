// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The bot: construction (`getMe` once), the long-poll
//! loop, the allowlist gate, turn tracking, shutdown.
//!
//! Go sources: `internal/telegram/bot.go`
//! (`PollTimeout`/`ClientTimeout`, `NewBot`, `Run`,
//! `getMe`, `processUpdate`, `onMessage`, `onCallback`,
//! `BeginTurn`/`EndTurn`/`HasActiveTurn`, `SetCommands`,
//! `MaxHandledID`),
//! `internal/telegram/dispatcher.go`
//! (`onOffset`/`onDropped` hook semantics),
//! `internal/commands/telegram.go:214-234`
//! (owner merged into the allowlist at startup).

use std::collections::HashSet;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use castctl_config::telegram::valid_telegram_token_shape;
use castctl_transport::TransportError;

use crate::api::{BotApi, ShutdownSignal};
use crate::claims::ClaimManager;
use crate::commands::{CommandHandler, CommandHandlerConfig};
use crate::dispatcher::{Dispatcher, UpdateProcessor};
use crate::error::BotError;
use crate::files::media_of;
use crate::registry::CallbackRegistry;
use crate::router::{BotServices, COMMAND_MENU};
use crate::send::validate_commands;
use crate::state::TelegramStateStore;
use crate::types::{MessageContext, Update};

/// Long-poll timeout the bot asks Telegram for (the
/// library sends `pollTimeout − 1s`).
/// Source: `internal/telegram/bot.go:62-67`
/// (`PollTimeout = 26s`).
pub const POLL_TIMEOUT: Duration = Duration::from_secs(26);

/// Default 5xx backoff ladder for the poll loop.
/// [DEVIATION] Go's bot core has no 5xx retry — a 5xx
/// surfaces to `errorsHandler` (log-only) and the library
/// polls again. Here a bounded ladder spaces retries out
/// instead of hot-looping on a sick upstream; the ladder
/// resets on the first successful poll. See PORTING §M5a.
pub const DEFAULT_5XX_BACKOFF: &[Duration] = &[
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(30),
];

/// Fixed pause before retrying a poll that failed for a
/// non-5xx reason (auth, decode, network). No direct Go
/// counterpart: Go's library logs the error via
/// `errorsHandler` and polls again; the 1s pause keeps a
/// persistently failing poll (e.g. a revoked token) from
/// spinning the CPU.
pub const POLL_ERROR_PAUSE: Duration = Duration::from_secs(1);

/// Settings for [`Bot::new`]. No direct Go type
/// counterpart: Go spreads these across `botSettings`
/// (`internal/telegram/bot.go:96-120`) and the
/// `telegram.go` startup wiring.
#[derive(Debug, Clone)]
pub struct BotSettings {
    /// Allowed user ids (the owner is merged in by
    /// [`Bot::new`]; callers pass the config allowlist).
    pub allowed_user_ids: Vec<i64>,
    /// 5xx backoff ladder (empty = [`DEFAULT_5XX_BACKOFF`]).
    pub backoff_ladder: Vec<Duration>,
}

impl Default for BotSettings {
    fn default() -> Self {
        Self {
            allowed_user_ids: Vec::new(),
            backoff_ladder: DEFAULT_5XX_BACKOFF.to_vec(),
        }
    }
}

/// The bot: owns the API client, the dispatcher, the
/// command handler, the state store, and turn tracking.
///
/// Construction calls `getMe` once, exactly like Go
/// (`internal/telegram/bot.go`: `NewBot` calls `getMe`
/// unless `WithSkipGetMe` — the upload instance is the
/// only skip, and this crate has no upload instance).
pub struct Bot {
    api: Arc<BotApi>,
    state: Arc<TelegramStateStore>,
    registry: Arc<CallbackRegistry>,
    claims: Arc<ClaimManager>,
    services: Arc<dyn BotServices>,
    handler: CommandHandler,
    dispatcher: Arc<Dispatcher>,
    allowed: HashSet<i64>,
    active_turns: Mutex<HashSet<i64>>,
    /// Shutdown flag, checked at the top of every poll
    /// iteration. `Notify` alone is not enough:
    /// `notify_waiters()` wakes only waiters that are
    /// CURRENTLY waiting, so a shutdown requested while
    /// the loop is between selects would be lost and the
    /// loop would poll forever. The flag makes the
    /// request durable; the `Notify` only wakes a
    /// sleeping poll early. Shared with the API client
    /// (429 retry sleeps) via one [`ShutdownSignal`].
    shutdown_signal: Arc<ShutdownSignal>,
    /// Whether `run()` has started (Go `Start`'s
    /// `started` guard, `bot.go:505-523`: a second start
    /// returns `"telegram: bot already started"`).
    started: AtomicBool,
    backoff_ladder: Vec<Duration>,
}

impl std::fmt::Debug for Bot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bot")
            .field("api", &self.api)
            .field("allowed_count", &self.allowed.len())
            .field("max_handled_id", &self.dispatcher.max_seen())
            .finish_non_exhaustive()
    }
}

impl UpdateProcessor for Bot {
    fn process(
        self: Arc<Self>,
        update: Update,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            self.process_update(update).await;
        })
    }
}

impl Bot {
    /// Build the bot and call `getMe` once. Rejects an
    /// empty allowlist (after merging the owner) and a
    /// malformed token, before any network call.
    /// Source: `internal/telegram/bot.go:191-274`
    /// (`NewBot`); token shape
    /// `internal/telegram/bot.go:63-65` (`botTokenShape`).
    pub async fn new(
        api: Arc<BotApi>,
        state: Arc<TelegramStateStore>,
        registry: Arc<CallbackRegistry>,
        claims: Arc<ClaimManager>,
        services: Arc<dyn BotServices>,
        handler_config: CommandHandlerConfig,
        settings: BotSettings,
    ) -> Result<Arc<Self>, BotError> {
        if !valid_telegram_token_shape(api.token()) {
            return Err(BotError::Validation(
                "telegram token has an invalid shape".to_string(),
            ));
        }
        let mut allowed: HashSet<i64> = settings.allowed_user_ids.iter().copied().collect();
        // Owner merged into the allowlist at startup.
        // Source: `internal/commands/telegram.go:214-234`.
        if handler_config.owner_id_set {
            allowed.insert(handler_config.owner_id);
        }
        if allowed.is_empty() {
            return Err(BotError::Validation(
                "telegram allowlist is empty".to_string(),
            ));
        }
        // `getMe` at construction (no `SkipGetMe` here).
        // The shutdown signal is installed AFTER this call
        // (below), so a 429 sleep during construction is
        // uncancellable — but that window is moot: no `Bot`
        // handle exists yet for anyone to call
        // `request_shutdown` on (fix loop 2, red NIT 7).
        let _me = api.get_me().await?;
        let dispatcher = Arc::new(Dispatcher::new());
        // One shutdown signal for the poll loop, the 429
        // retry sleeps (installed on the API client), and
        // the claims manager's `decide_once` waiters.
        let shutdown_signal = ShutdownSignal::new();
        api.set_shutdown_signal(Arc::clone(&shutdown_signal));
        let handler = CommandHandler::new(
            Arc::clone(&api),
            Arc::clone(&state),
            Arc::clone(&registry),
            Arc::clone(&claims),
            Arc::clone(&services),
            handler_config,
        );
        let bot = Arc::new(Self {
            api,
            state: Arc::clone(&state),
            registry,
            claims,
            services,
            handler,
            dispatcher: Arc::clone(&dispatcher),
            allowed,
            active_turns: Mutex::new(HashSet::new()),
            shutdown_signal,
            started: AtomicBool::new(false),
            backoff_ladder: if settings.backoff_ladder.is_empty() {
                DEFAULT_5XX_BACKOFF.to_vec()
            } else {
                settings.backoff_ladder
            },
        });
        // Offset hook: persist the max update id BEFORE
        // handling (at-most-once). The hook runs under the
        // dispatcher lock, exactly as Go does
        // (`internal/telegram/dispatcher.go:100-114`).
        let state_hook = Arc::clone(&state);
        dispatcher.set_on_offset(Arc::new(move |id| {
            let _ = state_hook.note_offset(id);
        }));
        dispatcher.set_processor(Arc::clone(&bot) as Arc<dyn UpdateProcessor>);
        Ok(bot)
    }

    /// The command handler (routing, gates, callbacks).
    #[must_use]
    pub fn handler(&self) -> &CommandHandler {
        &self.handler
    }

    /// The callback registry.
    #[must_use]
    pub fn registry(&self) -> &Arc<CallbackRegistry> {
        &self.registry
    }

    /// The claims manager.
    #[must_use]
    pub fn claims(&self) -> &Arc<ClaimManager> {
        &self.claims
    }

    /// Highest update id accepted so far (dispatcher
    /// `maxSeen`; the state file holds the same value via
    /// the offset hook).
    /// Source: `internal/telegram/bot.go:499`
    /// (`MaxHandledID`).
    #[must_use]
    pub fn max_handled_id(&self) -> i64 {
        self.dispatcher.max_seen()
    }

    /// Number of updates dropped (queue-full / shutdown /
    /// no-processor). No direct Go getter counterpart: Go
    /// reports drops only via the `onDropped` hook; this
    /// counter mirrors `Dispatcher::dropped`. No
    /// `on_dropped` hook is wired in this crate (there is
    /// no logger to send it to — Go's contract is "the log
    /// is the only observability for the loss",
    /// `dispatcher.go:100-122`), so this counter is the
    /// ONLY observability for drops until a logger lands
    /// (fix loop 1, red N2).
    #[must_use]
    pub fn dropped(&self) -> i64 {
        self.dispatcher.dropped()
    }

    /// Mark a turn active for `chat_id`. Callers are the
    /// turn runner only; the core never marks a turn
    /// active itself.
    /// Source: `internal/telegram/bot.go:529-538`
    /// (`BeginTurn`).
    pub fn begin_turn(&self, chat_id: i64) {
        self.active_turns.lock().expect("turn lock").insert(chat_id);
    }

    /// Clear the active-turn mark for `chat_id`.
    /// Source: `internal/telegram/bot.go:539-547`
    /// (`EndTurn`).
    pub fn end_turn(&self, chat_id: i64) {
        self.active_turns
            .lock()
            .expect("turn lock")
            .remove(&chat_id);
    }

    /// Whether `chat_id` has an active turn.
    /// Source: `internal/telegram/bot.go:548-554`
    /// (`HasActiveTurn`).
    #[must_use]
    pub fn has_active_turn(&self, chat_id: i64) -> bool {
        self.active_turns
            .lock()
            .expect("turn lock")
            .contains(&chat_id)
    }

    /// Whether any chat has an active turn.
    /// Source: `internal/telegram/bot.go:529-554` (used by
    /// `NotifyPending`'s early return).
    #[must_use]
    pub fn any_active_turn(&self) -> bool {
        !self.active_turns.lock().expect("turn lock").is_empty()
    }

    /// Validate the command menu and push it to Telegram.
    /// Validation runs BEFORE any request; on failure the
    /// error is returned and zero API calls are made.
    /// Source: `internal/telegram/bot.go:1786-1816`
    /// (`SetCommands`).
    pub async fn set_commands(&self, commands: &[(String, String)]) -> Result<(), BotError> {
        validate_commands(commands)?;
        self.api.set_my_commands(commands).await
    }

    /// Push the built-in 30-command menu to Telegram.
    /// No direct Go counterpart: Go's caller passes
    /// `telegramCommandMenu` (`internal/commands/telegram_commands.go:73-118`);
    /// this is the same list, from `router::COMMAND_MENU`.
    pub async fn set_menu_commands(&self) -> Result<(), BotError> {
        let commands: Vec<(String, String)> = COMMAND_MENU
            .iter()
            .map(|e| (e.name.to_string(), e.description.to_string()))
            .collect();
        self.set_commands(&commands).await
    }

    /// Signal the poll loop to stop. The in-flight poll is
    /// cancelled via `tokio::select!`; a 429 sleep inside
    /// `call_json` is cancelled the same way (the future
    /// is dropped, and the sleep itself observes the
    /// signal). The flag (not just the `Notify`) is what
    /// the loop checks, so a request made while the loop
    /// is between selects is never lost. Also signals the
    /// claims manager, so `decide_once` waiters return
    /// `Cancelled` instead of hanging.
    pub fn request_shutdown(&self) {
        self.shutdown_signal.request();
        self.claims.request_shutdown();
    }

    /// Wait for shutdown. The waiter is registered
    /// (`enable()`) BEFORE the flag is re-checked, so a
    /// request landing between the loop-top flag check and
    /// the `select!` is still observed promptly instead
    /// of waiting out one poll (up to 40s) — fix loop 1,
    /// red N5.
    async fn shutdown_wait(&self) {
        self.shutdown_signal.wait().await;
    }

    /// Run the long-poll loop until shutdown is requested
    /// or the poll fails fatally. A poll error never ends
    /// the loop: 5xx backs off on the ladder, other errors
    /// pause 1s, then polling resumes — Go's
    /// `errorsHandler` is log-only and the library polls
    /// again.
    /// Source: `internal/telegram/bot.go:445-479` (the poll
    /// instance: `WithAllowedUpdates{message,
    /// callback_query}`, `WithInitialOffset`).
    ///
    /// Deliberate: an empty `Ok` batch is re-polled
    /// immediately, with no pacing sleep (fix loop 2, red
    /// NIT 5). In production this cannot spin: the server
    /// holds an empty long poll for `POLL_TIMEOUT_SECS`
    /// (25s) before answering, so the loop runs at ~0.04
    /// req/s. Only a server/proxy returning empty batches
    /// immediately would spin it — and Go's library (same
    /// 26s poll timeout, `bot.go:62-67`) would spin
    /// identically there. No pacing sleep is added.
    ///
    /// A second concurrent (or later) `run()` returns
    /// `"telegram: bot already started"`, like Go's
    /// `Start` (`bot.go:505-523`); the guard is never
    /// reset. Offset arithmetic saturates: an
    /// `update_id` of `i64::MAX` advances the poll offset
    /// to `i64::MAX`, never wraps to `i64::MIN` (fix
    /// loop 1, red R4).
    pub async fn run(self: &Arc<Self>) -> Result<(), BotError> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Err(BotError::Validation(
                "telegram: bot already started".to_string(),
            ));
        }
        let mut backoff_idx = 0usize;
        // In-memory poll offset: advances past EVERY update
        // received (strangers included), mirroring the Go
        // library, which advances its offset after handing
        // each update to the handler. The STATE offset only
        // advances for accepted updates, via the
        // dispatcher's `onOffset` hook.
        let mut poll_offset = self.state.offset().saturating_add(1);
        loop {
            if self.shutdown_signal.is_set() {
                break;
            }
            let poll = self.api.get_updates(poll_offset);
            let result = tokio::select! {
                () = self.shutdown_wait() => break,
                r = poll => r,
            };
            match result {
                Ok(updates) => {
                    backoff_idx = 0;
                    for update in updates {
                        poll_offset = poll_offset.max(update.update_id.saturating_add(1));
                        // Allowlist BEFORE enqueue: a stranger
                        // is dropped SILENTLY — no reply, no
                        // state change, never reaches the
                        // dispatcher, never advances the
                        // offset hook. `uid == 0` (no sender)
                        // is dropped unconditionally, as Go's
                        // `allowlistMiddleware` does
                        // (`bot.go:651-667`).
                        // Source: `internal/telegram/bot.go:651-667`.
                        let uid = update.sender_id();
                        if uid == 0 || !self.allowed.contains(&uid) {
                            continue;
                        }
                        let _ = self.dispatcher.enqueue(update);
                    }
                }
                Err(ref e) if is_http_5xx(e) => {
                    let ladder = &self.backoff_ladder;
                    let wait = ladder[backoff_idx.min(ladder.len() - 1)];
                    backoff_idx = backoff_idx.saturating_add(1);
                    tokio::select! {
                        () = self.shutdown_wait() => break,
                        () = tokio::time::sleep(wait) => {}
                    }
                }
                Err(_) => {
                    tokio::select! {
                        () = self.shutdown_wait() => break,
                        () = tokio::time::sleep(POLL_ERROR_PAUSE) => {}
                    }
                }
            }
        }
        self.dispatcher.shutdown().await;
        self.services.wait_turns().await;
        Ok(())
    }

    /// Process one accepted update: callback first, else
    /// message, else ignore (no logger in this crate).
    /// The allowlist is enforced here as defence-in-depth
    /// for any future direct caller (the poll loop already
    /// gates before enqueue; Go's `allowlistMiddleware`
    /// wraps the handler so all paths pass it —
    /// `bot.go:651-667`; fix loop 1, safety N4).
    /// Source: `internal/telegram/bot.go` (`processUpdate`
    /// / `onMessage` / `onCallback` dispatch).
    async fn process_update(self: &Arc<Self>, update: Update) {
        let uid = update.sender_id();
        if uid == 0 || !self.allowed.contains(&uid) {
            return;
        }
        if let Some(cb) = update.callback_query {
            let _ = self.handler.handle_callback(&cb).await;
            return;
        }
        if let Some(msg) = update.message {
            self.on_message(msg).await;
        }
        // Edited messages and anything else: no handler in
        // this crate (Go routes them through `senderID`
        // only for identification; nothing dispatches on
        // them).
    }

    /// Build the message context and dispatch it. A
    /// message with no text AND no media is ignored.
    /// Source: `internal/telegram/bot.go` (`onMessage`).
    async fn on_message(&self, msg: crate::types::Message) {
        let media = media_of(&msg);
        let text = msg.text.clone().unwrap_or_default();
        if text.is_empty() && media.is_none() {
            return;
        }
        let mc = MessageContext {
            chat_id: msg.chat.id,
            user_id: msg.from.as_ref().map_or(0, |u| u.id),
            text,
            message_id: msg.message_id,
            media: media.clone(),
            caption: msg.caption.clone().unwrap_or_default(),
            is_document: media.as_ref().is_some_and(|m| m.kind == "document"),
        };
        let _ = self.handler.dispatch_message(mc).await;
    }
}

/// Whether the error is an HTTP 5xx (API envelope code or
/// transport gateway status). Used only by the poll loop's
/// backoff ladder. No direct Go counterpart (Go's bot core
/// has no 5xx retry — see [`DEFAULT_5XX_BACKOFF`]).
fn is_http_5xx(e: &BotError) -> bool {
    match e {
        BotError::Api { code, .. } => (500..=599).contains(code),
        BotError::Transport(TransportError::Gateway(summary)) => {
            (500..=599).contains(&summary.status)
        }
        _ => false,
    }
}
