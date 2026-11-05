// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Telegram bot core for the castctl Rust port (M5a).
//!
//! Go sources: `internal/telegram` (`bot.go`, `dispatcher.go`,
//! `state.go`, `approvals.go`, `claims.go`, `files.go`,
//! `inbound.go`, `text.go`) and `internal/commands`
//! (`telegram.go`, `telegram_commands.go`, `telegram_read.go`,
//! `telegram_fs.go`, `telegram_owner.go`,
//! `telegram_approvals.go`) at `main` `1396697`.
//!
//! Crate map:
//!
//! | Module | Contents |
//! | `error` | `BotError` taxonomy + allowlist summary |
//! | `types` | Bot API wire types (`Update`, `Message`, `CallbackQuery`, media) |
//! | `tls` | TEMPORARY minimal TLS HTTP client (parent decision, see `tls.rs`; delete on M4b rebase) |
//! | `api` | `BotApi`: Bot API calls, 429 retry, envelope decode, multipart upload |
//! | `send` | `Send` / `SendMD` / `Edit` / `EditPlain` / `Delete` / `answer` surface |
//! | `state` | `telegram-state.json` v1 store (atomic save, toggles, sent-media) |
//! | `dispatcher` | Per-chat FIFO workers, dedupe window, offset-before-handle |
//! | `registry` | `CallbackRegistry` (`c:` tokens, cap 3000) + markup builders |
//! | `approvals` | `Approval` / `DescribeApproval` / `ChooseAutoDecision` / `ApprovalText` |
//! | `claims` | Claim protocol + `decideOnce` single-flight + auto-log |
//! | `files` | `SendFile`, `MediaOf`, `InboxName`, `DownloadMedia` |
//! | `router` | 30-command table, parse, owner gate, `BotServices` seam trait |
//! | `commands` | `CommandHandler`: full handlers + seam dispatch + callbacks |
//! | `bot` | `Bot`: construction (`getMe`), poll loop, allowlist gate, turn tracking |
//!
//! Invariants (each has a test; see PORTING.md §M5a):
//! - The bot token NEVER appears in any `Debug`/`Display`/log/error
//!   string. Every struct holding the token has a hand-written
//!   `Debug` rendering `[redacted]`; every error/log line goes
//!   through `castctl-log-redact` summaries.
//! - No proxy environment variables are ever read: HTTP goes
//!   through the supplied `castctl-transport` dialer only
//!   (`HttpClient` for plaintext tests, `tls::TlsHttpClient`
//!   for production HTTPS). Redirects are never followed.
//! - Offset is persisted BEFORE handling (at-most-once per
//!   update id); a crash mid-handle loses that update instead
//!   of redelivering it (`internal/telegram/state.go:13-47`).
//! - Turn streaming is M5b: handlers needing a turn or the
//!   gateway go through the `BotServices` trait and are marked
//!   `seam` in the PORTING §M5a command table, never claimed
//!   as fully implemented.
//! - No `unsafe` in this crate's code. No `unwrap()`/`expect()`
//!   on external input in non-test code.

pub mod api;
pub mod approvals;
pub mod bot;
pub mod claims;
pub mod commands;
pub mod dispatcher;
pub mod error;
pub mod files;
pub mod registry;
pub mod router;
pub mod send;
pub mod state;
pub mod tls;
pub mod types;

pub use api::{BotApi, BotApiConfig};
pub use approvals::{Approval, approval_text, choose_auto_decision, describe_approval};
pub use bot::{Bot, BotSettings, POLL_TIMEOUT};
pub use claims::{AutoLogEntry, ClaimManager};
pub use commands::{COMMAND_HELP_TEXT, CommandHandler, CommandHandlerConfig, is_auth_error};
pub use dispatcher::{
    DISPATCHER_DEDUPE_WINDOW, DISPATCHER_IDLE_TIMEOUT, DISPATCHER_QUEUE_DEPTH,
    DISPATCHER_SHUTDOWN_TIMEOUT, Dispatcher,
};
pub use error::BotError;
pub use files::{InboxMedia, download_media, inbox_name, media_of};
pub use registry::{CallbackEntry, CallbackRegistry, approval_markup, approve_all_markup};
pub use router::{
    BotServices, COMMAND_MENU, ChatRow, CommandKind, DownloadedFile, FsOutcome, IdeaCard,
    NewChatOutcome, OWNER_ONLY_SENTENCE, SessionOp, SessionRow, SharedFileRow, command_kind,
    is_known_command, is_owner_command, is_valid_command_name, parse_command,
};
pub use send::{HtmlMode, SendOptions};
pub use state::{ChatEntry, TelegramStateStore, state_path_for_profile_dir};
pub use types::{CallbackQuery, Chat, Message, Update, User};
