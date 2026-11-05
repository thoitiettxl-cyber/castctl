// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Command table, parsing, owner gate, and the `BotServices`
//! seam trait.
//!
//! Go sources: `internal/commands/telegram_commands.go:73-235`
//! (`telegramCommandMenu`, `dispatch`, `runCommand`) and
//! `internal/commands/telegram_owner.go:65-81`
//! (`isOwnerCommand`, `isOwner`).
//!
//! The routing table has ALL 30 commands from
//! `telegramCommandMenu` + the `runCommand` switch. Commands
//! whose handler needs the gateway or the turn runner go
//! through [`BotServices`]; the PR-body table in PORTING.md
//! §M5a marks each command full vs seam — a seam command is
//! routed and gated here, but its work is M5b/M4b wiring,
//! never claimed as fully implemented.

use std::future::Future;
use std::pin::Pin;

use crate::approvals::Approval;
use crate::error::BotError;
use crate::files::InboxMedia;

/// One menu entry: command name + short description.
/// Source: `internal/commands/telegram_commands.go:73-118`
/// (`telegramCommandMenu`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandMenuEntry {
    /// Command name (without `/`).
    pub name: &'static str,
    /// Menu description.
    pub description: &'static str,
}

/// The "/" menu: exactly the commands `runCommand` wires,
/// in dispatch order, with short English descriptions.
/// Source: `internal/commands/telegram_commands.go:73-118`.
pub const COMMAND_MENU: &[CommandMenuEntry] = &[
    CommandMenuEntry {
        name: "start",
        description: "Start the bot and show how to talk to Muse",
    },
    CommandMenuEntry {
        name: "help",
        description: "Show the command list and how to talk to Muse",
    },
    CommandMenuEntry {
        name: "stop",
        description: "Stop Muse's current turn in this chat",
    },
    CommandMenuEntry {
        name: "status",
        description: "Show Muse, chat, and toggle status",
    },
    CommandMenuEntry {
        name: "chats",
        description: "Open another chat or the main chat",
    },
    CommandMenuEntry {
        name: "main",
        description: "Switch back to the main chat",
    },
    CommandMenuEntry {
        name: "new",
        description: "Start a new side chat",
    },
    CommandMenuEntry {
        name: "history",
        description: "Show recent messages in this chat",
    },
    CommandMenuEntry {
        name: "unread",
        description: "Show unread counts",
    },
    CommandMenuEntry {
        name: "rename",
        description: "Rename the current side chat",
    },
    CommandMenuEntry {
        name: "pin",
        description: "Pin the current side chat",
    },
    CommandMenuEntry {
        name: "unpin",
        description: "Unpin the current side chat",
    },
    CommandMenuEntry {
        name: "archive",
        description: "Archive the current side chat",
    },
    CommandMenuEntry {
        name: "unarchive",
        description: "Unarchive the current side chat",
    },
    CommandMenuEntry {
        name: "delete",
        description: "Delete the current side chat (asks first)",
    },
    CommandMenuEntry {
        name: "approvals",
        description: "List pending approvals",
    },
    CommandMenuEntry {
        name: "autoapprove",
        description: "Show or change auto-approve settings",
    },
    CommandMenuEntry {
        name: "watch",
        description: "Show or change the watch flag",
    },
    CommandMenuEntry {
        name: "files",
        description: "List recent files with download buttons",
    },
    CommandMenuEntry {
        name: "feed",
        description: "Show your feed",
    },
    CommandMenuEntry {
        name: "goals",
        description: "List goals",
    },
    CommandMenuEntry {
        name: "goal",
        description: "Show one goal by id",
    },
    CommandMenuEntry {
        name: "ideas",
        description: "List idea cards with Execute buttons",
    },
    CommandMenuEntry {
        name: "usage",
        description: "Show plan usage and reset time",
    },
    CommandMenuEntry {
        name: "wake",
        description: "Ask muse.ai to wake the VM",
    },
    CommandMenuEntry {
        name: "fs",
        description: "Browse System Files (ls, tree, cat, get, find, stat, mkdir, mv, rm)",
    },
    CommandMenuEntry {
        name: "profile",
        description: "Show the linked profile (cannot switch from chat)",
    },
    CommandMenuEntry {
        name: "update",
        description: "Check for a castctl update (owner only, check only)",
    },
    CommandMenuEntry {
        name: "login",
        description: "Replace the muse.ai cookies (owner only)",
    },
    CommandMenuEntry {
        name: "raw",
        description: "Raw gateway call (owner only)",
    },
];

/// Whether a command name is one of the 30 wired commands.
#[must_use]
pub fn is_known_command(name: &str) -> bool {
    COMMAND_MENU.iter().any(|e| e.name == name)
}

/// Whether `name` is one of the four owner-gated commands.
/// Source: `internal/commands/telegram_owner.go:67-76`
/// (`isOwnerCommand`).
#[must_use]
pub fn is_owner_command(name: &str) -> bool {
    matches!(name, "profile" | "update" | "login" | "raw")
}

/// The fixed owner-gate refusal sentence. It is identical
/// whether no owner is configured or the sender is not the
/// owner — the two cases stay indistinguishable.
/// Source: `internal/commands/telegram_owner.go:58-65`
/// (`ownerOnlySentence`).
pub const OWNER_ONLY_SENTENCE: &str = "Only the owner can use that command.";

impl std::fmt::Display for CommandMenuEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "/{} — {}", self.name, self.description)
    }
}

/// What kind of handling a routed command gets.
/// No direct Go counterpart: Go has the wiring; this enum
/// records the Rust port's full-vs-seam split for the
/// PORTING §M5a command table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    /// Fully implemented in this crate (Bot API + state only).
    Full,
    /// Routed and gated here; the work goes through
    /// [`BotServices`] (M5b turn runner / M4b gateway wiring).
    Seam,
}

/// Full/seam split for each of the 30 commands.
/// Full: `start`, `help`, `main`, `delete` (prompt only —
/// the confirm goes through the seam), `autoapprove`,
/// `watch`, `login` (arming only — saving cookies is a
/// seam). Everything else is a seam: the router admits and
/// gates it, the service does the work. (`/chats` is a seam:
/// the picker rows come from `sessions.list`, a gateway call
/// — `internal/commands/telegram_commands.go:423-447`.)
#[must_use]
pub fn command_kind(name: &str) -> Option<CommandKind> {
    match name {
        "start" | "help" | "main" | "delete" | "autoapprove" | "watch" | "login" => {
            Some(CommandKind::Full)
        }
        "stop" | "status" | "chats" | "new" | "history" | "unread" | "rename" | "pin" | "unpin"
        | "archive" | "unarchive" | "approvals" | "files" | "feed" | "goals" | "goal" | "ideas"
        | "usage" | "wake" | "fs" | "profile" | "update" | "raw" => Some(CommandKind::Seam),
        _ => None,
    }
}

/// Parse a message text starting with `/` into
/// `(name, arg)`: the name is the head before the first
/// space, lowercased, with any `@botname` suffix stripped;
/// the arg is the stripped remainder.
/// Source: `internal/commands/telegram_commands.go:119-153`
/// (`dispatch`).
#[must_use]
pub fn parse_command(text: &str) -> Option<(String, String)> {
    if !text.starts_with('/') {
        return None;
    }
    let (head, rest) = match text.split_once(' ') {
        Some((h, r)) => (h, r),
        None => (text, ""),
    };
    let name = head[1..].split('@').next().unwrap_or("").to_lowercase();
    Some((name, rest.trim().to_string()))
}

/// Whether a command name matches Go's `commandNameRe`
/// (`^[a-z_]+$`, `internal/commands/telegram_commands.go:67`).
/// Empty or non-matching names take the escaped
/// `Unknown command` branch in `runCommand`.
#[must_use]
pub fn is_valid_command_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
}

/// One session row for the `/chats` picker.
/// Source: `internal/commands/telegram_commands.go:423-447`
/// (`chatSessionRow` from `sessions.list`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    /// Session id.
    pub session_id: String,
    /// Display title.
    pub title: String,
    /// Pinned first in the picker.
    pub pinned: bool,
}

/// One chat row for the `/chats` picker.
/// Source: `internal/commands/telegram_commands.go:488`
/// (`showChats` reads the state store's chat mappings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatRow {
    /// Session id ("" = main chat).
    pub session_id: String,
    /// Display title.
    pub title: String,
    /// Whether this is the current chat.
    pub is_current: bool,
}

/// One recent-file row for `/files`.
/// Source: `internal/commands/telegram_commands.go:664-682`
/// (`files` builds rows from `shared.FileRows`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFileRow {
    /// File path (registry-carried for the `dl` button).
    pub path: String,
    /// Declared size, when known.
    pub size: Option<i64>,
    /// MIME, when known.
    pub mime: Option<String>,
}

/// One idea card for `/ideas`.
/// Source: `internal/commands/telegram_read.go:193`
/// (`ideas` lists `api.idea-cards.list`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdeaCard {
    /// Card id.
    pub id: String,
    /// Card title (carried RAW in the registry, per Go).
    pub title: String,
    /// Card section, when present (rendered italic).
    pub section: Option<String>,
}

/// Outcome of starting a new side chat.
/// Source: `internal/commands/telegram_commands.go:549`
/// (`newChat`): the session id from `session_id` / `id` /
/// `session.session_id` in that order; empty id → the
/// warning reply, no switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewChatOutcome {
    /// New session id ("" = none returned).
    pub session_id: String,
    /// Chat title (arg, or "new chat").
    pub title: String,
    /// Reply text to send.
    pub reply: String,
}

/// Session operations for `/pin` / `/unpin` / `/unarchive`.
/// Source: `internal/commands/telegram_commands.go:862-906`
/// (`sessionOpCmd` / `archive` via `deliver.SessionOp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOp {
    /// Pin.
    Pin,
    /// Unpin.
    Unpin,
    /// Archive.
    Archive,
    /// Unarchive.
    Unarchive,
}

/// Outcome of an `/fs` run.
/// Source: `internal/commands/telegram_fs.go:146-374`
/// (`fs`): text replies, file sends, and the `rm` confirm
/// keyboard. The gateway-side work (listing, reading,
/// deleting) is a seam; this enum is the seam's reply shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsOutcome {
    /// Plain reply text.
    Text(String),
    /// Send a file (name + bytes + caption).
    File {
        /// File name.
        name: String,
        /// File bytes.
        data: Vec<u8>,
        /// Caption.
        caption: String,
    },
    /// Ask for `rm` confirmation (button carries path).
    ConfirmDelete {
        /// Path to delete.
        path: String,
        /// Recursive flag.
        recursive: bool,
    },
}

/// A file downloaded for a `dl` button tap.
/// Source: `internal/commands/telegram_commands.go:711-756`
/// (`downloadFile`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedFile {
    /// File name.
    pub name: String,
    /// File bytes.
    pub data: Vec<u8>,
    /// MIME, when known.
    pub mime: Option<String>,
}

/// The seam into the turn runner (M5b) and the gateway
/// (M4b): every command handler that needs either calls one
/// of these methods. The router admits, gates, and renders;
/// the service does the work. Methods return the reply text
/// (already rendered) or a structured outcome; the handler
/// sends it.
///
/// All methods are async via boxed futures (no `async-trait`
/// dependency): each returns a pinned boxed future, as the
/// `Decider` trait does in `claims.rs`.
pub trait BotServices: Send + Sync {
    /// Start a turn in `chat_id` with `text` (M5b).
    /// Source: `internal/commands/telegram_turn.go:262`
    /// (`startTurn`).
    fn start_turn(
        &self,
        chat_id: i64,
        text: String,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// Stop the chat's active turn (M5b). Returns whether a
    /// turn was actually cancelled.
    /// Source: `internal/commands/telegram_turn.go:431`
    /// (`stopTurn`).
    fn stop_turn(
        &self,
        chat_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, BotError>> + Send + '_>>;

    /// Join in-flight turns (M5b shutdown).
    /// Source: `internal/commands/telegram_turn.go:247`
    /// (`Wait`).
    fn wait_turns(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// Resume a turn after a manual approval decision
    /// (decide button with a resume triple, no turn active).
    /// Source: `internal/telegram/bot.go:157-179`
    /// (`ResumeFunc` / `ResumeInfo`) and
    /// `internal/commands/telegram_turn.go:316`
    /// (`startResume`).
    fn resume_turn(
        &self,
        chat_id: i64,
        session_id: &str,
        title: &str,
        after_seq: i64,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// List chat sessions for the `/chats` picker
    /// (threads only, archived excluded, newest first,
    /// pinned-first stable reorder).
    /// Source: `internal/commands/telegram_commands.go:423-447`
    /// (`listChatSessions`).
    fn list_sessions(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SessionRow>, BotError>> + Send + '_>>;

    /// `/status` reply body.
    /// Source: `internal/commands/telegram_commands.go:274`
    /// (`status`).
    fn status_text(
        &self,
        chat_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// Start a new side chat; returns the session id, title,
    /// and reply text (the handler owns the state mapping).
    /// Source: `internal/commands/telegram_commands.go:549`
    /// (`newChat`).
    fn new_chat(
        &self,
        chat_id: i64,
        title: &str,
    ) -> Pin<Box<dyn Future<Output = Result<NewChatOutcome, BotError>> + Send + '_>>;

    /// `/history` reply body (N clamped [1, 50] by the
    /// handler before this call).
    /// Source: `internal/commands/telegram_commands.go:595`
    /// (`history`).
    fn history_text(
        &self,
        chat_id: i64,
        n: usize,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// `/unread` reply body (raw JSON, truncated to 3500
    /// runes by the handler).
    /// Source: `internal/commands/telegram_commands.go:832`
    /// (`unread`).
    fn unread_text(
        &self,
        chat_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// Rename the current side chat.
    /// Source: `internal/commands/telegram_commands.go:869`
    /// (`rename`).
    fn rename_chat(
        &self,
        chat_id: i64,
        title: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>>;

    /// Pin / unpin / archive / unarchive the current side
    /// chat. Archive also resets the mapping to main (the
    /// handler does that from the state store).
    /// Source: `internal/commands/telegram_commands.go:862-906`.
    fn session_op(
        &self,
        chat_id: i64,
        session_id: &str,
        op: SessionOp,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>>;

    /// Delete a side chat (after the confirm button).
    /// Source: `internal/commands/telegram_commands.go:930`
    /// (`deletePrompt` + `handleCallback` `delete` action).
    fn delete_chat(
        &self,
        chat_id: i64,
        session_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>>;

    /// List pending approvals (fresh read, never decides).
    /// Source: `internal/commands/telegram_approvals.go:70-86`
    /// (`telegramPendingApprovals`).
    fn pending_approvals(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Approval>, BotError>> + Send + '_>>;

    /// Decide one approval (one `egress.approval.decide`
    /// call, no retry).
    /// Source: `internal/commands/telegram_approvals.go:45-68`
    /// (`gatewayDecider`).
    fn decide_approval(
        &self,
        approval_id: &str,
        decision: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>>;

    /// List recent files for `/files` (last 40 history
    /// events → rows, reversed, deduped by path, capped at
    /// 12 by the handler).
    /// Source: `internal/commands/telegram_commands.go:664-682`
    /// (`files`).
    fn files_list(
        &self,
        chat_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SharedFileRow>, BotError>> + Send + '_>>;

    /// Download a file for a `dl` button tap (both size
    /// gates live in the handler; this fetches the bytes).
    /// Source: `internal/commands/telegram_commands.go:711-756`
    /// (`downloadFile`).
    fn download_file(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<DownloadedFile, BotError>> + Send + '_>>;

    /// `/feed` reply body (limit sanitised by the handler).
    /// Source: `internal/commands/telegram_read.go:59`
    /// (`feed`).
    fn feed_text(
        &self,
        limit: usize,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// `/goals` reply body.
    /// Source: `internal/commands/telegram_read.go:87`
    /// (`goals`).
    fn goals_text(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// `/goal` reply body (head text; the handler sends a
    /// `goal.json` document when the body is >3000 runes).
    /// Source: `internal/commands/telegram_read.go:129`
    /// (`goal`).
    fn goal_text(
        &self,
        id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// List idea cards for `/ideas` (first 15 by the handler).
    /// Source: `internal/commands/telegram_read.go:193`
    /// (`ideas`).
    fn ideas_list(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IdeaCard>, BotError>> + Send + '_>>;

    /// Execute one idea card (`idea_exec` button).
    /// Source: `internal/commands/telegram_read.go:193`
    /// (`ideas`).
    fn execute_idea(
        &self,
        card_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// `/usage` reply body.
    /// Source: `internal/commands/telegram_read.go:270`
    /// (`usage`).
    fn usage_text(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// `/wake` reply body.
    /// Source: `internal/commands/telegram_read.go:296`
    /// (`wake`).
    fn wake(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// Run one `/fs` operation; the handler renders the
    /// outcome (text, file, or rm-confirm keyboard).
    /// Source: `internal/commands/telegram_fs.go:146`
    /// (`fs`).
    fn fs_run(
        &self,
        chat_id: i64,
        arg: &str,
    ) -> Pin<Box<dyn Future<Output = Result<FsOutcome, BotError>> + Send + '_>>;

    /// Delete a path for the `fs_rm` button.
    /// Source: `internal/commands/telegram_fs.go:393-413`
    /// (`fsRm`).
    fn fs_delete(
        &self,
        path: &str,
        recursive: bool,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// `/profile` reply body (display-only: name + VM id +
    /// cookies present/missing; no gateway call in Go).
    /// Source: `internal/commands/telegram_owner.go:87`
    /// (`ownerProfile`).
    fn profile_text(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// `/update` reply body (dry-run check only; never
    /// replaces the binary).
    /// Source: `internal/commands/telegram_owner.go:107`
    /// (`ownerUpdate`).
    fn update_check(&self) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// `/raw` reply body (route checked before the gateway
    /// opens; the handler owns the route check only when a
    /// route table is available — until M4b, the service
    /// performs it).
    /// Source: `internal/commands/telegram_owner.go:145`
    /// (`ownerRaw`).
    fn raw_call(
        &self,
        method: &str,
        params_json: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// Save cookies received after `/login` arming. Returns
    /// the reply text (`✅ Cookies saved…` / fixed failure
    /// sentences). The arming state itself lives in the
    /// handler; this saves + probes.
    /// Source: `internal/commands/telegram_owner.go:252-388`
    /// (`ownerLogin` / `takeAwaitingCookies` /
    /// `saveLoginCookies`).
    fn save_login_cookies(
        &self,
        chat_id: i64,
        user_id: i64,
        cookies_text: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, BotError>> + Send + '_>>;

    /// Handle one inbound media message (save to System
    /// Files + tell Muse). The download itself is bot-core
    /// (`files::download_media`); this persists + starts
    /// the turn.
    /// Source: `internal/commands/telegram_commands.go:758`
    /// (`inboundMedia`).
    fn inbound_media(
        &self,
        chat_id: i64,
        media: InboxMedia,
        caption: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_has_thirty_commands() {
        assert_eq!(COMMAND_MENU.len(), 30);
        for entry in COMMAND_MENU {
            assert!(is_valid_command_name(entry.name));
            assert!(!entry.description.is_empty());
            assert!(command_kind(entry.name).is_some());
        }
    }

    #[test]
    fn command_kinds_cover_all_thirty() {
        let full = COMMAND_MENU
            .iter()
            .filter(|e| command_kind(e.name) == Some(CommandKind::Full))
            .count();
        let seam = COMMAND_MENU
            .iter()
            .filter(|e| command_kind(e.name) == Some(CommandKind::Seam))
            .count();
        assert_eq!(full, 7);
        assert_eq!(seam, 23);
        assert_eq!(full + seam, 30);
    }

    #[test]
    fn parse_command_strips_botname_and_lowercases() {
        assert_eq!(
            parse_command("/Help@MyBot  arg here "),
            Some(("help".to_string(), "arg here".to_string()))
        );
        assert_eq!(
            parse_command("/fs ls /tmp"),
            Some(("fs".to_string(), "ls /tmp".to_string()))
        );
        assert_eq!(parse_command("hello"), None);
        assert_eq!(
            parse_command("/start"),
            Some(("start".to_string(), String::new()))
        );
    }

    #[test]
    fn owner_commands_are_exactly_four() {
        let owners: Vec<&&str> = COMMAND_MENU
            .iter()
            .map(|e| &e.name)
            .filter(|n| is_owner_command(n))
            .collect();
        assert_eq!(owners, vec![&"profile", &"update", &"login", &"raw"]);
    }

    #[test]
    fn valid_command_name_matches_go_regex() {
        assert!(is_valid_command_name("fs"));
        assert!(is_valid_command_name("autoapprove"));
        assert!(!is_valid_command_name(""));
        assert!(!is_valid_command_name("fs2"));
        assert!(!is_valid_command_name("a-b"));
        assert!(!is_valid_command_name("UPPER"));
    }
}
