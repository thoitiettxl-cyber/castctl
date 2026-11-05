// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Send / edit surface over [`crate::api::BotApi`].
//!
//! Go sources: `internal/telegram/bot.go:1547-1846`
//! (`isParseError`, `isNotModified`, `Send`, `SendMD`,
//! `sendOne`, `sendMessageCall`, `Edit`, `EditPlain`,
//! `answer`, `Delete`, `SetCommands`, `ClearMarkup`).
//!
//! Text splitting/rendering is reused from `castctl-tg-text`
//! (`split_text`, `md_to_html`, `strip_tags`, `button_text`)
//! — M1 parity, not re-ported here.

use castctl_tg_text::{CHUNK_SIZE, TEXT_LIMIT, button_text, md_to_html, split_text, strip_tags};
use serde_json::Value;

use crate::api::BotApi;
use crate::error::BotError;

/// HTML mode for a send.
/// Source: `internal/telegram/bot.go:76-93` (`HTMLMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HtmlMode {
    /// Already HTML (`HTMLModeHTML`).
    #[default]
    Html,
    /// Plain text, never parsed (`HTMLModePlain`).
    Plain,
    /// Markdown, converted via `MDToHTML` (`HTMLModeMarkdown`).
    Markdown,
}

/// One inline-keyboard button.
/// Source: go-telegram/bot `models.InlineKeyboardButton`, as
/// built by `ApprovalMarkup`
/// (`internal/telegram/approvals.go:378-403`) and friends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineKeyboardButton {
    /// Button label (truncated to 64 chars by `ButtonText` at
    /// construction sites, not here).
    pub text: String,
    /// Callback data (a `c:` token; never approval data).
    pub callback_data: String,
}

impl InlineKeyboardButton {
    /// Build a button, truncating the label to 64 chars.
    /// Source: `internal/telegram/text.go:260` (`ButtonText`).
    #[must_use]
    pub fn new(text: &str, callback_data: &str) -> Self {
        Self {
            text: button_text(text),
            callback_data: callback_data.to_string(),
        }
    }
}

/// One inline keyboard.
/// Source: go-telegram/bot `models.InlineKeyboardMarkup`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InlineKeyboardMarkup {
    /// Rows of buttons.
    pub inline_keyboard: Vec<Vec<InlineKeyboardButton>>,
}

impl InlineKeyboardMarkup {
    /// Render as the Bot API `reply_markup` JSON value.
    /// No direct Go function counterpart: Go passes the
    /// struct to the library; this renders the same wire
    /// shape the library would send.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let rows: Vec<Value> = self
            .inline_keyboard
            .iter()
            .map(|row| {
                Value::Array(
                    row.iter()
                        .map(|b| {
                            serde_json::json!({
                                "text": b.text,
                                "callback_data": b.callback_data,
                            })
                        })
                        .collect(),
                )
            })
            .collect();
        serde_json::json!({ "inline_keyboard": rows })
    }
}

/// Options for one send.
/// Source: `internal/telegram/bot.go:1567-1591` (`Send`).
#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    /// HTML mode for the text.
    pub mode: HtmlMode,
    /// Silent send (`disable_notification`).
    pub silent: bool,
    /// Reply to this message id (0 = no reply).
    pub reply_to: i64,
    /// Inline keyboard (attached only to the last piece).
    pub markup: Option<InlineKeyboardMarkup>,
}

/// The send surface: one [`BotApi`] plus the split/fallback
/// rules. There is no direct Go type counterpart: Go puts
/// these methods on `*Bot`
/// (`internal/telegram/bot.go:1567-1846`); this struct is
/// the Rust-side grouping so handlers can share it.
#[derive(Debug)]
pub struct Sender<'a> {
    api: &'a BotApi,
}

impl<'a> Sender<'a> {
    /// Wrap an API client.
    #[must_use]
    pub fn new(api: &'a BotApi) -> Self {
        Self { api }
    }

    /// Send text, splitting when longer than `CHUNK_SIZE`
    /// (3800 runes) via `SplitText`; the inline keyboard is
    /// attached only to the last piece; `ReplyTo` is passed
    /// to every piece; previews are always disabled.
    /// Returns the last message id.
    /// Source: `internal/telegram/bot.go:1567-1591` (`Send`).
    pub async fn send(&self, chat_id: i64, text: &str, opts: SendOptions) -> Result<i64, BotError> {
        let pieces = if text.chars().count() > CHUNK_SIZE {
            split_text(text)
        } else {
            vec![text.to_string()]
        };
        let last = pieces.len() - 1;
        let mut message_id = 0;
        for (i, piece) in pieces.iter().enumerate() {
            let piece_opts = SendOptions {
                mode: opts.mode,
                silent: opts.silent,
                reply_to: opts.reply_to,
                markup: if i == last { opts.markup.clone() } else { None },
            };
            message_id = self.send_one(chat_id, piece, piece_opts).await?;
        }
        Ok(message_id)
    }

    /// Same as [`Sender::send`] with Markdown mode.
    /// Source: `internal/telegram/bot.go:1592-1596` (`SendMD`).
    pub async fn send_md(
        &self,
        chat_id: i64,
        text: &str,
        opts: SendOptions,
    ) -> Result<i64, BotError> {
        let mut opts = opts;
        opts.mode = HtmlMode::Markdown;
        self.send(chat_id, text, opts).await
    }

    /// Send one piece (no splitting): HTML/Markdown mode
    /// tries HTML (≤ `TextLimit` 4096 runes) first; on parse
    /// error falls back to plain; an HTML body over 4096
    /// skips the HTML attempt entirely (HTML mode strips
    /// tags first). Plain mode truncates to `TextLimit`.
    /// Source: `internal/telegram/bot.go:1597-1627`
    /// (`sendOne`).
    pub async fn send_one(
        &self,
        chat_id: i64,
        text: &str,
        opts: SendOptions,
    ) -> Result<i64, BotError> {
        let html_text = match opts.mode {
            HtmlMode::Markdown => md_to_html(text),
            HtmlMode::Html => text.to_string(),
            HtmlMode::Plain => {
                return self
                    .send_message_call(chat_id, &truncate_runes(text, TEXT_LIMIT), None, &opts)
                    .await;
            }
        };
        if html_text.chars().count() <= TEXT_LIMIT {
            match self
                .send_message_call(chat_id, &html_text, Some("HTML"), &opts)
                .await
            {
                Ok(id) => Ok(id),
                Err(e) if e.is_parse_error() => {
                    let plain = fallback_text(opts.mode, text, &html_text);
                    self.send_message_call(chat_id, &plain, None, &opts).await
                }
                Err(e) => Err(e),
            }
        } else {
            let plain = fallback_text(opts.mode, text, &html_text);
            self.send_message_call(chat_id, &plain, None, &opts).await
        }
    }

    async fn send_message_call(
        &self,
        chat_id: i64,
        text: &str,
        parse_mode: Option<&str>,
        opts: &SendOptions,
    ) -> Result<i64, BotError> {
        let mut params = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "link_preview_options": {"is_disabled": true},
        });
        if let Some(mode) = parse_mode {
            params["parse_mode"] = Value::String(mode.to_string());
        }
        if opts.reply_to != 0 {
            params["reply_parameters"] = serde_json::json!({"message_id": opts.reply_to});
        }
        if opts.silent {
            params["disable_notification"] = Value::Bool(true);
        }
        if let Some(markup) = &opts.markup {
            params["reply_markup"] = markup.to_json();
        }
        // Source: `internal/telegram/bot.go:1635-1660`
        // (`sendMessageCall`): nil message → error
        // `telegram: sendMessage returned no message`.
        self.api.send_message_params(params).await
    }

    /// Edit a message, with the same HTML-then-plain fallback
    /// as `send_one`; swallows `message is not modified`.
    /// A JSON `true` result (inline messages) is success.
    /// Source: `internal/telegram/bot.go:1662-1699` (`Edit`).
    pub async fn edit(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
        mode: HtmlMode,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Result<(), BotError> {
        let html_text = match mode {
            HtmlMode::Markdown => md_to_html(text),
            HtmlMode::Html => text.to_string(),
            HtmlMode::Plain => {
                return self
                    .edit_call(
                        chat_id,
                        message_id,
                        &truncate_runes(text, TEXT_LIMIT),
                        None,
                        markup,
                    )
                    .await;
            }
        };
        if html_text.chars().count() <= TEXT_LIMIT {
            match self
                .edit_call(
                    chat_id,
                    message_id,
                    &html_text,
                    Some("HTML"),
                    markup.clone(),
                )
                .await
            {
                Ok(()) => Ok(()),
                Err(e) if e.is_parse_error() => {
                    let plain = fallback_text(mode, text, &html_text);
                    self.edit_call(chat_id, message_id, &plain, None, markup)
                        .await
                }
                Err(e) if e.is_not_modified() => Ok(()),
                Err(e) => Err(e),
            }
        } else {
            let plain = fallback_text(mode, text, &html_text);
            self.edit_call(chat_id, message_id, &plain, None, markup)
                .await
        }
    }

    async fn edit_call(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
        parse_mode: Option<&str>,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Result<(), BotError> {
        let mut params = serde_json::json!({
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "link_preview_options": {"is_disabled": true},
        });
        if let Some(mode) = parse_mode {
            params["parse_mode"] = Value::String(mode.to_string());
        }
        if let Some(markup) = &markup {
            params["reply_markup"] = markup.to_json();
        }
        match self.api.edit_message_text_params(params).await {
            Ok(()) => Ok(()),
            Err(e) if e.is_not_modified() => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Edit a message, swallowing ALL errors (debug-log only
    /// in Go; here: returns `Ok` always).
    /// [DEVIATION] Python's `edit_plain` catches only
    /// `(TelegramError, ConnectionError)`; narrowing is not
    /// expressible here without unwrapping raw errors
    /// (scrubbed errors drop transport-type distinctions).
    /// Source: `internal/telegram/bot.go:1701-1724`
    /// (`EditPlain`).
    pub async fn edit_plain(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
        markup: Option<InlineKeyboardMarkup>,
    ) {
        let _ = self
            .edit(chat_id, message_id, text, HtmlMode::Plain, markup)
            .await;
    }

    /// Delete a message.
    /// Source: `internal/telegram/bot.go:1738-1745` (`Delete`).
    pub async fn delete(&self, chat_id: i64, message_id: i64) -> Result<(), BotError> {
        self.api.delete_message(chat_id, message_id).await
    }

    /// Answer a callback query.
    /// Source: `internal/telegram/bot.go:1726-1736` (`answer`).
    pub async fn answer(&self, callback_query_id: &str, text: &str) -> Result<(), BotError> {
        self.api
            .answer_callback_query(callback_query_id, text)
            .await
    }

    /// Clear a message's inline keyboard.
    /// Source: `internal/telegram/bot.go:1819-1846`
    /// (`ClearMarkup` / `clearMarkup`).
    pub async fn clear_markup(&self, chat_id: i64, message_id: i64) -> Result<(), BotError> {
        self.api.clear_markup(chat_id, message_id).await
    }
}

/// Validate `setMyCommands` entries BEFORE any request:
/// name `^[a-z0-9_]{1,32}$` per Bot API, no duplicates,
/// description 1–256 runes. A bad entry makes no API call.
/// Source: `internal/telegram/bot.go:1786-1816`
/// (`SetCommands`).
pub fn validate_commands(commands: &[(String, String)]) -> Result<(), BotError> {
    let mut seen = std::collections::HashSet::new();
    for (name, description) in commands {
        if name.is_empty()
            || name.len() > 32
            || !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(BotError::Validation(format!(
                "invalid command name (must match ^[a-z0-9_]{{1,32}}$): length {}",
                name.chars().count()
            )));
        }
        if !seen.insert(name.clone()) {
            return Err(BotError::Validation(
                "duplicate command name in setMyCommands".to_string(),
            ));
        }
        let desc_len = description.chars().count();
        if !(1..=256).contains(&desc_len) {
            return Err(BotError::Validation(
                "command description must be 1-256 runes".to_string(),
            ));
        }
    }
    Ok(())
}

/// Truncate to at most `limit` runes (Go `runeCount` /
/// `truncateRunes` semantics: cut at a rune boundary).
/// No direct Go function counterpart in `bot.go`; the
/// truncation sites are `sendOne` / `Edit` /
/// `internal/telegram/bot.go:1597-1724`.
#[must_use]
pub fn truncate_runes(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        s.to_string()
    } else {
        s.chars().take(limit).collect()
    }
}

/// Fallback text for `send_one` / `edit` when the HTML
/// attempt fails to parse or the body is over
/// `TEXT_LIMIT`. Go strips tags ONLY in HTML mode
/// (`bot.go:1597-1627` `sendOne`, `:1662-1699` `Edit`):
/// in Markdown mode the ORIGINAL markdown text is sent
/// unchanged (truncated to 4096 runes) — e.g. `**bold**`
/// stays `**bold**`, it does not become `bold` (fix loop
/// 1, tech B5 — the old code stripped in both modes).
fn fallback_text(mode: HtmlMode, text: &str, html_text: &str) -> String {
    match mode {
        HtmlMode::Markdown => truncate_runes(text, TEXT_LIMIT),
        HtmlMode::Html => truncate_runes(&strip_tags(html_text), TEXT_LIMIT),
        HtmlMode::Plain => truncate_runes(text, TEXT_LIMIT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_commands_rejects_bad_names() {
        let bad = vec![("Bad-Name".to_string(), "ok".to_string())];
        assert!(validate_commands(&bad).is_err());
        let empty = vec![("".to_string(), "ok".to_string())];
        assert!(validate_commands(&empty).is_err());
        let long = vec![("a".repeat(33), "ok".to_string())];
        assert!(validate_commands(&long).is_err());
    }

    #[test]
    fn validate_commands_rejects_dupes_and_bad_descriptions() {
        let dupes = vec![
            ("help".to_string(), "one".to_string()),
            ("help".to_string(), "two".to_string()),
        ];
        assert!(validate_commands(&dupes).is_err());
        let empty_desc = vec![("help".to_string(), String::new())];
        assert!(validate_commands(&empty_desc).is_err());
        let long_desc = vec![("help".to_string(), "x".repeat(257))];
        assert!(validate_commands(&long_desc).is_err());
        let ok = vec![("help".to_string(), "Show help".to_string())];
        assert!(validate_commands(&ok).is_ok());
    }

    #[test]
    fn truncate_runes_cuts_at_rune_boundary() {
        assert_eq!(truncate_runes("héllo", 3), "hél");
        assert_eq!(truncate_runes("hi", 10), "hi");
    }
}
