// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Bot API wire types (subset).
//!
//! Go source: the go-telegram/bot `models` package as used by
//! `internal/telegram/bot.go:555-660` (`libraryHandler`,
//! `processUpdate`, `updateKind`, `senderID`, `callbackChat`,
//! `chatKey`) and `internal/telegram/inbound.go:64-170`
//! (`MediaOf`, `InboxName`). Only the fields the bot core
//! reads are modelled; unknown JSON fields are ignored
//! (forward tolerance, like Go's `encoding/json`).

use serde::Deserialize;

/// One `getUpdates` item.
/// Source: go-telegram/bot `models.Update`, read at
/// `internal/telegram/bot.go:555-568` (`processUpdate`).
#[derive(Debug, Clone, Deserialize)]
pub struct Update {
    /// `update_id`.
    pub update_id: i64,
    /// `message`, when present.
    #[serde(default)]
    pub message: Option<Message>,
    /// `callback_query`, when present.
    #[serde(default)]
    pub callback_query: Option<CallbackQuery>,
    /// `edited_message`: never arrives (the poller requests
    /// only `message` + `callback_query` in `allowed_updates`),
    /// but `senderID` still handles it, so it is modelled.
    /// Source: `internal/telegram/bot.go:570-579` (`updateKind`).
    #[serde(default)]
    pub edited_message: Option<Message>,
}

impl Update {
    /// The update kind, mirroring Go `updateKind`
    /// (`internal/telegram/bot.go:570-579`).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        if self.callback_query.is_some() {
            "callback_query"
        } else if self.message.is_some() {
            "message"
        } else if self.edited_message.is_some() {
            "edited_message"
        } else {
            "other"
        }
    }

    /// The sender user id, mirroring Go `senderID`
    /// (`internal/telegram/bot.go:598-618`): the callback
    /// sender first (a combined message+callback_query update
    /// is gated on the callback sender), then the message
    /// sender, then the edited-message sender, else 0.
    #[must_use]
    pub fn sender_id(&self) -> i64 {
        if let Some(cb) = &self.callback_query {
            return cb.from.id;
        }
        if let Some(m) = &self.message
            && let Some(u) = &m.from
        {
            return u.id;
        }
        if let Some(m) = &self.edited_message
            && let Some(u) = &m.from
        {
            return u.id;
        }
        0
    }

    /// The dispatcher serialisation key, mirroring Go `chatKey`
    /// (`internal/telegram/bot.go:648-660`): callback message
    /// chat, else message chat, else sender.
    #[must_use]
    pub fn chat_key(&self) -> i64 {
        if let Some(cb) = &self.callback_query {
            if let Some(m) = &cb.message {
                return m.chat.id;
            }
            return cb.from.id;
        }
        if let Some(m) = &self.message {
            return m.chat.id;
        }
        if let Some(m) = &self.edited_message {
            return m.chat.id;
        }
        self.sender_id()
    }
}

/// A Telegram user.
/// Source: go-telegram/bot `models.User`.
#[derive(Debug, Clone, Deserialize)]
pub struct User {
    /// `id`.
    pub id: i64,
    /// `is_bot`.
    #[serde(default)]
    pub is_bot: bool,
    /// `first_name`.
    #[serde(default)]
    pub first_name: String,
    /// `username`.
    #[serde(default)]
    pub username: Option<String>,
}

/// A Telegram chat.
/// Source: go-telegram/bot `models.Chat`.
#[derive(Debug, Clone, Deserialize)]
pub struct Chat {
    /// `id`.
    pub id: i64,
    /// `type` (`private`, `group`, ...).
    #[serde(default, rename = "type")]
    pub kind: String,
}

/// One photo size entry.
/// Source: go-telegram/bot `models.PhotoSize`, read at
/// `internal/telegram/inbound.go:64-144` (`MediaOf`).
#[derive(Debug, Clone, Deserialize)]
pub struct PhotoSize {
    /// `file_id`.
    pub file_id: String,
    /// `file_size`, when the server reports it.
    #[serde(default)]
    pub file_size: Option<i64>,
}

/// A file-bearing message object (document / video / audio /
/// voice / video_note / animation / sticker).
/// Source: go-telegram/bot `models.Document` and siblings,
/// read at `internal/telegram/inbound.go:64-144`.
#[derive(Debug, Clone, Deserialize)]
pub struct FileObject {
    /// `file_id`.
    pub file_id: String,
    /// `file_name`, when present.
    #[serde(default)]
    pub file_name: Option<String>,
    /// `mime_type`, when present.
    #[serde(default)]
    pub mime_type: Option<String>,
    /// `file_size`, when the server reports it.
    #[serde(default)]
    pub file_size: Option<i64>,
}

/// A Telegram message (subset).
/// Source: go-telegram/bot `models.Message`, read at
/// `internal/telegram/bot.go:1204-1229` (`onMessage`) and
/// `internal/telegram/inbound.go:64-144` (`MediaOf`).
#[derive(Debug, Clone, Deserialize)]
pub struct Message {
    /// `message_id`.
    pub message_id: i64,
    /// `from`.
    #[serde(default)]
    pub from: Option<User>,
    /// `chat`.
    pub chat: Chat,
    /// `date` (unix seconds).
    #[serde(default)]
    pub date: i64,
    /// `text`.
    #[serde(default)]
    pub text: Option<String>,
    /// `caption`.
    #[serde(default)]
    pub caption: Option<String>,
    /// `photo` sizes (last = largest).
    #[serde(default)]
    pub photo: Option<Vec<PhotoSize>>,
    /// `document`.
    #[serde(default)]
    pub document: Option<FileObject>,
    /// `video`.
    #[serde(default)]
    pub video: Option<FileObject>,
    /// `audio`.
    #[serde(default)]
    pub audio: Option<FileObject>,
    /// `voice`.
    #[serde(default)]
    pub voice: Option<FileObject>,
    /// `video_note`.
    #[serde(default)]
    pub video_note: Option<FileObject>,
    /// `animation`.
    #[serde(default)]
    pub animation: Option<FileObject>,
    /// `sticker`: present only so `MediaOf` can explicitly
    /// ignore it. Source: `internal/telegram/inbound.go:64-144`
    /// ("Nil message, no media, and **stickers** → nil").
    #[serde(default)]
    pub sticker: Option<serde_json::Value>,
}

/// A callback query (button tap).
/// Source: go-telegram/bot `models.CallbackQuery`, read at
/// `internal/telegram/bot.go:1230-1303` (`onCallback`).
#[derive(Debug, Clone, Deserialize)]
pub struct CallbackQuery {
    /// `id` (needed to answer the query).
    pub id: String,
    /// `from`.
    pub from: User,
    /// `message` (regular or inaccessible; absent for inline
    /// messages). Source: `internal/telegram/bot.go:633-646`
    /// (`callbackChat`).
    #[serde(default)]
    pub message: Option<Message>,
    /// `data` (the `c:` token).
    #[serde(default)]
    pub data: Option<String>,
}

/// A message as the command layer sees it.
/// Source: `internal/telegram/bot.go:1204-1229` (`onMessage`
/// builds `MessageContext`).
#[derive(Debug, Clone)]
pub struct MessageContext {
    /// Chat id.
    pub chat_id: i64,
    /// Sender user id.
    pub user_id: i64,
    /// Message text (empty when absent).
    pub text: String,
    /// Message id.
    pub message_id: i64,
    /// Attached media, when `MediaOf` found any.
    pub media: Option<crate::files::InboxMedia>,
    /// Caption text (empty when absent).
    pub caption: String,
    /// Whether the message carries a document.
    pub is_document: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_id_prefers_callback_sender() {
        let upd: Update = serde_json::from_str(
            r#"{"update_id": 7, "message": {"message_id": 1, "from": {"id": 11}, "chat": {"id": 100, "type": "private"}, "text": "x"}, "callback_query": {"id": "q", "from": {"id": 22}, "data": "c:abc"}}"#,
        )
        .expect("fixture parses");
        assert_eq!(upd.sender_id(), 22);
        assert_eq!(upd.chat_key(), 22);
        assert_eq!(upd.kind(), "callback_query");
    }

    #[test]
    fn sender_id_zero_when_no_sender() {
        let upd: Update =
            serde_json::from_str(r#"{"update_id": 8, "message": {"message_id": 1, "chat": {"id": 100, "type": "private"}}}"#)
                .expect("fixture parses");
        assert_eq!(upd.sender_id(), 0);
        assert_eq!(upd.chat_key(), 100);
    }
}
