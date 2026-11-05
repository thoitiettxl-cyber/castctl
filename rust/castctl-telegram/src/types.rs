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

/// Deserialize a field as its default when the wire value
/// is JSON `null` — or, with `#[serde(default)]`, when the
/// field is absent. Go's `encoding/json` treats `null`
/// into a non-nullable target as a no-op (zero value);
/// serde's `#[serde(default)]` only fires for ABSENT
/// fields, so a present `null` used to fail the whole
/// batch decode and stall the poll loop forever (fix loop
/// 2, red R5). A WRONG-TYPE value still fails the decode,
/// as in Go: `Option::<T>::deserialize` errors on it
/// instead of defaulting.
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// `photo` (`Option<Vec<PhotoSize>>`) with the same
/// null-as-default rule applied to the ELEMENTS: a
/// `null` element decodes to a default `PhotoSize`
/// (Go: a null array element is a zero value), while
/// a `null` field still decodes to `None` and a
/// wrong-type element still fails the decode.
fn null_photo_vec<'de, D>(deserializer: D) -> Result<Option<Vec<PhotoSize>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(
        Option::<Vec<Option<PhotoSize>>>::deserialize(deserializer)?.map(|items| {
            items
                .into_iter()
                .map(|item| item.unwrap_or_default())
                .collect()
        }),
    )
}

/// One `getUpdates` item.
/// Source: go-telegram/bot `models.Update`, read at
/// `internal/telegram/bot.go:555-568` (`processUpdate`).
///
/// Absent fields decode to zero values, exactly like Go's
/// `encoding/json` (fix loop 1, red R3); a field present
/// as explicit JSON `null` decodes to the same zero value
/// (fix loop 2, red R5 — Go no-ops `null` into a
/// non-nullable target). A field present with the WRONG
/// TYPE still fails the whole decode, as in Go (the
/// library's whole-array unmarshal fails); only absent
/// and `null` fields are zero-filled.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Update {
    /// `update_id` (absent or `null` → 0, Go zero value).
    #[serde(default, deserialize_with = "null_as_default")]
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
        // Edited messages have no chat key of their own:
        // Go `chatKey` falls through to `senderID`
        // (`bot.go:633-644`) — the edited chat id is NOT
        // used (fix loop 1, tech N4).
        self.sender_id()
    }
}

/// A Telegram user.
/// Source: go-telegram/bot `models.User`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct User {
    /// `id` (absent or `null` → 0, Go zero value).
    #[serde(default, deserialize_with = "null_as_default")]
    pub id: i64,
    /// `is_bot`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub is_bot: bool,
    /// `first_name`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub first_name: String,
    /// `username`.
    #[serde(default)]
    pub username: Option<String>,
}

/// A Telegram chat.
/// Source: go-telegram/bot `models.Chat`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Chat {
    /// `id` (absent or `null` → 0, Go zero value).
    #[serde(default, deserialize_with = "null_as_default")]
    pub id: i64,
    /// `type` (`private`, `group`, ...).
    #[serde(default, rename = "type", deserialize_with = "null_as_default")]
    pub kind: String,
}

/// One photo size entry.
/// Source: go-telegram/bot `models.PhotoSize`, read at
/// `internal/telegram/inbound.go:64-144` (`MediaOf`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PhotoSize {
    /// `file_id` (absent or `null` → "", Go zero value).
    #[serde(default, deserialize_with = "null_as_default")]
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
    /// `file_id` (absent or `null` → "", Go zero value).
    #[serde(default, deserialize_with = "null_as_default")]
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
    /// `message_id` (absent or `null` → 0, Go zero value).
    #[serde(default, deserialize_with = "null_as_default")]
    pub message_id: i64,
    /// `from`.
    #[serde(default)]
    pub from: Option<User>,
    /// `chat` (absent or `null` → `Chat{id: 0}`, Go zero value).
    #[serde(default, deserialize_with = "null_as_default")]
    pub chat: Chat,
    /// `date` (unix seconds).
    #[serde(default, deserialize_with = "null_as_default")]
    pub date: i64,
    /// `text`.
    #[serde(default)]
    pub text: Option<String>,
    /// `caption`.
    #[serde(default)]
    pub caption: Option<String>,
    /// `photo` sizes (last = largest). A `null`
    /// element decodes to a default `PhotoSize` (fix
    /// loop 2, red R5).
    #[serde(default, deserialize_with = "null_photo_vec")]
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
    /// `id` (needed to answer the query; absent or `null` → "").
    #[serde(default, deserialize_with = "null_as_default")]
    pub id: String,
    /// `from` (absent or `null` → `User{id: 0}`, Go zero
    /// value — the allowlist then drops the update).
    #[serde(default, deserialize_with = "null_as_default")]
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

    /// Absent fields decode to Go zero values instead of
    /// failing the decode (fix loop 1, red R3): a message
    /// with no `chat`, an update with no `update_id`, a
    /// callback with no `from` — each decodes, and the
    /// allowlist drops it by sender id 0.
    #[test]
    fn absent_fields_decode_to_zero_values_like_go() {
        let upd: Update =
            serde_json::from_str(r#"{"update_id": 99, "message": {"message_id": 1}}"#)
                .expect("missing chat decodes");
        assert_eq!(upd.message.as_ref().expect("message").chat.id, 0);
        assert_eq!(upd.sender_id(), 0);
        let upd: Update = serde_json::from_str(
            r#"{"message": {"message_id": 1, "from": {"id": 11}, "chat": {"id": 100, "type": "private"}}}"#,
        )
        .expect("missing update_id decodes");
        assert_eq!(upd.update_id, 0);
        assert_eq!(upd.sender_id(), 11);
        let upd: Update = serde_json::from_str(
            r#"{"update_id": 99, "callback_query": {"id": "q", "data": "c:abc"}}"#,
        )
        .expect("missing callback from decodes");
        assert_eq!(upd.callback_query.as_ref().expect("callback").from.id, 0);
        assert_eq!(upd.sender_id(), 0);
    }

    /// A field present with the WRONG TYPE still fails
    /// the whole decode, as in Go (fix loop 1, red R3):
    /// only ABSENT fields are zero-filled.
    #[test]
    fn wrong_type_fails_the_whole_decode_like_go() {
        let batch: Result<Vec<Update>, _> = serde_json::from_value(serde_json::json!([
            {"update_id": 1, "message": {"message_id": 1, "chat": {"id": 100, "type": "private"}}},
            {"update_id": "two", "message": {"message_id": 2, "chat": {"id": 100, "type": "private"}}},
        ]));
        assert!(batch.is_err(), "string update_id fails the batch");
    }

    /// A field present as explicit JSON `null` decodes
    /// to the Go zero value, exactly like an ABSENT field
    /// (fix loop 2, red R5): Go's `encoding/json`
    /// no-ops `null` into a non-nullable target, while
    /// bare `#[serde(default)]` only fires for absent
    /// fields — so `null` used to fail the whole batch
    /// decode and stall the poll loop forever. Every
    /// null shape in the decode path is covered here;
    /// the bare-`null` array element is covered at the
    /// `get_updates` level (it never reaches this
    /// `Vec<Update>` decode).
    #[test]
    fn explicit_null_fields_decode_to_zero_values_like_go() {
        let batch: Vec<Update> = serde_json::from_value(serde_json::json!([
            {"update_id": null, "message": {"message_id": null, "chat": null, "date": null, "from": null, "text": "a", "photo": [null, {"file_id": "p1"}]}},
            {"update_id": 6, "message": {"message_id": 2, "from": {"id": 111, "first_name": null, "is_bot": null}, "chat": {"id": null, "type": null}, "date": 0, "text": "good"}},
            {"update_id": 7, "callback_query": {"id": null, "from": null, "data": "c:x"}},
        ]))
        .expect("null fields decode");
        let m0 = batch[0].message.as_ref().expect("message");
        assert_eq!(batch[0].update_id, 0, "null update_id → 0");
        assert_eq!(m0.message_id, 0, "null message_id → 0");
        assert_eq!(m0.chat.id, 0, "null chat → zero Chat");
        assert_eq!(m0.date, 0, "null date → 0");
        assert!(m0.from.is_none(), "null from → None");
        let photo = m0.photo.as_ref().expect("photo");
        assert_eq!(photo.len(), 2, "null photo element kept as default");
        assert_eq!(photo[0].file_id, "", "null photo element → empty file_id");
        assert_eq!(photo[1].file_id, "p1");
        let m1 = batch[1].message.as_ref().expect("message");
        let from = m1.from.as_ref().expect("from");
        assert_eq!(from.id, 111);
        assert_eq!(from.first_name, "", "null first_name → empty");
        assert!(!from.is_bot, "null is_bot → false");
        assert_eq!(m1.chat.id, 0, "null chat.id → 0");
        assert_eq!(m1.chat.kind, "", "null chat.type → empty");
        let cb = batch[2].callback_query.as_ref().expect("callback");
        assert_eq!(cb.id, "", "null callback id → empty");
        assert_eq!(cb.from.id, 0, "null callback from → zero User");
    }

    /// `chat_key` for an edited-only update is the sender
    /// id, like Go `chatKey` (fix loop 1, tech N4).
    #[test]
    fn chat_key_edited_message_is_sender_id() {
        let upd: Update = serde_json::from_str(
            r#"{"update_id": 9, "edited_message": {"message_id": 1, "from": {"id": 33}, "chat": {"id": 100, "type": "private"}}}"#,
        )
        .expect("fixture parses");
        assert_eq!(upd.chat_key(), 33);
    }
}
