// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! File send / receive over the Bot API.
//!
//! Go sources: `internal/telegram/files.go` (whole file;
//! the pure part — `FileKindFor`, `DocName` — is reused
//! from `castctl-tg-files`, M1) and
//! `internal/telegram/inbound.go:33-221` (`DownloadLimit`,
//! `MediaOf`, `InboxName`, `DownloadMedia`).
//!
//! Caps (all in `files.go` unless noted):
//! upload 49 MiB, photo 10 MiB, caption 1024 runes, upload
//! client 120s, download 20 MiB, `/files` list 12 rows,
//! `/files` history window last 40 events, `sent_media`
//! state cap 500.

use castctl_tg_files::{UPLOAD_LIMIT, file_kind_for};
use castctl_tg_text::CAPTION_LIMIT;

use crate::api::BotApi;
use crate::error::BotError;
use crate::send::SendOptions;
use crate::types::{FileObject, Message};

/// Largest file the bot fetches from a user: 20 MiB.
/// Source: `internal/telegram/inbound.go:33-40`
/// (`DownloadLimit`; Python `src/muse_cli/tgapi.py:20`,
/// "bots may fetch up to 20 MB").
pub const DOWNLOAD_LIMIT: i64 = 20 << 20;

/// Refusal wording for an oversize download-button file.
/// [DEVIATION] the wording says 49 MB and names castctl,
/// where upstream says 50 MB and names muse-cli.
/// Source: `internal/commands/telegram_commands.go:711-720`
/// (`downloadFile`). Copy verbatim; do not "fix" it.
pub const TOO_BIG_DOWNLOAD_REFUSAL: &str = "Too big for Telegram (49 MB); use castctl download.";

/// Refusal wording for an oversize `/fs get` file. Note the
/// message says 50 MB while the gate is 49 MiB (upstream
/// wording kept here; contrast `TOO_BIG_DOWNLOAD_REFUSAL`).
/// Source: `internal/commands/telegram_fs.go:330-334`.
/// Copy verbatim; do not "fix" the inconsistency.
pub const TOO_BIG_FS_GET_REFUSAL: &str = "Too big for Telegram (50 MB).";

/// One inbound media attachment, normalised.
/// Source: `internal/telegram/inbound.go:64-144` (`MediaOf`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxMedia {
    /// Bot API `file_id`.
    pub file_id: String,
    /// Derived file name (e.g. `photo-<mid>.jpg`).
    pub name: String,
    /// MIME type, when known.
    pub mime_type: Option<String>,
    /// Declared size, when the server reports it.
    pub size: Option<i64>,
    /// Media kind (`photo`, `document`, `video`, `audio`,
    /// `voice`, `video_note`, `animation`).
    pub kind: String,
}

/// Extract the media attachment of a message, if any.
/// Photo takes the LAST size in the array (name
/// `photo-<message_id>.jpg`, mime `image/jpeg`); other kinds
/// are tried in order document, video, audio, voice,
/// video_note, animation; unnamed → `<kind>-<message_id><ext>`
/// (voice `.ogg`, video and video_note `.mp4`, audio `.mp3`,
/// animation `.mp4`; document takes no extension). Nil
/// message, no media, and **stickers** → `None`.
/// Source: `internal/telegram/inbound.go:64-144` (`MediaOf`;
/// Python `src/muse_cli/tgbot.py:1762-1775`).
#[must_use]
pub fn media_of(msg: &Message) -> Option<InboxMedia> {
    if let Some(photos) = &msg.photo
        && let Some(last) = photos.last()
    {
        return Some(InboxMedia {
            file_id: last.file_id.clone(),
            name: format!("photo-{}.jpg", msg.message_id),
            mime_type: Some("image/jpeg".to_string()),
            size: last.file_size,
            kind: "photo".to_string(),
        });
    }
    let candidates: [(&str, &Option<FileObject>, &str); 6] = [
        ("document", &msg.document, ""),
        ("video", &msg.video, ".mp4"),
        ("audio", &msg.audio, ".mp3"),
        ("voice", &msg.voice, ".ogg"),
        ("video_note", &msg.video_note, ".mp4"),
        ("animation", &msg.animation, ".mp4"),
    ];
    for (kind, obj, ext) in candidates {
        if let Some(file) = obj {
            // Go returns `""` for the file name of voice
            // and video_note (`inbound.go:100-110`), so
            // those ALWAYS take the derived name, even if
            // the object carries a `file_name` (fix loop
            // 1, tech N13).
            let name = match &file.file_name {
                Some(n) if !n.is_empty() && kind != "voice" && kind != "video_note" => n.clone(),
                _ => format!("{kind}-{}{ext}", msg.message_id),
            };
            return Some(InboxMedia {
                file_id: file.file_id.clone(),
                name,
                mime_type: file.mime_type.clone(),
                size: file.file_size,
                kind: kind.to_string(),
            });
        }
    }
    None
}

/// Inbox file name: runs of `[^A-Za-z0-9._-]` collapse to
/// one `_`, leading/trailing `.`/`_` stripped, empty →
/// `file`, prefixed `<YYYYmmdd-HHMMSS>-`.
/// Source: `internal/telegram/inbound.go:146-170`
/// (`InboxName`; Python `src/muse_cli/tgbot.py:1782-1783`).
///
/// [DEVIATION] Go prefixes local time; this port prefixes
/// UTC (no timezone database access in this crate — the
/// prefix is only a filename disambiguator, and the inbox
/// write path is an M5b seam anyway).
#[must_use]
pub fn inbox_name(name: &str, at_unix: i64) -> String {
    let mut cleaned = String::new();
    let mut last_was_sep = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            cleaned.push(c);
            last_was_sep = false;
        } else if !last_was_sep {
            cleaned.push('_');
            last_was_sep = true;
        }
    }
    let trimmed = cleaned.trim_matches(|c| c == '.' || c == '_').to_string();
    let base = if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed
    };
    format!("{}-{base}", format_timestamp(at_unix))
}

/// `YYYYmmdd-HHMMSS` in UTC from a unix timestamp
/// (Howard Hinnant's civil-from-days algorithm).
/// No direct Go function counterpart: Go formats
/// `time.Now()`; this is the UTC equivalent.
fn format_timestamp(at_unix: i64) -> String {
    let days = at_unix.div_euclid(86_400);
    let secs = at_unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, min, sec) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    format!("{year:04}{month:02}{day:02}-{hour:02}{min:02}{sec:02}")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Download one inbound media file: `getFile` via the poll
/// instance, then GET of the file URL via the 120s upload
/// client. Gate 1 refuses when `getFile`'s reported size >
/// `DOWNLOAD_LIMIT`, before downloading; empty `file_path`
/// = fetch failure. Gate 2 reads through a limit at cap+1
/// and refuses when more than `DOWNLOAD_LIMIT` bytes arrive.
/// The download URL contains the token: never logged, never
/// interpolated into an error, never stored; every error
/// leaving here is a scrubbed copy. A non-200 file response
/// carries only the status code.
/// Source: `internal/telegram/inbound.go:172-221`
/// (`DownloadMedia`).
///
/// Gate 2 is a [DEVIATION]: upstream has no post-download
/// gate. Both transport paths cap bodies at 16 MiB
/// (`MAX_RESPONSE_BODY`), so Gate 2 only ever observes
/// files up to that size; a file in (16 MiB, 20 MiB] fails
/// at the transport instead (see `api.rs`,
/// `download_file_bytes` — PORTING §M5a deviation 20).
pub async fn download_media(api: &BotApi, media: &InboxMedia) -> Result<Vec<u8>, BotError> {
    // Go `DownloadMedia` (`inbound.go:172-221`) errors
    // first on a nil/empty file id — before any `getFile`
    // call (fix loop 1, tech N14).
    if media.file_id.is_empty() {
        return Err(BotError::Validation(
            "telegram: no file to download".to_string(),
        ));
    }
    if let Some(size) = media.size
        && size > DOWNLOAD_LIMIT
    {
        return Err(BotError::Validation(
            "file exceeds the 20 MiB download limit".to_string(),
        ));
    }
    let file_path = api.get_file_path(&media.file_id).await?;
    let bytes = api
        .download_file_bytes(&file_path, (DOWNLOAD_LIMIT as usize) + 1)
        .await?;
    if bytes.len() as i64 > DOWNLOAD_LIMIT {
        return Err(BotError::Validation(
            "file exceeds the 20 MiB download limit".to_string(),
        ));
    }
    Ok(bytes.to_vec())
}

/// Send a file: kind via `FileKindFor(name, mime,
/// len(data))`; caption truncated to `CaptionLimit` runes,
/// sent plain (no `parse_mode`); `opts.Markup` attached,
/// `opts.Silent` → `disable_notification`, `opts.ReplyTo`
/// → `reply_parameters`. Returns the sent message id; every
/// failure path returns a scrubbed error.
/// Source: `internal/telegram/files.go:169-191` (`SendFile`)
/// and `:192-264` (`sendFileKind`).
///
/// [DEVIATION] `opts.Mode` is ignored (no upstream file
/// equivalent). [DEVIATION] mime feeds kind selection only.
/// [DEVIATION] goes through `retryCall` (429 retries);
/// upstream `send_file` posts once with the 120s timeout.
/// [DEVIATION] the `sendDocument` fallback triggers ONLY
/// on a BadRequest when kind ≠ document, exactly once
/// (upstream retries on ANY `TelegramError`).
///
/// No size limit is enforced here — callers refuse oversize
/// files before downloading (`UPLOAD_LIMIT`).
pub async fn send_file(
    api: &BotApi,
    chat_id: i64,
    name: &str,
    data: &[u8],
    mime: &str,
    caption: &str,
    opts: &SendOptions,
) -> Result<i64, BotError> {
    let kind = file_kind_for(name, mime, data.len() as i64);
    let method = match kind {
        castctl_tg_files::FileKind::Document => "sendDocument",
        castctl_tg_files::FileKind::Photo => "sendPhoto",
        castctl_tg_files::FileKind::Video => "sendVideo",
        castctl_tg_files::FileKind::Audio => "sendAudio",
    };
    let caption_trunc: String = caption.chars().take(CAPTION_LIMIT).collect();
    let result = api
        .send_file_multipart(
            method,
            chat_id,
            name,
            data,
            &caption_trunc,
            opts.reply_to,
            opts.silent,
            opts.markup.clone(),
        )
        .await;
    match result {
        Ok(id) => Ok(id),
        Err(e) if e.api_code() == Some(400) && kind != castctl_tg_files::FileKind::Document => {
            api.send_file_multipart(
                "sendDocument",
                chat_id,
                name,
                data,
                &caption_trunc,
                opts.reply_to,
                opts.silent,
                opts.markup.clone(),
            )
            .await
        }
        Err(e) => Err(e),
    }
}

/// Whether `data` exceeds the upload limit (callers refuse
/// before downloading).
/// Source: `internal/telegram/files.go:32-36`
/// (`UploadLimit = 49 MiB`).
#[must_use]
pub fn exceeds_upload_limit(size: i64) -> bool {
    size > UPLOAD_LIMIT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message_with_photo() -> Message {
        serde_json::from_str(
            r#"{"message_id": 9, "chat": {"id": 1, "type": "private"}, "photo": [{"file_id": "p1", "file_size": 100}, {"file_id": "p2", "file_size": 900}]}"#,
        )
        .expect("fixture parses")
    }

    #[test]
    fn media_of_photo_takes_last_size() {
        let media = media_of(&message_with_photo()).expect("media");
        assert_eq!(media.file_id, "p2");
        assert_eq!(media.name, "photo-9.jpg");
        assert_eq!(media.mime_type.as_deref(), Some("image/jpeg"));
        assert_eq!(media.size, Some(900));
    }

    #[test]
    fn media_of_document_unnamed_gets_kind_name() {
        let msg: Message = serde_json::from_str(
            r#"{"message_id": 4, "chat": {"id": 1, "type": "private"}, "document": {"file_id": "d1"}}"#,
        )
        .expect("fixture parses");
        let media = media_of(&msg).expect("media");
        assert_eq!(media.name, "document-4");
    }

    /// Go returns `""` for voice/video_note file names
    /// (`inbound.go:100-110`), so the derived name always
    /// wins — even when the object carries a `file_name`
    /// (fix loop 1, tech N13).
    #[test]
    fn media_of_voice_and_video_note_ignore_file_name() {
        let msg: Message = serde_json::from_str(
            r#"{"message_id": 3, "chat": {"id": 1, "type": "private"}, "voice": {"file_id": "v1", "file_name": "should-be-ignored.ogg", "mime_type": "audio/ogg"}}"#,
        )
        .expect("fixture parses");
        assert_eq!(media_of(&msg).expect("media").name, "voice-3.ogg");
        let msg: Message = serde_json::from_str(
            r#"{"message_id": 4, "chat": {"id": 1, "type": "private"}, "video_note": {"file_id": "vn1", "file_name": "ignored.mp4"}}"#,
        )
        .expect("fixture parses");
        assert_eq!(media_of(&msg).expect("media").name, "video_note-4.mp4");
    }

    #[test]
    fn media_of_sticker_is_none() {
        let msg: Message = serde_json::from_str(
            r#"{"message_id": 4, "chat": {"id": 1, "type": "private"}, "sticker": {"file_id": "s1"}}"#,
        )
        .expect("fixture parses");
        assert!(media_of(&msg).is_none());
    }

    #[test]
    fn inbox_name_sanitises_and_prefixes() {
        assert_eq!(
            inbox_name("my file!.txt", 0),
            "19700101-000000-my_file_.txt"
        );
        assert_eq!(inbox_name("!!!", 0), "19700101-000000-file");
        assert_eq!(inbox_name(".hidden.", 0), "19700101-000000-hidden");
    }

    #[test]
    fn civil_from_days_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_000), (2024, 10, 4));
    }
}
