// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `telegram-state.json` v1 store.
//!
//! Go source: `internal/telegram/state.go` (whole file) at
//! `main` `1396697`.
//!
//! Crash semantics (header, `state.go:13-47`): the offset is
//! persisted BEFORE handling, so a crash mid-handle LOSES
//! that update instead of redelivering it (at-most-once per
//! update id) — same as Python
//! (`src/muse_cli/tgbot.py:2445-2450`).
//! [DEVIATION vs Python's stored value] Python saves
//! `offset = update_id + 1`; Go persists the max `update_id`
//! itself and the library adds 1 on resume.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::BotError;

/// State file name in the profile dir.
/// Source: `internal/telegram/state.go:52` (`stateFileName`).
pub const STATE_FILE_NAME: &str = "telegram-state.json";

/// State schema version.
/// Source: `internal/telegram/state.go:49`
/// (`telegramStateVersion = 1`).
pub const STATE_VERSION: i64 = 1;

/// Cap on the `sent_media` list.
/// Source: `internal/telegram/state.go:65-70`
/// (`sentMediaCap`).
pub const SENT_MEDIA_CAP: usize = 500;

/// State file path for a profile directory.
/// Source: `internal/telegram/state.go:91-94` (`StatePath`).
#[must_use]
pub fn state_path_for_profile_dir(profile_dir: &Path) -> PathBuf {
    profile_dir.join(STATE_FILE_NAME)
}

/// Watermark key for a session id: the session id, or
/// `"main"` for empty (main chat).
/// Source: `internal/telegram/state.go:83-89`
/// (`WatermarkKey`).
#[must_use]
pub fn watermark_key(session_id: &str) -> String {
    if session_id.is_empty() {
        "main".to_string()
    } else {
        session_id.to_string()
    }
}

/// Sent-media key: identifies one delivery, not one file.
/// Source: `internal/telegram/state.go:77-81`
/// (`SentMediaKey`).
#[must_use]
pub fn sent_media_key(profile: &str, chat_id: i64, session_id: &str, path: &str) -> String {
    format!("{profile}|{chat_id}|{}|{path}", watermark_key(session_id))
}

/// One chat mapping.
/// Source: `internal/telegram/state.go:100-107`
/// (`ChatEntry`): `SessionID ""` = main chat.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatEntry {
    /// Session id ("" = main chat).
    #[serde(
        default,
        rename = "session_id",
        skip_serializing_if = "String::is_empty"
    )]
    pub session_id: String,
    /// Display title.
    #[serde(default)]
    pub title: String,
}

/// The on-disk state file.
/// Source: `internal/telegram/state.go:109-129`
/// (`telegramStateFile`). Serialization skips zero/empty/
/// nil fields, exactly like Go's `omitempty`
/// (fix loop 1, tech N3): a fresh store writes only
/// `{"version": 1}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StateFile {
    /// Schema version (must be 1).
    #[serde(default)]
    version: i64,
    /// Last handled `update_id`.
    #[serde(default, skip_serializing_if = "is_zero")]
    offset: i64,
    /// Chat mappings, keyed by decimal chat id string.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    chats: BTreeMap<String, ChatEntry>,
    /// Watermarks, keyed by [`watermark_key`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    watermarks: BTreeMap<String, i64>,
    /// Runtime `auto_approve` toggle (nil = never toggled,
    /// block values apply).
    #[serde(
        default,
        rename = "auto_approve",
        skip_serializing_if = "Option::is_none"
    )]
    auto_approve: Option<bool>,
    /// Runtime `auto_allow_once` toggle (nil = never toggled).
    #[serde(
        default,
        rename = "auto_allow_once",
        skip_serializing_if = "Option::is_none"
    )]
    auto_allow_once: Option<bool>,
    /// Runtime `watch` toggle (nil = never toggled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    watch: Option<bool>,
    /// Claimed sent-media keys, oldest first, cap 500.
    #[serde(default, rename = "sent_media", skip_serializing_if = "Vec::is_empty")]
    sent_media: Vec<String>,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

/// The effective toggles: block values overlaid with the
/// state file's non-nil values (gate D4).
/// Source: `internal/commands/telegram.go:197-213`
/// (effective-toggles closure) and
/// `internal/telegram/state.go:376-393` (`Toggles`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveToggles {
    /// Effective `auto_approve`.
    pub auto_approve: bool,
    /// Effective `auto_allow_once`.
    pub auto_allow_once: bool,
    /// Effective `watch`.
    pub watch: bool,
}

/// The state store: load once, mutate under one lock, save
/// atomically (temp + fsync + chmod 0600 + rename).
/// Source: `internal/telegram/state.go:188-458`
/// (`LoadStateStore`, `saveLocked`, accessors).
pub struct TelegramStateStore {
    path: PathBuf,
    inner: Mutex<StateFile>,
    /// Whether the loaded file was corrupt JSON (fresh store
    /// built; the caller logs once that offset resets to 0).
    /// Source: `internal/telegram/state.go:188-257`.
    corrupt: bool,
}

impl std::fmt::Debug for TelegramStateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramStateStore")
            .field("path", &self.path)
            .field("corrupt", &self.corrupt)
            .finish_non_exhaustive()
    }
}

impl TelegramStateStore {
    /// Load the store at `path`: missing or empty file →
    /// fresh store, `corrupt=false`; present file with
    /// corrupt JSON → fresh store, `corrupt=true`; unknown
    /// schema version → error, bot refuses to start rather
    /// than silently discard state; any other read failure →
    /// error. Unknown fields are ignored (forward tolerance).
    /// Source: `internal/telegram/state.go:188-257`
    /// (`LoadStateStore`).
    pub fn load(path: PathBuf) -> Result<Self, BotError> {
        match fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path,
                inner: Mutex::new(StateFile {
                    version: STATE_VERSION,
                    ..StateFile::default()
                }),
                corrupt: false,
            }),
            Err(e) => Err(BotError::State(format!(
                "cannot read state file: {}",
                io_error_kind(&e)
            ))),
            Ok(bytes) => {
                if bytes.iter().all(|b| b.is_ascii_whitespace()) {
                    return Ok(Self {
                        path,
                        inner: Mutex::new(StateFile {
                            version: STATE_VERSION,
                            ..StateFile::default()
                        }),
                        corrupt: false,
                    });
                }
                let value: serde_json::Value = match serde_json::from_slice(&bytes) {
                    Ok(v) => v,
                    Err(_) => {
                        return Ok(Self {
                            path,
                            inner: Mutex::new(StateFile {
                                version: STATE_VERSION,
                                ..StateFile::default()
                            }),
                            corrupt: true,
                        });
                    }
                };
                // Two-phase version check
                // (`internal/telegram/state.go:145-186`): the
                // version must be an integer literal; a
                // non-integer shape refuses with a ≤32-rune
                // echo, and an out-of-range integer refuses
                // too. Missing version counts as 0 (refused).
                let version_value = value.get("version");
                let version = match version_value {
                    Some(v) if v.is_i64() || v.is_u64() => v.as_i64().unwrap_or(-1),
                    Some(v) => {
                        let echo =
                            truncate_runes(&serde_json::to_string(v).unwrap_or_default(), 32);
                        return Err(BotError::State(format!(
                            "unknown telegram state version shape: {echo}"
                        )));
                    }
                    None => 0,
                };
                if version != STATE_VERSION {
                    let chats = value
                        .get("chats")
                        .and_then(|c| c.as_object())
                        .map_or(0, |o| o.len());
                    let watermarks = value
                        .get("watermarks")
                        .and_then(|w| w.as_object())
                        .map_or(0, |o| o.len());
                    // Go `state.go:188-215` also reports the
                    // offset and the runtime-toggle count in
                    // the refusal (fix loop 1, tech N3).
                    let offset = value.get("offset").and_then(|o| o.as_i64()).unwrap_or(0);
                    let toggles = ["auto_approve", "auto_allow_once", "watch"]
                        .iter()
                        .filter(|k| value.get(**k).is_some_and(|v| !v.is_null()))
                        .count();
                    return Err(BotError::State(format!(
                        "unknown telegram state version {version} (would discard {chats} chats, {watermarks} watermarks, offset {offset}, and {toggles} runtime toggles)"
                    )));
                }
                // Body type-mismatch (valid JSON, wrong field
                // type) → fresh store + corrupt, like Go's
                // `state.go:240-242`: the in-memory shape is
                // rebuilt from scratch, so a wrong-type
                // field is unrecoverable, while the file (and
                // the caller's data) is preserved for the
                // operator to inspect. Only the version
                // SHAPE (non-integer literal) and an unknown
                // numeric version refuse (above).
                let file: StateFile = match serde_json::from_value(value) {
                    Ok(f) => f,
                    Err(_) => {
                        return Ok(Self {
                            path,
                            inner: Mutex::new(StateFile {
                                version: STATE_VERSION,
                                ..StateFile::default()
                            }),
                            corrupt: true,
                        });
                    }
                };
                Ok(Self {
                    path,
                    inner: Mutex::new(file),
                    corrupt: false,
                })
            }
        }
    }

    /// Whether the loaded file was corrupt JSON.
    #[must_use]
    pub fn corrupt(&self) -> bool {
        self.corrupt
    }

    /// The state file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Atomic save: whole file, `MarshalIndent` + `\n`,
    /// unique temp file (0600 at creation) + fsync +
    /// rename in the same directory, `MkdirAll(dir, 0700)`
    /// only when the directory is created. The temp is
    /// unique per save (pid + atomic counter + nanos,
    /// `create_new`, like Go's `os.CreateTemp(dir,
    /// ".telegram-state-*.tmp")` — `state.go:273-310` —
    /// fix loop 1, tech B3) and removed on any error
    /// before the rename. The directory is chmod'd 0700
    /// ONLY when it did not exist: re-chmod'ing a
    /// pre-existing profile dir on every save could
    /// silently tighten (or, on a shared dir, fight) the
    /// operator's permissions.
    /// Source: `internal/telegram/state.go:273-310`
    /// (`saveLocked`).
    fn save_locked(&self, file: &StateFile) -> Result<(), BotError> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| BotError::State("state path has no parent".to_string()))?;
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(|e| {
                BotError::State(format!("cannot create state dir: {}", io_error_kind(&e)))
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
            }
        }
        let text = serde_json::to_string_pretty(file)
            .map_err(|_| BotError::State("cannot encode state file".to_string()))?;
        let (tmp_path, mut tmp) = create_unique_temp(dir)?;
        let mut guard = TempGuard {
            path: tmp_path.clone(),
            armed: true,
        };
        tmp.write_all(text.as_bytes()).map_err(|e| {
            BotError::State(format!(
                "cannot write state temp file: {}",
                io_error_kind(&e)
            ))
        })?;
        tmp.write_all(b"\n").map_err(|e| {
            BotError::State(format!(
                "cannot write state temp file: {}",
                io_error_kind(&e)
            ))
        })?;
        tmp.sync_all().map_err(|e| {
            BotError::State(format!(
                "cannot fsync state temp file: {}",
                io_error_kind(&e)
            ))
        })?;
        drop(tmp);
        fs::rename(&tmp_path, &self.path).map_err(|e| {
            BotError::State(format!("cannot rename state file: {}", io_error_kind(&e)))
        })?;
        guard.disarm();
        Ok(())
    }

    /// Last handled `update_id`.
    /// Source: `internal/telegram/state.go:312-317` (`Offset`).
    #[must_use]
    pub fn offset(&self) -> i64 {
        self.inner.lock().map_or(0, |f| f.offset)
    }

    /// Advance the offset when `id` is newer (smaller/equal
    /// = no-op); save failure is returned, but the in-memory
    /// offset still advances (next mutation retries the save).
    /// Source: `internal/telegram/state.go:322-332`
    /// (`NoteOffset`).
    pub fn note_offset(&self, id: i64) -> Result<(), BotError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| BotError::State("state lock poisoned".to_string()))?;
        if id <= guard.offset {
            return Ok(());
        }
        guard.offset = id;
        self.save_locked(&guard)
    }

    /// Chat mapping for `chat_id` (unseen chat defaults to
    /// main, not written until it switches).
    /// Source: `internal/telegram/state.go:334-349`
    /// (`Chat` / `SetChat`).
    #[must_use]
    pub fn chat(&self, chat_id: i64) -> ChatEntry {
        self.inner.lock().map_or_else(
            |_| ChatEntry {
                session_id: String::new(),
                title: "main chat".to_string(),
            },
            |f| {
                f.chats
                    .get(&chat_id.to_string())
                    .cloned()
                    .unwrap_or(ChatEntry {
                        session_id: String::new(),
                        title: "main chat".to_string(),
                    })
            },
        )
    }

    /// Set a chat mapping.
    /// Source: `internal/telegram/state.go:334-349`
    /// (`SetChat`).
    pub fn set_chat(&self, chat_id: i64, entry: ChatEntry) -> Result<(), BotError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| BotError::State("state lock poisoned".to_string()))?;
        guard.chats.insert(chat_id.to_string(), entry);
        self.save_locked(&guard)
    }

    /// Watermark for a session (0 when absent).
    /// Source: `internal/telegram/state.go:351-374`
    /// (`Watermark` / `SetWatermark`).
    #[must_use]
    pub fn watermark(&self, session_id: &str) -> i64 {
        self.inner.lock().map_or(0, |f| {
            f.watermarks
                .get(&watermark_key(session_id))
                .copied()
                .unwrap_or(0)
        })
    }

    /// Record a watermark, monotonic-max only; saves only
    /// when advancing.
    /// Source: `internal/telegram/state.go:351-374`.
    pub fn set_watermark(&self, session_id: &str, seq: i64) -> Result<(), BotError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| BotError::State("state lock poisoned".to_string()))?;
        let key = watermark_key(session_id);
        let current = guard.watermarks.get(&key).copied().unwrap_or(0);
        if seq <= current {
            return Ok(());
        }
        guard.watermarks.insert(key, seq);
        self.save_locked(&guard)
    }

    /// Effective toggles: fresh copies per field; state-file
    /// non-nil values win over block values.
    /// Source: `internal/telegram/state.go:376-393`
    /// (`Toggles`).
    #[must_use]
    pub fn toggles(
        &self,
        block_auto_approve: bool,
        block_auto_allow_once: bool,
    ) -> EffectiveToggles {
        self.inner.lock().map_or(
            EffectiveToggles {
                auto_approve: block_auto_approve,
                auto_allow_once: block_auto_allow_once,
                watch: false,
            },
            |f| EffectiveToggles {
                auto_approve: f.auto_approve.unwrap_or(block_auto_approve),
                auto_allow_once: f.auto_allow_once.unwrap_or(block_auto_allow_once),
                watch: f.watch.unwrap_or(false),
            },
        )
    }

    /// Write both toggles together.
    /// Source: `internal/telegram/state.go:395-402`
    /// (`SetToggles`).
    pub fn set_toggles(&self, auto_approve: bool, auto_allow_once: bool) -> Result<(), BotError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| BotError::State("state lock poisoned".to_string()))?;
        guard.auto_approve = Some(auto_approve);
        guard.auto_allow_once = Some(auto_allow_once);
        self.save_locked(&guard)
    }

    /// Write the watch flag.
    /// Source: `internal/telegram/state.go:404-411`
    /// (`SetWatch`).
    pub fn set_watch(&self, watch: bool) -> Result<(), BotError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| BotError::State("state lock poisoned".to_string()))?;
        guard.watch = Some(watch);
        self.save_locked(&guard)
    }

    /// Whether a sent-media key is already claimed.
    /// Source: `internal/telegram/state.go:413-447`
    /// (`SentMedia` / `ClaimSentMedia`).
    #[must_use]
    pub fn sent_media_claimed(&self, key: &str) -> bool {
        self.inner
            .lock()
            .is_ok_and(|f| f.sent_media.iter().any(|k| k == key))
    }

    /// Claim a sent-media key: check+append+cap-trim+save
    /// atomically under one lock (returns false when already
    /// claimed — caller must skip the send); save failure
    /// keeps the in-memory claim.
    /// Source: `internal/telegram/state.go:413-447`.
    pub fn claim_sent_media(&self, key: &str) -> Result<bool, BotError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| BotError::State("state lock poisoned".to_string()))?;
        if guard.sent_media.iter().any(|k| k == key) {
            return Ok(false);
        }
        guard.sent_media.push(key.to_string());
        while guard.sent_media.len() > SENT_MEDIA_CAP {
            guard.sent_media.remove(0);
        }
        // Go `ClaimSentMedia` returns the save error
        // (`state.go:413-448`); the in-memory claim still
        // stands on save failure (next mutation retries
        // the save) — fix loop 1, tech N2.
        self.save_locked(&guard)?;
        Ok(true)
    }

    /// Release a sent-media key so a later turn retries
    /// (download/send failure releases; success or too-big
    /// refusal keeps it).
    /// Source: `internal/telegram/state.go:449-458`
    /// (`ReleaseSentMedia`).
    pub fn release_sent_media(&self, key: &str) -> Result<(), BotError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| BotError::State("state lock poisoned".to_string()))?;
        let before = guard.sent_media.len();
        guard.sent_media.retain(|k| k != key);
        if guard.sent_media.len() != before {
            // Go `ReleaseSentMedia` returns the save error
            // when the key was present (`state.go:449-458`)
            // — fix loop 1, tech N2.
            self.save_locked(&guard)?;
        }
        Ok(())
    }
}

/// Short error-kind label for a state error message (never a
/// path or content).
fn io_error_kind(e: &std::io::Error) -> String {
    format!("{:?}", e.kind()).to_lowercase()
}

fn truncate_runes(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        s.to_string()
    } else {
        s.chars().take(limit).collect()
    }
}

/// A save temp file that is removed unless the rename
/// succeeded. `Drop` never panics (the remove result is
/// ignored — a leftover temp is harmless, and a panicking
/// drop during unwind would abort).
struct TempGuard {
    path: PathBuf,
    armed: bool,
}

impl TempGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Create a UNIQUE temp file in `dir` for one save, like
/// Go's `os.CreateTemp(dir, ".telegram-state-*.tmp")`
/// (`state.go:273-310`): pid + atomic counter + nanos,
/// `create_new` (no clobber), mode 0600 from creation
/// (unix). Retries on name collision; any other error is
/// returned.
fn create_unique_temp(dir: &Path) -> Result<(PathBuf, fs::File), BotError> {
    static SAVE_COUNTER: AtomicU64 = AtomicU64::new(0);
    for _ in 0..100 {
        let n = SAVE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        let path = dir.join(format!(
            ".telegram-state-{}-{n}-{nanos}.tmp",
            std::process::id()
        ));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(BotError::State(format!(
                    "cannot write state temp file: {}",
                    io_error_kind(&e)
                )));
            }
        }
    }
    Err(BotError::State(
        "cannot create unique state temp file".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tmp_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        // The pid makes the path unique across test-binary
        // invocations: without it, a previous run's saved
        // file (e.g. toggles written by `set_toggles`)
        // would be re-loaded and poison the test.
        std::env::temp_dir().join(format!(
            "castctl-telegram-state-test-{}-{n}.json",
            std::process::id()
        ))
    }

    #[test]
    fn missing_file_is_fresh_not_corrupt() {
        let path = tmp_path();
        let store = TelegramStateStore::load(path).expect("load");
        assert!(!store.corrupt());
        assert_eq!(store.offset(), 0);
    }

    #[test]
    fn offset_is_monotonic_and_persists() {
        let path = tmp_path();
        let store = TelegramStateStore::load(path.clone()).expect("load");
        store.note_offset(41).expect("save");
        store.note_offset(40).expect("no-op");
        assert_eq!(store.offset(), 41);
        let reloaded = TelegramStateStore::load(path).expect("reload");
        assert_eq!(reloaded.offset(), 41);
    }

    #[test]
    fn corrupt_json_is_fresh_and_flagged() {
        let path = tmp_path();
        fs::write(&path, "{not json").expect("write");
        let store = TelegramStateStore::load(path).expect("load");
        assert!(store.corrupt());
        assert_eq!(store.offset(), 0);
    }

    #[test]
    fn unknown_version_refuses_startup() {
        let path = tmp_path();
        fs::write(&path, r#"{"version": 2, "offset": 9}"#).expect("write");
        let err = TelegramStateStore::load(path).expect_err("must refuse");
        assert!(err.to_string().contains("unknown telegram state version 2"));
    }

    /// Go's refusal names the offset and the runtime
    /// toggles at stake (fix loop 1, tech N3).
    #[test]
    fn unknown_version_error_carries_offset_and_toggles() {
        let path = tmp_path();
        fs::write(
            &path,
            r#"{"version": 2, "offset": 9, "chats": {"7": {"title": "t"}}, "watermarks": {"main": 3}, "auto_approve": true, "watch": false}"#,
        )
        .expect("write");
        let err = TelegramStateStore::load(path).expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("offset 9"), "{msg}");
        assert!(msg.contains("1 chats"), "{msg}");
        assert!(msg.contains("1 watermarks"), "{msg}");
        assert!(msg.contains("2 runtime toggles"), "{msg}");
    }

    /// Valid JSON, wrong field TYPE → fresh store +
    /// corrupt, like Go `state.go:240-242` (fix loop 1,
    /// tech B3). The file is preserved on disk.
    #[test]
    fn body_type_mismatch_is_fresh_and_flagged() {
        for body in [
            r#"{"version": 1, "chats": "oops"}"#,
            r#"{"version": 1, "offset": "42"}"#,
            r#"{"version": 1, "watermarks": [1, 2]}"#,
        ] {
            let path = tmp_path();
            fs::write(&path, body).expect("write");
            let store = TelegramStateStore::load(path.clone()).expect("load");
            assert!(store.corrupt(), "body {body}");
            assert_eq!(store.offset(), 0);
            assert!(path.exists(), "file preserved for the operator");
        }
    }

    /// Concurrent saves from two stores on the same path
    /// all succeed and leave no `*.tmp` behind (unique
    /// temp per save, fix loop 1, tech B3).
    #[test]
    fn concurrent_saves_leave_no_temp_files() {
        use std::sync::Arc;
        // Dedicated directory: the shared temp dir holds
        // other tests' in-flight temps, which must not be
        // counted here.
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "castctl-telegram-state-concurrent-{}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("telegram-state.json");
        let a = Arc::new(TelegramStateStore::load(path.clone()).expect("load a"));
        let b = Arc::new(TelegramStateStore::load(path.clone()).expect("load b"));
        let mut handles = Vec::new();
        for i in 0..16 {
            let s = if i % 2 == 0 {
                Arc::clone(&a)
            } else {
                Arc::clone(&b)
            };
            handles.push(std::thread::spawn(move || {
                s.note_offset(i).expect("save");
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temps: {leftovers:?}");
        let reloaded = TelegramStateStore::load(path).expect("reload");
        assert!(reloaded.offset() >= 0);
    }

    /// A save must not chmod a pre-existing directory
    /// (fix loop 1, tech B3): 0755 stays 0755. Uses a
    /// DEDICATED directory — never the shared temp dir
    /// itself (an earlier draft chmod'd `/tmp`).
    #[cfg(unix)]
    #[test]
    fn save_does_not_chmod_existing_dir() {
        use std::os::unix::fs::PermissionsExt;
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "castctl-telegram-state-chmod-{}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod");
        let path = dir.join("telegram-state.json");
        let store = TelegramStateStore::load(path).expect("load");
        store.note_offset(7).expect("save");
        let mode = fs::metadata(&dir).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "dir perms must be untouched");
    }

    /// Fresh store serializes like Go's `omitempty` (fix
    /// loop 1, tech N3): only `version` is written.
    #[test]
    fn serialize_skips_nulls_like_go_omitempty() {
        let path = tmp_path();
        let store = TelegramStateStore::load(path.clone()).expect("load");
        store.set_watermark("main", 5).expect("save");
        let text = fs::read_to_string(&path).expect("read");
        assert!(text.contains("watermarks"), "{text}");
        assert!(!text.contains("offset"), "{text}");
        assert!(!text.contains("auto_approve"), "{text}");
        assert!(!text.contains("sent_media"), "{text}");
        assert!(!text.contains("session_id"), "{text}");
    }

    #[test]
    fn string_version_shape_refuses() {
        let path = tmp_path();
        fs::write(&path, r#"{"version": "2", "offset": 9}"#).expect("write");
        assert!(TelegramStateStore::load(path).is_err());
    }

    #[test]
    fn toggles_nil_means_block_values_win() {
        let path = tmp_path();
        let store = TelegramStateStore::load(path).expect("load");
        let t = store.toggles(true, false);
        assert!(t.auto_approve);
        assert!(!t.auto_allow_once);
        assert!(!t.watch);
        store.set_toggles(false, true).expect("save");
        let t = store.toggles(true, false);
        assert!(!t.auto_approve);
        assert!(t.auto_allow_once);
    }

    #[test]
    fn sent_media_cap_trims_oldest() {
        let path = tmp_path();
        let store = TelegramStateStore::load(path).expect("load");
        for i in 0..SENT_MEDIA_CAP + 2 {
            assert!(store.claim_sent_media(&format!("k{i}")).expect("claim"));
        }
        assert!(!store.sent_media_claimed("k0"));
        assert!(!store.sent_media_claimed("k1"));
        assert!(store.sent_media_claimed(&format!("k{}", SENT_MEDIA_CAP + 1)));
        assert!(
            !store
                .claim_sent_media(&format!("k{}", SENT_MEDIA_CAP + 1))
                .expect("dup")
        );
    }
}
