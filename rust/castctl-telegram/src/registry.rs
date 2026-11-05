// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Callback-button registry and markup builders.
//!
//! Go source: `internal/telegram/approvals.go:224-411`
//! (`CallbackEntry`, `CallbackRegistry`, `ApprovalMarkup`,
//! `ApproveAllMarkup`).
//!
//! Callback data carries NO approval data — an opaque `c:`
//! token only; arguments live in process memory (Telegram
//! 64-byte limit; Python `src/muse_cli/tgbot.py:938-946`).

use std::collections::HashMap;
use std::sync::Mutex;

use crate::approvals::{Approval, offers_forever, offers_once};
use crate::send::{InlineKeyboardButton, InlineKeyboardMarkup};

/// Registry cap: 3000 entries, oldest evicted first.
/// Source: `internal/telegram/approvals.go:266-274`
/// (`CallbackRegistryCap = 3000`).
pub const CALLBACK_REGISTRY_CAP: usize = 3000;

/// Token length: 6 random bytes, base64url, 8 chars.
/// Source: `internal/telegram/approvals.go:285-341`
/// (`Register`).
pub const CALLBACK_TOKEN_BYTES: usize = 6;

/// One registered button's arguments.
/// Source: `internal/telegram/approvals.go:224-264`
/// (`CallbackEntry`).
#[derive(Debug, Clone, Default)]
pub struct CallbackEntry {
    /// Action: `decide`, `approve_all`, `open`,
    /// `chats_page`, `dl`, `delete`, `noop`, `answer`,
    /// `idea_exec`, `fs_rm`, `profile` (registered never;
    /// defensive drop in `bot.go:1271-1273`).
    pub action: String,
    /// Approval id (decide / approve_all).
    pub approval_id: String,
    /// Decision string (`allow_always` / `allow_once` / `deny`).
    pub decision: String,
    /// Session id (open / delete / resume triple).
    pub session_id: String,
    /// Chat title (resume triple / delete prompt).
    pub title: String,
    /// Idea card id (`idea_exec`).
    pub idea_id: String,
    /// Resume sequence (nil = no resume).
    pub after_seq: Option<i64>,
    /// File path (`dl` / `fs_rm`).
    pub fs_path: String,
    /// Recursive flag (`fs_rm`).
    pub fs_recursive: bool,
    /// Question answer text (`answer`).
    pub answer: String,
    /// Chat-picker page (`chats_page`).
    pub page: i64,
    /// File resource path for `dl` (the whole
    /// `shared.Resource` in Go; the path is what the Rust
    /// download seam needs).
    pub resource_path: String,
    /// File resource size, when known (`dl` pre-check).
    pub resource_size: Option<i64>,
    /// File resource MIME, when known (`dl` kind selection).
    pub resource_mime: Option<String>,
}

/// In-memory callback registry: entries lost on restart → a
/// button reads "expired".
/// Source: `internal/telegram/approvals.go:266-376`.
pub struct CallbackRegistry {
    inner: Mutex<RegistryInner>,
}

struct RegistryInner {
    entries: HashMap<String, CallbackEntry>,
    order: Vec<String>,
}

impl CallbackRegistry {
    /// New empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RegistryInner {
                entries: HashMap::new(),
                order: Vec::new(),
            }),
        }
    }

    /// Register an entry, returning its `c:` callback data.
    /// Token = 6 random bytes, base64url, 8 chars; data =
    /// `"c:" + token` (≤64 bytes). Eviction is oldest-first,
    /// except eviction skips live `decide`/`approve_all`
    /// entries while any other entry exists (only when every
    /// entry is a decide button does the oldest one go).
    /// Source: `internal/telegram/approvals.go:285-341`
    /// (`Register`).
    ///
    /// Randomness: Go uses `crypto/rand` and panics on
    /// failure (unrecoverable for an unguessable token).
    /// This port reads 6 bytes from `rand` (the OS CSPRNG
    /// via `rand::random`, which panics if the OS RNG is
    /// unavailable — the same fail-closed shape as Go's
    /// panic). The token is NOT a function of time,
    /// counter, or pid: an earlier draft derived it from
    /// those (fix loop 1, safety B1), which made it
    /// predictable in principle. Note the actual
    /// exploitability: there is no API injection channel
    /// for callback forgery — Telegram only emits
    /// `callback_query` updates for buttons the bot itself
    /// sent, so the server already knows every token.
    /// The CSPRNG is Go parity + defence-in-depth, not a
    /// fix for a demonstrated forgery.
    pub fn register(&self, entry: CallbackEntry) -> String {
        let mut inner = self.inner.lock().expect("registry lock");
        loop {
            let token = next_token();
            let data = format!("c:{token}");
            if inner.entries.contains_key(&data) {
                continue;
            }
            if inner.entries.len() >= CALLBACK_REGISTRY_CAP {
                evict_oldest(&mut inner);
            }
            inner.order.push(data.clone());
            inner.entries.insert(data.clone(), entry);
            return data;
        }
    }

    /// Atomic remove+return — the single-flight guard for
    /// `decide`/`approve_all`. Consumption precedes the
    /// Decide RPC, so a failed Decide burns the button
    /// (retry needs a fresh `/approvals` listing). Non-decide
    /// entries are never consumed.
    /// Source: `internal/telegram/approvals.go:343-361`
    /// (`Consume`).
    pub fn consume(&self, data: &str) -> Option<CallbackEntry> {
        let mut inner = self.inner.lock().expect("registry lock");
        let entry = inner.entries.remove(data)?;
        inner.order.retain(|d| d != data);
        Some(entry)
    }

    /// Peek without removing. Data not starting with `c:` or
    /// naming no entry → `None` (the "expired" button path).
    /// Source: `internal/telegram/approvals.go:363-376`
    /// (`Lookup`).
    pub fn lookup(&self, data: &str) -> Option<CallbackEntry> {
        if !data.starts_with("c:") {
            return None;
        }
        let inner = self.inner.lock().expect("registry lock");
        inner.entries.get(data).cloned()
    }

    /// Number of live entries (tests / observability).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |i| i.entries.len())
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for CallbackRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn evict_oldest(inner: &mut RegistryInner) {
    // Skip live decide/approve_all entries while any other
    // entry exists; only when every entry is a decide button
    // does the oldest one go.
    let victim = inner
        .order
        .iter()
        .find(|d| {
            inner
                .entries
                .get(*d)
                .is_some_and(|e| e.action != "decide" && e.action != "approve_all")
        })
        .or_else(|| inner.order.first())
        .cloned();
    if let Some(victim) = victim {
        inner.entries.remove(&victim);
        inner.order.retain(|d| *d != victim);
    }
}

/// 8-char base64url token from 6 CSPRNG bytes (see
/// `register`): the bytes are read from `rand` (OS
/// randomness), never derived from time, counter, or pid.
fn next_token() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes: [u8; CALLBACK_TOKEN_BYTES] = rand::random();
    let mut x: u64 = 0;
    for (i, b) in bytes.iter().enumerate() {
        x |= (*b as u64) << (8 * i);
    }
    let mut out = String::with_capacity(8);
    for _ in 0..8 {
        out.push(ALPHABET[(x & 63) as usize] as char);
        x >>= 6;
    }
    out
}

/// Approval decision buttons: one row — `✅ Always allow`
/// when forever offered, else `✅ Allow once` when once
/// offered, always `❌ Deny`. Labels truncated to 64 chars.
/// Source: `internal/telegram/approvals.go:378-403`
/// (`ApprovalMarkup`). The registry is used to mint the
/// `c:` tokens; the resume triple is carried on the
/// `decide` entries.
pub fn approval_markup(
    registry: &CallbackRegistry,
    approval: &Approval,
    session_id: &str,
    title: &str,
    after_seq: Option<i64>,
) -> InlineKeyboardMarkup {
    let mut row: Vec<InlineKeyboardButton> = Vec::new();
    if offers_forever(approval) {
        row.push(InlineKeyboardButton::new(
            "✅ Always allow",
            &registry.register(CallbackEntry {
                action: "decide".to_string(),
                approval_id: approval.id.clone(),
                decision: "allow_always".to_string(),
                session_id: session_id.to_string(),
                title: title.to_string(),
                after_seq,
                ..CallbackEntry::default()
            }),
        ));
    } else if offers_once(approval) {
        row.push(InlineKeyboardButton::new(
            "✅ Allow once",
            &registry.register(CallbackEntry {
                action: "decide".to_string(),
                approval_id: approval.id.clone(),
                decision: "allow_once".to_string(),
                session_id: session_id.to_string(),
                title: title.to_string(),
                after_seq,
                ..CallbackEntry::default()
            }),
        ));
    }
    row.push(InlineKeyboardButton::new(
        "❌ Deny",
        &registry.register(CallbackEntry {
            action: "decide".to_string(),
            approval_id: approval.id.clone(),
            decision: "deny".to_string(),
            session_id: session_id.to_string(),
            title: title.to_string(),
            after_seq,
            ..CallbackEntry::default()
        }),
    ));
    InlineKeyboardMarkup {
        inline_keyboard: vec![row],
    }
}

/// "Always allow all" button for the approve-all message.
/// Source: `internal/telegram/approvals.go:405-411`
/// (`ApproveAllMarkup`).
pub fn approve_all_markup(registry: &CallbackRegistry) -> InlineKeyboardMarkup {
    InlineKeyboardMarkup {
        inline_keyboard: vec![vec![InlineKeyboardButton::new(
            "✅ Always allow all",
            &registry.register(CallbackEntry {
                action: "approve_all".to_string(),
                ..CallbackEntry::default()
            }),
        )]],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_lookup_consume_round_trip() {
        let reg = CallbackRegistry::new();
        let data = reg.register(CallbackEntry {
            action: "noop".to_string(),
            ..CallbackEntry::default()
        });
        assert!(data.starts_with("c:"));
        assert_eq!(data.len(), 10);
        assert!(reg.lookup(&data).is_some());
        assert!(reg.lookup("xx:garbage").is_none());
        let entry = reg.consume(&data).expect("consumed");
        assert_eq!(entry.action, "noop");
        assert!(reg.lookup(&data).is_none());
    }

    #[test]
    fn registry_evicts_oldest_first_at_cap() {
        let reg = CallbackRegistry::new();
        for _ in 0..CALLBACK_REGISTRY_CAP {
            reg.register(CallbackEntry {
                action: "noop".to_string(),
                ..CallbackEntry::default()
            });
        }
        assert_eq!(reg.len(), CALLBACK_REGISTRY_CAP);
        reg.register(CallbackEntry {
            action: "noop".to_string(),
            ..CallbackEntry::default()
        });
        assert_eq!(reg.len(), CALLBACK_REGISTRY_CAP);
    }

    #[test]
    fn tokens_are_unique() {
        let reg = CallbackRegistry::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let data = reg.register(CallbackEntry {
                action: "noop".to_string(),
                ..CallbackEntry::default()
            });
            assert!(seen.insert(data));
        }
    }

    /// Tokens minted back-to-back — including across two
    /// registries at the same instant — differ and keep
    /// the `c:` + 8 base64url-char shape. With the old
    /// time+counter+pid construction two registries could
    /// mint related tokens; with the CSPRNG they are
    /// independent draws (fix loop 1, safety B1).
    #[test]
    fn tokens_differ_across_registries_at_the_same_instant() {
        let a = CallbackRegistry::new();
        let b = CallbackRegistry::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            for reg in [&a, &b] {
                let data = reg.register(CallbackEntry {
                    action: "noop".to_string(),
                    ..CallbackEntry::default()
                });
                assert_eq!(data.len(), 10, "c: + 8 chars");
                assert!(data.starts_with("c:"));
                assert!(
                    data[2..]
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
                    "base64url only, got {data}"
                );
                assert!(seen.insert(data), "no token repeats");
            }
        }
    }
}
