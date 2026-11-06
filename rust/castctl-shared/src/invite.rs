// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Invite summary shaping.
//!
//! Go source: `internal/shared/invite.go:39`
//! (`InviteSummary`, `SummarizeInvite`).

use crate::value::{JsonValue, as_map, bool_ptr_field, int_ptr_field, string_ptr_field};

/// The reward block of an invite summary: the reward's
/// title and body, or absent entirely when the server
/// carries no reward object.
/// Source: `internal/shared/invite.go:10` (`InviteReward`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InviteReward {
    /// Reward title, when present and a string.
    pub title: Option<String>,
    /// Reward body, when present and a string.
    pub body: Option<String>,
}

/// The invite summary, ported from `cli.py:659-681`
/// (`summarize_invite`). Field order is the Python dict
/// order: state, code, link, max_uses, used,
/// uses_remaining, reward, offer, share_text,
/// redeemed_someone_elses_code. `None` fields render as
/// JSON null.
/// Source: `internal/shared/invite.go:19`
/// (`InviteSummary`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InviteSummary {
    /// `invite_state`.
    pub state: Option<String>,
    /// `code`.
    pub code: Option<String>,
    /// `invite_link`.
    pub link: Option<String>,
    /// `max_uses`.
    pub max_uses: Option<i64>,
    /// `use_count`.
    pub used: Option<i64>,
    /// Server `uses_remaining`, else `max(max_uses -
    /// use_count, 0)` when both inputs are present.
    pub uses_remaining: Option<i64>,
    /// `reward` object `{title, body}`, or `None` when the
    /// server carries no reward object.
    pub reward: Option<InviteReward>,
    /// `subtitle`.
    pub offer: Option<String>,
    /// `share_text`.
    pub share_text: Option<String>,
    /// `has_redeemed_invite_code`.
    pub redeemed_someone_elses_code: Option<bool>,
}

/// Extract the invite fields that matter from a GET
/// `/api/hatch/invite` result, ported verbatim from
/// `cli.py:659-681` (`summarize_invite`).
/// `uses_remaining` is computed as `max(max_uses -
/// use_count, 0)` only when the server left it null and
/// both `max_uses` and `use_count` are present; a
/// server-provided value (including 0) always wins. A
/// non-object reward yields a nil reward, exactly as
/// Python's `isinstance` check does.
/// Source: `internal/shared/invite.go:39`
/// (`SummarizeInvite`).
#[must_use]
pub fn summarize_invite(d: &JsonValue) -> InviteSummary {
    let Some(m) = as_map(d) else {
        return InviteSummary::default();
    };
    let reward = match m.get("reward") {
        Some(JsonValue::Object(rm)) => Some(InviteReward {
            title: string_ptr_field(rm, "title"),
            body: string_ptr_field(rm, "body"),
        }),
        _ => None,
    };
    let mut remaining = int_ptr_field(m, "uses_remaining");
    if remaining.is_none() {
        let max_uses = int_ptr_field(m, "max_uses");
        let used = int_ptr_field(m, "use_count");
        if let (Some(max), Some(used)) = (max_uses, used) {
            remaining = Some((max - used).max(0));
        }
    }
    InviteSummary {
        state: string_ptr_field(m, "invite_state"),
        code: string_ptr_field(m, "code"),
        link: string_ptr_field(m, "invite_link"),
        max_uses: int_ptr_field(m, "max_uses"),
        used: int_ptr_field(m, "use_count"),
        uses_remaining: remaining,
        reward,
        offer: string_ptr_field(m, "subtitle"),
        share_text: string_ptr_field(m, "share_text"),
        redeemed_someone_elses_code: bool_ptr_field(m, "has_redeemed_invite_code"),
    }
}

/// Render an `InviteSummary` as compact JSON in Go struct
/// field order (NOT sorted: `writeJSON` on a Go struct
/// keeps declaration order). `None` renders as `null`.
#[must_use]
pub fn invite_summary_to_json(s: &InviteSummary) -> String {
    let mut out = String::from("{");
    out.push_str("\"state\":");
    out.push_str(&opt_string_json(&s.state));
    out.push_str(",\"code\":");
    out.push_str(&opt_string_json(&s.code));
    out.push_str(",\"link\":");
    out.push_str(&opt_string_json(&s.link));
    out.push_str(",\"max_uses\":");
    out.push_str(&opt_int_json(&s.max_uses));
    out.push_str(",\"used\":");
    out.push_str(&opt_int_json(&s.used));
    out.push_str(",\"uses_remaining\":");
    out.push_str(&opt_int_json(&s.uses_remaining));
    out.push_str(",\"reward\":");
    match &s.reward {
        Some(r) => {
            out.push_str("{\"title\":");
            out.push_str(&opt_string_json(&r.title));
            out.push_str(",\"body\":");
            out.push_str(&opt_string_json(&r.body));
            out.push('}');
        }
        None => out.push_str("null"),
    }
    out.push_str(",\"offer\":");
    out.push_str(&opt_string_json(&s.offer));
    out.push_str(",\"share_text\":");
    out.push_str(&opt_string_json(&s.share_text));
    out.push_str(",\"redeemed_someone_elses_code\":");
    out.push_str(&opt_bool_json(&s.redeemed_someone_elses_code));
    out.push('}');
    out
}

fn opt_string_json(v: &Option<String>) -> String {
    match v {
        Some(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string()),
        None => "null".to_string(),
    }
}

fn opt_int_json(v: &Option<i64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

fn opt_bool_json(v: &Option<bool>) -> String {
    match v {
        Some(b) => b.to_string(),
        None => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::from_serde;

    fn summarize(json: serde_json::Value) -> InviteSummary {
        summarize_invite(&from_serde(&json))
    }

    #[test]
    fn summarize_invite_computes_remaining() {
        // Go TestUsageInviteRedeem fixture shape: max 5,
        // used 2 -> remaining 3 (computed).
        let s = summarize(serde_json::json!({
            "invite_state": "active",
            "code": "ABCDEF",
            "invite_link": "https://muse.ai/i/ABCDEF",
            "max_uses": 5,
            "use_count": 2,
            "reward": {"title": "Pro", "body": "1 month"},
            "subtitle": "Join!"
        }));
        assert_eq!(s.state.as_deref(), Some("active"));
        assert_eq!(s.code.as_deref(), Some("ABCDEF"));
        assert_eq!(s.uses_remaining, Some(3));
        assert_eq!(s.max_uses, Some(5));
        assert_eq!(s.used, Some(2));
        assert_eq!(
            s.reward,
            Some(InviteReward {
                title: Some("Pro".to_string()),
                body: Some("1 month".to_string()),
            })
        );
        assert_eq!(s.offer.as_deref(), Some("Join!"));
        assert_eq!(s.share_text, None);
        assert_eq!(s.redeemed_someone_elses_code, None);
        // Server-provided remaining (including 0) wins.
        let s = summarize(serde_json::json!({
            "max_uses": 5, "use_count": 2, "uses_remaining": 0
        }));
        assert_eq!(s.uses_remaining, Some(0));
        // Missing inputs -> no remaining.
        let s = summarize(serde_json::json!({"max_uses": 5}));
        assert_eq!(s.uses_remaining, None);
        // Non-object reward -> None; non-object input -> empty.
        let s = summarize(serde_json::json!({"reward": "Pro"}));
        assert_eq!(s.reward, None);
        assert_eq!(summarize_invite(&JsonValue::Null), InviteSummary::default());
    }

    #[test]
    fn invite_summary_json_key_order() {
        let s = summarize(serde_json::json!({
            "invite_state": "active",
            "code": "ABCDEF",
            "invite_link": "https://muse.ai/i/ABCDEF",
            "max_uses": 5,
            "use_count": 2,
            "reward": {"title": "Pro", "body": "1 month"},
            "subtitle": "Join!",
            "share_text": "share",
            "has_redeemed_invite_code": true
        }));
        assert_eq!(
            invite_summary_to_json(&s),
            "{\"state\":\"active\",\"code\":\"ABCDEF\",\"link\":\"https://muse.ai/i/ABCDEF\",\"max_uses\":5,\"used\":2,\"uses_remaining\":3,\"reward\":{\"title\":\"Pro\",\"body\":\"1 month\"},\"offer\":\"Join!\",\"share_text\":\"share\",\"redeemed_someone_elses_code\":true}"
        );
        assert_eq!(
            invite_summary_to_json(&InviteSummary::default()),
            "{\"state\":null,\"code\":null,\"link\":null,\"max_uses\":null,\"used\":null,\"uses_remaining\":null,\"reward\":null,\"offer\":null,\"share_text\":null,\"redeemed_someone_elses_code\":null}"
        );
    }
}
