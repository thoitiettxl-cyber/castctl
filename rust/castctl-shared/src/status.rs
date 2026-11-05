// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The `status` command output shape.
//!
//! Source: `internal/shared/status.go` (`StatusSummary`,
//! `SummarizeStatus`, ported from `cli.py:529-536`).

use crate::resources::{escape_json_string, write_json_value};
use crate::value::{JsonValue, as_list, as_map};

/// The `status` command output shape.
/// Source: `internal/shared/status.go:14` (`StatusSummary`).
/// Field order is the Python dict order: vm_id, sessions,
/// unread, identity.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusSummary {
    /// The gateway's VM id.
    pub vm_id: String,
    /// Number of sessions in the `sessions.list` result (0
    /// when the result carries no sessions list).
    pub sessions: usize,
    /// The `chat.unread_count` result, kept verbatim.
    pub unread: JsonValue,
    /// The `identity` result, kept verbatim.
    pub identity: JsonValue,
}

/// Build a `StatusSummary` from the three values `status_data`
/// reads: sessions counts the `"sessions"` list of the
/// `sessions.list` result, unread and identity pass through
/// untouched.
/// Source: `internal/shared/status.go:30` (`SummarizeStatus`).
pub fn summarize_status(
    vm_id: &str,
    sessions_result: &JsonValue,
    unread: JsonValue,
    identity: JsonValue,
) -> StatusSummary {
    let count = as_map(sessions_result)
        .and_then(|m| m.get("sessions"))
        .and_then(as_list)
        .map_or(0, |l| l.len());
    StatusSummary {
        vm_id: vm_id.to_string(),
        sessions: count,
        unread,
        identity,
    }
}

/// Serialize a `StatusSummary` exactly as Go's `encoding/json`
/// would with `writeJSON` (indent 2, HTML unescaped):
/// field order `vm_id`, `sessions`, `unread`, `identity`;
/// all fields always emitted.
/// Source: `internal/shared/status.go:14` (struct tags).
pub fn status_summary_to_json(s: &StatusSummary) -> String {
    let mut out = String::from("{");
    out.push_str("\"vm_id\":");
    escape_json_string(&s.vm_id, &mut out, false);
    out.push_str(",\"sessions\":");
    out.push_str(&s.sessions.to_string());
    out.push_str(",\"unread\":");
    write_json_value(&s.unread, &mut out, false);
    out.push_str(",\"identity\":");
    write_json_value(&s.identity, &mut out, false);
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::JsonValue;
    use std::collections::BTreeMap;

    fn s(v: &str) -> JsonValue {
        JsonValue::Str(v.to_string())
    }

    fn i(v: i64) -> JsonValue {
        JsonValue::Int(v)
    }

    fn obj(pairs: &[(&str, JsonValue)]) -> JsonValue {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), v.clone());
        }
        JsonValue::Object(m)
    }

    fn arr(items: &[JsonValue]) -> JsonValue {
        JsonValue::Array(items.to_vec())
    }

    // Ported from internal/shared/feed_test.go
    // TestSummarizeStatus.
    #[test]
    fn summarize_status_counts_sessions_and_passes_through() {
        let sessions_result = obj(&[("sessions", arr(&[obj(&[]), obj(&[])]))]);
        let got = summarize_status("vm-1", &sessions_result, i(3), obj(&[("name", s("Boss"))]));
        assert_eq!(got.vm_id, "vm-1");
        assert_eq!(got.sessions, 2);
        assert_eq!(got.unread, i(3));
        assert_eq!(got.identity, obj(&[("name", s("Boss"))]));

        let empty = summarize_status("vm-1", &obj(&[]), JsonValue::Null, JsonValue::Null);
        assert_eq!(empty.sessions, 0);
        assert_eq!(empty.unread, JsonValue::Null);
        assert_eq!(empty.identity, JsonValue::Null);
    }

    #[test]
    fn status_summary_json_order_matches_go() {
        let summary = StatusSummary {
            vm_id: "vm-1".to_string(),
            sessions: 2,
            unread: i(3),
            identity: obj(&[("name", s("Boss"))]),
        };
        assert_eq!(
            status_summary_to_json(&summary),
            r#"{"vm_id":"vm-1","sessions":2,"unread":3,"identity":{"name":"Boss"}}"#
        );
        // Nulls are emitted, never omitted (no omitempty).
        let nulls = StatusSummary {
            vm_id: "vm-1".to_string(),
            sessions: 0,
            unread: JsonValue::Null,
            identity: JsonValue::Null,
        };
        assert_eq!(
            status_summary_to_json(&nulls),
            r#"{"vm_id":"vm-1","sessions":0,"unread":null,"identity":null}"#
        );
    }
}
