// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The `threads` command rows.
//!
//! Source: `internal/shared/sessions.go` (`SessionRow`,
//! `SessionRows`, `formatUpdatedAt`, ported from
//! `cli.py:739-748`).

use chrono::TimeZone;

use crate::resources::escape_json_string;
use crate::timefmt::format_updated_at_ms;
use crate::value::{JsonValue, as_list, as_map, bool_ptr_field, int_field, string_ptr_field};

/// One row of the `threads` command output.
/// Source: `internal/shared/sessions.go:12` (`SessionRow`).
/// Field order is the Python dict order: session_id, title,
/// thread, pinned, archived, updated.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionRow {
    /// The session's id, or `None` when absent.
    pub session_id: Option<String>,
    /// The session's title, or `None` when absent.
    pub title: Option<String>,
    /// The session's `is_thread` flag, or `None` when absent.
    pub thread: Option<bool>,
    /// The session's `pinned` flag, or `None` when absent.
    pub pinned: Option<bool>,
    /// The session's `archived` flag, or `None` when absent.
    pub archived: Option<bool>,
    /// The session's `updated_at_ms` rendered as
    /// `"%Y-%m-%d %H:%M"` in `tz` (a missing `updated_at_ms`
    /// renders the local epoch, exactly as Python's
    /// `.get("updated_at_ms", 0)` does).
    pub updated: String,
}

/// Convert a `sessions.list` result into the rows `threads`
/// prints. Archived rows are dropped unless `include_archived`
/// is true.
/// Source: `internal/shared/sessions.go:35` (`SessionRows`).
pub fn session_rows<Tz: TimeZone>(d: &JsonValue, include_archived: bool, tz: &Tz) -> Vec<SessionRow>
where
    Tz::Offset: std::fmt::Display,
{
    let empty: Vec<JsonValue> = Vec::new();
    let sessions = as_map(d)
        .and_then(|m| m.get("sessions"))
        .and_then(as_list)
        .unwrap_or(&empty);
    let mut rows = Vec::with_capacity(sessions.len());
    for s in sessions {
        let Some(m) = as_map(s) else {
            continue;
        };
        let row = SessionRow {
            session_id: string_ptr_field(m, "session_id"),
            title: string_ptr_field(m, "title"),
            thread: bool_ptr_field(m, "is_thread"),
            pinned: bool_ptr_field(m, "pinned"),
            archived: bool_ptr_field(m, "archived"),
            updated: format_updated_at_ms(int_field(m, "updated_at_ms", 0), tz),
        };
        if !include_archived && row.archived == Some(true) {
            continue;
        }
        rows.push(row);
    }
    rows
}

/// Serialize a `SessionRow` exactly as Go's `encoding/json`
/// would with `writeJSON` (indent 2, HTML unescaped):
/// field order `session_id`, `title`, `thread`, `pinned`,
/// `archived`, `updated`; all fields always emitted
/// (`null` when `None`).
/// Source: `internal/shared/sessions.go:12` (struct tags).
pub fn session_row_to_json(row: &SessionRow) -> String {
    fn opt_bool(v: &Option<bool>, out: &mut String) {
        match v {
            Some(b) => out.push_str(if *b { "true" } else { "false" }),
            None => out.push_str("null"),
        }
    }
    fn opt_str(v: &Option<String>, out: &mut String) {
        match v {
            Some(s) => escape_json_string(s, out, false),
            None => out.push_str("null"),
        }
    }
    let mut out = String::from("{");
    out.push_str("\"session_id\":");
    opt_str(&row.session_id, &mut out);
    out.push_str(",\"title\":");
    opt_str(&row.title, &mut out);
    out.push_str(",\"thread\":");
    opt_bool(&row.thread, &mut out);
    out.push_str(",\"pinned\":");
    opt_bool(&row.pinned, &mut out);
    out.push_str(",\"archived\":");
    opt_bool(&row.archived, &mut out);
    out.push_str(",\"updated\":");
    escape_json_string(&row.updated, &mut out, false);
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::JsonValue;
    use chrono::FixedOffset;
    use std::collections::BTreeMap;

    fn ict() -> FixedOffset {
        FixedOffset::east_opt(7 * 3600).unwrap()
    }

    fn utc() -> FixedOffset {
        FixedOffset::east_opt(0).unwrap()
    }

    fn s(v: &str) -> JsonValue {
        JsonValue::Str(v.to_string())
    }

    fn i(v: i64) -> JsonValue {
        JsonValue::Int(v)
    }

    fn b(v: bool) -> JsonValue {
        JsonValue::Bool(v)
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

    fn fixture() -> JsonValue {
        obj(&[(
            "sessions",
            arr(&[
                obj(&[
                    ("session_id", s("s1")),
                    ("title", s("Main")),
                    ("is_thread", b(false)),
                    ("pinned", b(true)),
                    ("archived", b(false)),
                    ("updated_at_ms", i(1792821457000)),
                ]),
                obj(&[
                    ("session_id", s("s2")),
                    ("title", s("Old")),
                    ("is_thread", b(true)),
                    ("pinned", b(false)),
                    ("archived", b(true)),
                    ("updated_at_ms", i(0)),
                ]),
                obj(&[
                    ("session_id", s("s3")),
                    ("title", s("No stamp")),
                    ("is_thread", b(false)),
                    ("pinned", b(false)),
                    ("archived", b(false)),
                ]),
            ]),
        )])
    }

    // Ported from internal/shared/sessions_test.go
    // TestSessionRows.
    #[test]
    fn session_rows_drops_archived_by_default() {
        let rows = session_rows(&fixture(), false, &ict());
        assert_eq!(rows.len(), 2, "archived dropped");
        assert_eq!(
            rows[0],
            SessionRow {
                session_id: Some("s1".to_string()),
                title: Some("Main".to_string()),
                thread: Some(false),
                pinned: Some(true),
                archived: Some(false),
                updated: "2026-10-24 12:57".to_string(),
            }
        );
        // Missing stamp -> the local epoch in the same zone.
        assert_eq!(rows[1].updated, "1970-01-01 07:00");
        let all = session_rows(&fixture(), true, &ict());
        assert_eq!(all.len(), 3, "archived kept with --all");
        assert_eq!(all[1].updated, "1970-01-01 07:00");
    }

    // Ported from internal/shared/sessions_test.go
    // TestSessionRowsNumberForms.
    #[test]
    fn session_rows_number_forms_and_empty() {
        let d = obj(&[(
            "sessions",
            arr(&[obj(&[
                ("session_id", s("s1")),
                ("updated_at_ms", JsonValue::Float(1792821457000.0)),
            ])]),
        )]);
        let rows = session_rows(&d, false, &utc());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].updated, "2026-10-24 05:57");
        assert_eq!(session_rows(&obj(&[]), false, &utc()).len(), 0);
    }

    #[test]
    fn session_row_json_order_matches_go() {
        let row = SessionRow {
            session_id: Some("s1".to_string()),
            title: Some("Main".to_string()),
            thread: Some(false),
            pinned: Some(true),
            archived: Some(false),
            updated: "2026-10-24 12:57".to_string(),
        };
        assert_eq!(
            session_row_to_json(&row),
            r#"{"session_id":"s1","title":"Main","thread":false,"pinned":true,"archived":false,"updated":"2026-10-24 12:57"}"#
        );
        let nulls = SessionRow {
            session_id: None,
            title: None,
            thread: None,
            pinned: None,
            archived: None,
            updated: "1970-01-01 07:00".to_string(),
        };
        assert_eq!(
            session_row_to_json(&nulls),
            r#"{"session_id":null,"title":null,"thread":null,"pinned":null,"archived":null,"updated":"1970-01-01 07:00"}"#
        );
    }
}
