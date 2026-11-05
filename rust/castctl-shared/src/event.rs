// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! One formatted history event.
//!
//! Source: `internal/shared/event.go` (`EventRow`, `FmtEvent`,
//! `CleanText`, ported from `cli.py:757-763` and
//! `wait.py:42,209`).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::resources::escape_json_string;
use crate::value::{
    JsonObject, JsonValue, first_string, first_string_ptr, get_or_null, int_ptr_field, payload_of,
};

fn widget_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Go: `\[\[hatch_widget:[^\]]+\]\]` (event.go:28).
        // The marker body must contain at least one non-']'
        // character: an empty [[hatch_widget:]] is NOT a marker.
        Regex::new(r"\[\[hatch_widget:[^\]]+\]\]").expect("static widget regex is valid")
    })
}

/// Strip `[[hatch_widget:...]]` markers from text and trim
/// surrounding whitespace. A nil-like empty input yields `""`.
/// Source: `internal/shared/event.go:31` (`CleanText`).
pub fn clean_text(text: &str) -> String {
    widget_re().replace_all(text, "").trim().to_string()
}

/// One formatted history event.
/// Source: `internal/shared/event.go:31` (`EventRow`).
/// Field order is the Python dict order: seq, role,
/// message_id, text.
#[derive(Debug, Clone, PartialEq)]
pub struct EventRow {
    /// The event's seq, or `None` when the event carries no
    /// numeric seq (Python emits null there).
    pub seq: Option<i64>,
    /// The payload role, falling back to the event name.
    pub role: Option<String>,
    /// The payload message_id, falling back to the event's
    /// message_id.
    pub message_id: Option<String>,
    /// The payload display_text, falling back to content,
    /// or `""` when both are empty or absent.
    pub text: String,
}

/// Format one history event. Role and message_id use Python's
/// `or` fallback: an empty string falls through to the next
/// source, and a non-string source is treated as absent.
/// Source: `internal/shared/event.go:50` (`FmtEvent`).
pub fn fmt_event(ev: &JsonValue) -> EventRow {
    let empty: JsonObject = BTreeMap::new();
    let ev_map = match ev {
        JsonValue::Object(m) => m,
        _ => &empty,
    };
    let p = payload_of(ev_map);
    EventRow {
        seq: int_ptr_field(ev_map, "seq"),
        role: first_string_ptr(&[get_or_null(p, "role"), get_or_null(ev_map, "event_name")]),
        message_id: first_string_ptr(&[
            get_or_null(p, "message_id"),
            get_or_null(ev_map, "message_id"),
        ]),
        text: first_string(&[get_or_null(p, "display_text"), get_or_null(p, "content")]),
    }
}

/// Serialize an `EventRow` exactly as Go's `encoding/json`
/// would with `writeJSON` (indent 2, HTML unescaped):
/// field order `seq`, `role`, `message_id`, `text`; all
/// fields always emitted (`null` when `None`).
/// Source: `internal/shared/event.go:31` (struct tags).
pub fn event_row_to_json(row: &EventRow) -> String {
    fn opt_str(v: &Option<String>, out: &mut String) {
        match v {
            Some(s) => escape_json_string(s, out, false),
            None => out.push_str("null"),
        }
    }
    let mut out = String::from("{");
    out.push_str("\"seq\":");
    match row.seq {
        Some(n) => out.push_str(&n.to_string()),
        None => out.push_str("null"),
    }
    out.push_str(",\"role\":");
    opt_str(&row.role, &mut out);
    out.push_str(",\"message_id\":");
    opt_str(&row.message_id, &mut out);
    out.push_str(",\"text\":");
    escape_json_string(&row.text, &mut out, false);
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

    // Ported from internal/shared/event_test.go TestCleanText.
    #[test]
    fn clean_text_strips_widget_markers() {
        for (name, input, want) in [
            ("plain", "hello", "hello"),
            ("empty", "", ""),
            ("widget removed", "a [[hatch_widget:foo]] b", "a  b"),
            (
                "widget at ends trimmed",
                "[[hatch_widget:x]] hi [[hatch_widget:y]]",
                "hi",
            ),
            ("widget with spaces inside", "[[hatch_widget:pick one]]", ""),
            (
                "empty widget body is not a marker",
                "[[hatch_widget:]]",
                "[[hatch_widget:]]",
            ),
            (
                "other brackets kept",
                "[[not a widget]]",
                "[[not a widget]]",
            ),
            ("surrounding whitespace trimmed", "  hi\n", "hi"),
            (
                "multiple widgets",
                "[[hatch_widget:1]]x[[hatch_widget:2]]",
                "x",
            ),
        ] {
            assert_eq!(clean_text(input), want, "{name}");
        }
    }

    // Ported from internal/shared/event_test.go TestFmtEvent.
    #[test]
    fn fmt_event_fallbacks_match_python_or() {
        let cases: Vec<(&str, JsonValue, EventRow)> = vec![
            (
                "display text and payload ids",
                obj(&[
                    ("seq", i(7)),
                    (
                        "payload",
                        obj(&[
                            ("role", s("message.assistant")),
                            ("message_id", s("m1")),
                            ("display_text", s("hi")),
                        ]),
                    ),
                ]),
                EventRow {
                    seq: Some(7),
                    role: Some("message.assistant".to_string()),
                    message_id: Some("m1".to_string()),
                    text: "hi".to_string(),
                },
            ),
            (
                "content fallback and event name role",
                obj(&[
                    ("seq", i(3)),
                    ("event_name", s("message.user")),
                    (
                        "payload",
                        obj(&[("content", s("yo")), ("message_id", s("u9"))]),
                    ),
                ]),
                EventRow {
                    seq: Some(3),
                    role: Some("message.user".to_string()),
                    message_id: Some("u9".to_string()),
                    text: "yo".to_string(),
                },
            ),
            (
                "event message id fallback",
                obj(&[
                    ("seq", i(1)),
                    ("message_id", s("e5")),
                    ("payload", obj(&[])),
                ]),
                EventRow {
                    seq: Some(1),
                    role: None,
                    message_id: Some("e5".to_string()),
                    text: String::new(),
                },
            ),
            (
                "empty display text falls through to content",
                obj(&[(
                    "payload",
                    obj(&[("display_text", s("")), ("content", s("c"))]),
                )]),
                EventRow {
                    seq: None,
                    role: None,
                    message_id: None,
                    text: "c".to_string(),
                },
            ),
            (
                "non-object payload treated as empty",
                obj(&[("seq", i(2)), ("payload", s("junk"))]),
                EventRow {
                    seq: Some(2),
                    role: None,
                    message_id: None,
                    text: String::new(),
                },
            ),
            (
                "json.Number seq",
                obj(&[
                    ("seq", JsonValue::Float("42.0".to_string())),
                    ("payload", obj(&[("display_text", s("x"))])),
                ]),
                EventRow {
                    seq: Some(42),
                    role: None,
                    message_id: None,
                    text: "x".to_string(),
                },
            ),
        ];
        for (name, ev, want) in cases {
            assert_eq!(fmt_event(&ev), want, "{name}");
        }
    }

    // Ported from internal/shared/event_test.go
    // TestFmtEventJSONOrder.
    #[test]
    fn event_row_json_order_matches_go() {
        let row = fmt_event(&obj(&[
            ("seq", i(1)),
            (
                "payload",
                obj(&[
                    ("role", s("message.assistant")),
                    ("message_id", s("m1")),
                    ("display_text", s("hi")),
                ]),
            ),
        ]));
        assert_eq!(
            event_row_to_json(&row),
            r#"{"seq":1,"role":"message.assistant","message_id":"m1","text":"hi"}"#
        );
    }
}
