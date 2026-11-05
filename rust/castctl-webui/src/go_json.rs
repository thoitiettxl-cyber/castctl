// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Go `encoding/json` compatible rendering of [`JsonValue`].
//!
//! Go's `json.Encoder` (used by `writeEnvelope` / `writeError`)
//! and `json.MarshalIndent` (used by the endpoint-import preview)
//! escape HTML by default (`<` → `\u003c`, `>` → `\u003e`,
//! `&` → `\u0026`, U+2028/2029 escaped), append one trailing
//! `\n` per `Encode` call, and render struct fields in
//! declaration order / map keys sorted. `castctl-config`'s
//! `encode_ordered_json` does NOT escape HTML (it mirrors Go's
//! `SetEscapeHTML(false)` ordered encoder, which is what the
//! config file writer uses), so API responses need this module:
//! without it every `<redacted>` marker would render literally
//! where Go renders `\u003credated\u003e`, and raw bodies would
//! differ on every redacted response.
//!
//! Callers build response objects in Go emission order
//! (declaration order for structs, sorted keys for Go maps —
//! see each handler's note) and render here; this module never
//! reorders keys.

use castctl_config::jsonvalue::JsonValue;

/// Render `value` as compact JSON with Go `encoding/json`
/// HTML escaping on. Keys render in stored order.
pub fn encode_go_json(value: &JsonValue) -> String {
    let mut out = String::new();
    write_value(&mut out, value, false, 0, 0);
    out
}

/// Render `value` as Go `json.MarshalIndent(value, "", "  ")`:
/// 2-space indent, HTML escaping on, empty containers inline.
/// Keys render in stored order.
pub fn encode_go_json_indent(value: &JsonValue) -> String {
    let mut out = String::new();
    write_value(&mut out, value, true, 0, 2);
    out
}

/// Render `value` as compact JSON with Go HTML escaping on,
/// then the one trailing `\n` Go's `Encoder.Encode` appends.
pub fn encode_go_json_line(value: &JsonValue) -> String {
    let mut out = encode_go_json(value);
    out.push('\n');
    out
}

fn write_value(out: &mut String, value: &JsonValue, indent: bool, depth: usize, step: usize) {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Str(s) => write_go_string(out, s),
        JsonValue::Number(lit) => out.push_str(lit),
        JsonValue::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                if indent {
                    out.push('\n');
                    push_pad(out, (depth + 1) * step);
                }
                write_value(out, item, indent, depth + 1, step);
            }
            if indent {
                out.push('\n');
                push_pad(out, depth * step);
            }
            out.push(']');
        }
        JsonValue::Object(obj) => {
            if obj.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, v)) in obj.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                if indent {
                    out.push('\n');
                    push_pad(out, (depth + 1) * step);
                }
                write_go_string(out, k);
                out.push(':');
                if indent {
                    out.push(' ');
                }
                write_value(out, v, indent, depth + 1, step);
            }
            if indent {
                out.push('\n');
                push_pad(out, depth * step);
            }
            out.push('}');
        }
    }
}

fn push_pad(out: &mut String, n: usize) {
    for _ in 0..n {
        out.push(' ');
    }
}

/// Go `encoding/json` string escaping with HTML escaping ON
/// (the `Encoder` / `Marshal` default). Mirrors
/// `castctl-config`'s `encode_go_string` plus the three HTML
/// escapes Go adds when `SetEscapeHTML` is left on.
pub fn write_go_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Sort an object's keys (and every nested object's keys)
/// recursively, in place. Go `json.Marshal` of a
/// `map[string]any` sorts keys at every level; values built
/// from Go maps (the endpoint-import object, whose source is
/// `json.Marshal` of a struct followed by `decodeGeneric`)
/// must be sorted this way before rendering, or the preview
/// and the saved file bytes differ from Go's.
pub fn sort_keys_deep(value: &mut JsonValue) {
    match value {
        JsonValue::Object(obj) => {
            let mut pairs: Vec<(String, JsonValue)> =
                obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = castctl_config::jsonvalue::OrderedObject::new();
            for (k, mut v) in pairs {
                sort_keys_deep(&mut v);
                sorted.set(k, v);
            }
            *obj = sorted;
        }
        JsonValue::Array(items) => {
            for item in items.iter_mut() {
                sort_keys_deep(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use castctl_config::jsonvalue::{JsonValue, OrderedObject};

    fn obj(pairs: &[(&str, JsonValue)]) -> JsonValue {
        let mut o = OrderedObject::new();
        for (k, v) in pairs {
            o.set((*k).to_string(), v.clone());
        }
        JsonValue::Object(o)
    }

    #[test]
    fn html_escaping_matches_go_encoder() {
        // Go: json.NewEncoder(w).Encode(map[string]any{"error":
        // map[string]string{"type":"x","message":"a<b>&c"}})
        // renders {"error":{"message":"a\u003cb\u003e\u0026c","type":"x"}}
        // (inner map keys sorted, HTML escaped). Callers build
        // response objects in Go emission order; the encoder
        // preserves stored order and never re-sorts.
        let v = obj(&[(
            "error",
            obj(&[
                ("message", JsonValue::Str("a<b>&c".to_string())),
                ("type", JsonValue::Str("x".to_string())),
            ]),
        )]);
        assert_eq!(
            encode_go_json_line(&v),
            "{\"error\":{\"message\":\"a\\u003cb\\u003e\\u0026c\",\"type\":\"x\"}}\n"
        );
    }

    #[test]
    fn fail_before_html_escaping() {
        // If the HTML escapes are dropped, a <redacted> marker
        // renders literally: this test pins Go's rendering.
        let v = JsonValue::Str("<redacted>".to_string());
        assert_eq!(encode_go_json(&v), "\"\\u003credated\\u003e\"");
    }

    #[test]
    fn indent_matches_go_marshal_indent() {
        let v = obj(&[
            ("b", JsonValue::Number("1".to_string())),
            ("a", JsonValue::Array(vec![])),
        ]);
        assert_eq!(encode_go_json_indent(&v), "{\n  \"b\": 1,\n  \"a\": []\n}");
    }
}
