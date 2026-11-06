// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Go `encoding/json` Marshal-compatible JSON encoding.
//!
//! Go escapes `<`, `>`, `&` (and U+2028/U+2029) in every JSON
//! string it marshals — `json.Marshal` has HTML escaping ON by
//! default — while `serde_json` emits them raw. The Rust port
//! used `serde_json::to_vec` for request bodies, so any body
//! carrying user text with those characters differed byte-for-byte
//! from Go (M7b PR-2 fix loop 2, B1: the `chat.stream` body for
//! `a"b <c> d&e` was sent raw where Go sends
//! `a"b \u003cc\u003e d\u0026e`; the same gap affected every
//! unary body, e.g. `fs.list {"path":"a<b"}`).
//!
//! This module is the single home of the Go escaping rules: the
//! quoted-string escapers (moved here verbatim from
//! `castctl-cli/src/network.rs`, which re-exports them) and
//! [`to_go_json_bytes`], the recursive `serde_json::Value`
//! serialiser the gateway uses for request bodies. Object keys
//! sort (Go marshals maps sorted); numbers keep their literal
//! text (the workspace `arbitrary_precision` feature — a `Json`
//! float is never produced by callers, see
//! `castctl-gateway/src/gateway.rs` `Body`).

use serde_json::Value;

/// Escape one string's CONTENT (no surrounding quotes), Go
/// `json.Marshal` form: `"`/`\`/`\b`/`\f`/`\n`/`\r`/`\t` short
/// escapes, `<`/`>`/`&` as `\u003c`/`\u003e`/`\u0026` iff `html`,
/// U+2028/U+2029 escaped either way (Go escapes them even with
/// HTML escaping off), other control chars as `\u00XX`
/// (lowercase hex, as Go emits).
fn escape_inner(s: &str, html: bool, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x0C' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' if html => out.push_str("\\u003c"),
            '>' if html => out.push_str("\\u003e"),
            '&' if html => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

/// Go `encoding/json` string escaping with HTML escaping ON
/// (the `json.Marshal` default used by `classifyError`'s typed
/// branch and by request-body encoding): `"`/`\`/`\b`/`\f`/`\n`/
/// `\r`/`\t` short escapes, `<`/`>`/`&` as `\u003c`/`\u003e`/
/// `\u0026`, U+2028/U+2029 escaped, other control chars as
/// `\u00XX`.
pub fn escape_go_marshal_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    escape_inner(s, true, &mut out);
    out.push('"');
    out
}

/// Go `encoding/json` string escaping for CLI stdout JSON
/// (`writeJSON`, `commands.go:411`: `SetEscapeHTML(false)`):
/// identical to [`escape_go_marshal_string`] except `<` /
/// `>` / `&` are emitted raw. U+2028/U+2029 stay escaped
/// (Go escapes them even with HTML escaping off) and the
/// other control characters keep their `\u00XX` form
/// (`\b`/`\f` are short escapes, as in the marshal form).
/// Use this for every hand-built stdout JSON fragment
/// (approval rows, auto-approve status, download rows);
/// wire request bodies and typed auth JSON keep
/// [`escape_go_marshal_string`] (Go `json.Marshal` there).
pub fn escape_stdout_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    escape_inner(s, false, &mut out);
    out.push('"');
    out
}

/// Serialise a `serde_json::Value` exactly as Go `json.Marshal`
/// would: object keys sorted, HTML escaping ON, U+2028/U+2029
/// escaped, numbers emitted as their literal text (with the
/// workspace `arbitrary_precision` feature this is the input
/// literal, character-for-character).
pub fn to_go_json_bytes(value: &Value) -> Vec<u8> {
    let mut out = String::new();
    write_value(value, &mut out);
    out.into_bytes()
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push('"');
            escape_inner(s, true, out);
            out.push('"');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(obj) => {
            // Keys sort: Go marshals maps sorted. Sort
            // explicitly instead of relying on serde_json::Map's
            // BTreeMap order (no preserve_order feature).
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                escape_inner(k, true, out);
                out.push('"');
                out.push(':');
                write_value(&obj[*k], out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn marshal_string_escapes_html_and_controls() {
        assert_eq!(
            escape_go_marshal_string("a\"b <c> d&e"),
            "\"a\\\"b \\u003cc\\u003e d\\u0026e\""
        );
        assert_eq!(
            escape_go_marshal_string("a\u{2028}b\u{2029}c"),
            "\"a\\u2028b\\u2029c\""
        );
        assert_eq!(
            escape_go_marshal_string("a\x08b\x0Cc\nd\re\tf\x01g"),
            "\"a\\bb\\fc\\nd\\re\\tf\\u0001g\""
        );
        assert_eq!(escape_go_marshal_string("ünïcode ✓"), "\"ünïcode ✓\"");
    }

    #[test]
    fn stdout_string_keeps_html_raw_but_escapes_u2028() {
        assert_eq!(
            escape_stdout_string("a<b & c\u{2028}d"),
            "\"a<b & c\\u2028d\""
        );
    }

    #[test]
    fn to_go_json_bytes_matches_go_for_stream_body() {
        let v = json!({"capabilities": {}, "items": [{"text": "a\"b <c> d&e ünïcode ✓", "type": "text"}], "node_id": "wait-driver"});
        assert_eq!(
            String::from_utf8(to_go_json_bytes(&v)).unwrap(),
            "{\"capabilities\":{},\"items\":[{\"text\":\"a\\\"b \\u003cc\\u003e d\\u0026e ünïcode ✓\",\"type\":\"text\"}],\"node_id\":\"wait-driver\"}"
        );
    }

    #[test]
    fn to_go_json_bytes_sorts_keys_and_keeps_number_literals() {
        // Parse from a JSON literal, not json!: the macro coerces
        // 1e3 to f64 1000.0 at construction, so only from_str (with
        // the workspace arbitrary_precision feature) preserves the
        // input literal character-for-character.
        let v: Value =
            serde_json::from_str(r#"{"b": 1, "a": {"z": [true, null, 1.0, 1e3, "x<y"]}}"#).unwrap();
        assert_eq!(
            String::from_utf8(to_go_json_bytes(&v)).unwrap(),
            "{\"a\":{\"z\":[true,null,1.0,1e3,\"x\\u003cy\"]},\"b\":1}"
        );
    }

    #[test]
    fn to_go_json_bytes_escapes_u2028_u2029() {
        let v = json!({"text": "a\u{2028}b\u{2029}c"});
        assert_eq!(
            String::from_utf8(to_go_json_bytes(&v)).unwrap(),
            "{\"text\":\"a\\u2028b\\u2029c\"}"
        );
    }
}
