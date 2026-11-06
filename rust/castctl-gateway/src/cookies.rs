// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Cookie-file parsing — port of `internal/gateway/cookies.go`.
//!
//! Three forms are accepted: a JSON object (`{"cookies":
//! {...}}` or a flat dict), a one-line `a=b; c=d` form
//! containing `hatch_sess=` or `datr=`, or a Netscape cookie
//! jar (tab-separated, name/value in columns 6/7). JSON
//! cookie entries are joined in FILE ORDER (Python dict
//! insertion order), deterministically — the order-preserving
//! decoder comes from `castctl-config` (`decode_ordered_json`);
//! the gateway uses the config crate's JSON value model only,
//! never its config loading. Values render as Python's
//! `f"{k}={v}"`: strings verbatim, numbers as their literal,
//! booleans `True`/`False`, null `None`, and non-scalars as
//! compact JSON preserving key order (with Go
//! `json.Marshal` string escaping — `<`, `>`, `&` as
//! `\u003c`/`\u003e`/`\u0026`).
//!
//! The returned value is secret material: it must only ever
//! go into a Cookie header, never into an error or a log line.
//! The error type keeps the two failure kinds distinct
//! because the connector treats them differently: a missing
//! file is a plain I/O error the connector wraps into
//! `no cookies at <path>: ...`, while an unparseable file is
//! already an AuthError that passes through unchanged (Go
//! `connector.go`).

use castctl_config::jsonvalue::{JsonValue, OrderedObject, decode_ordered_json};

/// Failure loading a cookies file. The two kinds are kept
/// distinct (see the module docs); both messages contain
/// substrings the CLI maps to typed `cookies_missing`
/// (`"read cookies file"` / `"no cookies"` / `"could not
/// parse cookies"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieLoadError {
    /// The file could not be read. Message is
    /// `gateway: read cookies file: open <path>:
    /// <strerror>` (a plain error, NOT an AuthError —
    /// the connector wraps it).
    Read(String),
    /// The file could not be parsed. Message is the AuthError
    /// text `could not parse cookies file <path>`.
    Parse(String),
}

impl std::fmt::Display for CookieLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CookieLoadError::Read(m) | CookieLoadError::Parse(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for CookieLoadError {}

/// Reads a cookies file and returns the Cookie header value.
/// A missing file returns [`CookieLoadError::Read`]; an
/// unparseable file returns [`CookieLoadError::Parse`].
pub fn load_cookies(path: &str) -> Result<String, CookieLoadError> {
    match std::fs::read(path) {
        Err(e) => Err(CookieLoadError::Read(format!(
            // Go `cookies.go:38` wraps the `*PathError`:
            // `gateway: read cookies file: open <path>:
            // no such file or directory`.
            "gateway: read cookies file: {}",
            castctl_config::oserr::open_error_text(path, &e)
        ))),
        // Go strings hold arbitrary bytes; a cookies file is
        // text, so invalid UTF-8 is replaced (U+FFFD) rather
        // than failing the read.
        Ok(raw) => parse_cookies(&String::from_utf8_lossy(&raw), path),
    }
}

/// Parses already-read cookies file contents. Exported so
/// tests and wiring code can parse without a file.
pub fn parse_cookies(raw: &str, path: &str) -> Result<String, CookieLoadError> {
    let raw = raw.trim();
    if raw.starts_with('{')
        && let Ok(JsonValue::Object(obj)) = decode_ordered_json(raw.as_bytes())
    {
        if let Some(JsonValue::Object(inner)) = obj.get("cookies") {
            return Ok(join_cookie_pairs(inner));
        }
        return Ok(join_cookie_pairs(&obj));
    }
    // A "{" file that is not JSON, or a JSON value that is
    // not an object, falls through to the line-based forms
    // below, as in Python (JSONDecodeError is caught there;
    // a non-dict JSON value raises AttributeError in
    // Python — see doc.go — and here is reported as
    // AuthError by the jar parse below).
    if raw.contains("hatch_sess=") || raw.contains("datr=") {
        for line in raw.split('\n') {
            let line = line.trim();
            if !line.is_empty()
                && !line.starts_with('#')
                && line.contains('=')
                && line.contains(';')
            {
                return Ok(line.to_string());
            }
        }
        return Ok(raw.split_whitespace().collect::<Vec<_>>().join(" "));
    }
    let mut parts: Vec<String> = Vec::new();
    for line in raw.split('\n') {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() >= 7 {
            parts.push(format!("{}={}", cols[5], cols[6]));
        }
    }
    if parts.is_empty() {
        return Err(CookieLoadError::Parse(format!(
            "could not parse cookies file {path}"
        )));
    }
    Ok(parts.join("; "))
}

/// Joins one ordered object as `k=v; k=v` in key order.
pub fn join_cookie_pairs(obj: &OrderedObject) -> String {
    obj.iter()
        .map(|(k, v)| format!("{k}={}", cookie_value_string(v)))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Renders one cookie value as Python's `f"{v}"`: strings
/// verbatim, numbers as their literal, booleans `True`/
/// `False`, null `None`, non-scalars as compact JSON
/// preserving key order.
pub fn cookie_value_string(v: &JsonValue) -> String {
    match v {
        JsonValue::Str(s) => s.clone(),
        JsonValue::Number(lit) => lit.clone(),
        JsonValue::Bool(true) => "True".to_string(),
        JsonValue::Bool(false) => "False".to_string(),
        JsonValue::Null => "None".to_string(),
        _ => encode_cookie_json_value(v),
    }
}

/// Renders a decoded value as compact JSON, preserving
/// object key order, with Go `json.Marshal` string escaping
/// (`<`, `>`, `&` as `\u003c`/`\u003e`/`\u0026`). Used only
/// for non-scalar cookie values.
pub fn encode_cookie_json_value(v: &JsonValue) -> String {
    match v {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(true) => "true".to_string(),
        JsonValue::Bool(false) => "false".to_string(),
        JsonValue::Str(s) => escape_go_json_string(s),
        JsonValue::Number(lit) => lit.clone(),
        JsonValue::Array(items) => {
            let inner: Vec<String> = items.iter().map(encode_cookie_json_value).collect();
            format!("[{}]", inner.join(","))
        }
        JsonValue::Object(obj) => {
            let inner: Vec<String> = obj
                .iter()
                .map(|(k, val)| {
                    format!(
                        "{}:{}",
                        escape_go_json_string(k),
                        encode_cookie_json_value(val)
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
    }
}

/// Escapes one string exactly as Go's `json.Marshal` does
/// (HTML escaping ON): `"` `\` `\n` `\r` `\t`, `<` `>` `&` as
/// `\u003c` `\u003e` `\u0026`, U+2028/U+2029, other control
/// characters as `\u00XX`. The result includes the quotes.
pub fn escape_go_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
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
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_cookies_missing_file_go_path_error() {
        // B4 regression (red-team C9/C10): Go
        // `cookies.go:38` wraps the `*PathError` —
        // `gateway: read cookies file: open <path>: no
        // such file or directory` — not Rust's capitalized
        // Display with ` (os error 2)`.
        let err = load_cookies("/tmp/castctl-no-such-cookies.txt").unwrap_err();
        assert_eq!(
            err,
            CookieLoadError::Read(
                "gateway: read cookies file: open /tmp/castctl-no-such-cookies.txt: no such file or directory"
                    .to_string()
            )
        );
    }

    #[test]
    fn parse_cookies_order_and_python_scalars() {
        // Port of Go TestParseCookiesFileOrderAndPythonScalars
        // (cookies_test.go).
        let cases: Vec<(&str, &str, &str)> = vec![
            (
                "nested cookies dict preserves file order",
                r#"{"cookies": {"zebra": "1", "alpha": "2", "mid": "3"}}"#,
                "zebra=1; alpha=2; mid=3",
            ),
            (
                "flat dict preserves file order",
                r#"{"datr": "D", "hatch_sess": "S", "other": "O"}"#,
                "datr=D; hatch_sess=S; other=O",
            ),
            (
                "bool renders True and False like Python",
                r#"{"cookies": {"a": true, "b": false}}"#,
                "a=True; b=False",
            ),
            (
                "null renders None like Python",
                r#"{"cookies": {"a": null}}"#,
                "a=None",
            ),
            (
                "numbers render as their literal",
                r#"{"cookies": {"a": 42, "b": 1.5}}"#,
                "a=42; b=1.5",
            ),
            (
                "non-scalar renders compact JSON preserving inner order",
                r#"{"cookies": {"obj": {"y": 1, "x": 2}, "arr": [1, "a", true, null]}}"#,
                r#"obj={"y":1,"x":2}; arr=[1,"a",true,null]"#,
            ),
            (
                "duplicate key keeps first position, last value wins",
                r#"{"cookies": {"a": "1", "b": "2", "a": "3"}}"#,
                "a=3; b=2",
            ),
        ];
        for (name, raw, want) in cases {
            let got = parse_cookies(raw, "cookies.txt").expect(name);
            assert_eq!(got, want, "{name}");
        }
    }

    #[test]
    fn parse_cookies_deterministic() {
        // Port of Go TestParseCookiesDeterministic
        // (cookies_test.go): the join must be identical on
        // every call.
        let raw = r#"{"cookies": {"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": "v5", "k6": "v6"}}"#;
        let want = "k1=v1; k2=v2; k3=v3; k4=v4; k5=v5; k6=v6";
        for i in 0..50 {
            let got = parse_cookies(raw, "cookies.txt").expect("parse");
            assert_eq!(got, want, "iteration {i}");
        }
    }

    #[test]
    fn parse_cookies_line_and_jar_forms() {
        // One-line form: first non-empty non-# line with `=`
        // and `;` wins, verbatim (trimmed).
        let got = parse_cookies("# comment\nhatch_sess=S; datr=D\n", "cookies.txt").unwrap();
        assert_eq!(got, "hatch_sess=S; datr=D");
        // One-line fallback: no qualifying line -> fields joined
        // with single spaces.
        let got = parse_cookies("hatch_sess=S\ndatr=D\n", "cookies.txt").unwrap();
        assert_eq!(got, "hatch_sess=S datr=D");
        // Netscape jar: columns 6/7, comments and short lines
        // skipped.
        let jar = "# Netscape HTTP Cookie File\n\
                   .muse.ai\tTRUE\t/\tFALSE\t0\thatch_sess\tS\n\
                   .muse.ai\tTRUE\t/\tFALSE\t0\tdatr\tD\n\
                   short\tline\n";
        let got = parse_cookies(jar, "cookies.txt").unwrap();
        assert_eq!(got, "hatch_sess=S; datr=D");
        // Unparseable: AuthError text with the path.
        let err = parse_cookies("garbage with no equals", "cookies.txt").unwrap_err();
        assert_eq!(
            err,
            CookieLoadError::Parse("could not parse cookies file cookies.txt".to_string())
        );
        // "{" file that is not JSON falls through to the jar
        // parse and fails the same way.
        let err = parse_cookies("{not json", "cookies.txt").unwrap_err();
        assert_eq!(
            err,
            CookieLoadError::Parse("could not parse cookies file cookies.txt".to_string())
        );
        // Non-object JSON falls through too.
        let err = parse_cookies("[1, 2]", "cookies.txt").unwrap_err();
        assert_eq!(
            err,
            CookieLoadError::Parse("could not parse cookies file cookies.txt".to_string())
        );
        // "cookies" key present but not an object: the outer
        // object is joined.
        let got = parse_cookies(r#"{"cookies": "notobj"}"#, "cookies.txt").unwrap();
        assert_eq!(got, "cookies=notobj");
    }

    #[test]
    fn load_cookies_missing_file_is_read_error() {
        let err = load_cookies("/nonexistent/cookies.txt").unwrap_err();
        match err {
            CookieLoadError::Read(m) => {
                assert!(m.starts_with("gateway: read cookies file: "), "{m}")
            }
            other => panic!("want Read, got {other:?}"),
        }
    }

    #[test]
    fn escape_go_json_string_cases() {
        assert_eq!(
            escape_go_json_string("a<b>&\"c\""),
            r#""a\u003cb\u003e\u0026\"c\"""#
        );
        assert_eq!(
            escape_go_json_string("line\nbreak\ttab"),
            r#""line\nbreak\ttab""#
        );
        assert_eq!(escape_go_json_string("ctrl\u{1}"), r#""ctrl\u0001""#);
    }
}
