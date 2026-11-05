// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Cookie-file parsing (`internal/gateway/cookies.go`
//! `ParseCookies` + `internal/webui/handlers.go`
//! `cookiesFormat`).
//!
//! Three forms are accepted, in dispatch order: a JSON
//! object (`{"cookies": {...}}` or a flat dict), a one-line
//! `a=b; c=d` form containing `hatch_sess=` or `datr=`, or
//! a Netscape cookie jar (tab-separated, name/value in
//! columns 6/7). The returned value is secret material: it
//! must only ever go into a Cookie header, never into an
//! error or a log line — this module returns it, and the
//! login-status handler only ever reports the detected
//! FORM, never the value.
//!
//! JSON cookie entries join in FILE ORDER (Python dict
//! insertion order): the order-preserving decoder keeps
//! first-position/last-wins, matching Go's
//! `orderedCookieObject`. Values render as Python's
//! `f"{k}={v}"`: strings verbatim, numbers as their
//! literal, booleans `True`/`False`, null `None`, and
//! non-scalars as compact JSON preserving key order.

use crate::go_json::encode_go_json;
use castctl_config::jsonvalue::{JsonValue, decode_ordered_json};

/// `gateway.ParseCookies`: parse already-read cookies
/// file contents into the Cookie header value. `path` only
/// names the file in the unparseable error.
pub fn parse_cookies(raw: &str, path: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') {
        // A "{" file that is not JSON, or a JSON value
        // that is not an object, falls through to the
        // line-based forms below, as in Go (a non-dict
        // JSON value is reported as AuthError by the jar
        // parse below).
        if let Ok(value) = decode_ordered_json(trimmed.as_bytes())
            && let JsonValue::Object(obj) = &value
        {
            if let Some(JsonValue::Object(cookies)) = obj.get("cookies") {
                return Ok(join_cookie_pairs(cookies));
            }
            return Ok(join_cookie_pairs(obj));
        }
    }
    if trimmed.contains("hatch_sess=") || trimmed.contains("datr=") {
        for line in trimmed.split('\n') {
            let line = line.trim();
            if !line.is_empty()
                && !line.starts_with('#')
                && line.contains('=')
                && line.contains(';')
            {
                return Ok(line.to_string());
            }
        }
        return Ok(trimmed.split_whitespace().collect::<Vec<_>>().join(" "));
    }
    let mut parts: Vec<String> = Vec::new();
    for line in trimmed.split('\n') {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() >= 7 {
            parts.push(format!("{}={}", cols[5], cols[6]));
        }
    }
    if parts.is_empty() {
        return Err(format!("could not parse cookies file {path}"));
    }
    Ok(parts.join("; "))
}

fn join_cookie_pairs(obj: &castctl_config::jsonvalue::OrderedObject) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (k, v) in obj.iter() {
        parts.push(format!("{k}={}", cookie_value_string(v)));
    }
    parts.join("; ")
}

fn cookie_value_string(v: &JsonValue) -> String {
    match v {
        JsonValue::Str(s) => s.clone(),
        JsonValue::Number(n) => n.clone(),
        JsonValue::Bool(true) => "True".to_string(),
        JsonValue::Bool(false) => "False".to_string(),
        JsonValue::Null => "None".to_string(),
        _ => encode_go_json(v),
    }
}

/// `cookiesFormat` (handlers.go): detect the cookies-file
/// form structurally, the same dispatch `ParseCookies`
/// uses, without returning any value: `"json"` for a
/// leading `{`, `"header"` for the one-line form,
/// `"netscape"` for the jar form. `""` when the content
/// does not parse as any form.
pub fn cookies_format(content: &[u8]) -> &'static str {
    let text = String::from_utf8_lossy(content).into_owned();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return "";
    }
    if parse_cookies(&text, "cookies").is_err() {
        return "";
    }
    if trimmed.starts_with('{') {
        return "json";
    }
    if trimmed.contains("hatch_sess=") || trimmed.contains("datr=") {
        return "header";
    }
    "netscape"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_flat_joins_in_file_order() {
        let out = parse_cookies(r#"{"b": "2", "a": 1, "c": true, "d": null}"#, "x").unwrap();
        assert_eq!(out, "b=2; a=1; c=True; d=None");
    }

    #[test]
    fn json_cookies_key_wins() {
        let out = parse_cookies(r#"{"cookies": {"hatch_sess": "s1"}, "other": 1}"#, "x").unwrap();
        assert_eq!(out, "hatch_sess=s1");
    }

    #[test]
    fn header_form_returns_first_qualifying_line() {
        let raw = "# comment\nhatch_sess=abc; datr=def\n";
        assert_eq!(parse_cookies(raw, "x").unwrap(), "hatch_sess=abc; datr=def");
        assert_eq!(cookies_format(raw.as_bytes()), "header");
    }

    #[test]
    fn netscape_jar_uses_columns_6_7() {
        let raw = "# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tzzz\n";
        assert_eq!(parse_cookies(raw, "x").unwrap(), "hatch_sess=zzz");
        assert_eq!(cookies_format(raw.as_bytes()), "netscape");
    }

    #[test]
    fn empty_and_garbage_parse_to_nothing() {
        assert!(parse_cookies("", "x").is_err());
        assert_eq!(cookies_format(b""), "");
        assert_eq!(cookies_format(b"not a cookie file"), "");
        assert_eq!(cookies_format(b"{}"), "json");
    }

    #[test]
    fn brace_but_not_json_falls_through_to_jar_error() {
        // "{oops" is not JSON and has no cookie lines: the
        // jar parse finds no parts, so it errors.
        assert!(parse_cookies("{oops", "x").is_err());
        assert_eq!(cookies_format(b"{oops"), "");
    }
}
