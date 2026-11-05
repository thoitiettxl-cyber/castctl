// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Set-Cookie header parsing — the `http.ParseSetCookie`
//! analogue for the cheap chain (`internal/gateway/
//! authcookies.go: `ParseSetCookieHeader` parses every
//! Set-Cookie value with `http.ParseSetCookie`; unparseable
//! values are skipped and counted).
//!
//! Grammar (Go `net/http` `parseSetCookie`, stdlib):
//! `name=value; attr=value; ...`. The name is an RFC 7230
//! token; the value is a quoted string or a run of value
//! bytes (`0x20 < b < 0x7f`, `b != ';'`). Attributes are
//! case-insensitive; `Domain`, `Path`, `Expires` (HTTP date),
//! `Max-Age` (integer; an invalid value is ignored, exactly
//! like Go), `Secure`, `HttpOnly` are modeled; `SameSite`,
//! `Partitioned` and unknown attributes are ignored (the
//! jar format has no columns for them — `jar.go:26-37`).

use chrono::{DateTime, TimeZone, Utc};

/// One parsed Set-Cookie value (the `http.Cookie` fields the
/// keeper uses). `max_age` is `None` when the attribute is
/// absent; Go cannot distinguish absent from `Max-Age=0`
/// (both read `MaxAge 0`), so [`crate::jar::
/// effective_set_cookie`] treats `None` and `Some(0)` the
/// same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value. SECRET MATERIAL: never logged.
    pub value: String,
    /// Domain attribute, if present (as given, no dot added
    /// here — `effective_set_cookie` adds it).
    pub domain: Option<String>,
    /// Path attribute, if present.
    pub path: Option<String>,
    /// Expiry as an epoch, if the `Expires` attribute parsed.
    pub expires: Option<i64>,
    /// Max-Age in seconds, if the attribute parsed as an
    /// integer.
    pub max_age: Option<i64>,
    /// Secure attribute present.
    pub secure: bool,
    /// HttpOnly attribute present.
    pub http_only: bool,
}

fn is_token_char(b: u8) -> bool {
    // RFC 7230 tchar.
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_value_byte(b: u8) -> bool {
    0x20 < b && b < 0x7f && b != b';'
}

/// Parse one Set-Cookie header value. Returns `None` when
/// the value is unparseable (the caller counts it as
/// skipped). The input must be one header value, not a
/// comma-joined pair.
pub fn parse_set_cookie(header: &str) -> Option<ParsedCookie> {
    let bytes = header.as_bytes();
    let mut parts = split_semicolons(bytes);
    if parts.is_empty() {
        return None;
    }
    let first = parts.remove(0);
    let first = trim_ascii_spaces(first);
    let eq = first.iter().position(|&b| b == b'=')?;
    let name = &first[..eq];
    if name.is_empty() || !name.iter().all(|&b| is_token_char(b)) {
        return None;
    }
    let raw_value = trim_ascii_spaces(&first[eq + 1..]);
    let value = parse_cookie_value(raw_value)?;
    let mut out = ParsedCookie {
        name: String::from_utf8_lossy(name).into_owned(),
        value,
        domain: None,
        path: None,
        expires: None,
        max_age: None,
        secure: false,
        http_only: false,
    };
    for attr in parts {
        let attr = trim_ascii_spaces(attr);
        if attr.is_empty() {
            continue;
        }
        let (key, val) = match attr.iter().position(|&b| b == b'=') {
            Some(i) => (&attr[..i], Some(trim_ascii_spaces(&attr[i + 1..]))),
            None => (attr, None),
        };
        let key_lc = String::from_utf8_lossy(key).to_ascii_lowercase();
        match key_lc.as_str() {
            "domain" => {
                let v = val?;
                out.domain = Some(String::from_utf8_lossy(v).into_owned());
            }
            "path" => {
                let v = val?;
                out.path = Some(String::from_utf8_lossy(v).into_owned());
            }
            "expires" => {
                let v = val?;
                let s = String::from_utf8_lossy(v);
                out.expires = parse_http_date(&s);
            }
            "max-age" => {
                let v = val?;
                let s = String::from_utf8_lossy(v);
                if let Ok(n) = s.trim().parse::<i64>() {
                    out.max_age = Some(n);
                }
                // Invalid Max-Age is ignored (Go does the
                // same: only a successful Atoi sets MaxAge).
            }
            "secure" => out.secure = true,
            "httponly" => out.http_only = true,
            _ => {}
        }
    }
    Some(out)
}

/// Split on `;`, respecting a quoted value that contains
/// `;` (Go's `parseSetCookie` splits the same way: the
/// value parser consumes the quoted string first).
fn split_semicolons(input: &[u8]) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'"' if !in_quotes => in_quotes = true,
            b'"' if in_quotes => {
                // A quote closes unless escaped.
                if i == 0 || input[i - 1] != b'\\' {
                    in_quotes = false;
                }
            }
            b';' if !in_quotes => {
                parts.push(&input[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&input[start..]);
    parts
}

fn trim_ascii_spaces(b: &[u8]) -> &[u8] {
    let mut s = 0;
    let mut e = b.len();
    while s < e && (b[s] == b' ' || b[s] == b'\t') {
        s += 1;
    }
    while e > s && (b[e - 1] == b' ' || b[e - 1] == b'\t') {
        e -= 1;
    }
    &b[s..e]
}

/// Parse a cookie value: quoted (`"..."` with `\"`/`\\`
/// escapes) or unquoted value bytes.
fn parse_cookie_value(raw: &[u8]) -> Option<String> {
    if raw.is_empty() {
        return Some(String::new());
    }
    if raw[0] == b'"' {
        if raw.len() < 2 || raw[raw.len() - 1] != b'"' {
            return None;
        }
        let inner = &raw[1..raw.len() - 1];
        let mut out = Vec::with_capacity(inner.len());
        let mut i = 0;
        while i < inner.len() {
            if inner[i] == b'\\' && i + 1 < inner.len() {
                out.push(inner[i + 1]);
                i += 2;
            } else if inner[i] == b'"' {
                return None;
            } else {
                out.push(inner[i]);
                i += 1;
            }
        }
        return Some(String::from_utf8_lossy(&out).into_owned());
    }
    if !raw.iter().all(|&b| is_value_byte(b)) {
        return None;
    }
    Some(String::from_utf8_lossy(raw).into_owned())
}

/// Parse an HTTP date (`Expires` attribute). Layouts tried
/// in order (Go `time.Parse` in `parseSetCookie` tries
/// RFC1123, then RFC850, then ANSIC):
/// - `Mon, 02 Jan 2006 15:04:05 GMT`
/// - `Monday, 02-Jan-06 15:04:05 GMT`
/// - `Mon Jan  2 15:04:05 2006`
/// Returns the epoch, or `None` when no layout matches (Go
/// then leaves `Expires` zero, i.e. absent).
pub fn parse_http_date(s: &str) -> Option<i64> {
    let s = s.trim();
    // chrono's `%Z` parses `GMT`/`UTC`; `%e` accepts a
    // space-padded day.
    const FORMATS: &[&str] = &[
        "%a, %d %b %Y %H:%M:%S %Z",
        "%A, %d-%b-%y %H:%M:%S %Z",
        "%a %b %e %H:%M:%S %Y",
        "%a, %d %b %y %H:%M:%S %Z",
    ];
    for fmt in FORMATS {
        if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
            return Some(dt.timestamp());
        }
        // `%Z` fails on some chrono builds for `GMT`; retry
        // with the literal zone stripped.
        if let Some(stripped) = s
            .strip_suffix(" GMT")
            .or_else(|| s.strip_suffix(" UTC"))
            .or_else(|| s.strip_suffix(" UT"))
        {
            let fmt2 = fmt.replace(" %Z", "");
            if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(stripped, &fmt2) {
                return Some(Utc.from_utc_datetime(&naive).timestamp());
            }
        }
    }
    None
}

/// Parse every Set-Cookie header value, skipping
/// unparseable values and counting them (Go
/// `ParseSetCookieHeader`, `authcookies.go`). Returns the
/// parsed cookies and the skipped count.
pub fn parse_set_cookie_header(values: &[String]) -> (Vec<ParsedCookie>, usize) {
    let mut out = Vec::new();
    let mut skipped = 0;
    for v in values {
        match parse_set_cookie(v) {
            Some(c) => out.push(c),
            None => skipped += 1,
        }
    }
    (out, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_and_attrs() {
        let c = parse_set_cookie(
            "hatch_sess=abc123; Path=/; Domain=muse.ai; Secure; HttpOnly; Max-Age=3600",
        )
        .expect("parses");
        assert_eq!(c.name, "hatch_sess");
        assert_eq!(c.value, "abc123");
        assert_eq!(c.domain.as_deref(), Some("muse.ai"));
        assert_eq!(c.path.as_deref(), Some("/"));
        assert_eq!(c.max_age, Some(3600));
        assert!(c.secure && c.http_only);
        assert_eq!(c.expires, None);
    }

    #[test]
    fn parse_expires_rfc1123() {
        let c = parse_set_cookie("x=y; Expires=Wed, 21 Oct 2026 07:28:00 GMT").expect("parses");
        assert_eq!(c.expires, Some(1792567680));
    }

    #[test]
    fn parse_quoted_value_and_semicolon_inside() {
        let c = parse_set_cookie("x=\"a;b\"; Path=/").expect("parses");
        assert_eq!(c.value, "a;b");
        let c2 = parse_set_cookie("x=\"a\\\"b\"; Path=/").expect("parses");
        assert_eq!(c2.value, "a\"b");
    }

    #[test]
    fn parse_rejects_bad_name_and_unterminated_quote() {
        assert!(parse_set_cookie("bad name=v").is_none());
        assert!(parse_set_cookie("x=\"unterminated").is_none());
        assert!(parse_set_cookie("=v").is_none());
        assert!(parse_set_cookie("").is_none());
    }

    #[test]
    fn parse_invalid_max_age_ignored_not_rejected() {
        let c = parse_set_cookie("x=y; Max-Age=banana").expect("parses");
        assert_eq!(c.max_age, None);
        let c2 = parse_set_cookie("x=y; Max-Age=0").expect("parses");
        assert_eq!(c2.max_age, Some(0));
    }

    #[test]
    fn parse_header_counts_skipped() {
        let (cookies, skipped) = parse_set_cookie_header(&[
            "a=1; Path=/".to_string(),
            "bad name=2".to_string(),
            "b=3".to_string(),
        ]);
        assert_eq!(cookies.len(), 2);
        assert_eq!(skipped, 1);
    }
}
