// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Set-Cookie header parsing — the `http.ParseSetCookie`
//! analogue for the cheap chain (`internal/gateway/
//! authcookies.go: `ParseSetCookieHeader` parses every
//! Set-Cookie value with `http.ParseSetCookie`; unparseable
//! values are skipped and counted).
//!
//! Grammar (Go `net/http` `ParseSetCookie`,
//! `parseCookieValue`, `validCookieValueByte`, go1.27):
//! the value is split on `;` NAIVELY (a quoted `;` does
//! NOT protect the cookie — `x="a;b"` is dropped
//! whole); the name is `TrimString`'d and must be an RFC
//! 7230 token; the value is NOT trimmed (a leading space
//! is kept) and must be value bytes (`0x20 <= b < 0x7f`,
//! not `"`/`;`/backslash) after stripping one pair of
//! surrounding quotes — no unescaping (`\"` is invalid).
//! A bare attribute (no `=`) has an empty value; an
//! attribute whose value holds an invalid byte is skipped
//! and the cookie kept. `Max-Age` follows Go's `Atoi`
//! rule: invalid or leading-zero-with-nonzero-value is
//! ignored, `<= 0` becomes `-1` (delete). `Expires`
//! tries exactly two layouts (RFC1123, then
//! `Mon, 02-Jan-2006 15:04:05 MST`).

use chrono::{DateTime, TimeZone, Utc};

/// One parsed Set-Cookie value (the `http.Cookie` fields the
/// keeper uses). `max_age` is `None` when the attribute is
/// absent or ignored; `Some(-1)` means delete (Go
/// `MaxAge <= 0` after `ParseSetCookie`, which maps
/// `Max-Age=0` to `-1`); `Some(n > 0)` is seconds.
/// Go's `ParseSetCookie` never yields `Some(0)`.
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

/// Go `validCookieValueByte`: `0x20 <= b < 0x7f`,
/// not `"`, `;` or `\`. Space (`0x20`) IS allowed.
fn is_value_byte(b: u8) -> bool {
    (0x20..0x7f).contains(&b) && b != b'"' && b != b';' && b != b'\\'
}

/// Go `textproto.TrimString`: trim ASCII space and tab
/// from both ends (`net/http` `ParseSetCookie` trims
/// every part and the name this way; the VALUE is never
/// trimmed).
fn trim_ascii_spaces(b: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = b.len();
    while start < end && (b[start] == b' ' || b[start] == b'\t') {
        start += 1;
    }
    while end > start && (b[end - 1] == b' ' || b[end - 1] == b'\t') {
        end -= 1;
    }
    &b[start..end]
}

/// Parse one Set-Cookie header value. Returns `None` when
/// the value is unparseable (the caller counts it as
/// skipped). The input must be one header value, not a
/// comma-joined pair. Mirrors Go `ParseSetCookie`
/// step by step (see the module docs).
pub fn parse_set_cookie(header: &str) -> Option<ParsedCookie> {
    // Go splits NAIVELY on ';' (no quote awareness).
    let line = trim_ascii_spaces(header.as_bytes());
    if line.is_empty() {
        return None;
    }
    let mut parts = line.split(|&b| b == b';');
    let first = trim_ascii_spaces(parts.next()?);
    let eq = first.iter().position(|&b| b == b'=')?;
    let name = trim_ascii_spaces(&first[..eq]);
    if name.is_empty() || !name.iter().all(|&b| is_token_char(b)) {
        return None;
    }
    // The value is NOT trimmed: Go passes it to
    // `parseCookieValue` as cut (a leading space is kept).
    let value = parse_cookie_value(&first[eq + 1..], true)?;
    let mut out = ParsedCookie {
        name: ascii_string(name),
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
        // A bare attribute (no '=') has an empty value
        // (Go `strings.Cut` returns `""`).
        let (key, val) = match attr.iter().position(|&b| b == b'=') {
            Some(i) => (&attr[..i], &attr[i + 1..]),
            None => (attr, &[][..]),
        };
        // Non-ASCII attribute names are skipped (Go
        // `ascii.ToLower` reports non-ASCII).
        if !key.is_ascii() {
            continue;
        }
        // An attribute value holding an invalid byte
        // skips the ATTRIBUTE (Go `Unparsed`), not the
        // cookie. Quotes are NOT stripped here (Go
        // `allowDoubleQuote=false`).
        let Some(val) = parse_cookie_value(val, false) else {
            continue;
        };
        let key_lc = key.to_ascii_lowercase();
        match key_lc.as_slice() {
            b"domain" => out.domain = Some(val),
            b"path" => out.path = Some(val),
            b"expires" => out.expires = parse_http_date(&val),
            b"max-age" => {
                // Go: `secs, err := strconv.Atoi(val)`;
                // invalid, or `secs != 0 && val[0] == '0'`,
                // ignores the attribute; `secs <= 0`
                // becomes -1 (delete).
                if let Ok(secs) = val.parse::<i64>() {
                    if secs != 0 && val.as_bytes().first() == Some(&b'0') {
                        // Leading zero with a nonzero
                        // value: ignored.
                    } else if secs <= 0 {
                        out.max_age = Some(-1);
                    } else {
                        out.max_age = Some(secs);
                    }
                }
                // Invalid Max-Age is ignored (Go does the
                // same: only a successful Atoi sets MaxAge).
            }
            b"secure" => out.secure = true,
            b"httponly" => out.http_only = true,
            _ => {}
        }
    }
    Some(out)
}

/// Bytes that passed a byte-level check are ASCII by
/// construction; render them 1:1 without lossy
/// conversion (Go strings keep the bytes).
fn ascii_string(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// Parse a cookie value per Go `parseCookieValue`:
/// strip ONE pair of surrounding quotes when
/// `allow_double_quote` (and only then — no unescaping:
/// a `\` or inner `"` is an invalid byte), then every
/// byte must satisfy [`is_value_byte`].
fn parse_cookie_value(raw: &[u8], allow_double_quote: bool) -> Option<String> {
    let mut raw = raw;
    if allow_double_quote && raw.len() > 1 && raw[0] == b'"' && raw[raw.len() - 1] == b'"' {
        raw = &raw[1..raw.len() - 1];
    }
    if !raw.iter().all(|&b| is_value_byte(b)) {
        return None;
    }
    Some(ascii_string(raw))
}

/// Parse an HTTP date (`Expires` attribute). Go
/// `ParseSetCookie` tries exactly two layouts
/// (`time.RFC1123`, then `Mon, 02-Jan-2006 15:04:05
/// MST`): ANSIC and 2-digit-year forms are NOT tried
/// and leave `Expires` zero, i.e. absent.
///
/// Returns the epoch, or `None` when no layout matches.
pub fn parse_http_date(s: &str) -> Option<i64> {
    let s = s.trim();
    // chrono's `%Z` parses `GMT`/`UTC`; `%e` accepts a
    // space-padded day.
    const FORMATS: &[&str] = &["%a, %d %b %Y %H:%M:%S %Z", "%a, %d-%b-%Y %H:%M:%S %Z"];
    for fmt in FORMATS {
        let fmt2 = fmt.replace(" %Z", "");
        if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
            // chrono's `%a` accepts full weekday names
            // ("Wednesday") and `%Y` accepts short years
            // ("26"); Go's two layouts accept neither.
            // Re-format the parsed value and require it
            // to equal the input (minus the zone): this
            // also enforces weekday/date consistency,
            // which Go checks and chrono does not.
            if let Some((head, _)) = s.rsplit_once(' ')
                && dt.format(&fmt2).to_string() == head
            {
                return Some(dt.timestamp());
            }
            continue;
        }
        // `%Z` fails on some chrono builds for `GMT`; retry
        // with the literal zone stripped.
        if let Some(stripped) = s
            .strip_suffix(" GMT")
            .or_else(|| s.strip_suffix(" UTC"))
            .or_else(|| s.strip_suffix(" UT"))
            && let Ok(naive) = chrono::NaiveDateTime::parse_from_str(stripped, &fmt2)
            && naive.format(&fmt2).to_string() == stripped
        {
            return Some(Utc.from_utc_datetime(&naive).timestamp());
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
    fn parse_quoted_value_go_parity() {
        // Go splits on ';' NAIVELY: a quoted ';' does
        // NOT protect the cookie — the whole value is
        // dropped.
        assert!(parse_set_cookie("x=\"a;b\"; Path=/").is_none());
        // No unescaping: a backslash inside quotes is an
        // invalid value byte, so the whole value is
        // dropped.
        assert!(parse_set_cookie("x=\"a\\\"b\"; Path=/").is_none());
        // A clean quoted value strips one pair of quotes.
        let c = parse_set_cookie("x=\"abc\"; Path=/").expect("parses");
        assert_eq!(c.value, "abc");
        let c = parse_set_cookie("x=\"a b\"").expect("parses");
        assert_eq!(c.value, "a b");
        let c = parse_set_cookie("x=\"\"").expect("parses");
        assert_eq!(c.value, "");
    }

    #[test]
    fn parse_go_parity_pins() {
        // (f) The value is NOT trimmed: a leading space
        // is kept (Go `parseCookieValue` on the cut
        // value). The NAME is trimmed (Go
        // `TrimString(name)`).
        let c = parse_set_cookie("x= v").expect("parses");
        assert_eq!(c.value, " v");
        let c = parse_set_cookie("x =y").expect("parses");
        assert_eq!(c.name, "x");
        assert_eq!(c.value, "y");
        // Unquoted space is a valid value byte (0x20).
        let c = parse_set_cookie("x=a b").expect("parses");
        assert_eq!(c.value, "a b");
        // DEL (0x7f) is not a value byte.
        assert!(parse_set_cookie("x=a\x7f").is_none());
        // (c) A bare attribute (no '=') has an empty
        // value: Secure sets, Domain becomes "" — the
        // cookie is kept.
        let c = parse_set_cookie("x=y; Secure").expect("parses");
        assert!(c.secure);
        let c = parse_set_cookie("x=y; Domain").expect("parses");
        assert_eq!(c.domain.as_deref(), Some(""));
        let c = parse_set_cookie("x=y; Foo").expect("parses");
        assert_eq!(c.name, "x");
        // An attribute value with an invalid byte skips
        // the ATTRIBUTE, not the cookie (Go `Unparsed`).
        let c = parse_set_cookie("x=y; Domain=a\"b").expect("parses");
        assert_eq!(c.domain, None);
        let c = parse_set_cookie("x=y; Path=/a\\b").expect("parses");
        assert_eq!(c.path, None);
        // (d) `Max-Age= 3600`: Atoi rejects the space,
        // so the attribute is ignored.
        let c = parse_set_cookie("x=y; Max-Age= 3600").expect("parses");
        assert_eq!(c.max_age, None);
        // (e) Expires tries exactly two layouts: ANSIC
        // and 2-digit-year forms are absent in Go.
        let c = parse_set_cookie("x=y; Expires=Wed Oct 21 07:28:00 2026").expect("parses");
        assert_eq!(c.expires, None);
        let c = parse_set_cookie("x=y; Expires=Wed, 21 Oct 26 07:28:00 GMT").expect("parses");
        assert_eq!(c.expires, None);
        // Go's second layout takes the abbreviated
        // weekday only ("Wednesday" is unparsed).
        let c = parse_set_cookie("x=y; Expires=Wed, 21-Oct-2026 07:28:00 GMT").expect("parses");
        assert_eq!(c.expires, Some(1792567680));
        let c =
            parse_set_cookie("x=y; Expires=Wednesday, 21-Oct-2026 07:28:00 GMT").expect("parses");
        assert_eq!(c.expires, None);
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
        // F8: Go maps `Max-Age<=0` to -1 (delete).
        let c2 = parse_set_cookie("x=y; Max-Age=0").expect("parses");
        assert_eq!(c2.max_age, Some(-1));
        // Leading zero with a nonzero value: ignored.
        let c3 = parse_set_cookie("x=y; Max-Age=03600").expect("parses");
        assert_eq!(c3.max_age, None);
        // "00" is zero, so it is -1, not ignored.
        let c4 = parse_set_cookie("x=y; Max-Age=00").expect("parses");
        assert_eq!(c4.max_age, Some(-1));
        let c5 = parse_set_cookie("x=y; Max-Age=01").expect("parses");
        assert_eq!(c5.max_age, None);
        let c6 = parse_set_cookie("x=y; Max-Age=-5").expect("parses");
        assert_eq!(c6.max_age, Some(-1));
        let c7 = parse_set_cookie("x=y; Max-Age=+5").expect("parses");
        assert_eq!(c7.max_age, Some(5));
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
