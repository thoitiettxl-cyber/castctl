// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! A narrow hand-rolled port of the `net/url` slice used by
//! `redactParsedURL` (`internal/logging/safe.go`): parse, query
//! rebuild, fragment replacement, and `URL.String`
//! serialisation. Decision D-url: no `url` crate.
//!
//! Only the shapes `SafeString`'s URL pass can produce are
//! modelled: absolute URLs with scheme + authority (the `reURL`
//! grab always has `://`), plus the degenerate shapes the
//! probes pinned (`https:?q=1`, empty query/fragment, IPv6
//! hosts, bad ports). The parser is deliberately strict where
//! Go's is: control bytes, bad `%XX` escapes in path/userinfo/
//! host/fragment, bad ports, and invalid IPv6 literals are
//! parse errors, and `redact_url_all_query` maps errors to
//! `[redacted-url]` exactly as Go does.
//!
//! Known approximations, all documented in `rust/PORTING.md`:
//! IPv6 validation is a hand-rolled RFC 4291 check (Go
//! delegates to `net.ParseIP`); host serialisation escapes only
//! non-ASCII bytes (Go's `encodeHost` table is wider, but every
//! probed host shape round-trips identically); userinfo content
//! is validated but discarded (redaction always replaces it).

/// A parsed URL: only the fields `redactParsedURL` reads or
/// rewrites. Path bytes are kept as bytes because a decoded
/// path may hold non-UTF-8 bytes (`%FF`), which Go round-trips
/// through `String()` as `%FF`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedUrl {
    scheme: String,
    user_present: bool,
    /// Raw authority host part, including brackets and port.
    host: String,
    /// Decoded path bytes.
    path: Vec<u8>,
    /// Raw path bytes, when Go would keep `RawPath`.
    raw_path: Vec<u8>,
    /// Raw query string, when a `?` was present.
    query: Option<String>,
    /// A `?` was present (even with an empty query).
    force_query: bool,
    /// A `#` was present.
    fragment_present: bool,
    /// The decoded fragment was non-empty.
    fragment_nonempty: bool,
}

/// Parse error: the caller maps this to `[redacted-url]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UrlParseError;

fn is_ctl(b: u8) -> bool {
    b < 0x20 || b == 0x7f
}

/// Parse `raw` the way Go `url.Parse` does, for the shapes in
/// scope. Returns `Err` exactly where Go returns a parse error
/// for the probed corpus (see `rust/PORTING.md`).
pub(crate) fn parse_url(raw: &str) -> Result<ParsedUrl, UrlParseError> {
    if raw.bytes().any(is_ctl) {
        return Err(UrlParseError);
    }
    // Fragment first: everything after the first '#'.
    let (before_frag, fragment_raw) = match raw.find('#') {
        Some(i) => (&raw[..i], Some(&raw[i + 1..])),
        None => (raw, None),
    };
    let (fragment_present, fragment_nonempty) = match fragment_raw {
        None => (false, false),
        Some(frag) => {
            let decoded = unescape_bytes(frag.as_bytes())?;
            (true, !decoded.is_empty())
        }
    };
    // Query: everything after the first '?' in the remainder.
    let (before_query, query_raw) = match before_frag.find('?') {
        Some(i) => (&before_frag[..i], Some(&before_frag[i + 1..])),
        None => (before_frag, None),
    };
    let force_query = query_raw.is_some();
    let query = query_raw.map(str::to_string);
    // Scheme: a ':' before any '/'. An invalid scheme spelling
    // before the colon is a parse error in Go.
    let mut scheme = String::new();
    let mut rest = before_query;
    if let Some(colon) = before_query.find(':') {
        let slash = before_query.find('/');
        if slash.is_none_or(|s| colon < s) {
            let cand = &before_query[..colon];
            if !is_valid_scheme(cand) {
                return Err(UrlParseError);
            }
            scheme = cand.to_string();
            rest = &before_query[colon + 1..];
        }
    }
    // Authority: a leading "//" introduces it.
    let mut user_present = false;
    let mut host = String::new();
    let mut path_raw = rest;
    if let Some(after_slashes) = rest.strip_prefix("//") {
        let end = after_slashes.find('/').unwrap_or(after_slashes.len());
        let authority = &after_slashes[..end];
        path_raw = &after_slashes[end..];
        let hostport = match authority.rfind('@') {
            Some(at) => {
                let userinfo = &authority[..at];
                // Userinfo content is discarded by redaction, but
                // a bad escape still fails the parse in Go.
                let _ = unescape_bytes(userinfo.as_bytes())?;
                user_present = true;
                &authority[at + 1..]
            }
            None => authority,
        };
        host = parse_host(hostport)?;
    }
    // Path: validate escapes, keep decoded + raw forms.
    let path = unescape_bytes(path_raw.as_bytes())?;
    let raw_path = if path_raw.as_bytes() != escape_path(&path).as_slice()
        && valid_encoded(path_raw.as_bytes())
    {
        path_raw.as_bytes().to_vec()
    } else {
        Vec::new()
    };
    Ok(ParsedUrl {
        scheme,
        user_present,
        host,
        path,
        raw_path,
        query,
        force_query,
        fragment_present,
        fragment_nonempty,
    })
}

fn is_valid_scheme(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Validate the host part and return it verbatim for
/// serialisation. Bracketed literals must hold a valid IPv6
/// address (plus an optional zone); unbracketed hosts must
/// unescape cleanly to allowed characters, with a digits-only
/// optional port.
fn parse_host(hostport: &str) -> Result<String, UrlParseError> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let close = rest.find(']').ok_or(UrlParseError)?;
        let inside = &rest[..close];
        let after = &rest[close + 1..];
        validate_ipv6_literal(inside)?;
        if let Some(port) = after.strip_prefix(':') {
            if !port.bytes().all(|b| b.is_ascii_digit()) {
                return Err(UrlParseError);
            }
        } else if !after.is_empty() {
            return Err(UrlParseError);
        }
        return Ok(hostport.to_string());
    }
    // Unbracketed: split port at the first ':'; a second ':'
    // lands in the port and fails the digits check.
    let (host_part, port_part) = match hostport.find(':') {
        Some(i) => (&hostport[..i], Some(&hostport[i + 1..])),
        None => (hostport, None),
    };
    if let Some(port) = port_part {
        if !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(UrlParseError);
        }
    }
    let decoded = unescape_bytes(host_part.as_bytes())?;
    for &b in &decoded {
        if !is_host_byte(b) {
            return Err(UrlParseError);
        }
    }
    Ok(hostport.to_string())
}

/// Bytes Go allows in a decoded unbracketed host: letters,
/// digits, `-._~!$&'()*+,;=:` and `%` (a decoded `%25`, i.e. a
/// zone separator). Anything else (notably a decoded space)
/// fails the parse.
fn is_host_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'%'
        )
}

/// Validate an IPv6 literal with an optional `%25` zone suffix.
/// The zone is accepted verbatim when non-empty; the address
/// itself follows RFC 4291 (`::` compression at most once,
/// 1-4 hex digits per group, one trailing embedded IPv4).
/// Splits one side of a `::` in an IPv6 literal into groups.
fn parse_side<'a>(side: &'a str, groups: &mut Vec<&'a str>) {
    if side.is_empty() {
        return;
    }
    for g in side.split(':') {
        groups.push(g);
    }
}

fn validate_ipv6_literal(inside: &str) -> Result<(), UrlParseError> {
    let addr = match inside.find("%25") {
        Some(i) => {
            // Zone: Go lowercases the rest for the match; the
            // zone itself must be non-empty.
            let zone = &inside[i + 3..];
            if zone.is_empty() {
                return Err(UrlParseError);
            }
            &inside[..i]
        }
        None => inside,
    };
    if !addr.contains(':') {
        return Err(UrlParseError);
    }
    // Split on "::" (at most one occurrence).
    let mut halves = addr.splitn(3, "::");
    let head = halves.next().unwrap_or("");
    let tail = halves.next();
    if halves.next().is_some() {
        return Err(UrlParseError);
    }
    let mut groups: Vec<&str> = Vec::new();
    parse_side(head, &mut groups);
    let tail_groups_start = groups.len();
    if let Some(t) = tail {
        parse_side(t, &mut groups);
    }
    let compressed = tail.is_some();
    // An embedded IPv4 dotted quad counts as two groups.
    let mut total = groups.len();
    let mut ipv4 = false;
    if let Some(last) = groups.last() {
        if last.contains('.') {
            validate_ipv4(last)?;
            ipv4 = true;
            total += 1;
        }
    }
    for (idx, g) in groups.iter().enumerate() {
        if idx == groups.len() - 1 && ipv4 {
            continue;
        }
        if g.is_empty() || g.len() > 4 || !g.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(UrlParseError);
        }
    }
    if compressed {
        if total >= 8 {
            return Err(UrlParseError);
        }
    } else if total != 8 {
        return Err(UrlParseError);
    }
    let _ = tail_groups_start;
    Ok(())
}

fn validate_ipv4(s: &str) -> Result<(), UrlParseError> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(UrlParseError);
    }
    for p in parts {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(UrlParseError);
        }
        if p.parse::<u16>().map_or(true, |v| v > 255) {
            return Err(UrlParseError);
        }
    }
    Ok(())
}

/// `%XX` decoding over bytes; `+` is literal here (only query
/// unescaping treats `+` as space). Bad escapes are errors.
fn unescape_bytes(input: &[u8]) -> Result<Vec<u8>, UrlParseError> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            if i + 2 >= input.len() {
                return Err(UrlParseError);
            }
            let h = hex_val(input[i + 1]).ok_or(UrlParseError)?;
            let l = hex_val(input[i + 2]).ok_or(UrlParseError)?;
            out.push((h << 4) | l);
            i += 3;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Whether `raw` is a valid encoding in path mode, exactly
/// as Go `validEncoded` (`net/url/url.go`): sub-delims, `:`,
/// `@`, `[`, `]` are always fine, `%` is fine (decoding is
/// checked by the unescape-equality in `EscapedPath`), and
/// every other byte must not need escaping in path mode.
fn valid_encoded(raw: &[u8]) -> bool {
    for &b in raw {
        match b {
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':'
            | b'@' | b'[' | b']' | b'%' => {}
            _ => {
                if path_must_escape(b) {
                    return false;
                }
            }
        }
    }
    true
}

/// Bytes that stay unescaped in a path: unreserved marks plus
/// the pchar set Go keeps (`$&+,/:;=@`). Everything else
/// (including `?`, `'`, `[`, `]`, non-ASCII bytes) is escaped.
/// `?` is deliberately NOT kept: a decoded `?` in a path
/// serialises as `%3F` (probe ZZPATH).
fn path_must_escape(b: u8) -> bool {
    !(b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'$'
                | b'&'
                | b'+'
                | b','
                | b'/'
                | b':'
                | b';'
                | b'='
                | b'@'
        ))
}

/// Escape decoded path bytes the way Go `URL.String` does.
pub(crate) fn escape_path(decoded: &[u8]) -> Vec<u8> {
    escape_bytes(decoded, path_must_escape)
}

/// Escape a decoded fragment the way Go `escape` does in
/// `encodeFragment` mode (`net/url/encoding_table.go`): the
/// unreserved marks plus `!$&()*+,/:;=?@` stay; `'` escapes
/// (unlike in a path segment), as do `[`, `]`, space, `#`,
/// `%`, and non-ASCII bytes.
fn fragment_must_escape(b: u8) -> bool {
    !(b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b'/'
                | b':'
                | b';'
                | b'='
                | b'?'
                | b'@'
        ))
}

fn escape_fragment(decoded: &[u8]) -> Vec<u8> {
    escape_bytes(decoded, fragment_must_escape)
}

fn escape_bytes(decoded: &[u8], must_escape: impl Fn(u8) -> bool) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(decoded.len());
    for &b in decoded {
        if !must_escape(b) {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0xf) as usize]);
        }
    }
    out
}

/// Query unescaping: `+` becomes a space, `%XX` decodes;
/// bad escapes are errors (the caller falls back to the raw
/// key part, as Go's `redactParsedURL` does).
pub(crate) fn query_unescape(input: &[u8]) -> Result<Vec<u8>, UrlParseError> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 >= input.len() {
                    return Err(UrlParseError);
                }
                let h = hex_val(input[i + 1]).ok_or(UrlParseError)?;
                let l = hex_val(input[i + 2]).ok_or(UrlParseError)?;
                out.push((h << 4) | l);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Query escaping: only unreserved marks survive; space
/// becomes `+`; everything else is `%XX` (uppercase hex).
pub(crate) fn query_escape(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for &b in input {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else if b == b' ' {
            out.push('+');
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xf) as usize] as char);
        }
    }
    out
}

/// The index of the key/value separator in one query segment:
/// a literal `=`, or an encoded `%3D` / `%253D` (either hex
/// case), whichever comes first; -1 when there is none.
/// Mirrors Go `querySepIndex` (`safe.go`).
fn query_sep_index(seg: &str) -> Option<usize> {
    let bytes = seg.as_bytes();
    let mut best: Option<usize> = bytes.iter().position(|&b| b == b'=');
    let lower: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
    for sep in ["%253d", "%3d"] {
        if let Some(idx) = find_subslice(&lower, sep.as_bytes()) {
            if best.is_none_or(|b| idx < b) {
                best = Some(idx);
            }
        }
    }
    best
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Escape non-ASCII bytes in a host for serialisation
/// (UTF-8 `%XX`, uppercase hex); all other bytes pass through.
fn escape_host(host: &str) -> String {
    let mut out = String::with_capacity(host.len());
    for &b in host.as_bytes() {
        if b < 0x80 {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl ParsedUrl {
    /// Serialise after redaction: userinfo replaced, query
    /// rebuilt, fragment replaced. Mirrors Go
    /// `redactParsedURL` + `URL.String` for the fields in
    /// scope.
    pub(crate) fn serialize_redacted(&self) -> String {
        let mut out = String::new();
        if !self.scheme.is_empty() {
            out.push_str(&self.scheme);
            out.push(':');
        }
        if !self.host.is_empty() || !self.path.is_empty() || self.user_present {
            out.push_str("//");
        }
        if self.user_present {
            // Go `url.User("[redacted]")` serialises as
            // `%5Bredacted%5D`; SafeString pass 4 rewrites it
            // to the literal `<redacted>` marker.
            out.push_str("%5Bredacted%5D@");
        }
        out.push_str(&escape_host(&self.host));
        if !self.raw_path.is_empty() {
            out.push_str(&String::from_utf8_lossy(&self.raw_path));
        } else if !self.path.is_empty() {
            out.push_str(&String::from_utf8_lossy(&escape_path(&self.path)));
        }
        if let Some(rebuilt) = self.rebuilt_query() {
            out.push('?');
            out.push_str(&rebuilt);
        }
        if self.fragment_present && self.fragment_nonempty {
            out.push('#');
            out.push_str(&String::from_utf8_lossy(&escape_fragment(b"[redacted]")));
        }
        out
    }

    /// The rebuilt query string (`None` = no `?` is emitted),
    /// or `Some("")` when the original had a bare trailing `?`
    /// and no rebuild happened.
    fn rebuilt_query(&self) -> Option<String> {
        let raw = self.query.as_deref()?;
        if raw.is_empty() {
            // Go skips the rebuild when RawQuery is empty;
            // ForceQuery keeps the bare `?`.
            if self.force_query {
                return Some(String::new());
            }
            return None;
        }
        let mut keys: Vec<Vec<u8>> = Vec::new();
        let mut seen: Vec<Vec<u8>> = Vec::new();
        for seg in raw.split('&') {
            if seg.is_empty() {
                continue;
            }
            let key_part = match query_sep_index(seg) {
                Some(idx) => &seg[..idx],
                None => seg,
            };
            let key = query_unescape(key_part.as_bytes())
                .unwrap_or_else(|_| key_part.as_bytes().to_vec());
            if !seen.contains(&key) {
                seen.push(key.clone());
                keys.push(key);
            }
        }
        keys.sort();
        let parts: Vec<String> = keys
            .iter()
            .map(|k| format!("{}=[redacted]", query_escape(k)))
            .collect();
        let joined = parts.join("&");
        if joined.is_empty() {
            // Every segment was empty (e.g. RawQuery "&"): Go
            // rebuilds to an empty query with ForceQuery false,
            // so no `?` is emitted.
            None
        } else {
            Some(joined)
        }
    }
}

#[cfg(test)]
mod probes {
    use super::*;

    // Differential probes (NOT ported Go cases): URL shapes
    // measured against Go `net/url` + `redactParsedURL` on cue.
    #[test]
    fn probe_url_parse_serialize() {
        let cases: &[(&str, Result<&str, ()>)] = &[
            (
                "https://EXAMPLE.COM/Path?B=2&a=1",
                Ok("https://EXAMPLE.COM/Path?B=[redacted]&a=[redacted]"),
            ),
            (
                "https://example.com/a%2Fb?x=1",
                Ok("https://example.com/a%2Fb?x=[redacted]"),
            ),
            (
                "https://example.com/a%20b?x=1",
                Ok("https://example.com/a%20b?x=[redacted]"),
            ),
            (
                "https://example.com/a+b?k=a+b",
                Ok("https://example.com/a+b?k=[redacted]"),
            ),
            ("https://example.com/p?", Ok("https://example.com/p?")),
            ("https://example.com/p#", Ok("https://example.com/p")),
            (
                "https://example.com/p?k=%ZZ",
                Ok("https://example.com/p?k=[redacted]"),
            ),
            ("https://?q=1", Ok("https:?q=[redacted]")),
            (
                "https://[::1]:8080/p?x=1",
                Ok("https://[::1]:8080/p?x=[redacted]"),
            ),
            (
                "https://example.com/p?x=1#fr[ag]",
                Ok("https://example.com/p?x=[redacted]#%5Bredacted%5D"),
            ),
            (
                "https://example.com/a<b?x=1",
                Ok("https://example.com/a%3Cb?x=[redacted]"),
            ),
            (
                "https://example.com/a%2fb?x=1",
                Ok("https://example.com/a%2fb?x=[redacted]"),
            ),
            (
                "https://example.com/a%252fb?x=1",
                Ok("https://example.com/a%252fb?x=[redacted]"),
            ),
            ("https://host:99999/x", Ok("https://host:99999/x")),
            ("https://example.com/%zz", Err(())),
            ("https://example.com/%2", Err(())),
            ("https://[::1/p?x=1", Err(())),
            ("https://[xyz]/p?x=1", Err(())),
            ("https://host:abc/x", Err(())),
            ("https://ho%20st/x", Err(())),
            ("https://example.com/\x01bad?x=1", Err(())),
            ("https://example.com/p?&", Ok("https://example.com/p")),
            (
                "https://example.com/p?a=1&a=2&b=3",
                Ok("https://example.com/p?a=[redacted]&b=[redacted]"),
            ),
            (
                "https://example.com/p?%6Bey=1",
                Ok("https://example.com/p?key=[redacted]"),
            ),
            (
                "https://example.com/p?barekey",
                Ok("https://example.com/p?barekey=[redacted]"),
            ),
            (
                "https://example.com/p?k%253Dv",
                Ok("https://example.com/p?k=[redacted]"),
            ),
            (
                "https://example.com/caf\u{e9}?x=1",
                Ok("https://example.com/caf%C3%A9?x=[redacted]"),
            ),
            (
                "https://example.com/a%2Fb?x=1",
                Ok("https://example.com/a%2Fb?x=[redacted]"),
            ),
        ];
        for (input, want) in cases {
            let got = parse_url(input).map(|u| u.serialize_redacted());
            match want {
                Ok(w) => assert_eq!(got.as_deref(), Ok(*w), "url {input:?}"),
                Err(()) => assert!(
                    got.is_err(),
                    "url {input:?} should fail to parse, got {got:?}"
                ),
            }
        }
    }

    #[test]
    fn probe_query_escape_tables() {
        assert_eq!(query_escape(b"a b"), "a+b");
        assert_eq!(query_escape(b"a+b"), "a%2Bb");
        assert_eq!(query_escape(b"a~b"), "a~b");
        assert_eq!(query_escape("aéb".as_bytes()), "a%C3%A9b");
        assert_eq!(query_unescape(b"a+b").unwrap(), b"a b");
        assert_eq!(query_unescape(b"a%2Bb").unwrap(), b"a+b");
        assert!(query_unescape(b"a%ZZ").is_err());
        assert!(query_unescape(b"a%").is_err());
        assert_eq!(query_unescape(b"%FF").unwrap(), vec![0xFF]);
    }
}
