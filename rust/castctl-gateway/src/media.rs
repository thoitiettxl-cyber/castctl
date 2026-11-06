// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Sandbox media references → `/media/raw/…` download paths.
//!
//! Go source: `internal/gateway/media.go:47-91` (`MediaPath`,
//! `mediaRefString`, `quotePython`). The `media_path` body is
//! copied from the already-reviewed M5b port in
//! `castctl-telegram/src/turn.rs:282-360` (`media_path`), so its
//! helper set (`http_escaped_path`, `valid_escapes`,
//! `valid_port`, `percent_decode`, `quote_python_bytes`) is
//! reproduced here rather than re-derived; the M5b deviation
//! (case-insensitive `http(s)://` scheme gate, see below) is
//! carried over verbatim.

use castctl_transport::TransportError;

/// Resolve a sandbox media reference to its `/media/raw/…`
/// download path.
/// Source: `internal/gateway/media.go:47-91` (`MediaPath`,
/// `mediaRefString`).
///
/// `variants_original` is the resource dict's
/// `variants.original` value when present and non-empty: it
/// wins over `path`, exactly as Go's `mediaRefString` reads
/// `variants.original`, then `path`, then `url` out of a
/// resource dict. A leading `media/raw/` is stripped once;
/// the remainder is unquoted, `..` segments and empty paths
/// are rejected, and the result is re-quoted with `/` safe.
/// Bad input is a `Validation` error carrying only the kind
/// and the ref's byte length (loop 6, item 4): the ref is
/// peer-controlled, so its text must never reach an error
/// string.
#[must_use]
pub fn media_path(path: &str, variants_original: Option<&str>) -> Result<String, TransportError> {
    // `variants.original` wins over `path` whenever it is
    // non-empty (`media.go:80-91`).
    let mut refstr = String::new();
    if let Some(original) = variants_original
        && !original.is_empty()
    {
        refstr = original.to_string();
    }
    if refstr.is_empty() {
        refstr = path.to_string();
    }
    if refstr.is_empty() {
        return Err(TransportError::Validation {
            message: format!("bad sandbox path: ref_length={}", refstr.len()),
        });
    }
    let mut rel: &str = &refstr;
    let owned;
    if let Some(rest) = rel.strip_prefix("sandbox://") {
        rel = rest;
    } else if is_http_url(rel) {
        owned = http_escaped_path(rel).ok_or_else(|| TransportError::Validation {
            message: format!("bad sandbox path: ref_length={}", refstr.len()),
        })?;
        rel = &owned;
    }
    let rel = rel.trim_start_matches('/');
    let rel = rel.strip_prefix("media/raw/").unwrap_or(rel);
    // `url.PathUnescape` (`media.go:67-69`): unquote only
    // when the whole string unquotes; on any bad escape
    // keep the original string. The decode is bytewise:
    // `%FF` decodes to the single byte 0xFF (Go keeps it
    // as a byte in the string), NOT to the U+FFFD
    // replacement — the re-quote below turns it back into
    // `%FF` (M5b fix loop 2, Tech N1/N2).
    let unquoted: Vec<u8> =
        percent_decode(rel.as_bytes()).unwrap_or_else(|| rel.as_bytes().to_vec());
    if unquoted.is_empty() || unquoted.split(|b| *b == b'/').any(|seg| seg == b"..") {
        return Err(TransportError::Validation {
            message: format!("bad sandbox path: ref_length={}", refstr.len()),
        });
    }
    Ok(format!("/media/raw/{}", quote_python_bytes(&unquoted)))
}

/// Whether `s` is an http(s) URL: the scheme check is
/// case-insensitive, so `HTTP://…` counts — a deliberate
/// deviation from Go's `MediaPath` (`media.go:47-91`), whose
/// prefix gate only accepts lowercase `http://` /
/// `https://` and never calls `url.Parse` on an
/// uppercase-scheme ref. (M5b review round 3, Safety N4.)
/// Behaviour stays safe: the URL is still fully validated
/// and the result is a `/media/raw/…` path.
fn is_http_url(s: &str) -> bool {
    match s.find("://") {
        Some(idx) => {
            let scheme = &s[..idx];
            scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
        }
        None => false,
    }
}

/// The escaped path of an http(s) URL, Go `url.Parse` +
/// `EscapedPath` (`media.go:56-63`): the query/fragment
/// are dropped; a control character anywhere, a bad `%`
/// escape anywhere except the query, or an invalid port
/// fails the parse (probed against Go's `net/url`
/// 2026-11-06; see PORTING §M5b). The returned path is
/// still percent-encoded; the caller's unquote + re-quote
/// normalizes it exactly like Go's `PathUnescape` +
/// `quotePython` pair.
fn http_escaped_path(url: &str) -> Option<String> {
    if url.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    let after_scheme = url.split_once("://")?.1;
    let path_start = after_scheme.find('/').unwrap_or(after_scheme.len());
    let authority = &after_scheme[..path_start];
    if !valid_port(authority) || !valid_escapes(authority) {
        return None;
    }
    let path_and_rest = &after_scheme[path_start..];
    let (before_query, query_frag) = match path_and_rest.find('?') {
        Some(q) => (&path_and_rest[..q], Some(&path_and_rest[q + 1..])),
        None => (path_and_rest, None),
    };
    if !valid_escapes(before_query) {
        return None;
    }
    // The query is not escape-validated (Go keeps
    // `RawQuery` raw); a fragment after it is.
    if let Some(qf) = query_frag
        && let Some(f) = qf.find('#')
        && !valid_escapes(&qf[f..])
    {
        return None;
    }
    let path = path_and_rest.split(['?', '#']).next().unwrap_or("");
    Some(path.to_string())
}

/// Whether every `%` in `s` starts a valid `%XX`
/// escape.
fn valid_escapes(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || hex_val(bytes[i + 1]).is_none()
                || hex_val(bytes[i + 2]).is_none()
            {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

/// Whether the authority's port (if any) is valid: empty
/// or all digits; a bracketed IPv6 host keeps its colons.
fn valid_port(authority: &str) -> bool {
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if let Some(rest) = hostport.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        let after = &rest[end + 1..];
        return after.is_empty()
            || (after.starts_with(':') && after[1..].bytes().all(|b| b.is_ascii_digit()));
    }
    match hostport.matches(':').count() {
        0 => true,
        1 => {
            let port = hostport.split_once(':').map_or("", |(_, p)| p);
            port.bytes().all(|b| b.is_ascii_digit())
        }
        _ => false,
    }
}

/// Percent-decode `%XX` sequences, Go's
/// `url.PathUnescape`: `None` when ANY escape is bad
/// (the caller then keeps the original string). The
/// result is bytes: a decoded byte need not be valid
/// UTF-8 (`%FF` -> one 0xFF byte).
fn percent_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            if i + 2 >= s.len() {
                return None;
            }
            let (h, l) = (hex_val(s[i + 1])?, hex_val(s[i + 2])?);
            out.push(h * 16 + l);
            i += 3;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Hand-rolled `urllib.parse.quote(safe="/")` over bytes:
/// unreserved + `/` pass through, everything else is
/// `%XX` (uppercase hex). Bytewise so a decoded 0xFF
/// byte re-quotes to `%FF` instead of going through a
/// lossy UTF-8 conversion.
/// Source: `internal/gateway/media.go` (`quotePython`).
fn quote_python_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_path_literals() {
        assert_eq!(
            media_path("sandbox://a/b.png", None).unwrap(),
            "/media/raw/a/b.png"
        );
        assert_eq!(
            media_path("sandbox://workspace/pic.png", None).unwrap(),
            "/media/raw/workspace/pic.png"
        );
        assert_eq!(
            media_path("/media/raw/a/b.png", None).unwrap(),
            "/media/raw/a/b.png"
        );
        assert_eq!(
            media_path("media/raw/a.png", None).unwrap(),
            "/media/raw/a.png"
        );
        // variants.original wins over path.
        assert_eq!(
            media_path("sandbox://a/b.png", Some("sandbox://orig/c.png")).unwrap(),
            "/media/raw/orig/c.png"
        );
        // Empty original falls back to path.
        assert_eq!(
            media_path("sandbox://a/b.png", Some("")).unwrap(),
            "/media/raw/a/b.png"
        );
        // Spaces re-quote.
        assert_eq!(
            media_path("sandbox://a/b c.png", None).unwrap(),
            "/media/raw/a/b%20c.png"
        );
        // http(s) URL: path only, query dropped.
        assert_eq!(
            media_path("https://x.example/a/b.png?k=v", None).unwrap(),
            "/media/raw/a/b.png"
        );
        // Bad inputs: length-only errors, never the ref.
        assert!(media_path("", None).is_err());
        assert!(media_path("sandbox://a/../b.png", None).is_err());
        assert!(media_path("sandbox://", None).is_err());
        let e = media_path("", None).unwrap_err();
        assert!(matches!(
            e,
            TransportError::Validation { message } if message == "bad sandbox path: ref_length=0"
        ));
    }
}
