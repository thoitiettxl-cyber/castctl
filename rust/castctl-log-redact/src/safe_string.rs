// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The 12-pass `SafeString` backstop, ported from Go
//! `internal/logging/safe.go` (`SafeString`, `redactJSONSecrets`,
//! `normalizePctLabels`, `redactURLAllQuery`, `SafeHost`).
//!
//! Pass order is load-bearing and reproduced exactly:
//! URL pass, percent-query pass, percent-label normalisation,
//! `redact.String`, JSON-secret scanner, colon labels,
//! public-key labels, key=value labels, labelled Basic, bare
//! Basic, bare fragments, WireGuard peer abbreviations.
//!
//! Security note, carried from the Go doc: `SafeString` is a
//! BACKSTOP only. Bare secrets with no label are NOT stripped;
//! callers exclude them by construction.

use regex::Regex;
use std::sync::OnceLock;

use crate::redact_str::redact_string;
use crate::url::parse_url;

// ---------------------------------------------------------------------------
// Vocabularies (verbatim from safe.go)
// ---------------------------------------------------------------------------

/// Substring vocabulary for secret-looking keys in JSON forms.
/// Source: `internal/logging/safe.go`, `secretKeyVocab`.
const SECRET_KEY_VOCAB: &str = "password|token|secret|private_key|public_key|privateKey|publicKey|cookie|auth|vm_id|node_id|credential|passwd|apiKey|secretKey|sessionKey|clientSecret|api_key|session_key|access_key|preshared_key|pre_shared_key|private-key|bearer|x-api-key|session|hatch_sess|datr";

/// Vocabulary for bare label forms (colon / equals).
/// Source: `internal/logging/safe.go`, `secretLabelVocab`.
const SECRET_LABEL_VOCAB: &str = "private_key|privateKey|public_key|publicKey|preshared_key|pre_shared_key|password|passwd|auth_token|access_token|hatch_token|api_token|session_key|secret_key|client_secret|token|session|cookie|auth|secret|credential|api_key|apiKey|apikey|vm_id|node_id|access_key|bearer|x-api-key|private-key|hatch_sess|datr";

/// Separator characters between a bare label and `=`/`:`: the
/// five ASCII whitespace members plus VT, NBSP, and EM SPACE.
/// Other Unicode spaces are deliberately NOT covered.
/// Source: `internal/logging/safe.go:538`, `sepClass`.
const SEP_CLASS: &str = r"[\t\n\x0b\f\r \u{a0}\u{2003}]";

fn re_url() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Go `\s` is ASCII-only (RE2).
        Regex::new(r#"[a-zA-Z][a-zA-Z0-9+.-]*://[^\t\n\f\r "']+"#).expect("reURL")
    })
}

fn re_pct_query() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)([?&][A-Za-z0-9_.\-]*(?:token|secret|auth|session|cookie|credential|password|passwd|key|bearer|datr|hatch_sess)[A-Za-z0-9_.\-]*)(?:%253d|%3d)[^\t\n\f\r &;,'"]*"#)
            .expect("rePctQuery")
    })
}

fn re_secret_key_vocab() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(&format!("(?i)(?:{SECRET_KEY_VOCAB})")).expect("reSecretKeyVocab"))
}

fn re_json_scalar() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$").expect("reJSONScalar")
    })
}

fn re_key_colon_full() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Group 1 = label, group 2 = value. The trailing
        // `["']?` consumes one optional closing quote.
        // Go RE2 `\b` is ASCII-only: `ésession=` matches
        // (boundary between non-ASCII `é` and `s`) while
        // `xsession=` does not. Rust's default `\b` is
        // Unicode-aware and would miss it; `(?-u:\b)` spells
        // the ASCII boundary. `(?i)` stays Unicode.
        Regex::new(&format!(
            r#"(?i)(?-u:\b)((?:{SECRET_LABEL_VOCAB})|[A-Za-z0-9_]*_key){SEP_CLASS}*:{SEP_CLASS}*["']?([^\t\n\f\r ,;"'}}]+)["']?"#,
        ))
        .expect("reKeyColon")
    })
}

fn re_key_value() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r"(?i)(?-u:\b)((?:vm_id|node_id|private_key|privateKey|preshared_key|pre_shared_key|password|passwd|auth_token|access_token|hatch_token|api_token|session_key|secret_key|client_secret|token|session|cookie|auth|secret|credential|api_key|apiKey|apikey|access_key|bearer|x-api-key|private-key|hatch_sess|datr)|[A-Za-z0-9_]*_key){SEP_CLASS}*={SEP_CLASS}*[^\t\n\f\r ;&,]*",
        ))
        .expect("reKeyValue")
    })
}

fn re_public_key() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?-u:\b)(public_?key)[\t\n\f\r ]*=[\t\n\f\r ]*([^\t\n\f\r ;&,]*)")
            .expect("rePublicKey")
    })
}

fn re_auth_basic() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)((?:proxy-)?authorization:[\t\n\f\r ]*basic[\t\n\f\r ]+)[^\t\n\f\r ]+")
            .expect("reAuthBasic")
    })
}

fn re_bare_basic() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?-u:\b)(basic[\t\n\f\r ]+)([A-Za-z0-9_+\-/=]{8,})").expect("reBareBasic")
    })
}

fn re_bare_fragment() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"#[A-Za-z0-9_\-./=]{4,}").expect("reBareFragment"))
}

fn re_wg_peer() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"peer\(([A-Za-z0-9+/=]{4})(?:…|\.\.\.)([A-Za-z0-9+/=]{4})\)").expect("reWGPeer")
    })
}

fn re_host_safe() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9._:\[\]-]+$").expect("reHostSafe"))
}

/// Go `strings.ToLower`: simple per-rune folding.
pub(crate) fn go_lower(s: &str) -> String {
    s.chars().flat_map(|c| c.to_lowercase().next()).collect()
}

/// First 8 runes of `key`, plus an ellipsis when longer.
/// Source: `internal/logging/safe.go`, `wgKeyPrefix`.
fn wg_key_prefix(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    if chars.len() <= 8 {
        return key.to_string();
    }
    let mut out: String = chars[..8].iter().collect();
    out.push('…');
    out
}

/// Whether a lower-cased key denotes a WireGuard public key
/// (either spelling), excluding private-key spellings.
/// Source: `internal/logging/safe.go`, `isPublicKeyLabel`.
/// The caller lowercases first; the `Contains` checks here are
/// case-sensitive, exactly as in Go.
fn is_public_key_label(lower_key: &str) -> bool {
    if lower_key.contains("private_key") || lower_key.contains("privatekey") {
        return false;
    }
    lower_key.contains("public_key") || lower_key.contains("publickey")
}

/// Whether `key` is a snake_case key ending in `_key`.
/// Source: `internal/logging/safe.go`, `hasSnakeKeySuffix`.
fn has_snake_key_suffix(key: &str) -> bool {
    let lower = go_lower(key);
    let bytes = lower.as_bytes();
    if bytes.len() <= 4 || !lower.ends_with("_key") {
        return false;
    }
    bytes[..bytes.len() - 4]
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Whether a decoded JSON key is secret-looking.
/// Source: `internal/logging/safe.go`, `isSecretJSONKey`.
fn is_secret_json_key(decoded: &str) -> bool {
    re_secret_key_vocab().is_match(decoded) || has_snake_key_suffix(decoded)
}

// ---------------------------------------------------------------------------
// JSON secret scanner
// ---------------------------------------------------------------------------

/// Slice `s[a..b]`; all scanner indices land on ASCII
/// delimiters in valid UTF-8, so every slice is a char
/// boundary. The `expect` guards an internal invariant, never
/// external input.
fn slice_str(s: &[u8], a: usize, b: usize) -> &str {
    std::str::from_utf8(&s[a..b]).expect("scanner indices are ASCII boundaries")
}

fn parse_hex(s: &[u8]) -> Option<i32> {
    let mut v: i32 = 0;
    for &c in s {
        let d = match c {
            b'0'..=b'9' => (c - b'0') as i32,
            b'a'..=b'f' => (c - b'a') as i32 + 10,
            b'A'..=b'F' => (c - b'A') as i32 + 10,
            _ => return None,
        };
        v = v * 16 + d;
    }
    Some(v)
}

/// Decodes escapes in a quoted JSON key for vocabulary
/// matching only: `\uXXXX`, JSON single-letter escapes, and
/// `%XX`. Malformed escapes stay literal. Surrogates become
/// U+FFFD. The decoded form is never emitted.
/// Source: `internal/logging/safe.go`, `decodeQuotedKey`.
fn decode_quoted_key(raw: &[u8]) -> Vec<u8> {
    if !raw.iter().any(|&b| b == b'\\' || b == b'%') {
        return raw.to_vec();
    }
    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if c == b'\\' && i + 1 < raw.len() {
            let n = raw[i + 1];
            match n {
                b'u' => {
                    if i + 6 <= raw.len()
                        && let Some(v) = parse_hex(&raw[i + 2..i + 6])
                    {
                        let ch = char::from_u32(v as u32).unwrap_or('\u{fffd}');
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        i += 6;
                        continue;
                    }
                    out.push(c);
                    i += 1;
                    continue;
                }
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'b' => out.push(0x08),
                b'f' => out.push(0x0c),
                _ => out.push(n),
            }
            i += 2;
            continue;
        }
        if c == b'%'
            && i + 3 <= raw.len()
            && let Some(v) = parse_hex(&raw[i + 1..i + 3])
        {
            out.push(v as u8);
            i += 3;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Whether `v` is a JSON scalar literal: `true`, `false`,
/// `null`, or a JSON number.
/// Source: `internal/logging/safe.go`, `isJSONScalar`.
fn is_json_scalar(v: &str) -> bool {
    matches!(v, "true" | "false" | "null") || re_json_scalar().is_match(v)
}

/// End index just past the closing quote of the quoted string
/// starting at `s[start]` (quote `q`), and the raw inner
/// content. Backslash escapes consume two bytes; a literal
/// newline is content; only end-of-input fails.
/// Source: `internal/logging/safe.go`, `scanQuoted`.
fn scan_quoted(s: &[u8], start: usize, q: u8) -> Option<(usize, Vec<u8>)> {
    let mut i = start + 1;
    while i < s.len() {
        let c = s[i];
        if c == b'\\' {
            if i + 1 >= s.len() {
                return None;
            }
            i += 2;
            continue;
        }
        if c == q {
            return Some((i + 1, s[start + 1..i].to_vec()));
        }
        i += 1;
    }
    None
}

/// The end index and raw inner content of an escaped-quoted
/// string starting at `s[start]` (`\"` or `\'`): the string
/// ends at an escaped quote pair, and a literal newline or CR
/// fails the scan.
/// Source: `internal/logging/safe.go`, `scanEscapedQuoted`.
fn scan_escaped_quoted(s: &[u8], start: usize, q: u8) -> Option<(usize, Vec<u8>)> {
    let mut i = start + 2;
    while i + 1 < s.len() {
        let c = s[i];
        if c == b'\n' || c == b'\r' {
            return None;
        }
        if c == b'\\' {
            if s[i + 1] == q {
                return Some((i + 2, s[start + 2..i].to_vec()));
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    None
}

fn skip_spaces(s: &[u8], mut j: usize) -> usize {
    while j < s.len() && matches!(s[j], b' ' | b'\t' | b'\n' | b'\r') {
        j += 1;
    }
    j
}

/// The escaped-pair form of one JSON pair starting at an
/// escaped quote: returns the end index and the output text
/// (redacted when the key is secret), or `None` when the shape
/// is not an escaped pair.
/// Source: `internal/logging/safe.go`, `tryEscapedPair`.
fn try_escaped_pair(s: &[u8], i: usize, q: u8) -> Option<(usize, Vec<u8>)> {
    let (key_end, key_raw) = scan_escaped_quoted(s, i, q)?;
    let mut j = skip_spaces(s, key_end);
    if j >= s.len() || s[j] != b':' {
        return None;
    }
    j += 1;
    j = skip_spaces(s, j);
    if j >= s.len() {
        return None;
    }
    let decoded = decode_quoted_key(&key_raw);
    let decoded_str = String::from_utf8_lossy(&decoded);
    let secret = is_secret_json_key(&decoded_str);
    let public = is_public_key_label(&go_lower(&decoded_str));
    if s[j] == b'\\' && j + 1 < s.len() && s[j + 1] == q {
        let (v_end, val_raw) = scan_escaped_quoted(s, j, q)?;
        if !secret {
            return Some((v_end, s[i..v_end].to_vec()));
        }
        let mut out = s[i..j + 2].to_vec();
        if public {
            out.extend_from_slice(wg_key_prefix(slice_str(&val_raw, 0, val_raw.len())).as_bytes());
        } else {
            out.extend_from_slice(b"[redacted]");
        }
        out.extend_from_slice(&s[v_end - 2..v_end]);
        return Some((v_end, out));
    }
    if s[j] == b'{' || s[j] == b'[' {
        return Some((j + 1, s[i..j + 1].to_vec()));
    }
    if s[j] == b'"' || s[j] == b'\'' {
        let (v_end, val_raw) = scan_quoted(s, j, s[j])?;
        if !secret {
            return Some((v_end, s[i..v_end].to_vec()));
        }
        let mut out = s[i..j + 1].to_vec();
        if public {
            out.extend_from_slice(wg_key_prefix(slice_str(&val_raw, 0, val_raw.len())).as_bytes());
        } else {
            out.extend_from_slice(b"[redacted]");
        }
        out.push(s[j]);
        return Some((v_end, out));
    }
    let mut v_end = j;
    while v_end < s.len() && !matches!(s[v_end], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
    {
        v_end += 1;
    }
    let scalar = slice_str(s, j, v_end);
    if secret && is_json_scalar(scalar) {
        let mut out = s[i..j].to_vec();
        if public {
            out.extend_from_slice(wg_key_prefix(scalar).as_bytes());
        } else {
            out.extend_from_slice(b"[redacted]");
        }
        return Some((v_end, out));
    }
    Some((v_end, s[i..v_end].to_vec()))
}

/// Strips secret-keyed JSON values in free-form text: the one
/// mechanism for every key/value quote combination.
/// Source: `internal/logging/safe.go`, `redactJSONSecrets`.
fn redact_json_secrets(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 1 < bytes.len()
            && (bytes[i + 1] == b'"' || bytes[i + 1] == b'\'')
        {
            if let Some((end, text)) = try_escaped_pair(bytes, i, bytes[i + 1]) {
                out.extend_from_slice(&text);
                i = end;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let q = bytes[i];
        if q != b'"' && q != b'\'' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let Some((key_end, key_raw)) = scan_quoted(bytes, i, q) else {
            out.push(bytes[i]);
            i += 1;
            continue;
        };
        let mut j = skip_spaces(bytes, key_end);
        if j >= bytes.len() || bytes[j] != b':' {
            // Not a pair: if the quoted string contains
            // escapes it may enclose escaped pairs — consume
            // only the opening quote and re-scan inside.
            if key_raw.contains(&b'\\') {
                out.push(bytes[i]);
                i += 1;
                continue;
            }
            out.extend_from_slice(&bytes[i..key_end]);
            i = key_end;
            continue;
        }
        j += 1;
        j = skip_spaces(bytes, j);
        if j >= bytes.len() {
            out.extend_from_slice(&bytes[i..key_end]);
            i = key_end;
            continue;
        }
        let decoded = decode_quoted_key(&key_raw);
        let decoded_str = String::from_utf8_lossy(&decoded);
        let secret = is_secret_json_key(&decoded_str);
        let public = is_public_key_label(&go_lower(&decoded_str));
        let vq = bytes[j];
        if vq == b'"' || vq == b'\'' {
            let Some((v_end, val_raw)) = scan_quoted(bytes, j, vq) else {
                out.extend_from_slice(&bytes[i..]);
                break;
            };
            if !secret {
                out.extend_from_slice(&bytes[i..v_end]);
                i = v_end;
                continue;
            }
            out.extend_from_slice(&bytes[i..j + 1]);
            if public {
                out.extend_from_slice(
                    wg_key_prefix(slice_str(&val_raw, 0, val_raw.len())).as_bytes(),
                );
            } else {
                out.extend_from_slice(b"[redacted]");
            }
            out.push(vq);
            i = v_end;
            continue;
        }
        if vq == b'{' || vq == b'[' {
            out.extend_from_slice(&bytes[i..j + 1]);
            i = j + 1;
            continue;
        }
        if vq == b'\\' && j + 1 < bytes.len() && (bytes[j + 1] == b'"' || bytes[j + 1] == b'\'') {
            let Some((v_end, val_raw)) = scan_escaped_quoted(bytes, j, bytes[j + 1]) else {
                out.extend_from_slice(&bytes[i..]);
                break;
            };
            if !secret {
                out.extend_from_slice(&bytes[i..v_end]);
                i = v_end;
                continue;
            }
            out.extend_from_slice(&bytes[i..j + 2]);
            if public {
                out.extend_from_slice(
                    wg_key_prefix(slice_str(&val_raw, 0, val_raw.len())).as_bytes(),
                );
            } else {
                out.extend_from_slice(b"[redacted]");
            }
            out.extend_from_slice(&bytes[v_end - 2..v_end]);
            i = v_end;
            continue;
        }
        let mut v_end = j;
        while v_end < bytes.len()
            && !matches!(
                bytes[v_end],
                b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r'
            )
        {
            v_end += 1;
        }
        let scalar = slice_str(bytes, j, v_end);
        if secret && is_json_scalar(scalar) {
            out.extend_from_slice(&bytes[i..j]);
            if public {
                out.extend_from_slice(wg_key_prefix(scalar).as_bytes());
            } else {
                out.extend_from_slice(b"[redacted]");
            }
            i = v_end;
            continue;
        }
        out.extend_from_slice(&bytes[i..v_end]);
        i = v_end;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

// ---------------------------------------------------------------------------
// Percent-label machinery
// ---------------------------------------------------------------------------

/// Boundary-aware label check for percent-decoded words.
/// Source: `internal/logging/safe.go`, `isSecretPctLabel`.
fn is_secret_pct_label(decoded: &[u8]) -> bool {
    let decoded_str = String::from_utf8_lossy(decoded);
    if has_snake_key_suffix(&decoded_str) {
        return true;
    }
    let lower = go_lower(&decoded_str);
    for label in SECRET_LABEL_VOCAB.split('|') {
        let ll = go_lower(label);
        let mut idx = 0;
        while let Some(pos) = lower[idx..].find(&ll) {
            let abs = idx + pos;
            if abs == 0 || matches!(lower.as_bytes()[abs - 1], b'_' | b'.' | b'-') {
                return true;
            }
            idx = abs + 1;
        }
    }
    false
}

/// Consumes one label word: word characters and `%XX` escapes.
/// Returns the end index, the decoded word bytes, and whether
/// any `%XX` escape was present. Runs over 128 decoded bytes
/// are not labels.
/// Source: `internal/logging/safe.go`, `scanPctWord`.
fn scan_pct_word(s: &[u8], start: usize) -> (usize, Vec<u8>, bool) {
    let mut decoded: Vec<u8> = Vec::new();
    let mut encoded = false;
    let mut i = start;
    while i < s.len() && decoded.len() <= 128 {
        let c = s[i];
        if c == b'%'
            && i + 3 <= s.len()
            && let Some(v) = parse_hex(&s[i + 1..i + 3])
        {
            let v = v as u8;
            if v == b'=' || v == b':' {
                break;
            }
            if v == b'%' && i + 5 <= s.len() {
                let nxt = String::from_utf8_lossy(&s[i + 3..i + 5]).to_lowercase();
                if nxt == "3d" || nxt == "3a" {
                    break;
                }
            }
            decoded.push(v);
            encoded = true;
            i += 3;
            continue;
        }
        if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-') {
            decoded.push(c);
            i += 1;
            continue;
        }
        break;
    }
    if decoded.len() > 128 {
        return (start, Vec::new(), false);
    }
    (i, decoded, encoded)
}

/// The end index and normalised separator when `s[end]` starts
/// a key separator: literal `=`/`:` or a percent-encoded
/// (single or double) `%3D`/`%3A` form, case-insensitive.
/// Source: `internal/logging/safe.go`, `scanPctSep`.
fn scan_pct_sep(s: &[u8], end: usize) -> Option<(usize, u8)> {
    if end >= s.len() {
        return None;
    }
    match s[end] {
        b'=' => return Some((end + 1, b'=')),
        b':' => return Some((end + 1, b':')),
        _ => {}
    }
    let rest = &s[end..];
    let lower: Vec<u8> = rest
        .iter()
        .take(5)
        .map(|b| b.to_ascii_lowercase())
        .collect();
    if lower.starts_with(b"%253d") {
        return Some((end + 5, b'='));
    }
    if lower.starts_with(b"%3d") {
        return Some((end + 3, b'='));
    }
    if lower.starts_with(b"%253a") {
        return Some((end + 5, b':'));
    }
    if lower.starts_with(b"%3a") {
        return Some((end + 3, b':'));
    }
    None
}

/// Rewrites percent-encoded secret labels into their decoded
/// label plus a literal separator, so the later passes strip
/// the value. Only the label and separator bytes are touched.
/// Source: `internal/logging/safe.go`, `normalizePctLabels`.
fn normalize_pct_labels(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if !(c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-' | b'%')) {
            out.push(c);
            i += 1;
            continue;
        }
        let (end, decoded, encoded) = scan_pct_word(bytes, i);
        if end == i || decoded.is_empty() {
            out.push(c);
            i += 1;
            continue;
        }
        let Some((sep_end, sep)) = scan_pct_sep(bytes, end) else {
            out.extend_from_slice(&bytes[i..end]);
            i = end;
            continue;
        };
        if !is_secret_pct_label(&decoded) {
            out.extend_from_slice(&bytes[i..end]);
            i = end;
            continue;
        }
        if !encoded && sep_end == end + 1 && (bytes[end] == b'=' || bytes[end] == b':') {
            // Plain label, literal separator: downstream
            // passes already handle it; leave byte-identical.
            out.extend_from_slice(&bytes[i..end]);
            i = end;
            continue;
        }
        out.extend_from_slice(&decoded);
        out.push(sep);
        i = sep_end;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

// ---------------------------------------------------------------------------
// URL pass + SafeString + SafeHost
// ---------------------------------------------------------------------------

/// Returns `raw` with every query value, userinfo, and fragment
/// replaced by `[redacted]`. A parse failure yields
/// `[redacted-url]`, except for the idempotence retry: text
/// already carrying a marker retries with a parse-safe
/// placeholder, and the placeholder is restored over the whole
/// output.
/// Source: `internal/logging/safe.go`, `redactURLAllQuery`.
fn redact_url_all_query(raw: &str) -> String {
    match parse_url(raw) {
        Ok(u) => u.serialize_redacted(),
        Err(_) => {
            if raw.contains("[redacted]") || raw.contains("<redacted>") {
                let sub = raw
                    .replace("[redacted]", "REDACTED0")
                    .replace("<redacted>", "REDACTED0");
                if let Ok(u2) = parse_url(&sub) {
                    return u2.serialize_redacted().replace("REDACTED0", "[redacted]");
                }
            }
            "[redacted-url]".to_string()
        }
    }
}

/// One bare label: value pair redaction. The label survives
/// with normalised `": "` spacing; a public-key label keeps
/// its first-8-char prefix.
/// Source: `internal/logging/safe.go`, `redactColonSecretMatch`.
fn redact_colon_secret_match(caps: &regex::Captures<'_>) -> String {
    let label = caps.get(1).map_or("", |g| g.as_str());
    let value = caps.get(2).map_or("", |g| g.as_str());
    let lower = go_lower(label);
    if lower == "public_key" || lower == "publickey" {
        format!("{label}: {}", wg_key_prefix(value))
    } else {
        format!("{label}: [redacted]")
    }
}

/// One bare key=value fragment redaction. The label is kept,
/// the value replaced; a public-key label is left unchanged
/// (handled by the earlier public-key pass).
/// Source: `internal/logging/safe.go`, `redactKeyValueMatch`.
fn redact_key_value_match(caps: &regex::Captures<'_>, whole: &str) -> String {
    let label = caps.get(1).map_or("", |g| g.as_str());
    let lower = go_lower(label);
    if lower == "public_key" || lower == "publickey" {
        return whole.to_string();
    }
    format!("{label}=[redacted]")
}

/// Strips credentials from a free-form string for logging: the
/// 12-pass backstop. Empty input stays empty; the transform is
/// idempotent. Ordinary prose, hostnames, and non-secret fields
/// survive byte-identical.
/// Source: `internal/logging/safe.go:883` (`SafeString`).
pub fn safe_string(s: &str) -> String {
    if s.is_empty() {
        return s.to_string();
    }
    let mut s = re_url()
        .replace_all(s, |caps: &regex::Captures<'_>| {
            redact_url_all_query(caps.get(0).map_or("", |g| g.as_str()))
        })
        .into_owned();
    s = re_pct_query()
        .replace_all(&s, |caps: &regex::Captures<'_>| {
            format!("{}=[redacted]", caps.get(1).map_or("", |g| g.as_str()))
        })
        .into_owned();
    s = normalize_pct_labels(&s);
    s = redact_string(&s);
    s = redact_json_secrets(&s);
    s = re_key_colon_full()
        .replace_all(&s, |caps: &regex::Captures<'_>| {
            redact_colon_secret_match(caps)
        })
        .into_owned();
    s = re_public_key()
        .replace_all(&s, |caps: &regex::Captures<'_>| {
            let whole = caps.get(0).map_or("", |g| g.as_str());
            let value = caps.get(2).map_or("", |g| g.as_str());
            // Capture offsets are haystack-relative; make the
            // value start match-relative before slicing `whole`.
            let base = caps.get(0).map_or(0, |g| g.start());
            let value_start = caps.get(2).map_or(whole.len(), |g| g.start() - base);
            format!("{}{}", &whole[..value_start], wg_key_prefix(value))
        })
        .into_owned();
    s = re_key_value()
        .replace_all(&s, |caps: &regex::Captures<'_>| {
            let whole = caps.get(0).map_or("", |g| g.as_str());
            redact_key_value_match(caps, whole)
        })
        .into_owned();
    s = re_auth_basic()
        .replace_all(&s, |caps: &regex::Captures<'_>| {
            format!("{}[redacted]", caps.get(1).map_or("", |g| g.as_str()))
        })
        .into_owned();
    s = re_bare_basic()
        .replace_all(&s, |caps: &regex::Captures<'_>| {
            let whole = caps.get(0).map_or("", |g| g.as_str());
            let token = caps.get(2).map_or("", |g| g.as_str());
            if !token.bytes().any(|b| b.is_ascii_digit()) {
                return whole.to_string();
            }
            let keep = caps.get(1).map_or("", |g| g.as_str());
            format!("{keep}[redacted]")
        })
        .into_owned();
    s = re_bare_fragment()
        .replace_all(&s, "#[redacted]")
        .into_owned();
    s = re_wg_peer()
        .replace_all(&s, |caps: &regex::Captures<'_>| {
            format!("peer({}…)", caps.get(1).map_or("", |g| g.as_str()))
        })
        .into_owned();
    s
}

/// The host-shape rule for dial events: a host-shaped string
/// survives, anything else (including empty) becomes
/// `[redacted]`.
/// Source: `internal/logging/safe.go:1017` (`SafeHost`).
pub fn safe_host(host: &str) -> String {
    if !host.is_empty() && re_host_safe().is_match(host) {
        host.to_string()
    } else {
        "[redacted]".to_string()
    }
}

/// `SafeErr` for an optional error message: `None` (Go nil)
/// stays empty, `Some` text is passed through [`safe_string`].
/// Source: `internal/logging/safe.go:1028` (`SafeErr`).
/// The `Option` shape preserves Go's nil case; R2's `&str`
/// proposal dropped it, and is not followed here.
pub fn safe_err_text(err: Option<&str>) -> String {
    match err {
        None => String::new(),
        Some(msg) => safe_string(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixture values, invented in Go `internal/logging/safe_test.go`
    // (LOGFIX- prefix; never real values). Reused verbatim so
    // absence assertions have the same strength as Go's.
    const FIX_COOKIE: &str = "LOGFIX-SESS-9d2e41";
    const FIX_DATR: &str = "LOGFIX-DATR-51bc07";
    const FIX_ACCESS_TOKEN: &str = "LOGFIX-AT-83af10";
    const FIX_HATCH_TOKEN: &str = "LOGFIX-HT-2c6e88";
    const FIX_BEARER: &str = "LOGFIX-BEARER-1a8f33";
    const FIX_HEADER: &str = "LOGFIX-HDR-77d4e9";
    const FIX_WG_PRIV: &str = "LOGFIX-WGPRIV-6e19d0";
    const FIX_WG_PUB: &str = "LOGFIX-WGPUB-4b77c2";
    const FIX_VMID: &str = "LOGFIX-VMID-22d9f0";
    const FIX_PASSWORD: &str = "LOGFIX-PW-31c7aa";
    const FIX_PROXY_PASS: &str = "LOGFIX-PASS-55aa01";

    fn fix_values() -> [&'static str; 11] {
        [
            FIX_COOKIE,
            FIX_DATR,
            FIX_ACCESS_TOKEN,
            FIX_HATCH_TOKEN,
            FIX_BEARER,
            FIX_HEADER,
            FIX_WG_PRIV,
            FIX_WG_PUB,
            FIX_VMID,
            FIX_PASSWORD,
            FIX_PROXY_PASS,
        ]
    }

    fn assert_no_fixture(got: &str) {
        for v in fix_values() {
            assert!(
                !got.contains(v),
                "SafeString output contains fixture value {v:?} in {got:?}"
            );
        }
    }

    // Ported from Go `TestSafeStringWSURL`.
    #[test]
    fn test_safe_string_ws_url() {
        let input = format!(
            "dial failed: wss://gateway.example.invalid/v1/noise?vm_id={FIX_VMID}&auth_token={FIX_HATCH_TOKEN}"
        );
        let got = safe_string(&input);
        assert_no_fixture(&got);
        assert!(
            got.contains("vm_id=[redacted]") && got.contains("auth_token=[redacted]"),
            "SafeString({input:?}) = {got:?}"
        );
        assert!(
            got.contains("wss://gateway.example.invalid/v1/noise"),
            "SafeString({input:?}) = {got:?}"
        );
    }

    // Ported from Go `TestSafeStringUnknownQueryKey`.
    #[test]
    fn test_safe_string_unknown_query_key() {
        let input = format!("https://example.invalid/cb?session_key={FIX_ACCESS_TOKEN}&next=/ok");
        let got = safe_string(&input);
        assert_no_fixture(&got);
        assert!(
            got.contains("session_key=[redacted]"),
            "SafeString({input:?}) = {got:?}"
        );
    }

    // Ported from Go `TestSafeStringUserinfo`.
    #[test]
    fn test_safe_string_userinfo() {
        let input = format!(
            "proxy https://LOGFIX-USER:{FIX_PROXY_PASS}@proxy.example.invalid:8080 refused"
        );
        let got = safe_string(&input);
        assert_no_fixture(&got);
        assert!(
            got.contains("proxy.example.invalid:8080"),
            "SafeString({input:?}) = {got:?}"
        );
    }

    // Ported from Go `TestSafeStringCookieAndBearer`.
    #[test]
    fn test_safe_string_cookie_and_bearer() {
        let cases = [
            format!("Cookie: hatch_sess={FIX_COOKIE}; datr={FIX_DATR}"),
            format!(r#"{{"hatch_sess": "{FIX_COOKIE}"}}"#),
            format!("Authorization: Bearer {FIX_BEARER}"),
            format!("Bearer {FIX_BEARER} rejected"),
        ];
        for input in cases {
            let got = safe_string(&input);
            assert_no_fixture(&got);
            assert!(
                got.contains("[redacted]"),
                "SafeString({input:?}) = {got:?}"
            );
        }
    }

    // Ported from Go `TestSafeStringJSONSecretFragment`.
    #[test]
    fn test_safe_string_json_secret_fragment() {
        let input = format!(
            r#"server said {{"password": "{FIX_PASSWORD}", "user": "alice"}} and {{"private_key": "{FIX_WG_PRIV}"}}"#
        );
        let got = safe_string(&input);
        assert_no_fixture(&got);
        assert!(
            got.contains(r#""password": "[redacted]""#),
            "SafeString({input:?}) = {got:?}"
        );
        assert!(
            got.contains(r#""private_key": "[redacted]""#),
            "SafeString({input:?}) = {got:?}"
        );
        assert!(
            got.contains(r#""user": "alice""#),
            "SafeString({input:?}) = {got:?}"
        );
    }

    // Ported from Go `TestSafeStringKeyValueFragment`.
    #[test]
    fn test_safe_string_key_value_fragment() {
        let input =
            format!("private_key={FIX_WG_PRIV} public_key={FIX_WG_PUB} api_token={FIX_HEADER}");
        let got = safe_string(&input);
        assert!(!got.contains(FIX_WG_PUB), "SafeString({input:?}) = {got:?}");
        assert!(
            !got.contains(FIX_WG_PRIV),
            "SafeString({input:?}) = {got:?}"
        );
        assert!(
            got.contains("private_key=[redacted]"),
            "SafeString({input:?}) = {got:?}"
        );
        assert!(
            got.contains(&format!("public_key={}", &FIX_WG_PUB[..8])),
            "SafeString({input:?}) = {got:?}"
        );
        assert!(!got.contains(FIX_HEADER), "SafeString({input:?}) = {got:?}");
    }

    // Ported from Go `TestSafeStringWGPublicKeyForms`.
    #[test]
    fn test_safe_string_wg_public_key_forms() {
        let prefix = &FIX_WG_PUB[..8];
        let json_in =
            format!(r#"{{"public_key": "{FIX_WG_PUB}", "private_key": "{FIX_WG_PRIV}"}}"#);
        let got = safe_string(&json_in);
        assert!(
            !got.contains(FIX_WG_PUB) && !got.contains(FIX_WG_PRIV),
            "SafeString({json_in:?}) = {got:?}"
        );
        assert!(got.contains(prefix), "SafeString({json_in:?}) = {got:?}");
        assert!(
            got.contains(r#""private_key": "[redacted]""#),
            "SafeString({json_in:?}) = {got:?}"
        );
        let peer = format!(
            "peer({}…{}) created",
            &FIX_WG_PUB[..4],
            &FIX_WG_PUB[FIX_WG_PUB.len() - 4..]
        );
        let got = safe_string(&peer);
        assert!(
            !(got.contains(&FIX_WG_PUB[FIX_WG_PUB.len() - 4..]) && got.contains("peer(")),
            "SafeString({peer:?}) = {got:?}"
        );
        assert!(
            got.contains(&format!("peer({}…", &FIX_WG_PUB[..4])),
            "SafeString({peer:?}) = {got:?}"
        );
    }

    // Ported from Go `TestSafeStringBareHeaderValue`
    // (negative pin: byte-identical prose).
    #[test]
    fn test_safe_string_bare_header_value() {
        let input = "gateway said hello";
        assert_eq!(safe_string(input), input);
    }

    // Ported from Go `TestSafeStringIdempotent`.
    #[test]
    fn test_safe_string_idempotent() {
        let input = format!(
            "wss://gateway.example.invalid/v1/noise?vm_id={FIX_VMID}&auth_token={FIX_HATCH_TOKEN} {{\"password\": \"{FIX_PASSWORD}\"}}"
        );
        let once = safe_string(&input);
        let twice = safe_string(&once);
        assert_eq!(once, twice, "SafeString not idempotent");
        assert_no_fixture(&twice);
    }

    // Ported from Go `TestSafeHost`.
    #[test]
    fn test_safe_host() {
        for h in [
            "gateway.test",
            "127.0.0.1",
            "[::1]",
            "proxy-sg.example.invalid",
            "a-b_c.example",
        ] {
            assert_eq!(safe_host(h), h, "SafeHost({h:?})");
        }
        let bad = [
            String::new(),
            format!("https://gateway.example.invalid/v1/noise?vm_id={FIX_VMID}"),
            format!("host?token={FIX_HATCH_TOKEN}"),
            "user:pass@host".to_string(),
            "ho st".to_string(),
            "a=b".to_string(),
        ];
        for h in bad {
            assert_eq!(safe_host(&h), "[redacted]", "SafeHost({h:?})");
        }
    }

    // Ported from Go `TestSafeErrNilAndPlain`.
    #[test]
    fn test_safe_err_nil_and_plain() {
        assert_eq!(safe_err_text(None), "");
        assert_eq!(
            safe_err_text(Some("connection refused")),
            "connection refused"
        );
        let err = format!(
            "handshake: wss://gateway.example.invalid/v1/noise?vm_id={FIX_VMID}&auth_token={FIX_HATCH_TOKEN}"
        );
        assert_no_fixture(&safe_err_text(Some(&err)));
    }

    // Ported from Go `TestSafeStringTwelveServerShapes`.
    #[test]
    fn test_safe_string_twelve_server_shapes() {
        const COLON_VAL: &str = "LOGFIX-COLON-2c6e88";
        const SINGLE_VAL: &str = "LOGFIX-SINGLE-51bc07";
        const BASIC_VAL: &str = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==";
        const PCT_VAL: &str = "LOGFIX-PCT-83af10";
        const FRAG_VAL: &str = "LOGFIX-FRAG-9d2e41";
        const AUTH_VAL: &str = "LOGFIX-AUTH-77d4e9";
        const SECRET_VAL: &str = "LOGFIX-SECRET-22d9f0";
        struct Shape {
            name: &'static str,
            inputs: Vec<String>,
            forbidden: Vec<String>,
            want_prefix: &'static str,
            want_marker: bool,
        }
        let shapes = vec![
            Shape {
                name: "camelCase-privateKey-JSON",
                inputs: vec![format!(r#"{{"privateKey": "{FIX_WG_PRIV}"}}"#)],
                forbidden: vec![FIX_WG_PRIV.to_string()],
                want_prefix: "",
                want_marker: true,
            },
            Shape {
                name: "camelCase-publicKey-JSON",
                inputs: vec![format!(r#"{{"publicKey": "{FIX_WG_PUB}"}}"#)],
                forbidden: vec![FIX_WG_PUB.to_string()],
                want_prefix: &FIX_WG_PUB[..8],
                want_marker: false,
            },
            Shape {
                name: "colon-form",
                inputs: vec![
                    format!("private_key: {COLON_VAL}"),
                    format!("privateKey: {COLON_VAL}"),
                ],
                forbidden: vec![COLON_VAL.to_string()],
                want_prefix: "",
                want_marker: true,
            },
            Shape {
                name: "single-quote-JSON",
                inputs: vec![format!("{{'token': '{SINGLE_VAL}'}}")],
                forbidden: vec![SINGLE_VAL.to_string()],
                want_prefix: "",
                want_marker: true,
            },
            Shape {
                name: "authorization-basic",
                inputs: vec![
                    format!("Authorization: Basic {BASIC_VAL}"),
                    format!("Basic {BASIC_VAL} rejected"),
                ],
                forbidden: vec![BASIC_VAL.to_string()],
                want_prefix: "",
                want_marker: true,
            },
            Shape {
                name: "percent-encoded-equals-query",
                inputs: vec![
                    format!("https://example.invalid/cb?auth_token%3D{PCT_VAL}"),
                    format!("?auth_token%3D{PCT_VAL}"),
                ],
                forbidden: vec![PCT_VAL.to_string()],
                want_prefix: "",
                want_marker: true,
            },
            Shape {
                name: "bare-fragment",
                inputs: vec![
                    format!("https://example.invalid/reset#{FRAG_VAL}"),
                    format!("see #{FRAG_VAL}"),
                ],
                forbidden: vec![FRAG_VAL.to_string()],
                want_prefix: "",
                want_marker: false,
            },
            Shape {
                name: "bare-auth-equals",
                inputs: vec![format!("auth={AUTH_VAL}")],
                forbidden: vec![AUTH_VAL.to_string()],
                want_prefix: "",
                want_marker: true,
            },
            Shape {
                name: "bare-secret-equals",
                inputs: vec![
                    format!("secret={SECRET_VAL}"),
                    format!("api_key={SECRET_VAL}"),
                ],
                forbidden: vec![SECRET_VAL.to_string()],
                want_prefix: "",
                want_marker: true,
            },
            Shape {
                name: "double-quote-JSON-token (derived: already stripped)",
                inputs: vec![format!(r#"{{"token": "{FIX_ACCESS_TOKEN}"}}"#)],
                forbidden: vec![FIX_ACCESS_TOKEN.to_string()],
                want_prefix: "",
                want_marker: true,
            },
            Shape {
                name: "bare-keyvalue-token (derived: already stripped)",
                inputs: vec![format!("token={FIX_ACCESS_TOKEN}")],
                forbidden: vec![FIX_ACCESS_TOKEN.to_string()],
                want_prefix: "",
                want_marker: true,
            },
            Shape {
                name: "bearer (derived: already stripped)",
                inputs: vec![format!("Authorization: Bearer {FIX_BEARER}")],
                forbidden: vec![FIX_BEARER.to_string()],
                want_prefix: "",
                want_marker: true,
            },
        ];
        for sh in shapes {
            for input in &sh.inputs {
                let got = safe_string(input);
                for v in &sh.forbidden {
                    assert!(
                        !got.contains(v.as_str()),
                        "SafeString({input:?}) = {got:?}, want {v:?} absent"
                    );
                }
                if !sh.want_prefix.is_empty() {
                    assert!(
                        got.contains(sh.want_prefix),
                        "SafeString({input:?}) = {got:?}, want prefix {:?}",
                        sh.want_prefix
                    );
                }
                if sh.want_marker {
                    assert!(
                        got.contains("[redacted]"),
                        "SafeString({input:?}) = {got:?}, want a [redacted] marker"
                    );
                }
                if sh.name == "bare-fragment" {
                    assert!(
                        got.contains("#[redacted]") || got.contains("#%5Bredacted%5D"),
                        "SafeString({input:?}) = {got:?}, want a redacted fragment marker"
                    );
                }
            }
        }
    }

    // Ported from Go `TestSafeStringJSONQuoteCombinations`.
    #[test]
    fn test_safe_string_json_quote_combinations() {
        const VAL: &str = "LOGFIX-QUOTECOMB-83af10";
        let cases = [
            ("double-double", format!(r#"{{"token": "{VAL}"}}"#)),
            ("single-single", format!("{{'token': '{VAL}'}}")),
            ("double-single", format!(r#"{{"token": '{VAL}'}}"#)),
            ("single-double", format!(r#"{{'token': "{VAL}"}}"#)),
            (
                "double-single-spaces",
                format!(r#"{{ "token" : '{VAL}' }}"#),
            ),
            (
                "single-double-spaces",
                format!(r#"{{ 'token' : "{VAL}" }}"#),
            ),
        ];
        for (name, input) in cases {
            let got = safe_string(&input);
            assert!(
                !got.contains(VAL),
                "SafeString({input:?}) = {got:?} (case {name})"
            );
            assert!(
                got.contains("[redacted]"),
                "SafeString({input:?}) = {got:?} (case {name})"
            );
            assert!(
                got.contains("token"),
                "SafeString({input:?}) = {got:?} (case {name})"
            );
        }
        let plain = r#"{"name": "Alice", 'city': 'Lisbon'}"#;
        assert_eq!(safe_string(plain), plain, "non-secret JSON changed");
        let apos = safe_string(r#"{"token": "LOGFIX-APOS-77d4e9don't"}"#);
        assert!(
            !apos.contains("LOGFIX-APOS-77d4e9") && !apos.contains("don't"),
            "apostrophe value not stripped in full: {apos:?}"
        );
    }

    // Ported from Go `TestSafeStringUnicodeEscapedKeys`.
    #[test]
    fn test_safe_string_unicode_escaped_keys() {
        const VAL: &str = "LOGFIX-UNIESC-22d9f0";
        let cases = [
            format!(r#"{{"tok\u0065n": "{VAL}"}}"#),
            format!(r#"{{"\u0074oken": "{VAL}"}}"#),
            format!(r#"{{"tok\u0065\u006e": "{VAL}"}}"#),
            format!(r#"{{"TOK\u0045N": "{VAL}"}}"#),
            format!(r#"{{'tok\u0065n': '{VAL}'}}"#),
        ];
        for input in cases {
            let got = safe_string(&input);
            assert!(!got.contains(VAL), "SafeString({input:?}) = {got:?}");
        }
        let plain = r#"{"na\u006de": "Alice"}"#;
        assert_eq!(safe_string(plain), plain, "non-secret escaped key changed");
    }

    // Ported from Go `TestSafeStringJSONScalarValues`.
    #[test]
    fn test_safe_string_json_scalar_values() {
        let cases: [(&str, String, &str); 10] = [
            (
                "string",
                r#"{"token": "LOGFIX-SCALAR-83af10"}"#.to_string(),
                "LOGFIX-SCALAR-83af10",
            ),
            (
                "integer",
                r#"{"token": 987654321}"#.to_string(),
                "987654321",
            ),
            (
                "float",
                r#"{"token": 98765.4321}"#.to_string(),
                "98765.4321",
            ),
            (
                "negative",
                r#"{"token": -987654321}"#.to_string(),
                "-987654321",
            ),
            ("exponent", r#"{"token": 9.876e8}"#.to_string(), "9.876e8"),
            ("bool-true", r#"{"token": true}"#.to_string(), "true"),
            ("bool-false", r#"{"secret": false}"#.to_string(), "false"),
            ("null", r#"{"token": null}"#.to_string(), "null"),
            (
                "numeric-single-quote",
                r#"{'token': 987654321}"#.to_string(),
                "987654321",
            ),
            (
                "numeric-publicKey-prefix",
                r#"{"publicKey": 98765432109}"#.to_string(),
                "98765432109",
            ),
        ];
        for (name, input, absent) in cases {
            let got = safe_string(&input);
            assert!(
                !got.contains(absent),
                "SafeString({input:?}) = {got:?} (case {name})"
            );
            if name != "numeric-publicKey-prefix" {
                assert!(
                    got.contains("[redacted]"),
                    "SafeString({input:?}) = {got:?} (case {name})"
                );
            }
        }
        let got = safe_string(r#"{"publicKey": 98765432109}"#);
        assert!(
            got.contains("98765432") && !got.contains("98765432109"),
            "publicKey numeric value = {got:?}"
        );
        let plain = r#"{"count": 42, "ratio": 1.5}"#;
        assert_eq!(safe_string(plain), plain, "non-secret numeric JSON changed");
    }

    // Ported from Go `TestSafeStringDigitlessFragments`.
    #[test]
    fn test_safe_string_digitless_fragments() {
        let cases: [(&str, &str, &str); 4] = [
            (
                "digitless-long",
                "see #LOGFIXFRAG-abcdef",
                "LOGFIXFRAG-abcdef",
            ),
            ("digitless-mixed", "see #abcdef-ghijkl", "abcdef-ghijkl"),
            ("digit-long", "see #LOGFIXFRAG-123456", "LOGFIXFRAG-123456"),
            (
                "digitless-url",
                "https://example.invalid/reset#LOGFIXFRAG-abcdef",
                "LOGFIXFRAG-abcdef",
            ),
        ];
        for (name, input, absent) in cases {
            let got = safe_string(input);
            assert!(
                !got.contains(absent),
                "SafeString({input:?}) = {got:?} (case {name})"
            );
            assert!(
                got.contains("#[redacted]") || got.contains("#%5Bredacted%5D"),
                "SafeString({input:?}) = {got:?} (case {name})"
            );
        }
        let plain = "see #abc and issue #42";
        assert_eq!(safe_string(plain), plain, "short fragments changed");
    }

    // Ported from Go `TestSafeStringPercentEncodedKeyNames`.
    #[test]
    fn test_safe_string_percent_encoded_key_names() {
        const VAL: &str = "LOGFIX-PCTKEY-51bc07";
        let cases = [
            format!("%61uth_token={VAL}"),
            format!("%61uth_token%3D{VAL}"),
            format!("%61uth_token%253D{VAL}"),
            format!("auth_token%3D{VAL}"),
            format!("auth%5Ftoken={VAL}"),
            format!("%74oken={VAL}"),
            format!("%74oken%3D{VAL}"),
            format!("%74oken%3A {VAL}"),
            format!("%70assword={VAL}"),
        ];
        for input in cases {
            let got = safe_string(&input);
            assert!(!got.contains(VAL), "SafeString({input:?}) = {got:?}");
        }
        let plain = "%6Eext=/ok";
        assert_eq!(safe_string(plain), plain, "non-secret encoded key changed");
    }

    // Ported from Go `TestSafeStringEscapedQuoteJSON`.
    #[test]
    fn test_safe_string_escaped_quote_json() {
        const VAL: &str = "LOGFIX-ESCQ-83af10";
        let cases = [
            format!(r#"conn: gateway status=500 payload="{{\"token\": \"{VAL}\"}}""#),
            format!(r#"conn: gateway status=500 payload="{{\"token\": '{VAL}'}}""#),
            format!(r#"{{"tok\u0065n": \"{VAL}\"}}"#),
            r#"payload="{\"token\": 987654321}""#.to_string(),
        ];
        for input in cases {
            let got = safe_string(&input);
            assert!(
                !got.contains(VAL) && !got.contains("987654321"),
                "SafeString({input:?}) = {got:?}"
            );
            assert!(
                got.contains("[redacted]"),
                "SafeString({input:?}) = {got:?}"
            );
        }
        let plain = r#"payload="{\"name\": \"Alice\"}""#;
        assert_eq!(safe_string(plain), plain, "non-secret escaped JSON changed");
    }

    // Ported from Go `TestSafeStringIdempotentUserinfoURL`.
    #[test]
    fn test_safe_string_idempotent_userinfo_url() {
        let input = "see https://user:s3cret@example.com/x?auth_token=tok123";
        let once = safe_string(input);
        assert!(once.contains("example.com"), "first pass {once:?}");
        assert!(
            !once.contains("s3cret") && !once.contains("tok123"),
            "first pass {once:?} leaks fixture values"
        );
        let twice = safe_string(&once);
        assert_eq!(once, twice, "SafeString not idempotent for a userinfo URL");
    }

    // Ported from Go `TestSafeStringLoop7Separators`
    // (exact-equality table).
    #[test]
    fn test_safe_string_loop7_separators() {
        let cases: [(&str, &str, &str); 10] = [
            (
                "nbsp-equals-before",
                "token\u{a0}=LOGFIX-SEP-1",
                "token=[redacted]",
            ),
            (
                "emspace-equals-before",
                "token\u{2003}=LOGFIX-SEP-2",
                "token=[redacted]",
            ),
            (
                "vtab-equals-before",
                "token\u{0b}=LOGFIX-SEP-3",
                "token=[redacted]",
            ),
            (
                "nbsp-colon-before",
                "token\u{a0}:LOGFIX-SEP-4",
                "token: [redacted]",
            ),
            (
                "emspace-colon-before",
                "token\u{2003}:LOGFIX-SEP-5",
                "token: [redacted]",
            ),
            (
                "vtab-colon-before",
                "token\u{0b}:LOGFIX-SEP-6",
                "token: [redacted]",
            ),
            (
                "nbsp-equals-after",
                "token=\u{a0}LOGFIX-SEP-7",
                "token=[redacted]",
            ),
            (
                "emspace-colon-after",
                "token:\u{2003}LOGFIX-SEP-8",
                "token: [redacted]",
            ),
            ("plain-equals", "token=LOGFIX-SEP-9", "token=[redacted]"),
            ("plain-colon", "token: LOGFIX-SEP-10", "token: [redacted]"),
        ];
        for (name, input, want) in cases {
            assert_eq!(safe_string(input), want, "case {name}");
        }
        let plain = "hello\u{a0}world and a\u{2003}b";
        assert_eq!(
            safe_string(plain),
            plain,
            "wider separator class over-redacted prose"
        );
    }

    // Ported from Go `TestSafeStringLoop7NewlineJSONValue`
    // (exact-equality table).
    #[test]
    fn test_safe_string_loop7_newline_json_value() {
        let cases: [(&str, &str, &str); 4] = [
            (
                "double-quoted",
                "{\"token\": \"LOGFIX-NL-1\nTAIL\"}",
                "{\"token\": \"[redacted]\"}",
            ),
            (
                "single-quoted",
                "{'token': 'LOGFIX-NL-2\nTAIL'}",
                "{'token': '[redacted]'}",
            ),
            (
                "newline-in-key",
                "{\"tok\nen\": \"x\"}",
                "{\"tok\nen\": \"x\"}",
            ),
            (
                "non-secret-newline",
                "{\"name\": \"Alice\nBob\"}",
                "{\"name\": \"Alice\nBob\"}",
            ),
        ];
        for (name, input, want) in cases {
            assert_eq!(safe_string(input), want, "case {name}");
        }
    }

    // Ported from Go `TestSafeStringListedVocabulary`
    // (`internal/logging/allowlist_test.go`, 45 cases). The
    // companion `TestSafeErrForLevelTraceIsSummary` in that file
    // needs sing-box log levels and `SafeErrForLevel` and is
    // excluded as Go-only; see PORTING.md.
    #[test]
    fn test_safe_string_listed_vocabulary() {
        const VAL: &str = "ALLOW5VOCAB-7f3a91";
        let cases: [(&str, String); 45] = [
            ("session_key JSON", format!(r#"{{"session_key": "{VAL}"}}"#)),
            (
                "session_key single-quote JSON",
                format!("{{'session_key': '{VAL}'}}"),
            ),
            ("session_key colon", format!("session_key: {VAL}")),
            ("session_key equals", format!("session_key={VAL}")),
            ("api_key JSON", format!(r#"{{"api_key": "{VAL}"}}"#)),
            (
                "api_key single-quote JSON",
                format!("{{'api_key': '{VAL}'}}"),
            ),
            ("api_key colon", format!("api_key: {VAL}")),
            ("api_key equals", format!("api_key={VAL}")),
            ("access_key JSON", format!(r#"{{"access_key": "{VAL}"}}"#)),
            (
                "access_key single-quote JSON",
                format!("{{'access_key': '{VAL}'}}"),
            ),
            ("access_key colon", format!("access_key: {VAL}")),
            ("access_key equals", format!("access_key={VAL}")),
            (
                "generic _key JSON",
                format!(r#"{{"encryption_key": "{VAL}"}}"#),
            ),
            (
                "generic _key single-quote JSON",
                format!("{{'signing_key': '{VAL}'}}"),
            ),
            ("generic _key colon", format!("encryption_key: {VAL}")),
            ("generic _key equals", format!("signing_key={VAL}")),
            ("private-key JSON", format!(r#"{{"private-key": "{VAL}"}}"#)),
            ("private-key colon", format!("private-key: {VAL}")),
            ("private-key equals", format!("private-key={VAL}")),
            ("bearer JSON", format!(r#"{{"bearer": "{VAL}"}}"#)),
            ("bearer single-quote JSON", format!("{{'bearer': '{VAL}'}}")),
            ("bearer colon", format!("bearer: {VAL}")),
            ("bearer equals", format!("bearer={VAL}")),
            ("x-api-key JSON", format!(r#"{{"x-api-key": "{VAL}"}}"#)),
            (
                "x-api-key single-quote JSON",
                format!("{{'x-api-key': '{VAL}'}}"),
            ),
            ("x-api-key colon", format!("x-api-key: {VAL}")),
            ("x-api-key equals", format!("x-api-key={VAL}")),
            (
                "preshared_key JSON",
                format!(r#"{{"preshared_key": "{VAL}"}}"#),
            ),
            ("preshared_key colon", format!("preshared_key: {VAL}")),
            ("preshared_key equals", format!("preshared_key={VAL}")),
            (
                "pre_shared_key JSON",
                format!(r#"{{"pre_shared_key": "{VAL}"}}"#),
            ),
            ("pre_shared_key colon", format!("pre_shared_key: {VAL}")),
            ("pre_shared_key equals", format!("pre_shared_key={VAL}")),
            ("session JSON", format!(r#"{{"session": "{VAL}"}}"#)),
            (
                "session single-quote JSON",
                format!("{{'session': '{VAL}'}}"),
            ),
            ("session colon", format!("session: {VAL}")),
            ("session equals", format!("session={VAL}")),
            ("hatch_sess JSON", format!(r#"{{"hatch_sess": "{VAL}"}}"#)),
            (
                "hatch_sess single-quote JSON",
                format!("{{'hatch_sess': '{VAL}'}}"),
            ),
            ("hatch_sess colon", format!("hatch_sess: {VAL}")),
            ("hatch_sess equals", format!("hatch_sess={VAL}")),
            ("datr JSON", format!(r#"{{"datr": "{VAL}"}}"#)),
            ("datr single-quote JSON", format!("{{'datr': '{VAL}'}}")),
            ("datr colon", format!("datr: {VAL}")),
            ("datr equals", format!("datr={VAL}")),
        ];
        for (name, input) in cases {
            let got = safe_string(&input);
            assert!(!got.is_empty(), "SafeString({input:?}) empty (case {name})");
            assert!(
                !got.contains(VAL),
                "SafeString({input:?}) = {got:?} (case {name})"
            );
            assert!(
                got.contains("[redacted]"),
                "SafeString({input:?}) = {got:?} (case {name})"
            );
        }
    }
}
