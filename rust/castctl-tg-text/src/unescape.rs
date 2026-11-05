// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

// HTML entity unescaping: a byte-level port of Go's `html.UnescapeString`
// (`html/escape.go`, `unescapeEntity`), driven by the mechanically
// extracted tables in `entities.rs`.
//
// The algorithm is reproduced step for step, including its quirks:
// numeric references need no trailing `;`; `&#x;` decodes to U+FFFD
// (zero hex digits still counts as "matched"); legacy names without
// `;` resolve only for the short prefix list (at most 6 bytes);
// surrogate / out-of-range / zero code points become U+FFFD;
// U+0080..=U+009F go through the Windows-1252 replacement table;
// numeric accumulation wraps at 32 bits exactly as Go's `rune` does.

use crate::entities::{ENTITY, ENTITY2, REPLACEMENT_TABLE};

/// Unescapes HTML entities in `s`, mirroring Go `html.UnescapeString`.
/// Source: Go `html/escape.go`, `UnescapeString` + `unescapeEntity`.
/// Only used by [`crate::strip_tags`].
pub(crate) fn unescape_html(s: &str) -> String {
    let bytes = s.as_bytes();
    let Some(first) = bytes.iter().position(|&b| b == b'&') else {
        return s.to_string();
    };
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..first]);
    let mut src = first;
    while src < bytes.len() {
        if bytes[src] != b'&' {
            out.push(bytes[src]);
            src += 1;
            continue;
        }
        let (decoded, consumed) = unescape_entity(&bytes[src..]);
        out.extend_from_slice(&decoded);
        src += consumed;
    }
    // The input is valid UTF-8 and every decoded unit is valid UTF-8,
    // so the output is valid UTF-8. The lossy conversion is unreachable
    // in practice; it exists only to keep this total.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// One `unescapeEntity` step over `s` (which starts at `&`).
/// Returns the decoded bytes and how many input bytes were consumed.
fn unescape_entity(s: &[u8]) -> (Vec<u8>, usize) {
    // `i` starts at 1 because s[0] == '&'.
    if s.len() <= 1 {
        return (vec![b'&'], 1);
    }
    if s[1] == b'#' {
        // Numeric reference. At least "&#." must be present.
        if s.len() <= 3 {
            return (vec![b'&'], 1);
        }
        let mut i = 2usize;
        let mut hex = false;
        if s[i] == b'x' || s[i] == b'X' {
            hex = true;
            i += 1;
        }
        let mut x: i32 = 0;
        while i < s.len() {
            let c = s[i];
            i += 1;
            if hex {
                if c.is_ascii_digit() {
                    x = x.wrapping_mul(16).wrapping_add((c - b'0') as i32);
                    continue;
                } else if (b'a'..=b'f').contains(&c) {
                    x = x.wrapping_mul(16).wrapping_add((c - b'a') as i32 + 10);
                    continue;
                } else if (b'A'..=b'F').contains(&c) {
                    x = x.wrapping_mul(16).wrapping_add((c - b'A') as i32 + 10);
                    continue;
                }
            } else if c.is_ascii_digit() {
                x = x.wrapping_mul(10).wrapping_add((c - b'0') as i32);
                continue;
            }
            if c != b';' {
                i -= 1;
            }
            break;
        }
        // `i <= 3` means no digits matched (`&#;`, `&#x;` with the
        // terminator consumed still has i == 4, so only the no-digit
        // shapes land here... except `&#x` at end of input, where the
        // loop exits with i == 3).
        if i <= 3 {
            return (vec![b'&'], 1);
        }
        if (0x80..=0x9f).contains(&x) {
            x = REPLACEMENT_TABLE[(x - 0x80) as usize] as i32;
        } else if x == 0 || (0xd800..=0xdfff).contains(&x) || x > 0x10ffff {
            x = '\u{fffd}' as i32;
        }
        let ch = char::from_u32(x as u32).unwrap_or('\u{fffd}');
        let mut buf = [0u8; 4];
        let encoded = ch.encode_utf8(&mut buf);
        return (encoded.as_bytes().to_vec(), i);
    }

    // Named reference: consume the longest run of ASCII alphanumerics
    // plus one trailing `;` when present.
    let mut i = 1usize;
    while i < s.len() {
        let c = s[i];
        i += 1;
        if c.is_ascii_alphanumeric() {
            continue;
        }
        if c != b';' {
            i -= 1;
        }
        break;
    }
    let name = &s[1..i];
    if name.is_empty() {
        return (s[..i].to_vec(), i);
    }
    if let Ok(idx) = ENTITY.binary_search_by(|e| e.0.as_bytes().cmp(name)) {
        let mut buf = [0u8; 4];
        let encoded = ENTITY[idx].1.encode_utf8(&mut buf);
        return (encoded.as_bytes().to_vec(), i);
    }
    if let Ok(idx) = ENTITY2.binary_search_by(|e| e.0.as_bytes().cmp(name)) {
        let (a, b) = ENTITY2[idx].1;
        let mut out = Vec::with_capacity(8);
        let mut buf = [0u8; 4];
        out.extend_from_slice(a.encode_utf8(&mut buf).as_bytes());
        out.extend_from_slice(b.encode_utf8(&mut buf).as_bytes());
        return (out, i);
    }
    // Legacy fallback: longest prefix of at most 6 bytes, no `;`.
    let mut max_len = name.len().saturating_sub(1);
    if max_len > 6 {
        max_len = 6;
    }
    let mut j = max_len;
    while j > 1 {
        let prefix = &name[..j];
        if let Ok(idx) = ENTITY.binary_search_by(|e| e.0.as_bytes().cmp(prefix)) {
            let mut buf = [0u8; 4];
            let encoded = ENTITY[idx].1.encode_utf8(&mut buf);
            return (encoded.as_bytes().to_vec(), j + 1);
        }
        j -= 1;
    }
    // No match: copy the `&...` span verbatim.
    (s[..i].to_vec(), i)
}

#[cfg(test)]
mod probes {
    use super::*;

    // Differential probes (NOT ported Go cases): inputs measured
    // against Go `html.UnescapeString` on cue, probe rounds 1-2.
    #[test]
    fn probe_unescape_corpus() {
        let cases: &[(&str, &str)] = &[
            ("&amp;", "&"),
            ("&lt;", "<"),
            ("&gt;", ">"),
            ("&quot;", "\""),
            ("&apos;", "'"),
            ("&nbsp;", "\u{a0}"),
            ("&copy;", "©"),
            ("&reg;", "®"),
            ("&#65;", "A"),
            ("&#x41;", "A"),
            ("&#X41;", "A"),
            ("&#0;", "\u{fffd}"),
            ("&#xD800;", "\u{fffd}"),
            ("&#x110000;", "\u{fffd}"),
            ("&#xZZ;", "&#xZZ;"),
            ("&#;", "&#;"),
            ("&#x;", "\u{fffd}"),
            ("&unknown;", "&unknown;"),
            ("&amp;amp;", "&amp;"),
            ("&amp", "&"),
            ("&copy", "©"),
            ("&ampx;", "&x;"),
            ("&#97;", "a"),
            ("&#x61;", "a"),
            ("&#x00000041;", "A"),
            ("&AMP;", "&"),
            ("&Lt;", "≪"),
            ("&Tab;", "\t"),
            ("&NewLine;", "\n"),
            ("&fjlig;", "fj"),
            ("&frac12;", "½"),
            ("&hellip;", "…"),
            ("&mdash;", "—"),
            ("&notanentity123;", "¬anentity123;"),
            ("&#65", "A"),
            ("&#x41", "A"),
            ("&#65x", "Ax"),
            ("&#x41x", "Ax"),
            ("&amp ", "& "),
            ("&notit;", "¬it;"),
            ("&frac12", "½"),
            ("&hellipx", "&hellipx"),
            ("&Tabx", "&Tabx"),
            ("&#xD83D;&#xDE00;", "\u{fffd}\u{fffd}"),
            ("&nbsp", "\u{a0}"),
            ("&not", "¬"),
            ("&ampx", "&x"),
            ("&notin;", "∉"),
            ("&a;", "&a;"),
            ("&sup1", "¹"),
            ("&frac34;", "¾"),
            ("&fjlig", "&fjlig"),
            ("&#X41;", "A"),
            ("&#x00041;", "A"),
            ("&#0000065;", "A"),
            ("&#x80;", "€"),
            ("&#x9F;", "Ÿ"),
            ("&#128;", "€"),
            ("&#159;", "Ÿ"),
            ("&#13;", "\r"),
        ];
        for (input, want) in cases {
            assert_eq!(unescape_html(input), *want, "unescape {input:?}");
        }
    }
}
