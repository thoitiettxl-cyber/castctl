//! Go string helpers: trimming, case folding, `%q` quoting, and
//! integer parsing, mirroring the Go standard library behaviour the
//! config parser depends on.
//!
//! Sources (base `dev-rust` `85a8d5e`): `strings.TrimSpace` /
//! `strings.ToLower` (Go stdlib), `strconv.Quote` / `strconv.QuoteRune`
//! (Go stdlib), `strconv.ParseInt` (Go stdlib, via
//! `json.Number.Int64` in `internal/profile/jsonvalue.go`).

/// Go `strings.TrimSpace`: cut leading/trailing Unicode spaces.
///
/// Source: Go stdlib `strings.TrimSpace` (unicode.IsSpace). M1
/// established `char::is_whitespace` equals `unicode.IsSpace`.
pub fn go_trim_space(s: &str) -> &str {
    s.trim_matches(char::is_whitespace)
}

/// Go `strings.ToLower`: simple per-rune folding, first char of each
/// rune's lowercase mapping (so `İ` folds to `i`, with no final
/// sigma). Mirrors the M1 `go_lower` precedent.
///
/// Source: Go stdlib `strings.ToLower`.
pub fn go_lower(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let mut lower = ch.to_lowercase();
        match lower.next() {
            Some(first) => out.push(first),
            None => out.push(ch),
        }
    }
    out
}

/// Whether a rune is printable in Go's `strconv.IsPrint` sense, as
/// approximated without Unicode category tables: control characters,
/// separator characters (Zs/Zl/Zp), and a set of format characters
/// (Cf) are not printable; everything else is treated as printable.
/// The Zs/Zl/Zp set is probe-verified on cue against
/// `strconv.IsPrint` (U+00A0, U+1680, U+2000–U+200A, U+2028,
/// U+2029, U+202F, U+205F, U+3000); other unprobed categories
/// (private-use, unassigned) remain an approximation (see
/// PORTING.md). ASCII behaviour is exact.
///
/// Source: Go stdlib `strconv.IsPrint` (approximation; see PORTING.md).
fn go_is_print(c: char) -> bool {
    if c.is_control() {
        return false;
    }
    // Separator characters Go's IsPrint rejects (Zs/Zl/Zp), plus
    // format characters (Cf) and friends. U+00AD soft hyphen and
    // U+FEFF are the common Cf cases.
    !matches!(
        c,
        '\u{00a0}'
            | '\u{00ad}'
            | '\u{061c}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202a}'..='\u{202e}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{2060}'..='\u{2064}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// Go `%q` for a string: double-quoted Go string literal.
///
/// Source: Go stdlib `strconv.Quote`. Only `\n`, `\r`, `\t` get named
/// escapes among the C0 controls; `\a`, `\b`, `\f`, `\v` use their
/// short forms; other non-printable runes use `\x..`, `\u....`, or
/// `\U........` by size.
pub fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if go_is_print(c) => out.push(c),
            c => {
                let n = c as u32;
                if n < 0x80 {
                    out.push_str(&format!("\\x{n:02x}"));
                } else if n <= 0xffff {
                    out.push_str(&format!("\\u{n:04x}"));
                } else {
                    out.push_str(&format!("\\U{n:08x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

/// Go `quoteChar`: a byte rendered as a single-quoted rune, the form
/// `encoding/json` uses in `invalid character %c` messages. The byte
/// is treated as a Latin-1 rune (so byte `0xFF` renders as `ÿ`).
/// `"` renders unescaped (`'"'`); `'` renders escaped (`'\''`).
///
/// Source: Go stdlib `encoding/json` `quoteChar` (`scanner.go`).
pub fn go_quote_char(b: u8) -> String {
    let c = b as char;
    let mut out = String::with_capacity(6);
    out.push('\'');
    match c {
        '\'' => out.push_str("\\'"),
        '"' => out.push('"'),
        '\\' => out.push_str("\\\\"),
        '\u{7}' => out.push_str("\\a"),
        '\u{8}' => out.push_str("\\b"),
        '\u{c}' => out.push_str("\\f"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        '\u{b}' => out.push_str("\\v"),
        c if b < 0x80 && go_is_print(c) => out.push(c),
        c if (0xa1..=0xff).contains(&b) && b != 0xad => out.push(c),
        c => {
            let n = c as u32;
            if n < 0x80 {
                out.push_str(&format!("\\x{n:02x}"));
            } else {
                out.push_str(&format!("\\u{n:04x}"));
            }
        }
    }
    out.push('\'');
    out
}

/// Go `strconv.ParseInt(s, 10, 64)`, the operation behind
/// `json.Number.Int64`.
///
/// Rust `i64::from_str` accepts the same spellings (`+5`, `-5`,
/// `010`) and rejects the same ones (`" 5"`, `0x10`, `5_000`, `""`,
/// overflow). The ParseInt error *text* never surfaces: every caller
/// in Go reports a fixed message on failure.
pub fn go_parse_int64(s: &str) -> Result<i64, std::num::ParseIntError> {
    s.parse::<i64>()
}

/// Decode one rune from `bytes` at `i`, following Go's
/// `utf8.DecodeRune`: a valid encoding returns the rune and its size;
/// an invalid byte returns U+FFFD with size 1; an empty slice returns
/// U+FFFD with size 0.
///
/// Source: Go stdlib `unicode/utf8.DecodeRune`.
pub fn go_decode_rune(bytes: &[u8], i: usize) -> (char, usize) {
    if i >= bytes.len() {
        return ('\u{fffd}', 0);
    }
    let b0 = bytes[i];
    if b0 < 0x80 {
        return (b0 as char, 1);
    }
    // Second-byte ranges per Go's acceptRanges table.
    let (lo, hi, size): (u8, u8, usize) = match b0 {
        0xc2..=0xdf => (0x80, 0xbf, 2),
        0xe0 => (0xa0, 0xbf, 3),
        0xe1..=0xec => (0x80, 0xbf, 3),
        0xed => (0x80, 0x9f, 3),
        0xee..=0xef => (0x80, 0xbf, 3),
        0xf0 => (0x90, 0xbf, 4),
        0xf1..=0xf3 => (0x80, 0xbf, 4),
        0xf4 => (0x80, 0x8f, 4),
        _ => return ('\u{fffd}', 1),
    };
    if i + 1 >= bytes.len() {
        return ('\u{fffd}', 1);
    }
    let b1 = bytes[i + 1];
    if !(lo..=hi).contains(&b1) {
        return ('\u{fffd}', 1);
    }
    if size == 2 {
        let n = ((b0 as u32 & 0x1f) << 6) | (b1 as u32 & 0x3f);
        return (char::from_u32(n).unwrap_or('\u{fffd}'), 2);
    }
    if i + 2 >= bytes.len() {
        return ('\u{fffd}', 1);
    }
    let b2 = bytes[i + 2];
    if !(0x80..=0xbf).contains(&b2) {
        return ('\u{fffd}', 1);
    }
    if size == 3 {
        let n = ((b0 as u32 & 0x0f) << 12) | ((b1 as u32 & 0x3f) << 6) | (b2 as u32 & 0x3f);
        return (char::from_u32(n).unwrap_or('\u{fffd}'), 3);
    }
    if i + 3 >= bytes.len() {
        return ('\u{fffd}', 1);
    }
    let b3 = bytes[i + 3];
    if !(0x80..=0xbf).contains(&b3) {
        return ('\u{fffd}', 1);
    }
    let n = ((b0 as u32 & 0x07) << 18)
        | ((b1 as u32 & 0x3f) << 12)
        | ((b2 as u32 & 0x3f) << 6)
        | (b3 as u32 & 0x3f);
    (char::from_u32(n).unwrap_or('\u{fffd}'), 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_trim_space_unicode() {
        assert_eq!(go_trim_space("\u{a0} x \u{2003}"), "x");
        assert_eq!(go_trim_space(""), "");
        assert_eq!(go_trim_space("  "), "");
    }

    #[test]
    fn test_go_lower_simple_folding() {
        assert_eq!(go_lower("İ"), "i");
        assert_eq!(go_lower("ALWAYS"), "always");
        assert_eq!(go_lower("ABC"), "abc");
    }

    #[test]
    fn test_go_quote_ascii() {
        assert_eq!(go_quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(go_quote("a\nb\tc"), "\"a\\nb\\tc\"");
        assert_eq!(go_quote("\u{1}"), "\"\\x01\"");
        assert_eq!(go_quote("\u{7f}"), "\"\\x7f\"");
    }

    #[test]
    fn test_go_quote_separators_escaped() {
        // Zs/Zl/Zp are not printable in Go's strconv.IsPrint
        // (probe-verified on cue); %q escapes them, never emits
        // them raw.
        assert_eq!(go_quote("bogus\u{2028}"), "\"bogus\\u2028\"");
        assert_eq!(go_quote("bogus\u{2029}"), "\"bogus\\u2029\"");
        assert_eq!(go_quote("bogus\u{a0}"), "\"bogus\\u00a0\"");
        assert_eq!(go_quote("bogus\u{2003}"), "\"bogus\\u2003\"");
        assert_eq!(go_quote("bogus\u{3000}"), "\"bogus\\u3000\"");
        assert_eq!(go_quote("bogus\u{202f}"), "\"bogus\\u202f\"");
        // Printable neighbours stay raw.
        assert_eq!(go_quote("bogus\u{ff}"), "\"bogusÿ\"");
        assert_eq!(go_quote("bogus\u{20ac}"), "\"bogus€\"");
    }

    #[test]
    fn test_go_quote_char_probe_corpus() {
        assert_eq!(go_quote_char(0xff), "'ÿ'");
        assert_eq!(go_quote_char(0xa0), "'\\u00a0'");
        assert_eq!(go_quote_char(0x7f), "'\\x7f'");
        assert_eq!(go_quote_char(0x01), "'\\x01'");
        assert_eq!(go_quote_char(b'\t'), "'\\t'");
        assert_eq!(go_quote_char(b'"'), "'\"'");
        assert_eq!(go_quote_char(b'\''), "'\\''");
        assert_eq!(go_quote_char(b']'), "']'");
        assert_eq!(go_quote_char(0x85), "'\\u0085'");
        assert_eq!(go_quote_char(0xad), "'\\u00ad'");
    }

    #[test]
    fn test_go_parse_int64_spellings() {
        assert_eq!(go_parse_int64("111"), Ok(111));
        assert_eq!(go_parse_int64("+111"), Ok(111));
        assert_eq!(go_parse_int64("010"), Ok(10));
        assert_eq!(go_parse_int64("-5"), Ok(-5));
        assert!(go_parse_int64("111.0").is_err());
        assert!(go_parse_int64("1e3").is_err());
        assert!(go_parse_int64(" 111").is_err());
        assert!(go_parse_int64("9999999999999999999999").is_err());
        assert!(go_parse_int64("").is_err());
    }

    #[test]
    fn test_go_decode_rune_invalid() {
        assert_eq!(go_decode_rune(&[0xff], 0), ('\u{fffd}', 1));
        assert_eq!(go_decode_rune(&[0xc3, 0x28], 0), ('\u{fffd}', 1));
        assert_eq!(go_decode_rune("é".as_bytes(), 0), ('é', 2));
        assert_eq!(go_decode_rune(&[0xed, 0xa0, 0x80], 0), ('\u{fffd}', 1));
    }
}
