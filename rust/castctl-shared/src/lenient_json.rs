// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Lenient JSON decoding with Go `encoding/json` semantics.
//!
//! Go's `json.Unmarshal` is lenient where `serde_json` is
//! strict, and the M6c crates must match Go on untrusted
//! input (fix loop 2, red-team R2-B1/B2/B3):
//!
//! - a JSON `null` is a no-op everywhere: a field, an
//!   array element, or the whole document decodes to the
//!   zero value (Go `encoding/json`: `null` unmarshals
//!   into any Go value without effect);
//! - duplicate keys are last-wins (Go keeps the last
//!   occurrence; serde derive refuses with
//!   `duplicate field`);
//! - invalid UTF-8 bytes inside a string are coerced to
//!   U+FFFD, one per bad byte (Go `utf8.DecodeRune`
//!   semantics — the same rule `castctl-pluginhost`
//!   already uses in `text.rs::decode_rune`);
//! - type errors still refuse: a string where Go wants
//!   an int, a number where Go wants a bool, and so on
//!   are decode errors, exactly like Go.
//!
//! This cannot be a serde `Deserialize` impl:
//! `serde_json::from_slice` validates UTF-8 for the
//! whole document (including inside
//! `serde_json::value::RawValue`) before any visitor
//! runs, so no serde-based decoder can accept the
//! R2-B2 triggers. The parser here works directly on
//! bytes instead.
//!
//! The scanner is iterative (explicit `Expect` state +
//! a stack of open containers), never recursive, so a
//! hostile deeply-nested value cannot exhaust the
//! stack: Go accepts nesting to depth 10000 and so
//! does this parser. Typed decoders built on top of
//! it recurse only over known shallow shapes
//! (envelope / release / asset / error objects).
//!
//! What this parser does NOT do: it keeps the raw byte
//! span of every value, and decodes a string only when
//! the caller asks (`as_str`). A caller that needs the
//! raw bytes of a value (Go `json.RawMessage`, e.g.
//! the envelope `result`) takes `as_raw` and never
//! pays for — or trips over — string decoding.

use std::fmt;

/// The error of a lenient decode: a short message with
/// a byte offset, never echoing input bytes (hostile
/// input must not leak into logs through an error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LenientError(String);

impl LenientError {
    fn at(pos: usize, what: &str) -> Self {
        LenientError(format!("invalid JSON at byte {pos}: {what}"))
    }

    fn typed(what: &str) -> Self {
        LenientError(format!("type error: {what}"))
    }
}

impl fmt::Display for LenientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LenientError {}

/// The kind of a parsed JSON value, from its first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Null,
    Bool,
    Number,
    Str,
    Array,
    Object,
}

/// One parsed JSON value: the byte span `[start, end)`
/// of the value inside the original input. Strings are
/// decoded lazily (`as_str`); object fields and array
/// elements are re-walked from the span (`fields`,
/// `elements`).
#[derive(Debug, Clone, Copy)]
pub struct Parsed<'a> {
    input: &'a [u8],
    start: usize,
    end: usize,
}

impl<'a> Parsed<'a> {
    /// Parse one top-level JSON value; trailing bytes
    /// other than JSON whitespace refuse, like Go's
    /// `json.Unmarshal`.
    pub fn parse_document(input: &'a [u8]) -> Result<Self, LenientError> {
        let (start, end) = value_span(input, 0)?;
        let mut pos = end;
        pos = skip_ws(input, pos)?;
        if pos != input.len() {
            return Err(LenientError::at(
                pos,
                "trailing characters after top-level value",
            ));
        }
        Ok(Parsed { input, start, end })
    }

    /// The kind of this value.
    #[must_use]
    pub fn kind(&self) -> Kind {
        match self.input[self.start] {
            b'n' => Kind::Null,
            b't' | b'f' => Kind::Bool,
            b'"' => Kind::Str,
            b'[' => Kind::Array,
            b'{' => Kind::Object,
            _ => Kind::Number,
        }
    }

    /// Whether this value is the JSON literal `null`.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.kind() == Kind::Null
    }

    /// The raw bytes of this value, verbatim (for a
    /// string: including the quotes; for an object:
    /// including braces and the original key order and
    /// whitespace). This is the Go `json.RawMessage`
    /// view of the value.
    #[must_use]
    pub fn as_raw(&self) -> &'a [u8] {
        &self.input[self.start..self.end]
    }

    /// Decode this value as a bool; `null` and every
    /// other kind refuse (callers map `null` to the
    /// zero value themselves).
    pub fn as_bool(&self) -> Result<bool, LenientError> {
        if self.kind() != Kind::Bool {
            return Err(LenientError::typed("expected a boolean"));
        }
        Ok(self.input[self.start] == b't')
    }

    /// Decode this value as an `i64`: only a plain
    /// integer literal parses — `1e3`, `1.0`, `1.5`
    /// and overflows refuse, exactly like Go
    /// unmarshalling into an `int64` (probed on cue
    /// 2026-11-06).
    pub fn as_i64(&self) -> Result<i64, LenientError> {
        if self.kind() != Kind::Number {
            return Err(LenientError::typed("expected a number"));
        }
        let lit = std::str::from_utf8(self.as_raw())
            .map_err(|_| LenientError::typed("expected a number"))?;
        lit.parse::<i64>()
            .map_err(|_| LenientError::typed("number is not a valid i64"))
    }

    /// Decode this value as a string, coercing invalid
    /// UTF-8 bytes to U+FFFD like Go; every other kind
    /// refuses.
    pub fn as_str(&self) -> Result<String, LenientError> {
        if self.kind() != Kind::Str {
            return Err(LenientError::typed("expected a string"));
        }
        decode_string(self.as_raw())
    }

    /// The fields of an object, in document order,
    /// duplicates kept (callers that want Go's
    /// last-wins use `field`).
    pub fn fields(&self) -> Result<Vec<(String, Parsed<'a>)>, LenientError> {
        if self.kind() != Kind::Object {
            return Err(LenientError::typed("expected an object"));
        }
        let input = self.input;
        let mut out = Vec::new();
        let mut pos = skip_ws(input, self.start + 1)?;
        if input[pos] == b'}' {
            return Ok(out);
        }
        loop {
            pos = skip_ws(input, pos)?;
            let key_end = scan_string(input, pos)?;
            let key = decode_string(&input[pos..key_end])?;
            pos = skip_ws(input, key_end)?;
            if input.get(pos) != Some(&b':') {
                return Err(LenientError::at(pos, "expected ':' after object key"));
            }
            let (vs, ve) = value_span(input, pos + 1)?;
            out.push((
                key,
                Parsed {
                    input,
                    start: vs,
                    end: ve,
                },
            ));
            pos = skip_ws(input, ve)?;
            match input.get(pos) {
                Some(b',') => {
                    pos += 1;
                }
                Some(b'}') => return Ok(out),
                _ => return Err(LenientError::at(pos, "expected ',' or '}' in object")),
            }
        }
    }

    /// The LAST occurrence of `name` in an object (Go
    /// last-wins), or `None` when absent. Duplicate
    /// keys never error.
    pub fn field(&self, name: &str) -> Result<Option<Parsed<'a>>, LenientError> {
        Ok(self
            .fields()?
            .into_iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v))
    }

    /// The elements of an array, in order. A `null`
    /// element is returned as a null `Parsed` (callers
    /// map it to the zero value); it never errors.
    pub fn elements(&self) -> Result<Vec<Parsed<'a>>, LenientError> {
        if self.kind() != Kind::Array {
            return Err(LenientError::typed("expected an array"));
        }
        let input = self.input;
        let mut out = Vec::new();
        let mut pos = skip_ws(input, self.start + 1)?;
        if input[pos] == b']' {
            return Ok(out);
        }
        loop {
            let (vs, ve) = value_span(input, pos)?;
            out.push(Parsed {
                input,
                start: vs,
                end: ve,
            });
            pos = skip_ws(input, ve)?;
            match input.get(pos) {
                Some(b',') => {
                    pos = skip_ws(input, pos + 1)?;
                }
                Some(b']') => return Ok(out),
                _ => return Err(LenientError::at(pos, "expected ',' or ']' in array")),
            }
        }
    }
}

/// What the scanner expects next. `Key` (after a comma
/// in an object) must be a string — unlike `KeyOrEnd`
/// (right after `{`) it does not accept `}`: a trailing
/// comma is a syntax error, like Go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Value,
    KeyOrEnd,
    Key,
    Colon,
    ValueOrEnd,
    SepOrEnd,
}

/// Skip JSON whitespace (`space`, `\t`, `\n`, `\r`
/// only — Go's `encoding/json` accepts no other
/// whitespace). Errors on end of input.
fn skip_ws(input: &[u8], mut pos: usize) -> Result<usize, LenientError> {
    while pos < input.len() && matches!(input[pos], b' ' | b'\t' | b'\n' | b'\r') {
        pos += 1;
    }
    if pos > input.len() {
        return Err(LenientError::at(pos, "unexpected end of input"));
    }
    Ok(pos)
}

/// The byte span `[start, end)` of the single JSON
/// value starting at or after `start` (leading
/// whitespace skipped). Iterative: an explicit stack
/// of open containers (`b'{'` / `b'['`), so nesting
/// depth is bounded only by input length, never by
/// the call stack.
fn value_span(input: &[u8], start: usize) -> Result<(usize, usize), LenientError> {
    let mut stack: Vec<u8> = Vec::new();
    let mut expect = Expect::Value;
    let mut pos = skip_ws(input, start)?;
    let value_start = pos;
    loop {
        match expect {
            Expect::Value | Expect::ValueOrEnd => {
                pos = skip_ws(input, pos)?;
                let b = *input
                    .get(pos)
                    .ok_or_else(|| LenientError::at(pos, "unexpected end of input"))?;
                if expect == Expect::ValueOrEnd && b == b']' {
                    if stack.pop() != Some(b'[') {
                        return Err(LenientError::at(pos, "unmatched ']'"));
                    }
                    pos += 1;
                    if stack.is_empty() {
                        return Ok((value_start, pos));
                    }
                    expect = Expect::SepOrEnd;
                    continue;
                }
                match b {
                    b'"' => {
                        pos = scan_string(input, pos)?;
                    }
                    b'{' => {
                        stack.push(b'{');
                        pos += 1;
                        expect = Expect::KeyOrEnd;
                        continue;
                    }
                    b'[' => {
                        stack.push(b'[');
                        pos += 1;
                        expect = Expect::ValueOrEnd;
                        continue;
                    }
                    b't' => {
                        expect_literal(input, pos, b"true")?;
                        pos += 4;
                    }
                    b'f' => {
                        expect_literal(input, pos, b"false")?;
                        pos += 5;
                    }
                    b'n' => {
                        expect_literal(input, pos, b"null")?;
                        pos += 4;
                    }
                    b'-' | b'0'..=b'9' => {
                        pos = scan_number(input, pos)?;
                    }
                    _ => {
                        return Err(LenientError::at(pos, "expected a JSON value"));
                    }
                }
                if stack.is_empty() {
                    return Ok((value_start, pos));
                }
                expect = Expect::SepOrEnd;
            }
            Expect::KeyOrEnd | Expect::Key => {
                pos = skip_ws(input, pos)?;
                let b = *input
                    .get(pos)
                    .ok_or_else(|| LenientError::at(pos, "unexpected end of input"))?;
                if expect == Expect::KeyOrEnd && b == b'}' {
                    if stack.pop() != Some(b'{') {
                        return Err(LenientError::at(pos, "unmatched '}'"));
                    }
                    pos += 1;
                    if stack.is_empty() {
                        return Ok((value_start, pos));
                    }
                    expect = Expect::SepOrEnd;
                } else if b == b'"' {
                    pos = scan_string(input, pos)?;
                    expect = Expect::Colon;
                } else {
                    return Err(LenientError::at(pos, "expected an object key"));
                }
            }
            Expect::Colon => {
                pos = skip_ws(input, pos)?;
                let b = *input
                    .get(pos)
                    .ok_or_else(|| LenientError::at(pos, "unexpected end of input"))?;
                if b != b':' {
                    return Err(LenientError::at(pos, "expected ':' after object key"));
                }
                pos += 1;
                expect = Expect::Value;
            }
            Expect::SepOrEnd => {
                pos = skip_ws(input, pos)?;
                let b = *input
                    .get(pos)
                    .ok_or_else(|| LenientError::at(pos, "unexpected end of input"))?;
                if b == b',' {
                    pos += 1;
                    match stack.last() {
                        Some(b'[') => expect = Expect::Value,
                        Some(b'{') => expect = Expect::Key,
                        _ => return Err(LenientError::at(pos, "comma outside a container")),
                    }
                } else if b == b']' || b == b'}' {
                    let want = if b == b']' { b'[' } else { b'{' };
                    if stack.pop() != Some(want) {
                        return Err(LenientError::at(pos, "unmatched closing bracket"));
                    }
                    pos += 1;
                    if stack.is_empty() {
                        return Ok((value_start, pos));
                    }
                    expect = Expect::SepOrEnd;
                } else {
                    return Err(LenientError::at(pos, "expected ',' or a closing bracket"));
                }
            }
        }
    }
}

/// Expect the literal `lit` at `pos` (e.g. `true`):
/// a prefix mismatch or a truncated input is a syntax
/// error, like Go's `invalid character` errors.
fn expect_literal(input: &[u8], pos: usize, lit: &[u8]) -> Result<(), LenientError> {
    if input.len() < pos + lit.len() || &input[pos..pos + lit.len()] != lit {
        return Err(LenientError::at(pos, "invalid literal"));
    }
    Ok(())
}

/// The end index (one past the closing quote) of the
/// JSON string starting at `pos` (`input[pos]` is
/// `"`). Validates escapes (`\"\\/bfnrtu` + 4 hex
/// digits) and refuses unescaped control bytes, like
/// Go — but never validates UTF-8: invalid bytes
/// inside the string are content, coerced later by
/// `decode_string`.
fn scan_string(input: &[u8], pos: usize) -> Result<usize, LenientError> {
    debug_assert_eq!(input[pos], b'"');
    let mut i = pos + 1;
    while let Some(&b) = input.get(i) {
        match b {
            b'"' => return Ok(i + 1),
            b'\\' => {
                let e = *input
                    .get(i + 1)
                    .ok_or_else(|| LenientError::at(i, "unterminated escape"))?;
                match e {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => i += 2,
                    b'u' => {
                        for k in 0..4 {
                            let h = *input
                                .get(i + 2 + k)
                                .ok_or_else(|| LenientError::at(i, "unterminated \\u escape"))?;
                            if !h.is_ascii_hexdigit() {
                                return Err(LenientError::at(
                                    i + 2 + k,
                                    "invalid hex digit in \\u escape",
                                ));
                            }
                        }
                        i += 6;
                    }
                    _ => return Err(LenientError::at(i + 1, "invalid escape")),
                }
            }
            0x00..=0x1f => {
                return Err(LenientError::at(i, "unescaped control character in string"));
            }
            _ => i += 1,
        }
    }
    Err(LenientError::at(i, "unterminated string"))
}

/// The end index of the JSON number starting at `pos`.
/// Strict grammar: `-`? (`0` | `[1-9][0-9]*`)
/// (`.` `[0-9]+`)? (`e`/`E` `[+-]`? `[0-9]+`)? —
/// `01`, `1.`, `.5`, `+1`, `NaN`, `Infinity` all
/// refuse, like Go.
fn scan_number(input: &[u8], pos: usize) -> Result<usize, LenientError> {
    let mut i = pos;
    if input.get(i) == Some(&b'-') {
        i += 1;
    }
    match input.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            while input.get(i).is_some_and(|b| b.is_ascii_digit()) {
                i += 1;
            }
        }
        _ => return Err(LenientError::at(i, "invalid number")),
    }
    if input.get(i) == Some(&b'.') {
        i += 1;
        if !input.get(i).is_some_and(|b| b.is_ascii_digit()) {
            return Err(LenientError::at(i, "invalid number fraction"));
        }
        while input.get(i).is_some_and(|b| b.is_ascii_digit()) {
            i += 1;
        }
    }
    if matches!(input.get(i), Some(b'e') | Some(b'E')) {
        i += 1;
        if matches!(input.get(i), Some(b'+') | Some(b'-')) {
            i += 1;
        }
        if !input.get(i).is_some_and(|b| b.is_ascii_digit()) {
            return Err(LenientError::at(i, "invalid number exponent"));
        }
        while input.get(i).is_some_and(|b| b.is_ascii_digit()) {
            i += 1;
        }
    }
    Ok(i)
}

/// Decode one rune from the front of `b`, Go
/// `utf8.DecodeRune` semantics: an invalid or
/// truncated sequence decodes to U+FFFD consuming
/// exactly 1 byte. Same rule as `castctl-pluginhost`
/// `text.rs::decode_rune` (duplicated here because
/// this crate cannot depend on the pluginhost crate).
fn decode_rune_go(b: &[u8]) -> (char, usize) {
    if b.is_empty() {
        return ('\u{FFFD}', 0);
    }
    for len in 1..=4.min(b.len()) {
        if let Ok(s) = std::str::from_utf8(&b[..len])
            && let Some(c) = s.chars().next()
            && c.len_utf8() == len
        {
            return (c, len);
        }
    }
    ('\u{FFFD}', 1)
}

fn hex_val(b: u8) -> Option<u16> {
    match b {
        b'0'..=b'9' => Some((b - b'0') as u16),
        b'a'..=b'f' => Some((b - b'a' + 10) as u16),
        b'A'..=b'F' => Some((b - b'A' + 10) as u16),
        _ => None,
    }
}

/// The `\uXXXX` escape at `body[i]` (if any) as a code
/// unit; `None` when the bytes are not a `\u` escape
/// with 4 hex digits.
fn peek_u_escape(body: &[u8], i: usize) -> Option<u16> {
    if body.get(i) != Some(&b'\\') || body.get(i + 1) != Some(&b'u') {
        return None;
    }
    let mut unit: u16 = 0;
    for k in 0..4 {
        unit = unit * 16 + hex_val(*body.get(i + 2 + k)?)?;
    }
    Some(unit)
}

/// Decode a JSON string literal (including its quotes)
/// into a Rust `String`, coercing invalid UTF-8 bytes
/// to U+FFFD like Go's `encoding/json` (one U+FFFD
/// per bad byte) and lone `\u` surrogates to U+FFFD.
/// The input must be a single string value (as
/// produced by the scanner); anything else errors.
fn decode_string(raw: &[u8]) -> Result<String, LenientError> {
    if raw.len() < 2 || raw[0] != b'"' || raw[raw.len() - 1] != b'"' {
        return Err(LenientError::typed("expected a string"));
    }
    let body = &raw[1..raw.len() - 1];
    let mut out = String::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let b = body[i];
        match b {
            b'\\' => {
                let e = *body
                    .get(i + 1)
                    .ok_or_else(|| LenientError::at(i, "unterminated escape"))?;
                match e {
                    b'"' => {
                        out.push('"');
                        i += 2;
                    }
                    b'\\' => {
                        out.push('\\');
                        i += 2;
                    }
                    b'/' => {
                        out.push('/');
                        i += 2;
                    }
                    b'b' => {
                        out.push('\u{8}');
                        i += 2;
                    }
                    b'f' => {
                        out.push('\u{c}');
                        i += 2;
                    }
                    b'n' => {
                        out.push('\n');
                        i += 2;
                    }
                    b'r' => {
                        out.push('\r');
                        i += 2;
                    }
                    b't' => {
                        out.push('\t');
                        i += 2;
                    }
                    b'u' => {
                        let mut unit: u16 = 0;
                        for k in 0..4 {
                            let h = *body
                                .get(i + 2 + k)
                                .ok_or_else(|| LenientError::at(i, "unterminated \\u escape"))?;
                            unit = unit * 16
                                + hex_val(h).ok_or_else(|| {
                                    LenientError::at(i, "invalid hex digit in \\u escape")
                                })?;
                        }
                        i += 6;
                        if (0xd800..0xdc00).contains(&unit) {
                            // High surrogate: a following
                            // `\uDC00..DFFF` pairs with it;
                            // anything else is a lone
                            // surrogate → U+FFFD (Go).
                            match peek_u_escape(body, i) {
                                Some(low) if (0xdc00..0xe000).contains(&low) => {
                                    let c = 0x10000
                                        + ((unit - 0xd800) as u32) * 0x400
                                        + (low - 0xdc00) as u32;
                                    out.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
                                    i += 6;
                                }
                                _ => out.push('\u{FFFD}'),
                            }
                        } else if (0xdc00..0xe000).contains(&unit) {
                            out.push('\u{FFFD}');
                        } else {
                            out.push(char::from_u32(unit as u32).unwrap_or('\u{FFFD}'));
                        }
                    }
                    _ => return Err(LenientError::at(i + 1, "invalid escape")),
                }
            }
            0x00..=0x1f => {
                return Err(LenientError::at(i, "unescaped control character in string"));
            }
            b'"' => {
                // Unreachable for scanner-validated spans
                // (an interior quote is always `\"`), but
                // refuse rather than silently keeping it.
                return Err(LenientError::at(i, "unescaped quote in string"));
            }
            0x20..=0x7f => {
                out.push(b as char);
                i += 1;
            }
            _ => {
                let (c, size) = decode_rune_go(&body[i..]);
                out.push(c);
                i += size;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(input: &[u8]) -> Parsed<'_> {
        Parsed::parse_document(input).unwrap()
    }

    #[test]
    fn document_null_is_a_value() {
        let d = doc(b"null");
        assert!(d.is_null());
        assert_eq!(d.kind(), Kind::Null);
    }

    #[test]
    fn duplicate_keys_are_last_wins() {
        let d = doc(br#"{"a":1,"a":2,"b":"x","b":"y"}"#);
        assert_eq!(d.field("a").unwrap().unwrap().as_i64().unwrap(), 2);
        assert_eq!(d.field("b").unwrap().unwrap().as_str().unwrap(), "y");
        assert_eq!(d.fields().unwrap().len(), 4);
    }

    #[test]
    fn invalid_utf8_coerces_to_fffd_go_style() {
        // One 0xFF byte -> one U+FFFD.
        let d = doc(b"{\"s\":\"a\xffb\"}");
        assert_eq!(
            d.field("s").unwrap().unwrap().as_str().unwrap(),
            "a\u{FFFD}b"
        );
        // Truncated 2-byte sequence [E2, 82] -> TWO U+FFFD
        // (Go DecodeRune consumes 1 byte per failure;
        // `from_utf8_lossy` would give one — that is why
        // this parser does not use it).
        let d = doc(b"{\"s\":\"\xe2\x82\"}");
        assert_eq!(
            d.field("s").unwrap().unwrap().as_str().unwrap(),
            "\u{FFFD}\u{FFFD}"
        );
        // Valid multi-byte stays intact.
        let d = doc("{\"s\":\"caf\u{e9}\"}".as_bytes());
        assert_eq!(
            d.field("s").unwrap().unwrap().as_str().unwrap(),
            "caf\u{e9}"
        );
        // A genuine U+FFFD (EF BF BD) stays one char.
        let d = doc(b"{\"s\":\"\xef\xbf\xbd\"}");
        assert_eq!(d.field("s").unwrap().unwrap().as_str().unwrap(), "\u{FFFD}");
    }

    #[test]
    fn lone_surrogate_escapes_coerce() {
        let d = doc(br#"{"s":"\ud800"}"#);
        assert_eq!(d.field("s").unwrap().unwrap().as_str().unwrap(), "\u{FFFD}");
        let d = doc(br#"{"s":"\ud800\udc00"}"#);
        assert_eq!(
            d.field("s").unwrap().unwrap().as_str().unwrap(),
            "\u{10000}"
        );
        let d = doc("{\"s\":\"Aé\"}".as_bytes());
        assert_eq!(d.field("s").unwrap().unwrap().as_str().unwrap(), "A\u{e9}");
    }

    #[test]
    fn type_errors_still_refuse() {
        let d = doc(br#"{"size":"x","tag":123,"ok":1}"#);
        assert!(d.field("size").unwrap().unwrap().as_i64().is_err());
        assert!(d.field("tag").unwrap().unwrap().as_str().is_err());
        assert!(d.field("ok").unwrap().unwrap().as_bool().is_err());
        assert!(doc(b"1e3").as_i64().is_err());
        assert!(doc(b"1.0").as_i64().is_err());
        assert!(doc(b"9223372036854775808").as_i64().is_err());
        assert_eq!(doc(b"-5").as_i64().unwrap(), -5);
        assert_eq!(doc(b"100").as_i64().unwrap(), 100);
    }

    #[test]
    fn syntax_errors_refuse() {
        let cases: &[&[u8]] = &[
            b"",
            b" ",
            b"{",
            b"[1,]",
            b"{\"a\":1,}",
            b"{\"a\" 1}",
            b"{\"a\":01}",
            b"[1.]",
            b"[.5]",
            b"[+1]",
            b"[NaN]",
            b"[1e]",
            b"{\"a\":\"unterminated}",
            "{\"a\":\"bad\x01escape\"}".as_bytes(),
            b"{\"a\":tru}",
            b"{\"a\":1} garbage",
            b"{} {}",
            b"[1 2]",
        ];
        for bad in cases {
            assert!(Parsed::parse_document(bad).is_err(), "must refuse {bad:?}");
        }
    }

    #[test]
    fn raw_spans_keep_bytes_verbatim() {
        let d = doc(br#"{"ok":true,"result":{"b":1,"a":2}}"#);
        assert_eq!(
            d.field("result").unwrap().unwrap().as_raw(),
            br#"{"b":1,"a":2}"#
        );
        let d = doc(b"{\"ok\":true,\"result\":\"a\xffb\"}");
        assert_eq!(d.field("result").unwrap().unwrap().as_raw(), b"\"a\xffb\"");
        // Null stays 4 raw bytes, distinct from absent.
        let d = doc(br#"{"ok":true,"result":null}"#);
        let r = d.field("result").unwrap().unwrap();
        assert!(r.is_null());
        assert_eq!(r.as_raw(), b"null");
        assert!(doc(br#"{"ok":true}"#).field("result").unwrap().is_none());
    }

    #[test]
    fn deep_nesting_does_not_overflow() {
        // 200 and 1000 deep: Go accepts both, and the
        // round-1 B4 probe pinned 150/200 ACCEPT — the
        // scanner must not recurse.
        for depth in [200, 1000] {
            let mut input = Vec::new();
            for _ in 0..depth {
                input.extend_from_slice(b"{\"a\":");
            }
            input.extend_from_slice(b"1");
            input.extend(std::iter::repeat_n(b'}', depth));
            let d = Parsed::parse_document(&input).unwrap();
            assert_eq!(d.kind(), Kind::Object);
        }
        // ... nor does an unbalanced deep input hang or panic.
        let mut input = vec![b'['; 5000];
        input.push(b'1');
        assert!(Parsed::parse_document(&input).is_err());
    }

    #[test]
    fn array_null_elements_survive() {
        let d = doc(b"[null, 1, null]");
        let els = d.elements().unwrap();
        assert_eq!(els.len(), 3);
        assert!(els[0].is_null());
        assert_eq!(els[1].as_i64().unwrap(), 1);
        assert!(els[2].is_null());
    }

    #[test]
    fn unknown_fields_with_bad_bytes_are_skipped() {
        let d = doc(b"{\"ok\":true,\"zzz\":\"a\xff\",\"zzz\":2}");
        assert!(d.field("ok").unwrap().unwrap().as_bool().unwrap());
    }
}
