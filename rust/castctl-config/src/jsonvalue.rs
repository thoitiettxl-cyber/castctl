// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Order-preserving JSON values: decode preserving key order and
//! number literals, compact encode, and 2-space indent encode.
//!
//! This mirrors Go's `decodeOrderedJSON` / `decodeOrderedValue` /
//! `encodeOrderedJSON` / `encodeOrderedJSONIndent` / `marshalScalar`
//! (`internal/profile/jsonvalue.go:22-209`) together with the two
//! `encoding/json` machines they run on: the `Decoder.Token`
//! token-state machine (`stream.go`, `tokenError` contexts) and the
//! value scanner (`scanner.go` states). Error messages reproduce
//! the Go binary's messages byte-for-byte as measured by direct
//! binary comparison on cue (see PORTING.md §M2.5), including
//! the state-dependent truncated-input rule, the single
//! numeric-literal context, and the backticked escape-sequence
//! spans. Key-position, comma-anchored closer, and missing-value
//! errors follow the measured Go behaviour, which differs from
//! the Go 1.26 v1 `stream.go` shapes.

use crate::errors::ConfigError;
use crate::gostr::{go_decode_rune, go_quote, go_quote_char, go_quote_escape_span};

/// A JSON value. Numbers keep their literal spelling (Go
/// `json.Number`); objects keep insertion order (Go
/// `*orderedObject`).
///
/// Source: `internal/profile/jsonvalue.go:22` (`orderedObject` doc:
/// values decode to nil, bool, string, `json.Number`, `[]any`, or
/// `*orderedObject`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    /// JSON `null`.
    Null,
    /// JSON boolean.
    Bool(bool),
    /// JSON string (decoded).
    Str(String),
    /// JSON number, literal spelling preserved.
    Number(String),
    /// JSON array.
    Array(Vec<JsonValue>),
    /// JSON object, insertion order preserved.
    Object(OrderedObject),
}

impl JsonValue {
    /// `true` for `JsonValue::Null`.
    pub fn is_null(&self) -> bool {
        matches!(self, JsonValue::Null)
    }
}

/// Debug marker for a raw stored JSON value: presence + container
/// kind only, never content. Raw blocks may carry secret-adjacent
/// fields (credentials, WireGuard keys), so container `Debug` impls
/// must use this instead of printing the value itself.
pub(crate) fn raw_debug_marker(value: &Option<JsonValue>) -> String {
    match value {
        None => "None".to_string(),
        Some(JsonValue::Object(_)) => "[raw object]".to_string(),
        Some(JsonValue::Array(a)) => format!("[raw array; {} elements]", a.len()),
        Some(JsonValue::Str(_)) => "[raw string]".to_string(),
        Some(JsonValue::Number(_)) => "[raw number]".to_string(),
        Some(JsonValue::Bool(_)) => "[raw bool]".to_string(),
        Some(JsonValue::Null) => "[raw null]".to_string(),
    }
}

/// Debug marker for a raw stored JSON list: element count only,
/// never content (see `raw_debug_marker`).
pub(crate) fn raw_list_debug_marker(values: &[JsonValue]) -> String {
    format!("[raw list; {} elements]", values.len())
}

/// An order-preserving JSON object: `set` appends a new key at the
/// end and keeps the first position of a repeated key, with the last
/// value winning (Go `orderedObject.set`, `jsonvalue.go:36-42`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OrderedObject {
    keys: Vec<String>,
    values: Vec<JsonValue>,
}

impl OrderedObject {
    /// An empty object (Go `newOrderedObject`, `jsonvalue.go:29`).
    pub fn new() -> Self {
        Self::default()
    }

    /// The value for `key`, if present (Go `orderedObject.get`).
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        self.keys
            .iter()
            .position(|k| k == key)
            .map(|i| &self.values[i])
    }

    /// Whether `key` is present (Go `orderedObject.has`).
    pub fn has(&self, key: &str) -> bool {
        self.keys.iter().any(|k| k == key)
    }

    /// Set `key` to `value`: new keys append at the end, existing
    /// keys keep their first position with the last value winning.
    pub fn set(&mut self, key: String, value: JsonValue) {
        match self.keys.iter().position(|k| *k == key) {
            Some(i) => self.values[i] = value,
            None => {
                self.keys.push(key);
                self.values.push(value);
            }
        }
    }

    /// Keys in insertion order.
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    /// Key/value pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &JsonValue)> {
        self.keys.iter().zip(self.values.iter())
    }

    /// Number of keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the object is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// A decode failure inside the token/scanner machines, before the
/// `invalid json: ` wrap. `Eof` is Go `io.EOF`; `UnexpectedEof` is
/// Go `io.ErrUnexpectedEOF`.
enum TokErr {
    /// Input ended at a token boundary (Go `io.EOF`).
    Eof,
    /// Input ended mid-token (Go `io.ErrUnexpectedEOF`).
    UnexpectedEof,
    /// A scanner/token error message (Go `*SyntaxError` text, or the
    /// `decodeOrderedValue` defensive errors).
    Msg(String),
}

impl TokErr {
    fn invalid_character(b: u8, context: &str) -> TokErr {
        TokErr::Msg(format!("invalid character {}{context}", go_quote_char(b)))
    }
}

/// Token-stream states, mirroring `encoding/json` `stream.go`
/// (`tokenTopValue` … `tokenObjectComma`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenState {
    TopValue,
    ArrayStart,
    ArrayValue,
    ArrayComma,
    ObjectStart,
    ObjectKey,
    ObjectColon,
    ObjectValue,
    ObjectComma,
}

/// The token parser: byte cursor plus token-stream state, mirroring
/// `json.Decoder.Token` / `More` / `peek` (`stream.go:370-520`) with
/// literal scanning delegated to the scanner states
/// (`scanner.go`).
struct TokenParser<'a> {
    input: &'a [u8],
    pos: usize,
    state: TokenState,
    stack: Vec<TokenState>,
}

/// A token returned by `TokenParser::token`, mirroring Go's `Token`
/// (`Delim`, string, `json.Number`, bool, nil).
enum Token {
    Delim(u8),
    Str(String),
    Number(String),
    Bool(bool),
    Null,
}

impl<'a> TokenParser<'a> {
    fn new(input: &'a [u8]) -> Self {
        TokenParser {
            input,
            pos: 0,
            state: TokenState::TopValue,
            stack: Vec::new(),
        }
    }

    /// Go `isSpace` (`scanner.go`): only space, tab, CR, LF. VT and
    /// FF are NOT spaces (a `\x0b` after a value is trailing data).
    fn is_space(b: u8) -> bool {
        matches!(b, b' ' | b'\t' | b'\r' | b'\n')
    }

    /// `Decoder.peek` (`stream.go`): skip spaces, return the next
    /// byte, or `Eof` at end of input.
    fn peek(&mut self) -> Result<u8, TokErr> {
        while self.pos < self.input.len() {
            let b = self.input[self.pos];
            if Self::is_space(b) {
                self.pos += 1;
            } else {
                return Ok(b);
            }
        }
        Err(TokErr::Eof)
    }

    /// `Decoder.More` (`stream.go`): another element exists iff the
    /// peeked byte is present and is neither `]` nor `}`.
    fn more(&mut self) -> bool {
        match self.peek() {
            Ok(b) => b != b']' && b != b'}',
            Err(_) => false,
        }
    }

    fn token_value_allowed(&self) -> bool {
        matches!(
            self.state,
            TokenState::TopValue
                | TokenState::ArrayStart
                | TokenState::ArrayValue
                | TokenState::ObjectValue
        )
    }

    /// `tokenValueEnd` (`stream.go:343`): after a decoded value, an
    /// array state becomes `ArrayComma`, an object-value state
    /// becomes `ObjectComma`.
    fn token_value_end(&mut self) {
        match self.state {
            TokenState::ArrayStart | TokenState::ArrayValue => {
                self.state = TokenState::ArrayComma;
            }
            TokenState::ObjectValue => {
                self.state = TokenState::ObjectComma;
            }
            _ => {}
        }
    }

    /// `tokenError` (`stream.go:464`): the context depends on the
    /// token state; `ObjectStart` has NO context (bare message).
    /// Key-position states do NOT use this: see `token()`'s
    /// key-position arms, which reproduce the binary-measured
    /// behaviour (PORTING.md §M2.5).
    fn token_error(&self, b: u8) -> TokErr {
        let context = match self.state {
            TokenState::TopValue
            | TokenState::ArrayStart
            | TokenState::ArrayValue
            | TokenState::ObjectValue => " looking for beginning of value",
            TokenState::ArrayComma => " after array element",
            TokenState::ObjectKey => " looking for beginning of object key string",
            TokenState::ObjectColon => " after object key",
            TokenState::ObjectComma => " after object key:value pair",
            TokenState::ObjectStart => "",
        };
        TokErr::invalid_character(b, context)
    }

    /// Key-position error (binary-measured): a byte that cannot
    /// start any token while an object member name is expected
    /// reports "looking for beginning of value", NOT the bare /
    /// object-key-string contexts.
    fn key_position_error(&self, b: u8) -> TokErr {
        TokErr::invalid_character(b, " looking for beginning of value")
    }

    /// `Decoder.Token` (`stream.go:370`).
    fn token(&mut self) -> Result<Token, TokErr> {
        loop {
            // Truncated input at a token boundary: the Go binary
            // reports plain `EOF` only while it is waiting for a
            // value or a key's colon (TopValue/ObjectColon/
            // ObjectValue); in every other state (inside a
            // container, after a value, after a comma) it reports
            // "unexpected end of JSON input". Probe-measured on
            // cue across all token states; see
            // `test_decode_eof_vs_unexpected_end`.
            let c = match self.peek() {
                Ok(c) => c,
                Err(TokErr::Eof) => {
                    return Err(match self.state {
                        TokenState::TopValue
                        | TokenState::ObjectColon
                        | TokenState::ObjectValue => TokErr::Eof,
                        _ => TokErr::Msg("unexpected end of JSON input".to_string()),
                    });
                }
                Err(e) => return Err(e),
            };
            match c {
                b'[' => {
                    // Key position (binary-measured): a container
                    // open where a member name is expected is not a
                    // name at all.
                    if self.state == TokenState::ObjectStart || self.state == TokenState::ObjectKey
                    {
                        return Err(TokErr::Msg(
                            "object member name must be a string".to_string(),
                        ));
                    }
                    if !self.token_value_allowed() {
                        return Err(self.token_error(c));
                    }
                    self.pos += 1;
                    self.stack.push(self.state);
                    self.state = TokenState::ArrayStart;
                    return Ok(Token::Delim(b'['));
                }
                b']' => {
                    // Key position (binary-measured): a stray
                    // closer where a member name is expected
                    // reports "looking for beginning of value".
                    if self.state == TokenState::ObjectStart || self.state == TokenState::ObjectKey
                    {
                        return Err(self.key_position_error(c));
                    }
                    // A value expected after `:` that turns out to
                    // be the wrong closer reports the enclosing
                    // pair context (binary-measured): `{"a":]`
                    // errors "after object key:value pair".
                    if self.state == TokenState::ObjectValue {
                        return Err(TokErr::invalid_character(c, " after object key:value pair"));
                    }
                    // A closer right after a comma (ArrayValue is
                    // entered only via `,`) is reported at the
                    // comma (binary-measured): `[1,]` errors on
                    // `,`, not `]`.
                    if self.state == TokenState::ArrayValue {
                        return Err(self.key_position_error(b','));
                    }
                    if self.state != TokenState::ArrayStart && self.state != TokenState::ArrayComma
                    {
                        return Err(self.token_error(c));
                    }
                    self.pos += 1;
                    self.state = self.stack.pop().unwrap_or(TokenState::TopValue);
                    self.token_value_end();
                    return Ok(Token::Delim(b']'));
                }
                b'{' => {
                    if self.state == TokenState::ObjectStart || self.state == TokenState::ObjectKey
                    {
                        return Err(TokErr::Msg(
                            "object member name must be a string".to_string(),
                        ));
                    }
                    if !self.token_value_allowed() {
                        return Err(self.token_error(c));
                    }
                    self.pos += 1;
                    self.stack.push(self.state);
                    self.state = TokenState::ObjectStart;
                    return Ok(Token::Delim(b'{'));
                }
                b'}' => {
                    // `}` where a value is expected after a key
                    // reports the missing value (binary-measured),
                    // not an invalid-character error.
                    if self.state == TokenState::ObjectValue {
                        return Err(TokErr::Msg("missing value after object key".to_string()));
                    }
                    // `}` right after a comma (ObjectKey is entered
                    // only via `,`) is reported at the comma, like
                    // the `]` case above: `{"a":1,}` errors on `,`.
                    if self.state == TokenState::ObjectKey {
                        return Err(self.key_position_error(b','));
                    }
                    if self.state != TokenState::ObjectStart
                        && self.state != TokenState::ObjectComma
                    {
                        return Err(self.token_error(c));
                    }
                    self.pos += 1;
                    self.state = self.stack.pop().unwrap_or(TokenState::TopValue);
                    self.token_value_end();
                    return Ok(Token::Delim(b'}'));
                }
                b':' => {
                    if self.state == TokenState::ObjectStart || self.state == TokenState::ObjectKey
                    {
                        return Err(self.key_position_error(c));
                    }
                    if self.state != TokenState::ObjectColon {
                        return Err(self.token_error(c));
                    }
                    self.pos += 1;
                    self.state = TokenState::ObjectValue;
                }
                b',' => {
                    if self.state == TokenState::ArrayComma {
                        self.pos += 1;
                        self.state = TokenState::ArrayValue;
                    } else if self.state == TokenState::ObjectComma {
                        self.pos += 1;
                        self.state = TokenState::ObjectKey;
                    } else if self.state == TokenState::ObjectStart
                        || self.state == TokenState::ObjectKey
                    {
                        // Key position (binary-measured): `{,}`
                        // and `{"a":1,,}` report the comma with
                        // "looking for beginning of value".
                        return Err(self.key_position_error(c));
                    } else {
                        return Err(self.token_error(c));
                    }
                }
                b'"' if self.state == TokenState::ObjectStart
                    || self.state == TokenState::ObjectKey =>
                {
                    let old = self.state;
                    self.state = TokenState::TopValue;
                    let s = self.decode_string()?;
                    self.state = old;
                    // Decode's tokenValueEnd is a no-op for TopValue;
                    // the key arm then sets ObjectColon directly.
                    self.state = TokenState::ObjectColon;
                    return Ok(Token::Str(s));
                }
                _ => {
                    // Key position (binary-measured): a scalar
                    // where a member name is expected decodes as a
                    // token, and the name check then fails with
                    // "object member name must be a string" (the
                    // assembler reports it from the unchanged
                    // key state). Bytes that start no token error
                    // via decode_any with the "looking for
                    // beginning of value" context, matching Go.
                    if self.state == TokenState::ObjectStart || self.state == TokenState::ObjectKey
                    {
                        let value = self.decode_any()?;
                        return Ok(match value {
                            JsonValue::Str(s) => Token::Str(s),
                            JsonValue::Number(n) => Token::Number(n),
                            JsonValue::Bool(b) => Token::Bool(b),
                            JsonValue::Null => Token::Null,
                            _ => {
                                return Err(TokErr::Msg("unexpected token".to_string()));
                            }
                        });
                    }
                    if !self.token_value_allowed() {
                        return Err(self.token_error(c));
                    }
                    let value = self.decode_any()?;
                    // Decode's fixup: tokenValueEnd runs after every
                    // decoded value, even a scalar.
                    self.token_value_end();
                    return Ok(match value {
                        JsonValue::Str(s) => Token::Str(s),
                        JsonValue::Number(n) => Token::Number(n),
                        JsonValue::Bool(b) => Token::Bool(b),
                        JsonValue::Null => Token::Null,
                        _ => return Err(TokErr::Msg("unexpected token".to_string())),
                    });
                }
            }
        }
    }

    /// One decoded literal at the cursor, mirroring `Decoder.Decode`
    /// into `any` for a scalar: the scanner states for strings,
    /// numbers, and `true`/`false`/`null` (`scanner.go`). The cursor
    /// is at the first non-space byte (peeked, unconsumed).
    fn decode_any(&mut self) -> Result<JsonValue, TokErr> {
        let c = self.peek()?;
        match c {
            b'"' => Ok(JsonValue::Str(self.decode_string()?)),
            b't' | b'f' | b'n' => self.decode_literal(c),
            b'-' | b'0'..=b'9' => self.decode_number(),
            _ => Err(TokErr::invalid_character(
                c,
                " looking for beginning of value",
            )),
        }
    }

    /// Literal scan (`stateT`/`stateF`/`stateN` families,
    /// `scanner.go`): wrong byte → `in literal X (expecting 'y')`;
    /// EOF mid-literal → `UnexpectedEof`.
    fn decode_literal(&mut self, first: u8) -> Result<JsonValue, TokErr> {
        let (word, value): (&str, JsonValue) = match first {
            b't' => ("true", JsonValue::Bool(true)),
            b'f' => ("false", JsonValue::Bool(false)),
            _ => ("null", JsonValue::Null),
        };
        self.pos += 1; // consume the first byte (already peeked)
        for expected in word.as_bytes()[1..].iter() {
            if self.pos >= self.input.len() {
                return Err(TokErr::UnexpectedEof);
            }
            let b = self.input[self.pos];
            if b != *expected {
                return Err(TokErr::Msg(format!(
                    "invalid character {} in literal {} (expecting '{}')",
                    go_quote_char(b),
                    word,
                    *expected as char
                )));
            }
            self.pos += 1;
        }
        Ok(value)
    }

    /// Number scan (`stateNeg`/`state0`/`state1`/`stateDot`/
    /// `stateDot0`/`stateE`/`stateESign`/`stateE0`, `scanner.go`).
    /// In end states (`0`/`1`/frac/exponent-digits) a
    /// non-continuing byte ends the number unconsumed; in
    /// mid-number states it is a scanner error, and EOF there is
    /// `UnexpectedEof`. The literal spelling is preserved.
    fn decode_number(&mut self) -> Result<JsonValue, TokErr> {
        let start = self.pos;
        // stateNeg / first digit
        if self.pos < self.input.len() && self.input[self.pos] == b'-' {
            self.pos += 1;
            if self.pos >= self.input.len() {
                return Err(TokErr::UnexpectedEof);
            }
            let b = self.input[self.pos];
            if !(b == b'0' || (b'1'..=b'9').contains(&b)) {
                return Err(TokErr::invalid_character(b, " in numeric literal"));
            }
        }
        // integer part
        if self.pos < self.input.len() && self.input[self.pos] == b'0' {
            self.pos += 1;
        } else {
            while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }
        // fraction
        if self.pos < self.input.len() && self.input[self.pos] == b'.' {
            self.pos += 1;
            if self.pos >= self.input.len() {
                return Err(TokErr::UnexpectedEof);
            }
            if !self.input[self.pos].is_ascii_digit() {
                return Err(TokErr::invalid_character(
                    self.input[self.pos],
                    " in numeric literal",
                ));
            }
            while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }
        // exponent
        if self.pos < self.input.len()
            && (self.input[self.pos] == b'e' || self.input[self.pos] == b'E')
        {
            self.pos += 1;
            if self.pos < self.input.len()
                && (self.input[self.pos] == b'+' || self.input[self.pos] == b'-')
            {
                self.pos += 1;
            }
            if self.pos >= self.input.len() {
                return Err(TokErr::UnexpectedEof);
            }
            if !self.input[self.pos].is_ascii_digit() {
                return Err(TokErr::invalid_character(
                    self.input[self.pos],
                    " in numeric literal",
                ));
            }
            while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }
        let literal = String::from_utf8_lossy(&self.input[start..self.pos]).into_owned();
        Ok(JsonValue::Number(literal))
    }

    /// String scan (`stateInString` / `stateInStringEsc` /
    /// `stateInStringEscU*`, `scanner.go`), including Go's string
    /// unquoting: surrogate-pair combining, lone surrogates and
    /// invalid UTF-8 bytes become U+FFFD. The cursor is at the
    /// opening quote.
    fn decode_string(&mut self) -> Result<String, TokErr> {
        // Consume the opening quote (peeked).
        self.pos += 1;
        let mut out = String::new();
        loop {
            if self.pos >= self.input.len() {
                return Err(TokErr::UnexpectedEof);
            }
            let b = self.input[self.pos];
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    let escape_start = self.pos;
                    self.pos += 1;
                    if self.pos >= self.input.len() {
                        return Err(TokErr::UnexpectedEof);
                    }
                    let e = self.input[self.pos];
                    self.pos += 1;
                    match e {
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'"' => out.push('"'),
                        b'u' => {
                            let unit = self.decode_hex4_span(escape_start)?;
                            if (0xd800..0xdc00).contains(&unit) {
                                // High surrogate: combine with a
                                // following \uDC00-\uDFFF escape.
                                if self.pos + 1 < self.input.len()
                                    && self.input[self.pos] == b'\\'
                                    && self.input[self.pos + 1] == b'u'
                                {
                                    let save = self.pos;
                                    self.pos += 2;
                                    match self.decode_hex4() {
                                        Ok(low) if (0xdc00..0xe000).contains(&low) => {
                                            let n =
                                                0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                                            out.push(char::from_u32(n).unwrap_or('\u{fffd}'));
                                        }
                                        _ => {
                                            self.pos = save;
                                            out.push('\u{fffd}');
                                        }
                                    }
                                } else {
                                    out.push('\u{fffd}');
                                }
                            } else if (0xdc00..0xe000).contains(&unit) {
                                out.push('\u{fffd}');
                            } else {
                                out.push(char::from_u32(unit).unwrap_or('\u{fffd}'));
                            }
                        }
                        _ => {
                            // Invalid simple escape: the Go binary
                            // reports the two-byte escape sequence
                            // (`\` + the offending byte), quoted
                            // per `go_quote_escape_span`.
                            let span = &self.input[escape_start..self.pos];
                            return Err(TokErr::Msg(format!(
                                "invalid escape sequence {} in string",
                                go_quote_escape_span(span)
                            )));
                        }
                    }
                }
                0x00..=0x1f => {
                    return Err(TokErr::invalid_character(b, " in string literal"));
                }
                _ => {
                    let (ch, size) = go_decode_rune(self.input, self.pos);
                    out.push(ch);
                    self.pos += size;
                }
            }
        }
    }

    /// Four hex digits after `\u` (`stateInStringEscU*`): a
    /// non-hex byte errors with `in \u hexadecimal character escape`;
    /// EOF is `UnexpectedEof`. Used ONLY for the surrogate-pair
    /// lookahead, where the caller swallows the error and falls
    /// back to U+FFFD; the primary `\u` path uses
    /// `decode_hex4_span`, which reports the Go binary's
    /// `invalid escape sequence` span form.
    fn decode_hex4(&mut self) -> Result<u32, TokErr> {
        let mut value: u32 = 0;
        for _ in 0..4 {
            if self.pos >= self.input.len() {
                return Err(TokErr::UnexpectedEof);
            }
            let b = self.input[self.pos];
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'a'..=b'f' => (b - b'a' + 10) as u32,
                b'A'..=b'F' => (b - b'A' + 10) as u32,
                _ => {
                    return Err(TokErr::invalid_character(
                        b,
                        " in \\u hexadecimal character escape",
                    ));
                }
            };
            value = value * 16 + digit;
            self.pos += 1;
        }
        Ok(value)
    }

    /// Primary `\u` scan: four hex digits, but a non-hex byte
    /// reports the Go binary's `invalid escape sequence` form,
    /// with a fixed six-byte span starting at the backslash
    /// (`\` + `u` + the next four bytes, truncated at end of
    /// input) — measured on cue: the span extends past the
    /// offending byte and past the closing quote when the
    /// window covers them. EOF before the four slots fill (with
    /// no non-hex byte seen) is `UnexpectedEof`, as in
    /// `decode_hex4`.
    fn decode_hex4_span(&mut self, escape_start: usize) -> Result<u32, TokErr> {
        let mut value: u32 = 0;
        for _ in 0..4 {
            if self.pos >= self.input.len() {
                return Err(TokErr::UnexpectedEof);
            }
            let b = self.input[self.pos];
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'a'..=b'f' => (b - b'a' + 10) as u32,
                b'A'..=b'F' => (b - b'A' + 10) as u32,
                _ => {
                    let end = (escape_start + 6).min(self.input.len());
                    let span = &self.input[escape_start..end];
                    return Err(TokErr::Msg(format!(
                        "invalid escape sequence {} in string",
                        go_quote_escape_span(span)
                    )));
                }
            };
            value = value * 16 + digit;
            self.pos += 1;
        }
        Ok(value)
    }
}

/// Go `encoding/json` nesting cap (`scanner.go`, `maxNestingDepth`
/// = 10000, "to prevent stack overflow"): the 10001st nested
/// container errors `exceeded max depth` instead of overflowing
/// the stack. Probe-measured on cue: a decode of exactly 10000
/// `[` succeeds, 10001 fails (see PORTING.md §M2.5). `depth`
/// counts enclosing containers.
const MAX_NESTING_DEPTH: usize = 10000;

/// `decodeOrderedValue` (`internal/profile/jsonvalue.go:63`).
///
/// Iterative: an explicit stack of open containers, NOT
/// recursion. Go's 10000 nesting cap would overflow the Rust
/// call stack long before the cap if every level cost a frame
/// (measured on cue: stack overflow at depth 10000 on the 8MB
/// main stack). The token machine (`TokenParser`) is already
/// iterative; this loop only assembles values from its tokens.
/// A `Str` token is an object key iff the parser state after
/// the token is `ObjectColon` (key tokens set it; value strings
/// run `tokenValueEnd` instead, landing in a comma state).
fn decode_ordered_value(tp: &mut TokenParser<'_>) -> Result<JsonValue, TokErr> {
    enum Frame {
        Object(OrderedObject, Option<String>),
        Array(Vec<JsonValue>),
    }
    /// Attach a completed value to its parent frame, or return
    /// it as the top-level value when the stack is empty.
    fn complete(stack: &mut [Frame], value: JsonValue) -> Result<Option<JsonValue>, TokErr> {
        match stack.last_mut() {
            None => Ok(Some(value)),
            Some(Frame::Array(arr)) => {
                arr.push(value);
                Ok(None)
            }
            Some(Frame::Object(obj, key)) => match key.take() {
                Some(k) => {
                    obj.set(k, value);
                    Ok(None)
                }
                // A value with no pending key cannot come out of
                // the token machine (values only follow a key +
                // colon); defensive, never panics on input.
                None => Err(TokErr::Msg("unexpected token".to_string())),
            },
        }
    }
    let mut stack: Vec<Frame> = Vec::new();
    loop {
        match tp.token()? {
            Token::Delim(b'{') => {
                // Stack length == enclosing containers, exactly
                // the depth the recursive form counted.
                if stack.len() >= MAX_NESTING_DEPTH {
                    return Err(TokErr::Msg("exceeded max depth".to_string()));
                }
                stack.push(Frame::Object(OrderedObject::new(), None));
            }
            Token::Delim(b'[') => {
                if stack.len() >= MAX_NESTING_DEPTH {
                    return Err(TokErr::Msg("exceeded max depth".to_string()));
                }
                stack.push(Frame::Array(Vec::new()));
            }
            Token::Delim(b'}') => match stack.pop() {
                Some(Frame::Object(obj, None)) => {
                    let done = complete(&mut stack, JsonValue::Object(obj))?;
                    if let Some(value) = done {
                        return Ok(value);
                    }
                }
                _ => return Err(TokErr::Msg("unexpected token".to_string())),
            },
            Token::Delim(b']') => match stack.pop() {
                Some(Frame::Array(arr)) => {
                    let done = complete(&mut stack, JsonValue::Array(arr))?;
                    if let Some(value) = done {
                        return Ok(value);
                    }
                }
                _ => return Err(TokErr::Msg("unexpected token".to_string())),
            },
            Token::Delim(d) => {
                return Err(TokErr::Msg(format!(
                    "unexpected delimiter {}",
                    go_quote(&(d as char).to_string())
                )));
            }
            Token::Str(s) => {
                if tp.state == TokenState::ObjectColon {
                    match stack.last_mut() {
                        Some(Frame::Object(_, key @ None)) => *key = Some(s),
                        _ => {
                            return Err(TokErr::Msg("object key is not a string".to_string()));
                        }
                    }
                } else if let Some(value) = complete(&mut stack, JsonValue::Str(s))? {
                    return Ok(value);
                }
            }
            Token::Number(n) => {
                if tp.state == TokenState::ObjectStart || tp.state == TokenState::ObjectKey {
                    return Err(TokErr::Msg(
                        "object member name must be a string".to_string(),
                    ));
                }
                if let Some(value) = complete(&mut stack, JsonValue::Number(n))? {
                    return Ok(value);
                }
            }
            Token::Bool(b) => {
                if tp.state == TokenState::ObjectStart || tp.state == TokenState::ObjectKey {
                    return Err(TokErr::Msg(
                        "object member name must be a string".to_string(),
                    ));
                }
                if let Some(value) = complete(&mut stack, JsonValue::Bool(b))? {
                    return Ok(value);
                }
            }
            Token::Null => {
                if tp.state == TokenState::ObjectStart || tp.state == TokenState::ObjectKey {
                    return Err(TokErr::Msg(
                        "object member name must be a string".to_string(),
                    ));
                }
                if let Some(value) = complete(&mut stack, JsonValue::Null)? {
                    return Ok(value);
                }
            }
        }
    }
}

/// `decodeOrderedJSON` (`internal/profile/jsonvalue.go:50`): decode
/// one value, preserving order and number literals, rejecting
/// trailing data. `More()` after the value reports trailing data for
/// any remaining non-space byte other than `]`/`}` (a quirk of the
/// Go implementation: `{"a":1}}` and `[]]` decode successfully).
pub fn decode_ordered_json(data: &[u8]) -> Result<JsonValue, ConfigError> {
    let mut tp = TokenParser::new(data);
    let value = decode_ordered_value(&mut tp).map_err(|e| match e {
        TokErr::Eof => ConfigError {
            code: 2,
            kind: crate::errors::ErrorKind::ConfigParse,
            message: "profile: invalid json: EOF".to_string(),
        },
        TokErr::UnexpectedEof => ConfigError {
            code: 2,
            kind: crate::errors::ErrorKind::ConfigParse,
            message: "profile: invalid json: unexpected EOF".to_string(),
        },
        TokErr::Msg(m) => crate::errors::config_error(format!("invalid json: {m}")),
    })?;
    // Trailing-data check via More() semantics: a remaining byte
    // that is not `]`/`}` is trailing data (Go's `More()` after
    // the value; `{"a":1}}` and `[]]` decode successfully).
    if tp.more() {
        return Err(crate::errors::config_error("invalid json: trailing data"));
    }
    Ok(value)
}

/// `decodeOrderedObject` (`internal/profile/jsonvalue.go:194`): the
/// top-level value must be an object.
pub fn decode_ordered_object(data: &[u8]) -> Result<OrderedObject, ConfigError> {
    match decode_ordered_json(data)? {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(crate::errors::config_error("config must be a json object")),
    }
}

/// Whether a JSON number literal is valid per the scanner states
/// (used by the encoder for hand-built `Number` values; the parser
/// only ever produces valid literals).
fn is_valid_number_literal(literal: &str) -> bool {
    if literal.is_empty() {
        return false;
    }
    let bytes = literal.as_bytes();
    let mut tp = TokenParser {
        input: bytes,
        pos: 0,
        state: TokenState::TopValue,
        stack: Vec::new(),
    };
    match tp.decode_number() {
        Ok(JsonValue::Number(_)) => tp.pos == bytes.len(),
        _ => false,
    }
}

/// Go `encoding/json` string encoding with `SetEscapeHTML(false)`
/// (`marshalScalar`, `jsonvalue.go:155`): `"`, `\`, `\n`, `\r`,
/// `\t` escaped; other C0 controls as `\u00XX`; U+2028/U+2029
/// escaped; invalid UTF-8 bytes become `\ufffd`; `<`, `>`, `&` and
/// DEL stay literal.
fn encode_go_string(out: &mut String, s: &str) {
    out.push('"');
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let (ch, size) = go_decode_rune(bytes, i);
        if size == 1 && bytes[i] >= 0x80 {
            // Invalid UTF-8 byte: Go writes \ufffd for the byte.
            out.push_str("\\ufffd");
            i += 1;
            continue;
        }
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
        i += size;
    }
    out.push('"');
}

/// `marshalScalar` for a scalar value. A malformed hand-built number
/// literal errors like Go's `json: invalid number literal %q` (P-3;
/// unreachable from the parser).
fn encode_scalar(value: &JsonValue) -> Result<String, ConfigError> {
    Ok(match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(true) => "true".to_string(),
        JsonValue::Bool(false) => "false".to_string(),
        JsonValue::Str(s) => {
            let mut out = String::new();
            encode_go_string(&mut out, s);
            out
        }
        JsonValue::Number(literal) => {
            if !is_valid_number_literal(literal) {
                return Err(crate::errors::config_error(format!(
                    "json: invalid number literal {}",
                    go_quote(literal)
                )));
            }
            literal.clone()
        }
        JsonValue::Array(_) | JsonValue::Object(_) => {
            // Callers route containers through encode_value; this
            // arm is unreachable.
            return Err(crate::errors::config_error(
                "internal error: container in scalar position",
            ));
        }
    })
}

/// Container encode with the same nesting cap as the decoder
/// (`MAX_NESTING_DEPTH`): a hand-built value deeper than the cap
/// errors cleanly instead of overflowing the stack. The message is
/// a Rust-side approximation (Go's marshal-side depth behaviour
/// was not probed; see PORTING.md §M2.5).
///
/// Iterative, like the decoder: an explicit work stack, so
/// encoding a 10000-deep value cannot overflow the call stack.
/// `depth` counts enclosing containers, exactly as the recursive
/// form counted it; output bytes are identical.
fn encode_value(out: &mut String, value: &JsonValue) -> Result<(), ConfigError> {
    enum Item<'v> {
        Value(&'v JsonValue, usize),
        Raw(&'static str),
        Key(String),
    }
    let mut stack: Vec<Item<'_>> = vec![Item::Value(value, 0)];
    while let Some(item) = stack.pop() {
        match item {
            Item::Raw(s) => out.push_str(s),
            Item::Key(k) => {
                encode_go_string(out, &k);
                out.push(':');
            }
            Item::Value(v, depth) => match v {
                JsonValue::Object(obj) => {
                    if depth >= MAX_NESTING_DEPTH {
                        return Err(crate::errors::config_error("exceeded max depth"));
                    }
                    let mut items: Vec<Item<'_>> = vec![Item::Raw("{")];
                    for (i, (k, child)) in obj.iter().enumerate() {
                        if i > 0 {
                            items.push(Item::Raw(","));
                        }
                        items.push(Item::Key(k.clone()));
                        items.push(Item::Value(child, depth + 1));
                    }
                    items.push(Item::Raw("}"));
                    stack.extend(items.into_iter().rev());
                }
                JsonValue::Array(arr) => {
                    if depth >= MAX_NESTING_DEPTH {
                        return Err(crate::errors::config_error("exceeded max depth"));
                    }
                    let mut items: Vec<Item<'_>> = vec![Item::Raw("[")];
                    for (i, elem) in arr.iter().enumerate() {
                        if i > 0 {
                            items.push(Item::Raw(","));
                        }
                        items.push(Item::Value(elem, depth + 1));
                    }
                    items.push(Item::Raw("]"));
                    stack.extend(items.into_iter().rev());
                }
                scalar => out.push_str(&encode_scalar(scalar)?),
            },
        }
    }
    Ok(())
}

/// `encodeOrderedJSON` (`internal/profile/jsonvalue.go:128`): compact
/// rendering, key order and number literals preserved.
pub fn encode_ordered_json(value: &JsonValue) -> Result<String, ConfigError> {
    let mut out = String::new();
    encode_value(&mut out, value)?;
    Ok(out)
}

/// `rawOf` (`internal/profile/jsonvalue.go:205`): compact rendering
/// of one decoded value.
pub fn raw_of(value: &JsonValue) -> Result<String, ConfigError> {
    encode_ordered_json(value)
}

/// `encodeOrderedJSONIndent` (`internal/profile/jsonvalue.go:180`):
/// compact-encode, then `json.Indent` with 2-space indent. Empty
/// objects/arrays stay inline (`{}`, `[]`); every other `{`/`[` opens
/// a new indented line, `,` ends a line, `:` is followed by a space.
pub fn encode_ordered_json_indent(value: &JsonValue, indent: usize) -> Result<String, ConfigError> {
    let compact = encode_ordered_json(value)?;
    Ok(json_indent(compact.as_bytes(), indent))
}

fn json_indent(compact: &[u8], indent: usize) -> String {
    let pad = " ".repeat(indent);
    // Bytes, not chars: string contents (possibly multibyte UTF-8)
    // pass through verbatim. The compact input is valid UTF-8.
    let mut out: Vec<u8> = Vec::with_capacity(compact.len() + 16);
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut i = 0;
    while i < compact.len() {
        let b = compact[i];
        if in_string {
            out.push(b);
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => {
                in_string = true;
                out.push(b'"');
            }
            b'{' | b'[' => {
                // Empty container: keep the closer inline.
                let mut j = i + 1;
                while j < compact.len() && TokenParser::is_space(compact[j]) {
                    j += 1;
                }
                let closer = if b == b'{' { b'}' } else { b']' };
                if j < compact.len() && compact[j] == closer {
                    out.push(b);
                    out.push(closer);
                    i = j + 1;
                    continue;
                }
                out.push(b);
                depth += 1;
                out.push(b'\n');
                for _ in 0..depth {
                    out.extend_from_slice(pad.as_bytes());
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                out.push(b'\n');
                for _ in 0..depth {
                    out.extend_from_slice(pad.as_bytes());
                }
                out.push(b);
            }
            b',' => {
                out.push(b',');
                out.push(b'\n');
                for _ in 0..depth {
                    out.extend_from_slice(pad.as_bytes());
                }
            }
            b':' => out.extend_from_slice(b": "),
            b' ' | b'\t' | b'\r' | b'\n' => {}
            _ => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_err(input: &str) -> String {
        decode_ordered_json(input.as_bytes()).unwrap_err().message
    }

    fn decode_ok(input: &str) -> JsonValue {
        decode_ordered_json(input.as_bytes()).unwrap()
    }

    /// The probed Go decode corpus: every case with its verbatim
    /// Go binary error, measured by direct binary comparison on
    /// cue (`--config <fixture> status`, byte-for-byte stdout /
    /// stderr / exit code; see PORTING.md §M2.5). Key-position
    /// shapes, the comma-anchored closer errors, and the
    /// missing-value error are part of this table.
    #[test]
    fn test_decode_error_corpus() {
        let cases: &[(&str, &str)] = &[
            ("", "profile: invalid json: EOF"),
            (" ", "profile: invalid json: EOF"),
            ("tru", "profile: invalid json: unexpected EOF"),
            ("nul", "profile: invalid json: unexpected EOF"),
            ("-", "profile: invalid json: unexpected EOF"),
            ("1e", "profile: invalid json: unexpected EOF"),
            ("\"abc", "profile: invalid json: unexpected EOF"),
            (
                "[1,]",
                "profile: invalid json: invalid character ',' looking for beginning of value",
            ),
            (
                "{\"a\":}",
                "profile: invalid json: missing value after object key",
            ),
            (
                "{\"a\":01}",
                "profile: invalid json: invalid character '1' after object key:value pair",
            ),
            (
                "{\"a\":1,}",
                "profile: invalid json: invalid character ',' looking for beginning of value",
            ),
            (
                "{\"a\" 1}",
                "profile: invalid json: invalid character '1' after object key",
            ),
            (
                "[1 2]",
                "profile: invalid json: invalid character '2' after array element",
            ),
            (
                "{]",
                "profile: invalid json: invalid character ']' looking for beginning of value",
            ),
            (
                "{,}",
                "profile: invalid json: invalid character ',' looking for beginning of value",
            ),
            (
                "{\"a\":tru}",
                "profile: invalid json: invalid character '}' in literal true (expecting 'e')",
            ),
            (
                "falsx",
                "profile: invalid json: invalid character 'x' in literal false (expecting 'e')",
            ),
            (
                "nuxl",
                "profile: invalid json: invalid character 'x' in literal null (expecting 'l')",
            ),
            (
                "-}",
                "profile: invalid json: invalid character '}' in numeric literal",
            ),
            ("{\"a\":1} x", "profile: invalid json: trailing data"),
            ("123 456", "profile: invalid json: trailing data"),
            ("01", "profile: invalid json: trailing data"),
            ("{\"a\":1}\u{b}", "profile: invalid json: trailing data"),
            (
                "}",
                "profile: invalid json: invalid character '}' looking for beginning of value",
            ),
            (
                "]",
                "profile: invalid json: invalid character ']' looking for beginning of value",
            ),
            (
                ",",
                "profile: invalid json: invalid character ',' looking for beginning of value",
            ),
            (
                "[}",
                "profile: invalid json: invalid character '}' looking for beginning of value",
            ),
            (
                "[,]",
                "profile: invalid json: invalid character ',' looking for beginning of value",
            ),
            (
                "{invalid",
                "profile: invalid json: invalid character 'i' looking for beginning of value",
            ),
            (
                "{x}",
                "profile: invalid json: invalid character 'x' looking for beginning of value",
            ),
            (
                "{1}",
                "profile: invalid json: object member name must be a string",
            ),
            (
                "{true}",
                "profile: invalid json: object member name must be a string",
            ),
            (
                "{\"a\":1,1}",
                "profile: invalid json: object member name must be a string",
            ),
            (
                "{\"a\":1,x}",
                "profile: invalid json: invalid character 'x' looking for beginning of value",
            ),
            (
                "{[",
                "profile: invalid json: object member name must be a string",
            ),
            (
                "{{",
                "profile: invalid json: object member name must be a string",
            ),
            (
                "{\"a\":1,[",
                "profile: invalid json: object member name must be a string",
            ),
            (
                "{\"a\":1,,}",
                "profile: invalid json: invalid character ',' looking for beginning of value",
            ),
            (
                "[1,,2]",
                "profile: invalid json: invalid character ',' looking for beginning of value",
            ),
            (
                "{:}",
                "profile: invalid json: invalid character ':' looking for beginning of value",
            ),
            (
                "{\"a\"::1}",
                "profile: invalid json: invalid character ':' looking for beginning of value",
            ),
            (
                "{\"a\":]",
                "profile: invalid json: invalid character ']' after object key:value pair",
            ),
            (
                "{tru}",
                "profile: invalid json: invalid character '}' in literal true (expecting 'e')",
            ),
            (
                "{truex}",
                "profile: invalid json: object member name must be a string",
            ),
            (
                "[}",
                "profile: invalid json: invalid character '}' looking for beginning of value",
            ),
            // Truncated input inside a container (fix-loop round
            // 2, shape A): "unexpected end of JSON input".
            ("{", "profile: invalid json: unexpected end of JSON input"),
            (
                "{\"a\":1",
                "profile: invalid json: unexpected end of JSON input",
            ),
            // Number-context errors (shape B): one context.
            (
                "1e}",
                "profile: invalid json: invalid character '}' in numeric literal",
            ),
            (
                "1.}",
                "profile: invalid json: invalid character '}' in numeric literal",
            ),
            // String-escape errors (shapes C/D): backticked spans.
            (
                "\"a\\q\"",
                "profile: invalid json: invalid escape sequence `\\q` in string",
            ),
            (
                "\"\\u12\"",
                "profile: invalid json: invalid escape sequence `\\u12\"` in string",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(decode_err(input), *want, "input {input:?}");
        }
    }

    /// Truncated-input rule (shape A, binary-measured on cue):
    /// plain `EOF` only while waiting for a value or a key's
    /// colon; "unexpected end of JSON input" in every other
    /// token state; "unexpected EOF" mid-token (string,
    /// literal, number).
    #[test]
    fn test_decode_eof_vs_unexpected_end() {
        for input in [
            "", " ", "{\"a\":", "{\"a\": ", "{\"a\"", "{\"a\" ", "{\"k\":",
        ] {
            assert_eq!(
                decode_err(input),
                "profile: invalid json: EOF",
                "input {input:?}"
            );
        }
        for input in [
            "{",
            "{ ",
            "{\"a\":1",
            "{\"a\":1 ",
            "{\"a\":1,",
            "{\"a\":1, ",
            "[",
            "[1",
            "[1,",
            "[1, 2",
            "{\"k\": [1, 2",
            "{\"k\": [",
            "{\"a\": {}",
            "[[1]",
        ] {
            assert_eq!(
                decode_err(input),
                "profile: invalid json: unexpected end of JSON input",
                "input {input:?}"
            );
        }
        for input in [
            "\"abc",
            "{\"k\": \"abc",
            "tru",
            "{\"k\": tru",
            "-",
            "1e",
            "1.",
        ] {
            assert_eq!(
                decode_err(input),
                "profile: invalid json: unexpected EOF",
                "input {input:?}"
            );
        }
    }

    /// Escape-sequence spans (shapes C/D, binary-measured on
    /// cue): simple escapes quote the two-byte sequence;
    /// `\u` errors quote the six-byte window from the
    /// backslash, truncated at end of input; EOF inside the
    /// window with no bad byte is "unexpected EOF".
    #[test]
    fn test_decode_escape_sequence_spans() {
        let cases: &[(&str, &str)] = &[
            (
                "{\"k\": \"a\\q\"}",
                "profile: invalid json: invalid escape sequence `\\q` in string",
            ),
            (
                "{\"k\": \"a\\qXYZ\"}",
                "profile: invalid json: invalid escape sequence `\\q` in string",
            ),
            (
                "{\"k\": \"a\\x\"}",
                "profile: invalid json: invalid escape sequence `\\x` in string",
            ),
            (
                "{\"k\": \"a\\ \"}",
                "profile: invalid json: invalid escape sequence \"\\\\ \" in string",
            ),
            (
                "{\"k\": \"\\ug123\"}",
                "profile: invalid json: invalid escape sequence `\\ug123` in string",
            ),
            (
                "{\"k\": \"\\u12g3\"}",
                "profile: invalid json: invalid escape sequence `\\u12g3` in string",
            ),
            (
                "{\"k\": \"\\u12\", \"j\": 1}",
                "profile: invalid json: invalid escape sequence `\\u12\",` in string",
            ),
            (
                "{\"k\": \"\\u12\"}",
                "profile: invalid json: invalid escape sequence `\\u12\"}` in string",
            ),
            (
                "{\"k\": \"\\u123\"}",
                "profile: invalid json: invalid escape sequence `\\u123\"` in string",
            ),
            (
                "{\"k\": \"\\u12\\u34\"}",
                "profile: invalid json: invalid escape sequence `\\u12\\u` in string",
            ),
            (
                "{\"k\": \"\\u12g\"}",
                "profile: invalid json: invalid escape sequence `\\u12g\"` in string",
            ),
            (
                "{\"k\": \"\\u12x\"}",
                "profile: invalid json: invalid escape sequence `\\u12x\"` in string",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(decode_err(input), *want, "input {input:?}");
        }
        // EOF inside the \u window with no bad byte: unexpected EOF.
        for input in ["{\"k\": \"\\u12", "{\"k\": \"\\u123", "{\"k\": \"\\u"] {
            assert_eq!(
                decode_err(input),
                "profile: invalid json: unexpected EOF",
                "input {input:?}"
            );
        }
    }

    /// Nesting cap (F2, probe-measured on cue): exactly 10000
    /// nested arrays decode; 10001 errors cleanly with Go's
    /// message instead of overflowing the stack. A hand-built
    /// value deeper than the cap fails to encode the same way.
    #[test]
    fn test_nesting_depth_cap() {
        let at_cap = format!("{}{}", "[".repeat(10000), "]".repeat(10000));
        assert!(decode_ordered_json(at_cap.as_bytes()).is_ok());
        let over_cap = format!("{}{}", "[".repeat(10001), "]".repeat(10001));
        assert_eq!(
            decode_err(&over_cap),
            "profile: invalid json: exceeded max depth"
        );
        let mut deep = JsonValue::Array(Vec::new());
        for _ in 0..10001 {
            deep = JsonValue::Array(vec![deep]);
        }
        assert_eq!(
            encode_ordered_json(&deep).unwrap_err().message,
            "profile: exceeded max depth"
        );
        let mut at = JsonValue::Array(Vec::new());
        for _ in 0..9999 {
            at = JsonValue::Array(vec![at]);
        }
        assert!(encode_ordered_json(&at).is_ok());
    }

    #[test]
    fn test_decode_trailing_data_quirks() {
        // More() quirk: a trailing ] or } is NOT trailing data.
        assert!(decode_ordered_json(b"{\"a\":1}}").is_ok());
        assert!(decode_ordered_json(b"[]]").is_ok());
        assert!(decode_ordered_json(b"{}x").is_err());
        assert!(decode_ordered_json(b"truex").is_err());
    }

    #[test]
    fn test_decode_values_and_order() {
        let v = decode_ok("{\"b\":1,\"a\":[true,null,\"x\"],\"b\":2}");
        let obj = match &v {
            JsonValue::Object(o) => o,
            _ => panic!("not object"),
        };
        // Duplicate key: first position, last value wins.
        assert_eq!(obj.keys(), &["b".to_string(), "a".to_string()]);
        assert_eq!(obj.get("b"), Some(&JsonValue::Number("2".to_string())));
        assert_eq!(
            encode_ordered_json(&v).unwrap(),
            "{\"b\":2,\"a\":[true,null,\"x\"]}"
        );
    }

    #[test]
    fn test_decode_number_literals_preserved() {
        assert_eq!(
            encode_ordered_json(&decode_ok("[1.0,1e2,2.50,-0,1E+2,0.50]")).unwrap(),
            "[1.0,1e2,2.50,-0,1E+2,0.50]"
        );
        // +111 is accepted by Int64 but never arises from the decoder.
        assert!(decode_ordered_json(b"+111").is_err());
    }

    #[test]
    fn test_decode_string_escapes_and_surrogates() {
        assert_eq!(
            decode_ok("\"\\uD83D\\uDE00\""),
            JsonValue::Str("😀".to_string())
        );
        assert_eq!(
            decode_ok("\"\\uD800\""),
            JsonValue::Str("\u{fffd}".to_string())
        );
        assert_eq!(
            decode_ok("\"\\uD83D x\""),
            JsonValue::Str("\u{fffd} x".to_string())
        );
        assert_eq!(decode_ok("\"a\\nb\""), JsonValue::Str("a\nb".to_string()));
        assert_eq!(
            decode_ok("\"\\u2028\""),
            JsonValue::Str("\u{2028}".to_string())
        );
    }

    #[test]
    fn test_decode_invalid_utf8_in_string() {
        // A decoded invalid byte becomes U+FFFD; re-encoding writes
        // the literal replacement character (Go appendString only
        // escapes RuneError for a size-1 decode, which cannot arise
        // from an already-decoded string).
        let v = decode_ordered_json(b"{\"a\":\"\xff\"}").unwrap();
        assert_eq!(encode_ordered_json(&v).unwrap(), "{\"a\":\"\u{fffd}\"}");
    }

    #[test]
    fn test_encode_scalar_go_rules() {
        let v = decode_ok("\"<>&\\u0001\\u007f\"");
        assert_eq!(encode_ordered_json(&v).unwrap(), "\"<>&\\u0001\u{7f}\"");
        let v = decode_ok("\"\\u2028\\u2029\"");
        assert_eq!(encode_ordered_json(&v).unwrap(), "\"\\u2028\\u2029\"");
    }

    #[test]
    fn test_encode_empty_number_literal_rejected() {
        // A hand-built empty number literal is invalid (the parser
        // never produces one); encoding must error, not emit it.
        let v = JsonValue::Number(String::new());
        assert!(encode_ordered_json(&v).is_err());
    }

    #[test]
    fn test_encode_indent_layout() {
        let v = decode_ok("{\"a\":{},\"b\":[1,2],\"c\":{\"d\":[]}}");
        assert_eq!(
            encode_ordered_json_indent(&v, 2).unwrap(),
            "{\n  \"a\": {},\n  \"b\": [\n    1,\n    2\n  ],\n  \"c\": {\n    \"d\": []\n  }\n}"
        );
        assert_eq!(
            encode_ordered_json_indent(&decode_ok("{}"), 2).unwrap(),
            "{}"
        );
        assert_eq!(
            encode_ordered_json_indent(&decode_ok("[]"), 2).unwrap(),
            "[]"
        );
    }

    #[test]
    fn test_decode_object_must_be_object() {
        assert_eq!(
            decode_ordered_object(b"[1]").unwrap_err().message,
            "profile: config must be a json object"
        );
        assert!(decode_ordered_object(b"{\"a\":1}").is_ok());
    }

    #[test]
    fn test_ordered_object_set_semantics() {
        let mut o = OrderedObject::new();
        o.set("a".to_string(), JsonValue::Number("1".to_string()));
        o.set("b".to_string(), JsonValue::Number("2".to_string()));
        o.set("a".to_string(), JsonValue::Number("3".to_string()));
        assert_eq!(o.keys(), &["a".to_string(), "b".to_string()]);
        assert_eq!(o.get("a"), Some(&JsonValue::Number("3".to_string())));
    }
}
