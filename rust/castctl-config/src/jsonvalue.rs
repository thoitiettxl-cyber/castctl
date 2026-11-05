//! Order-preserving JSON values: decode preserving key order and
//! number literals, compact encode, and 2-space indent encode.
//!
//! This mirrors Go's `decodeOrderedJSON` / `decodeOrderedValue` /
//! `encodeOrderedJSON` / `encodeOrderedJSONIndent` / `marshalScalar`
//! (`internal/profile/jsonvalue.go:22-209`) together with the two
//! `encoding/json` machines they run on: the `Decoder.Token`
//! token-state machine (`stream.go`, `tokenError` contexts) and the
//! value scanner (`scanner.go` states). Error messages reproduce the
//! probed corpus byte-for-byte; unprobed scanner edges are labelled
//! `[DEVIATION]` in PORTING.md.

use crate::errors::ConfigError;
use crate::gostr::{go_decode_rune, go_quote, go_quote_char};

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

    /// `Decoder.Token` (`stream.go:370`).
    fn token(&mut self) -> Result<Token, TokErr> {
        loop {
            let c = self.peek()?;
            match c {
                b'[' => {
                    if !self.token_value_allowed() {
                        return Err(self.token_error(c));
                    }
                    self.pos += 1;
                    self.stack.push(self.state);
                    self.state = TokenState::ArrayStart;
                    return Ok(Token::Delim(b'['));
                }
                b']' => {
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
                    if !self.token_value_allowed() {
                        return Err(self.token_error(c));
                    }
                    self.pos += 1;
                    self.stack.push(self.state);
                    self.state = TokenState::ObjectStart;
                    return Ok(Token::Delim(b'{'));
                }
                b'}' => {
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
                    " after decimal point in numeric literal",
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
                    " in exponent of numeric literal",
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
                            let unit = self.decode_hex4()?;
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
                            return Err(TokErr::invalid_character(e, " in string escape code"));
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
    /// EOF is `UnexpectedEof`.
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
}

/// `decodeOrderedValue` (`internal/profile/jsonvalue.go:63`).
fn decode_ordered_value(tp: &mut TokenParser<'_>) -> Result<JsonValue, TokErr> {
    match tp.token()? {
        Token::Delim(b'{') => {
            let mut obj = OrderedObject::new();
            while tp.more() {
                let key = match tp.token()? {
                    Token::Str(s) => s,
                    _ => {
                        return Err(TokErr::Msg("object key is not a string".to_string()));
                    }
                };
                let value = decode_ordered_value(tp)?;
                obj.set(key, value);
            }
            // The closing token: errors (mismatched `]`, EOF) propagate.
            tp.token()?;
            Ok(JsonValue::Object(obj))
        }
        Token::Delim(b'[') => {
            let mut arr = Vec::new();
            while tp.more() {
                arr.push(decode_ordered_value(tp)?);
            }
            tp.token()?;
            Ok(JsonValue::Array(arr))
        }
        Token::Delim(d) => Err(TokErr::Msg(format!(
            "unexpected delimiter {}",
            go_quote(&(d as char).to_string())
        ))),
        Token::Str(s) => Ok(JsonValue::Str(s)),
        Token::Number(n) => Ok(JsonValue::Number(n)),
        Token::Bool(b) => Ok(JsonValue::Bool(b)),
        Token::Null => Ok(JsonValue::Null),
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
    // Trailing-data check via More() semantics: skip spaces; a
    // remaining byte that is not `]`/`}` is trailing data.
    let mut pos = tp.pos;
    while pos < data.len() && TokenParser::is_space(data[pos]) {
        pos += 1;
    }
    if pos < data.len() && data[pos] != b']' && data[pos] != b'}' {
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

fn encode_value(out: &mut String, value: &JsonValue) -> Result<(), ConfigError> {
    match value {
        JsonValue::Object(obj) => {
            out.push('{');
            for (i, (k, v)) in obj.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_go_string(out, k);
                out.push(':');
                encode_value(out, v)?;
            }
            out.push('}');
        }
        JsonValue::Array(arr) => {
            out.push('[');
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_value(out, elem)?;
            }
            out.push(']');
        }
        scalar => out.push_str(&encode_scalar(scalar)?),
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

    /// The probed Go decode corpus (m2-probes.log §2): every case
    /// with its verbatim Go error.
    #[test]
    fn test_decode_error_corpus() {
        let cases: &[(&str, &str)] = &[
            ("", "profile: invalid json: EOF"),
            (" ", "profile: invalid json: EOF"),
            ("{", "profile: invalid json: EOF"),
            ("{\"a\":1", "profile: invalid json: EOF"),
            ("tru", "profile: invalid json: unexpected EOF"),
            ("nul", "profile: invalid json: unexpected EOF"),
            ("-", "profile: invalid json: unexpected EOF"),
            ("1e", "profile: invalid json: unexpected EOF"),
            ("\"abc", "profile: invalid json: unexpected EOF"),
            (
                "[1,]",
                "profile: invalid json: invalid character ']' looking for beginning of value",
            ),
            (
                "{\"a\":}",
                "profile: invalid json: invalid character '}' looking for beginning of value",
            ),
            (
                "{\"a\":01}",
                "profile: invalid json: invalid character '1' after object key:value pair",
            ),
            (
                "{\"a\":1,}",
                "profile: invalid json: invalid character '}' looking for beginning of object key string",
            ),
            (
                "{\"a\" 1}",
                "profile: invalid json: invalid character '1' after object key",
            ),
            (
                "[1 2]",
                "profile: invalid json: invalid character '2' after array element",
            ),
            ("{]", "profile: invalid json: invalid character ']'"),
            ("{,}", "profile: invalid json: invalid character ','"),
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
                "1e}",
                "profile: invalid json: invalid character '}' in exponent of numeric literal",
            ),
            (
                "-}",
                "profile: invalid json: invalid character '}' in numeric literal",
            ),
            (
                "1.}",
                "profile: invalid json: invalid character '}' after decimal point in numeric literal",
            ),
            (
                "\"a\\q\"",
                "profile: invalid json: invalid character 'q' in string escape code",
            ),
            (
                "\"\\u12\"",
                "profile: invalid json: invalid character '\"' in \\u hexadecimal character escape",
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
        ];
        for (input, want) in cases {
            assert_eq!(decode_err(input), *want, "input {input:?}");
        }
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
