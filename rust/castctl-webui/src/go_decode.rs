// SPDX-License-Identifier: GPL-3.0-only
// Go `encoding/json` decoder semantics for request bodies
// and stored documents, ported from Go internal/webui:
//
// - `decodeGeneric` (store.go:87): decodes the FIRST JSON
//   value and ignores everything after it — no trailing
//   check at all.
// - `decodeBody` / `bodyJSON` (server.go): decodes the
//   first value, then attempts one more decode: trailing
//   GARBAGE (a second decode that errors with anything
//   other than EOF) is rejected with the fixed 400, but a
//   trailing VALID second JSON value is tolerated (the
//   second Decode succeeds, so no error is returned).
//
// Rust's `decode_ordered_json` (castctl-config) is strict:
// it rejects ANY trailing data. Using it directly for
// bodies and stored documents would diverge from Go on
// those edges, so the decoders here find the end of the
// first value first and apply Go's rule to the remainder.
//
// Boundary detection is a byte scanner (see
// `first_value_end`), never serde_json: serde's streaming
// deserializer rejects what Go accepts — depth over 128
// (Go allows 10000), out-of-range floats like `1e999`
// (Go's `UseNumber` keeps the literal), and invalid UTF-8
// inside strings (Go coerces to U+FFFD). The actual parse
// is always `decode_ordered_json`, so key order and number
// literals are preserved.

use crate::error::{ApiError, err_validation};
use castctl_config::ConfigError;
use castctl_config::jsonvalue::{JsonValue, decode_ordered_json};

/// Coerce arbitrary bytes to a `String` the way Go's
/// `encoding/json` does when it unmarshals a document:
/// invalid UTF-8 becomes U+FFFD per byte (`utf8.DecodeRune`
/// size 1), never an error. Rust's `from_utf8_lossy` is NOT
/// equivalent: it replaces maximal subparts (a truncated
/// 3-byte sequence becomes ONE U+FFFD; Go makes one per
/// byte). Used for stored documents (F-C6) and log tails
/// (F-D5).
pub fn go_coerce_lossy(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let (r, size) = castctl_config::gostr::go_decode_rune(raw, i);
        out.push(r);
        i += size.max(1);
    }
    out
}

/// Go `encoding/json` max nesting depth (10000).
const GO_MAX_DEPTH: usize = 10000;

/// End offset (exclusive) of the first complete JSON value
/// in `data`, or `None` when no complete value can be
/// found. Leading whitespace is skipped; the offset is
/// measured from the start of `data`.
///
/// A byte scanner, not a parser: it counts `{`/`[`
/// nesting (cap 10000, Go's limit), skips strings
/// (handling `\` escapes opaquely — the real parser
/// validates them), and scans numbers with the strict JSON
/// grammar and literals as opaque tokens. It never
/// interprets a number (so `1e999` has an end, where
/// serde_json errors `NumberOutOfRange`), never validates
/// UTF-8 (an invalid byte inside a string is content,
/// where serde's `from_slice` errors), and never recurses
/// (so depth 200 — or 10000 — is fine, where serde's
/// default limit is 128). Invalid JSON (trailing comma,
/// bad number, unterminated string) yields `None`, and
/// the caller reports the fixed 400 — the same outcome
/// as Go's decoder erroring.
pub fn first_value_end(data: &[u8]) -> Option<usize> {
    /// What the scanner expects next inside a container.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Expect {
        /// A value (object value, array element, top level).
        Value,
        /// An array element, or `]` closing an empty array.
        ValueOrEnd,
        /// An object key, or `}` closing an empty object.
        KeyOrEnd,
        /// `:` after an object key.
        Colon,
        /// `,` or the container's closer, after a value.
        CommaOrEnd,
    }
    /// A value just completed: the top level ends here
    /// (stack empty), else the enclosing container now
    /// expects `,` or its closer.
    fn value_done(stack: &[u8]) -> Option<Expect> {
        if stack.is_empty() {
            None
        } else {
            Some(Expect::CommaOrEnd)
        }
    }
    let mut i = skip_ws(data, 0);
    if i >= data.len() {
        return None;
    }
    // Open containers: b'{' or b'['.
    let mut stack: Vec<u8> = Vec::new();
    let mut expect = Expect::Value;
    loop {
        i = skip_ws(data, i);
        if i >= data.len() {
            return None;
        }
        match expect {
            Expect::Value | Expect::ValueOrEnd => match data[i] {
                b'{' => {
                    if stack.len() >= GO_MAX_DEPTH {
                        return None;
                    }
                    stack.push(b'{');
                    i += 1;
                    expect = Expect::KeyOrEnd;
                }
                b'[' => {
                    if stack.len() >= GO_MAX_DEPTH {
                        return None;
                    }
                    stack.push(b'[');
                    i += 1;
                    expect = Expect::ValueOrEnd;
                }
                b']'
                    if expect == Expect::ValueOrEnd
                        && stack.last() == Some(&b'[') =>
                {
                    stack.pop();
                    i += 1;
                    match value_done(&stack) {
                        None => return Some(i),
                        Some(e) => expect = e,
                    }
                }
                b'"' => {
                    i = scan_string(data, i)?;
                    match value_done(&stack) {
                        None => return Some(i),
                        Some(e) => expect = e,
                    }
                }
                b't' => {
                    i = scan_lit(data, i, b"true")?;
                    match value_done(&stack) {
                        None => return Some(i),
                        Some(e) => expect = e,
                    }
                }
                b'f' => {
                    i = scan_lit(data, i, b"false")?;
                    match value_done(&stack) {
                        None => return Some(i),
                        Some(e) => expect = e,
                    }
                }
                b'n' => {
                    i = scan_lit(data, i, b"null")?;
                    match value_done(&stack) {
                        None => return Some(i),
                        Some(e) => expect = e,
                    }
                }
                b'-' | b'0'..=b'9' => {
                    i = scan_number(data, i)?;
                    match value_done(&stack) {
                        None => return Some(i),
                        Some(e) => expect = e,
                    }
                }
                _ => return None,
            },
            Expect::KeyOrEnd => {
                if data[i] == b'}' && stack.last() == Some(&b'{') {
                    stack.pop();
                    i += 1;
                    match value_done(&stack) {
                        None => return Some(i),
                        Some(e) => expect = e,
                    }
                } else if data[i] == b'"' {
                    i = scan_string(data, i)?;
                    expect = Expect::Colon;
                } else {
                    return None;
                }
            }
            Expect::Colon => {
                if data[i] == b':' {
                    i += 1;
                    expect = Expect::Value;
                } else {
                    return None;
                }
            }
            Expect::CommaOrEnd => {
                let open = *stack.last()?;
                if data[i] == b',' {
                    i += 1;
                    expect = if open == b'{' {
                        Expect::KeyOrEnd
                    } else {
                        Expect::Value
                    };
                } else if (open == b'{' && data[i] == b'}')
                    || (open == b'[' && data[i] == b']')
                {
                    stack.pop();
                    i += 1;
                    match value_done(&stack) {
                        None => return Some(i),
                        Some(e) => expect = e,
                    }
                } else {
                    return None;
                }
            }
        }
    }
}

fn skip_ws(data: &[u8], mut i: usize) -> usize {
    while i < data.len() && matches!(data[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// End offset just past a string starting at `i` (the
/// opening quote), or `None` when unterminated. Escapes
/// are skipped opaquely (`\` + the next byte); the real
/// parser validates them. Raw bytes — including invalid
/// UTF-8 — are string content, exactly as Go's scanner
/// treats them.
fn scan_string(data: &[u8], mut i: usize) -> Option<usize> {
    debug_assert_eq!(data[i], b'"');
    i += 1;
    while i < data.len() {
        match data[i] {
            b'"' => return Some(i + 1),
            b'\\' => {
                i += 2;
                if i > data.len() {
                    return None;
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// End offset just past a literal (`true`/`false`/`null`)
/// starting at `i`, or `None`.
fn scan_lit(data: &[u8], i: usize, lit: &[u8]) -> Option<usize> {
    if data.len() - i < lit.len() || &data[i..i + lit.len()] != lit {
        return None;
    }
    Some(i + lit.len())
}

/// End offset just past a JSON number starting at `i`
/// (strict grammar: `-? (0 | [1-9][0-9]*) (.[0-9]+)?
/// ([eE][+-]?[0-9]+)?`), or `None`. The digits are never
/// interpreted, so `1e999` scans fine and the literal is
/// preserved by the real parser.
fn scan_number(data: &[u8], mut i: usize) -> Option<usize> {
    if i < data.len() && data[i] == b'-' {
        i += 1;
    }
    if i >= data.len() {
        return None;
    }
    if data[i] == b'0' {
        i += 1;
    } else if data[i].is_ascii_digit() {
        while i < data.len() && data[i].is_ascii_digit() {
            i += 1;
        }
    } else {
        return None;
    }
    if i < data.len() && data[i] == b'.' {
        i += 1;
        if i >= data.len() || !data[i].is_ascii_digit() {
            return None;
        }
        while i < data.len() && data[i].is_ascii_digit() {
            i += 1;
        }
    }
    if i < data.len() && (data[i] == b'e' || data[i] == b'E') {
        let mut j = i + 1;
        if j < data.len() && (data[j] == b'+' || data[j] == b'-') {
            j += 1;
        }
        if j >= data.len() || !data[j].is_ascii_digit() {
            return None;
        }
        while j < data.len() && data[j].is_ascii_digit() {
            j += 1;
        }
        i = j;
    }
    Some(i)
}

/// `decodeGeneric` semantics: decode the first JSON value,
/// ignore the rest entirely. Falls back to the strict
/// whole-input decode when the boundary cannot be located
/// but the whole input still parses (scanner/parser
/// disagreements, e.g. Go's `More()` quirk where a
/// trailing `}` is tolerated).
pub fn decode_first_value(data: &[u8]) -> Result<JsonValue, ConfigError> {
    if let Some(end) = first_value_end(data)
        && let Ok(v) = decode_ordered_json(&data[..end])
    {
        return Ok(v);
    }
    decode_ordered_json(data)
}

/// `decodeBody` / `bodyJSON` semantics: decode the first
/// value; trailing whitespace is fine; a trailing valid
/// second JSON value is tolerated; trailing garbage is
/// the fixed 400 `invalid JSON in request body`.
pub fn decode_body_value(data: &[u8]) -> Result<JsonValue, ApiError> {
    let err = || err_validation("invalid JSON in request body");
    let end = first_value_end(data).ok_or_else(err)?;
    let value = decode_ordered_json(&data[..end]).map_err(|_| err())?;
    let rest = &data[end..];
    let rest_trimmed = trim_ascii_ws(rest);
    if rest_trimmed.is_empty() {
        return Ok(value);
    }
    // A trailing valid value is tolerated (Go's second
    // Decode succeeds); trailing garbage is rejected.
    if first_value_end(rest_trimmed).is_some() || decode_ordered_json(rest_trimmed).is_ok() {
        return Ok(value);
    }
    Err(err())
}

fn trim_ascii_ws(data: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = data.len();
    while start < end && matches!(data[start], b' ' | b'\t' | b'\n' | b'\r') {
        start += 1;
    }
    while end > start && matches!(data[end - 1], b' ' | b'\t' | b'\n' | b'\r') {
        end -= 1;
    }
    &data[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_value_only_ignores_trailing_garbage() {
        let v = decode_first_value(b"{\"a\": 1} trailing garbage").unwrap();
        assert_eq!(v, decode_ordered_json(b"{\"a\": 1}").unwrap());
    }

    #[test]
    fn body_value_tolerates_trailing_valid_value() {
        let v = decode_body_value(b"{\"a\": 1} {\"b\": 2}").unwrap();
        assert_eq!(v, decode_ordered_json(b"{\"a\": 1}").unwrap());
    }

    #[test]
    fn body_value_rejects_trailing_garbage() {
        assert!(decode_body_value(b"{\"a\": 1} xyz").is_err());
        assert!(decode_body_value(b"{\"a\": 1").is_err());
        assert!(decode_body_value(b"not json").is_err());
    }

    #[test]
    fn body_value_accepts_clean_input() {
        let v = decode_body_value(b"  {\"a\": [1, 2.5, \"x\"]}  \n").unwrap();
        assert_eq!(v, decode_ordered_json(b"{\"a\": [1, 2.5, \"x\"]}").unwrap());
    }


    #[test]
    fn body_value_accepts_deep_nesting() {
        // F-C3(a): Go allows nesting to depth 10000;
        // serde_json's default limit is 128. Depth 200
        // must decode.
        let mut input = vec![b'['; 200];
        input.push(b'1');
        input.extend(vec![b']'; 200]);
        let v = decode_body_value(&input).expect("depth 200 decodes");
        assert_eq!(v, decode_ordered_json(&input).unwrap());
    }

    #[test]
    fn body_value_rejects_over_go_depth() {
        // Go's own cap is 10000: depth 10001 is a 400 on
        // both sides.
        let mut input = vec![b'['; 10001];
        input.push(b'1');
        input.extend(vec![b']'; 10001]);
        assert!(decode_body_value(&input).is_err());
    }

    #[test]
    fn body_value_keeps_out_of_range_float_literal() {
        // F-C3(b): Go UseNumber keeps `1e999` as a literal;
        // serde_json errors NumberOutOfRange.
        let v = decode_body_value(b"{\"n\": 1e999}").expect("1e999 decodes");
        let JsonValue::Object(obj) = &v else {
            panic!("expected object");
        };
        assert_eq!(
            obj.get("n"),
            Some(&JsonValue::Number("1e999".to_string()))
        );
    }

    #[test]
    fn body_value_coerces_invalid_utf8() {
        // F-C3(c): Go coerces an invalid UTF-8 byte inside
        // a string to U+FFFD (per byte, Go DecodeRune);
        // serde's from_slice rejects the whole body.
        let v = decode_body_value(b"{\"a\": \"\xff\"}").expect("invalid UTF-8 coerces");
        let JsonValue::Object(obj) = &v else {
            panic!("expected object");
        };
        assert_eq!(obj.get("a"), Some(&JsonValue::Str("\u{fffd}".to_string())));
    }

    #[test]
    fn first_value_end_rejects_bad_json() {
        assert_eq!(first_value_end(b""), None);
        assert_eq!(first_value_end(b"   "), None);
        assert_eq!(first_value_end(b"{\"a\": 1"), None);
        assert_eq!(first_value_end(b"[1,]"), None);
        assert_eq!(first_value_end(b"{\"a\": }"), None);
        assert_eq!(first_value_end(b"{\"a\" 1}"), None);
        assert_eq!(first_value_end(b"tru"), None);
        assert_eq!(first_value_end(b"1e"), None);
        assert_eq!(first_value_end(b"\"unterminated"), None);
        // Valid ends: scalar, empty containers, nested.
        assert_eq!(first_value_end(b"true"), Some(4));
        assert_eq!(first_value_end(b"[]"), Some(2));
        assert_eq!(first_value_end(b"{}"), Some(2));
        assert_eq!(first_value_end(b"[[1],{\"a\":null}] x"), Some(16));
        assert_eq!(first_value_end(b"\"a\\nb\""), Some(6));
    }

    #[test]
    fn body_value_preserves_number_literals() {
        // Numbers stay literals (never float64): 9007199254740993
        // must survive the round trip exactly.
        let v = decode_body_value(b"{\"n\": 9007199254740993}").unwrap();
        let JsonValue::Object(obj) = &v else {
            panic!("expected object");
        };
        assert_eq!(
            obj.get("n"),
            Some(&JsonValue::Number("9007199254740993".to_string()))
        );
    }
}
