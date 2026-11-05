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
// Boundary detection uses serde_json's streaming
// deserializer only to locate the end offset; the actual
// parse is always `decode_ordered_json`, so key order and
// number literals are preserved. If the stream parse fails
// (e.g. serde_json's 128-deep recursion limit, which the
// hand parser does not share), the decoders fall back to
// the strict whole-input decode.

use crate::error::{err_validation, ApiError};
use castctl_config::jsonvalue::{JsonValue, decode_ordered_json};
use castctl_config::ConfigError;

/// End offset (exclusive) of the first complete JSON value
/// in `data`, or `None` when no complete value can be
/// found. Leading whitespace is skipped; the offset is
/// measured from the start of `data`.
pub fn first_value_end(data: &[u8]) -> Option<usize> {
    let mut stream = serde_json::Deserializer::from_slice(data)
        .into_iter::<serde_json::Value>();
    match stream.next() {
        Some(Ok(_)) => Some(stream.byte_offset()),
        _ => None,
    }
}

/// `decodeGeneric` semantics: decode the first JSON value,
/// ignore the rest entirely. Falls back to the strict
/// whole-input decode when the boundary cannot be located
/// (deep nesting), so valid documents are never rejected
/// for a boundary-detection limitation.
pub fn decode_first_value(data: &[u8]) -> Result<JsonValue, ConfigError> {
    if let Some(end) = first_value_end(data) {
        if let Ok(v) = decode_ordered_json(&data[..end]) {
            return Ok(v);
        }
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
    if first_value_end(rest_trimmed).is_some()
        || decode_ordered_json(rest_trimmed).is_ok()
    {
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
