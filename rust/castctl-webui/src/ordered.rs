// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Order-preserving render of a merged config document
//! (`internal/webui/ordered.go` `marshalOrdered`).
//!
//! Stored key order wins everywhere, changed values overlay
//! in place, keys the save introduces append in sorted order
//! (deterministic). Number literals survive via
//! `JsonValue::Number`; HTML-significant characters stay
//! literal (no HTML escaping), matching the canonical
//! encoder's byte shape. With no stored bytes there is no
//! order to preserve: the document renders with sorted keys,
//! as `json.Marshal` would.
//!
//! Brand-new subtrees (no stored counterpart) render with
//! sorted keys at every level, exactly as Go's
//! `json.Marshal` of a `map[string]any` does inside
//! `marshalOrderedValue`'s default arm.

use crate::go_json::sort_keys_deep;
use castctl_config::jsonvalue::{
    JsonValue, OrderedObject, decode_ordered_json, encode_ordered_json,
};

/// `marshalOrdered(storedRaw, doc)`: render `doc` as compact
/// JSON preserving the stored document's key order.
pub fn marshal_ordered(stored_raw: &[u8], doc: &JsonValue) -> Result<Vec<u8>, String> {
    if stored_raw.iter().all(|b| b.is_ascii_whitespace()) {
        let mut sorted = doc.clone();
        sort_keys_deep(&mut sorted);
        let text = encode_ordered_json(&sorted).map_err(|e| e.message)?;
        return Ok(text.into_bytes());
    }
    let stored_text = String::from_utf8(stored_raw.to_vec())
        .map_err(|e| format!("stored config is not valid UTF-8: {e}"))?;
    let stored = decode_ordered_json(stored_text.as_bytes())
        .map_err(|e| format!("stored config is invalid: {e}"))?;
    let overlaid = overlay_ordered(&stored, doc);
    Ok(encode_ordered_json(&overlaid)
        .map_err(|e| e.message)?
        .into_bytes())
}

/// `overlayOrdered(stored, doc)`: stored keys keep their
/// order with merged values, stored keys absent from doc
/// drop, doc keys with no stored position append sorted.
/// Arrays overlay positionally; anything else takes the
/// merged value (a brand-new subtree renders sorted).
fn overlay_ordered(stored: &JsonValue, doc: &JsonValue) -> JsonValue {
    match (stored, doc) {
        (JsonValue::Object(stored_obj), JsonValue::Object(doc_obj)) => {
            let mut out = OrderedObject::new();
            for (k, stored_v) in stored_obj.iter() {
                if let Some(doc_v) = doc_obj.get(k) {
                    out.set(k.clone(), overlay_ordered(stored_v, doc_v));
                }
            }
            let mut extra: Vec<&str> = doc_obj
                .keys()
                .iter()
                .filter(|k| !stored_obj.has(k))
                .map(|k| k.as_str())
                .collect();
            extra.sort_unstable();
            for k in extra {
                let mut v = doc_obj.get(k).expect("extra key present").clone();
                sort_keys_deep(&mut v);
                out.set(k.to_string(), v);
            }
            JsonValue::Object(out)
        }
        (JsonValue::Array(stored_arr), JsonValue::Array(doc_arr)) => {
            let mut out: Vec<JsonValue> = Vec::with_capacity(doc_arr.len());
            for (i, doc_v) in doc_arr.iter().enumerate() {
                if i < stored_arr.len() {
                    out.push(overlay_ordered(&stored_arr[i], doc_v));
                } else {
                    let mut v = doc_v.clone();
                    sort_keys_deep(&mut v);
                    out.push(v);
                }
            }
            JsonValue::Array(out)
        }
        (_, doc_v) => {
            // Type change or scalar: the merged value as-is,
            // sorted when it is a brand-new subtree.
            let mut v = doc_v.clone();
            sort_keys_deep(&mut v);
            v
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use castctl_config::jsonvalue::decode_ordered_json;

    #[test]
    fn stored_order_wins_new_keys_append_sorted() {
        let stored = br#"{"b": 1, "a": {"z": 1, "y": 2}, "c": [1, 2]}"#;
        let doc = decode_ordered_json(
            r#"{"a": {"y": 20, "n": 1}, "d": {"q": 1, "p": 2}, "b": 10}"#.as_bytes(),
        )
        .unwrap();
        let out = marshal_ordered(stored, &doc).unwrap();
        // b keeps first position with the new value; a keeps
        // order (z dropped, y overlaid, n appended sorted);
        // c dropped (absent from doc); d appended sorted,
        // its subtree rendered sorted (p before q).
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"{"b":10,"a":{"y":20,"n":1},"d":{"p":2,"q":1}}"#
        );
    }

    #[test]
    fn empty_stored_renders_sorted() {
        let doc = decode_ordered_json(r#"{"b": 1, "a": 2}"#.as_bytes()).unwrap();
        let out = marshal_ordered(b"  \n", &doc).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn arrays_overlay_positionally() {
        let stored = br#"{"arr": [{"tag": "x", "v": 1}, {"tag": "y"}]}"#;
        let doc = decode_ordered_json(
            r#"{"arr": [{"tag": "x", "v": 9, "n": 1}, {"tag": "y"}, {"tag": "z"}]}"#.as_bytes(),
        )
        .unwrap();
        let out = marshal_ordered(stored, &doc).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"{"arr":[{"tag":"x","v":9,"n":1},{"tag":"y"},{"tag":"z"}]}"#
        );
    }

    #[test]
    fn fail_before_stored_order() {
        // A plain sorted render would put "a" first; Go
        // keeps the stored order ("b" first). This pins it.
        let stored = br#"{"b": 1, "a": 2}"#;
        let doc = decode_ordered_json(r#"{"a": 20, "b": 10}"#.as_bytes()).unwrap();
        let out = marshal_ordered(stored, &doc).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"b":10,"a":20}"#);
    }
}
