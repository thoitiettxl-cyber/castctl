// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Bridge from the gateway's JSON model (`serde_json::Value`,
//! `arbitrary_precision` — numbers keep their literal) to
//! this crate's closed [`JsonValue`] model, so the shaping
//! functions can run on gateway results.
//!
//! Number mapping (mirrors Go `json.Number` / `asInt64`,
//! `internal/shared/values.go:37`): an integer-spelled
//! number that fits `i64` becomes [`JsonValue::Int`]; any
//! other finite number becomes [`JsonValue::Float`] (a float
//! spelling, or an integer spelling above `i64::MAX` — Go's
//! `json.Number` float fallback converts those to
//! `i64::MIN` via `asInt64`, exactly as the `Float` arm does
//! here). Object keys iterate sorted (both models sort:
//! `serde_json::Value` without `preserve_order` is a
//! `BTreeMap`, as is [`JsonValue::Object`]).
//!
//! Limitation (recorded in `rust/PORTING.md` §M4b): a
//! float-spelled literal is not preserved character-for-
//! character through the bridge — `1.50` becomes `1.5`
//! when re-serialized. Values stay numerically identical;
//! only pass-through (unshaped) outputs avoid the bridge
//! entirely and keep the literal.

use std::collections::BTreeMap;

use serde_json::Value as SerdeValue;

use crate::value::JsonValue;

/// Convert a gateway JSON value to this crate's model.
pub fn from_serde(v: &SerdeValue) -> JsonValue {
    match v {
        SerdeValue::Null => JsonValue::Null,
        SerdeValue::Bool(b) => JsonValue::Bool(*b),
        SerdeValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                JsonValue::Int(i)
            } else if let Some(f) = n.as_f64() {
                JsonValue::Float(f)
            } else {
                // With arbitrary_precision the literal is kept
                // as a string; a u64 above i64::MAX with no
                // float form falls back to parsing the literal
                // (NaN only when the literal is unparseable,
                // which cannot happen for a decoded number).
                JsonValue::Float(n.to_string().parse().unwrap_or(f64::NAN))
            }
        }
        SerdeValue::String(s) => JsonValue::Str(s.clone()),
        SerdeValue::Array(items) => JsonValue::Array(items.iter().map(from_serde).collect()),
        SerdeValue::Object(map) => {
            let mut out = BTreeMap::new();
            for (k, val) in map {
                out.insert(k.clone(), from_serde(val));
            }
            JsonValue::Object(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_serde_numbers_keep_int_class() {
        let v: SerdeValue = serde_json::from_str("42").unwrap();
        assert_eq!(from_serde(&v), JsonValue::Int(42));
        let v: SerdeValue = serde_json::from_str("-7").unwrap();
        assert_eq!(from_serde(&v), JsonValue::Int(-7));
        // i64::MAX stays an integer.
        let v: SerdeValue = serde_json::from_str("9223372036854775807").unwrap();
        assert_eq!(from_serde(&v), JsonValue::Int(i64::MAX));
    }

    #[test]
    fn from_serde_floats_and_big_integers_become_float() {
        let v: SerdeValue = serde_json::from_str("1.5").unwrap();
        assert_eq!(from_serde(&v), JsonValue::Float(1.5));
        // Above i64::MAX: Go's json.Number float fallback
        // converts via int64(f) -> i64::MIN in asInt64.
        let v: SerdeValue = serde_json::from_str("9223372036854775808").unwrap();
        assert_eq!(from_serde(&v), JsonValue::Float(9223372036854775808.0));
        assert_eq!(
            crate::value::as_int64(&from_serde(&v)),
            Some(i64::MIN),
            "matches Go asInt64 float fallback"
        );
    }

    #[test]
    fn from_serde_objects_arrays_and_scalars() {
        let v: SerdeValue =
            serde_json::from_str(r#"{"b": [1, "x", true, null], "a": {"k": 2}}"#).unwrap();
        let got = from_serde(&v);
        // Object keys sort (both models are BTreeMap).
        let mut inner = BTreeMap::new();
        inner.insert("k".to_string(), JsonValue::Int(2));
        let mut outer = BTreeMap::new();
        outer.insert(
            "b".to_string(),
            JsonValue::Array(vec![
                JsonValue::Int(1),
                JsonValue::Str("x".to_string()),
                JsonValue::Bool(true),
                JsonValue::Null,
            ]),
        );
        outer.insert("a".to_string(), JsonValue::Object(inner));
        assert_eq!(got, JsonValue::Object(outer));
        assert_eq!(from_serde(&SerdeValue::Null), JsonValue::Null);
        assert_eq!(
            from_serde(&SerdeValue::String("s".to_string())),
            JsonValue::Str("s".to_string())
        );
    }
}
