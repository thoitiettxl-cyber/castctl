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
//! other number becomes [`JsonValue::Float`] carrying its
//! original literal text (`serde_json` with
//! `arbitrary_precision` keeps the literal, so
//! `n.to_string()` returns it verbatim) — with one known
//! exception: `-0` is normalized to integer `0` by
//! serde_json at parse time (`parse_any_number` tries
//! `i64` first), so it arrives here as `Int(0)` and
//! re-emits `0`, while Go emits `-0`. See
//! `rust/PORTING.md` §M4c.10. Object keys iterate sorted
//! (both models sort: `serde_json::Value` without
//! `preserve_order` is a `BTreeMap`, as is
//! [`JsonValue::Object`]).
//!
//! Literals are preserved character-for-character through
//! the bridge — `1.0` stays `1.0`, `1e3` stays `1e3` —
//! because `JsonValue::Float` stores the literal, not an
//! `f64`. Equality follows the literal too (`1.0 != 1.00`,
//! `1e3 != 1000`), exactly like Go's `json.Number` (a
//! string type). See `rust/PORTING.md` §M4c.10.

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
            } else {
                // Every decoded number carries its literal
                // (arbitrary_precision); keep it verbatim.
                // Integer spellings above i64::MAX land here
                // too — Go's json.Number float fallback
                // converts those to i64::MIN via asInt64,
                // exactly as the Float arm does there.
                JsonValue::Float(n.to_string())
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
    fn from_serde_floats_keep_literal_spelling() {
        // Literals survive the bridge character-for-character
        // (Go json.Number parity); equality follows the
        // literal, not the numeric value.
        let v: SerdeValue = serde_json::from_str("1.5").unwrap();
        assert_eq!(from_serde(&v), JsonValue::Float("1.5".to_string()));
        let v: SerdeValue = serde_json::from_str("1.0").unwrap();
        assert_eq!(from_serde(&v), JsonValue::Float("1.0".to_string()));
        let v: SerdeValue = serde_json::from_str("1.00").unwrap();
        assert_eq!(from_serde(&v), JsonValue::Float("1.00".to_string()));
        assert_ne!(
            from_serde(&serde_json::from_str::<SerdeValue>("1.0").unwrap()),
            from_serde(&serde_json::from_str::<SerdeValue>("1.00").unwrap()),
            "1.0 != 1.00, like Go json.Number"
        );
        // The discriminator: 1e3 keeps its exponent form.
        let v: SerdeValue = serde_json::from_str("1e3").unwrap();
        assert_eq!(from_serde(&v), JsonValue::Float("1e3".to_string()));
        assert_ne!(
            from_serde(&v),
            JsonValue::Int(1000),
            "1e3 != 1000, like Go json.Number"
        );
        // Above i64::MAX: Go's json.Number float fallback
        // converts via int64(f) -> i64::MIN in asInt64.
        let v: SerdeValue = serde_json::from_str("9223372036854775808").unwrap();
        assert_eq!(
            from_serde(&v),
            JsonValue::Float("9223372036854775808".to_string())
        );
        assert_eq!(
            crate::value::as_int64(&from_serde(&v)),
            Some(i64::MIN),
            "matches Go asInt64 float fallback"
        );
    }

    #[test]
    fn from_serde_neg_zero_collapses_to_int_zero_known_limitation() {
        // KNOWN LIMITATION (PORTING §M4c.10), pinned so it
        // cannot silently change: serde_json 1.0.145
        // normalizes "-0" to integer 0 at parse time
        // (`parse_any_number` tries `i64` first), so the
        // Value reaching from_serde is indistinguishable
        // from input "0" (`to_string()` is "0", `as_i64()`
        // is Some(0)). No special-case here can recover the
        // minus — it is already gone. Go emits "-0"
        // verbatim (json.Number). A real fix needs the
        // decode layer (RawValue / custom number handling
        // in the gateway), not this bridge.
        let v: SerdeValue = serde_json::from_str("-0").unwrap();
        assert_eq!(from_serde(&v), JsonValue::Int(0));
        let w: SerdeValue = serde_json::from_str("0").unwrap();
        assert_eq!(from_serde(&v), from_serde(&w));
    }

    #[test]
    fn from_serde_float_as_int64_follows_go() {
        // Go asInt64 float fallback, via the stored literal:
        // truncate toward zero; out-of-range -> i64::MIN;
        // non-finite -> None.
        let lit = |s: &str| {
            crate::value::as_int64(&from_serde(&serde_json::from_str::<SerdeValue>(s).unwrap()))
        };
        assert_eq!(lit("1e3"), Some(1000));
        assert_eq!(lit("1.0"), Some(1));
        assert_eq!(lit("0.0"), Some(0));
        assert_eq!(lit("-0.5"), Some(0));
        assert_eq!(lit("9007199254740993"), Some(9007199254740993));
        assert_eq!(lit("1e100"), Some(i64::MIN));
        assert_eq!(lit("-1e100"), Some(i64::MIN));
        assert_eq!(lit("1e999"), None);
        // "-0" keeps its literal as Float but still
        // converts to 0, like Go asInt64 (0, true).
        assert_eq!(lit("-0"), Some(0));
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
