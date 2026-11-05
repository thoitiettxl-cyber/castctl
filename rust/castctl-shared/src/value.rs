// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Decoded-JSON value model and the `values.go` shaping helpers.
//!
//! The Go code works on `any` values decoded from JSON. The Rust
//! model is a closed [`JsonValue`] enum; object keys iterate in
//! sorted (byte) order via [`BTreeMap`], which reproduces both
//! Go's `sort.Strings` visit order in `EventResources` and Go's
//! `encoding/json` map-key order.

use std::collections::BTreeMap;
use std::sync::OnceLock;

/// A decoded JSON value.
///
/// Numbers keep their spelling class: [`JsonValue::Int`] for
/// integer spellings (Go `int64` / `json.Number` integer form),
/// [`JsonValue::Float`] for float spellings (Go `float64` /
/// `json.Number` float form). That split is what lets
/// `as_int64` reproduce Go's integer-first, float-fallback
/// conversion. There is deliberately no `UInt` variant: a Go
/// `uint64` fixture value above `i64::MAX` has no M1 model;
/// see `rust/PORTING.md`.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    /// JSON `null`.
    Null,
    /// JSON boolean.
    Bool(bool),
    /// Integer-spelled number.
    Int(i64),
    /// Float-spelled number.
    Float(f64),
    /// JSON string.
    Str(String),
    /// JSON array.
    Array(Vec<JsonValue>),
    /// JSON object; keys iterate in sorted order.
    Object(BTreeMap<String, JsonValue>),
}

/// Object type alias, for readability in helper signatures.
pub type JsonObject = BTreeMap<String, JsonValue>;

fn empty_object() -> &'static JsonObject {
    static EMPTY: OnceLock<JsonObject> = OnceLock::new();
    EMPTY.get_or_init(BTreeMap::new)
}

/// Returns `v` as a JSON object, or `None` when it is not one.
/// Source: `internal/shared/values.go:13` (`asMap`).
pub(crate) fn as_map(v: &JsonValue) -> Option<&JsonObject> {
    match v {
        JsonValue::Object(m) => Some(m),
        _ => None,
    }
}

/// Returns `v` as a JSON array, or `None` when it is not one.
/// Source: `internal/shared/values.go:19` (`asList`).
pub(crate) fn as_list(v: &JsonValue) -> Option<&Vec<JsonValue>> {
    match v {
        JsonValue::Array(l) => Some(l),
        _ => None,
    }
}

/// Returns `v` as a string, or `None` for any other type
/// (including null). The empty string is a string.
/// Source: `internal/shared/values.go:26` (`asString`).
pub(crate) fn as_string(v: &JsonValue) -> Option<&str> {
    match v {
        JsonValue::Str(s) => Some(s),
        _ => None,
    }
}

/// Converts a decoded JSON number to `i64`: integer spellings
/// directly, float spellings truncated toward zero; NaN and
/// infinities are not numbers. Booleans, strings and null are
/// not numbers.
/// Source: `internal/shared/values.go:37` (`asInt64`).
///
/// The float arm reproduces Go's `int64(f)` on amd64 exactly:
/// out-of-range values (either direction, including `1e100`)
/// convert to `i64::MIN` — the x86 CVTTSD2SI indefinite value —
/// rather than saturating as a Rust `as` cast would. Measured
/// by probe P-6 on cue: `1e100` and `-1e100` both yield
/// `i64::MIN` with `ok=true`; NaN/`±Inf` yield `ok=false`.
pub(crate) fn as_int64(v: &JsonValue) -> Option<i64> {
    match v {
        JsonValue::Int(n) => Some(*n),
        JsonValue::Float(f) => {
            if f.is_nan() || f.is_infinite() {
                None
            } else if *f >= 9_223_372_036_854_775_808.0 || *f <= -9_223_372_036_854_775_808.0 {
                // 2^63, as the nearest `f64`. Go `int64(f)` for
                // |f| >= 2^63 is the indefinite value.
                Some(i64::MIN)
            } else {
                Some(*f as i64)
            }
        }
        _ => None,
    }
}

/// Returns `v` as a bool, or `None` for any other type.
/// Source: `internal/shared/values.go:74` (`asBool`).
pub(crate) fn as_bool(v: &JsonValue) -> Option<bool> {
    match v {
        JsonValue::Bool(b) => Some(*b),
        _ => None,
    }
}

/// Python truthiness: null is false, `false`/`0`/`""`/empty
/// array/object are false, everything else is true. A float
/// NaN is true: it is not a number per `as_int64`, so it
/// falls through to the default arm, as in Go.
/// Source: `internal/shared/values.go:84` (`truthy`).
pub(crate) fn truthy(v: &JsonValue) -> bool {
    match v {
        JsonValue::Null => false,
        JsonValue::Bool(b) => *b,
        JsonValue::Str(s) => !s.is_empty(),
        JsonValue::Array(l) => !l.is_empty(),
        JsonValue::Object(m) => !m.is_empty(),
        _ => match as_int64(v) {
            Some(n) => n != 0,
            None => true,
        },
    }
}

/// Returns `ev`'s `"payload"` object, or an empty object when
/// `ev` has no payload or it is not an object.
/// Source: `internal/shared/values.go:108` (`payloadOf`).
pub(crate) fn payload_of(ev: &JsonObject) -> &JsonObject {
    match ev.get("payload") {
        Some(v) => match as_map(v) {
            Some(p) => p,
            None => empty_object(),
        },
        None => empty_object(),
    }
}

/// Returns `m[key]` when it is a string, else `""`.
/// Source: `internal/shared/values.go:116` (`stringField`).
pub(crate) fn string_field<'a>(m: &'a JsonObject, key: &str) -> &'a str {
    match m.get(key) {
        Some(v) => as_string(v).unwrap_or(""),
        None => "",
    }
}

/// Returns `m[key]` when the key is present with a string value
/// (including `""`), else `None`. Null, missing and non-string
/// values all yield `None`.
/// Source: `internal/shared/values.go:125` (`stringPtrField`).
pub(crate) fn string_ptr_field(m: &JsonObject, key: &str) -> Option<String> {
    match m.get(key) {
        Some(JsonValue::Null) | None => None,
        Some(v) => as_string(v).map(str::to_string),
    }
}

/// Returns `m[key]` as `i64` when the key is present with a
/// numeric value, else `None`.
/// Source: `internal/shared/values.go:139` (`intPtrField`).
pub(crate) fn int_ptr_field(m: &JsonObject, key: &str) -> Option<i64> {
    match m.get(key) {
        Some(JsonValue::Null) | None => None,
        Some(v) => as_int64(v),
    }
}

/// Returns `m[key]` as `i64`, or `def` when the key is absent,
/// null, or non-numeric.
/// Source: `internal/shared/values.go:153` (`intField`).
/// 0 ported cases (D5): no M1-scope test exercises it directly.
/// The allow is deliberate: deleting the helper would drop a
/// ported function, inventing a test table would violate D5.
#[allow(dead_code)]
pub(crate) fn int_field(m: &JsonObject, key: &str, def: i64) -> i64 {
    match m.get(key) {
        Some(v) => as_int64(v).unwrap_or(def),
        None => def,
    }
}

/// Returns `m[key]` when it is a JSON boolean, else `None`.
/// Source: `internal/shared/values.go:162` (`boolPtrField`).
/// 0 ported cases (D5): no M1-scope test exercises it directly.
/// The allow is deliberate: deleting the helper would drop a
/// ported function, inventing a test table would violate D5.
#[allow(dead_code)]
pub(crate) fn bool_ptr_field(m: &JsonObject, key: &str) -> Option<bool> {
    match m.get(key) {
        Some(JsonValue::Null) | None => None,
        Some(v) => as_bool(v),
    }
}

/// First non-empty string among `vs`, or `""`.
/// Source: `internal/shared/values.go:176` (`firstString`).
/// 0 ported cases (D5): no M1-scope test exercises it directly.
/// The allow is deliberate: deleting the helper would drop a
/// ported function, inventing a test table would violate D5.
#[allow(dead_code)]
pub(crate) fn first_string(vs: &[&JsonValue]) -> String {
    for v in vs {
        if let Some(s) = as_string(v)
            && !s.is_empty()
        {
            return s.to_string();
        }
    }
    String::new()
}

/// First non-empty string among `vs`, or `None`. Unlike
/// [`string_ptr_field`], an empty string in the first source
/// falls through to the next (Python `or` fallback).
/// Source: `internal/shared/event.go:64` (`firstStringPtr`).
pub(crate) fn first_string_ptr(vs: &[&JsonValue]) -> Option<String> {
    for v in vs {
        if let Some(s) = as_string(v)
            && !s.is_empty()
        {
            return Some(s.to_string());
        }
    }
    None
}

/// Returns `m[key]`, or null when the key is absent. Used where
/// Go indexes a map and passes the (possibly nil) value on.
pub(crate) fn get_or_null<'a>(m: &'a JsonObject, key: &str) -> &'a JsonValue {
    match m.get(key) {
        Some(v) => v,
        None => &JsonValue::Null,
    }
}
