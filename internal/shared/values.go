// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

import (
	"encoding/json"
	"math"
)

// asMap reports v as a JSON object, or false when v is not one.
func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// asList reports v as a JSON array, or false when v is not one.
func asList(v any) ([]any, bool) {
	l, ok := v.([]any)
	return l, ok
}

// asString reports v as a string, or false for any other type
// (including nil). JSON null is not a string.
func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// asInt64 converts a decoded JSON number to int64. Accepted forms
// are json.Number (integer or float spelling, truncated toward
// zero), int64, int, int32 and float64 (truncated toward zero).
// Booleans, strings and nil are not numbers. This mirrors the
// plan's JSON invariant: numbers arrive as int64/json.Number, never
// float64, but fakes and hand-built fixtures may use plain ints.
func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return int64(f), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, false
		}
		return int64(n), true
	default:
		return 0, false
	}
}

// asBool reports v as a bool, or false for any other type. Only a
// real JSON boolean counts; 0/1 and "true"/"false" do not.
func asBool(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

// truthy mirrors Python truthiness for the values shaping code
// inspects: nil is false, false/0/"" are false, empty arrays and
// objects are false, everything else is true. It is used only where
// Python tests truthiness (e.g. an entry's "missing" flag), never
// where Python reads a typed value.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		if n, ok := asInt64(v); ok {
			return n != 0
		}
		return v != nil
	}
}

// payloadOf returns ev's "payload" object, or an empty object when
// ev has no payload or it is not an object. This is Python's
// `e.get("payload", {}) if isinstance(e.get("payload"), dict)
// else {}`.
func payloadOf(ev map[string]any) map[string]any {
	if p, ok := asMap(ev["payload"]); ok {
		return p
	}
	return map[string]any{}
}

// stringField returns m[key] when it is a string, else "".
func stringField(m map[string]any, key string) string {
	s, _ := asString(m[key])
	return s
}

// stringPtrField returns a pointer to m[key] when the key is present
// with a string value (including ""), else nil. JSON null, a missing
// key and a non-string value all yield nil, matching Python's .get()
// returning None for the JSON null those cases produce.
func stringPtrField(m map[string]any, key string) *string {
	v, present := m[key]
	if !present || v == nil {
		return nil
	}
	s, ok := asString(v)
	if !ok {
		return nil
	}
	return &s
}

// intPtrField returns a pointer to m[key] as int64 when the key is
// present with a numeric value, else nil.
func intPtrField(m map[string]any, key string) *int64 {
	v, present := m[key]
	if !present || v == nil {
		return nil
	}
	n, ok := asInt64(v)
	if !ok {
		return nil
	}
	return &n
}

// intField returns m[key] as int64, or def when the key is absent,
// null, or non-numeric.
func intField(m map[string]any, key string, def int64) int64 {
	if n, ok := asInt64(m[key]); ok {
		return n
	}
	return def
}

// boolPtrField returns a pointer to m[key] when it is a JSON
// boolean, else nil.
func boolPtrField(m map[string]any, key string) *bool {
	v, present := m[key]
	if !present || v == nil {
		return nil
	}
	b, ok := asBool(v)
	if !ok {
		return nil
	}
	return &b
}

// firstString returns the first non-empty string among vs, or "".
// This is Python's `a or b or ""` over string fields.
func firstString(vs ...any) string {
	for _, v := range vs {
		if s, ok := asString(v); ok && s != "" {
			return s
		}
	}
	return ""
}
