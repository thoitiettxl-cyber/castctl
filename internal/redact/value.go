// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package redact

import (
	"reflect"
	"strings"
)

// Marker is the replacement for every redacted structured value.
// It is exactly "<redacted>", with no brackets or spaces, so it
// survives JSON encoding literally (callers encode with HTML
// escaping disabled for the same reason).
const Marker = "<redacted>"

// secretKeys are the map keys whose values are secret material.
// The set is the union of the PR1/PR2 profile show-serialisation
// list and the sing-box 1.14.4 schema fields the delta list
// missed, plus the header key "authorization" (NB12: header values
// must never be printed by profile show). "secret" and "cookie"
// are carried from the profile helper: sing-box option objects
// carry those names for genuinely secret material (OpenConnect
// token secret, OpenConnect session cookie). "obfs" is redacted
// wholesale, whatever its type: an obfs object carries its own
// password, and the profile tests pin the whole object redacted.
// The B1 additions are the remaining secret-bearing sing-box
// 1.14.4 option fields: ACME/Origin CA credentials (api_token,
// access_key_secret, account_key, mac_key, origin_ca_key,
// security_token, zone_token), OpenConnect material
// (client_key_password, mca_key, mca_key_password,
// submission_key), the Tailscale mesh key (mesh_psk), the OpenVPN
// static key (static_key), TLS client material (client_key,
// client_certificate), and the Snell user key (userkey).
// Matching is exact after lowercasing (see IsSecretKey); there is
// no substring or suffix matching. Header maps are NOT in this
// set: they are redacted wholesale by the header rule in
// redactChild/redactHeaders, whatever the header names are.
var secretKeys = map[string]bool{
	"access_key":             true,
	"access_key_secret":      true,
	"account_key":            true,
	"api_key":                true,
	"api_token":              true,
	"auth":                   true,
	"auth_key":               true,
	"auth_str":               true,
	"auth_token":             true,
	"authorization":          true,
	"certificate":            true,
	"client_certificate":     true,
	"client_key":             true,
	"client_key_password":    true,
	"client_secret":          true,
	"cookie":                 true,
	"key":                    true,
	"mac_key":                true,
	"mca_key":                true,
	"mca_key_password":       true,
	"mesh_psk":               true,
	"node_id":                true,
	"obfs":                   true,
	"origin_ca_key":          true,
	"password":               true,
	"pre_shared_key":         true,
	"private_key":            true,
	"private_key_passphrase": true,
	"psk":                    true,
	"public_key":             true,
	"secret":                 true,
	"security_token":         true,
	"session_key":            true,
	"short_id":               true,
	"static_key":             true,
	"submission_key":         true,
	"subscription_action_id": true,
	"token":                  true,
	"userkey":                true,
	"uuid":                   true,
	"vm_id":                  true,
	"zone_token":             true,
}

// IsSecretKey reports whether key names secret material. The
// comparison is case-insensitive and exact after lowercasing:
// "Password" matches, "my_token" and "vmid" do not.
func IsSecretKey(key string) bool {
	return secretKeys[strings.ToLower(key)]
}

// OrderedMap is the interface an order-preserving JSON object type
// implements so Value can redact it. The concrete type lives in
// the calling package (its methods are defined alongside the
// caller's redaction wrapper), because redact cannot import that
// package: the owner imports redact, so importing the owner back
// would be a cycle. An OrderedMap value is redacted into a fresh
// instance of the same concrete type, in the same key order; the
// dynamic type of the result is the concrete type, so the caller's
// encoder keeps recognising it.
type OrderedMap interface {
	// OrderedKeys returns the keys in insertion order.
	OrderedKeys() []string
	// OrderedGet returns the value stored under key.
	OrderedGet(key string) (any, bool)
	// OrderedSet stores value under key, appending the key to the
	// order on first set.
	OrderedSet(key string, value any)
	// NewOrderedMap returns an empty OrderedMap of the same
	// concrete type.
	NewOrderedMap() OrderedMap
}

// Value recursively redacts a JSON-shaped value and returns the
// redacted copy; the input is never mutated.
//
//   - A map entry whose key is secret (IsSecretKey) is replaced
//     wholesale with Marker, whatever the value's type: string,
//     object, array, number, bool, or nil.
//   - A map entry whose key names an HTTP header map ("headers"
//     or "extra_headers", exact after lowercasing) has EVERY
//     value replaced with Marker, whatever the header name: a
//     benign X-Custom value is redacted too, so the next
//     credential header cannot leak by having an unknown name.
//     Header names (the map keys) are preserved; only values
//     are replaced. A nil header map stays nil, and a
//     non-map header value is replaced wholesale with Marker.
//   - Every other string value has embedded URL userinfo redacted
//     (RedactURLUserinfo), whatever its key and at any depth.
//   - Slices, arrays, and maps are rebuilt element by element, so
//     no field is dropped and no unrelated key is touched.
//   - nil, bools, numbers (including json.Number, whose literal
//     form is preserved), and any other scalar are returned
//     unchanged.
//   - Struct values and pointers are returned unchanged: Value
//     never walks struct fields, so it can neither drop nor leak
//     one silently. Marshal a struct to a map or JSON shape
//     before calling Value.
//   - Typed slices, arrays, and maps (for example []string or
//     map[string]string, as used for header values) are handled
//     by the same rules through reflection: a secret string key
//     in a typed map is replaced with Marker when the element
//     type can hold a string, and with the element type's zero
//     value otherwise.
//
// Value applies only URL-userinfo redaction inside strings. A
// token query parameter, cookie fragment, or Bearer token inside
// a string value is left alone; use String for free-form error
// text. Conversely, Value's key-based replacement does not apply
// to strings passed to String.
func Value(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return RedactURLUserinfo(t)
	case OrderedMap:
		return redactOrderedMap(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			out[k] = redactChild(k, child)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = Value(child)
		}
		return out
	default:
		return valueByReflection(v)
	}
}

// redactChild applies the key rule to one map entry: a secret key
// is replaced wholesale, a header-map key has every value
// replaced (see redactHeaders), any other key recurses into
// Value. The secret rule wins over the header rule: a key cannot
// be both, but checking the secret rule first keeps a secret
// value Marker even if a future header-map key is ever added to
// the secret set.
func redactChild(key string, child any) any {
	if IsSecretKey(key) {
		return Marker
	}
	if isHeaderMapKey(key) {
		return redactHeaders(child)
	}
	return Value(child)
}

// isHeaderMapKey reports whether key names an HTTP header map in
// the sing-box 1.14.4 option schema: "headers"
// (badoption.HTTPHeader in ccm, dns, http, hysteria2, ocm, simple,
// and v2ray_transport option objects) or "extra_headers" (naive).
// The comparison is exact after lowercasing, like IsSecretKey:
// "custom_headers" and "early_data_header_name" are not header
// maps (the latter is a header NAME, not values, and must survive).
func isHeaderMapKey(key string) bool {
	switch strings.ToLower(key) {
	case "headers", "extra_headers":
		return true
	default:
		return false
	}
}

// redactHeaders replaces every value in a header map with Marker,
// preserving the header names (map keys) and, for an OrderedMap,
// key order. A nil header map has no values to leak and stays
// nil; any non-map value is replaced wholesale with Marker, so a
// malformed headers value cannot leak either. Typed maps are
// rebuilt by reflection: a value whose element type can hold a
// string becomes Marker, any other element type becomes its zero
// value (the same convention as secretReplacement for a secret
// key in a typed map, e.g. a []string header value becomes nil).
// The input is never mutated.
func redactHeaders(v any) any {
	if v == nil {
		return nil
	}
	switch t := v.(type) {
	case OrderedMap:
		out := t.NewOrderedMap()
		for _, k := range t.OrderedKeys() {
			if _, ok := t.OrderedGet(k); !ok {
				continue
			}
			out.OrderedSet(k, Marker)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k := range t {
			out[k] = Marker
		}
		return out
	default:
		return redactHeadersByReflection(v)
	}
}

// redactHeadersByReflection rebuilds a typed header map with every
// value replaced (see redactHeaders). A non-map value is replaced
// wholesale with Marker; a nil typed map is returned unchanged.
func redactHeadersByReflection(v any) any {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Map {
		return Marker
	}
	if rv.IsNil() {
		return v
	}
	out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
	for _, k := range rv.MapKeys() {
		out.SetMapIndex(k, secretReplacement(rv.Type().Elem()))
	}
	return out.Interface()
}

// redactOrderedMap redacts an OrderedMap into a fresh instance of
// the same concrete type, preserving key order.
func redactOrderedMap(m OrderedMap) any {
	out := m.NewOrderedMap()
	for _, k := range m.OrderedKeys() {
		child, ok := m.OrderedGet(k)
		if !ok {
			continue
		}
		out.OrderedSet(k, redactChild(k, child))
	}
	return out
}

// valueByReflection handles typed slices, arrays, and maps by the
// same rules as the JSON shapes. Anything else (scalars, structs,
// pointers) is returned unchanged.
func valueByReflection(v any) any {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice:
		if rv.IsNil() {
			return v
		}
		out := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := 0; i < rv.Len(); i++ {
			setRedacted(out.Index(i), Value(rv.Index(i).Interface()), rv.Index(i))
		}
		return out.Interface()
	case reflect.Array:
		out := reflect.New(rv.Type()).Elem()
		for i := 0; i < rv.Len(); i++ {
			setRedacted(out.Index(i), Value(rv.Index(i).Interface()), rv.Index(i))
		}
		return out.Interface()
	case reflect.Map:
		if rv.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		for _, k := range rv.MapKeys() {
			if k.Kind() == reflect.String && IsSecretKey(k.String()) {
				out.SetMapIndex(k, secretReplacement(rv.Type().Elem()))
				continue
			}
			if k.Kind() == reflect.String && isHeaderMapKey(k.String()) {
				out.SetMapIndex(k, headerReplacement(rv.MapIndex(k)))
				continue
			}
			orig := rv.MapIndex(k)
			redacted := Value(orig.Interface())
			ev := reflect.ValueOf(redacted)
			if ev.IsValid() && ev.Type().AssignableTo(rv.Type().Elem()) {
				out.SetMapIndex(k, ev)
			} else {
				out.SetMapIndex(k, orig)
			}
		}
		return out.Interface()
	default:
		return v
	}
}

// setRedacted stores the redacted element in dst, falling back to
// the original element when the redacted value cannot be assigned
// to dst's type (for example a Marker string into a non-string
// element type, which the map path handles via
// secretReplacement instead).
func setRedacted(dst reflect.Value, redacted any, original reflect.Value) {
	ev := reflect.ValueOf(redacted)
	if ev.IsValid() && ev.Type().AssignableTo(dst.Type()) {
		dst.Set(ev)
		return
	}
	dst.Set(original)
}

// headerReplacement returns the redacted value for a header-map
// entry in a typed map: the header-redacted value when it can be
// stored in the entry's type, the type's zero value otherwise.
// It never falls back to the original value: an unassignable
// redacted value must not leak the header it replaced.
func headerReplacement(orig reflect.Value) reflect.Value {
	redacted := reflect.ValueOf(redactHeaders(orig.Interface()))
	if redacted.IsValid() && redacted.Type().AssignableTo(orig.Type()) {
		return redacted
	}
	return reflect.Zero(orig.Type())
}

// secretReplacement returns the value a secret map key is replaced
// with in a typed map: Marker when the element type can hold a
// string, the element type's zero value otherwise.
func secretReplacement(elemType reflect.Type) reflect.Value {
	marker := reflect.ValueOf(Marker)
	switch elemType.Kind() {
	case reflect.String:
		return marker.Convert(elemType)
	case reflect.Interface:
		if marker.Type().Implements(elemType) {
			v := reflect.New(elemType).Elem()
			v.Set(marker)
			return v
		}
	}
	return reflect.Zero(elemType)
}
