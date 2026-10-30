// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// LoadCookies reads a cookies file and returns the Cookie header
// value, ported from gateway.py load_cookies. Three forms are
// accepted: a JSON object ({"cookies": {...}} or a flat dict), a
// one-line 'a=b; c=d' form containing hatch_sess= or datr=, or a
// Netscape cookie jar (tab-separated, name/value in columns 6/7).
// An unparseable file returns *conn.AuthError; a missing file
// returns the I/O error unwrapped (Python raises FileNotFoundError
// there, not AuthError). The returned value is secret material: it
// must only ever go into a Cookie header, never into an error or a
// log line.
//
// JSON cookie entries are joined in FILE ORDER (Python dict
// insertion order), deterministically: Go map iteration is random,
// so the JSON object is decoded with an order-preserving decoder
// (orderedCookieObject) instead of encoding/json into a map.
// Values render as Python's f"{k}={v}": strings verbatim, numbers
// as their literal, booleans "True"/"False", null "None", and
// non-scalars as compact JSON preserving key order.
func LoadCookies(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("gateway: read cookies file: %w", err)
	}
	return ParseCookies(string(raw), path)
}

// ParseCookies parses already-read cookies file contents. It is
// exported so tests and wiring code can parse without a file.
func ParseCookies(raw, path string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "{") {
		if v, err := decodeOrderedCookieJSON([]byte(raw)); err == nil {
			if obj, ok := v.(*orderedCookieObject); ok {
				if cookies, ok := obj.get("cookies"); ok {
					if cm, ok := cookies.(*orderedCookieObject); ok {
						return joinCookiePairs(cm), nil
					}
				}
				return joinCookiePairs(obj), nil
			}
		}
		// A "{" file that is not JSON, or a JSON value that is
		// not an object, falls through to the line-based forms
		// below, as in Python (JSONDecodeError is caught there;
		// a non-dict JSON value raises AttributeError in
		// Python — see doc.go — and here is reported as
		// AuthError by the jar parse below).
	}
	if strings.Contains(raw, "hatch_sess=") || strings.Contains(raw, "datr=") {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && strings.Contains(line, "=") && strings.Contains(line, ";") {
				return line, nil
			}
		}
		return strings.Join(strings.Fields(raw), " "), nil
	}
	var parts []string
	for _, line := range strings.Split(raw, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) >= 7 {
			parts = append(parts, cols[5]+"="+cols[6])
		}
	}
	if len(parts) == 0 {
		return "", conn.NewAuthError(fmt.Sprintf("could not parse cookies file %s", path))
	}
	return strings.Join(parts, "; "), nil
}

func joinCookiePairs(obj *orderedCookieObject) string {
	parts := make([]string, 0, len(obj.keys))
	for _, k := range obj.keys {
		v, _ := obj.get(k)
		parts = append(parts, k+"="+cookieValueString(v))
	}
	return strings.Join(parts, "; ")
}

func cookieValueString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "True"
		}
		return "False"
	case nil:
		return "None"
	default:
		raw, err := encodeCookieJSONValue(v)
		if err != nil {
			return ""
		}
		return string(raw)
	}
}

// orderedCookieObject is a JSON object that preserves key insertion
// order and number literals (via json.Number), so cookie entries
// join in file order. Duplicate keys collapse (last value wins,
// first position kept), matching encoding/json and Python dicts.
// Non-object JSON values decode to nil, bool, string,
// json.Number, []any, or *orderedCookieObject.
type orderedCookieObject struct {
	keys   []string
	values map[string]any
}

func (o *orderedCookieObject) get(key string) (any, bool) {
	v, ok := o.values[key]
	return v, ok
}

func (o *orderedCookieObject) set(key string, value any) {
	if _, ok := o.values[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

// decodeOrderedCookieJSON decodes JSON preserving object key order
// and number literals. It rejects trailing data (Python's
// json.loads does too).
func decodeOrderedCookieJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeOrderedCookieValue(dec)
	if err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("invalid json: trailing data")
	}
	return v, nil
}

func decodeOrderedCookieValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := &orderedCookieObject{values: make(map[string]any)}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, fmt.Errorf("object key is not a string")
				}
				val, err := decodeOrderedCookieValue(dec)
				if err != nil {
					return nil, err
				}
				obj.set(key, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := decodeOrderedCookieValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %q", string(t))
		}
	case string, json.Number, bool, nil:
		return t, nil
	default:
		return nil, fmt.Errorf("unexpected token %T", tok)
	}
}

// encodeCookieJSONValue renders a decoded value as compact JSON,
// preserving object key order. It is used only for non-scalar
// cookie values (arrays/objects), which Python would render with
// str(); compact JSON is the documented rendering for this port
// (see LoadCookies).
func encodeCookieJSONValue(v any) ([]byte, error) {
	var b strings.Builder
	if err := writeCookieJSONValue(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func writeCookieJSONValue(b *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		raw, err := json.Marshal(t)
		if err != nil {
			return err
		}
		b.Write(raw)
	case json.Number:
		b.WriteString(t.String())
	case *orderedCookieObject:
		b.WriteByte('{')
		for i, k := range t.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			raw, err := json.Marshal(k)
			if err != nil {
				return err
			}
			b.Write(raw)
			b.WriteByte(':')
			val, _ := t.get(k)
			if err := writeCookieJSONValue(b, val); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, elem := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCookieJSONValue(b, elem); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	default:
		raw, err := json.Marshal(t)
		if err != nil {
			return err
		}
		b.Write(raw)
	}
	return nil
}
