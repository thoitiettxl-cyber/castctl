// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
)

// Order-preserving render of a merged config document.
//
// saveGuarded validates the merged document by re-parsing it,
// and the parse captures raw blocks whose key order the
// canonical encoder then re-emits verbatim. A plain
// json.Marshal of the merged map (Go sorts map keys) would
// therefore reorder every raw block on the first web UI save.
// marshalOrdered renders the merged document against the
// stored bytes instead: stored key order wins everywhere,
// changed values overlay in place, and keys the save
// introduces append in sorted order (deterministic). Number
// literals survive via json.Number, and HTML-significant
// characters stay literal (no HTML escaping), matching the
// canonical encoder's byte shape for values.
//
// With no stored bytes there is no order to preserve: the
// document renders with sorted keys, as json.Marshal would.

// orderedObject is one JSON object with its keys in stored
// order. Values are decoded with UseNumber so number literals
// survive the round trip.
type orderedObject struct {
	keys []string
	vals map[string]any
}

func decodeOrderedValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := &orderedObject{vals: map[string]any{}}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, errUnexpectedJSON
				}
				val, err := decodeOrderedValue(dec)
				if err != nil {
					return nil, err
				}
				obj.keys = append(obj.keys, key)
				obj.vals[key] = val
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			var arr []any
			for dec.More() {
				val, err := decodeOrderedValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return arr, nil
		}
		return nil, errUnexpectedJSON
	default:
		return tok, nil
	}
}

var errUnexpectedJSON = errors.New("unexpected JSON token")

// overlayOrdered overlays the merged document doc onto the
// stored shape: stored keys keep their order with merged
// values, stored keys absent from doc drop, and doc keys with
// no stored position append sorted. Arrays overlay
// positionally; anything else takes the merged value.
func overlayOrdered(stored, doc any) any {
	switch st := stored.(type) {
	case *orderedObject:
		m, ok := doc.(map[string]any)
		if !ok {
			return doc
		}
		out := &orderedObject{vals: map[string]any{}}
		for _, k := range st.keys {
			if v, ok := m[k]; ok {
				out.keys = append(out.keys, k)
				out.vals[k] = overlayOrdered(st.vals[k], v)
			}
		}
		var extra []string
		for k := range m {
			if _, ok := st.vals[k]; !ok {
				extra = append(extra, k)
			}
		}
		sort.Strings(extra)
		for _, k := range extra {
			out.keys = append(out.keys, k)
			out.vals[k] = m[k]
		}
		return out
	case []any:
		arr, ok := doc.([]any)
		if !ok {
			return doc
		}
		out := make([]any, len(arr))
		for i, v := range arr {
			if i < len(st) {
				out[i] = overlayOrdered(st[i], v)
			} else {
				out[i] = v
			}
		}
		return out
	default:
		return doc
	}
}

func marshalOrderedValue(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case *orderedObject:
		buf.WriteByte('{')
		for i, k := range t.keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJSONString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := marshalOrderedValue(buf, t.vals[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := marshalOrderedValue(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		// Scalars, json.Number literals, and brand-new
		// subtrees (encoding/json sorts their map keys):
		// one encoder with HTML escaping disabled.
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return err
		}
		// Encode appends one newline; the rendered
		// document is compact, so trim it.
		buf.Truncate(buf.Len() - 1)
		return nil
	}
}

func writeJSONString(buf *bytes.Buffer, s string) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	buf.Truncate(buf.Len() - 1)
	return nil
}

// marshalOrdered renders doc as compact JSON preserving the
// stored document's key order. It never emits secret values:
// doc holds only the merged document the caller already
// validated, and no value is logged here.
func marshalOrdered(storedRaw []byte, doc map[string]any) ([]byte, error) {
	if len(bytes.TrimSpace(storedRaw)) == 0 {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(doc); err != nil {
			return nil, err
		}
		return bytes.TrimRight(buf.Bytes(), "\n"), nil
	}
	dec := json.NewDecoder(bytes.NewReader(storedRaw))
	dec.UseNumber()
	stored, err := decodeOrderedValue(dec)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := marshalOrderedValue(&buf, overlayOrdered(stored, doc)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
