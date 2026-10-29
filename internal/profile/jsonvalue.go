package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// orderedObject is a JSON object that preserves key insertion order and
// number literals (via json.Number). It exists so that re-encoding a
// parsed config preserves field order where feasible, and so redaction
// can operate on serialised output without reordering fields.
//
// Ordering limitation: duplicate keys collapse (last value wins, first
// position kept), matching encoding/json. Non-object JSON values decode
// to nil, bool, string, json.Number, []any, or *orderedObject.
type orderedObject struct {
	keys   []string
	values map[string]any
}

func newOrderedObject() *orderedObject {
	return &orderedObject{values: make(map[string]any)}
}

func (o *orderedObject) get(key string) (any, bool) {
	v, ok := o.values[key]
	return v, ok
}

func (o *orderedObject) set(key string, value any) {
	if _, ok := o.values[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

func (o *orderedObject) has(key string) bool {
	_, ok := o.values[key]
	return ok
}

// decodeOrderedJSON decodes JSON preserving object key order and number
// literals. It rejects trailing data.
func decodeOrderedJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeOrderedValue(dec)
	if err != nil {
		return nil, newConfigError("invalid json: " + err.Error())
	}
	if dec.More() {
		return nil, newConfigError("invalid json: trailing data")
	}
	return v, nil
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
			obj := newOrderedObject()
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, fmt.Errorf("object key is not a string")
				}
				val, err := decodeOrderedValue(dec)
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
		default:
			return nil, fmt.Errorf("unexpected delimiter %q", string(t))
		}
	case string, json.Number, bool, nil:
		return t, nil
	default:
		return nil, fmt.Errorf("unexpected token %T", tok)
	}
}

// encodeOrderedJSON renders a decoded value compactly, preserving key order.
func encodeOrderedJSON(v any) ([]byte, error) {
	var b strings.Builder
	if err := writeOrderedValue(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func writeOrderedValue(b *strings.Builder, v any) error {
	switch t := v.(type) {
	case *orderedObject:
		b.WriteByte('{')
		for i, k := range t.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			keyJSON, err := marshalScalar(k)
			if err != nil {
				return err
			}
			b.Write(keyJSON)
			b.WriteByte(':')
			if err := writeOrderedValue(b, t.values[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
		return nil
	case []any:
		b.WriteByte('[')
		for i, elem := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeOrderedValue(b, elem); err != nil {
				return err
			}
		}
		b.WriteByte(']')
		return nil
	default:
		raw, err := marshalScalar(v)
		if err != nil {
			return err
		}
		b.Write(raw)
		return nil
	}
}

// marshalScalar renders a scalar with HTML escaping disabled, so
// "<redacted>" stays literal (encoding/json escapes < > & by default,
// unlike Python's json.dumps).
func marshalScalar(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// encodeOrderedJSONIndent renders a decoded value with 2-space indent,
// matching Python json.dump(indent=2) layout for the top-level structure.
func encodeOrderedJSONIndent(v any, indent int) ([]byte, error) {
	compact, err := encodeOrderedJSON(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, compact, "", strings.Repeat(" ", indent)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeOrderedObject decodes JSON that must be a top-level object.
func decodeOrderedObject(data []byte) (*orderedObject, error) {
	v, err := decodeOrderedJSON(data)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(*orderedObject)
	if !ok {
		return nil, newConfigError("config must be a json object")
	}
	return obj, nil
}

// rawOf renders one decoded value back to compact JSON bytes.
func rawOf(v any) ([]byte, error) {
	return encodeOrderedJSON(v)
}
