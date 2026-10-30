// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// ValidationError is the typed equivalent of Python's ValueError for
// caller-side validation failures in this package (bad invite code,
// bad sandbox path, unknown method name, unencodable body). The
// exit-code mapping for it belongs to PR3 commands, not here.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return "gateway: " + e.Message }

// decodeJSONValue decodes one JSON value with numbers as
// json.Number, never float64 (the plan's JSON invariant). Trailing
// data after the first value is an error, as json.loads would
// reject it.
func decodeJSONValue(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after JSON value")
	}
	// A second Decode must hit EOF; anything else is trailing junk
	// the More() check can miss for scalar values.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing data after JSON value")
		}
		return nil, err
	}
	return v, nil
}

// decodeJSONObject decodes data as a JSON object (numbers as
// json.Number). It returns an error for empty input, non-JSON, and
// non-object top-level values.
func decodeJSONObject(data []byte) (map[string]any, error) {
	v, err := decodeJSONValue(data)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("JSON top level is %T, want object", v)
	}
	return m, nil
}

// encodeBody renders a RequestOptions body to wire bytes: nil means
// no body; []byte and string are sent verbatim (the
// conn.RequestOptions contract); anything else is JSON-encoded.
// json.Number/int64 bodies marshal as numbers; a float64 body
// would marshal as a float, which callers must not pass.
func encodeBody(body any) ([]byte, error) {
	switch b := body.(type) {
	case nil:
		return nil, nil
	case []byte:
		return b, nil
	case string:
		return []byte(b), nil
	case json.RawMessage:
		return []byte(b), nil
	default:
		out, err := json.Marshal(body)
		if err != nil {
			// An unencodable body is a caller-side validation
			// failure raised before anything is sent, so it
			// is a *ValidationError (NB-R2: PhaseNotSent).
			return nil, &ValidationError{Message: fmt.Sprintf("encode body: %v", err)}
		}
		return out, nil
	}
}

// bodyToQuery converts a GET body into query parameters, mirroring
// Python's `query, body = body, None` in request() followed by
// urlencode in _open: nil values are dropped, other values are
// rendered as Python's str() would (True/False for bools, decimal
// for numbers). Only map bodies convert; anything else is a
// ValidationError.
func bodyToQuery(body any) (map[string]string, error) {
	switch m := body.(type) {
	case map[string]string:
		out := make(map[string]string, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out, nil
	case map[string]any:
		out := make(map[string]string, len(m))
		for k, v := range m {
			if v == nil {
				continue
			}
			out[k] = pythonStr(v)
		}
		return out, nil
	default:
		return nil, &ValidationError{Message: fmt.Sprintf("GET body must be a map to convert to query, got %T", body)}
	}
}

// pythonStr renders a scalar the way Python's str() does for the
// values urlencode accepts.
func pythonStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case json.Number:
		return t.String()
	case int64:
		return fmt.Sprintf("%d", t)
	case int:
		return fmt.Sprintf("%d", t)
	case float64:
		return fmt.Sprintf("%v", t)
	default:
		return fmt.Sprintf("%v", v)
	}
}
