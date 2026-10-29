// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"bytes"
	"encoding/json"
	"io"
)

// Event is one decoded history/stream record: a JSON object. The
// pure core works on decoded maps so the same code feeds records
// from chat.subscribe (NDJSON bytes) and chat.history (decoded
// JSON) alike. Numbers arrive as json.Number when decoded with
// UseNumber, or as float64/int64 from other decoders; the helpers
// below accept every numeric shape.
type Event = map[string]any

// decodeRecord decodes one NDJSON record into an Event, or nil
// when the record is empty, unparseable, not an object, or
// followed by trailing data after one JSON value. It is the ONE
// NDJSON decoder for the package: both the Waiter (FeedRecord)
// and the Runner use it, so the trailing-data rule is defined
// and tested exactly once, here.
func decodeRecord(record []byte) Event {
	record = bytes.TrimSpace(record)
	if len(record) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(record))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil
	}
	ev, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return ev
}

// payload returns the event's payload dict, or an empty dict when
// the payload is absent or not a dict. A non-dict payload is
// discarded, not an error.
func payload(ev Event) Event {
	if ev == nil {
		return Event{}
	}
	if p, ok := ev["payload"].(map[string]any); ok {
		return p
	}
	return Event{}
}

// eventName returns the event name: the first truthy of "event",
// "event_name", "type". A non-string or empty value does not count.
func eventName(ev Event) string {
	if ev == nil {
		return ""
	}
	for _, key := range []string{"event", "event_name", "type"} {
		if s, ok := ev[key].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// inScope reports whether ev belongs to the wait's scope. With a
// thread, only events whose payload session_id is absent or equal
// to the thread count; without one, events marked is_thread in the
// payload do not. Only payload fields are read: an event-level
// session_id is ignored.
func inScope(ev Event, thread string) bool {
	p := payload(ev)
	if thread != "" {
		sid, ok := p["session_id"].(string)
		return !ok || sid == thread
	}
	isThread, _ := p["is_thread"].(bool)
	return !isThread
}

// truthy mirrors Python truthiness for JSON values: nil, false,
// "", 0, and empty lists/maps are falsy; everything else is truthy.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case json.Number:
		f, err := t.Float64()
		return err == nil && f != 0
	case float64:
		return t != 0
	case float32:
		return t != 0
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return numericFloat(v) != 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return v != nil
	}
}

func numericFloat(v any) float64 {
	switch t := v.(type) {
	case int:
		return float64(t)
	case int8:
		return float64(t)
	case int16:
		return float64(t)
	case int32:
		return float64(t)
	case int64:
		return float64(t)
	case uint:
		return float64(t)
	case uint8:
		return float64(t)
	case uint16:
		return float64(t)
	case uint32:
		return float64(t)
	case uint64:
		return float64(t)
	case float64:
		return t
	case float32:
		return float64(t)
	case json.Number:
		f, _ := t.Float64()
		return f
	}
	return 0
}

// seqOf extracts an event's seq as an int64. A missing or
// non-numeric seq is 0, matching Python's `e.get("seq") or 0` for
// well-formed records.
func seqOf(ev Event) int64 {
	if ev == nil {
		return 0
	}
	v, ok := ev["seq"]
	if !ok || v == nil {
		return 0
	}
	if b, ok := v.(bool); ok {
		// Python: True or 0 == True; a bool seq is not a number
		// in JSON practice. Treat it as absent.
		_ = b
		return 0
	}
	if n, ok := v.(json.Number); ok {
		if i, err := n.Int64(); err == nil {
			return i
		}
		if f, err := n.Float64(); err == nil {
			return int64(f)
		}
		return 0
	}
	return int64(numericFloat(v))
}

// hasSeq reports whether ev carries a numeric seq at all, for the
// stored ignored-terminal seq (which is never used as proof).
func hasSeq(ev Event) bool {
	if ev == nil {
		return false
	}
	v, ok := ev["seq"]
	if !ok || v == nil {
		return false
	}
	switch v.(type) {
	case json.Number, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	}
	return false
}

// idKey renders a message id for dedupe purposes. Two absent ids
// share the empty key, so two id-less events with the same seq
// dedupe to one, as in Python.
func idKey(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		// Numeric ids render in canonical form; anything else
		// renders as its JSON shape so distinct ids stay distinct.
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
		return ""
	}
}

// firstText returns the first non-empty string among the values,
// mirroring Python's `or` chain over display_text/content fields,
// except for one deliberate strictness: a non-string value is
// skipped, never taken as text. Python's `or` chain would take
// the first truthy value of any type; the server always sends
// strings in these fields, and a non-string carries no display
// text. Callers that need Python's stringify-everything rule
// (task status) use stringifyStatus instead.
func firstText(vs ...any) string {
	for _, v := range vs {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}
