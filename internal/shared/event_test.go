// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

import (
	"encoding/json"
	"reflect"
	"testing"
)

func strPtr(s string) *string { return &s }

func intPtr(n int64) *int64 { return &n }

func TestCleanText(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello", "hello"},
		{"empty", "", ""},
		{"widget removed", "a [[hatch_widget:foo]] b", "a  b"},
		{"widget at ends trimmed", "[[hatch_widget:x]] hi [[hatch_widget:y]]", "hi"},
		{"widget with spaces inside", "[[hatch_widget:pick one]]", ""},
		{"empty widget body is not a marker", "[[hatch_widget:]]", "[[hatch_widget:]]"},
		{"other brackets kept", "[[not a widget]]", "[[not a widget]]"},
		{"surrounding whitespace trimmed", "  hi\n", "hi"},
		{"multiple widgets", "[[hatch_widget:1]]x[[hatch_widget:2]]", "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CleanText(tc.in); got != tc.want {
				t.Errorf("CleanText(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFmtEvent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ev   map[string]any
		want EventRow
	}{
		{
			name: "display text and payload ids",
			ev: map[string]any{"seq": int64(7), "payload": map[string]any{
				"role": "message.assistant", "message_id": "m1", "display_text": "hi"}},
			want: EventRow{Seq: intPtr(7), Role: strPtr("message.assistant"), MessageID: strPtr("m1"), Text: "hi"},
		},
		{
			name: "content fallback and event name role",
			ev: map[string]any{"seq": int64(3), "event_name": "message.user", "payload": map[string]any{
				"content": "yo", "message_id": "u9"}},
			want: EventRow{Seq: intPtr(3), Role: strPtr("message.user"), MessageID: strPtr("u9"), Text: "yo"},
		},
		{
			name: "event message id fallback",
			ev:   map[string]any{"seq": int64(1), "message_id": "e5", "payload": map[string]any{}},
			want: EventRow{Seq: intPtr(1), Role: nil, MessageID: strPtr("e5"), Text: ""},
		},
		{
			name: "empty display text falls through to content",
			ev:   map[string]any{"payload": map[string]any{"display_text": "", "content": "c"}},
			want: EventRow{Seq: nil, Role: nil, MessageID: nil, Text: "c"},
		},
		{
			name: "non-object payload treated as empty",
			ev:   map[string]any{"seq": int64(2), "payload": "junk"},
			want: EventRow{Seq: intPtr(2), Role: nil, MessageID: nil, Text: ""},
		},
		{
			name: "json.Number seq",
			ev:   map[string]any{"seq": json.Number("42"), "payload": map[string]any{"display_text": "x"}},
			want: EventRow{Seq: intPtr(42), Role: nil, MessageID: nil, Text: "x"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FmtEvent(tc.ev)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("FmtEvent(%v) = %+v, want %+v", tc.ev, got, tc.want)
			}
		})
	}
}

func TestFmtEventJSONOrder(t *testing.T) {
	t.Parallel()
	row := FmtEvent(map[string]any{"seq": int64(1), "payload": map[string]any{
		"role": "message.assistant", "message_id": "m1", "display_text": "hi"}})
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"seq":1,"role":"message.assistant","message_id":"m1","text":"hi"}`
	if string(b) != want {
		t.Errorf("Marshal(EventRow) = %s, want %s", b, want)
	}
}
