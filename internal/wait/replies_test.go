// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"testing"
)

// asst builds a message.assistant event.
func asst(seq int, status string, text string, extra map[string]any) Event {
	p := map[string]any{"status": status}
	if text != "" {
		p["display_text"] = text
	}
	for k, v := range extra {
		p[k] = v
	}
	ev := Event{"event_name": "message.assistant", "seq": seq, "payload": p}
	return ev
}

func TestIsSelfReferential(t *testing.T) {
	tests := []struct {
		name  string
		ev    Event
		want  bool
		level string
	}{
		{
			name: "prefix-stripped match",
			ev: Event{"event_name": "message.assistant", "payload": map[string]any{
				"message_id": "assistant-msg-abc", "reply_to_message_id": "abc",
			}},
			want: true, level: "payload",
		},
		{
			name: "full form match",
			ev: Event{"event_name": "message.assistant", "payload": map[string]any{
				"message_id": "assistant-msg-abc", "reply_to_message_id": "assistant-msg-abc",
			}},
			want: true,
		},
		{
			name: "reply to user kept",
			ev: Event{"event_name": "message.assistant", "payload": map[string]any{
				"message_id": "assistant-msg-abc", "reply_to_message_id": "user-msg-9",
			}},
			want: false,
		},
		{
			name: "execution root match for 2nd message",
			ev: Event{"event_name": "message.assistant", "payload": map[string]any{
				"message_id":          "assistant-msg-abc",
				"metadata":            map[string]any{"root_message_execution_id": "exec-1"},
				"reply_to_message_id": "exec-1",
			}},
			want: true,
		},
		{
			name: "no id fail open",
			ev: Event{"event_name": "message.assistant", "payload": map[string]any{
				"reply_to_message_id": "x",
			}},
			want: false,
		},
		{
			name: "cross-level match",
			ev: Event{"event_name": "message.assistant", "reply_to_message_id": "abc",
				"payload": map[string]any{"message_id": "assistant-msg-abc"}},
			want: true, level: "event",
		},
		{
			name: "either own id when event and payload ids differ",
			ev: Event{"event_name": "message.assistant", "message_id": "assistant-msg-e1",
				"payload": map[string]any{"message_id": "assistant-msg-p1", "reply_to_message_id": "e1"}},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, level, _ := IsSelfReferential(tt.ev)
			if got != tt.want {
				t.Errorf("selfRef = %v, want %v", got, tt.want)
			}
			if tt.level != "" && level != tt.level {
				t.Errorf("level = %q, want %q", level, tt.level)
			}
		})
	}
}

// TestRepliesAfterWorkedTable is the §8.2 worked example:
// after_seq=100, upto=150, jumbled input order.
func TestRepliesAfterWorkedTable(t *testing.T) {
	upto := int64(150)
	events := []any{
		asst(90, "completed", "old", nil),
		asst(160, "completed", "too new", nil),
		Event{"event_name": "message.user", "seq": 110, "payload": map[string]any{"status": "completed", "display_text": "user"}},
		Event{"event": "message.assistant", "seq": 111, "payload": map[string]any{"status": "completed", "display_text": "no event_name"}},
		asst(112, "", "partial", nil),
		asst(113, "interrupted", "cut off", nil),
		asst(114, "Completed", "caps", nil),
		asst(115, "completed", "push", map[string]any{"message_id": "assistant-msg-abc", "reply_to_message_id": "abc"}),
		asst(116, "completed", "answer", map[string]any{"message_id": "m1", "reply_to_message_id": "user-msg-9"}),
		asst(116, "completed", "answer", map[string]any{"message_id": "m1", "reply_to_message_id": "user-msg-9"}),
		asst(117, "completed", "", map[string]any{"widgets": []any{map[string]any{"widget_id": "w1", "kind": "q", "state": map[string]any{}, "display_text": "Pick?"}}}),
		asst(118, "completed", "", map[string]any{"data": map[string]any{"videos": []any{map[string]any{"path": "sandbox://workspace/x.mp4"}}}}),
		asst(119, "completed", "", nil),
	}
	replies, dropped := RepliesAfter(events, 100, &upto)
	if len(replies) != 3 {
		t.Fatalf("replies = %+v, want 3", replies)
	}
	if replies[0].Seq != 116 || replies[0].Text != "answer" {
		t.Errorf("reply 0 = %+v", replies[0])
	}
	if replies[1].Seq != 117 || len(replies[1].Widgets) != 1 || replies[1].Widgets[0].Text == nil || *replies[1].Widgets[0].Text != "Pick?" {
		t.Errorf("reply 1 = %+v", replies[1])
	}
	if replies[2].Seq != 118 || !replies[2].Media {
		t.Errorf("reply 2 = %+v", replies[2])
	}
	if len(dropped) != 3 || dropped[0] != 112 || dropped[1] != 113 || dropped[2] != 114 {
		t.Errorf("dropped = %v, want [112 113 114]", dropped)
	}
}

func TestRepliesAfterDedupeNilID(t *testing.T) {
	// Two id-less events with the same seq dedupe to one.
	events := []any{asst(10, "completed", "one", nil), asst(10, "completed", "two", nil)}
	replies, _ := RepliesAfter(events, 0, nil)
	if len(replies) != 1 || replies[0].Text != "one" {
		t.Errorf("replies = %+v, want first only", replies)
	}
}

func TestRepliesAfterTextSourcesAndCleaning(t *testing.T) {
	// Empty display_text falls through to content; widget
	// markers are removed; surrounding space stripped.
	ev := asst(10, "completed", "", map[string]any{"display_text": "", "content": "Hi [[hatch_widget:q1]] there "})
	replies, _ := RepliesAfter([]any{ev}, 0, nil)
	if len(replies) != 1 || replies[0].Text != "Hi  there" {
		t.Errorf("replies = %+v", replies)
	}
	// Event-level display_text fallback.
	ev2 := Event{"event_name": "message.assistant", "seq": 11, "display_text": "event text",
		"payload": map[string]any{"status": "completed"}}
	replies, _ = RepliesAfter([]any{ev2}, 0, nil)
	if len(replies) != 1 || replies[0].Text != "event text" {
		t.Errorf("replies = %+v", replies)
	}
}

func TestOpenWidgets(t *testing.T) {
	ev := Event{"payload": map[string]any{"widgets": []any{
		map[string]any{"widget_id": "w1", "kind": "q", "state": map[string]any{}, "display_text": "Pick?"},
		map[string]any{"widget_id": "w2", "state": map[string]any{"value": "yes"}},
		map[string]any{"widget_id": "w3", "state": map[string]any{"value": ""}},
		map[string]any{"widget_id": "w4", "state": map[string]any{"value": false}},
		map[string]any{"widget_id": "w5", "state": map[string]any{"value": 0}},
		map[string]any{"widget_id": "w6", "state": map[string]any{"selected": []any{}}},
		map[string]any{"widget_id": "w7", "state": map[string]any{"selected": []any{1}}},
		map[string]any{"widget_id": "w8", "state": "junk", "display_text": "D", "fallback_text": "F"},
		"junk",
		map[string]any{"widget_id": "w9", "kind": "k", "display_text": "NoState",
			"data": map[string]any{"options": []any{"a", "b"}}},
	}}}
	got := OpenWidgets(ev)
	ids := []any{}
	for _, w := range got {
		ids = append(ids, w.ID)
	}
	want := []any{"w1", "w3", "w6", "w8", "w9"}
	if len(ids) != len(want) {
		t.Fatalf("widget ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Errorf("widget %d = %v, want %v", i, ids[i], want[i])
		}
	}
	if got[3].Text == nil || *got[3].Text != "D" {
		t.Errorf("w8 text = %v, want D (display_text wins over fallback)", got[3].Text)
	}
	if got[4].Options == nil {
		t.Error("w9 options must be carried")
	}
}

func TestEventHasMedia(t *testing.T) {
	cases := []struct {
		name string
		ev   Event
		want bool
	}{
		{"sandbox video", asst(1, "completed", "", map[string]any{"data": map[string]any{"videos": []any{map[string]any{"path": "sandbox://workspace/x.mp4"}}}}), true},
		{"media raw variant", asst(1, "completed", "", map[string]any{"data": map[string]any{"images": []any{map[string]any{"variants": map[string]any{"original": "https://h/media/raw/a.png"}}}}}), true},
		{"plain https", asst(1, "completed", "", map[string]any{"data": map[string]any{"images": []any{map[string]any{"path": "https://example.com/a.png"}}}}), false},
		{"string data value ignored", asst(1, "completed", "", map[string]any{"data": map[string]any{"images": "sandbox://workspace/x.png"}}), false},
		{"missing flag ignored", Event{"event_name": "message.assistant", "resources": []any{map[string]any{"path": "sandbox://workspace/x.png", "missing": true}}, "payload": map[string]any{"status": "completed"}}, true},
		{"string resource item", Event{"event_name": "message.assistant", "payload": map[string]any{"status": "completed", "resources": []any{"sandbox://workspace/x.png"}}}, true},
		{"text link not scanned", asst(1, "completed", "see sandbox://workspace/x.png", nil), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EventHasMedia(tc.ev); got != tc.want {
				t.Errorf("EventHasMedia = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCleanText(t *testing.T) {
	if got := CleanText("Hi [[hatch_widget:q1]] there "); got != "Hi  there" {
		t.Errorf("CleanText = %q", got)
	}
	if got := CleanText("[[hatch_widget:q]]"); got != "" {
		t.Errorf("CleanText = %q", got)
	}
	if got := CleanText(""); got != "" {
		t.Errorf("CleanText = %q", got)
	}
}

func TestUserAck(t *testing.T) {
	events := []any{
		Event{"event_name": "message.user", "seq": 5, "payload": map[string]any{"display_text": "hello world"}},
		Event{"event_name": "message.user", "seq": 8, "payload": map[string]any{"display_text": "other"}},
	}
	if seq, ok := UserAck(events, 0, strptr("hello")); !ok || seq != 5 {
		t.Errorf("UserAck = (%d, %v)", seq, ok)
	}
	// seq 5 is at the baseline, so it is excluded; seq 8 does
	// not match in either direction.
	if _, ok := UserAck(events, 5, strptr("hello")); ok {
		t.Error("UserAck above baseline must not match")
	}
	if seq, ok := UserAck(events, 0, nil); !ok || seq != 5 {
		t.Errorf("nil text UserAck = (%d, %v)", seq, ok)
	}
	// Contained-in direction: sent text contains the event text.
	if seq, ok := UserAck(events, 0, strptr("say hello world please")); !ok || seq != 5 {
		t.Errorf("contained-in UserAck = (%d, %v)", seq, ok)
	}
}

func strptr(s string) *string { return &s }

func TestRepliesAfterMarkerOnlyAndWhitespaceKept(t *testing.T) {
	// The keep decision tests the RAW text, as Python does: a
	// marker-only reply, a whitespace-only reply, and a real
	// reply are all kept (3 entries); the cleaned text of the
	// first two is "".
	events := []any{
		asst(10, "completed", "[[hatch_widget:q1]]", nil),
		asst(11, "completed", "   ", nil),
		asst(12, "completed", "hello", nil),
	}
	replies, _ := RepliesAfter(events, 0, nil)
	if len(replies) != 3 {
		t.Fatalf("replies = %+v, want 3", replies)
	}
	if replies[0].Text != "" || replies[1].Text != "" || replies[2].Text != "hello" {
		t.Errorf("texts = %q %q %q, want \"\" \"\" \"hello\"", replies[0].Text, replies[1].Text, replies[2].Text)
	}
}

func TestRepliesAfterNegativeSeqs(t *testing.T) {
	// Dedupe keys render seqs exactly, including negatives:
	// two events at the same negative seq with the same id
	// dedupe to one, and different ids are both kept. The
	// seq rendering itself is strconv.FormatInt (the old
	// hand-rolled renderer overflowed on math.MinInt64, which
	// no afterSeq can admit through the seq filter — traced,
	// not observable here).
	events := []any{
		asst(-5, "completed", "one", map[string]any{"message_id": "m1"}),
		asst(-5, "completed", "one again", map[string]any{"message_id": "m1"}),
		asst(-5, "completed", "two", map[string]any{"message_id": "m2"}),
	}
	replies, _ := RepliesAfter(events, -10, nil)
	if len(replies) != 2 {
		t.Fatalf("replies = %+v, want 2 (one, two)", replies)
	}
	if replies[0].Text != "one" || replies[1].Text != "two" {
		t.Errorf("texts = %q %q", replies[0].Text, replies[1].Text)
	}
}
