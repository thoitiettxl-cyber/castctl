// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

import (
	"regexp"
	"strings"
)

// widgetRe matches a [[hatch_widget:...]] marker, ported verbatim
// from wait.py:42 (WIDGET_RE). The marker body must contain at least
// one non-']' character: an empty [[hatch_widget:]] is NOT a marker
// and is left in place, exactly as in Python.
var widgetRe = regexp.MustCompile(`\[\[hatch_widget:[^\]]+\]\]`)

// CleanText strips [[hatch_widget:...]] markers from text and trims
// surrounding whitespace, ported verbatim from wait.py:209
// (clean_text: WIDGET_RE.sub("", text or "").strip()). A nil-like
// empty input yields "". The wait package (PR3) owns reply
// filtering; it imports CleanText from here so the marker rule has
// exactly one implementation.
func CleanText(text string) string {
	return strings.TrimSpace(widgetRe.ReplaceAllString(text, ""))
}

// EventRow is one formatted history event, ported from cli.py:757-763
// (fmt_event). Field order is the Python dict order: seq, role,
// message_id, text.
type EventRow struct {
	// Seq is the event's seq, or nil when the event carries no
	// numeric seq (Python emits null there).
	Seq *int64 `json:"seq"`
	// Role is the payload role, falling back to the event name.
	Role *string `json:"role"`
	// MessageID is the payload message_id, falling back to the
	// event's message_id.
	MessageID *string `json:"message_id"`
	// Text is the payload display_text, falling back to content,
	// or "" when both are empty or absent.
	Text string `json:"text"`
}

// FmtEvent formats one history event, ported verbatim from
// cli.py:757-763 (fmt_event). Role and message_id use Python's `or`
// fallback: an empty string falls through to the next source, and a
// non-string source is treated as absent (lenient shaping; see the
// package doc).
func FmtEvent(ev map[string]any) EventRow {
	p := payloadOf(ev)
	return EventRow{
		Seq:       intPtrField(ev, "seq"),
		Role:      firstStringPtr(p["role"], ev["event_name"]),
		MessageID: firstStringPtr(p["message_id"], ev["message_id"]),
		Text:      firstString(p["display_text"], p["content"]),
	}
}

// firstStringPtr returns a pointer to the first non-empty string
// among vs, or nil when none is a non-empty string. Unlike
// stringPtrField it applies Python's `or` fallback, so an empty
// string in the first source falls through to the next.
func firstStringPtr(vs ...any) *string {
	for _, v := range vs {
		if s, ok := asString(v); ok && s != "" {
			return &s
		}
	}
	return nil
}
