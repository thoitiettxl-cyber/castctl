// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Reply is one final assistant reply after the boundary: the
// oldest-first, deduped, cleaned text of a completed
// message.assistant event, kept only when it has text, unanswered
// widgets, or media. AgentID/RootAgentID carry the payload's
// agent identity when the event states it as strings; they are
// recorded, never invented, and are used only by the settle
// proof (Settle) — the final reply list is unattributed, as
// before. Whether real history events carry these fields is
// [UNVERIFIED] pending live capture (U-A2).
type Reply struct {
	Seq         int64
	MessageID   string
	Text        string
	Widgets     []Widget
	Media       bool
	AgentID     string
	RootAgentID string
}

// SubagentShaped reports whether the reply is identifiably a
// subagent's: both identity fields are present as strings and
// differ. An event with absent or non-string fields is not
// identifiably subagent-shaped; it counts as unattributed,
// never as proof of subagent origin.
func (r Reply) SubagentShaped() bool {
	return r.AgentID != "" && r.RootAgentID != "" && r.AgentID != r.RootAgentID
}

// Widget is one unanswered hatch widget carried by a reply.
type Widget struct {
	ID      any
	Kind    string
	Text    *string
	Options any
}

var widgetMarkerRe = regexp.MustCompile(`\[\[hatch_widget:[^\]]+\]\]`)

// CleanText removes [[hatch_widget:...]] markers and strips
// surrounding whitespace. An empty result means "no text".
func CleanText(text string) string {
	return strings.TrimSpace(widgetMarkerRe.ReplaceAllString(text, ""))
}

// IsSelfReferential reports whether ev is a proactive push talking
// to itself: its reply_to_message_id (event level or payload
// level) exactly equals its own id. The own id covers three forms:
// the message_id itself (payload or event level), the message_id
// without its "assistant-msg-" prefix, and
// payload.metadata.root_message_execution_id. When no id exists
// at either level, self-reference cannot be proved and the event
// is kept (fail open). It returns the match level ("event" or
// "payload") and the matched id, or ("", "") when not
// self-referential.
func IsSelfReferential(ev Event) (selfRef bool, level string, matched string) {
	p := payload(ev)
	own := map[string]bool{}
	for _, mid := range []any{p["message_id"], ev["message_id"]} {
		if s, ok := mid.(string); ok && s != "" {
			own[s] = true
			if strings.HasPrefix(s, "assistant-msg-") {
				own[strings.TrimPrefix(s, "assistant-msg-")] = true
			}
		}
	}
	if meta, ok := p["metadata"].(map[string]any); ok {
		if s, ok := meta["root_message_execution_id"].(string); ok && s != "" {
			own[s] = true
		}
	}
	for _, ref := range []struct {
		level string
		value any
	}{
		{"event", ev["reply_to_message_id"]},
		{"payload", p["reply_to_message_id"]},
	} {
		if s, ok := ref.value.(string); ok && s != "" && own[s] {
			return true, ref.level, s
		}
	}
	return false, "", ""
}

// RepliesAfter filters history events to this turn's final
// replies: events after afterSeq (and at or below upto when
// given), oldest-first, keeping only completed message.assistant
// events that are not self-referential, deduped by (seq,
// message_id), and kept when the RAW text is non-empty (before
// cleaning), or when they carry unanswered widgets or media. The
// keep decision tests the raw text, as Python does: a
// marker-only or whitespace-only reply is kept, with the cleaned
// text (possibly "") in the reply. Non-string text fields are
// skipped (see firstText). It also returns the seqs of
// text-bearing assistant events dropped for lacking payload
// status "completed". HistoryReplies discards those seqs: the
// core has no log sink, so a status-less partial that costs a
// wait its reply is a pre-existing visibility gap, stated here
// rather than claimed logged.
//
// Filter order matters and is preserved: seq window, literal
// event_name (no event/type fallback), exact case-sensitive
// "completed" status, self-reference, dedupe, content.
func RepliesAfter(events []any, afterSeq int64, upto *int64) (replies []Reply, dropped []int64) {
	sorted := append([]any(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return seqOf(eventMap(sorted[i])) < seqOf(eventMap(sorted[j]))
	})
	seen := map[[2]string]bool{}
	for _, raw := range sorted {
		ev, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		seq := seqOf(ev)
		if seq <= afterSeq || (upto != nil && seq > *upto) {
			continue
		}
		if ev["event_name"] != "message.assistant" {
			continue
		}
		p := payload(ev)
		if p["status"] != "completed" {
			if firstText(p["display_text"], p["content"], ev["display_text"]) != "" {
				dropped = append(dropped, seq)
			}
			continue
		}
		if selfRef, _, _ := IsSelfReferential(ev); selfRef {
			continue
		}
		mid := idKey(firstTruthy(p["message_id"], ev["message_id"]))
		key := [2]string{strconv.FormatInt(seq, 10), mid}
		if seen[key] {
			continue
		}
		seen[key] = true
		rawText := firstText(p["display_text"], p["content"], ev["display_text"])
		text := CleanText(rawText)
		widgets := OpenWidgets(ev)
		hasMedia := EventHasMedia(ev)
		if rawText == "" && len(widgets) == 0 && !hasMedia {
			continue
		}
		r := Reply{Seq: seq, MessageID: mid, Text: text, Media: hasMedia}
		if agentID, ok := p["agent_id"].(string); ok {
			r.AgentID = agentID
		}
		if rootID, ok := p["root_agent_id"].(string); ok {
			r.RootAgentID = rootID
		}
		if len(widgets) > 0 {
			r.Widgets = widgets
		}
		replies = append(replies, r)
	}
	return replies, dropped
}

func eventMap(v any) Event {
	if ev, ok := v.(map[string]any); ok {
		return ev
	}
	return nil
}

func firstTruthy(vs ...any) any {
	for _, v := range vs {
		if truthy(v) {
			return v
		}
	}
	return nil
}

// OpenWidgets returns the unanswered hatch widgets in ev: only
// payload-level widgets, non-dict widgets skipped, a non-dict
// state treated as unanswered. Answered iff any of the six state
// keys holds a value outside (nil, "", [], {}): false and 0 count
// as answered.
func OpenWidgets(ev Event) []Widget {
	p := payload(ev)
	list, ok := p["widgets"].([]any)
	if !ok {
		return nil
	}
	var out []Widget
	for _, raw := range list {
		w, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		var state map[string]any
		if st, ok := w["state"].(map[string]any); ok {
			state = st
		} else {
			state = map[string]any{}
		}
		answered := false
		for _, key := range []string{"value", "selected", "selection", "answer", "submitted", "response"} {
			if v, present := state[key]; present && !unansweredValue(v) {
				answered = true
				break
			}
		}
		if answered {
			continue
		}
		var data map[string]any
		if d, ok := w["data"].(map[string]any); ok {
			data = d
		}
		var text *string
		if t := firstText(w["display_text"], w["fallback_text"]); t != "" {
			text = &t
		}
		var options any
		if data != nil {
			options = data["options"]
		}
		out = append(out, Widget{
			ID:      w["widget_id"],
			Kind:    stringField(w["kind"]),
			Text:    text,
			Options: options,
		})
	}
	return out
}

// unansweredValue reports whether v is one of (nil, "", [], {}).
func unansweredValue(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	default:
		return false
	}
}

func stringField(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// EventHasMedia reports whether ev references sandbox/media-raw
// media: every list-valued entry of payload.data (any key), then
// event-level and payload-level resources lists. A string item
// becomes {path: item}; the path is item.path, else
// variants.original when variants is a dict. Media iff the path
// starts with "sandbox://" or contains "/media/raw/". The
// "missing" flag is not checked, and text links are never scanned:
// this diverges from cli.event_resources deliberately.
func EventHasMedia(ev Event) bool {
	p := payload(ev)
	var items []any
	if data, ok := p["data"].(map[string]any); ok {
		for _, val := range data {
			if list, ok := val.([]any); ok {
				items = append(items, list...)
			}
		}
	}
	for _, src := range []any{ev["resources"], p["resources"]} {
		if list, ok := src.([]any); ok {
			items = append(items, list...)
		}
	}
	for _, raw := range items {
		var item map[string]any
		switch t := raw.(type) {
		case string:
			item = map[string]any{"path": t}
		case map[string]any:
			item = t
		default:
			continue
		}
		var path string
		if s, ok := item["path"].(string); ok && s != "" {
			path = s
		} else if variants, ok := item["variants"].(map[string]any); ok {
			path, _ = variants["original"].(string)
		}
		if path != "" && (strings.HasPrefix(path, "sandbox://") || strings.Contains(path, "/media/raw/")) {
			return true
		}
	}
	return false
}

// UserAck finds the first (lowest-seq) message.user event above
// baseline whose text contains, or is contained in, the sent
// text, and returns its seq. A nil text matches the first user
// event above the baseline. An empty or whitespace-only text
// matches nothing (loop-2 F10/RT13c): an empty needle must not
// ack any event. No status or self-reference check is applied
// here.
//
// The substring match is trusted ONLY above a proved baseline:
// the caller must have read the baseline from history
// successfully before sending (deliverSend fails the send when
// that read fails, never falling back to 0). Above a proved
// baseline the first match is the just-sent message's own seq;
// above a stale 0 it could be an older turn's. The baseline
// itself is two windows, not one (see deliverSend): no
// ordering contract for chat.history windows is stated
// anywhere in this tree, so a single limit=1 read cannot prove
// the newest seq, and an interleaved identical message from
// another client can still win the first-match race (carried
// residual, RT13d).
func UserAck(events []any, baseline int64, text *string) (int64, bool) {
	if text != nil && strings.TrimSpace(*text) == "" {
		return 0, false
	}
	sorted := append([]any(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return seqOf(eventMap(sorted[i])) < seqOf(eventMap(sorted[j]))
	})
	for _, raw := range sorted {
		ev, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		seq := seqOf(ev)
		if seq <= baseline || ev["event_name"] != "message.user" {
			continue
		}
		p := payload(ev)
		t := firstText(p["display_text"], p["content"], ev["display_text"])
		if text == nil {
			return seq, true
		}
		needle := strings.TrimSpace(*text)
		if strings.Contains(t, needle) || strings.Contains(*text, strings.TrimSpace(t)) {
			return seq, true
		}
	}
	return 0, false
}
