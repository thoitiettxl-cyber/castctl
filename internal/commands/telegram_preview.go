// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/thoitiettxl-cyber/castctl/internal/shared"
	"github.com/thoitiettxl-cyber/castctl/internal/wait"
)

// The streaming preview: the Telegram bubble's live text, fed by
// the wait Runner's OnEvent seam. Behaviour mirrors Python 0.6.1's
// Turn (src/muse_cli/tgbot.py:312-518, surveyed, reimplemented):
// delta.* events accumulate per-message parts, agent.status /
// delta.tool_start derive the status line, and render() produces
// the bubble text with the 3300-char tail rule and the elapsed
// timer. The final reply text is NEVER taken from here: it is
// re-read from history by the wait Result (finish_turn), exactly
// as in Python. This preview only ever shows growing text.
//
// Part keying (tgbot.py:350-378, _part_key) is the subtle part:
// one parts key per message, whatever id a delta carries. A
// message's start may carry message_id while its appends/done
// carry message_seq (or vice versa); both ids seen on one event
// name the same message, keys are namespaced by field, and the
// first id seen wins as canonical. Keying on the raw id would
// split one message into two parts, duplicating it on
// message_done and truncating it on resubscribe.

type streamPreview struct {
	mu      sync.Mutex
	parts   map[string]string
	order   []string
	aliases map[string]string

	status    string
	appStatus string
	seenWork  bool
	dirty     bool
	started   time.Time
}

func newStreamPreview(started time.Time) *streamPreview {
	return &streamPreview{
		parts:   map[string]string{},
		aliases: map[string]string{},
		status:  "⏳ Muse is working…",
		started: started,
	}
}

// feed consumes one stream record. It never blocks and never
// calls out: it runs on the Runner's goroutine via OnEvent.
func (p *streamPreview) feed(ev wait.Event) {
	name := previewEventName(ev)
	payload := previewPayload(ev)
	p.mu.Lock()
	defer p.mu.Unlock()
	switch name {
	case "delta.text_append":
		key := p.partKeyLocked(payload, ev)
		if _, ok := p.parts[key]; !ok {
			p.order = append(p.order, key)
		}
		p.parts[key] = p.parts[key] + previewString(payload["text"])
		p.dirty = true
	case "delta.message_start":
		// A re-subscription may restart a message's stream: start
		// it over. A start for an unknown key creates nothing.
		key := p.partKeyLocked(payload, ev)
		if _, ok := p.parts[key]; ok {
			p.parts[key] = ""
		}
	case "delta.message_done":
		key := p.partKeyLocked(payload, ev)
		full := firstNonBlankString(previewString(payload["content"]), previewString(payload["display_text"]), previewString(payload["text"]))
		if strings.TrimSpace(full) != "" {
			if _, ok := p.parts[key]; !ok {
				p.order = append(p.order, key)
			}
			p.parts[key] = full
			p.dirty = true
		}
	case "delta.presentation":
		// Live media: PR-B work. The preview ignores it; the
		// bubble is not frozen around files in PR-A.
	default:
		st := previewStatusFromEvent(name, payload)
		online := name == "agent.status" && previewString(payload["activity_code"]) == "online"
		if name == "agent.status" && st != "" && !online {
			p.seenWork = true
		}
		if online && !p.seenWork {
			// The replayed idle state from before this turn
			// started: suppressed until real work is seen.
			st = ""
		}
		if name == "agent.status" && st != "" {
			p.appStatus = st
		} else if p.appStatus != "" && !strings.HasPrefix(name, "approvals") {
			// The app's own status wins over derived tool labels.
			st = ""
		}
		if st != "" && st != p.status {
			p.status = st
			p.dirty = true
		}
	}
}

// partKeyLocked resolves one message's canonical parts key. The
// caller holds p.mu.
func (p *streamPreview) partKeyLocked(payload map[string]any, ev wait.Event) string {
	var ids []string
	for _, field := range []string{"message_id", "message_seq"} {
		if v, ok := previewIDValue(payload[field]); ok {
			ids = append(ids, field+":"+v)
			continue
		}
		if v, ok := previewIDValue(ev[field]); ok {
			ids = append(ids, field+":"+v)
		}
	}
	for _, k := range ids {
		if canon, ok := p.aliases[k]; ok {
			for _, j := range ids {
				p.aliases[j] = canon
			}
			return canon
		}
	}
	canon := "m"
	if len(ids) > 0 {
		canon = ids[0]
	}
	for _, k := range ids {
		p.aliases[k] = canon
	}
	return canon
}

// render produces the bubble text at now: the cleaned joined
// parts (last 3300 chars with a "…" prefix when longer), then the
// status line and elapsed time.
func (p *streamPreview) render(now time.Time) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var texts []string
	for _, key := range p.order {
		if t := strings.TrimSpace(p.parts[key]); t != "" {
			texts = append(texts, p.parts[key])
		}
	}
	body := strings.TrimSpace(shared.CleanText(strings.Join(texts, "\n\n")))
	if utf8.RuneCountInString(body) > 3300 {
		body = "…" + string([]rune(body)[utf8.RuneCountInString(body)-3300:])
	}
	elapsed := formatElapsedSecs(now.Sub(p.started))
	if body != "" {
		return body + "\n\n" + p.status + " · " + elapsed
	}
	return p.status + " · " + elapsed
}

// statusLine returns the current status label (without the
// elapsed timer), for the /status "Now:" line: the same label
// the bubble shows.
func (p *streamPreview) statusLine() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

// startedAt returns the turn's start time, for the /status
// elapsed timer.
func (p *streamPreview) startedAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.started
}

// edit. clearDirty marks the current rendered state as shown;
// it is called only when an edit was actually attempted, so a
// throttled edit never loses a change.
func (p *streamPreview) isDirty() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dirty
}

func (p *streamPreview) clearDirty() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dirty = false
}

// formatElapsedSecs formats a duration like Python fmt_secs
// (tgbot.py:175-182): "Ns" / "Mm SSs" / "Hh MMm".
func formatElapsedSecs(d time.Duration) string {
	s := int(d.Seconds())
	if s < 0 {
		s = 0
	}
	if s < 60 {
		return fmt.Sprintf("%ds", s)
	}
	if s < 3600 {
		return fmt.Sprintf("%dm %02ds", s/60, s%60)
	}
	return fmt.Sprintf("%dh %02dm", s/3600, (s%3600)/60)
}

// previewStatusFromEvent derives a status line from one event
// (tgbot.py:226-277, status_from_event / app_status). It returns
// "" when the event carries no status.
func previewStatusFromEvent(name string, payload map[string]any) string {
	switch name {
	case "delta.tool_start":
		tool := firstNonBlankString(previewString(payload["tool_name"]), previewString(payload["name"]), previewString(payload["display_name"]), previewString(payload["title"]))
		if tool != "" {
			return "🔧 " + tool
		}
		return "🔧 using a tool"
	case "agent.status":
		return previewAppStatus(payload)
	default:
		return ""
	}
}

// previewAppStatus renders the live status line the Muse app
// shows (tgbot.py:263-277, app_status): activity_emoji +
// activity_text; generic "is working" gets ⏳ and a subject;
// "online" means the turn end is being confirmed.
func previewAppStatus(payload map[string]any) string {
	if previewString(payload["activity_code"]) == "online" {
		return "⏳ Muse is wrapping up…"
	}
	t := strings.TrimSpace(firstNonBlankString(previewString(payload["activity_text"]), previewString(payload["status_text"])))
	if t == "" {
		return ""
	}
	emoji := truncateRunes(strings.TrimSpace(previewString(payload["activity_emoji"])), 8)
	if emoji == "" {
		emoji = "⏳"
	}
	return emoji + " " + truncateRunes(previewActivity(t), 120)
}

// previewActivity names the subject of a generic activity
// (tgbot.py:255-259, _activity): "is working" -> "Muse is working".
func previewActivity(t string) string {
	t = strings.TrimSpace(t)
	if strings.HasPrefix(t, "is ") || strings.HasPrefix(t, "was ") {
		return "Muse " + t
	}
	return t
}

func previewEventName(ev wait.Event) string {
	for _, key := range []string{"event", "event_name"} {
		if s, ok := ev[key].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func previewPayload(ev wait.Event) map[string]any {
	if p, ok := ev["payload"].(map[string]any); ok {
		return p
	}
	return map[string]any{}
}

func previewString(v any) string {
	s, _ := v.(string)
	return s
}

func firstNonBlankString(vs ...string) string {
	for _, s := range vs {
		if s != "" {
			return s
		}
	}
	return ""
}

// previewIDValue renders an id field for part keying. Strings,
// JSON numbers, and ints count; bools, nil, and other shapes do
// not (a bool seq is not a number, as in wait.seqOf).
func previewIDValue(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		if t == "" {
			return "", false
		}
		return t, true
	case json.Number:
		return t.String(), true
	case float64:
		return strconv.FormatInt(int64(t), 10), true
	case float32:
		return strconv.FormatInt(int64(t), 10), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	case int32:
		return strconv.FormatInt(int64(t), 10), true
	case uint64:
		return strconv.FormatUint(t, 10), true
	default:
		return "", false
	}
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
