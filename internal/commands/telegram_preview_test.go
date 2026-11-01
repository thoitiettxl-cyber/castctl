// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"strings"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/wait"
)

func previewEvent(name string, payload map[string]any) wait.Event {
	return wait.Event{"event": name, "payload": payload}
}

func TestStreamPreviewPartKeyingMixedIDs(t *testing.T) {
	p := newStreamPreview(time.Now())
	// Resubscribe shape: start carries message_id, appends and
	// done carry message_seq. All three name ONE message.
	p.feed(previewEvent("delta.message_start", map[string]any{"message_id": "m1"}))
	p.feed(previewEvent("delta.text_append", map[string]any{"message_seq": 9, "text": "hel"}))
	p.feed(previewEvent("delta.text_append", map[string]any{"message_seq": 9, "text": "lo"}))
	p.feed(previewEvent("delta.message_done", map[string]any{"message_seq": 9, "content": "hello world"}))
	body := p.render(time.Now())
	if !strings.HasPrefix(body, "hello world\n\n") {
		t.Fatalf("render = %q; want body 'hello world' (no duplication)", body)
	}
	if strings.Count(body, "hello world") != 1 {
		t.Errorf("render = %q; message_done must replace the partial, not duplicate it", body)
	}
}

func TestStreamPreviewMessageStartResets(t *testing.T) {
	p := newStreamPreview(time.Now())
	p.feed(previewEvent("delta.text_append", map[string]any{"message_id": "m1", "text": "stale"}))
	p.feed(previewEvent("delta.message_start", map[string]any{"message_id": "m1"}))
	p.feed(previewEvent("delta.text_append", map[string]any{"message_id": "m1", "text": "fresh"}))
	if body := p.render(time.Now()); !strings.HasPrefix(body, "fresh\n\n") {
		t.Fatalf("render = %q; want restarted stream to replace the stale partial", body)
	}
}

func TestStreamPreviewTwoPartsJoin(t *testing.T) {
	p := newStreamPreview(time.Now())
	p.feed(previewEvent("delta.text_append", map[string]any{"message_id": "a", "text": "first"}))
	p.feed(previewEvent("delta.text_append", map[string]any{"message_id": "b", "text": "second"}))
	body := p.render(time.Now())
	if !strings.HasPrefix(body, "first\n\nsecond\n\n") {
		t.Fatalf("render = %q; want parts joined with a blank line in first-seen order", body)
	}
}

func TestStreamPreviewNoIDSinglePart(t *testing.T) {
	p := newStreamPreview(time.Now())
	p.feed(previewEvent("delta.text_append", map[string]any{"text": "one"}))
	p.feed(previewEvent("delta.text_append", map[string]any{"text": "two"}))
	if body := p.render(time.Now()); !strings.HasPrefix(body, "onetwo\n\n") {
		t.Fatalf("render = %q; want id-less deltas in one part", body)
	}
}

func TestStreamPreviewStatusLines(t *testing.T) {
	start := time.Now()
	p := newStreamPreview(start)
	// Replayed idle state before any work: suppressed.
	p.feed(previewEvent("agent.status", map[string]any{"activity_code": "online"}))
	if got := p.render(start); !strings.HasPrefix(got, "⏳ Muse is working…") {
		t.Errorf("render after replayed online = %q; want the default working status", got)
	}
	// Tool label while no app status is known.
	p.feed(previewEvent("delta.tool_start", map[string]any{"tool_name": "shell"}))
	if got := p.render(start); !strings.Contains(got, "🔧 shell") {
		t.Errorf("render after tool_start = %q; want the tool label", got)
	}
	// App status arrives and wins over later tool labels.
	p.feed(previewEvent("agent.status", map[string]any{"activity_text": "is working", "activity_emoji": "🦆"}))
	if got := p.render(start); !strings.Contains(got, "🦆 Muse is working") {
		t.Errorf("render after app status = %q; want emoji + subject", got)
	}
	p.feed(previewEvent("delta.tool_start", map[string]any{"tool_name": "shell"}))
	if got := p.render(start); !strings.Contains(got, "🦆 Muse is working") {
		t.Errorf("render after later tool_start = %q; app status must win", got)
	}
	// Online after work: wrapping up.
	p.feed(previewEvent("agent.status", map[string]any{"activity_code": "online"}))
	if got := p.render(start); !strings.Contains(got, "⏳ Muse is wrapping up…") {
		t.Errorf("render after online-with-work = %q; want wrapping up", got)
	}
}

func TestStreamPreviewRenderTailAndElapsed(t *testing.T) {
	start := time.Now()
	p := newStreamPreview(start)
	long := strings.Repeat("x", 4000)
	p.feed(previewEvent("delta.text_append", map[string]any{"text": long}))
	body := p.render(start.Add(65 * time.Second))
	if !strings.HasPrefix(body, "…") {
		t.Errorf("long render = %.20q...; want the … tail prefix", body)
	}
	if !strings.HasSuffix(body, "⏳ Muse is working… · 1m 05s") {
		t.Errorf("long render suffix = %q; want status + 1m 05s", body)
	}
	empty := newStreamPreview(start)
	if got := empty.render(start.Add(2 * time.Second)); got != "⏳ Muse is working… · 2s" {
		t.Errorf("empty render = %q; want status + elapsed only", got)
	}
	if got := formatElapsedSecs(3661 * time.Second); got != "1h 01m" {
		t.Errorf("formatElapsedSecs(3661s) = %q; want 1h 01m", got)
	}
	// Widget markers are stripped from the streamed body.
	marker := newStreamPreview(start)
	marker.feed(previewEvent("delta.text_append", map[string]any{"text": "hi [[hatch_widget:{\"a\":1}]] there"}))
	if got := marker.render(start); !strings.HasPrefix(got, "hi  there\n\n") {
		t.Errorf("marker render = %q; want the widget marker stripped", got)
	}
}
