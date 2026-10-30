// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"context"
	"errors"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

type historyResp struct {
	events  []any
	hasMore bool
	err     error
}

// scriptHistory is a HistoryReader scripted per limit: each
// ReadHistory pops the next queued response for its limit, or
// returns the default response.
type scriptHistory struct {
	byLimit map[int][]historyResp
	def     historyResp
	calls   []int
}

func (h *scriptHistory) ReadHistory(ctx context.Context, limit int) ([]any, bool, error) {
	h.calls = append(h.calls, limit)
	if q := h.byLimit[limit]; len(q) > 0 {
		resp := q[0]
		h.byLimit[limit] = q[1:]
		return resp.events, resp.hasMore, resp.err
	}
	return h.def.events, h.def.hasMore, h.def.err
}

var errTransport = errors.New("transport down")

func TestDefaultHistoryLimitsAccessorReturnsCopy(t *testing.T) {
	// The accessor returns a fresh copy: mutating it must not
	// change the defaults the next Runner gets.
	got := DefaultHistoryLimits()
	got[0] = 999
	if again := DefaultHistoryLimits(); len(again) != 3 || again[0] != 200 {
		t.Errorf("second accessor call = %v, want [200 500 1000] (mutation leaked)", again)
	}
}

// userEv builds a message.user history event.
func userEv(seq int) Event {
	return Event{"event_name": "message.user", "seq": seq, "payload": map[string]any{"display_text": "hi"}}
}

func TestDeriveBoundary(t *testing.T) {
	ctx := context.Background()
	limits := []int{200, 500, 1000}
	tests := []struct {
		name  string
		h     *scriptHistory
		seq   int64
		known bool
	}{
		{
			name: "first window with user",
			h: &scriptHistory{byLimit: map[int][]historyResp{
				200: {{events: []any{userEv(90), userEv(100)}, hasMore: true}},
			}},
			seq: 100, known: true,
		},
		{
			name: "empty window is known zero",
			h: &scriptHistory{byLimit: map[int][]historyResp{
				200: {{events: []any{}, hasMore: true}},
			}},
			seq: 0, known: true,
		},
		{
			name: "no user and no more pages is known zero",
			h: &scriptHistory{byLimit: map[int][]historyResp{
				200: {{events: []any{asst(50, "completed", "old", nil)}, hasMore: false}},
			}},
			seq: 0, known: true,
		},
		{
			name: "all windows fail is unknown",
			h:    &scriptHistory{def: historyResp{err: errTransport}},
			seq:  0, known: false,
		},
		{
			name: "exhaustion falls back to seen max",
			h: &scriptHistory{byLimit: map[int][]historyResp{
				200:  {{events: []any{asst(10, "completed", "a", nil)}, hasMore: true}},
				500:  {{events: []any{asst(20, "completed", "b", nil)}, hasMore: true}},
				1000: {{events: []any{asst(30, "completed", "c", nil)}, hasMore: true}},
			}},
			seq: 30, known: true,
		},
		{
			name: "retry once per window then succeed",
			h: &scriptHistory{byLimit: map[int][]historyResp{
				200: {{err: errTransport}, {events: []any{userEv(42)}, hasMore: false}},
			}},
			seq: 42, known: true,
		},
		{
			name: "failed window then next window succeeds",
			h: &scriptHistory{byLimit: map[int][]historyResp{
				200: {{err: errTransport}, {err: errTransport}},
				500: {{events: []any{userEv(77)}, hasMore: false}},
			}},
			seq: 77, known: true,
		},
		{
			name: "partial failure keeps seen max",
			h: &scriptHistory{byLimit: map[int][]historyResp{
				200:  {{events: []any{asst(15, "completed", "a", nil)}, hasMore: true}},
				500:  {{err: errTransport}, {err: errTransport}},
				1000: {{err: errTransport}, {err: errTransport}},
			}},
			seq: 15, known: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seq, known, derived, err := DeriveBoundary(ctx, tt.h, limits)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if seq != tt.seq || known != tt.known || !derived {
				t.Errorf("DeriveBoundary = (%d, %v, %v), want (%d, %v, true)", seq, known, derived, tt.seq, tt.known)
			}
		})
	}
}

func TestDeriveBoundaryAuthErrorPropagates(t *testing.T) {
	h := &scriptHistory{def: historyResp{err: conn.NewAuthError("expired")}}
	if _, _, _, err := DeriveBoundary(context.Background(), h, []int{200}); err == nil {
		t.Fatal("AuthError must propagate")
	} else {
		var authErr *conn.AuthError
		if !errors.As(err, &authErr) {
			t.Errorf("err = %v, want AuthError", err)
		}
	}
}

func TestLatestUserSeq(t *testing.T) {
	ctx := context.Background()
	// Accumulates across windows; stops when the window reaches
	// the boundary.
	h := &scriptHistory{byLimit: map[int][]historyResp{
		200: {{events: []any{userEv(90), userEv(100)}, hasMore: true}},
		500: {{events: []any{userEv(80), asst(95, "completed", "r", nil)}, hasMore: true}},
	}}
	seq, found, err := LatestUserSeq(ctx, h, []int{200, 500}, 85)
	if err != nil || !found || seq != 100 {
		t.Errorf("LatestUserSeq = (%d, %v, %v), want (100, true, nil)", seq, found, err)
	}
	// No user event: not found.
	h2 := &scriptHistory{def: historyResp{events: []any{asst(10, "completed", "r", nil)}, hasMore: false}}
	if _, found, err := LatestUserSeq(ctx, h2, []int{200}, 0); err != nil || found {
		t.Errorf("LatestUserSeq = found=%v err=%v", found, err)
	}
	// A read error propagates.
	h3 := &scriptHistory{def: historyResp{err: errTransport}}
	if _, _, err := LatestUserSeq(ctx, h3, []int{200}, 0); err == nil {
		t.Error("read error must propagate")
	}
}

func TestHistoryReplies(t *testing.T) {
	ctx := context.Background()
	// Window grows while has_more and oldest > afterSeq; the last
	// window's replies win, capped at its newest seq.
	h := &scriptHistory{byLimit: map[int][]historyResp{
		200: {{events: []any{asst(150, "completed", "too new", nil)}, hasMore: true}},
		500: {{events: []any{asst(120, "completed", "reply", nil), asst(90, "completed", "old", nil)}, hasMore: false}},
	}}
	replies, exhausted, err := HistoryReplies(ctx, h, []int{200, 500}, 100)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if exhausted {
		t.Error("exhausted must be false when the windows close")
	}
	if len(replies) != 1 || replies[0].Seq != 120 || replies[0].Text != "reply" {
		t.Errorf("replies = %+v", replies)
	}
	// Empty window: no replies, no upper bound beyond afterSeq.
	h2 := &scriptHistory{def: historyResp{events: []any{}, hasMore: false}}
	replies, exhausted, err = HistoryReplies(ctx, h2, []int{200}, 100)
	if err != nil || len(replies) != 0 || exhausted {
		t.Errorf("replies = %+v err=%v exhausted=%v", replies, err, exhausted)
	}
	// Exhaustion: has_more still true at the largest limit.
	h4 := &scriptHistory{byLimit: map[int][]historyResp{
		200: {{events: []any{userEv(150)}, hasMore: true}},
		500: {{events: []any{userEv(150)}, hasMore: true}},
	}}
	replies, exhausted, err = HistoryReplies(ctx, h4, []int{200, 500}, 100)
	if err != nil || len(replies) != 0 || !exhausted {
		t.Errorf("replies = %+v err=%v exhausted=%v, want exhausted=true", replies, err, exhausted)
	}
	// Error propagates for the caller to retry.
	h3 := &scriptHistory{def: historyResp{err: errTransport}}
	if _, _, err := HistoryReplies(ctx, h3, []int{200}, 100); err == nil {
		t.Error("read error must propagate")
	}
}

func TestReadWindowRetryScope(t *testing.T) {
	ctx := context.Background()
	// A transport error is retried once (two attempts total),
	// then the second attempt's success wins.
	h := &scriptHistory{byLimit: map[int][]historyResp{
		200: {{err: errTransport}, {events: []any{userEv(42)}, hasMore: false}},
	}}
	events, _, err := readWindow(ctx, h, 200)
	if err != nil || len(events) != 1 {
		t.Fatalf("retried read = (%v, %v), want 1 event", events, err)
	}
	if got := len(h.calls); got != 2 {
		t.Errorf("calls = %d, want 2 (one retry)", got)
	}
	// An AuthError is fatal: no retry, one attempt.
	h2 := &scriptHistory{def: historyResp{err: conn.NewAuthError("expired")}}
	if _, _, err := readWindow(ctx, h2, 200); err == nil {
		t.Fatal("AuthError must propagate")
	}
	if got := len(h2.calls); got != 1 {
		t.Errorf("calls = %d, want 1 (no retry on fatal)", got)
	}
	// A cancelled context is fatal too: no retry.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	h3 := &scriptHistory{def: historyResp{err: errTransport}}
	if _, _, err := readWindow(cancelled, h3, 200); err == nil {
		t.Fatal("cancelled read must propagate")
	}
	if got := len(h3.calls); got != 1 {
		t.Errorf("calls = %d, want 1 (no retry when cancelled)", got)
	}
}
