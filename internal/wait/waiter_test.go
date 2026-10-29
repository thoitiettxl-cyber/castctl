// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/approvals"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// taskEv builds a task.status event. count nil means the field is
// absent; use countVal for an explicit value.
func taskEv(status, root, agent string, seq int, count any) Event {
	p := map[string]any{"status": status}
	if root != "" {
		p["root_agent_id"] = root
	}
	if agent != "" {
		p["agent_id"] = agent
	}
	if count != nil {
		p["active_subagent_count"] = count
	}
	ev := Event{"event": "task.status", "payload": p}
	if seq != 0 {
		ev["seq"] = seq
	}
	return ev
}

func statusOf(w *Waiter) string {
	s, _ := w.Status()
	return s
}

func TestVocabularies(t *testing.T) {
	// 1 + 3 + 6 + 6 = 16 distinct strings. (The survey doc says
	// 14; the code sets sum to 16, verified by executing the
	// Python sets.)
	if len(done) != 1 || len(failed) != 3 || len(suspectDone) != 6 || len(suspectFailed) != 6 || len(terminal) != 16 {
		t.Errorf("vocabulary sizes: done=%d failed=%d suspectDone=%d suspectFailed=%d terminal=%d",
			len(done), len(failed), len(suspectDone), len(suspectFailed), len(terminal))
	}
	if terminal["running"] || terminal["queued"] || terminal["error "] {
		t.Error("non-terminal strings must not be in TERMINAL")
	}
}

func TestTaskStatusInfo(t *testing.T) {
	tests := []struct {
		name string
		ev   Event
		want *TaskStatus
	}{
		{
			name: "completed root confirmed lowercased",
			ev:   taskEv("Completed", "R", "R", 0, nil),
			want: &TaskStatus{Status: "completed", HasStatus: true, RootConfirmed: true, RootAgentID: "R", AgentID: "R"},
		},
		{
			name: "subagent dropped entirely",
			ev:   taskEv("completed", "R", "S", 0, nil),
			want: nil,
		},
		{
			name: "agent without root is not dropped",
			ev:   taskEv("completed", "", "S", 0, nil),
			want: &TaskStatus{Status: "completed", HasStatus: true, RootAgentID: "", AgentID: "S"},
		},
		{
			name: "root without agent unconfirmed",
			ev:   taskEv("completed", "R", "", 0, nil),
			want: &TaskStatus{Status: "completed", HasStatus: true, RootAgentID: "R"},
		},
		{
			name: "missing status still returns info",
			ev:   taskEv("", "R", "R", 0, nil),
			want: &TaskStatus{HasStatus: false, RootConfirmed: true, RootAgentID: "R", AgentID: "R"},
		},
		{
			name: "wrong event name",
			ev:   Event{"event": "message.assistant", "payload": map[string]any{"status": "completed"}},
			want: nil,
		},
		{
			name: "event_name fallback",
			ev:   Event{"event_name": "task.status", "payload": map[string]any{"status": "RUNNING", "root_agent_id": "R", "agent_id": "R"}},
			want: &TaskStatus{Status: "running", HasStatus: true, RootConfirmed: true, RootAgentID: "R", AgentID: "R"},
		},
		{
			name: "spaces not stripped",
			ev:   taskEv(" completed ", "R", "R", 0, nil),
			want: &TaskStatus{Status: " completed ", HasStatus: true, RootConfirmed: true, RootAgentID: "R", AgentID: "R"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TaskStatusInfo(tt.ev, "")
			if tt.want == nil {
				if got != nil {
					t.Errorf("got %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("got nil, want %+v", tt.want)
			}
			if got.Status != tt.want.Status || got.HasStatus != tt.want.HasStatus ||
				got.RootConfirmed != tt.want.RootConfirmed || got.RootAgentID != tt.want.RootAgentID ||
				got.AgentID != tt.want.AgentID {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestScope(t *testing.T) {
	// Payload session_id only: an event-level session_id is ignored.
	ev := Event{
		"event":      "task.status",
		"session_id": "T2",
		"payload":    map[string]any{"status": "running", "root_agent_id": "R", "agent_id": "R"},
	}
	if TaskStatusInfo(ev, "T1") == nil {
		t.Error("event-level session_id must be ignored; payload has none, so in scope")
	}
	ev2 := Event{
		"event":   "task.status",
		"payload": map[string]any{"status": "running", "session_id": "T2", "root_agent_id": "R", "agent_id": "R"},
	}
	if TaskStatusInfo(ev2, "T1") != nil {
		t.Error("payload session_id T2 must be out of scope for T1")
	}
	ev3 := Event{
		"event":   "task.status",
		"payload": map[string]any{"status": "running", "is_thread": true, "root_agent_id": "R", "agent_id": "R"},
	}
	if TaskStatusInfo(ev3, "") != nil {
		t.Error("is_thread must be out of scope without a thread")
	}
}

// TestFeedTraceA is the live-done trace.
func TestFeedTraceA(t *testing.T) {
	w := New("")
	if out := w.Feed(taskEv("running", "R", "R", 120, nil)); out != nil {
		t.Fatalf("running must not decide: %v", out)
	}
	if !w.SeenRunning() || statusOf(w) != "running" {
		t.Errorf("after running: seen=%v status=%q", w.SeenRunning(), statusOf(w))
	}
	out := w.Feed(taskEv("completed", "R", "R", 180, nil))
	if out == nil || out.Kind != KindDone || out.Detail != "completed" {
		t.Fatalf("completed after running = %v, want done/completed", out)
	}
}

// TestFeedTraceB is the replayed-completed trace: root is not
// learned from a terminal, and the terminal is ignored.
func TestFeedTraceB(t *testing.T) {
	w := New("")
	if out := w.Feed(taskEv("completed", "R", "R", 0, nil)); out != nil {
		t.Fatalf("replayed completed must not decide: %v", out)
	}
	if _, ok := w.RootID(); ok {
		t.Error("terminal must not teach the root")
	}
	term, _ := w.IgnoredTerminal()
	if term != "completed" || w.IgnoredReason() != "" || w.SeenRunning() {
		t.Errorf("ignored=%q reason=%q seen=%v", term, w.IgnoredReason(), w.SeenRunning())
	}
	if out := w.Settle([]Reply{{Seq: 150, Text: "hi"}}); out == nil || out.Kind != KindDone || out.Detail != "completed" {
		t.Fatalf("settle = %v, want done/completed", out)
	}
}

// TestFeedTraceC is the suspect-string trace: still needs proof.
func TestFeedTraceC(t *testing.T) {
	w := New("")
	w.Feed(taskEv("running", "R", "R", 0, nil))
	w.Feed(taskEv("idle", "R", "R", 0, nil))
	term, _ := w.IgnoredTerminal()
	if term != "idle" || statusOf(w) != "idle" {
		t.Errorf("ignored=%q status=%q", term, statusOf(w))
	}
	if out := w.Settle([]Reply{{Seq: 1, Text: "x"}}); out == nil || out.Detail != "idle" {
		t.Fatalf("settle idle = %v, want done/idle", out)
	}
}

// TestFeedTraceD is the subagent trace: state entirely unchanged.
func TestFeedTraceD(t *testing.T) {
	w := New("")
	w.Feed(taskEv("completed", "R", "S", 0, nil))
	if w.SeenRunning() || statusOf(w) != "" {
		t.Errorf("subagent event must teach nothing: seen=%v status=%q", w.SeenRunning(), statusOf(w))
	}
	if _, ok := w.IgnoredTerminal(); ok {
		t.Error("subagent event must not store an ignored terminal")
	}
}

// TestFeedTraceE is the unconfirmed-running trace.
func TestFeedTraceE(t *testing.T) {
	w := New("")
	w.Feed(taskEv("running", "", "S", 0, nil))
	if w.SeenRunning() {
		t.Error("unconfirmed running must not arm seen_running")
	}
	if statusOf(w) != "running" {
		t.Errorf("status=%q, want running", statusOf(w))
	}
	w.Feed(taskEv("completed", "", "S", 0, nil))
	term, _ := w.IgnoredTerminal()
	if term != "completed" || w.IgnoredReason() != "missing_root" {
		t.Errorf("ignored=%q reason=%q", term, w.IgnoredReason())
	}
}

// TestFeedTraceF is the non-terminal trace: status untouched.
func TestFeedTraceF(t *testing.T) {
	w := New("")
	w.Feed(taskEv("running", "R", "R", 0, nil))
	w.Feed(taskEv("queued", "R", "R", 0, nil))
	w.Feed(taskEv("bogus_xyz", "R", "R", 0, nil))
	if statusOf(w) != "running" {
		t.Errorf("status=%q, want running", statusOf(w))
	}
}

// TestFeedTraceG is the foreign-root trace.
func TestFeedTraceG(t *testing.T) {
	w := New("")
	w.Feed(taskEv("running", "R", "R", 0, nil))
	w.Feed(taskEv("completed", "R2", "R2", 0, nil))
	if statusOf(w) != "running" {
		t.Errorf("status=%q, want running", statusOf(w))
	}
	if _, ok := w.IgnoredTerminal(); ok {
		t.Error("foreign-root terminal must leave no ignored terminal")
	}
}

// TestFeedTraceH is the second-root trace: first root wins,
// ignored terminal is not cleared by a foreign running.
func TestFeedTraceH(t *testing.T) {
	w := New("")
	w.Feed(taskEv("running", "R", "R", 0, nil))
	w.Feed(taskEv("completed", "R", "R", 0, 2))
	term, _ := w.IgnoredTerminal()
	if term != "completed" || w.IgnoredReason() != "subagents" {
		t.Fatalf("ignored=%q reason=%q", term, w.IgnoredReason())
	}
	w.Feed(taskEv("running", "R2", "R2", 0, nil))
	root, _ := w.RootID()
	if root != "R" {
		t.Errorf("root=%q, want R", root)
	}
	term, _ = w.IgnoredTerminal()
	if term != "completed" {
		t.Errorf("foreign running must not clear ignored terminal, got %q", term)
	}
}

// TestFeedTraceI covers malformed feed input.
func TestFeedTraceI(t *testing.T) {
	w := New("")
	if out := w.FeedRecord([]byte(`{"status": "completed"`)); out != nil {
		t.Errorf("invalid JSON = %v", out)
	}
	if out := w.FeedRecord([]byte(`42`)); out != nil {
		t.Errorf("non-object JSON = %v", out)
	}
	if out := w.FeedRecord([]byte(`{"event": "task.status", "payload": "junk"}`)); out != nil {
		t.Errorf("non-dict payload = %v", out)
	}
	if out := w.FeedRecord([]byte(`{"event":"task.status","payload":{"status":"completed"}} {"x":1}`)); out != nil {
		t.Errorf("trailing data = %v", out)
	}
	if w.SeenRunning() || statusOf(w) != "" {
		t.Error("malformed input must change no state")
	}
	// FeedRecord with a real record works, with json.Number seqs.
	if out := w.FeedRecord([]byte(`{"event":"task.status","seq":120,"payload":{"status":"running","root_agent_id":"R","agent_id":"R"}}`)); out != nil {
		t.Fatalf("running record = %v", out)
	}
	if seq, ok := w.RunningSeq(); !ok || seq != 120 {
		t.Errorf("running_seq=%d ok=%v, want 120", seq, ok)
	}
}

func TestFeedFailedDirect(t *testing.T) {
	for _, s := range []string{"interrupted", "cancelled", "canceled"} {
		w := New("")
		w.Feed(taskEv("running", "R", "R", 0, nil))
		out := w.Feed(taskEv(s, "R", "R", 0, nil))
		if out == nil || out.Kind != KindFailed || out.Detail != s {
			t.Errorf("status %q after running = %v", s, out)
		}
	}
}

func TestF8Rearm(t *testing.T) {
	w := New("")
	w.Feed(taskEv("running", "R", "R", 0, nil))
	w.Feed(taskEv("completed", "R", "R", 0, 2))
	if w.IgnoredReason() != "subagents" {
		t.Fatalf("reason=%q", w.IgnoredReason())
	}
	// Count None does not re-arm.
	w.Feed(taskEv("queued", "R", "R", 0, nil))
	if w.IgnoredReason() != "subagents" {
		t.Errorf("count None must not re-arm, reason=%q", w.IgnoredReason())
	}
	// Count 0 re-arms; the terminal itself is kept.
	w.Feed(taskEv("queued", "R", "R", 0, 0))
	if w.IgnoredReason() != "" {
		t.Errorf("count 0 must re-arm, reason=%q", w.IgnoredReason())
	}
	term, _ := w.IgnoredTerminal()
	if term != "completed" {
		t.Errorf("re-arm must keep the terminal, got %q", term)
	}
	if out := w.Settle([]Reply{{Seq: 1, Text: "x"}}); out == nil || out.Detail != "completed" {
		t.Fatalf("settle after re-arm = %v", out)
	}
}

func TestF8RearmByForeignRoot(t *testing.T) {
	// Step 2 precedes the foreign-root check: a foreign-root
	// event with count 0 clears the reason even though the event
	// itself is then ignored.
	w := New("")
	w.Feed(taskEv("running", "R", "R", 0, nil))
	w.Feed(taskEv("completed", "R", "R", 0, 2))
	w.Feed(taskEv("completed", "R2", "R2", 0, 0))
	if w.IgnoredReason() != "" {
		t.Errorf("foreign count-0 event must re-arm, reason=%q", w.IgnoredReason())
	}
	if statusOf(w) != "completed" {
		t.Errorf("foreign event must not update status, got %q", statusOf(w))
	}
}

func TestSettleGates(t *testing.T) {
	// No ignored terminal.
	w := New("")
	if out := w.Settle([]Reply{{Text: "x"}}); out != nil {
		t.Errorf("settle without terminal = %v", out)
	}
	// Boundary unknown blocks.
	w2 := New("")
	w2.Feed(taskEv("completed", "R", "R", 0, nil))
	w2.SetBoundary(100, true, false)
	if out := w2.Settle([]Reply{{Text: "x"}}); out != nil {
		t.Errorf("settle with unknown boundary = %v", out)
	}
	// Empty replies keep the terminal.
	w3 := New("")
	w3.Feed(taskEv("completed", "R", "R", 0, nil))
	if out := w3.Settle(nil); out != nil {
		t.Errorf("settle with no replies = %v", out)
	}
	if _, ok := w3.IgnoredTerminal(); !ok {
		t.Error("failed settle must keep the terminal")
	}
	// FAILED never settles here, even with replies.
	w4 := New("")
	w4.Feed(taskEv("interrupted", "R", "R", 0, nil))
	if out := w4.Settle([]Reply{{Text: "x"}}); out != nil {
		t.Errorf("settle FAILED = %v", out)
	}
	// SUSPECT_FAILED settles to failed.
	w5 := New("")
	w5.Feed(taskEv("failed", "R", "R", 0, nil))
	out := w5.Settle([]Reply{{Text: "x"}})
	if out == nil || out.Kind != KindFailed || out.Detail != "failed" {
		t.Fatalf("settle suspect-failed = %v", out)
	}
	// missing_root does NOT block settle.
	w6 := New("")
	w6.Feed(taskEv("completed", "", "S", 0, nil))
	out = w6.Settle([]Reply{{Text: "x"}})
	if out == nil || out.Kind != KindDone {
		t.Fatalf("settle missing_root = %v", out)
	}
	// A later terminal overwrites an earlier ignored one.
	w7 := New("")
	w7.Feed(taskEv("idle", "R", "R", 0, nil))
	w7.Feed(taskEv("failed", "R", "R", 0, nil))
	term, _ := w7.IgnoredTerminal()
	if term != "failed" {
		t.Errorf("later terminal must overwrite, got %q", term)
	}
}

func TestAcceptReplayedFailedTable(t *testing.T) {
	mk := func() *Waiter {
		w := New("")
		w.Feed(taskEv("interrupted", "R", "R", 0, nil))
		w.SetBoundary(200, false, true)
		return w
	}
	seq := func(n int64) *int64 { return &n }
	tests := []struct {
		name     string
		modify   func(*Waiter)
		latest   *int64
		wantFail bool
	}{
		{"equal accepts", nil, seq(200), true},
		{"newer user rejects", nil, seq(201), false},
		{"older user rejects", nil, seq(199), false},
		{"nil latest rejects", nil, nil, false},
		{"explicit boundary rejects", func(w *Waiter) { w.SetBoundary(200, false, false) }, seq(200), false},
		{"nil after_seq rejects", func(w *Waiter) { w.SetBoundary(200, false, true); w.afterSeq = nil }, seq(200), false},
		{"missing_root rejects", func(w *Waiter) {
			w2 := New("")
			w2.Feed(taskEv("interrupted", "", "S", 0, nil))
			w2.SetBoundary(200, false, true)
			*w = *w2
		}, seq(200), false},
		{"suspect failed rejects", func(w *Waiter) {
			w2 := New("")
			w2.Feed(taskEv("failed", "R", "R", 0, nil))
			w2.SetBoundary(200, false, true)
			*w = *w2
		}, seq(200), false},
		{"unknown boundary rejects", func(w *Waiter) { w.SetBoundary(200, true, true) }, seq(200), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := mk()
			if tt.modify != nil {
				tt.modify(w)
			}
			out := w.AcceptReplayedFailed(tt.latest)
			if tt.wantFail && (out == nil || out.Kind != KindFailed || out.Detail != "interrupted") {
				t.Errorf("accept = %v, want failed/interrupted", out)
			}
			if !tt.wantFail && out != nil {
				t.Errorf("accept = %v, want nil", out)
			}
		})
	}
}

func TestRequireRunningIsDead(t *testing.T) {
	for _, flag := range []bool{false, true} {
		w := New("", WithRequireRunning(flag))
		if w.RequireRunning() != flag {
			t.Errorf("flag not stored: %v", flag)
		}
		w.Feed(taskEv("completed", "R", "R", 0, nil))
		if w.Result() != nil {
			t.Errorf("require_running=%v must not change detection", flag)
		}
	}
}

func TestResultStickinessD1(t *testing.T) {
	w := New("")
	w.Feed(taskEv("running", "R", "R", 0, nil))
	w.Feed(taskEv("completed", "R", "R", 0, nil))
	// A later terminal cannot flip a decided turn (deviation D1).
	w.Feed(taskEv("interrupted", "R", "R", 0, nil))
	out := w.Result()
	if out == nil || out.Kind != KindDone || out.Detail != "completed" {
		t.Fatalf("result = %v, want done/completed", out)
	}
	if out2 := w.Settle([]Reply{{Text: "x"}}); out2 != nil {
		t.Errorf("settle after result = %v, want nil", out2)
	}
}

func approvalEv(pending []any, recent []any) Event {
	p := map[string]any{"pending_approvals": pending}
	if recent != nil {
		p["recent_approvals"] = recent
	}
	return Event{"event": "approvals.snapshot", "payload": p}
}

func appr(id string, opts ...string) map[string]any {
	m := map[string]any{"approval_id": id}
	if len(opts) > 0 {
		var list []any
		for _, o := range opts {
			list = append(list, map[string]any{"kind": o})
		}
		m["decision_options"] = list
	}
	return m
}

func TestFeedApprovalsNoApprover(t *testing.T) {
	w := New("")
	out := w.Feed(approvalEv([]any{appr("A")}, nil))
	if out == nil || out.Kind != KindApproval || len(out.Approvals) != 1 {
		t.Fatalf("approval result = %v", out)
	}
	if *out.Approvals[0].ApprovalID != "A" {
		t.Errorf("approval id = %v", out.Approvals[0].ApprovalID)
	}
}

func TestFeedApprovalsExpiredOnlyKeepsWaiting(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w := New("", WithNow(func() time.Time { return now }))
	past := appr("A")
	past["request_expires_at_ms"] = float64(now.UnixMilli() - 1000)
	if out := w.Feed(approvalEv([]any{past}, nil)); out != nil {
		t.Fatalf("expired-only = %v", out)
	}
	// Non-numeric expiry is not expired.
	w2 := New("", WithNow(func() time.Time { return now }))
	strExp := appr("B")
	strExp["request_expires_at_ms"] = "yesterday"
	if out := w2.Feed(approvalEv([]any{strExp}, nil)); out == nil {
		t.Fatal("string expiry must not expire the approval")
	}
	// Bool expiry counts as 1: expired.
	w3 := New("", WithNow(func() time.Time { return now }))
	boolExp := appr("C")
	boolExp["request_expires_at_ms"] = true
	if out := w3.Feed(approvalEv([]any{boolExp}, nil)); out != nil {
		t.Fatalf("bool expiry = %v", out)
	}
}

func TestFeedApprovalsRecentDecisions(t *testing.T) {
	// With an approver, a recently decided approval is not
	// re-offered and, when nothing is left, the wait continues.
	called := false
	w := New("", WithApprover(func(items []approvals.DescribedApproval) approvals.ApprovalResult {
		called = true
		return approvals.ApprovalResult{}
	}))
	recent := []any{map[string]any{"approval_id": "A", "decision": "allow_always"}}
	if out := w.Feed(approvalEv([]any{appr("A")}, recent)); out != nil {
		t.Fatalf("recently decided must keep waiting: %v", out)
	}
	if called {
		t.Error("recently decided approval must not be offered to the approver")
	}
	// Without an approver there is no left-filter in the code:
	// the pending approval still ends the wait for a human.
	w2 := New("")
	if out := w2.Feed(approvalEv([]any{appr("A")}, recent)); out == nil || out.Kind != KindApproval {
		t.Fatalf("no-approver recent decision = %v, want approval result", out)
	}
}

func TestFeedApprovalsApprover(t *testing.T) {
	calls := 0
	approver := func(items []approvals.DescribedApproval) approvals.ApprovalResult {
		calls++
		return approvals.ApprovalResult{Handled: []string{"A"}}
	}
	w := New("", WithApprover(approver))
	if out := w.Feed(approvalEv([]any{appr("A"), appr("B")}, nil)); out == nil || len(out.Approvals) != 1 {
		t.Fatalf("partial approval = %v", out)
	}
	if *w.Result().Approvals[0].ApprovalID != "B" {
		t.Errorf("left approval = %v", w.Result().Approvals[0].ApprovalID)
	}
	if calls != 1 {
		t.Errorf("approver calls = %d", calls)
	}
	// All handled: keep waiting.
	w2 := New("", WithApprover(func(items []approvals.DescribedApproval) approvals.ApprovalResult {
		return approvals.ApprovalResult{Handled: []string{"A"}}
	}))
	if out := w2.Feed(approvalEv([]any{appr("A")}, nil)); out != nil {
		t.Fatalf("all handled = %v", out)
	}
	if out := w2.Feed(taskEv("running", "R", "R", 0, nil)); out != nil {
		t.Fatalf("running after approvals = %v", out)
	}
}

func TestFeedApprovalsApproverRaises(t *testing.T) {
	calls := 0
	approver := func(items []approvals.DescribedApproval) approvals.ApprovalResult {
		calls++
		// Partial decisions made before the raise are lost.
		return approvals.ApprovalResult{Handled: []string{"A"}, Err: errBoom}
	}
	w := New("", WithApprover(approver))
	out := w.Feed(approvalEv([]any{appr("A")}, nil))
	if out == nil || out.Kind != KindApproval {
		t.Fatalf("raise result = %v", out)
	}
	if w.handled["A"] {
		t.Error("partial decision before a raise must not be recorded handled")
	}
	if !w.approverFailed["A"] {
		t.Error("raised id must be in approver_failed")
	}
	// The id is never offered again: the approver is not called
	// a second time even on a fresh snapshot (white-box: the
	// offered set blocks it; D1 also stops the feed).
	if calls != 1 {
		t.Errorf("calls = %d", calls)
	}
}

var errBoom = errString("boom")

type errString string

func (e errString) Error() string { return string(e) }

func TestFeedApprovalsNilIDNeverOfferedButEndsWait(t *testing.T) {
	called := false
	approver := func(items []approvals.DescribedApproval) approvals.ApprovalResult {
		called = true
		return approvals.ApprovalResult{}
	}
	w := New("", WithApprover(approver))
	pend := []any{map[string]any{"display": map[string]any{"summary_title": "X"}}}
	out := w.Feed(approvalEv(pend, nil))
	if called {
		t.Error("nil-id approval must never be offered to the approver")
	}
	if out == nil || out.Kind != KindApproval || len(out.Approvals) != 1 {
		t.Fatalf("nil-id approval must still end the wait: %v", out)
	}
}

func TestFeedApprovalsPrecedenceOverTaskStatus(t *testing.T) {
	// A combined event with approvals runs the approval path
	// without ever looking at the task status.
	w := New("")
	ev := approvalEv([]any{appr("A")}, nil)
	ev["payload"].(map[string]any)["status"] = "completed"
	ev["event"] = "approvals.snapshot"
	out := w.Feed(ev)
	if out == nil || out.Kind != KindApproval {
		t.Fatalf("combined event = %v", out)
	}
	if _, ok := w.IgnoredTerminal(); ok {
		t.Error("task status in a combined event must not be examined")
	}
}

func TestFeedApprovalsPendingFallback(t *testing.T) {
	// pending_approvals absent -> pending; empty list does not
	// fall back.
	w := New("")
	ev := Event{"event": "approvals.snapshot", "payload": map[string]any{
		"pending": []any{appr("A")},
	}}
	if out := w.Feed(ev); out == nil || out.Kind != KindApproval {
		t.Fatalf("pending fallback = %v", out)
	}
	w2 := New("")
	ev2 := Event{"event": "approvals.snapshot", "payload": map[string]any{
		"pending_approvals": []any{},
		"pending":           []any{appr("A")},
	}}
	if out := w2.Feed(ev2); out != nil {
		t.Fatalf("empty pending_approvals must not fall back: %v", out)
	}
}

func TestFeedApprovalsDuplicateIDsDedupedFirstWins(t *testing.T) {
	var offered [][]approvals.DescribedApproval
	approver := func(items []approvals.DescribedApproval) approvals.ApprovalResult {
		offered = append(offered, items)
		return approvals.ApprovalResult{}
	}
	w := New("", WithApprover(approver))
	out := w.Feed(approvalEv([]any{appr("A"), appr("A"), appr("B"), appr("B")}, nil))
	if out == nil || out.Kind != KindApproval || len(out.Approvals) != 2 {
		t.Fatalf("duplicate snapshot = %v, want 2 approvals", out)
	}
	if len(offered) != 1 || len(offered[0]) != 2 {
		t.Fatalf("offered = %v, want one call with [A B]", offered)
	}
	if *offered[0][0].ApprovalID != "A" || *offered[0][1].ApprovalID != "B" {
		t.Errorf("offered ids = %v %v, want A B", offered[0][0].ApprovalID, offered[0][1].ApprovalID)
	}
}

func TestFeedApprovalsNilIDsNotDeduped(t *testing.T) {
	// Nil-id descriptions carry no id to dedupe on: both are
	// reported, and neither is offered to the approver.
	called := false
	w := New("", WithApprover(func(items []approvals.DescribedApproval) approvals.ApprovalResult {
		called = true
		return approvals.ApprovalResult{}
	}))
	pend := []any{
		map[string]any{"display": map[string]any{"summary_title": "X"}},
		map[string]any{"display": map[string]any{"summary_title": "Y"}},
	}
	out := w.Feed(approvalEv(pend, nil))
	if called {
		t.Error("nil-id approvals must never be offered")
	}
	if out == nil || out.Kind != KindApproval || len(out.Approvals) != 2 {
		t.Fatalf("nil-id snapshot = %v, want 2 approvals", out)
	}
}

func TestFeedApprovalsEmptyIDsDedupedFirstWins(t *testing.T) {
	// "" is a present id: two "" descriptions in one snapshot
	// dedupe first-wins, are offered/decided at most once, and
	// are not re-offered on a later snapshot. The first
	// description's options pin the decision.
	decided := []string{}
	decideCalls := 0
	aa := approvals.NewAutoApprover(func(ctx context.Context) (approvals.Decider, func(), error) {
		return func(ctx context.Context, a approvals.DescribedApproval, decision string) error {
			decideCalls++
			decided = append(decided, decision)
			return nil
		}, func() {}, nil
	}, false)
	w := New("", WithApprover(aa.AsApprover()))
	first := map[string]any{
		"approval_id":      "",
		"display":          map[string]any{"summary_title": "first"},
		"decision_options": []any{map[string]any{"kind": "allow_always"}},
	}
	second := map[string]any{
		"approval_id":      "",
		"display":          map[string]any{"summary_title": "second"},
		"decision_options": []any{map[string]any{"kind": "allow_always"}, map[string]any{"kind": "allow_once"}},
	}
	snap := approvalEv([]any{first, second}, nil)
	if out := w.Feed(snap); out != nil {
		t.Fatalf("handled \"\" snapshot = %v, want nil (keep waiting)", out)
	}
	if decideCalls != 1 || len(decided) != 1 || decided[0] != approvals.Forever {
		t.Fatalf("decide calls = %d decided = %v, want 1 call with allow_always (first wins)", decideCalls, decided)
	}
	if recs := w.ApprovedRecords(); len(recs) != 1 || recs[0].Title != "first" {
		t.Errorf("approved records = %v, want the first description", recs)
	}
	if out := w.Feed(snap); out != nil {
		t.Fatalf("second \"\" snapshot = %v, want nil", out)
	}
	if decideCalls != 1 {
		t.Errorf("decide calls after second snapshot = %d, want 1 (never re-decided)", decideCalls)
	}
}

func TestFeedApprovalsAuthErrorIsFatal(t *testing.T) {
	authErr := conn.NewAuthError("expired")
	w := New("", WithApprover(func(items []approvals.DescribedApproval) approvals.ApprovalResult {
		return approvals.ApprovalResult{Err: authErr}
	}))
	out := w.Feed(approvalEv([]any{appr("A")}, nil))
	if out != nil {
		t.Fatalf("fatal approver error must set no result: %v", out)
	}
	if w.FatalErr() == nil {
		t.Fatal("FatalErr must be set")
	}
	var gotAuth *conn.AuthError
	if !errors.As(w.FatalErr(), &gotAuth) {
		t.Errorf("FatalErr = %v, want an AuthError", w.FatalErr())
	}
	if w.approverFailed["A"] {
		t.Error("fatal ids must not be marked approver-failed")
	}
}

func TestFeedApprovalsAccumulatesRecords(t *testing.T) {
	rec := approvals.ApprovedRecord{ApprovalID: "A", Decision: approvals.Forever}
	appErr := &approvals.ApproveError{ApprovalID: "B", Err: errBoom}
	w := New("", WithApprover(func(items []approvals.DescribedApproval) approvals.ApprovalResult {
		return approvals.ApprovalResult{
			Approved: []approvals.ApprovedRecord{rec},
			Errors:   []*approvals.ApproveError{appErr},
		}
	}))
	w.Feed(approvalEv([]any{appr("A"), appr("B")}, nil))
	if got := w.ApprovedRecords(); len(got) != 1 || got[0].ApprovalID != "A" {
		t.Errorf("ApprovedRecords = %v", got)
	}
	if got := w.ApproveErrors(); len(got) != 1 || got[0].ApprovalID != "B" {
		t.Errorf("ApproveErrors = %v", got)
	}
}

func TestWaiterZeroValueUsable(t *testing.T) {
	var w Waiter
	w.Feed(taskEv("running", "R", "R", 0, nil))
	out := w.Feed(taskEv("completed", "R", "R", 0, nil))
	if out == nil || out.Kind != KindDone || out.Detail != "completed" {
		t.Fatalf("zero-value waiter = %v, want done/completed", out)
	}
	var w2 Waiter
	out2 := w2.Feed(approvalEv([]any{appr("A")}, nil))
	if out2 == nil || out2.Kind != KindApproval {
		t.Fatalf("zero-value waiter approvals = %v, want approval", out2)
	}
}

func TestResultDeepCopiesApprovalOptions(t *testing.T) {
	w := New("")
	w.Feed(approvalEv([]any{appr("A", approvals.Forever)}, nil))
	r1 := w.Result()
	if len(r1.Approvals) != 1 || len(r1.Approvals[0].Options) != 1 {
		t.Fatalf("result = %v", r1)
	}
	r1.Approvals[0].Options[0] = "mutated"
	r2 := w.Result()
	if r2.Approvals[0].Options[0] != approvals.Forever {
		t.Errorf("second Result Options = %v, want [%q] (mutation leaked)", r2.Approvals[0].Options, approvals.Forever)
	}
}

func TestResultDeepCopiesApprovalPointerFields(t *testing.T) {
	// All seven pointer fields must be deep-copied: mutating
	// *Title/*ApprovalID (or any other) on a returned Result
	// must not corrupt the Waiter's stored description.
	w := New("")
	pend := map[string]any{
		"approval_id": "A",
		"display": map[string]any{
			"summary_title":     "T",
			"short_explanation": "W",
			"permission_question": map[string]any{
				"text": "Q", "kind": "K", "scope": "S",
			},
		},
		"request_expires_at_ms": float64(4102444800000),
	}
	w.Feed(approvalEv([]any{pend}, nil))
	r1 := w.Result()
	if len(r1.Approvals) != 1 {
		t.Fatalf("result = %v", r1)
	}
	d := &r1.Approvals[0]
	if d.ApprovalID == nil || d.Title == nil || d.Question == nil || d.Kind == nil ||
		d.Scope == nil || d.Why == nil || d.ExpiresAtMS == nil {
		t.Fatalf("approval pointers = %+v, want all seven non-nil", d)
	}
	*d.ApprovalID, *d.Title, *d.Question = "mutated", "mutated", "mutated"
	*d.Kind, *d.Scope, *d.Why = "mutated", "mutated", "mutated"
	*d.ExpiresAtMS = 0
	r2 := w.Result()
	got := r2.Approvals[0]
	if *got.ApprovalID != "A" || *got.Title != "T" || *got.Question != "Q" ||
		*got.Kind != "K" || *got.Scope != "S" || *got.Why != "W" ||
		*got.ExpiresAtMS != float64(4102444800000) {
		t.Errorf("second Result approval = %+v (fields %q %q %q %q %q %q %v), want the stored values (mutation leaked)",
			got, *got.ApprovalID, *got.Title, *got.Question, *got.Kind, *got.Scope, *got.Why, *got.ExpiresAtMS)
	}
}

func TestApproveErrorsReturnsCopies(t *testing.T) {
	// ApproveErrors clones each record: mutating a returned
	// record must not corrupt the Waiter's stored errors.
	appErr := &approvals.ApproveError{ApprovalID: "B", Title: "T", Err: errBoom}
	w := New("", WithApprover(func(items []approvals.DescribedApproval) approvals.ApprovalResult {
		return approvals.ApprovalResult{Errors: []*approvals.ApproveError{appErr}}
	}))
	w.Feed(approvalEv([]any{appr("A"), appr("B")}, nil))
	got1 := w.ApproveErrors()
	if len(got1) != 1 {
		t.Fatalf("ApproveErrors = %v", got1)
	}
	got1[0].Title = "mutated"
	got1[0].ApprovalID = "mutated"
	got2 := w.ApproveErrors()
	if got2[0].Title != "T" || got2[0].ApprovalID != "B" {
		t.Errorf("second ApproveErrors = %+v, want the stored record (mutation leaked)", got2[0])
	}
}
