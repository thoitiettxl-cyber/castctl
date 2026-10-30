// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

// Red/green tests for the wait redesign (overnight item 3).
// Numbering follows phase1-r3-seams-tests-docs.md §2 (T1–T18).
// T1–T4 are pins: they must stay green on the pre-redesign code
// and after it. T5–T8 are RED demonstrations: they fail on the
// pre-redesign code and pass only with the new semantics.

import (
	"testing"
	"testing/synctest"
	"time"
)

// T1 (pin): derived boundary is the last message.user seq.
func TestWaitRedesignT1DerivedBoundary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(30), userEv(41), asst(20, "completed", "old", nil)}),
			historyOK([]any{userEv(41), asst(42, "completed", "done", nil)}),
		}}
		res := runRunner(t, Config{
			Timeout: 60 * time.Second,
			Dial:    sub.dial,
			History: hist,
		})
		if res.Kind != KindDone || res.Outcome != "done" || res.ExitCode != 0 {
			t.Errorf("res = %+v", res)
		}
		if res.AfterSeq != 41 || len(res.Replies) != 1 || res.Replies[0].Seq != 42 || res.FinalText != "done" {
			t.Errorf("res = %+v, want boundary 41 and reply [42]", res)
		}
	})
}

// T2 (pin): an explicit boundary is never ratcheted, and replies
// at or below it are never reported, even after a live running
// event with a much larger stream seq.
func TestWaitRedesignT2ExplicitBoundaryNeverRatchets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 500, nil)),
			recordJSON(taskEv("completed", "R", "R", 501, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(9), asst(11, "completed", "new", nil)}),
		}}
		res := runRunner(t, Config{
			Timeout:     60 * time.Second,
			AfterSeq:    10,
			HasAfterSeq: true,
			Dial:        sub.dial,
			History:     hist,
		})
		if res.Kind != KindDone || res.ExitCode != 0 {
			t.Errorf("res = %+v", res)
		}
		if res.AfterSeq != 10 {
			t.Errorf("AfterSeq = %d, want 10 (ratchet must not move an explicit boundary)", res.AfterSeq)
		}
		if len(res.Replies) != 1 || res.Replies[0].Seq != 11 {
			t.Errorf("replies = %+v, want [11] only", res.Replies)
		}
		if hist.calls != 1 {
			t.Errorf("history calls = %d, want 1 (final read only, no derivation)", hist.calls)
		}
	})
}

// T3 (pin): an unknown boundary suppresses replies. Every
// derivation window fails; a root completed arrives with no
// prior running (settle-blocked); the final read finds a reply,
// but it must not be reported.
func TestWaitRedesignT3BoundaryUnknownSuppressesReplies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		resps := []historyResp{
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			historyOK([]any{userEv(100), asst(150, "completed", "stale?", nil)}),
		}
		hist := &queueHistory{resps: resps}
		res := runRunner(t, Config{
			Timeout: 60 * time.Second,
			Dial:    sub.dial,
			History: hist,
		})
		if res.Kind != KindTimeout || res.ExitCode != 124 {
			t.Errorf("res = %+v, want KindTimeout/124", res)
		}
		if len(res.Replies) != 0 {
			t.Errorf("replies = %+v, want none (boundary unknown)", res.Replies)
		}
		wantNote := "turn-end boundary unknown: history could not be read, so no replies are reported; run `castctl wait` again"
		if res.Note != wantNote {
			t.Errorf("note = %q, want %q", res.Note, wantNote)
		}
	})
}

// T4 (pin, approvals): a pending approval ends the wait as
// KindApproval / needs_approval / exit 4.
func TestWaitRedesignT4ApprovalEndsWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(approvalEv([]any{appr("A")}, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
		}}
		res := runRunner(t, Config{
			Timeout: 60 * time.Second,
			Dial:    sub.dial,
			History: hist,
		})
		if res.Kind != KindApproval || res.Outcome != "needs_approval" || res.ExitCode != 4 {
			t.Errorf("res = %+v", res)
		}
		if len(res.Approvals) != 1 {
			t.Errorf("approvals = %+v, want 1", res.Approvals)
		}
	})
}

// T4 (pin, needs-input): a Done turn whose LAST reply carries an
// unanswered widget is needs_input / exit 4.
func TestWaitRedesignT4NeedsInputWidget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		widget := map[string]any{"widget_id": "w1", "kind": "choice", "state": map[string]any{}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
			historyOK([]any{userEv(100), asst(150, "completed", "pick one", map[string]any{"widgets": []any{widget}})}),
		}}
		res := runRunner(t, Config{
			Timeout: 60 * time.Second,
			Dial:    sub.dial,
			History: hist,
		})
		if res.Kind != KindDone || res.Outcome != "needs_input" || res.ExitCode != 4 {
			t.Errorf("res = %+v", res)
		}
		if res.NeedsInputReason != "widget" {
			t.Errorf("NeedsInputReason = %q, want widget", res.NeedsInputReason)
		}
	})
}
