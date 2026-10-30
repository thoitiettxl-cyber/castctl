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

// T5 (RED): held terminal, quiet stream, late reply — the reported
// bug. A root completed held for subagents, no further stream event,
// and the reply lands in history after the first settle proof.
// Required: KindDone / exit 0 / replies [11], decided by a
// history re-poll, without any count-0 event or server replay.
func TestWaitRedesignT5HeldTerminalQuietStreamLateReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{
			block: true,
			loopScript: [][]byte{
				recordJSON(taskEv("running", "R", "R", 120, nil)),
				recordJSON(taskEv("completed", "R", "R", 180, 2)),
			},
		}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(10)}),
			historyOK([]any{userEv(10)}),
			historyOK([]any{userEv(10), asst(11, "completed", "main's reply", nil)}),
		}}
		res := runRunner(t, Config{
			Timeout:      600 * time.Second,
			RecheckAfter: 20 * time.Second,
			CheckEvery:   60 * time.Second,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindDone || res.Outcome != "done" || res.ExitCode != 0 {
			t.Errorf("res = %+v, want KindDone/done/0", res)
		}
		if len(res.Replies) != 1 || res.Replies[0].Seq != 11 || res.FinalText != "main's reply" {
			t.Errorf("res = %+v, want reply [11]", res)
		}
		// Derivation + first (empty) settle + re-poll settle +
		// final read: exactly 4 history reads.
		if hist.calls != 4 {
			t.Errorf("history calls = %d, want 4", hist.calls)
		}
	})
}

// T6 (RED): suspect terminal, reply lands after a too-early
// settle, no new stream record. Required: the re-poll finds the
// reply and decides KindDone within the stated bound, with the
// history-read count asserted.
func TestWaitRedesignT6SuspectTerminalLateReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{
			block: true,
			loopScript: [][]byte{
				recordJSON(taskEv("running", "R", "R", 120, nil)),
				recordJSON(taskEv("idle", "R", "R", 180, nil)),
			},
		}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(10)}),
			historyOK([]any{userEv(10)}),
			historyOK([]any{userEv(10), asst(11, "completed", "late reply", nil)}),
		}}
		res := runRunner(t, Config{
			Timeout:      600 * time.Second,
			RecheckAfter: 20 * time.Second,
			CheckEvery:   60 * time.Second,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindDone || res.ExitCode != 0 {
			t.Errorf("res = %+v, want KindDone/0", res)
		}
		if len(res.Replies) != 1 || res.Replies[0].Seq != 11 {
			t.Errorf("res = %+v, want reply [11]", res)
		}
		if hist.calls != 4 {
			t.Errorf("history calls = %d, want 4 (derivation + 2 settle proofs + final read)", hist.calls)
		}
	})
}

// T7 (RED, documented-limit branch): history window exhaustion.
// The reply sits older than the largest window's oldest event, so
// no window ever contains it. Required: the loss is VISIBLE —
// the final read reports exhaustion in the result note instead
// of silently exiting 0 with no replies and no note.
func TestWaitRedesignT7WindowExhaustionIsVisible(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		// Every window is exhausted (has_more) and holds only
		// user events: the reply at an older seq never appears
		// in any window, so the final read finds no replies.
		window := func() historyResp {
			return historyResp{events: []any{
				userEv(50),
				userEv(30),
			}, hasMore: true}
		}
		hist := &scriptHistory{
			byLimit: map[int][]historyResp{
				200:  {window()},
				500:  {window()},
				1000: {window()},
			},
			def: window(),
		}
		res := runRunner(t, Config{
			Timeout:       60 * time.Second,
			AfterSeq:      10,
			HasAfterSeq:   true,
			HistoryLimits: []int{200, 500, 1000},
			Dial:          sub.dial,
			History:       hist,
		})
		if res.Kind != KindDone || res.ExitCode != 0 {
			t.Errorf("res = %+v, want KindDone/0 (the terminal itself is proven)", res)
		}
		if len(res.Replies) != 0 {
			t.Errorf("replies = %+v, want none (reply is beyond the window)", res.Replies)
		}
		wantNote := "history window exhausted at 1000 events; older replies may be missed; run `castctl wait` again"
		if res.Note != wantNote {
			t.Errorf("note = %q, want %q", res.Note, wantNote)
		}
	})
}

// T8 (pin, D1 first form): an absent active_subagent_count still
// decides Done directly, and the final read collects both replies
// that are already in history at decision time. Replies landing
// after the final read are out of scope for this turn (stated
// limit, not a silent claim).
func TestWaitRedesignT8AbsentCountDecidesDirectly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(10)}),
			historyOK([]any{
				userEv(10),
				asst(11, "completed", "subagent work", nil),
				asst(12, "completed", "main's reply", nil),
			}),
		}}
		res := runRunner(t, Config{
			Timeout: 60 * time.Second,
			Dial:    sub.dial,
			History: hist,
		})
		if res.Kind != KindDone || res.ExitCode != 0 {
			t.Errorf("res = %+v, want KindDone/0", res)
		}
		if len(res.Replies) != 2 || res.Replies[0].Seq != 11 || res.Replies[1].Seq != 12 {
			t.Errorf("replies = %+v, want [11 12]", res.Replies)
		}
		if res.FinalText != "main's reply" {
			t.Errorf("FinalText = %q", res.FinalText)
		}
		if hist.calls != 2 {
			t.Errorf("history calls = %d, want 2 (derivation + final read, no settle)", hist.calls)
		}
	})
}

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
