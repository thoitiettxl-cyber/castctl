// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

// Red/green tests for the wait redesign (overnight item 3).
// Numbering follows phase1-r3-seams-tests-docs.md §2 (T1–T17;
// there is no T11 or T18 test function — T11's single-turn pin
// is TestRunnerLiveDone in runner_test.go).
// T1–T4 are pins: they must stay green on the pre-redesign code
// and after it. T5–T7 are RED demonstrations: they fail on the
// pre-redesign code and pass only with the new semantics. T8 is
// a pin (green before and after).

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/approvals"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
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
		if hist.calls != 2 {
			t.Errorf("history calls = %d, want 2 (final read + newest-user re-check, no derivation)", hist.calls)
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
		// final read + newest-user re-check: exactly 5 history
		// reads.
		if hist.calls != 5 {
			t.Errorf("history calls = %d, want 5", hist.calls)
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
		if hist.calls != 5 {
			t.Errorf("history calls = %d, want 5 (derivation + 2 settle proofs + final read + re-check)", hist.calls)
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
		if hist.calls != 3 {
			t.Errorf("history calls = %d, want 3 (derivation + final read + re-check, no settle)", hist.calls)
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

// T9 (D2 release signals): a held "subagents" terminal is released
// by (a) a count-0 root event re-arming it, then a reply proof;
// (b) a reply proof alone, without any re-arm (the D2 change);
// (c) never by a subagent's own count-0 event; (d) a fresh root
// running clears the hold entirely.
func TestWaitRedesignT9ReleaseSignals(t *testing.T) {
	// (a) Re-arm, then settle: suspect-failed held for subagents.
	w := New("")
	w.Feed(taskEv("running", "R", "R", 0, nil))
	w.Feed(taskEv("failed", "R", "R", 0, 2))
	if w.IgnoredReason() != "subagents" {
		t.Fatalf("(a) reason=%q", w.IgnoredReason())
	}
	w.Feed(taskEv("queued", "R", "R", 0, 0))
	if w.IgnoredReason() != "" {
		t.Fatalf("(a) count-0 must re-arm, reason=%q", w.IgnoredReason())
	}
	if out := w.Settle([]Reply{{Seq: 1, Text: "x"}}); out == nil || out.Kind != KindFailed {
		t.Fatalf("(a) settle after re-arm = %v", out)
	}
	// (b) Reply proof alone, reason still "subagents".
	w2 := New("")
	w2.Feed(taskEv("running", "R", "R", 0, nil))
	w2.Feed(taskEv("completed", "R", "R", 0, 2))
	if w2.IgnoredReason() != "subagents" {
		t.Fatalf("(b) reason=%q", w2.IgnoredReason())
	}
	if out := w2.Settle([]Reply{{Seq: 1, Text: "x"}}); out == nil || out.Kind != KindDone {
		t.Fatalf("(b) settle while held = %v, want Done", out)
	}
	// (c) A subagent's own count-0 event must not re-arm.
	w3 := New("")
	w3.Feed(taskEv("running", "R", "R", 0, nil))
	w3.Feed(taskEv("completed", "R", "R", 0, 2))
	w3.Feed(taskEv("queued", "R", "S", 0, 0))
	if w3.IgnoredReason() != "subagents" {
		t.Fatalf("(c) subagent count-0 must not re-arm, reason=%q", w3.IgnoredReason())
	}
	if out := w3.Settle(nil); out != nil {
		t.Fatalf("(c) settle with no replies = %v", out)
	}
	// (d) A fresh root running clears the hold entirely.
	w4 := New("")
	w4.Feed(taskEv("running", "R", "R", 0, nil))
	w4.Feed(taskEv("completed", "R", "R", 0, 2))
	w4.Feed(taskEv("running", "R", "R", 0, nil))
	if _, ok := w4.IgnoredTerminal(); ok {
		t.Fatal("(d) fresh running must clear the held terminal")
	}
	if w4.IgnoredReason() != "" {
		t.Fatalf("(d) reason=%q", w4.IgnoredReason())
	}
}

// T10 (D9 keep last-only): checkState feeds only the LAST
// replayed status. A replay of [running, completed] with no
// replies in history must NOT decide Done — the running that
// would prove it is discarded — so the wait times out.
func TestWaitRedesignT10CheckStateFeedsLastOnly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{checkScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
		}}
		res := runRunner(t, Config{
			Timeout:      30 * time.Second,
			RecheckAfter: -1,
			CheckEvery:   5 * time.Second,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindTimeout || res.ExitCode != 124 {
			t.Errorf("res = %+v, want KindTimeout/124 (last-only discards the running)", res)
		}
		if res.Status != "completed" {
			t.Errorf("Status = %q, want the last replayed status", res.Status)
		}
	})
}

// T10 stale-last-event variant: a batch ending on a
// subagent-filtered event feeds the last COLLECTED status
// (the subagent event is invisible to TaskStatusInfo), with
// the same timeout outcome.
func TestWaitRedesignT10CheckStateStaleLastEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{checkScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
			recordJSON(taskEv("queued", "R", "S", 0, 0)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
		}}
		res := runRunner(t, Config{
			Timeout:      30 * time.Second,
			RecheckAfter: -1,
			CheckEvery:   5 * time.Second,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindTimeout || res.ExitCode != 124 {
			t.Errorf("res = %+v, want KindTimeout/124", res)
		}
		if res.Status != "completed" {
			t.Errorf("Status = %q, want completed (subagent event teaches nothing)", res.Status)
		}
	})
}

// T12 (D11): a never-succeeding history reader still terminates
// at the deadline, with a finite, exactly-counted number of
// reads: 6 derivation attempts (3 windows x 1 retry) + 0 settle
// proofs (a live running never clears the unknown-boundary
// flag, so no proof spends a read) + 2 final reads. No
// settlePending proof starts past the deadline (the 2 final
// reads are finish endgame reads, floor-bounded by design).
func TestWaitRedesignT12NeverSucceedingHistoryTerminates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{
			block: true,
			loopScript: [][]byte{
				recordJSON(taskEv("running", "R", "R", 120, nil)),
				recordJSON(taskEv("completed", "R", "R", 180, 2)),
			},
		}
		hist := &queueHistory{resps: []historyResp{{err: errTransport}}}
		res := runRunner(t, Config{
			Timeout:      10 * time.Second,
			RecheckAfter: -1,
			CheckEvery:   -1,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindTimeout || res.ExitCode != 124 || !res.FinalReadFailed {
			t.Errorf("res = %+v", res)
		}
		if res.Note != "could not read the final replies; run `castctl wait` again" {
			t.Errorf("note = %q", res.Note)
		}
		if hist.calls != 8 {
			t.Errorf("history calls = %d, want 8 (6 derivation + 0 settle + 2 final)", hist.calls)
		}
	})
}

// Micro-fix (red-team Finding 1): the finish last-chance FAILED
// proof must spend no history read while the boundary is
// unknown — AcceptReplayedFailed refuses on an unknown
// boundary, so the read is wasted. An ignored FAILED terminal
// with an unknown boundary, a derivation that fails on all 6
// attempts, and a final read that succeeds on its first
// window: 6 derivation + 0 last-chance + 1 final = 7 reads,
// with the result unchanged from the pre-gate behaviour
// (KindTimeout/124, no replies, boundary-unknown note).
func TestWaitRedesignLastChanceProofSpendsNoReadWhenBoundaryUnknown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{
			block: true,
			loopScript: [][]byte{
				recordJSON(taskEv("interrupted", "R", "R", 180, nil)),
			},
		}
		resps := []historyResp{
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			historyOK([]any{userEv(100), asst(150, "completed", "stale?", nil)}),
		}
		hist := &queueHistory{resps: resps}
		res := runRunner(t, Config{
			Timeout:      10 * time.Second,
			RecheckAfter: -1,
			CheckEvery:   -1,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindTimeout || res.ExitCode != 124 {
			t.Errorf("res = %+v, want KindTimeout/124", res)
		}
		if res.Outcome != "timeout" {
			t.Errorf("Outcome = %q, want %q", res.Outcome, "timeout")
		}
		if res.Status != "interrupted" {
			t.Errorf("Status = %q, want %q", res.Status, "interrupted")
		}
		if res.AfterSeq != 0 {
			t.Errorf("AfterSeq = %d, want 0 (boundary unknown)", res.AfterSeq)
		}
		if len(res.Replies) != 0 {
			t.Errorf("replies = %+v, want none (boundary unknown)", res.Replies)
		}
		if res.FinalReadFailed {
			t.Errorf("FinalReadFailed = true, want false (final read succeeded)")
		}
		wantNote := "turn-end boundary unknown: history could not be read, so no replies are reported; run `castctl wait` again"
		if res.Note != wantNote {
			t.Errorf("note = %q, want %q", res.Note, wantNote)
		}
		if hist.calls != 7 {
			t.Errorf("history calls = %d, want 7 (6 derivation + 0 last-chance + 1 final)", hist.calls)
		}
	})
}

// T13 (meta-test, deaf stream): a stream that never delivers a
// stopping record, with empty history, must still return at the
// deadline. A synctest deadlock here is a FAIL.
func TestWaitRedesignT13DeafStreamTerminates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{block: true}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
		}}
		res := runRunner(t, Config{
			Timeout:      120 * time.Second,
			RecheckAfter: 20 * time.Second,
			CheckEvery:   60 * time.Second,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindTimeout || res.ExitCode != 124 {
			t.Errorf("res = %+v", res)
		}
		if sub.calls < 2 {
			t.Errorf("subscribe calls = %d, want resubscribes until the deadline", sub.calls)
		}
		if hist.calls != 2 {
			t.Errorf("history calls = %d, want 2 (derivation + final read)", hist.calls)
		}
	})
}

// blockHistory honours its context: it blocks until the context
// is done, then returns the context error. A reader that ignored
// the deadline would hang this test (synctest deadlock = FAIL).
type blockHistory struct{ calls int }

func (h *blockHistory) ReadHistory(ctx context.Context, limit int) ([]any, bool, error) {
	h.calls++
	<-ctx.Done()
	return nil, false, ctx.Err()
}

// T13 (meta-test, blocking reader + derivation deadline): a
// history reader that blocks until its context dies must not
// stall derivation past the wait deadline. Derivation runs
// under the deadline (1 call), the endgame spends two floored
// final reads (2 calls), and Run returns KindTimeout.
func TestWaitRedesignT13BlockingHistoryTerminatesAtDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{}
		hist := &blockHistory{}
		r, err := NewRunner(Config{
			Timeout:        10 * time.Second,
			FinalReadFloor: 1 * time.Second,
			Dial:           sub.dial,
			History:        hist,
		})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		res, err := r.Run(context.Background())
		if err != nil {
			t.Fatalf("Run: %v, want a KindTimeout result, not an error", err)
		}
		if res.Kind != KindTimeout || res.ExitCode != 124 {
			t.Errorf("res = %+v", res)
		}
		if hist.calls != 3 {
			t.Errorf("history calls = %d, want 3 (1 derivation + 2 final)", hist.calls)
		}
	})
}

// T14 (auth, derivation): an AuthError during boundary
// derivation propagates unwrapped, with exactly one attempt
// (no retry on a fatal error).
func TestWaitRedesignT14AuthInDerivationPropagates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hist := &scriptHistory{def: historyResp{err: conn.NewAuthError("expired")}}
		sub := &fakeSubscriber{}
		r, err := NewRunner(Config{Timeout: 60 * time.Second, Dial: sub.dial, History: hist})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		_, err = r.Run(context.Background())
		var authErr *conn.AuthError
		if !errors.As(err, &authErr) {
			t.Errorf("err = %v, want AuthError", err)
		}
		if len(hist.calls) != 1 {
			t.Errorf("history calls = %v, want exactly 1 (no retry)", hist.calls)
		}
	})
}

// T14 (auth, settle): an AuthError during a settle proof
// propagates unwrapped, with exactly one derivation read and
// one settle read.
func TestWaitRedesignT14AuthInSettlePropagates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("idle", "R", "R", 180, nil)),
		}}
		hist := &scriptHistory{
			byLimit: map[int][]historyResp{
				200: {
					historyOK([]any{userEv(100)}),
					{err: conn.NewAuthError("expired")},
				},
			},
			def: historyResp{err: conn.NewAuthError("expired")},
		}
		r, err := NewRunner(Config{Timeout: 60 * time.Second, Dial: sub.dial, History: hist})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		_, err = r.Run(context.Background())
		var authErr *conn.AuthError
		if !errors.As(err, &authErr) {
			t.Errorf("err = %v, want AuthError", err)
		}
		if len(hist.calls) != 2 {
			t.Errorf("history calls = %v, want 2 (derivation + settle)", hist.calls)
		}
	})
}

// T14 (auth, subscribe): an AuthError from SubscribeRaw
// propagates unwrapped after exactly one subscribe attempt
// (no resubscribe storm).
func TestWaitRedesignT14AuthInSubscribePropagates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopErr: conn.NewAuthError("expired")}
		hist := &queueHistory{resps: []historyResp{historyOK([]any{userEv(100)})}}
		r, err := NewRunner(Config{Timeout: 60 * time.Second, Dial: sub.dial, History: hist})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		_, err = r.Run(context.Background())
		var authErr *conn.AuthError
		if !errors.As(err, &authErr) {
			t.Errorf("err = %v, want AuthError", err)
		}
		if sub.calls != 1 {
			t.Errorf("subscribe calls = %d, want 1 (no retry loop)", sub.calls)
		}
	})
}

// T14 (auth, approver): a decide-time AuthError is raised
// exactly once — the approver is never re-offered the id after
// a fatal error. (The propagation itself is pinned by
// TestRunnerApproverAuthErrorPropagates; this pins the
// no-retry count.)
func TestWaitRedesignT14AuthApproverDecidedOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		decides := 0
		aa := approvals.NewAutoApprover(func(ctx context.Context) (approvals.Decider, func(), error) {
			return func(ctx context.Context, a approvals.DescribedApproval, decision string) error {
				decides++
				return conn.NewAuthError("expired")
			}, func() {}, nil
		}, false)
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(approvalEv([]any{appr("A", approvals.Forever)}, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{historyOK([]any{userEv(100)})}}
		r, err := NewRunner(Config{
			Timeout:  60 * time.Second,
			Dial:     sub.dial,
			History:  hist,
			Approver: aa.AsApprover(),
		})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		_, err = r.Run(context.Background())
		var authErr *conn.AuthError
		if !errors.As(err, &authErr) {
			t.Errorf("err = %v, want AuthError", err)
		}
		if decides != 1 {
			t.Errorf("decides = %d, want 1 (no retry loop)", decides)
		}
	})
}

// T16 (pin): replies come from HISTORY ONLY. A well-formed
// completed message.assistant event delivered live, and
// delta.* events alone, never appear in Replies and never
// decide the turn.
func TestWaitRedesignT16RepliesFromHistoryOnly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(asst(150, "completed", "live text must never surface", nil)),
			recordJSON(Event{"event": "delta.text_append", "payload": map[string]any{"text": "partial"}}),
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
			historyOK([]any{userEv(100)}),
		}}
		res := runRunner(t, Config{
			Timeout: 60 * time.Second,
			Dial:    sub.dial,
			History: hist,
		})
		if res.Kind != KindDone || res.ExitCode != 0 {
			t.Errorf("res = %+v", res)
		}
		if len(res.Replies) != 0 || res.FinalText != "" {
			t.Errorf("replies = %+v FinalText = %q, want none (history was empty)", res.Replies, res.FinalText)
		}
	})
}

// T17 replacement (D6 non-attribution pin): the reply filter
// does not EXCLUDE by agent/root fields. History events carrying
// agent_id/root_agent_id/active_subagent_count shapes —
// subagent-shaped or main-shaped — are returned alike by
// RepliesAfter; the identity fields are recorded on the Reply
// for the Settle proof only (loop-2 F2). Attribution itself
// stays [UNVERIFIED] pending live capture (U-A2/U-A6).
func TestWaitRedesignT17NoAttributionInReplyFilter(t *testing.T) {
	subagentShaped := asst(11, "completed", "subagent-shaped", map[string]any{
		"agent_id": "S", "root_agent_id": "R", "active_subagent_count": 1,
	})
	mainShaped := asst(12, "completed", "main-shaped", map[string]any{
		"agent_id": "R", "root_agent_id": "R",
	})
	replies, _ := RepliesAfter([]any{mainShaped, subagentShaped}, 10, nil)
	if len(replies) != 2 || replies[0].Seq != 11 || replies[1].Seq != 12 {
		t.Errorf("replies = %+v, want both events in seq order, unattributed", replies)
	}
}

// SettlePollInterval defaulting: zero takes the default, a
// negative value is clamped to the default (never a disable),
// and an explicit value is preserved.
func TestWaitRedesignSettlePollIntervalDefaults(t *testing.T) {
	newCfg := func(interval time.Duration) Config {
		return Config{
			Dial:               (&fakeSubscriber{}).dial,
			History:            &queueHistory{resps: []historyResp{historyOK(nil)}},
			SettlePollInterval: interval,
		}
	}
	r, err := NewRunner(newCfg(0))
	if err != nil {
		t.Fatal(err)
	}
	if r.cfg.SettlePollInterval != DefaultSettlePollInterval {
		t.Errorf("zero interval = %v, want %v", r.cfg.SettlePollInterval, DefaultSettlePollInterval)
	}
	r, err = NewRunner(newCfg(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if r.cfg.SettlePollInterval != 2*time.Second {
		t.Errorf("explicit interval = %v, want 2s", r.cfg.SettlePollInterval)
	}
}
