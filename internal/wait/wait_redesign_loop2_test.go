// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

// Loop-2 regression tests for the wait redesign (overnight item 3).
// Each test pins one proven loop-1 defect (F1–F10 in the loop-1
// review verdicts) and was written RED against the loop-1 head
// before the fix. Shapes are named after the red-team probes
// (RT1–RT15) they reproduce.

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

const loop2BoundaryNote = "turn-end boundary unknown: history could not be read, so no replies are reported; run `castctl wait` again"

// F1 / RT1: derivation fails, then a live root running carries a
// stream seq. The stream seq must never become the history
// boundary: the reply at history seq 42 (below the stream seq
// 120) must not be silently dropped, and the boundary must stay
// unknown.
func TestLoop2StreamSeqNeverBecomesBoundary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			historyOK([]any{userEv(10), asst(42, "completed", "reply", nil)}),
		}}
		res := runRunner(t, Config{
			Timeout: 60 * time.Second,
			Dial:    sub.dial,
			History: hist,
		})
		if res.AfterSeq != 0 {
			t.Errorf("AfterSeq = %d, want 0 (a stream seq must never be installed as the history boundary)", res.AfterSeq)
		}
		if len(res.Replies) != 0 {
			t.Errorf("replies = %+v, want none (boundary unknown suppresses replies)", res.Replies)
		}
		if res.Note != loop2BoundaryNote {
			t.Errorf("note = %q, want the boundary-unknown note", res.Note)
		}
	})
}

// F1 / RT2: a root running with NO seq must not clear the
// unknown-boundary flag either: with the boundary stuck at 0,
// an ancient reply must not be reported as this turn's.
func TestLoop2SeqLessRunningDoesNotClearUnknownBoundary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 0, nil)),
			recordJSON(taskEv("completed", "R", "R", 0, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			historyOK([]any{userEv(10), asst(6, "completed", "ancient", nil)}),
		}}
		res := runRunner(t, Config{
			Timeout: 60 * time.Second,
			Dial:    sub.dial,
			History: hist,
		})
		if len(res.Replies) != 0 {
			t.Errorf("replies = %+v, want none (no boundary, no lookback from 0)", res.Replies)
		}
		if res.Note != loop2BoundaryNote {
			t.Errorf("note = %q, want the boundary-unknown note", res.Note)
		}
	})
}

// F1 / RT1b: a suspect terminal after a running event must not
// bypass boundary-unknown suppression via the running event:
// the outcome stays KindTimeout with the boundary note, not an
// empty note.
func TestLoop2SuspectTerminalKeepsUnknownBoundary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("idle", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			historyOK([]any{userEv(10), asst(42, "completed", "reply", nil)}),
		}}
		res := runRunner(t, Config{
			Timeout:      5 * time.Second,
			RecheckAfter: -1,
			CheckEvery:   -1,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindTimeout || res.ExitCode != 124 {
			t.Errorf("res = %+v, want KindTimeout/124", res)
		}
		if len(res.Replies) != 0 {
			t.Errorf("replies = %+v, want none", res.Replies)
		}
		if res.Note != loop2BoundaryNote {
			t.Errorf("note = %q, want the boundary-unknown note", res.Note)
		}
	})
}

// F2 / RT3 (Waiter level): a reply identifiably shaped as a
// subagent's (agent_id != root_agent_id, both present) must not
// release a subagents hold on its own. An unattributed or
// root-confirmed reply still releases it.
func TestLoop2SettleRefusesSubagentShapedReply(t *testing.T) {
	subagentShaped, _ := RepliesAfter([]any{asst(11, "completed", "subagent-only text", map[string]any{
		"agent_id": "S", "root_agent_id": "R",
	})}, 10, nil)
	if len(subagentShaped) != 1 {
		t.Fatalf("subagent-shaped filter = %+v, want 1 reply", subagentShaped)
	}
	mk := func() *Waiter {
		w := New("")
		w.Feed(taskEv("running", "R", "R", 0, nil))
		w.Feed(taskEv("completed", "R", "R", 0, 2))
		return w
	}
	if out := mk().Settle(subagentShaped); out != nil {
		t.Errorf("Settle(subagent-shaped only) = %v, want nil (no release)", out)
	}
	mixed, _ := RepliesAfter([]any{
		asst(11, "completed", "subagent-only text", map[string]any{"agent_id": "S", "root_agent_id": "R"}),
		asst(12, "completed", "main reply", nil),
	}, 10, nil)
	if out := mk().Settle(mixed); out == nil || out.Kind != KindDone {
		t.Errorf("Settle(mixed) = %v, want Done (the unattributed reply is proof)", out)
	}
	rootShaped, _ := RepliesAfter([]any{asst(11, "completed", "main reply", map[string]any{
		"agent_id": "R", "root_agent_id": "R",
	})}, 10, nil)
	if out := mk().Settle(rootShaped); out == nil || out.Kind != KindDone {
		t.Errorf("Settle(root-confirmed) = %v, want Done", out)
	}
}

// F2 / RT3 (Runner level): explicit boundary 10, completed held
// with active_subagent_count=2, no count-0 event ever arrives,
// history holds exactly one completed event shaped as a
// subagent's. The hold must NOT release as Done.
func TestLoop2SubagentShapedReplyDoesNotReleaseHold(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{
			block: true,
			loopScript: [][]byte{
				recordJSON(taskEv("running", "R", "R", 120, nil)),
				recordJSON(taskEv("completed", "R", "R", 180, 2)),
			},
		}
		proof := historyOK([]any{userEv(10), asst(11, "completed", "subagent-only text", map[string]any{
			"agent_id": "S", "root_agent_id": "R",
		})})
		hist := &queueHistory{resps: []historyResp{proof, proof}}
		res := runRunner(t, Config{
			Timeout:      5 * time.Second,
			RecheckAfter: -1,
			CheckEvery:   -1,
			AfterSeq:     10,
			HasAfterSeq:  true,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindTimeout || res.ExitCode != 124 {
			t.Errorf("res = %+v, want KindTimeout/124 (subagent-shaped proof must not release the hold)", res)
		}
	})
}

// F3 / RT5: the reply that decided the turn via a settle proof
// must survive a final read that no longer contains it —
// reported, with a note saying so — never silently dropped.
func TestLoop2ProofReplySurvivesVanishingFinalRead(t *testing.T) {
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
			historyOK([]any{userEv(10), asst(11, "completed", "proof reply", nil)}),
			historyOK([]any{userEv(10)}),
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
		if len(res.Replies) != 1 || res.Replies[0].Seq != 11 || res.FinalText != "proof reply" {
			t.Errorf("res = %+v, want the proof reply [11] reported", res)
		}
		wantNote := "final read missed the settle proof reply; reporting the proof reply"
		if res.Note != wantNote {
			t.Errorf("note = %q, want %q", res.Note, wantNote)
		}
	})
}

// F4 / RT15b: a follow-up turn's reply in the final read must
// not be returned as this turn's. The final read holds this
// turn's reply (11), a newer user message (20), and the
// follow-up reply (21): only 11 is this turn's.
func TestLoop2FollowUpTurnReplyExcluded(t *testing.T) {
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
			historyOK([]any{userEv(10), asst(11, "completed", "this turn", nil)}),
			historyOK([]any{userEv(10), asst(11, "completed", "this turn", nil), userEv(20), asst(21, "completed", "FOLLOWUP", nil)}),
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
		if len(res.Replies) != 1 || res.Replies[0].Seq != 11 || res.FinalText != "this turn" {
			t.Errorf("res = %+v, want only reply [11]", res)
		}
		wantNote := "replies after a newer user message were excluded"
		if res.Note != wantNote {
			t.Errorf("note = %q, want %q", res.Note, wantNote)
		}
	})
}

// F5 / RT4a: an AuthError on the first lag-window poll must
// propagate as an error (exit 2 at the CLI boundary), never as
// a silent Done/0.
func TestLoop2LagWindowAuthErrorPropagates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
			historyOK([]any{userEv(100)}),
			{err: conn.NewAuthError("expired")},
		}}
		r, err := NewRunner(Config{Timeout: 60 * time.Second, Dial: sub.dial, History: hist})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		_, err = r.Run(context.Background())
		var authErr *conn.AuthError
		if !errors.As(err, &authErr) {
			t.Errorf("Run err = %v, want AuthError (lag-window auth must not become Done/0)", err)
		}
	})
}

// F5 / RT4b: one transient lag-poll failure must not kill the
// window: the reply on the next poll is still caught.
func TestLoop2LagWindowRetriesTransientError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
			historyOK([]any{userEv(100)}),
			{err: errTransport},
			historyOK([]any{userEv(100), asst(190, "completed", "late reply", nil)}),
		}}
		res := runRunner(t, Config{
			Timeout:   60 * time.Second,
			LagWindow: 2 * time.Second,
			LagPoll:   250 * time.Millisecond,
			Dial:      sub.dial,
			History:   hist,
		})
		if res.Kind != KindDone || res.ExitCode != 0 || res.FinalText != "late reply" {
			t.Errorf("res = %+v, want KindDone/0 with the late reply", res)
		}
	})
}

// F6 / RT7a: an explicit boundary accepts a replayed FAILED
// terminal exactly like a derived one (parity): same evidence,
// same outcome.
func TestLoop2ExplicitBoundaryAcceptsReplayedFailed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("interrupted", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(200)}),
		}}
		res := runRunner(t, Config{
			Timeout:     5 * time.Second,
			HasAfterSeq: true,
			AfterSeq:    200,
			Dial:        sub.dial,
			History:     hist,
		})
		if res.Kind != KindFailed || res.ExitCode != 2 {
			t.Errorf("explicit boundary + replayed failed = %+v, want KindFailed/2", res)
		}
	})
}

// F6 / RT8: an interrupted terminal held for "subagents" has a
// settle path via the replayed-failed proof (no newer user
// message): it must end KindFailed, not stall to the deadline.
func TestLoop2InterruptedHeldForSubagentsSettlesFailed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("interrupted", "R", "R", 180, 2)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(200)}),
		}}
		res := runRunner(t, Config{
			Timeout:     5 * time.Second,
			HasAfterSeq: true,
			AfterSeq:    200,
			Dial:        sub.dial,
			History:     hist,
		})
		if res.Kind != KindFailed || res.ExitCode != 2 {
			t.Errorf("interrupted held for subagents = %+v, want KindFailed/2", res)
		}
	})
}

// F6 (Waiter level): AcceptReplayedFailed parity — explicit
// boundaries and "subagents" reasons accept on the same
// user-seq equality proof; missing_root still refuses.
func TestLoop2AcceptReplayedFailedParity(t *testing.T) {
	seq := func(n int64) *int64 { return &n }
	// Explicit boundary accepts.
	w := New("")
	w.Feed(taskEv("interrupted", "R", "R", 0, nil))
	w.SetBoundary(200, false, false)
	if out := w.AcceptReplayedFailed(seq(200)); out == nil || out.Kind != KindFailed {
		t.Errorf("explicit boundary accept = %v, want KindFailed", out)
	}
	// Subagents reason accepts.
	w2 := New("")
	w2.Feed(taskEv("interrupted", "R", "R", 0, 2))
	w2.SetBoundary(200, false, true)
	if out := w2.AcceptReplayedFailed(seq(200)); out == nil || out.Kind != KindFailed {
		t.Errorf("subagents reason accept = %v, want KindFailed", out)
	}
	// Missing root still refuses.
	w3 := New("")
	w3.Feed(taskEv("interrupted", "", "S", 0, nil))
	w3.SetBoundary(200, false, true)
	if out := w3.AcceptReplayedFailed(seq(200)); out != nil {
		t.Errorf("missing_root accept = %v, want nil", out)
	}
}

// F7 / RT9a: a later EMPTY window must not discard the reply a
// previous window proved.
func TestLoop2HistoryRepliesRetainsEarlierWindowOnEmptyLater(t *testing.T) {
	h := &scriptHistory{byLimit: map[int][]historyResp{
		200: {{events: []any{userEv(50), asst(55, "completed", "reply", nil)}, hasMore: true}},
		500: {{events: []any{}, hasMore: false}},
	}}
	replies, exhausted, err := HistoryReplies(context.Background(), h, []int{200, 500}, 10)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if exhausted {
		t.Error("exhausted must be false (windows closed)")
	}
	if len(replies) != 1 || replies[0].Seq != 55 {
		t.Errorf("replies = %+v, want [55] retained from the earlier window", replies)
	}
}

// F7 / RT9b: a later empty window must not discard the max seq
// seen earlier in derivation.
func TestLoop2DeriveBoundaryRetainsSeenMaxOnEmptyLater(t *testing.T) {
	h := &scriptHistory{byLimit: map[int][]historyResp{
		200: {{events: []any{asst(30, "completed", "a", nil)}, hasMore: true}},
		500: {{events: []any{}, hasMore: false}},
	}}
	seq, known, _, err := DeriveBoundary(context.Background(), h, []int{200, 500})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if seq != 30 || !known {
		t.Errorf("DeriveBoundary = (%d, %v), want (30, true) retaining the seen max", seq, known)
	}
}

// F7 / RT9c: replies accumulate across shifting windows: a reply
// seen in an earlier window is reported even when a later
// non-empty window's slice does not contain it.
func TestLoop2HistoryRepliesAccumulatesAcrossShiftingWindows(t *testing.T) {
	h := &scriptHistory{byLimit: map[int][]historyResp{
		200: {{events: []any{asst(55, "completed", "reply", nil)}, hasMore: true}},
		500: {{events: []any{userEv(50)}, hasMore: false}},
	}}
	replies, _, err := HistoryReplies(context.Background(), h, []int{200, 500}, 10)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(replies) != 1 || replies[0].Seq != 55 {
		t.Errorf("replies = %+v, want [55] accumulated across windows", replies)
	}
}

// F7 / RT10a: an empty FIRST window with has_more must not end
// derivation; the larger window is read.
func TestLoop2DeriveBoundaryReadsPastEmptyFirstWindow(t *testing.T) {
	h := &scriptHistory{byLimit: map[int][]historyResp{
		200: {{events: []any{}, hasMore: true}},
		500: {{events: []any{userEv(77)}, hasMore: false}},
	}}
	seq, known, _, err := DeriveBoundary(context.Background(), h, []int{200, 500})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if seq != 77 || !known {
		t.Errorf("DeriveBoundary = (%d, %v), want (77, true)", seq, known)
	}
}

// F7 / RT10b: an empty FIRST window with has_more must not end
// reply collection; the larger window is read.
func TestLoop2HistoryRepliesReadsPastEmptyFirstWindow(t *testing.T) {
	h := &scriptHistory{byLimit: map[int][]historyResp{
		200: {{events: []any{}, hasMore: true}},
		500: {{events: []any{asst(55, "completed", "reply", nil)}, hasMore: false}},
	}}
	replies, _, err := HistoryReplies(context.Background(), h, []int{200, 500}, 10)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(replies) != 1 || replies[0].Seq != 55 {
		t.Errorf("replies = %+v, want [55] from the larger window", replies)
	}
}

// F7 (same family, LatestUserSeq): an empty first window with
// has_more must not end the newest-user search.
func TestLoop2LatestUserSeqReadsPastEmptyFirstWindow(t *testing.T) {
	h := &scriptHistory{byLimit: map[int][]historyResp{
		200: {{events: []any{}, hasMore: true}},
		500: {{events: []any{userEv(77)}, hasMore: false}},
	}}
	seq, found, err := LatestUserSeq(context.Background(), h, []int{200, 500}, 10)
	if err != nil || !found || seq != 77 {
		t.Errorf("LatestUserSeq = (%d, %v, %v), want (77, true, nil)", seq, found, err)
	}
}

// F8 / RT6: flapping terminals inside one batch must not storm
// history: proofs are interval-gated, so a 12s wait with a 5s
// interval spends at most a handful of reads.
func TestLoop2FlappingTerminalsDoNotStormHistory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := [][]byte{recordJSON(taskEv("running", "R", "R", 120, nil))}
		for i := 0; i < 3; i++ {
			script = append(script,
				recordJSON(taskEv("completed", "R", "R", 180, 2)),
				recordJSON(taskEv("idle", "R", "R", 181, nil)),
			)
		}
		sub := &fakeSubscriber{loopScript: script}
		hist := &scriptHistory{def: historyResp{events: []any{userEv(10)}, hasMore: false}}
		res := runRunner(t, Config{
			Timeout:      12 * time.Second,
			RecheckAfter: -1,
			CheckEvery:   -1,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindTimeout {
			t.Errorf("res = %+v, want KindTimeout", res)
		}
		if got := len(hist.calls); got > 6 {
			t.Errorf("history reads = %d windows, want <= 6 (interval-gated proofs)", got)
		}
	})
}

// F8 / RT6b: 20 records against an always-failing reader must
// not prove once per record: the failure does not re-arm the
// throttle, and the interval gate bounds retries.
func TestLoop2FailingReaderDoesNotStormHistory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, 2)),
		}
		for i := 0; i < 18; i++ {
			script = append(script, recordJSON(taskEv("idle", "R", "R", 181, nil)))
		}
		sub := &fakeSubscriber{loopScript: script}
		hist := &queueHistory{resps: []historyResp{{err: errTransport}}}
		res := runRunner(t, Config{
			Timeout:      5 * time.Second,
			RecheckAfter: -1,
			CheckEvery:   -1,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindTimeout {
			t.Errorf("res = %+v, want KindTimeout", res)
		}
		if hist.calls > 10 {
			t.Errorf("history calls = %d, want <= 10 (6 derivation + 1 gated proof + 2 final + slack)", hist.calls)
		}
	})
}

// F8/N3: a positive SettlePollInterval below the per-read floor
// is clamped up to the floor (100ms): a 1ns cadence must not
// disable the interval gate.
func TestLoop2SettlePollIntervalMinimumClamp(t *testing.T) {
	for _, interval := range []time.Duration{time.Nanosecond, 50 * time.Millisecond} {
		r, err := NewRunner(Config{
			Dial:               (&fakeSubscriber{}).dial,
			History:            &queueHistory{resps: []historyResp{historyOK(nil)}},
			SettlePollInterval: interval,
		})
		if err != nil {
			t.Fatal(err)
		}
		if r.cfg.SettlePollInterval != 100*time.Millisecond {
			t.Errorf("interval %v clamped to %v, want 100ms", interval, r.cfg.SettlePollInterval)
		}
	}
	r, err := NewRunner(Config{
		Dial:               (&fakeSubscriber{}).dial,
		History:            &queueHistory{resps: []historyResp{historyOK(nil)}},
		SettlePollInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.cfg.SettlePollInterval != 200*time.Millisecond {
		t.Errorf("interval 200ms = %v, want 200ms preserved", r.cfg.SettlePollInterval)
	}
}

// F9 / RT11a: settlePending must not start a proof past the
// deadline: with the deadline already dead, no history read is
// spent.
func TestLoop2SettlePendingDoesNotStartPastDeadline(t *testing.T) {
	sub := &fakeSubscriber{}
	hist := &queueHistory{resps: []historyResp{historyOK([]any{userEv(10), asst(11, "completed", "x", nil)})}}
	r, err := NewRunner(Config{Timeout: 60 * time.Second, Dial: sub.dial, History: hist})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	r.waiter.Feed(taskEv("running", "R", "R", 120, nil))
	r.waiter.Feed(taskEv("idle", "R", "R", 180, nil))
	r.waiter.SetBoundary(10, false, false)
	r.afterSeq = 10
	r.deadline = r.clock.Now().Add(-time.Second)
	if err := r.settlePending(context.Background(), "idle"); err != nil {
		t.Errorf("settlePending past deadline err = %v, want nil (no proof started)", err)
	}
	if hist.calls != 0 {
		t.Errorf("history calls = %d, want 0 (no settlePending proof starts past the deadline)", hist.calls)
	}
}

// F9 / RT11b: checkState must not dial past the deadline: the
// noteFailure path reaches it unguarded, so the guard lives in
// checkState itself.
func TestLoop2CheckStateDoesNotStartPastDeadline(t *testing.T) {
	dials := 0
	sub := &fakeSubscriber{}
	dial := func(ctx context.Context) (Subscriber, error) {
		dials++
		return sub, nil
	}
	hist := &queueHistory{resps: []historyResp{historyOK([]any{userEv(10)})}}
	r, err := NewRunner(Config{Timeout: 60 * time.Second, Dial: dial, History: hist})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	r.deadline = r.clock.Now().Add(-time.Second)
	if err := r.checkState(context.Background()); err != nil {
		t.Errorf("checkState past deadline err = %v, want nil", err)
	}
	if dials != 0 {
		t.Errorf("dials = %d, want 0 (no state check starts past the deadline)", dials)
	}
}

// F10 / RT13c (UserAck level): an empty sent text is an empty
// needle and must never ack any user event.
func TestLoop2UserAckEmptyTextNeverAcks(t *testing.T) {
	empty := ""
	events := []any{
		map[string]any{"event_name": "message.user", "seq": int64(5), "payload": map[string]any{"display_text": "hello"}},
	}
	if seq, ok := UserAck(events, 0, &empty); ok {
		t.Errorf("UserAck(empty needle) = (%d, true), want no ack", seq)
	}
	blank := "   "
	if seq, ok := UserAck(events, 0, &blank); ok {
		t.Errorf("UserAck(whitespace needle) = (%d, true), want no ack", seq)
	}
}
