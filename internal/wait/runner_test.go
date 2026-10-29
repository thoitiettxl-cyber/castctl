// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/approvals"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// recordJSON encodes one event as an NDJSON record line.
func recordJSON(ev Event) []byte {
	b, err := json.Marshal(ev)
	if err != nil {
		panic(err)
	}
	return b
}

// fakeSubscriber scripts SubscribeRaw by call: loop subscribes
// (MaxRecords huge) get loopScript records; state checks
// (MaxRecords 50) get checkScript records. When block is set, a
// loop subscribe with no stopping record polls ShouldStop until
// it fires, exercising the watchdog / online-grace paths.
type fakeSubscriber struct {
	loopScript  [][]byte
	checkScript [][]byte
	block       bool
	dialErr     error
	loopErr     error
	calls       int
	checkCalls  int
	closed      int
}

func (f *fakeSubscriber) SubscribeRaw(ctx context.Context, method string, opts conn.SubscribeOptions) ([][]byte, error) {
	if opts.MaxRecords == 50 {
		f.checkCalls++
		for _, rec := range f.checkScript {
			if opts.OnRecord != nil && opts.OnRecord(rec) {
				break
			}
		}
		return nil, nil
	}
	f.calls++
	if f.loopErr != nil {
		err := f.loopErr
		f.loopErr = nil
		return nil, err
	}
	script := f.loopScript
	f.loopScript = nil
	var out [][]byte
	for _, rec := range script {
		out = append(out, rec)
		if opts.OnRecord != nil && opts.OnRecord(rec) {
			return out, nil
		}
	}
	if f.block {
		for {
			if opts.ShouldStop != nil && opts.ShouldStop() {
				return out, nil
			}
			select {
			case <-ctx.Done():
				return out, ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	return out, nil
}

func (f *fakeSubscriber) Close() error {
	f.closed++
	return nil
}

func (f *fakeSubscriber) dial(ctx context.Context) (Subscriber, error) {
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	return f, nil
}

// queueHistory serves scripted history responses in call order,
// then repeats the last one.
type queueHistory struct {
	resps []historyResp
	calls int
}

func (h *queueHistory) ReadHistory(ctx context.Context, limit int) ([]any, bool, error) {
	h.calls++
	i := h.calls - 1
	if i >= len(h.resps) {
		i = len(h.resps) - 1
	}
	r := h.resps[i]
	return r.events, r.hasMore, r.err
}

func historyOK(events []any) historyResp {
	return historyResp{events: events, hasMore: false}
}

func runRunner(t *testing.T, cfg Config) *Result {
	t.Helper()
	r, err := NewRunner(cfg)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

func TestRunnerLiveDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
			historyOK([]any{userEv(100), asst(150, "completed", "done", nil)}),
		}}
		res := runRunner(t, Config{
			Timeout:      60 * time.Second,
			NodeID:       "node-1",
			Dial:         sub.dial,
			History:      hist,
			Approver:     nil,
			RecheckAfter: 20 * time.Second,
		})
		if res.Kind != KindDone || res.Outcome != "done" || res.ExitCode != 0 {
			t.Errorf("res = %+v", res)
		}
		if res.FinalText != "done" || len(res.Replies) != 1 || res.AfterSeq != 100 || res.NodeID != "node-1" {
			t.Errorf("res = %+v", res)
		}
		if sub.closed != 1 {
			t.Errorf("closed = %d, want 1 (one subscribe, closed after use)", sub.closed)
		}
	})
}

func TestRunnerReplaySettle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
			historyOK([]any{userEv(100), asst(150, "completed", "settled reply", nil)}),
			historyOK([]any{userEv(100), asst(150, "completed", "settled reply", nil)}),
		}}
		res := runRunner(t, Config{Timeout: 60 * time.Second, Dial: sub.dial, History: hist})
		if res.Kind != KindDone || res.ExitCode != 0 || res.FinalText != "settled reply" {
			t.Errorf("res = %+v", res)
		}
	})
}

func TestRunnerReplayFailedAccept(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("interrupted", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(200)}),
			historyOK([]any{userEv(200)}),
			historyOK([]any{userEv(200)}),
		}}
		res := runRunner(t, Config{Timeout: 60 * time.Second, Dial: sub.dial, History: hist})
		if res.Kind != KindFailed || res.Outcome != "failed" || res.ExitCode != 2 {
			t.Errorf("res = %+v", res)
		}
		if len(res.Replies) != 0 {
			t.Errorf("cancelled turn must exit with 0 replies, got %+v", res.Replies)
		}
	})
}

func TestRunnerTimeout124(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
			historyOK([]any{userEv(100)}),
		}}
		res := runRunner(t, Config{Timeout: 5 * time.Second, Dial: sub.dial, History: hist})
		if res.Kind != KindTimeout || res.ExitCode != 124 || res.Outcome != "timeout" {
			t.Errorf("res = %+v", res)
		}
		if sub.calls < 2 {
			t.Errorf("subscribe calls = %d, want resubscribes until the deadline", sub.calls)
		}
	})
}

func TestRunnerFailClosed124(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
			{err: errTransport},
			{err: errTransport},
		}}
		res := runRunner(t, Config{Timeout: 60 * time.Second, Dial: sub.dial, History: hist})
		if res.Kind != KindTimeout || res.ExitCode != 124 || !res.FinalReadFailed {
			t.Errorf("res = %+v", res)
		}
		if res.Note != "could not read the final replies; run `muse-cli wait` again" {
			t.Errorf("note = %q", res.Note)
		}
	})
}

func TestRunnerBoundaryUnknownSuppressesReplies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Derive fails on every window (6 attempts: 3 windows x
		// 2), then the final read succeeds. The approval result
		// keeps its kind; replies are suppressed with the
		// boundary note.
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(approvalEv([]any{appr("A")}, nil)),
		}}
		resps := []historyResp{
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			historyOK([]any{userEv(100), asst(150, "completed", "stale?", nil)}),
		}
		hist := &queueHistory{resps: resps}
		res := runRunner(t, Config{Timeout: 60 * time.Second, Dial: sub.dial, History: hist})
		if res.Kind != KindApproval || res.ExitCode != 4 {
			t.Errorf("res = %+v", res)
		}
		if len(res.Replies) != 0 {
			t.Errorf("replies must be suppressed, got %+v", res.Replies)
		}
		wantNote := "turn-end boundary unknown: history could not be read, so no replies are reported; run `muse-cli wait` again"
		if res.Note != wantNote {
			t.Errorf("note = %q", res.Note)
		}
	})
}

func TestRunnerWatchdogEndsDeafStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{
			block: true,
			loopScript: [][]byte{
				recordJSON(Event{"event": "sessions.updated", "payload": map[string]any{}}),
			},
		}
		hist := &queueHistory{resps: []historyResp{historyOK([]any{userEv(100)})}}
		res := runRunner(t, Config{
			Timeout:      60 * time.Second,
			RecheckAfter: 20 * time.Second,
			CheckEvery:   -1,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindTimeout {
			t.Errorf("res = %+v", res)
		}
		if sub.calls < 2 {
			t.Errorf("subscribe calls = %d, want the watchdog to end the deaf stream and resubscribe", sub.calls)
		}
	})
}

func TestRunnerOnlineGraceForcesRecheck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{
			block: true,
			loopScript: [][]byte{
				recordJSON(taskEv("running", "R", "R", 120, nil)),
				recordJSON(Event{"event": "agent.status", "payload": map[string]any{"activity_code": "online"}}),
			},
		}
		hist := &queueHistory{resps: []historyResp{historyOK([]any{userEv(100)})}}
		res := runRunner(t, Config{
			Timeout:      30 * time.Second,
			RecheckAfter: -1,
			CheckEvery:   -1,
			Dial:         sub.dial,
			History:      hist,
		})
		if res.Kind != KindTimeout {
			t.Errorf("res = %+v", res)
		}
		if sub.calls < 2 {
			t.Errorf("subscribe calls = %d, want the online grace to end the stream", sub.calls)
		}
	})
}

func TestRunnerAuthErrorPropagates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{dialErr: conn.NewAuthError("expired")}
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
	})
}

func TestRunnerAuthErrorInFinalReadPropagates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
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
			t.Errorf("err = %v, want AuthError, not 124", err)
		}
	})
}

func TestRunnerDecideNeverRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		decides := 0
		aa := approvals.NewAutoApprover(func(ctx context.Context) (approvals.Decider, func(), error) {
			return func(ctx context.Context, a approvals.DescribedApproval, decision string) error {
				decides++
				return nil
			}, func() {}, nil
		}, false)
		expired := appr("OLD")
		expired["request_expires_at_ms"] = float64(1)
		// A approves forever; B offers only allow_once with the
		// fallback off, so it is skipped and left for a human.
		// The expired snapshot is dropped before the approver
		// runs at all.
		scripts := [][][]byte{
			{recordJSON(approvalEv([]any{expired}, nil))},
			{recordJSON(approvalEv([]any{appr("A", approvals.Forever), appr("B", approvals.Once)}, nil))},
		}
		dialCount := 0
		dial := func(ctx context.Context) (Subscriber, error) {
			dialCount++
			idx := dialCount - 1
			if idx >= len(scripts) {
				idx = len(scripts) - 1
			}
			return &fakeSubscriber{loopScript: scripts[idx]}, nil
		}
		hist := &queueHistory{resps: []historyResp{historyOK([]any{userEv(100)})}}
		r, err := NewRunner(Config{
			Timeout:  60 * time.Second,
			Dial:     dial,
			History:  hist,
			Approver: aa.AsApprover(),
		})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		// The approver's expiry check uses wall time: the OLD
		// approval expired at epoch 1ms, so it is dropped.
		res, err := r.Run(context.Background())
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Kind != KindApproval || res.ExitCode != 4 {
			t.Errorf("res = %+v", res)
		}
		if len(res.Approvals) != 1 || *res.Approvals[0].ApprovalID != "B" {
			t.Errorf("approvals = %+v, want only B left", res.Approvals)
		}
		if decides != 1 {
			t.Errorf("decide calls = %d, want exactly 1", decides)
		}
	})
}

func TestRunnerSafetyNetCheckSettles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{
			checkScript: [][]byte{
				recordJSON(taskEv("completed", "R", "R", 180, nil)),
			},
		}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
			historyOK([]any{userEv(100), asst(150, "completed", "checked", nil)}),
			historyOK([]any{userEv(100), asst(150, "completed", "checked", nil)}),
		}}
		res := runRunner(t, Config{
			Timeout:    130 * time.Second,
			CheckEvery: 60 * time.Second,
			Dial:       sub.dial,
			History:    hist,
		})
		if res.Kind != KindDone || res.FinalText != "checked" {
			t.Errorf("res = %+v", res)
		}
		if sub.checkCalls == 0 {
			t.Error("safety-net check never ran")
		}
	})
}

func TestRunnerRatchet(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Boundary unknown (history always fails), then a live
		// root running ratchets after_seq to the running seq.
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 300, nil)),
			recordJSON(taskEv("completed", "R", "R", 400, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			{err: errTransport}, {err: errTransport},
			historyOK([]any{userEv(300), asst(350, "completed", "ratcheted", nil)}),
		}}
		r, err := NewRunner(Config{Timeout: 60 * time.Second, Dial: sub.dial, History: hist})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		res, err := r.Run(context.Background())
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Kind != KindDone || res.AfterSeq != 300 || res.FinalText != "ratcheted" {
			t.Errorf("res = %+v", res)
		}
	})
}

func TestRunnerLagWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		// Final read: first two attempts return no replies
		// (the done read + the lag polls use the same queue;
		// the third response carries the late reply).
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
			historyOK([]any{userEv(100)}),
			historyOK([]any{userEv(100)}),
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
			t.Errorf("res = %+v", res)
		}
	})
}

func TestRunnerExplicitBoundaryNeverAcceptsReplayedFailed(t *testing.T) {
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
		if res.Kind != KindTimeout || res.ExitCode != 124 {
			t.Errorf("explicit boundary must keep waiting: res = %+v", res)
		}
	})
}
