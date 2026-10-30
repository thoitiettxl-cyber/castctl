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

	"github.com/thoitiettxl-cyber/castctl/internal/approvals"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
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
	loopOpts    conn.SubscribeOptions
	checkOpts   conn.SubscribeOptions
}

func (f *fakeSubscriber) SubscribeRaw(ctx context.Context, method string, opts conn.SubscribeOptions) ([][]byte, error) {
	if opts.MaxRecords == 50 {
		f.checkCalls++
		f.checkOpts = opts
		for _, rec := range f.checkScript {
			if opts.OnRecord != nil && opts.OnRecord(rec) {
				break
			}
		}
		return nil, nil
	}
	f.calls++
	f.loopOpts = opts
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
		if res.Note != "could not read the final replies; run `castctl wait` again" {
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
		wantNote := "turn-end boundary unknown: history could not be read, so no replies are reported; run `castctl wait` again"
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

func TestRunnerLagWindowCancelReturnsCtxErr(t *testing.T) {
	// Cancelling during the lag window must end the wait with
	// the context error, never a Done/0 result: Python's
	// KeyboardInterrupt is a BaseException that _run_wait never
	// converts into a result, and ctx cancellation is its Go
	// analogue. Pre-fix the lag loop swallowed the cancel and
	// reported Done.
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
			historyOK([]any{userEv(100)}),
			historyOK([]any{userEv(100)}),
		}}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(300 * time.Millisecond)
			cancel()
		}()
		r, err := NewRunner(Config{
			Timeout:   60 * time.Second,
			LagWindow: 2 * time.Second,
			LagPoll:   250 * time.Millisecond,
			Dial:      sub.dial,
			History:   hist,
		})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		res, err := r.Run(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run err = %v (res = %+v), want context.Canceled, never a Done result", err, res)
		}
		if res != nil {
			t.Errorf("res = %+v, want nil on cancellation", res)
		}
	})
}

// cancelPollHistory serves two OK windows (boundary + final
// read), then blocks on the passed context and returns its
// error: a lag poll whose reader honors cancellation.
type cancelPollHistory struct {
	calls int
}

func (h *cancelPollHistory) ReadHistory(ctx context.Context, limit int) ([]any, bool, error) {
	h.calls++
	if h.calls <= 2 {
		return []any{userEv(100)}, false, nil
	}
	<-ctx.Done()
	return nil, false, ctx.Err()
}

func TestRunnerLagPollCtxErrReturnsCtxErr(t *testing.T) {
	// A lag poll whose reader returns ctx.Err() (cancel fired
	// while the poll was in flight) must end the wait with
	// ctx.Err(), never a Done result.
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(taskEv("completed", "R", "R", 180, nil)),
		}}
		hist := &cancelPollHistory{}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(300 * time.Millisecond)
			cancel()
		}()
		r, err := NewRunner(Config{
			Timeout:   60 * time.Second,
			LagWindow: 2 * time.Second,
			LagPoll:   250 * time.Millisecond,
			Dial:      sub.dial,
			History:   hist,
		})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		res, err := r.Run(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run err = %v (res = %+v), want context.Canceled, never a Done result", err, res)
		}
		if res != nil {
			t.Errorf("res = %+v, want nil on cancellation", res)
		}
	})
}

func TestRunnerSettlePendingPrefersCtxErr(t *testing.T) {
	// A non-conforming HistoryReader that returns a transport
	// error after the context died must not mask the
	// cancellation: settlePending returns ctx.Err(), on both
	// the replies path and the failed-terminal path.
	setup := func(status string) *Runner {
		t.Helper()
		sub := &fakeSubscriber{}
		hist := &queueHistory{resps: []historyResp{{err: errTransport}}}
		r, err := NewRunner(Config{Timeout: 60 * time.Second, Dial: sub.dial, History: hist})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		r.waiter.Feed(taskEv(status, "R", "R", 180, nil))
		if term, ok := r.waiter.IgnoredTerminal(); !ok || term != status {
			t.Fatalf("ignored terminal = %q, %v, want %q", term, ok, status)
		}
		return r
	}
	for _, status := range []string{"idle", "interrupted"} {
		t.Run(status, func(t *testing.T) {
			r := setup(status)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := r.settlePending(ctx, status); !errors.Is(err, context.Canceled) {
				t.Errorf("settlePending err = %v, want context.Canceled (ctx.Err() wins over the transport error)", err)
			}
		})
	}
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

// stormSubscriber fails every loop subscribe with a transport
// error but serves state checks, so a reconnect storm reaches
// checkState.
type stormSubscriber struct {
	checkScript [][]byte
	loopErr     error
	checkCalls  int
	closed      int
}

func (f *stormSubscriber) SubscribeRaw(ctx context.Context, method string, opts conn.SubscribeOptions) ([][]byte, error) {
	if opts.MaxRecords == 50 {
		f.checkCalls++
		for _, rec := range f.checkScript {
			if opts.OnRecord != nil && opts.OnRecord(rec) {
				break
			}
		}
		return nil, nil
	}
	return nil, f.loopErr
}

func (f *stormSubscriber) Close() error {
	f.closed++
	return nil
}

func TestRunnerCheckStateSwallowsHistoryReadFailure(t *testing.T) {
	// Reconnect storm -> checkState -> ignored terminal ->
	// transient history failure. Pre-fix, checkState returned
	// the settle error and Run aborted with it; post-fix the
	// failure is swallowed like trySettle swallows it, and
	// the wait runs to its timeout instead.
	synctest.Test(t, func(t *testing.T) {
		sub := &stormSubscriber{
			checkScript: [][]byte{
				recordJSON(taskEv("completed", "R", "R", 180, nil)),
			},
			loopErr: errTransport,
		}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
			{err: errTransport},
		}}
		r, err := NewRunner(Config{
			Timeout:         60 * time.Second,
			ReconnectBudget: 5 * time.Second,
			Dial: func(ctx context.Context) (Subscriber, error) {
				return sub, nil
			},
			History: hist,
		})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		res, err := r.Run(context.Background())
		if err != nil {
			t.Fatalf("Run: %v, want no error (history failure swallowed in checkState)", err)
		}
		if res.Kind != KindTimeout || res.ExitCode != 124 {
			t.Errorf("res = %+v, want timeout/124", res)
		}
		if sub.checkCalls == 0 {
			t.Error("storm never reached checkState")
		}
	})
}

func TestRunnerApprovalStatusUsesWaiterStatus(t *testing.T) {
	// An approval outcome reports the Waiter's last stored
	// status (Python: res["status"] = w.status regardless of
	// kind), not the approval Outcome's empty Detail.
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(taskEv("running", "R", "R", 120, nil)),
			recordJSON(approvalEv([]any{appr("A")}, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{
			historyOK([]any{userEv(100)}),
		}}
		res := runRunner(t, Config{Timeout: 60 * time.Second, Dial: sub.dial, History: hist})
		if res.Kind != KindApproval || res.ExitCode != 4 {
			t.Errorf("res = %+v, want approval/4", res)
		}
		if res.Status != "running" {
			t.Errorf("Status = %q, want %q", res.Status, "running")
		}
	})
}

func TestRunnerPlumbsAutoApproveRecords(t *testing.T) {
	// A decides A (forever); B offers only allow_once with the
	// fallback off, so it is skipped. Both records land in
	// the Result for the caller to log to stderr.
	synctest.Test(t, func(t *testing.T) {
		aa := approvals.NewAutoApprover(func(ctx context.Context) (approvals.Decider, func(), error) {
			return func(ctx context.Context, a approvals.DescribedApproval, decision string) error {
				return nil
			}, func() {}, nil
		}, false)
		sub := &fakeSubscriber{loopScript: [][]byte{
			recordJSON(approvalEv([]any{appr("A", approvals.Forever), appr("B", approvals.Once)}, nil)),
		}}
		hist := &queueHistory{resps: []historyResp{historyOK([]any{userEv(100)})}}
		res := runRunner(t, Config{
			Timeout:  60 * time.Second,
			Dial:     sub.dial,
			History:  hist,
			Approver: aa.AsApprover(),
		})
		if res.Kind != KindApproval || res.ExitCode != 4 {
			t.Errorf("res = %+v, want approval/4", res)
		}
		if len(res.AutoApproved) != 1 || res.AutoApproved[0].ApprovalID != "A" ||
			res.AutoApproved[0].Decision != approvals.Forever {
			t.Errorf("AutoApproved = %+v, want [A allow_always]", res.AutoApproved)
		}
		if len(res.AutoApproveErrors) != 1 || res.AutoApproveErrors[0].ApprovalID != "B" {
			t.Errorf("AutoApproveErrors = %+v, want [B skip]", res.AutoApproveErrors)
		}
	})
}

func TestRunnerApproverAuthErrorPropagates(t *testing.T) {
	// A decide-time AuthError ends the wait as an error, not
	// as exit 4.
	synctest.Test(t, func(t *testing.T) {
		aa := approvals.NewAutoApprover(func(ctx context.Context) (approvals.Decider, func(), error) {
			return func(ctx context.Context, a approvals.DescribedApproval, decision string) error {
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
			t.Errorf("err = %v, want AuthError, not an exit-4 result", err)
		}
	})
}

func TestRunnerNilSubscriberIsTransportFailure(t *testing.T) {
	// Dial returning (nil, nil) must never panic: it is a
	// transport failure, resubscribed with backoff until the
	// deadline.
	synctest.Test(t, func(t *testing.T) {
		hist := &queueHistory{resps: []historyResp{historyOK([]any{userEv(100)})}}
		r, err := NewRunner(Config{
			Timeout: 5 * time.Second,
			Dial: func(ctx context.Context) (Subscriber, error) {
				return nil, nil
			},
			History: hist,
		})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		res, err := r.Run(context.Background())
		if err != nil {
			t.Fatalf("Run: %v, want no error", err)
		}
		if res.Kind != KindTimeout || res.ExitCode != 124 {
			t.Errorf("res = %+v, want timeout/124", res)
		}
	})
}

func TestIsNilSubscriber(t *testing.T) {
	var nilFake *fakeSubscriber
	var nilStorm *stormSubscriber
	tests := []struct {
		name string
		sub  Subscriber
		want bool
	}{
		{"nil interface", nil, true},
		{"typed nil fakeSubscriber", nilFake, true},
		{"typed nil stormSubscriber", nilStorm, true},
		{"live subscriber", &fakeSubscriber{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNilSubscriber(tt.sub); got != tt.want {
				t.Errorf("isNilSubscriber = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunnerTypedNilSubscriberIsTransportFailure(t *testing.T) {
	// Dial returning a typed-nil Subscriber (a nil pointer
	// inside the interface) must never panic: it is a
	// transport failure, resubscribed with backoff until the
	// deadline, exactly like (nil, nil).
	synctest.Test(t, func(t *testing.T) {
		var nilSub *fakeSubscriber
		hist := &queueHistory{resps: []historyResp{historyOK([]any{userEv(100)})}}
		r, err := NewRunner(Config{
			Timeout: 5 * time.Second,
			Dial: func(ctx context.Context) (Subscriber, error) {
				return nilSub, nil
			},
			History: hist,
		})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		res, err := r.Run(context.Background())
		if err != nil {
			t.Fatalf("Run: %v, want no error", err)
		}
		if res.Kind != KindTimeout || res.ExitCode != 124 {
			t.Errorf("res = %+v, want timeout/124", res)
		}
	})
}

func TestRunnerCheckStateTypedNilSubscriber(t *testing.T) {
	// checkState's Dial returning a typed-nil Subscriber must
	// fail silently (no panic, nil error), like (nil, nil).
	var nilSub *fakeSubscriber
	hist := &queueHistory{resps: []historyResp{historyOK([]any{userEv(100)})}}
	r, err := NewRunner(Config{
		Timeout: 60 * time.Second,
		Dial: func(ctx context.Context) (Subscriber, error) {
			return nilSub, nil
		},
		History: hist,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	r.deadline = r.clock.Now().Add(time.Minute)
	if err := r.checkState(context.Background()); err != nil {
		t.Errorf("checkState = %v, want nil (typed-nil Subscriber is a silent transport failure)", err)
	}
}

func TestRunnerEmptyHistoryLimitsUseDefaults(t *testing.T) {
	// An explicitly empty HistoryLimits is unset, not "no
	// windows": the boundary is derived from the defaults.
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
			Timeout:       60 * time.Second,
			Dial:          sub.dial,
			History:       hist,
			HistoryLimits: []int{},
		})
		if res.Kind != KindDone || res.FinalText != "done" || res.AfterSeq != 100 {
			t.Errorf("res = %+v, want done with boundary 100", res)
		}
	})
}

func TestRunnerSubscribeOptionsNoKeepAlive(t *testing.T) {
	// G5/S10 pin: the Runner builds SubscribeOptions with no
	// keep-alive mechanism reachable through them — this
	// base's SubscribeOptions has no keep-alive field, and
	// the Runner sets no OnOpen/Route either. The options
	// below are the complete shape the Runner may build.
	synctest.Test(t, func(t *testing.T) {
		sub := &fakeSubscriber{
			loopScript: [][]byte{
				recordJSON(taskEv("running", "R", "R", 120, nil)),
			},
			checkScript: [][]byte{
				recordJSON(taskEv("running", "R", "R", 120, nil)),
			},
		}
		hist := &queueHistory{resps: []historyResp{historyOK([]any{userEv(100)})}}
		_ = runRunner(t, Config{
			Timeout:    130 * time.Second,
			CheckEvery: 60 * time.Second,
			Dial:       sub.dial,
			History:    hist,
		})
		if sub.loopOpts.OnOpen != nil || sub.loopOpts.Route != nil {
			t.Errorf("loop opts = %+v, want no OnOpen/Route", sub.loopOpts)
		}
		if sub.loopOpts.MaxRecords != 1000000000 {
			t.Errorf("loop MaxRecords = %d", sub.loopOpts.MaxRecords)
		}
		if sub.checkOpts.OnOpen != nil || sub.checkOpts.Route != nil {
			t.Errorf("check opts = %+v, want no OnOpen/Route", sub.checkOpts)
		}
		if sub.checkOpts.MaxRecords != 50 {
			t.Errorf("check MaxRecords = %d, want 50", sub.checkOpts.MaxRecords)
		}
	})
}

func TestNewRunnerClampsNegativeDurations(t *testing.T) {
	r, err := NewRunner(Config{
		Dial:             (&fakeSubscriber{}).dial,
		History:          &queueHistory{resps: []historyResp{historyOK(nil)}},
		Timeout:          -1,
		StateCheckBudget: -1,
		ReconnectBudget:  -1,
		ResubPause:       -1,
		FinalReadFloor:   -1,
		LagWindow:        -1,
		LagPoll:          -1,
		RecheckAfter:     -1,
		CheckEvery:       -1,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	if r.cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", r.cfg.Timeout, DefaultTimeout)
	}
	if r.cfg.StateCheckBudget != DefaultStateCheckBudget {
		t.Errorf("StateCheckBudget = %v, want %v", r.cfg.StateCheckBudget, DefaultStateCheckBudget)
	}
	if r.cfg.ReconnectBudget != DefaultReconnectBudget {
		t.Errorf("ReconnectBudget = %v, want %v", r.cfg.ReconnectBudget, DefaultReconnectBudget)
	}
	if r.cfg.ResubPause != DefaultResubPause {
		t.Errorf("ResubPause = %v, want %v", r.cfg.ResubPause, DefaultResubPause)
	}
	if r.cfg.FinalReadFloor != DefaultFinalReadFloor {
		t.Errorf("FinalReadFloor = %v, want %v", r.cfg.FinalReadFloor, DefaultFinalReadFloor)
	}
	if r.cfg.LagWindow != DefaultLagWindow {
		t.Errorf("LagWindow = %v, want %v", r.cfg.LagWindow, DefaultLagWindow)
	}
	if r.cfg.LagPoll != DefaultLagPoll {
		t.Errorf("LagPoll = %v, want %v", r.cfg.LagPoll, DefaultLagPoll)
	}
	// RecheckAfter/CheckEvery keep negative = disable.
	if r.cfg.RecheckAfter != -1 || r.cfg.CheckEvery != -1 {
		t.Errorf("RecheckAfter/CheckEvery = %v/%v, want -1/-1 (disable)", r.cfg.RecheckAfter, r.cfg.CheckEvery)
	}
	// HistoryLimits defaults are a fresh copy per Runner.
	if len(r.cfg.HistoryLimits) != len(DefaultHistoryLimits()) {
		t.Fatalf("HistoryLimits = %v, want %v", r.cfg.HistoryLimits, DefaultHistoryLimits())
	}
	r.cfg.HistoryLimits[0] = 999
	if DefaultHistoryLimits()[0] == 999 {
		t.Error("mutating the Runner's limits must not mutate DefaultHistoryLimits")
	}
}

// cancelOnReadHistory cancels ctx on a chosen read, then
// returns its scripted result: a reader that reports success
// (or a transport error) after cancellation.
type cancelOnReadHistory struct {
	cancelAt int
	cancel   context.CancelFunc
	calls    int
	events   []any
	err      error
}

func (h *cancelOnReadHistory) ReadHistory(ctx context.Context, limit int) ([]any, bool, error) {
	h.calls++
	if h.calls == h.cancelAt {
		h.cancel()
	}
	if h.err != nil {
		return nil, false, h.err
	}
	return h.events, false, nil
}

func TestRunnerFinishFinalReadSuccessAfterCancelReturnsCtxErr(t *testing.T) {
	// A final read returning replies after cancellation must
	// end the wait with ctx.Err(), never Done/0: the success
	// path of finish had no ctx check. The reader cancels the
	// parent ctx mid-read and still returns replies.
	sub := &fakeSubscriber{loopScript: [][]byte{
		recordJSON(taskEv("running", "R", "R", 120, nil)),
		recordJSON(taskEv("completed", "R", "R", 180, nil)),
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hist := &cancelOnReadHistory{
		cancelAt: 1,
		cancel:   cancel,
		events:   []any{userEv(100), asst(150, "completed", "late", nil)},
	}
	r, err := NewRunner(Config{
		Timeout:     60 * time.Second,
		HasAfterSeq: true,
		AfterSeq:    100,
		Dial:        sub.dial,
		History:     hist,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	res, err := r.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run err = %v (res = %+v), want context.Canceled, never a Done result", err, res)
	}
	if res != nil {
		t.Errorf("res = %+v, want nil on cancellation", res)
	}
}

func TestRunnerFinishLastChanceProofErrorAfterCancelReturnsCtxErr(t *testing.T) {
	// A last-chance FAILED proof whose reader returns a
	// transport error after cancellation must end the wait
	// with ctx.Err(), not the reader's error. The first
	// history read is trySettle's (empty window, no proof);
	// the cancel lands on the second read, inside finish's
	// last-chance proof. The short timeout reaches finish
	// without waiting out the default 600 s deadline.
	sub := &fakeSubscriber{loopScript: [][]byte{
		recordJSON(taskEv("interrupted", "R", "R", 180, nil)),
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hist := &cancelOnReadHistory{cancelAt: 2, cancel: cancel, err: errTransport}
	// Call 1 (trySettle) sees an empty window; call 2
	// (finish) cancels and errors. queueHistory-style
	// scripting is local: wrap the cancelling reader so the
	// first call returns empty without cancelling.
	first := true
	scripted := &scriptedHistory{fn: func(ctx context.Context, limit int) ([]any, bool, error) {
		if first {
			first = false
			return []any{}, false, nil
		}
		return hist.ReadHistory(ctx, limit)
	}}
	// cancelOnReadHistory counts its own calls: align it so
	// its first (and only relevant) call is the finish read.
	hist.cancelAt = 1
	r, err := NewRunner(Config{
		Timeout:     200 * time.Millisecond,
		ResubPause:  time.Millisecond,
		HasAfterSeq: true,
		AfterSeq:    200,
		Dial:        sub.dial,
		History:     scripted,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	res, err := r.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run err = %v (res = %+v), want context.Canceled, not the reader's transport error", err, res)
	}
	if res != nil {
		t.Errorf("res = %+v, want nil on cancellation", res)
	}
}

// scriptedHistory serves one scripted ReadHistory function.
type scriptedHistory struct {
	fn func(ctx context.Context, limit int) ([]any, bool, error)
}

func (h *scriptedHistory) ReadHistory(ctx context.Context, limit int) ([]any, bool, error) {
	return h.fn(ctx, limit)
}

func TestRunnerFinishFinalReadErrorAfterCancelReturnsCtxErr(t *testing.T) {
	// A final read returning a transport error after
	// cancellation must end the wait with ctx.Err(), not the
	// reader's error.
	sub := &fakeSubscriber{loopScript: [][]byte{
		recordJSON(taskEv("running", "R", "R", 120, nil)),
		recordJSON(taskEv("completed", "R", "R", 180, nil)),
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hist := &cancelOnReadHistory{cancelAt: 1, cancel: cancel, err: errTransport}
	r, err := NewRunner(Config{
		Timeout:     60 * time.Second,
		HasAfterSeq: true,
		AfterSeq:    100,
		Dial:        sub.dial,
		History:     hist,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	res, err := r.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run err = %v (res = %+v), want context.Canceled, not the reader's transport error", err, res)
	}
	if res != nil {
		t.Errorf("res = %+v, want nil on cancellation", res)
	}
}

func TestRunnerFinishCancelDuringLagReadReturnsCtxErr(t *testing.T) {
	// Linearization semantics of finish's endgame, pinned
	// deterministically. The final guard in finish is the
	// linearization point of the endgame: a cancel that lands
	// after the guard's ctx.Err() read linearizes after the
	// return, so no check-then-return sequence can demand
	// zero Done/0 outcomes under arbitrary scheduling —
	// goroutine preemption between the guard read and the
	// return stretches the single-branch window arbitrarily
	// (measured: 1 Done/0 hit per 201 timed cancels under
	// parallel-package load). The timing-sweep probe that
	// asserted 0 hits, TestRunnerFinishCancelRaceProbe, was
	// therefore removed: it asserted something unachievable
	// in this API shape. These subtests pin instead every
	// ordering the existing seams can express synchronously:
	// a cancel injected during a lag-loop read precedes both
	// the post-lag check and the final guard and must yield
	// ctx.Err(), never a result — via the post-lag check when
	// the read returns replies, via the lag sleep's ctx.Done()
	// select when it returns an empty window. The final
	// guard in isolation is pinned by
	// TestRunnerFinishFinalGuardReturnsCtxErr, which cancels
	// ctx from the beforeFinalGuard hook immediately before
	// the guard — an ordering no earlier check can observe,
	// because the tail performs no I/O and no hookable call
	// after the post-lag check. A cancel landing after the
	// guard's read still linearizes after the return; see
	// the linearization paragraph in finish. The
	// final-read and last-chance orderings are pinned by
	// TestRunnerFinishFinalReadSuccessAfterCancelReturnsCtxErr,
	// TestRunnerFinishFinalReadErrorAfterCancelReturnsCtxErr,
	// and TestRunnerFinishLastChanceProofErrorAfterCancelReturnsCtxErr.
	cancelCases := []struct {
		name   string
		events []any // returned by the lag-loop read (call 2)
	}{
		{
			name:   "replies returned",
			events: []any{userEv(100), asst(150, "completed", "late", nil)},
		},
		{
			name:   "empty window",
			events: []any{},
		},
	}
	for _, tc := range cancelCases {
		t.Run(tc.name, func(t *testing.T) {
			sub := &fakeSubscriber{loopScript: [][]byte{
				recordJSON(taskEv("running", "R", "R", 120, nil)),
				recordJSON(taskEv("completed", "R", "R", 180, nil)),
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			extraReads := 0
			hist := &scriptedHistory{fn: func(ctx context.Context, limit int) ([]any, bool, error) {
				calls++
				switch calls {
				case 1:
					// Final read: empty, so finish
					// enters the lag window.
					return []any{}, false, nil
				case 2:
					// Lag-loop read: cancel
					// synchronously, before the
					// post-lag check and the final
					// guard can read the context.
					cancel()
					return tc.events, false, nil
				default:
					extraReads++
					return []any{}, false, nil
				}
			}}
			r, err := NewRunner(Config{
				Timeout:     60 * time.Second,
				HasAfterSeq: true,
				AfterSeq:    100,
				LagWindow:   60 * time.Second,
				LagPoll:     time.Millisecond,
				Dial:        sub.dial,
				History:     hist,
			})
			if err != nil {
				t.Fatalf("NewRunner: %v", err)
			}
			res, err := r.Run(ctx)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Run err = %v (res = %+v), want context.Canceled", err, res)
			}
			if res != nil {
				t.Errorf("res = %+v, want nil on cancellation", res)
			}
			if calls != 2 || extraReads != 0 {
				t.Errorf("history reads = %d (%d extra), want exactly 2 (final read + lag-loop read)", calls, extraReads)
			}
		})
	}
}

func TestRunnerFinishFinalGuardReturnsCtxErr(t *testing.T) {
	// The final guard in finish is pinned in isolation: the
	// beforeFinalGuard hook cancels ctx immediately before
	// the guard, an ordering no earlier ctx check in finish
	// can observe (the tail performs no I/O after the
	// post-lag check). With the guard deleted, the cancel
	// case below returns the Done result; with the guard
	// present it returns ctx.Err(). The no-cancel case proves
	// the hook itself neither masks a success nor fires
	// spuriously: the guard must not observe a cancellation
	// that never happened.
	cases := []struct {
		name   string
		cancel bool
	}{
		{name: "cancel before final guard returns ctx err", cancel: true},
		{name: "no cancel returns done result", cancel: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub := &fakeSubscriber{loopScript: [][]byte{
				recordJSON(taskEv("running", "R", "R", 120, nil)),
				recordJSON(taskEv("completed", "R", "R", 180, nil)),
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			fired := 0
			var gotCtx context.Context
			hist := &scriptedHistory{fn: func(ctx context.Context, limit int) ([]any, bool, error) {
				calls++
				return []any{userEv(100), asst(150, "completed", "late", nil)}, false, nil
			}}
			r, err := NewRunner(Config{
				Timeout:     60 * time.Second,
				HasAfterSeq: true,
				AfterSeq:    100,
				Dial:        sub.dial,
				History:     hist,
				beforeFinalGuard: func(hookCtx context.Context) {
					fired++
					gotCtx = hookCtx
					if tc.cancel {
						cancel()
					}
				},
			})
			if err != nil {
				t.Fatalf("NewRunner: %v", err)
			}
			res, err := r.Run(ctx)
			if gotCtx != ctx {
				t.Errorf("hook ctx = %v, want the ctx passed to Run", gotCtx)
			}
			if fired != 1 {
				t.Errorf("hook fired %d times, want exactly 1", fired)
			}
			if calls != 1 {
				t.Errorf("history reads = %d, want exactly 1 (final read; no lag read)", calls)
			}
			if tc.cancel {
				if !errors.Is(err, context.Canceled) {
					t.Errorf("Run err = %v (res = %+v), want context.Canceled, never a Done result", err, res)
				}
				if res != nil {
					t.Errorf("res = %+v, want nil on cancellation", res)
				}
				return
			}
			if err != nil {
				t.Fatalf("Run err = %v, want nil", err)
			}
			if res == nil {
				t.Fatalf("res = nil, want a Done result")
			}
			if res.Kind != KindDone {
				t.Errorf("res.Kind = %v, want KindDone", res.Kind)
			}
			if res.Outcome != "done" || res.ExitCode != 0 {
				t.Errorf("res.Outcome = %q, res.ExitCode = %d, want \"done\"/0", res.Outcome, res.ExitCode)
			}
		})
	}
}

func TestRunnerSettlePendingCancelledSuccessReturnsCtxErr(t *testing.T) {
	// settlePending must return ctx.Err() with NO outcome
	// applied when the context is cancelled, on both the
	// replies path and the failed-terminal path. A
	// pre-cancelled context with a successful proof currently
	// settles the waiter.
	setup := func(status string, events []any) *Runner {
		t.Helper()
		sub := &fakeSubscriber{}
		hist := &queueHistory{resps: []historyResp{historyOK(events)}}
		r, err := NewRunner(Config{Timeout: 60 * time.Second, Dial: sub.dial, History: hist})
		if err != nil {
			t.Fatalf("NewRunner: %v", err)
		}
		r.waiter.Feed(taskEv(status, "R", "R", 180, nil))
		if term, ok := r.waiter.IgnoredTerminal(); !ok || term != status {
			t.Fatalf("ignored terminal = %q, %v, want %q", term, ok, status)
		}
		return r
	}
	t.Run("replies path", func(t *testing.T) {
		r := setup("idle", []any{userEv(100), asst(150, "completed", "settled", nil)})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := r.settlePending(ctx, "idle"); !errors.Is(err, context.Canceled) {
			t.Errorf("settlePending err = %v, want context.Canceled", err)
		}
		if out := r.waiter.Result(); out != nil {
			t.Errorf("waiter result = %+v, want nil (no outcome applied after cancel)", out)
		}
		if _, ok := r.waiter.IgnoredTerminal(); !ok {
			t.Error("ignored terminal must still be pending after a cancelled settle")
		}
		// Baseline: the same proof without cancellation
		// still settles.
		r2 := setup("idle", []any{userEv(100), asst(150, "completed", "settled", nil)})
		if err := r2.settlePending(context.Background(), "idle"); err != nil {
			t.Fatalf("live settlePending err = %v", err)
		}
		if out := r2.waiter.Result(); out == nil || out.Kind != KindDone {
			t.Errorf("live settle result = %+v, want KindDone", out)
		}
	})
	t.Run("failed path", func(t *testing.T) {
		r := setup("interrupted", []any{userEv(200)})
		r.waiter.SetBoundary(200, false, true)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := r.settlePending(ctx, "interrupted"); !errors.Is(err, context.Canceled) {
			t.Errorf("settlePending err = %v, want context.Canceled", err)
		}
		if out := r.waiter.Result(); out != nil {
			t.Errorf("waiter result = %+v, want nil (no outcome applied after cancel)", out)
		}
		if _, ok := r.waiter.IgnoredTerminal(); !ok {
			t.Error("ignored terminal must still be pending after a cancelled settle")
		}
		// Baseline: the same proof without cancellation
		// still settles.
		r2 := setup("interrupted", []any{userEv(200)})
		r2.waiter.SetBoundary(200, false, true)
		if err := r2.settlePending(context.Background(), "interrupted"); err != nil {
			t.Fatalf("live settlePending err = %v", err)
		}
		if out := r2.waiter.Result(); out == nil || out.Kind != KindFailed {
			t.Errorf("live settle result = %+v, want KindFailed", out)
		}
	})
}
