// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/approvals"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// Timing defaults, verbatim from cli.py (seconds unless noted).
// All enforced on the monotonic clock.
const (
	// DefaultRecheckAfter (WATCHDOG) is the seconds without
	// scoped progress before the stream is ended and resubscribed.
	DefaultRecheckAfter = 20 * time.Second
	// DefaultStateCheckBudget bounds one server state check.
	DefaultStateCheckBudget = 8 * time.Second
	// DefaultReconnectBudget is the shared deadline for a storm
	// of failed resubscribes before one bounded state check.
	DefaultReconnectBudget = 30 * time.Second
	// DefaultOnlineGrace is the idle-online grace before a re-check.
	DefaultOnlineGrace = 3 * time.Second
	// DefaultResubPause is the base pause before resubscribing.
	DefaultResubPause = 1 * time.Second
	// DefaultFinalReadFloor is the minimum budget for the final
	// history read and the last-chance user-seq read.
	DefaultFinalReadFloor = 5 * time.Second
	// DefaultLagWindow is the post-done polling window for a
	// just-landed reply.
	DefaultLagWindow = 2 * time.Second
	// DefaultLagPoll is the interval between lag-window reads.
	DefaultLagPoll = 250 * time.Millisecond
	// DefaultCheckEvery is the safety-net cadence: an
	// unconditional server state check.
	DefaultCheckEvery = 60 * time.Second
	// DefaultTimeout is the wait --timeout default.
	DefaultTimeout = 600 * time.Second
)

// Subscriber is one subscribe-capable connection: the
// conn.Gateway interface narrowed to what the Runner uses. The
// Runner never dials: Dial supplies a fresh Subscriber per
// subscribe iteration (and per state check), and the Runner
// closes it after use. conn.Gateway satisfies this interface;
// SharedConn.Close is a no-op, so closing a shared connection is
// safe.
type Subscriber interface {
	SubscribeRaw(ctx context.Context, method string, opts conn.SubscribeOptions) ([][]byte, error)
	Close() error
}

// Config configures a Runner. Zero values take the defaults
// above; a negative duration disables that timer (watchdog,
// safety-net cadence). Timeout <= 0 means DefaultTimeout.
// HistoryLimits nil means DefaultHistoryLimits. Clock nil means
// the real clock.
//
// NodeID is the caller-supplied stable per-profile identity (see
// NODE_ID.md). The Runner carries it, never generates, persists
// or rotates it, and never sends it: the send path (deferred
// wiring) reads it from the Result. An empty NodeID means the
// caller supplied none; the Runner invents nothing.
type Config struct {
	Thread           string
	NodeID           string
	AfterSeq         int64
	HasAfterSeq      bool
	Timeout          time.Duration
	RecheckAfter     time.Duration
	CheckEvery       time.Duration
	StateCheckBudget time.Duration
	ReconnectBudget  time.Duration
	ResubPause       time.Duration
	FinalReadFloor   time.Duration
	LagWindow        time.Duration
	LagPoll          time.Duration
	HistoryLimits    []int
	Approver         approvals.Approver
	Recheck          func() bool
	UserStop         func() bool
	Clock            Clock
	Dial             func(ctx context.Context) (Subscriber, error)
	History          HistoryReader
}

// Result is the wait's endgame result, mirroring the Python
// result dict. Empty strings mean "none" (no status was ever
// stored, no final text, no input reason).
type Result struct {
	Kind             Kind
	Outcome          string
	Status           string
	AfterSeq         int64
	FinalText        string
	Replies          []Reply
	FinalReadFailed  bool
	Note             string
	Approvals        []approvals.DescribedApproval
	NeedsInputReason string
	Question         string
	ExitCode         int
	NodeID           string
}

var errHistoryRead = errors.New("wait: history read failed")

// Runner drives a Waiter over a subscription: boundary
// derivation, the subscribe loop with watchdog / safety-net /
// online-idle / reconnect-storm rules, and the endgame (last
// chance, final read, lag window, fail-closed 124, boundary
// suppression). It runs on one goroutine; no lock is needed.
//
// State checks run synchronously between subscribe batches
// (deviation D2): the Python check thread is replaced by a
// between-batch check, because SubscribeRaw's batch shape gives
// the Runner control only between batches. No I/O happens under
// a lock because there is no lock.
//
// An AuthError anywhere propagates unwrapped: swallowing it as
// 124 would send every retry-on-124 caller into an infinite loop
// on expired cookies.
type Runner struct {
	cfg            Config
	waiter         *Waiter
	clock          Clock
	deadline       time.Time
	afterSeq       int64
	boundaryKnown  bool
	lastProgress   time.Time
	lastCheck      time.Time
	onlineAt       time.Time
	onlineArmed    bool
	failures       int
	firstFailureAt time.Time
	settleTried    bool
	settleKey      string
	pendingErr     error
}

// NewRunner validates cfg and builds the Runner. Dial and
// History are required: the Runner takes its connection and its
// history source from the caller and never dials itself.
func NewRunner(cfg Config) (*Runner, error) {
	if cfg.Dial == nil {
		return nil, errors.New("wait: Runner requires Dial")
	}
	if cfg.History == nil {
		return nil, errors.New("wait: Runner requires History")
	}
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.RecheckAfter == 0 {
		cfg.RecheckAfter = DefaultRecheckAfter
	}
	if cfg.CheckEvery == 0 {
		cfg.CheckEvery = DefaultCheckEvery
	}
	if cfg.StateCheckBudget == 0 {
		cfg.StateCheckBudget = DefaultStateCheckBudget
	}
	if cfg.ReconnectBudget == 0 {
		cfg.ReconnectBudget = DefaultReconnectBudget
	}
	if cfg.ResubPause == 0 {
		cfg.ResubPause = DefaultResubPause
	}
	if cfg.FinalReadFloor == 0 {
		cfg.FinalReadFloor = DefaultFinalReadFloor
	}
	if cfg.LagWindow == 0 {
		cfg.LagWindow = DefaultLagWindow
	}
	if cfg.LagPoll == 0 {
		cfg.LagPoll = DefaultLagPoll
	}
	if cfg.HistoryLimits == nil {
		cfg.HistoryLimits = DefaultHistoryLimits
	}
	r := &Runner{cfg: cfg, clock: cfg.Clock}
	r.waiter = New(cfg.Thread, WithApprover(cfg.Approver))
	return r, nil
}

// Waiter exposes the driven state machine for inspection.
func (r *Runner) Waiter() *Waiter { return r.waiter }

// Run waits for the turn to end and returns the endgame result.
// It returns an error only for AuthError, context cancellation,
// or a stalled Dial/History failure the endgame cannot absorb;
// a timeout is a Result with KindTimeout, never an error.
func (r *Runner) Run(ctx context.Context) (*Result, error) {
	now := r.clock.Now()
	r.deadline = now.Add(r.cfg.Timeout)
	r.lastCheck = now
	if r.cfg.HasAfterSeq {
		r.afterSeq = r.cfg.AfterSeq
		r.boundaryKnown = true
		r.waiter.SetBoundary(r.afterSeq, false, false)
	} else {
		afterSeq, known, derived, err := DeriveBoundary(ctx, r.cfg.History, r.cfg.HistoryLimits)
		if err != nil {
			return nil, err
		}
		r.afterSeq = afterSeq
		r.boundaryKnown = known
		r.waiter.SetBoundary(afterSeq, !known, derived && known)
	}
	attempt := 0
	for r.waiter.Result() == nil && r.clock.Now().Before(r.deadline) && !r.userStop() {
		if attempt > 0 {
			remaining := r.deadline.Sub(r.clock.Now())
			if remaining <= 0 {
				break
			}
			backoff := r.cfg.ResubPause
			if r.failures > 0 {
				shift := r.failures - 1
				if shift > 5 {
					shift = 5
				}
				backoff = r.cfg.ResubPause * time.Duration(1<<uint(shift))
			}
			if backoff > remaining {
				backoff = remaining
			}
			if err := r.sleepCtx(ctx, backoff); err != nil {
				return nil, err
			}
			if r.waiter.Result() != nil || r.userStop() || !r.clock.Now().Before(r.deadline) {
				break
			}
		}
		attempt++
		r.settleTried = false
		r.lastProgress = r.clock.Now()
		r.onlineArmed = false
		if err := r.subscribeOnce(ctx); err != nil {
			return nil, err
		}
		if r.pendingErr != nil {
			return nil, r.pendingErr
		}
		if r.waiter.Result() == nil && !r.userStop() && r.clock.Now().Before(r.deadline) {
			if r.cfg.CheckEvery > 0 && r.clock.Now().Sub(r.lastCheck) >= r.cfg.CheckEvery {
				r.lastCheck = r.clock.Now()
				if err := r.checkState(ctx); err != nil {
					return nil, err
				}
			}
		}
	}
	if r.pendingErr != nil {
		return nil, r.pendingErr
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return r.finish(ctx)
}

func (r *Runner) userStop() bool {
	return r.cfg.UserStop != nil && r.cfg.UserStop()
}

// sleepCtx sleeps for d on the monotonic clock, or until ctx is
// done. A nil error means the full sleep elapsed.
func (r *Runner) sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	select {
	case <-r.clock.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// subscribeOnce dials one fresh connection, subscribes, feeds
// every captured record into the Waiter (the G6 workaround:
// records are captured in OnRecord because SubscribeRaw
// discards them on error and conflates end reasons), and closes
// the connection. A nil error means the subscription ended
// without a transport failure; the Waiter may still be waiting.
func (r *Runner) subscribeOnce(ctx context.Context) error {
	left := r.deadline.Sub(r.clock.Now())
	if left < time.Second {
		left = time.Second
	}
	idle := left
	if r.cfg.RecheckAfter > 0 && r.cfg.RecheckAfter < idle {
		idle = r.cfg.RecheckAfter
	}
	sub, err := r.cfg.Dial(ctx)
	if err != nil {
		if isAuthError(err) || ctx.Err() != nil {
			return err
		}
		r.failures++
		return r.noteFailure(ctx)
	}
	opts := conn.SubscribeOptions{
		Body:           r.subscribeBody(),
		MaxRecords:     1000000000,
		IdleTimeout:    idle,
		OverallTimeout: left,
		OnRecord:       r.onRecord(ctx),
		ShouldStop:     r.shouldStop(ctx),
	}
	_, subErr := sub.SubscribeRaw(ctx, "chat.subscribe", opts)
	_ = sub.Close()
	if subErr != nil {
		if isAuthError(subErr) || ctx.Err() != nil {
			return subErr
		}
		r.failures++
		return r.noteFailure(ctx)
	}
	r.failures = 0
	r.firstFailureAt = time.Time{}
	return nil
}

func (r *Runner) subscribeBody() map[string]any {
	body := map[string]any{"capabilities": []any{"chat_cancel", "delta_stream"}}
	if r.cfg.Thread != "" {
		body["session_id"] = r.cfg.Thread
	}
	return body
}

// onRecord feeds one NDJSON record line. It returns true to stop
// the subscription: once the Waiter decides, or once an AuthError
// is stashed for the loop to re-raise.
func (r *Runner) onRecord(ctx context.Context) func([]byte) bool {
	return func(record []byte) bool {
		if r.waiter.Result() != nil {
			return true
		}
		ev := parseRecord(record)
		if ev != nil {
			r.waiter.Feed(ev)
			r.ratchet()
			if r.waiter.Result() != nil {
				return true
			}
			r.noteProgress(ev)
			if err := r.trySettle(ctx); err != nil {
				r.pendingErr = err
				return true
			}
			if r.waiter.Result() != nil {
				return true
			}
		}
		return false
	}
}

// shouldStop ends the stream when the wait is decided, the
// caller stopped, the watchdog fired, the online grace expired,
// the safety-net cadence is due, or the caller's recheck
// callback fires.
func (r *Runner) shouldStop(ctx context.Context) func() bool {
	return func() bool {
		if ctx.Err() != nil || r.userStop() || r.waiter.Result() != nil || r.pendingErr != nil {
			return true
		}
		if !r.clock.Now().Before(r.deadline) {
			// The overall timeout: the gateway enforces it
			// for real subscriptions; a Subscriber that
			// blocks past it must still be ended here.
			return true
		}
		if r.cfg.Recheck != nil && r.cfg.Recheck() {
			return true
		}
		if r.cfg.RecheckAfter > 0 && r.clock.Now().Sub(r.lastProgress) > r.cfg.RecheckAfter {
			return true
		}
		if r.onlineArmed && r.clock.Now().Sub(r.onlineAt) > DefaultOnlineGrace {
			r.onlineArmed = false
			return true
		}
		if r.cfg.CheckEvery > 0 && r.clock.Now().Sub(r.lastCheck) > r.cfg.CheckEvery {
			return true
		}
		return false
	}
}

// noteProgress updates the watchdog clock and the online-idle
// arm from one event. Scoped progress is an event whose name
// (event/event_name only, as in cli.py) starts with delta./
// task./agent./message. and is in scope; keep-alives and
// other-thread records do not count.
func (r *Runner) noteProgress(ev Event) {
	name := recordName(ev)
	if strings.HasPrefix(name, "delta.") || strings.HasPrefix(name, "task.") ||
		strings.HasPrefix(name, "agent.") || strings.HasPrefix(name, "message.") {
		if inScope(ev, r.cfg.Thread) {
			r.lastProgress = r.clock.Now()
		}
	}
	p := payload(ev)
	activity, _ := p["activity_code"].(string)
	activityPresent := p["activity_code"] != nil
	if name == "agent.status" && activity == "online" && r.waiter.SeenRunning() && inScope(ev, r.cfg.Thread) {
		if !r.onlineArmed {
			r.onlineArmed = true
			r.onlineAt = r.clock.Now()
		}
	} else if name == "delta.text_append" || name == "delta.message_start" ||
		(name == "agent.status" && activityPresent && activity != "online") {
		r.onlineArmed = false
	}
}

// recordName is the cli.py on_record name: event, then
// event_name. The "type" fallback of eventName does not apply
// here.
func recordName(ev Event) string {
	if s, ok := ev["event"].(string); ok && s != "" {
		return s
	}
	if s, ok := ev["event_name"].(string); ok {
		return s
	}
	return ""
}

// ratchet moves the boundary up to the first live root running
// seq when the boundary was never read. One-way only; a no-op
// once the boundary was read.
func (r *Runner) ratchet() {
	if r.boundaryKnown {
		return
	}
	if seq, ok := r.waiter.RunningSeq(); ok && seq > r.afterSeq {
		r.afterSeq = seq
		r.waiter.SetAfterSeq(seq)
	}
}

// noteFailure accounts one failed resubscribe. After
// ReconnectBudget of failures it runs one bounded state check
// instead of storming until the deadline, then resets the storm
// clock.
func (r *Runner) noteFailure(ctx context.Context) error {
	now := r.clock.Now()
	if r.firstFailureAt.IsZero() {
		r.firstFailureAt = now
		return nil
	}
	if now.Sub(r.firstFailureAt) > r.cfg.ReconnectBudget {
		r.firstFailureAt = time.Time{}
		return r.checkState(ctx)
	}
	return nil
}

// trySettle attempts one history proof for the current ignored
// terminal, throttled to one read per terminal value per
// subscribe iteration. A failed read resets the throttle so the
// next record retries. A FAILED terminal is proved by user-seq
// equality only (no replies are read); any other terminal is
// proved by replies.
func (r *Runner) trySettle(ctx context.Context) error {
	ignored, ok := r.waiter.IgnoredTerminal()
	if !ok {
		return nil
	}
	key := ignored + "|" + r.waiter.IgnoredReason()
	if key != r.settleKey {
		r.settleKey = key
		r.settleTried = false
	}
	if r.settleTried {
		return nil
	}
	r.settleTried = true
	if err := r.settlePending(ctx, ignored); err != nil {
		if errors.Is(err, errHistoryRead) {
			r.settleTried = false
			return nil
		}
		return err
	}
	return nil
}

// settlePending proves one captured pending terminal with fresh
// history reads, re-checking that the same terminal is still
// pending before applying. It returns errHistoryRead (wrapped)
// when a history read fails, an AuthError when auth failed, or
// nil when the proof was attempted (whether or not it
// accepted).
func (r *Runner) settlePending(ctx context.Context, pending string) error {
	hctx, cancel := r.historyCtx(ctx, 100*time.Millisecond, nil)
	defer cancel()
	if Failed[pending] {
		latest, found, err := LatestUserSeq(hctx, r.cfg.History, r.cfg.HistoryLimits, r.afterSeq)
		if err != nil {
			if isAuthError(err) || ctx.Err() != nil {
				return err
			}
			return fmt.Errorf("%w: %w", errHistoryRead, err)
		}
		if !found {
			return nil
		}
		if term, ok := r.waiter.IgnoredTerminal(); ok && term == pending && r.waiter.Result() == nil {
			r.waiter.AcceptReplayedFailed(&latest)
		}
		return nil
	}
	replies, err := HistoryReplies(hctx, r.cfg.History, r.cfg.HistoryLimits, r.afterSeq)
	if err != nil {
		if isAuthError(err) || ctx.Err() != nil {
			return err
		}
		return fmt.Errorf("%w: %w", errHistoryRead, err)
	}
	if term, ok := r.waiter.IgnoredTerminal(); ok && term == pending && r.waiter.Result() == nil {
		r.waiter.Settle(replies)
	}
	return nil
}

// checkState reads the turn state on its own short subscription
// (the server replays task.status), feeds the last scoped
// task.status event, ratchets, and settles it like a live one.
// A failed check is silent except for AuthError, which
// propagates. No network I/O happens while applying: the state
// read and the history read complete before the Waiter is fed
// or settled.
func (r *Runner) checkState(ctx context.Context) error {
	budget := r.cfg.StateCheckBudget
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	sub, err := r.cfg.Dial(cctx)
	if err != nil {
		if isAuthError(err) {
			return err
		}
		return nil
	}
	var found []Event
	opts := conn.SubscribeOptions{
		Body:           r.subscribeBody(),
		MaxRecords:     50,
		IdleTimeout:    budget,
		OverallTimeout: budget,
		OnRecord: func(record []byte) bool {
			if ev := parseRecord(record); ev != nil {
				if TaskStatusInfo(ev, r.cfg.Thread) != nil {
					found = append(found, ev)
				}
			}
			return false
		},
		ShouldStop: func() bool { return cctx.Err() != nil },
	}
	_, subErr := sub.SubscribeRaw(cctx, "chat.subscribe", opts)
	_ = sub.Close()
	if subErr != nil {
		if isAuthError(subErr) {
			return subErr
		}
		return nil
	}
	if len(found) == 0 {
		return nil
	}
	ev := found[len(found)-1]
	running := false
	if info := TaskStatusInfo(ev, r.cfg.Thread); info != nil && info.Status == "running" && info.RootConfirmed {
		running = true
	}
	if r.waiter.Result() == nil {
		r.waiter.Feed(ev)
		r.ratchet()
	}
	if running {
		r.lastProgress = r.clock.Now()
	}
	pending, ok := r.waiter.IgnoredTerminal()
	if !ok || r.waiter.Result() != nil {
		return nil
	}
	return r.settlePending(ctx, pending)
}

// historyCtx bounds one history read: at least floor, and at
// most the remaining deadline, optionally capped (lag polls).
func (r *Runner) historyCtx(ctx context.Context, floor time.Duration, cap *time.Duration) (context.Context, context.CancelFunc) {
	budget := floor
	if remaining := r.deadline.Sub(r.clock.Now()); remaining > budget {
		budget = remaining
	}
	if cap != nil {
		capped := *cap
		if capped < 100*time.Millisecond {
			capped = 100 * time.Millisecond
		}
		if budget > capped {
			budget = capped
		}
	}
	return context.WithTimeout(ctx, budget)
}

// finish runs the endgame in order: last-chance FAILED proof,
// final history read (two attempts), lag window, fail-closed
// 124, boundary suppression, then the result object. The
// boundary-unknown rule follows the code, not the comment: kind
// is unchanged, only replies are suppressed.
func (r *Runner) finish(ctx context.Context) (*Result, error) {
	kind := KindTimeout
	detail := ""
	if out := r.waiter.Result(); out != nil {
		kind = out.Kind
		detail = out.Detail
	} else if status, ok := r.waiter.Status(); ok {
		detail = status
	}
	if kind == KindTimeout {
		if ignored, ok := r.waiter.IgnoredTerminal(); ok && Failed[ignored] {
			hctx, cancel := r.historyCtx(ctx, r.cfg.FinalReadFloor, nil)
			latest, found, err := LatestUserSeq(hctx, r.cfg.History, r.cfg.HistoryLimits, r.afterSeq)
			cancel()
			if err != nil {
				if isAuthError(err) || ctx.Err() != nil {
					return nil, err
				}
				// A read failure leaves the timeout standing.
			} else if found {
				if accepted := r.waiter.AcceptReplayedFailed(&latest); accepted != nil {
					kind = KindFailed
					detail = accepted.Detail
				}
			}
		}
	}
	var replies []Reply
	finalReadFailed := false
	for attempt := 0; attempt < 2; attempt++ {
		hctx, cancel := r.historyCtx(ctx, r.cfg.FinalReadFloor, nil)
		rs, err := HistoryReplies(hctx, r.cfg.History, r.cfg.HistoryLimits, r.afterSeq)
		cancel()
		if err == nil {
			replies = rs
			finalReadFailed = false
			break
		}
		if isAuthError(err) || ctx.Err() != nil {
			return nil, err
		}
		finalReadFailed = true
	}
	if !finalReadFailed && kind == KindDone && len(replies) == 0 {
		lagUntil := r.clock.Now().Add(r.cfg.LagWindow)
		for r.clock.Now().Before(lagUntil) {
			remaining := lagUntil.Sub(r.clock.Now())
			poll := r.cfg.LagPoll
			if poll > remaining {
				poll = remaining
			}
			select {
			case <-r.clock.After(poll):
			case <-ctx.Done():
				remaining = 0
			}
			if remaining <= 0 || ctx.Err() != nil {
				break
			}
			capDur := remaining
			hctx, cancel := r.historyCtx(ctx, 100*time.Millisecond, &capDur)
			rs, err := HistoryReplies(hctx, r.cfg.History, r.cfg.HistoryLimits, r.afterSeq)
			cancel()
			if err != nil {
				// A failed poll ends the window without
				// failing the done result.
				break
			}
			replies = rs
			if len(replies) > 0 {
				break
			}
		}
	}
	if finalReadFailed && kind == KindDone {
		kind = KindTimeout
		detail, _ = r.waiter.Status()
	}
	note := ""
	if r.waiter.BoundaryUnknown() {
		replies = nil
		note = "turn-end boundary unknown: history could not be read, so no replies are reported; run `muse-cli wait` again"
	}
	if finalReadFailed {
		// The final-read note wins over the boundary note, as in
		// the Python result construction.
		note = "could not read the final replies; run `muse-cli wait` again"
	}
	outcome := OutcomeOf(kind, replies)
	res := &Result{
		Kind:            kind,
		Outcome:         outcome,
		Status:          detail,
		AfterSeq:        r.afterSeq,
		Replies:         replies,
		FinalReadFailed: finalReadFailed,
		Note:            note,
		ExitCode:        ExitCode(kind, replies),
		NodeID:          r.cfg.NodeID,
	}
	if len(replies) > 0 {
		res.FinalText = replies[len(replies)-1].Text
	}
	if out := r.waiter.Result(); out != nil && out.Kind == KindApproval {
		res.Approvals = out.Approvals
	}
	if outcome == "needs_input" && len(replies) > 0 {
		last := replies[len(replies)-1]
		if len(last.Widgets) > 0 {
			res.NeedsInputReason = "widget"
		} else {
			res.NeedsInputReason = NeedsInputReason(last.Text)
		}
		res.Question = QuestionOf(last.Text)
	}
	return res, nil
}

func isAuthError(err error) bool {
	var authErr *conn.AuthError
	return errors.As(err, &authErr)
}

// parseRecord decodes one NDJSON record into an Event, or nil
// when the record is unparseable or not an object.
func parseRecord(record []byte) Event {
	record = bytes.TrimSpace(record)
	if len(record) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(record))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil
	}
	ev, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return ev
}
