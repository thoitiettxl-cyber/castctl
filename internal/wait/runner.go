// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/approvals"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
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
//
// The OnRecord and ShouldStop callbacks in SubscribeOptions are
// invoked serially, on the goroutine that called SubscribeRaw:
// the Runner's callbacks assume single-goroutine access and no
// other goroutine feeds the Waiter.
//
// Dial contract: Dial must return a usable Subscriber or an
// error. A nil Subscriber (nil, or a typed nil inside the
// interface) is treated as a transport failure, never a panic
// (see isNilSubscriber); a Dial that returns a non-nil
// Subscriber must honor Close and SubscribeRaw on it.
//
// Panic contract: a Subscriber MUST NOT panic. The Runner
// calls SubscribeRaw and Close synchronously with no recover
// in this package, so a panic from a contract-violating
// Subscriber propagates out of `Run`. The CLI-boundary recover
// exists in Run (R2 decision): a panic anywhere on the dispatch
// path converts to exit 2 with a redacted error message and no
// secret-bearing stack, so the CLI path is covered by it; the
// recover is in the CLI boundary (wiring step, not this
// package), and none is added here.
type Subscriber interface {
	SubscribeRaw(ctx context.Context, method string, opts conn.SubscribeOptions) ([][]byte, error)
	Close() error
}

// conn.Gateway must satisfy Subscriber: the Runner's Dial
// closures return gateways, and this assertion fails the build
// if the Gateway contract ever drifts from the narrowed one.
var _ Subscriber = (conn.Gateway)(nil)

// isNilSubscriber reports whether s is nil or holds a nil
// value: a typed-nil pointer inside the Subscriber interface
// (a Dial returning (*fakeGateway)(nil), say) compares non-nil
// against the interface, and only reflection sees through it.
// The Runner treats such a Subscriber as a transport failure,
// never a panic. Dial's contract is to return a usable
// Subscriber or an error; this guard is the fail-closed backstop
// for a Dial that breaks it.
func isNilSubscriber(s Subscriber) bool {
	if s == nil {
		return true
	}
	v := reflect.ValueOf(s)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return v.IsNil()
	default:
		return false
	}
}

// Config configures a Runner. Zero values take the defaults
// above; a negative duration disables that timer (watchdog,
// safety-net cadence) for RecheckAfter and CheckEvery only. Every
// other negative duration is clamped to its default in NewRunner:
// a negative budget or pause is a misconfiguration, not a
// disable. Timeout <= 0 means DefaultTimeout.
// HistoryLimits nil or empty means DefaultHistoryLimits()
// (a fresh copy per Runner: the Runner never aliases the shared
// defaults). Clock nil means the real clock.
//
// There is no OnlineGrace field: the 3 s online-idle grace is a
// fixed protocol constant (DefaultOnlineGrace), not a
// caller-tunable timer.
//
// NodeID is the caller-supplied stable per-profile identity (see
// NODE_ID.md). The Runner carries it, never generates, persists
// or rotates it, and never sends it: the send path (deferred
// wiring) reads it from the Result. An empty NodeID means the
// caller supplied none; the Runner invents nothing.
//
// Approver is the wait core's Approver func. The records its
// calls produce (approved + errors) are accumulated by the
// Waiter and copied into Result.AutoApproved /
// Result.AutoApproveErrors. The Runner has no logger and writes
// nothing to stderr: the caller (the CLI wiring) logs those
// records from the Result.
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

	// beforeFinalGuard is a test-only hook, invoked synchronously
	// on the Runner's goroutine immediately before the final
	// guard in finish, with finish's ctx. It is unexported so no
	// caller outside this package can set it, and it is nil in
	// production. A test sets it in the Config literal before
	// NewRunner and must not mutate it after Run starts.
	beforeFinalGuard func(ctx context.Context)
}

// Result is the wait's endgame result, mirroring the Python
// result dict. Empty strings mean "none" (no status was ever
// stored, no final text, no input reason). Status is the
// Waiter's last stored status (running or terminal) regardless
// of kind — including KindApproval, where Python reports
// w.status too. AutoApproved and AutoApproveErrors carry the
// auto-approve records (Python's auto_approved /
// auto_approve_errors) when an approver ran; they are empty
// otherwise. The caller logs them to stderr: the Runner has no
// logger and the core never writes to stderr.
type Result struct {
	Kind              Kind
	Outcome           string
	Status            string
	AfterSeq          int64
	FinalText         string
	Replies           []Reply
	FinalReadFailed   bool
	Note              string
	Approvals         []approvals.DescribedApproval
	NeedsInputReason  string
	Question          string
	ExitCode          int
	NodeID            string
	AutoApproved      []approvals.ApprovedRecord
	AutoApproveErrors []*approvals.ApproveError
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
	if cfg.StateCheckBudget < 0 {
		cfg.StateCheckBudget = DefaultStateCheckBudget
	}
	if cfg.ReconnectBudget < 0 {
		cfg.ReconnectBudget = DefaultReconnectBudget
	}
	if cfg.ResubPause < 0 {
		cfg.ResubPause = DefaultResubPause
	}
	if cfg.FinalReadFloor < 0 {
		cfg.FinalReadFloor = DefaultFinalReadFloor
	}
	if cfg.LagWindow < 0 {
		cfg.LagWindow = DefaultLagWindow
	}
	if cfg.LagPoll < 0 {
		cfg.LagPoll = DefaultLagPoll
	}
	// A nil or explicitly empty HistoryLimits means "unset":
	// an empty slice would otherwise disable every history
	// proof (no windows to read). DefaultHistoryLimits
	// returns a fresh copy, so the Runner never aliases the
	// shared defaults.
	if len(cfg.HistoryLimits) == 0 {
		cfg.HistoryLimits = DefaultHistoryLimits()
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
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if isAuthError(err) {
			return err
		}
		r.failures++
		return r.noteFailure(ctx)
	}
	if isNilSubscriber(sub) {
		// A Dial that returns a nil Subscriber (nil, or a
		// typed nil inside the interface) is a transport
		// failure, never a panic: resubscribe with backoff
		// like any other failed dial.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.failures++
		return r.noteFailure(ctx)
	}
	// Close is deferred, not called after SubscribeRaw: a
	// panic in SubscribeRaw must not skip the close Python's
	// finally guarantees.
	defer func() { _ = sub.Close() }()
	opts := conn.SubscribeOptions{
		Body:           r.subscribeBody(),
		MaxRecords:     1000000000,
		IdleTimeout:    idle,
		OverallTimeout: left,
		OnRecord:       r.onRecord(ctx),
		ShouldStop:     r.shouldStop(ctx),
	}
	_, subErr := sub.SubscribeRaw(ctx, "chat.subscribe", opts)
	if subErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if isAuthError(subErr) {
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
		ev := decodeRecord(record)
		if ev != nil {
			r.waiter.Feed(ev)
			if ferr := r.waiter.FatalErr(); ferr != nil {
				r.pendingErr = ferr
				return true
			}
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
//
// The throttle key is the terminal plus its ignored reason,
// not the terminal alone as in Python: when the reason clears
// (the F8 re-arm), the settle gates change, so the proof is
// re-attempted instead of waiting for a new terminal or a
// server check. The extra read is outcome-equivalent — Settle
// still applies every gate — it only settles sooner.
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
// when a history read fails, an AuthError when auth failed,
// ctx.Err() when the context died before the proof was applied,
// or nil when the proof was attempted (whether or not it
// accepted). A successful proof is never applied after
// cancellation: the ctx check sits immediately before each
// apply site, so a cancelled wait settles nothing.
func (r *Runner) settlePending(ctx context.Context, pending string) error {
	hctx, cancel := r.historyCtx(ctx, 100*time.Millisecond, nil)
	defer cancel()
	if failed[pending] {
		latest, found, err := LatestUserSeq(hctx, r.cfg.History, r.cfg.HistoryLimits, r.afterSeq)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if isAuthError(err) {
				return err
			}
			return fmt.Errorf("%w: %w", errHistoryRead, err)
		}
		if !found {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if term, ok := r.waiter.IgnoredTerminal(); ok && term == pending && r.waiter.Result() == nil {
			r.waiter.AcceptReplayedFailed(&latest)
		}
		return nil
	}
	replies, err := HistoryReplies(hctx, r.cfg.History, r.cfg.HistoryLimits, r.afterSeq)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if isAuthError(err) {
			return err
		}
		return fmt.Errorf("%w: %w", errHistoryRead, err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
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
// propagates — and except for a transient history-read failure
// in the settle, which is swallowed exactly as trySettle
// swallows it: only AuthError and context errors propagate from
// the settle. No network I/O happens while applying: the state
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
	if isNilSubscriber(sub) {
		// (nil, nil) — or a typed nil — from Dial is a
		// silent transport failure here, as in
		// subscribeOnce: never a panic.
		return nil
	}
	// Close is deferred, not called after SubscribeRaw: a
	// panic in SubscribeRaw must not skip the close Python's
	// finally guarantees.
	defer func() { _ = sub.Close() }()
	var found []Event
	opts := conn.SubscribeOptions{
		Body:           r.subscribeBody(),
		MaxRecords:     50,
		IdleTimeout:    budget,
		OverallTimeout: budget,
		OnRecord: func(record []byte) bool {
			if ev := decodeRecord(record); ev != nil {
				if TaskStatusInfo(ev, r.cfg.Thread) != nil {
					found = append(found, ev)
				}
			}
			return false
		},
		ShouldStop: func() bool { return cctx.Err() != nil },
	}
	_, subErr := sub.SubscribeRaw(cctx, "chat.subscribe", opts)
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
		if ferr := r.waiter.FatalErr(); ferr != nil {
			return ferr
		}
		r.ratchet()
	}
	if running {
		r.lastProgress = r.clock.Now()
	}
	pending, ok := r.waiter.IgnoredTerminal()
	if !ok || r.waiter.Result() != nil {
		return nil
	}
	if err := r.settlePending(ctx, pending); err != nil {
		if errors.Is(err, errHistoryRead) {
			return nil
		}
		return err
	}
	return nil
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
		if ignored, ok := r.waiter.IgnoredTerminal(); ok && failed[ignored] {
			hctx, cancel := r.historyCtx(ctx, r.cfg.FinalReadFloor, nil)
			latest, found, err := LatestUserSeq(hctx, r.cfg.History, r.cfg.HistoryLimits, r.afterSeq)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if isAuthError(err) {
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
			// A read that succeeded after cancellation
			// must not become a result: the wait is dead,
			// whatever the reader returned.
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			replies = rs
			finalReadFailed = false
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if isAuthError(err) {
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
				// Cancellation during the endgame
				// propagates, as Python's BaseException
				// does out of _run_wait: never a Done/0
				// result for a wait the caller stopped.
				return nil, ctx.Err()
			}
			if remaining <= 0 || ctx.Err() != nil {
				break
			}
			capDur := remaining
			hctx, cancel := r.historyCtx(ctx, 100*time.Millisecond, &capDur)
			rs, err := HistoryReplies(hctx, r.cfg.History, r.cfg.HistoryLimits, r.afterSeq)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				// A failed poll ends the window without
				// failing the done result.
				break
			}
			replies = rs
			if len(replies) > 0 {
				break
			}
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if finalReadFailed && kind == KindDone {
		kind = KindTimeout
		detail, _ = r.waiter.Status()
	}
	note := ""
	if r.waiter.BoundaryUnknown() {
		replies = nil
		note = "turn-end boundary unknown: history could not be read, so no replies are reported; run `castctl wait` again"
	}
	if finalReadFailed {
		// The final-read note wins over the boundary note, as in
		// the Python result construction.
		note = "could not read the final replies; run `castctl wait` again"
	}
	if kind == KindApproval {
		// An approval Outcome carries no Detail; the status
		// is the Waiter's last stored status, as Python
		// reports w.status regardless of kind.
		if status, ok := r.waiter.Status(); ok {
			detail = status
		}
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
	// Auto-approve records, for the caller to log to stderr
	// from (the core never logs): empty when no approver ran.
	res.AutoApproved = r.waiter.ApprovedRecords()
	res.AutoApproveErrors = r.waiter.ApproveErrors()
	if outcome == "needs_input" && len(replies) > 0 {
		last := replies[len(replies)-1]
		if len(last.Widgets) > 0 {
			res.NeedsInputReason = "widget"
		} else {
			res.NeedsInputReason = NeedsInputReason(last.Text)
		}
		res.Question = QuestionOf(last.Text)
	}
	// Final guard: this check is the linearization point of
	// the endgame. A cancel that lands after this read
	// linearizes after the return, so no check-then-return
	// sequence can demand zero Done/0 outcomes under
	// arbitrary scheduling: preemption between this read and
	// the return stretches the single-branch window
	// arbitrarily. Cancellation ordered before this read —
	// injected synchronously during any history read,
	// including the lag loop — always yields ctx.Err(),
	// pinned deterministically by
	// TestRunnerFinishCancelDuringLagReadReturnsCtxErr and
	// the final-read/last-chance cancel tests; this guard's
	// position, immediately before `return res, nil` with
	// nothing between but the beforeFinalGuard invocation
	// and the branch, is pinned deterministically by
	// TestRunnerFinishFinalGuardReturnsCtxErr.
	if r.cfg.beforeFinalGuard != nil {
		r.cfg.beforeFinalGuard(ctx)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return res, nil
}

func isAuthError(err error) bool {
	var authErr *conn.AuthError
	return errors.As(err, &authErr)
}
