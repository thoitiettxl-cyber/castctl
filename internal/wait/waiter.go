// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/approvals"
)

// Terminal vocabularies, verbatim from wait.py. Only "completed"
// (DONE) and the FAILED strings are proven terminal values; every
// other TERMINAL string is suspect and ends the wait only with
// history proof. All comparisons happen after lower-casing in
// TaskStatusInfo; " completed " (with spaces) does not match, and
// no stripping is done anywhere.
var (
	// Done holds the proven-done status.
	Done = map[string]bool{"completed": true}
	// Failed holds the proven-failed statuses, retained from the
	// pre-existing cancel flow.
	Failed = map[string]bool{"interrupted": true, "cancelled": true, "canceled": true}
	// SuspectDone holds suspect done-like statuses.
	SuspectDone = map[string]bool{"idle": true, "complete": true, "done": true, "finished": true, "succeeded": true, "success": true}
	// SuspectFailed holds suspect failed-like statuses.
	SuspectFailed = map[string]bool{"failed": true, "failure": true, "error": true, "errored": true, "aborted": true, "timed_out": true}
	// Terminal is the union of all four sets (16 distinct strings).
	Terminal = map[string]bool{
		"completed": true, "interrupted": true, "cancelled": true, "canceled": true,
		"idle": true, "complete": true, "done": true, "finished": true, "succeeded": true, "success": true,
		"failed": true, "failure": true, "error": true, "errored": true, "aborted": true, "timed_out": true,
	}
)

// Outcome is a decided turn end: KindDone or KindFailed with Detail
// set to the terminal status string, or KindApproval with
// Approvals set to the described pending approvals.
type Outcome struct {
	Kind      Kind
	Detail    string
	Approvals []approvals.DescribedApproval
}

// TaskStatus is the extracted fact from one task.status event,
// or nil-equivalent when the event is not a usable root task
// status. Subagent events (root and agent both present, agent !=
// root) return no info at all: they teach nothing, not even the
// F8 re-arm.
type TaskStatus struct {
	Status              string
	HasStatus           bool
	RootConfirmed       bool
	RootAgentID         string
	AgentID             string
	ActiveSubagentCount any
}

// TaskStatusInfo extracts the task-status facts from ev for the
// given thread scope. The status is lower-cased; a missing or
// falsy status yields HasStatus false while the info is still
// returned (when the event passed the name/scope/subagent
// checks).
func TaskStatusInfo(ev Event, thread string) *TaskStatus {
	if ev == nil || eventName(ev) != "task.status" || !inScope(ev, thread) {
		return nil
	}
	p := payload(ev)
	root, _ := p["root_agent_id"].(string)
	agent, _ := p["agent_id"].(string)
	rootPresent := truthy(p["root_agent_id"])
	agentPresent := truthy(p["agent_id"])
	if rootPresent && agentPresent && agent != root {
		return nil
	}
	info := &TaskStatus{
		RootConfirmed:       rootPresent && agent == root,
		RootAgentID:         root,
		AgentID:             agent,
		ActiveSubagentCount: p["active_subagent_count"],
	}
	if s, ok := p["status"].(string); ok && s != "" {
		info.Status = strings.ToLower(s)
		info.HasStatus = true
	} else if truthy(p["status"]) {
		// A non-string truthy status stringifies, as Python's
		// str(s).lower() does. Non-string falsy values (0,
		// false) yield no status.
		info.Status = strings.ToLower(stringifyStatus(p["status"]))
		info.HasStatus = info.Status != ""
	}
	return info
}

func stringifyStatus(v any) string {
	switch t := v.(type) {
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return ""
	default:
		if b, err := json.Marshal(v); err == nil {
			return strings.Trim(string(b), `"`)
		}
		return ""
	}
}

// TaskStatusString returns just the status string, or "" when the event
// carries no usable task status.
func TaskStatusString(ev Event, thread string) string {
	if info := TaskStatusInfo(ev, thread); info != nil {
		return info.Status
	}
	return ""
}

// Option configures a Waiter.
type Option func(*Waiter)

// WithRequireRunning stores the require_running flag. It is a dead
// parameter: stored, never read by any decision, preserved only
// so callers (wait --require-running, send --wait) keep passing
// it. No behaviour is invented for it.
func WithRequireRunning(requireRunning bool) Option {
	return func(w *Waiter) { w.requireRunning = requireRunning }
}

// WithApprover sets the optional approver callable.
func WithApprover(approver approvals.Approver) Option {
	return func(w *Waiter) { w.approver = approver }
}

// WithNow sets the wall-clock source used only for the approval
// expiry comparison (_expired). Every other decision in the
// Waiter is clock-free. Tests inject a fixed now to pin expiry.
func WithNow(now func() time.Time) Option {
	return func(w *Waiter) {
		if now != nil {
			w.now = now
		}
	}
}

// Waiter is the pure turn-end state machine. Feed it events in
// arrival order: the same event sequence in a different order
// yields different outcomes, by design (replay protection).
//
// The Waiter is not safe for concurrent use; the driver serialises
// all feeds through one goroutine. It never dials, never reads
// history, and never generates a node_id: the driver owns the
// connection and the identity.
//
// Deviation D1 (documented, deliberate): once Result is set, Feed,
// Settle and AcceptReplayedFailed refuse to change it. In Python
// 0.6.1 the guard lives in the driver (which stops feeding), and a
// bare Waiter fed after a result can overwrite it. The observable
// behaviour under any driver is identical; the Go state machine
// itself enforces the invariant so a caller that feeds late cannot
// flip a decided turn.
type Waiter struct {
	thread            string
	requireRunning    bool
	approver          approvals.Approver
	now               func() time.Time
	handled           map[string]bool
	offered           map[string]bool
	approverFailed    map[string]bool
	seenRunning       bool
	result            *Outcome
	status            *string
	ignoredTerminal   *string
	ignoredReason     string
	ignoredTermSeq    int64
	ignoredTermHasSeq bool
	rootID            *string
	boundaryUnknown   bool
	runningSeq        *int64
	afterSeq          *int64
	boundaryDerived   bool
}

// New builds a Waiter scoped to thread ("" means unscoped: the
// payload is_thread rule applies).
func New(thread string, opts ...Option) *Waiter {
	w := &Waiter{
		thread:         thread,
		now:            time.Now,
		handled:        map[string]bool{},
		offered:        map[string]bool{},
		approverFailed: map[string]bool{},
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Thread returns the scope thread.
func (w *Waiter) Thread() string { return w.thread }

// RequireRunning returns the stored dead flag.
func (w *Waiter) RequireRunning() bool { return w.requireRunning }

// Result returns the decided outcome, or nil while waiting. The
// returned Outcome is a copy; mutating it does not affect the
// Waiter.
func (w *Waiter) Result() *Outcome {
	if w.result == nil {
		return nil
	}
	cp := *w.result
	if w.result.Approvals != nil {
		cp.Approvals = append([]approvals.DescribedApproval(nil), w.result.Approvals...)
	}
	return &cp
}

// SeenRunning reports whether a root-confirmed running for the
// learned root was seen.
func (w *Waiter) SeenRunning() bool { return w.seenRunning }

// Status returns the last stored status (running or terminal
// only), and whether any was stored.
func (w *Waiter) Status() (string, bool) {
	if w.status == nil {
		return "", false
	}
	return *w.status, true
}

// IgnoredTerminal returns the stored ignored terminal status, if any.
func (w *Waiter) IgnoredTerminal() (string, bool) {
	if w.ignoredTerminal == nil {
		return "", false
	}
	return *w.ignoredTerminal, true
}

// IgnoredReason returns "subagents", "missing_root", or "".
func (w *Waiter) IgnoredReason() string { return w.ignoredReason }

// IgnoredTerminalSeq returns the seq of the ignored terminal
// record, if it carried a numeric one. Stored only; never proof.
func (w *Waiter) IgnoredTerminalSeq() (int64, bool) {
	return w.ignoredTermSeq, w.ignoredTermHasSeq
}

// RootID returns the learned root id, if any.
func (w *Waiter) RootID() (string, bool) {
	if w.rootID == nil {
		return "", false
	}
	return *w.rootID, true
}

// BoundaryUnknown reports whether the history boundary is unreadable.
func (w *Waiter) BoundaryUnknown() bool { return w.boundaryUnknown }

// RunningSeq returns the seq of the first root-confirmed running,
// if the record carried a numeric one.
func (w *Waiter) RunningSeq() (int64, bool) {
	if w.runningSeq == nil {
		return 0, false
	}
	return *w.runningSeq, true
}

// AfterSeq returns the wait's boundary seq, if set.
func (w *Waiter) AfterSeq() (int64, bool) {
	if w.afterSeq == nil {
		return 0, false
	}
	return *w.afterSeq, true
}

// BoundaryDerived reports whether the boundary was derived from
// history by a standalone wait.
func (w *Waiter) BoundaryDerived() bool { return w.boundaryDerived }

// SetBoundary installs the driver-owned boundary: the boundary
// seq, whether it is unknown, and whether it was derived.
func (w *Waiter) SetBoundary(afterSeq int64, unknown, derived bool) {
	w.afterSeq = &afterSeq
	w.boundaryUnknown = unknown
	w.boundaryDerived = derived
}

// SetAfterSeq moves the boundary seq (the ratchet: a live root
// running ratchets after_seq up when the boundary was never
// read). It never moves the boundary backwards.
func (w *Waiter) SetAfterSeq(seq int64) {
	if w.afterSeq == nil || seq > *w.afterSeq {
		w.afterSeq = &seq
	}
}

// expired reports whether a described approval is past its
// server epoch-millisecond expiry, compared against wall time:
// the compared value is itself a wall timestamp, so this is the
// one legitimate wall-clock comparison in the pure layer.
// Non-numeric expiry is treated as not expired; a bool expiry
// counts as 1 (true) or 0 (false), as in Python.
func (w *Waiter) expired(d approvals.DescribedApproval) bool {
	if d.ExpiresAtMS == nil {
		return false
	}
	return *d.ExpiresAtMS <= float64(w.now().UnixMilli())
}

// pendingApprovals extracts the pending list from an approvals
// event, or nil. Only events whose name starts with "approvals"
// count; pending_approvals is preferred and an explicitly empty
// list does not fall back to "pending".
func pendingApprovals(ev Event) []any {
	if !strings.HasPrefix(eventName(ev), "approvals") {
		return nil
	}
	p := payload(ev)
	pend, ok := p["pending_approvals"]
	if pend == nil {
		pend, ok = p["pending"]
		_ = ok
	}
	list, ok := pend.([]any)
	if !ok {
		return nil
	}
	return list
}

// Feed feeds one event and returns the decided outcome when this
// feed sets one, else nil. Steps run in order and the order
// matters: approvals first (a pending approval ends the wait
// without ever looking at the task status in the same event),
// then the F8 re-arm, running, non-terminal, foreign-root,
// subagent-count, unconfirmed, proven-terminal and suspect
// steps. Once a result is set (deviation D1), Feed is a no-op
// returning the existing result.
func (w *Waiter) Feed(ev Event) *Outcome {
	if w.result != nil {
		return w.Result()
	}
	if pend := pendingApprovals(ev); len(pend) > 0 {
		return w.feedApprovals(ev, pend)
	}
	info := TaskStatusInfo(ev, w.thread)
	if info == nil || !info.HasStatus {
		return nil
	}
	// F8 re-arm: runs for every info event that reaches here,
	// including non-terminal, running, foreign-root and
	// unconfirmed events, before any step below. Only the
	// reason is cleared; the terminal itself is kept.
	if w.ignoredReason == "subagents" && countIsZero(info.ActiveSubagentCount) {
		w.ignoredReason = ""
	}
	s := info.Status
	if s == "running" {
		if info.RootConfirmed {
			if w.rootID == nil {
				root := info.RootAgentID
				w.rootID = &root
			}
			if info.RootAgentID == *w.rootID {
				w.seenRunning = true
				w.ignoredTerminal = nil
				w.ignoredReason = ""
				w.ignoredTermSeq = 0
				w.ignoredTermHasSeq = false
				w.boundaryUnknown = false
				if w.runningSeq == nil && hasSeq(ev) {
					seq := seqOf(ev)
					w.runningSeq = &seq
				}
			}
		}
		w.status = &s
		return nil
	}
	if !Terminal[s] {
		return nil
	}
	// Foreign root: teaches nothing, status not updated. (The
	// F8 re-arm above already ran.)
	if w.rootID != nil && info.RootAgentID != "" && info.RootAgentID != *w.rootID {
		return nil
	}
	w.status = &s
	if truthy(info.ActiveSubagentCount) {
		w.storeIgnored(s, "subagents", ev)
		return nil
	}
	if !info.RootConfirmed {
		w.storeIgnored(s, "missing_root", ev)
		return nil
	}
	if Done[s] || Failed[s] {
		if w.seenRunning {
			w.result = &Outcome{Kind: KindFailed, Detail: s}
			if Done[s] {
				w.result.Kind = KindDone
			}
			return w.Result()
		}
		w.storeIgnored(s, "", ev)
		return nil
	}
	// Suspect string: history proof required, even with
	// seen_running.
	w.storeIgnored(s, "", ev)
	return nil
}

func (w *Waiter) storeIgnored(s, reason string, ev Event) {
	w.ignoredTerminal = &s
	w.ignoredReason = reason
	if hasSeq(ev) {
		w.ignoredTermSeq = seqOf(ev)
		w.ignoredTermHasSeq = true
	} else {
		w.ignoredTermSeq = 0
		w.ignoredTermHasSeq = false
	}
}

// feedApprovals runs the approval path of Feed.
func (w *Waiter) feedApprovals(ev Event, pend []any) *Outcome {
	p := payload(ev)
	recent := map[string]bool{}
	for _, key := range []string{"recent_approvals", "recent"} {
		if lst, ok := p[key].([]any); ok {
			for _, e := range lst {
				if em, ok := e.(map[string]any); ok {
					if id, ok := em["approval_id"].(string); ok && id != "" && truthy(em["decision"]) {
						recent[id] = true
					}
				}
			}
		}
	}
	described := make([]approvals.DescribedApproval, 0, len(pend))
	for _, a := range pend {
		d := approvals.DescribeApproval(a)
		if recent[derefID(d.ApprovalID)] {
			w.handled[derefID(d.ApprovalID)] = true
		}
		if !w.expired(d) {
			described = append(described, d)
		}
	}
	if w.approver != nil {
		var fresh []approvals.DescribedApproval
		for _, d := range described {
			id := derefID(d.ApprovalID)
			if d.ApprovalID == nil || w.offered[id] || w.approverFailed[id] || w.handled[id] {
				continue
			}
			fresh = append(fresh, d)
		}
		if len(fresh) > 0 {
			for _, d := range fresh {
				w.offered[derefID(d.ApprovalID)] = true
			}
			handled, err := w.approver(fresh)
			if err != nil {
				// Decide is not idempotent: a lost reply
				// must never be re-decided blindly. All
				// offered ids go to approver_failed and
				// none is recorded handled, even if the
				// approver decided some before raising.
				for _, d := range fresh {
					w.approverFailed[derefID(d.ApprovalID)] = true
				}
			} else {
				for _, id := range handled {
					w.handled[id] = true
				}
			}
		}
		var left []approvals.DescribedApproval
		for _, d := range described {
			if !w.handled[derefID(d.ApprovalID)] {
				left = append(left, d)
			}
		}
		if len(left) == 0 {
			return nil
		}
		described = left
	} else if len(described) == 0 {
		// Every pending approval is expired: keep waiting.
		return nil
	}
	w.result = &Outcome{Kind: KindApproval, Approvals: described}
	return w.Result()
}

func derefID(id *string) string {
	if id == nil {
		return ""
	}
	return *id
}

// countIsZero reports whether a subagent count equals exactly 0.
// None (absent) does not re-arm; false counts as 0, as Python's
// False == 0 does.
func countIsZero(v any) bool {
	if v == nil {
		return false
	}
	if b, ok := v.(bool); ok {
		return !b
	}
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return err == nil && f == 0
	default:
		return numericFloat(v) == 0 && isNumeric(v)
	}
}

func isNumeric(v any) bool {
	switch v.(type) {
	case float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number:
		return true
	}
	return false
}

// FeedRecord parses one NDJSON record (a JSON object) and feeds
// it. Unparseable input and non-object JSON change no state and
// return nil, as in Python.
func (w *Waiter) FeedRecord(record []byte) *Outcome {
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
	// Trailing data after one JSON value is unparseable input.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil
	}
	ev, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return w.Feed(ev)
}

// Settle accepts the ignored terminal when chat.history already
// holds a reply to the turn's message. All gates are required;
// on any failure the terminal is kept. On success the ignored
// terminal is cleared and the result maps SUSPECT_FAILED to
// failed, anything else stored to done.
func (w *Waiter) Settle(replies []Reply) *Outcome {
	s, ok := w.IgnoredTerminal()
	if w.result != nil || !ok {
		return nil
	}
	if w.boundaryUnknown {
		return nil
	}
	if w.ignoredReason == "subagents" || Failed[s] {
		return nil
	}
	if len(replies) == 0 {
		return nil
	}
	w.clearIgnored()
	kind := KindDone
	if SuspectFailed[s] {
		kind = KindFailed
	}
	w.result = &Outcome{Kind: kind, Detail: s}
	return w.Result()
}

// AcceptReplayedFailed accepts a replayed FAILED terminal that
// provably ends the awaited turn: a standalone wait started after
// a cancel. The proof is the boundary: the boundary was derived,
// is known, the terminal carries no suspect reason, and no user
// message newer than the boundary exists. SUSPECT_FAILED never
// takes this path, and the replayed record's seq is never used:
// stream seqs and history seqs are different namespaces.
func (w *Waiter) AcceptReplayedFailed(latestUserSeq *int64) *Outcome {
	s, ok := w.IgnoredTerminal()
	if w.result != nil || !ok || !Failed[s] {
		return nil
	}
	if w.boundaryUnknown || w.ignoredReason != "" {
		return nil
	}
	if !w.boundaryDerived || w.afterSeq == nil {
		return nil
	}
	if latestUserSeq == nil || *latestUserSeq != *w.afterSeq {
		return nil
	}
	w.clearIgnored()
	w.result = &Outcome{Kind: KindFailed, Detail: s}
	return w.Result()
}

func (w *Waiter) clearIgnored() {
	w.ignoredTerminal = nil
	w.ignoredReason = ""
	w.ignoredTermSeq = 0
	w.ignoredTermHasSeq = false
}
