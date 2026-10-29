// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package approvals is the pure port of the shared auto-decision
// helper from wait.py (muse-cli 0.6.1): describing one pending
// approval, and choosing the decision an auto-approver may send.
//
// No I/O, no clock, no network. The decide call itself
// (egress.approval.decide) is transport and lives with the caller:
// the caller supplies a Decider, and AutoApprover calls it at most
// once per approval. Decide is not idempotent, so a lost reply must
// never be re-decided blindly; nothing in this package retries it.
//
// Policy lives with the caller: ChooseAutoDecision only reads the
// offered options. It never picks options[0], never picks
// allow_session/allow_today, and never restricts by kind.
package approvals

import (
	"context"
	"fmt"
	"strings"
)

// Forever is Muse's "forever" / "Always allow" choice.
const Forever = "allow_always"

// Once is Muse's "Allow once" choice.
const Once = "allow_once"

// DescribedApproval is one pending approval, described for a human
// or an auto-approver. Nil pointer fields mean the source had no
// value (Python None); Options is nil when the server listed none.
type DescribedApproval struct {
	ApprovalID  *string
	Title       *string
	Question    *string
	Kind        *string
	Scope       *string
	Why         *string
	ExpiresAtMS *float64
	Options     []string
}

// DescribeApproval describes one approval and never panics on
// malformed input: a non-map approval (or non-map display /
// permission_question / payload) degrades to empty fields with a
// nil ApprovalID instead of failing the wait.
func DescribeApproval(a any) DescribedApproval {
	m, ok := a.(map[string]any)
	if !ok {
		return DescribedApproval{}
	}
	display := subMap(m["display"])
	question := subMap(display["permission_question"])
	payload := subMap(m["payload"])
	rows := map[string]any{}
	if list, ok := display["detail_rows"].([]any); ok {
		for _, r := range list {
			if rm, ok := r.(map[string]any); ok {
				if label, ok := rm["label"].(string); ok {
					rows[label] = rm["value"]
				}
			}
		}
	}
	var options []string
	if list, ok := m["decision_options"].([]any); ok {
		for _, o := range list {
			if om, ok := o.(map[string]any); ok {
				if kind, ok := om["kind"].(string); ok && kind != "" {
					options = append(options, kind)
				}
			}
		}
	}
	if len(options) == 0 {
		options = nil
	}
	return DescribedApproval{
		ApprovalID:  stringPtr(m["approval_id"]),
		Title:       firstString(display["summary_title"], display["display_name"]),
		Question:    questionText(question["text"]),
		Kind:        firstString(question["kind"], payload["type"]),
		Scope:       firstString(question["scope"], rows["Host"]),
		Why:         firstString(display["short_explanation"], display["reason"], m["reason"]),
		ExpiresAtMS: expiresAtMS(m["request_expires_at_ms"]),
		Options:     options,
	}
}

// subMap returns v when it is a map, else an empty map.
func subMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// stringPtr returns a pointer to v when v is a string, else nil.
// An empty string is still a present id: Python treats "" as not
// None, so it is offered to the approver like any other id.
func stringPtr(v any) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

// firstString returns the first non-empty string among vs, else nil.
// Non-string values are skipped: the wire fields are strings, and a
// non-string value carries no display text.
func firstString(vs ...any) *string {
	for _, v := range vs {
		if s, ok := v.(string); ok && s != "" {
			return &s
		}
	}
	return nil
}

// questionText applies the "{assistant}" -> "Muse" replacement and
// returns nil when the result is empty.
func questionText(v any) *string {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	replaced := strings.ReplaceAll(s, "{assistant}", "Muse")
	if replaced == "" {
		return nil
	}
	return &replaced
}

// expiresAtMS converts a raw expiry to milliseconds since the epoch.
// Only numbers count (Python: isinstance(exp, (int, float))); a bool
// is an int in Python, so true counts as 1 and false as 0. Any other
// type means "no expiry" and is treated as not expired.
func expiresAtMS(v any) *float64 {
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case float32:
		f = float64(n)
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	case int32:
		f = float64(n)
	case uint64:
		f = float64(n)
	case bool:
		if n {
			f = 1
		}
	case string:
		// Numeric strings are not numbers in Python either.
		return nil
	default:
		// json.Number and anything else: try the fmt-free path via
		// the number interface used by encoding/json decoding.
		if num, ok := v.(interface{ Float64() (float64, error) }); ok {
			if fv, err := num.Float64(); err == nil {
				f = fv
			} else {
				return nil
			}
		} else {
			return nil
		}
	}
	return &f
}

// OffersForever reports whether the approval can be decided with
// the forever choice. Approvals that list no options (older
// servers) are assumed to accept it.
func OffersForever(d DescribedApproval) bool {
	if len(d.Options) == 0 {
		return true
	}
	for _, o := range d.Options {
		if o == Forever {
			return true
		}
	}
	return false
}

// OffersOnce reports whether allow_once is explicitly listed in
// the options. It is false when no options are listed.
func OffersOnce(d DescribedApproval) bool {
	for _, o := range d.Options {
		if o == Once {
			return true
		}
	}
	return false
}

// ChooseAutoDecision returns the decision an auto-approver may
// send, or ("", false) to leave the approval for a human.
//
// allow_always wins when offered (or when no options are listed
// at all). Otherwise allow_once, only when the caller explicitly
// enabled the fallback (allowOnce) and auto-approve is on. An
// approval listing no options keeps the offers-forever assumption;
// it is not turned into allow_once.
func ChooseAutoDecision(d DescribedApproval, autoApprove, allowOnce bool) (string, bool) {
	if !autoApprove {
		return "", false
	}
	if OffersForever(d) {
		return Forever, true
	}
	if allowOnce && OffersOnce(d) {
		return Once, true
	}
	return "", false
}

// Approver decides new pending approvals and returns the ids it
// handled. It is called synchronously by the wait core; an error
// return means the approver failed, and every id it was offered in
// that call is never offered again.
type Approver func(items []DescribedApproval) ([]string, error)

// Decider performs one egress.approval.decide call. It must be
// called at most once per approval: AutoApprover never retries it.
type Decider func(ctx context.Context, approval DescribedApproval, decision string) error

// ApprovedRecord is one successful auto-approval, in the shape the
// result object reports.
type ApprovedRecord struct {
	ApprovalID string
	Title      string
	Kind       string
	Scope      string
	Decision   string
}

// ApproveError is one approval the auto-approver could not decide:
// a skipped approval (no decision), a failed decide, or a
// connector failure before any decide.
type ApproveError struct {
	ApprovalID string
	Title      string
	Kind       string
	Scope      string
	Decision   string
	Err        error
}

func (e *ApproveError) Error() string {
	return fmt.Sprintf("auto-approve %s: %v", e.ApprovalID, e.Err)
}

func (e *ApproveError) Unwrap() error { return e.Err }

// AutoApprover is the wait core's approver: it opens one fresh
// connection per Approve call (through Connect), decides each item
// once with ChooseAutoDecision, records successes, and records (but
// never retries) failures. A skipped approval is warned about once
// per id: the warning is the ApproveError entry, emitted only on
// the first skip; later skips of the same id produce no entry but
// the approval stays undecided.
//
// A connector failure before any decide records an error for every
// item and returns no handled ids.
type AutoApprover struct {
	connect   func(ctx context.Context) (Decider, func(), error)
	allowOnce bool
	warned    map[string]bool
}

// NewAutoApprover builds an AutoApprover. Connect opens one fresh
// connection and returns its Decider plus a close function; the
// close function runs even when deciding fails, and is never
// called when Connect itself fails.
func NewAutoApprover(connect func(ctx context.Context) (Decider, func(), error), allowOnce bool) *AutoApprover {
	return &AutoApprover{connect: connect, allowOnce: allowOnce, warned: map[string]bool{}}
}

// Approve decides items. It returns the handled ids, the approved
// records, and the errors, in item order. A Decider is invoked at
// most once per item in this call, and never for an item with no
// decision.
func (a *AutoApprover) Approve(ctx context.Context, items []DescribedApproval) (handled []string, approved []ApprovedRecord, errs []*ApproveError) {
	decide, closeConn, err := a.connect(ctx)
	if err != nil {
		for _, item := range items {
			errs = append(errs, a.errFor(item, "", err))
		}
		return nil, nil, errs
	}
	defer closeConn()
	for _, item := range items {
		decision, ok := ChooseAutoDecision(item, true, a.allowOnce)
		rec := ApprovedRecord{
			ApprovalID: deref(item.ApprovalID),
			Title:      deref(item.Title),
			Kind:       deref(item.Kind),
			Scope:      deref(item.Scope),
			Decision:   decision,
		}
		if !ok {
			if id := deref(item.ApprovalID); !a.warned[id] {
				a.warned[id] = true
				errs = append(errs, a.errFor(item, "", fmt.Errorf("no forever option (offers %v)", item.Options)))
			}
			continue
		}
		if err := decide(ctx, item, decision); err != nil {
			errs = append(errs, a.errFor(item, decision, err))
			continue
		}
		approved = append(approved, rec)
		handled = append(handled, deref(item.ApprovalID))
	}
	return handled, approved, errs
}

// AsApprover adapts this AutoApprover to the wait core's Approver
// shape, deciding on a background context. An error return marks
// every offered id as approver-failed in the waiter, so the
// connection error surfaces once as an approval result for a
// human rather than being retried.
func (a *AutoApprover) AsApprover() Approver {
	return func(items []DescribedApproval) ([]string, error) {
		handled, _, errs := a.Approve(context.Background(), items)
		if len(errs) > 0 && len(handled) == 0 && len(items) > 0 {
			// Surface the first failure so the waiter records the
			// offered ids as approver-failed instead of silently
			// leaving them undecided on every snapshot.
			return handled, errs[0]
		}
		return handled, nil
	}
}

func (a *AutoApprover) errFor(item DescribedApproval, decision string, err error) *ApproveError {
	return &ApproveError{
		ApprovalID: deref(item.ApprovalID),
		Title:      deref(item.Title),
		Kind:       deref(item.Kind),
		Scope:      deref(item.Scope),
		Decision:   decision,
		Err:        err,
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
