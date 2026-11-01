// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package approvals

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

func strp(s string) *string { return &s }

// flatDescribed renders a DescribedApproval with pointer values
// dereferenced, for comparable assertions.
func flatDescribed(d DescribedApproval) string {
	return fmt.Sprintf("%q|%q|%q|%q|%q|%q|%v|%v",
		deref(d.ApprovalID), deref(d.Title), deref(d.Question), deref(d.Kind),
		deref(d.Scope), deref(d.Why), d.ExpiresAtMS, d.Options)
}

func TestDescribeApproval(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want DescribedApproval
	}{
		{
			name: "full approval",
			in: map[string]any{
				"approval_id": "ap1",
				"display": map[string]any{
					"summary_title": "Network",
					"permission_question": map[string]any{
						"text": "{assistant} wants net", "kind": "network_access", "scope": "x.com",
					},
					"detail_rows": []any{map[string]any{"label": "Host", "value": "h"}},
				},
				"payload":          map[string]any{"type": "p"},
				"decision_options": []any{map[string]any{"kind": "allow_once"}, map[string]any{"kind": "deny"}},
			},
			want: DescribedApproval{
				ApprovalID: strp("ap1"), Title: strp("Network"),
				Question: strp("Muse wants net"), Kind: strp("network_access"),
				Scope:   strp("x.com"),
				Options: []string{"allow_once", "deny"},
			},
		},
		{
			name: "non-dict approval degrades",
			in:   "junk",
			want: DescribedApproval{},
		},
		{
			name: "display name fallback and host scope fallback",
			in: map[string]any{
				"display": map[string]any{
					"display_name": "Title2",
					"detail_rows":  []any{map[string]any{"label": "Host", "value": "host.example"}},
				},
			},
			want: DescribedApproval{Title: strp("Title2"), Scope: strp("host.example")},
		},
		{
			name: "question scope wins over host row",
			in: map[string]any{
				"display": map[string]any{
					"permission_question": map[string]any{"scope": "qscope"},
					"detail_rows":         []any{map[string]any{"label": "Host", "value": "h"}},
				},
			},
			want: DescribedApproval{Scope: strp("qscope")},
		},
		{
			name: "placeholder-only question text becomes Muse",
			in: map[string]any{
				"display": map[string]any{"permission_question": map[string]any{"text": "{assistant}"}},
			},
			want: DescribedApproval{Question: strp("Muse")},
		},
		{
			name: "empty question text is nil",
			in: map[string]any{
				"display": map[string]any{"permission_question": map[string]any{"text": ""}},
			},
			want: DescribedApproval{Question: nil},
		},
		{
			name: "kind falls back to payload type",
			in:   map[string]any{"payload": map[string]any{"type": "ptype"}},
			want: DescribedApproval{Kind: strp("ptype")},
		},
		{
			name: "why chain",
			in: map[string]any{
				"display": map[string]any{"reason": "dreason"},
				"reason":  "areason",
			},
			want: DescribedApproval{Why: strp("dreason")},
		},
		{
			name: "options drop non-dict and empty kinds, nil when empty",
			in: map[string]any{
				"decision_options": []any{map[string]any{"kind": ""}, "junk", map[string]any{}},
			},
			want: DescribedApproval{},
		},
		{
			name: "non-dict detail rows skipped",
			in: map[string]any{
				"display": map[string]any{"detail_rows": []any{"junk", map[string]any{"label": "Host", "value": "h2"}}},
			},
			want: DescribedApproval{Scope: strp("h2")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DescribeApproval(tt.in)
			if flatDescribed(got) != flatDescribed(tt.want) {
				t.Errorf("DescribeApproval = %v, want %v", flatDescribed(got), flatDescribed(tt.want))
			}
		})
	}
}

func TestChooseAutoDecision(t *testing.T) {
	withOpts := func(opts ...string) DescribedApproval { return DescribedApproval{Options: opts} }
	tests := []struct {
		name       string
		d          DescribedApproval
		auto, once bool
		want       string
		wantOK     bool
	}{
		{"off", withOpts(Forever), false, false, "", false},
		{"forever offered", withOpts(Forever, Once), true, false, Forever, true},
		{"no options assumes forever", DescribedApproval{}, true, false, Forever, true},
		{"once only, fallback off", withOpts(Once), true, false, "", false},
		{"once only, fallback on", withOpts(Once), true, true, Once, true},
		{"forever wins over once", withOpts(Once, Forever), true, true, Forever, true},
		{"deny only", withOpts("deny"), true, true, "", false},
		{"session never picked", withOpts("allow_session"), true, true, "", false},
		{"today never picked", withOpts("allow_today"), true, true, "", false},
		{"first option never picked blindly", withOpts("deny", "allow_session"), true, true, "", false},
		{"no options not turned into once", DescribedApproval{}, true, true, Forever, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ChooseAutoDecision(tt.d, tt.auto, tt.once)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("ChooseAutoDecision = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestOffersForeverAndOnce(t *testing.T) {
	if !OffersForever(DescribedApproval{}) {
		t.Error("no options must offer forever")
	}
	if OffersOnce(DescribedApproval{}) {
		t.Error("no options must not offer once")
	}
	if OffersForever(DescribedApproval{Options: []string{"deny"}}) {
		t.Error("deny-only must not offer forever")
	}
	if !OffersOnce(DescribedApproval{Options: []string{Once}}) {
		t.Error("explicit once must offer once")
	}
}

func TestAutoApproverDecidesEachAtMostOnce(t *testing.T) {
	calls := map[string]int{}
	decide := func(ctx context.Context, a DescribedApproval, decision string) error {
		calls[deref(a.ApprovalID)]++
		return nil
	}
	connect := func(ctx context.Context) (Decider, func(), error) {
		return decide, func() {}, nil
	}
	aa := NewAutoApprover(connect, false)
	items := []DescribedApproval{
		{ApprovalID: strp("a1"), Options: []string{Forever}},
		{ApprovalID: strp("a2"), Options: []string{Once}},
	}
	handled, approved, errs := aa.Approve(context.Background(), items)
	if len(handled) != 1 || handled[0] != "a1" {
		t.Errorf("handled = %v, want [a1]", handled)
	}
	if len(approved) != 1 || approved[0].Decision != Forever {
		t.Errorf("approved = %v", approved)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want 1 skip error", errs)
	}
	if calls["a1"] != 1 || calls["a2"] != 0 {
		t.Errorf("decide calls = %v, want a1:1 a2:0", calls)
	}
	// Second call: a1 is already claimed (decided once per
	// AutoApprover lifetime) and the a2 skip warning fired
	// once already: no re-decide, no new errors.
	handled2, _, errs2 := aa.Approve(context.Background(), items)
	if len(handled2) != 0 || len(errs2) != 0 {
		t.Errorf("second Approve = handled %v errs %v, want none", handled2, errs2)
	}
	if calls["a1"] != 1 {
		t.Errorf("decide calls after second Approve = %v, want a1:1 (claimed, never re-decided)", calls)
	}
	if calls["a2"] != 0 {
		t.Errorf("decide calls after second Approve = %v, want a2:0", calls)
	}
}

func TestAutoApproverOnDecided(t *testing.T) {
	var mu sync.Mutex
	var got []string
	decide := func(ctx context.Context, a DescribedApproval, decision string) error {
		if deref(a.ApprovalID) == "bad" {
			return errors.New("gateway down")
		}
		return nil
	}
	aa := NewAutoApprover(func(ctx context.Context) (Decider, func(), error) {
		return decide, func() {}, nil
	}, false)
	aa.OnDecided = func(id, decision string) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, id+"="+decision)
	}
	handled, _, errs := aa.Approve(context.Background(), []DescribedApproval{
		{ApprovalID: strp("a1"), Options: []string{Forever}},
		{ApprovalID: strp("bad"), Options: []string{Forever}},
	})
	if len(handled) != 1 || handled[0] != "a1" {
		t.Errorf("handled = %v, want [a1]", handled)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want 1 (the failed decide)", errs)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "a1="+Forever {
		t.Errorf("OnDecided calls = %v, want [a1=%s] (success only, never on failure)", got, Forever)
	}
}

func TestAutoApproverDecideFailureIsNotRetried(t *testing.T) {
	calls := 0
	decide := func(ctx context.Context, a DescribedApproval, decision string) error {
		calls++
		return errors.New("gateway down")
	}
	aa := NewAutoApprover(func(ctx context.Context) (Decider, func(), error) {
		return decide, func() {}, nil
	}, false)
	handled, _, errs := aa.Approve(context.Background(), []DescribedApproval{
		{ApprovalID: strp("a1"), Options: []string{Forever}},
	})
	if len(handled) != 0 || len(errs) != 1 || calls != 1 {
		t.Errorf("handled=%v errs=%v calls=%d", handled, errs, calls)
	}
	if errs[0].Err == nil || errs[0].ApprovalID != "a1" {
		t.Errorf("err record = %+v", errs[0])
	}
}

func TestAutoApproverConnectorFailureErrorsEveryItem(t *testing.T) {
	aa := NewAutoApprover(func(ctx context.Context) (Decider, func(), error) {
		return nil, nil, errors.New("connect failed")
	}, false)
	handled, approved, errs := aa.Approve(context.Background(), []DescribedApproval{
		{ApprovalID: strp("a1")}, {ApprovalID: strp("a2")},
	})
	if len(handled) != 0 || len(approved) != 0 || len(errs) != 2 {
		t.Errorf("handled=%v approved=%v errs=%v", handled, approved, errs)
	}
}

func TestAutoApproverAllowOnceFallback(t *testing.T) {
	decided := []string{}
	aa := NewAutoApprover(func(ctx context.Context) (Decider, func(), error) {
		return func(ctx context.Context, a DescribedApproval, decision string) error {
			decided = append(decided, decision)
			return nil
		}, func() {}, nil
	}, true)
	handled, _, _ := aa.Approve(context.Background(), []DescribedApproval{
		{ApprovalID: strp("a1"), Options: []string{Once}},
	})
	if len(handled) != 1 || len(decided) != 1 || decided[0] != Once {
		t.Errorf("handled=%v decided=%v", handled, decided)
	}
}

func TestAutoApproverConcurrentSameIDDecidesOnce(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	decide := func(ctx context.Context, a DescribedApproval, decision string) error {
		mu.Lock()
		calls++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		return nil
	}
	aa := NewAutoApprover(func(ctx context.Context) (Decider, func(), error) {
		return decide, func() {}, nil
	}, false)
	item := DescribedApproval{ApprovalID: strp("a1"), Options: []string{Forever}}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			aa.Approve(context.Background(), []DescribedApproval{item})
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("concurrent decide calls = %d, want 1", calls)
	}
}

func TestAutoApproverDuplicateIDsInOneCallDecideOnce(t *testing.T) {
	calls := 0
	aa := NewAutoApprover(func(ctx context.Context) (Decider, func(), error) {
		return func(ctx context.Context, a DescribedApproval, decision string) error {
			calls++
			return nil
		}, func() {}, nil
	}, false)
	item := DescribedApproval{ApprovalID: strp("a1"), Options: []string{Forever}}
	handled, _, _ := aa.Approve(context.Background(), []DescribedApproval{item, item})
	if calls != 1 {
		t.Errorf("decide calls = %d, want 1", calls)
	}
	if len(handled) != 1 {
		t.Errorf("handled = %v, want [a1] once", handled)
	}
}

func TestAutoApproverSequentialSecondCallSkipsDecided(t *testing.T) {
	calls := 0
	aa := NewAutoApprover(func(ctx context.Context) (Decider, func(), error) {
		return func(ctx context.Context, a DescribedApproval, decision string) error {
			calls++
			return nil
		}, func() {}, nil
	}, false)
	item := DescribedApproval{ApprovalID: strp("a1"), Options: []string{Forever}}
	aa.Approve(context.Background(), []DescribedApproval{item})
	handled, _, errs := aa.Approve(context.Background(), []DescribedApproval{item})
	if calls != 1 {
		t.Errorf("decide calls = %d, want 1", calls)
	}
	if len(handled) != 0 || len(errs) != 0 {
		t.Errorf("second Approve = handled %v errs %v, want none", handled, errs)
	}
}

func TestAutoApproverFailedDecideClaimsID(t *testing.T) {
	calls := 0
	aa := NewAutoApprover(func(ctx context.Context) (Decider, func(), error) {
		return func(ctx context.Context, a DescribedApproval, decision string) error {
			calls++
			return errors.New("gateway down")
		}, func() {}, nil
	}, false)
	item := DescribedApproval{ApprovalID: strp("a1"), Options: []string{Forever}}
	aa.Approve(context.Background(), []DescribedApproval{item})
	_, _, errs := aa.Approve(context.Background(), []DescribedApproval{item})
	if calls != 1 {
		t.Errorf("decide calls = %d, want 1 (a failed decide still claims the id)", calls)
	}
	if len(errs) != 0 {
		t.Errorf("second Approve errs = %v, want none (claimed)", errs)
	}
}

func TestAutoApproverAuthErrorPropagatesAndStops(t *testing.T) {
	authErr := conn.NewAuthError("expired")
	decided := []string{}
	aa := NewAutoApprover(func(ctx context.Context) (Decider, func(), error) {
		return func(ctx context.Context, a DescribedApproval, decision string) error {
			decided = append(decided, deref(a.ApprovalID))
			return authErr
		}, func() {}, nil
	}, false)
	items := []DescribedApproval{
		{ApprovalID: strp("a1"), Options: []string{Forever}},
		{ApprovalID: strp("a2"), Options: []string{Forever}},
	}
	_, _, errs := aa.Approve(context.Background(), items)
	if len(decided) != 1 || decided[0] != "a1" {
		t.Errorf("decided = %v, want [a1] only (AuthError stops the call)", decided)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want 1", errs)
	}
	var gotAuth *conn.AuthError
	if !errors.As(errs[0], &gotAuth) {
		t.Errorf("err = %v, want an AuthError", errs[0])
	}
	// AsApprover surfaces the AuthError unwrapped as the
	// fatal result error.
	res := aa.AsApprover()(items)
	var resAuth *conn.AuthError
	if !errors.As(res.Err, &resAuth) {
		t.Errorf("AsApprover Err = %v, want an AuthError", res.Err)
	}
	// A fresh approver whose Connect fails with AuthError
	// surfaces it the same way.
	aa2 := NewAutoApprover(func(ctx context.Context) (Decider, func(), error) {
		return nil, nil, authErr
	}, false)
	res2 := aa2.AsApprover()(items)
	if !errors.As(res2.Err, &resAuth) {
		t.Errorf("connect-AuthError Err = %v, want an AuthError", res2.Err)
	}
}

func TestAutoApproverEmptyIDClaimedOnce(t *testing.T) {
	// An empty-string id is still a present id (ApprovalID !=
	// nil): two "" items in one Approve must decide once, like
	// any other duplicated id.
	calls := 0
	aa := NewAutoApprover(func(ctx context.Context) (Decider, func(), error) {
		return func(ctx context.Context, a DescribedApproval, decision string) error {
			calls++
			return nil
		}, func() {}, nil
	}, false)
	item := DescribedApproval{ApprovalID: strp(""), Options: []string{Forever}}
	handled, _, _ := aa.Approve(context.Background(), []DescribedApproval{item, item})
	if calls != 1 {
		t.Errorf("decide calls = %d, want 1 (\"\" is a present id, claimed once)", calls)
	}
	if len(handled) != 1 || handled[0] != "" {
		t.Errorf("handled = %q, want [\"\"] once", handled)
	}
}

func TestDescribedApprovalClone(t *testing.T) {
	// Clone deep-copies every pointer field and Options:
	// mutating the clone must not touch the original.
	orig := DescribedApproval{
		ApprovalID: strp("A"), Title: strp("T"), Question: strp("Q"),
		Kind: strp("K"), Scope: strp("S"), Why: strp("W"),
		ExpiresAtMS: func() *float64 { f := float64(7); return &f }(),
		Options:     []string{Forever},
	}
	cp := orig.Clone()
	*cp.ApprovalID, *cp.Title, *cp.Question = "m", "m", "m"
	*cp.Kind, *cp.Scope, *cp.Why = "m", "m", "m"
	*cp.ExpiresAtMS = 0
	cp.Options[0] = "m"
	if deref(orig.ApprovalID) != "A" || deref(orig.Title) != "T" || deref(orig.Question) != "Q" ||
		deref(orig.Kind) != "K" || deref(orig.Scope) != "S" || deref(orig.Why) != "W" ||
		orig.ExpiresAtMS == nil || *orig.ExpiresAtMS != 7 || len(orig.Options) != 1 || orig.Options[0] != Forever {
		t.Errorf("original mutated by clone: %v", flatDescribed(orig))
	}
}

func TestAutoApproverZeroAndNilGuards(t *testing.T) {
	// Zero value with no Connect: errors, no panic.
	var aa AutoApprover
	_, _, errs := aa.Approve(context.Background(), []DescribedApproval{{ApprovalID: strp("a1")}})
	if len(errs) != 1 {
		t.Fatalf("zero-value errs = %v, want 1", errs)
	}
	// Nil receiver: errors, no panic.
	var nilAA *AutoApprover
	_, _, errs = nilAA.Approve(context.Background(), []DescribedApproval{{ApprovalID: strp("a1")}})
	if len(errs) != 1 {
		t.Fatalf("nil-receiver errs = %v, want 1", errs)
	}
}

func TestAutoApproverWarnedDistinguishesNilAndEmptyID(t *testing.T) {
	// A skipped nil-id approval and a skipped "" approval are
	// different warnings: each keeps its own
	// auto_approve_errors entry. Pre-fix both shared the ""
	// warned key, so the second skip in any order produced no
	// error entry.
	nilItem := DescribedApproval{Options: []string{"deny"}}
	emptyItem := DescribedApproval{ApprovalID: strp(""), Options: []string{"deny"}}
	newApprover := func(t *testing.T) *AutoApprover {
		t.Helper()
		decide := func(ctx context.Context, a DescribedApproval, decision string) error {
			t.Errorf("decide must never run for a skipped approval: %+v", a)
			return nil
		}
		return NewAutoApprover(func(ctx context.Context) (Decider, func(), error) {
			return decide, func() {}, nil
		}, false)
	}
	tests := []struct {
		name  string
		calls [][]DescribedApproval
	}{
		{name: "nil then empty in one call", calls: [][]DescribedApproval{{nilItem, emptyItem}}},
		{name: "empty then nil in one call", calls: [][]DescribedApproval{{emptyItem, nilItem}}},
		{name: "nil then empty across calls", calls: [][]DescribedApproval{{nilItem}, {emptyItem}}},
		{name: "empty then nil across calls", calls: [][]DescribedApproval{{emptyItem}, {nilItem}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aa := newApprover(t)
			totalErrs := 0
			for _, items := range tt.calls {
				_, _, errs := aa.Approve(context.Background(), items)
				totalErrs += len(errs)
			}
			if totalErrs != 2 {
				t.Errorf("skip errors = %d, want 2 (one warning per distinct id)", totalErrs)
			}
		})
	}
}
