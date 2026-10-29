// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package approvals

import (
	"context"
	"errors"
	"fmt"
	"testing"
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
	// Second call: the skip warning fires once per id.
	_, _, errs2 := aa.Approve(context.Background(), items)
	if len(errs2) != 0 {
		t.Errorf("second Approve errs = %v, want none (warned once)", errs2)
	}
	if calls["a1"] != 2 {
		t.Errorf("decide calls after second Approve = %v, want a1:2 (one per Approve call)", calls)
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
