// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Port of test_invite.py InviteTest.

func TestSummarizeInvite(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   map[string]any
		want InviteSummary
	}{
		{
			name: "with code computes remaining",
			in: map[string]any{"invite_state": "ACTIVE", "code": "R4O8PL", "max_uses": int64(30),
				"use_count": int64(12), "uses_remaining": nil,
				"reward": map[string]any{"title": "You earned 12B tokens", "body": "12 friends redeemed"}},
			want: InviteSummary{State: strPtr("ACTIVE"), Code: strPtr("R4O8PL"),
				MaxUses: intPtr(30), Used: intPtr(12), UsesRemaining: intPtr(18),
				Reward: &InviteReward{Title: strPtr("You earned 12B tokens"), Body: strPtr("12 friends redeemed")}},
		},
		{
			name: "server remaining wins",
			in: map[string]any{"code": "ABCDEF", "max_uses": int64(30),
				"use_count": int64(12), "uses_remaining": int64(5)},
			want: InviteSummary{Code: strPtr("ABCDEF"), MaxUses: intPtr(30),
				Used: intPtr(12), UsesRemaining: intPtr(5)},
		},
		{
			name: "server zero remaining wins",
			in: map[string]any{"code": "ABCDEF", "max_uses": int64(30),
				"use_count": int64(30), "uses_remaining": int64(0)},
			want: InviteSummary{Code: strPtr("ABCDEF"), MaxUses: intPtr(30),
				Used: intPtr(30), UsesRemaining: intPtr(0)},
		},
		{
			name: "overused floors at zero",
			in: map[string]any{"code": "ABCDEF", "max_uses": int64(5),
				"use_count": int64(9)},
			want: InviteSummary{Code: strPtr("ABCDEF"), MaxUses: intPtr(5),
				Used: intPtr(9), UsesRemaining: intPtr(0)},
		},
		{
			name: "no code yet",
			in:   map[string]any{"invite_state": "ELIGIBLE", "code": nil, "reward": nil},
			want: InviteSummary{State: strPtr("ELIGIBLE")},
		},
		{
			name: "missing use count leaves remaining nil",
			in:   map[string]any{"code": "ABCDEF", "max_uses": int64(30)},
			want: InviteSummary{Code: strPtr("ABCDEF"), MaxUses: intPtr(30)},
		},
		{
			name: "non-object reward is nil",
			in:   map[string]any{"code": "ABCDEF", "reward": "bonus!"},
			want: InviteSummary{Code: strPtr("ABCDEF")},
		},
		{
			name: "full shape",
			in: map[string]any{"invite_state": "ACTIVE", "code": "ABCDEF",
				"invite_link": "https://muse.ai/i/ABCDEF", "max_uses": int64(10),
				"use_count": int64(1), "uses_remaining": int64(9),
				"reward":   map[string]any{"title": "T", "body": "B"},
				"subtitle": "Offer", "share_text": "Share me",
				"has_redeemed_invite_code": true},
			want: InviteSummary{State: strPtr("ACTIVE"), Code: strPtr("ABCDEF"),
				Link: strPtr("https://muse.ai/i/ABCDEF"), MaxUses: intPtr(10),
				Used: intPtr(1), UsesRemaining: intPtr(9),
				Reward: &InviteReward{Title: strPtr("T"), Body: strPtr("B")},
				Offer:  strPtr("Offer"), ShareText: strPtr("Share me"),
				RedeemedSomeonesElseCode: boolPtr(true)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SummarizeInvite(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("SummarizeInvite = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestSummarizeInviteJSON(t *testing.T) {
	t.Parallel()
	s := SummarizeInvite(map[string]any{"invite_state": "ACTIVE", "code": "R4O8PL",
		"max_uses": int64(30), "use_count": int64(12)})
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"state":"ACTIVE","code":"R4O8PL","link":null,"max_uses":30,"used":12,"uses_remaining":18,"reward":null,"offer":null,"share_text":null,"redeemed_someone_elses_code":null}`
	if string(b) != want {
		t.Errorf("Marshal(InviteSummary) = %s, want %s", b, want)
	}
}
