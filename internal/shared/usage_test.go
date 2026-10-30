// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// Port of test_usage.py: the RSC fixture is replaced by the decoded
// subscription object itself (parse_rsc_result belongs to the
// gateway package); the summary assertions are the same.

func usageFixture() map[string]any {
	return map[string]any{
		"tier": map[string]any{"name": "Muse Free", "tierCode": "HATCH_FREE", "isPaid": false},
		"usage": map[string]any{"state": "METERED", "percentUsed": int64(87),
			"resetsAt": int64(1792821457), "quotaStatus": "SUFFICIENT"},
		"usageRowLabel":      "Free plan",
		"usageRowValueLabel": "Đã dùng 87%",
		"topupBalance":       int64(480000000),
		"topupTotal":         int64(500000000),
		"topupRowLabel":      "Token bổ sung",
		"topupRowValueLabel": "Đã dùng 4% (còn 12 tỷ token)",
		"entryPointCtaLabel": "Upgrade",
	}
}

func TestSummarizeUsage(t *testing.T) {
	t.Parallel()
	u := SummarizeUsage(usageFixture(), ict(t))
	if u.UsedPercent == nil || *u.UsedPercent != 87 {
		t.Errorf("used_percent = %v, want 87", u.UsedPercent)
	}
	if u.BonusTokens == nil {
		t.Fatal("bonus_tokens is nil, want a bonus block")
	}
	if u.BonusTokens.UsedPercent != 4 {
		t.Errorf("bonus used_percent = %d, want 4", u.BonusTokens.UsedPercent)
	}
	if u.BonusTokens.RemainingTokens == nil || *u.BonusTokens.RemainingTokens != 12_000_000_000 {
		t.Errorf("bonus remaining_tokens = %v, want 12000000000", u.BonusTokens.RemainingTokens)
	}
	if u.BonusTokens.ValueLabel != "Đã dùng 4% (còn 12 tỷ token)" {
		t.Errorf("bonus value_label = %q", u.BonusTokens.ValueLabel)
	}
	if u.ValueLabel == nil || *u.ValueLabel != "Đã dùng 87%" {
		t.Errorf("value_label = %v, want Đã dùng 87%%", u.ValueLabel)
	}
	if u.ResetsAt == nil || *u.ResetsAt != "2026-10-24T12:57:37+0700" {
		t.Errorf("resets_at = %v, want 2026-10-24T12:57:37+0700", u.ResetsAt)
	}
	if u.Plan == nil || *u.Plan != "Muse Free" {
		t.Errorf("plan = %v", u.Plan)
	}
}

func TestSummarizeUsageLiveShapeUnitsAreNotTokens(t *testing.T) {
	t.Parallel()
	u := SummarizeUsage(map[string]any{
		"topupBalance": int64(120000000), "topupTotal": int64(120000000),
		"topupRowValueLabel": "0% used (3B tokens left)",
	}, time.FixedZone("UTC", 0))
	if u.BonusTokens == nil {
		t.Fatal("bonus_tokens is nil")
	}
	if u.BonusTokens.UsedPercent != 0 {
		t.Errorf("bonus used_percent = %d, want 0", u.BonusTokens.UsedPercent)
	}
	if u.BonusTokens.RemainingTokens == nil || *u.BonusTokens.RemainingTokens != 3_000_000_000 {
		t.Errorf("bonus remaining_tokens = %v, want 3000000000", u.BonusTokens.RemainingTokens)
	}
	if u.BonusTokens.Label != "Additional tokens" {
		t.Errorf("bonus label = %q, want default", u.BonusTokens.Label)
	}
}

func TestSummarizeUsageNoTopup(t *testing.T) {
	t.Parallel()
	u := SummarizeUsage(map[string]any{
		"usage": map[string]any{"state": "UNLIMITED"}, "topupTotal": int64(0),
	}, time.FixedZone("UTC", 0))
	if u.BonusTokens != nil {
		t.Errorf("bonus_tokens = %+v, want nil", u.BonusTokens)
	}
	if u.UsedPercent != nil {
		t.Errorf("used_percent = %v, want nil", u.UsedPercent)
	}
	if u.ResetsAt != nil {
		t.Errorf("resets_at = %v, want nil", u.ResetsAt)
	}
}

func TestSummarizeUsageBonusGates(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("UTC", 0)
	cases := []struct {
		name string
		sub  map[string]any
		want bool // bonus present?
	}{
		{"blank value label", map[string]any{"topupTotal": int64(10), "topupRowValueLabel": "  "}, false},
		{"null value label", map[string]any{"topupTotal": int64(10), "topupRowValueLabel": nil}, false},
		{"zero total", map[string]any{"topupTotal": int64(0), "topupRowValueLabel": "x (1K tokens left)"}, false},
		{"balance clamped above total", map[string]any{
			"topupTotal": int64(100), "topupBalance": int64(500),
			"topupRowValueLabel": "0% used (1K tokens left)"}, true},
		{"negative balance clamped", map[string]any{
			"topupTotal": int64(100), "topupBalance": int64(-5),
			"topupRowValueLabel": "all used"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := SummarizeUsage(tc.sub, loc)
			if (u.BonusTokens != nil) != tc.want {
				t.Errorf("bonus present = %v, want %v (%+v)", u.BonusTokens != nil, tc.want, u.BonusTokens)
			}
		})
	}
	// Clamped cases both use the full total.
	u := SummarizeUsage(map[string]any{
		"topupTotal": int64(100), "topupBalance": int64(500),
		"topupRowValueLabel": "0% used (1K tokens left)"}, loc)
	if u.BonusTokens.UsedPercent != 0 {
		t.Errorf("clamped-above used_percent = %d, want 0", u.BonusTokens.UsedPercent)
	}
	u = SummarizeUsage(map[string]any{
		"topupTotal": int64(100), "topupBalance": int64(-5),
		"topupRowValueLabel": "all used"}, loc)
	if u.BonusTokens.UsedPercent != 100 {
		t.Errorf("clamped-below used_percent = %d, want 100", u.BonusTokens.UsedPercent)
	}
}

func TestSummarizeUsageBankersRounding(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("UTC", 0)
	// 100*1/200 = 0.5 -> Python round() gives 0 (banker's); 100*3/200
	// = 1.5 -> 2.
	for _, tc := range []struct {
		used, total int64
		want        int64
	}{
		{1, 200, 0},
		{3, 200, 2},
		{5, 200, 2}, // 2.5 -> 2 (banker's)
		{7, 200, 4}, // 3.5 -> 4 (banker's)
	} {
		u := SummarizeUsage(map[string]any{
			"topupTotal": tc.total, "topupBalance": tc.total - tc.used,
			"topupRowValueLabel": "x"}, loc)
		if u.BonusTokens.UsedPercent != tc.want {
			t.Errorf("used=%d total=%d: used_percent = %d, want %d",
				tc.used, tc.total, u.BonusTokens.UsedPercent, tc.want)
		}
	}
}

func TestParseTokensLeft(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		label string
		want  *int64
	}{
		{"en billions", "0% used (3B tokens left)", intPtr(3_000_000_000)},
		{"vi trillions", "Đã dùng 4% (còn 12 tỷ token)", intPtr(12_000_000_000)},
		{"en millions decimal", "12% used (1.5M tokens left)", intPtr(1_500_000)},
		{"unlimited", "Unlimited", nil},
		{"empty", "", nil},
		{"no tokens word", "87% used", nil},
		{"bare thousands", "1K tokens", intPtr(1000)},
		{"bare no unit", "42 tokens left", intPtr(42)},
		{"vietnamese thousand", "còn 12 nghìn token", intPtr(12000)},
		{"vietnamese million", "còn 3 triệu tokens left", intPtr(3_000_000)},
		{"tera", "2T tokens left", intPtr(2_000_000_000_000)},
		{"decimal comma", "1,5K tokens left", intPtr(1500)},
		{"thousands commas", "1,234,567 tokens left", intPtr(1234567)},
		// Verbatim Python quirk: a single comma with no dot is read
		// as a decimal comma, so "1,500" parses as 1.5, not 1500.
		{"single comma thousands quirk", "1,500 tokens", intPtr(2)},
		{"lowercase unit", "3b tokens left", intPtr(3_000_000_000)},
		{"percent before count ignored", "Đã dùng 87% (còn 5M token)", intPtr(5_000_000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseTokensLeft(tc.label)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseTokensLeft(%q) = %v, want %v", tc.label, got, tc.want)
			}
		})
	}
}

func TestHumanTokens(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   int64
		want string
	}{
		{12_000_000_000, "12B"},
		{1_500_000, "1.5M"},
		{999, "999"},
		{1000, "1K"},
		{1500, "1.5K"},
		{0, "0"},
		{-1500, "-1.5K"},
		{1_000_000_000, "1B"},
		{2_500_000_000, "2.5B"},
	}
	for _, tc := range cases {
		if got := HumanTokens(tc.in); got != tc.want {
			t.Errorf("HumanTokens(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUsageSummaryJSONOrder(t *testing.T) {
	t.Parallel()
	u := SummarizeUsage(usageFixture(), ict(t))
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	// Order check: plan must precede tier, tier precede paid.
	if idx(s, `"plan":`) > idx(s, `"tier":`) || idx(s, `"tier":`) > idx(s, `"paid":`) {
		t.Errorf("usage JSON field order wrong: %s", s)
	}
	for _, want := range []string{`"plan":`, `"tier":`, `"paid":`, `"label":`, `"bonus_tokens":`} {
		if !contains(s, want) {
			t.Errorf("usage JSON missing %s in %s", want, s)
		}
	}
}

func idx(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func contains(s, sub string) bool { return idx(s, sub) >= 0 }

func TestUsageLines(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("UTC", 0)
	u := UsageSummary{
		Plan: strPtr("Free plan"), ValueLabel: strPtr("Đã dùng 87%"),
		ResetsAt:    strPtr("2026-10-24T12:57:37+0000"),
		QuotaStatus: strPtr("SUFFICIENT"), Upgrade: strPtr("Upgrade"),
		Paid: boolPtr(false),
	}
	lines := UsageLines(u, loc)
	want := []string{
		"Free plan: Đã dùng 87% (resets 2026-10-24 12:57 UTC)",
		"Additional tokens: none",
		"Upgrade: https://muse.ai/settings",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Errorf("UsageLines = %q, want %q", lines, want)
	}
	u2 := UsageSummary{
		Label: strPtr("Plan"), UsedPercent: intPtr(50),
		QuotaStatus: strPtr("EXHAUSTED"),
		BonusTokens: &BonusTokens{Label: "Token bổ sung", ValueLabel: "x (1K tokens left)"},
		Paid:        boolPtr(true),
	}
	lines2 := UsageLines(u2, loc)
	want2 := []string{
		"Plan: 50% used",
		"  quota: EXHAUSTED",
		"Token bổ sung: x (1K tokens left) (never expire)",
	}
	if !reflect.DeepEqual(lines2, want2) {
		t.Errorf("UsageLines = %q, want %q", lines2, want2)
	}
}
