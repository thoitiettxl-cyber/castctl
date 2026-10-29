// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// tokenScales maps a unit suffix to its multiplier, ported verbatim
// from cli.py:552-553 (_SCALE). Single-letter units are looked up
// upper-cased, multi-letter (Vietnamese) units lower-cased; see
// ParseTokensLeft.
var tokenScales = map[string]int64{
	"":      1,
	"K":     1_000,
	"M":     1_000_000,
	"B":     1_000_000_000,
	"T":     1_000_000_000_000,
	"nghìn": 1_000,
	"triệu": 1_000_000,
	"tỷ":    1_000_000_000,
}

// tokensLeftRe is the remaining-tokens label parser, ported
// verbatim from cli.py:554-555 (_TOKENS_LEFT_RE), including the
// case-insensitive flag and the optional Vietnamese "còn" prefix:
//
//	(?:còn\s*)?([\d][\d.,]*)\s*(K|M|B|T|nghìn|triệu|tỷ)?\s*tokens?(?:\s*left)?
func tokensLeftRe() *regexp.Regexp {
	return regexp.MustCompile(`(?i)(?:còn\s*)?([\d][\d.,]*)\s*(K|M|B|T|nghìn|triệu|tỷ)?\s*tokens?(?:\s*left)?`)
}

var tokensLeftPattern = tokensLeftRe()

// ParseTokensLeft parses a token count out of a usage label, ported
// verbatim from cli.py:558-572 (parse_tokens_left):
// "'0% used (3B tokens left)' / 'Đã dùng 4% (còn 12 tỷ token)' ->
// 3e9 / 12e9". It returns nil when the label is empty, has no
// match, or the number does not parse.
//
// The number spelling rule is Python's, quirks included: when the
// digits contain a "." or a number of commas other than exactly
// one, commas are removed ("1,234,567" -> "1234567", "1.5" stays
// "1.5"); with exactly one comma and no ".", the comma becomes the
// decimal point ("1,5" -> "1.5", and "1,500" -> "1.5", i.e. a
// thousands separator written with a single comma is misread as a
// decimal comma, exactly as Python misreads it). The result is
// int(round(number * scale)) with Go's math.RoundToEven, Python
// round()'s banker's rounding.
func ParseTokensLeft(label string) *int64 {
	if label == "" {
		return nil
	}
	m := tokensLeftPattern.FindStringSubmatch(label)
	if m == nil {
		return nil
	}
	num := m[1]
	if strings.Contains(num, ".") || strings.Count(num, ",") != 1 {
		num = strings.ReplaceAll(num, ",", "")
	} else {
		num = strings.ReplaceAll(num, ",", ".")
	}
	unit := m[2]
	var scale int64 = 1
	if len([]rune(unit)) == 1 {
		scale = tokenScales[strings.ToUpper(unit)]
		if scale == 0 {
			scale = 1
		}
	} else {
		scale = tokenScales[strings.ToLower(unit)]
		if scale == 0 {
			scale = 1
		}
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return nil
	}
	// math.RoundToEven is Python round()'s banker's rounding:
	// an exact .5 fraction rounds to the even neighbour.
	n := int64(math.RoundToEven(f * float64(scale)))
	return &n
}

// BonusTokens is the additional-tokens block of a usage summary,
// ported from cli.py:578-587 (the bonus dict inside
// summarize_usage). It is present only when the subscription
// carries a positive topup total and a non-empty topup value label.
type BonusTokens struct {
	// Label is the server's topup row label, defaulting to
	// "Additional tokens" when the server label is empty or absent.
	Label string `json:"label"`
	// ValueLabel is the server's topup row value label, verbatim.
	ValueLabel string `json:"value_label"`
	// UsedPercent is round(100 * used / total), with Python's
	// banker's rounding (math.RoundToEven), where used is the
	// total minus the balance clamped to [0, total].
	UsedPercent int64 `json:"used_percent"`
	// RemainingTokens is the token count parsed from the value
	// label, or nil when the label carries no parseable count.
	RemainingTokens *int64 `json:"remaining_tokens"`
	// BalanceUnits and TotalUnits are the server's topupBalance
	// and topupTotal. They are NOT tokens (a server-side unit);
	// only the percent and the label-parsed count are token
	// figures, exactly as Python's docstring warns.
	BalanceUnits int64 `json:"balance_units"`
	TotalUnits   int64 `json:"total_units"`
}

// UsageSummary is the flattened subscription summary, ported from
// cli.py:574-601 (summarize_usage). Field order is the Python dict
// order. Nullable fields are pointers: JSON null in Python becomes
// a nil pointer here.
type UsageSummary struct {
	Plan        *string      `json:"plan"`
	Tier        *string      `json:"tier"`
	Paid        *bool        `json:"paid"`
	Label       *string      `json:"label"`
	ValueLabel  *string      `json:"value_label"`
	State       *string      `json:"state"`
	UsedPercent *int64       `json:"used_percent"`
	QuotaStatus *string      `json:"quota_status"`
	ResetsAt    *string      `json:"resets_at"`
	Status      *string      `json:"status"`
	BonusTokens *BonusTokens `json:"bonus_tokens"`
	Upgrade     *string      `json:"upgrade"`
}

// SummarizeUsage flattens fetchSubscriptionAction's result into
// the numbers that matter, ported verbatim from cli.py:574-601
// (summarize_usage). topupBalance/topupTotal are used only for the
// bonus bar percent; the token count comes from parsing the label.
// resets_at renders resetsAt (epoch seconds) as
// "%Y-%m-%dT%H:%M:%S%z" in loc (nil means time.Local), or nil when
// resetsAt is absent or zero. loc is explicit so tests never
// depend on the machine timezone.
func SummarizeUsage(sub map[string]any, loc *time.Location) UsageSummary {
	if loc == nil {
		loc = time.Local
	}
	tier, _ := asMap(sub["tier"])
	usage, _ := asMap(sub["usage"])
	total := intField(sub, "topupTotal", 0)
	balance := intField(sub, "topupBalance", 0)
	valueLabel := stringField(sub, "topupRowValueLabel")
	valueLabelPresent := false
	if v, present := sub["topupRowValueLabel"]; present {
		_, valueLabelPresent = asString(v)
	}

	var bonus *BonusTokens
	if total > 0 && valueLabelPresent && strings.TrimSpace(valueLabel) != "" {
		clamped := balance
		if clamped < 0 {
			clamped = 0
		}
		if clamped > total {
			clamped = total
		}
		used := total - clamped
		bonus = &BonusTokens{
			Label:           firstNonEmpty(stringField(sub, "topupRowLabel"), "Additional tokens"),
			ValueLabel:      valueLabel,
			UsedPercent:     int64(math.RoundToEven(float64(used) * 100 / float64(total))),
			RemainingTokens: ParseTokensLeft(valueLabel),
			BalanceUnits:    balance,
			TotalUnits:      total,
		}
	}

	var resetsAt *string
	if resets, ok := asInt64(usage["resetsAt"]); ok && resets != 0 {
		s := time.Unix(resets, 0).In(loc).Format("2006-01-02T15:04:05-0700")
		resetsAt = &s
	}

	return UsageSummary{
		Plan:        stringPtrField(tier, "name"),
		Tier:        stringPtrField(tier, "tierCode"),
		Paid:        boolPtrField(tier, "isPaid"),
		Label:       stringPtrField(sub, "usageRowLabel"),
		ValueLabel:  stringPtrField(sub, "usageRowValueLabel"),
		State:       stringPtrField(usage, "state"),
		UsedPercent: intPtrField(usage, "percentUsed"),
		QuotaStatus: stringPtrField(usage, "quotaStatus"),
		ResetsAt:    resetsAt,
		Status:      stringPtrField(sub, "statusSubtitle"),
		BonusTokens: bonus,
		Upgrade:     stringPtrField(sub, "entryPointCtaLabel"),
	}
}

// firstNonEmpty returns s, or def when s is empty. It mirrors
// Python's `x or default` over strings.
func firstNonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// HumanTokens renders a token count with B/M/K suffixes, ported
// from cli.py:604-609 (_human_tokens): the first suffix whose
// divisor the absolute value reaches wins, formatted with one
// decimal with trailing zeros and a trailing dot stripped
// ("12B", "1.5M"); smaller counts render as plain digits.
func HumanTokens(n int64) string {
	abs := n
	if abs < 0 {
		abs = -abs
	}
	for _, div := range []struct {
		div  float64
		unit string
	}{{1e9, "B"}, {1e6, "M"}, {1e3, "K"}} {
		if float64(abs) >= div.div {
			s := fmt.Sprintf("%.1f", float64(n)/div.div)
			s = strings.TrimRight(s, "0")
			s = strings.TrimRight(s, ".")
			return s + div.unit
		}
	}
	return strconv.FormatInt(n, 10)
}

// UsageLines renders a usage summary as human lines, ported from
// cli.py:630-647 (usage_lines). The resets line appends the
// timezone abbreviation of loc (Python's time.strftime('%Z'));
// pass the same loc used for SummarizeUsage so the two agree.
func UsageLines(u UsageSummary, loc *time.Location) []string {
	if loc == nil {
		loc = time.Local
	}
	head := firstNonEmpty(ptrOrEmpty(u.Label), ptrOrEmpty(u.Plan))
	if head == "" {
		head = "Plan"
	}
	var line string
	switch {
	case ptrOrEmpty(u.ValueLabel) != "":
		line = head + ": " + ptrOrEmpty(u.ValueLabel)
	case u.UsedPercent != nil:
		line = fmt.Sprintf("%s: %d%% used", head, *u.UsedPercent)
	default:
		line = head + ": " + firstNonEmpty(ptrOrEmpty(u.State), "unknown")
	}
	if u.ResetsAt != nil {
		resets := *u.ResetsAt
		if len(resets) >= 16 {
			resets = resets[:16]
		}
		resets = strings.Replace(resets, "T", " ", 1)
		line += " (resets " + resets + " " + time.Now().In(loc).Format("MST") + ")"
	}
	lines := []string{line}
	if u.QuotaStatus != nil && *u.QuotaStatus != "SUFFICIENT" {
		lines = append(lines, "  quota: "+*u.QuotaStatus)
	}
	if u.BonusTokens != nil {
		lines = append(lines, u.BonusTokens.Label+": "+u.BonusTokens.ValueLabel+" (never expire)")
	} else {
		lines = append(lines, "Additional tokens: none")
	}
	if u.Upgrade != nil && *u.Upgrade != "" && (u.Paid == nil || !*u.Paid) {
		lines = append(lines, "Upgrade: https://muse.ai/settings")
	}
	return lines
}

// ptrOrEmpty dereferences a *string, or "" when nil.
func ptrOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
