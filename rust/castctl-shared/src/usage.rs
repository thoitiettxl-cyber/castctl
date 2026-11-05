// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The `usage` command summary.
//!
//! Source: `internal/shared/usage.go` (`BonusTokens`,
//! `UsageSummary`, `SummarizeUsage`, `UsageLines`,
//! `ParseTokensLeft`, `HumanTokens`, ported from
//! `cli.py:552-647`).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use chrono::TimeZone;
use regex::Regex;

use crate::resources::escape_json_string;
use crate::timefmt::format_resets_at;
use crate::value::{
    JsonObject, JsonValue, as_int64, as_map, bool_ptr_field, int_field, int_ptr_field,
    string_field, string_ptr_field,
};

fn tokens_left_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Go: `(?i)(?:còn\s*)?([\d][\d.,]*)\s*(K|M|B|T|nghìn|triệu|tỷ)?\s*tokens?(?:\s*left)?`
        // (usage.go:30). Go `\d` / `\s` are ASCII-only, so the
        // Rust classes spell the ASCII sets explicitly (M1
        // precedent: sandbox_re).
        Regex::new(
            r"(?i)(?:còn[\t\n\f\r ]*)?([0-9][0-9.,]*)[\t\n\f\r ]*(K|M|B|T|nghìn|triệu|tỷ)?[\t\n\f\r ]*tokens?(?:[\t\n\f\r ]*left)?",
        )
        .expect("static tokens-left regex is valid")
    })
}

fn token_scale(unit: &str) -> i64 {
    if unit.is_empty() {
        return 1;
    }
    if unit.chars().count() == 1 {
        // Single-letter units are looked up upper-cased.
        match unit.to_uppercase().as_str() {
            "K" => 1_000,
            "M" => 1_000_000,
            "B" => 1_000_000_000,
            "T" => 1_000_000_000_000,
            _ => 1,
        }
    } else {
        // Multi-letter (Vietnamese) units lower-cased.
        match unit.to_lowercase().as_str() {
            "nghìn" => 1_000,
            "triệu" => 1_000_000,
            "tỷ" => 1_000_000_000,
            _ => 1,
        }
    }
}

/// Parse a token count out of a usage label:
/// `"'0% used (3B tokens left)' / 'Đã dùng 4% (còn 12 tỷ
/// token)' -> 3e9 / 12e9"`. Returns `None` when the label is
/// empty, has no match, or the number does not parse.
///
/// The number spelling rule is Python's, quirks included:
/// when the digits contain a `"."` or a number of commas
/// other than exactly one, commas are removed
/// (`"1,234,567" -> "1234567"`, `"1.5"` stays `"1.5"`); with
/// exactly one comma and no `"."`, the comma becomes the
/// decimal point (`"1,5" -> "1.5"`, and `"1,500" -> "1.5"`,
/// i.e. a thousands separator written with a single comma
/// is misread as a decimal comma, exactly as Python
/// misreads it). The result is `int(round(number * scale))`
/// with banker's rounding (`f64::round_ties_even`, Python
/// `round()`).
/// Source: `internal/shared/usage.go:56` (`ParseTokensLeft`).
pub fn parse_tokens_left(label: &str) -> Option<i64> {
    if label.is_empty() {
        return None;
    }
    let caps = tokens_left_re().captures(label)?;
    let mut num = caps.get(1)?.as_str().to_string();
    if num.contains('.') || num.matches(',').count() != 1 {
        num = num.replace(',', "");
    } else {
        num = num.replace(',', ".");
    }
    let unit = caps.get(2).map_or("", |g| g.as_str());
    let scale = token_scale(unit);
    let f: f64 = num.parse().ok()?;
    // Go returns nil when ParseFloat fails, which includes
    // overflow (a >300-digit literal parses to +Inf with
    // ErrRange); Rust's parse returns Ok(Inf) there, so the
    // finite check reproduces the nil.
    if !f.is_finite() {
        return None;
    }
    Some(go_f64_to_i64((f * scale as f64).round_ties_even()))
}

/// Go `int64(f)` on amd64 (the x86 CVTTSD2SI indefinite
/// value): out-of-range values in either direction — and
/// NaN — convert to `i64::MIN`, rather than saturating as
/// a Rust `as` cast would. Mirrors the float arm of
/// `as_int64` in `value.rs` (probe P-6).
fn go_f64_to_i64(f: f64) -> i64 {
    if f.is_nan() || f >= 9_223_372_036_854_775_808.0 || f <= -9_223_372_036_854_775_808.0 {
        i64::MIN
    } else {
        f as i64
    }
}

/// The additional-tokens block of a usage summary. It is
/// present only when the subscription carries a positive
/// topup total and a non-empty topup value label.
/// Source: `internal/shared/usage.go:75` (`BonusTokens`).
#[derive(Debug, Clone, PartialEq)]
pub struct BonusTokens {
    /// The server's topup row label, defaulting to
    /// `"Additional tokens"` when the server label is empty
    /// or absent.
    pub label: String,
    /// The server's topup row value label, verbatim.
    pub value_label: String,
    /// `round(100 * used / total)` (banker's rounding),
    /// where used is the total minus the balance clamped to
    /// `[0, total]`.
    pub used_percent: i64,
    /// The token count parsed from the value label, or
    /// `None` when the label carries no parseable count.
    pub remaining_tokens: Option<i64>,
    /// The server's `topupBalance` and `topupTotal`. They
    /// are NOT tokens (a server-side unit); only the
    /// percent and the label-parsed count are token figures.
    pub balance_units: i64,
    /// See `balance_units`.
    pub total_units: i64,
}

/// The flattened subscription summary.
/// Source: `internal/shared/usage.go:123` (`UsageSummary`).
/// Field order is the Python dict order. Nullable fields are
/// `Option`s: JSON null in Python becomes `None` here.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UsageSummary {
    /// `tier.name`.
    pub plan: Option<String>,
    /// `tier.tierCode`.
    pub tier: Option<String>,
    /// `tier.isPaid`.
    pub paid: Option<bool>,
    /// `usageRowLabel`.
    pub label: Option<String>,
    /// `usageRowValueLabel`.
    pub value_label: Option<String>,
    /// `usage.state`.
    pub state: Option<String>,
    /// `usage.percentUsed`.
    pub used_percent: Option<i64>,
    /// `usage.quotaStatus`.
    pub quota_status: Option<String>,
    /// `usage.resetsAt` (epoch seconds) rendered as
    /// `"%Y-%m-%dT%H:%M:%S%z"` in `tz`, or `None` when
    /// `resetsAt` is absent or zero.
    pub resets_at: Option<String>,
    /// `statusSubtitle`.
    pub status: Option<String>,
    /// The bonus block, when present (see `BonusTokens`).
    pub bonus_tokens: Option<BonusTokens>,
    /// `entryPointCtaLabel`.
    pub upgrade: Option<String>,
}

/// Flatten `fetchSubscriptionAction`'s result into the
/// numbers that matter. `topupBalance`/`topupTotal` are used
/// only for the bonus bar percent; the token count comes
/// from parsing the label. `resets_at` renders `resetsAt`
/// (epoch seconds) as `"%Y-%m-%dT%H:%M:%S%z"` in `tz`, or
/// `None` when `resetsAt` is absent or zero.
/// Source: `internal/shared/usage.go:146`
/// (`SummarizeUsage`).
pub fn summarize_usage<Tz: TimeZone>(sub: &JsonValue, tz: &Tz) -> UsageSummary
where
    Tz::Offset: std::fmt::Display,
{
    let empty: JsonObject = BTreeMap::new();
    let sub_map = as_map(sub).unwrap_or(&empty);
    let tier = sub_map.get("tier").and_then(as_map).unwrap_or(&empty);
    let usage = sub_map.get("usage").and_then(as_map).unwrap_or(&empty);
    let total = int_field(sub_map, "topupTotal", 0);
    let balance = int_field(sub_map, "topupBalance", 0);
    let value_label = string_field(sub_map, "topupRowValueLabel");
    let value_label_present = matches!(sub_map.get("topupRowValueLabel"), Some(JsonValue::Str(_)));

    let mut bonus = None;
    if total > 0 && value_label_present && !value_label.trim().is_empty() {
        let clamped = balance.clamp(0, total);
        let used = total - clamped;
        let topup_label = string_field(sub_map, "topupRowLabel");
        bonus = Some(BonusTokens {
            label: if topup_label.is_empty() {
                "Additional tokens".to_string()
            } else {
                topup_label.to_string()
            },
            value_label: value_label.to_string(),
            used_percent: (used as f64 * 100.0 / total as f64).round_ties_even() as i64,
            remaining_tokens: parse_tokens_left(value_label),
            balance_units: balance,
            total_units: total,
        });
    }

    let resets_at = match usage.get("resetsAt").and_then(as_int64) {
        Some(r) if r != 0 => Some(format_resets_at(r, tz)),
        _ => None,
    };

    UsageSummary {
        plan: string_ptr_field(tier, "name"),
        tier: string_ptr_field(tier, "tierCode"),
        paid: bool_ptr_field(tier, "isPaid"),
        label: string_ptr_field(sub_map, "usageRowLabel"),
        value_label: string_ptr_field(sub_map, "usageRowValueLabel"),
        state: string_ptr_field(usage, "state"),
        used_percent: int_ptr_field(usage, "percentUsed"),
        quota_status: string_ptr_field(usage, "quotaStatus"),
        resets_at,
        status: string_ptr_field(sub_map, "statusSubtitle"),
        bonus_tokens: bonus,
        upgrade: string_ptr_field(sub_map, "entryPointCtaLabel"),
    }
}

/// Render a token count with B/M/K suffixes: the first
/// suffix whose divisor the absolute value reaches wins,
/// formatted with one decimal with trailing zeros and a
/// trailing dot stripped (`"12B"`, `"1.5M"`); smaller counts
/// render as plain digits.
/// Source: `internal/shared/usage.go:216` (`HumanTokens`).
pub fn human_tokens(n: i64) -> String {
    // Go: abs := n; if abs < 0 { abs = -abs } — the negation
    // wraps for i64::MIN (no panic in Go), so wrapping_neg
    // reproduces it; a wrapped MIN stays negative as a float
    // and matches no suffix, rendering as plain digits.
    let abs = if n < 0 { n.wrapping_neg() } else { n };
    for (div, unit) in [(1e9f64, "B"), (1e6, "M"), (1e3, "K")] {
        if abs as f64 >= div {
            let s = format!("{:.1}", n as f64 / div);
            let s = s.trim_end_matches('0').trim_end_matches('.');
            return format!("{s}{unit}");
        }
    }
    n.to_string()
}

/// Render a usage summary as human lines. The resets line
/// appends the timezone abbreviation of `tz_abbr_now`
/// (Go: `time.Now().In(loc).Format("MST")`); pass the
/// abbreviation of the same zone used for `SummarizeUsage`
/// so the two agree. On cue that abbreviation is `"+07"`
/// (probed live from Go, not `"ICT"`).
/// Source: `internal/shared/usage.go:239` (`UsageLines`).
pub fn usage_lines(u: &UsageSummary, tz_abbr_now: &str) -> Vec<String> {
    let head = {
        let h = u.label.as_deref().unwrap_or("");
        let h = if h.is_empty() {
            u.plan.as_deref().unwrap_or("")
        } else {
            h
        };
        if h.is_empty() {
            "Plan".to_string()
        } else {
            h.to_string()
        }
    };
    let mut line = match (&u.value_label, u.used_percent, &u.state) {
        (Some(v), _, _) if !v.is_empty() => format!("{head}: {v}"),
        (_, Some(p), _) => format!("{head}: {p}% used"),
        (_, _, state) => format!(
            "{head}: {}",
            state
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("unknown")
        ),
    };
    if let Some(resets) = &u.resets_at {
        // Go truncates the resets string to 16 BYTES
        // (resets[:16]); the rendered timestamp is always
        // ASCII, so byte truncation is char-safe here.
        let mut r = resets.clone();
        if r.len() >= 16 {
            r.truncate(16);
        }
        let r = r.replacen('T', " ", 1);
        line.push_str(&format!(" (resets {r} {tz_abbr_now})"));
    }
    let mut lines = vec![line];
    if let Some(q) = &u.quota_status
        && q != "SUFFICIENT"
    {
        lines.push(format!("  quota: {q}"));
    }
    match &u.bonus_tokens {
        Some(b) => lines.push(format!("{}: {} (never expire)", b.label, b.value_label)),
        None => lines.push("Additional tokens: none".to_string()),
    }
    if let Some(up) = &u.upgrade
        && !up.is_empty()
        && (u.paid.is_none() || u.paid == Some(false))
    {
        lines.push("Upgrade: https://muse.ai/settings".to_string());
    }
    lines
}

fn opt_str_field(v: &Option<String>, out: &mut String) {
    match v {
        Some(s) => escape_json_string(s, out, false),
        None => out.push_str("null"),
    }
}

fn opt_int_field(v: &Option<i64>, out: &mut String) {
    match v {
        Some(n) => out.push_str(&n.to_string()),
        None => out.push_str("null"),
    }
}

fn opt_bool_field(v: &Option<bool>, out: &mut String) {
    match v {
        Some(b) => out.push_str(if *b { "true" } else { "false" }),
        None => out.push_str("null"),
    }
}

/// Serialize a `BonusTokens` exactly as Go's `encoding/json`
/// would with `writeJSON` (indent 2, HTML unescaped):
/// field order `label`, `value_label`, `used_percent`,
/// `remaining_tokens`, `balance_units`, `total_units`; all
/// fields always emitted (`null` when `None`).
/// Source: `internal/shared/usage.go:75` (struct tags).
pub fn bonus_tokens_to_json(b: &BonusTokens) -> String {
    let mut out = String::from("{");
    out.push_str("\"label\":");
    escape_json_string(&b.label, &mut out, false);
    out.push_str(",\"value_label\":");
    escape_json_string(&b.value_label, &mut out, false);
    out.push_str(",\"used_percent\":");
    out.push_str(&b.used_percent.to_string());
    out.push_str(",\"remaining_tokens\":");
    opt_int_field(&b.remaining_tokens, &mut out);
    out.push_str(",\"balance_units\":");
    out.push_str(&b.balance_units.to_string());
    out.push_str(",\"total_units\":");
    out.push_str(&b.total_units.to_string());
    out.push('}');
    out
}

/// Serialize a `UsageSummary` exactly as Go's `encoding/json`
/// would with `writeJSON` (indent 2, HTML unescaped):
/// field order `plan`, `tier`, `paid`, `label`,
/// `value_label`, `state`, `used_percent`, `quota_status`,
/// `resets_at`, `status`, `bonus_tokens`, `upgrade`; all
/// fields always emitted (`null` when `None`).
/// Source: `internal/shared/usage.go:123` (struct tags).
pub fn usage_summary_to_json(u: &UsageSummary) -> String {
    let mut out = String::from("{");
    out.push_str("\"plan\":");
    opt_str_field(&u.plan, &mut out);
    out.push_str(",\"tier\":");
    opt_str_field(&u.tier, &mut out);
    out.push_str(",\"paid\":");
    opt_bool_field(&u.paid, &mut out);
    out.push_str(",\"label\":");
    opt_str_field(&u.label, &mut out);
    out.push_str(",\"value_label\":");
    opt_str_field(&u.value_label, &mut out);
    out.push_str(",\"state\":");
    opt_str_field(&u.state, &mut out);
    out.push_str(",\"used_percent\":");
    opt_int_field(&u.used_percent, &mut out);
    out.push_str(",\"quota_status\":");
    opt_str_field(&u.quota_status, &mut out);
    out.push_str(",\"resets_at\":");
    opt_str_field(&u.resets_at, &mut out);
    out.push_str(",\"status\":");
    opt_str_field(&u.status, &mut out);
    out.push_str(",\"bonus_tokens\":");
    match &u.bonus_tokens {
        Some(b) => out.push_str(&bonus_tokens_to_json(b)),
        None => out.push_str("null"),
    }
    out.push_str(",\"upgrade\":");
    opt_str_field(&u.upgrade, &mut out);
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::JsonValue;
    use chrono::FixedOffset;
    use std::collections::BTreeMap;

    fn ict() -> FixedOffset {
        FixedOffset::east_opt(7 * 3600).unwrap()
    }

    fn utc() -> FixedOffset {
        FixedOffset::east_opt(0).unwrap()
    }

    fn s(v: &str) -> JsonValue {
        JsonValue::Str(v.to_string())
    }

    fn i(v: i64) -> JsonValue {
        JsonValue::Int(v)
    }

    fn b(v: bool) -> JsonValue {
        JsonValue::Bool(v)
    }

    fn obj(pairs: &[(&str, JsonValue)]) -> JsonValue {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), v.clone());
        }
        JsonValue::Object(m)
    }

    // Ported from internal/shared/usage_test.go usageFixture.
    fn usage_fixture() -> JsonValue {
        obj(&[
            (
                "tier",
                obj(&[
                    ("name", s("Muse Free")),
                    ("tierCode", s("HATCH_FREE")),
                    ("isPaid", b(false)),
                ]),
            ),
            (
                "usage",
                obj(&[
                    ("state", s("METERED")),
                    ("percentUsed", i(87)),
                    ("resetsAt", i(1792821457)),
                    ("quotaStatus", s("SUFFICIENT")),
                ]),
            ),
            ("usageRowLabel", s("Free plan")),
            ("usageRowValueLabel", s("Đã dùng 87%")),
            ("topupBalance", i(480000000)),
            ("topupTotal", i(500000000)),
            ("topupRowLabel", s("Token bổ sung")),
            ("topupRowValueLabel", s("Đã dùng 4% (còn 12 tỷ token)")),
            ("entryPointCtaLabel", s("Upgrade")),
        ])
    }

    // Ported from internal/shared/usage_test.go
    // TestSummarizeUsage.
    #[test]
    fn summarize_usage_full_fixture() {
        let u = summarize_usage(&usage_fixture(), &ict());
        assert_eq!(u.used_percent, Some(87));
        let bonus = u.bonus_tokens.as_ref().expect("bonus block present");
        assert_eq!(bonus.used_percent, 4);
        assert_eq!(bonus.remaining_tokens, Some(12_000_000_000));
        assert_eq!(bonus.value_label, "Đã dùng 4% (còn 12 tỷ token)");
        assert_eq!(u.value_label.as_deref(), Some("Đã dùng 87%"));
        assert_eq!(u.resets_at.as_deref(), Some("2026-10-24T12:57:37+0700"));
        assert_eq!(u.plan.as_deref(), Some("Muse Free"));
    }

    // Ported from TestSummarizeUsageLiveShapeUnitsAreNotTokens.
    #[test]
    fn summarize_usage_live_shape_units_are_not_tokens() {
        let u = summarize_usage(
            &obj(&[
                ("topupBalance", i(120000000)),
                ("topupTotal", i(120000000)),
                ("topupRowValueLabel", s("0% used (3B tokens left)")),
            ]),
            &utc(),
        );
        let bonus = u.bonus_tokens.as_ref().expect("bonus block present");
        assert_eq!(bonus.used_percent, 0);
        assert_eq!(bonus.remaining_tokens, Some(3_000_000_000));
        assert_eq!(bonus.label, "Additional tokens");
    }

    // Ported from TestSummarizeUsageNoTopup.
    #[test]
    fn summarize_usage_no_topup() {
        let u = summarize_usage(
            &obj(&[
                ("usage", obj(&[("state", s("UNLIMITED"))])),
                ("topupTotal", i(0)),
            ]),
            &utc(),
        );
        assert!(u.bonus_tokens.is_none());
        assert!(u.used_percent.is_none());
        assert!(u.resets_at.is_none());
    }

    // Ported from TestSummarizeUsageBonusGates.
    #[test]
    fn summarize_usage_bonus_gates() {
        for (name, sub, want) in [
            (
                "blank value label",
                obj(&[("topupTotal", i(10)), ("topupRowValueLabel", s("  "))]),
                false,
            ),
            (
                "null value label",
                obj(&[
                    ("topupTotal", i(10)),
                    ("topupRowValueLabel", JsonValue::Null),
                ]),
                false,
            ),
            (
                "zero total",
                obj(&[
                    ("topupTotal", i(0)),
                    ("topupRowValueLabel", s("x (1K tokens left)")),
                ]),
                false,
            ),
            (
                "balance clamped above total",
                obj(&[
                    ("topupTotal", i(100)),
                    ("topupBalance", i(500)),
                    ("topupRowValueLabel", s("0% used (1K tokens left)")),
                ]),
                true,
            ),
            (
                "negative balance clamped",
                obj(&[
                    ("topupTotal", i(100)),
                    ("topupBalance", i(-5)),
                    ("topupRowValueLabel", s("all used")),
                ]),
                true,
            ),
        ] {
            let u = summarize_usage(&sub, &utc());
            assert_eq!(u.bonus_tokens.is_some(), want, "{name}");
        }
        let clamped_above = summarize_usage(
            &obj(&[
                ("topupTotal", i(100)),
                ("topupBalance", i(500)),
                ("topupRowValueLabel", s("0% used (1K tokens left)")),
            ]),
            &utc(),
        );
        assert_eq!(
            clamped_above.bonus_tokens.unwrap().used_percent,
            0,
            "clamped-above"
        );
        let clamped_below = summarize_usage(
            &obj(&[
                ("topupTotal", i(100)),
                ("topupBalance", i(-5)),
                ("topupRowValueLabel", s("all used")),
            ]),
            &utc(),
        );
        assert_eq!(
            clamped_below.bonus_tokens.unwrap().used_percent,
            100,
            "clamped-below"
        );
    }

    // Ported from TestSummarizeUsageBankersRounding.
    #[test]
    fn summarize_usage_bankers_rounding() {
        for (used, total, want) in [(1, 200, 0), (3, 200, 2), (5, 200, 2), (7, 200, 4)] {
            let u = summarize_usage(
                &obj(&[
                    ("topupTotal", i(total)),
                    ("topupBalance", i(total - used)),
                    ("topupRowValueLabel", s("x")),
                ]),
                &utc(),
            );
            assert_eq!(
                u.bonus_tokens.unwrap().used_percent,
                want,
                "used={used} total={total}"
            );
        }
    }

    // Ported from TestParseTokensLeft.
    #[test]
    fn parse_tokens_left_table() {
        for (name, label, want) in [
            (
                "en billions",
                "0% used (3B tokens left)",
                Some(3_000_000_000),
            ),
            (
                "vi trillions",
                "Đã dùng 4% (còn 12 tỷ token)",
                Some(12_000_000_000),
            ),
            (
                "en millions decimal",
                "12% used (1.5M tokens left)",
                Some(1_500_000),
            ),
            ("unlimited", "Unlimited", None),
            ("empty", "", None),
            ("no tokens word", "87% used", None),
            ("bare thousands", "1K tokens", Some(1000)),
            ("bare no unit", "42 tokens left", Some(42)),
            ("vietnamese thousand", "còn 12 nghìn token", Some(12000)),
            (
                "vietnamese million",
                "còn 3 triệu tokens left",
                Some(3_000_000),
            ),
            ("tera", "2T tokens left", Some(2_000_000_000_000)),
            ("decimal comma", "1,5K tokens left", Some(1500)),
            ("thousands commas", "1,234,567 tokens left", Some(1234567)),
            ("single comma thousands quirk", "1,500 tokens", Some(2)),
            ("lowercase unit", "3b tokens left", Some(3_000_000_000)),
            (
                "percent before count ignored",
                "Đã dùng 87% (còn 5M token)",
                Some(5_000_000),
            ),
        ] {
            assert_eq!(parse_tokens_left(label), want, "{name}");
        }
    }

    // Ported from TestHumanTokens.
    #[test]
    fn human_tokens_table() {
        for (input, want) in [
            (12_000_000_000, "12B"),
            (1_500_000, "1.5M"),
            (999, "999"),
            (1000, "1K"),
            (1500, "1.5K"),
            (0, "0"),
            (-1500, "-1.5K"),
            (1_000_000_000, "1B"),
            (2_500_000_000, "2.5B"),
        ] {
            assert_eq!(human_tokens(input), want, "{input}");
        }
    }

    // Ported from TestUsageSummaryJSONOrder.
    #[test]
    fn usage_summary_json_order_matches_go() {
        let out = usage_summary_to_json(&summarize_usage(&usage_fixture(), &ict()));
        let plan = out.find("\"plan\":").expect("plan field");
        let tier = out.find("\"tier\":").expect("tier field");
        let paid = out.find("\"paid\":").expect("paid field");
        assert!(plan < tier && tier < paid, "field order: {out}");
        for want in [
            "\"plan\":",
            "\"tier\":",
            "\"paid\":",
            "\"label\":",
            "\"bonus_tokens\":",
        ] {
            assert!(out.contains(want), "missing {want} in {out}");
        }
    }

    // Ported from TestUsageLines.
    #[test]
    fn usage_lines_table() {
        let u = UsageSummary {
            plan: Some("Free plan".to_string()),
            value_label: Some("Đã dùng 87%".to_string()),
            resets_at: Some("2026-10-24T12:57:37+0000".to_string()),
            quota_status: Some("SUFFICIENT".to_string()),
            upgrade: Some("Upgrade".to_string()),
            paid: Some(false),
            ..Default::default()
        };
        assert_eq!(
            usage_lines(&u, "UTC"),
            vec![
                "Free plan: Đã dùng 87% (resets 2026-10-24 12:57 UTC)".to_string(),
                "Additional tokens: none".to_string(),
                "Upgrade: https://muse.ai/settings".to_string(),
            ]
        );
        let u2 = UsageSummary {
            label: Some("Plan".to_string()),
            used_percent: Some(50),
            quota_status: Some("EXHAUSTED".to_string()),
            bonus_tokens: Some(BonusTokens {
                label: "Token bổ sung".to_string(),
                value_label: "x (1K tokens left)".to_string(),
                used_percent: 0,
                remaining_tokens: Some(1000),
                balance_units: 0,
                total_units: 100,
            }),
            paid: Some(true),
            ..Default::default()
        };
        assert_eq!(
            usage_lines(&u2, "UTC"),
            vec![
                "Plan: 50% used".to_string(),
                "  quota: EXHAUSTED".to_string(),
                "Token bổ sung: x (1K tokens left) (never expire)".to_string(),
            ]
        );
    }
}
