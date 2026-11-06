// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Approval description + JSON shapes for the
//! `approvals` / `approve` / `deny` commands.
//!
//! Go sources: `internal/approvals/approvals.go`
//! (`DescribeApproval`, `OffersForever`, `OffersOnce`,
//! `ChooseAutoDecision`) and
//! `internal/commands/wait.go:551-600` (`approvalJSON`,
//! `approvedJSON`, `approvedListJSON`, `approvalsJSON`,
//! `recentJSON`), `wait.go:400-469` (structural stderr
//! rendering) and `wait.go:1189-1230` (`approveAll`).
//!
//! The description is the pure port: nil pointer fields
//! mean the source had no value, and `Options` is `None`
//! when the server listed none (Go nil slice → JSON null).
//! `expires_at_ms` keeps the number literal: Go's
//! `*float64` marshals an integer-valued float without a
//! decimal point, so it renders through
//! [`go_float64_json`] (Go `encoding/json` float rules),
//! not Rust's `Display`.

use castctl_shared::JsonValue;

use crate::network::escape_go_marshal_string;

/// One pending approval, described for a human or an
/// auto-approver. `None` fields mean the source had no
/// value; `options` is `None` when the server listed none.
/// Source: `internal/approvals/approvals.go:40`
/// (`DescribedApproval`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DescribedApproval {
    /// `approval_id`.
    pub approval_id: Option<String>,
    /// `display.summary_title` or `display.display_name`.
    pub title: Option<String>,
    /// `display.permission_question.text`, with
    /// `"{assistant}"` replaced by `"Muse"`.
    pub question: Option<String>,
    /// `permission_question.kind` or `payload.type`.
    pub kind: Option<String>,
    /// `permission_question.scope` or the `Host` detail row.
    pub scope: Option<String>,
    /// `display.short_explanation`, `display.reason`, or
    /// top-level `reason`.
    pub why: Option<String>,
    /// `request_expires_at_ms` as a float64 (bool counts as
    /// 1/0, as in Python); `None` for any other type.
    pub expires_at_ms: Option<f64>,
    /// `decision_options[].kind`, non-empty kinds only;
    /// `None` when the server listed none.
    pub options: Option<Vec<String>>,
}

/// `DescribeApproval` (`approvals.go:55`): describes one
/// approval and never panics on malformed input — a
/// non-map approval (or non-map display /
/// permission_question / payload) degrades to empty
/// fields with a nil approval id.
#[must_use]
pub fn describe_approval(v: &JsonValue) -> DescribedApproval {
    let JsonValue::Object(m) = v else {
        return DescribedApproval::default();
    };
    let get = map_get;
    let sub_map = |v: Option<&JsonValue>| -> std::collections::BTreeMap<String, JsonValue> {
        match v {
            Some(JsonValue::Object(m)) => m.clone(),
            _ => std::collections::BTreeMap::new(),
        }
    };
    let display = sub_map(get(m, "display"));
    let question = sub_map(get(&display, "permission_question"));
    let payload = sub_map(get(m, "payload"));
    // detail_rows: label -> value, first label wins per
    // map assignment (later rows overwrite earlier ones
    // with the same label, as in Go).
    let mut rows: std::collections::BTreeMap<String, JsonValue> = std::collections::BTreeMap::new();
    if let Some(JsonValue::Array(list)) = get(&display, "detail_rows") {
        for r in list {
            if let JsonValue::Object(rm) = r
                && let Some(JsonValue::Str(label)) = rm.get("label")
                && let Some(value) = rm.get("value")
            {
                rows.insert(label.clone(), value.clone());
            }
        }
    }
    let mut options: Vec<String> = Vec::new();
    if let Some(JsonValue::Array(list)) = get(m, "decision_options") {
        for o in list {
            if let JsonValue::Object(om) = o
                && let Some(JsonValue::Str(kind)) = om.get("kind")
                && !kind.is_empty()
            {
                options.push(kind.clone());
            }
        }
    }
    let options = if options.is_empty() {
        None
    } else {
        Some(options)
    };
    DescribedApproval {
        approval_id: string_ptr(get(m, "approval_id")),
        title: first_string(&[
            get(&display, "summary_title"),
            get(&display, "display_name"),
        ]),
        question: question_text(get(&question, "text")),
        kind: first_string(&[get(&question, "kind"), get(&payload, "type")]),
        scope: first_string(&[get(&question, "scope"), rows.get("Host")]),
        why: first_string(&[
            get(&display, "short_explanation"),
            get(&display, "reason"),
            get(m, "reason"),
        ]),
        expires_at_ms: expires_at_ms(get(m, "request_expires_at_ms")),
        options,
    }
}

/// Map lookup with the map's lifetime (the closure form
/// cannot name it).
fn map_get<'a>(
    m: &'a std::collections::BTreeMap<String, JsonValue>,
    k: &str,
) -> Option<&'a JsonValue> {
    m.get(k)
}

/// `subMap` is inlined in `describe_approval` above.
/// `stringPtr` (`approvals.go:120`): the string when the
/// value is a string (an empty string is still a present
/// id), else `None`.
fn string_ptr(v: Option<&JsonValue>) -> Option<String> {
    match v {
        Some(JsonValue::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

/// `firstString` (`approvals.go:130`): the first
/// non-empty string among the values, else `None`.
/// Non-string values are skipped.
fn first_string(vs: &[Option<&JsonValue>]) -> Option<String> {
    for v in vs {
        if let Some(JsonValue::Str(s)) = v
            && !s.is_empty()
        {
            return Some(s.clone());
        }
    }
    None
}

/// `questionText` (`approvals.go:141`): the
/// `"{assistant}"` -> `"Muse"` replacement, `None` when
/// the result is empty.
fn question_text(v: Option<&JsonValue>) -> Option<String> {
    let Some(JsonValue::Str(s)) = v else {
        return None;
    };
    let replaced = s.replace("{assistant}", "Muse");
    if replaced.is_empty() {
        None
    } else {
        Some(replaced)
    }
}

/// `expiresAtMS` (`approvals.go:148`): only numbers count
/// (a bool is an int in Python, so true counts as 1 and
/// false as 0). A numeric string is not a number. A
/// number literal that does not parse to a finite float64
/// (e.g. `1e999`, which Go's `json.Number.Float64`
/// rejects with `ErrRange`) yields `None`.
fn expires_at_ms(v: Option<&JsonValue>) -> Option<f64> {
    match v {
        Some(JsonValue::Int(n)) => Some(*n as f64),
        Some(JsonValue::Float(lit)) => {
            let f: f64 = lit.parse().ok()?;
            if f.is_finite() { Some(f) } else { None }
        }
        Some(JsonValue::Bool(b)) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

/// `OffersForever` (`approvals.go:200`): the forever
/// choice. Approvals that list no options (older servers)
/// are assumed to accept it.
#[must_use]
pub fn offers_forever(d: &DescribedApproval) -> bool {
    match &d.options {
        None => true,
        Some(options) => options.iter().any(|o| o == "allow_always"),
    }
}

/// `OffersOnce` (`approvals.go:211`): whether
/// `allow_once` is explicitly listed. False when no
/// options are listed.
#[must_use]
pub fn offers_once(d: &DescribedApproval) -> bool {
    match &d.options {
        None => false,
        Some(options) => options.iter().any(|o| o == "allow_once"),
    }
}

/// Go `encoding/json` float64 rendering (the
/// `*float64` `expires_at_ms` field): integer-valued
/// floats below 1e21 render as decimal integers
/// (`123`, never `123.0`); larger magnitudes and
/// fractions use the shortest-repr exponent form with an
/// explicit sign and at least two exponent digits
/// (`1e+21`, `1.5e-07`). `-0` renders as `-0`.
#[must_use]
pub fn go_float64_json(f: f64) -> String {
    if f == 0.0 {
        return if f.is_sign_negative() {
            "-0".to_string()
        } else {
            "0".to_string()
        };
    }
    if f.fract() == 0.0 && f.abs() < 1e21 {
        // `{:.0}` prints the full decimal integer; `f as
        // i64` would saturate above i64::MAX (e.g. 1e20).
        return format!("{f:.0}");
    }
    if f.abs() >= 1e-6 && f.abs() < 1e21 {
        // Go `encoding/json` uses 'f' here: shortest
        // decimal that round-trips (Rust `{}`).
        return format!("{f}");
    }
    // Exponent form: abs < 1e-6 or abs >= 1e21. Shortest-repr
    // mantissa via Rust's `{:e}` (same digits as Go's
    // strconv), then Go's exponent shape.
    let sci = format!("{f:e}");
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci[..], "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    if exp >= 0 {
        format!("{mant}e+{exp:02}")
    } else {
        format!("{mant}e-{exp_abs:02}", exp_abs = exp.unsigned_abs())
    }
}

/// Render one `DescribedApproval` as compact JSON in Go
/// `approvalJSON` struct field order: approval_id, title,
/// question, kind, scope, why, expires_at_ms, options.
/// `None` renders as `null`; no options renders as
/// `null` (Go nil slice).
#[must_use]
pub fn approval_json(d: &DescribedApproval) -> String {
    let mut out = String::from("{");
    out.push_str("\"approval_id\":");
    out.push_str(&opt_string_json(&d.approval_id));
    out.push_str(",\"title\":");
    out.push_str(&opt_string_json(&d.title));
    out.push_str(",\"question\":");
    out.push_str(&opt_string_json(&d.question));
    out.push_str(",\"kind\":");
    out.push_str(&opt_string_json(&d.kind));
    out.push_str(",\"scope\":");
    out.push_str(&opt_string_json(&d.scope));
    out.push_str(",\"why\":");
    out.push_str(&opt_string_json(&d.why));
    out.push_str(",\"expires_at_ms\":");
    match d.expires_at_ms {
        Some(f) => out.push_str(&go_float64_json(f)),
        None => out.push_str("null"),
    }
    out.push_str(",\"options\":");
    match &d.options {
        Some(options) => {
            out.push('[');
            let parts: Vec<String> = options
                .iter()
                .map(|o| escape_go_marshal_string(o))
                .collect();
            out.push_str(&parts.join(","));
            out.push(']');
        }
        None => out.push_str("null"),
    }
    out.push('}');
    out
}

/// Render one `approveAll` result row as compact JSON in
/// Go `approvedJSON` struct field order: approval_id,
/// title, kind, scope, decision. Empty values render as
/// `null` (Go `strPtrOrNil(derefStr(...))`).
#[must_use]
pub fn approved_json(
    approval_id: &str,
    title: &str,
    kind: &str,
    scope: &str,
    decision: &str,
) -> String {
    let mut out = String::from("{");
    out.push_str("\"approval_id\":");
    out.push_str(&str_or_null_json(approval_id));
    out.push_str(",\"title\":");
    out.push_str(&str_or_null_json(title));
    out.push_str(",\"kind\":");
    out.push_str(&str_or_null_json(kind));
    out.push_str(",\"scope\":");
    out.push_str(&str_or_null_json(scope));
    out.push_str(",\"decision\":");
    out.push_str(&str_or_null_json(decision));
    out.push('}');
    out
}

fn opt_string_json(v: &Option<String>) -> String {
    match v {
        Some(s) => escape_go_marshal_string(s),
        None => "null".to_string(),
    }
}

/// Go `strPtrOrNil(derefStr(...))`: an empty string is
/// nil (JSON null); a non-empty string is quoted.
fn str_or_null_json(s: &str) -> String {
    if s.is_empty() {
        "null".to_string()
    } else {
        escape_go_marshal_string(s)
    }
}

/// `structuralApprovalID` (`wait.go:422`): the id when it
/// is 1-64 chars of `[A-Za-z0-9_-]`, else `"[omitted]"`.
/// An empty id renders `[omitted]`.
#[must_use]
pub fn structural_approval_id(id: &str) -> String {
    let mut n = 0usize;
    for r in id.chars() {
        n += 1;
        if n > 64 {
            return "[omitted]".to_string();
        }
        if !(r.is_ascii_alphanumeric() || r == '_' || r == '-') {
            return "[omitted]".to_string();
        }
    }
    if n == 0 {
        return "[omitted]".to_string();
    }
    id.to_string()
}

/// `structuralDecision` (`wait.go:444`): the decision
/// when it is one of allow_always/allow_once/
/// allow_session/allow_today, else `"[omitted]"`.
#[must_use]
pub fn structural_decision(s: &str) -> String {
    match s {
        "allow_always" | "allow_once" | "allow_session" | "allow_today" => s.to_string(),
        _ => "[omitted]".to_string(),
    }
}

/// `structuralKind` (`wait.go:448`): the kind when it is
/// one of browse/network_access/shell, else `"[omitted]"`.
#[must_use]
pub fn structural_kind(s: &str) -> String {
    match s {
        "browse" | "network_access" | "shell" => s.to_string(),
        _ => "[omitted]".to_string(),
    }
}

/// `structuralScope` (`wait.go:456`): always
/// `"[omitted]"` — scope has no finite enum set.
#[must_use]
pub fn structural_scope(_s: &str) -> &'static str {
    "[omitted]"
}

/// The `approveAll` skipped line
/// (`wait.go:1204`): `skipped <id>: no forever option
/// option_count=<N>`.
#[must_use]
pub fn skipped_line(d: &DescribedApproval) -> String {
    format!(
        "skipped {}: no forever option option_count={}\n",
        structural_approval_id(d.approval_id.as_deref().unwrap_or("")),
        d.options.as_ref().map(Vec::len).unwrap_or(0)
    )
}

/// The `approveAll` approved line (`wait.go:1223`):
/// `approved <id> (<decision>): title_length=<N>
/// [<kind> [omitted]]>`.
#[must_use]
pub fn approved_line(
    approval_id: &str,
    decision: &str,
    title: &str,
    kind: &str,
    scope: &str,
) -> String {
    format!(
        "approved {} ({}): title_length={} [{} {}]\n",
        structural_approval_id(approval_id),
        structural_decision(decision),
        title.chars().count(),
        structural_kind(kind),
        structural_scope(scope)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use castctl_shared::from_serde;

    fn describe(json: serde_json::Value) -> DescribedApproval {
        describe_approval(&from_serde(&json))
    }

    #[test]
    fn describe_approval_go_fixtures() {
        // Port of Go TestDescribeApproval
        // (internal/approvals/approvals_test.go:28).
        let d = describe(serde_json::json!({
            "approval_id": "ap1",
            "display": {
                "summary_title": "Network",
                "permission_question": {"text": "{assistant} wants net", "kind": "network_access", "scope": "x.com"},
                "detail_rows": [{"label": "Host", "value": "h"}]
            },
            "payload": {"type": "p"},
            "decision_options": [{"kind": "allow_once"}, {"kind": "deny"}]
        }));
        assert_eq!(d.approval_id.as_deref(), Some("ap1"));
        assert_eq!(d.title.as_deref(), Some("Network"));
        assert_eq!(d.question.as_deref(), Some("Muse wants net"));
        assert_eq!(d.kind.as_deref(), Some("network_access"));
        assert_eq!(d.scope.as_deref(), Some("x.com"));
        assert_eq!(d.why, None);
        assert_eq!(d.expires_at_ms, None);
        assert_eq!(
            d.options,
            Some(vec!["allow_once".to_string(), "deny".to_string()])
        );
        // Non-dict approval degrades.
        assert_eq!(
            describe(serde_json::json!("junk")),
            DescribedApproval::default()
        );
        // Display name fallback and host scope fallback.
        let d = describe(serde_json::json!({
            "display": {
                "display_name": "Title2",
                "detail_rows": [{"label": "Host", "value": "host.example"}]
            }
        }));
        assert_eq!(d.title.as_deref(), Some("Title2"));
        assert_eq!(d.scope.as_deref(), Some("host.example"));
        // Question scope wins over host row.
        let d = describe(serde_json::json!({
            "display": {
                "permission_question": {"scope": "qscope"},
                "detail_rows": [{"label": "Host", "value": "h"}]
            }
        }));
        assert_eq!(d.scope.as_deref(), Some("qscope"));
        // Placeholder-only question text becomes Muse.
        let d = describe(serde_json::json!({
            "display": {"permission_question": {"text": "{assistant}"}}
        }));
        assert_eq!(d.question.as_deref(), Some("Muse"));
        // Empty question text is nil.
        let d = describe(serde_json::json!({
            "display": {"permission_question": {"text": ""}}
        }));
        assert_eq!(d.question, None);
        // Kind falls back to payload type.
        let d = describe(serde_json::json!({"payload": {"type": "ptype"}}));
        assert_eq!(d.kind.as_deref(), Some("ptype"));
        // Why chain.
        let d = describe(serde_json::json!({
            "display": {"reason": "dreason"}, "reason": "areason"
        }));
        assert_eq!(d.why.as_deref(), Some("dreason"));
        // Options drop non-dict and empty kinds, nil when empty.
        let d = describe(serde_json::json!({
            "decision_options": [{"kind": ""}, "junk", {}]
        }));
        assert_eq!(d, DescribedApproval::default());
        // Non-dict detail rows skipped.
        let d = describe(serde_json::json!({
            "display": {"detail_rows": ["junk", {"label": "Host", "value": "h2"}]}
        }));
        assert_eq!(d.scope.as_deref(), Some("h2"));
    }

    #[test]
    fn expires_at_ms_cases() {
        // Integer ms stays integral.
        let d = describe(serde_json::json!({"request_expires_at_ms": 1700000000000i64}));
        assert_eq!(d.expires_at_ms, Some(1_700_000_000_000.0));
        // Bool counts as 1/0 (Python int).
        let d = describe(serde_json::json!({"request_expires_at_ms": true}));
        assert_eq!(d.expires_at_ms, Some(1.0));
        let d = describe(serde_json::json!({"request_expires_at_ms": false}));
        assert_eq!(d.expires_at_ms, Some(0.0));
        // Numeric string is not a number.
        let d = describe(serde_json::json!({"request_expires_at_ms": "123"}));
        assert_eq!(d.expires_at_ms, None);
        // Float literal keeps its value.
        let d = describe(serde_json::json!({"request_expires_at_ms": 1.5}));
        assert_eq!(d.expires_at_ms, Some(1.5));
    }

    #[test]
    fn go_float64_json_cases() {
        assert_eq!(go_float64_json(123.0), "123");
        assert_eq!(go_float64_json(0.0), "0");
        assert_eq!(go_float64_json(-0.0), "-0");
        assert_eq!(go_float64_json(1.5), "1.5");
        assert_eq!(go_float64_json(1e21), "1e+21");
        assert_eq!(go_float64_json(1.5e-7), "1.5e-07");
        assert_eq!(go_float64_json(1_700_000_000_000.0), "1700000000000");
    }

    #[test]
    fn approval_json_shape() {
        let d = describe(serde_json::json!({
            "approval_id": "ap1",
            "display": {"summary_title": "Network"},
            "request_expires_at_ms": 1700000000000i64,
            "decision_options": [{"kind": "allow_once"}]
        }));
        assert_eq!(
            approval_json(&d),
            "{\"approval_id\":\"ap1\",\"title\":\"Network\",\"question\":null,\"kind\":null,\"scope\":null,\"why\":null,\"expires_at_ms\":1700000000000,\"options\":[\"allow_once\"]}"
        );
        assert_eq!(
            approval_json(&DescribedApproval::default()),
            "{\"approval_id\":null,\"title\":null,\"question\":null,\"kind\":null,\"scope\":null,\"why\":null,\"expires_at_ms\":null,\"options\":null}"
        );
        assert_eq!(
            approved_json("ap1", "Network", "network_access", "x.com", "allow_once"),
            "{\"approval_id\":\"ap1\",\"title\":\"Network\",\"kind\":\"network_access\",\"scope\":\"x.com\",\"decision\":\"allow_once\"}"
        );
        assert_eq!(
            approved_json("", "", "", "", "allow_once"),
            "{\"approval_id\":null,\"title\":null,\"kind\":null,\"scope\":null,\"decision\":\"allow_once\"}"
        );
    }

    #[test]
    fn structural_helpers() {
        assert_eq!(structural_approval_id("ap-1_x"), "ap-1_x");
        assert_eq!(structural_approval_id(""), "[omitted]");
        assert_eq!(structural_approval_id("a b"), "[omitted]");
        assert_eq!(structural_approval_id(&"a".repeat(65)), "[omitted]");
        assert_eq!(structural_decision("allow_once"), "allow_once");
        assert_eq!(structural_decision("deny"), "[omitted]");
        assert_eq!(structural_kind("shell"), "shell");
        assert_eq!(structural_kind("exec"), "[omitted]");
        assert_eq!(structural_scope("x.com"), "[omitted]");
        let d = describe(serde_json::json!({
            "approval_id": "ap1",
            "decision_options": [{"kind": "allow_once"}]
        }));
        assert_eq!(
            skipped_line(&d),
            "skipped ap1: no forever option option_count=1\n"
        );
        assert_eq!(
            approved_line("ap1", "allow_once", "Network", "network_access", "x.com"),
            "approved ap1 (allow_once): title_length=7 [network_access [omitted]]\n"
        );
        assert!(!offers_forever(&d));
        assert!(offers_once(&d));
        let d = DescribedApproval::default();
        assert!(offers_forever(&d));
        assert!(!offers_once(&d));
    }
}
