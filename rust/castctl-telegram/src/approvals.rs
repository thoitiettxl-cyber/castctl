// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Approval normalisation and rendering.
//!
//! Go source: `internal/telegram/approvals.go:32-222`
//! (`Decision*`, `Approval`, `DescribeApproval`,
//! `OffersForever`, `OffersOnce`, `ChooseAutoDecision`,
//! `ApprovalText`, `ResumeTriple`).

use castctl_tg_text::escape_text;
use serde_json::Value;

/// Decide with Muse's forever choice.
/// Source: `internal/telegram/approvals.go:32-38`
/// (`DecisionForever = "allow_always"`; Muse's strings,
/// `wait.py:129-130`).
pub const DECISION_FOREVER: &str = "allow_always";

/// Decide with the once choice.
/// Source: `internal/telegram/approvals.go:32-38`
/// (`DecisionOnce = "allow_once"`).
pub const DECISION_ONCE: &str = "allow_once";

/// Deny the approval.
/// Source: `internal/telegram/approvals.go:32-38`
/// (`DecisionDeny = "deny"`).
pub const DECISION_DENY: &str = "deny";

/// One normalised approval.
/// Source: `internal/telegram/approvals.go:39-49`
/// (`Approval`; `Options` is `None` when the approval lists
/// no options — older servers).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Approval {
    /// Approval id.
    pub id: String,
    /// Title.
    pub title: String,
    /// Question text (`{assistant}` already replaced).
    pub question: String,
    /// Kind.
    pub kind: String,
    /// Scope.
    pub scope: String,
    /// Why (short explanation / reason).
    pub why: String,
    /// Expiry, unix milliseconds.
    pub expires_at_ms: i64,
    /// Listed decision options (`None` = none listed).
    pub options: Option<Vec<String>>,
}

/// The resume triple carried by a decide button.
/// Source: `internal/telegram/approvals.go:214-222`
/// (`ResumeTriple`); `None` `after_seq` = no resume.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResumeTriple {
    /// Session id.
    pub session_id: String,
    /// Title.
    pub title: String,
    /// Resume sequence (`None` = no resume).
    pub after_seq: Option<i64>,
}

fn str_field<'a>(m: &'a Value, key: &str) -> &'a str {
    m.get(key).and_then(Value::as_str).unwrap_or("")
}

fn dict_field(v: &Value) -> &Value {
    if v.is_object() { v } else { &Value::Null }
}

fn int_field(m: &Value, key: &str) -> i64 {
    match m.get(key) {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        _ => 0,
    }
}

/// Normalise one raw approval into an `Approval`
/// (`src/muse_cli/wait.py:102-127`). A non-dict approval,
/// display, question, or payload degrades to empty fields
/// instead of panicking: a malformed snapshot must not kill
/// a wait. The `"{assistant}"` placeholder in the question
/// is replaced with `"Muse"`, as in Python.
/// Source: `internal/telegram/approvals.go:84-151`
/// (`DescribeApproval`).
#[must_use]
pub fn describe_approval(raw: &Value) -> Approval {
    if !raw.is_object() {
        return Approval::default();
    }
    let display = dict_field(raw.get("display").unwrap_or(&Value::Null));
    let question = dict_field(display.get("permission_question").unwrap_or(&Value::Null));
    let payload = dict_field(raw.get("payload").unwrap_or(&Value::Null));
    let mut rows: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if let Some(arr) = display.get("detail_rows").and_then(Value::as_array) {
        for r in arr {
            if r.is_object() {
                let label = str_field(r, "label");
                if !label.is_empty() {
                    rows.insert(label.to_string(), str_field(r, "value").to_string());
                }
            }
        }
    }
    let mut title = str_field(display, "summary_title").to_string();
    if title.is_empty() {
        title = str_field(display, "display_name").to_string();
    }
    let question_text = str_field(question, "text").replace("{assistant}", "Muse");
    let mut kind = str_field(question, "kind").to_string();
    if kind.is_empty() {
        kind = str_field(payload, "type").to_string();
    }
    let mut scope = str_field(question, "scope").to_string();
    if scope.is_empty() {
        scope = rows.get("Host").cloned().unwrap_or_default();
    }
    let mut why = str_field(display, "short_explanation").to_string();
    if why.is_empty() {
        why = str_field(display, "reason").to_string();
    }
    if why.is_empty() {
        why = str_field(raw, "reason").to_string();
    }
    let mut options: Option<Vec<String>> = None;
    if let Some(arr) = raw.get("decision_options").and_then(Value::as_array) {
        let mut list: Vec<String> = Vec::new();
        for o in arr {
            if o.is_object() {
                let kind = str_field(o, "kind");
                if !kind.is_empty() {
                    list.push(kind.to_string());
                }
            }
        }
        if !list.is_empty() {
            options = Some(list);
        }
    }
    Approval {
        id: str_field(raw, "approval_id").to_string(),
        title,
        question: question_text,
        kind,
        scope,
        why,
        expires_at_ms: int_field(raw, "request_expires_at_ms"),
        options,
    }
}

/// Whether the approval can be decided with Muse's forever
/// choice. Approvals that list no options (older servers)
/// are assumed to accept it.
/// Source: `internal/telegram/approvals.go:152-165`
/// (`OffersForever`).
#[must_use]
pub fn offers_forever(d: &Approval) -> bool {
    match &d.options {
        None => true,
        Some(options) => options.iter().any(|o| o == DECISION_FOREVER),
    }
}

/// Whether `allow_once` is explicitly listed.
/// Source: `internal/telegram/approvals.go:166-175`
/// (`OffersOnce`).
#[must_use]
pub fn offers_once(d: &Approval) -> bool {
    match &d.options {
        None => false,
        Some(options) => options.iter().any(|o| o == DECISION_ONCE),
    }
}

/// The decision an auto-approver may send, or `None` to
/// leave the approval for a human: `allow_always` wins when
/// offered; otherwise `allow_once`, and only when the caller
/// explicitly enabled the fallback and auto-approve is on.
/// It never picks `options[0]`, never `allow_session` /
/// `allow_today`, and never restricts by kind.
/// Source: `internal/telegram/approvals.go:182-197`
/// (`ChooseAutoDecision`).
#[must_use]
pub fn choose_auto_decision(
    d: &Approval,
    auto_approve: bool,
    allow_once: bool,
) -> Option<&'static str> {
    if !auto_approve {
        return None;
    }
    if offers_forever(d) {
        return Some(DECISION_FOREVER);
    }
    if allow_once && offers_once(d) {
        return Some(DECISION_ONCE);
    }
    None
}

/// Render the approval message: title, question, optional
/// italic why.
/// Source: `internal/telegram/approvals.go:198-213`
/// (`ApprovalText`).
#[must_use]
pub fn approval_text(d: &Approval) -> String {
    let title = if d.title.is_empty() {
        "Approval"
    } else {
        d.title.as_str()
    };
    let mut t = format!(
        "🔐 <b>{}</b>\n{}",
        escape_text(title),
        escape_text(&d.question)
    );
    if !d.why.is_empty() {
        t += &format!("\n<i>{}</i>", escape_text(&d.why));
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_approval_full_shape() {
        let raw = serde_json::json!({
            "approval_id": "ap1",
            "display": {
                "summary_title": "Run tests",
                "permission_question": {"text": "May {assistant} run tests?", "kind": "shell", "scope": "repo"},
                "short_explanation": "Needed for CI",
                "detail_rows": [{"label": "Host", "value": "h1"}]
            },
            "payload": {"type": "fallback-kind"},
            "decision_options": [{"kind": "allow_always"}, {"kind": "deny"}],
            "request_expires_at_ms": 12345
        });
        let a = describe_approval(&raw);
        assert_eq!(a.id, "ap1");
        assert_eq!(a.title, "Run tests");
        assert_eq!(a.question, "May Muse run tests?");
        assert_eq!(a.kind, "shell");
        assert_eq!(a.scope, "repo");
        assert_eq!(a.why, "Needed for CI");
        assert_eq!(a.expires_at_ms, 12345);
        assert_eq!(
            a.options,
            Some(vec!["allow_always".to_string(), "deny".to_string()])
        );
        assert!(offers_forever(&a));
    }

    #[test]
    fn describe_approval_degrades_on_non_dict() {
        let a = describe_approval(&serde_json::json!("nope"));
        assert_eq!(a, Approval::default());
        let a = describe_approval(&serde_json::json!({"display": "nope"}));
        assert_eq!(a.title, "");
        assert_eq!(a.options, None);
        assert!(offers_forever(&a));
    }

    #[test]
    fn choose_auto_decision_rules() {
        let no_opts = Approval {
            options: None,
            ..Approval::default()
        };
        assert_eq!(choose_auto_decision(&no_opts, false, false), None);
        assert_eq!(
            choose_auto_decision(&no_opts, true, false),
            Some(DECISION_FOREVER)
        );
        let once_only = Approval {
            options: Some(vec![DECISION_ONCE.to_string()]),
            ..Approval::default()
        };
        assert_eq!(choose_auto_decision(&once_only, true, false), None);
        assert_eq!(
            choose_auto_decision(&once_only, true, true),
            Some(DECISION_ONCE)
        );
    }

    #[test]
    fn approval_text_defaults_title_and_escapes() {
        let a = Approval {
            question: "Do <x> & y?".to_string(),
            why: "because".to_string(),
            ..Approval::default()
        };
        assert_eq!(
            approval_text(&a),
            "🔐 <b>Approval</b>\nDo &lt;x&gt; &amp; y?\n<i>because</i>"
        );
    }
}
