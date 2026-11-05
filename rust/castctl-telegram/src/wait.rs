// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The wait core: the pure turn-end state machine
//! (`Waiter`), reply extraction from history, and the
//! outcome/exit-code mapping.
//!
//! Go sources: `internal/wait/waiter.go` (terminal
//! vocabulary, `Feed`, `Settle`, `AcceptReplayedFailed`),
//! `internal/wait/replies.go` (`Reply`, `RepliesAfter`,
//! `UserAck`, `OpenWidgets`, `EventHasMedia`,
//! `IsSelfReferential`, `CleanText`),
//! `internal/wait/events.go` (`decodeRecord`, `eventName`,
//! `payload`, `truthy`), `internal/wait/outcome.go`
//! (`OutcomeOf`, `ExitCode`), `internal/wait/reason.go`
//! (`NeedsInputReason`).
//!
//! What is NOT here: the Runner's subscribe loop
//! (`internal/wait/runner.go`, `chat.subscribe` NDJSON).
//! Rust has no public subscribe API yet — no
//! `SubscribeRaw` / `SubscribeJSON` and no
//! `chat.subscribe` follow-loop consumer — so the turn
//! follow in `turn.rs` drives this state machine from
//! `chat.history` polls instead (see PORTING.md §M5b
//! deviation 1). That is not the same as having no
//! stream primitive at all: the internal stream frame
//! (`deliver_to_open_streams` + the `streams` map) exists
//! at base, and this milestone adds the narrow deliver
//! primitive `Gateway::open_stream` (track=false, for
//! `chat.stream` delivery only). The state
//! machine itself is a faithful port: feed it events in
//! arrival order and it decides exactly as Go does; the
//! only deliberate difference is that the approver runs
//! through the async [`WaitApprover`] trait instead of
//! Go's sync `approvals.Approver` closure.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use regex::Regex;
use serde_json::Value;

use crate::approvals::{Approval, describe_approval};
use crate::error::BotError;
use castctl_shared::clean_text;

/// Proven-done status (only `"completed"`).
/// Source: `internal/wait/waiter.go:24-26`.
#[must_use]
pub fn is_done_status(s: &str) -> bool {
    s == "completed"
}

/// Proven-failed statuses.
/// Source: `internal/wait/waiter.go:27-28`.
#[must_use]
pub fn is_failed_status(s: &str) -> bool {
    matches!(s, "interrupted" | "cancelled" | "canceled")
}

/// Any terminal-vocabulary string, proven or suspect.
/// Source: `internal/wait/waiter.go:29-37`.
#[must_use]
pub fn is_terminal_status(s: &str) -> bool {
    is_done_status(s)
        || is_failed_status(s)
        || is_suspect_done_status(s)
        || is_suspect_failed_status(s)
}

/// Suspect done-like statuses: terminal only with history
/// proof. Source: `internal/wait/waiter.go:31-32`.
#[must_use]
pub fn is_suspect_done_status(s: &str) -> bool {
    matches!(
        s,
        "idle" | "complete" | "done" | "finished" | "succeeded" | "success"
    )
}

/// Suspect failed-like statuses: terminal only with history
/// proof. Source: `internal/wait/waiter.go:33-34`.
#[must_use]
pub fn is_suspect_failed_status(s: &str) -> bool {
    matches!(
        s,
        "failed" | "failure" | "error" | "errored" | "aborted" | "timed_out"
    )
}

/// Exit codes, verbatim from `wait.py`.
/// Source: `internal/wait/outcome.go:16-24`.
pub const EXIT_OK: i32 = 0;
/// Failed or cancelled turn.
pub const EXIT_FAILED: i32 = 2;
/// Needs a human: a question or a pending approval.
pub const EXIT_HUMAN: i32 = 4;
/// Turn that never ended.
pub const EXIT_TIMEOUT: i32 = 124;

/// One final assistant reply after the boundary.
/// Source: `internal/wait/replies.go:14-27`.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    /// History seq.
    pub seq: i64,
    /// Message id (first truthy payload/event id).
    pub message_id: String,
    /// Cleaned reply text.
    pub text: String,
    /// Unanswered widgets.
    pub widgets: Vec<Widget>,
    /// Whether the event references media.
    pub media: bool,
    /// Payload `agent_id`, when a string.
    pub agent_id: String,
    /// Payload `root_agent_id`, when a string.
    pub root_agent_id: String,
}

impl Reply {
    /// Whether the reply is identifiably a subagent's:
    /// both identity fields present as strings and differ.
    /// Source: `internal/wait/replies.go:29-36`.
    #[must_use]
    pub fn subagent_shaped(&self) -> bool {
        !self.agent_id.is_empty()
            && !self.root_agent_id.is_empty()
            && self.agent_id != self.root_agent_id
    }
}

/// One unanswered hatch widget carried by a reply.
/// Source: `internal/wait/replies.go:38-45`.
#[derive(Debug, Clone, PartialEq)]
pub struct Widget {
    /// Raw `widget_id` value.
    pub id: Value,
    /// Widget kind.
    pub kind: String,
    /// Display/fallback text, when non-empty.
    pub text: Option<String>,
    /// Raw `data.options` value.
    pub options: Value,
}

/// A decided turn end.
/// Source: `internal/wait/waiter.go:67-73`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Decided kind.
    pub kind: WaitKind,
    /// Terminal status string (done/failed), or "".
    pub detail: String,
    /// Pending approvals (kind approval only).
    pub approvals: Vec<Approval>,
}

/// The wait core's end kind.
/// Source: `internal/wait/outcome.go:7-15`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WaitKind {
    /// Finished turn.
    Done,
    /// Failed or cancelled turn.
    Failed,
    /// Turn stopped on a pending approval.
    Approval,
    /// Turn that never ended before the deadline.
    #[default]
    Timeout,
}

/// One auto-approved record (turn's `AutoApproved`).
/// Source: `internal/approvals/approvals.go`
/// (`ApprovedRecord`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedRecord {
    /// Approval id.
    pub approval_id: String,
    /// Approval title.
    pub title: String,
    /// Permission-question kind.
    pub kind: String,
    /// Permission-question scope.
    pub scope: String,
    /// Decision sent (`allow_always` / `allow_once`).
    pub decision: String,
}

/// One auto-approve error record.
/// Source: `internal/approvals/approvals.go`
/// (`ApproveError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproveError {
    /// Approval id.
    pub approval_id: String,
    /// Allowlist summary of the error (never raw text).
    pub summary: String,
}

/// Result of offering fresh approvals to the approver.
/// Source: `internal/wait/waiter.go:520-560`
/// (`feedApprovals` consumes `ApproverResult`).
#[derive(Debug, Default)]
pub struct ApproveOutcome {
    /// Ids the approver handled (decided).
    pub handled: Vec<String>,
    /// Records of decisions made.
    pub approved: Vec<ApprovedRecord>,
    /// Per-id decide errors (non-fatal).
    pub errors: Vec<ApproveError>,
    /// Fatal approver error (auth failure): ends the wait
    /// as an error, never as needs_approval.
    pub fatal: Option<BotError>,
}

/// The turn's approver: decides fresh pending approvals.
/// The turn runner implements this over
/// `ClaimManager::approve_forever`.
/// Source: `internal/wait/waiter.go:164-167`
/// (`WithApprover`; Go's `approvals.Approver`).
pub trait WaitApprover: Send + Sync {
    /// Decide `fresh` approvals; never decide an id twice.
    fn approve(
        &self,
        fresh: &[Approval],
    ) -> Pin<Box<dyn Future<Output = ApproveOutcome> + Send + '_>>;
}

/// Event name: first truthy of `event`, `event_name`,
/// `type`.
/// Source: `internal/wait/events.go:67-80`.
#[must_use]
pub fn event_name(ev: &Value) -> String {
    for key in ["event", "event_name", "type"] {
        if let Some(s) = ev.get(key).and_then(Value::as_str)
            && !s.is_empty()
        {
            return s.to_string();
        }
    }
    String::new()
}

/// Event payload dict, or empty when absent / not a dict.
/// Source: `internal/wait/events.go:55-64`.
#[must_use]
pub fn payload(ev: &Value) -> serde_json::Map<String, Value> {
    ev.get("payload")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// Numeric seq from a history event, leniently: a
/// non-numeric or absent seq reads as 0.
/// Source: `internal/commands/wait.go:835-849`
/// (`eventSeq`).
#[must_use]
pub fn seq_of(ev: &Value) -> i64 {
    match ev.get("seq") {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                i
            } else if let Some(u) = n.as_u64() {
                u as i64
            } else {
                n.as_f64().map_or(0, |f| f as i64)
            }
        }
        _ => 0,
    }
}

/// Whether the event carries a numeric seq at all.
/// Source: `internal/commands/telegram_turn.go:1020-1035`
/// (`historySeq`).
#[must_use]
pub fn history_seq(ev: &Value) -> Option<i64> {
    match ev.get("seq") {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                Some(i)
            } else if let Some(u) = n.as_u64() {
                Some(u as i64)
            } else {
                n.as_f64().map(|f| f as i64)
            }
        }
        _ => None,
    }
}

/// Python truthiness for JSON values: nil, false, `""`,
/// 0, and empty lists/maps are falsy; everything else is
/// truthy. Source: `internal/wait/events.go:91-117`.
#[must_use]
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

/// First non-empty string among the values.
/// Source: `internal/wait/replies.go` (`firstText`).
fn first_text(vs: &[&Value]) -> String {
    for v in vs {
        if let Some(s) = v.as_str()
            && !s.is_empty()
        {
            return s.to_string();
        }
    }
    String::new()
}

/// First truthy value, or null.
/// Source: `internal/wait/replies.go` (`firstTruthy`).
fn first_truthy(vs: &[&Value]) -> Value {
    for v in vs {
        if truthy(v) {
            return (*v).clone();
        }
    }
    Value::Null
}

/// Whether `ev` belongs to the wait's scope. With a
/// thread, only events whose payload `session_id` is
/// absent or equal to the thread count; without one,
/// events marked `is_thread` in the payload do not. Only
/// payload fields are read.
/// Source: `internal/wait/events.go:82-89`.
#[must_use]
pub fn in_scope(ev: &Value, thread: &str) -> bool {
    let p = payload(ev);
    if !thread.is_empty() {
        let sid = p.get("session_id").and_then(Value::as_str);
        return sid.is_none_or(|s| s == thread);
    }
    let is_thread = p
        .get("is_thread")
        .is_some_and(|v| v.as_bool().unwrap_or(false));
    !is_thread
}

/// Whether `ev` is a proactive push talking to itself:
/// its `reply_to_message_id` exactly equals its own id.
/// Source: `internal/wait/replies.go:56-94`.
#[must_use]
pub fn is_self_referential(ev: &Value) -> bool {
    let p = payload(ev);
    let mut own: HashSet<String> = HashSet::new();
    for mid in [p.get("message_id"), ev.get("message_id")] {
        if let Some(s) = mid.and_then(Value::as_str)
            && !s.is_empty()
        {
            own.insert(s.to_string());
            if let Some(t) = s.strip_prefix("assistant-msg-") {
                own.insert(t.to_string());
            }
        }
    }
    if let Some(meta) = p.get("metadata").and_then(Value::as_object)
        && let Some(s) = meta
            .get("root_message_execution_id")
            .and_then(Value::as_str)
        && !s.is_empty()
    {
        own.insert(s.to_string());
    }
    for r in [ev.get("reply_to_message_id"), p.get("reply_to_message_id")] {
        if let Some(s) = r.and_then(Value::as_str)
            && !s.is_empty()
            && own.contains(s)
        {
            return true;
        }
    }
    false
}

/// Unanswered hatch widgets in `ev`: only payload-level
/// widgets; answered iff any of the six state keys holds
/// a value outside (nil, `""`, `[]`, `{}`); `false` and
/// `0` count as answered.
/// Source: `internal/wait/replies.go:181-227`.
#[must_use]
pub fn open_widgets(ev: &Value) -> Vec<Widget> {
    let p = payload(ev);
    let Some(list) = p.get("widgets").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for raw in list {
        let Some(w) = raw.as_object() else { continue };
        let state = w
            .get("state")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut answered = false;
        for key in [
            "value",
            "selected",
            "selection",
            "answer",
            "submitted",
            "response",
        ] {
            if let Some(v) = state.get(key)
                && !unanswered_value(v)
            {
                answered = true;
                break;
            }
        }
        if answered {
            continue;
        }
        let data = w.get("data").and_then(Value::as_object);
        let text = {
            let t = first_text(&[
                w.get("display_text").unwrap_or(&Value::Null),
                w.get("fallback_text").unwrap_or(&Value::Null),
            ]);
            if t.is_empty() { None } else { Some(t) }
        };
        let options = data
            .and_then(|d| d.get("options"))
            .cloned()
            .unwrap_or(Value::Null);
        out.push(Widget {
            id: w.get("widget_id").cloned().unwrap_or(Value::Null),
            kind: w
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            text,
            options,
        });
    }
    out
}

/// Whether `v` is one of (nil, `""`, `[]`, `{}`).
/// Source: `internal/wait/replies.go:229-244`.
fn unanswered_value(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(m) => m.is_empty(),
        _ => false,
    }
}

/// Whether `ev` references sandbox/media-raw media.
/// Source: `internal/wait/replies.go:246-283`.
#[must_use]
pub fn event_has_media(ev: &Value) -> bool {
    let p = payload(ev);
    let mut items: Vec<Value> = Vec::new();
    if let Some(data) = p.get("data").and_then(Value::as_object) {
        for val in data.values() {
            if let Some(list) = val.as_array() {
                items.extend(list.iter().cloned());
            }
        }
    }
    for src in [ev.get("resources"), p.get("resources")] {
        if let Some(list) = src.and_then(Value::as_array) {
            items.extend(list.iter().cloned());
        }
    }
    for raw in items {
        let item: serde_json::Map<String, Value> = match &raw {
            Value::String(s) => {
                let mut m = serde_json::Map::new();
                m.insert("path".to_string(), Value::String(s.clone()));
                m
            }
            Value::Object(m) => m.clone(),
            _ => continue,
        };
        let mut path = item
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if path.is_empty()
            && let Some(variants) = item.get("variants").and_then(Value::as_object)
        {
            path = variants
                .get("original")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
        }
        if !path.is_empty() && (path.starts_with("sandbox://") || path.contains("/media/raw/")) {
            return true;
        }
    }
    false
}

/// Filter history events to this turn's final replies.
/// Source: `internal/wait/replies.go:106-168`
/// (`RepliesAfter`).
#[must_use]
pub fn replies_after(events: &[Value], after_seq: i64, upto: Option<i64>) -> Vec<Reply> {
    let mut sorted: Vec<Value> = events.to_vec();
    sorted.sort_by_key(seq_of);
    let mut seen: HashSet<(i64, String)> = HashSet::new();
    let mut replies = Vec::new();
    for ev in &sorted {
        let seq = seq_of(ev);
        if seq <= after_seq || upto.is_some_and(|u| seq > u) {
            continue;
        }
        if ev.get("event_name").and_then(Value::as_str) != Some("message.assistant") {
            continue;
        }
        let p = payload(ev);
        if p.get("status").and_then(Value::as_str) != Some("completed") {
            continue;
        }
        if is_self_referential(ev) {
            continue;
        }
        let mid = {
            let v = first_truthy(&[
                p.get("message_id").unwrap_or(&Value::Null),
                ev.get("message_id").unwrap_or(&Value::Null),
            ]);
            v.as_str().unwrap_or("").to_string()
        };
        if !seen.insert((seq, mid.clone())) {
            continue;
        }
        let raw_text = first_text(&[
            p.get("display_text").unwrap_or(&Value::Null),
            p.get("content").unwrap_or(&Value::Null),
            ev.get("display_text").unwrap_or(&Value::Null),
        ]);
        let widgets = open_widgets(ev);
        let has_media = event_has_media(ev);
        if raw_text.is_empty() && widgets.is_empty() && !has_media {
            continue;
        }
        replies.push(Reply {
            seq,
            message_id: mid,
            text: clean_text(&raw_text),
            widgets,
            media: has_media,
            agent_id: p
                .get("agent_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            root_agent_id: p
                .get("root_agent_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        });
    }
    replies
}

/// Find the first (lowest-seq) `message.user` event above
/// `baseline` whose text contains, or is contained in,
/// the sent text. A nil text matches the first user event
/// above the baseline. An empty or whitespace-only text
/// matches nothing.
/// Source: `internal/wait/replies.go:285-331`
/// (`UserAck`).
#[must_use]
pub fn user_ack(events: &[Value], baseline: i64, text: Option<&str>) -> Option<i64> {
    if let Some(t) = text
        && t.trim().is_empty()
    {
        return None;
    }
    let mut sorted: Vec<Value> = events.to_vec();
    sorted.sort_by_key(seq_of);
    for ev in &sorted {
        let seq = seq_of(ev);
        if seq <= baseline || ev.get("event_name").and_then(Value::as_str) != Some("message.user") {
            continue;
        }
        let p = payload(ev);
        let t = first_text(&[
            p.get("display_text").unwrap_or(&Value::Null),
            p.get("content").unwrap_or(&Value::Null),
            ev.get("display_text").unwrap_or(&Value::Null),
        ]);
        match text {
            None => return Some(seq),
            Some(needle) => {
                let needle = needle.trim();
                if t.contains(needle) || needle.contains(t.trim()) {
                    return Some(seq);
                }
            }
        }
    }
    None
}

/// The waiting-phrase vocabulary, in list order: 21
/// Vietnamese + 13 English = 34. Order decides which
/// phrase is named when several match.
/// Source: `internal/wait/reason.go:15-55`.
pub const WAIT_PHRASES: &[&str] = &[
    "chờ boss",
    "chờ bạn",
    "tôi chờ",
    "mình chờ",
    "đợi boss",
    "đợi bạn",
    "boss muốn",
    "bạn muốn",
    "boss có muốn",
    "bạn có muốn",
    "trước khi tiếp tục",
    "trước khi làm tiếp",
    "boss xác nhận",
    "bạn xác nhận",
    "cần boss",
    "cần bạn",
    "boss quyết",
    "bạn quyết",
    "hay không?",
    "được không?",
    "nhé?",
    "should i",
    "do you want",
    "would you like",
    "waiting for your",
    "let me know if",
    "let me know whether",
    "please confirm",
    "can you confirm",
    "before i continue",
    "before i proceed",
    "shall i",
    "which do you prefer",
    "your call",
];

fn safety_re() -> &'static Regex {
    static SAFETY_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    SAFETY_RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:safety check|kiểm tra an toàn|cơ chế an toàn|tripped .{0,30}safety|refus(?:e|ed) to (?:run|do|continue)|từ chối (?:chạy|làm))",
        )
        .expect("safety regex is a literal")
    })
}

fn gate_prefix_re() -> &'static Regex {
    static GATE_PREFIX_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    GATE_PREFIX_RE.get_or_init(|| {
        Regex::new(r"(?i)(?:gate|policy)[ _-]?questions?").expect("gate regex is a literal")
    })
}

/// Whether `s` starts with "none" followed by a word
/// boundary (end of string or a non-word rune),
/// case-insensitively.
/// Source: `internal/wait/reason.go:123-134`.
fn starts_with_none_word(s: &str) -> bool {
    let lower = s.to_lowercase();
    let Some(rest) = lower.strip_prefix("none") else {
        return false;
    };
    let mut chars = rest.chars();
    match chars.next() {
        None => true,
        Some(r) => !(r.is_alphanumeric() || r == '_'),
    }
}

/// The Python gate regex
/// `(gate|policy)[ _-]?questions?\s*[:=]\s*(?!none\b)\S`,
/// with the separator whitespace and the negative
/// lookahead done by hand (no RE2 equivalent).
/// Source: `internal/wait/reason.go:71-120`.
fn gate_matches(t: &str) -> bool {
    let re = gate_prefix_re();
    for m in re.find_iter(t) {
        let rest = &t[m.end()..];
        let mut chars = rest.char_indices();
        let mut i = 0usize;
        for (idx, r) in &mut chars {
            if !r.is_whitespace() {
                i = idx;
                break;
            }
            i = idx + r.len_utf8();
        }
        if i >= rest.len() {
            continue;
        }
        let sep = rest[i..].chars().next().unwrap_or('\0');
        if sep != ':' && sep != '=' {
            continue;
        }
        let after = &rest[i + sep.len_utf8()..];
        let mut j = 0usize;
        for (idx, r) in after.char_indices() {
            if !r.is_whitespace() {
                j = idx;
                break;
            }
            j = idx + r.len_utf8();
        }
        if j >= after.len() {
            continue;
        }
        if starts_with_none_word(&after[j..]) {
            continue;
        }
        return true;
    }
    false
}

/// Classify the last reply's text, or "" when the reply
/// does not ask for input. Precedence, first match wins:
/// gate/policy regex, safety regex, waiting phrases in
/// list order, trailing question mark.
/// Source: `internal/wait/reason.go:147-169`.
#[must_use]
pub fn needs_input_reason(text: &str) -> String {
    let t = clean_text(text);
    if t.is_empty() {
        return String::new();
    }
    if gate_matches(&t) {
        return "gate/policy question".to_string();
    }
    if safety_re().is_match(&t) {
        return "stopped by a safety check".to_string();
    }
    let low = t.to_lowercase();
    for ph in WAIT_PHRASES {
        if low.contains(ph) {
            return format!("waiting phrase: '{ph}'");
        }
    }
    let tail = t.trim_end_matches(|c: char| {
        c == ' '
            || c == '\n'
            || c == '*'
            || c == '_'
            || c == '`'
            || c == ')'
            || c == '"'
            || c == '\''
    });
    let last_line = tail.lines().last().unwrap_or("").trim();
    if last_line.ends_with('?') || last_line.ends_with('？') {
        return "ends with a question".to_string();
    }
    String::new()
}

/// Map a kind and its final replies to an outcome:
/// `done` | `needs_input` | `needs_approval` |
/// `failed` | `timeout`. Only the last reply is
/// inspected, and only when kind is done.
/// Source: `internal/wait/outcome.go:26-45`.
#[must_use]
pub fn outcome_of(kind: WaitKind, replies: &[Reply]) -> &'static str {
    match kind {
        WaitKind::Approval => "needs_approval",
        WaitKind::Failed => "failed",
        WaitKind::Done => {
            if let Some(last) = replies.last()
                && (!last.widgets.is_empty() || !needs_input_reason(&last.text).is_empty())
            {
                return "needs_input";
            }
            "done"
        }
        WaitKind::Timeout => "timeout",
    }
}

/// Map a kind and its final replies to a process exit
/// code: 0 done, 2 failed, 4 needs a human, 124 timeout.
/// Source: `internal/wait/outcome.go:47-59`.
#[must_use]
pub fn exit_code(kind: WaitKind, replies: &[Reply]) -> i32 {
    match outcome_of(kind, replies) {
        "done" => EXIT_OK,
        "needs_input" | "needs_approval" => EXIT_HUMAN,
        "failed" => EXIT_FAILED,
        _ => EXIT_TIMEOUT,
    }
}

/// The pure turn-end state machine. Feed it events in
/// arrival order: the same event sequence in a different
/// order yields different outcomes, by design (replay
/// protection). The driver serialises all feeds through
/// one task. It never dials, never reads history, and
/// never generates a node id.
///
/// Deviation D1 (documented, deliberate): once a result
/// is set, `feed` refuses to change it.
/// Source: `internal/wait/waiter.go:180-236`.
pub struct Waiter {
    thread: String,
    handled: HashSet<String>,
    offered: HashSet<String>,
    approver_failed: HashSet<String>,
    seen_running: bool,
    result: Option<Outcome>,
    status: Option<String>,
    ignored_terminal: Option<String>,
    ignored_reason: String,
    ignored_term_seq: i64,
    ignored_term_has_seq: bool,
    root_id: Option<String>,
    boundary_unknown: bool,
    after_seq: Option<i64>,
    boundary_derived: bool,
    fatal_err: Option<BotError>,
    approved_records: Vec<ApprovedRecord>,
    approve_errors: Vec<ApproveError>,
    now_unix_millis: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl Waiter {
    /// New waiter scoped to `thread` ("" = unscoped:
    /// the payload `is_thread` rule applies).
    #[must_use]
    pub fn new(thread: &str) -> Self {
        Self {
            thread: thread.to_string(),
            handled: HashSet::new(),
            offered: HashSet::new(),
            approver_failed: HashSet::new(),
            seen_running: false,
            result: None,
            status: None,
            ignored_terminal: None,
            ignored_reason: String::new(),
            ignored_term_seq: 0,
            ignored_term_has_seq: false,
            root_id: None,
            boundary_unknown: false,
            after_seq: None,
            boundary_derived: false,
            fatal_err: None,
            approved_records: Vec::new(),
            approve_errors: Vec::new(),
            now_unix_millis: Arc::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0)
            }),
        }
    }

    /// Fixed wall clock (tests pin expiry).
    #[must_use]
    pub fn with_now(thread: &str, now_unix_millis: i64) -> Self {
        let mut w = Self::new(thread);
        w.now_unix_millis = Arc::new(move || now_unix_millis);
        w
    }

    /// Decided outcome, or `None` while waiting.
    #[must_use]
    pub fn result(&self) -> Option<&Outcome> {
        self.result.as_ref()
    }

    /// Fatal approver error, if any.
    #[must_use]
    pub fn fatal_err(&self) -> Option<&BotError> {
        self.fatal_err.as_ref()
    }

    /// Auto-approved records accumulated across approver
    /// calls, in offer order.
    #[must_use]
    pub fn approved_records(&self) -> &[ApprovedRecord] {
        &self.approved_records
    }

    /// Auto-approve error records, in offer order.
    #[must_use]
    pub fn approve_errors(&self) -> &[ApproveError] {
        &self.approve_errors
    }

    /// Whether a root-confirmed running for the learned
    /// root was seen.
    #[must_use]
    pub fn seen_running(&self) -> bool {
        self.seen_running
    }

    /// Last stored status (running or terminal only).
    #[must_use]
    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// Stored ignored terminal status, if any.
    #[must_use]
    pub fn ignored_terminal(&self) -> Option<&str> {
        self.ignored_terminal.as_deref()
    }

    /// Ignored reason: `"subagents"`, `"missing_root"`,
    /// or `""`.
    #[must_use]
    pub fn ignored_reason(&self) -> &str {
        &self.ignored_reason
    }

    /// Learned root id, if any.
    #[must_use]
    pub fn root_id(&self) -> Option<&str> {
        self.root_id.as_deref()
    }

    /// Whether the history boundary is unreadable.
    #[must_use]
    pub fn boundary_unknown(&self) -> bool {
        self.boundary_unknown
    }

    /// Install the driver-owned boundary.
    /// Source: `internal/wait/waiter.go:346-350`.
    pub fn set_boundary(&mut self, after_seq: i64, unknown: bool, derived: bool) {
        self.after_seq = Some(after_seq);
        self.boundary_unknown = unknown;
        self.boundary_derived = derived;
    }

    /// Feed one event; returns the decided outcome when
    /// this feed sets one, else `None`. Steps run in
    /// order and the order matters: approvals first, then
    /// the F8 re-arm, running, non-terminal, foreign-root,
    /// subagent-count, unconfirmed, proven-terminal and
    /// suspect steps.
    /// Source: `internal/wait/waiter.go:383-470`.
    pub async fn feed(
        &mut self,
        ev: &Value,
        approver: Option<&dyn WaitApprover>,
    ) -> Option<Outcome> {
        if self.result.is_some() {
            return self.result.clone();
        }
        if let Some(pend) = pending_approvals(ev)
            && !pend.is_empty()
        {
            return self.feed_approvals(ev, &pend, approver).await;
        }
        let info = task_status_info(ev, &self.thread)?;
        if !info.has_status {
            return None;
        }
        // F8 re-arm: runs for every info event that reaches
        // here, before any step below. Only the reason is
        // cleared; the terminal itself is kept.
        if self.ignored_reason == "subagents" && count_is_zero(&info.active_subagent_count) {
            self.ignored_reason = String::new();
        }
        let s = info.status.clone();
        if s == "running" {
            if info.root_confirmed {
                if self.root_id.is_none() {
                    self.root_id = Some(info.root_agent_id.clone());
                }
                if Some(info.root_agent_id.as_str()) == self.root_id.as_deref() {
                    self.seen_running = true;
                    self.ignored_terminal = None;
                    self.ignored_reason = String::new();
                    self.ignored_term_seq = 0;
                    self.ignored_term_has_seq = false;
                }
            }
            self.status = Some(s);
            return None;
        }
        if !is_terminal_status(&s) {
            return None;
        }
        // Foreign root: teaches nothing, status not updated.
        if self.root_id.is_some()
            && !info.root_agent_id.is_empty()
            && Some(info.root_agent_id.as_str()) != self.root_id.as_deref()
        {
            return None;
        }
        self.status = Some(s.clone());
        if truthy(&info.active_subagent_count) {
            self.store_ignored(&s, "subagents", ev);
            return None;
        }
        if !info.root_confirmed {
            self.store_ignored(&s, "missing_root", ev);
            return None;
        }
        if is_done_status(&s) || is_failed_status(&s) {
            if self.seen_running {
                let kind = if is_done_status(&s) {
                    WaitKind::Done
                } else {
                    WaitKind::Failed
                };
                self.result = Some(Outcome {
                    kind,
                    detail: s,
                    approvals: Vec::new(),
                });
                return self.result.clone();
            }
            self.store_ignored(&s, "", ev);
            return None;
        }
        // Suspect string: history proof required, even with
        // seen_running.
        self.store_ignored(&s, "", ev);
        None
    }

    fn store_ignored(&mut self, s: &str, reason: &str, ev: &Value) {
        self.ignored_terminal = Some(s.to_string());
        self.ignored_reason = reason.to_string();
        if let Some(seq) = history_seq(ev) {
            self.ignored_term_seq = seq;
            self.ignored_term_has_seq = true;
        } else {
            self.ignored_term_seq = 0;
            self.ignored_term_has_seq = false;
        }
    }

    async fn feed_approvals(
        &mut self,
        ev: &Value,
        pend: &[Value],
        approver: Option<&dyn WaitApprover>,
    ) -> Option<Outcome> {
        let p = payload(ev);
        let mut recent: HashSet<String> = HashSet::new();
        for key in ["recent_approvals", "recent"] {
            if let Some(list) = p.get(key).and_then(Value::as_array) {
                for e in list {
                    if let Some(em) = e.as_object()
                        && let Some(id) = em.get("approval_id").and_then(Value::as_str)
                        && !id.is_empty()
                        && truthy(em.get("decision").unwrap_or(&Value::Null))
                    {
                        recent.insert(id.to_string());
                    }
                }
            }
        }
        // [DEVIATION] Go dedupes by a nil-vs-present id key:
        // nil-id descriptions are all kept (never deduped).
        // `describe_approval` (M5a) collapses nil and "" to
        // "", so this port dedupes "" ids first-wins like any
        // other id. The difference only matters for server
        // approvals with no id at all.
        let mut described: Vec<Approval> = Vec::new();
        let mut seen_ids: HashSet<String> = HashSet::new();
        for a in pend {
            let d = describe_approval(a);
            if recent.contains(&d.id) {
                self.handled.insert(d.id.clone());
            }
            if self.expired(&d) {
                continue;
            }
            if seen_ids.contains(&d.id) {
                continue;
            }
            seen_ids.insert(d.id.clone());
            described.push(d);
        }
        if let Some(approver) = approver {
            let mut fresh: Vec<Approval> = Vec::new();
            for d in &described {
                if d.id.is_empty()
                    || self.offered.contains(&d.id)
                    || self.approver_failed.contains(&d.id)
                    || self.handled.contains(&d.id)
                {
                    continue;
                }
                fresh.push(d.clone());
            }
            if !fresh.is_empty() {
                for d in &fresh {
                    self.offered.insert(d.id.clone());
                }
                let res = approver.approve(&fresh).await;
                self.approved_records.extend(res.approved.iter().cloned());
                self.approve_errors.extend(res.errors.iter().cloned());
                if let Some(fatal) = res.fatal {
                    self.fatal_err = Some(fatal);
                    return None;
                }
                for id in &res.handled {
                    self.handled.insert(id.clone());
                }
            }
            let left: Vec<Approval> = described
                .iter()
                .filter(|d| !self.handled.contains(&d.id))
                .cloned()
                .collect();
            if left.is_empty() {
                return None;
            }
            described = left;
        } else if described.is_empty() {
            // Every pending approval is expired: keep waiting.
            return None;
        }
        self.result = Some(Outcome {
            kind: WaitKind::Approval,
            detail: String::new(),
            approvals: described,
        });
        self.result.clone()
    }

    fn expired(&self, d: &Approval) -> bool {
        // `expires_at_ms` is 0 when the server sent none
        // (M5a `Approval`); only a present value expires.
        d.expires_at_ms != 0 && d.expires_at_ms <= (self.now_unix_millis)()
    }

    /// Accept the ignored terminal when `chat.history`
    /// already holds a reply to the turn's message. FAILED
    /// terminals never settle here: they take the
    /// replayed-failed path only.
    /// Source: `internal/wait/waiter.go:657-687`.
    pub fn settle(&mut self, replies: &[Reply]) -> Option<Outcome> {
        let s = self.ignored_terminal.clone()?;
        if self.result.is_some() || self.boundary_unknown {
            return None;
        }
        if is_failed_status(&s) {
            return None;
        }
        let proof = replies.iter().any(|r| !r.subagent_shaped());
        if !proof {
            return None;
        }
        self.clear_ignored();
        let kind = if is_suspect_failed_status(&s) {
            WaitKind::Failed
        } else {
            WaitKind::Done
        };
        self.result = Some(Outcome {
            kind,
            detail: s,
            approvals: Vec::new(),
        });
        self.result.clone()
    }

    /// Accept a replayed FAILED terminal that provably ends
    /// the awaited turn: a standalone wait started after a
    /// cancel. SUSPECT_FAILED never takes this path.
    /// Source: `internal/wait/waiter.go:689-721`.
    pub fn accept_replayed_failed(&mut self, latest_user_seq: Option<i64>) -> Option<Outcome> {
        let s = self.ignored_terminal.clone()?;
        if self.result.is_some() || !is_failed_status(&s) {
            return None;
        }
        if self.boundary_unknown || self.after_seq.is_none() {
            return None;
        }
        if !self.ignored_reason.is_empty() && self.ignored_reason != "subagents" {
            return None;
        }
        if latest_user_seq != Some(self.after_seq.unwrap_or(0)) {
            return None;
        }
        self.clear_ignored();
        self.result = Some(Outcome {
            kind: WaitKind::Failed,
            detail: s,
            approvals: Vec::new(),
        });
        self.result.clone()
    }

    fn clear_ignored(&mut self) {
        self.ignored_terminal = None;
        self.ignored_reason = String::new();
        self.ignored_term_seq = 0;
        self.ignored_term_has_seq = false;
    }
}

/// Extract the pending list from an approvals event, or
/// `None`. Only events whose name starts with
/// `"approvals"` count; `pending_approvals` is preferred
/// and an explicitly empty list does not fall back to
/// `"pending"`.
/// Source: `internal/wait/waiter.go:352-367`.
fn pending_approvals(ev: &Value) -> Option<Vec<Value>> {
    if !event_name(ev).starts_with("approvals") {
        return None;
    }
    let p = payload(ev);
    let pend = match p.get("pending_approvals") {
        Some(v) if !v.is_null() => Some(v),
        _ => p.get("pending"),
    };
    pend.and_then(Value::as_array).cloned()
}

/// Extracted facts from one `task.status` event, or
/// `None` when the event is not a usable root task status.
/// Source: `internal/wait/waiter.go:88-145`.
struct TaskStatusInfo {
    status: String,
    has_status: bool,
    root_confirmed: bool,
    root_agent_id: String,
    active_subagent_count: Value,
}

fn task_status_info(ev: &Value, thread: &str) -> Option<TaskStatusInfo> {
    if event_name(ev) != "task.status" || !in_scope(ev, thread) {
        return None;
    }
    let p = payload(ev);
    let root = p
        .get("root_agent_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let agent = p
        .get("agent_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let root_present = truthy(p.get("root_agent_id").unwrap_or(&Value::Null));
    let agent_present = truthy(p.get("agent_id").unwrap_or(&Value::Null));
    if root_present && agent_present && agent != root {
        return None;
    }
    let mut info = TaskStatusInfo {
        status: String::new(),
        has_status: false,
        root_confirmed: root_present && agent == root,
        root_agent_id: root,
        active_subagent_count: p
            .get("active_subagent_count")
            .cloned()
            .unwrap_or(Value::Null),
    };
    match p.get("status") {
        Some(Value::String(s)) if !s.is_empty() => {
            info.status = s.to_lowercase();
            info.has_status = true;
        }
        Some(v) if truthy(v) => {
            let s = stringify_status(v).to_lowercase();
            info.status = s.clone();
            info.has_status = !s.is_empty();
        }
        _ => {}
    }
    Some(info)
}

/// A non-string truthy status stringifies, as Python's
/// `str(s).lower()` does.
/// Source: `internal/wait/waiter.go:147-159`.
fn stringify_status(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        Value::Bool(true) => "true".to_string(),
        Value::Bool(false) => String::new(),
        _ => serde_json::to_string(v)
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default(),
    }
}

/// Whether a subagent count equals exactly 0. None
/// (absent) does not re-arm; `false` counts as 0, as
/// Python's `False == 0` does.
/// Source: `internal/wait/waiter.go:730-745`.
fn count_is_zero(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => !*b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f == 0.0),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn running(root: &str) -> Value {
        json!({"event": "task.status", "payload": {"status": "running", "root_agent_id": root, "agent_id": root}})
    }

    fn terminal(status: &str, root: &str) -> Value {
        json!({"event": "task.status", "payload": {"status": status, "root_agent_id": root, "agent_id": root}})
    }

    #[tokio::test]
    async fn done_requires_seen_running() {
        let mut w = Waiter::new("");
        // Completed with no running seen: ignored, keep waiting.
        let out = w.feed(&terminal("completed", "r1"), None).await;
        assert!(out.is_none());
        assert_eq!(w.ignored_terminal(), Some("completed"));
        // Running (root-confirmed) clears the ignored terminal.
        let out = w.feed(&running("r1"), None).await;
        assert!(out.is_none());
        assert!(w.seen_running());
        assert!(w.ignored_terminal().is_none());
        // Now completed decides.
        let out = w.feed(&terminal("completed", "r1"), None).await;
        assert_eq!(
            out,
            Some(Outcome {
                kind: WaitKind::Done,
                detail: "completed".to_string(),
                approvals: Vec::new(),
            })
        );
        // D1: a later feed cannot flip the result.
        let out = w.feed(&terminal("interrupted", "r1"), None).await;
        assert_eq!(out.map(|o| o.kind), Some(WaitKind::Done));
    }

    #[tokio::test]
    async fn failed_terminal_decides_when_seen_running() {
        let mut w = Waiter::new("");
        w.feed(&running("r1"), None).await;
        let out = w.feed(&terminal("cancelled", "r1"), None).await;
        assert_eq!(
            out.map(|o| (o.kind, o.detail)),
            Some((WaitKind::Failed, "cancelled".to_string()))
        );
    }

    #[tokio::test]
    async fn suspect_terminal_needs_history_proof() {
        let mut w = Waiter::new("");
        w.feed(&running("r1"), None).await;
        // "done" is suspect: ignored even with seen_running.
        let out = w.feed(&terminal("done", "r1"), None).await;
        assert!(out.is_none());
        assert_eq!(w.ignored_terminal(), Some("done"));
        // No reply proof: settle refuses.
        assert!(w.settle(&[]).is_none());
        // A non-subagent reply proves it: suspect-done -> Done.
        let replies = vec![Reply {
            seq: 5,
            message_id: "m1".to_string(),
            text: "hi".to_string(),
            widgets: Vec::new(),
            media: false,
            agent_id: String::new(),
            root_agent_id: String::new(),
        }];
        let out = w.settle(&replies);
        assert_eq!(out.map(|o| o.kind), Some(WaitKind::Done));
    }

    #[tokio::test]
    async fn foreign_root_teaches_nothing() {
        let mut w = Waiter::new("");
        w.feed(&running("r1"), None).await;
        let out = w.feed(&terminal("completed", "r2"), None).await;
        assert!(out.is_none());
        assert!(w.ignored_terminal().is_none());
        assert_eq!(w.status(), Some("running"));
    }

    #[tokio::test]
    async fn subagents_hold_then_rearm_on_zero() {
        let mut w = Waiter::new("");
        w.feed(&running("r1"), None).await;
        let ev = json!({"event": "task.status", "payload": {"status": "completed", "root_agent_id": "r1", "agent_id": "r1", "active_subagent_count": 2}});
        let out = w.feed(&ev, None).await;
        assert!(out.is_none());
        assert_eq!(w.ignored_reason(), "subagents");
        // A later running event with count 0 re-arms the
        // reason (cleared), without deciding anything.
        let ev0 = json!({"event": "task.status", "payload": {"status": "running", "root_agent_id": "r1", "agent_id": "r1", "active_subagent_count": 0}});
        let out = w.feed(&ev0, None).await;
        assert!(out.is_none());
        assert_eq!(w.ignored_reason(), "");
        // A fresh proven terminal now decides.
        let out = w.feed(&terminal("completed", "r1"), None).await;
        assert_eq!(out.map(|o| o.kind), Some(WaitKind::Done));
    }

    #[test]
    fn replies_after_filters_window_status_and_dedupe() {
        let events = vec![
            json!({"seq": 9, "event_name": "message.assistant", "payload": {"status": "completed", "display_text": "old"}}),
            json!({"seq": 11, "event_name": "message.assistant", "payload": {"status": "completed", "display_text": "first", "message_id": "m1"}}),
            json!({"seq": 11, "event_name": "message.assistant", "payload": {"status": "completed", "display_text": "first", "message_id": "m1"}}),
            json!({"seq": 12, "event_name": "message.assistant", "payload": {"status": "running", "display_text": "partial"}}),
            json!({"seq": 13, "event_name": "message.user", "payload": {"status": "completed", "display_text": "user"}}),
        ];
        let replies = replies_after(&events, 10, None);
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].seq, 11);
        assert_eq!(replies[0].text, "first");
        // upto cap excludes seq 11.
        assert!(replies_after(&events, 10, Some(10)).is_empty());
    }

    #[test]
    fn user_ack_matches_contains_either_way() {
        let events = vec![
            json!({"seq": 5, "event_name": "message.user", "payload": {"display_text": "hello muse, do x"}}),
            json!({"seq": 6, "event_name": "message.user", "payload": {"display_text": "other"}}),
        ];
        assert_eq!(user_ack(&events, 4, Some("hello muse")), Some(5));
        // Sent text contained in the event text.
        assert_eq!(
            user_ack(&events, 4, Some("hello muse, do x and more")),
            Some(5)
        );
        // Baseline excludes seq 5.
        assert_eq!(user_ack(&events, 5, Some("hello muse")), None);
        // Empty needle matches nothing.
        assert_eq!(user_ack(&events, 4, Some("   ")), None);
        // Nil text matches the first user event above baseline.
        assert_eq!(user_ack(&events, 4, None), Some(5));
    }

    #[test]
    fn outcome_of_needs_input_via_widget_or_question() {
        let done = WaitKind::Done;
        assert_eq!(outcome_of(done, &[]), "done");
        let with_widget = vec![Reply {
            seq: 1,
            message_id: "m".to_string(),
            text: "pick one".to_string(),
            widgets: vec![Widget {
                id: json!(1),
                kind: "choice".to_string(),
                text: None,
                options: json!(["a"]),
            }],
            media: false,
            agent_id: String::new(),
            root_agent_id: String::new(),
        }];
        assert_eq!(outcome_of(done, &with_widget), "needs_input");
        let question = vec![Reply {
            seq: 1,
            message_id: "m".to_string(),
            text: "Should I continue?".to_string(),
            widgets: Vec::new(),
            media: false,
            agent_id: String::new(),
            root_agent_id: String::new(),
        }];
        assert_eq!(outcome_of(done, &question), "needs_input");
        assert_eq!(exit_code(done, &question), EXIT_HUMAN);
        assert_eq!(exit_code(WaitKind::Approval, &[]), EXIT_HUMAN);
        assert_eq!(exit_code(WaitKind::Failed, &[]), EXIT_FAILED);
        assert_eq!(exit_code(WaitKind::Timeout, &[]), EXIT_TIMEOUT);
    }

    #[test]
    fn needs_input_reason_literals() {
        assert_eq!(
            needs_input_reason("gate questions: which one?"),
            "gate/policy question"
        );
        assert_eq!(needs_input_reason("gate questions: none"), "");
        assert_eq!(
            needs_input_reason("The safety check stopped it"),
            "stopped by a safety check"
        );
        assert_eq!(
            needs_input_reason("boss có muốn tiếp tục không"),
            "waiting phrase: 'boss có muốn'"
        );
        assert_eq!(
            needs_input_reason("Done. What next?"),
            "ends with a question"
        );
        assert_eq!(needs_input_reason("Done."), "");
    }

    #[tokio::test]
    async fn approvals_event_without_approver_decides() {
        let mut w = Waiter::new("");
        let ev = json!({"event": "approvals.pending", "payload": {"pending_approvals": [{"approval_id": "a1", "display": {"summary_title": "Run shell", "permission_question": {"text": "Allow?"}}}]}});
        let out = w.feed(&ev, None).await;
        let out = out.expect("decides");
        assert_eq!(out.kind, WaitKind::Approval);
        assert_eq!(out.approvals.len(), 1);
        assert_eq!(out.approvals[0].id, "a1");
        assert_eq!(out.approvals[0].title, "Run shell");
    }
}
