// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The streaming preview: the Telegram bubble's live text,
//! fed by the wait follow's event callback.
//!
//! Go source: `internal/commands/telegram_preview.go`
//! (whole file; mirrors Python 0.6.1
//! `src/muse_cli/tgbot.py:312-518`).
//!
//! The final reply text is NEVER taken from here: it is
//! re-read from history by the wait result (`deliver_final`
//! in `turn.rs`), exactly as in Go. This preview only ever
//! shows growing text.
//!
//! Part keying is the subtle part (Go header comment):
//! one parts key per message, whatever id a delta carries.
//! A message's start may carry `message_id` while its
//! appends/done carry `message_seq` (or vice versa); both
//! ids seen on one event name the same message, keys are
//! namespaced by field, and the first id seen wins as
//! canonical. Keying on the raw id would split one message
//! into two parts, duplicating it on `message_done` and
//! truncating it on resubscribe.
//!
//! Elapsed-timer note (Go `telegram_turn.go:678-680`
//! comment vs `maybeEdit` code, research 01 §3.3): the
//! ticker "forces an edit attempt every second", but
//! `maybeEdit` returns early when the preview is not dirty
//! — and `dirty` is only set by `feed`, never by time
//! passing. So between deltas more than 1s apart the
//! bubble is NOT edited and the elapsed timer stands still
//! until the next delta. This port keeps Go's behaviour
//! (elapsed only changes when an edit happens), not the
//! comment's.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

use castctl_shared::clean_text;

/// Bubble shows only the last 3300 runes of the body,
/// with a `…` prefix when longer.
/// Source: `internal/commands/telegram_preview.go:183-184`.
pub const PREVIEW_TAIL_RUNES: usize = 3300;

/// Initial bubble status line.
/// Source: `internal/commands/telegram_preview.go:56-60`
/// (`newStreamPreview`).
pub const INITIAL_STATUS: &str = "⏳ Muse is working…";

/// First non-blank string, in order.
/// Source: `internal/commands/telegram_preview.go:332-334`.
fn first_non_blank(vs: &[&str]) -> String {
    for s in vs {
        if !s.is_empty() {
            return (*s).to_string();
        }
    }
    String::new()
}

/// Event name: first truthy of `event`, `event_name`,
/// `type`.
/// Source: `internal/commands/telegram_preview.go:313-321`.
fn preview_event_name(ev: &Value) -> String {
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
/// Source: `internal/commands/telegram_preview.go:323-328`.
fn preview_payload(ev: &Value) -> serde_json::Map<String, Value> {
    ev.get("payload")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// String field, or "" when absent / not a string.
/// Source: `internal/commands/telegram_preview.go:330-331`.
fn preview_string(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or("").to_string()
}

/// Renders an id field for part keying. Strings, JSON
/// numbers, and ints count; bools, nil, and other shapes
/// do not (a bool seq is not a number, as in `wait.seqOf`).
/// Source: `internal/commands/telegram_preview.go:336-360`.
fn preview_id_value(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                Some(i.to_string())
            } else if let Some(u) = n.as_u64() {
                Some(u.to_string())
            } else {
                n.as_f64().map(|f| (f as i64).to_string())
            }
        }
        _ => None,
    }
}

/// Truncate to at most `n` runes (no suffix).
/// Source: `internal/commands/telegram_preview.go:361-366`.
fn truncate_runes(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Format a duration like Python `fmt_secs`
/// (`tgbot.py:175-182`): `"Ns"` / `"Mm SSs"` / `"Hh MMm"`.
/// Source: `internal/commands/telegram_preview.go:230-241`.
#[must_use]
pub fn format_elapsed_secs(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{}h {:02}m", s / 3600, (s % 3600) / 60)
    }
}

struct PreviewInner {
    parts: HashMap<String, String>,
    order: Vec<String>,
    aliases: HashMap<String, String>,
    status: String,
    app_status: String,
    seen_work: bool,
    dirty: bool,
    started: Instant,
}

/// The streaming preview. Feed consumes one stream record;
/// it never blocks and never calls out (it runs on the
/// follow loop's goroutine via the event callback).
/// Source: `internal/commands/telegram_preview.go:39-211`.
pub struct StreamPreview {
    inner: Mutex<PreviewInner>,
}

impl StreamPreview {
    /// New preview, status `"⏳ Muse is working…"`.
    #[must_use]
    pub fn new(started: Instant) -> Self {
        Self {
            inner: Mutex::new(PreviewInner {
                parts: HashMap::new(),
                order: Vec::new(),
                aliases: HashMap::new(),
                status: INITIAL_STATUS.to_string(),
                app_status: String::new(),
                seen_work: false,
                dirty: false,
                started,
            }),
        }
    }

    /// Current status label (without the elapsed timer),
    /// for the `/status` "Now:" line: the same label the
    /// bubble shows.
    /// Source: `internal/commands/telegram_preview.go:206-211`.
    #[must_use]
    pub fn status_line(&self) -> String {
        self.inner
            .lock()
            .map(|i| i.status.clone())
            .unwrap_or_else(|_| INITIAL_STATUS.to_string())
    }

    /// Start time, for the `/status` elapsed timer.
    /// Source: `internal/commands/telegram_preview.go:213-218`.
    #[must_use]
    pub fn started_at(&self) -> Instant {
        self.inner
            .lock()
            .map(|i| i.started)
            .unwrap_or_else(|_| Instant::now())
    }

    /// Feed one event. See the module docs for the rules.
    /// Source: `internal/commands/telegram_preview.go:63-120`.
    pub fn feed(&self, ev: &Value) {
        let name = preview_event_name(ev);
        let payload = preview_payload(ev);
        let Ok(mut p) = self.inner.lock() else {
            return;
        };
        match name.as_str() {
            "delta.text_append" => {
                let key = part_key_locked(&mut p, &payload, ev);
                if !p.parts.contains_key(&key) {
                    p.order.push(key.clone());
                }
                let text = preview_string(payload.get("text"));
                let cur = p.parts.get(&key).cloned().unwrap_or_default();
                p.parts.insert(key, cur + &text);
                p.dirty = true;
            }
            "delta.message_start" => {
                // A re-subscription may restart a message's
                // stream: start it over. A start for an
                // unknown key creates nothing.
                let key = part_key_locked(&mut p, &payload, ev);
                if p.parts.contains_key(&key) {
                    p.parts.insert(key, String::new());
                }
            }
            "delta.message_done" => {
                let key = part_key_locked(&mut p, &payload, ev);
                let full = first_non_blank(&[
                    &preview_string(payload.get("content")),
                    &preview_string(payload.get("display_text")),
                    &preview_string(payload.get("text")),
                ]);
                if !full.trim().is_empty() {
                    if !p.parts.contains_key(&key) {
                        p.order.push(key.clone());
                    }
                    p.parts.insert(key, full);
                    p.dirty = true;
                }
            }
            "delta.presentation" => {
                // Live media: ignored; the bubble is not
                // frozen around files.
            }
            _ => {
                let mut st = preview_status_from_event(&name, &payload);
                let online = name == "agent.status"
                    && preview_string(payload.get("activity_code")) == "online";
                if name == "agent.status" && !st.is_empty() && !online {
                    p.seen_work = true;
                }
                if online && !p.seen_work {
                    // The replayed idle state from before
                    // this turn started: suppressed until
                    // real work is seen.
                    st = String::new();
                }
                if name == "agent.status" && !st.is_empty() {
                    p.app_status = st.clone();
                } else if !p.app_status.is_empty() && !name.starts_with("approvals") {
                    // The app's own status wins over derived
                    // tool labels.
                    st = String::new();
                }
                if !st.is_empty() && st != p.status {
                    p.status = st;
                    p.dirty = true;
                }
            }
        }
    }

    /// Render the bubble text at `now` (does not touch
    /// the dirty flag; only `render_and_clear` does).
    /// Source: `internal/commands/telegram_preview.go:158-166`.
    #[must_use]
    pub fn render_at(&self, now: Instant) -> String {
        let Ok(p) = self.inner.lock() else {
            return String::new();
        };
        render_locked(&p, now)
    }

    /// Render and clear the dirty flag in one lock hold,
    /// reporting whether the preview was dirty. A feed
    /// landing during an edit decision is still dirty for
    /// the next attempt.
    /// Source: `internal/commands/telegram_preview.go:167-174`.
    pub fn render_and_clear(&self, now: Instant) -> (String, bool) {
        let Ok(mut p) = self.inner.lock() else {
            return (String::new(), false);
        };
        let dirty = p.dirty;
        p.dirty = false;
        (render_locked(&p, now), dirty)
    }
}

/// Resolve one message's canonical parts key. The caller
/// holds the lock.
/// Source: `internal/commands/telegram_preview.go:122-149`.
fn part_key_locked(
    p: &mut PreviewInner,
    payload: &serde_json::Map<String, Value>,
    ev: &Value,
) -> String {
    let mut ids: Vec<String> = Vec::new();
    for field in ["message_id", "message_seq"] {
        if let Some(v) = preview_id_value(payload.get(field)) {
            ids.push(format!("{field}:{v}"));
            continue;
        }
        if let Some(v) = preview_id_value(ev.get(field)) {
            ids.push(format!("{field}:{v}"));
        }
    }
    for k in &ids {
        if let Some(canon) = p.aliases.get(k).cloned() {
            for j in &ids {
                p.aliases.insert(j.clone(), canon.clone());
            }
            return canon;
        }
    }
    let canon = if ids.is_empty() {
        "m".to_string()
    } else {
        ids[0].clone()
    };
    for k in &ids {
        p.aliases.insert(k.clone(), canon.clone());
    }
    canon
}

fn render_locked(p: &PreviewInner, now: Instant) -> String {
    let mut texts: Vec<String> = Vec::new();
    for key in &p.order {
        if let Some(t) = p.parts.get(key)
            && !t.trim().is_empty()
        {
            texts.push(t.clone());
        }
    }
    let mut body = clean_text(&texts.join("\n\n"));
    body = body.trim().to_string();
    let runes: Vec<char> = body.chars().collect();
    if runes.len() > PREVIEW_TAIL_RUNES {
        let tail: String = runes[runes.len() - PREVIEW_TAIL_RUNES..].iter().collect();
        body = format!("…{tail}");
    }
    let elapsed = format_elapsed_secs(now.duration_since(p.started));
    if body.is_empty() {
        format!("{} · {elapsed}", p.status)
    } else {
        format!("{body}\n\n{} · {elapsed}", p.status)
    }
}

/// Derive a status line from one event.
/// Source: `internal/commands/telegram_preview.go:243-258`.
fn preview_status_from_event(name: &str, payload: &serde_json::Map<String, Value>) -> String {
    match name {
        "delta.tool_start" => {
            let tool = first_non_blank(&[
                &preview_string(payload.get("tool_name")),
                &preview_string(payload.get("name")),
                &preview_string(payload.get("display_name")),
                &preview_string(payload.get("title")),
            ]);
            if tool.is_empty() {
                "🔧 using a tool".to_string()
            } else {
                format!("🔧 {tool}")
            }
        }
        "agent.status" => preview_app_status(payload),
        _ => String::new(),
    }
}

/// Render the live status line the Muse app shows:
/// `activity_emoji + activity_text`; generic "is working"
/// gets ⏳ and a subject; "online" means the turn end is
/// being confirmed.
/// Source: `internal/commands/telegram_preview.go:260-277`.
fn preview_app_status(payload: &serde_json::Map<String, Value>) -> String {
    if preview_string(payload.get("activity_code")) == "online" {
        return "⏳ Muse is wrapping up…".to_string();
    }
    let t = first_non_blank(&[
        &preview_string(payload.get("activity_text")),
        &preview_string(payload.get("status_text")),
    ]);
    let t = t.trim().to_string();
    if t.is_empty() {
        return String::new();
    }
    let emoji = truncate_runes(preview_string(payload.get("activity_emoji")).trim(), 8);
    let emoji = if emoji.is_empty() {
        "⏳".to_string()
    } else {
        emoji
    };
    format!("{} {}", emoji, truncate_runes(&preview_activity(&t), 120))
}

/// Name the subject of a generic activity:
/// "is working" -> "Muse is working".
/// Source: `internal/commands/telegram_preview.go:279-285`.
fn preview_activity(t: &str) -> String {
    let t = t.trim();
    if t.starts_with("is ") || t.starts_with("was ") {
        format!("Muse {t}")
    } else {
        t.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn preview() -> (StreamPreview, Instant) {
        let started = Instant::now();
        (StreamPreview::new(started), started)
    }

    #[test]
    fn append_and_done_replace_parts() {
        let (p, now) = preview();
        p.feed(
            &json!({"event": "delta.text_append", "payload": {"text": "Hel", "message_id": "m1"}}),
        );
        p.feed(
            &json!({"event": "delta.text_append", "payload": {"text": "lo", "message_id": "m1"}}),
        );
        let (text, dirty) = p.render_and_clear(now);
        assert!(dirty);
        assert!(text.starts_with("Hello\n\n"), "{text}");
        // message_done REPLACES the whole part (content wins
        // over display_text/text), it does not append.
        p.feed(&json!({"event": "delta.message_done", "payload": {"content": "Full text", "display_text": "Display", "text": "appended", "message_id": "m1"}}));
        let (text, _) = p.render_and_clear(now);
        assert!(text.starts_with("Full text\n\n"), "{text}");
    }

    #[test]
    fn blank_message_done_is_ignored() {
        let (p, now) = preview();
        p.feed(&json!({"event": "delta.text_append", "payload": {"text": "kept"}}));
        p.feed(&json!({"event": "delta.message_done", "payload": {"content": "   ", "text": ""}}));
        let (text, _) = p.render_and_clear(now);
        assert!(text.starts_with("kept\n\n"), "{text}");
    }

    #[test]
    fn message_start_resets_known_key_only() {
        let (p, now) = preview();
        p.feed(
            &json!({"event": "delta.text_append", "payload": {"text": "old", "message_id": "m1"}}),
        );
        // Start for an unknown key creates nothing.
        p.feed(&json!({"event": "delta.message_start", "payload": {"message_id": "m9"}}));
        let (text, _) = p.render_and_clear(now);
        assert!(text.starts_with("old\n\n"), "{text}");
        // Start for the known key resets it.
        p.feed(&json!({"event": "delta.message_start", "payload": {"message_id": "m1"}}));
        p.feed(
            &json!({"event": "delta.text_append", "payload": {"text": "new", "message_id": "m1"}}),
        );
        let (text, _) = p.render_and_clear(now);
        assert!(text.starts_with("new\n\n"), "{text}");
    }

    #[test]
    fn part_keying_aliases_message_id_and_seq() {
        let (p, now) = preview();
        // Start carries message_id; appends carry
        // message_seq — same message, one part.
        p.feed(&json!({"event": "delta.message_start", "payload": {"message_id": "abc"}}));
        p.feed(&json!({"event": "delta.text_append", "payload": {"text": "one", "message_id": "abc", "message_seq": 7}}));
        p.feed(
            &json!({"event": "delta.text_append", "payload": {"text": " two", "message_seq": 7}}),
        );
        let (text, _) = p.render_and_clear(now);
        assert!(text.starts_with("one two\n\n"), "{text}");
    }

    #[test]
    fn online_suppressed_until_real_work() {
        let (p, now) = preview();
        p.feed(&json!({"event": "agent.status", "payload": {"activity_code": "online"}}));
        // Suppressed: status stays the initial line.
        assert_eq!(p.status_line(), INITIAL_STATUS);
        let (text, dirty) = p.render_and_clear(now);
        assert!(!dirty);
        assert!(text.starts_with("⏳ Muse is working…"), "{text}");
        // Real work arrives: online now renders wrapping-up.
        p.feed(&json!({"event": "agent.status", "payload": {"activity_code": "thinking", "activity_text": "is working"}}));
        assert_eq!(p.status_line(), "⏳ Muse is working");
        p.feed(&json!({"event": "agent.status", "payload": {"activity_code": "online"}}));
        assert_eq!(p.status_line(), "⏳ Muse is wrapping up…");
    }

    #[test]
    fn app_status_wins_over_tool_label() {
        let (p, _) = preview();
        p.feed(&json!({"event": "delta.tool_start", "payload": {"tool_name": "shell"}}));
        assert_eq!(p.status_line(), "🔧 shell");
        p.feed(&json!({"event": "agent.status", "payload": {"activity_code": "thinking", "activity_text": "is reading"}}));
        assert_eq!(p.status_line(), "⏳ Muse is reading");
        // A later tool event must not overwrite the app status.
        p.feed(&json!({"event": "delta.tool_start", "payload": {"tool_name": "browser"}}));
        assert_eq!(p.status_line(), "⏳ Muse is reading");
    }

    #[test]
    fn preview_tail_keeps_last_3300_runes() {
        let (p, now) = preview();
        let body = "x".repeat(3301);
        p.feed(&json!({"event": "delta.text_append", "payload": {"text": body}}));
        let (text, _) = p.render_and_clear(now);
        let head = text.split("\n\n").next().unwrap_or("");
        assert_eq!(head.chars().count(), 3301); // … + 3300
        assert!(head.starts_with('…'));
        assert!(head.ends_with('x'));
    }

    #[test]
    fn elapsed_formats_match_python_fmt_secs() {
        assert_eq!(format_elapsed_secs(Duration::from_secs(0)), "0s");
        assert_eq!(format_elapsed_secs(Duration::from_secs(59)), "59s");
        assert_eq!(format_elapsed_secs(Duration::from_secs(60)), "1m 00s");
        assert_eq!(format_elapsed_secs(Duration::from_secs(3599)), "59m 59s");
        assert_eq!(format_elapsed_secs(Duration::from_secs(3600)), "1h 00m");
        assert_eq!(format_elapsed_secs(Duration::from_secs(7261)), "2h 01m");
    }

    #[test]
    fn render_and_clear_is_atomic_for_dirty() {
        let (p, now) = preview();
        let (_, dirty) = p.render_and_clear(now);
        assert!(!dirty);
        p.feed(&json!({"event": "delta.text_append", "payload": {"text": "a"}}));
        let (_, dirty) = p.render_and_clear(now);
        assert!(dirty);
        let (_, dirty) = p.render_and_clear(now);
        assert!(!dirty);
    }

    #[test]
    fn widget_markers_are_stripped_from_body() {
        let (p, now) = preview();
        p.feed(&json!({"event": "delta.text_append", "payload": {"text": "hi [[hatch_widget:{\"a\":1}]] there"}}));
        let (text, _) = p.render_and_clear(now);
        assert!(text.starts_with("hi  there\n\n"), "{text}");
    }
}
