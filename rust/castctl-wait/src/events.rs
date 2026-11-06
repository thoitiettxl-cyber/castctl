// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The two `internal/wait` pure helpers M5b left unported:
//! `decode_record` (`events.go`) and `question_of`
//! (`reason.go`), plus the runner's record-name helper
//! (`runner.go` `recordName`).

use castctl_shared::clean_text;
use serde::Deserialize;
use serde_json::Value;

/// Decode one NDJSON record into an event object, or `None`
/// when the record is empty, unparseable, not an object, or
/// followed by trailing data after one JSON value (Go
/// `internal/wait/events.go:28-46` `decodeRecord`). This is
/// the ONE NDJSON decoder for the wait package: both the
/// wait core and the Runner use it, so the trailing-data
/// rule is defined and tested exactly once, here.
///
/// Numbers decode with `arbitrary_precision` (the workspace
/// `serde_json` feature), so a seq keeps its literal
/// (`"120"`, as Go's `json.Number`) instead of rounding
/// through float64.
///
/// Deliberate deviation: Go's `encoding/json` coerces
/// invalid UTF-8 inside a string value to U+FFFD and still
/// decodes the record; `serde_json::from_slice` rejects
/// invalid UTF-8 outright. A record with invalid UTF-8
/// decodes to `None` here. Server NDJSON is valid UTF-8;
/// a malformed record is dropped either way.
#[must_use]
pub fn decode_record(record: &[u8]) -> Option<Value> {
    // Go trims Unicode whitespace first
    // (`bytes.TrimSpace`); `serde_json` only skips ASCII
    // whitespace, so trim here to accept a padded record.
    let trimmed: &[u8] = match std::str::from_utf8(record) {
        Ok(s) => s.trim().as_bytes(),
        Err(_) => record,
    };
    if trimmed.is_empty() {
        return None;
    }
    let mut de = serde_json::Deserializer::from_slice(trimmed);
    let v = Value::deserialize(&mut de).ok()?;
    // Exactly one JSON value: trailing data or garbage
    // after it rejects the record (Go's second `Decode`
    // must return `io.EOF`).
    de.end().ok()?;
    if !v.is_object() {
        return None;
    }
    Some(v)
}

/// Extract the question from reply text for display: the
/// last two question-bearing sentences (split after `.` /
/// `!` / `?` / `。` followed by whitespace), or the last
/// line when no sentence contains `?`, or `""` for empty
/// text (Go `internal/wait/reason.go:167-187` `QuestionOf`).
#[must_use]
pub fn question_of(text: &str) -> String {
    let t = clean_text(text);
    if t.is_empty() {
        return String::new();
    }
    let mut qs: Vec<String> = Vec::new();
    for s in split_sentences(&t) {
        let s = s.trim();
        if s.contains('?') {
            qs.push(s.to_string());
        }
    }
    if !qs.is_empty() {
        if qs.len() > 2 {
            qs.drain(..qs.len() - 2);
        }
        return qs.join(" ");
    }
    let lines = split_lines(&t);
    lines.last().cloned().unwrap_or_default()
}

/// Split after a sentence-ending rune (`.`, `!`, `?`, `。`)
/// followed by a whitespace run, keeping the punctuation
/// with the preceding sentence (Go `reason.go:190-212`
/// `splitSentences`).
fn split_sentences(t: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut start = 0usize;
    let mut it = t.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if c != '.' && c != '!' && c != '?' && c != '。' {
            continue;
        }
        let j = i + c.len_utf8();
        if j < t.len() && t[j..].chars().next().is_some_and(char::is_whitespace) {
            let mut k = j;
            while k < t.len() && t[k..].chars().next().is_some_and(char::is_whitespace) {
                k += t[k..].chars().next().unwrap_or(' ').len_utf8();
            }
            out.push(t[start..i + c.len_utf8()].to_string());
            start = k;
            // Skip ahead to the char at `k`.
            while let Some(&(ni, _)) = it.peek() {
                if ni >= k {
                    break;
                }
                it.next();
            }
        }
    }
    out.push(t[start..].to_string());
    out
}

/// Split like Python's `str.splitlines` on `\n`, `\r\n` and
/// `\r`. A trailing line break does not produce a final
/// empty line, but `"a\n\n"` keeps its empty middle line
/// (Go `reason.go:216-226` `splitLines`).
fn split_lines(t: &str) -> Vec<String> {
    let t = t.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<String> = t.split('\n').map(str::to_string).collect();
    if lines.len() > 1 && lines[lines.len() - 1].is_empty() && t.ends_with('\n') {
        lines.pop();
    }
    lines
}

/// The `cli.py` record name for one event: `event`, then
/// `event_name`. The `"type"` fallback of `eventName` does
/// NOT apply here (Go `internal/wait/runner.go:660-672`
/// `recordName`).
#[must_use]
pub fn record_name(ev: &Value) -> String {
    if let Some(s) = ev.get("event").and_then(Value::as_str)
        && !s.is_empty()
    {
        return s.to_string();
    }
    ev.get("event_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Go `internal/wait/events_test.go` `TestDecodeRecord`:
    /// the single test of the NDJSON trailing-data rule.
    #[test]
    fn decode_record_cases() {
        let ev =
            decode_record(br#"{"event":"task.status","seq":120,"payload":{"status":"running"}}"#);
        assert!(ev.is_some(), "valid record = {ev:?}");
        let ev = ev.unwrap();
        assert_eq!(ev["event"], json!("task.status"));
        // The seq must decode as json.Number 120, kept as a
        // literal by arbitrary_precision.
        assert_eq!(ev["seq"].to_string(), "120");
        for (name, rec) in [
            ("empty", ""),
            ("whitespace", "  \n "),
            ("invalid json", r#"{"status": "completed"#),
            ("non-object", "42"),
            ("trailing data", r#"{"event":"task.status"} {"x":1}"#),
            ("trailing garbage", r#"{"event":"task.status"} junk"#),
            ("array", "[1,2]"),
        ] {
            assert_eq!(decode_record(rec.as_bytes()), None, "{name}: {rec:?}");
        }
        // Leading/trailing whitespace around one object is fine.
        let ev = decode_record(b"  {\"event\":\"x\"}  \n");
        assert!(ev.is_some() && ev.unwrap()["event"] == json!("x"));
    }

    /// Go `internal/wait/reason_test.go` `TestQuestionOf`.
    #[test]
    fn question_of_cases() {
        for (text, want) in [
            ("First. What now? Second. Really?", "What now? Really?"),
            ("No question here.", "No question here."),
            ("", ""),
            ("One? Two? Three? Four?", "Three? Four?"),
            ("Done! Really? Yes.", "Really?"),
            ("Câu hỏi？ Tiếp theo。", "Câu hỏi？ Tiếp theo。"),
        ] {
            assert_eq!(question_of(text), want, "QuestionOf({text:?})");
        }
    }

    #[test]
    fn split_lines_python_semantics() {
        assert_eq!(split_lines("a\nb"), vec!["a", "b"]);
        assert_eq!(split_lines("a\n"), vec!["a"]);
        assert_eq!(split_lines("a\n\n"), vec!["a", ""]);
        assert_eq!(split_lines("a\r\nb\rc"), vec!["a", "b", "c"]);
        assert_eq!(split_lines(""), vec![""]);
    }

    #[test]
    fn record_name_no_type_fallback() {
        let ev = json!({"type": "task.status", "event_name": "task.status"});
        assert_eq!(record_name(&ev), "task.status");
        let ev = json!({"type": "task.status"});
        assert_eq!(record_name(&ev), "");
        let ev = json!({"event": "", "event_name": "delta.text_append"});
        assert_eq!(record_name(&ev), "delta.text_append");
    }
}
