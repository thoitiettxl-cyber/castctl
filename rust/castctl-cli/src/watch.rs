// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `watch` — tail live agent events: one JSON row per event
//! as it arrives (M7b PR-2).
//!
//! Go `internal/commands/read.go:643` (`cmdWatch`) via
//! `SubscribeRaw` (`chat.subscribe`, `noiseOnly`,
//! `streamMode: subscription`): the body carries
//! `capabilities: ["chat_cancel", "delta_stream"]` plus
//! `session_id` iff `--thread` is non-empty; `MaxRecords`
//! is `--n` (default 50), `IdleTimeout`/`OverallTimeout`
//! are `--timeout` (default 60s). `OnRecord` prints the
//! row and returns `false` (keep going); the subscription
//! ends on max records, idle/overall timeout, or error.
//!
//! Row shaping is `printWatchRow` (`read.go:677`), a pure
//! function ported verbatim below (incl. the R1-fix: EVERY
//! truthy key in the order `display_text, content, text,
//! activity_text, status` — not just the first).
//!
//! Deliberate deviation (timing only): Go prints each row
//! the moment it arrives (its `OnRecord` writes straight
//! to stdout); this CLI buffers every command's stdout in
//! `Ctx` and prints at the end (the same buffering every
//! other command uses), so rows appear when the
//! subscription ends, not live. The bytes are identical.
//!
//! Escaping trap (do NOT "fix" by rendering `\u0008`):
//! Go's stdlib `encoding/json` uses the `\b`/`\f`
//! short forms, exactly like `castctl_fsclient::
//! go_json_string` (the fs custom encoder agrees with
//! stdlib here). The string leaf reuses the network
//! escapers (`escape_go_marshal_string` for field
//! values, `json.Marshal` HTML ON; `escape_stdout_string`
//! for event/seq, `SetEscapeHTML(false)` HTML OFF).
//! U+2028/U+2029 are escaped in BOTH forms — Go escapes
//! them even with HTML off (verified by a `go run`
//! probe against `SetEscapeHTML(false)`); the first
//! version of the local escaper wrongly passed them
//! through raw when HTML was off.
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use castctl_gateway::subscribe::{SubscribeHandler, SubscribeOptions};
use serde_json::Value;

use crate::network::{
    CmdOut, classify_conn_error, escape_go_marshal_string, escape_stdout_string, render_flow_err,
};
use crate::parser::Parsed;
use crate::run::{FlowErr, GlobalOpts, msg, resolve_and_load_single};
use crate::runtime::{Runtime, build_runtime};

/// The five text-ish payload keys, in the exact order
/// `printWatchRow` scans them (Go `read.go:703`).
const WATCH_TEXT_KEYS: [&str; 5] = ["display_text", "content", "text", "activity_text", "status"];

/// The string leaf of `go_json_compact`: Go
/// `encoding/json` escaping, HTML ON for field values
/// (`writeWatchField`, `json.Marshal`) and HTML OFF
/// for event/seq (`marshalJSONLine`,
/// `SetEscapeHTML(false)`). Both reuse the network
/// escapers; U+2028/U+2029 are escaped in both forms
/// (Go escapes them even with HTML off — verified by
/// a `go run` probe against `SetEscapeHTML(false)`).
#[must_use]
pub(crate) fn go_json_string(s: &str, html_escape: bool) -> String {
    if html_escape {
        escape_go_marshal_string(s)
    } else {
        escape_stdout_string(s)
    }
}

/// Compact JSON for one decoded value, Go
/// `encoding/json` semantics (map keys sorted —
/// `serde_json::Value`'s `Map` is a `BTreeMap`, like
/// Go's sorted map keys). Numbers render as their
/// literal (`arbitrary_precision`, the same guarantee as
/// Go `decodeJSONNumber` with `UseNumber`).
#[must_use]
pub fn go_json_compact(v: &Value, html_escape: bool) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(true) => "true".to_string(),
        Value::Bool(false) => "false".to_string(),
        Value::Number(n) => n.as_str().to_string(),
        Value::String(s) => go_json_string(s, html_escape),
        Value::Array(items) => {
            let inner: Vec<String> = items
                .iter()
                .map(|i| go_json_compact(i, html_escape))
                .collect();
            format!("[{}]", inner.join(","))
        }
        Value::Object(map) => {
            let inner: Vec<String> = map
                .iter()
                .map(|(k, val)| {
                    format!(
                        "{}:{}",
                        go_json_string(k, html_escape),
                        go_json_compact(val, html_escape)
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
    }
}

/// Go `truthyJSON` (`read.go:717`): nil false; bool
/// itself; string non-empty; `json.Number` literal !=
/// `"0"`; `[]`/`map` non-empty; anything else true.
/// (The `float64` arm is dead in Go — `decodeJSONNumber`
/// uses `UseNumber`, so numbers are always literals —
/// and unreachable here for the same reason:
/// `arbitrary_precision` never yields an f64.)
#[must_use]
pub fn truthy_json(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_str() != "0",
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

/// Go `pythonStr` (`read.go:750`): string as-is; bool
/// → `True`/`False`; nil → `None`; `json.Number` →
/// the literal; anything else → compact JSON via
/// `marshalJSONLine` (HTML escaping OFF).
#[must_use]
pub fn python_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        Value::Number(n) => n.as_str().to_string(),
        Value::Array(_) | Value::Object(_) => go_json_compact(v, false),
    }
}

/// Go `truncRunes` (`commands.go:430`): at most `n`
/// runes (Unicode scalar values, like Go's `[]rune`).
#[must_use]
pub fn trunc_runes(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect()
    }
}

/// Go `printWatchRow` (`read.go:677`): shape one raw
/// record line into its output row (`\n`-terminated),
/// or `None` when the line is dropped (bad JSON,
/// non-object, `agent.status` without `--all`).
///
/// Decode is a single value (Go's one `Decode` call):
/// trailing garbage after valid JSON is ignored.
#[must_use]
pub fn print_watch_row(line: &[u8], show_all: bool) -> Option<String> {
    let mut de = serde_json::Deserializer::from_slice(line).into_iter::<Value>();
    let value = match de.next() {
        Some(Ok(v)) => v,
        _ => return None,
    };
    let obj = value.as_object()?;
    let event = match obj.get("event") {
        Some(v) if !v.is_null() => v.clone(),
        _ => obj.get("type").cloned().unwrap_or(Value::Null),
    };
    if let Value::String(s) = &event
        && s == "agent.status"
        && !show_all
    {
        return None;
    }
    let seq = obj.get("seq").cloned().unwrap_or(Value::Null);
    let mut out = String::new();
    out.push_str("{\"event\":");
    out.push_str(&go_json_compact(&event, false));
    out.push_str(",\"seq\":");
    out.push_str(&go_json_compact(&seq, false));
    if let Some(payload) = obj.get("payload").and_then(|p| p.as_object()) {
        for k in WATCH_TEXT_KEYS {
            let Some(v) = payload.get(k) else {
                continue;
            };
            if !truthy_json(v) {
                continue;
            }
            let rendered = trunc_runes(&python_str(v), 300);
            out.push(',');
            out.push_str(&escape_go_marshal_string(k));
            out.push(':');
            out.push_str(&escape_go_marshal_string(&rendered));
        }
    }
    out.push_str("}\n");
    Some(out)
}

/// The `SubscribeHandler` for `watch`: renders each
/// record the moment it arrives (Go's `OnRecord`) and
/// appends the row to `rows`; returns `false` (keep
/// going — Go's `false = keep going, true stops`).
pub struct WatchHandler {
    /// Rows rendered so far, in arrival order.
    pub rows: Vec<u8>,
    /// `--all`: keep `agent.status` rows.
    pub show_all: bool,
}

impl WatchHandler {
    /// A fresh handler with no rows yet.
    #[must_use]
    pub fn new(show_all: bool) -> Self {
        Self {
            rows: Vec::new(),
            show_all,
        }
    }
}

impl SubscribeHandler for WatchHandler {
    fn on_record<'a>(
        &'a mut self,
        record: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            if let Some(row) = print_watch_row(record, self.show_all) {
                self.rows.extend_from_slice(row.as_bytes());
            }
            false
        })
    }
}

/// Run `watch` against an already-built runtime: open
/// the `chat.subscribe` subscription and collect the
/// rows. A mid-subscription transport error keeps the
/// rows already rendered (Go prints them as they
/// arrive, so they survive the error): the error is
/// folded into `Ok(CmdOut{code, stderr})` instead of
/// `Err`, the same pattern `render_flow_err`'s docs
/// describe for approve-all's mid-loop lines.
pub(crate) async fn watch_async(rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    // Go passes the raw timeout straight through and
    // its SubscribeRaw defaults `<= 0` (10s idle /
    // 120s overall); Rust's `subscribe_raw` defaults
    // `0`, so clamp non-positive to zero instead of
    // wrapping a negative `i64` into a huge `u64`.
    let timeout = p.int_val("timeout");
    let dur = if timeout <= 0 {
        Duration::ZERO
    } else {
        Duration::from_secs(timeout as u64)
    };
    let mut body = serde_json::Map::new();
    body.insert(
        "capabilities".to_string(),
        Value::Array(vec![
            Value::String("chat_cancel".to_string()),
            Value::String("delta_stream".to_string()),
        ]),
    );
    let thread = p.str("thread");
    if !thread.is_empty() {
        body.insert("session_id".to_string(), Value::String(thread));
    }
    let opts = SubscribeOptions {
        body: Some(Value::Object(body)),
        max_records: p.int_val("n"),
        idle_timeout: dur,
        overall_timeout: dur,
        ..Default::default()
    };
    let mut handler = WatchHandler::new(p.bool("all"));
    match rt
        .shared
        .subscribe_raw("chat.subscribe", opts, &mut handler)
        .await
    {
        Ok(_) => Ok(CmdOut::bytes(handler.rows)),
        Err(e) => {
            let (code, stderr) = render_flow_err(&classify_conn_error(&e));
            Ok(CmdOut {
                stdout_bytes: handler.rows,
                stderr,
                code,
                ..Default::default()
            })
        }
    }
}

/// `watch` at the `Ctx` level (mirrors
/// `run_fs_command` / `run_send_command`): resolve +
/// load the single profile, build the runtime, run
/// `watch_async`, append the streams, exit non-zero
/// when the command reports a code.
pub(crate) fn run_watch_command(
    ctx: &mut crate::run::Ctx<'_>,
    g: &GlobalOpts,
    p: &Parsed,
) -> Result<(), FlowErr> {
    let (loc, single) = resolve_and_load_single(ctx, g)?;
    let profile_flag = if g.profile_set {
        Some(g.profile_flag.as_str())
    } else {
        None
    };
    let getenv = ctx.getenv;
    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| msg(1, format!("failed to start async runtime: {e}")))?;
    let p = p.clone();
    let out = tokio_rt.block_on(async move {
        let runtime = build_runtime(&loc, single.as_ref(), profile_flag, getenv)?;
        watch_async(&runtime, &p).await
    })?;
    ctx.out.stdout.push_str(&out.stdout);
    ctx.out.stdout_bytes.extend_from_slice(&out.stdout_bytes);
    ctx.out.stderr.push_str(&out.stderr);
    if out.code != 0 {
        return Err(FlowErr::Exit(out.code));
    }
    Ok(())
}

/// Run `watch` against an already-built runtime (a
/// fake gateway in tests) and return (stdout bytes,
/// stderr, exit code), rendering `FlowErr` exactly
/// like `run_driver_command` does. Test-only:
/// production never calls this.
pub async fn run_driver_watch(rt: &Runtime, p: &Parsed) -> (Vec<u8>, String, i32) {
    match watch_async(rt, p).await {
        Ok(out) => (out.stdout_combined(), out.stderr, out.code),
        Err(FlowErr::HelpShown) => (Vec::new(), String::new(), 0),
        Err(FlowErr::Exit(code)) => (Vec::new(), String::new(), code),
        Err(FlowErr::Verbatim { code, text }) => (
            Vec::new(),
            if text.is_empty() {
                String::new()
            } else {
                format!("{text}\n")
            },
            code,
        ),
        Err(FlowErr::Msg { code, message }) => (
            Vec::new(),
            message
                .map(|m| format!("castctl: {m}\n"))
                .unwrap_or_default(),
            code,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(line: &str, show_all: bool) -> Option<String> {
        print_watch_row(line.as_bytes(), show_all)
    }

    #[test]
    fn basic_row() {
        assert_eq!(
            row(
                r#"{"event":"agent.message","seq":6,"payload":{"display_text":"Hello"}}"#,
                false
            ),
            Some(
                "{\"event\":\"agent.message\",\"seq\":6,\"display_text\":\"Hello\"}\n".to_string()
            )
        );
    }

    #[test]
    fn all_five_keys_in_fixed_order() {
        // Input order scrambled; the row scans
        // display_text, content, text, activity_text,
        // status — every truthy key, not just the first.
        let got = row(
            r#"{"event":"agent.message","seq":1,"payload":{"status":"s","text":"t","display_text":"d","activity_text":"a","content":"c"}}"#,
            false,
        )
        .unwrap();
        assert_eq!(
            got,
            "{\"event\":\"agent.message\",\"seq\":1,\"display_text\":\"d\",\"content\":\"c\",\"text\":\"t\",\"activity_text\":\"a\",\"status\":\"s\"}\n"
        );
    }

    #[test]
    fn agent_status_dropped_unless_all() {
        let line = r#"{"event":"agent.status","seq":1,"payload":{"display_text":"working"}}"#;
        assert_eq!(row(line, false), None);
        assert_eq!(
            row(line, true),
            Some(
                "{\"event\":\"agent.status\",\"seq\":1,\"display_text\":\"working\"}\n".to_string()
            )
        );
    }

    #[test]
    fn event_falls_back_to_type() {
        assert_eq!(
            row(
                r#"{"type":"agent.message","seq":2,"payload":{"text":"hi"}}"#,
                false
            ),
            Some("{\"event\":\"agent.message\",\"seq\":2,\"text\":\"hi\"}\n".to_string())
        );
        // An explicit null event falls back too.
        assert_eq!(
            row(
                r#"{"event":null,"type":"agent.message","seq":2,"payload":{"text":"hi"}}"#,
                false
            ),
            Some("{\"event\":\"agent.message\",\"seq\":2,\"text\":\"hi\"}\n".to_string())
        );
    }

    #[test]
    fn bad_json_and_non_object_dropped() {
        assert_eq!(row("not-json", false), None);
        assert_eq!(row("[1,2]", false), None);
        assert_eq!(row("", false), None);
        // No event and no type: nulls, not a drop.
        assert_eq!(
            row(r#"{}"#, false),
            Some("{\"event\":null,\"seq\":null}\n".to_string())
        );
    }

    #[test]
    fn trailing_garbage_after_valid_json_parses() {
        // Go decodes one value and ignores the rest.
        assert_eq!(
            row(r#"{"event":"m","seq":1} trailing"#, false),
            Some("{\"event\":\"m\",\"seq\":1}\n".to_string())
        );
    }

    #[test]
    fn truncation_is_300_runes() {
        // Exact equality: the key `display_text` itself
        // contains an 'x', so counting matches would
        // miscount.
        let long = "x".repeat(301);
        let line = format!(
            "{{\"event\":\"agent.message\",\"seq\":1,\"payload\":{{\"display_text\":\"{long}\"}}}}"
        );
        assert_eq!(
            row(&line, false).unwrap(),
            format!(
                "{{\"event\":\"agent.message\",\"seq\":1,\"display_text\":\"{}\"}}\n",
                "x".repeat(300)
            )
        );
        // Exactly 300 runes is untouched.
        let exact = "x".repeat(300);
        let line = format!(
            "{{\"event\":\"agent.message\",\"seq\":1,\"payload\":{{\"display_text\":\"{exact}\"}}}}"
        );
        assert_eq!(
            row(&line, false).unwrap(),
            format!("{{\"event\":\"agent.message\",\"seq\":1,\"display_text\":\"{exact}\"}}\n")
        );
        // Rune count, not bytes: 301 multibyte runes
        // truncate to 300.
        let wide = "é".repeat(301);
        let line = format!(
            "{{\"event\":\"agent.message\",\"seq\":1,\"payload\":{{\"display_text\":\"{wide}\"}}}}"
        );
        assert_eq!(
            row(&line, false).unwrap(),
            format!(
                "{{\"event\":\"agent.message\",\"seq\":1,\"display_text\":\"{}\"}}\n",
                "é".repeat(300)
            )
        );
    }

    #[test]
    fn falsy_values_omitted() {
        let got = row(
            r#"{"event":"agent.message","seq":1,"payload":{"display_text":"","content":"c","text":0,"activity_text":false,"status":null}}"#,
            false,
        )
        .unwrap();
        assert_eq!(
            got,
            "{\"event\":\"agent.message\",\"seq\":1,\"content\":\"c\"}\n"
        );
    }

    #[test]
    fn number_truthiness_and_big_seq_literal() {
        // The literal "0" is falsy; "0.0" is truthy (Go
        // compares the json.Number literal to "0").
        let got = row(
            r#"{"event":"m","seq":1,"payload":{"display_text":"0.0"}}"#,
            false,
        )
        .unwrap();
        assert!(got.contains("\"display_text\":\"0.0\""), "{got}");
        assert_eq!(
            row(
                r#"{"event":"m","seq":9007199254740993,"payload":{"display_text":"x"}}"#,
                false
            ),
            Some("{\"event\":\"m\",\"seq\":9007199254740993,\"display_text\":\"x\"}\n".to_string())
        );
    }

    #[test]
    fn python_str_scalars() {
        let got = row(r#"{"event":"m","seq":1,"payload":{"status":true}}"#, false).unwrap();
        assert_eq!(got, "{\"event\":\"m\",\"seq\":1,\"status\":\"True\"}\n");
        // false is falsy, so it never reaches pythonStr.
        assert_eq!(
            row(r#"{"event":"m","seq":1,"payload":{"status":false}}"#, false),
            Some("{\"event\":\"m\",\"seq\":1}\n".to_string())
        );
    }

    #[test]
    fn html_escaping_differs_by_layer() {
        // Field values go through json.Marshal (HTML
        // escaping ON); event/seq go through
        // marshalJSONLine (HTML escaping OFF).
        let got = row(
            r#"{"event":"a<b","seq":1,"payload":{"display_text":"<a>&"}}"#,
            false,
        )
        .unwrap();
        assert_eq!(
            got,
            "{\"event\":\"a<b\",\"seq\":1,\"display_text\":\"\\u003ca\\u003e\\u0026\"}\n"
        );
    }

    #[test]
    fn control_escapes_use_short_forms() {
        // Go's encoding/json renders \x08 as \b and
        // \x0C as \f (the first version of this file
        // wrongly rendered \u0008/\u000c; the watch
        // harness caught it). \n and \t keep their
        // short forms too.
        let got = row(
            "{\"event\":\"m\",\"seq\":1,\"payload\":{\"display_text\":\"A\\u0008B\\u000cC\\nD\\tE\"}}",
            false,
        )
        .unwrap();
        assert_eq!(
            got,
            "{\"event\":\"m\",\"seq\":1,\"display_text\":\"A\\bB\\fC\\nD\\tE\"}\n"
        );
        assert_eq!(escape_go_marshal_string("A\x08B\x0cC"), "\"A\\bB\\fC\"");
        assert_eq!(escape_go_marshal_string("<>&"), "\"\\u003c\\u003e\\u0026\"");
        assert_eq!(escape_stdout_string("<>&"), "\"<>&\"");
        assert_eq!(escape_go_marshal_string("\u{2028}"), "\"\\u2028\"");
        assert_eq!(escape_stdout_string("\u{2028}"), "\"\\u2028\"");
    }

    #[test]
    fn list_value_is_compact_json_then_string_escaped() {
        // pythonStr renders the list as compact JSON
        // with HTML escaping OFF; the field encoder
        // then escapes that string with HTML ON.
        let got = row(
            r#"{"event":"m","seq":1,"payload":{"content":["a<b"]}}"#,
            false,
        )
        .unwrap();
        assert_eq!(
            got,
            "{\"event\":\"m\",\"seq\":1,\"content\":\"[\\\"a\\u003cb\\\"]\"}\n"
        );
    }

    #[test]
    fn handler_accumulates_rows_and_keeps_going() {
        let mut h = WatchHandler::new(false);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let stop = rt.block_on(h.on_record(
            b"{\"event\":\"agent.message\",\"seq\":1,\"payload\":{\"display_text\":\"hi\"}}",
        ));
        assert!(!stop);
        let stop = rt.block_on(h.on_record(b"not-json"));
        assert!(!stop);
        assert_eq!(
            String::from_utf8(h.rows).unwrap(),
            "{\"event\":\"agent.message\",\"seq\":1,\"display_text\":\"hi\"}\n"
        );
    }
}
