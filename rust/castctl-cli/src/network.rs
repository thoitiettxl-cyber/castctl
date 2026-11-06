// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The M4b network path: `classifyError` / `classifyConnError`
//! / `classifyAuthMessage` (`internal/commands/commands.go:
//! 268-337`, `347-396`), Go's `writeJSON` (indent 2,
//! `SetEscapeHTML(false)`), and the 13 read-only command
//! handlers (`internal/commands/read.go`).
//!
//! M7b adds the Phase A write/unary commands (session-*,
//! stop, seen, feed-react, idea-exec, approvals/approve/
//! deny, invite, redeem, wake, download, raw) plus the
//! driver seam `run_driver_command` (fake-server tests).
//! Handlers return `CmdOut` (stdout + stderr + exit code)
//! so the silent-exit commands (redeem exit 1, download
//! row-error exit 3) and the approveAll stderr lines work
//! through the same dispatch.
//!
//! Error rendering follows Go exactly, including the loop-6
//! boundary: the typed JSON's `error` field is
//! `logging.SummarizeErr` — the `LogSummary`, never message
//! bytes. For an `AuthError` that is `conn: auth_failed
//! message_length=N`; for a `GatewayError` that is Go's
//! `GatewayError.Error()` (`conn: gateway status=N[
//! body_length=M][ content_type=X][ error=Y]`), rendered here
//! from the `BodySummary` fields — NOT `TransportError::
//! log_summary()` (whose gateway shape is the M4a `render()`
//! deviation, kept for logs). For a plain error wrapped in a
//! typed auth error (the `Runtime.Cookies` stat/empty/read
//! cases) the field is the plain text itself (`SafeString`,
//! identity for these fixed messages).
//!
//! Exit codes (Go `classifyError` order, for the errors this
//! layer can see): typed auth 2, bare auth 2 (typed JSON),
//! gateway 3, timeout 4, cancelled 130 (empty text),
//! validation 2, everything else 1. Q8 option (b): ONLY
//! config parse/dispatch errors map to exit 2 — the runtime
//! builder (`runtime::build_runtime`) returns those as
//! `FlowErr::Msg{2, ...}` directly; call-time `Unsupported`
//! reaches here and maps to 1 via `TransportError::exit_code`
//! semantics.
//!
//! `writeJSON` shape: shaped outputs are compact JSON strings
//! from `castctl-shared` (Go declaration order, Go escaping)
//! re-indented with 2 spaces by `indent_json` (order
//! preserving, Go-encoder string rules — including the
//! `\b`→`\u0008` / `\f`→`\u000c` translation serde_json does
//! not apply, and raw U+2028/U+2029 escaping); passthrough
//! outputs are `serde_json::Value` compacted (keys sorted, as
//! Go's `json.Marshal` on a `map[string]any`) then put through
//! the same indenter.
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input.

use std::time::Duration;

use chrono::Local;

use castctl_gateway::auth::{fetch_access_token_base, fetch_session_info, fetch_session_info_base};
use castctl_gateway::invite::{
    create_invite_base, fetch_invite_base, redeem_invite_code_base, wake_vm_base,
};
use castctl_gateway::media_path;
use castctl_gateway::subscription::{SubscriptionOptions, fetch_subscription};
use castctl_shared::{
    JsonValue as SharedValue, Resource, event_resources, event_row_to_json, feed_row_to_json,
    feed_rows, file_row_to_json, file_rows, fmt_event, from_serde, goal_row_to_json, goal_rows,
    idea_row_to_json, idea_rows, invite_summary_to_json, local_abbr_now, local_name,
    session_row_to_json, session_rows, status_summary_to_json, summarize_invite, summarize_status,
    summarize_usage, usage_lines, usage_summary_to_json,
};
use castctl_transport::{BodySummary, RouteTable, TransportError};
use serde_json::Value as SerdeValue;

use crate::approvals::{
    approval_json, approved_json, approved_line, describe_approval, offers_forever, skipped_line,
};
use crate::parser::Parsed;
use crate::run::{Ctx, FlowErr, GlobalOpts, msg, msg_empty, resolve_and_load_single};
use crate::runtime::{Runtime, build_runtime};
use crate::table::CommandSpec;
use castctl_gateway::gateway::{Body, RequestOptions};

/// One compact JSON line, Go `json.Marshal` on a
/// `map[string]string`: keys sorted (`error` before `type`),
/// HTML escaping ON (`<`/`>`/`&` → `\u003c`/`\u003e`/`\u0026` —
/// unlike `writeJSON`, which disables it).
pub(crate) fn typed_json(typ: &str, summary: &str) -> String {
    format!(
        "{{\"error\":{},\"type\":{}}}",
        escape_go_marshal_string(summary),
        escape_go_marshal_string(typ)
    )
}

/// Go `encoding/json` string escaping with HTML escaping ON
/// (the `json.Marshal` default used by `classifyError`'s typed
/// branch and by request-body encoding): `"`/`\`/`\n`/`\r`/`\t`
/// short escapes, `<`/`>`/`&` as `\u003c`/`\u003e`/`\u0026`,
/// U+2028/U+2029 escaped, other control chars as `\u00XX`.
pub(crate) fn escape_go_marshal_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A typed auth failure: exit 2, one compact JSON line on
/// stderr, no `castctl: ` prefix (Go `typedAuthError` /
/// bare `AuthError` branch of `classifyError`, rendered by
/// `runInner` with `Fprintln`).
pub(crate) fn typed(typ: &str, summary: &str) -> FlowErr {
    FlowErr::Verbatim {
        code: 2,
        text: typed_json(typ, summary),
    }
}

/// Go `conn.AuthError.LogSummary()`: the class plus the
/// message length only — never message bytes.
pub(crate) fn auth_summary(message: &str) -> String {
    format!("conn: auth_failed message_length={}", message.len())
}

/// Go `classifyAuthMessage` (`commands.go:381`): substring
/// mapping over the `AuthError` message (the `"conn: "`
/// prefix of `Error()` carries no classified substring, so
/// the raw message is equivalent).
pub(crate) fn classify_auth_message(message: &str) -> FlowErr {
    let typ = if message.contains("could not parse cookies")
        || message.contains("no cookies")
        || message.contains("empty cookies")
    {
        "cookies_missing"
    } else if message.contains("api/session") || message.contains("VM unavailable") {
        "session_unavailable"
    } else if message.contains("auth/check") {
        "auth_check_failed"
    } else if message.contains("hatch/token") {
        "hatch_token_failed"
    } else {
        "auth_failed"
    };
    typed(typ, &auth_summary(message))
}

/// Go `conn.GatewayError.Error()` (`internal/conn/errors.go`):
/// `conn: gateway status=N[ body_length=M][
/// content_type=X][ error=Y]`. The fields were validated at
/// construction (allowlist gates), so they render verbatim;
/// an unknown length omits the field (loop 8, F1).
pub(crate) fn gateway_error_text(s: &BodySummary) -> String {
    let mut out = format!("conn: gateway status={}", s.status);
    if let Some(len) = s.body_length {
        out.push_str(&format!(" body_length={len}"));
    }
    if let Some(ct) = &s.content_type {
        out.push_str(&format!(" content_type={ct}"));
    }
    if let Some(code) = &s.error_code {
        out.push_str(&format!(" error={code}"));
    }
    out
}

/// Go `classifyConnError` (`commands.go:347`): the `read
/// cookies file` backstop, then `AuthError` →
/// `classifyAuthMessage`, then `GatewayError` status -1 with
/// the `vm_unavailable` marker (the Rust replacement for
/// Go's `Payload` substring check on `"VM unavailable"` —
/// the payload text is never stored, per the loop-5 rule) →
/// `session_unavailable`; anything else passes through to
/// `classify_error` unchanged.
pub(crate) fn classify_conn_error(err: &TransportError) -> FlowErr {
    if let TransportError::Auth { message } = err {
        if message.contains("read cookies file") {
            return typed("cookies_missing", &auth_summary(message));
        }
        return classify_auth_message(message);
    }
    if let TransportError::Gateway(summary) = err
        && summary.status == -1
        && summary.error_code.as_deref() == Some("vm_unavailable")
    {
        return typed("session_unavailable", &gateway_error_text(summary));
    }
    classify_error(err)
}

/// Go `classifyError` (`commands.go:268`) for the errors this
/// layer can see, in that function's check order. Plain
/// branches render through `FlowErr::Msg`, so `run_inner`
/// prepends `castctl: ` exactly once (Go's branches return
/// the prefix as part of the text); typed branches render
/// through `FlowErr::Verbatim` (no prefix).
pub(crate) fn classify_error(err: &TransportError) -> FlowErr {
    match err {
        TransportError::Auth { message } => typed("auth_failed", &auth_summary(message)),
        TransportError::Gateway(summary) => msg(3, gateway_error_text(summary)),
        TransportError::Timeout { message } => msg(4, format!("conn: {message}")),
        TransportError::Cancelled => msg_empty(130),
        TransportError::Validation { message } => msg(2, format!("gateway: {message}")),
        TransportError::ConnectionDown { message } => {
            if message.is_empty() {
                msg(1, "conn: connection down")
            } else {
                msg(1, format!("conn: connection down: {message}"))
            }
        }
        // Go `ConnectionError.LogSummary`: the inner summary
        // when the cause has one, else the class plus the
        // cause length only. The Rust cause is flattened
        // into `message`, so the length form is used.
        TransportError::ConnectionError { message } => msg(
            1,
            format!("conn: connection error error_length={}", message.len()),
        ),
        TransportError::RedirectRefused => msg(1, "redirect refused: redirects are not followed"),
        // Call-time `Unsupported` is a runtime error (Q8
        // option (b)): exit 1, unlike dispatch-time
        // `Unsupported` (exit 2, decided in the builder).
        TransportError::Unsupported { .. } => msg(1, err.to_string()),
    }
}

/// Go `writeJSON` (`commands.go:411`): indented JSON (2
/// spaces, HTML unescaped) plus a trailing newline.
pub(crate) fn write_json_text(compact: &str) -> String {
    let mut out = indent_json(compact);
    out.push('\n');
    out
}

/// `writeJSON` for a passthrough `serde_json::Value` (Go
/// `json.Marshal` on a `map[string]any`: keys sorted):
/// compact first, then the shared indenter.
pub(crate) fn write_json_serde(v: &SerdeValue) -> Result<String, FlowErr> {
    match serde_json::to_string(v) {
        Ok(s) => Ok(write_json_text(&s)),
        Err(_) => Err(msg(1, "failed to serialize gateway response")),
    }
}

/// Re-indent compact JSON with 2 spaces, Go-encoder style:
/// `": "` after object keys, `",\n"` between members, empty
/// `{}`/`[]` stay compact, key order preserved (the input is
/// scanned as tokens, never re-parsed into a map). String
/// tokens are copied with Go's encoder rules applied where
/// serde_json differs: `\b` → `\u0008`, `\f` → `\u000c`
/// (Go has no `\b`/`\f` short escapes), raw U+2028/U+2029 →
/// `\u2028`/`\u2029` (Go always escapes them, even with
/// `SetEscapeHTML(false)`).
pub(crate) fn indent_json(compact: &str) -> String {
    let chars: Vec<char> = compact.chars().collect();
    let mut out = String::with_capacity(compact.len() + 32);
    let mut depth = 0usize;
    let mut i = 0usize;
    let n = chars.len();
    while i < n {
        let c = chars[i];
        match c {
            '{' | '[' => {
                let close = if c == '{' { '}' } else { ']' };
                if i + 1 < n && chars[i + 1] == close {
                    out.push(c);
                    out.push(close);
                    i += 2;
                } else {
                    out.push(c);
                    depth += 1;
                    out.push('\n');
                    for _ in 0..depth {
                        out.push_str("  ");
                    }
                    i += 1;
                }
            }
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                out.push('\n');
                for _ in 0..depth {
                    out.push_str("  ");
                }
                out.push(c);
                i += 1;
            }
            ',' => {
                out.push(',');
                out.push('\n');
                for _ in 0..depth {
                    out.push_str("  ");
                }
                i += 1;
            }
            ':' => {
                out.push_str(": ");
                i += 1;
            }
            '"' => {
                out.push('"');
                i += 1;
                while i < n {
                    let sc = chars[i];
                    if sc == '"' {
                        out.push('"');
                        i += 1;
                        break;
                    }
                    if sc == '\\' && i + 1 < n {
                        match chars[i + 1] {
                            'b' => out.push_str("\\u0008"),
                            'f' => out.push_str("\\u000c"),
                            e => {
                                out.push('\\');
                                out.push(e);
                            }
                        }
                        i += 2;
                    } else if sc == '\u{2028}' {
                        out.push_str("\\u2028");
                        i += 1;
                    } else if sc == '\u{2029}' {
                        out.push_str("\\u2029");
                        i += 1;
                    } else {
                        out.push(sc);
                        i += 1;
                    }
                }
            }
            c if c.is_whitespace() => {
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Go `%T` for a decoded JSON value (`callMap`'s
/// not-an-object error). Numbers decode as `json.Number`
/// (`decodeJSONValue` uses `UseNumber`), never `float64`.
pub(crate) fn go_type_name(v: &SerdeValue) -> &'static str {
    match v {
        SerdeValue::Null => "<nil>",
        SerdeValue::Bool(_) => "bool",
        SerdeValue::Number(_) => "json.Number",
        SerdeValue::String(_) => "string",
        SerdeValue::Array(_) => "[]interface {}",
        SerdeValue::Object(_) => "map[string]interface {}",
    }
}

/// One gateway call through the shared connection, with
/// `classifyConnError` applied (Go `callJSON` + `runNetwork`
/// wrapping).
async fn call_json(
    rt: &Runtime,
    method: &str,
    opts: RequestOptions,
) -> Result<SerdeValue, FlowErr> {
    rt.shared
        .call_json(method, opts)
        .await
        .map_err(|e| classify_conn_error(&e))
}

/// `callJSON` + the object check (Go `callMap`): a
/// non-object result is a plain error, exit 1.
async fn call_map(rt: &Runtime, method: &str, opts: RequestOptions) -> Result<SerdeValue, FlowErr> {
    let v = call_json(rt, method, opts).await?;
    if v.is_object() {
        Ok(v)
    } else {
        Err(msg(
            1,
            format!(
                "gateway: {method} result is not an object: {}",
                go_type_name(&v)
            ),
        ))
    }
}

/// Go `historyResult` (`read.go`): `chat.history` with
/// `{"limit": limit}` plus `session_id` when a thread is
/// given; returns the full object and its `chat_events` list
/// (missing / non-array → empty).
async fn history_result(
    rt: &Runtime,
    thread: &str,
    limit: i64,
) -> Result<(SerdeValue, Vec<SerdeValue>), FlowErr> {
    let mut body = serde_json::Map::new();
    body.insert("limit".to_string(), SerdeValue::Number(limit.into()));
    if !thread.is_empty() {
        body.insert(
            "session_id".to_string(),
            SerdeValue::String(thread.to_string()),
        );
    }
    let d = call_map(
        rt,
        "chat.history",
        RequestOptions {
            body: Body::Json(SerdeValue::Object(body)),
            ..Default::default()
        },
    )
    .await?;
    let events = d
        .get("chat_events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    Ok((d, events))
}

/// One handler's output: stdout text, stderr text, and the
/// exit code (0 for the normal path). Go handlers write
/// stdout/stderr through `Env` and return an error for the
/// exit code; the Rust dispatch collects the same three
/// values so the silent-exit commands (redeem exit 1,
/// download row-error exit 3) and the approveAll stderr
/// lines flow through one return type. `run_network_command`
/// appends both streams and turns a non-zero code into
/// `FlowErr::Exit`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CmdOut {
    /// Bytes for stdout.
    pub stdout: String,
    /// Bytes for stderr (approveAll lines; on a mid-loop
    /// decide failure, those lines plus the rendered error
    /// text — see `render_flow_err`).
    pub stderr: String,
    /// Process exit code (0 = success).
    pub code: i32,
}

impl CmdOut {
    /// Stdout only, exit 0.
    pub(crate) fn out(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            code: 0,
        }
    }

    /// Stdout with a non-zero exit code and no stderr
    /// (redeem failure, download row error: Go's
    /// `errCode(N, nil)` after printing).
    pub(crate) fn code(stdout: String, code: i32) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            code,
        }
    }
}

/// A request body in Go struct field order, built from
/// ordered (key, JSON-fragment) pairs. Go marshals struct
/// bodies in declaration order and map bodies in sorted
/// key order; `Body::Json(serde_json::Value)` sorts keys,
/// which matches the map cases but NOT the struct cases
/// (session-start params: origin, lifecycle, title).
/// Callers pass values already escaped with
/// `escape_go_marshal_string` (Go `json.Marshal` string
/// rules, HTML escaping ON) or raw JSON literals.
fn ordered_body(pairs: &[(&str, String)]) -> Body {
    let mut out = String::from("{");
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&escape_go_marshal_string(k));
        out.push(':');
        out.push_str(v);
    }
    out.push('}');
    Body::Bytes(out.into_bytes())
}

/// Go `logging.SummarizeErr` for the error kinds a
/// download row can carry (`internal/shared/resources.
/// go:297`): the allowlist summary only, never peer text.
/// Auth and Cancelled never reach a row (they propagate);
/// they are rendered here only for completeness.
fn summarize_transport_error(err: &TransportError) -> String {
    match err {
        TransportError::Auth { message } => auth_summary(message),
        TransportError::Gateway(summary) => gateway_error_text(summary),
        TransportError::Timeout { message } => format!("conn: {message}"),
        TransportError::Cancelled => String::new(),
        TransportError::Validation { message } => format!("gateway: {message}"),
        TransportError::ConnectionDown { message } => {
            if message.is_empty() {
                "conn: connection down".to_string()
            } else {
                format!("conn: connection down: {message}")
            }
        }
        TransportError::ConnectionError { message } => {
            format!("conn: connection error error_length={}", message.len())
        }
        TransportError::RedirectRefused => {
            "redirect refused: redirects are not followed".to_string()
        }
        TransportError::Unsupported { .. } => err.to_string(),
    }
}

/// Go `%v` of an `os` error prints the lowercase message
/// (`permission denied`); Rust's `Display` appends
/// ` (os error N)`. Strip that suffix so filesystem
/// error text matches Go.
fn io_error_text(e: &std::io::Error) -> String {
    let text = e.to_string();
    match text.rfind(" (os error ") {
        Some(idx) if text.ends_with(')') => text[..idx].to_string(),
        _ => text,
    }
}

/// Go `filepath.Abs`: the lexical absolute path (cwd +
/// clean, no filesystem access). `std::path::absolute`
/// is not used: it keeps `.` components on some inputs,
/// while Go's `Clean` removes them.
fn abs_path(p: &str) -> String {
    use std::path::{Component, Path, PathBuf};
    let path = Path::new(p);
    let joined: PathBuf = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => path.to_path_buf(),
        }
    };
    let mut out = PathBuf::new();
    for c in joined.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out.to_string_lossy().into_owned()
}

/// Go `writeMergedJSON` (`read.go:345`): `{"status":
/// status, **body}` with status first and the body keys
/// in sorted order (Go maps have no wire order). Each
/// value is rendered with `marshalJSONIndent` (indent 2,
/// prefix "  " on continuation lines — see
/// `marshal_json_indent`).
fn write_merged_json(status: i32, body: &serde_json::Map<String, SerdeValue>) -> String {
    let mut out = String::from("{\n");
    out.push_str(&format!("  \"status\": {status}"));
    let mut keys: Vec<&String> = body.keys().collect();
    keys.sort();
    for k in keys {
        let v = &body[k];
        out.push_str(",\n  ");
        out.push_str(&escape_go_marshal_string(k));
        out.push_str(": ");
        out.push_str(&marshal_json_indent(v));
    }
    out.push_str("\n}\n");
    out
}

/// Go `marshalJSONIndent` (`read.go:368`): `json.Encoder`
/// with `SetEscapeHTML(false)`, prefix `"  "`, indent
/// `"  "`. The prefix lands on continuation lines only
/// (never the first line), so: indent the compact value
/// with `indent_json`, then prefix every line after the
/// first with two spaces. Scalars stay single-line.
fn marshal_json_indent(v: &SerdeValue) -> String {
    let compact = match serde_json::to_string(v) {
        Ok(s) => s,
        Err(_) => return "null".to_string(),
    };
    let indented = indent_json(&compact);
    let mut out = String::new();
    for (i, line) in indented.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
            out.push_str("  ");
        }
        out.push_str(line);
    }
    out
}

/// Go `decodeJSONNumber` (`commands.go:440`): decode the
/// first JSON value, IGNORING trailing data (unlike the
/// gateway's `decodeJSONValue`, which rejects it).
/// DEVIATION (recorded in PORTING.md §M7b): the error
/// text on malformed input is serde_json's, not Go's
/// `encoding/json` text; fake tests use valid bodies.
fn decode_json_number_loose(data: &[u8]) -> Result<SerdeValue, String> {
    let mut stream = serde_json::Deserializer::from_slice(data).into_iter::<SerdeValue>();
    match stream.next() {
        Some(Ok(v)) => Ok(v),
        Some(Err(e)) => Err(e.to_string()),
        None => Err("unexpected end of JSON input".to_string()),
    }
}

/// Go `eventHasText` (`read.go:465`): the payload's
/// `display_text`/`content` is a non-empty string, or a
/// present non-null non-`false` value of any other kind.
/// NOTE the quirk: an EMPTY string still counts in the
/// second arm (`"" != false` in Go), so it must not be
/// filtered by a truthiness check.
fn event_has_text(ev: &SerdeValue) -> bool {
    let Some(p) = ev.get("payload").and_then(|v| v.as_object()) else {
        return false;
    };
    for key in ["display_text", "content"] {
        if let Some(s) = p.get(key).and_then(|v| v.as_str())
            && !s.is_empty()
        {
            return true;
        }
    }
    for key in ["display_text", "content"] {
        if let Some(v) = p.get(key)
            && !v.is_null()
            && v.as_bool() != Some(false)
        {
            return true;
        }
    }
    false
}

/// Go `filterEvents` (`read.go:476`): events that are maps
/// with text, shaped in order; never null (empty → `[]`).
fn filter_events(events: &[SerdeValue]) -> Vec<String> {
    events
        .iter()
        .filter(|ev| ev.is_object() && event_has_text(ev))
        .map(|ev| event_row_to_json(&fmt_event(&from_serde(ev))))
        .collect()
}

/// `[` + comma-joined compact row JSON + `]` (empty → `[]`,
/// never `null` — every handler replaces a nil row slice
/// with an empty one, as Go does).
fn rows_json(items: &[String]) -> String {
    let mut out = String::with_capacity(items.iter().map(String::len).sum::<usize>() + 2);
    out.push('[');
    out.push_str(&items.join(","));
    out.push(']');
    out
}

/// Go `statusVMID` (`read.go:111`): the profile's `vm_id`
/// when configured, else `FetchSessionInfo` over the
/// dialer's HTTP client.
async fn status_vm_id(rt: &Runtime) -> Result<String, FlowErr> {
    if !rt.profile.vm_id.is_empty() {
        return Ok(rt.profile.vm_id.clone());
    }
    let cookies = rt.cookies()?;
    let info = fetch_session_info(&rt.http, &cookies)
        .await
        .map_err(|e| classify_conn_error(&e))?;
    Ok(info.vm_id)
}

/// `cmdStatus` (`read.go:126`): `sessions.list` →
/// `chat.unread_count` → `identity` → `statusVMID`, then
/// `writeJSON(SummarizeStatus(...))`.
async fn cmd_status(rt: &Runtime) -> Result<String, FlowErr> {
    let sessions = call_map(rt, "sessions.list", RequestOptions::default()).await?;
    let unread = call_json(rt, "chat.unread_count", RequestOptions::default()).await?;
    let identity = call_json(rt, "identity", RequestOptions::default()).await?;
    let vm_id = status_vm_id(rt).await?;
    let summary = summarize_status(
        &vm_id,
        &from_serde(&sessions),
        from_serde(&unread),
        from_serde(&identity),
    );
    Ok(write_json_text(&status_summary_to_json(&summary)))
}

/// `cmdUsage` (`read.go:155`): cookies first (typed
/// `cookies_missing` on failure), then `FetchSubscription`
/// with the profile's action id, no store (re-discovers
/// every call, as Go does — a read command must not rewrite
/// the config). `--raw` prints the raw subscription object;
/// `--json` prints `SummarizeUsage`; otherwise the text
/// lines (`UsageLines`, local TZ abbreviation of now).
async fn cmd_usage(rt: &Runtime, p: &Parsed) -> Result<String, FlowErr> {
    let cookies = rt.cookies()?;
    let (sub, _action_id) = fetch_subscription(
        &rt.http,
        &cookies,
        SubscriptionOptions {
            action_id: rt.profile.subscription_action_id.clone(),
            include_agreement: false,
            store: None,
            page: String::new(),
        },
    )
    .await
    .map_err(|e| classify_conn_error(&e))?;
    let sub = SerdeValue::Object(sub);
    if p.bool("raw") {
        return write_json_serde(&sub);
    }
    let u = summarize_usage(&from_serde(&sub), &Local);
    if p.bool("json") {
        return Ok(write_json_text(&usage_summary_to_json(&u)));
    }
    let mut out = String::new();
    for line in usage_lines(&u, &local_abbr_now()) {
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// `cmdThreads` (`read.go:383`): `sessions.list` +
/// `SessionRows(all, Local)`; empty → `[]`.
async fn cmd_threads(rt: &Runtime, p: &Parsed) -> Result<String, FlowErr> {
    let d = call_map(rt, "sessions.list", RequestOptions::default()).await?;
    let rows = session_rows(&from_serde(&d), p.bool("all"), &Local);
    let items: Vec<String> = rows.iter().map(session_row_to_json).collect();
    Ok(write_json_text(&rows_json(&items)))
}

/// `cmdHistory` (`read.go:440`): `--raw` prints the whole
/// `chat.history` object, otherwise the filtered events.
/// (`--download` is excluded: it stubs before this point.)
async fn cmd_history(rt: &Runtime, p: &Parsed) -> Result<String, FlowErr> {
    let (d, events) = history_result(rt, &p.str("thread"), p.int_val("limit")).await?;
    if p.bool("raw") {
        return write_json_serde(&d);
    }
    let items = filter_events(&events);
    Ok(write_json_text(&rows_json(&items)))
}

/// `cmdFiles` (`read.go:507`): `historyResult` + `FileRows`;
/// empty → `[]`.
async fn cmd_files(rt: &Runtime, p: &Parsed) -> Result<String, FlowErr> {
    let (_d, events) = history_result(rt, &p.str("thread"), p.int_val("limit")).await?;
    let events_shared: Vec<castctl_shared::JsonValue> = events.iter().map(from_serde).collect();
    let rows = file_rows(&events_shared);
    let items: Vec<String> = rows.iter().map(file_row_to_json).collect();
    Ok(write_json_text(&rows_json(&items)))
}

/// `cmdFeed` (`read.go:774`): the `limit` query parameter is
/// sent only when the flag was set and is non-zero;
/// `--raw` prints the whole object, otherwise `FeedRows`;
/// empty → `[]`.
async fn cmd_feed(rt: &Runtime, p: &Parsed) -> Result<String, FlowErr> {
    let limit = p.int_val("limit");
    let mut query = Vec::new();
    if p.int_is_set("limit") && limit != 0 {
        query.push(("limit".to_string(), limit.to_string()));
    }
    let d = call_map(
        rt,
        "feed.list",
        RequestOptions {
            query,
            ..Default::default()
        },
    )
    .await?;
    if p.bool("raw") {
        return write_json_serde(&d);
    }
    let rows = feed_rows(&from_serde(&d), limit);
    let items: Vec<String> = rows.iter().map(feed_row_to_json).collect();
    Ok(write_json_text(&rows_json(&items)))
}

/// `cmdFeedStatus` (`read.go:803`): `feed.status`
/// passthrough.
async fn cmd_feed_status(rt: &Runtime) -> Result<String, FlowErr> {
    let v = call_json(rt, "feed.status", RequestOptions::default()).await?;
    write_json_serde(&v)
}

/// `cmdFeedPrompt` (`read.go:850`): `feed.prompt.get`
/// passthrough.
async fn cmd_feed_prompt(rt: &Runtime) -> Result<String, FlowErr> {
    let v = call_json(rt, "feed.prompt.get", RequestOptions::default()).await?;
    write_json_serde(&v)
}

/// `cmdGoals` (`read.go:867`): `goals.list` + `GoalRows`;
/// empty → `[]`.
async fn cmd_goals(rt: &Runtime) -> Result<String, FlowErr> {
    let d = call_map(rt, "goals.list", RequestOptions::default()).await?;
    let rows = goal_rows(&from_serde(&d));
    let items: Vec<String> = rows.iter().map(goal_row_to_json).collect();
    Ok(write_json_text(&rows_json(&items)))
}

/// `cmdGoal` (`read.go:888`): `goals.get` with path param
/// `id`, passthrough.
async fn cmd_goal(rt: &Runtime, p: &Parsed) -> Result<String, FlowErr> {
    let id = p.positionals.first().cloned().unwrap_or_default();
    let v = call_json(
        rt,
        "goals.get",
        RequestOptions {
            path_params: vec![("id".to_string(), id)],
            ..Default::default()
        },
    )
    .await?;
    write_json_serde(&v)
}

/// `cmdIdeas` (`read.go:908`): `api.idea-cards.list` +
/// `IdeaRows`; empty → `[]`.
async fn cmd_ideas(rt: &Runtime) -> Result<String, FlowErr> {
    let d = call_map(rt, "api.idea-cards.list", RequestOptions::default()).await?;
    let rows = idea_rows(&from_serde(&d));
    let items: Vec<String> = rows.iter().map(idea_row_to_json).collect();
    Ok(write_json_text(&rows_json(&items)))
}

/// `cmdIdea` (`read.go:929`): `api.idea-cards.detail` with
/// path param `ideaCardId`, passthrough.
async fn cmd_idea(rt: &Runtime, p: &Parsed) -> Result<String, FlowErr> {
    let id = p.positionals.first().cloned().unwrap_or_default();
    let v = call_json(
        rt,
        "api.idea-cards.detail",
        RequestOptions {
            path_params: vec![("ideaCardId".to_string(), id)],
            ..Default::default()
        },
    )
    .await?;
    write_json_serde(&v)
}

/// `cmdUnread` (`read.go:974`): `chat.unread_count`
/// passthrough.
async fn cmd_unread(rt: &Runtime) -> Result<String, FlowErr> {
    let v = call_json(rt, "chat.unread_count", RequestOptions::default()).await?;
    write_json_serde(&v)
}

/// `cmdSessionStart` (`deliver.go:153`): `session.start`
/// with `{"method":"/api/session/start","params":
/// {"origin":"fresh","lifecycle":"persistent"[,"title"]}}`
/// (`deliver/session.go:83`). The params object is struct
/// order (origin, lifecycle, title), NOT sorted, so the
/// body is hand-built. The reply is returned verbatim.
async fn cmd_session_start(rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    let title = if p.str_is_set("title") {
        p.str("title")
    } else {
        String::new()
    };
    let mut body = String::from(
        "{\"method\":\"/api/session/start\",\"params\":{\"origin\":\"fresh\",\"lifecycle\":\"persistent\"",
    );
    if !title.is_empty() {
        body.push_str(",\"title\":");
        body.push_str(&escape_go_marshal_string(&title));
    }
    body.push_str("}}");
    let v = call_json(
        rt,
        "session.start",
        RequestOptions {
            body: Body::Bytes(body.into_bytes()),
            ..Default::default()
        },
    )
    .await?;
    Ok(CmdOut::out(write_json_serde(&v)?))
}

/// `cmdSessionOp` (`deliver.go:176`): rename sends
/// `{"session_id","title"}`; every other kind sends
/// `{"method":"/api/session/<kind>","session_id"}`
/// (`deliver/session.go:103`). Both are struct order;
/// the sorted `Body::Json` order coincides, but the
/// ordered builder is used so the wire order is explicit.
async fn cmd_session_op(rt: &Runtime, p: &Parsed, kind: &str) -> Result<CmdOut, FlowErr> {
    let id = p.positionals.first().cloned().unwrap_or_default();
    let body = if kind == "rename" {
        let title = p.positionals.get(1).cloned().unwrap_or_default();
        ordered_body(&[
            ("session_id", escape_go_marshal_string(&id)),
            ("title", escape_go_marshal_string(&title)),
        ])
    } else {
        ordered_body(&[
            (
                "method",
                escape_go_marshal_string(&format!("/api/session/{kind}")),
            ),
            ("session_id", escape_go_marshal_string(&id)),
        ])
    };
    let v = call_json(
        rt,
        &format!("session.{kind}"),
        RequestOptions {
            body,
            ..Default::default()
        },
    )
    .await?;
    Ok(CmdOut::out(write_json_serde(&v)?))
}

/// `cmdStop` (`deliver.go:205`): `chat.cancel` with `{}`
/// for the main chat or `{"session_id": thread}` for a
/// side chat (`deliver/stop.go:29`).
async fn cmd_stop(rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    let thread = if p.str_is_set("thread") {
        p.str("thread")
    } else {
        String::new()
    };
    let body = if thread.is_empty() {
        Body::Bytes(b"{}".to_vec())
    } else {
        ordered_body(&[("session_id", escape_go_marshal_string(&thread))])
    };
    let v = call_json(
        rt,
        "chat.cancel",
        RequestOptions {
            body,
            ..Default::default()
        },
    )
    .await?;
    Ok(CmdOut::out(write_json_serde(&v)?))
}

/// `cmdSeen` (`read.go:991`): `chat.mark_seen` with path
/// param `thread_id`, passthrough.
async fn cmd_seen(rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    let thread = p.positionals.first().cloned().unwrap_or_default();
    let v = call_json(
        rt,
        "chat.mark_seen",
        RequestOptions {
            path_params: vec![("thread_id".to_string(), thread)],
            ..Default::default()
        },
    )
    .await?;
    Ok(CmdOut::out(write_json_serde(&v)?))
}

/// `cmdFeedReact` (`read.go:820`): `feed.unit.reaction`
/// with path param `unit_id` and body `{"reaction"}`
/// (default `"love"`), passthrough.
async fn cmd_feed_react(rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    let unit = p.positionals.first().cloned().unwrap_or_default();
    let reaction = p
        .positionals
        .get(1)
        .cloned()
        .unwrap_or_else(|| "love".to_string());
    let v = call_json(
        rt,
        "feed.unit.reaction",
        RequestOptions {
            path_params: vec![("unit_id".to_string(), unit)],
            body: ordered_body(&[("reaction", escape_go_marshal_string(&reaction))]),
            ..Default::default()
        },
    )
    .await?;
    Ok(CmdOut::out(write_json_serde(&v)?))
}

/// `cmdIdeaExec` (`read.go:949`): `api.idea-cards.
/// execute` with path param `ideaCardId` and body
/// `{"ideaCardId","mode":"full"[,"session_id"]}` — a Go
/// map, so sorted key order (ideaCardId, mode,
/// session_id). The id appears twice: path + body.
async fn cmd_idea_exec(rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    let id = p.positionals.first().cloned().unwrap_or_default();
    let thread = p.str("thread");
    let mut pairs: Vec<(&str, String)> = vec![
        ("ideaCardId", escape_go_marshal_string(&id)),
        ("mode", "\"full\"".to_string()),
    ];
    if !thread.is_empty() {
        pairs.push(("session_id", escape_go_marshal_string(&thread)));
    }
    let v = call_json(
        rt,
        "api.idea-cards.execute",
        RequestOptions {
            path_params: vec![("ideaCardId".to_string(), id)],
            body: ordered_body(&pairs),
            ..Default::default()
        },
    )
    .await?;
    Ok(CmdOut::out(write_json_serde(&v)?))
}

/// `pendingApprovals` (`wait.go:1147`): `egress.
/// approvals` + the pending list (`pending_approvals`,
/// falling back to `pending`). Python `or` semantics: an
/// empty first list falls through to the fallback key; a
/// non-list first value also falls through. A non-object
/// result is a plain error, exit 1 (Go's `callMap` shape:
/// `gateway: egress.approvals result is not an object:
/// %T`).
async fn pending_approvals(rt: &Runtime) -> Result<(SerdeValue, Vec<SerdeValue>), FlowErr> {
    let v = call_map(rt, "egress.approvals", RequestOptions::default()).await?;
    let pend = match v.get("pending_approvals").and_then(|x| x.as_array()) {
        Some(list) if !list.is_empty() => list.clone(),
        _ => match v.get("pending").and_then(|x| x.as_array()) {
            Some(list) => list.clone(),
            None => Vec::new(),
        },
    };
    Ok((v, pend))
}

/// `decideApproval` (`wait.go:1184`): the one call
/// behind approve, deny, approve --all and auto-approve.
/// `egress.approval.decide` with path param
/// `approval_id` and body `{"decision"}`. Never retried.
async fn decide_approval(
    rt: &Runtime,
    approval_id: &str,
    decision: &str,
) -> Result<SerdeValue, FlowErr> {
    call_json(
        rt,
        "egress.approval.decide",
        RequestOptions {
            path_params: vec![("approval_id".to_string(), approval_id.to_string())],
            body: ordered_body(&[("decision", escape_go_marshal_string(decision))]),
            ..Default::default()
        },
    )
    .await
}

/// `approveAll` (`wait.go:1189`): decide every currently
/// pending approval with `decision`, skipping approvals
/// with no forever option when the decision is
/// `allow_always`. One structural stderr line per
/// approval (skipped / approved); the rows render as
/// `approvedJSON` (empty fields → null). A decide error
/// aborts the loop and propagates.
async fn approve_all(
    rt: &Runtime,
    decision: &str,
    stderr: &mut String,
) -> Result<Vec<String>, FlowErr> {
    let (_raw, pend) = pending_approvals(rt).await?;
    let mut done: Vec<String> = Vec::new();
    for item in &pend {
        let d = describe_approval(&from_serde(item));
        if decision == "allow_always" && !offers_forever(&d) {
            stderr.push_str(&skipped_line(&d));
            continue;
        }
        let id = d.approval_id.clone().unwrap_or_default();
        decide_approval(rt, &id, decision).await?;
        let title = d.title.clone().unwrap_or_default();
        let kind = d.kind.clone().unwrap_or_default();
        let scope = d.scope.clone().unwrap_or_default();
        done.push(approved_json(&id, &title, &kind, &scope, decision));
        stderr.push_str(&approved_line(&id, decision, &title, &kind, &scope));
    }
    Ok(done)
}

/// `{"approved": [...]}` (`wait.go:1240`,
/// `approvedListJSON`): empty → `[]`, never null.
fn approved_list_json(rows: &[String]) -> String {
    format!("{{\"approved\":{}}}", rows_json(rows))
}

/// `cmdApprovals` (`wait.go:1248`): `--approve-all`
/// decides everything with `allow_always` and prints the
/// approved list; `--raw` prints the raw
/// `egress.approvals` object; otherwise the described
/// pending list, plus `recent` when `--recent` is given
/// (recent key order: `recent_approvals` non-empty, else
/// `recent`; the key is present even when the list is
/// empty).
async fn cmd_approvals(rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    if p.bool("approve-all") {
        let mut stderr = String::new();
        match approve_all(rt, "allow_always", &mut stderr).await {
            Ok(done) => {
                let mut out = CmdOut::out(write_json_text(&approved_list_json(&done)));
                out.stderr = stderr;
                return Ok(out);
            }
            Err(e) => {
                let (code, text) = render_flow_err(&e);
                stderr.push_str(&text);
                return Ok(CmdOut {
                    stdout: String::new(),
                    stderr,
                    code,
                });
            }
        }
    }
    let (raw, pend) = pending_approvals(rt).await?;
    if p.bool("raw") {
        return Ok(CmdOut::out(write_json_serde(&raw)?));
    }
    let items: Vec<String> = pend
        .iter()
        .map(|item| approval_json(&describe_approval(&from_serde(item))))
        .collect();
    let mut out = String::from("{\"pending\":");
    out.push_str(&rows_json(&items));
    if p.bool("recent") {
        let recent = match raw.get("recent_approvals").and_then(|x| x.as_array()) {
            Some(list) if !list.is_empty() => list.clone(),
            _ => match raw.get("recent").and_then(|x| x.as_array()) {
                Some(list) => list.clone(),
                None => Vec::new(),
            },
        };
        let mut rows: Vec<String> = Vec::new();
        for item in &recent {
            let d = describe_approval(&from_serde(item));
            let decision = item
                .as_object()
                .and_then(|m| m.get("decision"))
                .cloned()
                .unwrap_or(SerdeValue::Null);
            let mut row = approval_json(&d);
            row.pop();
            row.push_str(",\"decision\":");
            row.push_str(&serde_json::to_string(&decision).unwrap_or_else(|_| "null".into()));
            row.push('}');
            rows.push(row);
        }
        out.push_str(",\"recent\":");
        out.push_str(&rows_json(&rows));
    }
    out.push('}');
    Ok(CmdOut::out(write_json_text(&out)))
}

/// `approveDecision` (`wait.go:1277`): at most one of
/// once/session/today/always; the second reports the
/// first as the conflicting argument. Default
/// `allow_once`. (The positional checks already ran
/// this validation in `run.rs`; the loop is repeated
/// here because the handler needs the decision string.)
fn approve_decision_str(p: &Parsed) -> Result<String, FlowErr> {
    let mut seen: Option<&str> = None;
    let mut decision = "allow_once".to_string();
    for k in ["once", "session", "today", "always"] {
        if p.bool(k) {
            match seen {
                Some(first) => {
                    return Err(msg(
                        2,
                        format!("argument --{k}: not allowed with argument --{first}"),
                    ));
                }
                None => {
                    seen = Some(k);
                    decision = format!("allow_{k}");
                }
            }
        }
    }
    Ok(decision)
}

/// `cmdApprove` (`wait.go:1295`): `--all` decides
/// everything (same loop as `approvals --approve-all`);
/// otherwise one decide call, passthrough.
async fn cmd_approve(rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    let decision = approve_decision_str(p)?;
    if p.bool("all") {
        let mut stderr = String::new();
        match approve_all(rt, &decision, &mut stderr).await {
            Ok(done) => {
                let mut out = CmdOut::out(write_json_text(&approved_list_json(&done)));
                out.stderr = stderr;
                return Ok(out);
            }
            Err(e) => {
                let (code, text) = render_flow_err(&e);
                stderr.push_str(&text);
                return Ok(CmdOut {
                    stdout: String::new(),
                    stderr,
                    code,
                });
            }
        }
    }
    let id = p.positionals.first().cloned().unwrap_or_default();
    let res = decide_approval(rt, &id, &decision).await?;
    Ok(CmdOut::out(write_json_serde(&res)?))
}

/// `cmdDeny` (`wait.go:1330`): decide `deny`, or
/// `deny_always` with `--always`; passthrough.
async fn cmd_deny(rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    let decision = if p.bool("always") {
        "deny_always"
    } else {
        "deny"
    };
    let id = p.positionals.first().cloned().unwrap_or_default();
    let res = decide_approval(rt, &id, decision).await?;
    Ok(CmdOut::out(write_json_serde(&res)?))
}

/// `printInviteText` (`read.go:241`): the text form of
/// an invite summary.
fn print_invite_text(s: &castctl_shared::InviteSummary) -> String {
    let mut out = String::new();
    let code = s.code.as_deref().unwrap_or("");
    if !code.is_empty() {
        out.push_str(&format!("Invite code: {code}\n"));
        let link = s.link.as_deref().unwrap_or("");
        if !link.is_empty() {
            out.push_str(&format!("Link: {link}\n"));
        }
        if let Some(remaining) = s.uses_remaining {
            let mut extra = String::new();
            if let Some(max) = s.max_uses {
                extra = format!(" of {max}");
            }
            out.push_str(&format!("Uses left: {remaining}{extra}\n"));
        }
    } else {
        let state = s.state.as_deref().unwrap_or("");
        out.push_str(&format!(
            "Invite code: none yet (state {state}). Open Invite friends in the muse.ai app once, or run `castctl invite --create`.\n"
        ));
    }
    if let Some(reward) = &s.reward {
        let mut parts: Vec<&str> = Vec::new();
        if let Some(t) = reward.title.as_deref()
            && !t.is_empty()
        {
            parts.push(t);
        }
        if let Some(b) = reward.body.as_deref()
            && !b.is_empty()
        {
            parts.push(b);
        }
        if !parts.is_empty() {
            out.push_str(&parts.join(" "));
            out.push('\n');
        }
    }
    if let Some(offer) = s.offer.as_deref()
        && !offer.is_empty()
    {
        out.push_str(offer);
        out.push('\n');
    }
    out
}

/// `cmdInvite` (`read.go:195`): cookies first, then
/// `FetchInvite`; `--create` POSTs only when no code
/// exists yet, then re-fetches. `--raw` prints the raw
/// object; `--json` prints the summary; otherwise the
/// text form. Plain HTTPS through the dialer, never the
/// gateway connection.
async fn cmd_invite(rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    let cookies = rt.cookies()?;
    let mut d = fetch_invite_base(&rt.http, &cookies, &rt.http_base)
        .await
        .map_err(|e| classify_conn_error(&e))?;
    if p.bool("create") {
        let code = d.get("code").and_then(|v| v.as_str()).unwrap_or("");
        if code.is_empty() {
            create_invite_base(&rt.http, &cookies, &rt.http_base)
                .await
                .map_err(|e| classify_conn_error(&e))?;
            d = fetch_invite_base(&rt.http, &cookies, &rt.http_base)
                .await
                .map_err(|e| classify_conn_error(&e))?;
        }
    }
    if p.bool("raw") {
        return Ok(CmdOut::out(write_json_serde(&SerdeValue::Object(d))?));
    }
    let summary = summarize_invite(&from_serde(&SerdeValue::Object(d)));
    if p.bool("json") {
        return Ok(CmdOut::out(write_json_text(&invite_summary_to_json(
            &summary,
        ))));
    }
    Ok(CmdOut::out(print_invite_text(&summary)))
}

/// `cmdRedeem` (`read.go:276`): cookies first, then
/// `RedeemInviteCode` (code validation happens inside,
/// before any request). `--json` merges `{"status",
/// **body}` (status first, body keys sorted; the failure
/// path keeps only success/reason/detail). Text success
/// prints `Redeemed: <redemptionStatus|"ok">`; text
/// failure prints `Not redeemed (<reason>): <detail>`
/// with trailing `:`/space trimmed. Failure exits 1,
/// silently, after printing.
async fn cmd_redeem(rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    let code = p.positionals.first().cloned().unwrap_or_default();
    let cookies = rt.cookies()?;
    let (status, body) = redeem_invite_code_base(&rt.http, &cookies, &code, &rt.http_base)
        .await
        .map_err(|e| classify_conn_error(&e))?;
    let body_map = body.as_object().cloned().unwrap_or_default();
    let success = body_map
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if p.bool("json") {
        let filtered = if success {
            body_map
        } else {
            let mut out = serde_json::Map::new();
            for k in ["success", "reason", "detail"] {
                if let Some(v) = body_map.get(k) {
                    out.insert(k.to_string(), v.clone());
                }
            }
            out
        };
        let text = write_merged_json(status as i32, &filtered);
        return Ok(if success {
            CmdOut::out(text)
        } else {
            CmdOut::code(text, 1)
        });
    }
    if success {
        let redemption = body_map
            .get("redemptionStatus")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let redemption = if redemption.is_empty() {
            "ok"
        } else {
            redemption
        };
        return Ok(CmdOut::out(format!("Redeemed: {redemption}\n")));
    }
    let reason = body_map
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let detail = body_map
        .get("detail")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let line = format!("Not redeemed ({reason}): {detail}");
    let line = line.trim_end_matches([':', ' ']);
    Ok(CmdOut::code(format!("{line}\n"), 1))
}

/// `cmdWake` (`deliver.go:228`, `deliver/wake.go:95`):
/// cookies first, then `FetchAccessToken`, the vm id
/// from the profile or `FetchSessionInfo`, then the wake
/// POST (15s bound inside `WakeVM`). Renders
/// `{"status","body"}` in struct order. Plain HTTPS
/// through the dialer, never the gateway connection. The
/// `deliver: wake: …` error wraps are not reproduced:
/// typed errors classify identically with or without
/// them, and the wrap text is never rendered.
async fn cmd_wake(rt: &Runtime) -> Result<CmdOut, FlowErr> {
    let cookies = rt.cookies()?;
    let token = fetch_access_token_base(&rt.http, &cookies, &rt.http_base)
        .await
        .map_err(|e| classify_conn_error(&e))?;
    let vm_id = if !rt.profile.vm_id.is_empty() {
        rt.profile.vm_id.clone()
    } else {
        let info = fetch_session_info_base(&rt.http, &cookies, &rt.http_base)
            .await
            .map_err(|e| classify_conn_error(&e))?;
        info.vm_id
    };
    let (status, body) = wake_vm_base(&rt.http, &cookies, &token, &vm_id, &rt.http_base)
        .await
        .map_err(|e| classify_conn_error(&e))?;
    let body_compact =
        serde_json::to_string(&body).map_err(|_| msg(1, "failed to serialize gateway response"))?;
    let mut out = String::from("{\"status\":");
    out.push_str(&status.to_string());
    out.push_str(",\"body\":");
    out.push_str(&body_compact);
    out.push('}');
    Ok(CmdOut::out(write_json_text(&out)))
}

/// Go `stringifyID` (`read.go:627`): nil → `""`, string
/// → itself, number → its literal, bool → `True` /
/// `False`. Other JSON values fall back to the compact
/// rendering (Go `%v` of a map/slice is Go syntax, which
/// no id ever is; recorded approximation).
fn stringify_id(v: Option<&SerdeValue>) -> String {
    match v {
        None | Some(SerdeValue::Null) => String::new(),
        Some(SerdeValue::String(s)) => s.clone(),
        Some(SerdeValue::Number(n)) => n.to_string(),
        Some(SerdeValue::Bool(b)) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Some(other) => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Go `eventMatchesRef` (`read.go:615`): any of the
/// event's ids (`seq`, `payload.message_id`,
/// `payload.id`, top-level `message_id`) equals the ref.
fn event_matches_ref(ev: &SerdeValue, ref_: &str) -> bool {
    let payload = ev.get("payload").and_then(|v| v.as_object());
    let ids = [
        stringify_id(ev.get("seq")),
        stringify_id(payload.and_then(|m| m.get("message_id"))),
        stringify_id(payload.and_then(|m| m.get("id"))),
        stringify_id(ev.get("message_id")),
    ];
    ids.iter().any(|id| !id.is_empty() && id == ref_)
}

/// One `SaveResources` result row (`internal/shared/
/// resources.go:230`, `SaveRow`): field order path, file,
/// skipped, bytes, error, warning; `None` fields are
/// omitted (`omitempty`).
#[derive(Debug, Clone, Default)]
struct SaveRow {
    /// Resource path that was downloaded.
    path: String,
    /// Absolute local path saved to (or would-be, on failure).
    file: String,
    /// `"exists"` when the destination already existed.
    skipped: Option<String>,
    /// Existing size (skipped) or downloaded size (saved).
    bytes: Option<i64>,
    /// Download failure summary (row error).
    error: Option<String>,
    /// `expected <N> bytes` on a byte_len mismatch.
    warning: Option<String>,
}

fn save_row_to_json(row: &SaveRow) -> String {
    let mut out = String::from("{");
    out.push_str("\"path\":");
    out.push_str(&escape_go_marshal_string(&row.path));
    out.push_str(",\"file\":");
    out.push_str(&escape_go_marshal_string(&row.file));
    if let Some(skipped) = &row.skipped {
        out.push_str(",\"skipped\":");
        out.push_str(&escape_go_marshal_string(skipped));
    }
    if let Some(bytes) = row.bytes {
        out.push_str(",\"bytes\":");
        out.push_str(&bytes.to_string());
    }
    if let Some(error) = &row.error {
        out.push_str(",\"error\":");
        out.push_str(&escape_go_marshal_string(error));
    }
    if let Some(warning) = &row.warning {
        out.push_str(",\"warning\":");
        out.push_str(&escape_go_marshal_string(warning));
    }
    out.push('}');
    out
}

/// `SaveResources` (`internal/shared/resources.go:267`):
/// mkdir the directory (0777), skip existing
/// destinations unless overwrite, download each resource
/// through the live gateway (`media_path` resolves
/// `sandbox://` refs and the `variants.original`
/// preference), write to a `.part` file (0666) and rename
/// into place, warn on a `byte_len` mismatch. A download
/// failure is captured in the row's error field (the
/// allowlist summary only); an auth failure or a
/// cancelled context propagates, as does any local
/// filesystem failure (`save resources: …`).
async fn save_resources(
    rt: &Runtime,
    resources: &[Resource],
    directory: &str,
    overwrite: bool,
) -> Result<Vec<SaveRow>, FlowErr> {
    if let Err(e) = std::fs::create_dir_all(directory) {
        return Err(msg(
            1,
            format!(
                "save resources: create directory: mkdir {directory}: {}",
                io_error_text(&e)
            ),
        ));
    }
    let mut rows: Vec<SaveRow> = Vec::new();
    for r in resources {
        let dest = local_name(&r.path, directory);
        let abs = abs_path(&dest);
        let mut row = SaveRow {
            path: r.path.clone(),
            file: abs,
            ..Default::default()
        };
        if let Ok(meta) = std::fs::metadata(&dest)
            && !overwrite
        {
            row.skipped = Some("exists".to_string());
            row.bytes = Some(meta.len() as i64);
            rows.push(row);
            continue;
        }
        let variants_original = match &r.variants {
            Some(SharedValue::Object(m)) => match m.get("original") {
                Some(SharedValue::Str(s)) => Some(s.as_str()),
                _ => None,
            },
            _ => None,
        };
        let resolved = match media_path(&r.path, variants_original) {
            Ok(p) => p,
            Err(e) => {
                return Err(classify_conn_error(&e));
            }
        };
        let data = match rt.shared.live().await {
            Ok(gw) => match gw.download_file(&resolved, Duration::from_secs(0)).await {
                Ok(data) => data,
                Err(e) => match e {
                    TransportError::Cancelled | TransportError::Auth { .. } => {
                        return Err(classify_conn_error(&e));
                    }
                    _ => {
                        row.error = Some(summarize_transport_error(&e));
                        rows.push(row);
                        continue;
                    }
                },
            },
            Err(e) => {
                return Err(classify_conn_error(&e));
            }
        };
        let tmp = format!("{dest}.part");
        if let Err(e) = std::fs::write(&tmp, &data) {
            return Err(msg(
                1,
                format!(
                    "save resources: write {tmp}: open {tmp}: {}",
                    io_error_text(&e)
                ),
            ));
        }
        if let Err(e) = std::fs::rename(&tmp, &dest) {
            return Err(msg(
                1,
                format!("save resources: rename {tmp} {dest}: {}", io_error_text(&e)),
            ));
        }
        let size = data.len() as i64;
        row.bytes = Some(size);
        if let Some(expected) = r.byte_len
            && expected != size
        {
            row.warning = Some(format!("expected {expected} bytes"));
        }
        rows.push(row);
    }
    Ok(rows)
}

/// `cmdDownload` (`read.go:535`): a `sandbox://` ref or
/// a ref containing `/media/raw/` downloads directly;
/// otherwise the ref is matched against the last N
/// messages' events (`eventMatchesRef` + `EventResources`,
/// deduped by path). No files → exit 1 with the message.
/// Rows print as JSON; any row error exits 3, silently,
/// after printing.
async fn cmd_download(rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    let ref_ = p.positionals.first().cloned().unwrap_or_default();
    let output = if p.str_is_set("output") {
        p.str("output")
    } else {
        ".".to_string()
    };
    let force = p.bool("force");
    let resources: Vec<Resource> = if ref_.starts_with("sandbox://") || ref_.contains("/media/raw/")
    {
        vec![Resource {
            path: ref_.clone(),
            kind: String::new(),
            mime: None,
            byte_len: None,
            label: None,
            variants: None,
        }]
    } else {
        let (_d, events) = history_result(rt, &p.str("thread"), p.int_val("limit")).await?;
        let mut resources: Vec<Resource> = Vec::new();
        for ev in &events {
            if !event_matches_ref(ev, &ref_) {
                continue;
            }
            for r in event_resources(&from_serde(ev)) {
                if !resources.iter().any(|x| x.path == r.path) {
                    resources.push(r);
                }
            }
        }
        if resources.is_empty() {
            let thread = p.str("thread");
            let where_ = if thread.is_empty() {
                " of the main chat".to_string()
            } else {
                format!(" of thread {thread}")
            };
            return Err(msg(
                1,
                format!(
                    "no files found for '{ref_}' in the last {} messages{where_} (try --thread / --limit)",
                    p.int_val("limit")
                ),
            ));
        }
        resources
    };
    let rows = save_resources(rt, &resources, &output, force).await?;
    let items: Vec<String> = rows.iter().map(save_row_to_json).collect();
    let text = write_json_text(&rows_json(&items));
    if rows.iter().any(|r| r.error.is_some()) {
        Ok(CmdOut::code(text, 3))
    } else {
        Ok(CmdOut::out(text))
    }
}

/// `cmdRaw` (`read.go:1010`): route-lookup first (exit 2
/// on an unknown method, before any connection is
/// opened), then `--body` JSON parse, then `--param` k=v
/// checks. The raw reply bytes print as JSON when they
/// parse (first value only, trailing data ignored — Go
/// `decodeJSONNumber`), else as text. Empty reply →
/// `{}`. Timeout defaults to 30s (table default).
async fn cmd_raw(rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    let method = p.positionals.first().cloned().unwrap_or_default();
    let table = RouteTable::default_routes().map_err(|e| classify_error(&e))?;
    if table.lookup_route(&method).is_none() {
        return Err(msg(
            2,
            format!(
                "unknown method '{method}' (see routes.json for the {} known methods)",
                table.len()
            ),
        ));
    }
    let mut body = Body::None;
    if !p.str("body").is_empty() {
        let v = decode_json_number_loose(p.str("body").as_bytes())
            .map_err(|e| msg(2, format!("invalid --body JSON: {e}")))?;
        body = Body::Json(v);
    }
    let mut path_params: Vec<(String, String)> = Vec::new();
    for kv in p.list("param") {
        match kv.split_once('=') {
            Some((k, v)) => path_params.push((k.to_string(), v.to_string())),
            None => {
                return Err(msg(2, format!("bad --param '{kv}': expected k=v")));
            }
        }
    }
    let timeout_secs = p.int_val("timeout");
    let timeout = if timeout_secs > 0 {
        Duration::from_secs(timeout_secs as u64)
    } else {
        Duration::ZERO
    };
    let data = rt
        .shared
        .request(
            &method,
            RequestOptions {
                body,
                path_params,
                timeout,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| classify_conn_error(&e))?;
    if data.is_empty() {
        return Ok(CmdOut::out(write_json_text("{}")));
    }
    match decode_json_number_loose(&data) {
        Ok(v) => Ok(CmdOut::out(write_json_serde(&v)?)),
        Err(_) => Ok(CmdOut::out(format!("{}\n", String::from_utf8_lossy(&data)))),
    }
}

async fn dispatch(spec: &CommandSpec, rt: &Runtime, p: &Parsed) -> Result<CmdOut, FlowErr> {
    match spec.name {
        "status" => cmd_status(rt).await.map(CmdOut::out),
        "usage" => cmd_usage(rt, p).await.map(CmdOut::out),
        "threads" => cmd_threads(rt, p).await.map(CmdOut::out),
        "history" => cmd_history(rt, p).await.map(CmdOut::out),
        "files" => cmd_files(rt, p).await.map(CmdOut::out),
        "feed" => cmd_feed(rt, p).await.map(CmdOut::out),
        "feed-status" => cmd_feed_status(rt).await.map(CmdOut::out),
        "feed-prompt" => cmd_feed_prompt(rt).await.map(CmdOut::out),
        "goals" => cmd_goals(rt).await.map(CmdOut::out),
        "goal" => cmd_goal(rt, p).await.map(CmdOut::out),
        "ideas" => cmd_ideas(rt).await.map(CmdOut::out),
        "idea" => cmd_idea(rt, p).await.map(CmdOut::out),
        "unread" => cmd_unread(rt).await.map(CmdOut::out),
        "session-start" => cmd_session_start(rt, p).await,
        "session-rename" => cmd_session_op(rt, p, "rename").await,
        "session-pin" => cmd_session_op(rt, p, "pin").await,
        "session-unpin" => cmd_session_op(rt, p, "unpin").await,
        "session-archive" => cmd_session_op(rt, p, "archive").await,
        "session-unarchive" => cmd_session_op(rt, p, "unarchive").await,
        "session-delete" => cmd_session_op(rt, p, "delete").await,
        "stop" => cmd_stop(rt, p).await,
        "seen" => cmd_seen(rt, p).await,
        "feed-react" => cmd_feed_react(rt, p).await,
        "idea-exec" => cmd_idea_exec(rt, p).await,
        "approvals" => cmd_approvals(rt, p).await,
        "approve" => cmd_approve(rt, p).await,
        "deny" => cmd_deny(rt, p).await,
        "invite" => cmd_invite(rt, p).await,
        "redeem" => cmd_redeem(rt, p).await,
        "wake" => cmd_wake(rt).await,
        "download" => cmd_download(rt, p).await,
        "raw" => cmd_raw(rt, p).await,
        _ => Err(msg(
            1,
            format!("command {} is not a network command", spec.name),
        )),
    }
}

/// Run one network command: resolve config + parse (kept
/// for the runtime builder), build the tokio runtime and
/// the per-profile runtime, dispatch, and append the
/// stdout/stderr text to the outcome. A non-zero command
/// code becomes `FlowErr::Exit` (silent, after the
/// streams are appended). Errors surface as `FlowErr`
/// (typed JSON via `Verbatim`, plain via `Msg`).
pub(crate) fn run_network_command(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    spec: &CommandSpec,
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
    let out = tokio_rt.block_on(async move {
        let runtime = build_runtime(&loc, single.as_ref(), profile_flag, getenv)?;
        dispatch(spec, &runtime, p).await
    })?;
    ctx.out.stdout.push_str(&out.stdout);
    ctx.out.stderr.push_str(&out.stderr);
    if out.code != 0 {
        return Err(FlowErr::Exit(out.code));
    }
    Ok(())
}

/// Render a `FlowErr` exactly as `run_inner` does
/// (`run.rs`): the (exit code, stderr text) pair. Used by
/// the approve-all handlers, which must keep `approveAll`'s
/// already-printed lines on stderr even when a later decide
/// fails (Go prints those lines directly to stderr as the
/// loop runs, so they survive a mid-loop error; `run_inner`
/// would drop them if the handler returned `Err`).
pub(crate) fn render_flow_err(e: &FlowErr) -> (i32, String) {
    match e {
        FlowErr::HelpShown => (0, String::new()),
        FlowErr::Exit(code) => (*code, String::new()),
        FlowErr::Verbatim { code, text } => {
            if text.is_empty() {
                (*code, String::new())
            } else {
                (*code, format!("{text}\n"))
            }
        }
        FlowErr::Msg { code, message } => (
            *code,
            message
                .as_ref()
                .map(|m| format!("castctl: {m}\n"))
                .unwrap_or_default(),
        ),
    }
}
/// against an already-built runtime (a fake gateway /
/// fake muse.ai base in tests) and return
/// (stdout, stderr, exit code), rendering `FlowErr`
/// exactly like `run_inner` does. Test-only: production
/// never calls this, and no CLI flag/env/config selects
/// a gateway host.
pub async fn run_driver_command(
    spec: &CommandSpec,
    rt: &Runtime,
    p: &Parsed,
) -> (String, String, i32) {
    match dispatch(spec, rt, p).await {
        Ok(out) => (out.stdout, out.stderr, out.code),
        Err(FlowErr::HelpShown) => (String::new(), String::new(), 0),
        Err(FlowErr::Exit(code)) => (String::new(), String::new(), code),
        Err(FlowErr::Verbatim { code, text }) => (
            String::new(),
            if text.is_empty() {
                String::new()
            } else {
                format!("{text}\n")
            },
            code,
        ),
        Err(FlowErr::Msg { code, message }) => (
            String::new(),
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
    use crate::run::{Outcome, STUB_LINE, run};
    use std::collections::HashMap;

    fn flow_render(e: &FlowErr) -> (i32, String) {
        match e {
            FlowErr::Msg { code, message } => (
                *code,
                message
                    .as_ref()
                    .map(|m| format!("castctl: {m}\n"))
                    .unwrap_or_default(),
            ),
            FlowErr::Verbatim { code, text } => (*code, format!("{text}\n")),
            FlowErr::Exit(code) => (*code, String::new()),
            FlowErr::HelpShown => (0, String::new()),
        }
    }

    fn run_args(args: &[&str]) -> Outcome {
        let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        run(&argv, None)
    }

    fn run_env(args: &[&str], map: HashMap<String, String>) -> Outcome {
        let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let g = move |k: &str| map.get(k).cloned();
        run(&argv, Some(&g))
    }

    fn temp_home(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("castctl-cli-network-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn isolated_env() -> (std::path::PathBuf, HashMap<String, String>) {
        let home = temp_home("home");
        let mut map = HashMap::new();
        map.insert("HOME".to_string(), home.to_str().unwrap().to_string());
        map.insert(
            "XDG_CONFIG_HOME".to_string(),
            home.join(".config").to_str().unwrap().to_string(),
        );
        (home, map)
    }

    #[test]
    fn typed_json_shape() {
        assert_eq!(
            typed_json("cookies_missing", "conn: auth_failed message_length=42"),
            "{\"error\":\"conn: auth_failed message_length=42\",\"type\":\"cookies_missing\"}"
        );
        // Go `json.Marshal` escapes HTML in the typed line.
        assert_eq!(
            typed_json("x", "a<b>&\"q\""),
            "{\"error\":\"a\\u003cb\\u003e\\u0026\\\"q\\\"\",\"type\":\"x\"}"
        );
    }

    #[test]
    fn classify_auth_message_cases() {
        let cases = [
            ("no cookies at /x: nope", "cookies_missing"),
            ("could not parse cookies file /x", "cookies_missing"),
            // NOTE: the real empty-file message ("cookies
            // file is empty") does NOT contain "empty
            // cookies" — Go constructs that typed error
            // directly in Runtime.Cookies, not via this
            // classifier.
            ("empty cookies in the jar", "cookies_missing"),
            (
                "api/session -> 401 (cookies expired? re-export)",
                "session_unavailable",
            ),
            ("VM unavailable; retry shortly", "session_unavailable"),
            (
                "auth/check -> 401 (cookies expired? re-export)",
                "auth_check_failed",
            ),
            ("hatch/token -> 401", "hatch_token_failed"),
            ("something else entirely", "auth_failed"),
        ];
        for (message, want_type) in cases {
            let err = classify_auth_message(message);
            let (code, text) = flow_render(&err);
            assert_eq!(code, 2, "{message}");
            assert_eq!(
                text,
                format!(
                    "{{\"error\":\"conn: auth_failed message_length={}\",\"type\":\"{want_type}\"}}\n",
                    message.len()
                ),
                "{message}"
            );
        }
    }

    #[test]
    fn classify_conn_error_gateway_vm_unavailable() {
        let err = TransportError::Gateway(BodySummary {
            status: -1,
            body_length: Some(123),
            content_type: Some("application/json".to_string()),
            error_code: Some("vm_unavailable".to_string()),
        });
        let (code, text) = flow_render(&classify_conn_error(&err));
        assert_eq!(code, 2);
        assert_eq!(
            text,
            "{\"error\":\"conn: gateway status=-1 body_length=123 content_type=application/json error=vm_unavailable\",\"type\":\"session_unavailable\"}\n"
        );
    }

    #[test]
    fn classify_conn_error_read_cookies_backstop() {
        let err = TransportError::Auth {
            message: "no cookies at /x: gateway: read cookies file: nope".to_string(),
        };
        let (code, text) = flow_render(&classify_conn_error(&err));
        assert_eq!(code, 2);
        assert!(text.contains("\"type\":\"cookies_missing\""), "{text}");
    }

    #[test]
    fn classify_error_branches() {
        // Bare auth -> typed auth_failed.
        let (code, text) = flow_render(&classify_error(&TransportError::Auth {
            message: "api/session -> 401 (x)".to_string(),
        }));
        assert_eq!(code, 2);
        assert!(text.contains("\"type\":\"auth_failed\""), "{text}");
        // Gateway 500 -> exit 3, `castctl: ` + Go-exact text.
        let (code, text) = flow_render(&classify_error(&TransportError::Gateway(
            BodySummary::new(500, Some(b"{}"), "application/json"),
        )));
        assert_eq!(code, 3);
        assert_eq!(
            text,
            "castctl: conn: gateway status=500 body_length=2 content_type=application/json\n"
        );
        // Timeout -> 4.
        let (code, text) = flow_render(&classify_error(&TransportError::Timeout {
            message: "no response for chat.history".to_string(),
        }));
        assert_eq!(code, 4);
        assert_eq!(text, "castctl: conn: no response for chat.history\n");
        // Cancelled -> 130, empty text.
        let (code, text) = flow_render(&classify_error(&TransportError::Cancelled));
        assert_eq!((code, text.as_str()), (130, ""));
        // Validation -> 2, `gateway: ` prefix.
        let (code, text) = flow_render(&classify_error(&TransportError::Validation {
            message: "bad method".to_string(),
        }));
        assert_eq!(code, 2);
        assert_eq!(text, "castctl: gateway: bad method\n");
        // Call-time Unsupported -> 1 (Q8 option (b)).
        let (code, _text) = flow_render(&classify_error(&TransportError::Unsupported {
            message: "detour chains are not resolved in M3".to_string(),
        }));
        assert_eq!(code, 1);
    }

    #[test]
    fn classify_error_connection_variants() {
        // Safety N3 (fix loop 1): `ConnectionError` renders
        // length-only; `ConnectionDown` renders its message
        // (already truncated to 200 chars at construction in
        // `castctl-transport/src/http.rs`), or the bare form
        // when empty. Pins the CLI render so a future change
        // cannot start echoing peer text here.
        let (code, text) = flow_render(&classify_error(&TransportError::ConnectionError {
            message: "gateway: websocket TLS failed".to_string(),
        }));
        assert_eq!(code, 1);
        assert_eq!(text, "castctl: conn: connection error error_length=29\n");
        let (code, text) = flow_render(&classify_error(&TransportError::ConnectionDown {
            message: "boom".to_string(),
        }));
        assert_eq!(code, 1);
        assert_eq!(text, "castctl: conn: connection down: boom\n");
        let (code, text) = flow_render(&classify_error(&TransportError::ConnectionDown {
            message: String::new(),
        }));
        assert_eq!(code, 1);
        assert_eq!(text, "castctl: conn: connection down\n");
    }

    #[test]
    fn gateway_error_text_unknown_length() {
        let s = BodySummary {
            status: -1,
            body_length: None,
            content_type: None,
            error_code: None,
        };
        assert_eq!(gateway_error_text(&s), "conn: gateway status=-1");
    }

    #[test]
    fn indent_json_cases() {
        assert_eq!(indent_json("{}"), "{}");
        assert_eq!(indent_json("[]"), "[]");
        assert_eq!(
            indent_json(r#"{"a":1,"b":[1,2,{"c":null}]}"#),
            "{\n  \"a\": 1,\n  \"b\": [\n    1,\n    2,\n    {\n      \"c\": null\n    }\n  ]\n}"
        );
        // Key order is preserved (not sorted).
        assert_eq!(
            indent_json(r#"{"z":1,"a":2}"#),
            "{\n  \"z\": 1,\n  \"a\": 2\n}"
        );
        // Empty containers stay compact inside.
        assert_eq!(
            indent_json(r#"{"a":{},"b":[]}"#),
            "{\n  \"a\": {},\n  \"b\": []\n}"
        );
        // serde_json `\b`/`\f` become Go's `\u0008`/`\u000c`;
        // raw U+2028 is escaped; other escapes pass through.
        assert_eq!(
            indent_json("{\"a\":\"x\\b\\f\\n\\u2028y\"}"),
            "{\n  \"a\": \"x\\u0008\\u000c\\n\\u2028y\"\n}"
        );
        // Top-level scalar passes through.
        assert_eq!(indent_json("42"), "42");
        assert_eq!(indent_json("\"hi\""), "\"hi\"");
    }

    #[test]
    fn write_json_serde_sorts_keys() {
        let v = serde_json::json!({"z": 1, "a": {"b": 2}});
        assert_eq!(
            write_json_serde(&v).unwrap(),
            "{\n  \"a\": {\n    \"b\": 2\n  },\n  \"z\": 1\n}\n"
        );
    }

    #[test]
    fn go_type_name_cases() {
        assert_eq!(go_type_name(&SerdeValue::Null), "<nil>");
        assert_eq!(go_type_name(&SerdeValue::Bool(true)), "bool");
        assert_eq!(go_type_name(&serde_json::json!(1.5)), "json.Number");
        assert_eq!(go_type_name(&serde_json::json!("s")), "string");
        assert_eq!(go_type_name(&serde_json::json!([1])), "[]interface {}");
        assert_eq!(
            go_type_name(&serde_json::json!({"a": 1})),
            "map[string]interface {}"
        );
    }

    #[test]
    fn event_has_text_quirk() {
        // Non-empty string counts.
        let ev = serde_json::json!({"payload": {"display_text": "hi"}});
        assert!(event_has_text(&ev));
        // Empty string STILL counts (Go `"" != false`).
        let ev = serde_json::json!({"payload": {"display_text": ""}});
        assert!(event_has_text(&ev));
        // Explicit false does not count.
        let ev = serde_json::json!({"payload": {"display_text": false}});
        assert!(!event_has_text(&ev));
        // Number 0 counts (non-string truthy arm).
        let ev = serde_json::json!({"payload": {"content": 0}});
        assert!(event_has_text(&ev));
        // Null does not count.
        let ev = serde_json::json!({"payload": {"content": null}});
        assert!(!event_has_text(&ev));
        // Missing payload does not count.
        let ev = serde_json::json!({});
        assert!(!event_has_text(&ev));
    }

    #[test]
    fn rows_json_empty_is_brackets() {
        assert_eq!(rows_json(&[]), "[]");
        assert_eq!(rows_json(&["{\"a\":1}".to_string()]), "[{\"a\":1}]");
    }

    // --- Offline `run()` tests (no network) ---

    #[test]
    fn bad_config_is_exit_2() {
        let dir = temp_home("bad-config");
        std::fs::write(dir.join("config.json"), "{not json").unwrap();
        let (_home, map) = isolated_env();
        let out = run_env(
            &[
                "--config",
                dir.join("config.json").to_str().unwrap(),
                "status",
            ],
            map,
        );
        assert_eq!(out.code, 2);
        assert!(out.stdout.is_empty());
        assert!(out.stderr.starts_with("castctl: "), "{}", out.stderr);
    }

    #[test]
    fn unknown_profile_is_typed_cookies_missing() {
        // Go's LoadProfile synthesises SourceNone defaults
        // for a ghost name (config.go:1205), so `status
        // --profile nosuch` reaches the connector and fails
        // on the missing cookies file — exit 2, typed JSON.
        let dir = temp_home("unknown-profile");
        std::fs::write(
            dir.join("config.json"),
            r#"{"profiles":{"no1":{"outbound":"direct"}}}"#,
        )
        .unwrap();
        let (_home, map) = isolated_env();
        let out = run_env(
            &[
                "--config",
                dir.join("config.json").to_str().unwrap(),
                "--profile",
                "nosuch",
                "status",
            ],
            map,
        );
        assert_eq!(out.code, 2);
        assert!(out.stdout.is_empty());
        assert!(
            out.stderr
                .starts_with("{\"error\":\"conn: auth_failed message_length="),
            "{}",
            out.stderr
        );
        assert!(
            out.stderr.contains("\"type\":\"cookies_missing\""),
            "{}",
            out.stderr
        );
        // The cookies path is NOT in the output by design:
        // the typed JSON carries only the Auth log summary
        // (class + message length), never message bytes.
    }

    #[test]
    fn dispatch_detour_is_exit_2() {
        let dir = temp_home("detour");
        std::fs::write(
            dir.join("config.json"),
            r#"{"profiles":{"no1":{"outbound":"t1"}},"outbounds":[{"tag":"t1","type":"direct","detour":"t2"}]}"#,
        )
        .unwrap();
        let (_home, map) = isolated_env();
        let out = run_env(
            &[
                "--config",
                dir.join("config.json").to_str().unwrap(),
                "--profile",
                "no1",
                "status",
            ],
            map,
        );
        assert_eq!(out.code, 2);
        assert!(out.stdout.is_empty());
        assert!(out.stderr.starts_with("castctl: "), "{}", out.stderr);
    }

    #[test]
    fn status_with_no_cookies_is_typed_json() {
        // Isolated HOME, no config file at all: the default
        // profile synthesises, the connector finds no cookies
        // file — exit 2, typed cookies_missing JSON (Go's
        // LoadProfile + connector behaviour, not a stub).
        let (_home, map) = isolated_env();
        let out = run_env(&["status"], map);
        assert_eq!(out.code, 2);
        assert!(out.stdout.is_empty());
        assert!(
            out.stderr.contains("\"type\":\"cookies_missing\""),
            "{}",
            out.stderr
        );
    }

    #[test]
    fn history_download_stubs_exit_1() {
        let dir = temp_home("download");
        std::fs::write(
            dir.join("config.json"),
            r#"{"profiles":{"no1":{"outbound":"direct"}}}"#,
        )
        .unwrap();
        let (_home, map) = isolated_env();
        let out = run_env(
            &[
                "--config",
                dir.join("config.json").to_str().unwrap(),
                "history",
                "--download",
                "/tmp/dl",
            ],
            map,
        );
        assert_eq!(out.code, 1);
        assert_eq!(out.stderr, STUB_LINE);
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn read_commands_still_parse_before_network() {
        // A parser error exits 2 with the 3-line shape, before
        // any config/network work.
        let out = run_args(&["goal", "a", "b"]);
        assert_eq!(out.code, 2);
        assert!(out.stderr.contains("unrecognized arguments: b"));
        let out = run_args(&["goal"]);
        assert_eq!(out.code, 2);
        assert!(
            out.stderr
                .contains("the following arguments are required: id")
        );
    }
}
