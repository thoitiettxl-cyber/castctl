// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The M4b network path: `classifyError` / `classifyConnError`
//! / `classifyAuthMessage` (`internal/commands/commands.go:
//! 268-337`, `347-396`), Go's `writeJSON` (indent 2,
//! `SetEscapeHTML(false)`), and the 13 read-only command
//! handlers (`internal/commands/read.go`).
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

use chrono::Local;

use castctl_gateway::auth::fetch_session_info;
use castctl_gateway::subscription::{SubscriptionOptions, fetch_subscription};
use castctl_shared::{
    event_row_to_json, feed_row_to_json, feed_rows, file_row_to_json, file_rows, fmt_event,
    from_serde, goal_row_to_json, goal_rows, idea_row_to_json, idea_rows, local_abbr_now,
    session_row_to_json, session_rows, status_summary_to_json, summarize_status, summarize_usage,
    usage_lines, usage_summary_to_json,
};
use castctl_transport::{BodySummary, TransportError};
use serde_json::Value as SerdeValue;

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
/// branch): `"`/`\`/`\n`/`\r`/`\t` short escapes, `<`/`>`/`&`
/// as `\u003c`/`\u003e`/`\u0026`, U+2028/U+2029 escaped, other
/// control chars as `\u00XX`.
fn escape_go_marshal_string(s: &str) -> String {
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
fn go_type_name(v: &SerdeValue) -> &'static str {
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

async fn dispatch(spec: &CommandSpec, rt: &Runtime, p: &Parsed) -> Result<String, FlowErr> {
    match spec.name {
        "status" => cmd_status(rt).await,
        "usage" => cmd_usage(rt, p).await,
        "threads" => cmd_threads(rt, p).await,
        "history" => cmd_history(rt, p).await,
        "files" => cmd_files(rt, p).await,
        "feed" => cmd_feed(rt, p).await,
        "feed-status" => cmd_feed_status(rt).await,
        "feed-prompt" => cmd_feed_prompt(rt).await,
        "goals" => cmd_goals(rt).await,
        "goal" => cmd_goal(rt, p).await,
        "ideas" => cmd_ideas(rt).await,
        "idea" => cmd_idea(rt, p).await,
        "unread" => cmd_unread(rt).await,
        _ => Err(msg(
            1,
            format!("command {} is not a network command", spec.name),
        )),
    }
}

/// Run one read-only command: resolve config + parse (kept
/// for the runtime builder), build the tokio runtime and the
/// per-profile runtime, dispatch, and append the stdout text
/// to the outcome. Errors surface as `FlowErr` (typed JSON
/// via `Verbatim`, plain via `Msg`).
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
    ctx.out.stdout.push_str(&out);
    Ok(())
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
    fn invite_stubs_exit_1() {
        let dir = temp_home("invite");
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
                "invite",
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
