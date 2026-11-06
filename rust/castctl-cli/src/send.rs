// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `send` (`internal/commands/wait.go:1028-1112` `cmdSend`,
//! `862-986` `deliverSend`, `988-1026` `sendBaseJSON` /
//! `sendWaitJSON` / `buildSendWaitJSON`, `1113-...`
//! `sendDownloadStep`): send one text turn, wait for the
//! delivery ack on `chat.history`, then — unless `--wait 0`
//! — follow the turn with M7a's `wait` Runner (via
//! `execute_wait`, the same crate's `wait` path — no
//! rewritten wait mechanism, no duplicated state machine),
//! and optionally save the turn's resources.
//!
//! Exit codes: deliver failure → the gateway/auth code
//! (2/3/4); no ack → JSON + silent 5; `--wait 0` → JSON +
//! 0; waited → the Runner's exit code (0/2/4/124, silent).
//! `--text` prints `user_seq=<N>` + the wait text instead
//! of JSON. The `wait` note is copied, except a timeout
//! reports the re-run hint (`buildSendWaitJSON`, D-1).

use std::sync::Arc;
use std::time::{Duration, Instant};

use castctl_config::jsonvalue::{JsonValue, OrderedObject, encode_ordered_json};
use castctl_config::profile::Profile;
use castctl_gateway::gateway::{Body, RequestOptions};
use castctl_gateway::shared::SharedConn;
use castctl_shared::bridge::from_serde;
use castctl_shared::resources::{Resource, event_resources};
use castctl_telegram::wait::{Reply, user_ack};
use castctl_transport::TransportError;
use castctl_wait::{Cancel, WaitResult};
use serde_json::Value as SerdeValue;

use crate::network::{
    CmdOut, classify_conn_error, go_type_name, render_flow_err, save_resources, save_row_json,
    summarize_transport_error, write_json_text,
};
use crate::parser::Parsed;
use crate::run::{Ctx, FlowErr, GlobalOpts, config_err, msg, msg_empty, resolve_and_load_single};
use crate::runtime::{Runtime, build_runtime};
use crate::wait::{
    ensure_node_id, execute_wait, lookup_env, print_wait_text, resolve_auto_allow_once,
    resolve_auto_approve, to_wait_result_json,
};
use castctl_config::config::resolve_active_profile;

/// `eventSeq` (`wait.go:825-...`): a numeric `seq`,
/// lenient — a non-numeric or absent `seq` reads as 0.
/// A float truncates, like Go's `int64(float64)` case.
pub(crate) fn event_seq(ev: &SerdeValue) -> i64 {
    match ev.get("seq") {
        Some(SerdeValue::Number(n)) => {
            if let Some(i) = n.as_i64() {
                i
            } else if let Some(f) = n.as_f64() {
                f as i64
            } else {
                0
            }
        }
        _ => 0,
    }
}

/// `maxSeq` (`wait.go:825-...`): the max seq across the
/// events, starting at 0 — a negative seq never wins.
pub(crate) fn max_seq(events: &[SerdeValue]) -> i64 {
    events.iter().map(event_seq).fold(0, i64::max)
}

/// `swallowableHistoryError` (`wait.go:816-823`): only a
/// gateway error or a timeout is swallowed in the ack
/// poll; anything else fails the send.
fn swallowable_history_error(err: &TransportError) -> bool {
    matches!(
        err,
        TransportError::Gateway(_) | TransportError::Timeout { .. }
    )
}

/// An ordered-object builder (field order = insertion
/// order, Go struct order). Same shape as `wait::obj`.
fn obj(pairs: &[(&str, JsonValue)]) -> JsonValue {
    let mut o = OrderedObject::new();
    for (k, v) in pairs {
        o.set((*k).to_string(), v.clone());
    }
    JsonValue::Object(o)
}

/// `strPtrOrNil`: `""` → `null`, else the string.
fn str_or_null(s: &str) -> JsonValue {
    if s.is_empty() {
        JsonValue::Null
    } else {
        JsonValue::Str(s.to_string())
    }
}

/// One field of the wait result JSON, by key.
fn wait_field<'a>(w: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    match w {
        JsonValue::Object(o) => o.get(key),
        _ => None,
    }
}

/// The wait result's `note` (present only when
/// non-empty), else `""`.
fn wait_note(w: &JsonValue) -> &str {
    match wait_field(w, "note") {
        Some(JsonValue::Str(s)) => s,
        _ => "",
    }
}

/// The send head (`sendBaseJSON`): `sent`, `delivered`,
/// `user_seq` (null when no ack), `stream`.
fn send_base_pairs(
    sent: bool,
    delivered: bool,
    user_seq: Option<i64>,
    stream: i64,
) -> Vec<(&'static str, JsonValue)> {
    vec![
        ("sent", JsonValue::Bool(sent)),
        ("delivered", JsonValue::Bool(delivered)),
        (
            "user_seq",
            user_seq.map_or(JsonValue::Null, |s| JsonValue::Number(s.to_string())),
        ),
        ("stream", JsonValue::Number(stream.to_string())),
    ]
}

/// `sendNoWaitJSON`: the head plus an optional note (the
/// no-ack case only).
fn send_no_wait_json(
    sent: bool,
    delivered: bool,
    user_seq: Option<i64>,
    stream: i64,
    note: Option<&str>,
) -> JsonValue {
    let mut pairs = send_base_pairs(sent, delivered, user_seq, stream);
    if let Some(n) = note {
        pairs.push(("note", JsonValue::Str(n.to_string())));
    }
    obj(&pairs)
}

/// `sendReplyJSON`: the last reply, with the fixed role
/// `message.assistant` and `message_id` null when empty.
fn send_reply_json(last: &Reply) -> JsonValue {
    obj(&[
        ("seq", JsonValue::Number(last.seq.to_string())),
        ("role", JsonValue::Str("message.assistant".to_string())),
        ("message_id", str_or_null(&last.message_id)),
        ("text", JsonValue::Str(last.text.clone())),
    ])
}

/// `buildSendWaitJSON` (`wait.go:1001-1026`): the head,
/// then the wait result in SEND key order — `question`
/// BEFORE `needs_input_reason` (the reverse of the wait
/// shape), `after_seq` and `final_read_failed` dropped —
/// then the last reply, `downloads` / `download_error`,
/// and the note last. A timeout always reports the re-run
/// hint, not the wait note (loop-2 safety D-1).
#[allow(clippy::too_many_arguments)]
fn build_send_json(
    sent: bool,
    delivered: bool,
    user_seq: i64,
    stream: i64,
    res: &WaitResult,
    auto_approve_enabled: bool,
    wait_seconds: i64,
    downloads: Option<Vec<JsonValue>>,
    download_error: Option<&str>,
) -> JsonValue {
    let w = to_wait_result_json(res, auto_approve_enabled);
    let mut pairs = send_base_pairs(sent, delivered, Some(user_seq), stream);
    for key in ["outcome", "status", "final_text", "replies"] {
        if let Some(v) = wait_field(&w, key) {
            pairs.push((key, v.clone()));
        }
    }
    for key in [
        "approvals",
        "auto_approved",
        "auto_approve_errors",
        "widgets",
    ] {
        if let Some(v) = wait_field(&w, key) {
            pairs.push((key, v.clone()));
        }
    }
    // SEND order: `question` before `needs_input_reason`
    // (the reverse of the wait shape).
    if let Some(v) = wait_field(&w, "question") {
        pairs.push(("question", v.clone()));
    }
    if let Some(v) = wait_field(&w, "needs_input_reason") {
        pairs.push(("needs_input_reason", v.clone()));
    }
    if let Some(last) = res.replies.last() {
        pairs.push(("reply", send_reply_json(last)));
    }
    if let Some(rows) = downloads
        && !rows.is_empty()
    {
        pairs.push(("downloads", JsonValue::Array(rows)));
    }
    if let Some(e) = download_error
        && !e.is_empty()
    {
        pairs.push(("download_error", JsonValue::Str(e.to_string())));
    }
    let note = if res.outcome == "timeout" {
        format!(
            "turn not finished within {wait_seconds}s; run `castctl wait --after-seq {user_seq}`"
        )
    } else {
        wait_note(&w).to_string()
    };
    if !note.is_empty() {
        pairs.push(("note", JsonValue::Str(note)));
    }
    obj(&pairs)
}

/// `dedupResources` (`wait.go`, `dedupResources`) over the
/// fresh events: resources from events with `seq >
/// after_seq`, deduplicated by path in first-seen order.
fn dedup_resources(events: &[SerdeValue], after_seq: i64) -> Vec<Resource> {
    let mut out: Vec<Resource> = Vec::new();
    for ev in events {
        if event_seq(ev) <= after_seq {
            continue;
        }
        for r in event_resources(&from_serde(ev)) {
            if !out.iter().any(|x| x.path == r.path) {
                out.push(r);
            }
        }
    }
    out
}

/// Render an ordered JSON value the way Go `writeJSON`
/// does: compact, then the shared 2-space indenter +
/// trailing newline.
fn render_json(v: &JsonValue) -> Result<String, FlowErr> {
    let compact = encode_ordered_json(v)
        .map_err(|e| msg(1, format!("failed to serialize send result: {e}")))?;
    Ok(write_json_text(&compact))
}

/// The `FlowErr` code (all variants), for the download
/// step's auth/cancel check.
pub(crate) fn flow_err_code(e: &FlowErr) -> i32 {
    match e {
        FlowErr::HelpShown => 0,
        FlowErr::Exit(code) => *code,
        FlowErr::Verbatim { code, .. } => *code,
        FlowErr::Msg { code, .. } => *code,
    }
}

/// The `FlowErr` message text (the already-short summary),
/// for `download_error`.
pub(crate) fn flow_err_text(e: &FlowErr) -> String {
    match e {
        FlowErr::Msg { message, .. } => message.clone().unwrap_or_default(),
        FlowErr::Verbatim { text, .. } => text.clone(),
        FlowErr::Exit(_) | FlowErr::HelpShown => String::new(),
    }
}

/// `callHistoryEvents` (`wait.go:799-814`): `chat.history`
/// `{limit, session_id?}` → the `chat_events` array
/// (missing / non-array → empty). A non-object result is
/// a validation error, with the same text as the wait
/// `HistoryAdapter`.
async fn read_history_events(
    shared: &Arc<SharedConn>,
    thread: &str,
    limit: usize,
) -> Result<Vec<SerdeValue>, TransportError> {
    let mut body = serde_json::Map::new();
    body.insert("limit".to_string(), SerdeValue::Number(limit.into()));
    if !thread.is_empty() {
        body.insert(
            "session_id".to_string(),
            SerdeValue::String(thread.to_string()),
        );
    }
    let v = shared
        .call_json(
            "chat.history",
            RequestOptions {
                body: Body::Json(SerdeValue::Object(body)),
                ..Default::default()
            },
        )
        .await?;
    let Some(m) = v.as_object() else {
        return Err(TransportError::Validation {
            message: format!(
                "gateway: chat.history result is not an object: {}",
                go_type_name(&v)
            ),
        });
    };
    Ok(m.get("chat_events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default())
}

/// `deliverSend` (`wait.go:862-986`): read the baseline
/// (limit=1, cross-checked by limit=20 — a single window
/// cannot prove the newest seq), open `chat.stream`
/// (`Track=false`: nobody reads the stream's own frames),
/// then poll `chat.history` (limit=10, every 100 ms) for
/// the delivery ack — our `message.user` above the
/// baseline. A failed baseline read fails the send before
/// anything is sent. Returns `(user_seq, stream_id)`;
/// `user_seq` is `None` when no ack arrived within
/// `ack_timeout`.
pub(crate) async fn deliver_send(
    rt: &Runtime,
    profile: &Profile,
    text: &str,
    thread: &str,
    ack_timeout: Duration,
    cancel: &Cancel,
) -> Result<(Option<i64>, i64), FlowErr> {
    let shared = &rt.shared;
    let events = read_history_events(shared, thread, 1)
        .await
        .map_err(|e| classify_conn_error(&e))?;
    let mut baseline = max_seq(&events);
    let confirm = read_history_events(shared, thread, 20)
        .await
        .map_err(|e| classify_conn_error(&e))?;
    baseline = baseline.max(max_seq(&confirm));
    let gw = shared.live().await.map_err(|e| classify_conn_error(&e))?;
    // Go's `params` is a `map[string]any`: `encoding/json`
    // sorts the keys, so the body is built in sorted order
    // (capabilities, items, node_id, session_id).
    let mut body = serde_json::Map::new();
    body.insert(
        "capabilities".to_string(),
        SerdeValue::Object(serde_json::Map::new()),
    );
    body.insert(
        "items".to_string(),
        serde_json::json!([{"type": "text", "text": text}]),
    );
    body.insert(
        "node_id".to_string(),
        SerdeValue::String(profile.node_id.clone()),
    );
    if !thread.is_empty() {
        body.insert(
            "session_id".to_string(),
            SerdeValue::String(thread.to_string()),
        );
    }
    let stream_id = gw
        .open_stream("chat.stream", Some(SerdeValue::Object(body)))
        .await
        .map_err(|e| classify_conn_error(&e))?;
    let deadline = Instant::now() + ack_timeout;
    let mut user_seq = None;
    while user_seq.is_none() && Instant::now() < deadline {
        if cancel.is_set() {
            return Err(msg_empty(130));
        }
        match read_history_events(shared, thread, 10).await {
            Ok(events) => {
                user_seq = user_ack(&events, baseline, Some(text));
            }
            Err(e) if swallowable_history_error(&e) => {}
            Err(e) => return Err(classify_conn_error(&e)),
        }
        if user_seq.is_none() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let pause = remaining.min(Duration::from_millis(100));
            tokio::select! {
                () = tokio::time::sleep(pause) => {}
                () = cancel.notified() => return Err(msg_empty(130)),
            }
        }
    }
    Ok((user_seq, stream_id))
}

/// `sendDownloadStep` (`wait.go:1113-...`): a fresh
/// history read (limit=30) → the resources of events
/// after `user_seq` → `save_resources` (overwrite=false).
/// Auth / cancel propagate; anything else becomes
/// `download_error` and the command continues with the
/// send result. Returns `(downloads, download_error)`.
async fn send_download_step(
    rt: &Runtime,
    thread: &str,
    user_seq: i64,
    dir: &str,
    res: &WaitResult,
) -> Result<(Option<Vec<JsonValue>>, Option<String>), FlowErr> {
    if dir.is_empty() || res.replies.is_empty() {
        return Ok((None, None));
    }
    let events = match read_history_events(&rt.shared, thread, 30).await {
        Ok(ev) => ev,
        Err(e) => match e {
            TransportError::Auth { .. } => return Err(classify_conn_error(&e)),
            TransportError::Cancelled => return Err(msg_empty(130)),
            _ => return Ok((None, Some(summarize_transport_error(&e)))),
        },
    };
    let resources = dedup_resources(&events, user_seq);
    match save_resources(rt, &resources, dir, false).await {
        // Go `sendWaitJSON.Downloads` is `omitempty`: an
        // empty row list is omitted, not `"downloads":[]`.
        Ok(rows) if rows.is_empty() => Ok((None, None)),
        Ok(rows) => Ok((Some(rows.iter().map(save_row_json).collect()), None)),
        Err(e) => {
            let code = flow_err_code(&e);
            if code == 2 || code == 130 {
                Err(e)
            } else {
                Ok((None, Some(flow_err_text(&e))))
            }
        }
    }
}

/// The send core: deliver, then wait (unless
/// `--wait 0`), then the optional download step, then
/// render (JSON, or `--text`). The caller owns the
/// profile (node id already ensured) and the resolved
/// auto-approve toggles.
async fn send_async(
    rt: &Runtime,
    profile: &Profile,
    p: &Parsed,
    approve_enabled: bool,
    allow_once: bool,
) -> Result<CmdOut, FlowErr> {
    let text = p.positionals.first().cloned().unwrap_or_default();
    let thread = p.str("thread");
    let ack_timeout = Duration::from_secs(p.int_val("ack-timeout").max(0) as u64);
    let wait_seconds = if p.bool("until-done") {
        24 * 3600
    } else {
        p.int_val("wait")
    };
    // SIGINT cancels the deliver poll (Go `ctx`); the wait
    // phase installs its own watcher inside `execute_wait`.
    let cancel = Cancel::new();
    let sig_cancel = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            sig_cancel.set();
        }
    });
    let (user_seq, stream_id) =
        deliver_send(rt, profile, &text, &thread, ack_timeout, &cancel).await?;
    let Some(user_seq) = user_seq else {
        let note = format!(
            "no delivery ack within {}s; check `castctl history`",
            ack_timeout.as_secs()
        );
        let v = send_no_wait_json(true, false, None, stream_id, Some(&note));
        return Ok(CmdOut::code(render_json(&v)?, 5));
    };
    if wait_seconds == 0 {
        let v = send_no_wait_json(true, true, Some(user_seq), stream_id, None);
        return Ok(CmdOut::code(render_json(&v)?, 0));
    }
    let (res, enabled, wait_stderr) = execute_wait(
        rt,
        profile,
        &thread,
        Some(user_seq),
        Duration::from_secs(wait_seconds.max(0) as u64),
        approve_enabled,
        allow_once,
    )
    .await?;
    let (downloads, download_error) =
        send_download_step(rt, &thread, user_seq, &p.str("download"), &res).await?;
    let v = build_send_json(
        true,
        true,
        user_seq,
        stream_id,
        &res,
        enabled,
        wait_seconds,
        downloads,
        download_error.as_deref(),
    );
    if p.bool("text") {
        let mut stdout = format!("user_seq={user_seq}\n");
        let (w_out, w_err) = print_wait_text(&res);
        stdout.push_str(&w_out);
        let mut stderr = wait_stderr;
        stderr.push_str(&w_err);
        Ok(CmdOut {
            stdout,
            stderr,
            code: res.exit_code,
            ..Default::default()
        })
    } else {
        Ok(CmdOut {
            stdout: render_json(&v)?,
            stderr: wait_stderr,
            code: res.exit_code,
            ..Default::default()
        })
    }
}

/// `cmdSend` (`wait.go:1028-1112`): parse (already done
/// by `cmd_plain`, incl. `parseAutoToggles`), resolve the
/// profile + node id + toggles exactly like
/// `run_wait_command`, build the runtime, run the send,
/// print the streams, and exit silently on a non-zero
/// code — mirroring `run_network_command`.
pub(crate) fn run_send_command(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    p: &Parsed,
) -> Result<(), FlowErr> {
    let flag_approve = if p.bool("auto-approve") {
        Some(true)
    } else if p.bool("no-auto-approve") {
        Some(false)
    } else {
        None
    };
    let flag_once = if p.bool("auto-allow-once") {
        Some(true)
    } else if p.bool("no-auto-allow-once") {
        Some(false)
    } else {
        None
    };
    let (loc, single) = resolve_and_load_single(ctx, g)?;
    let profile_flag = if g.profile_set {
        Some(g.profile_flag.as_str())
    } else {
        None
    };
    let getenv = ctx.getenv;
    let mut profile =
        resolve_active_profile(&loc.config_dir, profile_flag, getenv).map_err(config_err)?;
    ensure_node_id(&mut profile, lookup_env(ctx, "MUSE_NODE_ID"));
    let approve_enabled =
        resolve_auto_approve(&profile, flag_approve, lookup_env(ctx, "MUSE_AUTO_APPROVE"))?;
    let allow_once =
        resolve_auto_allow_once(&profile, flag_once, lookup_env(ctx, "MUSE_AUTO_ALLOW_ONCE"))?;
    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| msg(1, format!("failed to start async runtime: {e}")))?;
    let out = tokio_rt.block_on(async move {
        let runtime = build_runtime(&loc, single.as_ref(), profile_flag, getenv)?;
        send_async(&runtime, &profile, p, approve_enabled, allow_once).await
    })?;
    ctx.out.stdout.push_str(&out.stdout);
    ctx.out.stdout_bytes.extend_from_slice(&out.stdout_bytes);
    ctx.out.stderr.push_str(&out.stderr);
    if out.code != 0 {
        return Err(FlowErr::Exit(out.code));
    }
    Ok(())
}

/// Test-only driver entry (same role as
/// `run_driver_command`): `send` against an already-built
/// runtime + profile, rendering `FlowErr` exactly like
/// `run_inner`. The driver profile carries
/// `node_id = "wait-driver"`; the toggles resolve from the
/// flags + the process environment (unset in the harness).
pub async fn run_driver_send(
    rt: &Runtime,
    profile: &Profile,
    p: &Parsed,
) -> (Vec<u8>, String, i32) {
    let flag_approve = if p.bool("auto-approve") {
        Some(true)
    } else if p.bool("no-auto-approve") {
        Some(false)
    } else {
        None
    };
    let flag_once = if p.bool("auto-allow-once") {
        Some(true)
    } else if p.bool("no-auto-allow-once") {
        Some(false)
    } else {
        None
    };
    let approve_enabled = match resolve_auto_approve(
        profile,
        flag_approve,
        std::env::var("MUSE_AUTO_APPROVE").ok(),
    ) {
        Ok(v) => v,
        Err(e) => {
            let (code, stderr) = render_flow_err(&e);
            return (Vec::new(), stderr, code);
        }
    };
    let allow_once = match resolve_auto_allow_once(
        profile,
        flag_once,
        std::env::var("MUSE_AUTO_ALLOW_ONCE").ok(),
    ) {
        Ok(v) => v,
        Err(e) => {
            let (code, stderr) = render_flow_err(&e);
            return (Vec::new(), stderr, code);
        }
    };
    match send_async(rt, profile, p, approve_enabled, allow_once).await {
        Ok(out) => (out.stdout_combined(), out.stderr, out.code),
        Err(e) => {
            let (code, stderr) = render_flow_err(&e);
            (Vec::new(), stderr, code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use castctl_telegram::wait::{Reply, WaitKind, Widget};
    use serde_json::json;

    fn reply(seq: i64, message_id: &str, text: &str) -> Reply {
        Reply {
            seq,
            message_id: message_id.to_string(),
            text: text.to_string(),
            widgets: vec![],
            media: false,
            agent_id: String::new(),
            root_agent_id: String::new(),
        }
    }

    fn done_result() -> WaitResult {
        WaitResult {
            kind: WaitKind::Done,
            outcome: "done".to_string(),
            status: "completed".to_string(),
            after_seq: 42,
            final_text: "hello".to_string(),
            replies: vec![reply(42, "m1", "hello")],
            final_read_failed: false,
            note: String::new(),
            approvals: vec![],
            needs_input_reason: String::new(),
            question: String::new(),
            exit_code: 0,
            node_id: String::new(),
            auto_approved: vec![],
            auto_approve_errors: vec![],
        }
    }

    fn compact(v: &JsonValue) -> String {
        encode_ordered_json(v).expect("send test JSON encodes")
    }

    #[test]
    fn build_send_json_done_shape() {
        let got = build_send_json(true, true, 7, 3, &done_result(), false, 90, None, None);
        assert_eq!(
            compact(&got),
            r#"{"sent":true,"delivered":true,"user_seq":7,"stream":3,"outcome":"done","status":"completed","final_text":"hello","replies":[{"seq":42,"message_id":"m1","text":"hello"}],"reply":{"seq":42,"role":"message.assistant","message_id":"m1","text":"hello"}}"#
        );
    }

    #[test]
    fn build_send_json_timeout_note_overrides_wait_note() {
        let mut res = done_result();
        res.kind = WaitKind::Timeout;
        res.outcome = "timeout".to_string();
        res.status = String::new();
        res.final_text = String::new();
        res.replies = vec![];
        res.note = "wait failed internally; run `castctl wait` again".to_string();
        res.exit_code = 124;
        let got = build_send_json(true, true, 7, 3, &res, false, 90, None, None);
        assert_eq!(
            compact(&got),
            r#"{"sent":true,"delivered":true,"user_seq":7,"stream":3,"outcome":"timeout","status":null,"final_text":null,"replies":[],"note":"turn not finished within 90s; run `castctl wait --after-seq 7`"}"#
        );
    }

    #[test]
    fn build_send_json_needs_input_question_before_reason() {
        let mut res = done_result();
        res.outcome = "needs_input".to_string();
        res.needs_input_reason = "waiting".to_string();
        res.question = "Q?".to_string();
        res.exit_code = 2;
        let got = build_send_json(true, true, 7, 3, &res, false, 90, None, None);
        let s = compact(&got);
        let q = s.find("\"question\"").expect("question key");
        let r = s.find("\"needs_input_reason\"").expect("reason key");
        assert!(q < r, "question must precede needs_input_reason: {s}");
        assert!(
            s.contains(r#""question":"Q?","needs_input_reason":"waiting""#),
            "{s}"
        );
    }

    #[test]
    fn build_send_json_no_replies_nulls() {
        let mut res = done_result();
        res.replies = vec![];
        res.status = String::new();
        res.final_text = String::new();
        let got = build_send_json(true, true, 7, 3, &res, false, 90, None, None);
        let s = compact(&got);
        assert!(
            s.contains(r#""status":null,"final_text":null,"replies":[]}"#),
            "{s}"
        );
        assert!(!s.contains("\"reply\""), "{s}");
    }

    #[test]
    fn build_send_json_empty_downloads_omitted() {
        // Go `sendWaitJSON.Downloads` is `omitempty`: zero
        // rows omit the key entirely (harness
        // send-download-empty caught the Rust side
        // emitting `"downloads":[]`).
        let got = build_send_json(
            true,
            true,
            7,
            3,
            &done_result(),
            false,
            90,
            Some(vec![]),
            None,
        );
        let s = compact(&got);
        assert!(!s.contains("\"downloads\""), "{s}");
    }

    #[test]
    fn build_send_json_downloads_and_error_last() {
        let rows = vec![obj(&[
            ("path", JsonValue::Str("sandbox://a.jpg".to_string())),
            ("file", JsonValue::Str("/tmp/dl/a.jpg".to_string())),
            ("bytes", JsonValue::Number("7".to_string())),
        ])];
        let got = build_send_json(
            true,
            true,
            7,
            3,
            &done_result(),
            false,
            90,
            Some(rows),
            Some("gateway error"),
        );
        let s = compact(&got);
        assert!(
            s.contains(
                r#""reply":{"seq":42,"role":"message.assistant","message_id":"m1","text":"hello"},"downloads":[{"path":"sandbox://a.jpg","file":"/tmp/dl/a.jpg","bytes":7}],"download_error":"gateway error"}"#
            ),
            "{s}"
        );
    }

    #[test]
    fn build_send_json_reply_message_id_null_when_empty() {
        let mut res = done_result();
        res.replies = vec![reply(42, "", "hello")];
        let got = build_send_json(true, true, 7, 3, &res, false, 90, None, None);
        let s = compact(&got);
        assert!(
            s.contains(
                r#""reply":{"seq":42,"role":"message.assistant","message_id":null,"text":"hello"}"#
            ),
            "{s}"
        );
        assert!(
            s.contains(r#""replies":[{"seq":42,"message_id":null,"text":"hello"}]"#),
            "{s}"
        );
    }

    #[test]
    fn build_send_json_widgets_from_last_reply() {
        let mut res = done_result();
        res.replies = vec![Reply {
            widgets: vec![Widget {
                id: json!("w1"),
                kind: "confirm".to_string(),
                text: Some("Go?".to_string()),
                options: json!(["yes", "no"]),
            }],
            ..reply(42, "m1", "hello")
        }];
        let got = build_send_json(true, true, 7, 3, &res, false, 90, None, None);
        let s = compact(&got);
        assert!(
            s.contains(r#""widgets":[{"widget_id":"w1","kind":"confirm","text":"Go?","options":["yes","no"]}]"#),
            "{s}"
        );
    }

    #[test]
    fn send_no_wait_json_with_and_without_note() {
        let with_note = send_no_wait_json(
            true,
            false,
            None,
            3,
            Some("no delivery ack within 30s; check `castctl history`"),
        );
        assert_eq!(
            compact(&with_note),
            r#"{"sent":true,"delivered":false,"user_seq":null,"stream":3,"note":"no delivery ack within 30s; check `castctl history`"}"#
        );
        let without = send_no_wait_json(true, true, Some(7), 3, None);
        assert_eq!(
            compact(&without),
            r#"{"sent":true,"delivered":true,"user_seq":7,"stream":3}"#
        );
    }

    #[test]
    fn event_seq_and_max_seq() {
        assert_eq!(event_seq(&json!({"seq": 5})), 5);
        assert_eq!(event_seq(&json!({"seq": 5.7})), 5);
        assert_eq!(event_seq(&json!({"seq": "5"})), 0);
        assert_eq!(event_seq(&json!({})), 0);
        assert_eq!(event_seq(&json!("x")), 0);
        assert_eq!(
            max_seq(&[json!({"seq": 3}), json!({"seq": 9}), json!({})]),
            9
        );
        assert_eq!(max_seq(&[json!({"seq": -4})]), 0);
        assert_eq!(max_seq(&[]), 0);
    }

    #[test]
    fn dedup_resources_by_path_first_seen() {
        let events = vec![
            json!({"seq": 5, "resources": ["sandbox://old.jpg"]}),
            json!({"seq": 9, "resources": ["sandbox://a.jpg"]}),
            json!({"seq": 10, "resources": ["sandbox://a.jpg", "sandbox://b.jpg"]}),
        ];
        let got = dedup_resources(&events, 7);
        let paths: Vec<&str> = got.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, vec!["sandbox://a.jpg", "sandbox://b.jpg"]);
    }
}
