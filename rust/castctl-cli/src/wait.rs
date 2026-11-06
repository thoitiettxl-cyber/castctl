// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `castctl wait` (Go `internal/commands/wait.go`: `cmdWait`,
//! `executeWait`, `runWaitNetwork`, `ensureNodeID`,
//! `historyAdapter`, `waitDial`, `waitApprover`,
//! `toWaitResultJSON`, `printWaitText`/`printWaitTail`,
//! `logAutoApproved` + the structural renderers).
//!
//! The Runner (`castctl-wait`) does the waiting; this
//! module is the CLI seam: flag/env/profile resolution,
//! the production `Dial` (a `SharedConn` lease under the
//! 30 s connect cap) and `HistoryReader` (chat.history
//! with `has_more`), the production approver (fresh lease
//! per approve batch, `egress.approval.decide`, never
//! retried), heartbeat + SIGINT (exit 130), and the exact
//! JSON/text/stderr renderings.
//!
//! `send --wait` is NOT wired here (Target, not Floor):
//! `send` stays stubbed; see the writer report.
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use castctl_approvals::{AutoApprover, BoxError, DescribedApproval};
use castctl_config::config::resolve_active_profile;
use castctl_config::errors::config_error;
use castctl_config::gostr::go_quote;
use castctl_config::jsonvalue::{JsonValue, OrderedObject, encode_ordered_json};
use castctl_config::profile::Profile;
use castctl_gateway::gateway::{Body, RequestOptions};
use castctl_gateway::shared::SharedConn;
use castctl_logging::summarize_err;
use castctl_telegram::Approval as TelegramApproval;
use castctl_telegram::BotError;
use castctl_telegram::wait::{ApprovedRecord, Reply, WaitKind, Widget};
use castctl_transport::TransportError;
use castctl_wait::{
    AutoApproverAdapter, Cancel, Config, DialFn, HistoryReader, RunError, Runner, WaitResult,
    subscriber::shared_subscriber,
};
use serde_json::Value as SerdeValue;

use crate::network::{classify_conn_error, go_type_name, write_json_text};
use crate::parser::Parsed;
use crate::run::{Ctx, FlowErr, GlobalOpts, config_err, msg, msg_empty, resolve_and_load_single};
use crate::runtime::{Runtime, build_runtime};

/// The 30 s connect cap (`wait.go:209-220`: `waitDial`,
/// Python's `_wait_connection connect_timeout=30`).
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// The synthetic-timeout note (`executeWait`'s catch-all,
/// `wait.go:300-373`).
const INTERNAL_FAILURE_NOTE: &str = "wait failed internally; run `castctl wait` again";

/// A plain message error (Go `errors.New`): the nil-id
/// decide guard (`wait.go: waitApprover`'s decide closure).
#[derive(Debug)]
struct MsgError(String);

impl std::fmt::Display for MsgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MsgError {}

/// `Env.lookupEnv` for this module (`Ctx::getenv` is
/// private to `run.rs`; this mirrors it): the injected
/// getter wins, else the process environment (lossy).
fn lookup_env(ctx: &Ctx<'_>, key: &str) -> Option<String> {
    match ctx.getenv {
        Some(getenv) => getenv(key),
        None => std::env::var_os(key).map(|v| v.to_string_lossy().into_owned()),
    }
}

/// `ResolveAutoApprove` (`internal/profile/autoapprove.go:
/// 37-64`): per-call flag > `MUSE_AUTO_APPROVE` > config.
/// Defaults off. An invalid env value is a config error
/// (exit 2) echoing the raw value, Go `%q`.
fn resolve_auto_approve(
    profile: &Profile,
    flag: Option<bool>,
    env: Option<String>,
) -> Result<bool, FlowErr> {
    if let Some(v) = flag {
        return Ok(v);
    }
    if let Some(raw) = env {
        let v = raw.trim().to_lowercase();
        return match v.as_str() {
            "always" | "on" | "1" | "true" | "yes" => Ok(true),
            "off" | "0" | "false" | "no" | "never" | "" => Ok(false),
            _ => Err(config_err(config_error(format!(
                "MUSE_AUTO_APPROVE must be always or off, not {}",
                go_quote(&raw)
            )))),
        };
    }
    Ok(profile.auto_approve.trim().to_lowercase() == "always")
}

/// `ResolveAutoAllowOnce` (`autoapprove.go:66-96`): per-call
/// flag > `MUSE_AUTO_ALLOW_ONCE` > config (a bool, or an
/// on/off word normalised at parse time). Defaults off.
fn resolve_auto_allow_once(
    profile: &Profile,
    flag: Option<bool>,
    env: Option<String>,
) -> Result<bool, FlowErr> {
    if let Some(v) = flag {
        return Ok(v);
    }
    if let Some(raw) = env {
        let v = raw.trim().to_lowercase();
        return match v.as_str() {
            "on" | "1" | "true" | "yes" | "always" => Ok(true),
            "off" | "0" | "false" | "no" | "never" | "" => Ok(false),
            _ => Err(config_err(config_error(format!(
                "MUSE_AUTO_ALLOW_ONCE must be on or off, not {}",
                go_quote(&raw)
            )))),
        };
    }
    Ok(profile.auto_allow_once)
}

/// `ensureNodeID` (`wait.go:107-141`): file >
/// `MUSE_NODE_ID` env > generate (16 hex chars) + persist.
///
/// DEVIATION (M7a): the persist step is NOT implemented.
/// Go writes the generated id back into the profile's
/// single-file entry (`UpdateSingleConfig`); Rust has no
/// single-config update primitive yet, and re-encoding
/// the file from the parsed struct would drop unknown
/// fields and formatting. The generated id is kept in
/// memory only. Unobservable for the live Tier B profile
/// (its node_id is already persisted, so both Go and Rust
/// take the early return); a profile that has never run
/// `wait`/`send` keeps generating a fresh id per
/// invocation until the persist lands. Recorded in
/// PORTING.md §M7a.
fn ensure_node_id(profile: &mut Profile, env: Option<String>) {
    if !profile.node_id.is_empty() {
        return;
    }
    if let Some(v) = env
        && !v.is_empty()
    {
        profile.node_id = v;
        return;
    }
    // `rand::random` panics if the OS RNG fails — the
    // tree's established idiom (`gateway.rs:219`,
    // `framing.rs:179`); Go returns the `rand.Read`
    // error instead (unobservable: the OS RNG does not
    // fail on a live system).
    let b: [u8; 8] = rand::random();
    profile.node_id = b.iter().map(|x| format!("{x:02x}")).collect();
}

/// The production history adapter (`wait.go: historyAdapter`):
/// `chat.history` through the profile's shared connection,
/// scoped to the thread, bounded by the run cancel. Auth
/// failures pass through as `TransportError::Auth` so the
/// Runner ends the wait with exit 2 instead of 124.
struct HistoryAdapter {
    shared: Arc<SharedConn>,
    thread: String,
}

impl HistoryReader for HistoryAdapter {
    fn read_history(
        &self,
        limit: usize,
        cancel: &Cancel,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<SerdeValue>, bool), TransportError>> + Send + '_>>
    {
        let shared = Arc::clone(&self.shared);
        let thread = self.thread.clone();
        let cancel = cancel.clone();
        Box::pin(async move {
            let mut body = serde_json::Map::new();
            body.insert("limit".to_string(), SerdeValue::Number(limit.into()));
            if !thread.is_empty() {
                body.insert("session_id".to_string(), SerdeValue::String(thread));
            }
            let call = shared.call_json(
                "chat.history",
                RequestOptions {
                    body: Body::Json(SerdeValue::Object(body)),
                    ..Default::default()
                },
            );
            let v = tokio::select! {
                res = call => res?,
                () = cancel.notified() => return Err(TransportError::Cancelled),
            };
            let Some(m) = v.as_object() else {
                return Err(TransportError::Validation {
                    message: format!(
                        "gateway: chat.history result is not an object: {}",
                        go_type_name(&v)
                    ),
                });
            };
            let events = m
                .get("chat_events")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let has_more = m.get("has_more").and_then(|v| v.as_bool()).unwrap_or(false);
            Ok((events, has_more))
        })
    }
}

/// The production dial (`wait.go:209-220`): a lease of the
/// profile's shared connection, opened under the 30 s
/// connect cap. Leases share the one warm connection, so
/// the wait follows the turn on the connection that sent
/// it and a dropped connection is replaced by the
/// heartbeat.
///
/// RESOLVED (M7a): the lease is the `SharedConn` (its
/// `SubscribeRaw` retries 3 attempts with a 250 ms pause,
/// Go `internal/conn/shared.go:296-360`), NOT a fresh
/// `Gateway` (single attempt, Go `internal/gateway/
//// calls.go:261-384`). `Muse.Connect` returns a
/// `SharedConn` lease whenever the live gateway is a
/// `Leaser` (`internal/conn/conn.go:576-585`).
fn wait_dial(shared: Arc<SharedConn>) -> DialFn {
    Arc::new(move |cancel: Cancel| {
        let shared = Arc::clone(&shared);
        Box::pin(async move {
            let shared2 = Arc::clone(&shared);
            let live = shared2.live();
            tokio::select! {
                res = live => match res {
                    Ok(_) => Ok(Some(shared_subscriber(shared))),
                    Err(e) => Err(e),
                },
                () = cancel.notified() => Err(TransportError::Cancelled),
                () = tokio::time::sleep(DIAL_TIMEOUT) => Err(TransportError::Timeout {
                    message: "dial timed out".to_string(),
                }),
            }
        })
    })
}

/// The production approver (`wait.go: waitApprover`): one
/// `AutoApprover` for a turn. Its `Decider` opens a fresh
/// lease per approve batch and decides with
/// `egress.approval.decide`, which is never retried (the
/// shared connection only repeats safe reads and pre-send
/// failures).
///
/// The `Decider` is sync (Go's is sync) but the decide RPC
/// is async: it runs through `handle.block_on` on the
/// `spawn_blocking` thread the adapter uses — legal on a
/// multi-thread runtime (the blocking thread holds no
/// runtime context). `connect` warms the connection with
/// `live()` first, mirroring Go's `muse.Connect` dial.
fn wait_approver(
    shared: Arc<SharedConn>,
    handle: tokio::runtime::Handle,
    allow_once: bool,
) -> Arc<AutoApprover> {
    let connect: Box<castctl_approvals::ConnectFn> = Box::new(move || {
        let shared = Arc::clone(&shared);
        let handle = handle.clone();
        // Warm the connection (Go `muse.Connect` dials);
        // a dial/auth failure here fails `Connect`, so
        // the approver records it instead of deciding.
        if let Err(e) = handle.block_on(shared.live()) {
            return Err(Box::new(e) as BoxError);
        }
        let decide_shared = Arc::clone(&shared);
        let decide_handle = handle.clone();
        let decide: Box<castctl_approvals::Decider> =
            Box::new(move |approval: &DescribedApproval, decision: &str| {
                let Some(id) = approval.approval_id.clone() else {
                    return Err(Box::new(MsgError(
                        "approvals: cannot decide an approval without an id".to_string(),
                    )) as BoxError);
                };
                let body = serde_json::json!({ "decision": decision });
                decide_handle
                    .block_on(decide_shared.call_json(
                        "egress.approval.decide",
                        RequestOptions {
                            path_params: vec![("approval_id".to_string(), id)],
                            body: Body::Json(body),
                            ..Default::default()
                        },
                    ))
                    .map(|_| ())
                    .map_err(|e| Box::new(e) as BoxError)
            });
        // The shared connection has no close (dropping
        // the `Arc` is the close); the close fn is a
        // no-op, mirroring Go's lease `gw.Close()` on a
        // shared lease.
        Ok((decide, Box::new(|| {})))
    });
    Arc::new(AutoApprover::new(Some(connect), allow_once))
}

/// `executeWait` (`wait.go:300-373`): one Runner turn on
/// the profile's connection with the heartbeat started. It
/// returns the `WaitResult`, whether auto-approve was
/// enabled (for the `auto_approved` key), and the stderr
/// lines it owns (`logAutoApproved`, or the synthetic-124
/// line). An error is returned only for auth failures and
/// cancellation — any other failure is reported as a
/// timeout (exit 124), mirroring `_run_wait`'s catch-all.
async fn execute_wait(
    rt: &Runtime,
    profile: &Profile,
    thread: &str,
    after_seq: Option<i64>,
    timeout: Duration,
    approve_enabled: bool,
    allow_once: bool,
) -> Result<(WaitResult, bool, String), FlowErr> {
    let mut cfg = Config {
        thread: thread.to_string(),
        node_id: profile.node_id.clone(),
        timeout,
        ..Default::default()
    };
    if let Some(seq) = after_seq {
        cfg.after_seq = seq;
        cfg.has_after_seq = true;
    }
    cfg.dial = Some(wait_dial(Arc::clone(&rt.shared)));
    cfg.history = Some(Arc::new(HistoryAdapter {
        shared: Arc::clone(&rt.shared),
        thread: thread.to_string(),
    }));
    if approve_enabled {
        let handle = tokio::runtime::Handle::current();
        let auto = wait_approver(Arc::clone(&rt.shared), handle, allow_once);
        cfg.approver = Some(Arc::new(AutoApproverAdapter::new(&auto)));
    }
    let mut runner = Runner::new(cfg).map_err(|e| msg(1, e.to_string()))?;
    // SIGINT cancels in-flight network work (Go `main.go`:
    // `signal.NotifyContext`); commands map a cancelled
    // context to exit 130, the shell convention. The
    // watcher task dies with the runtime at shutdown.
    let cancel = Cancel::new();
    let sig_cancel = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            sig_cancel.set();
        }
    });
    rt.shared.start_heartbeat();
    let run_res = runner.run(cancel).await;
    rt.shared.stop_heartbeat().await;
    match run_res {
        Ok(res) => {
            let stderr = log_auto_approved(&res);
            Ok((res, approve_enabled, stderr))
        }
        Err(RunError::Auth(te)) => Err(classify_conn_error(&te)),
        Err(RunError::Cancelled) => Err(msg_empty(130)),
        Err(RunError::ApproverFatal(BotError::Transport(te)))
            if matches!(te, TransportError::Auth { .. }) =>
        {
            Err(classify_conn_error(&te))
        }
        Err(RunError::ApproverFatal(fatal)) => Ok(synthetic_timeout(
            &fatal,
            after_seq.unwrap_or(0),
            approve_enabled,
        )),
        Err(RunError::HistoryRead(te)) => Ok(synthetic_timeout(
            &te,
            after_seq.unwrap_or(0),
            approve_enabled,
        )),
    }
}

/// The synthetic-124 result for an unexpected runner
/// failure: the stderr line plus a timeout `WaitResult`
/// (`executeWait`'s catch-all). Returned as `Ok` — the
/// caller renders it and exits 124 — never as `Err`.
fn synthetic_timeout(
    err: &(dyn std::error::Error + 'static),
    after_seq: i64,
    enabled: bool,
) -> (WaitResult, bool, String) {
    let stderr = format!(
        "castctl: wait: unexpected error ({}); reporting timeout\n",
        summarize_err(Some(err))
    );
    let res = WaitResult {
        kind: WaitKind::Timeout,
        outcome: "timeout".to_string(),
        status: String::new(),
        after_seq,
        final_text: String::new(),
        replies: Vec::new(),
        final_read_failed: false,
        note: INTERNAL_FAILURE_NOTE.to_string(),
        approvals: Vec::new(),
        needs_input_reason: String::new(),
        question: String::new(),
        exit_code: 124,
        node_id: String::new(),
        auto_approved: Vec::new(),
        auto_approve_errors: Vec::new(),
    };
    (res, enabled, stderr)
}

// --- structural stderr rendering (loop 8, Boss ruling) ---

/// `structuralApprovalID` (`wait.go`): 1–64 runes of
/// `[A-Za-z0-9_-]`; anything else renders `[omitted]`,
/// fail-closed. JSON data output carries the full id
/// unchanged.
fn structural_approval_id(id: &str) -> String {
    let mut n = 0;
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

/// `structuralDecision`: one of the four decisions castctl
/// itself can send; anything else renders `[omitted]`.
fn structural_decision(s: &str) -> &str {
    match s {
        "allow_always" | "allow_once" | "allow_session" | "allow_today" => s,
        _ => "[omitted]",
    }
}

/// `structuralKind`: one of the three permission-question
/// kind values observed in the tree's fixtures; anything
/// else renders `[omitted]`.
fn structural_kind(s: &str) -> &str {
    match s {
        "browse" | "network_access" | "shell" => s,
        _ => "[omitted]",
    }
}

/// `structuralScope` always renders `[omitted]`: Scope has
/// no finite enum set.
fn structural_scope() -> &'static str {
    "[omitted]"
}

/// `logAutoApproved` (`wait.go`): one stderr line per
/// approved record and per error, in result order. Every
/// line is structural: no peer free text. Title is
/// `title_length` only (BYTE length); option labels are
/// `option_count` only.
fn log_auto_approved(res: &WaitResult) -> String {
    let mut out = String::new();
    for rec in &res.auto_approved {
        out.push_str(&format!(
            "auto-approved {} ({}): title_length={} [{} {}]\n",
            structural_approval_id(&rec.approval_id),
            structural_decision(&rec.decision),
            rec.title.len(),
            structural_kind(&rec.kind),
            structural_scope()
        ));
    }
    for e in &res.auto_approve_errors {
        let underlying = match e.option_count {
            Some(n) => format!("no forever option option_count={n}"),
            None => e.summary.clone(),
        };
        if e.decision.is_empty() {
            out.push_str(&format!(
                "auto-approve SKIPPED {}: {} [{} {}]\n",
                structural_approval_id(&e.approval_id),
                underlying,
                structural_kind(&e.kind),
                structural_scope()
            ));
        } else {
            out.push_str(&format!(
                "auto-approve FAILED {}: {}\n",
                structural_approval_id(&e.approval_id),
                underlying
            ));
        }
    }
    out
}

// --- JSON shapes (ordered structs, never maps) ---

/// An ordered-object builder (field order = insertion
/// order, Go struct order).
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

/// A `serde_json::Value` as an ordered `JsonValue`
/// (number literals kept verbatim via
/// `arbitrary_precision`; object keys sort, exactly as
/// Go's `json.Marshal` on a `map[string]any` sorts them).
fn serde_to_ordered(v: &SerdeValue) -> JsonValue {
    match v {
        SerdeValue::Null => JsonValue::Null,
        SerdeValue::Bool(b) => JsonValue::Bool(*b),
        SerdeValue::Number(n) => JsonValue::Number(n.to_string()),
        SerdeValue::String(s) => JsonValue::Str(s.clone()),
        SerdeValue::Array(items) => JsonValue::Array(items.iter().map(serde_to_ordered).collect()),
        SerdeValue::Object(map) => {
            let mut o = OrderedObject::new();
            for (k, val) in map {
                o.set(k.clone(), serde_to_ordered(val));
            }
            JsonValue::Object(o)
        }
    }
}

/// A `float64` as Go's `encoding/json` renders it:
/// integral values with `|f| < 1e21` render as integers
/// (the only shape that occurs for `expires_at_ms`);
/// anything else renders with Rust's shortest decimal.
/// The exponent shapes for `|f| >= 1e21` or tiny
/// fractions differ from Go's `%g` — unobservable for
/// millisecond timestamps, recorded in PORTING.md §M7a.
fn go_float_literal(f: f64) -> String {
    if f.fract() == 0.0 && f.abs() < 1e21 {
        format!("{}", f as i64)
    } else {
        format!("{f}")
    }
}

/// `widgetJSON` (`wait.go`): `widget_id` (raw), `kind`,
/// `text` (null when absent), `options` (raw).
fn widget_json(w: &Widget) -> JsonValue {
    obj(&[
        ("widget_id", serde_to_ordered(&w.id)),
        ("kind", JsonValue::Str(w.kind.clone())),
        (
            "text",
            w.text
                .as_deref()
                .map_or(JsonValue::Null, |t| JsonValue::Str(t.to_string())),
        ),
        ("options", serde_to_ordered(&w.options)),
    ])
}

/// `replyJSON` (`wait.go`): `seq`, `message_id` (null when
/// `""`), `text`, `widgets?`, `media?`.
fn reply_json(r: &Reply) -> JsonValue {
    let mut pairs: Vec<(&str, JsonValue)> = vec![
        ("seq", JsonValue::Number(r.seq.to_string())),
        ("message_id", str_or_null(&r.message_id)),
        ("text", JsonValue::Str(r.text.clone())),
    ];
    if !r.widgets.is_empty() {
        pairs.push((
            "widgets",
            JsonValue::Array(r.widgets.iter().map(widget_json).collect()),
        ));
    }
    if r.media {
        pairs.push(("media", JsonValue::Bool(true)));
    }
    obj(&pairs)
}

/// `approvalJSON` (`wait.go`): `approval_id`, `title`,
/// `question`, `kind`, `scope`, `why` (null when `""`),
/// `expires_at_ms` (null when absent), `options` (null
/// when absent).
fn approval_json(a: &TelegramApproval) -> JsonValue {
    obj(&[
        ("approval_id", str_or_null(&a.id)),
        ("title", str_or_null(&a.title)),
        ("question", str_or_null(&a.question)),
        ("kind", str_or_null(&a.kind)),
        ("scope", str_or_null(&a.scope)),
        ("why", str_or_null(&a.why)),
        (
            "expires_at_ms",
            if a.expires_at_ms == 0 {
                JsonValue::Null
            } else {
                JsonValue::Number(go_float_literal(a.expires_at_ms as f64))
            },
        ),
        (
            "options",
            match &a.options {
                None => JsonValue::Null,
                Some(opts) => {
                    JsonValue::Array(opts.iter().map(|s| JsonValue::Str(s.clone())).collect())
                }
            },
        ),
    ])
}

/// `approvedJSON` (`wait.go`): `approval_id`, `title`,
/// `kind`, `scope`, `decision` (null when `""`).
fn approved_json(r: &ApprovedRecord) -> JsonValue {
    obj(&[
        ("approval_id", str_or_null(&r.approval_id)),
        ("title", str_or_null(&r.title)),
        ("kind", str_or_null(&r.kind)),
        ("scope", str_or_null(&r.scope)),
        ("decision", str_or_null(&r.decision)),
    ])
}

/// `approveErrorJSON` (`wait.go`): the `approvedJSON`
/// fields plus `error` (the allowlist summary, always
/// present).
fn approve_error_json(e: &castctl_telegram::wait::ApproveError) -> JsonValue {
    obj(&[
        ("approval_id", str_or_null(&e.approval_id)),
        ("title", str_or_null(&e.title)),
        ("kind", str_or_null(&e.kind)),
        ("scope", str_or_null(&e.scope)),
        ("decision", str_or_null(&e.decision)),
        ("error", JsonValue::Str(e.summary.clone())),
    ])
}

/// `toWaitResultJSON` (`wait.go`): field order outcome,
/// status, after_seq, final_text, replies,
/// final_read_failed?, note?, approvals?,
/// auto_approved?, auto_approve_errors?, widgets?,
/// needs_input_reason?, question?.
///
/// Public for the Tier A parity driver
/// (`examples/wait_driver.rs`), which renders the Runner
/// result with the production code under test instead of a
/// copy; the driver is the only external caller.
pub fn to_wait_result_json(res: &WaitResult, auto_approve_enabled: bool) -> JsonValue {
    let mut pairs: Vec<(&str, JsonValue)> = vec![
        ("outcome", JsonValue::Str(res.outcome.clone())),
        ("status", str_or_null(&res.status)),
        ("after_seq", JsonValue::Number(res.after_seq.to_string())),
        (
            "final_text",
            if res.replies.is_empty() {
                JsonValue::Null
            } else {
                JsonValue::Str(res.final_text.clone())
            },
        ),
        (
            "replies",
            JsonValue::Array(res.replies.iter().map(reply_json).collect()),
        ),
    ];
    if res.final_read_failed {
        pairs.push(("final_read_failed", JsonValue::Bool(true)));
    }
    if !res.note.is_empty() {
        pairs.push(("note", JsonValue::Str(res.note.clone())));
    }
    if res.kind == WaitKind::Approval {
        pairs.push((
            "approvals",
            JsonValue::Array(res.approvals.iter().map(approval_json).collect()),
        ));
    }
    if auto_approve_enabled {
        pairs.push((
            "auto_approved",
            JsonValue::Array(res.auto_approved.iter().map(approved_json).collect()),
        ));
    }
    if !res.auto_approve_errors.is_empty() {
        pairs.push((
            "auto_approve_errors",
            JsonValue::Array(
                res.auto_approve_errors
                    .iter()
                    .map(approve_error_json)
                    .collect(),
            ),
        ));
    }
    if let Some(last) = res.replies.last()
        && !last.widgets.is_empty()
    {
        pairs.push((
            "widgets",
            JsonValue::Array(last.widgets.iter().map(widget_json).collect()),
        ));
    }
    if res.outcome == "needs_input" {
        pairs.push((
            "needs_input_reason",
            JsonValue::Str(res.needs_input_reason.clone()),
        ));
        pairs.push(("question", JsonValue::Str(res.question.clone())));
    }
    obj(&pairs)
}

// --- text display ---

/// Go `fmt.Sprint` for one JSON value, as `widgetIDStr` /
/// `widgetOptionsStr` use it: numbers keep their literal,
/// strings render bare, bools `true`/`false`, null is
/// `"<nil>"` inside option lists and `"None"` as a widget
/// id (the id case is handled by the caller). Nested
/// arrays/objects render as compact JSON — Go's `%v`
/// renders Go syntax (`[a b]`, `map[k:v]`), which is
/// nondeterministic for maps; widget ids/options are
/// scalars or flat lists in practice. Recorded in
/// PORTING.md §M7a.
fn go_sprint(v: &SerdeValue) -> String {
    match v {
        SerdeValue::Null => "<nil>".to_string(),
        SerdeValue::Bool(b) => b.to_string(),
        SerdeValue::Number(n) => n.to_string(),
        SerdeValue::String(s) => s.clone(),
        SerdeValue::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(|i| serde_json::to_string(i).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(",")
        ),
        SerdeValue::Object(_) => serde_json::to_string(v).unwrap_or_default(),
    }
}

/// `widgetIDStr` (`wait.go`): nil → `"None"`, else
/// `fmt.Sprint(id)`.
fn widget_id_str(id: &SerdeValue) -> String {
    if id.is_null() {
        "None".to_string()
    } else {
        go_sprint(id)
    }
}

/// `widgetOptionsStr` (`wait.go`): a list joins its
/// elements with `" / "`; a non-list non-nil value renders
/// as itself; nil renders `""`.
fn widget_options_str(options: &SerdeValue) -> String {
    match options {
        SerdeValue::Null => String::new(),
        SerdeValue::Array(items) => items.iter().map(go_sprint).collect::<Vec<_>>().join(" / "),
        other => go_sprint(other),
    }
}

/// `printWaitText` + `printWaitTail` (`wait.go`): replies
/// and the tail to stdout, the note and the summary line
/// to stderr. Returns `(stdout, stderr)`.
///
/// Public for the Tier A parity driver
/// (`examples/wait_driver.rs`); see `to_wait_result_json`.
pub fn print_wait_text(res: &WaitResult) -> (String, String) {
    let mut stdout = String::new();
    let mut stderr = String::new();
    for r in &res.replies {
        stdout.push_str(&format!("[{}] {}\n", r.seq, r.text));
        for wd in &r.widgets {
            let mut line = format!(
                "  ? widget {}: {}",
                widget_id_str(&wd.id),
                wd.text.as_deref().unwrap_or("")
            );
            let opts = widget_options_str(&wd.options);
            if !opts.is_empty() {
                line.push_str(&format!(" [{opts}]"));
            }
            stdout.push_str(&line);
            stdout.push('\n');
        }
    }
    if res.outcome == "needs_input" && !res.question.is_empty() {
        stdout.push_str(&format!(
            "NEEDS INPUT ({}): {}\n",
            res.needs_input_reason, res.question
        ));
    }
    for a in &res.approvals {
        stdout.push_str(&format!(
            "NEEDS APPROVAL {}: {} - {}\n",
            a.id, a.title, a.question
        ));
        if !a.why.is_empty() {
            stdout.push_str(&format!("  why: {}\n", a.why));
        }
    }
    if !res.note.is_empty() {
        stderr.push_str(&format!("note: {}\n", res.note));
    }
    stderr.push_str(&format!("-- {} (status={})\n", res.outcome, res.status));
    (stdout, stderr)
}

// --- command ---

/// `cmdWait` (`wait.go`): parse (done by `cmd_plain`),
/// resolve config + profile, ensure the node id, build
/// the runtime, run one wait, render, exit with the
/// result's code.
pub(crate) fn run_wait_command(
    ctx: &mut Ctx<'_>,
    g: &GlobalOpts,
    p: &Parsed,
) -> Result<(), FlowErr> {
    let thread = p.str("thread");
    let after_seq = if p.int_is_set("after-seq") {
        Some(p.int_val("after-seq"))
    } else {
        None
    };
    let timeout = Duration::from_secs(p.int_val("timeout").max(0) as u64);
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
    let (res, enabled, mut stderr) = tokio_rt.block_on(async move {
        let runtime = build_runtime(&loc, single.as_ref(), profile_flag, getenv)?;
        execute_wait(
            &runtime,
            &profile,
            &thread,
            after_seq,
            timeout,
            approve_enabled,
            allow_once,
        )
        .await
    })?;
    if p.bool("json") {
        let v = to_wait_result_json(&res, enabled);
        let compact = encode_ordered_json(&v)
            .map_err(|e| msg(1, format!("failed to serialize wait result: {e}")))?;
        ctx.out.stdout.push_str(&write_json_text(&compact));
    } else {
        let (stdout, tail_stderr) = print_wait_text(&res);
        ctx.out.stdout.push_str(&stdout);
        stderr.push_str(&tail_stderr);
    }
    ctx.out.stderr.push_str(&stderr);
    if res.exit_code != 0 {
        return Err(msg_empty(res.exit_code));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use castctl_telegram::wait::{ApproveError, Widget};

    fn approval(id: &str) -> TelegramApproval {
        TelegramApproval {
            id: id.to_string(),
            title: format!("title {id}"),
            question: "Allow?".to_string(),
            kind: "shell".to_string(),
            scope: "example.com".to_string(),
            why: "needed".to_string(),
            expires_at_ms: 1790000000000,
            options: Some(vec!["allow_always".to_string(), "allow_once".to_string()]),
        }
    }

    fn done_result() -> WaitResult {
        WaitResult {
            kind: WaitKind::Done,
            outcome: "done".to_string(),
            status: "completed".to_string(),
            after_seq: 42,
            final_text: "hello".to_string(),
            replies: vec![Reply {
                seq: 42,
                message_id: "m1".to_string(),
                text: "hello".to_string(),
                widgets: vec![],
                media: false,
                agent_id: String::new(),
                root_agent_id: String::new(),
            }],
            final_read_failed: false,
            note: String::new(),
            approvals: Vec::new(),
            needs_input_reason: String::new(),
            question: String::new(),
            exit_code: 0,
            node_id: "abcdef0123456789".to_string(),
            auto_approved: Vec::new(),
            auto_approve_errors: Vec::new(),
        }
    }

    #[test]
    fn wait_json_done_shape() {
        let v = to_wait_result_json(&done_result(), false);
        let compact = encode_ordered_json(&v).expect("encode");
        assert_eq!(
            compact,
            r#"{"outcome":"done","status":"completed","after_seq":42,"final_text":"hello","replies":[{"seq":42,"message_id":"m1","text":"hello"}]}"#
        );
    }

    #[test]
    fn wait_json_empty_result_shape() {
        let mut res = done_result();
        res.outcome = "timeout".to_string();
        res.status = String::new();
        res.after_seq = 0;
        res.final_text = String::new();
        res.replies = Vec::new();
        res.exit_code = 124;
        res.note = "turn-end boundary unknown: history could not be read, so no replies are reported; run `castctl wait` again".to_string();
        let v = to_wait_result_json(&res, false);
        let compact = encode_ordered_json(&v).expect("encode");
        assert_eq!(
            compact,
            r#"{"outcome":"timeout","status":null,"after_seq":0,"final_text":null,"replies":[],"note":"turn-end boundary unknown: history could not be read, so no replies are reported; run `castctl wait` again"}"#
        );
    }

    #[test]
    fn wait_json_approval_and_auto_approved() {
        let mut res = done_result();
        res.kind = WaitKind::Approval;
        res.outcome = "needs_approval".to_string();
        res.status = "waiting".to_string();
        res.approvals = vec![approval("A1")];
        res.exit_code = 4;
        res.auto_approved = vec![ApprovedRecord {
            approval_id: "B2".to_string(),
            title: "t".to_string(),
            kind: "shell".to_string(),
            scope: String::new(),
            decision: "allow_once".to_string(),
        }];
        res.auto_approve_errors = vec![ApproveError {
            approval_id: "C3".to_string(),
            summary: "no forever option (offers [allow_once])".to_string(),
            title: "t3".to_string(),
            kind: "browse".to_string(),
            scope: "x.com".to_string(),
            decision: String::new(),
            option_count: Some(1),
        }];
        let v = to_wait_result_json(&res, true);
        let compact = encode_ordered_json(&v).expect("encode");
        assert_eq!(
            compact,
            r#"{"outcome":"needs_approval","status":"waiting","after_seq":42,"final_text":"hello","replies":[{"seq":42,"message_id":"m1","text":"hello"}],"approvals":[{"approval_id":"A1","title":"title A1","question":"Allow?","kind":"shell","scope":"example.com","why":"needed","expires_at_ms":1790000000000,"options":["allow_always","allow_once"]}],"auto_approved":[{"approval_id":"B2","title":"t","kind":"shell","scope":null,"decision":"allow_once"}],"auto_approve_errors":[{"approval_id":"C3","title":"t3","kind":"browse","scope":"x.com","decision":null,"error":"no forever option (offers [allow_once])"}]}"#
        );
    }

    #[test]
    fn wait_json_needs_input_and_widgets() {
        let mut res = done_result();
        res.outcome = "needs_input".to_string();
        res.needs_input_reason = "question".to_string();
        res.question = "Shall I proceed?".to_string();
        res.exit_code = 4;
        res.replies[0].widgets = vec![Widget {
            id: serde_json::json!(7),
            kind: "confirm".to_string(),
            text: Some("Proceed?".to_string()),
            options: serde_json::json!(["yes", "no"]),
        }];
        let v = to_wait_result_json(&res, false);
        let compact = encode_ordered_json(&v).expect("encode");
        assert_eq!(
            compact,
            r#"{"outcome":"needs_input","status":"completed","after_seq":42,"final_text":"hello","replies":[{"seq":42,"message_id":"m1","text":"hello","widgets":[{"widget_id":7,"kind":"confirm","text":"Proceed?","options":["yes","no"]}]}],"widgets":[{"widget_id":7,"kind":"confirm","text":"Proceed?","options":["yes","no"]}],"needs_input_reason":"question","question":"Shall I proceed?"}"#
        );
    }

    #[test]
    fn wait_json_null_id_and_text_and_options() {
        let mut res = done_result();
        res.replies[0].message_id = String::new();
        res.replies[0].widgets = vec![Widget {
            id: SerdeValue::Null,
            kind: "confirm".to_string(),
            text: None,
            options: SerdeValue::Null,
        }];
        let v = to_wait_result_json(&res, false);
        let compact = encode_ordered_json(&v).expect("encode");
        assert_eq!(
            compact,
            r#"{"outcome":"done","status":"completed","after_seq":42,"final_text":"hello","replies":[{"seq":42,"message_id":null,"text":"hello","widgets":[{"widget_id":null,"kind":"confirm","text":null,"options":null}]}],"widgets":[{"widget_id":null,"kind":"confirm","text":null,"options":null}]}"#
        );
    }

    #[test]
    fn print_wait_text_shape() {
        let mut res = done_result();
        res.replies[0].widgets = vec![Widget {
            id: serde_json::json!(7),
            kind: "confirm".to_string(),
            text: Some("Proceed?".to_string()),
            options: serde_json::json!(["yes", "no"]),
        }];
        res.note = "some note".to_string();
        let (stdout, stderr) = print_wait_text(&res);
        assert_eq!(stdout, "[42] hello\n  ? widget 7: Proceed? [yes / no]\n");
        assert_eq!(stderr, "note: some note\n-- done (status=completed)\n");
    }

    #[test]
    fn print_wait_text_needs_input_and_approval() {
        let mut res = done_result();
        res.outcome = "needs_input".to_string();
        res.needs_input_reason = "question".to_string();
        res.question = "Shall I?".to_string();
        res.exit_code = 4;
        res.approvals = vec![approval("A1")];
        let (stdout, stderr) = print_wait_text(&res);
        assert_eq!(
            stdout,
            "[42] hello\nNEEDS INPUT (question): Shall I?\nNEEDS APPROVAL A1: title A1 - Allow?\n  why: needed\n"
        );
        assert_eq!(stderr, "-- needs_input (status=completed)\n");
    }

    #[test]
    fn structural_gates() {
        assert_eq!(structural_approval_id("A1"), "A1");
        assert_eq!(structural_approval_id(""), "[omitted]");
        assert_eq!(structural_approval_id("a b"), "[omitted]");
        assert_eq!(structural_approval_id("a".repeat(65).as_str()), "[omitted]");
        assert_eq!(
            structural_approval_id("a".repeat(64).as_str()),
            "a".repeat(64)
        );
        assert_eq!(structural_decision("allow_once"), "allow_once");
        assert_eq!(structural_decision("deny"), "[omitted]");
        assert_eq!(structural_kind("shell"), "shell");
        assert_eq!(structural_kind("exec"), "[omitted]");
        assert_eq!(structural_scope(), "[omitted]");
    }

    #[test]
    fn log_auto_approved_lines() {
        let mut res = done_result();
        res.auto_approved = vec![ApprovedRecord {
            approval_id: "A1".to_string(),
            title: "título".to_string(),
            kind: "shell".to_string(),
            scope: "example.com".to_string(),
            decision: "allow_always".to_string(),
        }];
        res.auto_approve_errors = vec![
            ApproveError {
                approval_id: "B2".to_string(),
                summary: "no forever option (offers [allow_once])".to_string(),
                title: String::new(),
                kind: "browse".to_string(),
                scope: "x.com".to_string(),
                decision: String::new(),
                option_count: Some(1),
            },
            ApproveError {
                approval_id: "bad id!".to_string(),
                summary: "conn: gateway status=502 body_length=0".to_string(),
                title: String::new(),
                kind: "shell".to_string(),
                scope: String::new(),
                decision: "allow_once".to_string(),
                option_count: None,
            },
        ];
        assert_eq!(
            log_auto_approved(&res),
            "auto-approved A1 (allow_always): title_length=7 [shell [omitted]]\n\
             auto-approve SKIPPED B2: no forever option option_count=1 [browse [omitted]]\n\
             auto-approve FAILED [omitted]: conn: gateway status=502 body_length=0\n"
        );
    }

    #[test]
    fn go_float_literal_cases() {
        assert_eq!(go_float_literal(1790000000000.0), "1790000000000");
        assert_eq!(go_float_literal(0.0), "0");
        assert_eq!(go_float_literal(1.5), "1.5");
    }

    #[test]
    fn widget_id_and_options_rendering() {
        assert_eq!(widget_id_str(&SerdeValue::Null), "None");
        assert_eq!(widget_id_str(&serde_json::json!(7)), "7");
        assert_eq!(widget_id_str(&serde_json::json!("abc")), "abc");
        assert_eq!(widget_id_str(&serde_json::json!(true)), "true");
        assert_eq!(widget_options_str(&SerdeValue::Null), "");
        assert_eq!(
            widget_options_str(&serde_json::json!(["yes", "no"])),
            "yes / no"
        );
        assert_eq!(
            widget_options_str(&serde_json::json!([1, true, "x"])),
            "1 / true / x"
        );
        assert_eq!(widget_options_str(&serde_json::json!("only")), "only");
    }

    fn test_profile() -> Profile {
        Profile {
            auto_approve: "off".to_string(),
            auto_allow_once: false,
            ..Default::default()
        }
    }

    #[test]
    fn resolve_toggles_precedence() {
        let p = test_profile();
        // Flag wins over env and config.
        assert!(resolve_auto_approve(&p, Some(true), Some("off".to_string())).unwrap());
        assert!(!resolve_auto_approve(&p, Some(false), Some("always".to_string())).unwrap());
        // Env wins over config.
        assert!(resolve_auto_approve(&p, None, Some("always".to_string())).unwrap());
        assert!(!resolve_auto_approve(&p, None, Some("off".to_string())).unwrap());
        assert!(resolve_auto_approve(&p, None, Some("ON".to_string())).unwrap());
        assert!(!resolve_auto_approve(&p, None, Some("  ".to_string())).unwrap());
        // Config fallback.
        let mut p2 = test_profile();
        p2.auto_approve = "always".to_string();
        assert!(resolve_auto_approve(&p2, None, None).unwrap());
        // Invalid env is a config error (exit 2) echoing the raw value.
        let err = resolve_auto_approve(&p, None, Some("maybe".to_string())).unwrap_err();
        assert_eq!(
            format!("{err:?}"),
            "Msg { code: 2, message: Some(\"profile: MUSE_AUTO_APPROVE must be always or off, not \\\"maybe\\\"\") }"
        );
        // Allow-once: same shape, different words.
        assert!(resolve_auto_allow_once(&p, None, Some("always".to_string())).unwrap());
        let err = resolve_auto_allow_once(&p, None, Some("maybe".to_string())).unwrap_err();
        assert_eq!(
            format!("{err:?}"),
            "Msg { code: 2, message: Some(\"profile: MUSE_AUTO_ALLOW_ONCE must be on or off, not \\\"maybe\\\"\") }"
        );
    }

    #[test]
    fn ensure_node_id_cases() {
        // Present in file: untouched.
        let mut p = test_profile();
        p.node_id = "file-id".to_string();
        ensure_node_id(&mut p, Some("env-id".to_string()));
        assert_eq!(p.node_id, "file-id");
        // Env wins over generate.
        let mut p = test_profile();
        ensure_node_id(&mut p, Some("env-id".to_string()));
        assert_eq!(p.node_id, "env-id");
        // Empty env falls through to generate: 16 lowercase hex chars.
        let mut p = test_profile();
        ensure_node_id(&mut p, Some(String::new()));
        assert_eq!(p.node_id.len(), 16);
        assert!(p.node_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(p.node_id.to_lowercase(), p.node_id);
        // No env at all: also generates.
        let mut p = test_profile();
        ensure_node_id(&mut p, None);
        assert_eq!(p.node_id.len(), 16);
    }
}
