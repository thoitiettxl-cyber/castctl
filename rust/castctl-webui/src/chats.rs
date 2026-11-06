// SPDX-License-Identifier: GPL-3.0-only
// Chats/sessions over the profile's gateway connection,
// exposed read + send through /api/v1. Port of Go
// internal/webui/chats.go.
//
// The shapes reuse the CLI's: sessions.list rows, chat
// history events, deliverSend + executeWait for send.
// This package never imports the command layer: the
// command layer injects the five seams below, each
// building and closing its own Runtime per call. A send
// job therefore pays one runtime build; reads pay one
// each. No Runtime is held across requests.
//
// Send is async by design: a turn can run past the 30 s
// API timeout, so POST creates a job and GET polls it.
// One send runs at a time per profile: a second POST
// while one is in flight gets a fixed 409. Jobs live in
// memory only, bounded and TTL'd, and are never logged —
// job results hold chat text, which is sensitive display,
// never persisted to disk, never put in browser storage
// by the frontend, and never echoed in an error message.
//
// Chat bodies are never redacted with SafeString on read:
// the authenticated operator reads their own chats
// verbatim, as the CLI prints them. The control is
// structural instead: no chat text is ever logged, no
// chat text enters an error envelope (errors carry fixed
// messages only), and job state is memory-only.

use crate::error::{ApiError, err_not_found, err_unavailable, err_upstream};
use castctl_config::jsonvalue::{JsonValue, OrderedObject};
use chrono::{DateTime, Utc};
use rand::Rng as _;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

/// `chatJobTimeout` bounds one send job end to end: the
/// 30 s delivery-ack budget plus the 90 s default wait
/// budget, with margin for the runtime build.
pub const CHAT_JOB_TIMEOUT_SECS: u64 = 150;
/// `chatJobTTL` bounds how long a finished job stays
/// pollable.
pub const CHAT_JOB_TTL_SECS: i64 = 3600;
/// `chatJobMax` is the job-store cap: the oldest finished
/// jobs are evicted past it.
pub const CHAT_JOB_MAX: usize = 32;

/// Format a timestamp as Go's `time.Time` JSON
/// (RFC3339Nano): fractional seconds with trailing zeros
/// trimmed, `Z` for UTC.
pub fn rfc3339_nano(dt: DateTime<Utc>) -> String {
    let base = dt.format("%Y-%m-%dT%H:%M:%S").to_string();
    let nanos = dt.timestamp_subsec_nanos();
    if nanos == 0 {
        format!("{}Z", base)
    } else {
        let frac = format!("{:09}", nanos);
        format!("{}.{}Z", base, frac.trim_end_matches('0'))
    }
}

/// `ChatSession` is one sessions.list row, as the CLI's
/// `threads` shapes it. SessionID is None when the server
/// sent no id.
#[derive(Debug, Clone)]
pub struct ChatSession {
    pub session_id: Option<String>,
    pub title: Option<String>,
    pub thread: Option<bool>,
    pub pinned: Option<bool>,
    pub archived: Option<bool>,
    pub updated: String,
}

impl ChatSession {
    pub fn to_json(&self) -> JsonValue {
        let mut obj = OrderedObject::new();
        obj.set("session_id", opt_str(&self.session_id));
        obj.set("title", opt_str(&self.title));
        obj.set("thread", opt_bool(&self.thread));
        obj.set("pinned", opt_bool(&self.pinned));
        obj.set("archived", opt_bool(&self.archived));
        obj.set("updated", JsonValue::Str(self.updated.clone()));
        JsonValue::Object(obj)
    }
}

/// `ChatEvent` is one chat.history event (FmtEvent): text
/// only, no payload, no resources.
#[derive(Debug, Clone)]
pub struct ChatEvent {
    pub seq: Option<i64>,
    pub role: Option<String>,
    pub message_id: Option<String>,
    pub text: String,
}

impl ChatEvent {
    pub fn to_json(&self) -> JsonValue {
        let mut obj = OrderedObject::new();
        obj.set("seq", opt_num(&self.seq));
        obj.set("role", opt_str(&self.role));
        obj.set("message_id", opt_str(&self.message_id));
        obj.set("text", JsonValue::Str(self.text.clone()));
        JsonValue::Object(obj)
    }
}

/// `ChatReply` is one assistant reply in a finished send
/// job.
#[derive(Debug, Clone)]
pub struct ChatReply {
    pub seq: i64,
    pub text: String,
    pub message_id: Option<String>,
}

impl ChatReply {
    pub fn to_json(&self) -> JsonValue {
        let mut obj = OrderedObject::new();
        obj.set("seq", JsonValue::Number(self.seq.to_string()));
        obj.set("text", JsonValue::Str(self.text.clone()));
        obj.set("message_id", opt_str(&self.message_id));
        JsonValue::Object(obj)
    }
}

/// `ChatSendResult` is a finished send job's turn result:
/// the wait outcome vocabulary (done, needs_input,
/// needs_approval, failed, timeout, undelivered), the
/// final text, and the replies. Approvals are counted,
/// never described.
#[derive(Debug, Clone)]
pub struct ChatSendResult {
    pub outcome: String,
    pub status: Option<String>,
    pub after_seq: i64,
    pub final_text: Option<String>,
    pub replies: Vec<ChatReply>,
    pub note: Option<String>,
    pub approvals_count: Option<i64>,
    pub needs_input_reason: Option<String>,
    pub question: Option<String>,
}

impl ChatSendResult {
    pub fn to_json(&self) -> JsonValue {
        let mut obj = OrderedObject::new();
        obj.set("outcome", JsonValue::Str(self.outcome.clone()));
        if let Some(s) = &self.status {
            obj.set("status", JsonValue::Str(s.clone()));
        }
        obj.set("after_seq", JsonValue::Number(self.after_seq.to_string()));
        if let Some(t) = &self.final_text {
            obj.set("final_text", JsonValue::Str(t.clone()));
        }
        obj.set(
            "replies",
            JsonValue::Array(self.replies.iter().map(|r| r.to_json()).collect()),
        );
        if let Some(n) = &self.note {
            obj.set("note", JsonValue::Str(n.clone()));
        }
        if let Some(c) = self.approvals_count {
            obj.set("approvals_count", JsonValue::Number(c.to_string()));
        }
        if let Some(r) = &self.needs_input_reason {
            obj.set("needs_input_reason", JsonValue::Str(r.clone()));
        }
        if let Some(q) = &self.question {
            obj.set("question", JsonValue::Str(q.clone()));
        }
        JsonValue::Object(obj)
    }
}

fn opt_str(v: &Option<String>) -> JsonValue {
    match v {
        Some(s) => JsonValue::Str(s.clone()),
        None => JsonValue::Null,
    }
}

fn opt_bool(v: &Option<bool>) -> JsonValue {
    match v {
        Some(b) => JsonValue::Bool(*b),
        None => JsonValue::Null,
    }
}

fn opt_num(v: &Option<i64>) -> JsonValue {
    match v {
        Some(n) => JsonValue::Number(n.to_string()),
        None => JsonValue::Null,
    }
}

/// A chat-seam failure. The error carries no payload by
/// design: seam errors come from the gateway transport,
/// whose messages could carry server-supplied text, and
/// chat bodies must never reach an error envelope — the
/// handler maps every seam failure to the fixed 502
/// `upstream_error` / `upstream error`.
#[derive(Debug, Clone, Copy)]
pub struct ChatSeamError;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

type ListSessionsFn =
    Arc<dyn Fn(String, bool) -> BoxFuture<Result<Vec<ChatSession>, ChatSeamError>> + Send + Sync>;
type GetHistoryFn = Arc<
    dyn Fn(String, String, i64) -> BoxFuture<Result<Vec<ChatEvent>, ChatSeamError>> + Send + Sync,
>;
type StartSessionFn =
    Arc<dyn Fn(String, String) -> BoxFuture<Result<String, ChatSeamError>> + Send + Sync>;
type SessionOpFn = Arc<
    dyn Fn(String, String, String, String) -> BoxFuture<Result<(), ChatSeamError>> + Send + Sync,
>;
type SendChatFn = Arc<
    dyn Fn(String, String, String) -> BoxFuture<Result<ChatSendResult, ChatSeamError>>
        + Send
        + Sync,
>;

/// `ChatDeps` are the injected chat seams, mirroring Go's
/// struct of func fields. Each builds and closes its own
/// Runtime per call and returns transport errors only:
/// implementations must never return chat text inside an
/// error. `None` (no deps wired) means chats are
/// unavailable: the handlers report it explicitly instead
/// of serving fake data.
pub struct ChatDeps {
    /// ListSessions returns the profile's sessions.list rows.
    pub list_sessions: ListSessionsFn,
    /// GetHistory returns one session's chat.history events,
    /// newest-first as the gateway returns them, capped at
    /// limit events.
    pub get_history: GetHistoryFn,
    /// StartSession starts a new side chat and returns the
    /// server-assigned session id.
    pub start_session: StartSessionFn,
    /// SessionOp runs one session operation: rename, pin,
    /// unpin, archive, unarchive, or delete. Title is used
    /// only for rename.
    pub session_op: SessionOpFn,
    /// SendChat sends text and waits for the turn, bounded
    /// by the job timeout. It resolves the profile's
    /// auto_approve/auto_allow_once toggles as-is.
    pub send_chat: SendChatFn,
}

// --- job store --------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatJobStatus {
    Running,
    Done,
    Failed,
}

impl ChatJobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChatJobStatus::Running => "running",
            ChatJobStatus::Done => "done",
            ChatJobStatus::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChatJob {
    pub id: String,
    pub profile: String,
    pub session_id: String,
    pub status: ChatJobStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub result: Option<ChatSendResult>,
    pub err: String,
}

impl ChatJob {
    /// `chatJobView`: the poll shape — the job plus its
    /// result when finished. Chat text appears only in
    /// Result, only to the authenticated caller that
    /// created the job.
    pub fn view(&self) -> JsonValue {
        let mut obj = OrderedObject::new();
        obj.set("id", JsonValue::Str(self.id.clone()));
        obj.set("profile", JsonValue::Str(self.profile.clone()));
        obj.set("session_id", JsonValue::Str(self.session_id.clone()));
        obj.set("status", JsonValue::Str(self.status.as_str().to_string()));
        obj.set("created_at", JsonValue::Str(rfc3339_nano(self.created_at)));
        obj.set("updated_at", JsonValue::Str(rfc3339_nano(self.updated_at)));
        if self.status == ChatJobStatus::Done
            && let Some(r) = &self.result
        {
            obj.set("result", r.to_json());
        }
        if self.status == ChatJobStatus::Failed {
            obj.set("error", JsonValue::Str(self.err.clone()));
        }
        JsonValue::Object(obj)
    }
}

struct JobStoreInner {
    jobs: HashMap<String, ChatJob>,
    /// Creation order (oldest first), for eviction.
    order: Vec<String>,
}

/// `chatJobStore` is the bounded in-memory job store. Jobs
/// are never persisted and never logged. All methods are
/// safe for concurrent use.
pub struct ChatJobStore {
    inner: Mutex<JobStoreInner>,
    /// Overridable clock (tests pin it); `None` means
    /// `Utc::now` (Go's `nowUTC`).
    now_fn: Option<fn() -> DateTime<Utc>>,
}

impl ChatJobStore {
    pub fn new() -> Self {
        ChatJobStore {
            inner: Mutex::new(JobStoreInner {
                jobs: HashMap::new(),
                order: Vec::new(),
            }),
            now_fn: None,
        }
    }

    pub fn with_clock(now_fn: fn() -> DateTime<Utc>) -> Self {
        let mut s = Self::new();
        s.now_fn = Some(now_fn);
        s
    }

    /// Replace the clock (tests advance time to prove
    /// pruning).
    pub fn set_clock(&mut self, now_fn: fn() -> DateTime<Utc>) {
        self.now_fn = Some(now_fn);
    }

    fn clock(&self) -> DateTime<Utc> {
        match self.now_fn {
            Some(f) => f(),
            None => Utc::now(),
        }
    }

    /// `create` registers a new running job, or reports
    /// busy when one is already running for the profile.
    /// Expired jobs are pruned and the oldest finished jobs
    /// evicted past the cap, under the same lock, so the
    /// store cannot grow without bound.
    ///
    /// [DEVIATION] Go's `create` loops `for len(jobs) >
    /// chatJobMax { evictOldestFinishedLocked() }` with no
    /// progress check: with 33 running jobs (33 profiles)
    /// the evict finds nothing finished and the loop never
    /// terminates (chats.go `create`). This port breaks out
    /// when nothing can be evicted — a hang is never the
    /// matching behaviour. See PORTING.md §M6b.
    pub fn create(&self, profile_name: &str, session_id: &str) -> Result<ChatJob, ApiError> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.prune_locked(&mut inner);
        for j in inner.jobs.values() {
            if j.profile == profile_name && j.status == ChatJobStatus::Running {
                return Err(ApiError {
                    status: 409,
                    typ: "send_in_flight",
                    msg: "a send is already in flight for this profile".to_string(),
                });
            }
        }
        let mut b = [0u8; 16];
        rand::rng().fill_bytes(&mut b);
        let id = hex_encode(&b);
        let now = self.clock();
        let job = ChatJob {
            id: id.clone(),
            profile: profile_name.to_string(),
            session_id: session_id.to_string(),
            status: ChatJobStatus::Running,
            created_at: now,
            updated_at: now,
            result: None,
            err: String::new(),
        };
        inner.jobs.insert(id.clone(), job.clone());
        inner.order.push(id);
        while inner.jobs.len() > CHAT_JOB_MAX {
            if !self.evict_oldest_finished_locked(&mut inner) {
                break;
            }
        }
        Ok(job)
    }

    /// `get` returns a job by id, pruning expired jobs
    /// first. A pruned job reads as not found: the TTL is
    /// part of the contract.
    pub fn get(&self, id: &str) -> Option<ChatJob> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.prune_locked(&mut inner);
        inner.jobs.get(id).cloned()
    }

    /// `finish` records a job's terminal result. A job
    /// finished by a stale worker (pruned while running)
    /// is dropped, never resurrected. A non-running job
    /// is left alone.
    pub fn finish(&self, id: &str, result: Option<ChatSendResult>, err_msg: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(j) = inner.jobs.get_mut(id) else {
            return;
        };
        if j.status != ChatJobStatus::Running {
            return;
        }
        j.updated_at = self.clock();
        if !err_msg.is_empty() {
            j.status = ChatJobStatus::Failed;
            j.err = err_msg.to_string();
            return;
        }
        j.status = ChatJobStatus::Done;
        j.result = result;
    }

    /// `pruneLocked` drops jobs older than the TTL. The
    /// caller holds the mutex.
    fn prune_locked(&self, inner: &mut JobStoreInner) {
        let now = self.clock();
        let mut kept: Vec<String> = Vec::new();
        for id in inner.order.drain(..) {
            let Some(j) = inner.jobs.get(&id) else {
                continue;
            };
            if (now - j.created_at) > chrono::Duration::seconds(CHAT_JOB_TTL_SECS) {
                inner.jobs.remove(&id);
                continue;
            }
            kept.push(id);
        }
        inner.order = kept;
    }

    /// `evictOldestFinishedLocked` drops the oldest
    /// finished job. A running job is never evicted: the
    /// cap yields to in-flight work, and the next create
    /// prunes again.
    fn evict_oldest_finished_locked(&self, inner: &mut JobStoreInner) -> bool {
        for (i, id) in inner.order.iter().enumerate() {
            if let Some(j) = inner.jobs.get(id)
                && j.status != ChatJobStatus::Running
            {
                let id = inner.order.remove(i);
                inner.jobs.remove(&id);
                return true;
            }
        }
        false
    }
}

impl Default for ChatJobStore {
    fn default() -> Self {
        Self::new()
    }
}

fn hex_encode(raw: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len() * 2);
    for b in raw {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// `chatSessionID` maps a path session segment to the
/// gateway session id: the literal "main" is the main
/// chat (the CLI's empty --thread), anything else passes
/// through verbatim.
pub fn chat_session_id(segment: &str) -> String {
    if segment == "main" {
        String::new()
    } else {
        segment.to_string()
    }
}

/// `requireChatProfile` validates that name is a profile
/// key in the stored config. Unknown profiles 404 with a
/// fixed message.
pub fn require_chat_profile(config_dir: &std::path::Path, name: &str) -> Result<(), ApiError> {
    let load = crate::store::load_config(config_dir)?;
    let (cfg, _) = crate::store::parse_loaded(&load, config_dir)?;
    if !cfg.profiles.contains_key(name) {
        return Err(err_not_found("profile not found"));
    }
    Ok(())
}

/// The injected chat seams, or the fixed 501 when the
/// command layer wired none.
pub fn chat_deps(deps: &Option<Arc<ChatDeps>>) -> Result<Arc<ChatDeps>, ApiError> {
    match deps {
        Some(d) => Ok(Arc::clone(d)),
        None => Err(err_unavailable("chats are unavailable in this build")),
    }
}

/// `errUpstream` maps a chat-seam error to a fixed 502:
/// the failure class only, with no error text at all.
pub fn err_upstream_chat() -> ApiError {
    err_upstream()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_clock() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 5, 12, 0, 0).unwrap()
    }

    #[test]
    fn rfc3339_nano_trims_trailing_zeros() {
        let dt = Utc.with_ymd_and_hms(2026, 11, 5, 12, 0, 0).unwrap();
        assert_eq!(rfc3339_nano(dt), "2026-11-05T12:00:00Z");
        let dt = dt + chrono::Duration::nanoseconds(123_400_000);
        assert_eq!(rfc3339_nano(dt), "2026-11-05T12:00:00.1234Z");
        let dt =
            Utc.with_ymd_and_hms(2026, 11, 5, 12, 0, 0).unwrap() + chrono::Duration::nanoseconds(1);
        assert_eq!(rfc3339_nano(dt), "2026-11-05T12:00:00.000000001Z");
    }

    #[test]
    fn job_store_create_busy_and_finish() {
        let store = ChatJobStore::with_clock(fixed_clock);
        let job = store.create("muse01", "").unwrap();
        assert_eq!(job.id.len(), 32);
        assert!(store.create("muse01", "").is_err());
        // A different profile is unaffected.
        let job2 = store.create("other", "").unwrap();
        assert_ne!(job.id, job2.id);
        // Finish one; the profile frees up.
        store.finish(&job.id, None, "upstream error");
        let got = store.get(&job.id).unwrap();
        assert_eq!(got.status, ChatJobStatus::Failed);
        assert_eq!(got.err, "upstream error");
        assert!(store.create("muse01", "").is_ok());
        // A finished job cannot be re-finished.
        let result = ChatSendResult {
            outcome: "done".to_string(),
            status: None,
            after_seq: 3,
            final_text: Some("hi".to_string()),
            replies: vec![],
            note: None,
            approvals_count: None,
            needs_input_reason: None,
            question: None,
        };
        store.finish(&job.id, Some(result), "");
        let got = store.get(&job.id).unwrap();
        assert_eq!(got.status, ChatJobStatus::Failed);
    }

    #[test]
    fn job_store_prunes_expired() {
        let mut store = ChatJobStore::with_clock(fixed_clock);
        let job = store.create("muse01", "").unwrap();
        assert!(store.get(&job.id).is_some());
        // Advance the clock past the 1h TTL: the job reads
        // as not found.
        fn later() -> DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 11, 5, 14, 0, 1).unwrap()
        }
        store.set_clock(later);
        assert!(store.get(&job.id).is_none());
    }

    #[test]
    fn job_view_shapes() {
        let job = ChatJob {
            id: "abc".to_string(),
            profile: "muse01".to_string(),
            session_id: String::new(),
            status: ChatJobStatus::Running,
            created_at: fixed_clock(),
            updated_at: fixed_clock(),
            result: None,
            err: String::new(),
        };
        let rendered = crate::go_json::encode_go_json(&job.view());
        assert!(rendered.contains("\"status\":\"running\""));
        assert!(!rendered.contains("\"result\""));
        assert!(!rendered.contains("\"error\""));
        assert!(rendered.contains("\"created_at\":\"2026-11-05T12:00:00Z\""));
    }

    #[test]
    fn session_and_event_shapes() {
        let s = ChatSession {
            session_id: None,
            title: Some("t".to_string()),
            thread: Some(true),
            pinned: None,
            archived: None,
            updated: "2026-11-05T12:00:00Z".to_string(),
        };
        let rendered = crate::go_json::encode_go_json(&s.to_json());
        assert!(rendered.contains("\"session_id\":null"));
        assert!(rendered.contains("\"title\":\"t\""));
        let e = ChatEvent {
            seq: Some(1),
            role: None,
            message_id: None,
            text: "hi".to_string(),
        };
        let rendered = crate::go_json::encode_go_json(&e.to_json());
        assert!(rendered.contains("\"seq\":1"));
        assert!(rendered.contains("\"role\":null"));
    }
}
