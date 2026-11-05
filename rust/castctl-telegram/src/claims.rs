// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Approval-claim protocol and pending-approval notifications.
//!
//! Go sources: `internal/telegram/claims.go` (whole file) and
//! `internal/telegram/bot.go:1300-1484` (`decideOnce`,
//! `RecordDecided`, `cbDecide`, `cbApproveAll`).
//!
//! Model (header, `claims.go:5-21`): mirrors Python's
//! in-memory approval state machine
//! (`src/muse_cli/tgbot.py:1505-1701`). All state is
//! process-memory only, lost on restart; the state file
//! persists only toggles + offset, never claims.
//! `allow_once` is a decision string for ONE approval id
//! gated by the persistent `auto_allow_once` toggle — NOT a
//! consumed one-shot grant. Per-id consumption lives only
//! in the in-memory `decided` set.
//!
//! [DEVIATION — CLAIM STORM, DOCUMENTED RESIDUAL] With a
//! slow decider and a short `ClaimWait`, every concurrent
//! caller times out, takes over, and decides the same id
//! (pinned by Go
//! `TestApproveForeverClaimStormDocumentedResidual`: 20
//! goroutines, 150ms decider, 20ms ClaimWait → 20 decider
//! calls). Defect in the mirrored Python protocol, not a
//! transcription error; no fix keeps the surveyed
//! timeout-takeover semantics. Do NOT "fix" the storm by
//! changing takeover semantics. Gateway-side idempotency is
//! REQUIRED in step 5.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use crate::api::BotApi;
use crate::approvals::{Approval, DECISION_FOREVER, approval_text, choose_auto_decision};
use crate::error::BotError;
use crate::registry::{CallbackRegistry, approval_markup};
use crate::send::{SendOptions, Sender};

/// Maximum takeover hops while awaiting a claim.
/// Source: `internal/telegram/claims.go:60-65`
/// (`claimChainMax = 3`).
pub const CLAIM_CHAIN_MAX: usize = 3;

/// Default claim wait.
/// Source: `internal/telegram/claims.go:60-65`
/// (`claimWaitDefault = 15s`).
pub const CLAIM_WAIT_DEFAULT: Duration = Duration::from_secs(15);

/// Cap on the auto-decision log.
/// Source: `internal/telegram/claims.go:36-44`
/// (Python keeps at most 51: append then `[-50:]+[entry]`,
/// `src/muse_cli/tgbot.py:1594-1597`).
pub const AUTO_LOG_CAP: usize = 51;

/// Cap on the decided set, oldest-first eviction.
/// Source: `internal/telegram/bot.go:1300-1303`
/// (`decidedCap`).
pub const DECIDED_CAP: usize = 1024;

/// One auto-decision log entry, newest last.
/// Source: `internal/telegram/claims.go:36-44`
/// (`AutoLogEntry`). `time_unix_ms` is unix milliseconds
/// (Go stores a `time.Time`; the port keeps the instant as
/// millis — no `chrono` dependency exists on `dev-rust`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoLogEntry {
    /// Decision time, unix milliseconds.
    pub time_unix_ms: i64,
    /// Approval id.
    pub approval_id: String,
    /// Title.
    pub title: String,
    /// Decision string.
    pub decision: String,
    /// Kind.
    pub kind: String,
    /// Scope.
    pub scope: String,
}

/// Decides one approval (one `egress.approval.decide` call).
/// Source: `internal/telegram/bot.go:1345-1397`
/// (`decideOnce` calls the `Decider`) and
/// `internal/commands/telegram_approvals.go:45-68`
/// (`gatewayDecider`: one call, **no retry** — decide is
/// not idempotent; server-side idempotency unproven).
pub trait Decider: Send + Sync {
    /// Decide `approval_id` with `decision`.
    fn decide(
        &self,
        approval_id: &str,
        decision: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>>;
}

/// One in-flight claim (shared between its owner and
/// waiters). Mirrors Go's `inflightClaim`
/// (`internal/telegram/claims.go:45-58`): `done` channel +
/// `decision` / `failed` / `superseded` flags. The Rust
/// `Notify` replaces the `done` channel (a closed channel
/// is level-triggered; `Notify` is edge-triggered, so the
/// `settled` flag is always checked first under the lock —
/// see `await_claim`).
struct InflightClaim {
    inner: Mutex<InflightInner>,
    notify: Notify,
}

struct InflightInner {
    decision: Option<String>,
    failed: bool,
    superseded: bool,
}

impl InflightClaim {
    fn new() -> Self {
        Self {
            inner: Mutex::new(InflightInner {
                decision: None,
                failed: false,
                superseded: false,
            }),
            notify: Notify::new(),
        }
    }

    fn has_decision(&self) -> bool {
        self.inner.lock().is_ok_and(|i| i.decision.is_some())
    }

    fn is_settled(&self) -> bool {
        self.inner
            .lock()
            .is_ok_and(|i| i.decision.is_some() || i.failed)
    }

    fn is_superseded(&self) -> bool {
        self.inner.lock().is_ok_and(|i| i.superseded)
    }

    fn set_decision(&self, decision: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.decision = Some(decision.to_string());
        }
    }

    fn set_superseded(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.superseded = true;
        }
    }

    fn mark_failed(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.failed = true;
        }
    }

    fn settle(&self) {
        self.notify.notify_waiters();
    }
}

struct ClaimInner {
    decided: HashMap<String, String>,
    decided_order: Vec<String>,
    decide_inflight: HashMap<String, Arc<Notify>>,
    claimed: HashSet<String>,
    inflight: HashMap<String, Arc<InflightClaim>>,
    notified: HashSet<String>,
    auto_log: Vec<AutoLogEntry>,
}

/// The claim manager: `decided` set, in-flight claims,
/// `decideOnce` single-flight, auto-log.
/// Source: the `Bot` claim fields
/// (`internal/telegram/bot.go:280-310`) and `claims.go`.
pub struct ClaimManager {
    decider: Arc<dyn Decider>,
    claim_wait: Duration,
    inner: Mutex<ClaimInner>,
}

impl std::fmt::Debug for ClaimManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimManager")
            .field("claim_wait", &self.claim_wait)
            .finish_non_exhaustive()
    }
}

impl ClaimManager {
    /// New claim manager. `claim_wait` of zero means the
    /// default 15s (Go: `ClaimWait` 0 = 15s,
    /// `internal/telegram/bot.go:242-243`).
    #[must_use]
    pub fn new(decider: Arc<dyn Decider>, claim_wait: Duration) -> Self {
        Self {
            decider,
            claim_wait: if claim_wait.is_zero() {
                CLAIM_WAIT_DEFAULT
            } else {
                claim_wait
            },
            inner: Mutex::new(ClaimInner {
                decided: HashMap::new(),
                decided_order: Vec::new(),
                decide_inflight: HashMap::new(),
                claimed: HashSet::new(),
                inflight: HashMap::new(),
                notified: HashSet::new(),
                auto_log: Vec::new(),
            }),
        }
    }

    /// The claim wait in effect.
    #[must_use]
    pub fn claim_wait(&self) -> Duration {
        self.claim_wait
    }

    /// Whether `id` is already decided.
    #[must_use]
    pub fn is_decided(&self, id: &str) -> bool {
        self.inner.lock().is_ok_and(|i| i.decided.contains_key(id))
    }

    /// Record a decision made outside `decide_once` (turn
    /// auto-approve path) in the same `decided` set.
    /// Source: `internal/telegram/bot.go:1326-1343`
    /// (`RecordDecided`).
    pub fn record_decided(&self, id: &str, decision: &str) {
        let mut inner = self.inner.lock().expect("claims lock");
        set_decided_locked(&mut inner, id, decision);
    }

    /// Copy of the auto-decision log.
    /// Source: `internal/telegram/claims.go:319-327`
    /// (`AutoLog`).
    #[must_use]
    pub fn auto_log(&self) -> Vec<AutoLogEntry> {
        self.inner
            .lock()
            .map_or_else(|_| Vec::new(), |i| i.auto_log.clone())
    }

    /// At most one Decide RPC per approval id per process
    /// lifetime. Check + RPC + record is atomic per id; a
    /// second caller for the SAME id waits on the in-flight
    /// signal then re-checks; different ids proceed
    /// concurrently. A failed RPC records nothing (retry
    /// stays possible).
    /// Source: `internal/telegram/bot.go:1345-1397`
    /// (`decideOnce`). Returns `true` when this caller
    /// performed the decide, `false` when already decided.
    pub async fn decide_once(&self, id: &str, decision: &str) -> Result<bool, BotError> {
        loop {
            let waiter = {
                let inner = self.inner.lock().expect("claims lock");
                if inner.decided.contains_key(id) {
                    return Ok(false);
                }
                match inner.decide_inflight.get(id) {
                    Some(notify) => Some(Arc::clone(notify)),
                    None => None,
                }
            };
            if let Some(notify) = waiter {
                notify.notified().await;
                continue;
            }
            {
                let mut inner = self.inner.lock().expect("claims lock");
                if inner.decided.contains_key(id) {
                    return Ok(false);
                }
                if inner.decide_inflight.contains_key(id) {
                    continue;
                }
                inner
                    .decide_inflight
                    .insert(id.to_string(), Arc::new(Notify::new()));
            }
            let result = self.decider.decide(id, decision).await;
            let notify = {
                let mut inner = self.inner.lock().expect("claims lock");
                let notify = inner.decide_inflight.remove(id);
                if result.is_ok() {
                    set_decided_locked(&mut inner, id, decision);
                }
                notify
            };
            if let Some(notify) = notify {
                notify.notify_waiters();
            }
            return match result {
                Ok(()) => Ok(true),
                Err(e) => Err(e),
            };
        }
    }

    /// Auto-decide every approval that offers a forever
    /// option, skipping empty ids, already-decided ids, and
    /// ids with an in-flight claim owned elsewhere (those
    /// are awaited, then decided on takeover). Returns the
    /// ids it decided.
    /// Source: `internal/telegram/claims.go:133-221`
    /// (`ApproveForever`).
    pub async fn approve_forever(
        &self,
        items: &[Approval],
        auto_approve: bool,
        auto_allow_once: bool,
    ) -> Vec<String> {
        struct Work {
            approval: Approval,
            claim: Arc<InflightClaim>,
        }
        let mut done: Vec<String> = Vec::new();
        let mut waited: Vec<Work> = Vec::new();
        let mut todo: Vec<Work> = Vec::new();
        {
            let mut inner = self.inner.lock().expect("claims lock");
            for a in items {
                if a.id.is_empty() {
                    continue;
                }
                if inner.decided.contains_key(&a.id) {
                    done.push(a.id.clone());
                    continue;
                }
                if let Some(claim) = inner.inflight.get(&a.id) {
                    waited.push(Work {
                        approval: a.clone(),
                        claim: Arc::clone(claim),
                    });
                    continue;
                }
                if inner.claimed.contains(&a.id) {
                    continue;
                }
                let claim = Arc::new(InflightClaim::new());
                inner.inflight.insert(a.id.clone(), Arc::clone(&claim));
                inner.claimed.insert(a.id.clone());
                todo.push(Work {
                    approval: a.clone(),
                    claim,
                });
            }
        }
        for w in waited {
            let (is_done, takeover) = self.await_claim(&w.approval, &w.claim).await;
            if is_done {
                done.push(w.approval.id.clone());
            } else if let Some(takeover) = takeover {
                todo.push(Work {
                    approval: w.approval,
                    claim: takeover,
                });
            }
        }
        for w in todo {
            let Some(decision) = choose_auto_decision(&w.approval, auto_approve, auto_allow_once)
            else {
                self.fail_claim(&w.approval.id, &w.claim);
                continue;
            };
            if let Err(_e) = self.decider.decide(&w.approval.id, decision).await {
                self.fail_claim(&w.approval.id, &w.claim);
                continue;
            }
            if self.record_claim(&w.approval, decision, &w.claim) {
                done.push(w.approval.id.clone());
            }
        }
        done
    }

    /// Wait for another owner's in-flight claim to settle,
    /// following up to `CLAIM_CHAIN_MAX - 1` takeover hops.
    /// Returns `(true, None)` when the claim settled with a
    /// decision, `(false, Some(takeover))` when this caller
    /// owns the claim now.
    /// Source: `internal/telegram/claims.go:222-268`
    /// (`awaitClaim`).
    async fn await_claim(
        &self,
        approval: &Approval,
        claim: &Arc<InflightClaim>,
    ) -> (bool, Option<Arc<InflightClaim>>) {
        let mut current = Arc::clone(claim);
        let mut hops = 0usize;
        loop {
            // Wait for the settle signal or the claim wait.
            // The settled flag is checked under the manager
            // lock first (Notify is edge-triggered; the flag
            // is the level).
            let settled = {
                let notified = current.notify.notified();
                tokio::pin!(notified);
                // Register the waiter before re-checking the
                // flag, so a settle between the check and the
                // wait cannot be lost: settle sets the flag
                // under the manager lock, then notifies.
                let _ = notified.as_mut().enable();
                let done = current.is_settled();
                if done {
                    true
                } else {
                    tokio::time::timeout(self.claim_wait, notified)
                        .await
                        .is_ok()
                }
            };
            let _ = settled;
            {
                let mut inner = self.inner.lock().expect("claims lock");
                if current.has_decision() {
                    return (true, None);
                }
                let next = inner.inflight.get(&approval.id).cloned();
                if let Some(next) = next
                    && !Arc::ptr_eq(&next, &current)
                {
                    hops += 1;
                    if hops < CLAIM_CHAIN_MAX {
                        current = next;
                        continue;
                    }
                    next.set_superseded();
                    current.set_superseded();
                }
                if !current.is_settled() {
                    current.set_superseded();
                }
                if let Some(existing) = inner.inflight.get(&approval.id)
                    && Arc::ptr_eq(existing, &current)
                {
                    inner.inflight.remove(&approval.id);
                }
                inner.claimed.insert(approval.id.clone());
                let takeover = Arc::new(InflightClaim::new());
                inner
                    .inflight
                    .insert(approval.id.clone(), Arc::clone(&takeover));
                return (false, Some(takeover));
            }
        }
    }

    /// Record a decision and settle the claim. Returns false
    /// when the claim was superseded: the decision still
    /// happened, but the superseding owner records it, so
    /// this caller must not report the id as decided-by-it.
    /// Source: `internal/telegram/claims.go:270-299`
    /// (`recordClaim`).
    fn record_claim(
        &self,
        approval: &Approval,
        decision: &str,
        claim: &Arc<InflightClaim>,
    ) -> bool {
        let mut inner = self.inner.lock().expect("claims lock");
        if claim.is_superseded() {
            claim.mark_failed();
            claim.settle();
            return false;
        }
        set_decided_locked(&mut inner, &approval.id, decision);
        claim.set_decision(decision);
        inner.auto_log.push(AutoLogEntry {
            time_unix_ms: unix_millis_now(),
            approval_id: approval.id.clone(),
            title: approval.title.clone(),
            decision: decision.to_string(),
            kind: approval.kind.clone(),
            scope: approval.scope.clone(),
        });
        if inner.auto_log.len() > AUTO_LOG_CAP {
            let excess = inner.auto_log.len() - AUTO_LOG_CAP;
            inner.auto_log.drain(..excess);
        }
        if let Some(existing) = inner.inflight.get(&approval.id)
            && Arc::ptr_eq(existing, claim)
        {
            inner.inflight.remove(&approval.id);
        }
        claim.settle();
        true
    }

    /// Release a claim after a failed decide, so a retry can
    /// take it over.
    /// Source: `internal/telegram/claims.go:301-317`
    /// (`failClaim`).
    fn fail_claim(&self, id: &str, claim: &Arc<InflightClaim>) -> bool {
        let mut inner = self.inner.lock().expect("claims lock");
        if claim.is_superseded() {
            claim.mark_failed();
            claim.settle();
            return false;
        }
        claim.mark_failed();
        if let Some(existing) = inner.inflight.get(id)
            && Arc::ptr_eq(existing, claim)
        {
            inner.inflight.remove(id);
        }
        inner.claimed.remove(id);
        claim.settle();
        true
    }

    /// Whether `id` was already notified (and mark it).
    /// Helper for `notify_pending`; no direct Go function
    /// counterpart (Go reads `b.notified` inline in
    /// `NotifyPending`, `internal/telegram/claims.go:335-412`).
    fn take_notify(&self, id: &str) -> bool {
        let mut inner = self.inner.lock().expect("claims lock");
        if inner.notified.contains(id) {
            return false;
        }
        inner.notified.insert(id.to_string());
        true
    }

    /// Snapshot of the decided map (id → decision).
    fn decided_snapshot(&self) -> HashMap<String, String> {
        self.inner
            .lock()
            .map_or_else(|_| HashMap::new(), |i| i.decided.clone())
    }
}

/// Record a decision in the `decided` set with oldest-first
/// eviction at the cap. Caller must hold the manager lock.
/// Source: `internal/telegram/bot.go:1304-1324`
/// (`setDecidedLocked`).
fn set_decided_locked(inner: &mut ClaimInner, id: &str, decision: &str) {
    if !inner.decided.contains_key(id) {
        inner.decided_order.push(id.to_string());
    }
    inner.decided.insert(id.to_string(), decision.to_string());
    while inner.decided_order.len() > DECIDED_CAP {
        if let Some(oldest) = inner.decided_order.first().cloned() {
            inner.decided_order.remove(0);
            inner.decided.remove(&oldest);
        } else {
            break;
        }
    }
}

/// Current unix time in milliseconds.
fn unix_millis_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// Render an approval id for a log line only. The id is
/// token-scrubbed first, then emitted only when it matches
/// the strict structural gate — 1–64 runes of
/// `[A-Za-z0-9_-]` — and renders `[omitted]` otherwise,
/// fail-closed.
/// Source: `internal/telegram/claims.go:109-131`
/// (`logApprovalID`).
#[must_use]
pub fn log_approval_id(id: &str, token: &str) -> String {
    let scrubbed = if token.is_empty() {
        id.to_string()
    } else {
        id.replace(token, "***")
    };
    let mut n = 0;
    for r in scrubbed.chars() {
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
    scrubbed
}

/// Auto-decide newly pending approvals, notify the chat
/// once per decided approval, then send undecidable
/// approvals as buttons — unless a turn is running, in
/// which case it returns early and never notifies later
/// for those ids (deliberate: no reminder queue; the bot
/// keeps no record).
/// Source: `internal/telegram/claims.go:335-412`
/// (`NotifyPending`).
#[allow(clippy::too_many_arguments)]
pub async fn notify_pending(
    api: &BotApi,
    registry: &CallbackRegistry,
    claims: &ClaimManager,
    auto_approve: bool,
    auto_allow_once: bool,
    any_active_turn: bool,
    chat_id: i64,
    items: &[Approval],
) {
    let sender = Sender::new(api);
    let mut remaining: Vec<Approval> = items.to_vec();
    if auto_approve {
        let fresh: Vec<Approval> = items
            .iter()
            .filter(|d| !claims.is_decided(&d.id))
            .cloned()
            .collect();
        let decided_ids = claims
            .approve_forever(&fresh, auto_approve, auto_allow_once)
            .await;
        let decided_set: HashSet<&str> = decided_ids.iter().map(String::as_str).collect();
        if any_active_turn {
            return;
        }
        let decisions = claims.decided_snapshot();
        for d in &fresh {
            if decided_set.contains(d.id.as_str()) && claims.take_notify(&d.id) {
                let label = match decisions.get(&d.id) {
                    Some(dec) if dec != DECISION_FOREVER => "once",
                    _ => "always",
                };
                let title = if d.title.is_empty() { &d.id } else { &d.title };
                let text = format!(
                    "✅ Auto-approved ({label}): {}",
                    castctl_tg_text::escape_text(title)
                );
                let _ = sender
                    .send(
                        chat_id,
                        &text,
                        SendOptions {
                            silent: true,
                            ..SendOptions::default()
                        },
                    )
                    .await;
            }
        }
        let mut undecidable: Vec<Approval> = Vec::new();
        for d in items {
            if claims.is_decided(&d.id) {
                continue;
            }
            if choose_auto_decision(d, true, auto_allow_once).is_some() {
                continue;
            }
            undecidable.push(d.clone());
        }
        remaining = undecidable;
        if remaining.is_empty() {
            return;
        }
    }
    if any_active_turn {
        return;
    }
    for d in &remaining {
        if !claims.take_notify(&d.id) {
            continue;
        }
        let markup = approval_markup(registry, d, "", "", None);
        let _ = sender
            .send(
                chat_id,
                &approval_text(d),
                SendOptions {
                    markup: Some(markup),
                    ..SendOptions::default()
                },
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingDecider {
        calls: Arc<AtomicUsize>,
    }

    impl Decider for CountingDecider {
        fn decide(
            &self,
            _approval_id: &str,
            _decision: &str,
        ) -> Pin<Box<dyn Future<Output = Result<(), BotError>> + Send + '_>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(()) })
        }
    }

    fn manager() -> (ClaimManager, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let decider = Arc::new(CountingDecider {
            calls: Arc::clone(&calls),
        });
        (ClaimManager::new(decider, Duration::from_millis(50)), calls)
    }

    fn approval(id: &str) -> Approval {
        Approval {
            id: id.to_string(),
            title: format!("title {id}"),
            ..Approval::default()
        }
    }

    #[tokio::test]
    async fn approve_forever_decides_no_option_approvals() {
        let (m, calls) = manager();
        let done = m
            .approve_forever(&[approval("a1"), approval("a2")], true, false)
            .await;
        assert_eq!(done.len(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(m.is_decided("a1"));
        assert_eq!(m.auto_log().len(), 2);
    }

    #[tokio::test]
    async fn approve_forever_skips_empty_and_decided_ids() {
        let (m, calls) = manager();
        let done = m
            .approve_forever(&[approval(""), approval("a1")], true, false)
            .await;
        assert_eq!(done, vec!["a1".to_string()]);
        let done2 = m.approve_forever(&[approval("a1")], true, false).await;
        assert_eq!(done2, vec!["a1".to_string()]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn decide_once_is_single_flight() {
        let (m, calls) = manager();
        let m = Arc::new(m);
        let m2 = Arc::clone(&m);
        let m3 = Arc::clone(&m);
        let (r1, r2, r3) = tokio::join!(
            m.decide_once("x", "allow_always"),
            m2.decide_once("x", "allow_always"),
            m3.decide_once("x", "allow_always"),
        );
        assert!(r1.expect("r1"));
        assert!(!r2.expect("r2"));
        assert!(!r3.expect("r3"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn log_approval_id_gate() {
        assert_eq!(log_approval_id("abc-123_X", ""), "abc-123_X");
        assert_eq!(log_approval_id("", ""), "[omitted]");
        assert_eq!(log_approval_id("has space", ""), "[omitted]");
        assert_eq!(log_approval_id("a".repeat(65).as_str(), ""), "[omitted]");
        assert_eq!(
            log_approval_id("tok123456:secret-id", "123456:secret"),
            "[omitted]"
        );
    }
}
