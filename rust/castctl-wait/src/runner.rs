// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The wait runner (Go `internal/wait/runner.go`): drives
//! M5b's [`Waiter`] over a `chat.subscribe` NDJSON stream,
//! with boundary derivation, watchdog / safety-net /
//! online-idle / reconnect-storm rules, and a fail-closed
//! endgame (last-chance FAILED proof, final read, lag
//! window, reconciliation, `124`).
//!
//! The Runner runs on one task; no lock is needed. State
//! checks run synchronously between subscribe batches
//! (Go deviation D2). No I/O happens under a lock because
//! there is no lock.
//!
//! An `Auth` error anywhere propagates unwrapped:
//! swallowing it as 124 would send every retry-on-124
//! caller into an infinite loop on expired cookies.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use castctl_gateway::subscribe::{SubscribeHandler, SubscribeOptions};
use castctl_telegram::Approval as TelegramApproval;
use castctl_telegram::BotError;
use castctl_telegram::wait::{
    ApproveError, ApprovedRecord, Outcome, Reply, WaitApprover, WaitKind, Waiter, exit_code,
    in_scope, is_failed_status, needs_input_reason, outcome_of, payload, task_status_info,
};
use castctl_transport::TransportError;
use serde_json::{Value, json};
use tokio::time::Instant;

use crate::Cancel;
use crate::events::{decode_record, question_of, record_name};
use crate::history::{
    HistoryError, HistoryReader, derive_boundary, history_replies, latest_user_seq,
};

/// Timing defaults, verbatim from Go `runner.go:22-65`
/// (seconds unless noted). All enforced on the monotonic
/// (tokio) clock.
pub const DEFAULT_RECHECK_AFTER: Duration = Duration::from_secs(20);
/// Bounds one server state check.
pub const DEFAULT_STATE_CHECK_BUDGET: Duration = Duration::from_secs(8);
/// Shared deadline for a storm of failed resubscribes
/// before one bounded state check.
pub const DEFAULT_RECONNECT_BUDGET: Duration = Duration::from_secs(30);
/// The idle-online grace before a re-check. Fixed protocol
/// constant, not a caller-tunable timer (there is no
/// `OnlineGrace` field in `Config`).
pub const DEFAULT_ONLINE_GRACE: Duration = Duration::from_secs(3);
/// Base pause before resubscribing.
pub const DEFAULT_RESUB_PAUSE: Duration = Duration::from_secs(1);
/// Minimum budget for the final history read and the
/// last-chance user-seq read.
pub const DEFAULT_FINAL_READ_FLOOR: Duration = Duration::from_secs(5);
/// Post-done polling window for a just-landed reply.
pub const DEFAULT_LAG_WINDOW: Duration = Duration::from_secs(2);
/// Interval between lag-window reads.
pub const DEFAULT_LAG_POLL: Duration = Duration::from_millis(250);
/// Safety-net cadence: an unconditional server state check.
pub const DEFAULT_CHECK_EVERY: Duration = Duration::from_secs(60);
/// How often a held ignored terminal is re-proved against
/// history while the stream is quiet (redesign decision
/// D3).
pub const DEFAULT_SETTLE_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Floor for a caller-supplied `SettlePollInterval` (Go
/// `minSettlePollInterval`).
pub const MIN_SETTLE_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// The wait `--timeout` default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
/// History-read budget floor (Go `historyCtx`).
pub const HISTORY_READ_FLOOR: Duration = Duration::from_millis(100);

/// One subscribe-capable connection: the gateway narrowed
/// to what the Runner uses (Go `runner.go` `Subscriber`).
/// The Runner never dials: `Dial` supplies a fresh
/// `Subscriber` per subscribe iteration (and per state
/// check), and the Runner closes it after use.
pub trait Subscriber: Send + Sync {
    /// Subscribe and return the raw NDJSON record bytes.
    /// The handler's `on_record` runs with each record
    /// the moment it arrives. The method string, the
    /// handler borrow and the subscriber borrow share one
    /// lifetime `'a` (the future is awaited immediately at
    /// every call site), so no owned copies are needed.
    fn subscribe_raw<'a>(
        &'a self,
        method: &'a str,
        opts: SubscribeOptions,
        handler: &'a mut dyn SubscribeHandler,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Vec<u8>>, TransportError>> + Send + 'a>>;

    /// Close after use. The Runner ignores the result
    /// (Go: `_ = sub.Close()`), but the interface keeps
    /// it for contract parity.
    fn close(&self) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>>;
}

/// Dial supplies a fresh [`Subscriber`] per subscribe
/// iteration (Go `Config.Dial`). `Ok(None)` is a nil
/// Subscriber: a transport failure, never a panic. The
/// `Cancel` is the run cancel; a dial that honors it
/// ends promptly when the wait is cancelled.
pub type DialFn = Arc<
    dyn Fn(
            Cancel,
        ) -> Pin<
            Box<dyn Future<Output = Result<Option<Arc<dyn Subscriber>>, TransportError>> + Send>,
        > + Send
        + Sync,
>;

/// Whether a transport error is an auth failure (Go
/// `isAuthError`: an `AuthError` anywhere in the chain).
/// Rust's `TransportError` is a flat enum, so the check
/// is a direct variant match.
#[must_use]
pub fn is_auth_error(e: &TransportError) -> bool {
    matches!(e, TransportError::Auth { .. })
}

/// A `Config` error: `Dial` or `History` missing (Go
/// `NewRunner`: `"wait: Runner requires Dial"` /
/// `"wait: Runner requires History"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Configures a `Runner`. Zero values take the defaults
/// above; `None` disables that timer for `RecheckAfter`
/// and `CheckEvery` only (Go's negative durations — Rust
/// `Duration` cannot be negative, so `None` is the
/// disable spelling and `Some(Duration::ZERO)` takes the
/// default, exactly as Go's zero does). Every other zero
/// duration is clamped to its default in `Runner::new`.
///
/// There is no `OnlineGrace` field: the 3 s online-idle
/// grace is a fixed protocol constant, not a
/// caller-tunable timer.
///
/// `NodeID` is the caller-supplied stable per-profile
/// identity. The Runner carries it, never generates,
/// persists or rotates it, and never sends it.
///
/// `Approver` is the wait core's approver. The records
/// its calls produce (approved + errors) are accumulated
/// by the `Waiter` and copied into
/// `WaitResult::auto_approved` /
/// `WaitResult::auto_approve_errors`. The Runner has no
/// logger and writes nothing to stderr: the caller (the
/// CLI wiring) logs those records from the `WaitResult`.
#[derive(Clone)]
pub struct Config {
    /// Thread (session) id to wait on (`""` = main chat).
    pub thread: String,
    /// Caller-supplied stable per-profile identity.
    pub node_id: String,
    /// Explicit boundary; used only when
    /// `has_after_seq` is set.
    pub after_seq: i64,
    /// Whether `after_seq` is an explicit boundary.
    pub has_after_seq: bool,
    /// Overall wait timeout (`Duration::ZERO` = 600 s).
    pub timeout: Duration,
    /// Watchdog: seconds without scoped progress before
    /// the stream is ended and resubscribed
    /// (`None` = disabled, `Some(ZERO)` = 20 s).
    pub recheck_after: Option<Duration>,
    /// Safety-net cadence (`None` = disabled,
    /// `Some(ZERO)` = 60 s).
    pub check_every: Option<Duration>,
    /// Budget for one server state check.
    pub state_check_budget: Duration,
    /// Shared deadline for a storm of failed
    /// resubscribes before one bounded state check.
    pub reconnect_budget: Duration,
    /// Base pause before resubscribing.
    pub resub_pause: Duration,
    /// Minimum budget for the final history read and
    /// the last-chance user-seq read.
    pub final_read_floor: Duration,
    /// Post-done polling window for a just-landed reply.
    pub lag_window: Duration,
    /// Interval between lag-window reads.
    pub lag_poll: Duration,
    /// Re-poll cadence for a held ignored terminal.
    /// Zero takes the default; a positive value below
    /// 100 ms clamps up to the floor — never a disable.
    pub settle_poll_interval: Duration,
    /// History window growth (`[]` = the defaults).
    pub history_limits: Vec<usize>,
    /// The wait core's approver, if any.
    pub approver: Option<Arc<dyn WaitApprover>>,
    /// Caller recheck callback: when it returns `true`
    /// the stream ends and resubscribes.
    pub recheck: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    /// Caller stop callback: when it returns `true` the
    /// wait ends (the loop exits and `finish` runs).
    pub user_stop: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    /// Supplies a fresh `Subscriber` per iteration.
    pub dial: Option<DialFn>,
    /// The history source.
    pub history: Option<Arc<dyn HistoryReader>>,
    /// Receives every decoded stream record the Runner
    /// feeds to the `Waiter`, in arrival order, before
    /// the record's progress/settle handling. Must
    /// return quickly, must not block, must not panic,
    /// and must not call `Runner` methods.
    pub on_event: Option<Arc<dyn Fn(&Value) + Send + Sync>>,
    /// Test-only hook, invoked synchronously immediately
    /// before the final guard in `finish`, with the run
    /// cancel. `None` in production.
    pub before_final_guard: Option<Arc<dyn Fn(Cancel) + Send + Sync>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            thread: String::new(),
            node_id: String::new(),
            after_seq: 0,
            has_after_seq: false,
            timeout: Duration::ZERO,
            recheck_after: Some(Duration::ZERO),
            check_every: Some(Duration::ZERO),
            state_check_budget: Duration::ZERO,
            reconnect_budget: Duration::ZERO,
            resub_pause: Duration::ZERO,
            final_read_floor: Duration::ZERO,
            lag_window: Duration::ZERO,
            lag_poll: Duration::ZERO,
            settle_poll_interval: Duration::ZERO,
            history_limits: Vec::new(),
            approver: None,
            recheck: None,
            user_stop: None,
            dial: None,
            history: None,
            on_event: None,
            before_final_guard: None,
        }
    }
}

/// The wait's endgame result, mirroring the Go `Result`
/// (Python result dict). Empty strings mean "none" (no
/// status was ever stored, no final text, no input
/// reason). `Status` is the `Waiter`'s last stored status
/// regardless of kind — including `Approval`, where the
/// status is reported too.
#[derive(Debug, Clone)]
pub struct WaitResult {
    /// Decided kind.
    pub kind: WaitKind,
    /// Outcome string (`done` / `failed` /
    /// `needs_approval` / `needs_input` / `timeout`).
    pub outcome: String,
    /// Last stored status (`running` or terminal).
    pub status: String,
    /// Turn-end boundary (0 when unknown).
    pub after_seq: i64,
    /// Last reply's text (`""` when no replies).
    pub final_text: String,
    /// This turn's replies from history, oldest-first.
    pub replies: Vec<Reply>,
    /// Whether the final history read failed.
    pub final_read_failed: bool,
    /// Endgame note (`""` when none).
    pub note: String,
    /// Pending approvals (kind `Approval` only).
    pub approvals: Vec<TelegramApproval>,
    /// Why the last reply needs input (`""` unless
    /// `needs_input`).
    pub needs_input_reason: String,
    /// The question extracted from the last reply.
    pub question: String,
    /// Process exit code (0 / 2 / 4 / 124).
    pub exit_code: i32,
    /// Caller-supplied node id, carried through.
    pub node_id: String,
    /// Auto-approved records, for the caller to log.
    pub auto_approved: Vec<ApprovedRecord>,
    /// Auto-approve error records, for the caller to log.
    pub auto_approve_errors: Vec<ApproveError>,
}

/// What `Runner::run` returns on failure. A timeout is a
/// [`WaitResult`] with kind `Timeout`, never an error.
#[derive(Debug)]
pub enum RunError {
    /// An auth failure anywhere (dial, subscribe,
    /// history, approver). Propagates unwrapped.
    Auth(TransportError),
    /// The wait's [`Cancel`] fired.
    Cancelled,
    /// A fatal approver error from the wait core (the
    /// `Waiter`'s `fatal_err`, e.g. a decide-time auth
    /// failure).
    ApproverFatal(BotError),
    /// A history-read transport failure. Internal only:
    /// `try_settle` and `check_state` swallow it; it
    /// never escapes `run`.
    HistoryRead(TransportError),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth(e) => write!(f, "wait: auth error: {e}"),
            Self::Cancelled => write!(f, "wait: cancelled"),
            Self::ApproverFatal(e) => write!(f, "wait: approver fatal: {e:?}"),
            Self::HistoryRead(e) => write!(f, "wait: history read failed: {e}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Map a [`HistoryError`] to a [`RunError`] after a
/// history read, checking cancellation first (Go: every
/// history-read error site checks `ctx.Err()` before
/// `isAuthError`).
fn map_history_err(e: HistoryError, cancel: &Cancel) -> RunError {
    if cancel.is_set() {
        return RunError::Cancelled;
    }
    match e {
        HistoryError::Cancelled => RunError::Cancelled,
        HistoryError::Deadline => RunError::HistoryRead(TransportError::Timeout {
            message: "wait: history read past the wait deadline".to_string(),
        }),
        HistoryError::Transport(t) if is_auth_error(&t) => RunError::Auth(t),
        HistoryError::Transport(t) => RunError::HistoryRead(t),
    }
}

/// The Runner drives a `Waiter` over a subscription:
/// boundary derivation, the subscribe loop with
/// watchdog / safety-net / online-idle / reconnect-storm
/// rules, and the endgame. It runs on one task; no lock
/// is needed.
pub struct Runner {
    cfg: Config,
    waiter: Waiter,
    dial: DialFn,
    history: Arc<dyn HistoryReader>,
    deadline: Option<Instant>,
    after_seq: i64,
    boundary_known: bool,
    last_progress: Instant,
    last_check: Instant,
    online_at: Instant,
    online_armed: bool,
    failures: u32,
    first_failure_at: Option<Instant>,
    settle_tried: bool,
    settle_key: String,
    pending_err: Option<RunError>,
    /// The monotonic time the last settle proof started a
    /// history read. Zero (`None`) means no proof has
    /// read yet.
    last_settle_proof: Option<Instant>,
    /// Replies of the last successful settle proof, if
    /// any: the evidence the turn was decided on.
    proof_replies: Vec<Reply>,
}

impl Runner {
    /// Validate `cfg` and build a `Runner`. `Dial` and
    /// `History` are required; the clock is always tokio
    /// time (see the crate docs). Durations clamp exactly
    /// as Go `NewRunner` (`runner.go:293-363`) clamps
    /// them, with `None` as the disable spelling for
    /// `RecheckAfter`/`CheckEvery`.
    pub fn new(mut cfg: Config) -> Result<Self, ConfigError> {
        let dial = cfg
            .dial
            .take()
            .ok_or_else(|| ConfigError("wait: Runner requires Dial".to_string()))?;
        let history = cfg
            .history
            .take()
            .ok_or_else(|| ConfigError("wait: Runner requires History".to_string()))?;
        if cfg.timeout.is_zero() {
            cfg.timeout = DEFAULT_TIMEOUT;
        }
        if let Some(d) = cfg.recheck_after {
            if d.is_zero() {
                cfg.recheck_after = Some(DEFAULT_RECHECK_AFTER);
            }
        }
        if let Some(d) = cfg.check_every {
            if d.is_zero() {
                cfg.check_every = Some(DEFAULT_CHECK_EVERY);
            }
        }
        if cfg.state_check_budget.is_zero() {
            cfg.state_check_budget = DEFAULT_STATE_CHECK_BUDGET;
        }
        if cfg.reconnect_budget.is_zero() {
            cfg.reconnect_budget = DEFAULT_RECONNECT_BUDGET;
        }
        if cfg.resub_pause.is_zero() {
            cfg.resub_pause = DEFAULT_RESUB_PAUSE;
        }
        if cfg.final_read_floor.is_zero() {
            cfg.final_read_floor = DEFAULT_FINAL_READ_FLOOR;
        }
        if cfg.lag_window.is_zero() {
            cfg.lag_window = DEFAULT_LAG_WINDOW;
        }
        if cfg.lag_poll.is_zero() {
            cfg.lag_poll = DEFAULT_LAG_POLL;
        }
        if cfg.settle_poll_interval.is_zero() {
            cfg.settle_poll_interval = DEFAULT_SETTLE_POLL_INTERVAL;
        }
        if cfg.settle_poll_interval < MIN_SETTLE_POLL_INTERVAL {
            cfg.settle_poll_interval = MIN_SETTLE_POLL_INTERVAL;
        }
        if cfg.history_limits.is_empty() {
            cfg.history_limits = crate::history::default_history_limits();
        }
        let waiter = Waiter::new(&cfg.thread);
        Ok(Self {
            cfg,
            waiter,
            dial,
            history,
            deadline: None,
            after_seq: 0,
            boundary_known: false,
            last_progress: Instant::now(),
            last_check: Instant::now(),
            online_at: Instant::now(),
            online_armed: false,
            failures: 0,
            first_failure_at: None,
            settle_tried: false,
            settle_key: String::new(),
            pending_err: None,
            last_settle_proof: None,
            proof_replies: Vec::new(),
        })
    }

    /// The driven state machine, for inspection (Go
    /// `Runner.Waiter`).
    #[must_use]
    pub fn waiter(&self) -> &Waiter {
        &self.waiter
    }

    /// Wait for the turn to end and return the endgame
    /// result. Returns an error only for `Auth`, context
    /// cancellation, or a stalled dial/history failure
    /// the endgame cannot absorb; a timeout is a
    /// `WaitResult` with kind `Timeout`, never an error.
    /// (Go `runner.go` `Run`.)
    pub async fn run(&mut self, cancel: Cancel) -> Result<WaitResult, RunError> {
        let now = Instant::now();
        let deadline = now + self.cfg.timeout;
        self.deadline = Some(deadline);
        self.last_check = now;
        if self.cfg.has_after_seq {
            self.after_seq = self.cfg.after_seq;
            self.boundary_known = true;
            self.waiter.set_boundary(self.after_seq, false, false);
        } else {
            // Boundary derivation runs under the wait
            // deadline: an unbounded derivation could
            // otherwise consume time past a short
            // `--timeout` before any subscription starts.
            // A deadline expiry during derivation is not
            // an error return: the boundary is unknown,
            // the loop below does not run, and finish
            // yields `KindTimeout`. An `Auth` error still
            // propagates, and a dead wait still returns
            // the cancellation.
            match derive_boundary(
                self.history.as_ref(),
                &self.cfg.history_limits,
                &cancel,
                self.deadline,
            )
            .await
            {
                Ok((seq, known, derived)) => {
                    self.after_seq = seq;
                    self.boundary_known = known;
                    self.waiter.set_boundary(seq, !known, derived && known);
                }
                Err(HistoryError::Transport(t)) if is_auth_error(&t) => {
                    return Err(RunError::Auth(t));
                }
                Err(HistoryError::Cancelled) => return Err(RunError::Cancelled),
                Err(_) => {
                    // Any other derivation error with a
                    // live wait can only be the deadline
                    // expiring: the boundary is unknown
                    // and the wait times out below.
                    self.after_seq = 0;
                    self.boundary_known = false;
                    self.waiter.set_boundary(0, true, false);
                }
            }
        }
        let mut attempt: u32 = 0;
        while self.waiter.result().is_none() && Instant::now() < deadline && !self.user_stop() {
            if attempt > 0 {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let mut backoff = self.cfg.resub_pause;
                if self.failures > 0 {
                    let shift = (self.failures - 1).min(5);
                    backoff = self.cfg.resub_pause.saturating_mul(1u32 << shift);
                }
                if backoff > remaining {
                    backoff = remaining;
                }
                self.sleep_cancel(&cancel, backoff).await?;
                if self.waiter.result().is_some() || self.user_stop() || Instant::now() >= deadline
                {
                    break;
                }
            }
            attempt += 1;
            self.settle_tried = false;
            self.last_progress = Instant::now();
            self.online_armed = false;
            self.subscribe_once(&cancel, deadline).await?;
            if let Some(e) = self.pending_err.take() {
                return Err(e);
            }
            // Post-batch settle (redesign decision D3): a
            // subscribe iteration that delivered no record
            // must still re-prove a held terminal.
            // `try_settle` is a no-op when no terminal is
            // held, and the per-iteration throttle keeps a
            // record-fed attempt from being repeated at
            // this point in the same iteration.
            if self.waiter.result().is_none() && !self.settle_tried && Instant::now() < deadline {
                self.try_settle(&cancel).await?;
            }
            if let Some(e) = self.pending_err.take() {
                return Err(e);
            }
            if self.waiter.result().is_none() && !self.user_stop() && Instant::now() < deadline {
                if let Some(ce) = self.cfg.check_every
                    && Instant::now().saturating_duration_since(self.last_check) >= ce
                {
                    self.last_check = Instant::now();
                    self.check_state(&cancel).await?;
                }
            }
        }
        if let Some(e) = self.pending_err.take() {
            return Err(e);
        }
        if cancel.is_set() {
            return Err(RunError::Cancelled);
        }
        self.finish(&cancel).await
    }

    fn user_stop(&self) -> bool {
        self.cfg.user_stop.as_ref().is_some_and(|f| f())
    }

    /// Sleep for `d` on the monotonic clock, or until the
    /// wait is cancelled (Go `sleepCtx`).
    async fn sleep_cancel(&self, cancel: &Cancel, d: Duration) -> Result<(), RunError> {
        if d.is_zero() {
            return Ok(());
        }
        tokio::select! {
            () = tokio::time::sleep(d) => Ok(()),
            () = cancel.notified() => Err(RunError::Cancelled),
        }
    }

    /// Dial one fresh connection, subscribe, feed every
    /// captured record into the `Waiter` (the G6
    /// workaround: records are captured in `on_record`
    /// because `SubscribeRaw` discards them on error and
    /// conflates end reasons), and close the connection.
    /// A nil error means the subscription ended without a
    /// transport failure; the `Waiter` may still be
    /// waiting. (Go `runner.go` `subscribeOnce`.)
    ///
    /// The deadline is a parameter, not read from
    /// `self.deadline`: `run` computes it once and is the
    /// only caller, so there is no `expect()` on an
    /// internal field here (technical F10, fix loop 1).
    /// `self.deadline` still exists for the derivation
    /// and the endgame paths that need it after `run`
    /// returns the local.
    async fn subscribe_once(&mut self, cancel: &Cancel, deadline: Instant) -> Result<(), RunError> {
        let left = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_secs(1));
        let mut idle = left;
        if let Some(ra) = self.cfg.recheck_after
            && ra < idle
        {
            idle = ra;
        }
        let sub = match (self.dial)(cancel.clone()).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                // A Dial that returns a nil Subscriber
                // is a transport failure, never a panic.
                if cancel.is_set() {
                    return Err(RunError::Cancelled);
                }
                self.failures += 1;
                return self.note_failure(cancel).await;
            }
            Err(e) => {
                if cancel.is_set() {
                    return Err(RunError::Cancelled);
                }
                if is_auth_error(&e) {
                    return Err(RunError::Auth(e));
                }
                self.failures += 1;
                return self.note_failure(cancel).await;
            }
        };
        // Close is awaited, not deferred: Go defers it so
        // a panic in `SubscribeRaw` cannot skip it, but a
        // `Subscriber` MUST NOT panic (contract), and an
        // awaited close keeps the fake-subscriber `closed`
        // counts deterministic in tests. A panic would
        // unwind to the CLI boundary recover instead.
        let opts = SubscribeOptions {
            body: Some(self.subscribe_body()),
            max_records: 1_000_000_000,
            idle_timeout: idle,
            overall_timeout: left,
            ..Default::default()
        };
        let mut handler = RunnerHandler {
            runner: self,
            cancel: cancel.clone(),
        };
        let sub_err = sub
            .subscribe_raw("chat.subscribe", opts, &mut handler)
            .await;
        drop(handler);
        let _ = sub.close().await;
        match sub_err {
            Ok(_) => {
                self.failures = 0;
                self.first_failure_at = None;
                Ok(())
            }
            Err(e) => {
                if cancel.is_set() {
                    return Err(RunError::Cancelled);
                }
                if is_auth_error(&e) {
                    return Err(RunError::Auth(e));
                }
                self.failures += 1;
                self.note_failure(cancel).await
            }
        }
    }

    /// The subscribe body: `{"capabilities":
    /// ["chat_cancel", "delta_stream"]}` plus
    /// `session_id` iff the thread is non-empty (Go
    /// `runner.go` `subscribeBody`).
    fn subscribe_body(&self) -> Value {
        if self.cfg.thread.is_empty() {
            json!({"capabilities": ["chat_cancel", "delta_stream"]})
        } else {
            json!({"capabilities": ["chat_cancel", "delta_stream"], "session_id": self.cfg.thread})
        }
    }

    /// End the stream when the wait is decided, the
    /// caller stopped, the watchdog fired, the online
    /// grace expired, the safety-net cadence is due, or
    /// the caller's recheck callback fires (Go
    /// `shouldStop`).
    fn should_stop(&mut self, cancel: &Cancel) -> bool {
        if cancel.is_set()
            || self.user_stop()
            || self.waiter.result().is_some()
            || self.pending_err.is_some()
        {
            return true;
        }
        let now = Instant::now();
        if let Some(d) = self.deadline
            && now >= d
        {
            // The overall timeout: the gateway enforces
            // it for real subscriptions; a Subscriber
            // that blocks past it must still be ended
            // here.
            return true;
        }
        if let Some(recheck) = &self.cfg.recheck
            && recheck()
        {
            return true;
        }
        if let Some(ra) = self.cfg.recheck_after
            && now.saturating_duration_since(self.last_progress) > ra
        {
            return true;
        }
        if self.online_armed && now.saturating_duration_since(self.online_at) > DEFAULT_ONLINE_GRACE
        {
            self.online_armed = false;
            return true;
        }
        if let Some(ce) = self.cfg.check_every
            && now.saturating_duration_since(self.last_check) > ce
        {
            return true;
        }
        // Settle re-poll (redesign decision D3): end the
        // stream when a held terminal's proof is due, so
        // the loop re-proves it against history instead
        // of waiting for a new record, a count-0 event,
        // or a server replay. No terminal held, no proof
        // ever read, or an unknown boundary means no
        // re-poll: the cadence measures from the last
        // proof that read, never from the wait start.
        if self.waiter.ignored_terminal().is_some()
            && !self.waiter.boundary_unknown()
            && let Some(last) = self.last_settle_proof
            && self.cfg.settle_poll_interval > Duration::ZERO
            && now.saturating_duration_since(last) >= self.cfg.settle_poll_interval
        {
            return true;
        }
        false
    }

    /// Update the watchdog clock and the online-idle arm
    /// from one event. Scoped progress is an event whose
    /// name (`event`/`event_name` only, as in `cli.py`)
    /// starts with `delta.` / `task.` / `agent.` /
    /// `message.` and is in scope; keep-alives and
    /// other-thread records do not count (Go
    /// `noteProgress`).
    fn note_progress(&mut self, ev: &Value) {
        let name = record_name(ev);
        if name.starts_with("delta.")
            || name.starts_with("task.")
            || name.starts_with("agent.")
            || name.starts_with("message.")
        {
            if in_scope(ev, &self.cfg.thread) {
                self.last_progress = Instant::now();
            }
        }
        let p = payload(ev);
        let activity = p.get("activity_code").and_then(Value::as_str).unwrap_or("");
        let activity_present = p.get("activity_code").is_some_and(|v| !v.is_null());
        if name == "agent.status"
            && activity == "online"
            && self.waiter.seen_running()
            && in_scope(ev, &self.cfg.thread)
        {
            if !self.online_armed {
                self.online_armed = true;
                self.online_at = Instant::now();
            }
        } else if name == "delta.text_append"
            || name == "delta.message_start"
            || (name == "agent.status" && activity_present && activity != "online")
        {
            self.online_armed = false;
        }
    }

    /// Account one failed resubscribe. After
    /// `ReconnectBudget` of failures it runs one bounded
    /// state check instead of storming until the
    /// deadline, then resets the storm clock (Go
    /// `noteFailure`).
    async fn note_failure(&mut self, cancel: &Cancel) -> Result<(), RunError> {
        let now = Instant::now();
        match self.first_failure_at {
            None => {
                self.first_failure_at = Some(now);
                Ok(())
            }
            Some(first) => {
                if now.saturating_duration_since(first) > self.cfg.reconnect_budget {
                    self.first_failure_at = None;
                    self.check_state(cancel).await
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Attempt one history proof for the current ignored
    /// terminal, throttled to one attempt per terminal
    /// value per subscribe iteration. A failed read does
    /// NOT reset the throttle: the interval gate in
    /// `settle_pending` bounds retries, so a failing
    /// reader is re-proved at the cadence, not once per
    /// record. A FAILED terminal is proved by user-seq
    /// equality only (no replies are read); any other
    /// terminal is proved by replies.
    ///
    /// The throttle key is the terminal plus its ignored
    /// reason, not the terminal alone: when the reason
    /// clears (the F8 re-arm), the settle gates change,
    /// so the proof is re-attempted instead of waiting
    /// for a new terminal or a server check. (Go
    /// `trySettle`.)
    async fn try_settle(&mut self, cancel: &Cancel) -> Result<(), RunError> {
        let Some(ignored) = self.waiter.ignored_terminal().map(str::to_string) else {
            return Ok(());
        };
        let key = format!("{ignored}|{}", self.waiter.ignored_reason());
        if key != self.settle_key {
            self.settle_key = key;
            self.settle_tried = false;
        }
        if self.settle_tried {
            return Ok(());
        }
        self.settle_tried = true;
        match self.settle_pending(cancel, &ignored).await {
            Ok(()) => Ok(()),
            Err(RunError::HistoryRead(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Prove one captured pending terminal with fresh
    /// history reads, re-checking that the same terminal
    /// is still pending before applying. Returns
    /// `HistoryRead` when a history read fails, `Auth`
    /// when auth failed, `Cancelled` when the wait died
    /// before the proof was applied, or `Ok` when the
    /// proof was attempted (whether or not it accepted),
    /// skipped as gate-forbidden, or not started because
    /// the deadline passed. A successful proof is never
    /// applied after cancellation: the cancel check sits
    /// immediately before each apply site. (Go
    /// `settlePending`.)
    async fn settle_pending(&mut self, cancel: &Cancel, pending: &str) -> Result<(), RunError> {
        // No proof starts past the deadline (loop-2 F9;
        // the finish endgame is excepted — its reads run
        // after the deadline on floor budgets, by design).
        // A zero deadline means `run` never set one (a
        // direct call in tests): the guard does not fire.
        if let Some(d) = self.deadline
            && Instant::now() >= d
        {
            return Ok(());
        }
        // Interval gate (loop-2 F8): at most one proof
        // per `SettlePollInterval`, whatever the terminal
        // flapping or read failures do.
        if let Some(last) = self.last_settle_proof
            && Instant::now().saturating_duration_since(last) < self.cfg.settle_poll_interval
        {
            return Ok(());
        }
        // No history read is spent on a proof the gates
        // already forbid: with an unknown boundary neither
        // `Settle` nor `AcceptReplayedFailed` can accept,
        // so the attempt is evaluated and skipped.
        if self.waiter.boundary_unknown() {
            return Ok(());
        }
        // Stamp before reading: this proof counts against
        // the cadence whether it succeeds or fails. A
        // proof cut short by cancellation does not consume
        // cadence: the stamp is cleared on any return with
        // a dead wait, so a later live attempt is not
        // gated by a dead one.
        self.last_settle_proof = Some(Instant::now());
        let res = self.settle_pending_inner(cancel, pending).await;
        if cancel.is_set() {
            self.last_settle_proof = None;
        }
        res
    }

    async fn settle_pending_inner(
        &mut self,
        cancel: &Cancel,
        pending: &str,
    ) -> Result<(), RunError> {
        let budget = self.history_budget(HISTORY_READ_FLOOR, None);
        if is_failed_status(pending) {
            let (latest, found) = latest_user_seq(
                self.history.as_ref(),
                &self.cfg.history_limits,
                self.after_seq,
                cancel,
                budget,
            )
            .await
            .map_err(|e| map_history_err(e, cancel))?;
            if !found {
                return Ok(());
            }
            if cancel.is_set() {
                return Err(RunError::Cancelled);
            }
            if let Some(term) = self.waiter.ignored_terminal()
                && term == pending
                && self.waiter.result().is_none()
            {
                self.waiter.accept_replayed_failed(Some(latest));
            }
            return Ok(());
        }
        let (replies, _) = history_replies(
            self.history.as_ref(),
            &self.cfg.history_limits,
            self.after_seq,
            cancel,
            budget,
        )
        .await
        .map_err(|e| map_history_err(e, cancel))?;
        if cancel.is_set() {
            return Err(RunError::Cancelled);
        }
        if let Some(term) = self.waiter.ignored_terminal()
            && term == pending
            && self.waiter.result().is_none()
        {
            if self.waiter.settle(&replies).is_some() {
                self.proof_replies = replies;
            }
        }
        Ok(())
    }

    /// Read the turn state on its own short subscription
    /// (the server replays `task.status`), feed the last
    /// scoped `task.status` event, and settle it like a
    /// live one. A failed check is silent except for
    /// `Auth`, which propagates — and except for a
    /// transient history-read failure in the settle,
    /// which is swallowed exactly as `try_settle`
    /// swallows it. (Go `checkState`.)
    async fn check_state(&mut self, cancel: &Cancel) -> Result<(), RunError> {
        // No state check starts past the deadline
        // (loop-2 F9): `noteFailure` reaches here
        // unguarded, so the guard lives here.
        if let Some(d) = self.deadline
            && Instant::now() >= d
        {
            return Ok(());
        }
        let budget = self.cfg.state_check_budget;
        let child = Cancel::child_with_timeout(cancel, budget);
        let sub = match (self.dial)(child.clone()).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                // (nil, nil) — or a typed nil — from
                // Dial is a silent transport failure
                // here, as in `subscribe_once`.
                return Ok(());
            }
            Err(e) => {
                if is_auth_error(&e) {
                    return Err(RunError::Auth(e));
                }
                return Ok(());
            }
        };
        let mut handler = CheckHandler {
            found: Vec::new(),
            thread: self.cfg.thread.clone(),
            cancel: child.clone(),
        };
        let opts = SubscribeOptions {
            body: Some(self.subscribe_body()),
            max_records: 50,
            idle_timeout: budget,
            overall_timeout: budget,
            ..Default::default()
        };
        let sub_err = sub
            .subscribe_raw("chat.subscribe", opts, &mut handler)
            .await;
        let _ = sub.close().await;
        if let Err(e) = sub_err {
            if is_auth_error(&e) {
                return Err(RunError::Auth(e));
            }
            return Ok(());
        }
        if handler.found.is_empty() {
            return Ok(());
        }
        // `pop` takes the last collected event (Go:
        // `found[len(found)-1]`); the empty case returned
        // above, so this is always `Some`.
        let Some(ev) = handler.found.pop() else {
            return Ok(());
        };
        let running = task_status_info(&ev, &self.cfg.thread)
            .is_some_and(|info| info.status == "running" && info.root_confirmed);
        if self.waiter.result().is_none() {
            let approver = self.cfg.approver.clone();
            self.waiter.feed(&ev, approver.as_deref()).await;
            if let Some(fatal) = self.waiter.fatal_err() {
                return Err(RunError::ApproverFatal(fatal.clone()));
            }
        }
        if running {
            self.last_progress = Instant::now();
        }
        let Some(pending) = self.waiter.ignored_terminal().map(str::to_string) else {
            return Ok(());
        };
        if self.waiter.result().is_some() {
            return Ok(());
        }
        // The settle uses the run cancel, not the
        // state-check budget cancel (Go: `settlePending`
        // takes `ctx`, not `cctx`).
        match self.settle_pending(cancel, &pending).await {
            Ok(()) => Ok(()),
            Err(RunError::HistoryRead(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Bound one history read: at least `floor`, and at
    /// most the remaining deadline, optionally capped
    /// (lag polls). (Go `historyCtx`.)
    fn history_budget(&self, floor: Duration, cap: Option<Duration>) -> Duration {
        let mut budget = floor;
        if let Some(d) = self.deadline {
            let remaining = d.saturating_duration_since(Instant::now());
            if remaining > budget {
                budget = remaining;
            }
        }
        if let Some(c) = cap {
            let capped = c.max(HISTORY_READ_FLOOR);
            if budget > capped {
                budget = capped;
            }
        }
        budget
    }

    /// Run the endgame in order: last-chance FAILED
    /// proof, final history read (two attempts), lag
    /// window, endgame reconciliation against the settle
    /// proof and the awaited turn, fail-closed 124,
    /// boundary suppression, then the result object.
    /// (Go `runner.go` `finish`.)
    async fn finish(&mut self, cancel: &Cancel) -> Result<WaitResult, RunError> {
        let mut kind = WaitKind::Timeout;
        let mut detail = String::new();
        if let Some(out) = self.waiter.result() {
            kind = out.kind;
            detail = out.detail.clone();
        } else if let Some(status) = self.waiter.status() {
            detail = status.to_string();
        }
        if kind == WaitKind::Timeout {
            // The last-chance proof spends no read while
            // the boundary is unknown: `AcceptReplayedFailed`
            // refuses on an unknown boundary, so the read
            // could never accept.
            if let Some(ignored) = self.waiter.ignored_terminal()
                && is_failed_status(ignored)
                && !self.waiter.boundary_unknown()
            {
                let budget = self.history_budget(self.cfg.final_read_floor, None);
                match latest_user_seq(
                    self.history.as_ref(),
                    &self.cfg.history_limits,
                    self.after_seq,
                    cancel,
                    budget,
                )
                .await
                {
                    Ok((latest, found)) => {
                        if found
                            && let Some(accepted) = self.waiter.accept_replayed_failed(Some(latest))
                        {
                            kind = WaitKind::Failed;
                            detail = accepted.detail.clone();
                        }
                    }
                    Err(e) => {
                        let mapped = map_history_err(e, cancel);
                        match mapped {
                            RunError::Cancelled => return Err(RunError::Cancelled),
                            RunError::Auth(_) => return Err(mapped),
                            _ => {
                                // A read failure leaves the
                                // timeout standing.
                            }
                        }
                    }
                }
            }
        }
        let mut replies: Vec<Reply> = Vec::new();
        let mut final_read_failed = false;
        let mut final_exhausted = false;
        for _attempt in 0..2 {
            let budget = self.history_budget(self.cfg.final_read_floor, None);
            match history_replies(
                self.history.as_ref(),
                &self.cfg.history_limits,
                self.after_seq,
                cancel,
                budget,
            )
            .await
            {
                Ok((rs, exhausted)) => {
                    // A read that succeeded after
                    // cancellation must not become a
                    // result: the wait is dead, whatever
                    // the reader returned.
                    if cancel.is_set() {
                        return Err(RunError::Cancelled);
                    }
                    replies = rs;
                    final_exhausted = exhausted;
                    final_read_failed = false;
                    break;
                }
                Err(e) => {
                    let mapped = map_history_err(e, cancel);
                    match mapped {
                        RunError::Cancelled => return Err(RunError::Cancelled),
                        RunError::Auth(_) => return Err(mapped),
                        _ => {
                            final_read_failed = true;
                        }
                    }
                }
            }
        }
        if !final_read_failed && kind == WaitKind::Done && replies.is_empty() {
            let lag_until = Instant::now() + self.cfg.lag_window;
            while Instant::now() < lag_until {
                let remaining = lag_until.saturating_duration_since(Instant::now());
                let poll = self.cfg.lag_poll.min(remaining);
                self.sleep_cancel(cancel, poll).await?;
                if remaining.is_zero() || cancel.is_set() {
                    break;
                }
                let cap_dur = remaining;
                let budget = self.history_budget(HISTORY_READ_FLOOR, Some(cap_dur));
                match history_replies(
                    self.history.as_ref(),
                    &self.cfg.history_limits,
                    self.after_seq,
                    cancel,
                    budget,
                )
                .await
                {
                    Ok((rs, _)) => {
                        replies = rs;
                        if !replies.is_empty() {
                            break;
                        }
                    }
                    Err(e) => {
                        let mapped = map_history_err(e, cancel);
                        match mapped {
                            RunError::Cancelled => return Err(RunError::Cancelled),
                            RunError::Auth(_) => return Err(mapped),
                            _ => {
                                // A transient poll failure
                                // no longer ends the window:
                                // keep polling until it
                                // expires.
                            }
                        }
                    }
                }
            }
            if cancel.is_set() {
                return Err(RunError::Cancelled);
            }
        }
        // Endgame reconciliation (loop-2 F3/F4): the
        // final read must agree with the settle proof and
        // with the awaited turn.
        let mut reconcile_note = String::new();
        if !final_read_failed
            && !self.waiter.boundary_unknown()
            && (!replies.is_empty() || !self.proof_replies.is_empty())
        {
            let mut newest_user: i64 = 0;
            let mut have_newest_user = false;
            let budget = self.history_budget(HISTORY_READ_FLOOR, None);
            match latest_user_seq(
                self.history.as_ref(),
                &self.cfg.history_limits,
                self.after_seq,
                cancel,
                budget,
            )
            .await
            {
                Ok((latest, found)) => {
                    if found {
                        newest_user = latest;
                        have_newest_user = true;
                    }
                }
                Err(e) => {
                    let mapped = map_history_err(e, cancel);
                    match mapped {
                        RunError::Cancelled => return Err(RunError::Cancelled),
                        RunError::Auth(_) => return Err(mapped),
                        _ => {
                            // Best effort on a transport
                            // failure: the reads stand
                            // unverified.
                        }
                    }
                }
            }
            let within_turn = |rs: Vec<Reply>| -> Vec<Reply> {
                if !have_newest_user || newest_user <= self.after_seq {
                    return rs;
                }
                rs.into_iter().filter(|rp| rp.seq <= newest_user).collect()
            };
            let mut excluded_follow_up = false;
            if !replies.is_empty() {
                let original_len = replies.len();
                let filtered = within_turn(std::mem::take(&mut replies));
                excluded_follow_up = filtered.len() < original_len;
                replies = filtered;
            }
            let mut restored_any = false;
            if !self.proof_replies.is_empty() {
                let proof_copy = self.proof_replies.clone();
                let mut missing: Vec<Reply> = Vec::new();
                for rp in within_turn(proof_copy) {
                    let present = replies
                        .iter()
                        .any(|kept| kept.seq == rp.seq && kept.message_id == rp.message_id);
                    if !present {
                        missing.push(rp);
                    }
                }
                if !missing.is_empty() {
                    replies.append(&mut missing);
                    replies.sort_by_key(|r| r.seq);
                    restored_any = true;
                }
            }
            if restored_any {
                reconcile_note =
                    "final read missed the settle proof reply; reporting the proof reply"
                        .to_string();
            } else if excluded_follow_up {
                reconcile_note = "replies after a newer user message were excluded".to_string();
            }
        }
        if final_read_failed && kind == WaitKind::Done {
            kind = WaitKind::Timeout;
            detail = self.waiter.status().unwrap_or("").to_string();
        }
        let mut note = String::new();
        if final_exhausted && !self.waiter.boundary_unknown() {
            // Window exhaustion is visible, never silent.
            let largest = self.cfg.history_limits.last().copied().unwrap_or(0);
            note = format!(
                "history window exhausted at {largest} events; older replies may be missed; run `castctl wait` again"
            );
        }
        if self.waiter.boundary_unknown() {
            replies = Vec::new();
            note = "turn-end boundary unknown: history could not be read, so no replies are reported; run `castctl wait` again"
                .to_string();
        }
        if final_read_failed {
            // The final-read note wins over the boundary
            // note, as in the Python result construction.
            note = "could not read the final replies; run `castctl wait` again".to_string();
        }
        if !reconcile_note.is_empty() && !final_read_failed && !self.waiter.boundary_unknown() {
            // Reconciliation is more specific than
            // exhaustion: the proof/follow-up note wins
            // over the window note, but never over the
            // boundary/final-read notes above.
            note = reconcile_note;
        }
        if kind == WaitKind::Approval {
            // An approval `Outcome` carries no detail; the
            // status is the `Waiter`'s last stored status.
            if let Some(status) = self.waiter.status() {
                detail = status.to_string();
            }
        }
        let outcome = outcome_of(kind, &replies).to_string();
        let mut res = WaitResult {
            kind,
            outcome: outcome.clone(),
            status: detail,
            after_seq: self.after_seq,
            final_text: String::new(),
            replies,
            final_read_failed,
            note,
            approvals: Vec::new(),
            needs_input_reason: String::new(),
            question: String::new(),
            exit_code: 0,
            node_id: self.cfg.node_id.clone(),
            auto_approved: self.waiter.approved_records().to_vec(),
            auto_approve_errors: self.waiter.approve_errors().to_vec(),
        };
        res.exit_code = exit_code(kind, &res.replies);
        if !res.replies.is_empty() {
            res.final_text = res.replies[res.replies.len() - 1].text.clone();
        }
        if let Some(out) = self.waiter.result()
            && out.kind == WaitKind::Approval
        {
            res.approvals = out.approvals.clone();
        }
        if outcome == "needs_input" && !res.replies.is_empty() {
            let last = &res.replies[res.replies.len() - 1];
            if !last.widgets.is_empty() {
                res.needs_input_reason = "widget".to_string();
            } else {
                res.needs_input_reason = needs_input_reason(&last.text);
            }
            res.question = question_of(&last.text);
        }
        // Final guard: this check is the linearization
        // point of the endgame.
        if let Some(hook) = self.cfg.before_final_guard.clone() {
            hook(cancel.clone());
        }
        if cancel.is_set() {
            return Err(RunError::Cancelled);
        }
        Ok(res)
    }
}

/// Parse one NDJSON record and feed it to the `Waiter`
/// (Go `Waiter.FeedRecord`, `internal/wait/waiter.go:671`):
/// unparseable input and non-object JSON change no state
/// and return `None`, as in Go; decoding is
/// `decode_record`'s job, this function only feeds the
/// decoded event. It has no production caller in Go
/// either — the Runner inlines decode+feed — and none
/// here; it exists so the ported API surface is complete
/// (technical F1, fix loop 1).
pub async fn feed_record(
    waiter: &mut Waiter,
    approver: Option<&dyn WaitApprover>,
    record: &[u8],
) -> Option<Outcome> {
    let ev = decode_record(record)?;
    waiter.feed(&ev, approver).await
}

/// The `SubscribeHandler` the Runner feeds records
/// through: `on_record` decodes, feeds the `Waiter`,
/// runs the `OnEvent` callback, updates progress, and
/// tries a settle proof (Go `onRecord`).
struct RunnerHandler<'a> {
    runner: &'a mut Runner,
    cancel: Cancel,
}

impl SubscribeHandler for RunnerHandler<'_> {
    fn on_open(&mut self) {
        // Go's Runner sets no `OnOpen`.
    }

    fn should_stop(&mut self) -> bool {
        self.runner.should_stop(&self.cancel)
    }

    fn on_record<'a>(
        &'a mut self,
        record: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            if self.runner.waiter.result().is_some() {
                return true;
            }
            let Some(ev) = decode_record(record) else {
                return false;
            };
            let approver = self.runner.cfg.approver.clone();
            self.runner.waiter.feed(&ev, approver.as_deref()).await;
            if let Some(fatal) = self.runner.waiter.fatal_err() {
                self.runner.pending_err = Some(RunError::ApproverFatal(fatal.clone()));
                return true;
            }
            if let Some(on_event) = self.runner.cfg.on_event.clone() {
                on_event(&ev);
            }
            if self.runner.waiter.result().is_some() {
                return true;
            }
            self.runner.note_progress(&ev);
            if let Err(e) = self.runner.try_settle(&self.cancel).await {
                self.runner.pending_err = Some(e);
                return true;
            }
            if self.runner.waiter.result().is_some() {
                return true;
            }
            false
        })
    }
}

/// The `SubscribeHandler` a state check collects through:
/// every decodable record with a usable `task.status`
/// is kept; the Runner feeds only the last one (Go
/// `checkState` `OnRecord`).
struct CheckHandler {
    found: Vec<Value>,
    thread: String,
    cancel: Cancel,
}

impl SubscribeHandler for CheckHandler {
    fn on_open(&mut self) {}

    fn should_stop(&mut self) -> bool {
        self.cancel.is_set()
    }

    fn on_record<'a>(
        &'a mut self,
        record: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        let ev = decode_record(record);
        let thread = self.thread.clone();
        let found = &mut self.found;
        Box::pin(async move {
            if let Some(ev) = ev
                && task_status_info(&ev, &thread).is_some()
            {
                found.push(ev);
            }
            false
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AutoApproverAdapter;
    use crate::history::tests::{HistoryResp, ScriptHistory, history_ok, user_ev};
    use castctl_approvals::{AutoApprover, Decider, DescribedApproval};
    use castctl_telegram::wait::replies_after;
    use serde_json::json;
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration as StdDuration;

    // -- event builders (Go waiter_test.go helpers) --

    fn task_ev(status: &str, root: &str, agent: &str, seq: i64, count: Option<Value>) -> Value {
        let mut p = json!({
            "status": status,
            "root_agent_id": root,
            "agent_id": agent,
        });
        if let Some(c) = count {
            p["active_subagent_count"] = c;
        }
        json!({"event_name": "task.status", "seq": seq, "payload": p})
    }

    // Go `waiter_test.go` `appr`: only the id plus
    // `decision_options` (one `{"kind": o}` per option).
    // The approver reads the forever option from
    // `decision_options`; any other shape (title/question/
    // `options`) is ignored by `describe_approval`.
    fn appr(id: &str, opts: &[&str]) -> Value {
        let mut m = json!({"approval_id": id});
        if !opts.is_empty() {
            m["decision_options"] =
                json!(opts.iter().map(|o| json!({"kind": o})).collect::<Vec<_>>());
        }
        m
    }

    // Go `waiter_test.go` `approvalEv`: the event name is
    // `"approvals.snapshot"` (key `"event"`). The
    // waiter's `pending_approvals` only accepts names
    // starting with `"approvals"`; `"egress.approvals"`
    // is the gateway RPC method name, NOT an event name,
    // and was silently ignored (all approval tests timed
    // out with kind Timeout instead of Approval).
    fn approval_ev(pending: Vec<Value>, recent: Option<Vec<Value>>) -> Value {
        let mut p = json!({"pending_approvals": pending});
        if let Some(r) = recent {
            p["recent_approvals"] = serde_json::Value::Array(r);
        }
        json!({"event": "approvals.snapshot", "payload": p})
    }

    fn asst(seq: i64, status: &str, text: &str, extra: Option<Value>) -> Value {
        // Go `replies_test.go` `asst`: payload is status +
        // display_text + the extras merged in.
        let mut p = json!({"status": status});
        if !text.is_empty() {
            p["display_text"] = json!(text);
        }
        if let Some(Value::Object(extra)) = extra {
            let obj = p.as_object_mut().expect("object literal");
            for (k, v) in extra {
                obj.insert(k, v);
            }
        }
        json!({"event_name": "message.assistant", "seq": seq, "payload": p})
    }

    fn record_json(ev: &Value) -> Vec<u8> {
        serde_json::to_vec(ev).expect("test event must serialise")
    }

    // -- QueueHistory (Go queueHistory: call-order script, repeats last) --

    struct QueueHistory {
        resps: StdMutex<VecDeque<HistoryResp>>,
        calls: StdMutex<usize>,
    }

    impl QueueHistory {
        fn new(resps: Vec<HistoryResp>) -> Self {
            Self {
                resps: StdMutex::new(resps.into()),
                calls: StdMutex::new(0),
            }
        }
        fn calls(&self) -> usize {
            *self.calls.lock().expect("lock")
        }
    }

    impl HistoryReader for QueueHistory {
        fn read_history(
            &self,
            _limit: usize,
            _cancel: &Cancel,
        ) -> Pin<Box<dyn Future<Output = Result<(Vec<Value>, bool), TransportError>> + Send + '_>>
        {
            let mut resps = self.resps.lock().expect("lock");
            *self.calls.lock().expect("lock") += 1;
            let resp = if resps.len() > 1 {
                resps.pop_front().expect("queue non-empty")
            } else {
                resps.front().expect("queue non-empty").clone()
            };
            Box::pin(async move {
                match resp.err {
                    Some(e) => Err(e),
                    None => Ok((resp.events, resp.has_more)),
                }
            })
        }
    }

    // -- FakeSubscriber (Go fakeSubscriber) --

    struct FakeSubscriber {
        loop_script: StdMutex<VecDeque<Vec<u8>>>,
        /// Check records, replayed verbatim on every check
        /// subscribe (Go's fakeSubscriber never consumes it).
        check_script: Vec<Vec<u8>>,
        block: bool,
        loop_err: StdMutex<Option<TransportError>>,
        loop_err_repeat: bool,
        /// Dial-time failure (Go `fakeSubscriber.dialErr`).
        dial_err: StdMutex<Option<TransportError>>,
        calls: StdMutex<usize>,
        check_calls: StdMutex<usize>,
        closed: StdMutex<usize>,
        loop_opts: StdMutex<Option<SubscribeOptions>>,
        check_opts: StdMutex<Option<SubscribeOptions>>,
    }

    impl FakeSubscriber {
        fn new(loop_script: Vec<Vec<u8>>) -> Self {
            Self {
                loop_script: StdMutex::new(loop_script.into()),
                check_script: Vec::new(),
                block: false,
                loop_err: StdMutex::new(None),
                loop_err_repeat: false,
                dial_err: StdMutex::new(None),
                calls: StdMutex::new(0),
                check_calls: StdMutex::new(0),
                closed: StdMutex::new(0),
                loop_opts: StdMutex::new(None),
                check_opts: StdMutex::new(None),
            }
        }
        fn calls(&self) -> usize {
            *self.calls.lock().expect("lock")
        }
        fn check_calls(&self) -> usize {
            *self.check_calls.lock().expect("lock")
        }
        fn closed(&self) -> usize {
            *self.closed.lock().expect("lock")
        }
        fn dial(self: &Arc<Self>) -> DialFn {
            let sub = Arc::clone(self);
            Arc::new(move |_cancel: Cancel| {
                let sub = Arc::clone(&sub);
                Box::pin(async move {
                    if let Some(e) = sub.dial_err.lock().expect("lock").clone() {
                        return Err(e);
                    }
                    Ok(Some(sub as Arc<dyn Subscriber>))
                })
            })
        }

        /// A dial that serves a different fake subscriber
        /// per call, repeating the last (Go's per-dial
        /// `scripts` closure in `TestRunnerDecideNeverRetried`).
        fn dial_script(subs: Vec<Arc<FakeSubscriber>>) -> DialFn {
            let queue = Arc::new(StdMutex::new(VecDeque::from(subs)));
            Arc::new(move |_cancel: Cancel| {
                let queue = Arc::clone(&queue);
                Box::pin(async move {
                    let mut q = queue.lock().expect("lock");
                    if q.len() > 1 {
                        let sub = q.pop_front().expect("queue non-empty");
                        Ok(Some(sub as Arc<dyn Subscriber>))
                    } else {
                        let sub = q.front().expect("queue non-empty").clone();
                        Ok(Some(sub as Arc<dyn Subscriber>))
                    }
                })
            })
        }
    }

    impl Subscriber for FakeSubscriber {
        fn subscribe_raw<'a>(
            &'a self,
            _method: &'a str,
            opts: SubscribeOptions,
            handler: &'a mut dyn SubscribeHandler,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Vec<u8>>, TransportError>> + Send + 'a>>
        {
            let is_check = opts.max_records == 50;
            if is_check {
                *self.check_calls.lock().expect("lock") += 1;
                *self.check_opts.lock().expect("lock") = Some(opts.clone());
                let records = self.check_script.clone();
                Box::pin(async move {
                    for rec in &records {
                        if handler.on_record(rec).await {
                            break;
                        }
                    }
                    Ok(Vec::new())
                })
            } else {
                *self.calls.lock().expect("lock") += 1;
                *self.loop_opts.lock().expect("lock") = Some(opts.clone());
                let err = {
                    let mut slot = self.loop_err.lock().expect("lock");
                    if self.loop_err_repeat {
                        slot.clone()
                    } else {
                        slot.take()
                    }
                };
                if let Some(e) = err {
                    return Box::pin(async move { Err(e) });
                }
                let records: Vec<Vec<u8>> = {
                    let mut script = self.loop_script.lock().expect("lock");
                    std::mem::take(&mut *script).into_iter().collect()
                };
                let block = self.block;
                Box::pin(async move {
                    let mut out = Vec::new();
                    for rec in &records {
                        out.push(rec.clone());
                        if handler.on_record(rec).await {
                            return Ok(out);
                        }
                    }
                    if block {
                        loop {
                            if handler.should_stop() {
                                return Ok(out);
                            }
                            tokio::time::sleep(StdDuration::from_millis(10)).await;
                        }
                    }
                    Ok(out)
                })
            }
        }

        fn close(&self) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
            *self.closed.lock().expect("lock") += 1;
            Box::pin(async { Ok(()) })
        }
    }

    // -- run driver (Go runRunner + synctest) --
    //
    // Paused-time tests spawn the run, then advance the
    // clock in 100 ms steps until the run finishes; a
    // 3600 s budget guards a runaway.

    /// A `ConnectFn` that always connects and delegates
    /// every decide to `decide` (Go `approvals_test.go`
    /// `connect_ok`).
    fn connect_ok(decide: Arc<Decider>) -> Box<castctl_approvals::ConnectFn> {
        Box::new(move || {
            let d = Arc::clone(&decide);
            let decider: Box<Decider> = Box::new(move |a, decision| d(a, decision));
            Ok((decider, Box::new(|| {}) as Box<dyn FnOnce() + Send>))
        })
    }

    async fn drive<T: Send + 'static>(handle: tokio::task::JoinHandle<T>) -> T {
        let mut advanced = StdDuration::ZERO;
        loop {
            if handle.is_finished() {
                break;
            }
            tokio::time::advance(StdDuration::from_millis(100)).await;
            tokio::task::yield_now().await;
            advanced += StdDuration::from_millis(100);
            assert!(
                advanced < StdDuration::from_secs(3600),
                "runaway: run did not finish within 3600s of virtual time"
            );
        }
        handle.await.expect("run task must not panic")
    }

    async fn run_runner(cfg: Config) -> WaitResult {
        let mut runner = Runner::new(cfg).expect("test config must build");
        let cancel = Cancel::new();
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        outcome.expect("run must succeed")
    }

    fn default_config() -> Config {
        Config {
            timeout: StdDuration::from_secs(600),
            recheck_after: Some(StdDuration::from_secs(20)),
            check_every: Some(StdDuration::from_secs(60)),
            ..Config::default()
        }
    }

    // -- runner_test.go (36 fns; TestIsNilSubscriber has no
    // Rust equivalent — no reflection nil-interface — and is
    // recorded as not ported) --

    #[tokio::test(start_paused = true)]
    async fn runner_live_done() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let res = run_runner(Config {
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.after_seq, 100);
        assert!(res.replies.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn runner_on_event_sees_stream_records_in_order() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let seen: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let seen2 = Arc::clone(&seen);
        let cfg = Config {
            dial: Some(sub.dial()),
            history: Some(hist),
            on_event: Some(Arc::new(move |ev: &Value| {
                let name = ev
                    .get("event_name")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
                    .to_string();
                seen2.lock().expect("lock").push(name);
            })),
            ..default_config()
        };
        let res = run_runner(cfg).await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(
            *seen.lock().expect("lock"),
            vec!["task.status".to_string(), "task.status".to_string()]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_replay_settle() {
        // The completed record alone (no running seen)
        // holds the terminal; the settle read proves it
        // from history.
        let sub = Arc::new(FakeSubscriber::new(vec![record_json(&task_ev(
            "completed",
            "R",
            "R",
            180,
            None,
        ))]));
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(100)]),
            history_ok(vec![
                user_ev(100),
                asst(150, "completed", "settled reply", None),
            ]),
            history_ok(vec![
                user_ev(100),
                asst(150, "completed", "settled reply", None),
            ]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.final_text, "settled reply");
    }

    #[tokio::test(start_paused = true)]
    async fn runner_replay_failed_accept() {
        // The interrupted record alone holds the terminal;
        // the derived boundary (200) equals the latest user
        // seq, so the replayed failure is accepted — with
        // zero replies, like a cancelled turn.
        let sub = Arc::new(FakeSubscriber::new(vec![record_json(&task_ev(
            "interrupted",
            "R",
            "R",
            180,
            None,
        ))]));
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(200)]),
            history_ok(vec![user_ev(200)]),
            history_ok(vec![user_ev(200)]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Failed);
        assert_eq!(res.outcome, "failed");
        assert_eq!(res.exit_code, 2);
        assert!(res.replies.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn runner_timeout_124() {
        let sub = Arc::new(FakeSubscriber::new(vec![record_json(&task_ev(
            "running", "R", "R", 100, None,
        ))]));
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(100)]),
            history_ok(vec![user_ev(100)]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(5),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
        assert_eq!(res.outcome, "timeout");
        assert!(
            sub.calls() >= 2,
            "subscribe calls = {}, want resubscribes until the deadline",
            sub.calls()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_fail_closed_124() {
        // The turn decides Done from the stream, but both
        // final-read attempts fail: the result is a
        // timeout with the final-read note, never a Done
        // built on unread replies.
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let err_resp = || HistoryResp {
            events: Vec::new(),
            has_more: false,
            err: Some(TransportError::ConnectionError {
                message: "transport down".to_string(),
            }),
        };
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(100)]),
            err_resp(),
            err_resp(),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
        assert!(res.final_read_failed);
        assert_eq!(
            res.note,
            "could not read the final replies; run `castctl wait` again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_boundary_unknown_suppresses_replies() {
        // Derivation fails on every window (6 attempts: 3
        // windows x 2), then the final read succeeds. The
        // approval result keeps its kind; replies are
        // suppressed with the boundary note.
        let sub = Arc::new(FakeSubscriber::new(vec![record_json(&approval_ev(
            vec![appr("A", &["allow_always"])],
            None,
        ))]));
        let err_resp = || HistoryResp {
            events: Vec::new(),
            has_more: false,
            err: Some(TransportError::ConnectionError {
                message: "transport down".to_string(),
            }),
        };
        let hist = Arc::new(QueueHistory::new(vec![
            err_resp(),
            err_resp(),
            err_resp(),
            err_resp(),
            err_resp(),
            err_resp(),
            history_ok(vec![user_ev(100), asst(150, "completed", "stale?", None)]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Approval);
        assert_eq!(res.exit_code, 4);
        assert!(res.replies.is_empty());
        assert_eq!(
            res.note,
            "turn-end boundary unknown: history could not be read, so no replies are reported; run `castctl wait` again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_watchdog_ends_deaf_stream() {
        let mut sub = FakeSubscriber::new(vec![record_json(&json!({
            "event": "sessions.updated",
            "payload": {},
        }))]);
        sub.block = true;
        let sub = Arc::new(sub);
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            recheck_after: Some(StdDuration::from_secs(20)),
            check_every: None,
            dial: Some(sub.dial()),
            history: Some(Arc::clone(&hist) as Arc<dyn HistoryReader>),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert!(
            sub.calls() >= 2,
            "subscribe calls = {}, want the watchdog to end the deaf stream and resubscribe",
            sub.calls()
        );
        assert_eq!(hist.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn runner_online_grace_forces_recheck() {
        let mut sub = FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&json!({
                "event_name": "agent.status",
                "payload": {"activity_code": "online"},
            })),
        ]);
        sub.block = true;
        let sub = Arc::new(sub);
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(30),
            recheck_after: None,
            check_every: None,
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert!(
            sub.calls() >= 2,
            "subscribe calls = {}, want the online grace to end the stream",
            sub.calls()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_auth_error_propagates() {
        // The dial itself fails with auth: the error
        // propagates at once, never a timeout.
        let sub = Arc::new(FakeSubscriber::new(vec![]));
        *sub.dial_err.lock().expect("lock") = Some(TransportError::Auth {
            message: "expired".to_string(),
        });
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .expect("config");
        let cancel = Cancel::new();
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        assert!(
            matches!(outcome, Err(RunError::Auth(TransportError::Auth { .. }))),
            "outcome = {outcome:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_auth_error_in_final_read_propagates() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(100)]),
            HistoryResp {
                events: Vec::new(),
                has_more: false,
                err: Some(TransportError::Auth {
                    message: "expired".to_string(),
                }),
            },
        ]));
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(120),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .expect("config");
        let cancel = Cancel::new();
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        assert!(
            matches!(outcome, Err(RunError::Auth(TransportError::Auth { .. }))),
            "outcome = {outcome:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_decide_never_retried() {
        // A approves forever; B offers only allow_once
        // with the fallback off, so it is skipped and left
        // for a human. The expired snapshot is dropped
        // before the approver runs at all (the approver's
        // expiry check uses wall time: OLD expired at
        // epoch 1ms).
        let mut expired = appr("OLD", &["allow_always"]);
        expired["request_expires_at_ms"] = json!(1.0);
        let first = Arc::new(FakeSubscriber::new(vec![record_json(&approval_ev(
            vec![expired],
            None,
        ))]));
        let second = Arc::new(FakeSubscriber::new(vec![record_json(&approval_ev(
            vec![appr("A", &["allow_always"]), appr("B", &["allow_once"])],
            None,
        ))]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let decides: Arc<StdMutex<usize>> = Arc::new(StdMutex::new(0));
        let decides2 = Arc::clone(&decides);
        let decider: Arc<Decider> = Arc::new(move |_a: &DescribedApproval, _d: &str| {
            *decides2.lock().expect("lock") += 1;
            Ok(())
        });
        let approver = Arc::new(AutoApprover::new(Some(connect_ok(decider)), false));
        let adapter = Arc::new(AutoApproverAdapter::new(&approver));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(FakeSubscriber::dial_script(vec![first, second])),
            history: Some(hist),
            approver: Some(adapter),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Approval);
        assert_eq!(res.exit_code, 4);
        assert_eq!(res.approvals.len(), 1);
        assert_eq!(res.approvals[0].id, "B");
        assert_eq!(*decides.lock().expect("lock"), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn runner_safety_net_check_settles() {
        let mut sub = FakeSubscriber::new(vec![]);
        sub.check_script = vec![record_json(&task_ev("completed", "R", "R", 180, None))];
        let sub = Arc::new(sub);
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(100)]),
            history_ok(vec![user_ev(100), asst(150, "completed", "checked", None)]),
            history_ok(vec![user_ev(100), asst(150, "completed", "checked", None)]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(130),
            recheck_after: Some(StdDuration::from_secs(20)),
            check_every: Some(StdDuration::from_secs(60)),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.final_text, "checked");
        assert!(
            sub.check_calls() >= 1,
            "check_calls = {}",
            sub.check_calls()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_stream_seq_never_ratchets_boundary() {
        // Boundary unknown (history always fails), then a
        // live root running carries stream seq 300. The
        // stream seq must NEVER become the history
        // boundary: the turn decides Done on the proven
        // terminal, but the reply in the final read is
        // suppressed with the boundary-unknown note and
        // AfterSeq stays 0.
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 300, None)),
            record_json(&task_ev("completed", "R", "R", 400, None)),
        ]));
        let err_resp = || HistoryResp {
            events: Vec::new(),
            has_more: false,
            err: Some(TransportError::ConnectionError {
                message: "transport down".to_string(),
            }),
        };
        let hist = Arc::new(QueueHistory::new(vec![
            err_resp(),
            err_resp(),
            err_resp(),
            err_resp(),
            err_resp(),
            err_resp(),
            history_ok(vec![
                user_ev(300),
                asst(350, "completed", "ratcheted", None),
            ]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.after_seq, 0);
        assert_eq!(res.final_text, "");
        assert!(res.replies.is_empty());
        assert_eq!(
            res.note,
            "turn-end boundary unknown: history could not be read, so no replies are reported; run `castctl wait` again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_lag_window() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        // Final read: first two attempts return no replies
        // (the done read + the lag polls use the same
        // queue; the third response carries the late
        // reply).
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(100)]),
            history_ok(vec![user_ev(100)]),
            history_ok(vec![user_ev(100)]),
            history_ok(vec![
                user_ev(100),
                asst(190, "completed", "late reply", None),
            ]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            lag_window: StdDuration::from_secs(2),
            lag_poll: StdDuration::from_millis(250),
            dial: Some(sub.dial()),
            history: Some(Arc::clone(&hist) as Arc<dyn HistoryReader>),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.final_text, "late reply");
        // Five reads, not four: boundary derivation (1)
        // + final read (1) + lag polls (2: empty, then
        // the late reply) + endgame reconciliation
        // `LatestUserSeq` (1, Go `runner.go:1107` —
        // it runs whenever there is something to
        // reconcile). Go's test asserts no count; the
        // writer's 4 forgot the reconciliation read.
        assert_eq!(hist.calls(), 5);
    }

    struct CancelPollHistory {
        cancel: Cancel,
        calls: StdMutex<usize>,
    }

    impl HistoryReader for CancelPollHistory {
        fn read_history(
            &self,
            _limit: usize,
            _cancel: &Cancel,
        ) -> Pin<Box<dyn Future<Output = Result<(Vec<Value>, bool), TransportError>> + Send + '_>>
        {
            let mut calls = self.calls.lock().expect("lock");
            *calls += 1;
            if *calls <= 2 {
                return Box::pin(async { Ok((vec![user_ev(100)], false)) });
            }
            let cancel = self.cancel.clone();
            Box::pin(async move {
                cancel.notified().await;
                Err(TransportError::ConnectionError {
                    message: "context canceled".to_string(),
                })
            })
        }
    }

    // Go `cancelOnReadHistory`: cancels the run context on
    // the `cancel_at`-th call and returns the configured
    // events, or the configured error on every call when
    // one is set.
    struct CancelOnReadHistory {
        cancel: Cancel,
        cancel_at: usize,
        events: Vec<Value>,
        err: Option<TransportError>,
        calls: StdMutex<usize>,
    }

    impl HistoryReader for CancelOnReadHistory {
        fn read_history(
            &self,
            _limit: usize,
            _cancel: &Cancel,
        ) -> Pin<Box<dyn Future<Output = Result<(Vec<Value>, bool), TransportError>> + Send + '_>>
        {
            let mut calls = self.calls.lock().expect("lock");
            *calls += 1;
            if *calls == self.cancel_at {
                self.cancel.set();
            }
            let events = self.events.clone();
            let err = self.err.clone();
            Box::pin(async move {
                match err {
                    Some(e) => Err(e),
                    None => Ok((events, false)),
                }
            })
        }
    }

    struct BlockHistory {
        calls: StdMutex<usize>,
    }

    impl HistoryReader for BlockHistory {
        fn read_history(
            &self,
            _limit: usize,
            _cancel: &Cancel,
        ) -> Pin<Box<dyn Future<Output = Result<(Vec<Value>, bool), TransportError>> + Send + '_>>
        {
            *self.calls.lock().expect("lock") += 1;
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn runner_lag_window_cancel_returns_ctx_err() {
        // Cancelling during the lag window must end the
        // wait with the cancellation, never a Done/0
        // result: the lag sleep's cancel select fires
        // after the poll read returns an empty window.
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(100)]),
            history_ok(vec![user_ev(100)]),
            history_ok(vec![user_ev(100)]),
        ]));
        let cancel = Cancel::new();
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(60),
            lag_window: StdDuration::from_secs(2),
            lag_poll: StdDuration::from_millis(250),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .expect("config");
        let run_cancel = cancel.clone();
        let canceller = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(300)).await;
            canceller.set();
        });
        let handle = tokio::spawn(async move { runner.run(run_cancel).await });
        let outcome = drive(handle).await;
        assert!(
            matches!(outcome, Err(RunError::Cancelled)),
            "outcome = {outcome:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_lag_poll_ctx_err_returns_ctx_err() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let cancel = Cancel::new();
        let hist = Arc::new(CancelPollHistory {
            cancel: cancel.clone(),
            calls: StdMutex::new(0),
        });
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(120),
            lag_window: StdDuration::from_secs(2),
            lag_poll: StdDuration::from_millis(1),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .expect("config");
        let run_cancel = cancel.clone();
        let canceller = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(300)).await;
            canceller.set();
        });
        let handle = tokio::spawn(async move { runner.run(run_cancel).await });
        let outcome = drive(handle).await;
        assert!(
            matches!(outcome, Err(RunError::Cancelled)),
            "outcome = {outcome:?}"
        );
    }

    #[tokio::test]
    async fn runner_settle_pending_prefers_ctx_err() {
        // Go `TestRunnerSettlePendingPrefersCtxErr`: a
        // non-conforming HistoryReader that returns a
        // transport error after the context died must not
        // mask the cancellation — `settle_pending`
        // returns Cancelled, on both the replies path and
        // the failed-terminal path. One FRESH runner per
        // status: a second settle on the same runner
        // would hit the interval gate (loop-2 F8) and
        // return Ok, which is correct Go behaviour, not
        // a ctx preference — the earlier port did a live
        // settle first on one runner and failed exactly
        // there.
        for status in ["idle", "interrupted"] {
            let err_resp = HistoryResp {
                events: Vec::new(),
                has_more: false,
                err: Some(TransportError::ConnectionError {
                    message: "transport down".to_string(),
                }),
            };
            let hist = Arc::new(QueueHistory::new(vec![err_resp]));
            let sub = Arc::new(FakeSubscriber::new(vec![]));
            let mut runner = Runner::new(Config {
                after_seq: 10,
                has_after_seq: true,
                dial: Some(sub.dial()),
                history: Some(hist),
                ..Config::default()
            })
            .expect("config");
            runner
                .waiter
                .feed(&task_ev(status, "R", "R", 11, Some(json!(2))), None)
                .await;
            let cancel = Cancel::new();
            cancel.set();
            let err = runner.settle_pending(&cancel, status).await;
            assert!(
                matches!(err, Err(RunError::Cancelled)),
                "{status}: err = {err:?} (ctx.Err() wins over the transport error)"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn runner_explicit_boundary_accepts_replayed_failed() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&task_ev("interrupted", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(200)]),
            history_ok(vec![user_ev(200)]),
        ]));
        let res = run_runner(Config {
            after_seq: 200,
            has_after_seq: true,
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Failed);
        assert_eq!(res.exit_code, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn runner_check_state_swallows_history_read_failure() {
        let mut sub = FakeSubscriber::new(vec![]);
        sub.loop_err_repeat = true;
        *sub.loop_err.lock().expect("lock") = Some(TransportError::ConnectionError {
            message: "transport down".to_string(),
        });
        sub.check_script = vec![record_json(&task_ev("completed", "R", "R", 180, None))];
        let sub = Arc::new(sub);
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(100)]),
            HistoryResp {
                events: Vec::new(),
                has_more: false,
                err: Some(TransportError::ConnectionError {
                    message: "transport down".to_string(),
                }),
            },
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            recheck_after: Some(StdDuration::from_secs(20)),
            check_every: None,
            reconnect_budget: StdDuration::from_secs(5),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
        assert!(
            sub.check_calls() >= 1,
            "check_calls = {}",
            sub.check_calls()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_approval_status_uses_waiter_status() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&approval_ev(vec![appr("A", &["allow_always"])], None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let res = run_runner(Config {
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Approval);
        assert_eq!(res.exit_code, 4);
        assert_eq!(res.approvals.len(), 1);
        assert_eq!(res.approvals[0].id, "A");
    }

    #[tokio::test(start_paused = true)]
    async fn runner_plumbs_auto_approve_records() {
        // Go `TestRunnerPlumbsAutoApproveRecords`: A decides
        // A (forever); B offers only allow_once with the
        // fallback off, so it is skipped. Both records land
        // in the Result. B MUST be present: when every
        // pending approval is handled, `feed_approvals`
        // returns nil and the wait continues (Go
        // `waiter.go` `len(left) == 0`), so a single-A
        // event can never end as Approval — the earlier
        // port dropped B and timed out.
        let sub = Arc::new(FakeSubscriber::new(vec![record_json(&approval_ev(
            vec![appr("A", &["allow_always"]), appr("B", &["allow_once"])],
            None,
        ))]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let decider: Arc<Decider> = Arc::new(|_a: &DescribedApproval, _d: &str| Ok(()));
        let approver = Arc::new(AutoApprover::new(Some(connect_ok(decider)), false));
        let adapter = Arc::new(AutoApproverAdapter::new(&approver));
        let res = run_runner(Config {
            dial: Some(sub.dial()),
            history: Some(hist),
            approver: Some(adapter),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Approval);
        assert_eq!(res.exit_code, 4);
        assert_eq!(res.auto_approved.len(), 1);
        assert_eq!(res.auto_approved[0].approval_id, "A");
        assert_eq!(res.auto_approved[0].decision, "allow_always");
        assert_eq!(res.auto_approve_errors.len(), 1);
        assert_eq!(res.auto_approve_errors[0].approval_id, "B");
    }

    #[tokio::test(start_paused = true)]
    async fn runner_approver_auth_error_propagates() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&approval_ev(vec![appr("A", &["allow_always"])], None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let decider: Arc<Decider> = Arc::new(|_a: &DescribedApproval, _d: &str| {
            Err(Box::new(TransportError::Auth {
                message: "expired".to_string(),
            }))
        });
        let approver = Arc::new(AutoApprover::new(Some(connect_ok(decider)), false));
        let adapter = Arc::new(AutoApproverAdapter::new(&approver));
        let mut runner = Runner::new(Config {
            dial: Some(sub.dial()),
            history: Some(hist),
            approver: Some(adapter),
            ..default_config()
        })
        .expect("config");
        let cancel = Cancel::new();
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        assert!(
            matches!(
                outcome,
                Err(RunError::ApproverFatal(BotError::Transport(
                    TransportError::Auth { .. }
                )))
            ),
            "outcome = {outcome:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_nil_subscriber_is_transport_failure() {
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let dial: DialFn = Arc::new(|_cancel: Cancel| Box::pin(async { Ok(None) }));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(5),
            recheck_after: Some(StdDuration::from_secs(1)),
            check_every: None,
            dial: Some(dial),
            history: Some(hist),
            ..default_config()
        })
        .await;
        // Go: nil subscriber is a transport failure that
        // ends in timeout 124, never a panic; the typed-nil
        // variant is the same `None` case in Rust.
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
    }

    #[tokio::test(start_paused = true)]
    async fn runner_check_state_nil_subscriber() {
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let dial: DialFn = Arc::new(|_cancel: Cancel| Box::pin(async { Ok(None) }));
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(5),
            recheck_after: Some(StdDuration::from_secs(1)),
            check_every: Some(StdDuration::from_secs(1)),
            dial: Some(dial),
            history: Some(hist),
            ..default_config()
        })
        .expect("config");
        let cancel = Cancel::new();
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        let res = outcome.expect("run must succeed");
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
    }

    #[tokio::test(start_paused = true)]
    async fn runner_empty_history_limits_use_defaults() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(ScriptHistory::new(history_ok(vec![user_ev(100)])));
        let res = run_runner(Config {
            history_limits: Vec::new(),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
    }

    #[tokio::test(start_paused = true)]
    async fn runner_subscribe_options_no_keep_alive() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            recheck_after: Some(StdDuration::from_secs(20)),
            check_every: None,
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        let loop_opts = sub
            .loop_opts
            .lock()
            .expect("lock")
            .clone()
            .expect("loop subscribe happened");
        assert_eq!(loop_opts.max_records, 1_000_000_000);
        assert_eq!(loop_opts.route, None);
    }

    #[test]
    fn new_runner_clamps_negative_durations() {
        // Rust `Duration` cannot be negative: `None` is
        // Go's negative (disabled) for RecheckAfter /
        // CheckEvery, `Duration::ZERO` is Go's 0
        // (default) for every duration.
        // `Runner::new` requires Dial + History (Go
        // `runner.go:294-298`); this test only constructs,
        // so both are never-called dummies.
        let sub = Arc::new(FakeSubscriber::new(vec![]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![])]));
        let runner = Runner::new(Config {
            timeout: StdDuration::ZERO,
            recheck_after: None,
            check_every: None,
            state_check_budget: StdDuration::ZERO,
            reconnect_budget: StdDuration::ZERO,
            resub_pause: StdDuration::ZERO,
            final_read_floor: StdDuration::ZERO,
            lag_window: StdDuration::ZERO,
            lag_poll: StdDuration::ZERO,
            settle_poll_interval: StdDuration::from_millis(1),
            history_limits: Vec::new(),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..Config::default()
        })
        .expect("config");
        assert_eq!(runner.cfg.timeout, StdDuration::from_secs(600));
        assert_eq!(runner.cfg.recheck_after, None);
        assert_eq!(runner.cfg.check_every, None);
        assert_eq!(runner.cfg.state_check_budget, StdDuration::from_secs(8));
        assert_eq!(runner.cfg.reconnect_budget, StdDuration::from_secs(30));
        assert_eq!(runner.cfg.resub_pause, StdDuration::from_secs(1));
        assert_eq!(runner.cfg.final_read_floor, StdDuration::from_secs(5));
        assert_eq!(runner.cfg.lag_window, StdDuration::from_secs(2));
        assert_eq!(runner.cfg.lag_poll, StdDuration::from_millis(250));
        assert_eq!(
            runner.cfg.settle_poll_interval,
            StdDuration::from_millis(100)
        );
        assert_eq!(runner.cfg.history_limits, vec![200, 500, 1000]);
    }

    #[tokio::test(start_paused = true)]
    async fn runner_finish_final_read_success_after_cancel_returns_ctx_err() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let cancel = Cancel::new();
        let hist = Arc::new(CancelOnReadHistory {
            cancel: cancel.clone(),
            cancel_at: 2,
            events: vec![user_ev(100), asst(150, "completed", "hello", None)],
            err: None,
            calls: StdMutex::new(0),
        });
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(10),
            recheck_after: None,
            check_every: None,
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .expect("config");
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        assert!(
            matches!(outcome, Err(RunError::Cancelled)),
            "outcome = {outcome:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_finish_last_chance_proof_error_after_cancel_returns_ctx_err() {
        let sub = Arc::new(FakeSubscriber::new(vec![record_json(&task_ev(
            "interrupted",
            "R",
            "R",
            180,
            None,
        ))]));
        let cancel = Cancel::new();
        let hist = Arc::new(CancelOnReadHistory {
            cancel: cancel.clone(),
            cancel_at: 2,
            events: Vec::new(),
            err: Some(TransportError::ConnectionError {
                message: "transport down".to_string(),
            }),
            calls: StdMutex::new(0),
        });
        let mut runner = Runner::new(Config {
            after_seq: 200,
            has_after_seq: true,
            timeout: StdDuration::from_secs(10),
            recheck_after: Some(StdDuration::from_secs(1)),
            check_every: None,
            resub_pause: StdDuration::from_millis(1),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .expect("config");
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        assert!(
            matches!(outcome, Err(RunError::Cancelled)),
            "outcome = {outcome:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn runner_finish_final_read_error_after_cancel_returns_ctx_err() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 100, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let cancel = Cancel::new();
        let hist = Arc::new(CancelOnReadHistory {
            cancel: cancel.clone(),
            cancel_at: 1,
            events: Vec::new(),
            err: Some(TransportError::ConnectionError {
                message: "transport down".to_string(),
            }),
            calls: StdMutex::new(0),
        });
        let mut runner = Runner::new(Config {
            after_seq: 100,
            has_after_seq: true,
            timeout: StdDuration::from_secs(10),
            recheck_after: None,
            check_every: None,
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .expect("config");
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        assert!(
            matches!(outcome, Err(RunError::Cancelled)),
            "outcome = {outcome:?}"
        );
    }

    // Go `scriptedHistory` for the lag-cancel table test:
    // call 1 (final read) returns empty so finish enters
    // the lag window; call 2 (lag-loop read) cancels
    // synchronously and returns the case events; any
    // further call counts as an extra read.
    struct LagReadHistory {
        cancel: Cancel,
        events: Vec<Value>,
        calls: StdMutex<usize>,
        extra_reads: StdMutex<usize>,
    }

    impl HistoryReader for LagReadHistory {
        fn read_history(
            &self,
            _limit: usize,
            _cancel: &Cancel,
        ) -> Pin<Box<dyn Future<Output = Result<(Vec<Value>, bool), TransportError>> + Send + '_>>
        {
            let mut calls = self.calls.lock().expect("lock");
            *calls += 1;
            match *calls {
                1 => Box::pin(async { Ok((Vec::new(), false)) }),
                2 => {
                    self.cancel.set();
                    let events = self.events.clone();
                    Box::pin(async move { Ok((events, false)) })
                }
                _ => {
                    *self.extra_reads.lock().expect("lock") += 1;
                    Box::pin(async { Ok((Vec::new(), false)) })
                }
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn runner_finish_cancel_during_lag_read_returns_ctx_err() {
        // A cancel injected during a lag-loop read precedes
        // both the post-lag check and the final guard and
        // must yield the cancellation, never a result —
        // via the post-lag check when the read returns
        // replies, via the lag sleep's cancel select when
        // it returns an empty window.
        for (name, events) in [
            (
                "replies returned",
                vec![user_ev(100), asst(150, "completed", "late", None)],
            ),
            ("empty window", Vec::new()),
        ] {
            let sub = Arc::new(FakeSubscriber::new(vec![
                record_json(&task_ev("running", "R", "R", 100, None)),
                record_json(&task_ev("completed", "R", "R", 180, None)),
            ]));
            let cancel = Cancel::new();
            let hist = Arc::new(LagReadHistory {
                cancel: cancel.clone(),
                events,
                calls: StdMutex::new(0),
                extra_reads: StdMutex::new(0),
            });
            let mut runner = Runner::new(Config {
                after_seq: 100,
                has_after_seq: true,
                timeout: StdDuration::from_secs(120),
                lag_window: StdDuration::from_secs(2),
                lag_poll: StdDuration::from_millis(1),
                dial: Some(sub.dial()),
                history: Some(hist.clone()),
                ..default_config()
            })
            .expect("config");
            let handle = tokio::spawn(async move { runner.run(cancel).await });
            let outcome = drive(handle).await;
            assert!(
                matches!(outcome, Err(RunError::Cancelled)),
                "{name}: outcome = {outcome:?}"
            );
            assert_eq!(
                *hist.calls.lock().expect("lock"),
                2,
                "{name}: want exactly 2 reads (final read + lag-loop read)"
            );
            assert_eq!(
                *hist.extra_reads.lock().expect("lock"),
                0,
                "{name}: no reads past the lag read"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn runner_finish_final_guard_returns_ctx_err() {
        // The final guard in isolation: the hook cancels
        // immediately before the guard — an ordering no
        // earlier check can observe. The no-cancel case
        // proves the hook itself neither masks a success
        // nor fires spuriously.
        for (name, cancel_case) in [
            ("cancel before final guard returns ctx err", true),
            ("no cancel returns done result", false),
        ] {
            let sub = Arc::new(FakeSubscriber::new(vec![
                record_json(&task_ev("running", "R", "R", 100, None)),
                record_json(&task_ev("completed", "R", "R", 180, None)),
            ]));
            let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![
                user_ev(100),
                asst(150, "completed", "late", None),
            ])]));
            let cancel = Cancel::new();
            let fired: Arc<StdMutex<usize>> = Arc::new(StdMutex::new(0));
            let fired2 = Arc::clone(&fired);
            let got: Arc<StdMutex<Option<Cancel>>> = Arc::new(StdMutex::new(None));
            let got2 = Arc::clone(&got);
            let cancel2 = cancel.clone();
            let guard: Arc<dyn Fn(Cancel) + Send + Sync> = Arc::new(move |c: Cancel| {
                *fired2.lock().expect("lock") += 1;
                *got2.lock().expect("lock") = Some(c);
                if cancel_case {
                    cancel2.set();
                }
            });
            let mut runner = Runner::new(Config {
                after_seq: 100,
                has_after_seq: true,
                timeout: StdDuration::from_secs(60),
                recheck_after: None,
                check_every: None,
                dial: Some(sub.dial()),
                history: Some(Arc::clone(&hist) as Arc<dyn HistoryReader>),
                before_final_guard: Some(guard),
                ..default_config()
            })
            .expect("config");
            let run_cancel = cancel.clone();
            let handle = tokio::spawn(async move { runner.run(run_cancel).await });
            let outcome = drive(handle).await;
            if cancel_case {
                assert!(
                    matches!(outcome, Err(RunError::Cancelled)),
                    "{name}: outcome = {outcome:?}"
                );
            } else {
                let res = outcome.expect("run must succeed");
                assert_eq!(res.kind, WaitKind::Done, "{name}");
                assert_eq!(res.exit_code, 0, "{name}");
            }
            assert_eq!(*fired.lock().expect("lock"), 1, "{name}");
            assert_eq!(hist.calls(), 2, "{name}");
            assert!(
                got.lock()
                    .expect("lock")
                    .as_ref()
                    .is_some_and(|c| c.is_same(&cancel)),
                "{name}: guard must receive the run cancel"
            );
        }
    }

    #[tokio::test]
    async fn runner_settle_pending_cancelled_success_returns_ctx_err() {
        // Go `TestRunnerSettlePendingCancelledSuccessReturnsCtxErr`:
        // `settle_pending` must return Cancelled with NO
        // outcome applied when the context is cancelled,
        // on both the replies path and the failed-terminal
        // path. Each case uses a FRESH runner for the
        // cancelled call and a second fresh runner for the
        // live baseline — the earlier port did a live
        // settle first on one runner, so the cancelled
        // call hit the interval gate (loop-2 F8) and
        // returned Ok.
        // Replies path ("idle"): a successful proof under
        // a pre-cancelled context settles nothing.
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![
            user_ev(100),
            asst(150, "completed", "settled", None),
        ])]));
        let sub = Arc::new(FakeSubscriber::new(vec![]));
        let mut runner = Runner::new(Config {
            after_seq: 10,
            has_after_seq: true,
            dial: Some(sub.dial()),
            history: Some(hist),
            ..Config::default()
        })
        .expect("config");
        runner
            .waiter
            .feed(&task_ev("idle", "R", "R", 11, Some(json!(2))), None)
            .await;
        let cancel = Cancel::new();
        cancel.set();
        let err = runner.settle_pending(&cancel, "idle").await;
        assert!(matches!(err, Err(RunError::Cancelled)), "err = {err:?}");
        assert!(runner.waiter.result().is_none(), "no outcome after cancel");
        assert!(
            runner.waiter.ignored_terminal().is_some(),
            "ignored terminal must still be pending after a cancelled settle"
        );
        // Live baseline: the same proof without
        // cancellation still settles.
        let hist2 = Arc::new(QueueHistory::new(vec![history_ok(vec![
            user_ev(100),
            asst(150, "completed", "settled", None),
        ])]));
        let sub2 = Arc::new(FakeSubscriber::new(vec![]));
        let mut runner2 = Runner::new(Config {
            after_seq: 10,
            has_after_seq: true,
            dial: Some(sub2.dial()),
            history: Some(hist2),
            ..Config::default()
        })
        .expect("config");
        runner2
            .waiter
            .feed(&task_ev("idle", "R", "R", 11, Some(json!(2))), None)
            .await;
        runner2
            .settle_pending(&Cancel::new(), "idle")
            .await
            .expect("live settle must succeed");
        assert_eq!(runner2.waiter.result().expect("done").kind, WaitKind::Done);
        // Failed path ("interrupted"): same shape, the
        // replayed-failed proof. Go sets the boundary
        // explicitly (200); the waiter needs after_seq
        // to match the latest user seq or
        // `accept_replayed_failed` refuses.
        let hist3 = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(200)])]));
        let sub3 = Arc::new(FakeSubscriber::new(vec![]));
        let mut runner3 = Runner::new(Config {
            after_seq: 200,
            has_after_seq: true,
            dial: Some(sub3.dial()),
            history: Some(hist3),
            ..Config::default()
        })
        .expect("config");
        runner3.waiter.set_boundary(200, false, true);
        runner3
            .waiter
            .feed(&task_ev("interrupted", "R", "R", 11, Some(json!(2))), None)
            .await;
        let cancel3 = Cancel::new();
        cancel3.set();
        let err3 = runner3.settle_pending(&cancel3, "interrupted").await;
        assert!(matches!(err3, Err(RunError::Cancelled)), "err = {err3:?}");
        assert!(runner3.waiter.result().is_none(), "no outcome after cancel");
        assert!(
            runner3.waiter.ignored_terminal().is_some(),
            "ignored terminal must still be pending after a cancelled settle"
        );
        let hist4 = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(200)])]));
        let sub4 = Arc::new(FakeSubscriber::new(vec![]));
        let mut runner4 = Runner::new(Config {
            after_seq: 200,
            has_after_seq: true,
            dial: Some(sub4.dial()),
            history: Some(hist4),
            ..Config::default()
        })
        .expect("config");
        runner4.waiter.set_boundary(200, false, true);
        runner4
            .waiter
            .feed(&task_ev("interrupted", "R", "R", 11, Some(json!(2))), None)
            .await;
        runner4
            .settle_pending(&Cancel::new(), "interrupted")
            .await
            .expect("live settle must succeed");
        assert_eq!(
            runner4.waiter.result().expect("failed").kind,
            WaitKind::Failed
        );
    }

    // -- wait_redesign_test.go (23 fns) --

    #[tokio::test(start_paused = true)]
    async fn redesign_t1_derived_boundary() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![
                user_ev(30),
                user_ev(41),
                asst(20, "completed", "old", None),
            ]),
            history_ok(vec![user_ev(41), asst(42, "completed", "done", None)]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.outcome, "done");
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.after_seq, 41);
        assert_eq!(res.replies.len(), 1);
        assert_eq!(res.replies[0].seq, 42);
        assert_eq!(res.final_text, "done");
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t2_explicit_boundary_never_ratchets() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 500, None)),
            record_json(&task_ev("completed", "R", "R", 501, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![
            user_ev(9),
            asst(11, "completed", "new", None),
        ])]));
        let res = run_runner(Config {
            after_seq: 10,
            has_after_seq: true,
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(Arc::clone(&hist) as Arc<dyn HistoryReader>),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.after_seq, 10);
        assert_eq!(res.replies.len(), 1);
        assert_eq!(res.replies[0].seq, 11);
        assert_eq!(hist.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t3_boundary_unknown_suppresses_replies() {
        // Same shape as the runner_test boundary test but
        // with a held terminal (no running seen): the
        // result is a timeout, not an approval.
        let sub = Arc::new(FakeSubscriber::new(vec![record_json(&task_ev(
            "completed",
            "R",
            "R",
            180,
            None,
        ))]));
        let err_resp = || HistoryResp {
            events: Vec::new(),
            has_more: false,
            err: Some(TransportError::ConnectionError {
                message: "transport down".to_string(),
            }),
        };
        let hist = Arc::new(QueueHistory::new(vec![
            err_resp(),
            err_resp(),
            err_resp(),
            err_resp(),
            err_resp(),
            err_resp(),
            history_ok(vec![user_ev(100), asst(150, "completed", "stale?", None)]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
        assert!(res.replies.is_empty());
        assert_eq!(
            res.note,
            "turn-end boundary unknown: history could not be read, so no replies are reported; run `castctl wait` again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t4_approval_ends_wait() {
        let sub = Arc::new(FakeSubscriber::new(vec![record_json(&approval_ev(
            vec![appr("A", &["allow_always"])],
            None,
        ))]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Approval);
        assert_eq!(res.outcome, "needs_approval");
        assert_eq!(res.exit_code, 4);
        assert_eq!(res.approvals.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t5_held_terminal_quiet_stream_late_reply() {
        let mut sub = FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, Some(json!(2)))),
        ]);
        sub.block = true;
        let sub = Arc::new(sub);
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(10)]),
            history_ok(vec![user_ev(10)]),
            history_ok(vec![
                user_ev(10),
                asst(11, "completed", "main's reply", None),
            ]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(600),
            recheck_after: Some(StdDuration::from_secs(20)),
            check_every: Some(StdDuration::from_secs(60)),
            dial: Some(sub.dial()),
            history: Some(Arc::clone(&hist) as Arc<dyn HistoryReader>),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.outcome, "done");
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.replies.len(), 1);
        assert_eq!(res.replies[0].seq, 11);
        assert_eq!(res.final_text, "main's reply");
        assert_eq!(hist.calls(), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t6_suspect_terminal_late_reply() {
        let mut sub = FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("idle", "R", "R", 180, None)),
        ]);
        sub.block = true;
        let sub = Arc::new(sub);
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(10)]),
            history_ok(vec![user_ev(10)]),
            history_ok(vec![user_ev(10), asst(11, "completed", "late reply", None)]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(600),
            recheck_after: Some(StdDuration::from_secs(20)),
            check_every: Some(StdDuration::from_secs(60)),
            dial: Some(sub.dial()),
            history: Some(Arc::clone(&hist) as Arc<dyn HistoryReader>),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.replies.len(), 1);
        assert_eq!(res.replies[0].seq, 11);
        assert_eq!(hist.calls(), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t7_window_exhaustion_is_visible() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        // Every window is exhausted (has_more) and holds
        // only user events: the reply at an older seq never
        // appears in any window.
        let window = || HistoryResp {
            events: vec![user_ev(50), user_ev(30)],
            has_more: true,
            err: None,
        };
        let hist = Arc::new(
            ScriptHistory::new(window())
                .with(200, vec![window()])
                .with(500, vec![window()])
                .with(1000, vec![window()]),
        );
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            after_seq: 10,
            has_after_seq: true,
            history_limits: vec![200, 500, 1000],
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.exit_code, 0);
        assert!(res.replies.is_empty());
        assert_eq!(
            res.note,
            "history window exhausted at 1000 events; older replies may be missed; run `castctl wait` again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t8_absent_count_decides_directly() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(10)]),
            history_ok(vec![
                user_ev(10),
                asst(11, "completed", "subagent work", None),
                asst(12, "completed", "main's reply", None),
            ]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(Arc::clone(&hist) as Arc<dyn HistoryReader>),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.replies.len(), 2);
        assert_eq!(res.replies[0].seq, 11);
        assert_eq!(res.replies[1].seq, 12);
        assert_eq!(res.final_text, "main's reply");
        assert_eq!(hist.calls(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t4_needs_input_widget() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let widget = json!({"widget_id": "w1", "kind": "choice", "state": {}});
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(100)]),
            history_ok(vec![
                user_ev(100),
                asst(
                    150,
                    "completed",
                    "pick one",
                    Some(json!({"widgets": [widget]})),
                ),
            ]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.outcome, "needs_input");
        assert_eq!(res.exit_code, 4);
        assert_eq!(res.needs_input_reason, "widget");
    }

    #[tokio::test]
    async fn feed_record_malformed_input_changes_no_state() {
        use castctl_telegram::wait::Waiter;
        // Port of Go `TestFeedTraceI` (`waiter_test.go`):
        // malformed input changes no state; a real
        // running record feeds and sets SeenRunning
        // only. (Technical F1: `FeedRecord` was missing
        // from the port; fix loop 1 adds it.)
        let mut w = Waiter::new("");
        assert!(
            feed_record(&mut w, None, b"{\"status\": \"completed\"")
                .await
                .is_none()
        );
        assert!(feed_record(&mut w, None, b"42").await.is_none());
        assert!(
            feed_record(
                &mut w,
                None,
                b"{\"event\": \"task.status\", \"payload\": \"junk\"}"
            )
            .await
            .is_none()
        );
        assert!(
            feed_record(
                &mut w,
                None,
                b"{\"event\":\"task.status\",\"payload\":{\"status\":\"completed\"}} {\"x\":1}"
            )
            .await
            .is_none()
        );
        assert!(!w.seen_running(), "malformed input must change no state");
        assert_eq!(w.status(), None, "malformed input must change no state");
        // A real record works, with json.Number seqs.
        let out = feed_record(
            &mut w,
            None,
            b"{\"event\":\"task.status\",\"seq\":120,\"payload\":{\"status\":\"running\",\"root_agent_id\":\"R\",\"agent_id\":\"R\"}}",
        )
        .await;
        assert!(out.is_none(), "running record = {out:?}");
        // A running record teaches SeenRunning only: its
        // stream seq is never stored as boundary evidence
        // (Go loop-2 F1). Rust has no `after_seq`
        // accessor — the boundary is only observable via
        // `set_boundary` / `boundary_unknown`, and a
        // running record touches neither.
        assert!(w.seen_running(), "running record must set SeenRunning");
        assert_eq!(w.status(), Some("running"));
    }

    #[tokio::test]
    async fn redesign_t9_release_signals() {
        use castctl_telegram::wait::{Reply, Waiter};
        let reply = |seq: i64| Reply {
            seq,
            message_id: String::new(),
            text: "x".to_string(),
            widgets: Vec::new(),
            media: false,
            agent_id: String::new(),
            root_agent_id: String::new(),
        };
        // (a) Re-arm, then settle: suspect-failed held for
        // subagents.
        let mut w = Waiter::new("");
        w.feed(&task_ev("running", "R", "R", 0, None), None).await;
        w.feed(&task_ev("failed", "R", "R", 0, Some(json!(2))), None)
            .await;
        assert_eq!(w.ignored_reason(), "subagents", "(a)");
        w.feed(&task_ev("queued", "R", "R", 0, Some(json!(0))), None)
            .await;
        assert_eq!(w.ignored_reason(), "", "(a) count-0 must re-arm");
        let out = w.settle(&[reply(1)]);
        assert!(
            matches!(out, Some(ref o) if o.kind == WaitKind::Failed),
            "(a) settle after re-arm = {out:?}"
        );
        // (b) Reply proof alone, reason still "subagents".
        let mut w2 = Waiter::new("");
        w2.feed(&task_ev("running", "R", "R", 0, None), None).await;
        w2.feed(&task_ev("completed", "R", "R", 0, Some(json!(2))), None)
            .await;
        assert_eq!(w2.ignored_reason(), "subagents", "(b)");
        let out = w2.settle(&[reply(1)]);
        assert!(
            matches!(out, Some(ref o) if o.kind == WaitKind::Done),
            "(b) settle while held = {out:?}, want Done"
        );
        // (c) A subagent's own count-0 event must not
        // re-arm.
        let mut w3 = Waiter::new("");
        w3.feed(&task_ev("running", "R", "R", 0, None), None).await;
        w3.feed(&task_ev("completed", "R", "R", 0, Some(json!(2))), None)
            .await;
        w3.feed(&task_ev("queued", "R", "S", 0, Some(json!(0))), None)
            .await;
        assert_eq!(
            w3.ignored_reason(),
            "subagents",
            "(c) subagent count-0 must not re-arm"
        );
        assert!(w3.settle(&[]).is_none(), "(c) settle with no replies");
        // (d) A fresh root running clears the hold entirely.
        let mut w4 = Waiter::new("");
        w4.feed(&task_ev("running", "R", "R", 0, None), None).await;
        w4.feed(&task_ev("completed", "R", "R", 0, Some(json!(2))), None)
            .await;
        w4.feed(&task_ev("running", "R", "R", 0, None), None).await;
        assert!(
            w4.ignored_terminal().is_none(),
            "(d) fresh running must clear the held terminal"
        );
        assert_eq!(w4.ignored_reason(), "", "(d)");
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t10_check_state_feeds_last_only() {
        let mut sub = FakeSubscriber::new(vec![]);
        sub.check_script = vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ];
        let sub = Arc::new(sub);
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(30),
            recheck_after: None,
            check_every: Some(StdDuration::from_secs(5)),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
        assert_eq!(res.status, "completed");
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t10_check_state_stale_last_event() {
        let mut sub = FakeSubscriber::new(vec![]);
        sub.check_script = vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
            record_json(&task_ev("queued", "R", "S", 0, Some(json!(0)))),
        ];
        let sub = Arc::new(sub);
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(30),
            recheck_after: None,
            check_every: Some(StdDuration::from_secs(5)),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
        assert_eq!(res.status, "completed");
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t12_never_succeeding_history_terminates() {
        let mut sub = FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, Some(json!(2)))),
        ]);
        sub.block = true;
        let sub = Arc::new(sub);
        let hist = Arc::new(QueueHistory::new(vec![HistoryResp {
            events: Vec::new(),
            has_more: false,
            err: Some(TransportError::ConnectionError {
                message: "transport down".to_string(),
            }),
        }]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(10),
            recheck_after: None,
            check_every: None,
            dial: Some(sub.dial()),
            history: Some(Arc::clone(&hist) as Arc<dyn HistoryReader>),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
        assert!(res.final_read_failed);
        assert_eq!(
            res.note,
            "could not read the final replies; run `castctl wait` again"
        );
        assert_eq!(hist.calls(), 8);
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_last_chance_proof_spends_no_read_when_boundary_unknown() {
        let mut sub = FakeSubscriber::new(vec![record_json(&task_ev(
            "interrupted",
            "R",
            "R",
            180,
            None,
        ))]);
        sub.block = true;
        let sub = Arc::new(sub);
        let err_resp = || HistoryResp {
            events: Vec::new(),
            has_more: false,
            err: Some(TransportError::ConnectionError {
                message: "transport down".to_string(),
            }),
        };
        let hist = Arc::new(QueueHistory::new(vec![
            err_resp(),
            err_resp(),
            err_resp(),
            err_resp(),
            err_resp(),
            err_resp(),
            history_ok(vec![user_ev(100), asst(150, "completed", "stale?", None)]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(10),
            recheck_after: None,
            check_every: None,
            dial: Some(sub.dial()),
            history: Some(Arc::clone(&hist) as Arc<dyn HistoryReader>),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
        assert_eq!(res.outcome, "timeout");
        assert_eq!(res.status, "interrupted");
        assert_eq!(res.after_seq, 0);
        assert!(res.replies.is_empty());
        assert!(!res.final_read_failed);
        assert_eq!(
            res.note,
            "turn-end boundary unknown: history could not be read, so no replies are reported; run `castctl wait` again"
        );
        assert_eq!(hist.calls(), 7);
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t13_deaf_stream_terminates() {
        let mut sub = FakeSubscriber::new(vec![]);
        sub.block = true;
        let sub = Arc::new(sub);
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(120),
            recheck_after: Some(StdDuration::from_secs(20)),
            check_every: Some(StdDuration::from_secs(60)),
            dial: Some(sub.dial()),
            history: Some(Arc::clone(&hist) as Arc<dyn HistoryReader>),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
        assert!(
            sub.calls() >= 2,
            "subscribe calls = {}, want resubscribes until the deadline",
            sub.calls()
        );
        assert_eq!(hist.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t13_blocking_history_terminates_at_deadline() {
        let sub = Arc::new(FakeSubscriber::new(vec![]));
        let hist = Arc::new(BlockHistory {
            calls: StdMutex::new(0),
        });
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(10),
            final_read_floor: StdDuration::from_secs(1),
            dial: Some(sub.dial()),
            history: Some(hist.clone()),
            ..default_config()
        })
        .expect("config");
        let cancel = Cancel::new();
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        let res = outcome.expect("run must succeed");
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
        assert_eq!(*hist.calls.lock().expect("lock"), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t14_auth_in_derivation_propagates() {
        let hist = Arc::new(ScriptHistory::new(HistoryResp {
            events: Vec::new(),
            has_more: false,
            err: Some(TransportError::Auth {
                message: "expired".to_string(),
            }),
        }));
        let sub = Arc::new(FakeSubscriber::new(vec![]));
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist.clone()),
            ..default_config()
        })
        .expect("config");
        let cancel = Cancel::new();
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        assert!(
            matches!(outcome, Err(RunError::Auth(TransportError::Auth { .. }))),
            "outcome = {outcome:?}"
        );
        assert_eq!(hist.call_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t14_auth_in_settle_propagates() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("idle", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(
            ScriptHistory::new(HistoryResp {
                events: Vec::new(),
                has_more: false,
                err: Some(TransportError::Auth {
                    message: "expired".to_string(),
                }),
            })
            .with(
                200,
                vec![
                    history_ok(vec![user_ev(100)]),
                    HistoryResp {
                        events: Vec::new(),
                        has_more: false,
                        err: Some(TransportError::Auth {
                            message: "expired".to_string(),
                        }),
                    },
                ],
            ),
        );
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist.clone()),
            ..default_config()
        })
        .expect("config");
        let cancel = Cancel::new();
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        assert!(
            matches!(outcome, Err(RunError::Auth(TransportError::Auth { .. }))),
            "outcome = {outcome:?}"
        );
        assert_eq!(hist.call_count(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t14_auth_in_subscribe_propagates() {
        let sub = Arc::new(FakeSubscriber::new(vec![]));
        *sub.loop_err.lock().expect("lock") = Some(TransportError::Auth {
            message: "expired".to_string(),
        });
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .expect("config");
        let cancel = Cancel::new();
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        assert!(
            matches!(outcome, Err(RunError::Auth(TransportError::Auth { .. }))),
            "outcome = {outcome:?}"
        );
        assert_eq!(sub.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t14_auth_approver_decided_once() {
        let decides: Arc<StdMutex<usize>> = Arc::new(StdMutex::new(0));
        let decides2 = Arc::clone(&decides);
        let decider: Arc<Decider> = Arc::new(move |_a: &DescribedApproval, _d: &str| {
            *decides2.lock().expect("lock") += 1;
            Err(Box::new(TransportError::Auth {
                message: "expired".to_string(),
            }))
        });
        let approver = Arc::new(AutoApprover::new(Some(connect_ok(decider)), false));
        let adapter = Arc::new(AutoApproverAdapter::new(&approver));
        let sub = Arc::new(FakeSubscriber::new(vec![record_json(&approval_ev(
            vec![appr("A", &["allow_always"])],
            None,
        ))]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(100)])]));
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            approver: Some(adapter),
            ..default_config()
        })
        .expect("config");
        let cancel = Cancel::new();
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        assert!(
            matches!(
                outcome,
                Err(RunError::ApproverFatal(BotError::Transport(
                    TransportError::Auth { .. }
                )))
            ),
            "outcome = {outcome:?}"
        );
        assert_eq!(*decides.lock().expect("lock"), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn redesign_t16_replies_from_history_only() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&asst(
                150,
                "completed",
                "live text must never surface",
                None,
            )),
            record_json(&json!({"event": "delta.text_append", "payload": {"text": "partial"}})),
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(100)]),
            history_ok(vec![user_ev(100)]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.exit_code, 0);
        assert!(res.replies.is_empty());
        assert_eq!(res.final_text, "");
    }

    #[test]
    fn redesign_t17_no_attribution_in_reply_filter() {
        let subagent_shaped = asst(
            11,
            "completed",
            "subagent-shaped",
            Some(json!({"agent_id": "S", "root_agent_id": "R", "active_subagent_count": 1})),
        );
        let main_shaped = asst(
            12,
            "completed",
            "main-shaped",
            Some(json!({"agent_id": "R", "root_agent_id": "R"})),
        );
        let replies = replies_after(&[main_shaped, subagent_shaped], 10, None);
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0].seq, 11);
        assert_eq!(replies[1].seq, 12);
    }

    #[test]
    fn redesign_settle_poll_interval_defaults() {
        let cfg = |interval: StdDuration| Config {
            dial: Some(Arc::new(FakeSubscriber::new(vec![])).dial()),
            history: Some(Arc::new(QueueHistory::new(vec![history_ok(vec![])]))),
            settle_poll_interval: interval,
            ..Config::default()
        };
        let runner = Runner::new(cfg(StdDuration::ZERO)).expect("config");
        assert_eq!(
            runner.cfg.settle_poll_interval,
            StdDuration::from_secs(5),
            "zero interval must take the default"
        );
        let runner = Runner::new(cfg(StdDuration::from_secs(2))).expect("config");
        assert_eq!(
            runner.cfg.settle_poll_interval,
            StdDuration::from_secs(2),
            "explicit interval must be preserved"
        );
    }

    // -- wait_redesign_loop2_test.go (24 fns; the 6 F7
    // history-level tests live in history.rs) --

    const LOOP2_BOUNDARY_NOTE: &str = "turn-end boundary unknown: history could not be read, so no replies are reported; run `castctl wait` again";

    fn err_history_resp() -> HistoryResp {
        HistoryResp {
            events: Vec::new(),
            has_more: false,
            err: Some(TransportError::ConnectionError {
                message: "transport down".to_string(),
            }),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn loop2_stream_seq_never_becomes_boundary() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![
            err_history_resp(),
            err_history_resp(),
            err_history_resp(),
            err_history_resp(),
            err_history_resp(),
            err_history_resp(),
            history_ok(vec![user_ev(10), asst(42, "completed", "reply", None)]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.after_seq, 0);
        assert!(res.replies.is_empty());
        assert_eq!(res.note, LOOP2_BOUNDARY_NOTE);
    }

    #[tokio::test(start_paused = true)]
    async fn loop2_seq_less_running_does_not_clear_unknown_boundary() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 0, None)),
            record_json(&task_ev("completed", "R", "R", 0, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![
            err_history_resp(),
            err_history_resp(),
            err_history_resp(),
            err_history_resp(),
            err_history_resp(),
            err_history_resp(),
            history_ok(vec![user_ev(10), asst(6, "completed", "ancient", None)]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert!(res.replies.is_empty());
        assert_eq!(res.note, LOOP2_BOUNDARY_NOTE);
    }

    #[tokio::test(start_paused = true)]
    async fn loop2_suspect_terminal_keeps_unknown_boundary() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("idle", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![
            err_history_resp(),
            err_history_resp(),
            err_history_resp(),
            err_history_resp(),
            err_history_resp(),
            err_history_resp(),
            history_ok(vec![user_ev(10), asst(42, "completed", "reply", None)]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(5),
            recheck_after: None,
            check_every: None,
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
        assert!(res.replies.is_empty());
        assert_eq!(res.note, LOOP2_BOUNDARY_NOTE);
    }

    #[tokio::test]
    async fn loop2_settle_refuses_subagent_shaped_reply() {
        use castctl_telegram::wait::Waiter;
        let subagent_shaped = replies_after(
            &[asst(
                11,
                "completed",
                "subagent-only text",
                Some(json!({"agent_id": "S", "root_agent_id": "R"})),
            )],
            10,
            None,
        );
        assert_eq!(subagent_shaped.len(), 1);
        // (subagent-shaped only) must not release.
        let mut w = Waiter::new("");
        w.feed(&task_ev("running", "R", "R", 0, None), None).await;
        w.feed(&task_ev("completed", "R", "R", 0, Some(json!(2))), None)
            .await;
        assert!(
            w.settle(&subagent_shaped).is_none(),
            "Settle(subagent-shaped only) must not release"
        );
        // (mixed) the unattributed reply is proof.
        let mixed = replies_after(
            &[
                asst(
                    11,
                    "completed",
                    "subagent-only text",
                    Some(json!({"agent_id": "S", "root_agent_id": "R"})),
                ),
                asst(12, "completed", "main reply", None),
            ],
            10,
            None,
        );
        let mut w = Waiter::new("");
        w.feed(&task_ev("running", "R", "R", 0, None), None).await;
        w.feed(&task_ev("completed", "R", "R", 0, Some(json!(2))), None)
            .await;
        let out = w.settle(&mixed);
        assert!(
            matches!(out, Some(ref o) if o.kind == WaitKind::Done),
            "Settle(mixed) = {out:?}, want Done (the unattributed reply is proof)"
        );
        // (root-confirmed) releases.
        let root_shaped = replies_after(
            &[asst(
                11,
                "completed",
                "main reply",
                Some(json!({"agent_id": "R", "root_agent_id": "R"})),
            )],
            10,
            None,
        );
        let mut w = Waiter::new("");
        w.feed(&task_ev("running", "R", "R", 0, None), None).await;
        w.feed(&task_ev("completed", "R", "R", 0, Some(json!(2))), None)
            .await;
        let out = w.settle(&root_shaped);
        assert!(
            matches!(out, Some(ref o) if o.kind == WaitKind::Done),
            "Settle(root-confirmed) = {out:?}, want Done"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn loop2_subagent_shaped_reply_does_not_release_hold() {
        let mut sub = FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, Some(json!(2)))),
        ]);
        sub.block = true;
        let sub = Arc::new(sub);
        let proof = history_ok(vec![
            user_ev(10),
            asst(
                11,
                "completed",
                "subagent-only text",
                Some(json!({"agent_id": "S", "root_agent_id": "R"})),
            ),
        ]);
        let hist = Arc::new(QueueHistory::new(vec![proof.clone(), proof]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(5),
            recheck_after: None,
            check_every: None,
            after_seq: 10,
            has_after_seq: true,
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert_eq!(res.exit_code, 124);
    }

    #[tokio::test(start_paused = true)]
    async fn loop2_proof_reply_survives_vanishing_final_read() {
        let mut sub = FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, Some(json!(2)))),
        ]);
        sub.block = true;
        let sub = Arc::new(sub);
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(10)]),
            history_ok(vec![
                user_ev(10),
                asst(11, "completed", "proof reply", None),
            ]),
            history_ok(vec![user_ev(10)]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(600),
            recheck_after: Some(StdDuration::from_secs(20)),
            check_every: Some(StdDuration::from_secs(60)),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.replies.len(), 1);
        assert_eq!(res.replies[0].seq, 11);
        assert_eq!(res.final_text, "proof reply");
        assert_eq!(
            res.note,
            "final read missed the settle proof reply; reporting the proof reply"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn loop2_follow_up_turn_reply_excluded() {
        let mut sub = FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, Some(json!(2)))),
        ]);
        sub.block = true;
        let sub = Arc::new(sub);
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(10)]),
            history_ok(vec![user_ev(10), asst(11, "completed", "this turn", None)]),
            history_ok(vec![
                user_ev(10),
                asst(11, "completed", "this turn", None),
                user_ev(20),
                asst(21, "completed", "FOLLOWUP", None),
            ]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(600),
            recheck_after: Some(StdDuration::from_secs(20)),
            check_every: Some(StdDuration::from_secs(60)),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.replies.len(), 1);
        assert_eq!(res.replies[0].seq, 11);
        assert_eq!(res.final_text, "this turn");
        assert_eq!(res.note, "replies after a newer user message were excluded");
    }

    #[tokio::test(start_paused = true)]
    async fn loop2_lag_window_auth_error_propagates() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(100)]),
            history_ok(vec![user_ev(100)]),
            HistoryResp {
                events: Vec::new(),
                has_more: false,
                err: Some(TransportError::Auth {
                    message: "expired".to_string(),
                }),
            },
        ]));
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .expect("config");
        let cancel = Cancel::new();
        let handle = tokio::spawn(async move { runner.run(cancel).await });
        let outcome = drive(handle).await;
        assert!(
            matches!(outcome, Err(RunError::Auth(TransportError::Auth { .. }))),
            "outcome = {outcome:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn loop2_lag_window_retries_transient_error() {
        let sub = Arc::new(FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, None)),
        ]));
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(100)]),
            history_ok(vec![user_ev(100)]),
            err_history_resp(),
            history_ok(vec![
                user_ev(100),
                asst(190, "completed", "late reply", None),
            ]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(60),
            lag_window: StdDuration::from_secs(2),
            lag_poll: StdDuration::from_millis(250),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.final_text, "late reply");
    }

    #[tokio::test(start_paused = true)]
    async fn loop2_explicit_boundary_accepts_replayed_failed() {
        let sub = Arc::new(FakeSubscriber::new(vec![record_json(&task_ev(
            "interrupted",
            "R",
            "R",
            180,
            None,
        ))]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(200)])]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(5),
            has_after_seq: true,
            after_seq: 200,
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Failed);
        assert_eq!(res.exit_code, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn loop2_interrupted_held_for_subagents_settles_failed() {
        let sub = Arc::new(FakeSubscriber::new(vec![record_json(&task_ev(
            "interrupted",
            "R",
            "R",
            180,
            Some(json!(2)),
        ))]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(200)])]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(5),
            has_after_seq: true,
            after_seq: 200,
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Failed);
        assert_eq!(res.exit_code, 2);
    }

    #[tokio::test]
    async fn loop2_accept_replayed_failed_parity() {
        use castctl_telegram::wait::Waiter;
        // Explicit boundary accepts.
        let mut w = Waiter::new("");
        w.feed(&task_ev("interrupted", "R", "R", 0, None), None)
            .await;
        w.set_boundary(200, false, false);
        let out = w.accept_replayed_failed(Some(200));
        assert!(
            matches!(out, Some(ref o) if o.kind == WaitKind::Failed),
            "explicit boundary accept = {out:?}, want KindFailed"
        );
        // Subagents reason accepts.
        let mut w2 = Waiter::new("");
        w2.feed(&task_ev("interrupted", "R", "R", 0, Some(json!(2))), None)
            .await;
        w2.set_boundary(200, false, true);
        let out = w2.accept_replayed_failed(Some(200));
        assert!(
            matches!(out, Some(ref o) if o.kind == WaitKind::Failed),
            "subagents reason accept = {out:?}, want KindFailed"
        );
        // Missing root still refuses.
        let mut w3 = Waiter::new("");
        w3.feed(&task_ev("interrupted", "", "S", 0, None), None)
            .await;
        w3.set_boundary(200, false, true);
        let out = w3.accept_replayed_failed(Some(200));
        assert!(out.is_none(), "missing_root accept = {out:?}, want nil");
    }

    #[tokio::test(start_paused = true)]
    async fn loop2_flapping_terminals_do_not_storm_history() {
        let mut script = vec![record_json(&task_ev("running", "R", "R", 120, None))];
        for _ in 0..3 {
            script.push(record_json(&task_ev(
                "completed",
                "R",
                "R",
                180,
                Some(json!(2)),
            )));
            script.push(record_json(&task_ev("idle", "R", "R", 181, None)));
        }
        let sub = Arc::new(FakeSubscriber::new(script));
        let hist = Arc::new(ScriptHistory::new(history_ok(vec![user_ev(10)])));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(12),
            recheck_after: None,
            check_every: None,
            dial: Some(sub.dial()),
            history: Some(hist.clone()),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert!(
            hist.call_count() <= 6,
            "history reads = {}, want <= 6 (interval-gated proofs)",
            hist.call_count()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn loop2_failing_reader_does_not_storm_history() {
        let mut script = vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, Some(json!(2)))),
        ];
        for _ in 0..18 {
            script.push(record_json(&task_ev("idle", "R", "R", 181, None)));
        }
        let sub = Arc::new(FakeSubscriber::new(script));
        let hist = Arc::new(QueueHistory::new(vec![err_history_resp()]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(5),
            recheck_after: None,
            check_every: None,
            dial: Some(sub.dial()),
            history: Some(Arc::clone(&hist) as Arc<dyn HistoryReader>),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Timeout);
        assert!(
            hist.calls() <= 10,
            "history calls = {}, want <= 10 (6 derivation + 1 gated proof + 2 final + slack)",
            hist.calls()
        );
    }

    #[test]
    fn loop2_settle_poll_interval_minimum_clamp() {
        let cfg = |interval: StdDuration| Config {
            dial: Some(Arc::new(FakeSubscriber::new(vec![])).dial()),
            history: Some(Arc::new(QueueHistory::new(vec![history_ok(vec![])]))),
            settle_poll_interval: interval,
            ..Config::default()
        };
        for interval in [StdDuration::from_nanos(1), StdDuration::from_millis(50)] {
            let runner = Runner::new(cfg(interval)).expect("config");
            assert_eq!(
                runner.cfg.settle_poll_interval,
                StdDuration::from_millis(100),
                "interval {interval:?} must clamp to 100ms"
            );
        }
        let runner = Runner::new(cfg(StdDuration::from_millis(200))).expect("config");
        assert_eq!(
            runner.cfg.settle_poll_interval,
            StdDuration::from_millis(200),
            "interval 200ms must be preserved"
        );
    }

    #[tokio::test]
    async fn loop2_settle_pending_does_not_start_past_deadline() {
        let sub = Arc::new(FakeSubscriber::new(vec![]));
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![
            user_ev(10),
            asst(11, "completed", "x", None),
        ])]));
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(sub.dial()),
            history: Some(Arc::clone(&hist) as Arc<dyn HistoryReader>),
            ..Config::default()
        })
        .expect("config");
        runner
            .waiter
            .feed(&task_ev("running", "R", "R", 120, None), None)
            .await;
        runner
            .waiter
            .feed(&task_ev("idle", "R", "R", 180, None), None)
            .await;
        runner.waiter.set_boundary(10, false, false);
        runner.after_seq = 10;
        runner.deadline = Some(tokio::time::Instant::now() - StdDuration::from_secs(1));
        let cancel = Cancel::new();
        runner
            .settle_pending(&cancel, "idle")
            .await
            .expect("settle past deadline must return Ok");
        assert_eq!(hist.calls(), 0);
    }

    #[tokio::test]
    async fn loop2_check_state_does_not_start_past_deadline() {
        let dials: Arc<StdMutex<usize>> = Arc::new(StdMutex::new(0));
        let dials2 = Arc::clone(&dials);
        let sub = Arc::new(FakeSubscriber::new(vec![]));
        let dial: DialFn = Arc::new(move |_cancel: Cancel| {
            let dials2 = Arc::clone(&dials2);
            let sub = Arc::clone(&sub);
            Box::pin(async move {
                *dials2.lock().expect("lock") += 1;
                Ok(Some(sub as Arc<dyn Subscriber>))
            })
        });
        let hist = Arc::new(QueueHistory::new(vec![history_ok(vec![user_ev(10)])]));
        let mut runner = Runner::new(Config {
            timeout: StdDuration::from_secs(60),
            dial: Some(dial),
            history: Some(hist),
            ..Config::default()
        })
        .expect("config");
        runner.deadline = Some(tokio::time::Instant::now() - StdDuration::from_secs(1));
        let cancel = Cancel::new();
        runner
            .check_state(&cancel)
            .await
            .expect("check past deadline must return Ok");
        assert_eq!(*dials.lock().expect("lock"), 0);
    }

    #[test]
    fn loop2_user_ack_empty_text_never_acks() {
        use castctl_telegram::wait::user_ack;
        let events = vec![json!({
            "event_name": "message.user",
            "seq": 5,
            "payload": {"display_text": "hello"},
        })];
        assert!(
            user_ack(&events, 0, Some("")).is_none(),
            "empty needle must never ack"
        );
        assert!(
            user_ack(&events, 0, Some("   ")).is_none(),
            "whitespace needle must never ack"
        );
    }

    // -- wait_redesign_loop3_test.go (2 fns) --

    #[tokio::test(start_paused = true)]
    async fn loop3_proof_reply_restored_into_non_empty_final_read() {
        let mut sub = FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, Some(json!(2)))),
        ]);
        sub.block = true;
        let sub = Arc::new(sub);
        let proof = history_ok(vec![
            user_ev(10),
            asst(
                11,
                "completed",
                "subagent text",
                Some(json!({"agent_id": "S", "root_agent_id": "R"})),
            ),
            asst(
                12,
                "completed",
                "root reply",
                Some(json!({"agent_id": "R", "root_agent_id": "R"})),
            ),
        ]);
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(10)]),
            proof,
            history_ok(vec![
                user_ev(10),
                asst(
                    11,
                    "completed",
                    "subagent text",
                    Some(json!({"agent_id": "S", "root_agent_id": "R"})),
                ),
            ]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(600),
            recheck_after: Some(StdDuration::from_secs(20)),
            check_every: Some(StdDuration::from_secs(60)),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.replies.len(), 2);
        assert_eq!(res.replies[0].seq, 11);
        assert_eq!(res.replies[1].seq, 12);
        assert_eq!(res.final_text, "root reply");
        assert_eq!(
            res.note,
            "final read missed the settle proof reply; reporting the proof reply"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn loop3_restore_wins_over_follow_up_exclusion_note() {
        let mut sub = FakeSubscriber::new(vec![
            record_json(&task_ev("running", "R", "R", 120, None)),
            record_json(&task_ev("completed", "R", "R", 180, Some(json!(2)))),
        ]);
        sub.block = true;
        let sub = Arc::new(sub);
        let proof = history_ok(vec![
            user_ev(10),
            asst(
                11,
                "completed",
                "subagent text",
                Some(json!({"agent_id": "S", "root_agent_id": "R"})),
            ),
            asst(
                12,
                "completed",
                "root reply",
                Some(json!({"agent_id": "R", "root_agent_id": "R"})),
            ),
        ]);
        let hist = Arc::new(QueueHistory::new(vec![
            history_ok(vec![user_ev(10)]),
            proof,
            history_ok(vec![
                user_ev(10),
                asst(
                    11,
                    "completed",
                    "subagent text",
                    Some(json!({"agent_id": "S", "root_agent_id": "R"})),
                ),
                user_ev(20),
                asst(21, "completed", "FOLLOWUP", None),
            ]),
        ]));
        let res = run_runner(Config {
            timeout: StdDuration::from_secs(600),
            recheck_after: Some(StdDuration::from_secs(20)),
            check_every: Some(StdDuration::from_secs(60)),
            dial: Some(sub.dial()),
            history: Some(hist),
            ..default_config()
        })
        .await;
        assert_eq!(res.kind, WaitKind::Done);
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.replies.len(), 2);
        assert_eq!(res.replies[0].seq, 11);
        assert_eq!(res.replies[1].seq, 12);
        assert_eq!(res.final_text, "root reply");
        assert_eq!(
            res.note,
            "final read missed the settle proof reply; reporting the proof reply"
        );
    }

    // -- gateway_test.go: TestEndedWithoutTerminalPredicate --
    //
    // Helper-level only: it pins what counts as "terminal"
    // over gathered records, not that the Runner uses it
    // (the Runner never calls it — Go SEAMS.md §6 G2).
    // `TestGatewaySubscribeFeedsWaiter` is NOT ported as a
    // unit test: the Rust fake gateway server lives in
    // `castctl-gateway/tests/common/fake_server.rs`
    // (test-only, not importable from another crate), and
    // building a `Gateway::from_handshaked` test would need
    // reimplementing the WS+Noise handshake. Its intent —
    // the Runner consumes a real gateway through
    // SubscribeRaw — is covered by gate (b) live proof.

    fn ended_without_terminal(
        records: &[Vec<u8>],
        pred: Option<&mut dyn FnMut(&[u8]) -> bool>,
    ) -> bool {
        let Some(pred) = pred else {
            return true;
        };
        !records.iter().any(|rec| pred(rec))
    }

    fn terminal_predicate() -> impl FnMut(&[u8]) -> bool {
        use castctl_telegram::wait::{is_done_status, is_failed_status, task_status_info};
        let mut seen_running = false;
        let mut root = String::new();
        move |rec: &[u8]| {
            let Some(ev) = crate::events::decode_record(rec) else {
                return false;
            };
            let Some(info) = task_status_info(&ev, "") else {
                return false;
            };
            if !info.has_status {
                return false;
            }
            if info.status == "running" && info.root_confirmed {
                if !seen_running {
                    seen_running = true;
                    root = info.root_agent_id.clone();
                }
                return false;
            }
            if !seen_running || !info.root_confirmed || info.root_agent_id != root {
                return false;
            }
            is_done_status(&info.status) || is_failed_status(&info.status)
        }
    }

    #[test]
    fn gateway_ended_without_terminal_predicate() {
        let running = br#"{"event":"task.status","payload":{"status":"running","root_agent_id":"R","agent_id":"R"}}"#.to_vec();
        let completed = br#"{"event":"task.status","payload":{"status":"completed","root_agent_id":"R","agent_id":"R"}}"#.to_vec();
        let foreign = br#"{"event":"task.status","payload":{"status":"completed","root_agent_id":"R2","agent_id":"R2"}}"#.to_vec();
        let suspect = br#"{"event":"task.status","payload":{"status":"idle","root_agent_id":"R","agent_id":"R"}}"#.to_vec();
        assert!(
            ended_without_terminal(&[running.clone()], Some(&mut terminal_predicate())),
            "running-only records must end without terminal"
        );
        assert!(
            !ended_without_terminal(
                &[running.clone(), completed.clone()],
                Some(&mut terminal_predicate())
            ),
            "DONE after running must count as a terminal"
        );
        assert!(
            ended_without_terminal(&[completed.clone()], Some(&mut terminal_predicate())),
            "DONE before any running must not count as a terminal"
        );
        assert!(
            ended_without_terminal(
                &[running.clone(), suspect.clone()],
                Some(&mut terminal_predicate())
            ),
            "suspect strings must not count as terminal"
        );
        assert!(
            ended_without_terminal(
                &[running.clone(), foreign.clone()],
                Some(&mut terminal_predicate())
            ),
            "foreign-root DONE must not count as a terminal"
        );
        assert!(
            ended_without_terminal(&[running], None),
            "nil predicate must report no terminal"
        );
    }
}
