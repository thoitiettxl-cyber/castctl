// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Shared connection: retry across reconnects, heartbeat,
//! stale probe, down notice (M4a).
//!
//! Go sources: `internal/conn/gateway.go:14-54` (constants),
//! `internal/conn/conn.go` (`Muse`, `BoundedConnect`, `open`,
//! `Live`, `Drop`, `probeStale`, `markDown`/`markUp`,
//! `StartHeartbeat`/`heartbeatLoop`/`hbTick`/`StopHeartbeat`),
//! `internal/conn/shared.go` (`SharedConn`, `retryCall`,
//! `safeToRepeat`/`safeFor`, `SubscribeRaw` retry).
//!
//! Two retry budgets must not be confused (see PORTING.md
//! §M4a): the RPC-layer retry in `castctl-transport::retry`
//! (same numbers, one call, re-dial per attempt) and THIS
//! layer — `SharedConn` retry across reconnects (`retryCall`:
//! each iteration re-opens the shared gateway via `live()`,
//! then re-runs the call). Same constants, two different
//! layers; they are not merged.
//!
//! Cancellation: every await in this module is cancel-safe,
//! so dropping a `call_json`/`live`/heartbeat future cancels
//! it at the next await (a pause is a `tokio::time::sleep`,
//! a ping is a gateway call). No thread is ever blocked.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value as JsonValue;
use tokio::task::JoinHandle;

use crate::gateway::{Gateway, RequestOptions};
use castctl_transport::error::TransportError;
use castctl_transport::retry::{RetryPolicy, should_retry};
use castctl_transport::routes::Route;

/// Bounds one whole connect (token fetches, WebSocket and
/// Noise handshake) (Go `gateway.go:18`).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
/// Quiet interval after which a shared connection is pinged
/// by the stale probe and the heartbeat (Go `gateway.go:21`).
pub const HEARTBEAT: Duration = Duration::from_secs(25);
/// Time without a working connection before `OnDown` fires
/// once (Go `gateway.go:24`).
pub const DOWN_NOTICE: Duration = Duration::from_secs(60);
/// Coalesced failed reconnects before `OnDown` fires once
/// (Go `gateway.go:27`).
pub const DOWN_FAILS: u32 = 5;
/// Budget for `SharedConn` retry across reconnects (Go
/// `gateway.go:30`). Distinct from the RPC-layer budget of
/// the same value — see the module docs.
pub const RETRY_FOR: Duration = Duration::from_secs(30);
/// Failed reconnects closer than this coalesce into one
/// counted failure (Go `gateway.go:33`).
pub const FAIL_SPACING: Duration = Duration::from_secs(2);
/// Liveness ping bound in the stale probe (Go
/// `gateway.go:36`).
pub const STALE_PING_TIMEOUT: Duration = Duration::from_secs(5);
/// Heartbeat goroutine's ping bound (Go `gateway.go:39`).
pub const HEARTBEAT_PING_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound for `StopHeartbeat`'s wait for the heartbeat loop
/// (Go `gateway.go:42`).
pub const HEARTBEAT_STOP_TIMEOUT: Duration = Duration::from_secs(6);
/// Total attempts `SubscribeRaw` makes when the connection
/// is down before the stream opens (Go `gateway.go:46`).
pub const MAX_SUBSCRIBE_ATTEMPTS: u32 = 3;
/// First pause between `SharedConn` retries (Go
/// `gateway.go:50`).
pub const RETRY_PAUSE_INITIAL: Duration = Duration::from_millis(250);
/// Cap for the doubling pause ladder (Go `gateway.go:51`).
pub const RETRY_PAUSE_MAX: Duration = Duration::from_secs(4);
/// Fixed pause between `SubscribeRaw` attempts (Go
/// `gateway.go:54`).
pub const SUBSCRIBE_RETRY_PAUSE: Duration = Duration::from_millis(250);

/// How long a `SharedConn` waits between heartbeat ticks:
/// `min(5s, interval)` (Go `conn.go:836-840`
/// `heartbeatLoop` — with `Heartbeat` 25s that is a 5s tick).
pub fn heartbeat_tick(interval: Duration) -> Duration {
    std::cmp::min(Duration::from_secs(5), interval)
}

/// Down/outage tracking (Go `conn.go:261-312` `markDown` /
/// `markUp`). Pure logic over explicit `Instant`s, so tests
/// can drive it without waiting `DOWN_NOTICE`. The `OnDown`
/// / `OnUp` firing decision is returned to the caller, which
/// invokes the callback OUTSIDE the lock (Go `markDown` runs
/// callbacks outside `downMu`; a panicking callback must not
/// break the connection path — the caller wraps it).
#[derive(Debug, Clone)]
pub struct DownTracker {
    down_since: Option<Instant>,
    down_notified: bool,
    last_fail: Option<Instant>,
    fail_count: u32,
    down_notice: Duration,
    down_fails: u32,
    fail_spacing: Duration,
}

/// What `mark_down` decided (returned, not acted on, so the
/// caller can invoke the callback outside the lock).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownDecision {
    /// No notification (outage recorded or coalesced).
    None,
    /// Fire `OnDown` once for this outage: the connection
    /// has been down for `down_for` with `failed_reconnects`
    /// coalesced failures.
    Notify {
        /// How long the outage has lasted.
        down_for: Duration,
        /// Coalesced failed reconnects so far.
        failed_reconnects: u32,
    },
}

impl DownTracker {
    /// Production thresholds (Go `Muse` defaults from `New`).
    pub fn new() -> Self {
        Self {
            down_since: None,
            down_notified: false,
            last_fail: None,
            fail_count: 0,
            down_notice: DOWN_NOTICE,
            down_fails: DOWN_FAILS,
            fail_spacing: FAIL_SPACING,
        }
    }

    /// Test thresholds (same logic, smaller numbers).
    pub fn with_thresholds(down_notice: Duration, down_fails: u32, fail_spacing: Duration) -> Self {
        Self {
            down_since: None,
            down_notified: false,
            last_fail: None,
            fail_count: 0,
            down_notice,
            down_fails,
            fail_spacing,
        }
    }

    /// Whether an outage is currently recorded.
    pub fn has_down(&self) -> bool {
        self.down_since.is_some()
    }

    /// Coalesced failed reconnects counted in this outage.
    pub fn fail_count(&self) -> u32 {
        self.fail_count
    }

    /// Record that the gateway is down (Go `markDown`).
    /// `failed_connect` counts toward `DOWN_FAILS`, coalesced
    /// by `FAIL_SPACING`: several failures at the same moment
    /// count as one. `OnDown` fires at most once per outage,
    /// after `DOWN_NOTICE` or `DOWN_FAILS`. `AuthError` must
    /// never reach here (Go `open` does not `markDown` it).
    pub fn mark_down(
        &mut self,
        now: Instant,
        failed_connect: bool,
        _err: &TransportError,
    ) -> DownDecision {
        if self.down_since.is_none() {
            self.down_since = Some(now);
        }
        if failed_connect {
            let spaced = match self.last_fail {
                None => true,
                Some(last) => now.duration_since(last) >= self.fail_spacing,
            };
            if spaced {
                self.fail_count += 1;
                self.last_fail = Some(now);
            }
        }
        let since = self.down_since.expect("down_since just set");
        let notify = !self.down_notified
            && (now.duration_since(since) >= self.down_notice
                || self.fail_count >= self.down_fails);
        if notify {
            self.down_notified = true;
            DownDecision::Notify {
                down_for: now.duration_since(since),
                failed_reconnects: self.fail_count,
            }
        } else {
            DownDecision::None
        }
    }

    /// Record recovery (Go `markUp`). Returns `Some(duration)`
    /// only when the outage had been notified (then the caller
    /// fires `OnUp` with the outage duration); otherwise
    /// `None`. Clears all down state either way.
    pub fn mark_up(&mut self, now: Instant) -> Option<Duration> {
        let since = self.down_since?;
        let was = self.down_notified;
        self.down_since = None;
        self.down_notified = false;
        self.fail_count = 0;
        self.last_fail = None;
        if was {
            Some(now.duration_since(since))
        } else {
            None
        }
    }
}

impl Default for DownTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Opens one gateway connection (Go `internal/conn/gateway.go`
/// `Connector`: `fn(ctx, cfg) (Gateway, error)`). The
/// implementation lives in the wiring layer (M4b): it fetches
/// tokens over HTTPS, dials through the profile outbound, and
/// returns a `Gateway`. This trait is the seam `SharedConn`
/// retries across; tests inject a fake connector.
pub trait Connector: Send + Sync {
    /// Open one gateway. Auth failures MUST be returned as
    /// `TransportError::Auth` so they pass through
    /// unwrapped-typed (never retried, never counted down).
    fn connect(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<Gateway>, TransportError>> + Send + '_>>;
}

/// `OnDown` / `OnUp` notice callback (Go `Muse.onDown` /
/// `onUp`). Called outside the down-state lock; a panic in
/// the callback is caught by the caller and never breaks the
/// connection path (Go `callNotice`).
pub type NoticeCallback = Arc<dyn Fn(TransportError, Duration) + Send + Sync>;

/// The shared connection (Go `internal/conn/shared.go`
/// `SharedConn` + `internal/conn/conn.go` `Muse`): one shared
/// gateway slot, reconnect-on-demand, retry across reconnects,
/// heartbeat, stale probe, down notice.
pub struct SharedConn {
    connector: Arc<dyn Connector>,
    policy: RetryPolicy,
    heartbeat_interval: Duration,
    gateway: Mutex<Option<Arc<Gateway>>>,
    down: Mutex<DownTracker>,
    on_down: Option<NoticeCallback>,
    on_up: Option<Arc<dyn Fn(Duration) + Send + Sync>>,
    connects: AtomicU64,
    drops: AtomicU64,
    heartbeat: Mutex<Option<HeartbeatHandle>>,
    heartbeat_running: AtomicBool,
}

struct HeartbeatHandle {
    stop: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl SharedConn {
    /// Build a shared connection over `connector` with the
    /// production retry policy and heartbeat interval.
    pub fn new(connector: Arc<dyn Connector>) -> Self {
        Self::with_policy(
            connector,
            RetryPolicy {
                budget: RETRY_FOR,
                pause_initial: RETRY_PAUSE_INITIAL,
                pause_max: RETRY_PAUSE_MAX,
            },
            HEARTBEAT,
        )
    }

    /// Build with an explicit retry policy / heartbeat
    /// interval (tests inject small budgets; production uses
    /// `new` — a test that waited the full 30s budget would
    /// be a bad test, and the ladder math is identical at any
    /// scale).
    pub fn with_policy(
        connector: Arc<dyn Connector>,
        policy: RetryPolicy,
        heartbeat_interval: Duration,
    ) -> Self {
        Self {
            connector,
            policy,
            heartbeat_interval,
            gateway: Mutex::new(None),
            down: Mutex::new(DownTracker::new()),
            on_down: None,
            on_up: None,
            connects: AtomicU64::new(0),
            drops: AtomicU64::new(0),
            heartbeat: Mutex::new(None),
            heartbeat_running: AtomicBool::new(false),
        }
    }

    /// Replace the down tracker (test seam: inject
    /// `DownTracker::with_thresholds` so the down-notice path
    /// is exercisable without waiting `DOWN_NOTICE` /
    /// `DOWN_FAILS` at production scale; production uses the
    /// default tracker from `new` / `with_policy`).
    pub fn set_down_tracker(&mut self, tracker: DownTracker) {
        if let Ok(mut d) = self.down.lock() {
            *d = tracker;
        }
    }

    /// Set the `OnDown` notice callback.
    pub fn set_on_down(&mut self, cb: NoticeCallback) {
        self.on_down = Some(cb);
    }

    /// Set the `OnUp` notice callback.
    pub fn set_on_up(&mut self, cb: Arc<dyn Fn(Duration) + Send + Sync>) {
        self.on_up = Some(cb);
    }

    /// Total successful connects (Go `Muse.connects`).
    pub fn connects(&self) -> u64 {
        self.connects.load(Ordering::SeqCst)
    }

    /// Total drops (Go `Muse.drops`).
    pub fn drops(&self) -> u64 {
        self.drops.load(Ordering::SeqCst)
    }

    /// Current shared gateway, if any, without opening a
    /// connection (Go `sharedSnapshot`).
    pub fn snapshot(&self) -> Option<Arc<Gateway>> {
        self.gateway.lock().ok().and_then(|g| g.clone())
    }

    /// Whether a shared gateway is currently up, without
    /// opening a connection (Go `SharedConn.Alive`).
    pub fn alive(&self) -> bool {
        self.snapshot().map(|g| g.alive()).unwrap_or(false)
    }

    fn mark_down(&self, err: &TransportError, failed_connect: bool) {
        let decision = self
            .down
            .lock()
            .map(|mut d| d.mark_down(Instant::now(), failed_connect, err))
            .unwrap_or(DownDecision::None);
        if let DownDecision::Notify {
            down_for,
            failed_reconnects,
        } = decision
        {
            let _ = failed_reconnects;
            if let Some(cb) = &self.on_down {
                let cb = Arc::clone(cb);
                let err = err.clone();
                // A panicking callback must not break the
                // connection path (Go `callNotice`).
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    cb(err, down_for);
                }));
            }
        }
    }

    fn mark_up(&self) {
        let up = self
            .down
            .lock()
            .map(|mut d| d.mark_up(Instant::now()))
            .unwrap_or(None);
        if let Some(duration) = up
            && let Some(cb) = &self.on_up
        {
            let cb = Arc::clone(cb);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                cb(duration);
            }));
        }
    }

    /// Open (or reopen) the shared gateway (Go `Muse.Live`,
    /// simplified lock discipline: the slot is only touched
    /// under the lock, and `open` runs outside it — no network
    /// I/O under locks, as in Go). A gateway installed by
    /// another task meanwhile is used as-is (no re-probe under
    /// the lock).
    pub async fn live(&self) -> Result<Arc<Gateway>, TransportError> {
        // Fast path: a live gateway, stale-probed.
        if let Some(gw) = self.snapshot().filter(|gw| gw.alive()) {
            if self.probe_stale(&gw).await {
                return Ok(gw);
            }
            self.drop_gateway(&gw).await;
        }
        // Slow path: open outside the lock, then install.
        // Snapshot the slot first: Go `Live` detaches a dead
        // installed gateway BEFORE opening (`conn.go:500-520`),
        // so the drop is counted and the old gateway closed
        // even when the reopen fails. Rust opens first and
        // installs after, so remember the stale gateway here
        // and detach it on the open-error path below (fix
        // loop 2, F5/NB3). Only a dead gateway is detached:
        // a live one installed meanwhile is kept, as in Go.
        let stale_before_open = self.snapshot().filter(|gw| !gw.alive());
        let opened = self.open().await;
        let gw = match opened {
            Ok(gw) => gw,
            Err(e) => {
                if let Some(old) = &stale_before_open {
                    self.drop_dead(old).await;
                }
                if !matches!(e, TransportError::Auth { .. }) {
                    self.mark_down(&e, true);
                }
                return Err(e);
            }
        };
        // Decide under the lock, then act after it is
        // dropped: `std::sync::MutexGuard` is `!Send`, so no
        // await may sit inside the lock scope (the heartbeat
        // task spawns this future on the multi-threaded
        // runtime, which requires `Send`).
        enum SlotDecision {
            Use(Arc<Gateway>),
            New(Option<Arc<Gateway>>),
            Poisoned,
        }
        let decision = match self.gateway.lock() {
            Ok(mut slot) => match slot.as_ref() {
                Some(existing) if existing.alive() => {
                    // Another task installed one meanwhile:
                    // use theirs, close ours.
                    SlotDecision::Use(Arc::clone(existing))
                }
                _ => {
                    let replaced = slot.replace(Arc::clone(&gw));
                    SlotDecision::New(replaced)
                }
            },
            Err(_) => SlotDecision::Poisoned,
        };
        let installed = match decision {
            SlotDecision::Use(existing) => {
                let _ = gw.close().await;
                existing
            }
            SlotDecision::New(replaced) => {
                self.connects.fetch_add(1, Ordering::SeqCst);
                if let Some(old) = replaced {
                    // Go `Live` (`conn.go:500-520`): replacing
                    // a dead installed gateway counts the drop,
                    // records the outage (not a failed connect),
                    // and closes the old gateway after the new
                    // one is installed (`dead` falls back to
                    // Go `errGatewayClosed` ("closed") when the
                    // old gateway died without a recorded
                    // error — `internal/conn/errors.go:313-315`).
                    self.drops.fetch_add(1, Ordering::SeqCst);
                    let dead = Self::dead_error(&old);
                    self.mark_down(&dead, false);
                    old.close().await;
                }
                gw
            }
            SlotDecision::Poisoned => {
                let _ = gw.close().await;
                return Err(TransportError::ConnectionError {
                    message: "shared connection lock poisoned".to_string(),
                });
            }
        };
        self.mark_up();
        Ok(installed)
    }

    async fn open(&self) -> Result<Arc<Gateway>, TransportError> {
        self.connector.connect().await
    }

    /// Drop the shared gateway if it is exactly this instance
    /// (Go `Muse.Drop`): clear the slot, count the drop,
    /// record the outage (not a failed connect), and close
    /// outside the lock.
    pub async fn drop_gateway(&self, gw: &Arc<Gateway>) {
        let err = TransportError::ConnectionError {
            message: "heartbeat failed".to_string(),
        };
        self.drop_with(gw, err).await;
    }

    /// Drop a dead installed gateway with its own recorded
    /// death (Go `Live` detach, `conn.go:500-520`): same
    /// slot-clear + drop count + outage record + close as
    /// `drop_gateway`, but the mark-down cause is the dead
    /// error, not the heartbeat failure. Used on the
    /// `live()` open-error path (fix loop 2, F5/NB3).
    async fn drop_dead(&self, gw: &Arc<Gateway>) {
        let dead = Self::dead_error(gw);
        self.drop_with(gw, dead).await;
    }

    /// The recorded death of a gateway, falling back to Go
    /// `errGatewayClosed` ("closed") when it died without a
    /// recorded error (`internal/conn/errors.go:313-315`).
    fn dead_error(gw: &Arc<Gateway>) -> TransportError {
        gw.dead().unwrap_or(TransportError::ConnectionError {
            message: "closed".to_string(),
        })
    }

    /// Shared drop body for `drop_gateway` / `drop_dead`:
    /// clear the slot iff it still holds exactly `gw`, then
    /// count the drop, record the outage (not a failed
    /// connect), and close outside the lock. The `ptr_eq`
    /// guard also prevents double-counting when another task
    /// already dropped or replaced the gateway.
    async fn drop_with(&self, gw: &Arc<Gateway>, err: TransportError) {
        let same = {
            let mut slot = match self.gateway.lock() {
                Ok(slot) => slot,
                Err(_) => return,
            };
            match slot.as_ref() {
                Some(current) if Arc::ptr_eq(current, gw) => {
                    *slot = None;
                    true
                }
                _ => false,
            }
        };
        if same {
            self.drops.fetch_add(1, Ordering::SeqCst);
            self.mark_down(&err, false);
            gw.close().await;
        }
    }

    /// Stale probe (Go `conn.go:445-452` `probeStale`): a
    /// gateway used OR heard-from within `heartbeat_interval`
    /// is alive without a probe (two early returns in Go —
    /// either axis fresh short-circuits). Only when both are
    /// quiet for longer does a ping with `STALE_PING_TIMEOUT`
    /// settle it. The probe never drops the gateway itself;
    /// the caller does.
    pub async fn probe_stale(&self, gw: &Arc<Gateway>) -> bool {
        let now = Instant::now();
        let recv_age = now.duration_since(gw.last_recv());
        let used_age = now.duration_since(gw.last_used());
        if recv_age <= self.heartbeat_interval || used_age <= self.heartbeat_interval {
            return true;
        }
        gw.ping(STALE_PING_TIMEOUT).await.is_ok()
    }

    /// Safe-to-repeat decision for one call (Go
    /// `shared.go:138-147` `safeFor`): an explicit route wins;
    /// otherwise the gateway's `LookupRoute` supplies it;
    /// otherwise only the explicit POST-read set applies.
    pub fn safe_for(&self, gw: &Arc<Gateway>, method: &str, route: Option<&Route>) -> bool {
        if let Some(route) = route {
            return castctl_transport::retry::safe_to_repeat(method, Some(route));
        }
        if let Some(r) = gw.lookup_route(method) {
            return castctl_transport::retry::safe_to_repeat(method, Some(&r));
        }
        castctl_transport::retry::safe_to_repeat(method, None)
    }

    /// One `call_json`, retried per `retry_call` when the
    /// method is safe to repeat (Go `SharedConn.CallJSON`).
    pub async fn call_json(
        &self,
        method: &str,
        opts: RequestOptions,
    ) -> Result<JsonValue, TransportError> {
        // `safe` is decided against the gateway that will run
        // the call; resolve it lazily per attempt through a
        // fresh lookup so a reconnect can change the answer.
        // The retry loop below re-evaluates it each iteration.
        let opts2 = opts.clone();
        self.retry_call_with_safe(method, opts2, |gw, opts| {
            let method = method.to_string();
            async move { gw.call_json(&method, opts).await }
        })
        .await
    }

    /// `retry_call` variant that re-evaluates `safe_for` per
    /// attempt (the gateway may change across reconnects).
    async fn retry_call_with_safe<T, F, Fut>(
        &self,
        method: &str,
        opts: RequestOptions,
        mut call: F,
    ) -> Result<T, TransportError>
    where
        F: FnMut(Arc<Gateway>, RequestOptions) -> Fut,
        Fut: Future<Output = Result<T, TransportError>>,
    {
        let budget = Instant::now() + self.policy.budget;
        let mut pause = self.policy.pause_initial;
        loop {
            let gw = match self.live().await {
                Ok(gw) => gw,
                Err(e) => {
                    if matches!(e, TransportError::Auth { .. }) {
                        return Err(e);
                    }
                    if Instant::now() + pause > budget {
                        return Err(e);
                    }
                    tokio::time::sleep(pause).await;
                    pause = std::cmp::min(pause * 2, self.policy.pause_max);
                    continue;
                }
            };
            let safe = self.safe_for(&gw, method, opts.route.as_ref());
            match call(Arc::clone(&gw), opts.clone()).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    if matches!(e, TransportError::Auth { .. }) {
                        return Err(e);
                    }
                    let retryable = should_retry(&e, safe);
                    if !retryable || Instant::now() + pause > budget {
                        return Err(e);
                    }
                    tokio::time::sleep(pause).await;
                    pause = std::cmp::min(pause * 2, self.policy.pause_max);
                }
            }
        }
    }

    /// One `request`, retried per `retry_call` when the method
    /// is safe to repeat (Go `SharedConn.Request`).
    pub async fn request(
        &self,
        method: &str,
        opts: RequestOptions,
    ) -> Result<Vec<u8>, TransportError> {
        self.retry_call_with_safe(method, opts, |gw, opts| {
            let method = method.to_string();
            async move { gw.request(&method, opts).await }
        })
        .await
    }

    /// One ping on the current connection, with no retry (Go
    /// `SharedConn.Ping`: heartbeat / stale-probe callers own
    /// reconnect decisions).
    pub async fn ping(&self, timeout: Duration) -> Result<JsonValue, TransportError> {
        let gw = self.live().await?;
        gw.ping(timeout).await
    }

    /// Start the heartbeat loop (Go `StartHeartbeat`):
    /// no-op if already running; ticks every
    /// `min(5s, interval)`; `interval <= 0` means the
    /// `SharedConn` interval (default `HEARTBEAT`). The loop
    /// holds an `Arc` clone, so it keeps running until
    /// `stop_heartbeat` (or the `SharedConn` is dropped and
    /// the task is aborted by the runtime at shutdown).
    pub fn start_heartbeat(self: &Arc<Self>) {
        if self.heartbeat_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let interval = if self.heartbeat_interval.as_nanos() == 0 {
            HEARTBEAT
        } else {
            self.heartbeat_interval
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let this = Arc::clone(self);
        let tick = heartbeat_tick(interval);
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(tick).await;
                if stop2.load(Ordering::SeqCst) {
                    break;
                }
                this.heartbeat_tick(interval).await;
            }
        });
        if let Ok(mut slot) = self.heartbeat.lock() {
            *slot = Some(HeartbeatHandle { stop, task });
        }
    }

    /// One heartbeat tick (Go `hbTick`): never returns an
    /// error — reconnect and ping failures are logged by the
    /// caller (here: dropped) and the loop keeps trying
    /// quietly; only `mark_down` decides when to notify.
    pub async fn heartbeat_tick(&self, interval: Duration) {
        let Some(gw) = self.snapshot() else {
            if !self.down.lock().map(|d| d.has_down()).unwrap_or(false) && self.connects() == 0 {
                return; // never connected yet: first call opens it
            }
            let _ = self.live().await;
            return;
        };
        if !gw.alive() {
            let _ = self.live().await;
            return;
        }
        let now = Instant::now();
        let used = now.duration_since(gw.last_used());
        let quiet = now.duration_since(gw.last_recv());
        if used < interval && quiet < interval {
            return; // in use and the server is talking: alive
        }
        if gw.ping(HEARTBEAT_PING_TIMEOUT).await.is_err() {
            self.drop_gateway(&gw).await;
            let _ = self.live().await;
        }
    }

    /// Stop the heartbeat loop, waiting at most
    /// `HEARTBEAT_STOP_TIMEOUT` (6s) for the loop to exit
    /// (Go `StopHeartbeat`). Idempotent.
    pub async fn stop_heartbeat(&self) {
        self.heartbeat_running.store(false, Ordering::SeqCst);
        let handle = self.heartbeat.lock().ok().and_then(|mut h| h.take());
        if let Some(handle) = handle {
            handle.stop.store(true, Ordering::SeqCst);
            let _ = tokio::time::timeout(HEARTBEAT_STOP_TIMEOUT, handle.task).await;
        }
    }
}

// Hand-written Debug: a SharedConn holds no secret itself
// (the connector owns credentials), but Debug still prints
// only counts, never any gateway internals.
impl std::fmt::Debug for SharedConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SharedConn {{ connects: {}, drops: {}, alive: {} }}",
            self.connects(),
            self.drops(),
            self.alive()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_go_gateway_go_14_54() {
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(60));
        assert_eq!(HEARTBEAT, Duration::from_secs(25));
        assert_eq!(DOWN_NOTICE, Duration::from_secs(60));
        assert_eq!(DOWN_FAILS, 5);
        assert_eq!(RETRY_FOR, Duration::from_secs(30));
        assert_eq!(FAIL_SPACING, Duration::from_secs(2));
        assert_eq!(STALE_PING_TIMEOUT, Duration::from_secs(5));
        assert_eq!(HEARTBEAT_PING_TIMEOUT, Duration::from_secs(10));
        assert_eq!(HEARTBEAT_STOP_TIMEOUT, Duration::from_secs(6));
        assert_eq!(MAX_SUBSCRIBE_ATTEMPTS, 3);
        assert_eq!(RETRY_PAUSE_INITIAL, Duration::from_millis(250));
        assert_eq!(RETRY_PAUSE_MAX, Duration::from_secs(4));
        assert_eq!(SUBSCRIBE_RETRY_PAUSE, Duration::from_millis(250));
    }

    #[test]
    fn heartbeat_tick_is_min_5s_interval() {
        assert_eq!(
            heartbeat_tick(Duration::from_secs(25)),
            Duration::from_secs(5)
        );
        assert_eq!(
            heartbeat_tick(Duration::from_millis(200)),
            Duration::from_millis(200)
        );
    }

    #[test]
    fn down_tracker_coalesces_and_notifies_once_on_fails() {
        let mut t =
            DownTracker::with_thresholds(Duration::from_secs(60), 5, Duration::from_secs(2));
        let err = TransportError::ConnectionError {
            message: "down".to_string(),
        };
        let t0 = Instant::now();
        // Five failures inside FailSpacing count as ONE.
        for i in 0..5 {
            let d = t.mark_down(t0 + Duration::from_millis(i * 100), true, &err);
            assert_eq!(d, DownDecision::None, "burst must coalesce");
        }
        assert_eq!(t.fail_count(), 1);
        // Four more, each spaced >= 2s, reach 5 total.
        for i in 1..5 {
            let d = t.mark_down(t0 + Duration::from_secs(i * 2), true, &err);
            if i < 4 {
                assert_eq!(d, DownDecision::None);
            } else {
                assert_eq!(
                    d,
                    DownDecision::Notify {
                        down_for: Duration::from_secs(8),
                        failed_reconnects: 5
                    }
                );
            }
        }
        // Once notified, no second notice for the same outage.
        let d = t.mark_down(t0 + Duration::from_secs(10), true, &err);
        assert_eq!(d, DownDecision::None);
        // Recovery after a notified outage reports the duration.
        assert_eq!(
            t.mark_up(t0 + Duration::from_secs(12)),
            Some(Duration::from_secs(12))
        );
        assert!(!t.has_down());
    }

    #[test]
    fn down_tracker_notifies_on_time_even_without_fails() {
        let mut t =
            DownTracker::with_thresholds(Duration::from_secs(60), 5, Duration::from_secs(2));
        let err = TransportError::ConnectionError {
            message: "down".to_string(),
        };
        let t0 = Instant::now();
        assert_eq!(t.mark_down(t0, false, &err), DownDecision::None);
        assert_eq!(
            t.mark_down(t0 + Duration::from_secs(60), false, &err),
            DownDecision::Notify {
                down_for: Duration::from_secs(60),
                failed_reconnects: 0
            }
        );
        // An un-notified outage recovers silently.
        let mut t2 =
            DownTracker::with_thresholds(Duration::from_secs(60), 5, Duration::from_secs(2));
        assert_eq!(t2.mark_down(t0, false, &err), DownDecision::None);
        assert_eq!(t2.mark_up(t0 + Duration::from_secs(10)), None);
    }
}
