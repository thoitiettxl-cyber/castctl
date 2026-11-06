// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Time seam — port of `internal/keeper/clock.go`.
//!
//! Go: `Clock` interface (`Now`, `After`) + `RealClock`.
//! Rust: async `sleep` instead of the `After` channel, and a
//! [`CancelFlag`] instead of `context.Context` cancellation.
//! "No time.Sleep anywhere in keeper code" (`clock.go:20-23`)
//! holds here too: every wait goes through `Clock::sleep`.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};

/// Cancellation handle, the Rust analogue of Go's
/// `context.Context` Done channel for keeper waits. Cloning
/// shares the flag; [`CancelFlag::cancel`] wakes every
/// waiter exactly once per call.
#[derive(Debug, Clone)]
pub struct CancelFlag {
    inner: Arc<(AtomicBool, tokio::sync::Notify)>,
}

impl Default for CancelFlag {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelFlag {
    /// A flag that is not cancelled.
    pub fn new() -> Self {
        Self {
            inner: Arc::new((AtomicBool::new(false), tokio::sync::Notify::new())),
        }
    }

    /// A flag that is already cancelled.
    pub fn already_cancelled() -> Self {
        let flag = Self::new();
        flag.cancel();
        flag
    }

    /// Cancel: every current and future waiter observes it.
    pub fn cancel(&self) {
        self.inner.0.store(true, Ordering::SeqCst);
        self.inner.1.notify_waiters();
    }

    /// `true` once cancelled (never resets).
    pub fn is_cancelled(&self) -> bool {
        self.inner.0.load(Ordering::SeqCst)
    }

    /// A child flag: cancelled when this flag is cancelled,
    /// but independently cancellable (cancelling the child
    /// does NOT cancel the parent). One background task
    /// watches the parent; it ends when the parent cancels.
    pub fn child(&self) -> Self {
        let child = Self::new();
        let parent = self.clone();
        let child2 = child.clone();
        tokio::spawn(async move {
            parent.cancelled().await;
            child2.cancel();
        });
        child
    }

    /// Resolves when the flag is cancelled (immediately when
    /// already cancelled).
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.inner.1.notified();
        tokio::pin!(notified);
        // `enable` registers the waiter without polling, so a
        // cancel between registration and the await below is
        // not missed; re-check after enabling.
        notified.as_mut().enable();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

/// The keeper's time seam.
pub trait Clock: Send + Sync {
    /// Current time.
    fn now(&self) -> DateTime<Utc>;

    /// Sleep for `d`, or until `cancel` fires. Returns `true`
    /// when the full duration elapsed, `false` when cancelled
    /// first (Go `Backoff.Sleep`, `backoff.go:96-103`).
    fn sleep(
        &self,
        d: Duration,
        cancel: &CancelFlag,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
}

/// Production clock: wall time + `tokio::time::sleep`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn sleep(
        &self,
        d: Duration,
        cancel: &CancelFlag,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        let cancel = cancel.clone();
        Box::pin(async move {
            tokio::select! {
                () = tokio::time::sleep(d) => true,
                () = cancel.cancelled() => false,
            }
        })
    }
}

/// Test clock: a fixed, settable `now`; `sleep` returns
/// immediately (always `true` unless already cancelled).
#[derive(Debug, Clone)]
pub struct FakeClock {
    now: Arc<std::sync::Mutex<DateTime<Utc>>>,
}

impl FakeClock {
    /// A fake clock fixed at `now`.
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            now: Arc::new(std::sync::Mutex::new(now)),
        }
    }

    /// Move the fake time.
    pub fn set_now(&self, now: DateTime<Utc>) {
        *self.now.lock().expect("fake clock lock") = now;
    }

    /// Advance the fake time by `d`.
    pub fn advance(&self, d: Duration) {
        let mut now = self.now.lock().expect("fake clock lock");
        *now += d;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> DateTime<Utc> {
        *self.now.lock().expect("fake clock lock")
    }

    fn sleep(
        &self,
        _d: Duration,
        cancel: &CancelFlag,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        let cancelled = cancel.is_cancelled();
        Box::pin(async move { !cancelled })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[tokio::test]
    async fn cancel_flag_cancel_wakes_waiter() {
        let flag = CancelFlag::new();
        assert!(!flag.is_cancelled());
        let flag2 = flag.clone();
        let waiter = tokio::spawn(async move { flag2.cancelled().await });
        tokio::time::sleep(Duration::from_millis(5)).await;
        flag.cancel();
        assert!(flag.is_cancelled());
        waiter.await.expect("waiter joins");
    }

    #[tokio::test]
    async fn fake_clock_sleep_is_instant_and_cancellable() {
        let clock = FakeClock::new(Utc.with_ymd_and_hms(2026, 11, 5, 0, 0, 0).unwrap());
        assert!(
            clock
                .sleep(Duration::from_secs(3600), &CancelFlag::new())
                .await
        );
        assert!(
            !clock
                .sleep(Duration::from_secs(3600), &CancelFlag::already_cancelled())
                .await
        );
        clock.advance(Duration::from_secs(70 * 60));
        assert_eq!(
            clock.now(),
            Utc.with_ymd_and_hms(2026, 11, 5, 1, 10, 0).unwrap()
        );
    }
}
