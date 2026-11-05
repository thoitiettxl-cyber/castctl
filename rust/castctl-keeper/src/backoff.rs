// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Transient-error backoff — port of
//! `internal/keeper/backoff.go`.
//!
//! The ladder is CONFIG, not code: each keeper entry carries
//! its `retry_backoff` list (default 5m, 15m, 45m —
//! `profile.DefaultRetryBackoff`, `internal/profile/
//! keeper.go:230`), each step ±20% uniform jitter re-drawn
//! per delay, at most `len(ladder)` retries per tick.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::clock::{CancelFlag, Clock};

/// Retry cap per tick for the DEFAULT ladder
/// (`backoff.go:42`).
pub const BACKOFF_MAX_RETRIES: usize = 3;

/// The default ladder, referenced from the config default,
/// never copied as a second literal (`backoff.go:41`).
pub const DEFAULT_BACKOFF_LADDER: &[Duration] = &[
    Duration::from_secs(5 * 60),
    Duration::from_secs(15 * 60),
    Duration::from_secs(45 * 60),
];

/// Tracks one tick's transient retries (`backoff.go:47-52`).
pub struct Backoff {
    clock: Arc<dyn Clock>,
    jitter: Arc<dyn Fn() -> f64 + Send + Sync>,
    ladder: Vec<Duration>,
    attempts: usize,
}

impl Backoff {
    /// A backoff on the default ladder. A `None` jitter
    /// means `rand::random::<f64>()` (Go: `math/rand`'s
    /// locked global source).
    pub fn new(clock: Arc<dyn Clock>, jitter: Option<Arc<dyn Fn() -> f64 + Send + Sync>>) -> Self {
        Self::with_ladder(clock, jitter, &[])
    }

    /// A backoff on the given ladder. A nil or empty ladder
    /// means the default ladder; the ladder is copied
    /// (`backoff.go:62-76`).
    pub fn with_ladder(
        clock: Arc<dyn Clock>,
        jitter: Option<Arc<dyn Fn() -> f64 + Send + Sync>>,
        ladder: &[Duration],
    ) -> Self {
        let jitter: Arc<dyn Fn() -> f64 + Send + Sync> = match jitter {
            Some(j) => j,
            None => Arc::new(|| rand::random::<f64>()),
        };
        let ladder = if ladder.is_empty() {
            DEFAULT_BACKOFF_LADDER.to_vec()
        } else {
            ladder.to_vec()
        };
        Self {
            clock,
            jitter,
            ladder,
            attempts: 0,
        }
    }

    /// The next retry delay, or `None` when the ladder is
    /// exhausted. The ±20% jitter is re-drawn per call:
    /// `delay = base * (1 + (u*2-1)*0.2)` with `u` in
    /// `[0,1)` (`backoff.go:80-87`).
    pub fn next_delay(&mut self) -> Option<Duration> {
        if self.attempts >= self.ladder.len() {
            return None;
        }
        let base = self.ladder[self.attempts];
        self.attempts += 1;
        let j = 1.0 + ((self.jitter)() * 2.0 - 1.0) * 0.2;
        Some(Duration::from_secs_f64(base.as_secs_f64() * j))
    }

    /// Number of delays handed out so far.
    pub fn attempts(&self) -> usize {
        self.attempts
    }

    /// Wait for `d` or cancellation, via the clock seam.
    /// Returns `false` when the context ended first: the
    /// tick must stop, not retry. No `time.Sleep` anywhere
    /// in keeper code (`backoff.go:96-103`).
    pub async fn sleep(&self, d: Duration, cancel: &CancelFlag) -> bool {
        self.clock.sleep(d, cancel).await
    }
}

/// The entry's next scheduled delay after a tick (freeze
/// (b), `backoff.go:111-124`): when a driving expiry is
/// known, the delay is `min(base, clamp(remaining/4, 1h,
/// 7d))`; otherwise the base interval. `remaining` may be
/// negative (expiry already past): the clamp floors at 1h,
/// so an expired cookie re-checks hourly rather than
/// spinning.
pub fn next_delay_after(
    base: Duration,
    driving_expiry: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Duration {
    let Some(expiry) = driving_expiry else {
        return base;
    };
    let remaining = expiry.signed_duration_since(now);
    let mut adaptive = remaining / 4;
    let hour = chrono::Duration::hours(1);
    let week = chrono::Duration::hours(7 * 24);
    if adaptive < hour {
        adaptive = hour;
    } else if adaptive > week {
        adaptive = week;
    }
    let adaptive = adaptive.to_std().unwrap_or(Duration::from_secs(3600));
    if adaptive < base { adaptive } else { base }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;
    use chrono::TimeZone;

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).unwrap()
    }

    #[test]
    fn ladder_exhausts_after_len_steps() {
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(utc(2026, 11, 5, 0, 0, 0)));
        // Fixed jitter u=0.5 -> factor 1.0: literal delays.
        let mut b = Backoff::with_ladder(
            clock,
            Some(Arc::new(|| 0.5)),
            &[Duration::from_secs(300), Duration::from_secs(900)],
        );
        assert_eq!(b.next_delay(), Some(Duration::from_secs(300)));
        assert_eq!(b.next_delay(), Some(Duration::from_secs(900)));
        assert_eq!(b.next_delay(), None);
        assert_eq!(b.attempts(), 2);
    }

    #[test]
    fn jitter_bounds_plus_minus_twenty_percent() {
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(utc(2026, 11, 5, 0, 0, 0)));
        // u=0 -> 0.8x; u=1 (exclusive in practice, boundary) -> 1.2x.
        let mut b0 = Backoff::with_ladder(
            Arc::clone(&clock),
            Some(Arc::new(|| 0.0)),
            &[Duration::from_secs(300)],
        );
        assert_eq!(b0.next_delay(), Some(Duration::from_secs(240)));
        let mut b1 =
            Backoff::with_ladder(clock, Some(Arc::new(|| 1.0)), &[Duration::from_secs(300)]);
        assert_eq!(b1.next_delay(), Some(Duration::from_secs(360)));
    }

    #[test]
    fn next_delay_after_adaptive() {
        let now = utc(2026, 11, 5, 0, 0, 0);
        let base = Duration::from_secs(24 * 3600);
        // No driving expiry -> base.
        assert_eq!(next_delay_after(base, None, now), base);
        // Remaining 8h -> 8h/4 = 2h < base -> 2h.
        assert_eq!(
            next_delay_after(base, Some(utc(2026, 11, 5, 8, 0, 0)), now),
            Duration::from_secs(2 * 3600)
        );
        // Remaining 2h -> 30m, floored to 1h.
        assert_eq!(
            next_delay_after(base, Some(utc(2026, 11, 5, 2, 0, 0)), now),
            Duration::from_secs(3600)
        );
        // Remaining 40d -> 10d, capped to 7d; base 24h wins (min).
        assert_eq!(
            next_delay_after(base, Some(utc(2026, 12, 15, 0, 0, 0)), now),
            base
        );
        // Remaining 40d with base 10d -> 7d cap.
        assert_eq!(
            next_delay_after(
                Duration::from_secs(10 * 24 * 3600),
                Some(utc(2026, 12, 15, 0, 0, 0)),
                now
            ),
            Duration::from_secs(7 * 24 * 3600)
        );
        // Expiry already past -> floor 1h, not a spin.
        assert_eq!(
            next_delay_after(base, Some(utc(2026, 11, 4, 0, 0, 0)), now),
            Duration::from_secs(3600)
        );
    }
}
