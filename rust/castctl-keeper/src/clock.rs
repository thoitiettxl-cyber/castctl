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

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, FixedOffset, Local, TimeZone, Utc};

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
///
/// `now()` returns the machine-local time as a
/// `DateTime<FixedOffset>` (Go `time.Now()`): the stored
/// offset is the machine zone's offset at that instant, so
/// state files and outputs render `+07:00` on a `+07:00`
/// machine instead of `+00:00`. The zone is resolved the
/// way Go's `time.Local` resolves `TZ` (see
/// `go_local_now`, fix loop 1 B5) — an unknown `TZ` name
/// or a POSIX TZ string falls back to UTC, never to
/// `/etc/localtime`. `FixedOffset` (not `DateTime<Local>`)
/// because a parsed stored offset must survive a
/// round-trip verbatim — parsing into `Local` would
/// convert to the machine zone and drop it (M7g).
pub trait Clock: Send + Sync {
    /// Current time.
    fn now(&self) -> DateTime<FixedOffset>;

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
    fn now(&self) -> DateTime<FixedOffset> {
        // Read TZ as bytes (fix loop 2, R2-B3): a non-UTF8
        // value is an unknown zone name -> UTC, not
        // "unset" — `env::var` conflates the two errors.
        let tz = std::env::var_os("TZ");
        go_local_now(tz.as_deref(), Utc::now())
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

/// Go-compatible `time.Local` now (fix loop 1, B5): the
/// local time at `now_utc` under the `TZ` value `tz`
/// (`None` = unset). Go resolves `TZ` as a zoneinfo name
/// only — an unknown name or a POSIX TZ string falls back
/// to UTC, never to `/etc/localtime` and never by parsing
/// the POSIX form — while chrono's `Local` does both. The
/// `TZ` value is a parameter (not the process env) so
/// tests can pin the matrix without mutating global env
/// under the parallel test runner. It is passed as raw
/// bytes (`&OsStr`, fix loop 2 R2-B3): a non-UTF8 `TZ` is
/// an unknown name (Go's `loadLocation` fails on it ->
/// UTC), not "unset" — `env::var` conflates "unset" and
/// "not valid UTF-8" into one error.
///
/// Unlike Go, which resolves `time.Local` once
/// (`localOnce`), this re-reads `TZ` on every `now()`
/// call (round-2 red-team N1): nothing in-process
/// changes `TZ`, so the observable behaviour matches;
/// the re-read is documented, not fixed.
///
/// Rules, probed live on cue 2026-11-07 (Go vs chrono
/// `Local::now()`, see PORTING.md §M7g fix loop 1):
/// - `TZ` unset -> the local time at `now_utc` from
///   `/etc/localtime` (chrono `Local`, the one case where
///   it agrees with Go; fix loop 2 safety N1: derived
///   from the passed instant, not a fresh `Local::now()`
///   read).
/// - `TZ` set-but-empty -> UTC (Go: `TZ=""` is UTC,
///   unlike unset).
/// - One leading `:` is stripped (`:Asia/Ho_Chi_Minh`).
/// - `UTC` -> UTC.
/// - An absolute path is loaded directly (including `..`
///   segments: `/usr/share/zoneinfo/../zoneinfo/UTC`
///   loads in Go); a missing/unreadable/non-TZif file
///   -> UTC.
/// - A relative name is joined onto each zoneinfo dir in
///   order (`/usr/share/zoneinfo`, `/usr/share/lib/zoneinfo`,
///   `/usr/lib/locale/TZ`, `/etc/zoneinfo` — Go's
///   `platformZoneSources`, minus the GOROOT `zoneinfo.zip`,
///   which no Debian host with tzdata installed needs) and
///   the first readable TZif file wins; `..` segments
///   resolve through the OS exactly as in Go
///   (`../../../../etc/localtime` loads,
///   `../etc/localtime` does not exist -> UTC).
///   Anything else -> UTC (this is where Go and chrono
///   diverge: `GarbageXYZ`, `UTC+7`, `EST5EDT,…`).
///
/// A candidate must be a regular file first, so a
/// crafted `TZ` can never make the keeper read stdin or
/// another non-file (Go would try; failing closed to UTC
/// is the safe divergence, recorded in PORTING.md).
fn go_local_now(tz: Option<&OsStr>, now_utc: DateTime<Utc>) -> DateTime<FixedOffset> {
    let Some(tz) = tz else {
        // `TZ` unset: `/etc/localtime`, like Go's
        // `loadLocation("localtime")` — at the passed
        // instant, not "now" (safety N1).
        return Local.from_utc_datetime(&now_utc.naive_utc()).fixed_offset();
    };
    // Go strips one leading ':' (`:Asia/Ho_Chi_Minh`).
    // Bytes, not `str`: a non-UTF8 name must stay a name
    // (unknown -> UTC), never become "unset" (R2-B3).
    let name = tz.as_encoded_bytes();
    let name = name.strip_prefix(b":").unwrap_or(name);
    if name.is_empty() || name == b"UTC" {
        return now_utc.fixed_offset();
    }
    let unix = now_utc.timestamp();
    if name.starts_with(b"/") {
        // Absolute path: Go loads the file directly.
        let path = Path::new(OsStr::from_bytes(name));
        if path.is_file()
            && let Some(off) = castctl_shared::timefmt::tz_offset_at(path, unix)
        {
            return with_offset(now_utc, off);
        }
        return now_utc.fixed_offset();
    }
    // Relative name: first readable TZif file wins.
    for dir in [
        "/usr/share/zoneinfo",
        "/usr/share/lib/zoneinfo",
        "/usr/lib/locale/TZ",
        "/etc/zoneinfo",
    ] {
        let path = Path::new(dir).join(OsStr::from_bytes(name));
        if path.is_file()
            && let Some(off) = castctl_shared::timefmt::tz_offset_at(&path, unix)
        {
            return with_offset(now_utc, off);
        }
    }
    now_utc.fixed_offset()
}

/// Apply a raw TZif gmtoff to an instant; an
/// out-of-range offset (not representable as a
/// `FixedOffset`) falls back to UTC.
fn with_offset(now_utc: DateTime<Utc>, off: i32) -> DateTime<FixedOffset> {
    match FixedOffset::east_opt(off) {
        Some(fixed) => now_utc.with_timezone(&fixed),
        None => now_utc.fixed_offset(),
    }
}

/// Test clock: a fixed, settable `now`; `sleep` returns
/// immediately (always `true` unless already cancelled).
/// The fixed instant carries an explicit offset (e.g.
/// `FixedOffset::east_opt(7 * 3600)`), mirroring
/// `castctl-shared/src/timefmt.rs` tests.
#[derive(Debug, Clone)]
pub struct FakeClock {
    now: Arc<std::sync::Mutex<DateTime<FixedOffset>>>,
}

impl FakeClock {
    /// A fake clock fixed at `now`.
    pub fn new(now: DateTime<FixedOffset>) -> Self {
        Self {
            now: Arc::new(std::sync::Mutex::new(now)),
        }
    }

    /// Move the fake time.
    pub fn set_now(&self, now: DateTime<FixedOffset>) {
        *self.now.lock().expect("fake clock lock") = now;
    }

    /// Advance the fake time by `d`.
    pub fn advance(&self, d: Duration) {
        let mut now = self.now.lock().expect("fake clock lock");
        *now += d;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> DateTime<FixedOffset> {
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
    use std::ffi::OsStr;

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
        let fixed = FixedOffset::east_opt(7 * 3600).unwrap();
        let clock = FakeClock::new(fixed.with_ymd_and_hms(2026, 11, 5, 0, 0, 0).unwrap());
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
            fixed.with_ymd_and_hms(2026, 11, 5, 1, 10, 0).unwrap()
        );
    }

    #[test]
    fn real_clock_now_carries_the_local_offset() {
        // Production clock reads the machine zone (Go
        // `time.Now()`), not UTC: its offset equals
        // `chrono::Local`'s offset at the same instant.
        let now = RealClock.now();
        assert_eq!(now.offset(), Local::now().fixed_offset().offset());
    }

    #[test]
    fn go_local_now_matches_go_tz_matrix() {
        // Fix loop 1, B5: Go's `time.Local` resolves `TZ`
        // as a zoneinfo name only — an unknown name or a
        // POSIX TZ string falls back to UTC, never to
        // `/etc/localtime` and never by parsing the POSIX
        // form. Matrix probed live on cue 2026-11-07, Go
        // vs chrono `Local::now()` verbatim (see
        // PORTING.md §M7g fix loop 1): Go UTC for
        // `GarbageXYZ`, `UTC+7`, `EST5EDT,…`, `:`,
        // `../etc/localtime`, `/nonexistent`, while
        // `Local::now()` gave `+07:00` / `-07:00` /
        // `-05:00` there. The `TZ` value is a parameter
        // (not the process env) so parallel tests cannot
        // race on `std::env::set_var`.
        use chrono::{TimeZone, Utc};
        let nov = Utc.with_ymd_and_hms(2026, 11, 7, 12, 0, 0).unwrap();
        let jul = Utc.with_ymd_and_hms(2026, 7, 7, 12, 0, 0).unwrap();
        let epoch = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        // The machine-local offset at a fixed instant,
        // for the `None` / `/etc/localtime` rows (whatever
        // the test machine's zone is).
        let local_at_nov = Local
            .from_utc_datetime(&nov.naive_utc())
            .offset()
            .local_minus_utc();
        for (tz, at, want) in [
            (None, nov, local_at_nov),
            (Some(OsStr::new("")), nov, 0),
            (Some(OsStr::new("UTC")), nov, 0),
            (Some(OsStr::new(":UTC")), nov, 0),
            (Some(OsStr::new("Asia/Ho_Chi_Minh")), nov, 25200),
            (Some(OsStr::new(":Asia/Ho_Chi_Minh")), nov, 25200),
            (Some(OsStr::new("GarbageXYZ")), nov, 0),
            (Some(OsStr::new(":GarbageXYZ")), nov, 0),
            (Some(OsStr::new("UTC+7")), nov, 0),
            (Some(OsStr::new("EST5EDT,M3.2.0,M11.1.0")), nov, 0),
            (Some(OsStr::new("Etc/GMT+12")), nov, -43200),
            (Some(OsStr::new("America/New_York")), nov, -18000),
            (Some(OsStr::new("America/New_York")), jul, -14400),
            (
                Some(OsStr::new("/usr/share/zoneinfo/Asia/Ho_Chi_Minh")),
                nov,
                25200,
            ),
            (Some(OsStr::new("/etc/localtime")), nov, local_at_nov),
            (Some(OsStr::new(":")), nov, 0),
            (Some(OsStr::new("UTC0")), nov, 0),
            (Some(OsStr::new("../etc/localtime")), nov, 0),
            (Some(OsStr::new("/nonexistent")), nov, 0),
            (Some(OsStr::new("Asia/Ho_Chi_Minh")), epoch, 28800),
        ] {
            let got = go_local_now(tz, at).offset().local_minus_utc();
            assert_eq!(got, want, "TZ={tz:?} at {at}");
        }
    }

    #[test]
    fn go_local_now_non_utf8_tz_falls_back_to_utc() {
        // Fix loop 2, R2-B3 (round-2 red-team): a non-UTF8
        // TZ is an unknown name (Go: loadLocation fails
        // -> UTC), not "unset" (which would use
        // /etc/localtime, +07:00 on cue). The TZ value is
        // therefore read as bytes (`var_os`), never via
        // `env::var` — whose Err covers both "unset" and
        // "not valid UTF-8" and used to map both to None.
        let nov = Utc.with_ymd_and_hms(2026, 11, 7, 12, 0, 0).unwrap();
        let tz = OsStr::from_bytes(b"\xff\xfe");
        assert_eq!(
            go_local_now(Some(tz), nov).offset().local_minus_utc(),
            0,
            "non-UTF8 TZ must fall back to UTC, like Go"
        );
    }

    #[test]
    fn go_local_now_unset_uses_the_passed_instant() {
        // Safety N1 (round-2 safety): the None (TZ unset)
        // branch must derive from the passed `now_utc`,
        // not from a fresh `Local::now()` read — otherwise
        // the matrix test's None row is date-fragile on
        // DST machines (it only passes because today is
        // 2026-11-07 and cue has no DST).
        let nov = Utc.with_ymd_and_hms(2026, 11, 7, 12, 0, 0).unwrap();
        let want = Local.from_utc_datetime(&nov.naive_utc()).fixed_offset();
        assert_eq!(go_local_now(None, nov), want);
    }
}
