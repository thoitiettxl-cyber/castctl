// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The keeper runner — port of `internal/keeper/run.go`.
//!
//! `keeper run`: one task per entry, foreground. Each entry
//! ticks immediately, then waits its adaptive delay with
//! ±20% jitter re-drawn per wait, until cancellation or
//! the entry stops sticky. A stopped entry's task exits;
//! the runner returns when every task has exited or the
//! run is cancelled. The runner never holds the
//! cookies-file lock across a wait: the single-flight guard
//! is a heartbeat/owner file plus a SHORT flock hold per
//! check, never a flock held across a sleep.
//!
//! Single-flight: the guard is a heartbeat/owner file, NOT
//! a held flock. The flock is held only for the short
//! check-and-update window while reading/writing the owner
//! file, and is released before the caller sleeps or ticks.
//! The owner file carries the PID and the last heartbeat
//! (Unix seconds). A second runner refuses when the
//! heartbeat is fresh (≤ `OwnerStaleAfter`) AND the
//! recorded PID is alive; a stale heartbeat, or a dead PID,
//! means the previous runner is gone and the file is taken
//! over. The file is removed on a clean release; a crash
//! leaves it for the staleness rule to reclaim.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::clock::{CancelFlag, Clock};
use crate::error::KeeperError;
use crate::lockfile::lock_short_file;
use crate::notify::NoticeKind;
use crate::state::{OUTCOME_OK, STOPPED_STATE_CORRUPT, load_state};
use crate::tick::{TickDeps, TickResult, notify_stopped, tick};

/// Bounds owner-file freshness (`run.go:144`).
pub const OWNER_STALE_AFTER: Duration = Duration::from_secs(120);
/// The refresh cadence while a runner holds an entry
/// (`run.go:147`).
pub const OWNER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// One entry's run outcome for the command layer's
/// summary line (counts/names only, never values)
/// (`run.go:40-47`).
#[derive(Debug)]
pub struct RunResult {
    pub tag: String,
    pub stopped: bool,
    pub ticks: usize,
    pub last: Option<TickResult>,
}

/// The owner file body (`run.go:149-152`): PID + last
/// heartbeat (Unix seconds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerFile {
    pub pid: i32,
    pub heartbeat_unix: i64,
}

/// The owner-file path for a profile dir + tag
/// (`run.go:154-168`). The tag is validated at parse time,
/// but a hand-built entry must never escape the profile
/// directory through this path: the containment check
/// rejects any tag that would place the owner file outside
/// `profile_dir`.
pub fn owner_path(profile_dir: &str, tag: &str) -> Result<String, KeeperError> {
    let clean_dir = clean_path(profile_dir);
    let p = format!("{clean_dir}/keeper-{tag}.owner");
    let parent = std::path::Path::new(&p)
        .parent()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    if parent != clean_dir {
        return Err(KeeperError::Other(format!(
            "keeper tag {tag:?} escapes the profile directory"
        )));
    }
    Ok(p)
}

fn clean_path(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    if p.starts_with('/') {
        format!("/{}", out.join("/"))
    } else {
        out.join("/")
    }
}

/// Whether a PID exists (`run.go:282-293`). Signal 0
/// probes existence on unix; on non-unix targets the PID
/// is treated as alive (fail closed: a fresh heartbeat
/// alone refuses a second runner).
#[cfg(unix)]
pub fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    // EPERM means the process exists but we may not signal it.
    err.raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
pub fn pid_alive(_pid: i32) -> bool {
    true
}

/// A held single-flight claim. Dropping it stops the
/// heartbeat task; call [`SingleFlight::release`] for a
/// clean release (remove the owner file).
#[derive(Debug)]
pub struct SingleFlight {
    path: String,
    pid: i32,
    stop: CancelFlag,
    released: bool,
}

impl SingleFlight {
    /// Stop the heartbeat and remove the owner file (only
    /// when it still names this PID). Idempotent.
    pub fn release(mut self) {
        if self.released {
            return;
        }
        self.released = true;
        self.stop.cancel();
        release_owner(&self.path, self.pid);
    }
}

impl Drop for SingleFlight {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// Claim the entry (`run.go:171-242`). Returns the claim
/// (stop the heartbeat, remove the file) or an error
/// naming the live owner PID when the entry is already
/// running.
pub async fn acquire_single_flight(
    profile_dir: &str,
    tag: &str,
    clock: Arc<dyn Clock>,
) -> Result<SingleFlight, KeeperError> {
    castctl_config::blocks::validate_keeper_tag(tag).map_err(KeeperError::Config)?;
    let path = owner_path(profile_dir, tag)?;
    {
        let _guard = lock_short_file(&path, Duration::from_secs(1))?;
        // Short flock hold: check + update only. The lock
        // is released before the caller sleeps or ticks.
        let raw = std::fs::read(&path).unwrap_or_default();
        if !raw.is_empty()
            && let Ok(owner) = serde_json::from_slice::<OwnerFile>(&raw)
            && owner.pid > 0
        {
            let age = clock.now().timestamp() - owner.heartbeat_unix;
            if age <= OWNER_STALE_AFTER.as_secs() as i64 && pid_alive(owner.pid) {
                return Err(KeeperError::Other(format!(
                    "keeper entry {tag:?} is already running (pid {})",
                    owner.pid
                )));
            }
        }
        let now = clock.now().timestamp();
        let data = serde_json::to_string(&OwnerFile {
            pid: std::process::id() as i32,
            heartbeat_unix: now,
        })
        .map_err(|e| KeeperError::Other(e.to_string()))?;
        std::fs::write(&path, data).map_err(KeeperError::Io)?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
    let stop = CancelFlag::new();
    let stop2 = stop.clone();
    let path2 = path.clone();
    let clock2 = clock.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(OWNER_HEARTBEAT_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = stop2.cancelled() => return,
                _ = ticker.tick() => {
                    // Locked, ownership-checked refresh: a
                    // stale (SIGSTOPped) runner that resumes
                    // after a takeover must not overwrite the
                    // new owner's heartbeat.
                    refresh_owner(&path2, std::process::id() as i32, &clock2);
                }
            }
        }
    });
    Ok(SingleFlight {
        path,
        pid: std::process::id() as i32,
        stop,
        released: false,
    })
}

/// Rewrite the owner file's heartbeat under the short
/// flock, only when the file still names `pid`
/// (`run.go:244-261`). `false` when the file is owned by
/// someone else, unreadable, or the lock could not be
/// taken: the caller keeps ticking either way.
fn refresh_owner(path: &str, pid: i32, clock: &Arc<dyn Clock>) -> bool {
    let Ok(_guard) = lock_short_file(path, Duration::from_secs(1)) else {
        return false;
    };
    let Ok(raw) = std::fs::read(path) else {
        return false;
    };
    if raw.is_empty() {
        return false;
    }
    let Ok(owner) = serde_json::from_slice::<OwnerFile>(&raw) else {
        return false;
    };
    if owner.pid != pid {
        return false;
    }
    let data = match serde_json::to_string(&OwnerFile {
        pid,
        heartbeat_unix: clock.now().timestamp(),
    }) {
        Ok(d) => d,
        Err(_) => return false,
    };
    std::fs::write(path, data).is_ok()
}

/// Remove the owner file under the short flock, only when
/// it still names `pid` (or is empty: an empty file names
/// no owner) (`run.go:263-280`). A stale runner resuming
/// after a takeover must never delete the new owner's file.
fn release_owner(path: &str, pid: i32) -> bool {
    let Ok(_guard) = lock_short_file(path, Duration::from_secs(1)) else {
        return false;
    };
    let Ok(raw) = std::fs::read(path) else {
        return false;
    };
    if !raw.is_empty() {
        match serde_json::from_slice::<OwnerFile>(&raw) {
            Ok(owner) if owner.pid == pid => {}
            _ => return false,
        }
    }
    std::fs::remove_file(path).is_ok()
}

/// The `keeper status` read model (`run.go:294-320`):
/// state file only, no network. Field names match the
/// state file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub tag: String,
    pub profile: String,
    pub logged_out: bool,
    pub keeper_stopped: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keeper_stopped_reason: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::state::rfc3339::opt"
    )]
    pub last_checked_at: Option<DateTime<Utc>>,
    pub last_tick_outcome: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::state::rfc3339::opt"
    )]
    pub earliest_expiry: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub driving_cookie: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::state::rfc3339::opt"
    )]
    pub driving_expiry: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub warn_pending: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub warn_sent: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::state::rfc3339::opt"
    )]
    pub next_check_at: Option<DateTime<Utc>>,
    /// A corrupt or unknown-version state file: status
    /// still reports (with the `state_corrupt` reason)
    /// instead of erroring; the remedy is to delete
    /// `session-state.json`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub state_corrupt: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Read one entry's status from its profile's state file
/// (`run.go:322-360`). A missing state file is a
/// never-ticked entry, not an error. A corrupt or
/// unknown-version state file is reported distinctly
/// (`state_corrupt` + `state_corrupt` reason), not an
/// error. It performs no network I/O.
pub fn read_status(base_dir: &str, tag: &str, profile_name: &str) -> Result<Status, KeeperError> {
    let paths = castctl_config::profile::profile_paths(base_dir, profile_name)?;
    let st = match load_state(&paths.dir) {
        Ok(st) => st,
        Err(KeeperError::StateCorrupt(_)) => {
            return Ok(Status {
                tag: tag.to_string(),
                profile: profile_name.to_string(),
                logged_out: false,
                keeper_stopped: false,
                keeper_stopped_reason: STOPPED_STATE_CORRUPT.to_string(),
                last_checked_at: None,
                last_tick_outcome: String::new(),
                earliest_expiry: None,
                driving_cookie: String::new(),
                driving_expiry: None,
                warn_pending: false,
                warn_sent: false,
                next_check_at: None,
                state_corrupt: true,
            });
        }
        Err(e) => return Err(e),
    };
    Ok(Status {
        tag: tag.to_string(),
        profile: profile_name.to_string(),
        logged_out: st.logged_out,
        keeper_stopped: st.keeper_stopped,
        keeper_stopped_reason: st.keeper_stopped_reason,
        last_checked_at: st.last_checked_at,
        last_tick_outcome: st.last_tick_outcome,
        earliest_expiry: st.earliest_expiry,
        driving_cookie: st.driving_cookie,
        driving_expiry: st.driving_expiry,
        warn_pending: st.warn_pending,
        warn_sent: st.warn_sent,
        next_check_at: st.next_check_at,
        state_corrupt: false,
    })
}

/// The per-tick callback (the command layer's summary
/// line), called after every tick.
pub type OnTick = Arc<dyn Fn(&TickResult) + Send + Sync>;

/// Run one entry until cancellation or a sticky stop
/// (`run.go:65-139`). `on_tick`, when set, is called
/// after every tick (the command layer's summary line).
pub async fn run_entry(deps: TickDeps, cancel: CancelFlag, on_tick: Option<OnTick>) -> RunResult {
    run_entry_inner(deps, cancel, on_tick).await
}

async fn run_entry_inner(deps: TickDeps, cancel: CancelFlag, on_tick: Option<OnTick>) -> RunResult {
    let mut res = RunResult {
        tag: deps.tag.clone(),
        stopped: false,
        ticks: 0,
        last: None,
    };
    let clock = deps.clock.clone();
    loop {
        if cancel.is_cancelled() {
            return res;
        }
        let result = tick(&deps, &cancel).await;
        res.ticks += 1;
        let prev_outcome = res
            .last
            .as_ref()
            .map(|r| r.outcome.clone())
            .unwrap_or_default();
        if let Some(f) = &on_tick {
            f(&result);
        }
        let stopped = result.stopped;
        let recovered = result.recovered;
        res.last = Some(result);
        if stopped {
            res.stopped = true;
            notify_stopped(&deps, &cancel).await;
            return res;
        }
        if recovered {
            // Incident recovery only: the notice fires
            // when the PREVIOUS tick was not healthy, i.e.
            // this recovery closes a real incident. A
            // first-tick or routine self-healing recovery
            // stays silent.
            if res.ticks > 1
                && !prev_outcome.is_empty()
                && prev_outcome != OUTCOME_OK
                && let Some(notifier) = &deps.notifier
            {
                let _ = notifier
                    .notify(NoticeKind::Reexported, &deps.profile_name, &cancel)
                    .await;
            }
        }
        if cancel.is_cancelled() {
            return res;
        }
        let mut delay = res.last.as_ref().map(|r| r.next_delay).unwrap_or_default();
        if delay.is_zero() {
            delay = deps.interval;
        }
        // ±20% jitter, re-drawn per wait.
        let j = 1.0 + (rand::random::<f64>() * 2.0 - 1.0) * 0.2;
        delay = Duration::from_secs_f64(delay.as_secs_f64() * j);
        if delay.is_zero() {
            delay = deps.interval;
        }
        if !clock.sleep(delay, &cancel).await {
            return res;
        }
    }
}

/// Run the keeper for entries until cancellation or every
/// entry stops (`run.go:51-63`). Returns one result per
/// entry, in entry order.
pub async fn run_entries(
    entries: Vec<TickDeps>,
    cancel: CancelFlag,
    on_tick: Option<OnTick>,
) -> Vec<RunResult> {
    let mut handles = Vec::new();
    for deps in entries {
        let cancel = cancel.clone();
        let on_tick = on_tick.clone();
        handles.push(tokio::spawn(async move {
            run_entry_inner(deps, cancel, on_tick).await
        }));
    }
    let mut results = Vec::new();
    for h in handles {
        match h.await {
            Ok(r) => results.push(r),
            Err(_) => results.push(RunResult {
                tag: String::new(),
                stopped: false,
                ticks: 0,
                last: None,
            }),
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_path_rejects_escape() {
        assert!(owner_path("/tmp/base", "no.0").is_ok());
        assert!(owner_path("/tmp/base", "../evil").is_err());
    }

    #[test]
    fn pid_alive_self() {
        assert!(pid_alive(std::process::id() as i32));
        assert!(!pid_alive(-1));
    }

    #[tokio::test]
    async fn single_flight_second_acquire_refuses() {
        use crate::clock::RealClock;
        let base = std::env::temp_dir().join(format!(
            "castctl-keeper-flight-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let dir = base.to_str().unwrap();
        let clock: Arc<dyn Clock> = Arc::new(RealClock);
        let f1 = acquire_single_flight(dir, "no.0", clock.clone())
            .await
            .expect("first claim");
        let err = acquire_single_flight(dir, "no.0", clock.clone())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already running"));
        f1.release();
        let _f2 = acquire_single_flight(dir, "no.0", clock.clone())
            .await
            .expect("re-claim after release");
        let _ = std::fs::remove_dir_all(&base);
    }
}
