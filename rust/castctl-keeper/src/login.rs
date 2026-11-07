// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `auth login` session core — port of
//! `internal/keeper/login.go`.
//!
//! One `auth login` run: single-flight per profile (the
//! owner file refuses a second login), the keeper-pause
//! flag (a fresh flag refuses with
//! `ErrLoginInProgress`; a stale one is recovered), the
//! runner in a task with a poll for the logged-in hint
//! (phase only — it never auto-saves), and the save path
//! for Done only: final export, validate, write under
//! lock, clearing the sticky stop and recording
//! provenance. Nothing is written unless the user pressed
//! Done AND the final export validates.
//!
//! The audit file (`login-audit.jsonl`, bounded to the
//! last 50 records, 0600) carries session id, profile,
//! outcome enum, `cookies_saved`, saved names + earliest
//! expiry, duration. Never values, frames, or keys.
//! Best-effort: an audit failure never masks the outcome.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

use crate::checker::{CheckOutcome, Checker};
use crate::clock::{CancelFlag, Clock};
use crate::error::KeeperError;
use crate::export::Exporter;
use crate::jar::{StoredCookie, cookie_header, replace_with_export, serialize_jar};
use crate::state::{LOGIN_FLAG_STALE_AFTER, OUTCOME_OK};
use crate::store::Store;
use crate::tick::{run_export, validate_exported_set};
use crate::transport::{SessionPhase, Transport};

/// Default login timeout (`login.go:34`).
pub const DEFAULT_LOGIN_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Minimum login timeout (`login.go:35`).
pub const MIN_LOGIN_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum login timeout (`login.go:36`).
pub const MAX_LOGIN_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// The hint-only cookie poll cadence (`login.go:40`).
/// It never auto-saves: it only flips the phase notice to
/// `logged_in_detected` when the session already works.
pub const LOGIN_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// The bounded per-profile audit file (`login.go:42`).
pub const LOGIN_AUDIT_FILE_NAME: &str = "login-audit.jsonl";
/// The audit file bound (`login.go:44`).
pub const LOGIN_AUDIT_MAX_RECORDS: usize = 50;

/// The closed set of session outcomes (`login.go:50-72`).
/// Runners report Done, Cancelled, or Failed; the core
/// adds Timeout for its own deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginOutcome {
    /// The user pressed Done. The save path runs.
    Done,
    /// The save path wrote validated cookies.
    Saved,
    /// The user pressed Cancel, or the context ended.
    Cancelled,
    /// The core deadline elapsed.
    Timeout,
    /// The runner failed, the transport died, or the
    /// final export failed validation.
    Failed,
}

impl LoginOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            LoginOutcome::Done => "done",
            LoginOutcome::Saved => "saved",
            LoginOutcome::Cancelled => "cancelled",
            LoginOutcome::Timeout => "timeout",
            LoginOutcome::Failed => "failed",
        }
    }
}

/// The browser's own identity, recorded as login
/// provenance in the state file (`login.go:75-79`). Both
/// fields come from `Browser.getVersion` on the
/// attached/launched browser; nothing is invented, and
/// attach exports never write these fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrowserVersion {
    pub product: String,
    pub user_agent: String,
}

/// A `ScreencastRunner`'s terminal report
/// (`login.go:81-85`).
#[derive(Debug)]
pub struct RunnerResult {
    pub version: BrowserVersion,
    pub outcome: LoginOutcome,
    pub error: Option<KeeperError>,
}

impl RunnerResult {
    /// A failed result with no version.
    pub fn failed(err: KeeperError) -> Self {
        Self {
            version: BrowserVersion::default(),
            outcome: LoginOutcome::Failed,
            error: Some(err),
        }
    }
}

/// Serve one login session: frames out, inputs in, until
/// its context ends or the user sends Done or Cancel
/// through the transport (`login.go:98-106`). It must
/// never close, kill, or navigate an attached user
/// browser; a launch runner owns its browser and cleans
/// it up.
///
/// `exporter` returns the CDP exporter for the session's
/// browser: the attach runner's configured browser, the
/// launch runner's spawned browser (resolved lazily from
/// its `DevToolsActivePort` file). The session core uses
/// it for the hint poll and the final export.
#[async_trait::async_trait]
pub trait ScreencastRunner: Send + Sync {
    /// Run the session against `transport` until Done,
    /// Cancel, transport death, or `cancel`.
    async fn run(&self, transport: Arc<dyn Transport>, cancel: CancelFlag) -> RunnerResult;
    /// The CDP exporter for the session's browser.
    fn exporter(&self) -> Result<Box<dyn Exporter>, KeeperError>;
}

/// One `auth login` run's core state (`login.go:108-124`).
///
/// `exporter`, when `None`, is taken from
/// `Runner.exporter()` (the session browser's exporter).
/// An explicit exporter overrides it; tests use that
/// seam, production always uses the runner's.
pub struct LoginSession {
    pub clock: Arc<dyn Clock>,
    pub base_dir: String,
    pub profile_name: String,
    pub timeout: Duration,
    pub poll_interval: Duration,
    pub transport: Arc<dyn Transport>,
    pub checker: Arc<dyn Checker>,
    pub exporter: Option<Arc<dyn Exporter>>,
    pub runner: Arc<dyn ScreencastRunner>,
    pub session_id: String,
    pub lock_timeout: Duration,
}

/// The session's terminal report (`login.go:125-138`).
/// `cookies_saved` is false for every non-saved outcome:
/// nothing is written unless the user pressed Done AND
/// the final export validates.
#[derive(Debug)]
pub struct LoginResult {
    pub outcome: LoginOutcome,
    pub cookies_saved: bool,
    pub saved_names: Vec<String>,
    pub earliest_expiry: Option<DateTime<FixedOffset>>,
    pub version: BrowserVersion,
    pub duration: Duration,
    pub error: Option<KeeperError>,
}

/// One bounded audit record (`login.go:420-431`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub session_id: String,
    pub profile: String,
    pub outcome: String,
    pub cookies_saved: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub saved_cookie_names: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::state::rfc3339_offset::opt"
    )]
    pub earliest_expiry: Option<DateTime<FixedOffset>>,
    /// When the session started (LOCAL: Go
    /// `login.go:145` `started := clock.Now()`,
    /// `auditRecord.StartedAt`).
    #[serde(with = "crate::state::rfc3339_offset")]
    pub started_at: DateTime<FixedOffset>,
    pub duration_ms: i64,
}

impl LoginSession {
    /// Execute the session (`login.go:140-238`). It returns
    /// a `LoginResult` for every terminal path; `error` is
    /// set only for infrastructure failures (flag
    /// contention, export failure on the save path, timeout
    /// validation). A cancelled/timeout/failed outcome is a
    /// normal result, not an error.
    pub async fn run(&self, cancel: CancelFlag) -> LoginResult {
        let started = self.clock.now();
        let timeout = if self.timeout.is_zero() {
            DEFAULT_LOGIN_TIMEOUT
        } else {
            self.timeout
        };
        if timeout < MIN_LOGIN_TIMEOUT || timeout > MAX_LOGIN_TIMEOUT {
            return self.failed(
                started,
                KeeperError::Other(format!(
                    "login timeout {timeout:?} out of range [{MIN_LOGIN_TIMEOUT:?}, {MAX_LOGIN_TIMEOUT:?}]"
                )),
            );
        }
        let exporter: Arc<dyn Exporter> = match &self.exporter {
            Some(e) => e.clone(),
            None => match self.runner.exporter() {
                Ok(e) => Arc::from(e),
                Err(e) => return self.failed(started, e),
            },
        };
        let store = match Store::new(&self.base_dir, &self.profile_name, "", self.lock_timeout) {
            Ok(s) => s,
            Err(e) => return self.failed(started, e),
        };
        // Single-flight per profile: the owner file refuses
        // a second login for the same profile.
        let _flight = match crate::run::acquire_single_flight(
            &store.profile_dir,
            "login",
            self.clock.clone(),
        )
        .await
        {
            Ok(f) => f,
            Err(e) => return self.failed(started, e),
        };
        // Login pause flag: the keeper skips ticks while
        // set. A fresh flag refuses; a stale one is
        // recovered.
        let session_id = if self.session_id.is_empty() {
            format!("login-{}", started.timestamp_nanos_opt().unwrap_or(0))
        } else {
            self.session_id.clone()
        };
        if let Err(e) = self.set_login_flag(&store, &session_id, started).await {
            return self.failed(started, e);
        }
        let result = self
            .run_inner(cancel.clone(), started, &session_id, exporter.clone())
            .await;
        self.clear_login_flag(&store).await;
        result
    }

    async fn run_inner(
        &self,
        cancel: CancelFlag,
        started: DateTime<FixedOffset>,
        session_id: &str,
        exporter: Arc<dyn Exporter>,
    ) -> LoginResult {
        let timeout = if self.timeout.is_zero() {
            DEFAULT_LOGIN_TIMEOUT
        } else {
            self.timeout
        };
        let poll_interval = if self.poll_interval.is_zero() {
            LOGIN_POLL_INTERVAL
        } else {
            self.poll_interval
        };
        self.transport.send_phase(SessionPhase::Loading, "").await;
        let run_cancel = cancel.child();
        let runner = self.runner.clone();
        let transport = self.transport.clone();
        let run_cancel2 = run_cancel.clone();
        let mut runner_task = tokio::spawn(async move { runner.run(transport, run_cancel2).await });
        self.transport.send_phase(SessionPhase::Ready, "").await;
        let mut hint_sent = false;
        let mut poll = tokio::time::interval(poll_interval);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // `tokio::time::interval` ticks immediately; Go
        // (`login.go:140-238`) uses `clock.After(pollInterval)`,
        // so the first hint arrives after one interval (R-4).
        // Consume the immediate tick before the loop.
        poll.tick().await;
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        let outcome = loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    run_cancel.cancel();
                    break (LoginOutcome::Cancelled, RunnerResult {
                        version: BrowserVersion::default(),
                        outcome: LoginOutcome::Cancelled,
                        error: None,
                    });
                }
                _ = &mut deadline => {
                    run_cancel.cancel();
                    break (LoginOutcome::Timeout, RunnerResult {
                        version: BrowserVersion::default(),
                        outcome: LoginOutcome::Timeout,
                        error: None,
                    });
                }
                res = &mut runner_task => {
                    match res {
                        Ok(r) => {
                            let outcome = match r.outcome {
                                LoginOutcome::Done => LoginOutcome::Done,
                                LoginOutcome::Cancelled => LoginOutcome::Cancelled,
                                _ => LoginOutcome::Failed,
                            };
                            break (outcome, r);
                        }
                        Err(e) => {
                            break (LoginOutcome::Failed, RunnerResult {
                                version: BrowserVersion::default(),
                                outcome: LoginOutcome::Failed,
                                error: Some(KeeperError::Other(format!("runner task failed: {e}"))),
                            });
                        }
                    }
                }
                _ = poll.tick() => {
                    if !hint_sent && logged_in_hint(exporter.as_ref(), self.checker.as_ref(), self.clock.as_ref()).await {
                        hint_sent = true;
                        self.transport.send_phase(SessionPhase::LoggedInDetected, "").await;
                    }
                }
            }
        };
        let (outcome, runner_res) = outcome;
        self.finish(started, session_id, outcome, runner_res, exporter)
            .await
    }

    /// Resolve a terminal outcome: the save path for Done,
    /// audit + phase for everything else
    /// (`login.go:240-294`). It never runs the save path
    /// for a non-Done outcome.
    async fn finish(
        &self,
        started: DateTime<FixedOffset>,
        session_id: &str,
        outcome: LoginOutcome,
        runner_res: RunnerResult,
        exporter: Arc<dyn Exporter>,
    ) -> LoginResult {
        let duration = self
            .clock
            .now()
            .signed_duration_since(started)
            .to_std()
            .unwrap_or_default();
        let store = match Store::new(&self.base_dir, &self.profile_name, "", self.lock_timeout) {
            Ok(s) => s,
            Err(e) => {
                self.transport.send_phase(SessionPhase::Failed, "").await;
                return LoginResult {
                    outcome: LoginOutcome::Failed,
                    cookies_saved: false,
                    saved_names: vec![],
                    earliest_expiry: None,
                    version: runner_res.version,
                    duration,
                    error: Some(e),
                };
            }
        };
        let audit = |final_outcome: LoginOutcome,
                     saved: bool,
                     names: Vec<String>,
                     earliest: Option<DateTime<FixedOffset>>| {
            self.write_audit(
                &store,
                AuditRecord {
                    session_id: session_id.to_string(),
                    profile: self.profile_name.clone(),
                    outcome: final_outcome.as_str().to_string(),
                    cookies_saved: saved,
                    saved_cookie_names: names,
                    earliest_expiry: earliest,
                    started_at: started,
                    duration_ms: duration.as_millis() as i64,
                },
            );
        };
        if outcome != LoginOutcome::Done {
            let phase = if outcome == LoginOutcome::Cancelled {
                SessionPhase::Cancelled
            } else {
                SessionPhase::Failed
            };
            self.transport.send_phase(phase, "").await;
            audit(outcome, false, vec![], None);
            return LoginResult {
                outcome,
                cookies_saved: false,
                saved_names: vec![],
                earliest_expiry: None,
                version: runner_res.version,
                duration,
                error: runner_res.error,
            };
        }
        // Save path: final export, validate, write under lock.
        let (exported, _) = match run_export(exporter.as_ref()).await {
            Ok(v) => v,
            Err(e) => {
                self.transport.send_phase(SessionPhase::Failed, "").await;
                audit(LoginOutcome::Failed, false, vec![], None);
                return LoginResult {
                    outcome: LoginOutcome::Failed,
                    cookies_saved: false,
                    saved_names: vec![],
                    earliest_expiry: None,
                    version: runner_res.version,
                    duration,
                    error: Some(e),
                };
            }
        };
        match save_login_cookies(&store, &exported, &runner_res.version, self.clock.as_ref()) {
            Ok((names, earliest)) => {
                self.transport.send_phase(SessionPhase::Done, "").await;
                audit(LoginOutcome::Saved, true, names.clone(), earliest);
                LoginResult {
                    outcome: LoginOutcome::Saved,
                    cookies_saved: true,
                    saved_names: names,
                    earliest_expiry: earliest,
                    version: runner_res.version,
                    duration,
                    error: None,
                }
            }
            Err(e) => {
                self.transport.send_phase(SessionPhase::Failed, "").await;
                audit(LoginOutcome::Failed, false, vec![], None);
                LoginResult {
                    outcome: LoginOutcome::Failed,
                    cookies_saved: false,
                    saved_names: vec![],
                    earliest_expiry: None,
                    version: runner_res.version,
                    duration,
                    error: Some(e),
                }
            }
        }
    }

    fn failed(&self, started: DateTime<FixedOffset>, err: KeeperError) -> LoginResult {
        LoginResult {
            outcome: LoginOutcome::Failed,
            cookies_saved: false,
            saved_names: vec![],
            earliest_expiry: None,
            version: BrowserVersion::default(),
            duration: self
                .clock
                .now()
                .signed_duration_since(started)
                .to_std()
                .unwrap_or_default(),
            error: Some(err),
        }
    }

    /// Set the keeper-pause flag (`login.go:386-405`). A
    /// fresh flag from another session refuses with
    /// `ErrLoginInProgress`; a stale flag is recovered.
    async fn set_login_flag(
        &self,
        store: &Store,
        session_id: &str,
        now: DateTime<FixedOffset>,
    ) -> Result<(), KeeperError> {
        let mut ls = store.lock()?;
        let st = &mut ls.state;
        if st.login_active {
            let stale = match st.login_started_at {
                None => true,
                Some(t) => {
                    now.signed_duration_since(t).to_std().unwrap_or_default()
                        > LOGIN_FLAG_STALE_AFTER
                }
            };
            if !stale {
                return Err(KeeperError::LoginInProgress);
            }
        }
        st.login_active = true;
        st.login_session_id = session_id.to_string();
        st.login_started_at = Some(now);
        ls.save_state()
    }

    /// Clear the keeper-pause flag (`login.go:407-419`).
    /// Best-effort: a failure here must not mask the
    /// session outcome.
    async fn clear_login_flag(&self, store: &Store) {
        if let Ok(mut ls) = store.lock() {
            let st = &mut ls.state;
            st.login_active = false;
            st.login_session_id = String::new();
            st.login_started_at = None;
            let _ = ls.save_state();
        }
    }

    /// Append one bounded audit record (0600, last 50
    /// kept) (`login.go:435-486`). Best-effort.
    fn write_audit(&self, store: &Store, rec: AuditRecord) {
        let path = std::path::Path::new(&store.profile_dir).join(LOGIN_AUDIT_FILE_NAME);
        // Hold the store lock while rewriting the audit
        // file, so concurrent sessions serialise (Go
        // `writeAudit` locks the store the same way).
        let Ok(_ls) = store.lock() else {
            return;
        };
        let mut records: Vec<AuditRecord> = Vec::new();
        if let Ok(raw) = std::fs::read(&path)
            && !raw.is_empty()
        {
            for line in raw.split(|b| *b == b'\n') {
                if line.is_empty() {
                    continue;
                }
                if let Ok(r) = serde_json::from_slice::<AuditRecord>(line) {
                    records.push(r);
                }
            }
        }
        records.push(rec);
        if records.len() > LOGIN_AUDIT_MAX_RECORDS {
            records.drain(0..records.len() - LOGIN_AUDIT_MAX_RECORDS);
        }
        let mut out = Vec::new();
        for r in &records {
            if let Ok(line) = serde_json::to_string(r) {
                out.extend_from_slice(line.as_bytes());
                out.push(b'\n');
            }
        }
        // Temp name carries pid + counter + nanos (S-5);
        // mode 0600 from the moment of creation (S-1).
        let tmp_name = format!(".login-audit-{}.tmp", crate::lockfile::temp_suffix());
        let tmp_path = std::path::Path::new(&store.profile_dir).join(tmp_name);
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let Ok(mut tmp) = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
            else {
                return;
            };
            if tmp.write_all(&out).is_err() {
                let _ = std::fs::remove_file(&tmp_path);
                return;
            }
        }
        let _ = std::fs::rename(&tmp_path, &path);
    }
}

/// Validate the final export and write it under the
/// cookies lock, clearing the sticky stop and recording
/// provenance (`login.go:305-358`). It re-reads the stored
/// file under the lock (`replace_with_export` against the
/// fresh read), so a concurrent keeper write is not
/// silently dropped.
pub fn save_login_cookies(
    store: &Store,
    exported: &[StoredCookie],
    version: &BrowserVersion,
    clock: &dyn Clock,
) -> Result<(Vec<String>, Option<DateTime<FixedOffset>>), KeeperError> {
    let mut ls = store.lock()?;
    let (merged, _) = replace_with_export(&ls.cookies, exported);
    let now = clock.now();
    if !validate_exported_set(&merged, now) {
        return Err(KeeperError::Other(
            "final export failed validation: no usable hatch_sess in the browser session"
                .to_string(),
        ));
    }
    let data = serialize_jar(&merged)?;
    ls.cookies = merged.clone();
    let _ = ls.save_jar()?;
    let st = &mut ls.state;
    st.logged_out = false;
    st.keeper_stopped = false;
    st.keeper_stopped_reason = String::new();
    st.warn_pending = false;
    st.warn_sent = false;
    st.warn_kind = String::new();
    st.last_checked_at = Some(now);
    st.last_tick_outcome = OUTCOME_OK.to_string();
    st.refresh_cookie_records(&merged, now);
    st.cookies_sha256 = crate::state::sha256_hex(&data);
    st.login_user_agent = version.user_agent.clone();
    st.login_chromium_version = version.product.clone();
    st.login_at = Some(now);
    ls.save_state()?;
    let names: Vec<String> = merged
        .iter()
        .filter(|c| crate::jar::in_filtered_domain(c))
        .map(|c| c.name.clone())
        .collect();
    let earliest = crate::jar::earliest_expiry(&merged);
    Ok((names, earliest))
}

/// The hint-only check (`login.go:360-384`): export the
/// browser cookies and run the cheap chain against them.
/// `true` means the session already works. Hint only:
/// errors are ignored and nothing is saved.
pub async fn logged_in_hint(
    exporter: &dyn Exporter,
    checker: &dyn Checker,
    clock: &dyn Clock,
) -> bool {
    let (exported, _) = match run_export(exporter).await {
        Ok(v) => v,
        Err(_) => return false,
    };
    if exported.is_empty() {
        return false;
    }
    if !exported
        .iter()
        .any(|c| c.name == "hatch_sess" && !c.value.is_empty())
    {
        return false;
    }
    let header = cookie_header(&exported, clock.now());
    let outcome: CheckOutcome = checker.check(&header).await;
    outcome.error.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;
    use crate::jar::StoredCookie;
    use crate::state::load_state;

    #[test]
    fn timeout_range_constants() {
        assert_eq!(DEFAULT_LOGIN_TIMEOUT, Duration::from_secs(900));
        assert_eq!(MIN_LOGIN_TIMEOUT, Duration::from_secs(60));
        assert_eq!(MAX_LOGIN_TIMEOUT, Duration::from_secs(3600));
        assert_eq!(LOGIN_POLL_INTERVAL, Duration::from_secs(5));
        assert_eq!(LOGIN_AUDIT_MAX_RECORDS, 50);
    }

    #[test]
    fn save_login_cookies_validates_and_records_provenance() {
        let base = std::env::temp_dir().join(format!(
            "castctl-keeper-login-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let base_s = base.to_str().unwrap();
        let store = Store::new(base_s, "default", "", Duration::from_secs(5)).unwrap();
        let clock = FakeClock::new(chrono::Local::now().fixed_offset());
        let exported = vec![StoredCookie {
            domain: ".muse.ai".to_string(),
            path: "/".to_string(),
            secure: true,
            http_only: false,
            expires: 1_900_000_000,
            name: "hatch_sess".to_string(),
            value: "v".to_string(),
        }];
        let version = BrowserVersion {
            product: "Chrome/155.0.0.0".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
        };
        let (names, earliest) = save_login_cookies(&store, &exported, &version, &clock).unwrap();
        assert_eq!(names, vec!["hatch_sess".to_string()]);
        assert!(earliest.is_some());
        let st = load_state(&store.profile_dir).unwrap();
        assert_eq!(st.login_chromium_version, "Chrome/155.0.0.0");
        assert_eq!(st.login_user_agent, "Mozilla/5.0");
        assert_eq!(st.last_tick_outcome, OUTCOME_OK);
        // An export with no usable hatch_sess fails validation.
        let bad = vec![StoredCookie {
            domain: ".muse.ai".to_string(),
            path: "/".to_string(),
            secure: true,
            http_only: false,
            expires: 1_900_000_000,
            name: "other".to_string(),
            value: "v".to_string(),
        }];
        assert!(save_login_cookies(&store, &bad, &version, &clock).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn audit_record_started_at_keeps_local_offset() {
        // M7g: `started_at` is a LOCAL audit field (Go
        // `login.go:145` `started := clock.Now()`); the
        // JSONL audit line must carry the stored offset,
        // while `earliest_expiry` in the same record stays
        // `Z`.
        use chrono::{FixedOffset, TimeZone};
        let started = FixedOffset::east_opt(7 * 3600)
            .unwrap()
            .with_ymd_and_hms(2026, 11, 7, 18, 33, 11)
            .unwrap();
        let rec = AuditRecord {
            session_id: "login-1".to_string(),
            profile: "no.0".to_string(),
            outcome: "saved".to_string(),
            cookies_saved: true,
            saved_cookie_names: vec!["hatch_sess".to_string()],
            earliest_expiry: Some(
                FixedOffset::east_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2026, 12, 5, 0, 0, 0)
                    .unwrap(),
            ),
            started_at: started,
            duration_ms: 1000,
        };
        let text = serde_json::to_string(&rec).unwrap();
        assert!(
            text.contains("2026-11-07T18:33:11+07:00"),
            "started_at must keep +07:00, got:\n{text}"
        );
        assert!(
            text.contains("2026-12-05T00:00:00Z"),
            "earliest_expiry must stay Z, got:\n{text}"
        );
        let back: AuditRecord = serde_json::from_str(&text).unwrap();
        assert_eq!(back.started_at, started);
    }
}
