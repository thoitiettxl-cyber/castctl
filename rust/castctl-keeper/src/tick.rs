// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The keeper tick — port of `internal/keeper/tick.go`
//! (the `Tick` function and its helpers; `Checker` /
//! `GatewayChecker` / `Exporter` live in `checker.rs` /
//! `export.rs`).
//!
//! Phases:
//! 1. Locked snapshot (cookies + state under the
//!    cookies-file lock).
//! 2. Cheap chain with backoff on transient errors; then
//!    auto-wake (probe/wake/re-probe); then the AuthError
//!    path: CDP re-export → re-check → headless re-login →
//!    stop.
//! 3. Locked merge + write + state.
//!
//! Invariants carried over from Go:
//! - The stop path preserves the jar byte-identically
//!   (K-LIVE-2): the pre-stop jar survives for manual
//!   recovery or re-import; the server's verdict is
//!   recorded in state, not by mutating cookies.
//! - The transient path does NOT persist updates from a
//!   failed check (partial/untrusted); the gateway-down
//!   path DOES persist cheap-chain updates (they come from
//!   fully successful steps).
//! - `try_relogin` is invoked exactly once per tick.
//! - The credential reaches the driver only through the
//!   narrow provider, and the fetched copy is cleared
//!   after use.
//! - `NotifyStopped` runs AFTER Tick returns, never under
//!   the file lock.
//!
//! [DEVIATION] `TickDeps` carries the entry's RESOLVED
//! values (`interval`, `retry_backoff`,
//! `wake_on_gateway_failure`, `wake_attempts`,
//! `credentials_configured`) instead of a
//! `*profile.KeeperEntry`: the tick never re-reads the
//! entry, and the same deps shape serves tests without a
//! config file. Behaviour is identical — the values are
//! exactly the entry's `Effective*` results.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use castctl_transport::TransportError;
use chrono::{DateTime, FixedOffset};

use crate::backoff::{Backoff, next_delay_after};
use crate::checker::{CheckOutcome, Checker};
use crate::clock::{CancelFlag, Clock};
use crate::error::{KeeperError, ReloginBlocker, ReloginError};
use crate::export::Exporter;
use crate::jar::{
    CookieUpdate, StoredCookie, apply_updates, cookie_header, earliest_filtered_expiry,
    from_exported_cookie, in_filtered_domain, replace_with_export, serialize_jar,
};
use crate::lockfile::ensure_profile_dir;
use crate::notify::{NoticeKind, Notifier, valid_notice_kind};
use crate::relogin::ReloginDriver;
use crate::state::{
    LOGIN_FLAG_STALE_AFTER, OUTCOME_AUTH_ERROR, OUTCOME_ERROR, OUTCOME_EXPORT_FAILED, OUTCOME_OK,
    OUTCOME_SKIPPED, OUTCOME_TRANSIENT_ERROR, STOPPED_AUTH_ERROR, STOPPED_COOKIES_MISSING,
    sha256_hex,
};
use crate::store::{LockedStore, Store};

/// The gateway probe seam (`attemptWakeGateway`): one
/// handshake attempt. `Ok` means the gateway is
/// reachable; `Err(Auth)` means auth died mid-flight
/// (the caller falls into the export/re-login/stop path);
/// any other error is transient.
#[async_trait]
pub trait GatewayProbe: Send + Sync {
    async fn probe(&self) -> Result<(), TransportError>;
}

/// The wake seam: one VM wake attempt.
#[async_trait]
pub trait Wake: Send + Sync {
    async fn wake(&self) -> Result<(), TransportError>;
}

/// One tick's inputs (`tick.go:201-219`, resolved-values
/// form — see the module header).
pub struct TickDeps {
    pub clock: Arc<dyn Clock>,
    /// The keeper entry tag (e.g. `"no.0"`).
    pub tag: String,
    /// `Entry.EffectiveInterval()`.
    pub interval: Duration,
    /// `Entry.EffectiveRetryBackoff()` (copied).
    pub retry_backoff: Vec<Duration>,
    /// `Entry.EffectiveWakeOnGatewayFailure()`.
    pub wake_on_gateway_failure: bool,
    /// `Entry.EffectiveWakeAttempts()`.
    pub wake_attempts: usize,
    /// Whether the entry configures credentials
    /// (`Entry.Credentials != ""`).
    pub credentials_configured: bool,
    pub base_dir: String,
    pub profile_name: String,
    /// The profile's resolved cookies file
    /// (`Profile.cookies_file`, `config.go:798`): the tick reads and
    /// writes the jar here. Empty means the profile default
    /// (`Store::new` falls back to `profile_paths().cookies`).
    /// M7e: was missing entirely, so the tick always used the
    /// default path and ignored a configured `cookies_file`
    /// (Go honours it) — proven live, see `docs/e2e.md` M7e item 2.
    pub cookies_path: String,
    pub checker: Arc<dyn Checker>,
    pub exporter: Option<Arc<dyn Exporter>>,
    pub notifier: Option<Arc<dyn Notifier>>,
    pub gateway_probe: Option<Arc<dyn GatewayProbe>>,
    pub wake: Option<Arc<dyn Wake>>,
    pub relogin: Option<Arc<dyn ReloginDriver>>,
    /// The narrow credential provider (never an exported
    /// field). `None` (or a `None` return) means
    /// re-login is unavailable.
    pub credential_provider:
        Option<Arc<dyn Fn() -> Option<castctl_config::LoginCredential> + Send + Sync>>,
    pub jitter: Option<Arc<dyn Fn() -> f64 + Send + Sync>>,
    pub lock_timeout: Duration,
    /// Test seam: fired before every state save (nil in
    /// production).
    pub before_state_save: Option<Arc<dyn Fn() + Send + Sync>>,
}

/// One tick's observable outcome (`tick.go:231-250`).
/// `outcome` uses the state outcome enum;
/// `OutcomeError` is a hard failure. `error` is the
/// underlying typed error for command-layer exit mapping
/// and is never printed directly. `recovered` reports a
/// CDP re-export recovery; `state_corrupt` reports that
/// the state file was corrupt or an unknown version when
/// this tick read it (the tick substituted a fresh state
/// and re-observed from the cookies file).
#[derive(Debug)]
pub struct TickResult {
    pub outcome: String,
    pub stage: String,
    pub stopped: bool,
    pub recovered: bool,
    pub wrote_cookies: bool,
    pub dropped: usize,
    pub cdp_dropped: usize,
    pub exported: usize,
    pub cookies_seen: usize,
    pub skipped: usize,
    pub next_delay: Duration,
    pub state_corrupt: bool,
    pub error: Option<KeeperError>,
}

impl TickResult {
    fn fail(
        outcome: &str,
        stage: &str,
        err: KeeperError,
        base: Duration,
        corrupt_seen: bool,
    ) -> Self {
        Self {
            outcome: outcome.to_string(),
            stage: stage.to_string(),
            stopped: false,
            recovered: false,
            wrote_cookies: false,
            dropped: 0,
            cdp_dropped: 0,
            exported: 0,
            cookies_seen: 0,
            skipped: 0,
            next_delay: base,
            state_corrupt: corrupt_seen,
            error: Some(err),
        }
    }
}

/// `fail` as a free function (the tick's `fail` closure in
/// Go reads `corrupt_seen` at call time; a Rust closure
/// would capture the initial value — see the tick header).
fn fail_result(
    outcome: &str,
    stage: &str,
    err: KeeperError,
    base: Duration,
    corrupt_seen: bool,
) -> TickResult {
    TickResult::fail(outcome, stage, err, base, corrupt_seen)
}

/// `failSave` as a free function (same capture note as
/// `fail_result`).
fn fail_save_result(
    stage: &str,
    err: KeeperError,
    wrote: bool,
    base: Duration,
    corrupt_seen: bool,
) -> TickResult {
    let mut r = TickResult::fail(OUTCOME_ERROR, stage, err, base, corrupt_seen);
    r.wrote_cookies = wrote;
    r
}

/// The ONE mapping from a lock-acquisition (or
/// lock-window load/parse) failure to a Tick outcome
/// (`tick.go:332-345`): only a held lock — the exact
/// `LockTimeout` sentinel, never message text — is
/// `"skipped"`. A state-directory failure and every other
/// error is a hard failure (`"error"`). No other site in
/// Tick or its helpers may map a lock error to
/// `OutcomeSkipped`.
fn classify_lock_error(err: &KeeperError) -> (&'static str, &'static str) {
    if matches!(err, KeeperError::LockTimeout) {
        (OUTCOME_SKIPPED, "lock")
    } else {
        (OUTCOME_ERROR, "save")
    }
}

/// The one state-save path used by Tick and its helpers
/// (`tick.go:348-356`): re-ensure the state directory (it
/// may have been removed after the lock was taken), fire
/// the `before_state_save` test seam (nil in production),
/// then save. Any error is a hard failure for the caller.
fn save_tick_state(
    store: &Store,
    ls: &mut LockedStore<'_>,
    before: &Option<Arc<dyn Fn() + Send + Sync>>,
) -> Result<(), KeeperError> {
    ensure_profile_dir(&store.base_dir, &store.profile_name)
        .map_err(|e| KeeperError::StateDir(e.to_string()))?;
    if let Some(f) = before {
        f();
    }
    ls.save_state()
}

/// Enforce the pre-write gate for CDP exports
/// (`tick.go:913-931`): `hatch_sess` present + non-empty
/// in the MERGED set, and the earliest FILTERED-domain
/// expiry not already past. Non-filtered cookies are
/// excluded from both checks: an expired cookie from an
/// unrelated domain must never veto a valid re-export and
/// sticky-stop the entry.
pub fn validate_exported_set(merged: &[StoredCookie], now: DateTime<FixedOffset>) -> bool {
    let mut has_hatch = false;
    let mut filtered: Vec<&StoredCookie> = Vec::new();
    for c in merged {
        if !in_filtered_domain(c) {
            continue;
        }
        filtered.push(c);
        if c.name == "hatch_sess" && !c.value.is_empty() {
            has_hatch = true;
        }
    }
    if !has_hatch {
        return false;
    }
    let _ = filtered;
    if let Some(earliest) = earliest_filtered_expiry(merged)
        && !earliest.gt(&now)
    {
        return false;
    }
    true
}

/// Call the exporter, filter to the Muse domains, and
/// convert to merge form (`tick.go:1068-1084`).
/// Non-filtered cookies are dropped with a count only.
pub async fn run_export(
    exporter: &dyn Exporter,
) -> Result<(Vec<StoredCookie>, usize), KeeperError> {
    let raw = exporter.export().await?;
    let mut out = Vec::with_capacity(raw.len());
    let mut dropped = 0;
    for c in raw {
        let sc = from_exported_cookie(&c);
        if !in_filtered_domain(&sc) {
            dropped += 1;
            continue;
        }
        out.push(sc);
    }
    Ok((out, dropped))
}

/// Whether the check error is an auth error (the stop
/// path) rather than a transient one. Callers match the
/// variant, never message text.
fn is_auth_error(err: &TransportError) -> bool {
    matches!(err, TransportError::Auth { .. })
}

/// One tick (`tick.go:523-897`).
pub async fn tick(deps: &TickDeps, cancel: &CancelFlag) -> TickResult {
    let clock = deps.clock.clone();
    let now = clock.now();
    let base = deps.interval;
    let mut corrupt_seen = false;

    let store = match Store::new(
        &deps.base_dir,
        &deps.profile_name,
        &deps.cookies_path,
        deps.lock_timeout,
    ) {
        Ok(s) => s,
        Err(e) => return fail_result(OUTCOME_ERROR, "save", e, base, corrupt_seen),
    };

    // Phase 1: locked snapshot.
    let mut ls = match store.lock() {
        Ok(ls) => ls,
        Err(e) => {
            let (outcome, stage) = classify_lock_error(&e);
            return fail_result(outcome, stage, e, base, corrupt_seen);
        }
    };
    corrupt_seen = ls.state_corrupt;
    if ls.state.login_active {
        let stale = match ls.state.login_started_at {
            None => true,
            Some(t) => {
                now.signed_duration_since(t).to_std().unwrap_or_default() > LOGIN_FLAG_STALE_AFTER
            }
        };
        if !stale {
            let next = now + base;
            ls.state.last_tick_outcome = OUTCOME_SKIPPED.to_string();
            ls.state.last_tick_stage = String::new();
            ls.state.next_check_at = Some(next);
            if let Err(e) = save_tick_state(&store, &mut ls, &deps.before_state_save) {
                return fail_save_result("save", e, false, base, corrupt_seen);
            }
            return TickResult {
                outcome: OUTCOME_SKIPPED.to_string(),
                stage: String::new(),
                stopped: false,
                recovered: false,
                wrote_cookies: false,
                dropped: 0,
                cdp_dropped: 0,
                exported: 0,
                cookies_seen: 0,
                skipped: 0,
                next_delay: base,
                state_corrupt: corrupt_seen,
                error: None,
            };
        }
        // Stale flag: the login process is assumed dead.
        ls.state.login_active = false;
        ls.state.login_session_id = String::new();
        ls.state.login_started_at = None;
        if let Err(e) = save_tick_state(&store, &mut ls, &deps.before_state_save) {
            return fail_save_result("save", e, false, base, corrupt_seen);
        }
    }
    if ls.state.keeper_stopped {
        let pending = ls.state.warn_pending;
        let raw_kind = ls.state.warn_kind.clone();
        let kind = NoticeKind::parse_kind(&raw_kind).unwrap_or(NoticeKind::LoggedOut);
        let last = ls.state.last_tick_outcome.clone();
        drop(ls);
        if pending
            && let Some(notifier) = &deps.notifier
            && notifier
                .notify(kind, &deps.profile_name, cancel)
                .await
                .is_ok()
            && let Ok(mut ls2) = store.lock()
        {
            ls2.state.mark_warn_sent_raw(&raw_kind, clock.now());
            let _ = save_tick_state(&store, &mut ls2, &deps.before_state_save);
        }
        // The outcome is the last recorded outcome (the
        // sticky stop persists across ticks).
        return TickResult {
            outcome: last,
            stage: String::new(),
            stopped: true,
            recovered: false,
            wrote_cookies: false,
            dropped: 0,
            cdp_dropped: 0,
            exported: 0,
            cookies_seen: 0,
            skipped: 0,
            next_delay: Duration::ZERO,
            state_corrupt: corrupt_seen,
            error: None,
        };
    }
    let snapshot_cookies = ls.cookies.clone();
    let jar_form = ls.is_jar;
    let file_missing = ls.file_missing;
    drop(ls);

    let header = cookie_header(&snapshot_cookies, now);

    // Phase 2: cheap chain with backoff on transient errors.
    let mut backoff = Backoff::with_ladder(clock.clone(), deps.jitter.clone(), &deps.retry_backoff);
    let mut updates: Vec<CookieUpdate>;
    let mut skipped: usize;
    let mut check_err: Option<TransportError>;
    loop {
        let outcome: CheckOutcome = deps.checker.check(&header).await;
        updates = outcome.updates;
        skipped = outcome.skipped;
        check_err = outcome.error;
        match &check_err {
            None => break,
            Some(e) if is_auth_error(e) => break,
            Some(_) => {}
        }
        if cancel.is_cancelled() {
            return fail_result(
                OUTCOME_ERROR,
                "session",
                KeeperError::Other("tick cancelled".to_string()),
                base,
                corrupt_seen,
            );
        }
        let Some(delay) = backoff.next_delay() else {
            // Ladder exhausted: record the transient outcome.
            return record_transient(
                &clock,
                &store,
                base,
                check_err.unwrap(),
                "session",
                &deps.before_state_save,
                corrupt_seen,
            )
            .await;
        };
        if !backoff.sleep(delay, cancel).await {
            return fail_result(
                OUTCOME_ERROR,
                "session",
                KeeperError::Other("tick cancelled".to_string()),
                base,
                corrupt_seen,
            );
        }
    }

    // Phase 2a: auto-wake.
    if check_err.is_none()
        && deps.gateway_probe.is_some()
        && deps.wake_on_gateway_failure
        && let Err(werr) = attempt_wake_gateway(deps, cancel).await
    {
        if is_auth_error(&werr) {
            check_err = Some(werr);
        } else if cancel.is_cancelled() {
            return fail_result(
                OUTCOME_ERROR,
                "gateway",
                KeeperError::Other("tick cancelled".to_string()),
                base,
                corrupt_seen,
            );
        } else {
            return record_gateway_down(
                &clock,
                &store,
                base,
                &updates,
                jar_form,
                file_missing,
                werr,
                &deps.before_state_save,
            )
            .await;
        }
    }

    // Phase 2b: AuthError -> export/re-login/stop.
    let mut recovered = false;
    let export_err: Option<KeeperError>;
    let mut exported: Vec<StoredCookie> = Vec::new();
    let mut export_dropped = 0usize;
    if check_err.is_some() {
        let auth_err = check_err.as_ref().map(is_auth_error).unwrap_or(false);
        if !auth_err {
            return fail_result(
                OUTCOME_TRANSIENT_ERROR,
                "session",
                KeeperError::Other(format!("check failed: {}", check_err.unwrap())),
                base,
                corrupt_seen,
            );
        }
        // 1) CDP re-export from the attached browser.
        if let Some(exporter) = &deps.exporter {
            match run_export(exporter.as_ref()).await {
                Ok((exp, dropped)) => {
                    exported = exp;
                    export_dropped = dropped;
                    let (merged, _) = replace_with_export(&snapshot_cookies, &exported);
                    if !validate_exported_set(&merged, now) {
                        check_err = Some(TransportError::Auth {
                            message: "exported set failed validation".to_string(),
                        });
                    } else {
                        let header2 = cookie_header(&merged, now);
                        let outcome2: CheckOutcome = deps.checker.check(&header2).await;
                        updates.extend(outcome2.updates);
                        match outcome2.error {
                            None => {
                                recovered = true;
                                check_err = None;
                            }
                            Some(e2) => {
                                if !is_auth_error(&e2) {
                                    return record_transient(
                                        &clock,
                                        &store,
                                        base,
                                        e2,
                                        "auth_check",
                                        &deps.before_state_save,
                                        corrupt_seen,
                                    )
                                    .await;
                                }
                                check_err = Some(e2);
                            }
                        }
                    }
                }
                Err(KeeperError::ReexportUnavailable) => {
                    // Tag-off build: no recovery possible
                    // from the browser; fall through to
                    // re-login/stop below.
                }
                Err(e) => {
                    export_err = Some(e);
                    if deps.relogin.is_none() {
                        return record_export_failed(
                            &clock,
                            &store,
                            base,
                            export_err.unwrap(),
                            &deps.before_state_save,
                        )
                        .await;
                    }
                }
            }
        }
        // 2) Headless re-login, when configured. Exactly
        // one driver invocation per tick.
        if check_err.is_some()
            && let Some(driver) = &deps.relogin
        {
            match try_relogin(deps, driver.as_ref(), &snapshot_cookies, now).await {
                Ok((rel_exported, rel_dropped)) => {
                    exported = rel_exported;
                    export_dropped = rel_dropped;
                    let (merged, _) = replace_with_export(&snapshot_cookies, &exported);
                    if !validate_exported_set(&merged, now) {
                        return stop_entry(
                            &clock,
                            &store,
                            base,
                            STOPPED_AUTH_ERROR,
                            Some(NoticeKind::Failed),
                            check_err.unwrap(),
                            &deps.before_state_save,
                        )
                        .await;
                    }
                    let header2 = cookie_header(&merged, now);
                    let outcome2: CheckOutcome = deps.checker.check(&header2).await;
                    updates.extend(outcome2.updates);
                    match outcome2.error {
                        None => {
                            recovered = true;
                            check_err = None;
                        }
                        Some(e2) => {
                            if !is_auth_error(&e2) {
                                return record_transient(
                                    &clock,
                                    &store,
                                    base,
                                    e2,
                                    "auth_check",
                                    &deps.before_state_save,
                                    corrupt_seen,
                                )
                                .await;
                            }
                            check_err = Some(e2);
                        }
                    }
                }
                Err(TryReloginError::Blocker(b)) => {
                    return stop_entry(
                        &clock,
                        &store,
                        base,
                        STOPPED_AUTH_ERROR,
                        Some(b.kind),
                        check_err.unwrap(),
                        &deps.before_state_save,
                    )
                    .await;
                }
                Err(TryReloginError::Unavailable) => {
                    return stop_entry(
                        &clock,
                        &store,
                        base,
                        STOPPED_AUTH_ERROR,
                        Some(NoticeKind::Blocked),
                        check_err.unwrap(),
                        &deps.before_state_save,
                    )
                    .await;
                }
                Err(TryReloginError::Other) => {
                    return stop_entry(
                        &clock,
                        &store,
                        base,
                        STOPPED_AUTH_ERROR,
                        Some(NoticeKind::ReloginFailed),
                        check_err.unwrap(),
                        &deps.before_state_save,
                    )
                    .await;
                }
            }
        }
        if let Some(err) = check_err {
            // No re-login configured (or no exporter and no
            // driver): stop. When credentials are configured
            // but this build has no driver, the stop kind is
            // blocked, not logged_out: the user must know
            // automation could not even attempt the re-login.
            let mut kind: Option<NoticeKind> = None;
            if deps.relogin.is_none() && deps.credentials_configured {
                kind = Some(NoticeKind::Blocked);
            }
            return stop_entry(
                &clock,
                &store,
                base,
                stop_reason(file_missing),
                kind,
                err,
                &deps.before_state_save,
            )
            .await;
        }
    }
    // Phase 3: locked merge + write + state.
    let mut ls = match store.lock() {
        Ok(ls) => ls,
        Err(e) => {
            let (outcome, stage) = classify_lock_error(&e);
            return fail_result(outcome, stage, e, base, corrupt_seen);
        }
    };
    corrupt_seen = corrupt_seen || ls.state_corrupt;
    // Re-check the login pause under the fresh lock: a login
    // that started during the network phase wins.
    if ls.state.login_active {
        ls.state.last_tick_outcome = OUTCOME_SKIPPED.to_string();
        ls.state.last_tick_stage = String::new();
        let next = clock.now() + base;
        ls.state.next_check_at = Some(next);
        if let Err(e) = save_tick_state(&store, &mut ls, &deps.before_state_save) {
            return fail_save_result("save", e, false, base, corrupt_seen);
        }
        return TickResult {
            outcome: OUTCOME_SKIPPED.to_string(),
            stage: String::new(),
            stopped: false,
            recovered: false,
            wrote_cookies: false,
            dropped: 0,
            cdp_dropped: 0,
            exported: 0,
            cookies_seen: 0,
            skipped: 0,
            next_delay: base,
            state_corrupt: corrupt_seen,
            error: None,
        };
    }
    let now2 = clock.now();
    let merged: Vec<StoredCookie>;
    let mut dropped = 0usize;
    let mut wrote = false;
    let mut written: Vec<u8> = Vec::new();
    // A missing cookies file stays missing when there is
    // nothing to write: a successful tick with no cookies
    // must not conjure an empty jar into existence.
    let should_write: bool;
    if recovered {
        let (m, d) = replace_with_export(&ls.cookies, &exported);
        merged = m;
        dropped = d;
        should_write = !ls.file_missing || !merged.is_empty();
        let data = match serialize_jar(&merged) {
            Ok(d) => d,
            Err(e) => return fail_save_result("save", e, false, base, corrupt_seen),
        };
        if should_write {
            // `save_jar` serialises `ls.cookies`: point it
            // at the merged set first.
            ls.cookies = merged.clone();
            match ls.save_jar() {
                Ok(w) => {
                    wrote = w;
                    written = data;
                }
                Err(e) => return fail_save_result("save", e, false, base, corrupt_seen),
            }
        }
    } else if jar_form {
        merged = apply_updates(&ls.cookies, &updates);
        should_write = !ls.file_missing || !merged.is_empty();
        let data = match serialize_jar(&merged) {
            Ok(d) => d,
            Err(e) => return fail_save_result("save", e, false, base, corrupt_seen),
        };
        if should_write {
            ls.cookies = merged.clone();
            match ls.save_jar() {
                Ok(w) => {
                    wrote = w;
                    written = data;
                }
                Err(e) => return fail_save_result("save", e, false, base, corrupt_seen),
            }
        }
    } else {
        // Non-jar file: when the cheap chain rotated a
        // cookie, persist the rotation by converting the
        // file to jar form through the locked atomic
        // writer (G5). With no rotation there is nothing
        // to persist and the file keeps its form.
        merged = apply_updates(&ls.cookies, &updates);
        if !updates.is_empty() {
            should_write = !ls.file_missing || !merged.is_empty();
            if let Ok(data) = serialize_jar(&merged)
                && should_write
            {
                ls.cookies = merged.clone();
                match ls.save_jar() {
                    Ok(w) => {
                        wrote = w;
                        written = data;
                    }
                    Err(e) => return fail_save_result("save", e, false, base, corrupt_seen),
                }
            }
            // A serialisation failure degrades to no-write:
            // the file keeps its form, the state still
            // records the observed expiry, and the next
            // tick retries.
        }
    }
    let st = &mut ls.state;
    st.logged_out = false;
    st.keeper_stopped = false;
    st.keeper_stopped_reason = String::new();
    st.clear_warn_episode();
    st.last_checked_at = Some(now2);
    st.last_tick_outcome = OUTCOME_OK.to_string();
    st.last_tick_stage = String::new();
    st.refresh_cookie_records(&merged, now2);
    if wrote {
        st.cookies_sha256 = sha256_hex(&written);
    } else if !ls.raw.is_empty() {
        st.cookies_sha256 = sha256_hex(&ls.raw);
    } else {
        st.cookies_sha256 = String::new();
    }
    let delay = next_delay_after(base, st.driving_expiry, now2);
    let next = now2 + delay;
    st.next_check_at = Some(next);
    if let Err(e) = save_tick_state(&store, &mut ls, &deps.before_state_save) {
        return fail_save_result("save", e, wrote, base, corrupt_seen);
    }
    TickResult {
        outcome: OUTCOME_OK.to_string(),
        stage: String::new(),
        stopped: false,
        recovered,
        wrote_cookies: wrote,
        dropped,
        cdp_dropped: export_dropped,
        exported: exported.len(),
        cookies_seen: merged.len(),
        skipped,
        next_delay: delay,
        state_corrupt: corrupt_seen,
        error: None,
    }
}

/// The stop reason for a final stop (`tick.go:898-903`).
fn stop_reason(file_missing: bool) -> &'static str {
    if file_missing {
        STOPPED_COOKIES_MISSING
    } else {
        STOPPED_AUTH_ERROR
    }
}

/// Probe the gateway and, on handshake failure, wake the
/// VM up to the entry's wake attempts and re-probe after
/// each wake (`tick.go:944-988`). Returns `Ok` when the
/// gateway is reachable. An `Auth` error means auth died
/// during the probe/wake. Any other error means the
/// gateway stayed down after all wake attempts.
async fn attempt_wake_gateway(deps: &TickDeps, cancel: &CancelFlag) -> Result<(), TransportError> {
    let probe = deps.gateway_probe.as_ref().unwrap();
    let mut last_err = match probe.probe().await {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    if is_auth_error(&last_err) {
        return Err(last_err);
    }
    let attempts = deps.wake_attempts;
    for _ in 0..attempts {
        let Some(wake) = &deps.wake else {
            return Err(last_err);
        };
        if let Err(werr) = wake.wake().await
            && is_auth_error(&werr)
        {
            return Err(werr);
        }
        // A failed wake request still counts as an
        // attempt: re-probe below; the probe decides.
        if cancel.is_cancelled() {
            return Err(TransportError::Timeout {
                message: "tick cancelled".to_string(),
            });
        }
        match probe.probe().await {
            Ok(()) => return Ok(()),
            Err(e) => last_err = e,
        }
        if is_auth_error(&last_err) {
            return Err(last_err);
        }
    }
    Err(last_err)
}

/// Persist a wake-exhausted transient outcome
/// (`tick.go:989-1034`): the cheap chain succeeded, so its
/// Set-Cookie updates ARE persisted — through the same
/// convert-to-jar write as the normal path — but the entry
/// does not stop and no notice is sent.
#[allow(clippy::too_many_arguments)]
async fn record_gateway_down(
    clock: &Arc<dyn Clock>,
    store: &Store,
    base: Duration,
    updates: &[CookieUpdate],
    jar_form: bool,
    _file_missing: bool,
    err: TransportError,
    before: &Option<Arc<dyn Fn() + Send + Sync>>,
) -> TickResult {
    let mut ls = match store.lock() {
        Ok(ls) => ls,
        Err(e) => {
            if matches!(e, KeeperError::LockTimeout) {
                return TickResult {
                    outcome: OUTCOME_TRANSIENT_ERROR.to_string(),
                    stage: "gateway".to_string(),
                    stopped: false,
                    recovered: false,
                    wrote_cookies: false,
                    dropped: 0,
                    cdp_dropped: 0,
                    exported: 0,
                    cookies_seen: 0,
                    skipped: 0,
                    next_delay: base,
                    state_corrupt: false,
                    error: Some(KeeperError::Other(err.to_string())),
                };
            }
            return TickResult {
                outcome: OUTCOME_ERROR.to_string(),
                stage: "save".to_string(),
                stopped: false,
                recovered: false,
                wrote_cookies: false,
                dropped: 0,
                cdp_dropped: 0,
                exported: 0,
                cookies_seen: 0,
                skipped: 0,
                next_delay: base,
                state_corrupt: false,
                error: Some(KeeperError::Other(format!("{e}; {err}"))),
            };
        }
    };
    let state_corrupt = ls.state_corrupt;
    let now2 = clock.now();
    let mut merged = ls.cookies.clone();
    let mut wrote = false;
    if !updates.is_empty() {
        merged = apply_updates(&ls.cookies, updates);
        if (!ls.file_missing || !merged.is_empty())
            && let Ok(_data) = serialize_jar(&merged)
        {
            ls.cookies = merged.clone();
            match ls.save_jar() {
                Ok(w) => wrote = w,
                Err(serr) => {
                    return TickResult {
                        outcome: OUTCOME_ERROR.to_string(),
                        stage: "save".to_string(),
                        stopped: false,
                        recovered: false,
                        wrote_cookies: false,
                        dropped: 0,
                        cdp_dropped: 0,
                        exported: 0,
                        cookies_seen: 0,
                        skipped: 0,
                        next_delay: base,
                        state_corrupt,
                        error: Some(KeeperError::Other(format!("{serr}; {err}"))),
                    };
                }
            }
        }
    }
    let _ = jar_form;
    let st = &mut ls.state;
    st.last_checked_at = Some(now2);
    st.last_tick_outcome = OUTCOME_TRANSIENT_ERROR.to_string();
    st.last_tick_stage = "gateway".to_string();
    st.refresh_cookie_records(&merged, now2);
    let next = now2 + base;
    st.next_check_at = Some(next);
    if let Err(serr) = save_tick_state(store, &mut ls, before) {
        return TickResult {
            outcome: OUTCOME_ERROR.to_string(),
            stage: "save".to_string(),
            stopped: false,
            recovered: false,
            wrote_cookies: wrote,
            dropped: 0,
            cdp_dropped: 0,
            exported: 0,
            cookies_seen: 0,
            skipped: 0,
            next_delay: base,
            state_corrupt,
            error: Some(KeeperError::Other(format!("{serr}; {err}"))),
        };
    }
    TickResult {
        outcome: OUTCOME_TRANSIENT_ERROR.to_string(),
        stage: "gateway".to_string(),
        stopped: false,
        recovered: false,
        wrote_cookies: wrote,
        dropped: 0,
        cdp_dropped: 0,
        exported: 0,
        cookies_seen: merged.len(),
        skipped: 0,
        next_delay: base,
        state_corrupt,
        error: Some(KeeperError::Other(err.to_string())),
    }
}

/// The three outcomes of `try_relogin`.
enum TryReloginError {
    Blocker(ReloginBlocker),
    Unavailable,
    /// Any other driver error: the tick stops with
    /// `relogin_failed` and keeps the original auth
    /// error, so the driver error itself is not carried.
    Other,
}

/// Run one headless re-login attempt sequence
/// (`tick.go:1035-1066`): fetch the credential through the
/// narrow provider (never from an exported field), invoke
/// the driver once, and convert the harvest to merge form.
/// A missing credential provider or a missing credential
/// is `Unavailable` (the entry is misconfigured for
/// re-login). A blocker passes through untouched; any
/// other driver error passes through for the tick to stop
/// with `relogin_failed`. The fetched credential copy is
/// cleared on return.
async fn try_relogin(
    deps: &TickDeps,
    driver: &dyn ReloginDriver,
    _snapshot_cookies: &[StoredCookie],
    _now: DateTime<FixedOffset>,
) -> Result<(Vec<StoredCookie>, usize), TryReloginError> {
    let Some(provider) = &deps.credential_provider else {
        return Err(TryReloginError::Unavailable);
    };
    let Some(mut cred) = provider() else {
        return Err(TryReloginError::Unavailable);
    };
    let result = driver.relogin(cred.clone()).await;
    cred.clear();
    let raw = match result {
        Ok(raw) => raw,
        Err(ReloginError::Blocker(b)) => return Err(TryReloginError::Blocker(b)),
        Err(ReloginError::Unavailable) => return Err(TryReloginError::Unavailable),
        Err(ReloginError::Other(_msg)) => {
            return Err(TryReloginError::Other);
        }
    };
    let mut out = Vec::with_capacity(raw.len());
    let mut dropped = 0;
    for c in raw {
        let sc = from_exported_cookie(&c);
        if !in_filtered_domain(&sc) {
            dropped += 1;
            continue;
        }
        out.push(sc);
    }
    Ok((out, dropped))
}

/// Persist a transient-error outcome (backoff ladder
/// exhausted or a non-auth error after the export
/// re-check) (`tick.go:1099-1124`). No stop, no notice.
/// Updates received alongside the failed check are
/// intentionally NOT persisted here.
async fn record_transient(
    clock: &Arc<dyn Clock>,
    store: &Store,
    base: Duration,
    err: TransportError,
    stage: &str,
    before: &Option<Arc<dyn Fn() + Send + Sync>>,
    corrupt_seen: bool,
) -> TickResult {
    // Go `recordTransient` (`tick.go:1099-1123`) has no
    // accumulated flag: a lock failure returns NO
    // `StateCorrupt` (false), and success returns only
    // the NEW lock's `ls.stateCorrupt` — the caller's
    // `corrupt_seen` is ignored (S-7). The parameter
    // stays for call-site symmetry.
    let _ = corrupt_seen;
    let mut ls = match store.lock() {
        Ok(ls) => ls,
        Err(e) => {
            if matches!(e, KeeperError::LockTimeout) {
                return TickResult {
                    outcome: OUTCOME_TRANSIENT_ERROR.to_string(),
                    stage: stage.to_string(),
                    stopped: false,
                    recovered: false,
                    wrote_cookies: false,
                    dropped: 0,
                    cdp_dropped: 0,
                    exported: 0,
                    cookies_seen: 0,
                    skipped: 0,
                    next_delay: base,
                    state_corrupt: false,
                    error: Some(KeeperError::Other(err.to_string())),
                };
            }
            return TickResult {
                outcome: OUTCOME_ERROR.to_string(),
                stage: "save".to_string(),
                stopped: false,
                recovered: false,
                wrote_cookies: false,
                dropped: 0,
                cdp_dropped: 0,
                exported: 0,
                cookies_seen: 0,
                skipped: 0,
                next_delay: base,
                state_corrupt: false,
                error: Some(KeeperError::Other(format!("{e}; {err}"))),
            };
        }
    };
    let state_corrupt = ls.state_corrupt;
    let now2 = clock.now();
    let st = &mut ls.state;
    st.last_checked_at = Some(now2);
    st.last_tick_outcome = OUTCOME_TRANSIENT_ERROR.to_string();
    st.last_tick_stage = stage.to_string();
    let cookies = ls.cookies.clone();
    st.refresh_cookie_records(&cookies, now2);
    let next = now2 + base;
    st.next_check_at = Some(next);
    if let Err(serr) = save_tick_state(store, &mut ls, before) {
        return TickResult {
            outcome: OUTCOME_ERROR.to_string(),
            stage: "save".to_string(),
            stopped: false,
            recovered: false,
            wrote_cookies: false,
            dropped: 0,
            cdp_dropped: 0,
            exported: 0,
            cookies_seen: 0,
            skipped: 0,
            next_delay: base,
            state_corrupt,
            error: Some(KeeperError::Other(format!("{serr}; {err}"))),
        };
    }
    TickResult {
        outcome: OUTCOME_TRANSIENT_ERROR.to_string(),
        stage: stage.to_string(),
        stopped: false,
        recovered: false,
        wrote_cookies: false,
        dropped: 0,
        cdp_dropped: 0,
        exported: 0,
        cookies_seen: 0,
        skipped: 0,
        next_delay: base,
        state_corrupt,
        error: Some(KeeperError::Other(err.to_string())),
    }
}

/// Persist an export-failure outcome
/// (`tick.go:1125-1151`): the browser could not be
/// reached, but the session is not proven dead, so the
/// entry keeps ticking. No stop, no notice.
async fn record_export_failed(
    clock: &Arc<dyn Clock>,
    store: &Store,
    base: Duration,
    err: KeeperError,
    before: &Option<Arc<dyn Fn() + Send + Sync>>,
) -> TickResult {
    let mut ls = match store.lock() {
        Ok(ls) => ls,
        Err(e) => {
            if matches!(e, KeeperError::LockTimeout) {
                return TickResult {
                    outcome: OUTCOME_EXPORT_FAILED.to_string(),
                    stage: "export".to_string(),
                    stopped: false,
                    recovered: false,
                    wrote_cookies: false,
                    dropped: 0,
                    cdp_dropped: 0,
                    exported: 0,
                    cookies_seen: 0,
                    skipped: 0,
                    next_delay: base,
                    state_corrupt: false,
                    error: Some(err),
                };
            }
            return TickResult {
                outcome: OUTCOME_ERROR.to_string(),
                stage: "save".to_string(),
                stopped: false,
                recovered: false,
                wrote_cookies: false,
                dropped: 0,
                cdp_dropped: 0,
                exported: 0,
                cookies_seen: 0,
                skipped: 0,
                next_delay: base,
                state_corrupt: false,
                error: Some(KeeperError::Other(format!("{e}; {err}"))),
            };
        }
    };
    let state_corrupt = ls.state_corrupt;
    let now2 = clock.now();
    let st = &mut ls.state;
    st.last_checked_at = Some(now2);
    st.last_tick_outcome = OUTCOME_EXPORT_FAILED.to_string();
    st.last_tick_stage = "export".to_string();
    let cookies = ls.cookies.clone();
    st.refresh_cookie_records(&cookies, now2);
    let next = now2 + base;
    st.next_check_at = Some(next);
    if let Err(serr) = save_tick_state(store, &mut ls, before) {
        return TickResult {
            outcome: OUTCOME_ERROR.to_string(),
            stage: "save".to_string(),
            stopped: false,
            recovered: false,
            wrote_cookies: false,
            dropped: 0,
            cdp_dropped: 0,
            exported: 0,
            cookies_seen: 0,
            skipped: 0,
            next_delay: base,
            state_corrupt,
            error: Some(KeeperError::Other(format!("{serr}; {err}"))),
        };
    }
    TickResult {
        outcome: OUTCOME_EXPORT_FAILED.to_string(),
        stage: "export".to_string(),
        stopped: false,
        recovered: false,
        wrote_cookies: false,
        dropped: 0,
        cdp_dropped: 0,
        exported: 0,
        cookies_seen: 0,
        skipped: 0,
        next_delay: base,
        state_corrupt,
        error: Some(err),
    }
}

/// Persist the sticky stop (`tick.go:1169-1210`):
/// `logged_out`, stopped with reason, and a
/// per-(episode, kind) warn-once marker. It NEVER
/// rewrites the cookies file: when recovery has failed,
/// the pre-stop jar is preserved byte-identical for manual
/// recovery or re-import. `kind` names the notice kind:
/// `""` derives it from the reason as before
/// (`auth_error` → `logged_out`, anything else →
/// `failed`); a caller-supplied kind must be in the closed
/// `NoticeKind` set or it is ignored in favour of the
/// derived kind.
async fn stop_entry(
    clock: &Arc<dyn Clock>,
    store: &Store,
    _base: Duration,
    reason: &str,
    kind: Option<NoticeKind>,
    cause: TransportError,
    before: &Option<Arc<dyn Fn() + Send + Sync>>,
) -> TickResult {
    let mut ls = match store.lock() {
        Ok(ls) => ls,
        Err(e) => {
            if matches!(e, KeeperError::LockTimeout) {
                return TickResult {
                    outcome: OUTCOME_AUTH_ERROR.to_string(),
                    stage: "session".to_string(),
                    stopped: true,
                    recovered: false,
                    wrote_cookies: false,
                    dropped: 0,
                    cdp_dropped: 0,
                    exported: 0,
                    cookies_seen: 0,
                    skipped: 0,
                    next_delay: Duration::ZERO,
                    state_corrupt: false,
                    error: Some(KeeperError::Other(cause.to_string())),
                };
            }
            return TickResult {
                outcome: OUTCOME_ERROR.to_string(),
                stage: "save".to_string(),
                stopped: true,
                recovered: false,
                wrote_cookies: false,
                dropped: 0,
                cdp_dropped: 0,
                exported: 0,
                cookies_seen: 0,
                skipped: 0,
                next_delay: Duration::ZERO,
                state_corrupt: false,
                error: Some(KeeperError::Other(format!("{e}; {cause}"))),
            };
        }
    };
    let state_corrupt = ls.state_corrupt;
    let now2 = clock.now();
    let st = &mut ls.state;
    st.logged_out = true;
    st.keeper_stopped = true;
    st.keeper_stopped_reason = reason.to_string();
    st.last_checked_at = Some(now2);
    st.last_tick_outcome = OUTCOME_AUTH_ERROR.to_string();
    st.last_tick_stage = "session".to_string();
    let cookies = ls.cookies.clone();
    st.refresh_cookie_records(&cookies, now2);
    st.next_check_at = None;
    let kind = match kind {
        Some(k) if valid_notice_kind(k) => k,
        _ => {
            if reason == STOPPED_AUTH_ERROR {
                NoticeKind::LoggedOut
            } else {
                NoticeKind::Failed
            }
        }
    };
    st.mark_warn_pending(kind, now2);
    if let Err(serr) = save_tick_state(store, &mut ls, before) {
        return TickResult {
            outcome: OUTCOME_ERROR.to_string(),
            stage: "save".to_string(),
            stopped: true,
            recovered: false,
            wrote_cookies: false,
            dropped: 0,
            cdp_dropped: 0,
            exported: 0,
            cookies_seen: 0,
            skipped: 0,
            next_delay: Duration::ZERO,
            state_corrupt,
            error: Some(KeeperError::Other(format!("{serr}; {cause}"))),
        };
    }
    TickResult {
        outcome: OUTCOME_AUTH_ERROR.to_string(),
        stage: "session".to_string(),
        stopped: true,
        recovered: false,
        wrote_cookies: false,
        dropped: 0,
        cdp_dropped: 0,
        exported: 0,
        cookies_seen: 0,
        skipped: 0,
        next_delay: Duration::ZERO,
        state_corrupt,
        error: Some(KeeperError::Other(cause.to_string())),
    }
}

/// Send the pending warn-once notice for a stopped entry
/// and record the attempt (`tick.go:1211-1254`). Called by
/// the command layer AFTER Tick returns (never under the
/// lock). A failed send leaves the marker pending for a
/// later tick.
pub async fn notify_stopped(deps: &TickDeps, cancel: &CancelFlag) {
    let Some(notifier) = &deps.notifier else {
        return;
    };
    let Ok(store) = Store::new(&deps.base_dir, &deps.profile_name, "", deps.lock_timeout) else {
        return;
    };
    let Ok(ls) = store.lock() else {
        return;
    };
    let pending = ls.state.warn_pending;
    let raw_kind = ls.state.warn_kind.clone();
    let kind = NoticeKind::parse_kind(&raw_kind).unwrap_or(NoticeKind::LoggedOut);
    drop(ls);
    if !pending {
        return;
    }
    if notifier
        .notify(kind, &deps.profile_name, cancel)
        .await
        .is_err()
    {
        return;
    }
    if let Ok(mut ls2) = store.lock() {
        ls2.state.mark_warn_sent_raw(&raw_kind, deps.clock.now());
        let _ = save_tick_state(&store, &mut ls2, &deps.before_state_save);
    }
}

/// Clear a sticky stop after a successful login or import,
/// so the keeper resumes on its next tick
/// (`tick.go:1255-1277`). Called by the login/import
/// flows, never by the tick itself. A corrupt or
/// unknown-version state file is tolerated (fresh state is
/// written): the import half must never fail after the
/// cookies file was already written.
pub async fn reset_after_login(
    base_dir: &str,
    profile_name: &str,
    clock: Arc<dyn Clock>,
) -> Result<(), KeeperError> {
    let store = Store::new(
        base_dir,
        profile_name,
        "",
        crate::state::DEFAULT_LOCK_TIMEOUT,
    )?;
    let mut ls = store.lock_state_only()?;
    let st = &mut ls.state;
    st.logged_out = false;
    st.keeper_stopped = false;
    st.keeper_stopped_reason = String::new();
    st.clear_warn_episode();
    st.login_active = false;
    st.login_session_id = String::new();
    st.login_started_at = None;
    ls.save_state()?;
    let _ = clock;
    Ok(())
}
