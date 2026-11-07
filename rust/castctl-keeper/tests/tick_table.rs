// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

// Tick decision table — port of the Go tick cases
// (`internal/keeper/tick_test.go`, inventory §2.1).
// Literal expectations: every expected outcome is a
// string/number from the Go behaviour, never recomputed
// by the code under test.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use castctl_keeper::checker::CheckOutcome;
use castctl_keeper::clock::{CancelFlag, FakeClock};
use castctl_keeper::error::{KeeperError, ReloginBlocker, ReloginError};
use castctl_keeper::export::Exporter;
use castctl_keeper::jar::{CookieUpdate, ExportedCookie, StoredCookie};
use castctl_keeper::notify::{NoticeKind, Notifier};
use castctl_keeper::relogin::ReloginDriver;
use castctl_keeper::state::{SessionState, save_state};
use castctl_keeper::tick::{GatewayProbe, TickDeps, tick};
use castctl_transport::{BodySummary, TransportError};
use chrono::{FixedOffset, TimeZone};

const NOW: i64 = 1_792_000_000; // 2026-10-14T… fixed test time
const HATCH_EXP: i64 = NOW + 30 * 24 * 3600; // 30 days out

/// The tick's fixed `now` (M7g): the same instant as the
/// old UTC value, but at `+07:00` — the machine-local
/// offset on cue — so the saved state must carry
/// `+07:00`, not `+00:00`.
fn now() -> chrono::DateTime<FixedOffset> {
    FixedOffset::east_opt(7 * 3600)
        .unwrap()
        .timestamp_opt(NOW, 0)
        .single()
        .unwrap()
}

fn hatch(value: &str, expires: i64) -> StoredCookie {
    StoredCookie {
        name: "hatch_sess".to_string(),
        value: value.to_string(),
        domain: ".muse.ai".to_string(),
        path: "/".to_string(),
        secure: true,
        http_only: true,
        expires,
    }
}

fn jar_text(cookies: &[StoredCookie]) -> String {
    let mut out = String::from("# Netscape HTTP Cookie File\n");
    for c in cookies {
        out.push_str(&format!(
            "{}\tTRUE\t{}\t{}\t{}\t{}\t{}\n",
            c.domain,
            c.path,
            if c.secure { "TRUE" } else { "FALSE" },
            c.expires,
            c.name,
            c.value
        ));
    }
    out
}

struct Harness {
    base: std::path::PathBuf,
    clock: Arc<FakeClock>,
}

impl Harness {
    fn new(tag: &str) -> Self {
        let base =
            std::env::temp_dir().join(format!("castctl-keeper-tick-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        Self {
            base,
            clock: Arc::new(FakeClock::new(now())),
        }
    }

    fn profile_dir(&self) -> std::path::PathBuf {
        castctl_config::profile::profile_paths(self.base.to_str().unwrap(), "no.0")
            .unwrap()
            .dir
            .into()
    }

    fn write_jar(&self, cookies: &[StoredCookie]) {
        let dir = self.profile_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cookies.txt"), jar_text(cookies)).unwrap();
    }

    fn write_state(&self, st: &SessionState) {
        let dir = self.profile_dir();
        std::fs::create_dir_all(&dir).unwrap();
        save_state(dir.to_str().unwrap(), st).unwrap();
    }

    fn read_state(&self) -> SessionState {
        castctl_keeper::state::load_state(self.profile_dir().to_str().unwrap()).unwrap()
    }

    fn read_jar(&self) -> String {
        std::fs::read_to_string(self.profile_dir().join("cookies.txt")).unwrap_or_default()
    }

    fn deps(&self, checker: Arc<dyn castctl_keeper::checker::Checker>) -> TickDeps {
        TickDeps {
            clock: self.clock.clone(),
            tag: "no.0".to_string(),
            interval: Duration::from_secs(24 * 3600),
            retry_backoff: vec![
                Duration::from_secs(5 * 60),
                Duration::from_secs(15 * 60),
                Duration::from_secs(45 * 60),
            ],
            wake_on_gateway_failure: false,
            wake_attempts: 3,
            credentials_configured: false,
            base_dir: self.base.to_str().unwrap().to_string(),
            profile_name: "no.0".to_string(),
            cookies_path: String::new(),
            checker,
            exporter: None,
            notifier: None,
            gateway_probe: None,
            wake: None,
            relogin: None,
            credential_provider: None,
            jitter: Some(Arc::new(|| 0.5)),
            lock_timeout: Duration::from_secs(5),
            before_state_save: None,
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn ok_outcome() -> CheckOutcome {
    CheckOutcome {
        updates: vec![],
        skipped: 0,
        error: None,
    }
}

fn auth_outcome() -> CheckOutcome {
    CheckOutcome {
        updates: vec![],
        skipped: 0,
        error: Some(TransportError::Auth {
            message: "api/session -> 401 (cookies expired? re-export)".to_string(),
        }),
    }
}

fn transient_outcome() -> CheckOutcome {
    CheckOutcome {
        updates: vec![],
        skipped: 0,
        error: Some(TransportError::ConnectionDown {
            message: "connection refused".to_string(),
        }),
    }
}

/// A checker that replays a script, then repeats the
/// last outcome.
fn script_checker(script: Vec<CheckOutcome>) -> Arc<dyn castctl_keeper::checker::Checker> {
    use castctl_keeper::checker::CheckerFunc;
    let q = Arc::new(std::sync::Mutex::new(VecDeque::from(script)));
    let q2 = q.clone();
    Arc::new(CheckerFunc(move |_header: &str| {
        let q = q2.clone();
        Box::pin(async move {
            let mut guard = q.lock().unwrap();
            guard.pop_front().unwrap_or_else(ok_outcome)
        })
    }))
}

struct ScriptExporter {
    script: std::sync::Mutex<VecDeque<Result<Vec<ExportedCookie>, KeeperError>>>,
}

#[async_trait::async_trait]
impl Exporter for ScriptExporter {
    async fn export(&self) -> Result<Vec<ExportedCookie>, KeeperError> {
        let mut g = self.script.lock().unwrap();
        g.pop_front().unwrap_or(Ok(vec![]))
    }
}

struct ScriptRelogin {
    script: std::sync::Mutex<VecDeque<Result<Vec<ExportedCookie>, ReloginError>>>,
}

#[async_trait::async_trait]
impl ReloginDriver for ScriptRelogin {
    async fn relogin(
        &self,
        _cred: castctl_config::LoginCredential,
    ) -> Result<Vec<ExportedCookie>, ReloginError> {
        let mut g = self.script.lock().unwrap();
        g.pop_front().unwrap_or(Err(ReloginError::Unavailable))
    }
}

struct RecordingNotifier {
    kinds: Arc<std::sync::Mutex<Vec<NoticeKind>>>,
}

#[async_trait::async_trait]
impl Notifier for RecordingNotifier {
    async fn notify(
        &self,
        kind: NoticeKind,
        _profile_name: &str,
        _cancel: &CancelFlag,
    ) -> Result<(), KeeperError> {
        self.kinds.lock().unwrap().push(kind);
        Ok(())
    }
}

fn exported_hatch(expires: f64) -> ExportedCookie {
    ExportedCookie {
        name: "hatch_sess".to_string(),
        value: "fresh-value".to_string(),
        domain: ".muse.ai".to_string(),
        path: "/".to_string(),
        expires,
        secure: true,
        http_only: true,
        session: false,
    }
}

fn fresh_state() -> SessionState {
    let mut st = SessionState::new();
    st.last_tick_outcome = "ok".to_string();
    st
}

#[tokio::test]
async fn case_01_token_ok() {
    let h = Harness::new("01");
    h.write_jar(&[hatch("v1", HATCH_EXP)]);
    let deps = h.deps(script_checker(vec![ok_outcome()]));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "ok");
    assert!(!r.stopped);
    assert!(!r.recovered);
    assert_eq!(r.next_delay, Duration::from_secs(24 * 3600));
    assert_eq!(h.read_state().last_tick_outcome, "ok");
}

/// M7g: an ok tick writes `last/next_check_at` (and
/// `last_seen`) with the clock's local offset (`+07:00`
/// here) into `session-state.json` — the Go `time.Now()`
/// marshal — never `+00:00`. The raw file text is
/// asserted, not just the parsed value.
#[tokio::test]
async fn tick_writes_local_offset_state() {
    let h = Harness::new("local-offset");
    h.write_jar(&[hatch("v1", HATCH_EXP)]);
    let deps = h.deps(script_checker(vec![ok_outcome()]));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "ok");
    let raw = std::fs::read_to_string(h.profile_dir().join("session-state.json")).unwrap();
    assert!(
        raw.contains("+07:00"),
        "saved state must carry the local offset, got:\n{raw}"
    );
    assert!(
        !raw.contains("+00:00"),
        "saved state must not contain +00:00, got:\n{raw}"
    );
}

#[tokio::test]
async fn case_02_auth_error_recovered_by_export() {
    let h = Harness::new("02");
    h.write_jar(&[hatch("old", NOW - 3600)]); // expired driving cookie
    let mut deps = h.deps(script_checker(vec![auth_outcome(), ok_outcome()]));
    deps.exporter = Some(Arc::new(ScriptExporter {
        script: std::sync::Mutex::new(VecDeque::from(vec![Ok(vec![exported_hatch(
            HATCH_EXP as f64,
        )])])),
    }));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "ok");
    assert!(r.recovered);
    assert!(r.wrote_cookies);
    assert!(h.read_jar().contains("fresh-value"));
}

#[tokio::test]
async fn case_03_auth_error_no_exporter_no_relogin_stops() {
    let h = Harness::new("03");
    h.write_jar(&[hatch("old", NOW - 3600)]);
    let before = h.read_jar();
    let mut deps = h.deps(script_checker(vec![auth_outcome()]));
    deps.credentials_configured = false;
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "auth_error");
    assert!(r.stopped);
    assert_eq!(h.read_state().keeper_stopped_reason, "auth_error");
    // Stop path preserves the jar byte-identical (K-LIVE-2).
    assert_eq!(h.read_jar(), before);
}

#[tokio::test]
async fn case_04_export_failed_keeps_ticking() {
    let h = Harness::new("04");
    h.write_jar(&[hatch("old", NOW - 3600)]);
    let mut deps = h.deps(script_checker(vec![auth_outcome()]));
    deps.exporter = Some(Arc::new(ScriptExporter {
        script: std::sync::Mutex::new(VecDeque::from(vec![Err(KeeperError::Other(
            "browser unreachable".to_string(),
        ))])),
    }));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "export_failed");
    assert!(!r.stopped);
    assert_eq!(r.next_delay, Duration::from_secs(24 * 3600));
}

#[tokio::test]
async fn case_05_transient_error_backoff_ladder() {
    let h = Harness::new("05");
    h.write_jar(&[hatch("v1", HATCH_EXP)]);
    // Transient 4 times: 3 sleeps (5m/15m/45m) then the
    // ladder is exhausted.
    let deps = h.deps(script_checker(vec![
        transient_outcome(),
        transient_outcome(),
        transient_outcome(),
        transient_outcome(),
    ]));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "transient_error");
    assert!(!r.stopped);
    assert_eq!(r.next_delay, Duration::from_secs(24 * 3600));
    assert_eq!(h.read_state().last_tick_outcome, "transient_error");
}

#[tokio::test]
async fn case_06_transient_recovers_on_retry() {
    let h = Harness::new("06");
    h.write_jar(&[hatch("v1", HATCH_EXP)]);
    let deps = h.deps(script_checker(vec![transient_outcome(), ok_outcome()]));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "ok");
    assert!(!r.stopped);
}

#[tokio::test]
async fn case_07_cancelled_tick_is_hard_error() {
    let h = Harness::new("07");
    h.write_jar(&[hatch("v1", HATCH_EXP)]);
    let deps = h.deps(script_checker(vec![transient_outcome()]));
    let cancel = CancelFlag::new();
    cancel.cancel();
    let r = tick(&deps, &cancel).await;
    assert_eq!(r.outcome, "error");
    assert!(!r.stopped);
}

#[tokio::test]
async fn case_08_login_flag_fresh_skips() {
    let h = Harness::new("08");
    h.write_jar(&[hatch("v1", HATCH_EXP)]);
    let mut st = fresh_state();
    st.login_active = true;
    st.login_started_at = Some(now());
    st.login_session_id = "sess-1".to_string();
    h.write_state(&st);
    let deps = h.deps(script_checker(vec![ok_outcome()]));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "skipped");
    assert!(!r.stopped);
    assert_eq!(r.next_delay, Duration::from_secs(24 * 3600));
}

#[tokio::test]
async fn case_09_login_flag_stale_recovers() {
    let h = Harness::new("09");
    h.write_jar(&[hatch("v1", HATCH_EXP)]);
    let mut st = fresh_state();
    st.login_active = true;
    st.login_started_at = Some(now() - chrono::Duration::minutes(71));
    st.login_session_id = "sess-1".to_string();
    h.write_state(&st);
    let deps = h.deps(script_checker(vec![ok_outcome()]));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "ok");
    assert!(!h.read_state().login_active);
}

#[tokio::test]
async fn case_10_sticky_stop_persists_and_notifies() {
    let h = Harness::new("10");
    h.write_jar(&[hatch("v1", HATCH_EXP)]);
    let mut st = fresh_state();
    st.keeper_stopped = true;
    st.keeper_stopped_reason = "auth_error".to_string();
    st.last_tick_outcome = "auth_error".to_string();
    st.warn_pending = true;
    st.warn_kind = "logged_out".to_string();
    h.write_state(&st);
    let kinds = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut deps = h.deps(script_checker(vec![ok_outcome()]));
    deps.notifier = Some(Arc::new(RecordingNotifier {
        kinds: kinds.clone(),
    }));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "auth_error");
    assert!(r.stopped);
    assert_eq!(r.next_delay, Duration::ZERO);
    assert_eq!(*kinds.lock().unwrap(), vec![NoticeKind::LoggedOut]);
    assert!(!h.read_state().warn_pending);
}

#[tokio::test]
async fn case_11_state_corrupt_recovered() {
    let h = Harness::new("11");
    h.write_jar(&[hatch("v1", HATCH_EXP)]);
    let dir = h.profile_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("session-state.json"), "{not json").unwrap();
    let deps = h.deps(script_checker(vec![ok_outcome()]));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert!(r.state_corrupt);
    assert_eq!(r.outcome, "ok");
    // The corrupt file is replaced by a fresh state.
    assert!(h.read_state().last_tick_outcome == "ok");
}

#[tokio::test]
async fn case_12_cookies_missing_stops() {
    let h = Harness::new("12");
    // No cookies file at all.
    let deps = h.deps(script_checker(vec![auth_outcome()]));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "auth_error");
    assert!(r.stopped);
    assert_eq!(h.read_state().keeper_stopped_reason, "cookies_missing");
}

#[tokio::test]
async fn case_13_lock_held_skips() {
    let h = Harness::new("13");
    h.write_jar(&[hatch("v1", HATCH_EXP)]);
    let dir = h.profile_dir();
    let cookies_path = dir.join("cookies.txt");
    let _guard = castctl_keeper::lockfile::lock_cookies_file(
        h.base.to_str().unwrap(),
        "no.0",
        cookies_path.to_str().unwrap(),
        Duration::from_secs(5),
    )
    .unwrap();
    let mut deps = h.deps(script_checker(vec![ok_outcome()]));
    deps.lock_timeout = Duration::from_millis(200);
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "skipped");
    assert_eq!(r.stage, "lock");
    assert!(!r.stopped);
}

#[tokio::test]
async fn case_14_export_invalid_set_stops() {
    let h = Harness::new("14");
    h.write_jar(&[hatch("old", NOW - 3600)]);
    let mut deps = h.deps(script_checker(vec![auth_outcome(), ok_outcome()]));
    // Exported set has no hatch_sess: invalid.
    deps.exporter = Some(Arc::new(ScriptExporter {
        script: std::sync::Mutex::new(VecDeque::from(vec![Ok(vec![ExportedCookie {
            name: "datr".to_string(),
            value: "x".to_string(),
            domain: ".facebook.com".to_string(),
            path: "/".to_string(),
            expires: HATCH_EXP as f64,
            secure: true,
            http_only: false,
            session: false,
        }])])),
    }));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "auth_error");
    assert!(r.stopped);
}

#[tokio::test]
async fn case_15_relogin_blocker_stops_with_kind() {
    let h = Harness::new("15");
    h.write_jar(&[hatch("old", NOW - 3600)]);
    let mut deps = h.deps(script_checker(vec![auth_outcome()]));
    deps.credentials_configured = true;
    deps.credential_provider = Some(Arc::new(|| {
        Some(castctl_config::LoginCredential {
            username: "u".to_string(),
            password: "p".to_string(),
        })
    }));
    deps.relogin = Some(Arc::new(ScriptRelogin {
        script: std::sync::Mutex::new(VecDeque::from(vec![Err(ReloginError::Blocker(
            ReloginBlocker::new(NoticeKind::Captcha, "blocker_signal"),
        ))])),
    }));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "auth_error");
    assert!(r.stopped);
    assert_eq!(h.read_state().warn_kind, "captcha");
}

#[tokio::test]
async fn case_16_relogin_unavailable_stops_blocked() {
    let h = Harness::new("16");
    h.write_jar(&[hatch("old", NOW - 3600)]);
    let mut deps = h.deps(script_checker(vec![auth_outcome()]));
    deps.credentials_configured = true;
    // No provider, no driver: re-login cannot even start.
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "auth_error");
    assert!(r.stopped);
    assert_eq!(h.read_state().warn_kind, "blocked");
}

#[tokio::test]
async fn case_17_gateway_down_persists_updates() {
    let h = Harness::new("17");
    h.write_jar(&[hatch("v1", HATCH_EXP)]);
    // Cheap chain succeeds with a Set-Cookie update, then
    // the gateway probe stays down after wake attempts.
    let update = CookieUpdate {
        cookie: hatch("v2", HATCH_EXP + 3600),
        delete: false,
    };
    struct DownProbe;
    #[async_trait::async_trait]
    impl GatewayProbe for DownProbe {
        async fn probe(&self) -> Result<(), TransportError> {
            Err(TransportError::Gateway(BodySummary::new(500, None, "")))
        }
    }
    let mut deps = h.deps(script_checker(vec![CheckOutcome {
        updates: vec![update],
        skipped: 0,
        error: None,
    }]));
    deps.wake_on_gateway_failure = true;
    deps.gateway_probe = Some(Arc::new(DownProbe));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "transient_error");
    assert_eq!(r.stage, "gateway");
    assert!(!r.stopped);
    assert!(r.wrote_cookies);
    // The cheap-chain update IS persisted (gateway-down
    // path), unlike the transient path.
    assert!(h.read_jar().contains("v2"));
}

#[tokio::test]
async fn case_18_tick_writes_configured_cookies_file() {
    // M7e regression test for D-M7e-2: the tick ignored a
    // configured `cookies_file` (it passed "" to `Store::new`,
    // so it always read/wrote the profile default). The jar
    // lives ONLY at the configured path — the default file
    // does not exist — so a tick that ignores the configured
    // path cannot reach the jar at all.
    let h = Harness::new("18");
    let configured = h.base.join("custom-cookies.txt");
    std::fs::write(&configured, jar_text(&[hatch("old", NOW - 3600)])).unwrap();
    let mut deps = h.deps(script_checker(vec![auth_outcome(), ok_outcome()]));
    deps.cookies_path = configured.to_str().unwrap().to_string();
    deps.exporter = Some(Arc::new(ScriptExporter {
        script: std::sync::Mutex::new(VecDeque::from(vec![Ok(vec![exported_hatch(
            HATCH_EXP as f64,
        )])])),
    }));
    let r = tick(&deps, &CancelFlag::new()).await;
    assert_eq!(r.outcome, "ok");
    assert!(r.recovered);
    assert!(r.wrote_cookies);
    // The CONFIGURED file carries the exported value …
    let written = std::fs::read_to_string(&configured).unwrap();
    assert!(written.contains("fresh-value"));
    assert!(!written.contains("old"));
    // … and the default file was never created.
    assert!(!h.profile_dir().join("cookies.txt").exists());
}
