// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Session keeper — Rust port of Go `internal/keeper` (M6a).
//!
//! Go sources: `internal/keeper/*.go` at `origin/dev-rust`
//! (`07e1c0d`), plus the keeper-adjacent profile helpers
//! (`internal/profile/keeper.go` for the config block — ported
//! in `castctl-config::keeper` — `cookies.go` for the atomic
//! write and `cookielock.go` for the flock).
//!
//! Behaviour notes (see `rust/PORTING.md` §M6a for the full
//! list):
//! - The Go tick is synchronous; this port is async (tokio):
//!   `Checker`, `Exporter`, `ReloginDriver` and `Notifier`
//!   are async traits, and cancellation is a [`CancelFlag`]
//!   instead of a `context.Context`.
//! - Times: local-origin keeper times
//!   (`last/next_check_at`, `login_*`, `warned_at`,
//!   `last_seen`, audit `started_at`) are
//!   `chrono::DateTime<FixedOffset>` carrying the stored
//!   offset (Go `time.Time` JSON semantics — M7g);
//!   cookie-expiry times (`expires_at`,
//!   `earliest_expiry`, `driving_expiry`) are
//!   `chrono::DateTime<FixedOffset>` too since fix loop 1
//!   (B6): the values are UTC instants (Go
//!   `time.Unix(...).UTC()`, so they render `Z`), but the
//!   type keeps a stored non-`Z` offset on re-print like
//!   Go instead of normalising it away.
//!   Durations are `std::time::Duration`.
//! - Cookie VALUES never reach logs, errors, or state: error
//!   types carry names, counts and kinds only (the
//!   hand-written `Debug` impls enforce this).
//! - The `chromedp` feature (default ON) selects the real CDP
//!   client; with `--no-default-features` every CDP entry
//!   point refuses with the typed unavailable error, matching
//!   the Go `!with_chromedp` stubs.

pub mod authstatus;
pub mod backoff;
pub mod cdp;
pub mod checker;
pub mod clock;
pub mod contract;
pub mod error;
pub mod export;
pub mod jar;
pub mod launch;
pub mod lockfile;
pub mod login;
pub mod notify;
pub mod relogin;
pub mod run;
pub mod screencast;
pub mod setcookie;
pub mod state;
pub mod store;
pub mod tick;
pub mod transport;

pub use authstatus::{AuthStatus, AuthStatusValue, cookie_expiry_metadata, derive_auth_status};
pub use backoff::{BACKOFF_MAX_RETRIES, Backoff, DEFAULT_BACKOFF_LADDER, next_delay_after};
pub use cdp::{
    CdpClient, CdpError, CdpEvent, CdpSession, TargetInfo, discover_websocket_url, list_targets,
};
pub use checker::{AUTH_CHECK_URL, CheckOutcome, Checker, GatewayChecker, SESSION_CHECK_URL};
pub use clock::{CancelFlag, Clock, FakeClock, RealClock};
pub use contract::{
    LoginBlockerSignal, LoginContract, LoginContractStep, PageSnapshot, SnapshotDecisionError,
    SnapshotResult, default_login_contract, is_blocker_signal, match_contract, snapshot_decision,
    validate_contract,
};
pub use error::{KeeperError, ReloginBlocker, ReloginError};
pub use export::{CDP_AVAILABLE, CdpExporter, Exporter, new_cdp_exporter};
pub use jar::{
    CookieUpdate, ExportedCookie, FILTERED_DOMAINS, StoredCookie, apply_updates, cookie_header,
    driving_cookie, earliest_expiry, earliest_filtered_expiry, effective_set_cookie,
    from_exported_cookie, in_filtered_domain, parse_cookies_lenient, parse_jar,
    replace_with_export, serialize_jar,
};
pub use launch::{
    CHROMIUM_PATH_ENV, InboundBuilder, LaunchUnavailable, browser_profile_dir, resolve_browser_path,
};
pub use lockfile::{LockGuard, lock_cookies_file, lock_short_file, write_cookies_file};
pub use login::{
    BrowserVersion, DEFAULT_LOGIN_TIMEOUT, LOGIN_AUDIT_FILE_NAME, LOGIN_AUDIT_MAX_RECORDS,
    LOGIN_POLL_INTERVAL, LoginResult, LoginSession, MAX_LOGIN_TIMEOUT, MIN_LOGIN_TIMEOUT,
    RunnerResult, ScreencastRunner,
};
pub use notify::{
    ALL_NOTICE_KINDS, NoticeKind, Notifier, notice_text, sanitize_display, valid_notice_kind,
};
pub use relogin::{
    LoginPageObservation, ObserveOptions, ObservedElement, ReloginDriver, ReloginDriverFunc,
    ReloginOptions, ReloginTimeouts, new_relogin_driver, observe_login_page, relogin_available,
    snapshot_script, strip_observation_url,
};
pub use run::{
    OWNER_HEARTBEAT_INTERVAL, OWNER_STALE_AFTER, OnTick, RunResult, Status, acquire_single_flight,
    read_status, run_entries, run_entry,
};
pub use screencast::{
    http_base_from_browser_url, new_attach_runner, new_launch_runner, resolve_screencast_target,
};
pub use state::{
    CookieState, DEFAULT_LOCK_TIMEOUT, LOGIN_FLAG_STALE_AFTER, STATE_FILE_NAME, STATE_VERSION,
    STOPPED_AUTH_ERROR, STOPPED_COOKIES_MISSING, STOPPED_STATE_CORRUPT, SessionState, load_state,
    save_state, sha256_hex, state_path,
};
pub use store::{LockedStore, Store};
pub use tick::{
    TickDeps, TickResult, notify_stopped, reset_after_login, tick, validate_exported_set,
};
pub use transport::{FakeTransport, Frame, InputEvent, InputKind, SessionPhase, Transport};
