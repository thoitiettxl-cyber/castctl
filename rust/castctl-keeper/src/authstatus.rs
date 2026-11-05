// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Auth status: the state-only, no-network report behind
//! `castctl auth status` — port of
//! `internal/keeper/authstatus.go`.
//!
//! It reads only the profile's cookies file (expiry
//! metadata: names and dates, never values) and its keeper
//! state file. No network I/O, no browser contact, and
//! never a cookie name beyond the driving cookie's NAME
//! (which names the expiry that drives the status, not a
//! value).

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::KeeperError;
use crate::jar::driving_cookie;
use crate::state::{STOPPED_AUTH_ERROR, STOPPED_COOKIES_MISSING, SessionState};
use crate::store::classify_cookies_file;

/// The closed status enum for one profile
/// (`authstatus.go:25-38`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatusValue {
    /// The driving cookie is not expiring within the
    /// entry's window, or no expiry metadata exists to
    /// judge by (non-jar file with no keeper state,
    /// session-only cookies).
    Ok,
    /// The driving expiry falls within the entry's
    /// `expiring_within` window.
    Expiring,
    /// The driving expiry is past, or the keeper stopped
    /// the entry for a dead session.
    Expired,
}

impl AuthStatusValue {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthStatusValue::Ok => "ok",
            AuthStatusValue::Expiring => "expiring",
            AuthStatusValue::Expired => "expired",
        }
    }
}

/// One profile's state-only auth report
/// (`authstatus.go:41-55`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthStatus {
    pub profile: String,
    pub status: AuthStatusValue,
    /// Driving cookie NAME only, `""` when unknown.
    pub driving_cookie: String,
    /// `None` when no dated cookie exists.
    pub driving_expiry: Option<DateTime<Utc>>,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub keeper_stopped: bool,
    pub keeper_stopped_reason: String,
    pub headless_available: bool,
    /// Closed enum: `""`, `"no_chromedp"`,
    /// `"no_credentials"`, `"no_credentials_ref"`,
    /// `"no_keeper_entry"`, `"no_contract"`.
    pub headless_reason: String,
    pub needs_action: bool,
    pub cookies_seen: usize,
}

/// Read a cookies file and return its driving cookie (name
/// only), driving expiry, cookie count, and whether the
/// file is missing (`authstatus.go:64-80`). A missing file
/// returns `missing = true` and no error: absence is itself
/// the report (expired — there is nothing to authenticate
/// with). A corrupt file returns an error naming the file
/// only, never its bytes.
/// What [`cookie_expiry_metadata`] reports: (driving cookie
/// name, driving expiry, cookies seen, file missing).
pub type ExpiryMetadata = (String, Option<DateTime<Utc>>, usize, bool);

pub fn cookie_expiry_metadata(
    cookies_path: &str,
    _now: DateTime<Utc>,
) -> Result<ExpiryMetadata, KeeperError> {
    let raw = match std::fs::read(cookies_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((String::new(), None, 0, true));
        }
        Err(e) => return Err(KeeperError::Io(e)),
    };
    let (cookies, _is_jar) = classify_cookies_file(&raw, cookies_path)?;
    let (name, exp) = driving_cookie(&cookies);
    Ok((name, exp, cookies.len(), false))
}

/// Combine cookies-file expiry metadata with keeper state
/// into one [`AuthStatus`] (`authstatus.go:101-158`).
/// `expiring_within` is the entry's window
/// (`DefaultExpiringWithin` when the entry is absent). A
/// stopped entry whose reason names a dead session
/// (`auth_error`, `cookies_missing`) is expired regardless
/// of the file's dates: the keeper already proved the
/// session dead. `headless_available`/`headless_reason`
/// are computed by the caller and carried through
/// verbatim; they do not by themselves set `needs_action`.
#[allow(clippy::too_many_arguments)]
pub fn derive_auth_status(
    profile_name: &str,
    driving_name: &str,
    driving_expiry: Option<DateTime<Utc>>,
    cookies_seen: usize,
    file_missing: bool,
    st: Option<&SessionState>,
    expiring_within: Duration,
    headless_available: bool,
    headless_reason: &str,
    now: DateTime<Utc>,
) -> AuthStatus {
    let mut out = AuthStatus {
        profile: profile_name.to_string(),
        status: AuthStatusValue::Ok,
        driving_cookie: driving_name.to_string(),
        driving_expiry,
        last_checked_at: None,
        keeper_stopped: false,
        keeper_stopped_reason: String::new(),
        headless_available,
        headless_reason: headless_reason.to_string(),
        needs_action: false,
        cookies_seen,
    };
    if let Some(st) = st {
        out.last_checked_at = st.last_checked_at;
        out.keeper_stopped = st.keeper_stopped;
        out.keeper_stopped_reason = st.keeper_stopped_reason.clone();
    }
    // A missing cookies file is expired outright: there is
    // nothing to authenticate with, whatever the state file
    // last recorded. The keeper-stop fields above are still
    // carried through: the stop is the likeliest
    // explanation for the missing file, and hiding it would
    // hide the diagnosis.
    if file_missing {
        out.status = AuthStatusValue::Expired;
        out.needs_action = true;
        return out;
    }
    if let Some(st) = st {
        if st.keeper_stopped
            && (st.keeper_stopped_reason == STOPPED_AUTH_ERROR
                || st.keeper_stopped_reason == STOPPED_COOKIES_MISSING)
        {
            out.status = AuthStatusValue::Expired;
            out.needs_action = true;
            return out;
        }
        // State expiry metadata wins when the file has
        // none (e.g. the file was replaced since the last
        // tick): prefer the state's driving record.
        if driving_expiry.is_none()
            && let Some(exp) = st.driving_expiry
        {
            out.driving_cookie = st.driving_cookie.clone();
            out.driving_expiry = Some(exp);
        }
    }
    match out.driving_expiry {
        None => out.status = AuthStatusValue::Ok,
        Some(exp) if !exp.gt(&now) => {
            out.status = AuthStatusValue::Expired;
            out.needs_action = true;
        }
        Some(exp)
            if exp.signed_duration_since(now).num_milliseconds() as u128
                <= expiring_within.as_millis() =>
        {
            out.status = AuthStatusValue::Expiring;
            out.needs_action = true;
        }
        Some(_) => out.status = AuthStatusValue::Ok,
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 5, 12, 0, 0).unwrap()
    }

    #[test]
    fn ok_when_far_future() {
        let st = derive_auth_status(
            "no.0",
            "hatch_sess",
            Some(now() + chrono::Duration::days(30)),
            3,
            false,
            None,
            Duration::from_secs(72 * 3600),
            true,
            "",
            now(),
        );
        assert_eq!(st.status, AuthStatusValue::Ok);
        assert!(!st.needs_action);
    }

    #[test]
    fn expiring_within_window_and_expired_when_past() {
        let within = derive_auth_status(
            "no.0",
            "hatch_sess",
            Some(now() + chrono::Duration::hours(10)),
            3,
            false,
            None,
            Duration::from_secs(72 * 3600),
            true,
            "",
            now(),
        );
        assert_eq!(within.status, AuthStatusValue::Expiring);
        assert!(within.needs_action);
        let past = derive_auth_status(
            "no.0",
            "hatch_sess",
            Some(now() - chrono::Duration::hours(1)),
            3,
            false,
            None,
            Duration::from_secs(72 * 3600),
            true,
            "",
            now(),
        );
        assert_eq!(past.status, AuthStatusValue::Expired);
        assert!(past.needs_action);
    }

    #[test]
    fn missing_file_is_expired_and_stopped_auth_error_is_expired() {
        let missing = derive_auth_status(
            "no.0",
            "",
            None,
            0,
            true,
            None,
            Duration::from_secs(72 * 3600),
            false,
            "no_keeper_entry",
            now(),
        );
        assert_eq!(missing.status, AuthStatusValue::Expired);
        assert!(missing.needs_action);
        let mut st = SessionState::new();
        st.keeper_stopped = true;
        st.keeper_stopped_reason = STOPPED_AUTH_ERROR.to_string();
        let stopped = derive_auth_status(
            "no.0",
            "hatch_sess",
            Some(now() + chrono::Duration::days(30)),
            3,
            false,
            Some(&st),
            Duration::from_secs(72 * 3600),
            false,
            "no_chromedp",
            now(),
        );
        assert_eq!(stopped.status, AuthStatusValue::Expired);
        assert!(stopped.needs_action);
    }

    #[test]
    fn state_driving_record_wins_when_file_has_none() {
        let mut st = SessionState::new();
        st.driving_cookie = "hatch_sess".to_string();
        st.driving_expiry = Some(now() + chrono::Duration::hours(5));
        let out = derive_auth_status(
            "no.0",
            "",
            None,
            0,
            false,
            Some(&st),
            Duration::from_secs(72 * 3600),
            true,
            "",
            now(),
        );
        assert_eq!(out.status, AuthStatusValue::Expiring);
        assert_eq!(out.driving_cookie, "hatch_sess");
    }

    #[test]
    fn metadata_missing_file_and_jar() {
        let (name, exp, count, missing) =
            cookie_expiry_metadata("/nonexistent/path/cookies.txt", now()).unwrap();
        assert!(missing);
        assert_eq!(name, "");
        assert_eq!(exp, None);
        assert_eq!(count, 0);
    }
}
