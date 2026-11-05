// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Keeper error types.
//!
//! Go distinguishes errors with `errors.As` / `errors.Is`
//! against typed sentinels (`*conn.AuthError`,
//! `ErrCookiesLockTimeout`, `ErrReexportUnavailable`,
//! `ErrReloginUnavailable`, `*ReloginBlocker`,
//! `ErrStateCorrupt`, `ErrStateDir`); this port distinguishes
//! them with enum variants instead, so callers match on the
//! variant, never on message text (`tick.go:36-44`).
//!
//! Cookie VALUES never appear in any variant: `Debug` is
//! hand-written for the value-carrying types so a derived
//! `Debug` can never leak them.

use std::fmt;

use crate::notify::NoticeKind;

/// The stop-and-alert error for a login page that must never
/// be bypassed (Go `ReloginBlocker`, `relogin.go:38-49`).
/// `kind` is a closed [`NoticeKind`]; `detail` is a fixed
/// enum string, never page text, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloginBlocker {
    /// Closed notice kind for the alert.
    pub kind: NoticeKind,
    /// Fixed enum detail (`blocker_signal`, `blocker_selector`,
    /// `blocker_keyword`, `contract_bad_selector`,
    /// `contract_mismatch`, `contract_step_no_selector`,
    /// `contract_bad_version`, `contract_unknown_field`,
    /// `contract_click_field`, `contract_unknown_action`,
    /// `contract_empty`).
    pub detail: String,
}

impl ReloginBlocker {
    /// Build a blocker with a fixed-enum detail.
    pub fn new(kind: NoticeKind, detail: &str) -> Self {
        Self {
            kind,
            detail: detail.to_string(),
        }
    }
}

impl fmt::Display for ReloginBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Go: `re-login blocked: %s` with the kind only
        // (`relogin.go:52-58`).
        write!(f, "re-login blocked: {}", self.kind.as_str())
    }
}

impl std::error::Error for ReloginBlocker {}

/// Errors a re-login driver can return (Go: `*ReloginBlocker`
/// pass-through, `ErrReloginUnavailable`, or any other error
/// — `tick.go:730-768`).
#[derive(Debug)]
pub enum ReloginError {
    /// A blocker: stop immediately, never retry.
    Blocker(ReloginBlocker),
    /// This build has no driver (`ErrReloginUnavailable`).
    Unavailable,
    /// Any other driver failure (launch/nav/attempts
    /// exhausted): the tick stops with `relogin_failed`.
    /// The message is class-only, never a value.
    Other(String),
}

impl fmt::Display for ReloginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReloginError::Blocker(b) => write!(f, "{b}"),
            ReloginError::Unavailable => write!(
                f,
                "headless re-login unavailable in this build (rebuild with -tags with_chromedp)"
            ),
            ReloginError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ReloginError {}

impl From<ReloginBlocker> for ReloginError {
    fn from(b: ReloginBlocker) -> Self {
        ReloginError::Blocker(b)
    }
}

/// Keeper errors. Transport/checker failures are
/// `castctl_transport::TransportError` and are NOT wrapped
/// here: the tick matches `TransportError::Auth` exactly as
/// Go matches `*conn.AuthError` with `errors.As`.
#[derive(Debug)]
pub enum KeeperError {
    /// The cookies-file lock could not be acquired within
    /// the deadline (Go `profile.ErrCookiesLockTimeout`,
    /// `cookielock.go:124-130`). The tick maps this — and
    /// only this — to `OutcomeSkipped`.
    LockTimeout,
    /// The profile state directory could not be created
    /// (Go `ErrStateDir`, `state.go` + `tick.go:347-355`).
    StateDir(String),
    /// The state file is present but unreadable (corrupt JSON
    /// or unknown schema version; Go `ErrStateCorrupt`,
    /// `state.go:256-275`). The message names the file only,
    /// never its bytes.
    StateCorrupt(String),
    /// CDP re-export is unavailable in this build (Go
    /// `ErrReexportUnavailable`, `tick.go:158`).
    ReexportUnavailable,
    /// Headless re-login is unavailable in this build (Go
    /// `ErrReloginUnavailable`, `relogin.go:31`).
    ReloginUnavailable,
    /// Launch fallback is unavailable: no inbound plumbing
    /// (Go `ErrLaunchUnavailable`, `launch_types.go:13-15`).
    LaunchUnavailable,
    /// No observed login-form contract exists for this build
    /// (Go `ErrContractNotEstablished`, `contract.go:33`).
    ContractNotEstablished,
    /// A login is already in progress for this profile (Go
    /// `ErrLoginInProgress`, `login.go:79`).
    LoginInProgress,
    /// A cookies file is neither a jar nor a readable
    /// one-line/JSON form (Go `classifyCookiesFile`,
    /// `tick.go:456-490`).
    CookiesUnparseable(String),
    /// A jar row failed strict parsing. The message carries
    /// the line number only, never the row contents (Go
    /// `jar.go:160-164`).
    JarParse(String),
    /// CDP failure (discovery, dial, JSON-RPC). The inner
    /// error is class-only: it never carries cookie values.
    Cdp(crate::cdp::CdpError),
    /// A re-login blocker (Go `*ReloginBlocker`): stop
    /// immediately, never retry. Kept typed so callers match
    /// on the variant, never on message text.
    Blocked(ReloginBlocker),
    /// Filesystem I/O failure. The path is included; file
    /// contents are never included.
    Io(std::io::Error),
    /// A config/validation failure (message only, no values).
    Config(String),
    /// Any other keeper failure (message is class-only).
    Other(String),
}

impl fmt::Display for KeeperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeeperError::LockTimeout => write!(f, "cookies lock timeout"),
            KeeperError::StateDir(m) => write!(f, "cannot create state directory: {m}"),
            KeeperError::StateCorrupt(m) => write!(f, "session state corrupt: {m}"),
            KeeperError::ReexportUnavailable => write!(
                f,
                "re-export unavailable in this build (rebuild with -tags with_chromedp)"
            ),
            KeeperError::ReloginUnavailable => write!(
                f,
                "headless re-login unavailable in this build (rebuild with -tags with_chromedp)"
            ),
            KeeperError::LaunchUnavailable => write!(
                f,
                "launch fallback unavailable: no profile-inbound plumbing at this base (S2 gate)"
            ),
            KeeperError::ContractNotEstablished => write!(
                f,
                "login-form contract not established: no read-only observation recorded"
            ),
            KeeperError::LoginInProgress => {
                write!(f, "a login is already in progress for this profile")
            }
            KeeperError::CookiesUnparseable(m) => write!(f, "{m}"),
            KeeperError::JarParse(m) => write!(f, "{m}"),
            KeeperError::Blocked(b) => write!(f, "{b}"),
            KeeperError::Cdp(e) => write!(f, "{e}"),
            KeeperError::Io(e) => write!(f, "{e}"),
            KeeperError::Config(m) | KeeperError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for KeeperError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KeeperError::Cdp(e) => Some(e),
            KeeperError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for KeeperError {
    fn from(e: std::io::Error) -> Self {
        KeeperError::Io(e)
    }
}

impl From<castctl_config::ConfigError> for KeeperError {
    fn from(e: castctl_config::ConfigError) -> Self {
        KeeperError::Config(e.to_string())
    }
}
