// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Telegram notices — port of `internal/keeper/notify.go`.
//!
//! Fixed content, no secrets, no error text, no cookie
//! names, no values, no token URLs. The profile name is
//! configuration, not a secret, and is the only variable
//! content. Every notice ends with the no-automatic-action
//! line so a reader never mistakes a notice for an action
//! taken.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::clock::CancelFlag;
use crate::error::KeeperError;

/// The closed set of keeper notice kinds (`notify.go:16`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeKind {
    /// The cheap chain proved the session dead and the
    /// keeper stopped for this entry.
    LoggedOut,
    /// A CDP re-export recovered the session.
    #[serde(rename = "re-exported")]
    Reexported,
    /// The keeper stopped for a reason other than a
    /// proven-dead session.
    Failed,
    /// Headless re-login stopped: the login page presented a
    /// captcha. Never bypassed.
    Captcha,
    /// Headless re-login stopped: the login page demanded a
    /// second factor or checkpoint.
    TwoFactor,
    /// Headless re-login stopped: the login page presented an
    /// account checkpoint / review.
    Checkpoint,
    /// Headless re-login stopped: the account or login form
    /// is locked.
    Locked,
    /// Headless re-login stopped: the login page did not
    /// match the recorded contract, or the re-login driver
    /// is unavailable in this build.
    Blocked,
    /// Headless re-login exhausted its per-incident attempts
    /// without recovering the session and without a specific
    /// blocker kind.
    ReloginFailed,
}

impl NoticeKind {
    /// The Go string spelling (`notify.go:24-56`).
    pub fn as_str(&self) -> &'static str {
        match self {
            NoticeKind::LoggedOut => "logged_out",
            NoticeKind::Reexported => "re-exported",
            NoticeKind::Failed => "failed",
            NoticeKind::Captcha => "captcha",
            NoticeKind::TwoFactor => "two_factor",
            NoticeKind::Checkpoint => "checkpoint",
            NoticeKind::Locked => "locked",
            NoticeKind::Blocked => "blocked",
            NoticeKind::ReloginFailed => "relogin_failed",
        }
    }

    /// Parse a kind string; `None` when outside the closed
    /// set.
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "logged_out" => NoticeKind::LoggedOut,
            "re-exported" => NoticeKind::Reexported,
            "failed" => NoticeKind::Failed,
            "captcha" => NoticeKind::Captcha,
            "two_factor" => NoticeKind::TwoFactor,
            "checkpoint" => NoticeKind::Checkpoint,
            "locked" => NoticeKind::Locked,
            "blocked" => NoticeKind::Blocked,
            "relogin_failed" => NoticeKind::ReloginFailed,
            _ => return None,
        })
    }
}

impl fmt::Display for NoticeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The closed set, for validation and tests (`notify.go:61-66`).
pub const ALL_NOTICE_KINDS: &[NoticeKind] = &[
    NoticeKind::LoggedOut,
    NoticeKind::Reexported,
    NoticeKind::Failed,
    NoticeKind::Captcha,
    NoticeKind::TwoFactor,
    NoticeKind::Checkpoint,
    NoticeKind::Locked,
    NoticeKind::Blocked,
    NoticeKind::ReloginFailed,
];

/// Whether `kind` is in the closed set (`notify.go:69-76`).
pub fn valid_notice_kind(kind: NoticeKind) -> bool {
    ALL_NOTICE_KINDS.contains(&kind)
}

/// Whether a kind string is in the closed set.
pub fn valid_notice_kind_str(kind: &str) -> bool {
    NoticeKind::from_str(kind).is_some()
}

/// Sends one fixed-content notice. Implementations live in
/// the command layer (Telegram); the core never imports a
/// transport. Notify is best-effort: a failure never fails
/// the tick, it only leaves the warn marker pending
/// (`notify.go:80-83`).
#[async_trait::async_trait]
pub trait Notifier: Send + Sync {
    /// Send one notice for `profile_name`.
    async fn notify(
        &self,
        kind: NoticeKind,
        profile_name: &str,
        cancel: &CancelFlag,
    ) -> Result<(), KeeperError>;
}

/// Strip line/field breaks from a name before it is
/// embedded in a notice or a stdout summary line: a newline
/// in a profile or tag name must never forge a second output
/// line (`notify.go:91-99`).
pub fn sanitize_display(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Render the fixed notice body for a kind and profile
/// (`notify.go:108-123`). An unknown kind degrades to
/// `logged_out` (the default branch).
pub fn notice_text(kind: NoticeKind, profile_name: &str) -> String {
    let profile_name = sanitize_display(profile_name);
    let p = profile_name.as_str();
    match kind {
        NoticeKind::Reexported => format!(
            "castctl keeper: profile {p} session re-exported from the browser and verified. No action was taken automatically."
        ),
        NoticeKind::Failed => format!(
            "castctl keeper: profile {p} keeper stopped (session could not be verified). Re-login with `castctl auth login --profile {p}` or re-import with `castctl auth import --profile {p}`. No action was taken automatically."
        ),
        NoticeKind::Captcha => format!(
            "castctl keeper: profile {p} automatic re-login stopped: the login page presented a captcha. Automation never bypasses captchas. Re-login with `castctl auth login --profile {p}` or re-import with `castctl auth import --profile {p}`. No action was taken automatically."
        ),
        NoticeKind::TwoFactor => format!(
            "castctl keeper: profile {p} automatic re-login stopped: the login page demanded a second factor. Automation never answers second-factor prompts. Re-login with `castctl auth login --profile {p}` or re-import with `castctl auth import --profile {p}`. No action was taken automatically."
        ),
        NoticeKind::Checkpoint => format!(
            "castctl keeper: profile {p} automatic re-login stopped: the login page presented an account checkpoint. Re-login with `castctl auth login --profile {p}` or re-import with `castctl auth import --profile {p}`. No action was taken automatically."
        ),
        NoticeKind::Locked => format!(
            "castctl keeper: profile {p} automatic re-login stopped: the login page is locked. Re-login with `castctl auth login --profile {p}` or re-import with `castctl auth import --profile {p}`. No action was taken automatically."
        ),
        NoticeKind::Blocked => format!(
            "castctl keeper: profile {p} automatic re-login stopped: the login page did not match the expected form, or re-login is unavailable in this build. Re-login with `castctl auth login --profile {p}` or re-import with `castctl auth import --profile {p}`. No action was taken automatically."
        ),
        NoticeKind::ReloginFailed => format!(
            "castctl keeper: profile {p} automatic re-login failed after its attempts and the keeper stopped. Re-login with `castctl auth login --profile {p}` or re-import with `castctl auth import --profile {p}`. No action was taken automatically."
        ),
        NoticeKind::LoggedOut => format!(
            "castctl keeper: profile {p} is logged out (cookies expired or revoked). Re-login with `castctl auth login --profile {p}` or re-import with `castctl auth import --profile {p}`. No action was taken automatically."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notice_text_literals() {
        // Literal expectations from Go `notify.go:108-123`.
        assert_eq!(
            notice_text(NoticeKind::LoggedOut, "no.0"),
            "castctl keeper: profile no.0 is logged out (cookies expired or revoked). Re-login with `castctl auth login --profile no.0` or re-import with `castctl auth import --profile no.0`. No action was taken automatically."
        );
        assert_eq!(
            notice_text(NoticeKind::Reexported, "no.0"),
            "castctl keeper: profile no.0 session re-exported from the browser and verified. No action was taken automatically."
        );
        assert_eq!(
            notice_text(NoticeKind::Captcha, "no.0"),
            "castctl keeper: profile no.0 automatic re-login stopped: the login page presented a captcha. Automation never bypasses captchas. Re-login with `castctl auth login --profile no.0` or re-import with `castctl auth import --profile no.0`. No action was taken automatically."
        );
    }

    #[test]
    fn sanitize_display_replaces_breaks() {
        assert_eq!(sanitize_display("a\nb\rc\td"), "a b c d");
        assert_eq!(sanitize_display("plain"), "plain");
    }

    #[test]
    fn closed_set_round_trips() {
        assert_eq!(ALL_NOTICE_KINDS.len(), 9);
        for k in ALL_NOTICE_KINDS {
            assert_eq!(NoticeKind::from_str(k.as_str()), Some(*k));
            assert!(valid_notice_kind(*k));
        }
        assert_eq!(NoticeKind::from_str("bogus"), None);
        assert!(!valid_notice_kind_str("bogus"));
    }
}
