// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Update error taxonomy.
//!
//! Go sources: `internal/update/update.go:130-160` (`Error`,
//! `httpError`) and the exit-code contract at
//! `update.go:227-236`: 0 success / already-latest no-op /
//! dry-run report; 2 usage and policy refusals; 1 every
//! fetch, verify, or replace failure.
//!
//! Security invariant: `Display` for `UpdateError` NEVER
//! emits server body text, a URL, or transport error text.
//! Messages are built only from constants, parsed versions,
//! and constructed asset names, exactly like Go's `Error`
//! (whose `cause` is preserved for the logging boundary but
//! never rendered by `Display`).

use std::fmt;

/// One update failure, with its fixed exit code.
///
/// Source: Go `Error{code, msg, cause}`
/// (`internal/update/update.go:130-145`). There is no direct
/// Go type counterpart for this enum's shape: Go stores one
/// `(code, msg)` pair per call site, while Rust groups the
/// sites into variants so the exit code is decided by
/// construction, not by each call site remembering it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateError {
    /// Usage or policy refusal (exit code 2). The message is
    /// a fixed constant, possibly with parsed versions or a
    /// constructed asset name interpolated — never server text.
    /// Source: `internal/update/update.go:250-273,618-715`.
    Usage(String),
    /// Fetch, verify, or replace failure (exit code 1).
    /// Source: `internal/update/update.go:227-236` (code 1 =
    /// "every fetch/verify/replace failure").
    Failure(String),
}

impl UpdateError {
    /// The process exit code for this error: 2 for usage/policy,
    /// 1 for fetch/verify/replace. Source: Go `Error.Code()`
    /// (`internal/update/update.go:143-145`).
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            UpdateError::Usage(_) => 2,
            UpdateError::Failure(_) => 1,
        }
    }

    /// Build a usage/policy error from a fixed message.
    /// No direct Go function counterpart; mirrors Go
    /// `newError(2, msg)` (`internal/update/update.go:147`).
    #[must_use]
    pub fn usage(msg: impl Into<String>) -> Self {
        UpdateError::Usage(msg.into())
    }

    /// Build a fetch/verify/replace error from a fixed message.
    /// No direct Go function counterpart; mirrors Go
    /// `newError(1, msg)` (`internal/update/update.go:147`).
    #[must_use]
    pub fn failure(msg: impl Into<String>) -> Self {
        UpdateError::Failure(msg.into())
    }
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateError::Usage(m) | UpdateError::Failure(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for UpdateError {}

/// Summary of an HTTP failure: status, host, path, class, body
/// length — no body bytes, no URL query, no transport error text.
///
/// Source: Go `httpError` (`internal/update/update.go:120-160`).
/// The `LogSummary` rendering is the `Display` rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError {
    /// HTTP method (`GET`).
    pub op: &'static str,
    /// Host of the request URL, no port, no query.
    pub host: String,
    /// Path of the request URL.
    pub path: String,
    /// HTTP status, 0 when no response was received.
    pub status: u16,
    /// Bounded vocabulary from [`classify_transport_error`]
    /// (see `select.rs`).
    pub class: &'static str,
    /// Body bytes counted (capped at 4096 by the reader).
    pub body_len: i64,
}

impl HttpError {
    /// Build the fixed-vocabulary summary.
    /// Source: Go `httpError.summary()`
    /// (`internal/update/update.go:150-160`).
    #[must_use]
    pub fn summary(&self) -> String {
        if self.status > 0 {
            format!(
                "update: {} {}{} failed (status={} class={} body_length={})",
                self.op, self.host, self.path, self.status, self.class, self.body_len
            )
        } else {
            format!(
                "update: {} {}{} failed (class={} body_length={})",
                self.op, self.host, self.path, self.class, self.body_len
            )
        }
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

impl std::error::Error for HttpError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_go_contract() {
        assert_eq!(UpdateError::usage("update: no release found").code(), 2);
        assert_eq!(
            UpdateError::failure("update: download failed").code(),
            1
        );
    }

    #[test]
    fn http_error_summary_never_carries_body() {
        let e = HttpError {
            op: "GET",
            host: "api.github.com".to_string(),
            path: "/repos/thoitiettxl-cyber/castctl/releases/latest".to_string(),
            status: 500,
            class: "server_error",
            body_len: 123,
        };
        assert_eq!(
            e.summary(),
            "update: GET api.github.com/repos/thoitiettxl-cyber/castctl/releases/latest failed (status=500 class=server_error body_length=123)"
        );
        assert!(!e.summary().contains("SECRET"));
    }

    #[test]
    fn http_error_without_status_omits_status() {
        let e = HttpError {
            op: "GET",
            host: "api.github.com".to_string(),
            path: "/x".to_string(),
            status: 0,
            class: "dns",
            body_len: 0,
        };
        assert_eq!(
            e.summary(),
            "update: GET api.github.com/x failed (class=dns body_length=0)"
        );
    }
}
