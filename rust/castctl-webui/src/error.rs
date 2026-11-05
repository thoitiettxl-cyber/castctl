// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! API error type + fixed error vocabulary.
//!
//! Source: `internal/webui/server.go` (`apiError`, `errValidation`,
//! `errNotFound`, `errConfigChanged`, `errInternal`,
//! `internal/webui/chats.go` (`errUpstream`)) and `store.go`
//! (`safeMessage` = `logging.SafeString`).

use castctl_log_redact::safe_string;

/// One handler error: HTTP status + stable envelope type + fixed
/// or path-only message. Messages never contain secret values or
/// raw bodies; callers pass internal error text through
/// [`safe_message`] first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// HTTP status code.
    pub status: u16,
    /// Stable envelope `type`.
    pub typ: &'static str,
    /// Fixed or path-only message.
    pub msg: String,
}

impl ApiError {
    /// Build one error. `msg` must already be fixed or
    /// SafeString'd by the caller.
    pub fn new(status: u16, typ: &'static str, msg: impl Into<String>) -> Self {
        Self { status, typ, msg: msg.into() }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for ApiError {}

/// 400 `validation_failed`.
pub fn err_validation(msg: impl Into<String>) -> ApiError {
    ApiError::new(400, "validation_failed", msg)
}

/// 404 `not_found`.
pub fn err_not_found(msg: impl Into<String>) -> ApiError {
    ApiError::new(404, "not_found", msg)
}

/// 409 `config_changed` ("the config file changed on disk since
/// it was loaded").
pub fn err_config_changed() -> ApiError {
    ApiError::new(
        409,
        "config_changed",
        "the config file changed on disk since it was loaded",
    )
}

/// 500 `internal_error` / "internal error".
pub fn err_internal() -> ApiError {
    ApiError::new(500, "internal_error", "internal error")
}

/// 501 `unavailable` with a fixed message.
pub fn err_unavailable(msg: impl Into<String>) -> ApiError {
    ApiError::new(501, "unavailable", msg)
}

/// 502 `upstream_error` / "upstream error" (chats only): the
/// failure class only, no error text at all.
pub fn err_upstream() -> ApiError {
    ApiError::new(502, "upstream_error", "upstream error")
}

/// `safeMessage` (`store.go`): `logging.SafeString` — the second
/// redaction boundary. Parse/validation errors name paths and
/// keys only; SafeString strips any secret-keyed shape that
/// slips through.
pub fn safe_message(err: &dyn std::fmt::Display) -> String {
    safe_string(&err.to_string())
}

/// Same, for a plain message string.
pub fn safe_message_str(msg: &str) -> String {
    safe_string(msg)
}
