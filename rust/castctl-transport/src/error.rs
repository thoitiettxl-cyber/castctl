// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Error taxonomy for `castctl-transport`.
//!
//! Go source: `internal/conn/errors.go` (`AuthError`, `GatewayError`,
//! `ConnectionDown`, `ConnectionError`, `TimeoutError`) and
//! `internal/gateway/jsonutil.go` (`ValidationError`); exit codes from
//! `internal/commands/commands.go:268-337` `classifyError` (NOT the
//! `phaseExitCode` table in `internal/commands/profilecmd.go:901-929`,
//! which maps auth to 3 — see `exit_code` docs below).
//!
//! Render rule (Go `internal/gateway/summary.go` `summarizeFields`):
//! a `Gateway` error carries an allowlist summary only — status,
//! body length (when known), a validated content-type, and an
//! enum-gated `error` field. Raw server body bytes, tokens, cookies
//! and keys are NEVER stored in an error. `Display` therefore prints
//! only the summary; `Debug` is hand-written and prints the same
//! summary fields, never any payload.

/// Allowlist summary of a server response, mirroring Go
/// `internal/gateway/summary.go` `bodySummary`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodySummary {
    /// HTTP-like status, or -1 when there is none (non-JSON,
    /// `{"ok":false}`, reset). Mirrors Go `GatewayError.Status`.
    pub status: i32,
    /// Wire body length, when known.
    pub body_length: Option<usize>,
    /// Validated `type/subtype` (at most 64 chars), when present.
    pub content_type: Option<String>,
    /// Enum-gated `error` field (`[A-Za-z0-9_.-]{1,64}`), when present.
    pub error_code: Option<String>,
}

impl BodySummary {
    /// Build a summary from a status, an optional body and a raw
    /// Content-Type header value. The body bytes themselves are only
    /// measured, never kept.
    pub fn new(status: i32, body: Option<&[u8]>, raw_content_type: &str) -> Self {
        Self {
            status,
            body_length: body.map(<[u8]>::len),
            content_type: validate_content_type(raw_content_type),
            error_code: None,
        }
    }

    /// Render exactly like Go's summary text: label, then
    /// `; body_length=N` (only when known), then `; content_type=…`
    /// and `; error=…` when those fields are present.
    pub fn render(&self) -> String {
        let mut out = String::from("gateway error");
        if let Some(len) = self.body_length {
            out.push_str(&format!("; body_length={len}"));
        }
        if let Some(ct) = &self.content_type {
            out.push_str(&format!("; content_type={ct}"));
        }
        if let Some(code) = &self.error_code {
            out.push_str(&format!("; error={code}"));
        }
        out
    }
}

/// Validate a Content-Type the way Go `summarizeContentType` does:
/// keep only a `type/subtype` token pair (parameters stripped), at
/// most 64 chars; anything else is dropped (not passed through).
pub fn validate_content_type(raw: &str) -> Option<String> {
    let first = raw.split(';').next()?.trim();
    if first.is_empty() || first.len() > 64 {
        return None;
    }
    let (major, minor) = first.split_once('/')?;
    if major.is_empty()
        || minor.is_empty()
        || !major.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '!' | '#' | '$' | '&' | '^' | '_' | '-' | '+' | '.')
        })
        || !minor.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '!' | '#' | '$' | '&' | '^' | '_' | '-' | '+' | '.')
        })
    {
        return None;
    }
    Some(first.to_ascii_lowercase())
}

/// Validate an `error` field the way Go's enum gate does: 1–64 chars
/// of `[A-Za-z0-9_.-]`; anything else is dropped.
pub fn validate_error_code(raw: &str) -> Option<String> {
    if raw.is_empty()
        || raw.len() > 64
        || !raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return None;
    }
    Some(raw.to_string())
}

/// Truncate a diagnostic string to at most `max` chars (char-boundary
/// safe). Used so a wrapped transport error can never smuggle an
/// unbounded peer-controlled string into a log line.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

/// Transport error enum. Variants mirror the Go taxonomy; there is
/// deliberately no variant carrying raw body bytes, a token, a cookie
/// or a key.
#[derive(Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Auth failure (cookie/token rejected). Never retried.
    /// Go: `*conn.AuthError` (`internal/conn/errors.go:38-96`).
    Auth { message: String },
    /// Server-side failure: non-2xx, non-JSON, `{"ok":false}`.
    /// Go: `*conn.GatewayError` (`internal/conn/errors.go:111-201`).
    Gateway(BodySummary),
    /// Connection was down BEFORE anything was sent; safe to repeat
    /// for every method. Go: `*conn.ConnectionDown`
    /// (`internal/conn/errors.go:207-240`).
    ConnectionDown { message: String },
    /// Transport failure AFTER sending/opening; the reply may be
    /// lost, so it is only repeated when safe-to-repeat.
    /// Go: `*conn.ConnectionError` (`internal/conn/errors.go:244-297`).
    ConnectionError { message: String },
    /// Deadline exceeded waiting for a response. Never retried.
    /// Go: `*conn.TimeoutError` (`internal/conn/errors.go:302-322`).
    Timeout { message: String },
    /// Caller-side error: unknown method, bad body, bad config.
    /// Go: `*gateway.ValidationError` (`internal/gateway/jsonutil.go`).
    Validation { message: String },
    /// An HTTP redirect was received and refused (never followed).
    /// No Go error counterpart: Go `noFollowRedirect`
    /// (`internal/telegram/bot.go:350-352`) turns this into an
    /// `http.Client` error; M3 gives it its own variant so callers
    /// can distinguish "refused redirect" from other failures.
    /// It maps to exit code 1 (the generic bucket in
    /// `classifyError`), like any unlisted error. Whether a 3xx
    /// from the gateway should stay exit 1 or become exit 3
    /// (gateway error, Go's classification for gateway HTTP
    /// failures) is an M4 CLI decision — M4 must settle it
    /// explicitly and not let the default leak through silently.
    /// The variant deliberately carries NO `Location` value: no
    /// code in this crate reads one, and storing a server-chosen
    /// URL on an error that might be logged would leak redirect
    /// targets for no benefit.
    RedirectRefused,
    /// The requested protocol / TLS mode / config shape is not
    /// supported by this transport (fail-closed). No Go counterpart
    /// as an error type: Go rejects these at config parse
    /// (`internal/profile/errors.go:158-161`, code 2) or at
    /// outbound creation; M3 surfaces them as `Unsupported` and
    /// `exit_code` maps them to 1 here because this crate has no
    /// CLI — the CLI layer must map config rejections to 2 itself
    /// (see PORTING.md §M3).
    Unsupported { message: String },
    /// Caller cancellation (context done). Go: `context.Canceled`,
    /// mapped to exit 130 in `commands.go:320-322` and
    /// `cmd/castctl/main.go` (SIGINT cancels the context).
    Cancelled,
}

impl TransportError {
    /// Short class label, mirroring Go's `LogSummary` class names.
    pub fn class(&self) -> &'static str {
        match self {
            TransportError::Auth { .. } => "auth_failed",
            TransportError::Gateway(_) => "gateway",
            TransportError::ConnectionDown { .. } => "connection_down",
            TransportError::ConnectionError { .. } => "connection_error",
            TransportError::Timeout { .. } => "timeout",
            TransportError::Validation { .. } => "validation",
            TransportError::RedirectRefused => "redirect_refused",
            TransportError::Unsupported { .. } => "unsupported",
            TransportError::Cancelled => "cancelled",
        }
    }

    /// Exit code per Go `internal/commands/commands.go:268-337`
    /// `classifyError`, in that function's check order for the
    /// variants it knows: auth 2, gateway 3, timeout 4, cancel 130,
    /// validation 2, everything else 1. This is NOT the
    /// `phaseExitCode` table (`profilecmd.go:901-929`), where auth
    /// maps to 3 because the phase already reached the network;
    /// that table belongs to the profile-test CLI path (M4+), not
    /// to this crate.
    pub fn exit_code(&self) -> i32 {
        match self {
            TransportError::Auth { .. } => 2,
            TransportError::Gateway(_) => 3,
            TransportError::Timeout { .. } => 4,
            TransportError::Cancelled => 130,
            TransportError::Validation { .. } => 2,
            _ => 1,
        }
    }

    /// Whether `retry::should_retry` may repeat this error at all
    /// before the safe-to-repeat check. Mirrors Go
    /// `internal/conn/shared.go:148-221` `retryCall`: only
    /// `ConnectionDown` and (conditionally) `ConnectionError` are
    /// retryable; `AuthError` in particular is never retried, even
    /// when wrapped.
    pub fn is_retryable_kind(&self) -> bool {
        matches!(
            self,
            TransportError::ConnectionDown { .. } | TransportError::ConnectionError { .. }
        )
    }

    /// Summary rendering for logs: class plus, for gateway errors,
    /// the allowlist summary; for other errors, the message length
    /// only — never the message bytes (a wrapped cause may be
    /// peer-controlled, as Go `ConnectionError.LogSummary` notes).
    pub fn log_summary(&self) -> String {
        match self {
            TransportError::Gateway(summary) => {
                format!(
                    "conn: gateway status={} {}",
                    summary.status,
                    summary.render()
                )
            }
            TransportError::Auth { message } => {
                format!("conn: auth_failed message_length={}", message.len())
            }
            TransportError::ConnectionError { message } => {
                format!("conn: connection error error_length={}", message.len())
            }
            TransportError::ConnectionDown { message } => {
                format!("conn: connection down error_length={}", message.len())
            }
            TransportError::Timeout { message } => {
                format!("conn: timeout error_length={}", message.len())
            }
            TransportError::Validation { message } => {
                format!("conn: validation error_length={}", message.len())
            }
            TransportError::RedirectRefused => "conn: redirect_refused".to_string(),
            TransportError::Unsupported { message } => {
                format!("conn: unsupported error_length={}", message.len())
            }
            TransportError::Cancelled => "conn: cancelled".to_string(),
        }
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Auth { message } => {
                write!(f, "auth_failed: {}", truncate(message, 200))
            }
            TransportError::Gateway(summary) => write!(f, "{}", summary.render()),
            TransportError::ConnectionDown { message } => {
                write!(f, "connection down: {}", truncate(message, 200))
            }
            TransportError::ConnectionError { message } => {
                write!(f, "connection error: {}", truncate(message, 200))
            }
            TransportError::Timeout { message } => {
                write!(f, "timeout: {}", truncate(message, 200))
            }
            TransportError::Validation { message } => {
                write!(f, "validation: {}", truncate(message, 200))
            }
            TransportError::RedirectRefused => {
                write!(f, "redirect refused: redirects are not followed")
            }
            TransportError::Unsupported { message } => {
                write!(f, "unsupported: {}", truncate(message, 200))
            }
            TransportError::Cancelled => write!(f, "cancelled"),
        }
    }
}

// Hand-written Debug: identical fields to Display, never more.
// In particular no variant holds body bytes, tokens or keys, so
// there is nothing to redact — but Debug is still written by hand
// (not derived) so a future field cannot silently leak through a
// derived Debug.
impl std::fmt::Debug for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Auth { .. } => write!(f, "Auth"),
            TransportError::Gateway(summary) => write!(f, "Gateway({summary:?})"),
            TransportError::ConnectionDown { .. } => write!(f, "ConnectionDown"),
            TransportError::ConnectionError { .. } => write!(f, "ConnectionError"),
            TransportError::Timeout { .. } => write!(f, "Timeout"),
            TransportError::Validation { .. } => write!(f, "Validation"),
            TransportError::RedirectRefused => write!(f, "RedirectRefused"),
            TransportError::Unsupported { .. } => write!(f, "Unsupported"),
            TransportError::Cancelled => write!(f, "Cancelled"),
        }
    }
}

impl std::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_classify_error() {
        assert_eq!(
            TransportError::Auth {
                message: "x".to_string()
            }
            .exit_code(),
            2
        );
        assert_eq!(
            TransportError::Gateway(BodySummary::new(-1, None, "")).exit_code(),
            3
        );
        assert_eq!(
            TransportError::Timeout {
                message: "x".to_string()
            }
            .exit_code(),
            4
        );
        assert_eq!(TransportError::Cancelled.exit_code(), 130);
        assert_eq!(
            TransportError::Validation {
                message: "x".to_string()
            }
            .exit_code(),
            2
        );
        assert_eq!(
            TransportError::ConnectionDown {
                message: "x".to_string()
            }
            .exit_code(),
            1
        );
        assert_eq!(
            TransportError::Unsupported {
                message: "x".to_string()
            }
            .exit_code(),
            1
        );
    }

    #[test]
    fn gateway_summary_never_keeps_body_bytes() {
        let body = b"secret-token-body";
        let summary = BodySummary::new(500, Some(body), "application/json; charset=utf-8");
        assert_eq!(summary.body_length, Some(body.len()));
        assert_eq!(summary.content_type.as_deref(), Some("application/json"));
        assert!(!summary.render().contains("secret-token-body"));
        assert!(!format!("{summary:?}").contains("secret-token-body"));
    }

    #[test]
    fn content_type_and_error_code_gates() {
        assert_eq!(
            validate_content_type("text/html"),
            Some("text/html".to_string())
        );
        assert_eq!(
            validate_content_type("application/json; charset=utf-8"),
            Some("application/json".to_string())
        );
        assert_eq!(validate_content_type("not a type"), None);
        assert_eq!(validate_content_type(""), None);
        assert_eq!(
            validate_error_code("bad_request"),
            Some("bad_request".to_string())
        );
        assert_eq!(validate_error_code("has space"), None);
        assert_eq!(validate_error_code(""), None);
        assert_eq!(validate_error_code(&"a".repeat(65)), None);
    }

    #[test]
    fn only_down_and_conn_error_are_retryable_kinds() {
        assert!(
            TransportError::ConnectionDown {
                message: String::new()
            }
            .is_retryable_kind()
        );
        assert!(
            TransportError::ConnectionError {
                message: String::new()
            }
            .is_retryable_kind()
        );
        assert!(
            !TransportError::Auth {
                message: String::new()
            }
            .is_retryable_kind()
        );
        assert!(!TransportError::Gateway(BodySummary::new(500, None, "")).is_retryable_kind());
        assert!(
            !TransportError::Timeout {
                message: String::new()
            }
            .is_retryable_kind()
        );
    }
}
