// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Error rendering at the log boundary: `SummarizeErr`,
//! `SafeErrForLevel` and `WrapErr`.
//!
//! Port of Go `internal/logging/level.go` (`SummarizeErr`,
//! `SafeErrForLevel`) and `internal/logging/safe.go:1040-1061`
//! (`WrapErr`, `redactedError`).
//!
//! Loop-5 ruling (Boss, 2026-10-30): a server response body
//! must never reach a log emission at ANY level, including
//! trace. `SafeErrForLevel` renders the summary at every
//! level — there is no trace exception. (An earlier loop-4
//! rule allowed the redacted-then-truncated body at trace;
//! that allowance is SUPERSEDED. This is the PORTING §2.4
//! reversal: the Rust code carries no trace branch at all,
//! and `safe_err_for_level` ignores its `level` argument by
//! construction, so the old behaviour cannot come back.)
//!
//! Go finds the summary STRUCTURALLY (`errors.As` for the
//! `logSummary` interface, so a wrapped `GatewayError` still
//! summarises). Rust has no structural interface: the chain
//! walk below looks for `TransportError`, the only
//! body-carrying error type in the Rust tree, and renders it
//! with Go's exact literals. Any other error type falls back
//! to `SafeString(err.to_string())`.

use std::error::Error;
use std::fmt;

use castctl_log_redact::safe_string;
use castctl_transport::{BodySummary, TransportError};

/// Render a `Gateway` summary exactly like Go's
/// `GatewayError.Error()` (`internal/conn/errors.go:169-181`),
/// which is also its `LogSummary()`: `conn: gateway
/// status=<n>` plus ` body_length=<n>` when known, then the
/// validated `content_type` / `error` fields when present,
/// space-separated.
///
/// NOTE: this deliberately does NOT reuse
/// `TransportError::log_summary()`, whose `Gateway` arm
/// renders `conn: gateway status=<n> gateway error;
/// body_length=<n>` (M3's rendering, kept as-is). The log
/// boundary follows Go's literal.
fn gateway_summary(s: &BodySummary) -> String {
    let mut out = format!("conn: gateway status={}", s.status);
    if let Some(n) = s.body_length {
        out.push_str(&format!(" body_length={n}"));
    }
    if let Some(ct) = &s.content_type {
        out.push_str(&format!(" content_type={ct}"));
    }
    if let Some(code) = &s.error_code {
        out.push_str(&format!(" error={code}"));
    }
    out
}

fn transport_summary(te: &TransportError) -> String {
    match te {
        TransportError::Gateway(s) => gateway_summary(s),
        other => other.log_summary(),
    }
}

/// `SummarizeErr` (`level.go:44-53`): the `LogSummary` of
/// the first body-carrying error in the chain, or
/// `SafeString(err.Error())` for errors that carry no body.
/// A nil error renders as `""`.
pub fn summarize_err(err: Option<&(dyn Error + 'static)>) -> String {
    let Some(err) = err else {
        return String::new();
    };
    let mut cur: Option<&(dyn Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(te) = e.downcast_ref::<TransportError>() {
            return transport_summary(te);
        }
        cur = e.source();
    }
    safe_string(err.to_string())
}

/// `SafeErrForLevel` (`level.go:57-64`): under the loop-5
/// ruling every level renders the summary only
/// (`summarize_err`) — there is no trace exception. A nil
/// error renders as `""`. The `level` argument is ignored by
/// construction.
pub fn safe_err_for_level(err: Option<&(dyn Error + 'static)>, _level: crate::Level) -> String {
    summarize_err(err)
}

/// An error wrapped for safe printing (`safe.go:1040-1052`
/// `redactedError`): `Display` returns the
/// `SafeString`-redacted error text; `source()` exposes the
/// original error, so `errors.As`-style walks (here:
/// `summarize_err`'s chain walk) still find it.
pub struct RedactedError {
    inner: Box<dyn Error + Send + Sync>,
}

impl RedactedError {
    pub fn new(inner: Box<dyn Error + Send + Sync>) -> Self {
        RedactedError { inner }
    }

    /// The wrapped error, unredacted.
    pub fn inner(&self) -> &(dyn Error + Send + Sync) {
        self.inner.as_ref()
    }
}

impl fmt::Debug for RedactedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RedactedError")
            .field(&self.to_string())
            .finish()
    }
}

impl fmt::Display for RedactedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&safe_string(self.inner.to_string()))
    }
}

impl Error for RedactedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.inner.as_ref())
    }
}

/// `WrapErr` (`safe.go:1055-1061`): wrap `err` for safe
/// printing, unless it is `None` (Go's nil).
pub fn wrap_err(err: Option<Box<dyn Error + Send + Sync>>) -> Option<RedactedError> {
    err.map(RedactedError::new)
}

/// Convenience form for a concrete error value.
pub fn wrap_error<E: Error + Send + Sync + 'static>(err: E) -> RedactedError {
    RedactedError::new(Box::new(err))
}
