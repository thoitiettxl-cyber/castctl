// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Retry/timeout policy ported from `internal/conn`.
//!
//! Go sources: `internal/conn/gateway.go:21-55` (constants) and
//! `internal/conn/shared.go:46-56` (`safeToRepeat`),
//! `:136-147` (`safeFor`), `:148-221` (`retryCall`),
//! `:298-347` (`SubscribeRaw` retry).
//!
//! The shape that matters: for `CallJSON`/`Request` there is NO
//! fixed attempt count — the budget is TIME (`RetryFor = 30s`),
//! and the pause ladder doubles from 250ms to a 4s cap. The
//! brief's "number of retries" must therefore be answered in
//! this form, not as a hard-coded "retry N times". Only
//! `SubscribeRaw` has a fixed count (3 attempts, 250ms fixed
//! pause), and it is NOT ported in M3 (no subscriptions yet).
//!
//! Retryability (Go `retryCall`, `fn()` branch):
//! - `ConnectionDown` → retry for EVERY method (nothing sent).
//! - `ConnectionError` → retry ONLY when safe-to-repeat.
//! - `AuthError` → never retry (checked first, even if wrapped —
//!   here the enum is flat, so this is just "Auth is not
//!   retryable").
//! - Everything else (`Gateway`, `Timeout`, `Validation`, …) →
//!   return immediately.
//! The `gw()` (reconnect) branch of Go `retryCall` retries any
//! non-auth error until the budget runs out; M3's RPC layer has
//! no separate reconnect step (each attempt re-dials), so the
//! single `should_retry` rule below covers both branches: a dial
//! failure surfaces as `ConnectionDown` and is therefore retried
//! like Go's reconnect branch, while a post-send failure surfaces
//! as `ConnectionError` and follows the safe rule.
//!
//! Per-method safe rules (Go `shared.go:233-271`): `CallJSON`/
//! `Request` use the real `safeFor`; `OpenStream` uses
//! `safe=false` (only `ConnectionDown` repeats); `DownloadFile`
//! uses `safe=true`; `Ping`/`CancelStream`/`SubscribeJSON` do not
//! retry at this layer. M3 ports only the `CallJSON`/`Request`
//! rule; the others are recorded here so M4 does not re-derive
//! them wrong.

use std::time::Duration;

use crate::error::TransportError;
use crate::routes::Route;

/// `RetryFor` (Go `internal/conn/gateway.go:30`).
pub const RETRY_FOR: Duration = Duration::from_secs(30);
/// `RetryPauseInitial` (Go `gateway.go:50`).
pub const RETRY_PAUSE_INITIAL: Duration = Duration::from_millis(250);
/// `RetryPauseMax` (Go `gateway.go:51`).
pub const RETRY_PAUSE_MAX: Duration = Duration::from_secs(4);

/// The 9 POST read methods that are safe-to-repeat on a
/// `ConnectionError`, verbatim from Go
/// `internal/conn/gateway.go` `readMethods` (via `shared.go`
/// `safeToRepeat`). Membership is exact: a method merely
/// containing "read" (e.g. `state.update`,
/// `messenger-read.unlock`) is NOT safe, and
/// `egress.approval.decide` is deliberately NOT in this set.
pub const POST_READ_METHODS: &[&str] = &[
    "connection.ping",
    "custom_connectors.list",
    "fs.list",
    "fs.read",
    "fs.reads",
    "fs.stat",
    "fs.stats",
    "memory.get",
    "node.list",
];

/// Safe-to-repeat decision (Go `safeToRepeat`): the route's HTTP
/// verb is GET (case-insensitive), or the method is one of the 9
/// POST reads. An explicit route wins over the table lookup; with
/// no route at all, only the explicit set is consulted (Go
/// `safeFor` falls back to `safeToRepeat(method, nil)`).
pub fn safe_to_repeat(method: &str, route: Option<&Route>) -> bool {
    if let Some(route) = route {
        if route.http.eq_ignore_ascii_case("get") {
            return true;
        }
    }
    POST_READ_METHODS.contains(&method)
}

/// Whether this error may be retried for a request with the given
/// safe flag (Go `retryCall` `fn()` branch).
pub fn should_retry(err: &TransportError, safe: bool) -> bool {
    match err {
        TransportError::ConnectionDown { .. } => true,
        TransportError::ConnectionError { .. } => safe,
        _ => false,
    }
}

/// Retry policy: budget + pause ladder. Fields are public so tests
/// can inject a small budget (production uses `default_policy` —
/// a test that waited the full 30s budget would be a bad test, and
/// the ladder math is identical at any scale).
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Total budget for one logical request (`RetryFor`).
    pub budget: Duration,
    /// First pause (`RetryPauseInitial`).
    pub pause_initial: Duration,
    /// Pause cap (`RetryPauseMax`).
    pub pause_max: Duration,
}

impl RetryPolicy {
    /// Production policy, exactly the Go constants.
    pub fn default_policy() -> Self {
        Self {
            budget: RETRY_FOR,
            pause_initial: RETRY_PAUSE_INITIAL,
            pause_max: RETRY_PAUSE_MAX,
        }
    }

    /// Pause ladder: 250ms → 500ms → 1s → 2s → 4s → 4s … — the
    /// pause after attempt `n` (0-based) is
    /// `min(initial * 2^n, max)`. This is a pure function so the
    /// ladder is unit-testable without sleeping.
    pub fn pause_after(&self, attempt: u32) -> Duration {
        let mut pause = self.pause_initial;
        for _ in 0..attempt {
            pause = std::cmp::min(pause * 2, self.pause_max);
            if pause >= self.pause_max {
                break;
            }
        }
        pause
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}

/// Run `attempt` under the retry policy, sleeping between retries
/// (sleep is cancellable only by the caller's own deadline — M3
/// has no context object; the RPC layer bounds the whole call with
/// its request timeout instead, and `run_with_retry` additionally
/// stops when the elapsed time plus the next pause would exceed
/// the budget, mirroring Go's `now + pause > budget` check).
/// Returns the first success, or the last error when the error is
/// not retryable or the budget is exhausted.
pub async fn run_with_retry<T, F, Fut>(
    policy: RetryPolicy,
    safe: bool,
    mut attempt: F,
) -> Result<T, TransportError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, TransportError>>,
{
    let start = tokio::time::Instant::now();
    let mut attempt_no: u32 = 0;
    loop {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if !should_retry(&err, safe) {
                    return Err(err);
                }
                let pause = policy.pause_after(attempt_no);
                // Go: `if time.Now().Add(pause).After(budget) { return err }`.
                if start.elapsed() + pause > policy.budget {
                    return Err(err);
                }
                attempt_no += 1;
                tokio::time::sleep(pause).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_ladder_doubles_to_cap() {
        let policy = RetryPolicy::default_policy();
        assert_eq!(policy.pause_after(0), Duration::from_millis(250));
        assert_eq!(policy.pause_after(1), Duration::from_millis(500));
        assert_eq!(policy.pause_after(2), Duration::from_secs(1));
        assert_eq!(policy.pause_after(3), Duration::from_secs(2));
        assert_eq!(policy.pause_after(4), Duration::from_secs(4));
        assert_eq!(policy.pause_after(10), Duration::from_secs(4));
    }

    #[test]
    fn safe_set_is_exact() {
        let get = Route {
            method: "chat.history".to_string(),
            http: "GET".to_string(),
            path: "/chat/history".to_string(),
            service: crate::routes::Service::Daemon,
        };
        assert!(safe_to_repeat("chat.history", Some(&get)));
        assert!(safe_to_repeat("fs.read", None));
        assert!(safe_to_repeat("connection.ping", None));
        // Deliberately unsafe: not in the set, and not a GET.
        assert!(!safe_to_repeat("egress.approval.decide", None));
        // "read" in the name is not enough.
        assert!(!safe_to_repeat("state.update", None));
        assert!(!safe_to_repeat("messenger-read.unlock", None));
        let post = Route {
            method: "chat.send".to_string(),
            http: "POST".to_string(),
            path: "/chat/send".to_string(),
            service: crate::routes::Service::Daemon,
        };
        assert!(!safe_to_repeat("chat.send", Some(&post)));
    }

    #[test]
    fn retry_matrix() {
        assert!(should_retry(
            &TransportError::ConnectionDown {
                message: String::new()
            },
            false
        ));
        assert!(should_retry(
            &TransportError::ConnectionError {
                message: String::new()
            },
            true
        ));
        assert!(!should_retry(
            &TransportError::ConnectionError {
                message: String::new()
            },
            false
        ));
        assert!(!should_retry(
            &TransportError::Auth {
                message: String::new()
            },
            true
        ));
        assert!(!should_retry(
            &TransportError::Gateway(crate::error::BodySummary::new(500, None, "")),
            true
        ));
        assert!(!should_retry(
            &TransportError::Timeout {
                message: String::new()
            },
            true
        ));
    }

    #[tokio::test]
    async fn run_with_retry_stops_on_non_retryable() {
        let mut calls = 0;
        let result: Result<(), TransportError> = run_with_retry(
            RetryPolicy {
                budget: Duration::from_secs(5),
                pause_initial: Duration::from_millis(1),
                pause_max: Duration::from_millis(1),
            },
            true,
            || {
                calls += 1;
                async {
                    Err(TransportError::Gateway(crate::error::BodySummary::new(
                        500, None, "",
                    )))
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(calls, 1);
    }

    #[tokio::test]
    async fn run_with_retry_repeats_down_until_budget() {
        let mut calls = 0;
        let result: Result<(), TransportError> = run_with_retry(
            RetryPolicy {
                budget: Duration::from_millis(30),
                pause_initial: Duration::from_millis(5),
                pause_max: Duration::from_millis(5),
            },
            false,
            || {
                calls += 1;
                async {
                    Err(TransportError::ConnectionDown {
                        message: String::new(),
                    })
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert!(calls >= 2, "ConnectionDown must repeat within budget");
    }
}
