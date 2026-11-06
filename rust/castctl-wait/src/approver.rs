// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Adapt the sync `AutoApprover` (`castctl-approvals`, Go
//! `internal/approvals`) to the wait core's async
//! [`WaitApprover`] (M5b, Go `approvals.Approver` as the
//! `Waiter` consumes it).
//!
//! The sync approver does network I/O (the `decide` RPC),
//! so it never runs on an async worker: every call goes
//! through `tokio::task::spawn_blocking`, mirroring Go's
//! synchronous call on the Runner goroutine. The fatal
//! error is derived exactly as `AutoApprover::as_approver`
//! derives it: an `Auth` error from any decide (or from
//! `Connect`) is the fatal error, else the first error
//! when nothing was handled.
//!
//! The telegram `ApproveError.summary` is Go's
//! `logging.SummarizeErr` (`internal/commands/wait.go:
//! toWaitResultJSON` renders `auto_approve_errors[].error`
//! with it, and the turn runner logs the same summary):
//! the `LogSummary` of the first body-carrying error in
//! the chain (`conn: gateway status=<n> body_length=<n>`
//! for gateway errors, `conn: auth_failed
//! message_length=<n>` for auth), else `SafeString` of
//! the error text — so a `NoForeverError` contributes its
//! structural display (`no forever option (offers [...])`)
//! verbatim. This is the `castctl-logging` rendering,
//! not `TransportError::log_summary()` (whose Gateway arm
//! keeps M3's `gateway error; body_length=...` shape).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use castctl_approvals::{
    ApprovalResult, Approver, AutoApprover, DescribedApproval, NoForeverError,
};
use castctl_telegram::Approval as TelegramApproval;
use castctl_telegram::BotError;
use castctl_telegram::wait::{ApproveError, ApproveOutcome, ApprovedRecord, WaitApprover};
use castctl_transport::TransportError;

/// A sync auto-approver behind the wait core's async
/// approver trait.
pub struct AutoApproverAdapter {
    approver: Arc<Approver>,
}

impl AutoApproverAdapter {
    /// Build from an `AutoApprover` (its `as_approver`
    /// closure, which derives the fatal error).
    #[must_use]
    pub fn new(auto: &Arc<AutoApprover>) -> Self {
        Self {
            approver: Arc::from(auto.as_approver()),
        }
    }

    /// Build from a ready approver closure (tests and
    /// callers that already hold one).
    #[must_use]
    pub fn from_approver(approver: Box<Approver>) -> Self {
        Self {
            approver: Arc::from(approver),
        }
    }
}

/// Convert a bot-side approval back into a wait-core
/// description — the inverse of M5a's flattening
/// (`From<&DescribedApproval> for Approval`): an empty
/// string maps back to `None`, so a nil id stays nil
/// (nil-id approvals are never claimed as decided) and
/// an absent expiry (`0`) stays absent.
fn to_described(a: &TelegramApproval) -> DescribedApproval {
    let opt = |s: &str| {
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    };
    DescribedApproval {
        approval_id: opt(&a.id),
        title: opt(&a.title),
        question: opt(&a.question),
        kind: opt(&a.kind),
        scope: opt(&a.scope),
        why: opt(&a.why),
        expires_at_ms: if a.expires_at_ms == 0 {
            None
        } else {
            Some(a.expires_at_ms as f64)
        },
        options: a.options.clone(),
    }
}

/// Walk an error chain for the first `TransportError`
/// (the same walk `castctl-approvals::find_auth_error`
/// does for `Auth` only).
fn find_transport(mut err: &(dyn std::error::Error + 'static)) -> Option<TransportError> {
    loop {
        if let Some(t) = err.downcast_ref::<TransportError>() {
            return Some(t.clone());
        }
        err = err.source()?;
    }
}

/// Allowlisted summary for one auto-approve error: Go's
/// `logging.SummarizeErr` (`castctl_logging::summarize_err`).
/// In the CLI flow an auth decide error never reaches
/// this rendering — it is the fatal error and aborts the
/// run before the result JSON is written — but the same
/// summary is logged by the turn runner, so it must still
/// be Go's summary, not a fixed string.
fn error_summary(err: &castctl_approvals::ApproveError) -> String {
    let inner: &(dyn std::error::Error + 'static) = &**err.err;
    castctl_logging::summarize_err(Some(inner))
}

/// `Some(n)` when the error is a no-forever skip with `n`
/// offered options, else `None` (see `error_summary`'s
/// note on the CLI's structural skip rendering).
fn skip_option_count(err: &castctl_approvals::ApproveError) -> Option<usize> {
    let inner: &(dyn std::error::Error + 'static) = &**err.err;
    inner
        .downcast_ref::<NoForeverError>()
        .map(NoForeverError::option_count)
}

impl WaitApprover for AutoApproverAdapter {
    fn approve(
        &self,
        fresh: &[TelegramApproval],
    ) -> Pin<Box<dyn Future<Output = ApproveOutcome> + Send + '_>> {
        let described: Vec<DescribedApproval> = fresh.iter().map(to_described).collect();
        let approver = Arc::clone(&self.approver);
        Box::pin(async move {
            let joined = tokio::task::spawn_blocking(move || approver(&described)).await;
            let res: ApprovalResult = match joined {
                Ok(res) => res,
                Err(_) => {
                    // The blocking task panicked (a bug in
                    // the decider, never a server reply):
                    // a fixed fatal, never the panic
                    // payload text.
                    return ApproveOutcome {
                        handled: Vec::new(),
                        approved: Vec::new(),
                        errors: Vec::new(),
                        fatal: Some(BotError::Validation(
                            "auto-approver task failed".to_string(),
                        )),
                    };
                }
            };
            let mut out = ApproveOutcome {
                handled: res.handled,
                approved: res
                    .approved
                    .iter()
                    .map(|r| ApprovedRecord {
                        approval_id: r.approval_id.clone(),
                        title: r.title.clone(),
                        kind: r.kind.clone(),
                        scope: r.scope.clone(),
                        decision: r.decision.clone(),
                    })
                    .collect(),
                errors: res
                    .errors
                    .iter()
                    .map(|e| ApproveError {
                        approval_id: e.approval_id.clone(),
                        summary: error_summary(e),
                        title: e.title.clone(),
                        kind: e.kind.clone(),
                        scope: e.scope.clone(),
                        decision: e.decision.clone(),
                        // A skip error renders structurally
                        // in the CLI (`no forever option
                        // option_count=n`); the count is
                        // carried here because the summary
                        // text alone does not expose it.
                        option_count: skip_option_count(e),
                    })
                    .collect(),
                fatal: None,
            };
            if let Some(err) = res.err {
                let fatal = match find_transport(err.as_ref()) {
                    Some(t) => BotError::Transport(t),
                    None => BotError::Validation("auto-approve failed".to_string()),
                };
                out.fatal = Some(fatal);
            }
            out
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use castctl_approvals::ApprovedRecord as CoreRecord;

    fn telegram_approval(id: &str, opts: &[&str]) -> TelegramApproval {
        TelegramApproval {
            id: id.to_string(),
            title: format!("title {id}"),
            question: "q?".to_string(),
            kind: "shell".to_string(),
            scope: String::new(),
            why: String::new(),
            expires_at_ms: 0,
            options: if opts.is_empty() {
                None
            } else {
                Some(opts.iter().map(|s| s.to_string()).collect())
            },
        }
    }

    #[tokio::test]
    async fn adapter_decides_forever_and_skips_once_only() {
        let adapter = AutoApproverAdapter::from_approver(Box::new(|items| {
            let mut res = ApprovalResult::default();
            for item in items {
                if item.approval_id.as_deref() == Some("A") {
                    res.handled.push("A".to_string());
                    res.approved.push(CoreRecord {
                        approval_id: "A".to_string(),
                        title: item.title.clone().unwrap_or_default(),
                        kind: item.kind.clone().unwrap_or_default(),
                        scope: String::new(),
                        decision: castctl_approvals::FOREVER.to_string(),
                    });
                } else {
                    res.errors.push(castctl_approvals::ApproveError {
                        approval_id: item.approval_id.clone().unwrap_or_default(),
                        title: String::new(),
                        kind: String::new(),
                        scope: String::new(),
                        decision: String::new(),
                        err: Arc::new(NoForeverError {
                            options: vec!["allow_once".to_string()],
                        }),
                    });
                }
            }
            res
        }));
        let out = adapter
            .approve(&[
                telegram_approval("A", &["allow_always"]),
                telegram_approval("B", &["allow_once"]),
            ])
            .await;
        assert_eq!(out.handled, vec!["A".to_string()]);
        assert_eq!(out.approved.len(), 1);
        assert_eq!(out.approved[0].approval_id, "A");
        assert_eq!(out.approved[0].decision, "allow_always");
        assert_eq!(out.errors.len(), 1);
        assert_eq!(out.errors[0].approval_id, "B");
        assert_eq!(
            out.errors[0].summary,
            "no forever option (offers [allow_once])"
        );
        // M7a: the CLI golden output needs the full
        // record, not just id + summary.
        assert_eq!(out.errors[0].decision, "");
        assert_eq!(out.errors[0].option_count, Some(1));
        assert!(out.fatal.is_none());
    }

    #[tokio::test]
    async fn adapter_auth_error_is_fatal() {
        let adapter = AutoApproverAdapter::from_approver(Box::new(|items| {
            let mut res = ApprovalResult::default();
            res.errors.push(castctl_approvals::ApproveError {
                approval_id: items[0].approval_id.clone().unwrap_or_default(),
                title: String::new(),
                kind: String::new(),
                scope: String::new(),
                decision: String::new(),
                err: Arc::new(TransportError::Auth {
                    message: "expired".to_string(),
                }),
            });
            res.err = Some(Box::new(TransportError::Auth {
                message: "expired".to_string(),
            }));
            res
        }));
        let out = adapter
            .approve(&[telegram_approval("A", &["allow_always"])])
            .await;
        assert!(out.fatal.is_some(), "auth must be fatal");
        assert_eq!(
            out.errors[0].summary, "conn: auth_failed message_length=7",
            "Go SummarizeErr for AuthError: class + message length, no message bytes"
        );
        assert!(matches!(
            out.fatal,
            Some(BotError::Transport(TransportError::Auth { .. }))
        ));
    }

    #[test]
    fn to_described_round_trips_empty_to_none() {
        let d = to_described(&telegram_approval("", &[]));
        assert_eq!(d.approval_id, None);
        assert_eq!(d.expires_at_ms, None);
        assert_eq!(d.options, None);
        let d = to_described(&TelegramApproval {
            id: "A".to_string(),
            title: String::new(),
            question: "q".to_string(),
            kind: String::new(),
            scope: String::new(),
            why: String::new(),
            expires_at_ms: 42,
            options: Some(vec!["allow_once".to_string()]),
        });
        assert_eq!(d.approval_id.as_deref(), Some("A"));
        assert_eq!(d.expires_at_ms, Some(42.0));
    }
}
