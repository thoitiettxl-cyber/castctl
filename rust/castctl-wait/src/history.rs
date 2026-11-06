// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! History readers (Go `internal/wait/history.go`):
//! boundary derivation, newest-user lookup, and reply
//! collection over growing `chat.history` windows.
//!
//! A `HistoryReader` must fail closed: a transport error
//! is an error, never an empty window. Reads are bounded
//! two ways, exactly as Go bounds them with contexts:
//!
//! * Derivation reads run against the wait deadline
//!   (`read_with_deadline`): a read still in flight when
//!   the deadline passes ends with [`HistoryError::Deadline`]
//!   and derivation aborts — Go's `WithDeadline` context
//!   dying mid-read.
//! * Every other read runs against a floor/cap budget
//!   (`read_with_budget`, computed by the Runner's
//!   `history_budget`): a read still in flight when the
//!   budget passes ends with a transport `Timeout` error —
//!   Go's `historyCtx` timeout expiring while the caller's
//!   context is still alive.
//!
//! Only derivation retries a window (`read_window`: one
//! retry on a transport error, two attempts total). The
//! other two functions call the reader directly and
//! propagate errors at once — the callers retry at their
//! own level (the final read gets two attempts).

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use castctl_telegram::wait::{replies_after, seq_of};
use castctl_transport::TransportError;
use serde_json::Value;
use tokio::time::Instant;

use crate::Cancel;

/// One `chat.history` window read. Events are decoded JSON
/// values; `has_more` reports whether the server has more
/// events beyond this window. The reader must honor
/// `cancel`: when it is set, return promptly and never
/// block past it (Go `history.go` deadline contract).
/// The future returned by [`HistoryReader::read_history`].
pub type HistoryReadFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(Vec<Value>, bool), TransportError>> + Send + 'a>>;

pub trait HistoryReader: Send + Sync {
    /// Read one window of at most `limit` events.
    fn read_history(&self, limit: usize, cancel: &Cancel) -> HistoryReadFuture<'_>;
}

/// One history-read failure, classified for the caller.
/// `Transport` is any reader error (auth included — the
/// caller checks `is_auth_error`); `Cancelled` means the
/// wait's [`Cancel`] fired; `Deadline` means the wait
/// deadline passed during a derivation read.
#[derive(Debug)]
pub enum HistoryError {
    /// The reader failed (or the per-read budget expired,
    /// as a `Timeout` transport error).
    Transport(TransportError),
    /// The wait was cancelled.
    Cancelled,
    /// The wait deadline passed during derivation.
    Deadline,
}

impl HistoryError {
    /// Whether this error is an auth failure (Go
    /// `isAuthError` / `isFatalHistoryErr`).
    #[must_use]
    pub fn is_auth(&self) -> bool {
        matches!(self, Self::Transport(TransportError::Auth { .. }))
    }
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "history read failed: {e}"),
            Self::Cancelled => write!(f, "history read cancelled"),
            Self::Deadline => write!(f, "history read past the wait deadline"),
        }
    }
}

impl std::error::Error for HistoryError {}

/// The default history window growth: 200, then 500, then
/// 1000 events (Go `history.go` `DefaultHistoryLimits`).
/// Returns a fresh copy every call, so no Runner ever
/// aliases the shared defaults.
#[must_use]
pub fn default_history_limits() -> Vec<usize> {
    vec![200, 500, 1000]
}

/// Read one window against the wait deadline (Go
/// `DeriveBoundary`'s `dctx`). A read still in flight
/// when the deadline passes ends as [`HistoryError::Deadline`].
async fn read_with_deadline(
    reader: &dyn HistoryReader,
    limit: usize,
    cancel: &Cancel,
    deadline: Option<Instant>,
) -> Result<(Vec<Value>, bool), HistoryError> {
    let fut = reader.read_history(limit, cancel);
    let res = match deadline {
        Some(d) => {
            let remaining = d.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, fut).await {
                Ok(r) => r,
                Err(_) => {
                    if cancel.is_set() {
                        return Err(HistoryError::Cancelled);
                    }
                    return Err(HistoryError::Deadline);
                }
            }
        }
        None => fut.await,
    };
    match res {
        Ok(v) => Ok(v),
        Err(e) => {
            if cancel.is_set() {
                Err(HistoryError::Cancelled)
            } else {
                Err(HistoryError::Transport(e))
            }
        }
    }
}

/// Read one window against a floor/cap budget (Go
/// `historyCtx`). A read still in flight when the budget
/// passes ends as a transport `Timeout` error — the
/// caller's context is still alive, so this is not a
/// cancellation.
async fn read_with_budget(
    reader: &dyn HistoryReader,
    limit: usize,
    cancel: &Cancel,
    budget: Duration,
) -> Result<(Vec<Value>, bool), HistoryError> {
    match tokio::time::timeout(budget, reader.read_history(limit, cancel)).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => {
            if cancel.is_set() {
                Err(HistoryError::Cancelled)
            } else {
                Err(HistoryError::Transport(e))
            }
        }
        Err(_) => {
            if cancel.is_set() {
                Err(HistoryError::Cancelled)
            } else {
                Err(HistoryError::Transport(TransportError::Timeout {
                    message: "wait: history read timed out".to_string(),
                }))
            }
        }
    }
}

/// Read one window with one retry on a transport error
/// (two attempts total). The retry scope is exactly the
/// non-fatal errors: any error that is not an `Auth` error
/// and not a dead wait (cancelled / past deadline). A
/// fatal error is returned at once without a retry, and so
/// is a success (Go `history.go` `readWindow`).
async fn read_window(
    reader: &dyn HistoryReader,
    limit: usize,
    cancel: &Cancel,
    deadline: Option<Instant>,
) -> Result<(Vec<Value>, bool), HistoryError> {
    match read_with_deadline(reader, limit, cancel, deadline).await {
        Ok(v) => Ok(v),
        Err(e) if e.is_auth() || matches!(e, HistoryError::Cancelled | HistoryError::Deadline) => {
            Err(e)
        }
        Err(_) => read_with_deadline(reader, limit, cancel, deadline).await,
    }
}

/// Derive the boundary for a standalone wait: the last
/// `message.user` seq in history. Returns the boundary,
/// whether it is known, and that it was derived. The
/// derived flag is `true` in every non-error return,
/// including the unknown-boundary one: `(0, false, true)`
/// means "no window read ever succeeded, so the boundary
/// is unknown". On a fatal error (an `Auth` error, a
/// cancelled wait, or the deadline passing) the return is
/// an error, and the caller must not use the triple.
///
/// A boundary of 0 with `known = true` means genuinely
/// empty history (or history with no user event and no
/// more pages), not a failure. When every window read
/// fails, the boundary is unknown: settle and accept stay
/// disabled for the whole wait — no live event clears the
/// flag (loop-2 F1). Each window read is retried once on
/// a transport error (see [`read_window`]).
///
/// Retention (loop-2 F7): proven data is never discarded
/// by a later window. An empty window with `has_more` and
/// larger windows still to try is skipped, not terminal —
/// the larger window is read. An empty window that ends
/// the scan returns the max seq seen in any earlier window
/// instead of 0, so a shifting empty window cannot erase
/// earlier evidence. A non-empty window that closes
/// (`has_more` false) with no user event still returns 0:
/// a complete snapshot with no user event means no
/// boundary.
///
/// (Go `history.go` `DeriveBoundary`.)
pub async fn derive_boundary(
    reader: &dyn HistoryReader,
    limits: &[usize],
    cancel: &Cancel,
    deadline: Option<Instant>,
) -> Result<(i64, bool, bool), HistoryError> {
    let mut seen_max: i64 = 0;
    let mut any_success = false;
    for (i, &limit) in limits.iter().enumerate() {
        let (events, has_more) = match read_window(reader, limit, cancel, deadline).await {
            Ok(v) => v,
            Err(e)
                if e.is_auth() || matches!(e, HistoryError::Cancelled | HistoryError::Deadline) =>
            {
                return Err(e);
            }
            Err(_) => continue,
        };
        any_success = true;
        if events.is_empty() {
            if has_more && i < limits.len() - 1 {
                continue;
            }
            if seen_max > 0 {
                return Ok((seen_max, true, true));
            }
            return Ok((0, true, true));
        }
        let (max_user, has_user, max_seq) = scan_window(&events);
        if max_seq > seen_max {
            seen_max = max_seq;
        }
        if has_user {
            return Ok((max_user, true, true));
        }
        if !has_more {
            return Ok((0, true, true));
        }
        // Grow to the next window.
    }
    if !any_success {
        return Ok((0, false, true));
    }
    // Exhaustion: all windows succeeded, `has_more` still
    // true at the largest limit, no user event. Fall back
    // to the max seq seen in any successful window.
    Ok((seen_max, true, true))
}

/// Return the newest `message.user` seq in history, or
/// `(0, false)` when no user event was found in any
/// window. The windows stop early when `has_more` is
/// false, when a window is empty and no larger window
/// remains, or when the window already reaches the
/// boundary (its oldest seq is at or below `after_seq`).
/// That last stop trusts newest-first window ordering
/// (U-A8). An empty window with `has_more` and larger
/// windows still to try is skipped, not terminal. A read
/// error fails the attempt and propagates to the caller.
/// (Go `history.go` `LatestUserSeq`.)
pub async fn latest_user_seq(
    reader: &dyn HistoryReader,
    limits: &[usize],
    after_seq: i64,
    cancel: &Cancel,
    budget: Duration,
) -> Result<(i64, bool), HistoryError> {
    let mut seen: i64 = 0;
    let mut found = false;
    for (i, &limit) in limits.iter().enumerate() {
        let (events, has_more) = read_with_budget(reader, limit, cancel, budget).await?;
        if events.is_empty() {
            if has_more && i < limits.len() - 1 {
                continue;
            }
            break;
        }
        let (max_user, has_user, _) = scan_window(&events);
        if has_user && (!found || max_user > seen) {
            seen = max_user;
            found = true;
        }
        if !has_more {
            break;
        }
        if oldest_seq(&events) <= after_seq {
            break;
        }
    }
    Ok((seen, found))
}

/// Return this turn's final replies from history: replies
/// accumulated across every window read, deduped by
/// (`seq`, `message_id`), oldest-first (loop-2 F7).
/// Dedupe is first-wins. A reply seen in any window is
/// real and is reported even when a later window's slice
/// does not contain it. Windows grow while `has_more` is
/// true and the window does not yet reach the boundary; an
/// empty window with `has_more` and larger windows still
/// to try is skipped, not terminal, and an empty window
/// never discards replies accumulated from earlier
/// windows. A read error propagates: the caller retries at
/// its own level.
///
/// The second return value reports window exhaustion:
/// `has_more` was still true at the largest limit, so
/// events older than the window — including replies —
/// were never seen.
/// (Go `history.go` `HistoryReplies`.)
pub async fn history_replies(
    reader: &dyn HistoryReader,
    limits: &[usize],
    after_seq: i64,
    cancel: &Cancel,
    budget: Duration,
) -> Result<(Vec<castctl_telegram::wait::Reply>, bool), HistoryError> {
    use castctl_telegram::wait::Reply;
    let mut merged: Vec<Reply> = Vec::new();
    let mut seen: std::collections::HashSet<(i64, String)> = std::collections::HashSet::new();
    let mut exhausted = false;
    for (i, &limit) in limits.iter().enumerate() {
        let (events, has_more) = read_with_budget(reader, limit, cancel, budget).await?;
        if events.is_empty() {
            if has_more && i < limits.len() - 1 {
                continue;
            }
            if has_more {
                exhausted = true;
            }
            break;
        }
        let max_seq = newest_seq(&events);
        let replies = replies_after(&events, after_seq, Some(max_seq));
        for rp in replies {
            let key = (rp.seq, rp.message_id.clone());
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);
            merged.push(rp);
        }
        if !has_more {
            break;
        }
        if oldest_seq(&events) <= after_seq {
            break;
        }
        if i == limits.len() - 1 {
            exhausted = true;
        }
    }
    merged.sort_by_key(|r| r.seq);
    Ok((merged, exhausted))
}

/// The max `message.user` seq, whether any user event
/// exists, and the max seq of any event in the window
/// (Go `history.go` `scanWindow`).
fn scan_window(events: &[Value]) -> (i64, bool, i64) {
    let mut max_user: i64 = 0;
    let mut has_user = false;
    let mut max_seq: i64 = 0;
    let mut first = true;
    for ev in events {
        if !ev.is_object() {
            continue;
        }
        let seq = seq_of(ev);
        if first || seq > max_seq {
            max_seq = seq;
            first = false;
        }
        if ev.get("event_name").and_then(Value::as_str) == Some("message.user") {
            if !has_user || seq > max_user {
                max_user = seq;
            }
            has_user = true;
        }
    }
    (max_user, has_user, max_seq)
}

/// The smallest seq in the window (0 when the window has
/// no mappable event). (Go `history.go` `oldestSeq`.)
fn oldest_seq(events: &[Value]) -> i64 {
    let mut min: i64 = 0;
    let mut first = true;
    for ev in events {
        if !ev.is_object() {
            continue;
        }
        let seq = seq_of(ev);
        if first || seq < min {
            min = seq;
            first = false;
        }
    }
    min
}

/// The largest seq in the window (0 when the window has
/// no mappable event). (Go `history.go` `newestSeq`.)
fn newest_seq(events: &[Value]) -> i64 {
    let mut max: i64 = 0;
    let mut first = true;
    for ev in events {
        if !ev.is_object() {
            continue;
        }
        let seq = seq_of(ev);
        if first || seq > max {
            max = seq;
            first = false;
        }
    }
    max
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A scripted reader: per-limit queues, then the
    /// default response. (Go `history_test.go`
    /// `scriptHistory`.)
    pub struct ScriptHistory {
        pub by_limit: Mutex<HashMap<usize, Vec<HistoryResp>>>,
        pub def: HistoryResp,
        pub calls: Mutex<Vec<usize>>,
    }

    #[derive(Clone)]
    pub struct HistoryResp {
        pub events: Vec<Value>,
        pub has_more: bool,
        pub err: Option<TransportError>,
    }

    pub fn history_ok(events: Vec<Value>) -> HistoryResp {
        HistoryResp {
            events,
            has_more: false,
            err: None,
        }
    }

    impl ScriptHistory {
        pub fn new(def: HistoryResp) -> Self {
            Self {
                by_limit: Mutex::new(HashMap::new()),
                def,
                calls: Mutex::new(Vec::new()),
            }
        }

        pub fn with(self, limit: usize, resps: Vec<HistoryResp>) -> Self {
            self.by_limit.lock().unwrap().insert(limit, resps);
            self
        }

        pub fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl HistoryReader for ScriptHistory {
        fn read_history(&self, limit: usize, _cancel: &Cancel) -> HistoryReadFuture<'_> {
            self.calls.lock().unwrap().push(limit);
            let resp = {
                let mut by_limit = self.by_limit.lock().unwrap();
                if let Some(q) = by_limit.get_mut(&limit) {
                    if !q.is_empty() {
                        q.remove(0)
                    } else {
                        self.def.clone()
                    }
                } else {
                    self.def.clone()
                }
            };
            Box::pin(async move {
                match resp.err {
                    Some(e) => Err(e),
                    None => Ok((resp.events, resp.has_more)),
                }
            })
        }
    }

    pub fn user_ev(seq: i64) -> Value {
        json!({"event_name": "message.user", "seq": seq, "payload": {"display_text": "hi"}})
    }

    pub fn asst_ev(seq: i64, status: &str, text: &str) -> Value {
        json!({"event_name": "message.assistant", "seq": seq, "payload": {"status": status, "display_text": text}})
    }

    fn err_transport() -> TransportError {
        TransportError::ConnectionError {
            message: "transport down".to_string(),
        }
    }

    fn err_auth() -> TransportError {
        TransportError::Auth {
            message: "expired".to_string(),
        }
    }

    #[test]
    fn default_history_limits_accessor_returns_copy() {
        let got = default_history_limits();
        let mut got = got;
        got[0] = 999;
        assert_eq!(default_history_limits(), vec![200, 500, 1000]);
    }

    /// Go `history_test.go` `TestDeriveBoundary`.
    #[tokio::test]
    async fn derive_boundary_cases() {
        let limits = vec![200usize, 500, 1000];
        let cancel = Cancel::new();
        let cases: Vec<(&str, ScriptHistory, i64, bool)> = vec![
            (
                "first window with user",
                ScriptHistory::new(history_ok(vec![])).with(
                    200,
                    vec![HistoryResp {
                        events: vec![user_ev(90), user_ev(100)],
                        has_more: true,
                        err: None,
                    }],
                ),
                100,
                true,
            ),
            (
                "empty window is known zero",
                ScriptHistory::new(history_ok(vec![])).with(
                    200,
                    vec![HistoryResp {
                        events: vec![],
                        has_more: true,
                        err: None,
                    }],
                ),
                0,
                true,
            ),
            (
                "no user and no more pages is known zero",
                ScriptHistory::new(history_ok(vec![])).with(
                    200,
                    vec![HistoryResp {
                        events: vec![asst_ev(50, "completed", "old")],
                        has_more: false,
                        err: None,
                    }],
                ),
                0,
                true,
            ),
            (
                "all windows fail is unknown",
                ScriptHistory::new(HistoryResp {
                    events: vec![],
                    has_more: false,
                    err: Some(err_transport()),
                }),
                0,
                false,
            ),
            (
                "exhaustion falls back to seen max",
                ScriptHistory::new(history_ok(vec![]))
                    .with(
                        200,
                        vec![HistoryResp {
                            events: vec![asst_ev(10, "completed", "a")],
                            has_more: true,
                            err: None,
                        }],
                    )
                    .with(
                        500,
                        vec![HistoryResp {
                            events: vec![asst_ev(20, "completed", "b")],
                            has_more: true,
                            err: None,
                        }],
                    )
                    .with(
                        1000,
                        vec![HistoryResp {
                            events: vec![asst_ev(30, "completed", "c")],
                            has_more: true,
                            err: None,
                        }],
                    ),
                30,
                true,
            ),
            (
                "retry once per window then succeed",
                ScriptHistory::new(history_ok(vec![])).with(
                    200,
                    vec![
                        HistoryResp {
                            events: vec![],
                            has_more: false,
                            err: Some(err_transport()),
                        },
                        HistoryResp {
                            events: vec![user_ev(42)],
                            has_more: false,
                            err: None,
                        },
                    ],
                ),
                42,
                true,
            ),
            (
                "failed window then next window succeeds",
                ScriptHistory::new(history_ok(vec![]))
                    .with(
                        200,
                        vec![
                            HistoryResp {
                                events: vec![],
                                has_more: false,
                                err: Some(err_transport()),
                            },
                            HistoryResp {
                                events: vec![],
                                has_more: false,
                                err: Some(err_transport()),
                            },
                        ],
                    )
                    .with(
                        500,
                        vec![HistoryResp {
                            events: vec![user_ev(77)],
                            has_more: false,
                            err: None,
                        }],
                    ),
                77,
                true,
            ),
            (
                "partial failure keeps seen max",
                ScriptHistory::new(history_ok(vec![]))
                    .with(
                        200,
                        vec![HistoryResp {
                            events: vec![asst_ev(15, "completed", "a")],
                            has_more: true,
                            err: None,
                        }],
                    )
                    .with(
                        500,
                        vec![
                            HistoryResp {
                                events: vec![],
                                has_more: false,
                                err: Some(err_transport()),
                            },
                            HistoryResp {
                                events: vec![],
                                has_more: false,
                                err: Some(err_transport()),
                            },
                        ],
                    )
                    .with(
                        1000,
                        vec![
                            HistoryResp {
                                events: vec![],
                                has_more: false,
                                err: Some(err_transport()),
                            },
                            HistoryResp {
                                events: vec![],
                                has_more: false,
                                err: Some(err_transport()),
                            },
                        ],
                    ),
                15,
                true,
            ),
        ];
        for (name, h, want_seq, want_known) in cases {
            let (seq, known, derived) = derive_boundary(&h, &limits, &cancel, None)
                .await
                .unwrap_or_else(|e| panic!("{name}: err = {e}"));
            assert_eq!(
                (seq, known, derived),
                (want_seq, want_known, true),
                "{name}"
            );
        }
    }

    /// Go `history_test.go`
    /// `TestDeriveBoundaryAuthErrorPropagates`.
    #[tokio::test]
    async fn derive_boundary_auth_error_propagates() {
        let h = ScriptHistory::new(HistoryResp {
            events: vec![],
            has_more: false,
            err: Some(err_auth()),
        });
        let err = derive_boundary(&h, &[200], &Cancel::new(), None)
            .await
            .expect_err("AuthError must propagate");
        assert!(err.is_auth(), "err = {err}, want AuthError");
        assert_eq!(h.call_count(), 1, "no retry on a fatal error");
    }

    /// Go `history_test.go` `TestLatestUserSeq`.
    #[tokio::test]
    async fn latest_user_seq_cases() {
        let cancel = Cancel::new();
        let budget = Duration::from_secs(5);
        let h = ScriptHistory::new(history_ok(vec![]))
            .with(
                200,
                vec![HistoryResp {
                    events: vec![user_ev(90), user_ev(100)],
                    has_more: true,
                    err: None,
                }],
            )
            .with(
                500,
                vec![HistoryResp {
                    events: vec![user_ev(80), asst_ev(95, "completed", "r")],
                    has_more: true,
                    err: None,
                }],
            );
        let (seq, found) = latest_user_seq(&h, &[200, 500], 85, &cancel, budget)
            .await
            .expect("latest user seq");
        assert_eq!((seq, found), (100, true));
        // No user event: not found.
        let h2 = ScriptHistory::new(HistoryResp {
            events: vec![asst_ev(10, "completed", "r")],
            has_more: false,
            err: None,
        });
        let (seq2, found2) = latest_user_seq(&h2, &[200], 0, &cancel, budget)
            .await
            .expect("no user event");
        assert_eq!((seq2, found2), (0, false));
        // A read error propagates.
        let h3 = ScriptHistory::new(HistoryResp {
            events: vec![],
            has_more: false,
            err: Some(err_transport()),
        });
        assert!(
            latest_user_seq(&h3, &[200], 0, &cancel, budget)
                .await
                .is_err(),
            "read error must propagate"
        );
    }

    /// Go `history_test.go` `TestHistoryReplies`.
    #[tokio::test]
    async fn history_replies_cases() {
        let cancel = Cancel::new();
        let budget = Duration::from_secs(5);
        let h = ScriptHistory::new(history_ok(vec![]))
            .with(
                200,
                vec![HistoryResp {
                    events: vec![asst_ev(150, "completed", "too new")],
                    has_more: true,
                    err: None,
                }],
            )
            .with(
                500,
                vec![HistoryResp {
                    events: vec![
                        asst_ev(120, "completed", "reply"),
                        asst_ev(90, "completed", "old"),
                    ],
                    has_more: false,
                    err: None,
                }],
            );
        let (replies, exhausted) = history_replies(&h, &[200, 500], 100, &cancel, budget)
            .await
            .expect("history replies");
        assert!(!exhausted, "exhausted must be false when the windows close");
        assert_eq!(replies.len(), 2, "replies = {replies:?}");
        assert_eq!((replies[0].seq, replies[0].text.as_str()), (120, "reply"));
        assert_eq!((replies[1].seq, replies[1].text.as_str()), (150, "too new"));
        // Empty window: no replies, no upper bound beyond afterSeq.
        let h2 = ScriptHistory::new(history_ok(vec![]));
        let (replies, exhausted, _) = history_replies(&h2, &[200], 100, &cancel, budget)
            .await
            .map(|(r, e)| (r, e, ()))
            .expect("empty window");
        assert!(replies.is_empty() && !exhausted);
        // Exhaustion: has_more still true at the largest limit.
        let h4 = ScriptHistory::new(history_ok(vec![]))
            .with(
                200,
                vec![HistoryResp {
                    events: vec![user_ev(150)],
                    has_more: true,
                    err: None,
                }],
            )
            .with(
                500,
                vec![HistoryResp {
                    events: vec![user_ev(150)],
                    has_more: true,
                    err: None,
                }],
            );
        let (replies, exhausted) = history_replies(&h4, &[200, 500], 100, &cancel, budget)
            .await
            .expect("exhaustion");
        assert!(replies.is_empty() && exhausted, "want exhausted=true");
        // Error propagates for the caller to retry.
        let h3 = ScriptHistory::new(HistoryResp {
            events: vec![],
            has_more: false,
            err: Some(err_transport()),
        });
        assert!(
            history_replies(&h3, &[200], 100, &cancel, budget)
                .await
                .is_err(),
            "read error must propagate"
        );
    }

    /// Go `history_test.go` `TestReadWindowRetryScope`.
    #[tokio::test]
    async fn read_window_retry_scope() {
        let cancel = Cancel::new();
        // A transport error is retried once (two attempts
        // total), then the second attempt's success wins.
        let h = ScriptHistory::new(history_ok(vec![])).with(
            200,
            vec![
                HistoryResp {
                    events: vec![],
                    has_more: false,
                    err: Some(err_transport()),
                },
                HistoryResp {
                    events: vec![user_ev(42)],
                    has_more: false,
                    err: None,
                },
            ],
        );
        let (events, _) = read_window(&h, 200, &cancel, None)
            .await
            .expect("retried read");
        assert_eq!(events.len(), 1);
        assert_eq!(h.call_count(), 2, "want 2 (one retry)");
        // An AuthError is fatal: no retry, one attempt.
        let h2 = ScriptHistory::new(HistoryResp {
            events: vec![],
            has_more: false,
            err: Some(err_auth()),
        });
        assert!(read_window(&h2, 200, &cancel, None).await.is_err());
        assert_eq!(h2.call_count(), 1, "want 1 (no retry on fatal)");
        // A cancelled wait is fatal too: no retry.
        let cancelled = Cancel::new();
        cancelled.set();
        let h3 = ScriptHistory::new(HistoryResp {
            events: vec![],
            has_more: false,
            err: Some(err_transport()),
        });
        assert!(read_window(&h3, 200, &cancelled, None).await.is_err());
        assert_eq!(h3.call_count(), 1, "want 1 (no retry when cancelled)");
    }

    /// Go `wait_redesign_loop2_test.go` F7/RT9a.
    #[tokio::test]
    async fn history_replies_retains_earlier_window_on_empty_later() {
        let cancel = Cancel::new();
        let budget = Duration::from_secs(5);
        let h = ScriptHistory::new(history_ok(vec![]))
            .with(
                200,
                vec![HistoryResp {
                    events: vec![user_ev(50), asst_ev(55, "completed", "reply")],
                    has_more: true,
                    err: None,
                }],
            )
            .with(
                500,
                vec![HistoryResp {
                    events: vec![],
                    has_more: false,
                    err: None,
                }],
            );
        let (replies, exhausted) = history_replies(&h, &[200, 500], 10, &cancel, budget)
            .await
            .expect("replies");
        assert!(!exhausted);
        assert_eq!(replies.len(), 1, "replies = {replies:?}");
        assert_eq!(replies[0].seq, 55);
    }

    /// Go `wait_redesign_loop2_test.go` F7/RT9b.
    #[tokio::test]
    async fn derive_boundary_retains_seen_max_on_empty_later() {
        let cancel = Cancel::new();
        let h = ScriptHistory::new(history_ok(vec![]))
            .with(
                200,
                vec![HistoryResp {
                    events: vec![asst_ev(30, "completed", "a")],
                    has_more: true,
                    err: None,
                }],
            )
            .with(
                500,
                vec![HistoryResp {
                    events: vec![],
                    has_more: false,
                    err: None,
                }],
            );
        let (seq, known, _) = derive_boundary(&h, &[200, 500], &cancel, None)
            .await
            .expect("derive");
        assert_eq!((seq, known), (30, true));
    }

    /// Go `wait_redesign_loop2_test.go` F7/RT9c.
    #[tokio::test]
    async fn history_replies_accumulates_across_shifting_windows() {
        let cancel = Cancel::new();
        let budget = Duration::from_secs(5);
        let h = ScriptHistory::new(history_ok(vec![]))
            .with(
                200,
                vec![HistoryResp {
                    events: vec![asst_ev(55, "completed", "reply")],
                    has_more: true,
                    err: None,
                }],
            )
            .with(
                500,
                vec![HistoryResp {
                    events: vec![user_ev(50)],
                    has_more: false,
                    err: None,
                }],
            );
        let (replies, _) = history_replies(&h, &[200, 500], 10, &cancel, budget)
            .await
            .expect("replies");
        assert_eq!(replies.len(), 1, "replies = {replies:?}");
        assert_eq!(replies[0].seq, 55);
    }

    /// Go `wait_redesign_loop2_test.go` F7/RT10a.
    #[tokio::test]
    async fn derive_boundary_reads_past_empty_first_window() {
        let cancel = Cancel::new();
        let h = ScriptHistory::new(history_ok(vec![]))
            .with(
                200,
                vec![HistoryResp {
                    events: vec![],
                    has_more: true,
                    err: None,
                }],
            )
            .with(
                500,
                vec![HistoryResp {
                    events: vec![user_ev(77)],
                    has_more: false,
                    err: None,
                }],
            );
        let (seq, known, _) = derive_boundary(&h, &[200, 500], &cancel, None)
            .await
            .expect("derive");
        assert_eq!((seq, known), (77, true));
    }

    /// Go `wait_redesign_loop2_test.go` F7/RT10b.
    #[tokio::test]
    async fn history_replies_reads_past_empty_first_window() {
        let cancel = Cancel::new();
        let budget = Duration::from_secs(5);
        let h = ScriptHistory::new(history_ok(vec![]))
            .with(
                200,
                vec![HistoryResp {
                    events: vec![],
                    has_more: true,
                    err: None,
                }],
            )
            .with(
                500,
                vec![HistoryResp {
                    events: vec![asst_ev(55, "completed", "reply")],
                    has_more: false,
                    err: None,
                }],
            );
        let (replies, _) = history_replies(&h, &[200, 500], 10, &cancel, budget)
            .await
            .expect("replies");
        assert_eq!(replies.len(), 1, "replies = {replies:?}");
        assert_eq!(replies[0].seq, 55);
    }

    /// Go `wait_redesign_loop2_test.go` F7 (LatestUserSeq).
    #[tokio::test]
    async fn latest_user_seq_reads_past_empty_first_window() {
        let cancel = Cancel::new();
        let budget = Duration::from_secs(5);
        let h = ScriptHistory::new(history_ok(vec![]))
            .with(
                200,
                vec![HistoryResp {
                    events: vec![],
                    has_more: true,
                    err: None,
                }],
            )
            .with(
                500,
                vec![HistoryResp {
                    events: vec![user_ev(77)],
                    has_more: false,
                    err: None,
                }],
            );
        let (seq, found) = latest_user_seq(&h, &[200, 500], 10, &cancel, budget)
            .await
            .expect("latest");
        assert_eq!((seq, found), (77, true));
    }
}
