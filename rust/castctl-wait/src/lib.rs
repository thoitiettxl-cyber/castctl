// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The wait runner (M7a): drives M5b's [`Waiter`] state machine
//! over a `chat.subscribe` NDJSON stream, with history-derived
//! turn boundaries and a fail-closed endgame.
//!
//! Go source: `internal/wait/runner.go` (the `Runner`), `history.go`
//! (boundary derivation and reply collection), `clock.go` (the
//! clock), and the `chat.subscribe` NDJSON stream
//! (`internal/gateway/calls.go` `SubscribeRaw`,
//! `internal/conn/shared.go` `SubscribeRaw`). M5b already ported
//! `waiter.go`, `replies.go`, `events.go`, `outcome.go` and
//! `reason.go` into `castctl-telegram/src/wait.rs`; this crate
//! ports what M5b explicitly left out — the Runner, the history
//! readers, `decode_record`, `question_of`, and the subscribe
//! wiring — and connects them to M5b's state machine.
//!
//! ## `context.Context` → [`Cancel`]
//!
//! Go threads a `context.Context` through every call. Rust has
//! no equivalent, so the Runner takes one shared [`Cancel`]
//! (an atomic flag plus a [`tokio::sync::Notify`]): setting it
//! is the analogue of cancelling the context, and every
//! cancellation checkpoint in Go (`ctx.Err() != nil`) is a
//! `cancel.is_set()` check here. Sleeps select on the notify,
//! so a cancel wakes them at once. The `UserStop` callback and
//! the `Recheck` callback stay plain `Fn() -> bool` closures,
//! as in Go.
//!
//! ## Time
//!
//! Go's `Runner` takes a `Clock` interface and its tests run
//! under `testing/synctest` virtual time. Rust has no
//! `synctest`; the equivalent is tokio paused time
//! (`#[tokio::test(start_paused = true)]` +
//! `tokio::time::advance`), so this crate uses tokio time
//! directly (`tokio::time::Instant`, `tokio::time::sleep`,
//! `tokio::time::timeout`) and has no `Clock` trait — the
//! real clock under paused time IS the fake clock. All
//! deadlines are `tokio::time::Instant`s.
//!
//! ## Errors
//!
//! [`RunError`] is what `Runner::run` returns: `Auth` (an
//! auth failure anywhere, never swallowed), `Cancelled`
//! (the [`Cancel`] fired), or `ApproverFatal` (a fatal
//! approver error from the wait core). A timeout is a
//! [`WaitResult`] with kind `Timeout`, never an error —
//! exactly as in Go. [`RunError::HistoryRead`] is internal
//! only: a history-read transport failure that `try_settle`
//! and `check_state` swallow; it never escapes `run`.
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input.

pub mod approver;
pub mod events;
pub mod history;
pub mod runner;
pub mod subscriber;

pub use approver::AutoApproverAdapter;
pub use events::{decode_record, question_of};
pub use history::{
    HistoryError, HistoryReader, default_history_limits, derive_boundary, history_replies,
    latest_user_seq,
};
pub use runner::{
    Config, ConfigError, DialFn, RunError, Runner, Subscriber, WaitResult, is_auth_error,
};

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

/// Cancellation handle: the Rust analogue of Go's
/// `context.Context` for the wait runner. One shared flag
/// plus a notify; setting it wakes every sleep/select
/// waiting on it. Cloning shares the same flag.
#[derive(Clone, Default)]
pub struct Cancel {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl Cancel {
    /// A fresh, unset cancel handle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the flag and wake all waiters.
    pub fn set(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Whether the flag is set.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Wait until the flag is set. Returns at once when it
    /// is already set.
    pub async fn notified(&self) {
        if self.is_set() {
            return;
        }
        let notify = Arc::clone(&self.notify);
        notify.notified().await;
    }

    /// Whether two handles share the same flag (used by the
    /// `before_final_guard` test to prove the hook received
    /// the `run` cancel).
    #[must_use]
    pub fn is_same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.flag, &other.flag) && Arc::ptr_eq(&self.notify, &other.notify)
    }

    /// A child that fires when `parent` fires or after
    /// `timeout`, whichever comes first (Go
    /// `context.WithTimeout` for the state check's dial
    /// context). The forwarder task is detached and ends
    /// when either condition fires; the child stays usable
    /// after that.
    #[must_use]
    pub fn child_with_timeout(parent: &Self, timeout: std::time::Duration) -> Self {
        let child = Self::new();
        let parent = parent.clone();
        let child2 = child.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = parent.notified() => {}
                () = tokio::time::sleep(timeout) => {}
            }
            child2.set();
        });
        child
    }
}

impl fmt::Debug for Cancel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cancel")
            .field("is_set", &self.is_set())
            .finish()
    }
}
