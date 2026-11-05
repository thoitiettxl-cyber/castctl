// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Subscription primitives (M7a): `Gateway::subscribe_raw` and
//! `Gateway::open_stream`, ported from Go
//! `internal/gateway/calls.go` (`SubscribeRaw`, `OpenStream`)
//! with options/callbacks from `internal/conn`
//! (`SubscribeOptions`, `OpenStreamOptions`) and the retry
//! wrapper from `internal/conn/shared.go`
//! (`SharedConn.SubscribeRaw`).
//!
//! Go `SubscribeOptions` carries its callbacks as struct
//! fields (`OnOpen`, `ShouldStop`, `OnRecord`); Rust has no
//! `context.Context` to thread through them, so the callbacks
//! live on the [`SubscribeHandler`] trait instead and the
//! plain options live on [`SubscribeOptions`]. The handler's
//! `on_record` is async: Go's `OnRecord` runs synchronously
//! on the subscribing goroutine, and the wait runner's
//! record handler must do history reads (async) per record
//! — an async callback is the faithful equivalent, it does
//! not block the executor.
//!
//! Deliberate deviation (diagnostic only): Go wraps
//! subscribe/open errors with a phase (`withPhase`,
//! `PhaseSentNoReply` / `PhaseStreaming` / open phases).
//! Rust `TransportError` has no phase field, so phases are
//! not carried; the error itself and its taxonomy are
//! identical, and no CLI output includes a phase.
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use serde_json::Value as JsonValue;

use castctl_transport::routes::Route;

/// Default cap on records returned by one subscription when
/// the caller passes `max_records <= 0` (Go
/// `internal/gateway/calls.go:266-268`).
pub const DEFAULT_SUBSCRIBE_MAX_RECORDS: i64 = 100;

/// Default idle bound for one subscription when the caller
/// passes `idle_timeout <= 0` (Go `calls.go:270-272`).
pub const DEFAULT_SUBSCRIBE_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default overall bound for one subscription when the caller
/// passes `overall_timeout <= 0` (Go `calls.go:274-276`).
pub const DEFAULT_SUBSCRIBE_OVERALL_TIMEOUT: Duration = Duration::from_secs(120);

/// How often the subscription loop polls `ShouldStop` while
/// waiting for the next frame (Go `calls.go:296`:
/// `g.next(ctx, sid, 500*time.Millisecond)`).
pub const SUBSCRIBE_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Options for one subscription (Go `internal/conn`
/// `SubscribeOptions`, minus the callbacks — those live on
/// [`SubscribeHandler`]).
#[derive(Clone, Default)]
pub struct SubscribeOptions {
    /// Path parameters substituted into the route path.
    pub path_params: Vec<(String, String)>,
    /// Request body (JSON-encoded when present).
    pub body: Option<JsonValue>,
    /// Query parameters.
    pub query: Vec<(String, String)>,
    /// Route override (defaults to the route table's entry
    /// for the method).
    pub route: Option<Route>,
    /// Cap on records returned; `<= 0` means 100.
    pub max_records: i64,
    /// Idle bound; `<= 0` means 10s.
    pub idle_timeout: Duration,
    /// Overall bound; `<= 0` means 120s.
    pub overall_timeout: Duration,
}

/// Callbacks for one subscription (Go `internal/conn`
/// `SubscribeOptions` `OnOpen` / `ShouldStop` / `OnRecord`).
///
/// All methods run sequentially on the subscribing task:
/// `should_stop` is polled about every 500ms while no
/// records arrive, `on_record` runs the moment a record
/// arrives. A `true` return from `on_record` halts the
/// subscription right there (the record is kept).
pub trait SubscribeHandler: Send {
    /// Called once the subscription request is on the wire.
    fn on_open(&mut self) {}

    /// Polled about every 500ms; `true` halts the
    /// subscription.
    fn should_stop(&mut self) -> bool {
        false
    }

    /// Called with each record the moment it arrives.
    /// Return `true` to halt the subscription right there.
    fn on_record(
        &mut self,
        record: &[u8],
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
}

/// A handler that only collects records (used by tests and
/// by callers that do not need per-record work). Stops
/// after `stop_after` records when set.
pub struct CollectHandler {
    /// Records collected so far, in arrival order.
    pub records: Vec<Vec<u8>>,
    /// Whether `on_open` fired.
    pub opened: bool,
    /// Stop after this many records (`None` = never stop).
    pub stop_after: Option<usize>,
}

impl CollectHandler {
    /// A collecting handler with no stop limit.
    pub fn new() -> Self {
        CollectHandler {
            records: Vec::new(),
            opened: false,
            stop_after: None,
        }
    }

    /// A collecting handler that halts after `n` records.
    pub fn stop_after(n: usize) -> Self {
        CollectHandler {
            records: Vec::new(),
            opened: false,
            stop_after: Some(n),
        }
    }
}

impl Default for CollectHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SubscribeHandler for CollectHandler {
    fn on_open(&mut self) {
        self.opened = true;
    }

    fn on_record(
        &mut self,
        record: &[u8],
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        self.records.push(record.to_vec());
        let stop = match self.stop_after {
            Some(n) => self.records.len() >= n,
            None => false,
        };
        Box::pin(async move { stop })
    }
}
