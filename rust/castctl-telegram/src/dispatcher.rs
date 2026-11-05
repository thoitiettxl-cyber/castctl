// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Per-chat dispatcher: serialisation, dedupe, boundedness.
//!
//! Go source: `internal/telegram/dispatcher.go` (whole file).
//!
//! The library with `WithNotAsyncHandlers` + `WithWorkers(1)`
//! delivers updates serially into enqueue; this dispatcher
//! re-fans them out to one FIFO worker per chat, so a slow
//! handler for chat A never blocks chat B, and updates for
//! one chat are never handled concurrently (Python runs a
//! per-chat queue worker,
//! `src/muse_cli/tgbot.py:1073-1129`).
//!
//! Dedupe is checked and marked at enqueue, before handling
//! — the offset-before-handle order of
//! `src/muse_cli/tgbot.py:2454-2457` — so a redelivery seen
//! while its original is still queued is dropped instead of
//! handled twice. [DEVIATION] Python has no dedupe
//! (absence inspected, `tgbot.py:2435-2462`); the seen set
//! is writer-added, in-memory only, and lost on restart.
//!
//! Boundedness: the dedupe window holds the last 1024
//! update_ids (FIFO eviction; a redelivery of an evicted id
//! is handled again — window semantics, documented, not a
//! leak). Per-chat queues are bounded (64); a full queue
//! drops the arriving update and counts it, never blocking
//! the enqueuer. Queues idle for 5m are reaped (the worker
//! removes its own queue from the map and exits; a later
//! update for the chat creates a fresh queue). Shutdown
//! closes every queue; workers drain their buffered items
//! before returning, bounded by 10s: after the deadline the
//! drain is abandoned, remaining queued items are counted
//! as dropped, and shutdown returns.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::types::Update;

/// Dedupe window: the number of update_ids remembered.
/// Source: `internal/telegram/dispatcher.go:48-51`
/// (`dedupeWindow = 1024`).
pub const DISPATCHER_DEDUPE_WINDOW: usize = 1024;

/// Per-chat FIFO buffer depth.
/// Source: `internal/telegram/dispatcher.go:53-70`
/// (`queueDepth = 64`).
pub const DISPATCHER_QUEUE_DEPTH: usize = 64;

/// Idle reap timeout for a per-chat queue.
/// Source: `internal/telegram/dispatcher.go:53-70`
/// (`defaultIdleTimeout = 5m`).
pub const DISPATCHER_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Shutdown drain bound.
/// Source: `internal/telegram/dispatcher.go:53-70`
/// (`defaultShutdownTimeout = 10s`).
pub const DISPATCHER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// What `enqueue` did with an update.
/// No direct Go counterpart: Go's `enqueue` has no return
/// value; this enum makes the outcome observable for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// Queued for handling.
    Queued,
    /// Duplicate update id (already seen in the window).
    Duplicate,
    /// Dropped: per-chat queue full (newest update dropped).
    Dropped,
    /// Dropped: dispatcher is shutting down.
    Shutdown,
}

/// Processes one update. The `Arc<Self>` receiver lets the
/// worker task own the processor (the returned future is
/// `'static`, so a worker can `tokio::spawn` it and isolate
/// a panic per item — mirroring Go's per-item recover,
/// `internal/telegram/dispatcher.go:255-262`).
/// No direct Go type counterpart: Go passes a plain
/// `process func(ctx, *Update)`; this trait is the
/// Rust-side equivalent.
pub trait UpdateProcessor: Send + Sync {
    /// Process one update (fire-and-forget from the
    /// dispatcher's view; a panic in the future is caught
    /// by the worker task, not by this method).
    fn process(self: Arc<Self>, update: Update) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

type OffsetHook = Arc<dyn Fn(i64) + Send + Sync>;
type DroppedHook = Arc<dyn Fn(i64, i64, i64) + Send + Sync>;

struct ChatQueue {
    tx: mpsc::Sender<Update>,
    /// Held so the channel stays open when no processor
    /// (hence no worker) exists yet; the worker takes it
    /// when one spawns. Without this the receiver would
    /// drop at the end of `enqueue`, closing the channel,
    /// and every send would fail closed — the queue could
    /// never fill to its depth.
    rx: Option<mpsc::Receiver<Update>>,
}

struct DispatcherInner {
    queues: HashMap<i64, ChatQueue>,
    pending: HashMap<i64, usize>,
    seen: HashSet<i64>,
    seen_order: VecDeque<i64>,
    max_seen: i64,
    dropped: i64,
    shutdown: bool,
    abandoned: bool,
    workers: Vec<JoinHandle<()>>,
}

/// The dispatcher. `Debug` is hand-written: the hooks are
/// closures with no `Debug`.
pub struct Dispatcher {
    inner: Mutex<DispatcherInner>,
    processor: Mutex<Option<Arc<dyn UpdateProcessor>>>,
    idle_timeout: Duration,
    shutdown_timeout: Duration,
    window: usize,
    on_offset: Mutex<Option<OffsetHook>>,
    on_dropped: Mutex<Option<DroppedHook>>,
}

impl std::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher")
            .field("idle_timeout", &self.idle_timeout)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

impl Dispatcher {
    /// New dispatcher with production defaults.
    /// Source: `internal/telegram/dispatcher.go:93-99`
    /// (`newDispatcher`).
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(
            DISPATCHER_IDLE_TIMEOUT,
            DISPATCHER_SHUTDOWN_TIMEOUT,
            DISPATCHER_DEDUPE_WINDOW,
        )
    }

    /// New dispatcher with explicit timeouts/window (tests
    /// shorten them; production uses the defaults).
    /// Source: `internal/telegram/dispatcher.go:93-99`
    /// (the fields exist so tests can shorten them).
    #[must_use]
    pub fn with_config(idle_timeout: Duration, shutdown_timeout: Duration, window: usize) -> Self {
        Self {
            inner: Mutex::new(DispatcherInner {
                queues: HashMap::new(),
                pending: HashMap::new(),
                seen: HashSet::new(),
                seen_order: VecDeque::new(),
                max_seen: 0,
                dropped: 0,
                shutdown: false,
                abandoned: false,
                workers: Vec::new(),
            }),
            processor: Mutex::new(None),
            idle_timeout,
            shutdown_timeout,
            window,
            on_offset: Mutex::new(None),
            on_dropped: Mutex::new(None),
        }
    }

    /// Set the update processor (called once, right after
    /// the owning `Bot` exists — the dispatcher needs to
    /// call back into the bot). Queues that already exist
    /// (enqueued before any processor was set) get their
    /// workers spawned now, so they are no longer wedged
    /// silently (fix loop 1, tech N10). The `Arc`
    /// receiver is what lets this spawn workers on this
    /// dispatcher; `Bot::new` and the tests all hold one.
    pub fn set_processor(self: &Arc<Self>, processor: Arc<dyn UpdateProcessor>) {
        let pending_queues: Vec<(i64, mpsc::Receiver<Update>)> = {
            let mut inner = self.inner.lock().expect("dispatcher lock");
            *self.processor.lock().expect("dispatcher lock") = Some(Arc::clone(&processor));
            let mut v = Vec::new();
            for (key, queue) in inner.queues.iter_mut() {
                if let Some(rx) = queue.rx.take() {
                    v.push((*key, rx));
                }
            }
            v
        };
        let mut handles = Vec::new();
        for (chat_key, rx) in pending_queues {
            handles.push(Self::spawn_worker_arc(
                Arc::clone(self),
                chat_key,
                rx,
                Arc::clone(&processor),
            ));
        }
        if !handles.is_empty() {
            self.inner
                .lock()
                .expect("dispatcher lock")
                .workers
                .extend(handles);
        }
    }

    /// Set the offset hook: called synchronously in
    /// `enqueue` (under the lock) when a new maximum
    /// `update_id` is marked, before the update is handled.
    /// It must be fast, must not block, and must not call
    /// back into the dispatcher; a slow hook stalls polling
    /// for EVERY chat. The bot sets it to persist the offset
    /// to the state file.
    /// Source: `internal/telegram/dispatcher.go:100-114`.
    pub fn set_on_offset(&self, hook: OffsetHook) {
        *self.on_offset.lock().expect("dispatcher lock") = Some(hook);
    }

    /// Set the dropped hook: called with chat key, delta,
    /// and running total whenever updates are dropped.
    /// Source: `internal/telegram/dispatcher.go:115-122`.
    pub fn set_on_dropped(&self, hook: DroppedHook) {
        *self.on_dropped.lock().expect("dispatcher lock") = Some(hook);
    }

    /// Largest `update_id` seen (marked at enqueue).
    /// Source: `internal/telegram/bot.go:499` (`MaxHandledID`).
    #[must_use]
    pub fn max_seen(&self) -> i64 {
        self.inner.lock().map_or(0, |i| i.max_seen)
    }

    /// Total dropped updates.
    #[must_use]
    pub fn dropped(&self) -> i64 {
        self.inner.lock().map_or(0, |i| i.dropped)
    }

    /// Enqueue an update for its chat. Dedupe is checked
    /// AND marked here, before handling; the offset hook
    /// fires for a new maximum whether or not the queue
    /// accepted the update (a dropped update is still marked
    /// seen, so it is never replayed).
    /// Source: `internal/telegram/dispatcher.go:150-225`.
    /// The `Arc<Self>` receiver lets a new per-chat worker
    /// task hold the dispatcher.
    pub fn enqueue(self: &Arc<Self>, update: Update) -> EnqueueOutcome {
        let chat_key = update.chat_key();
        let update_id = update.update_id;
        let mut inner = self.inner.lock().expect("dispatcher lock");
        if inner.shutdown {
            inner.dropped += 1;
            let total = inner.dropped;
            drop(inner);
            self.call_on_dropped(chat_key, 1, total);
            return EnqueueOutcome::Shutdown;
        }
        if inner.seen.contains(&update_id) {
            return EnqueueOutcome::Duplicate;
        }
        inner.seen.insert(update_id);
        inner.seen_order.push_back(update_id);
        while inner.seen_order.len() > self.window {
            if let Some(old) = inner.seen_order.pop_front() {
                inner.seen.remove(&old);
            }
        }
        let is_new_max = update_id > inner.max_seen;
        if is_new_max {
            inner.max_seen = update_id;
        }
        let hook = self.on_offset.lock().expect("dispatcher lock").clone();
        if is_new_max && let Some(hook) = hook {
            // Called under the dispatcher lock, exactly
            // as Go does (`dispatcher.go:100-114`). A
            // panicking hook must not poison the lock and
            // wedge every later enqueue: it is caught here
            // (Go's `recoverMiddleware` logs and continues;
            // this crate has no logger, so the panic is
            // swallowed — fix loop 1, tech N18).
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(update_id)));
        }
        if !inner.queues.contains_key(&chat_key) {
            let processor = self.processor.lock().expect("dispatcher lock").clone();
            let (tx, rx) = mpsc::channel::<Update>(DISPATCHER_QUEUE_DEPTH);
            let mut queue = ChatQueue { tx, rx: Some(rx) };
            if let Some(processor) = processor {
                let rx = queue.rx.take().expect("fresh queue holds its receiver");
                let handle = Self::spawn_worker_arc(Arc::clone(self), chat_key, rx, processor);
                inner.workers.push(handle);
            }
            inner.queues.insert(chat_key, queue);
            inner.pending.insert(chat_key, 0);
        }
        let Some(queue) = inner.queues.get(&chat_key) else {
            // Queue absent (defensive; the insert above
            // always runs). Count it dropped, fail-closed.
            inner.dropped += 1;
            let total = inner.dropped;
            drop(inner);
            self.call_on_dropped(chat_key, 1, total);
            return EnqueueOutcome::Dropped;
        };
        match queue.tx.try_send(update) {
            Ok(()) => {
                *inner.pending.entry(chat_key).or_insert(0) += 1;
                EnqueueOutcome::Queued
            }
            Err(_) => {
                inner.dropped += 1;
                let total = inner.dropped;
                drop(inner);
                self.call_on_dropped(chat_key, 1, total);
                EnqueueOutcome::Dropped
            }
        }
    }

    fn call_on_dropped(&self, chat_id: i64, delta: i64, total: i64) {
        if let Some(hook) = self.on_dropped.lock().expect("dispatcher lock").clone() {
            hook(chat_id, delta, total);
        }
    }

    /// Spawn a per-chat worker task. `this` must be the
    /// `Arc` that owns the dispatcher.
    fn spawn_worker_arc(
        this: Arc<Self>,
        chat_key: i64,
        mut rx: mpsc::Receiver<Update>,
        processor: Arc<dyn UpdateProcessor>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let item = tokio::time::timeout(this.idle_timeout, rx.recv()).await;
                match item {
                    Ok(Some(update)) => {
                        // Abandoned FIRST, before any work:
                        // after `shutdown()` counted the
                        // buffered items as dropped, workers
                        // discard them without spawning the
                        // processor — exactly as Go does
                        // (`dispatcher.go:225-262`). The old
                        // code checked after `handle.await`,
                        // so counted-as-dropped items were
                        // still handled after shutdown
                        // returned (fix loop 1, tech B2 /
                        // red R2).
                        if this.inner.lock().is_ok_and(|i| i.abandoned) {
                            continue;
                        }
                        {
                            let mut inner = this.inner.lock().expect("dispatcher lock");
                            if let Some(pending) = inner.pending.get_mut(&chat_key) {
                                *pending = pending.saturating_sub(1);
                            }
                        }
                        // One task per item: a panic in the
                        // handler becomes a failed join (the
                        // worker survives and keeps the FIFO
                        // order), mirroring Go's per-item
                        // recover (`dispatcher.go:255-262`).
                        let handle = tokio::spawn(processor.clone().process(update));
                        let _ = handle.await;
                    }
                    Ok(None) => {
                        // Channel closed: shutdown.
                        break;
                    }
                    Err(_) => {
                        // Idle timeout: reap only when
                        // nothing is pending (an enqueue that
                        // landed after the timeout fired is
                        // still safe — it bumped `pending`).
                        let reap = {
                            let mut inner = this.inner.lock().expect("dispatcher lock");
                            let pending = inner.pending.get(&chat_key).copied().unwrap_or(0);
                            if pending == 0 {
                                inner.queues.remove(&chat_key);
                                inner.pending.remove(&chat_key);
                                true
                            } else {
                                false
                            }
                        };
                        if reap {
                            break;
                        }
                    }
                }
            }
        })
    }

    /// Shut down: close every queue, wait for the drain or
    /// the shutdown timeout, then abandon the remainder
    /// (counted as dropped, workers discard without
    /// double-counting). Leftovers are counted on BOTH
    /// exits: on timeout (the Go path,
    /// `dispatcher.go:264-304`) and on a clean join, where
    /// a queue with no worker (no processor was ever set)
    /// would otherwise vanish uncounted (fix loop 1, red
    /// N9). A normal drain leaves `pending` empty, so the
    /// clean-join count adds zero there.
    /// Source: `internal/telegram/dispatcher.go:264-304`
    /// (`shutdown`).
    pub async fn shutdown(self: &Arc<Self>) {
        let workers = {
            let mut inner = self.inner.lock().expect("dispatcher lock");
            inner.shutdown = true;
            inner.queues.clear();
            std::mem::take(&mut inner.workers)
        };
        let joined = tokio::spawn(async move {
            for handle in workers {
                let _ = handle.await;
            }
        });
        if tokio::time::timeout(self.shutdown_timeout, joined)
            .await
            .is_err()
        {
            {
                let mut inner = self.inner.lock().expect("dispatcher lock");
                inner.abandoned = true;
            }
            self.count_leftovers();
        } else {
            self.count_leftovers();
        }
    }

    /// Drain `pending` into `dropped` and report each
    /// chat's leftover count via `on_dropped`. Called by
    /// [`Dispatcher::shutdown`] on either exit.
    fn count_leftovers(&self) {
        let leftovers: Vec<(i64, i64, i64)> = {
            let mut inner = self.inner.lock().expect("dispatcher lock");
            let mut v = Vec::new();
            let pending: Vec<(i64, usize)> = inner.pending.drain().collect();
            for (chat, count) in pending {
                if count > 0 {
                    inner.dropped += count as i64;
                    v.push((chat, count as i64, inner.dropped));
                }
            }
            v
        };
        for (chat, count, total) in leftovers {
            self.call_on_dropped(chat, count, total);
        }
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RecordingProcessor {
        handled: Arc<Mutex<Vec<i64>>>,
    }

    impl UpdateProcessor for RecordingProcessor {
        fn process(self: Arc<Self>, update: Update) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let handled = Arc::clone(&self.handled);
            Box::pin(async move {
                handled.lock().expect("lock").push(update.update_id);
            })
        }
    }

    fn update(id: i64, chat: i64) -> Update {
        serde_json::from_str(&format!(
            r#"{{"update_id": {id}, "message": {{"message_id": 1, "chat": {{"id": {chat}, "type": "private"}}}}}}"#
        ))
        .expect("fixture parses")
    }

    #[tokio::test]
    async fn duplicate_update_handled_once() {
        let d = Arc::new(Dispatcher::with_config(
            Duration::from_secs(60),
            Duration::from_secs(5),
            1024,
        ));
        let handled = Arc::new(Mutex::new(Vec::new()));
        d.set_processor(Arc::new(RecordingProcessor {
            handled: Arc::clone(&handled),
        }));
        assert_eq!(d.enqueue(update(5, 100)), EnqueueOutcome::Queued);
        assert_eq!(d.enqueue(update(5, 100)), EnqueueOutcome::Duplicate);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*handled.lock().expect("lock"), vec![5]);
        assert_eq!(d.max_seen(), 5);
        d.shutdown().await;
    }

    #[tokio::test]
    async fn offset_hook_fires_before_handling() {
        let d = Arc::new(Dispatcher::with_config(
            Duration::from_secs(60),
            Duration::from_secs(5),
            1024,
        ));
        let seen_max = Arc::new(AtomicUsize::new(0));
        let seen_max2 = Arc::clone(&seen_max);
        d.set_on_offset(Arc::new(move |id| {
            seen_max2.store(id as usize, Ordering::SeqCst);
        }));
        let handled = Arc::new(Mutex::new(Vec::new()));
        d.set_processor(Arc::new(RecordingProcessor {
            handled: Arc::clone(&handled),
        }));
        d.enqueue(update(9, 100));
        // The hook fires synchronously in enqueue, before any
        // worker runs.
        assert_eq!(seen_max.load(Ordering::SeqCst), 9);
        d.shutdown().await;
    }

    #[tokio::test]
    async fn full_queue_drops_newest() {
        let d = Arc::new(Dispatcher::with_config(
            Duration::from_secs(60),
            Duration::from_secs(5),
            1024,
        ));
        // No processor set: the first enqueue creates the
        // queue but no worker; the queue then fills and
        // further updates drop. (Without a processor the
        // queue has no worker, so every enqueue after the
        // first fills the buffer.)
        let _ = d.enqueue(update(1, 100));
        for id in 2..=64 {
            assert_eq!(d.enqueue(update(id, 100)), EnqueueOutcome::Queued);
        }
        assert_eq!(d.enqueue(update(65, 100)), EnqueueOutcome::Dropped);
        assert_eq!(d.enqueue(update(66, 100)), EnqueueOutcome::Dropped);
        assert_eq!(d.dropped(), 2);
        d.shutdown().await;
    }

    /// Slow processor: one chat worker is stuck on the
    /// first item when shutdown times out (50ms). The
    /// buffered items must be counted dropped AND must
    /// never reach the processor — the old code checked
    /// `abandoned` after `handle.await` and handled them
    /// after `shutdown()` had returned (fix loop 1,
    /// tech B2 / red R2).
    struct SlowProcessor {
        handled: Arc<Mutex<Vec<i64>>>,
        delay: Duration,
        started: Arc<tokio::sync::Notify>,
    }

    impl UpdateProcessor for SlowProcessor {
        fn process(self: Arc<Self>, update: Update) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let handled = Arc::clone(&self.handled);
            let delay = self.delay;
            let started = Arc::clone(&self.started);
            Box::pin(async move {
                started.notify_waiters();
                tokio::time::sleep(delay).await;
                handled.lock().expect("lock").push(update.update_id);
            })
        }
    }

    #[tokio::test]
    async fn shutdown_abandon_discards_buffered_without_processing() {
        let d = Arc::new(Dispatcher::with_config(
            Duration::from_secs(60),
            Duration::from_millis(50),
            1024,
        ));
        let handled = Arc::new(Mutex::new(Vec::new()));
        let started = Arc::new(tokio::sync::Notify::new());
        let started_wait = Arc::clone(&started);
        d.set_processor(Arc::new(SlowProcessor {
            handled: Arc::clone(&handled),
            delay: Duration::from_millis(200),
            started,
        }));
        for id in 1..=10 {
            assert_eq!(d.enqueue(update(id, 100)), EnqueueOutcome::Queued);
        }
        // Wait until the worker has TAKEN item 1 (pending
        // is 9) before shutting down; otherwise the test
        // races the worker start and item 1 itself may be
        // the discarded one.
        tokio::time::timeout(Duration::from_secs(5), started_wait.notified())
            .await
            .expect("worker starts item 1");
        let start = std::time::Instant::now();
        d.shutdown().await;
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "shutdown must return at the timeout, took {:?}",
            start.elapsed()
        );
        // Let the worker observe `abandoned` and exit.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            *handled.lock().expect("lock"),
            vec![1],
            "only the in-flight item is processed; buffered items are discarded"
        );
        assert_eq!(
            d.dropped(),
            9,
            "the 9 buffered items are counted dropped exactly once"
        );
    }

    /// `set_processor` after enqueues spawns workers for
    /// the pre-existing queues (fix loop 1, tech N10).
    #[tokio::test]
    async fn set_processor_spawns_workers_for_existing_queues() {
        let d = Arc::new(Dispatcher::with_config(
            Duration::from_secs(60),
            Duration::from_secs(5),
            1024,
        ));
        let _ = d.enqueue(update(1, 100));
        let _ = d.enqueue(update(2, 100));
        let handled = Arc::new(Mutex::new(Vec::new()));
        d.set_processor(Arc::new(RecordingProcessor {
            handled: Arc::clone(&handled),
        }));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(*handled.lock().expect("lock"), vec![1, 2]);
        d.shutdown().await;
    }

    /// Shutdown with no workers counts the pending
    /// leftovers instead of losing them silently
    /// (fix loop 1, red N9).
    #[tokio::test]
    async fn shutdown_without_workers_counts_leftovers() {
        let d = Arc::new(Dispatcher::with_config(
            Duration::from_secs(60),
            Duration::from_secs(5),
            1024,
        ));
        for id in 1..=3 {
            assert_eq!(d.enqueue(update(id, 100)), EnqueueOutcome::Queued);
        }
        d.shutdown().await;
        assert_eq!(d.dropped(), 3, "buffered items are counted dropped");
    }
}
