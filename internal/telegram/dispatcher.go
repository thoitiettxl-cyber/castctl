// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-telegram/bot/models"
)

// The dispatcher owns per-chat serialisation. The library with
// WithNotAsyncHandlers + WithWorkers(1) delivers updates serially
// into enqueue; this dispatcher re-fans them out to one FIFO
// worker per chat, so a slow handler for chat A never blocks
// chat B, and updates for one chat are never handled
// concurrently. (Python runs a per-chat queue worker,
// src/muse_cli/tgbot.py:1073-1129, _run_chat / _queue_chat.)
//
// Dedupe is checked and marked at enqueue, before handling —
// the offset-before-handle order of src/muse_cli/tgbot.py:2454-2457
// — so a redelivery seen while its original is still queued is
// dropped instead of handled twice. [DEVIATION] Python has no
// dedupe (absence inspected, tgbot.py:2435-2462); the seen set
// is writer-added, in-memory only, and lost on restart.
//
// Boundedness: the dedupe window holds the last dedupeWindow
// update_ids (FIFO eviction; a redelivery of an evicted id is
// handled again — window semantics, documented, not a leak).
// Per-chat queues are bounded (queueDepth); a full queue drops
// the arriving update and counts it (dropped), never blocking
// the enqueuer, so one slow chat cannot stall polling for
// other chats. Queues idle for idleTimeout are reaped (the
// worker removes its own queue from the map and exits; a
// later update for the chat creates a fresh queue).
//
// shutdown closes every queue; workers drain their buffered
// items before returning, bounded by shutdownTimeout: after
// the deadline the drain is abandoned, remaining queued items
// are counted as dropped, and shutdown returns. Workers
// discard (and count) queued items once abandonment is set,
// so no item is both counted dropped and handled.

type dispatchItem struct {
	ctx context.Context
	upd *models.Update
}

type chatQueue struct {
	ch chan dispatchItem
}

// dedupeWindow is the number of update_ids the dedupe set
// remembers. Older ids are evicted FIFO.
const dedupeWindow = 1024

// queueDepth is the per-chat FIFO buffer. Arrivals past it
// are dropped and counted (see the boundedness note above).
const queueDepth = 64

// defaultIdleTimeout reaps a per-chat queue after this long
// with no update for the chat.
const defaultIdleTimeout = 5 * time.Minute

// defaultShutdownTimeout bounds the shutdown drain.
const defaultShutdownTimeout = 10 * time.Second

type dispatcher struct {
	process  func(context.Context, *models.Update)
	logPanic func(r any)

	mu        sync.Mutex
	queues    map[int64]*chatQueue
	seen      map[int64]struct{}
	seenOrder []int64
	shutdown_ bool
	wg        sync.WaitGroup
	maxSeen_  atomic.Int64
	dropped_  atomic.Int64
	abandoned atomic.Bool

	// idleTimeout, shutdownTimeout, and window are fields
	// (not constants) so tests can shorten them; production
	// uses the defaults above.
	idleTimeout     time.Duration
	shutdownTimeout time.Duration
	window          int

	// onOffset, when non-nil, is called synchronously in
	// enqueue (under d.mu) when a new maximum update_id is
	// marked, before the update is handled: the
	// offset-before-handle order. It must be fast and must
	// not call back into the dispatcher; a slow hook stalls
	// polling for every chat. The bot sets it to persist the
	// offset to the state file.
	onOffset func(int64)
}

func newDispatcher(process func(context.Context, *models.Update), logPanic func(r any)) *dispatcher {
	return &dispatcher{
		process:         process,
		logPanic:        logPanic,
		queues:          make(map[int64]*chatQueue),
		seen:            make(map[int64]struct{}),
		idleTimeout:     defaultIdleTimeout,
		shutdownTimeout: defaultShutdownTimeout,
	}
}

func (d *dispatcher) idleTimeoutValue() time.Duration {
	if d.idleTimeout > 0 {
		return d.idleTimeout
	}
	return defaultIdleTimeout
}

func (d *dispatcher) shutdownTimeoutValue() time.Duration {
	if d.shutdownTimeout > 0 {
		return d.shutdownTimeout
	}
	return defaultShutdownTimeout
}

func (d *dispatcher) windowValue() int {
	if d.window > 0 {
		return d.window
	}
	return dedupeWindow
}

// markSeen records id in the bounded dedupe window. The
// caller must hold d.mu.
func (d *dispatcher) markSeen(id int64) {
	window := d.windowValue()
	d.seen[id] = struct{}{}
	d.seenOrder = append(d.seenOrder, id)
	for len(d.seen) > window {
		oldest := d.seenOrder[0]
		d.seenOrder = d.seenOrder[1:]
		delete(d.seen, oldest)
	}
	// Compact the order slice when the dead prefix grows:
	// the window is bounded, so the live prefix stays short.
	if len(d.seenOrder) > 2*window {
		kept := make([]int64, 0, len(d.seen))
		for _, id := range d.seenOrder {
			if _, ok := d.seen[id]; ok {
				kept = append(kept, id)
			}
		}
		d.seenOrder = kept
	}
}

func (d *dispatcher) enqueue(ctx context.Context, upd *models.Update) {
	_ = ctx
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.shutdown_ {
		return
	}
	if _, dup := d.seen[upd.ID]; dup {
		return
	}
	d.markSeen(upd.ID)
	// MaxHandledID is updated with a CAS loop: enqueue is
	// serialised by d.mu today (the single library worker),
	// but the store must stay correct if that ever changes.
	prevMax := d.maxSeen_.Load()
	advanced := false
	for {
		cur := d.maxSeen_.Load()
		if upd.ID <= cur || d.maxSeen_.CompareAndSwap(cur, upd.ID) {
			break
		}
	}
	advanced = upd.ID > prevMax
	key := chatKey(upd)
	q, ok := d.queues[key]
	if !ok {
		q = &chatQueue{ch: make(chan dispatchItem, queueDepth)}
		d.queues[key] = q
		d.wg.Add(1)
		go d.run(key, q)
	}
	// Non-blocking enqueue, under d.mu so an idle-reaping
	// worker cannot remove/close this queue mid-send: a
	// sender either finds the queue in the map or creates
	// a fresh one, never sends on a reaped channel. A full
	// queue drops the arriving (newest) update and counts
	// it; the update is already marked seen
	// (offset-before-handle), matching the crash-mid-handle
	// semantics of the Python poll loop.
	select {
	case q.ch <- dispatchItem{ctx: ctx, upd: upd}:
	default:
		d.dropped_.Add(1)
	}
	// Offset-before-handle: a new maximum is reported before
	// the worker handles the update (and whether or not the
	// queue accepted it — a dropped update is still marked
	// seen above). Still under d.mu, so no second enqueue can
	// interleave a smaller max between the mark and the report.
	if advanced && d.onOffset != nil {
		d.onOffset(upd.ID)
	}
}

func (d *dispatcher) run(key int64, q *chatQueue) {
	defer d.wg.Done()
	for {
		select {
		case item, ok := <-q.ch:
			if !ok {
				return
			}
			if d.abandoned.Load() {
				// Already counted as dropped by shutdown()
				// from the buffered length at the deadline;
				// discard without double-counting.
				continue
			}
			d.processOne(item)
		case <-time.After(d.idleTimeoutValue()):
			d.mu.Lock()
			if len(q.ch) == 0 {
				if cur, ok := d.queues[key]; ok && cur == q {
					delete(d.queues, key)
				}
				d.mu.Unlock()
				return
			}
			d.mu.Unlock()
		}
	}
}

func (d *dispatcher) processOne(item dispatchItem) {
	defer func() {
		if r := recover(); r != nil {
			d.logPanic(r)
		}
	}()
	d.process(item.ctx, item.upd)
}

func (d *dispatcher) shutdown() {
	d.mu.Lock()
	if d.shutdown_ {
		d.mu.Unlock()
		return
	}
	d.shutdown_ = true
	var queues []*chatQueue
	for key, q := range d.queues {
		queues = append(queues, q)
		delete(d.queues, key)
	}
	for _, q := range queues {
		close(q.ch)
	}
	d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d.shutdownTimeoutValue()):
		// Bounded drain: abandon the remaining queued
		// work. Count what is still buffered as dropped;
		// workers discard those same items once they
		// observe abandonment, without recounting.
		d.abandoned.Store(true)
		for _, q := range queues {
			d.dropped_.Add(int64(len(q.ch)))
		}
	}
}

func (d *dispatcher) maxSeen() int64 { return d.maxSeen_.Load() }

// droppedCount reports updates dropped by a full queue or by
// an abandoned shutdown drain.
func (d *dispatcher) droppedCount() int64 { return d.dropped_.Load() }
