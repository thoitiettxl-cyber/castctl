// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

import (
	"context"
	"sync"
	"sync/atomic"

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
// shutdown closes every queue; workers drain their buffered
// items before returning, so a clean stop finishes in-flight
// turns instead of abandoning them mid-handler.

type dispatchItem struct {
	ctx context.Context
	upd *models.Update
}

type chatQueue struct {
	ch chan dispatchItem
}

type dispatcher struct {
	process  func(context.Context, *models.Update)
	logPanic func(r any)

	mu        sync.Mutex
	queues    map[int64]*chatQueue
	seen      map[int64]struct{}
	shutdown_ bool
	wg        sync.WaitGroup
	maxSeen_  atomic.Int64
}

func newDispatcher(process func(context.Context, *models.Update), logPanic func(r any)) *dispatcher {
	return &dispatcher{
		process:  process,
		logPanic: logPanic,
		queues:   make(map[int64]*chatQueue),
		seen:     make(map[int64]struct{}),
	}
}

func (d *dispatcher) enqueue(ctx context.Context, upd *models.Update) {
	d.mu.Lock()
	if d.shutdown_ {
		d.mu.Unlock()
		return
	}
	if _, dup := d.seen[upd.ID]; dup {
		d.mu.Unlock()
		return
	}
	d.seen[upd.ID] = struct{}{}
	if upd.ID > d.maxSeen_.Load() {
		d.maxSeen_.Store(upd.ID)
	}
	key := chatKey(upd)
	q, ok := d.queues[key]
	if !ok {
		q = &chatQueue{ch: make(chan dispatchItem, 64)}
		d.queues[key] = q
		d.wg.Add(1)
		go d.run(q)
	}
	d.mu.Unlock()
	select {
	case q.ch <- dispatchItem{ctx: ctx, upd: upd}:
	case <-ctx.Done():
		// Shutdown in progress: the update is marked seen
		// (offset-before-handle) but not handled, matching
		// the crash-mid-handle semantics of the Python poll
		// loop.
	}
}

func (d *dispatcher) run(q *chatQueue) {
	defer d.wg.Done()
	for item := range q.ch {
		d.processOne(item)
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
	for _, q := range d.queues {
		close(q.ch)
	}
	d.mu.Unlock()
	d.wg.Wait()
}

func (d *dispatcher) maxSeen() int64 { return d.maxSeen_.Load() }
