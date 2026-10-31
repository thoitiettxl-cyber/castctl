// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

// Dispatcher bounds tests: bounded dedupe window, idle-queue
// reaping, non-blocking enqueue under a full queue, and a
// bounded shutdown drain. All against the dispatcher directly
// (no network, no bot).

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-telegram/bot/models"
)

func dispatchMessage(id int64, chatID int64) *models.Update {
	return &models.Update{
		ID:      id,
		Message: &models.Message{ID: 1, Chat: models.Chat{ID: chatID}},
	}
}

func TestDispatcherDedupeBounded(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	handled := 0
	d := newDispatcher(func(_ context.Context, _ *models.Update) {
		mu.Lock()
		handled++
		mu.Unlock()
	}, func(r any) {})
	d.idleTimeout = time.Minute
	// A small window keeps the test fast: 10 ids fit the
	// 64-deep queue with no overflow drop, so every enqueue
	// is handled; only the dedupe window evicts.
	d.window = 8
	ctx := context.Background()
	for i := int64(1); i <= 10; i++ {
		d.enqueue(ctx, dispatchMessage(i, 500))
	}
	waitFor(t, "10 updates handled", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return handled == 10
	})
	d.mu.Lock()
	seenSize := len(d.seen)
	d.mu.Unlock()
	if seenSize > 8 {
		t.Errorf("seen size = %d; want at most the 8-id test window (production window %d)", seenSize, dedupeWindow)
	}
	// Within the window, a redelivery is still dropped.
	before := handled
	d.enqueue(ctx, dispatchMessage(10, 500))
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	if handled != before {
		t.Errorf("handled grew %d -> %d on a within-window redelivery; want dropped", before, handled)
	}
	mu.Unlock()
	// An id evicted from the window may be handled again
	// (documented window semantics, not a correctness bug).
	d.enqueue(ctx, dispatchMessage(1, 500))
	waitFor(t, "evicted id handled again", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return handled == before+1
	})
	d.shutdown()
	d.mu.Lock()
	queues := len(d.queues)
	d.mu.Unlock()
	if queues != 0 {
		t.Errorf("queues after shutdown = %d; want 0 (reaped)", queues)
	}
}

func TestDispatcherIdleQueueReaped(t *testing.T) {
	t.Parallel()
	handled := make(chan int64, 4)
	d := newDispatcher(func(_ context.Context, upd *models.Update) {
		handled <- upd.ID
	}, func(r any) {})
	d.idleTimeout = 50 * time.Millisecond
	ctx := context.Background()
	d.enqueue(ctx, dispatchMessage(1, 500))
	select {
	case id := <-handled:
		if id != 1 {
			t.Fatalf("handled id = %d; want 1", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first update never handled")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		d.mu.Lock()
		n := len(d.queues)
		d.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("queues = %d after idle; want 0 (reaped)", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A later update for the same chat creates a fresh queue
	// and is handled.
	d.enqueue(ctx, dispatchMessage(2, 500))
	select {
	case id := <-handled:
		if id != 2 {
			t.Fatalf("handled id = %d; want 2", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("update after reaping never handled")
	}
	d.shutdown()
}

func TestDispatcherQueueFullDoesNotBlockOtherChat(t *testing.T) {
	t.Parallel()
	gate := make(chan struct{})
	var first int32
	var handled600 atomic.Int64
	d := newDispatcher(func(_ context.Context, upd *models.Update) {
		if upd.Message != nil && upd.Message.Chat.ID == 500 && atomic.CompareAndSwapInt32(&first, 0, 1) {
			<-gate
			return
		}
		if upd.Message != nil && upd.Message.Chat.ID == 600 {
			handled600.Add(1)
		}
	}, func(r any) {})
	d.idleTimeout = time.Minute
	ctx := context.Background()
	d.enqueue(ctx, dispatchMessage(1, 500))
	// Fill the 64-deep queue behind the blocked worker.
	for i := int64(2); i <= 65; i++ {
		d.enqueue(ctx, dispatchMessage(i, 500))
	}
	// The 66th enqueue for the slow chat must drop, not block.
	start := time.Now()
	d.enqueue(ctx, dispatchMessage(66, 500))
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("overflow enqueue took %v; want non-blocking", elapsed)
	}
	// Enqueue for another chat must not be delayed by the
	// full slow-chat queue. (A fresh update_id: dedupe is
	// global by update_id, so reusing id 1 would be dropped
	// as a redelivery of the slow chat's first update.)
	start = time.Now()
	d.enqueue(ctx, dispatchMessage(1000, 600))
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("other-chat enqueue took %v; want non-blocking despite the full queue", elapsed)
	}
	waitFor(t, "other chat handled", func() bool { return handled600.Load() == 1 })
	if got := d.droppedCount(); got < 1 {
		t.Errorf("dropped enqueues = %d; want at least 1 (the overflow update)", got)
	}
	close(gate)
	d.shutdown()
}

func TestDispatcherShutdownDeadline(t *testing.T) {
	t.Parallel()
	gate := make(chan struct{})
	d := newDispatcher(func(_ context.Context, _ *models.Update) {
		<-gate
	}, func(r any) {})
	d.idleTimeout = time.Minute
	d.shutdownTimeout = 150 * time.Millisecond
	ctx := context.Background()
	d.enqueue(ctx, dispatchMessage(1, 500))
	d.enqueue(ctx, dispatchMessage(2, 500))
	// The first item blocks the worker; the second sits queued.
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	d.shutdown()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("shutdown took %v; want within the deadline plus margin", elapsed)
	}
	if got := d.droppedCount(); got < 1 {
		t.Errorf("dropped enqueues = %d after deadline shutdown; want the queued item counted as dropped", got)
	}
	close(gate)
	time.Sleep(100 * time.Millisecond)
}
