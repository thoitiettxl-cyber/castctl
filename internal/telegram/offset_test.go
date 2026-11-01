// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0-or-later.

package telegram

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type offsetRecorder struct {
	mu  sync.Mutex
	ids []int64
}

func (r *offsetRecorder) record(id int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, id)
}

func (r *offsetRecorder) recorded() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int64{}, r.ids...)
}

// OnOffset fires once per new maximum update_id, marked at
// enqueue before handling, and never for a redelivery or for an
// id at or below the seeded initial offset.
func TestBotOnOffsetBeforeHandle(t *testing.T) {
	srv := newFakeTelegramServer(t)
	rec := &offsetRecorder{}
	tb := newTestBot(t, srv, func(s *Settings) {
		s.InitialOffset = 50
		s.OnOffset = rec.record
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startBot(t, tb.bot, ctx)

	// Id 40 is below the seeded offset: no new maximum, no hook
	// call, even though the fake server replays it.
	srv.enqueueUpdates(messageUpdate(40, 500, 111, "old"))
	// Id 60 advances the maximum: exactly one hook call.
	srv.enqueueUpdates(messageUpdate(60, 500, 111, "hello"))
	// Redelivery of 60: dropped by the dedupe window, no hook.
	srv.enqueueUpdates(messageUpdate(60, 500, 111, "hello"))
	waitFor(t, "handler to see the new update", func() bool {
		return len(tb.handler.recorded()) >= 1
	})
	// Give the redelivery a chance to (incorrectly) fire the hook.
	time.Sleep(100 * time.Millisecond)
	if err := stopBot(t, cancel, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start returned %v; want context.Canceled", err)
	}
	if got := tb.bot.MaxHandledID(); got != 60 {
		t.Errorf("MaxHandledID = %d; want 60", got)
	}
	if got := rec.recorded(); len(got) != 1 || got[0] != 60 {
		t.Errorf("OnOffset calls = %v; want exactly [60]", got)
	}
}
