// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"sync"
	"time"
)

// FakeClock is a controllable Clock for tests (S10 seam): time
// only moves when Advance is called, so bounded waits are
// deterministic and never depend on wall-clock timing.
type FakeClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*fakeTimer
	tickers []*fakeTicker
}

type fakeTimer struct {
	at time.Time
	ch chan time.Time
}

type fakeTicker struct {
	interval time.Duration
	next     time.Time
	ch       chan time.Time
	stopped  bool
}

var _ Clock = (*FakeClock)(nil)

// NewFakeClock builds a fake clock starting at start.
func NewFakeClock(start time.Time) *FakeClock {
	return &FakeClock{now: start}
}

// Now returns the fake current time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// After returns a channel that fires when the clock advances past
// now+d. The channel is buffered, so firing before the waiter
// starts waiting still delivers.
func (c *FakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.timers = append(c.timers, &fakeTimer{at: c.now.Add(d), ch: ch})
	return ch
}

// NewTicker returns a ticker firing every d of fake time.
func (c *FakeClock) NewTicker(d time.Duration) Ticker {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTicker{interval: d, next: c.now.Add(d), ch: make(chan time.Time, 1)}
	c.tickers = append(c.tickers, t)
	return t
}

// Advance moves fake time forward by d, firing every due timer
// and ticker tick.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	var remaining []*fakeTimer
	for _, t := range c.timers {
		if !t.at.After(c.now) {
			select {
			case t.ch <- t.at:
			default:
			}
			continue
		}
		remaining = append(remaining, t)
	}
	c.timers = remaining
	for _, t := range c.tickers {
		if t.stopped {
			continue
		}
		for !t.next.After(c.now) {
			select {
			case t.ch <- t.next:
			default:
			}
			t.next = t.next.Add(t.interval)
		}
	}
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }

func (t *fakeTicker) Stop() { t.stopped = true }
