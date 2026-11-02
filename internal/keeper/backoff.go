// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"context"
	"math/rand"
	"time"
)

// Transient-error backoff: stdlib only, no failsafe-go.
//
// The ladder is CONFIG, not code: each keeper entry carries its
// `retry_backoff` list (default 5m, 15m, 45m, see
// profile.DefaultRetryBackoff), each step ±20% uniform jitter
// re-drawn per delay, at most len(ladder) retries per tick.
// After the ladder is exhausted the tick ends as a transient
// error and the entry waits until its next scheduled tick: the
// failure schedule never resets the entry schedule, and a
// failure never makes the next tick sooner. Jitter uses a
// package-level rand source injected for tests; production
// uses math/rand's locked global source, which is safe for
// concurrent use.

var backoffLadder = []time.Duration{5 * time.Minute, 15 * time.Minute, 45 * time.Minute}

// BackoffMaxRetries is the retry cap per tick for the DEFAULT
// ladder (len(backoffLadder)). A configured ladder's length
// governs its own cap: NewBackoffWithLadder caps at
// len(ladder), so a longer configured ladder retries longer.
// Kept for the default-ladder callers that pin the constant.
const BackoffMaxRetries = 3

// Backoff tracks one tick's transient retries.
type Backoff struct {
	clock    Clock
	jitter   func() float64
	ladder   []time.Duration
	attempts int
}

// NewBackoff returns a Backoff using clock and jitter (nil jitter
// means math/rand's global Float64) and the default ladder.
func NewBackoff(clock Clock, jitter func() float64) *Backoff {
	return NewBackoffWithLadder(clock, jitter, nil)
}

// NewBackoffWithLadder returns a Backoff using the given ladder.
// A nil or empty ladder means the default ladder. The ladder is
// copied: later mutation of the caller's slice cannot change
// the retries already in flight.
func NewBackoffWithLadder(clock Clock, jitter func() float64, ladder []time.Duration) *Backoff {
	if clock == nil {
		clock = RealClock
	}
	if jitter == nil {
		jitter = rand.Float64
	}
	if len(ladder) == 0 {
		ladder = backoffLadder
	}
	cp := make([]time.Duration, len(ladder))
	copy(cp, ladder)
	return &Backoff{clock: clock, jitter: jitter, ladder: cp}
}

// NextDelay returns the next retry delay, or (0, false) when the
// ladder is exhausted. The ±20% jitter is re-drawn per call:
// delay = base * (1 + (u*2-1)*0.2) with u in [0,1).
func (b *Backoff) NextDelay() (time.Duration, bool) {
	if b.attempts >= len(b.ladder) {
		return 0, false
	}
	base := b.ladder[b.attempts]
	b.attempts++
	j := 1 + (b.jitter()*2-1)*0.2
	return time.Duration(float64(base) * j), true
}

// Attempts returns the number of delays handed out so far.
func (b *Backoff) Attempts() int { return b.attempts }

// Sleep waits for d or ctx cancellation, via the clock seam. It
// reports false when the context ended first: the tick must
// stop, not retry. No time.Sleep anywhere in keeper code.
func (b *Backoff) Sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-b.clock.After(d):
		return true
	}
}

// NextDelayAfter returns the entry's next scheduled delay after
// a tick (freeze (b)): when a driving expiry is known, the
// delay is min(base, clamp(remaining/4, 1h, 7d)); otherwise the
// base interval. remaining may be negative (expiry already
// past): the clamp floors at 1h, so an expired cookie re-checks
// hourly rather than spinning.
func NextDelayAfter(base time.Duration, drivingExpiry *time.Time, now time.Time) time.Duration {
	if drivingExpiry == nil {
		return base
	}
	remaining := drivingExpiry.Sub(now)
	adaptive := remaining / 4
	switch {
	case adaptive < time.Hour:
		adaptive = time.Hour
	case adaptive > 7*24*time.Hour:
		adaptive = 7 * 24 * time.Hour
	}
	if adaptive < base {
		return adaptive
	}
	return base
}
