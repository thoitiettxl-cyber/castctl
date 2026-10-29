// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import "time"

// Clock is the time seam for the sleeps and timers inside this
// package (S10). Production code uses the real clock; tests inject
// a fake clock so bounded waits are deterministic and Ctrl-C
// during a wait never depends on wall-clock timing. There are no
// other sleeps or backoffs in this package: the stream queue waits
// on ctx cancellation (context.AfterFunc), writes are bounded by
// deadlines, and no retry loop with a sleep exists here. Jitter is
// deliberately NOT implemented: the default is no jitter, for
// parity with Python 0.6.1; jitter is a proposed intentional diff
// needing Boss approval (see doc.go).
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
	NewTicker(d time.Duration) Ticker
}

// Ticker is one ticking timer: the value type of Clock.NewTicker.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

func (realClock) NewTicker(d time.Duration) Ticker { return realTicker{time.NewTicker(d)} }

type realTicker struct{ t *time.Ticker }

func (r realTicker) C() <-chan time.Time { return r.t.C }

func (r realTicker) Stop() { r.t.Stop() }
