// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import "time"

// Clock abstracts the monotonic clock the Runner's deadlines run
// on. Now must return a value carrying a monotonic reading (as
// time.Now does); deadlines are compared with Before/After and
// Sub, never converted through Unix seconds, so a wall-clock
// jump can neither hide nor invent a timeout. The approval
// expiry comparison does not use this clock: it needs wall time
// (see Waiter.WithNow).
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
