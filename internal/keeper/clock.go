// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package keeper is the session keeper core: expiry detection,
// CDP re-export merging, atomic locked cookie writes, backoff,
// and per-profile state. It is transport-neutral on purpose —
// no HTTP client, no WebSocket, no Telegram import lives here —
// so the web UI (item 2) can embed the same package and the
// command layer supplies the transports. The only external
// packages it depends on are internal/profile (config + locks),
// internal/gateway (cheap-chain cookie parsing), internal/conn
// (error classes), and internal/logging (summaries only).
//
// Security invariants, enforced by tests in this package:
//   - Cookie VALUES never reach logs, errors, or state. Logs and
//     state carry names, counts, presence booleans, and expiry
//     dates only.
//   - No cookiejar anywhere: merges use the explicit
//     StoredCookie structs in jar.go.
//   - No time.Sleep anywhere: all waiting goes through Clock so
//     tests use a fake clock and production code honours ctx
//     cancellation.
package keeper

import "time"

// Clock is the keeper's time seam, following the
// internal/gateway/clock.go pattern: production uses realClock,
// tests inject a fake. After returns a channel that fires after
// d; callers select on it with ctx.Done() and never Sleep.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// After uses time.After: one timer per wait, no ticker leak.
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// RealClock is the production Clock.
var RealClock Clock = realClock{}
