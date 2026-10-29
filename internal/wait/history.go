// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"context"
	"errors"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// HistoryReader reads one chat.history window. Events are decoded
// JSON values (maps for history events); hasMore reports whether
// the server has more events beyond this window. The production
// adapter (deferred to post-PR3 wiring, see SEAMS.md) reads
// has_more from the chat.history envelope; conn.Muse.History
// drops it and cannot back this interface alone.
//
// A HistoryReader must fail closed: a transport error is an
// error, never an empty window. History reads use fresh
// connections in Python; the adapter owns that choice.
type HistoryReader interface {
	ReadHistory(ctx context.Context, limit int) (events []any, hasMore bool, err error)
}

// DefaultHistoryLimits is the window growth for history reads:
// 200, then 500, then 1000 events.
var DefaultHistoryLimits = []int{200, 500, 1000}

// DeriveBoundary derives the boundary for a standalone wait:
// the last message.user seq in history. It returns the boundary,
// whether it is known, and that it was derived. A boundary of 0
// with known=true means genuinely empty history (or history with
// no user event and no more pages), not a failure. When every
// window read fails, the boundary is unknown (0, false): settle
// and accept are disabled until a live root running clears the
// flag. Each window read is retried once on a transport error.
//
// Errors: an AuthError (or a cancelled context) propagates; any
// other read error fails that window and the next window is
// tried.
func DeriveBoundary(ctx context.Context, r HistoryReader, limits []int) (afterSeq int64, known bool, derived bool, err error) {
	seenMax := int64(0)
	anySuccess := false
	for _, limit := range limits {
		events, hasMore, readErr := readWindow(ctx, r, limit)
		if readErr != nil {
			if isFatalHistoryErr(ctx, readErr) {
				return 0, false, false, readErr
			}
			continue
		}
		anySuccess = true
		if len(events) == 0 {
			return 0, true, true, nil
		}
		maxUser, hasUser, maxSeq := scanWindow(events)
		if maxSeq > seenMax {
			seenMax = maxSeq
		}
		if hasUser {
			return maxUser, true, true, nil
		}
		if !hasMore {
			return 0, true, true, nil
		}
		// Grow to the next window.
	}
	if !anySuccess {
		return 0, false, true, nil
	}
	// Exhaustion: all windows succeeded, has_more still true at
	// the largest limit, no user event. Fall back to the max seq
	// seen in any successful window.
	return seenMax, true, true, nil
}

// LatestUserSeq returns the newest message.user seq in history,
// or (0, false) when no user event was found in any window. The
// windows stop early when has_more is false, when a window is
// empty, or when the window already reaches the boundary (its
// oldest seq is at or below afterSeq). The seen max accumulates
// across windows before the early-return checks. A read error
// fails the attempt and propagates to the caller, which treats
// it as a failed read (never as proof).
func LatestUserSeq(ctx context.Context, r HistoryReader, limits []int, afterSeq int64) (int64, bool, error) {
	seen := int64(0)
	found := false
	for _, limit := range limits {
		events, hasMore, err := r.ReadHistory(ctx, limit)
		if err != nil {
			return 0, false, err
		}
		if len(events) == 0 {
			break
		}
		maxUser, hasUser, _ := scanWindow(events)
		if hasUser && (!found || maxUser > seen) {
			seen = maxUser
			found = true
		}
		if !hasMore {
			break
		}
		if oldestSeq(events) <= afterSeq {
			break
		}
	}
	return seen, found, nil
}

// HistoryReplies returns this turn's final replies from history:
// the last window's events filtered by RepliesAfter, with upto
// set to that window's newest seq (no upper bound when the
// window is empty). Windows grow while has_more is true and the
// window does not yet reach the boundary. A read error
// propagates: the caller retries at its own level (the final
// read gets two attempts).
func HistoryReplies(ctx context.Context, r HistoryReader, limits []int, afterSeq int64) ([]Reply, error) {
	var lastEvents []any
	var lastUpto *int64
	for _, limit := range limits {
		events, hasMore, err := r.ReadHistory(ctx, limit)
		if err != nil {
			return nil, err
		}
		lastEvents = events
		if len(events) == 0 {
			lastUpto = nil
			break
		}
		maxSeq := newestSeq(events)
		lastUpto = &maxSeq
		if !hasMore {
			break
		}
		if oldestSeq(events) <= afterSeq {
			break
		}
	}
	replies, _ := RepliesAfter(lastEvents, afterSeq, lastUpto)
	return replies, nil
}

// readWindow reads one window with one retry on a transport
// error (two attempts total). A fatal error is returned at once
// without a retry.
func readWindow(ctx context.Context, r HistoryReader, limit int) ([]any, bool, error) {
	events, hasMore, err := r.ReadHistory(ctx, limit)
	if err == nil || isFatalHistoryErr(ctx, err) {
		return events, hasMore, err
	}
	return r.ReadHistory(ctx, limit)
}

// isFatalHistoryErr reports whether a history error must
// propagate instead of failing a window: an AuthError (which
// must never become a timeout) or a dead context.
func isFatalHistoryErr(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx.Err() != nil {
		return true
	}
	var authErr *conn.AuthError
	return errors.As(err, &authErr)
}

// scanWindow returns the max message.user seq, whether any user
// event exists, and the max seq of any event in the window.
func scanWindow(events []any) (maxUser int64, hasUser bool, maxSeq int64) {
	maxSeq = 0
	first := true
	for _, raw := range events {
		ev, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		seq := seqOf(ev)
		if first || seq > maxSeq {
			maxSeq = seq
			first = false
		}
		if ev["event_name"] == "message.user" {
			if !hasUser || seq > maxUser {
				maxUser = seq
			}
			hasUser = true
		}
	}
	return maxUser, hasUser, maxSeq
}

func oldestSeq(events []any) int64 {
	min := int64(0)
	first := true
	for _, raw := range events {
		ev, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		seq := seqOf(ev)
		if first || seq < min {
			min = seq
			first = false
		}
	}
	return min
}

func newestSeq(events []any) int64 {
	max := int64(0)
	first := true
	for _, raw := range events {
		ev, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		seq := seqOf(ev)
		if first || seq > max {
			max = seq
			first = false
		}
	}
	return max
}
