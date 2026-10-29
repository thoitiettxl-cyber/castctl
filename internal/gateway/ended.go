// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

// ErrStreamEndedNoTerminal reports that a subscription stream
// ended (end_body, idle timeout, or overall timeout) without
// delivering a terminal record (S3). It is defined in PR2 but
// does NOT change SubscribeRaw's return contract: SubscribeRaw
// keeps returning the records it gathered with a nil error when
// the stream ends cleanly, exactly as Python does. PR4's wait
// must use this type: when a chat.subscribe ends without a
// terminal task.status, wait must resubscribe + server_check,
// and must never settle the turn as done. The detection itself
// is EndedWithoutTerminal below: the caller supplies the
// terminal predicate (root task.status DONE/FAILED after
// seen_running, as wait defines it), because "terminal" is a
// wait-level concept, not a gateway one.
type ErrStreamEndedNoTerminal struct {
	// Records are the records gathered before the stream
	// ended, none of which was terminal.
	Records [][]byte
}

// Error renders the condition.
func (e *ErrStreamEndedNoTerminal) Error() string {
	return "subscription stream ended without a terminal record"
}

// EndedWithoutTerminal reports whether none of records satisfies
// isTerminal. A nil predicate means no record can be terminal.
func EndedWithoutTerminal(records [][]byte, isTerminal func([]byte) bool) bool {
	if isTerminal == nil {
		return true
	}
	for _, rec := range records {
		if isTerminal(rec) {
			return false
		}
	}
	return true
}
