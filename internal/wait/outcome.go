// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

// Kind is the wait core's end kind: the Waiter's decided kind, or
// KindTimeout when the deadline passed without a decision.
type Kind string

const (
	// KindDone is a finished turn.
	KindDone Kind = "done"
	// KindFailed is a failed or cancelled turn.
	KindFailed Kind = "failed"
	// KindApproval is a turn stopped on a pending approval.
	KindApproval Kind = "approval"
	// KindTimeout is a turn that never ended before the deadline.
	KindTimeout Kind = "timeout"
)

// Exit codes, verbatim from wait.py.
const (
	// ExitOK is a finished turn.
	ExitOK = 0
	// ExitFailed is a failed or cancelled turn.
	ExitFailed = 2
	// ExitHuman needs a human: a question or a pending approval.
	ExitHuman = 4
	// ExitTimeout is a turn that never ended.
	ExitTimeout = 124
)

// OutcomeOf maps a kind and its final replies to an outcome:
// done | needs_input | needs_approval | failed | timeout. Only
// the last reply is inspected, and only when kind is done: a
// widget in it, or a waiting reason in its text, makes the
// outcome needs_input. Any other kind string maps to timeout.
func OutcomeOf(kind Kind, replies []Reply) string {
	switch kind {
	case KindApproval:
		return "needs_approval"
	case KindFailed:
		return "failed"
	case KindDone:
		if len(replies) > 0 {
			last := replies[len(replies)-1]
			if len(last.Widgets) > 0 || NeedsInputReason(last.Text) != "" {
				return "needs_input"
			}
		}
		return "done"
	default:
		return "timeout"
	}
}

// ExitCode maps a kind and its final replies to a process exit
// code: 0 done, 2 failed, 4 needs a human, 124 timeout.
func ExitCode(kind Kind, replies []Reply) int {
	switch OutcomeOf(kind, replies) {
	case "done":
		return ExitOK
	case "needs_input", "needs_approval":
		return ExitHuman
	case "failed":
		return ExitFailed
	default:
		return ExitTimeout
	}
}
