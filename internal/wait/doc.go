// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package wait is the verbatim Go port of wait.py turn-end
// detection (muse-cli 0.6.1), plus the driver that feeds it.
//
// The pure layer (Waiter, RepliesAfter, NeedsInputReason,
// OutcomeOf) is deterministic given an event sequence and a
// history snapshot: no clock except the approval-expiry wall
// comparison, no I/O. The driver layer (Runner) owns the
// connection, the boundary, the deadlines and the endgame, and
// feeds the Waiter from one goroutine.
//
// Rules carried over from Python, in full:
//
//   - Vocabularies: DONE {"completed"}, FAILED
//     {"interrupted", "cancelled", "canceled"}, six suspect-done
//     and six suspect-failed strings. Only DONE/FAILED end a
//     wait directly, and only after a root-confirmed running was
//     seen; suspect strings need history proof via Settle.
//   - The root is learned only from a root-confirmed running
//     (first one wins); terminals never teach it. task_id is
//     agent identity, not a turn epoch, and is never keyed on.
//   - require_running is a dead parameter: stored, never read.
//   - Monotonic deadlines everywhere. The one wall-clock
//     comparison is approval expiry, whose value is itself a
//     wall epoch. chat.py's wall-clock deadline bug is not
//     ported.
//   - Stream seqs and history seqs are different namespaces and
//     are never compared; the ignored terminal's seq is stored
//     only, never proof.
//   - The Waiter never dials, never reads history, and never
//     generates a node_id. The caller supplies the connection
//     (a conn.Gateway behind the Subscriber interface) and the
//     stable per-profile node_id (RunnerConfig.NodeID); the
//     Waiter only consumes events. See NODE_ID.md.
//
// Deliberate deviations from bare-Waiter Python, each identical
// under the driver:
//
//   - D1: the state machine itself refuses to overwrite a set
//     result (Feed/Settle/AcceptReplayedFailed are no-ops once
//     decided). In Python the guard lives in the driver, which
//     stops feeding; a bare Python Waiter fed after a result can
//     overwrite it.
//   - D2: the Runner runs state checks synchronously between
//     subscribe batches instead of on a concurrent check thread
//     behind a lock; no I/O happens under a lock because there
//     is no lock. Settle attempts happen at batch boundaries
//     and when a new ignored terminal appears, throttled to one
//     history read per terminal value per subscribe iteration.
//   - D3: RepliesAfter skips non-object events instead of
//     failing while sorting, and FeedRecord rejects trailing
//     data after one JSON value. Both are unobservable for
//     well-formed server records.
//
// What the server does with node_id is unknown: see NODE_ID.md.
// The chat REPL is design-only: see CHAT-REPL-DESIGN.md. How
// the wait/send paths take the profile outbound, the PR3
// reassembly caps and the config-location rules: see SEAMS.md.
package wait
