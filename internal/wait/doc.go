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
//     stable per-profile node_id (Config.NodeID); the
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
// Wait redesign (2026-10-30): turn-end rules added on top of the
// port, each decided explicitly against muse-cli 0.6.1 as the
// differential reference and proved by the T1–T18 tests in
// wait_redesign_test.go:
//
//   - A terminal held for "subagents" settles on a history reply
//     proof, without waiting for a count-0 event or a server
//     replay. This deliberately diverges from 0.6.1, which
//     refuses the subagents reason in settle outright: the two
//     signals together — a stored root terminal plus a
//     completed reply in history after the boundary — release a
//     wait the live stream left held on a quiet stream. The
//     reply filter does not attribute replies to main vs
//     subagent (no agent fields are read anywhere in replies.go),
//     so a subagent's own completed reply can release the hold;
//     that residual is carried, not hidden, pending live
//     capture of real history shapes.
//   - Settle proofs re-poll on a clock cadence
//     (DefaultSettlePollInterval, 5s) while a terminal is held:
//     the Runner ends a quiet subscription when a proof is due
//     and re-proves after each subscribe batch, so a reply
//     landing seconds after a too-early proof is caught within
//     one interval plus one resubscribe pause. Proofs are
//     throttled as before, spend no read while the boundary is
//     unknown, and never start past the deadline.
//   - Boundary derivation runs under the wait deadline: a dead
//     history endpoint cannot consume wall time past a short
//     --timeout before any subscription starts. Expiry during
//     derivation yields an unknown boundary and a KindTimeout
//     result, never an error return; AuthError still propagates.
//   - History window exhaustion is visible: when has_more is
//     still true at the largest window, the final read reports
//     it in the result note instead of silently returning an
//     empty reply list. The 1000-event window bound itself is
//     unchanged and documented as a limit.
//   - Kept unchanged, deliberately: an absent
//     active_subagent_count still decides Done directly (the
//     0.6.1 rule; whether the server always populates the count
//     is unproven from code alone); checkState still feeds only
//     the last replayed status; there is still no persisted
//     cursor, no follow/until-idle/next-reply mode, no
//     no-timeout mode, and no wait-level liveness output; exit
//     codes are unchanged (auth errors surface as exit 2 at the
//     CLI boundary, never as 124 or a retry loop).
//   - The send path's boundary is proved, never fallen back:
//     deliverSend fails the send before sending when the
//     pre-send baseline history read fails, instead of falling
//     back to baseline 0 and letting the ack poll match an
//     older turn's identical text (the reply-reuse bug).
//
// What the server does with node_id is unknown: see NODE_ID.md.
// The chat REPL is design-only: see CHAT-REPL-DESIGN.md. How
// the wait/send paths take the profile outbound, the PR3
// reassembly caps and the config-location rules: see SEAMS.md.
package wait
