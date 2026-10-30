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
//     history read per terminal value per subscribe iteration
//     and gated to at most one proof per SettlePollInterval
//     (loop-2 F8).
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
//     proof is not existence-only (loop-2 F2): a reply
//     identifiably shaped as a subagent's (agent_id and
//     root_agent_id both present and different) never counts
//     as proof alone. Residual, carried: an unattributed reply
//     (identity fields absent) can still release the hold, and
//     can appear in Replies; whether real history events carry
//     the fields is unproven from code alone (U-A2/U-A6).
//   - Settle proofs re-poll on a clock cadence
//     (DefaultSettlePollInterval, 5s) while a terminal is held:
//     the Runner ends a quiet subscription when a proof is due
//     and re-proves after each subscribe batch, so a reply
//     landing seconds after a too-early proof is caught at the
//     cadence. The bound is twofold: at most one proof per
//     interval (a terminal change or a failed read never
//     bypasses the gate), and at most one proof per subscribe
//     iteration. Proofs spend no read while the boundary is
//     unknown, and no settle proof starts past the deadline
//     (a proof starting just before it may overshoot by at
//     most 100ms per window read, ≤3 reads). Exact read counts
//     in the T5/T6/T12 tests are fixture-specific, not general
//     bounds.
//   - Boundary derivation runs under the wait deadline: a dead
//     history endpoint cannot consume wall time past a short
//     --timeout before any subscription starts. Expiry during
//     derivation yields an unknown boundary and a KindTimeout
//     result, never an error return; AuthError still propagates.
//     A live stream event never installs a boundary: stream seqs
//     and history seqs are different namespaces, and the
//     unknown-boundary flag is never cleared by a live event.
//   - History window exhaustion is visible: when has_more is
//     still true at the largest window, the final read reports
//     it in the result note instead of silently returning an
//     empty reply list. Replies accumulate across windows
//     (loop-2 F7): a reply seen in any window is reported, and
//     an empty window never discards earlier replies. The
//     1000-event window bound itself is unchanged and
//     documented as a limit.
//   - The endgame reconciles the final read against the settle
//     proof and the awaited turn (loop-2 F3/F4): replies after
//     a newer user message are excluded as a follow-up turn's,
//     and a proof reply the final read no longer contains is
//     reported from the proof, with a note in either case. A
//     replayed FAILED terminal is accepted on the same
//     user-seq proof for explicit and derived boundaries
//     alike, including when held for "subagents" (loop-2 F6).
//   - The lag window propagates AuthError instead of reporting
//     Done, and a transient poll failure keeps polling until
//     the window expires (loop-2 F5).
//   - Kept unchanged, deliberately: an absent
//     active_subagent_count still decides Done directly, but
//     only for a root-confirmed terminal after a
//     root-confirmed running was seen (the 0.6.1 rule with its
//     qualifiers; whether the server always populates the count
//     is unproven from code alone); checkState still feeds only
//     the last replayed status; there is still no persisted
//     cursor, no follow/until-idle/next-reply mode, no
//     no-timeout mode, and no wait-level liveness output; exit
//     codes are unchanged (auth errors surface as exit 2 at the
//     CLI boundary, never as 124 or a retry loop).
//   - The send path's boundary is proved, never fallen back:
//     deliverSend fails the send before sending when either of
//     its two baseline history reads (limit=1 plus a limit=20
//     confirming read) fails, instead of falling back to
//     baseline 0 and letting the ack poll match an older
//     turn's identical text (the reply-reuse bug). No ordering
//     contract for chat.history windows is stated in this tree,
//     so the two-window baseline narrows but does not close
//     the stale-baseline hole, and an interleaved identical
//     message from another client can still win the
//     first-match race; both residuals are carried.
//
// Numbering note (loop-2 technical N6): the writer report's
// decisions D1–D13 map onto this file's and SEAMS.md's
// deviations D10–D14 as D2→D10, D3→D11, D11(a)→D12,
// D11(e)→D13, D13→D14. The report's other D-numbers are the
// kept rules restated in the list above, not deviations.
//
// What the server does with node_id is unknown: see NODE_ID.md.
// The chat REPL is design-only: see CHAT-REPL-DESIGN.md. How
// the wait/send paths take the profile outbound, the PR3
// reassembly caps and the config-location rules: see SEAMS.md.
package wait
