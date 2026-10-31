# Integration seams — how the wait core is wired in

Status: SEAMS ONLY. No dead code on this branch: the interface
sketches below are documentation (code blocks in this file), and
the live contracts are the Go interfaces in `runner.go`
(`Subscriber`), `history.go` (`HistoryReader`), and
`approvals.go` (`Approver`, `Decider`); `waiter.go` consumes
`Approver` via `WithApprover` and defines no seam of its own.

## 1. The driver contract (live, implemented)

The wait core takes its connection from the caller and never
dials itself:

- `Config.Dial(ctx) (Subscriber, error)` — one fresh
  subscription per call. The driver builds the connection
  through the profile's outbound Dialer (see §2) and returns a
  `Subscriber` (satisfied by `conn.Gateway`'s `SubscribeRaw` +
  `Close`). The Runner closes each subscription it dialed, and
  never closes anything it did not dial. A check call gets its
  own fresh `Dial` + close, mirroring Python's per-read fresh
  connections. The caller owns connection freshness and
  replacement (e.g. via `Muse.Live` / `Connect` / `SharedConn`
  in `internal/conn`); the Runner never inspects or replaces a
  connection.
- `Config.History HistoryReader` — history reads. See §4.
- `Config.Approver approvals.Approver` (nil = no
  auto-approve). The approver returns an `ApprovalResult`
  (handled ids, approved/error records, fatal error); the
  Runner surfaces the records in `Result` (see §1 and
  `runner.go`). The approver's `Connect` is likewise
  caller-supplied; the Runner never dials for it either.
- `Config.NodeID` — caller-supplied stable identity,
  carried through to `Result`. The wait core never generates,
  persists, or rotates it. See NODE_ID.md.
- `Config.UserStop func() bool`, `Recheck func()` —
  caller callbacks for user interrupt and interactive recheck.
  Both default to no-ops.
- Subscriber panic contract: a `Subscriber` MUST NOT panic.
  The Runner calls `SubscribeRaw` and `Close` synchronously
  with no recover, so a panic from a contract-violating
  Subscriber propagates out of `Run`. The CLI-boundary recover
  exists in Run (R2 decision): a panic anywhere on the dispatch
  path converts to exit 2 with a redacted error message and no
  secret-bearing stack, so the CLI path is covered by it. See the
  `Subscriber` doc in `runner.go`.

## 2. Outbound Dialer seam (wiring PR)

Proxy invariant (holds end to end): ALL network traffic goes
through the profile's outbound Dialer, fail-closed. The wait
core never reads proxy environment variables, never dials
direct, and never holds an outbound itself.

Sketch of the wiring PR's driver (not code on this branch):

```go
// The profile's outbound is built once per command run by the
// commands framework (PR3). The gateway connector is built
// over that outbound's DialContext; every Dial call below
// therefore inherits the profile outbound, fail-closed.
dial := func(ctx context.Context) (wait.Subscriber, error) {
    return connector(ctx, conn.Config{...}) // returns conn.Gateway
}
runner, _ := wait.NewRunner(wait.Config{Dial: dial, History: hist, ...})
```

Rules for the wiring PR: the Dial closure must fail (return
the error) when the outbound is absent/misconfigured — never
fall back to a direct dial; the Runner treats a Dial error as a
transport failure (resubscribe with backoff, AuthError fatal);
a `Subscriber` that dials itself outside the closure is a bug.

## 3. PR3 reassembly caps — constraints, not references

PR3 (`feat/go-port-pr3`, reference only — read-only worktree
`~/workspace/muse-cli-go-port-pr3`, do not edit, do not
import) caps gateway reassembly in
`internal/gateway/framing.go`:

- `MaxReassembledSize = 64 << 20` (64 MiB) per message,
- `MaxUnfinishedGroups = 16` concurrent chunk groups,
- `MaxPiecesPerGroup = 32768` distinct pieces per group,
  with typed errors on violation.

On THIS base (`feat/go-port`, PR2) there are NO reassembly
caps (only `SendPiece = 60000`). The wait core therefore
references no cap symbol and imports no PR3 API; it consumes
records the gateway already reassembled, so the caps bind the
gateway layer, not the wait layer. After PR3 merges, the
wiring PR inherits the caps for free through the gateway; the
wait core needs no change. Do not re-implement or duplicate
the caps in `internal/wait`.

## 4. History adapter (wiring PR)

`HistoryReader` is the live interface in `history.go`:

```go
type HistoryReader interface {
    ReadHistory(ctx context.Context, limit int) (events []any, hasMore bool, err error)
}
```

The production adapter (wiring PR) calls `CallJSON` with the
`chat.history` envelope and extracts `has_more` from the
response. `conn.Muse.History` (this base) drops `has_more`,
so it CANNOT back this interface alone — do not wire it
directly; the adapter must read the envelope. The adapter
must propagate `AuthError` unwrapped (the Runner treats it
as fatal everywhere) and must honor the passed context
deadline (the Runner budgets every history read).

## 5. Config-location rules (PR3, reference only)

PR3 `internal/profile/configlocation.go` resolves the config
location as: explicit `--config` flag > `CASTCTL_CONFIG` env
(non-empty) > `os.UserConfigDir`-derived home (`XDG` /
`%APPDATA%`; a relative `XDG_CONFIG_HOME` is ignored with a
warning). Cookie/secret paths are relative to the config dir.
Read-only loads never generate `node_id` (see NODE_ID.md).
The wait core resolves no config location and reads no files;
the wiring PR resolves the profile and hands the Runner its
`node_id`, outbound, and history adapter.

## 6. Gap disposition (G1–G10, from base-interfaces.md)

- G1 (no per-frame reader): worked around — `OnRecord`
  capture on `SubscribeRaw` records; the Runner never needs
  frame-level access. No gateway extension was needed.
- G2 (terminal predicate is wait-level): implemented in
  `wait.TaskStatusInfo` + the unexported done/failed
  vocabularies (`IsDoneStatus`/`IsFailedStatus` accessors).
  The Runner never calls `gateway.EndedWithoutTerminal`: S3
  is a helper over already-gathered records, and no
  production code on this branch calls it. The real
  predicate shape — a root-confirmed DONE/FAILED
  task.status only after a root-confirmed running was seen
  for the learned root — is pinned as a helper-level test in
  `gateway_test.go` (stateful predicate over the records,
  including the completed-before-running and foreign-root
  negatives), alongside the Runner-driving tests that prove
  the Runner itself ends on DONE-after-running. Do not cite
  the helper test as Runner evidence: it proves the
  predicate shape, not the Runner's use of it.
- G3/G4 (fake clock / clock seam): the Runner uses its own
  `Clock` interface (`clock.go`, monotonic only) plus
  `testing/synctest` in `runner_test.go`; the gateway's clock
  seam was mirrored, not duplicated. The base `FakeClock`
  ticker `Stop()` race was not reused. Clock seams are split
  by design: the Runner's Clock and the gateway's clock seam
  are separate; no shared clock seam exists on this base.
- G5 (keep-alive): default OFF, no wiring; the Runner never
  touches keep-alive. `SubscribeOptions` on this base has no
  keep-alive field at all (keep-alive lives on the concrete
  gateway type only, default OFF); `runner_test.go` pins the
  option shape the Runner builds (no `OnOpen`, no `Route`,
  keep-alive unreachable through the options). No
  `UseKeepAlive` field must appear in any wait-path
  `SubscribeOptions`.
- G6 (SubscribeRaw conflates end reasons / discards records
  on error): worked around — `OnRecord` capture + explicit
  `ShouldStop` (watchdog / online grace / deadline) + the
  Runner's own end-reason handling. No gateway change.
- G7 (generation / reconnect storm): the Runner resubscribes
  with backoff and runs at most one bounded state check after
  30 s of reconnect failures; it never re-sends a stream.
- G8 (retry classification): Runner rule — `Dial`/`SubscribeRaw`
  transport errors resubscribe (fresh connection, never a
  re-send); `AuthError` propagates as fatal; history-read
  errors are read failures (settle retries once, final read
  flips to fail-closed 124); outer-context cancellation
  propagates. A sent `chat.stream` is never re-sent, by any
  caller, for any reason.
- G9 (`server_check` / `stop_now`): built on the same two
  seams — a short `Dial` + subscribe for the state check, and
  `HistoryReader` for the user-seq proof. No new interface.
- G10 (harness): the PR2 `gatewaytest` harness was reused
  as-is (`gateway_test.go`); no extension was required.

## 7. Deviations from the Python driver shape (documented)

Numbering note (loop-2): this file's D10–D14 are the wait
redesign's five deliberate deviations. The writer report numbers
the same decisions D1–D13; the mapping is D2→D10, D3→D11,
D11(a)→D12, D11(e)→D13, D13→D14.

- D1: the state machine itself refuses to overwrite a set
  result (Python's guard was driver-level only). Identical
  under any driver; no driver code may rely on overwriting.
- D2: state checks run synchronously between subscribe
  batches instead of on a concurrent check thread behind a
  lock; settle attempts happen at batch boundaries, on each
  newly-ignored terminal, and on the settle re-poll cadence
  (D11), throttled to one history read per terminal value per
  subscribe iteration.
- D3: `RepliesAfter` skips non-object events instead of
  failing while sorting; `FeedRecord` rejects trailing data
  after one JSON value. Unobservable for well-formed records.
- D4: the Runner takes ONE `Dial` func (fresh connection per
  iteration/check, closed after use) rather than Python's
  per-iteration `conn(cfg)` plus per-read fresh connections.
  The caller owns connection freshness/replacement.
- D5: the settle throttle key is the ignored terminal plus its
  ignored reason, not the terminal alone as in Python. When
  the reason clears (the F8 re-arm) the proof is re-attempted
  instead of waiting for a new terminal or a server check;
  outcome-equivalent, one extra history read at most (see
  `trySettle` in `runner.go`).
- D6: auto-approve stderr lines have no Go equivalent in the
  core: Python's helper prints `auto-approved ...` /
  `SKIPPED` / `FAILED` lines to stderr, but the Runner has no
  logger. The records are carried in `Result.AutoApproved` /
  `Result.AutoApproveErrors` and the CLI wiring owns
  printing/logging them from there.
- D7: a decide-time AuthError is fatal in Go, not exit 4. In
  Python the bare Waiter catches every approver exception
  (`wait.py:292-297`, `except Exception`), including AuthError
  (a `RuntimeError`, `gateway.py:52`): `make_auto_approver`
  catches only `(GatewayError, TimeoutError)` around the
  decide call, so an AuthError from decide reaches the
  Waiter's catch, the ids go to `approver_failed`, and the
  wait ends as `("approval", ...)` for a human: exit 4. Go's
  `AutoApprover.AsApprover` instead returns the AuthError
  unwrapped as `ApprovalResult.Err`, the Waiter records it as
  fatal, and the Runner returns it as an error (exit 2),
  matching `_run_wait`'s outer contract that AuthError is
  re-raised, never swallowed (`cli.py:1254-1274`).
  Deliberate: an expired login must never become exit 4
  needs_approval, which would hide the re-login need behind
  a human step. Pinned by `TestRunnerApproverAuthErrorPropagates`.
- D8: cancellation during the endgame propagates `ctx.Err()`,
  never a Done result. Python has no context:
  KeyboardInterrupt is a BaseException that `_run_wait`'s
  `except Exception` never catches (`cli.py:1254-1274`), so
  an interrupt during the endgame propagates out of the wait
  instead of becoming a result. Go's context cancellation is
  the analogue: `finish()` returns `ctx.Err()` when the
  context dies during the lag window, including a lag poll
  whose reader returns `ctx.Err()`. Pinned by
  `TestRunnerLagWindowCancelReturnsCtxErr` and
  `TestRunnerLagPollCtxErrReturnsCtxErr`.
- D9: `Settle` and `AcceptReplayedFailed` take no context, by
  design. The Waiter is a context-free synchronous state
  machine (one goroutine, no I/O); threading a context into
  its methods would leak Runner concerns into the seam and
  change the exported Waiter API the wiring PR consumes.
  Cancellation containment therefore lives in the Runner,
  which owns the context: `settlePending` checks `ctx.Err()`
  before applying either proof, `finish()`'s last-chance
  proof is contained by the final-read ctx checks plus the
  final guard before the result return, and `Run` checks
  `ctx.Err()` after the loop before calling `finish()`. The
  only production call sites are `settlePending` and
  `finish()`'s last-chance proof (both in `runner.go`); a
  future caller applying `Settle`/`AcceptReplayedFailed`
  outside the Runner must check cancellation itself — the
  Waiter cannot know. Pinned by
  `TestRunnerSettlePendingCancelledSuccessReturnsCtxErr` and
  the `TestRunnerFinish*CtxErr` tests.
- D10: `Settle` accepts a terminal held for `"subagents"` on a
  history reply proof (wait redesign, 2026-10-30). 0.6.1
  refuses the subagents reason outright; the Go rule releases
  a quiet-stream hold on the two-signal proof (stored root
  terminal + reply after the boundary). The proof is not
  existence-only (loop-2 F2): a reply identifiably shaped as
  a subagent's (agent_id and root_agent_id both present and
  different) never counts alone; an unattributed reply still
  counts (fail-open on absence, U-A2/U-A6 carried).
  Attribution is recorded only from payload-level string
  fields: a non-string, agent-only, root-only, empty-string,
  event-level, or metadata-nested id counts as unattributed.
  FAILED terminals still never settle here. Pinned by
  `TestWaitRedesignT5*` (Runner level) and
  `TestWaitRedesignT9ReleaseSignals` (Waiter level), plus the
  loop-2 F2 tests.
- D11: settle re-poll (wait redesign, 2026-10-30).
  `Config.SettlePollInterval` (default 5s, never disable-able,
  positive values below 100ms clamped to the floor) bounds the
  delay between a too-early proof and its retry: `shouldStop`
  ends a quiet subscription when a proof is due, and the
  Runner re-proves after each subscribe batch that delivered
  no record. The bound is twofold (loop-2 F8): at most one
  proof per interval — a terminal change or a failed read
  never bypasses the gate — and at most one proof per
  subscribe iteration. No settle proof spends a read while
  the boundary is unknown (the gates forbid every proof; the
  endgame final read and derivation do read with an unknown
  boundary, as before), and no settlePending/checkState proof
  starts past the deadline (loop-2 F9; overshoot bounded by
  the 100ms historyCtx floor per window read). The finish
  endgame is excepted: its last-chance FAILED proof, final
  read, lag window, and reconciliation re-check run after
  the deadline on floor budgets, by design. Pinned by
  `TestWaitRedesignT5/T6/T12` and the loop-2 F8/F9 tests.
  Exact read counts are fixture-specific, not general bounds.
- D12: boundary derivation runs under the wait deadline (wait
  redesign, 2026-10-30). A deadline expiry during derivation
  yields an unknown boundary and a KindTimeout result; an
  AuthError still propagates and a dead caller context still
  returns the caller's error. No live event installs or clears
  the boundary (loop-2 F1: stream seqs and history seqs are
  different namespaces). Pinned by
  `TestWaitRedesignT13BlockingHistoryTerminatesAtDeadline`
  and the loop-2 F1 tests.
- D13: `HistoryReplies` reports window exhaustion (wait
  redesign, 2026-10-30): a third return value, true when
  `has_more` is still true at the largest limit. The Runner's
  finish turns exhaustion on the final read into a result
  note; settle proofs ignore it (a partial window's replies
  are still real replies), and the settle-time exhaustion
  flag is discarded by design — only final-read exhaustion
  surfaces a note. When the final read fails,
  reconciliation is skipped and the settle proof is lost to
  the fail-closed KindTimeout with only the generic
  final-read note (a stated exception to the "never silently
  lost" rule). Replies accumulate across windows
  (loop-2 F7): a reply seen in any window is reported, and an
  empty window never discards earlier replies. Dedupe is
  first-wins (same seq+message_id, different text: the first
  window's text stands). `HistoryReplies` has no internal
  cap on the window count — the bound lives in the caller's
  limits (three by default) — and `DeriveBoundary`'s
  seen-max fallback can install a boundary from a non-user
  event's seq; all-empty windows with `has_more` yield
  known-0. The reconciliation re-check trusts newest-first
  windows the same way the send baseline does
  (`LatestUserSeq` stops scanning at the boundary), so U-A8
  conditions the F4 turn check too. Pinned by
  `TestWaitRedesignT7WindowExhaustionIsVisible`, the extended
  `TestHistoryReplies`, and the loop-2 F7 tests.
- D14: `deliverSend` (in `internal/commands/wait.go`) fails the
  send before sending when either of its two baseline history
  reads (limit=1 plus a limit=20 confirming read, loop-2 F10)
  fails. No baseline-0 fallback, so the substring ack
  (`UserAck`) can only match above the two-window baseline
  read successfully before sending. No ordering contract
  for chat.history windows is stated in this tree, so the
  two-window baseline narrows but does not close the
  stale-baseline hole, and an interleaved identical message
  can still win the first-match race; both residuals are
  carried. `UserAck` refuses an empty needle. The send
  timeout re-run hint is JSON-only: `buildSendWaitJSON`
  replaces the wait note on timeout, while send text mode
  prints only the wait note via `printWaitTail`. Pinned by
  `TestDeliverSendBaselineReadFailureFailsBeforeSend`,
  `TestDeliverSendTwoWindowBaselineAcksOwnMessage`, and
  the loop-2 F10 tests.

## 8. Deferred wiring (exact list)

CLI command wiring (`wait` / `send --wait` / `send
--until-done`); the send path (`chat.stream` + ack poll);
the chat REPL code (design in CHAT-REPL-DESIGN.md); the
`HistoryReader` production adapter (§4); profile resolution
and `node_id` origin (§5, NODE_ID.md); Telegram wiring
(PR5); `update` command; approval claim coordination between
a monitor and a turn (the 15 s in-flight claim wait: a
driver/monitor concern, not part of `AutoApprover`); the
auto-approve stderr lines (logged by the CLI wiring from
`Result.AutoApproved` / `Result.AutoApproveErrors`, see §7
D6); anything needing PR3's commands framework. See
`README.md` for the same list.

## 9. Wait-redesign gap disposition (probe-A G1–G10)

Numbering is probe A's (`A-go-wait-today.md` / the Phase-1 R1
report), NOT §6's driver gaps. "Closed" means a test proves the
new behaviour on scripted streams; server-behaviour unknowns
stay [UNVERIFIED] until Boss's live capture settles them — no
fixture here is a real captured stream.

- A-G1 (settle single-attempt per iteration): CLOSED for the
  quiet-stream delay — the D11 re-poll bounds re-proof to at
  most one proof per interval and one per subscribe iteration
  (T5/T6/T12; loop-2 F8/F9 tests). Exact read counts are
  fixture-specific, not general bounds. The per-iteration
  throttle itself is kept.
- A-G2 (subagents holdback release): CLOSED for the
  quiet-stream case — D10 reply proof releases the hold
  (T5/T9; loop-2 F2/F6 tests). Release needs a reply that is
  not identifiably subagent-shaped; a hold with no such reply
  in history waits to the deadline, as before.
- A-G3 (checkState last-only): CARRIED deliberately — the
  last-only rule matches 0.6.1 and replay order/content is
  [UNVERIFIED]. Pinned by T10, including the
  subagent-filtered last event.
- A-G4 (no reply attribution): PARTLY CLOSED — the settle
  proof excludes identifiably-subagent replies (loop-2 F2),
  but the final reply list stays unattributed and whether
  real `message.assistant` events carry agent fields is
  [UNVERIFIED] (needs live capture). Attribution is
  recorded only from payload-level string fields; a
  non-string, agent-only, root-only, empty-string,
  event-level, or metadata-nested id counts as
  unattributed. T17 pins the non-exclusion rule for the
  filter; an unattributed reply can still release a hold
  and appear in Replies.
- A-G5 (narrow/Done-only lag window): PARTLY CLOSED — the
  re-poll (D11) now catches late replies for held/suspect
  terminals before the endgame, so the lag window is no
  longer the only late-reply path; the lag window itself
  now propagates AuthError and retries transient failures
  (loop-2 F5), still 2s, Done-only, empty-replies-only, and
  no lag window exists on the timeout path.
- A-G6 (absent count trusted): CARRIED deliberately — the
  0.6.1 rule is kept with its qualifiers (root-confirmed
  terminal after a root-confirmed running); whether the
  server always populates `active_subagent_count` on root
  terminals is [UNVERIFIED]. Pinned by T8 (first form:
  direct Done + final-read collection).
- A-G7 (no resume/cursor/persistence): CARRIED — no store was
  added. Restart recovery is history re-derivation only, with
  its stated limits. No test claims otherwise.
- A-G8 (always-on time limit, no modes): CARRIED — single
  overall deadline (default 600s) kept; no follow/until-idle/
  next-reply/no-timeout mode was added. T11 does not exist;
  single-turn exit after the first turn is pinned by the
  existing `TestRunnerLiveDone`.
- A-G9 (silence while waiting): CARRIED — the Runner still
  writes nothing while waiting. The re-poll bounds the
  decision latency after a reply lands; it is not liveness
  output. Result notes (exhaustion, reconciliation) surface
  only in the finished result, via `printWaitTail`/`--json`.
- A-G10 (boundary/window edges): PARTLY CLOSED — window
  exhaustion is now visible via the finish note (D13/T7);
  replies accumulate across windows and empty windows never
  discard earlier data (loop-2 F7); the 1000-event window
  bound is unchanged and documented as a limit. The
  endgame reconciles the final read against the settle
  proof and the awaited turn (loop-2 F3/F4, loop-3 H1:
  missing proof replies are restored into an empty or a
  non-empty final read). Two stated exceptions bound the
  visibility claim: the settle-time exhaustion flag is
  discarded (only final-read exhaustion surfaces a note),
  and a failed final read skips reconciliation. Dedupe is
  first-wins, `HistoryReplies` has no internal window-count
  cap (the bound lives in the caller's limits), and the
  F4 re-check trusts newest-first windows (U-A8). Boundary
  suppression on unknown boundary is unchanged (T3).

