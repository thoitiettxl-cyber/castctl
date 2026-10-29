# Chat REPL — design only (no code on this branch)

Status: DESIGN ONLY. The REPL needs PR3's commands framework
(command registration, profile loading, prompt seam). No REPL
code lives on `feat/go-port-pr4`; this doc records the design so
the wiring PR can implement it without re-deriving the semantics.

## What the REPL is

The interactive chat loop (`Chat` in Python `chat.py`, driven by
`cmd_chat` in `cli.py`): read a line, send it as one turn,
stream/print the reply, wait for the turn to end, repeat; with
slash commands (`/open`, `/main`, `/new`, ...) switching the
session scope. One `Chat` object per process; its `cfg` is loaded
once and reused for the whole session.

## Send path (per turn)

- Body: `{"items": [{"type": "text", "text": text}], "node_id":
  <profile value>, "capabilities": {}, **scope}` where scope is
  `{"session_id": <thread>}` only when scoped. `node_id` is the
  caller-supplied stable per-profile identity (see NODE_ID.md);
  `capabilities` is the empty object here, always — the
  subscribe sites' list form (`["chat_cancel", "delta_stream"]`)
  is a different method's shape and must not be copied here.
- One `chat.stream` open per turn on the raw gateway (no retry
  wrapper between send and open in Python). A mid-send failure
  surfaces; reconnect tells the user to retry. The retry is a
  NEW `chat.stream` with the SAME `node_id` and a NEW transport
  `stream_id`. A sent `chat.stream` frame is never re-sent.
- Delivery ack: after sending, poll history (`user_ack` in
  `wait.py`: first `message.user` above the baseline whose text
  contains, or is contained in, the sent text) on a MONOTONIC
  deadline (`send --ack-timeout`, default 30 s). No ack → the
  `send` exit 5 path (delivery failure, not a wait outcome).
  The ack poll is `deliver`'s job (cli.py:973-1010): it calls
  `gw.call_json("chat.history", ...)` on the SAME gateway that
  sent the message — not fresh connections — and it never
  closes the stream connection early: no raw fire-and-forget.
  `Chat.send` (chat.py:95-117) does NO ack poll at all: it
  opens the stream, then polls `new_replies` on a wall-clock
  deadline. Exit 5 belongs to `cmd_send` / `_send_finish`
  (cli.py:1036-1039) only; there is no exit-5 path in the
  REPL's send.
- DESIGN CHANGE (flagged explicitly, not a port of
  `Chat.send`): if the Go REPL acks before waiting, it follows
  `deliver`, not `Chat.send` — `Chat.send` never acks. The
  ack-before-wait shape is a deliberate change from the
  interactive `Chat` behavior, chosen so the REPL knows the
  message landed before it waits for the turn.

## Waiting for the reply

- After the ack, the turn end is the Waiter's job: feed the
  `chat.subscribe` stream into `wait.Waiter` via the `Runner`
  (same as `wait`/`send --wait`), with the same boundary,
  watchdog, settle/accept, and exit-code rules. The REPL must
  not run its own polling loop over history.
- DO NOT PORT the `chat.py:95-117` wall-clock bug: the
  interactive wait there computes its 300 s deadline and 10 s
  quiet extension from `time.time()`. A wall-clock jump moves
  the deadline. The Go REPL uses monotonic deadlines
  everywhere (the Runner's `Clock`), like the wait path.
- DO NOT PORT the divergent `chat.py:80-93` reply filter into
  the wait core: interactive `new_replies` requires only a
  truthy status, requires non-empty text (no widget/media
  keep-alive), and reads only the last 15 events. Display of
  already-arrived replies may use it; turn-end detection must
  use `RepliesAfter` (exact `"completed"`, widget/media rules).

## Sessions and scope

- Switching chats (`/open`, `/main`, `/new`) changes
  `session_id` only, never `node_id`. The same `cfg` object
  (and the same `node_id`) serves every conversation in the
  process. `Chat.reconnect()` reuses the same `cfg`.
- The Waiter's thread scope follows the active session; a
  scope switch mid-turn is a new wait with a new boundary, not
  a scope mutation of a running one.

## Approvals and auto-approve in the REPL

- The same `Waiter` approval path and the same
  `approvals.AutoApprover` (one fresh connection per approver
  invocation, decide at most once per approval) as `wait`.
- Toggle precedence, each toggle separately: per-call flag,
  then its env var (`MUSE_AUTO_APPROVE`,
  `MUSE_AUTO_ALLOW_ONCE`), then the profile config. Defaults:
  auto-approve off, `auto_allow_once` fallback off. The
  Telegram bot's toggles live in `telegram-state.json` and are
  separate (PR5); the REPL never reads bot state.
- Questions (`needs_input`) still exit 4 / still prompt the
  human: they cannot be auto-answered.

## Display

- After every wait, read the final reply text (`final_text`),
  not just the exit code. Outcomes: `done`, `needs_input`
  (`question` holds it), `needs_approval`, `failed`,
  `timeout`. A widget in the last reply, or a waiting phrase /
  gate question / safety stop in its text, is a `needs_input`
  prompt for the human, printed with the question.
- `time.strftime`/`localtime` formatting of a server timestamp
  for display (Python `chat.py:122-123`) is display only and
  is fine; it is not a deadline.

## Wiring checklist (for the commands PR)

1. Register the `chat` command in PR3's commands framework;
   resolve the profile (config location rules, SEAMS.md) and
   pass its persisted `node_id` into the send path and the
   Runner — never generate one on read.
2. Build the gateway through the profile's outbound Dialer
   (SEAMS.md); the REPL never dials directly and never reads
   proxy env vars.
3. Reuse `wait.Runner` for turn-end detection; reuse
   `wait.UserAck` for the delivery ack; reuse
   `approvals.AutoApprover` for auto-approve.
4. Monotonic deadlines on every wait/ack path; no
   wall-clock sleeps in tests (fake clock / `synctest`).
5. No `send --wait` / `wait` behavior changes: the REPL is a
   new caller of the same core, not a fork of it.
