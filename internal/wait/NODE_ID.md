# NODE_ID — stable client identity for chat.stream

## Decision

`node_id` is a per-profile stable client identity. The Go port MUST
preserve the Python (0.6.1) behavior exactly:

- Source: the profile's `config.json`, key `node_id`.
- Precedence on load: file value > `MUSE_NODE_ID` env var >
  generate `crypto/rand` 8 bytes as 16 lowercase hex chars and
  persist. Python `load_config` (cli.py:151-175) persists
  whenever it generates: `changed=True` triggers `json.dump`
  on ANY load call, including read-only wait paths. Only the
  env-var fill avoids the write (it sets the value without
  setting `changed`). Never writing on a read is PR3's
  deliberate change from Python — label it as such wherever
  the rule is stated; do not present it as Python's behavior.
- Scope: one value per profile, reused verbatim on EVERY
  `chat.stream` body for that profile, across turns, sessions,
  processes, and reconnects. No per-turn, per-session, or
  per-process regeneration. No per-stream derivation.
- Wire shape: `"node_id": "<value>", "capabilities": {}` alongside
  `items`, plus `session_id` only when scoped to a thread.
- It is NOT the transport `stream_id` (per-`_open` integer) and NOT
  the per-request `x-request-id` (fresh UUID). Never substitute one
  for another.
- It is part of the connection identity
  `(cookies_file, vm_id, node_id)`: changing it drops the warm
  connection (reload semantics). The 5-tuple
  `(cookies_file, vm_id, node_id, outbound_tag, outbound_hash)`
  is PR3-only (`internal/conn/gateway.go:66-72` there); this
  base's `conn.Identity` is the triple
  (`internal/conn/gateway.go:60-72` here).
- `tempNodeID()` (ephemeral, in-memory, never written) exists ONLY
  for the handshake-only `profile test` when a profile has no
  persisted value. It MUST NEVER be used for a real `chat.stream`.

## How this branch implements it

On the PR4 base (`feat/go-port`, PR2 interfaces), `node_id`
already travels as part of the connection identity:
`conn.Config` / `conn.Identity` carry `NodeID` alongside
`CookiesFile` and `VMID` (`internal/conn/gateway.go`). The wait
core adds no generation, persistence, or rotation anywhere:

- `Config.NodeID` is caller-supplied and carried through to
  `Result.NodeID`. The Runner never generates it, never persists
  it, never rotates it, and never sends it: the wait core has no
  send path (see SEAMS.md). An empty `NodeID` means the caller
  supplied none; the Runner invents nothing.
- The Waiter never sees `node_id` at all: `wait.py` contains zero
  occurrences, and the Go Waiter likewise has none. Waiting and
  replay logic never originate or alter it.
- Origin, validation, and persistence belong to the profile
  layer (PR3: read-only `LoadProfile`, generation only in
  `config migrate --write` and profile creation, env fill only
  for an absent key, never overriding, never writing). This
  branch references those rules; it does not re-implement them
  and must not import PR3-only APIs (see SEAMS.md).
- A retry or reconnect reuses the same value with a new
  transport `stream_id`: a sent `chat.stream` frame is never
  re-sent (see SEAMS.md §G8). The value survives every
  reconnect because the config file survives; a fresh process
  re-reads the same file.

## Unknown (do not assume)

What the server does with `node_id` is NOT established from code:
ignored, attribution key, or dedupe/uniqueness key are all
compatible with the client source. Settling evidence required:
redacted web-app traffic trace, or a controlled live experiment,
or an explicit recorded Boss decision. Until then, preserve the
client behavior byte-for-byte and build no server assumption into
reconnect, retry, or dedupe logic.

## What breaks if the wrong reading is chosen

- **Regenerating per turn / per process / per stream (treating
  `tempNodeID()` as the model for real sends):** the persisted
  identity becomes unstable. Every config reload would see a
  changed identity triple and drop the warm connection; any
  server-side attribution/dedupe keyed on `node_id` would see
  each turn as a new client — risking misattributed turns, lost
  continuity, or duplicate delivery. Restarts would mint new
  identities, and debugging "which client sent this" from logs
  would be impossible.
- **Assuming the server ignores it and dropping/omitting it:** if
  the attribution or dedupe reading holds, sends may be
  rejected, misrouted, or deduplicated incorrectly. The field is
  present in both Python send sites without exception; omitting
  it is a wire-format change with no evidence behind it.
- **Assuming the server validates uniqueness and adding a
  per-turn suffix/nonce:** if the server keys on the exact
  persisted value, suffixed values look like foreign clients; if
  it dedupes, the suffix defeats dedupe. Either way it invents a
  wire behavior the code does not show.
- **Sharing one `node_id` across profiles (global singleton):**
  violates the per-profile file scope; conflates distinct
  profiles' client identities server-side and weakens the reload
  triple (profiles would then differ only by cookies file).
  Copying a config file between profiles already copies the
  value — that is a Python behavior to preserve knowingly, not
  a pattern to extend.
- **Generating + persisting on read (Python's `load_config`
  behavior) in Go read paths:** PR3 forbids this by design
  (read-only `LoadProfile`; generation only in `migrate
  --write`). Doing it would be a surprise write and would
  diverge the Go port from its own documented contract.
- **Building security/authorization on `node_id`:** nothing in
  code shows any client- or server-side check on it. Treating it
  as an authenticator would be inventing a security property.
- **Replaying a sent `chat.stream` with the same `node_id` to
  "recover" a turn:** Python never replays a transmitted stream;
  PR3's gateway doc forbids re-sending. A replay could
  double-deliver the user's message if the server does not
  dedupe — the safe recovery is ack-poll + wait.

## Sources

- Python 0.6.1: `cli.py:151-175` (origin/precedence),
  `chat.py:98-99` and `cli.py:973-999` (the two send sites),
  `conn.py:115` (identity triple). `wait.py` and `gateway.py`
  contain zero occurrences.
- PR3 (reference only, do not edit/import):
  `internal/commands/runtime.go` (`tempNodeID`),
  `internal/profile/config.go` / `migrate.go` (read-only load,
  generate-on-migrate), `internal/conn/gateway.go`
  (`conn.Identity`).
- Survey: `~/workspace/tmp/pr4prep-research/node-id-survey.md`
  (occurrence census 5/5, decision §6, draft text §7 reused
  above and extended with the Go mapping).
