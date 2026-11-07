# Scope decision — the Rust port is an agent-facing CLI only

Status: **active** (Boss decision, 2026-11-07). Supersedes the "port every
Go surface" reading of the M-series milestones for the three surfaces named
below.

## Decision

The Rust artifact (`castctl-rs`) exists to be driven **by the agent over the
CLI**. Three Go surfaces are dropped from the Rust port:

| Dropped | Why it is not in the Rust CLI |
|---|---|
| `webui` (HTTP server, browser UI) | A human/browser surface. The agent never needs it, and it is the only place the port still reports a real divergence (`go_version` / `singbox_version` = `"unknown"` in `/status`) that parity work cannot close without porting Go's build metadata. |
| `telegram` (bot runtime) | A human chat surface. Binary-vs-binary parity is impossible to prove (rustls trusts webpki roots only, `SSL_CERT_FILE` ignored), so this surface can never be verified the way the rest of the port is. |
| `plugin` (plugin host + `__plugin-worker`) | An extensibility surface whose Go behaviour is a process-killing in-process loader; the Rust port deliberately diverges (subprocess worker, survives a segfault). Keeping a surface whose *correct* behaviour is a documented divergence buys nothing for agent use. |

Consequences:

- **No new Go-parity work** is scheduled for those three surfaces. Their
  remaining deviations stay recorded in `PORTING.md` and are not to be
  closed.
- The **config parser keeps accepting** the `webui` / `telegram` / `plugins`
  blocks: existing config files must keep loading, and the same config is
  shared with the Go binary. Dropping a command is not dropping a config key.
- Effort moves to *finishing the logic* of the kept surface, cheapest first
  (see "Open gaps" below).

## Kept surface

Crates that remain in the workspace and ship in the binary: `castctl-rs`,
`castctl-cli`, `castctl-config`, `castctl-shared`, `castctl-log-redact`,
`castctl-logging`, `castctl-transport`, `castctl-gateway`, `castctl-keeper`,
`castctl-approvals`, `castctl-fsclient`, `castctl-deliver`, `castctl-update`,
`castctl-wait`, `castctl-dns`, `castctl-tg-text`, `castctl-tg-files`
(the last two are text/attachment formatting used by `send`, `chat`, `wait`,
not the bot runtime).

Commands kept: everything except `webui`, `telegram`, `plugin` — 45 of Go's
46 (`rust/castctl-cli/src/table.rs` `COMMAND_ORDER`).

## Measured (cue, 2026-11-07, three slices on `feat/rust-agent-cli-only`)

Baseline = `dev-rust` `fd3eb1c` before any slice. Every number below was
produced on cue, not on the Debian host.

| Metric | Baseline | After plugin | After webui | After telegram |
|---|---|---|---|---|
| `castctl-rs` release binary | 37,549,240 B | 36,888,360 B | 34,381,344 B | **31,336,448 B** |
| Delta per slice | — | `-1.76%` | `-6.80%` | `-8.85%` |
| Command table (`COMMAND_ORDER`) | 46 | 45 | 44 | **43** |
| Parity argv cases | 62 | 61 | 60 | **59** |
| Crates built | 20 | 19 | 18 | **17** |

Cumulative: **`-6,212,792 B`, `-16.55%`** of the release binary.

Gates on the final tree (`castctl-telegram` and `castctl-pluginhost` deleted,
`castctl-webui` out of the workspace):

- `cargo fmt --check` exit 0.
- `cargo clippy -p castctl-cli -p castctl-rs -p castctl-wait --all-targets -- -D warnings` exit 0.
- `cargo test --workspace` — 54 suites, **1214 passed, 0 failed**. (Not
  comparable with the pre-decision 66 suites / 1703 tests: the three dropped
  crates took their own tests with them.)
- Live parity of the kept surface with Go `0.9.0 (1396697 …)` on the same
  live profile: `status`, `threads --all`, `history --limit 3`, `auth status`,
  `goals`, `ideas`, `unread`, `feed-status`, `files --limit 3`,
  `profile list`, `usage` — **11/11 byte-identical**.
- Dropped commands: `castctl plugin check …`, `castctl webui serve`,
  `castctl telegram run` each exit 2 with `invalid choice`, and the top-level
  help lists 43 names.

Kept on purpose:

- the `webui` / `telegram` / `plugins` **config blocks** still parse — the
  config file is shared with the Go binary;
- the keeper's Telegram **notice sender** (`castctl-cli/src/keepercmd.rs`,
  `api.telegram.org` over the profile outbound): keeper logic, never used the
  bot crate;
- `castctl-tg-text` / `castctl-tg-files`: message text and attachment
  formatting used by `send`, `wait`, `chat`.

## Sequence (done)

1. **plugin** — `be10656` / `f1b6913` after rebase.
2. **webui** — `82178f2` / `26df4a9`. No seam move was needed after all:
   `castctl_webui::chats::ChatDeps` was only consumed by `serve_webui`
   itself, so the whole command could go in one step.
3. **telegram bot** — `33d9acf` / `462c654`. The reply/approval model
   (`wait.rs`, `approvals.rs`, `error.rs`) moved into `castctl-wait`, which
   the CLI already used; `send`/`wait`/`chat` kept their behaviour.
4. **crate trees** — `45911d5`: `castctl-telegram` and
   `castctl-pluginhost` deleted (34,710 lines).

Still to delete: `castctl-webui/` (left on disk, out of the workspace) —
PR #94 edits `castctl-webui/src/keeper_status.rs` and `handlers.rs`, so
deleting it before #94 lands makes that PR unmergeable. Delete it right after
#94 merges. Note that #94's keeper-time fix itself lives in
`castctl-keeper` + `castctl-shared`, so the keeper half survives the deletion;
only its webui mirror becomes moot.

## Kept surface: what is verified now (cue, 2026-11-07/08)

| Area | Evidence |
|---|---|
| Read-only commands | 11/11 **byte-identical** to Go `0.9.0 (1396697 …)` on the live profile: `status`, `threads --all`, `history --limit 3`, `auth status`, `goals`, `ideas`, `unread`, `feed-status`, `files --limit 3`, `profile list`, `usage`. |
| Write commands | `session-pin`, `session-unpin`, `session-rename`, `approvals` byte-identical to Go on the same live session; `seen` identical apart from its `seen_at_ms` timestamp (two runs, one second apart). |
| Send + wait round trip | Live: `session-start` → `send … --wait 150 --text` exit 0, stdout `user_seq=29401 [29402] pong-from-castctl-rs`, stderr `-- done (status=completed)`. Reply delivery — the M7c gap — is **proven**. |
| `update --dry-run` | Rust and Go both exit 0 with `castctl is up to date: 0.9.0` on a stamped build. |
| Deterministic argv sweep | `TOTAL=101 DIFFS=0 skipped_live=9 skipped_dropped=8` — the 8 skips are the dropped commands plus the top-level `--help`. |
| Gates | `cargo fmt --check` 0, `cargo clippy … -D warnings` 0, `cargo test --workspace` 55 suites / 1220 passed / 0 failed. |

## `usage` — closed (was the only large gap)

`usage` was 39–60 s against Go's 13 s. Three measured causes, all fixed in
`bed453d`:

1. **No connection pool** in `castctl-transport` (a documented M3
   simplification): every one of the 547 chunk fetches dialled and
   TLS-handshaked. `HttpClient` now keeps up to 16 idle sockets per
   target, drops them after 90 s, never pools a `Connection: close` reply,
   and retries once on a fresh socket when a pooled one is dead — only
   when the request was never written (`hyper::Error::is_closed`), so no
   POST is replayed.
2. **No `Accept-Encoding: gzip`** where Go's transport adds it: the scan
   pulled ~37 MB of JS instead of ~11 MB. Now advertised unless the caller
   sets the header, decoded on the way out, header stripped like Go, and
   the 16 MiB cap is enforced **after** decompression.
3. **Batch-then-scan** in `find_action_id`: it fetched a 400-file batch
   before looking for the action id. It now consumes fetches as a stream
   and returns on the first match.

Wall time on cue, live profile, `usage`: 41–47 s → 22–29 s → **10.0–18.0 s**
(Go 12.9–26.1 s in the same windows), output byte-identical throughout.
Covered by `castctl-transport/tests/http_pool.rs` (6 cases: reuse, close,
idle-dead retry, gzip decode + header strip, caller header wins, gzip bomb).

## Remaining work

| Item | State |
|---|---|
| Delete `castctl-webui/` (still on disk, out of the workspace) | Blocked on PR #94: it edits `castctl-webui/src/keeper_status.rs` + `handlers.rs`. Its keeper-time fix itself lives in `castctl-keeper` + `castctl-shared`, so the keeper half survives the deletion. |
| Keeper time rendering on this branch | This branch predates #94, so keeper state still renders UTC (`Z`) where Go writes the local offset. Merge/rebase #94 to close it; nothing else in the kept surface depends on it. |
| `update` on an **unstamped** build | Rust exit 1 vs Go exit 0; stamped builds match (verified). Dev-only path — decide later whether to align. |
