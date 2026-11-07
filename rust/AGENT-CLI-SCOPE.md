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

## Measured (cue, this change only — the plugin slice)

| Metric | Before | After |
|---|---|---|
| `castctl-rs` release binary | 37,549,240 B | 36,888,360 B (`-660,880 B`, `-1.76%`) |
| `castctl-pluginhost` compiled | yes | no (out of the workspace) |
| Command table | 46 | 45 |
| Parity argv cases | 62 | 61 |
| `cargo clippy -p castctl-cli -p castctl-rs --all-targets -- -D warnings` | — | exit 0 |
| `cargo test -p castctl-cli -p castctl-rs` | — | 4 suites, 238 passed, 0 failed |
| `cargo fmt --check` | — | exit 0 |

Rust dependency footprint before the removals (own dep-tree lines,
`cargo tree -e normal`): `castctl-telegram` 344, `castctl-webui` 99,
`castctl-pluginhost` 85, whole `castctl-rs` 213 unique.
Release build baseline on cue: 186 s, 213 deps.

## Sequence

1. **plugin** — done in this change (`feat/rust-agent-cli-only`).
2. **webui** — needs one seam move first: `chat` uses
   `castctl_webui::chats::ChatDeps` (`castctl-cli/src/run.rs::failing_chat_deps`),
   so the chat seam must move to a kept crate before the `webui` command and
   the `castctl-webui` dependency can go.
3. **telegram bot** — needs one seam move first: `send`, `wait` and `chat`
   use `castctl_telegram::wait::{Reply, WaitKind, Widget, ApproveError}` and
   `castctl_telegram::Approval`, so the reply/approval model must move to a
   kept crate (`castctl-wait` is the natural home) before the bot runtime goes.

Ordering constraint: PR #94 (`feat/rust-m7g-keeper-times`) edits
`castctl-webui/src/keeper_status.rs`. Merge #94 **before** removing
`castctl-webui`, otherwise the keeper-time fix has to be re-applied by hand.

## Open gaps in the kept surface (finish-the-logic backlog)

Measured on cue 2026-11-07, Rust vs Go, same live profile/config:

| Gap | Evidence | Note |
|---|---|---|
| `usage` is slow | 127.6 s / 88.4 s (Rust) vs 21.8 s / 28.0 s (Go); one 60 s timeout | The only agent-facing command with a large, reproducible gap. Investigate before anything cosmetic. |
| `update` on an unstamped build | Rust exit 1 vs Go exit 0 for `--dry-run` | `PORTING.md` §M7b records it; decide whether to match or to document Rust-only behaviour. |
| `wait` reply delivery | M7c recorded `replies: []` on both sides — narrows the claim | Needs a live turn where the reply actually arrives. |

Everything else in the kept surface is live-parity verified: 14 read-only
commands byte-identical to Go on cue, keeper (tick, expiry, CDP re-export)
byte-identical, 109-case argv sweep `DIFFS=0`.
