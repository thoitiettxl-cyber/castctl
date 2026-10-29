# muse-cli Go port

Go port of the Python `muse-cli` (module `github.com/thoitiettxl-cyber/muse-cli/go`).
All commands below run from this directory (`go/`).

## Build and vet

```sh
go build ./...
go vet ./...
```

## Tests

Canonical test command (with all feature tags, race detection on):

```sh
go test -race -tags with_utls,with_quic,with_wireguard,with_gvisor ./...
```

### Flake loop

Repeat the gateway package 50 times with shuffling when hunting flakes.
The loop needs `-timeout 30m`: the full-package 50x run took 648s, past
the default 10-minute `go test` timeout.

```sh
go test -race -count=50 -shuffle=on -timeout 30m -v ./internal/gateway/
```

## Build tags

| Tag | Effect |
| --- | --- |
| `with_utls` | Enables uTLS (Chrome fingerprint) for gateway TLS. Required: without it, the untagged build fails 4 TLS subtests **by design** (see below). |
| `with_quic` | Enables QUIC transports (Hysteria/Hysteria2/TUIC/naive HTTP/3). |
| `with_wireguard` | Enables WireGuard endpoints. |
| `with_gvisor` | **Required** for WireGuard endpoints. Without it, `transport/wireguard/device_stack_stub.go` (`//go:build !with_gvisor`, sing-box v1.14.4) returns `tun.ErrGVisorNotIncluded` from both stack-device constructors. |

### Untagged build: 4 TLS subtests fail by design

Running `go test ./internal/outbound/` without `with_utls` fails exactly
these 4 subtests of `TestBuildTLSConfig` (verified 2026-10-29 in the PR2
worktree): `default_chrome_server_name_and_alpn_passthrough`,
`server_name_falls_back_to_server_address`,
`reality_options_pass_through_untouched`, and
`handshake_against_fake_tls_server`. They build a uTLS config, which the
stub TLS implementation rejects. This is expected, not a regression: run
the canonical tagged command above.

## Binary sizes (PR3 measurements, linux/amd64)

Measured in PR3, same flags as PR1:
`CGO_ENABLED=0`, `-trimpath`, `-ldflags '-s -w -buildid='`.
The command tree now imports the full command packages (PR1
measured a version/help-only binary: 34,574,460 / 38,985,852 /
43,053,180 for the same three tag sets).

| Tag set | Size (bytes) |
| --- | --- |
| `with_utls` | 35,782,780 |
| `with_utls,with_quic,with_wireguard` (+quic+wireguard) | 40,153,212 |
| `with_utls,with_quic,with_wireguard,with_gvisor` (+gvisor) | 44,220,540 |

No size budget is set; the numbers are recorded only.

## Bootstrap DNS lookup

`outbound.BootstrapLookup` (`internal/outbound/bootstrap.go`) is the
sole exception where a DNS server's own hostname is resolved via the
system resolver (`net.DefaultResolver`, 5 s timeout). It resolves the
hostname once, before that server can be used; the DNS package
substitutes the first IPv4 address (else the first address) for the
hostname and preserves the original hostname as the TLS ServerName
when TLS options exist with an empty ServerName. The lookup is
debug-logged with the hostname and the address count only — never the
resolved values.

Fail-closed boundary: bootstrap applies only to the DNS server's own
hostname. Every other lookup goes through the configured DNS server
and the outbound/detour that server is configured with; DNS failure
is an error, and there is no system-resolver fallback for any other
host. A bootstrap failure is a construction error, never a silent
fallback.

Recommendation: configure DNS servers by IP address to avoid the
bootstrap lookup entirely. An IP-address server needs no bootstrap
lookup at all, so the system resolver is never consulted.

## Real WireGuard conf test

`TestParseRealWireGuardConfRuntime`
(`internal/outbound/wireguard_conf_test.go`) reads a real wg-quick
conf at runtime only, asserts shape only, and never logs key
material. Its path comes from the `MUSE_CLI_WG_CONF_PATH` environment
variable when set, defaulting to
`~/.config/muse-cli/secrets/wg-proton-usca420.conf` when unset or
empty. If the file is missing or unreadable (including a bad
`MUSE_CLI_WG_CONF_PATH` value), the test skips with a visible reason
naming the resolved path — it never fails the suite on a machine
without the conf.

## Licence headers

Every `.go` file under `go/` carries the SPDX header
`SPDX-License-Identifier: GPL-3.0-or-later` at the top (after any
build tags). The generated `*.pb.go` files get the same header from
`internal/proto/generate/generate.sh` on every regeneration; see
`internal/proto/generate/README.md`. A test (`go/spdx_test.go`)
fails the suite if any `.go` file lacks the header.

## CLI surface (PR3)

`cmd/muse-cli` dispatches through `internal/commands` with a
hand-rolled parser mirroring Python argparse (help text, errors,
exit 2 for bad usage). Every command honours the global flags
`--profile NAME` and `--config PATH` (see Config location below),
`--version` prints `muse-cli <version>`, and `--help` works globally
and per command.

Implemented in PR3 (Python 0.6.1 contract: flags, JSON shapes, exit
codes):

| Group | Commands |
| --- | --- |
| Status & subscription | `status`, `usage`, `invite`, `redeem` |
| Chat history | `threads`, `history`, `files`, `download`, `watch` |
| Feed | `feed`, `feed-status`, `feed-react`, `feed-prompt` |
| Goals & ideas | `goals`, `goal`, `ideas`, `idea`, `idea-exec` |
| Inbox | `unread`, `seen` |
| Sessions & control | `session-start`, `session-rename`, `session-pin`, `session-unpin`, `session-archive`, `session-unarchive`, `session-delete`, `stop`, `wake` |
| Low level | `raw` |
| Sandbox filesystem | `fs ls`, `fs tree`, `fs stat`, `fs cat`, `fs get`, `fs find`, `fs put`, `fs write`, `fs edit`, `fs mkdir`, `fs mv`, `fs rm` |
| Auth & profiles | `auth list`, `auth export` (guidance-only, exit 1), `profile list`, `profile show`, `profile add`, `profile rm`, `profile set-outbound`, `profile set-fingerprint`, `profile set-tls-engine`, `profile test`, `config migrate` |

Deferred (the parser names the PR; `--help` still works):

| Commands | Lands in |
| --- | --- |
| `send`, `wait`, `approvals`, `approve`, `deny`, `auto-approve`, bare invocation (chat REPL) | PR4 |
| `telegram` (+ subcommands), `update` | PR5 |

`auth import` is approved but ships after PR3. No new login flow is
implemented in PR3 (no native endpoint login, no relay, no
device-code/QR, no paste-login); `auth export` only prints manual
guidance and exits 1 without writing anything.

`auth list` fails closed when any profile config is unparseable:
it returns the config error instead of listing. Python 0.6.1 is
lenient here — `list_profiles` shows defaults for a profile whose
config it cannot parse — while the Go profile package fails closed
on a corrupt config and `auth list` does not second-guess it.

Read commands do not start the 25 s heartbeat: Python starts it only
on the wait/send/bot paths, and the Go port matches that (heartbeat
belongs to PR4/PR5). A failed authentication never exits 0: auth
failures print a one-line JSON object with a `type` field on stderr
(`cookies_missing`, `session_unavailable`, `auth_check_failed`,
`hatch_token_failed`, `auth_failed`) and exit 2; gateway failures
exit 3; timeouts exit 4; `download` exits 3 on any row error.

## Config location

Precedence, highest first:

1. `--config PATH` (a file, not a directory; empty is an error).
2. `MUSE_CLI_CONFIG` (empty counts as unset).
3. The OS user config directory (`os.UserConfigDir()`, i.e. XDG on
   Linux): `<dir>/muse-cli/config.json`. A relative
   `XDG_CONFIG_HOME` warns on stderr and falls back to the default;
   an empty one falls back silently.

The directory containing the resolved `config.json` is `CONFIG_DIR`
for the whole invocation: `config.json.lock`, `profiles/<name>/`,
the default cookies file, `chat.json`, telegram files, and the global
`update.json` all live under it. A relative `--config` path is
resolved against the current directory (no tilde expansion);
the config file is opened through a symlink with standard open
semantics, and `CONFIG_DIR` is the cleaned as-given directory:
symlinks are NOT resolved. A missing explicit `--config` file exits 2, except
`config migrate` (which may create it with `--write`, and whose
dry run plans from a legacy-only layout). `--profile` resolution
inside the resolved home is unchanged: `--profile` flag, then
`MUSE_CLI_PROFILE`, then `default_profile`, then `"default"`.

Per-key relative paths inside a profile config: only `cookies_file`
is resolved, relative to `CONFIG_DIR`; an absolute value is kept
as-is. `vm_id`, `node_id`, `subscription_action_id`,
`auto_approve`, `auto_allow_once`, `default_profile`,
`fingerprint`, and `tls_engine` are not paths. The `outbound`,
`outbounds`, `endpoints`, and `dns` objects are opaque sing-box
configuration passed through verbatim: path-like fields inside
them (if any) are resolved by sing-box relative to the working
directory, not to `CONFIG_DIR`. This differs from Python 0.6.1,
which keeps `cookies_file` as-is (resolved against the working
directory when opened); the Go resolution is deliberate.

Single-file `auto_approve` rejects any value outside `always`/`off`
— including `on` — with a config error, while the legacy layout
coerces `on` to `off`.

Examples:

```sh
muse-cli --config /etc/muse-cli/config.json status
MUSE_CLI_CONFIG=~/work/muse-cli/config.json muse-cli threads
muse-cli profile show --config ./local/config.json
```

## Profile isolation

One `outbound.Manager`, one `dns.Client`, and one Dialer per profile
per invocation: `defaultBuildRuntime` constructs all three fresh on
every call and closes them in reverse order when the command ends.
There is no package-level or shared Manager/Dialer/DNS state in
`internal/commands` — the only package-level values are immutable
registries (the command table, flag definitions, help texts)
populated once by `init()` and read-only afterwards, plus one
fresh-per-call random `tempNodeID` that is never written to disk.
Inline outbounds without a tag are auto-tagged `profile:<name>`, so
each profile's inline stack lives in its own tag namespace; the
synthetic direct outbound is the fixed tag `muse-cli-dialer`. The
isolation itself comes from the per-Manager registries — each
Manager builds its outbound, endpoint, and DNS-transport
registries on a fresh registry context — not from tag names: the
`profile:<name>` auto-tag and the `muse-cli-dialer` synthetic tag
are naming conventions inside that registry, not the isolation
mechanism. No
ambient proxy detection exists anywhere in the commands layer:
proxy environment variables are read only when the user explicitly
passes `profile add --outbound-from-env`, and that read itself lives
in the profile library (`profile.OutboundFromEnv`), never in command
dispatch. The concurrent two-stack isolation proof (two
Managers/Dialers live at once, distinct egress) lives with the
isolation writer in `internal/outbound`/`internal/dns`; this package
only guarantees the fresh-per-invocation construction it rests on.

## Fingerprint and TLS engine (hold)

`fingerprint` (chrome, firefox, ios, safari; default chrome) and
`tls_engine` (cronet, stdlib, utls; default utls) are **stored and
validated only** in PR3. The runtime is unchanged: gateway TLS stays
uTLS Chrome, and the WebSocket stays gorilla + uTLS. No cronet code
is wired. The default is `utls` on every platform; `cronet` is an
opt-in build flavour for later (tag `with_cronet` plus a
hash-verified sidecar), only after a direct probe matches or comes
close to real Chrome of the same version. The `random`/`randomized`
uTLS preset exists in sing-box but is rejected: it is never accepted
as a fingerprint value. `profile test` reports the stored
fingerprint and the User-Agent used. Both are recorded-only
values: the result carries a `note` field stating that the
runtime always uses uTLS chrome until the TLS engine decision
lands.

Background: sing-box v1.14.4 documents uTLS as "Not Recommended"
(repeated fingerprinting vulnerabilities; it cannot really
replicate BoringSSL/NSS and lacks maintenance). Do not rely on uTLS
long-term and do not lock later fingerprint work on it; the
per-profile `tls_engine` setting exists so the engine can change
without changing stored profiles.

## Login-browser local inbound (binding constraint for a later PR)

Record only: PR3 builds no local-inbound or browser code. A later PR
(the screencast login flow) that runs a login browser MUST satisfy
all of the following — they are a binding constraint on that PR, not
an aspiration:

- The browser's local inbound binds `127.0.0.1` on an OS-assigned
  port (`:0`): a fresh listener, per profile AND per session.
- The inbound carries AUTH: a random username and password generated
  per session, so another profile — or another process on the same
  machine — cannot use the listener.
- The listener is closed when the session ends.
- Never a fixed port, never `0.0.0.0`.

No code in this PR implements, assumes, or depends on such an
inbound.

## Platforms

Portable code only: paths come from `os.UserConfigDir()` plus the
config-location rules above; no hard-coded home directory, launcher,
agent-browser, or sandbox paths. The port targets Debian/server
Linux, rooted Android (Termux/KernelSU, arm64), Windows, and macOS.
No browser is assumed: the screencast-login browser dependency is
optional and runtime-detected, and the no-browser fallback is
`auth import` (after PR3).

Cross-compile matrix, measured in PR3 (compile-only, no execution;
`CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -buildid='
./cmd/muse-cli`, Go 1.27.3). All ten combinations compile.

| Target | `with_utls` (bytes) | Canonical 4 tags (bytes) |
| --- | --- | --- |
| linux/amd64 | 35,782,780 | 44,220,540 |
| linux/arm64 | 33,226,876 | 41,156,732 |
| android/arm64 | 37,552,386 | 46,465,282 |
| windows/amd64 | 35,538,944 | 43,959,296 |
| darwin/arm64 | 32,602,898 | 40,906,098 |

Canonical tags: `with_utls,with_quic,with_wireguard,with_gvisor`.
An untagged linux/amd64 build also compiles (35,545,212 bytes);
its TLS subtests fail by design (uTLS needs `with_utls`). No
target-specific feature gap was found at compile time beyond the
tag-gated ones: WireGuard endpoints need `with_gvisor` (a stub
returns a clear error without it), QUIC transports need
`with_quic`, uTLS needs `with_utls`. Execution on non-linux
targets is untested.

Guarded writes fail closed on Windows: flock is unsupported off
unix (`flock_other.go` always errors), so `profile add`, `profile
rm`, `profile set-*`, and `config migrate --write` fail there
instead of running unlocked. Cross-compilation for Windows
requires COMPILE only; reads and `config migrate` dry-runs still
work, since they take no lock.

## Gateway frame reassembly caps

Deliberate Go-only fail-closed hardening ordered by Boss, NOT
parity — Python 0.6.1 has no cap: `join_chunks`
(`gateway.py:83-93` in the read-only 0.6.1 copy) grows an unbounded
`_partial` dict, and `download_file` joins every frame of a request
with no total bound. One reassembled message is capped at
`MaxReassembledSize` (64 MiB — 16x the 4 MiB `fs.read` window in
`fs.py:16`, over 3x the 20 MiB Telegram download cap in
`tgapi.py:20`, above the 49 MiB upload cap in `tgapi.py:19`), and
at most `MaxUnfinishedGroups` (16) unfinished `chunk_id` groups are
held (the single sequential reader normally holds exactly 1; 16 is
16x headroom for interleaved sends). One group holds at most
`MaxPiecesPerGroup` (32768) distinct pieces: the size cap counts
bytes, so it cannot bound a group of empty (size 0) pieces, and
the piece-count cap is what makes it effective (29.3x the 1119
full-size pieces a 64 MiB message needs at `SendPiece` chunking;
see `framing.go` for the computation). Exceeding the size cap fails
with a typed `*ReassemblySizeError`, exceeding the groups cap
with a typed `*TooManyUnfinishedGroupsError`, and exceeding the
piece-count cap with a typed `*TooManyPiecesError`; either way the group
is discarded and the reader keeps reading, so other streams on the
same gateway keep working. A chunk_id carries no stream id until
it reassembles, so with several streams open the error reaches
all of them; the single-stream case is exact. (Source:
`internal/gateway/doc.go`.)

## Wait core and approvals (PR4 prep)

`internal/wait` is a verbatim port of Python `wait.py` turn-end
detection (spec: `~/workspace/tmp/pr4prep-research/wait-semantics.md`):
DONE/FAILED/suspect vocabularies, root-learning, ignored-terminal
settle, replayed-failed accept, `RepliesAfter` self-referential
filtering + widget/media rules, `NeedsInputReason` with all 34
waiting phrases, exits 0/2/4/124, watchdog/recheck/final-read
bounds, fail-closed 124 on final-read failure, monotonic
deadlines everywhere. `internal/approvals` is the pure port of
the shared `choose_auto_decision` (forever if offered, else
allow-once only with the fallback on; never `options[0]` /
session / today) plus `AutoApprover` (fresh connection per
`Approve` call, decide at most once per item, never retries
`egress.approval.decide`). Both packages are tested against
the PR2 `gatewaytest` fake harness and `testing/synctest`;
timing tests use a fake clock, never wall-clock sleeps.

Package docs: `internal/wait/NODE_ID.md` (stable per-profile
`node_id` decision), `internal/wait/CHAT-REPL-DESIGN.md`
(design only — the REPL needs PR3's commands framework),
`internal/wait/SEAMS.md` (driver contract, outbound Dialer
seam, PR3 cap/config constraints, gap disposition G1–G10,
documented deviations D1–D4).

## Deferred wiring (exact list)

Deliberately NOT wired on this branch — the wiring PR (after
PR #5 merges, on PR3's commands framework) owns these:

- CLI command wiring: `wait`, `send --wait`, `send --until-done`
  (and their flags: `--after-seq`, `--timeout`, `--auto-approve`,
  `--auto-allow-once`).
- The send path: `chat.stream` body + delivery-ack poll
  (`user_ack`, exit 5 on no ack).
- The chat REPL code (design in
  `internal/wait/CHAT-REPL-DESIGN.md`).
- The `HistoryReader` production adapter (reads `has_more`
  from the `chat.history` envelope; `conn.Muse.History` drops
  it and cannot back the interface alone).
- Profile resolution and `node_id` origin (PR3 config-location
  rules; read-only loads never generate `node_id`).
- Telegram wiring (PR5) and the `update` command.
- Approval claim coordination between a monitor and a turn
  (the 15 s in-flight claim wait): a driver/monitor concern,
  not part of `AutoApprover`.
- Anything needing PR3's commands framework.
