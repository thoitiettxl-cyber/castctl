# castctl

Browser-free content pipeline CLI: generate content with AI agents (starting with muse.ai), then publish it to social platforms (Facebook, TikTok, YouTube — planned).

Each profile has its own account session, outbound proxy (WireGuard, VLESS, SOCKS… via sing-box) and TLS fingerprint, all kept in one `config.json`.

Status: early development. The Go port of [muse-cli](https://github.com/thoitiettxl-cyber/muse-cli) (v0.6.1 is the behavioral reference) has been migrated here, keeping only the `go/` history.

- Contributors and coding agents: start at [AGENTS.md](AGENTS.md).
- Docs: [docs/](docs/).

License: GPL-3.0. See [LICENSE](LICENSE).

## Build and vet

All commands below run from the repo root.

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
go test -race -count=50 -shuffle=on -timeout 30m -tags with_utls,with_quic,with_wireguard,with_gvisor -v ./internal/gateway/
```

## Build tags

| Tag | Effect |
| --- | --- |
| `with_utls` | Enables uTLS (Chrome fingerprint) for gateway TLS. Without it, 6 subtests that construct a uTLS client are skipped **by design** (see below); the untagged suite is fully green. |
| `with_quic` | Enables QUIC transports (Hysteria/Hysteria2/TUIC/naive HTTP/3). |
| `with_wireguard` | Enables WireGuard endpoints. |
| `with_gvisor` | **Required** for WireGuard endpoints. Without it, `transport/wireguard/device_stack_stub.go` (`//go:build !with_gvisor`, sing-box v1.14.4) returns `tun.ErrGVisorNotIncluded` from both stack-device constructors. |

### Untagged build: 6 uTLS subtests skip by design

Running `go test ./internal/outbound/` without `with_utls` skips exactly
these 6 subtests (via the `skipUnlessUTLS` helper pair), which build a
uTLS client that the stub TLS implementation rejects — 4 subtests of
`TestBuildTLSConfig`: `default_chrome_server_name_and_alpn_passthrough`,
`server_name_falls_back_to_server_address`,
`reality_options_pass_through_untouched`, and
`handshake_against_fake_tls_server`; plus 2 dialer subtests:
`https_through_dialer_tls_uses_insecure_fake_server` (of
`TestDialerHTTPClient`) and `secure_websocket_dial_handshakes_tls` (of
`TestDialerWebSocketDial`). The error-expecting TLS subtests (e.g.
`unknown_fingerprint_is_an_error`, `reality_without_utls_is_an_error`)
still run untagged, because the stub error is the behaviour they pin.
This is expected, not a regression: run the canonical tagged command
above for full coverage.

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
material. Its path comes from the `CASTCTL_WG_CONF_PATH` environment
variable when set, defaulting to
`~/.config/castctl/secrets/wg-proton-usca420.conf` when unset or
empty. If the file is missing or unreadable (including a bad
`CASTCTL_WG_CONF_PATH` value), the test skips with a visible reason
naming the resolved path — it never fails the suite on a machine
without the conf.

## Licence headers

Every `.go` file under the repo root carries the SPDX header
`SPDX-License-Identifier: GPL-3.0-or-later` at the top (after any
build tags). The generated `*.pb.go` files get the same header from
`internal/proto/generate/generate.sh` on every regeneration; see
`internal/proto/generate/README.md`. A test (`spdx_test.go`)
fails the suite if any `.go` file lacks the header.

## CLI surface (PR3)

`cmd/castctl` dispatches through `internal/commands` with a
hand-rolled parser mirroring Python argparse (help text, errors,
exit 2 for bad usage). Every command honours the global flags
`--profile NAME` and `--config PATH` (see Config location below),
`--version` prints `castctl <version>`, and `--help` works globally
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
| Auth & profiles | `auth list`, `auth import` (stdin only, see below), `auth export` (guidance-only, exit 1), `profile list`, `profile show`, `profile add`, `profile rm`, `profile set-outbound`, `profile set-fingerprint`, `profile set-tls-engine`, `profile test`, `config migrate` |

Wired in PR4, on PR3's commands framework: `send`, `wait`,
`approvals`, `approve`, `deny`, `auto-approve`, bare invocation
(chat REPL).

Deferred (the parser names the PR; `--help` still works):

| Commands | Lands in |
| --- | --- |
| `telegram` (+ subcommands), `update` | PR5 |

`auth import` is implemented (added after PR3): `castctl auth import
[--profile NAME] < cookies.txt` reads cookies from stdin only and
replaces the active profile's cookies file. It accepts the three
forms `ParseCookies` parses (one-line `a=b; c=d`, Netscape jar, JSON
object), requires a parsed `hatch_sess` pair with a non-empty value,
and stores the input verbatim after CRLF/CR line-ending
normalisation, with a single trailing newline. The write is atomic
(temp file + rename) with the previous file kept as `cookies.txt.bak`;
both files are mode 0600. All import failures exit 2 and write
nothing; success prints value-free JSON
(`{"ok": true, "profile": ..., "cookies_file": ..., "backup": ...}`).
Import makes no network request (validate with `castctl status`
afterwards) and never creates a config entry. Concurrent imports are
last-writer-wins with no lock. No other new login flow is implemented
(no native endpoint login, no relay, no device-code/QR, no
paste-login); `auth export` only prints manual guidance and exits 1
without writing anything. The CLI-boundary recover exists in
Run (R2 decision): a panic anywhere on the dispatch path converts
to exit 2 with a redacted error message and no secret-bearing
stack; `auth import` is written to never panic on hostile stdin.

`auth list` fails closed when any profile config is unparseable:
it returns the config error instead of listing. Python 0.6.1 is
lenient here — `list_profiles` shows defaults for a profile whose
config it cannot parse — while the Go profile package fails closed
on a corrupt config and `auth list` does not second-guess it.

Read commands do not start the 25 s heartbeat: Python starts it only
on the wait/send/bot paths, and the Go port matches that. A failed
authentication never exits 0: auth failures print a one-line JSON
object with a `type` field on stderr
(`cookies_missing`, `session_unavailable`, `auth_check_failed`,
`hatch_token_failed`, `auth_failed`) and exit 2; gateway failures
exit 3; timeouts exit 4; `download` exits 3 on any row error.

## Config location

Precedence, highest first:

1. `--config PATH` (a file, not a directory; empty is an error).
2. `CASTCTL_CONFIG` (empty counts as unset).
3. The OS user config directory (`os.UserConfigDir()`, i.e. XDG on
   Linux): `<dir>/castctl/config.json`. A relative
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
dry run plans from a legacy-only layout, or from a `--from`
source into a new destination). `--profile` resolution
inside the resolved home is unchanged: `--profile` flag, then
`CASTCTL_PROFILE`, then `default_profile`, then `"default"`.

Legacy directory fallback: if the default `<dir>/castctl`
directory does not exist but `<dir>/muse-cli` does, the old
directory becomes `CONFIG_DIR` for the invocation and a one-line
warning is printed telling the user to move it. Nothing is moved,
copied, or deleted automatically. This applies only to the default
location: an explicit `--config` or `CASTCTL_CONFIG` still wins.
The legacy per-profile file layout inside the directory is a
separate matter: profile loading refuses a load for any profile
name WITHOUT a single-file entry in a layout containing a legacy
per-profile file (see `docs/config.md` for the exact boundary);
a name WITH a single-file entry loads wholly, unaffected by
leftover legacy files — run `castctl config migrate --write`
first (see `docs/config.md`).

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
— including `on` — with a config error.

Examples:

```sh
castctl --config /etc/castctl/config.json status
CASTCTL_CONFIG=~/work/castctl/config.json castctl threads
castctl profile show --config ./local/config.json
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
synthetic direct outbound for endpoint-tag profiles is the fixed tag
`castctl-dialer`, and the synthesised DNS-detour direct outbound for
a direct profile is the per-profile tag `castctl-direct:<name>` (see
docs/config.md, Per-profile DNS, for the gate-2 mechanism). The
isolation itself comes from the per-Manager registries — each
Manager builds its outbound, endpoint, and DNS-transport
registries on a fresh registry context — not from tag names: the
`profile:<name>` auto-tag and the `castctl-dialer` synthetic tag
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
agent-browser, or sandbox paths. No browser is assumed: the screencast-login browser dependency is
optional and runtime-detected, and the no-browser fallback is
`auth import`.

Release targets are Linux only: `linux/amd64` and `linux/arm64`,
dynamically linked (`CGO_ENABLED=1`) on a GLIBC 2.17 (manylinux2014)
baseline. Each architecture also ships a `_no-plugin` static build
(see Release assets below). The plugin loader is not implemented,
so neither build loads plugins. There are no Android, Windows, or
macOS builds.

### Release assets

- `castctl_<version>_linux_<arch>.tar.gz` is the default Linux build: dynamically linked against glibc, built against a GLIBC 2.17 baseline. The plugin loader is not implemented, so it does not load plugins.
- `castctl_<version>_linux_<arch>_no-plugin.tar.gz` is the portable Linux build for musl-based or older systems such as OpenWrt: statically linked (`CGO_ENABLED=0`). The plugin loader is not implemented, so it does not load plugins either.

`<arch>` is `amd64` or `arm64`. Each archive contains the `castctl`
binary plus `LICENSE`, `LICENSE.sing-box`, `NOTICE`, and `README.md`. When all
four builds succeed, the release also carries a `checksums.txt`
(SHA-256, sorted by file name) covering the four archives; it is
uploaded by the checksums job after the builds, so a release whose
builds fail may lack it.

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

## Wait core and approvals (PR4)

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
(design note; the REPL is wired in PR4),
`internal/wait/SEAMS.md` (driver contract, outbound Dialer
seam, PR3 cap/config constraints, gap disposition G1–G10,
documented deviations D1–D4).

## Deferred wiring (exact list)

Wired in PR4, on PR3's commands framework: `wait`, `send` (with
`--wait` / `--until-done`), the `chat.stream` + delivery-ack send
path, the `HistoryReader` production adapter, profile resolution +
`node_id` origin wiring, the chat REPL, `approvals` / `approve` /
`deny` / `auto-approve`, and the auto-approve stderr lines.

Still deferred:

- Telegram wiring (PR5) and the `update` command.
- Approval claim coordination between a monitor and a turn
  (the 15 s in-flight claim wait): a driver/monitor concern,
  not part of `AutoApprover`; PR5 Telegram territory.
- Anything needing PR3's commands framework.
