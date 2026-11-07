# End-to-end test plan — castctl core

Status: scripted, runnable by the operator on their own machine.
Script: `scripts/e2e.sh`. Base: `origin/main` `2a3c1fa` (PR #21).
No Go core change belongs to this item; a real bug found by the
script is reported first, never fixed silently here.

## What it proves

One runnable pass over the whole core, with one PASS/FAIL/SKIP
verdict per check and a counts-only secret scan at the end:

| # | Leg | What is checked |
|---|-----|-----------------|
| 1 | Profile test | `profile show` + `profile test` JSON phases: `dns.ok`, `https.ok`, `gateway.ok`, `dns.source` in its closed enum. Egress failure (`egress_ip: null` + warning) is non-fatal by design and is SKIP-recorded, never a PASS for a check that did not run. Capture files use hashed names, never the raw profile name (a `/` in a name must not break the run). |
| 2 | Send / wait | Offline: conflicting toggles exit 2. Live (`--live-send` only): one probe message, `delivered=true`, `user_seq` present, outcome in the closed set; re-wait with `--after-seq`. |
| 3 | Approvals | `auto-approve status` shape; env override wins without writing; invalid env value exits 2; `approve` with no id exits 2; `auto-approve on` persists on a throwaway copy (mode stays 0600). Live listing is shape + count only; deciding a pending approval is manual, never automated here. |
| 4 | Watch | Bounded run, clean exit 0 on idle timeout, every row JSON with `event` + `seq`. An unseeded window SKIP; zero rows in a seeded window SKIP, never PASS. |
| 5 | DNS | `profile test` DNS phase fields (stdout and stderr both checked for the sandbox string); `config migrate` dry-run (SHA-256 captured before the run and compared after — a vacuous same-file comparison is not a check); empty per-profile `dns: {}` fails at runtime construction (exact construction error unpinned — any non-zero exit is asserted, see below); profile `dns` + top-level `dns` together exit 2 naming `dns` (G1). No resolver is re-implemented. |
| 6 | Outbounds / WireGuard | Shape only, from the config copy: tags unique, `wireguard` in `outbounds[]` rejected, duplicate tag rejected, WireGuard endpoint field presence/type/counts only. **Never** a key value. Key-sharing error with fake key material must name tags but not the value. Liveness is leg 1's gateway phase only — no no-dial WireGuard liveness command exists. |
| 7 | Logging | Off-gate (no block + no flag = one typed JSON stderr line); file output created mode 0600 (content not asserted on a failing run); `disabled: true` creates no file; `--log-level trace` override with the typed JSON last; no `--trace` flag; invalid level exits 2 without echoing the value; log output equal to the config file is refused. Live-success log content is [NEEDS-MEASUREMENT]. |
| 8 | Telegram | `telegram status` offline JSON (`configured`, `token_valid`); bounded `telegram run` until SIGINT (exit 130). One chat turn, one approval allow, one approval deny, and `/autoapprove` persistence across a restart are manual, [NEEDS-MEASUREMENT]. See the token-source rule below. |
| 9 | Update | Unstamped refusal (exit 2, fixed message) is the PASS-able check for a script-built binary. A stamped `--dry-run` is SKIP with reason when unstamped. A non-dry-run update is never run. |
| 10 | Keeper | `keeper status` (state files only). `keeper check` can rewrite cookies, so it stays dry/SKIP on real profiles unless `--live-keeper` is given; exit 3 (entry stopped) is a distinct SKIP outcome, never a healthy PASS. `session-state.json` is checked at the per-profile path the keeper actually writes, `profiles/<name>/session-state.json`, mode 0600 when present. Real CDP re-export and single-flight refusal are [NEEDS-MEASUREMENT]. |
| 11 | Web UI | Loopback bind verified via `ss` (supplementary evidence; castctl itself validates loopback); a non-loopback `listen` key in the config copy exits 2 naming the loopback rule, without echoing the address (the listen check is parse-time and runs before the token check when a `webui` block exists; without a block the block gate fires first and the probe SKIPs); no-token and wrong-token both 401, good token 200 with `data.remote_exposure: false` (all success bodies are read under the `data` envelope); the block token is hashed with bcrypt and written back on serve start (the stored value is a hash, never the plaintext); `GET /config` carries `<redacted>` markers at secret positions; `GET /settings/telegram` masked exactly `***` only when `data.configured` is true (unconfigured → SKIP); `/logs` gate `reason` compared against the config (closed enum: `logging_disabled`, `log_output_not_file`, `log_output_refused`); the server process itself (not a wrapper subshell) is killed and the port is verified closed after the leg. External-connect refusal is [NEEDS-MEASUREMENT]. |
| 12 | Secret scan | Counts only over captured outputs (Scope A). See below. |

## Interface

```sh
scripts/e2e.sh --config PATH <profile>... [--live-send] [--live-keeper] [--binary PATH] [--help]
```

- `--config PATH` (required) must name an existing `config.json` file.
- `<profile>...` (required, at least one) are the only profile names
  the script ever uses. No profile name is hardcoded anywhere in the
  script or this document; examples below use `<profile>` placeholders.
- `--live-send` (opt-in) sends one real probe message per profile:
  `castctl e2e probe (no action needed)`. Without it, legs 2 and 4
  and the approvals live listing SKIP with a reason. Review the probe
  text before running with `--live-send`.
- `--live-keeper` (opt-in) allows the keeper legs that would rewrite
  cookies to run. Without it, those legs stay dry/SKIP with a
  reason, and any change to a cookies original (content, mtime, or
  a new/vanished `.bak`) is FAIL. `--live-send` does NOT imply
  `--live-keeper`.
- `--binary PATH` (optional) tests a given binary. Without it, the
  script builds one from this checkout with tags
  `with_utls,with_quic,with_wireguard,with_gvisor,with_chromedp`.
  A build failure is FAIL, not SKIP.
- `--help` / `-h` prints the usage text and exits 0.
- The Telegram token comes only from the environment:
  `CASTCTL_TELEGRAM_TOKEN`. It is never taken from argv and never
  embedded in the script or this document. The web UI token is
  generated inside the script and injected into the temp config
  copy's `webui` block (never echoed, never written outside the
  temp dir); there is no environment token source for the web
  UI.
- Exit code is non-zero if any check FAILs. SKIP alone does not fail
  the run; the summary lists every SKIP with its reason.

## Prerequisites

| Prerequisite | If missing |
|---|---|
| `bash`, `python3`, `sha256sum`, `stat` | **Required.** The script fails fast (exit 2) with a clear message before creating anything. `python3` is stdlib only: the config tool and the Telegram injector use exactly one method, python3 stdlib — there is no `jq` fallback anywhere in the script or this document. |
| `go` (only when building), `curl` (web UI leg), `ss` (bind leg) | The affected checks SKIP with a reason naming the missing tool. Runs are bounded internally by the script; no external `timeout` command is needed. |
| A config file whose profiles have cookies files | Legs needing a live profile SKIP per profile with reason `no cookies file for profile`. Cookies presence is read from `profile list` (`cookies` field), never by reading a cookies file. |
| A running Chrome with remote debugging, for CDP re-export | The re-export sub-check SKIP with reason. Never faked with a stub CDP server. |
| Network to the release API, for a stamped `update --dry-run` | SKIP with reason. |

Run with a normal environment: a warm Go build cache and the usual
proxy variables. A sterile environment (cold cache, no proxy vars)
can make live legs behave differently; headline counts are
environment-dependent
and must be read with the run's environment stated.

The script sets `umask 077` and verifies the temp dir is mode 0700
itself; it does not assume the ambient umask. Building the binary
needs temp space for Go's build work dir: if `/tmp` is a small
tmpfs, run with `TMPDIR` set to a disk-backed directory (the
script's temp dir and the Go work dir both follow `TMPDIR`).

## Isolation (hard rules)

1. Every castctl invocation passes `--config` pointing at the temp
   copy. The supplied config is never modified: its SHA-256 is
   recorded at start and re-checked at end; a mismatch is FAIL.
   `~/.config/castctl` is never read or written.
2. One temp dir (`mktemp -d`, mode 0700) holds the config copy,
   state, logs, ports, captured outputs and the built binary. The
   trap is installed immediately after `mktemp`/`chmod`, before the
   mode check, so every exit path removes the temp dir. On INT/TERM
   the signal trap ENDS the run: it kills started servers and
   descendant processes, removes the temp dir, and exits 130
   without printing a summary or a secret-scan verdict over
   deleted files. A SIGKILL (`kill -9`) or a crash bypasses the
   trap and leaves the temp dir behind; remove the printed path
   manually in that case. The web UI server is started so the
   recorded PID is the castctl process itself (not a wrapper
   subshell), and after the leg the script verifies the port
   closes; the trap is a backstop for the same PID.
3. The temp config copy is the only config the script's castctl
   invocations see. **Cookies are never copied and never read.**
   The temp copy's `cookies_file` for every profile is pointed at
   the ORIGINAL absolute path (a relative `cookies_file` resolves
   against the supplied config's directory; an absolute path is
   kept as-is; an absent one resolves to the supplied directory's
   default location). The script records SHA-256 + mtime of each
   original cookies file (and `.bak` if present) before the legs
   and after, and FAILs on any unexpected change; only changed
   yes/no is printed, never a hash value. Keeper legs that would
   rewrite cookies stay dry/SKIP unless `--live-keeper` is given;
   with it, a resulting change is recorded as expected, not a
   failure. Cookies files are never content-scanned (see the scan
   scopes below).
4. Ambient `CASTCTL_CONFIG`, `CASTCTL_PROFILE`, `MUSE_AUTO_APPROVE`,
   `MUSE_AUTO_ALLOW_ONCE` are stripped for every castctl invocation
   and set deliberately only inside the approvals leg. The token
   env vars are unset after injection (see D1) so no child process
   can inherit them; the web UI key is exported only for the web
   UI server process, from a saved shell copy.
5. No profile name, cookie value, token, or key is ever printed by
   the script. Verdict reasons are fixed strings, counts, exit codes,
   profile names and field names only. The script is never run under
   `set -x`.

## Telegram token source (D1, Boss-decided)

**castctl itself reads the Telegram token only from the `telegram`
block in config** (`internal/profile/telegram.go`). There is no
`CASTCTL_TELEGRAM_TOKEN` support in castctl at this head, and this
item adds none (no Go change).

`CASTCTL_TELEGRAM_TOKEN` is a **script-level convenience only**:

- When it is set (non-empty, after trimming whitespace — a
  whitespace-only value counts as unset) and the temp config copy
  has a `telegram` block, the script injects the env value into
  that block **in the temp copy only**, replacing any token there.
  The injection reads the value from the environment inside the
  injector (python3 stdlib only); the token never appears on any
  command line. The supplied config is untouched. After
  injection the script unsets both token env vars, keeping saved
  shell copies only for the final scan and the web UI server
  start, so no later child process inherits them.
- When it is unset, the temp copy is unchanged and the positive
  Telegram leg is SKIP with a reason — unless the supplied config
  already has `telegram.token`, in which case the leg runs against
  the config-supplied token and the script holds no value to scan
  for (the label-pattern scan still runs).
- When the config has no `telegram` block at all, injection cannot
  make a valid block (profile + non-empty allowlist are required),
  so the positive leg is SKIP with a reason.
- The script greps its own collected output for the token **value**
  (only when it holds the env value) and reports only a count;
  a non-zero count is FAIL.

Do not describe the env var as a castctl feature. Any future
env-var support in castctl is a separate, Go-changing item.

## Sandbox rule (D3, Boss-decided)

A network leg is SKIP with reason `suspected sandbox` **only** when
its captured output contains the exact fixed string:

```text
first record does not look like a TLS handshake
```

Only that string is printed for such a SKIP. Every other failure is
FAIL. A sandbox SKIP never counts as PASS toward Floor, and the
summary lists it explicitly (the summary counts suspected-sandbox
SKIPs separately). This rule covers the assistant sandbox, which
intercepts raw outbound TCP; on the operator's own machine the same
legs are expected to run live.

## Secret scan (leg 12, counts only)

Scopes:

- **Scope A — scanned, counts only:** every captured stdout/stderr
  file, web UI response bodies, and castctl log files under the temp
  dir, plus `verdicts.txt` for VALUE patterns only (label patterns
  would self-match on the scan lines' own pattern names, so
  `verdicts.txt` is excluded from the label scan). The scan asserts
  Scope A is non-empty: an empty scope would make a zero-count
  verdict vacuous. Patterns: the held env token values (fixed
  strings) and labelled forms (`hatch_sess=<value>`, `datr=<value>`,
  `private_key`/`preshared_key` labels, `BEGIN ... PRIVATE KEY`,
  `Authorization: Bearer ...`). Only integer counts are printed, per
  pattern. Any non-zero value-pattern or label-pattern count is FAIL.
- **Scope B — never content-scanned:** the temp config copy, curl
  header files, and the cookies ORIGINALS (SHA-256 + mtime recorded
  only, content never read). For these the script asserts existence
  and mode only. Scanning them would load secrets into the scanner
  and prove nothing about output leakage.
- **Scope C — control:** a file holding a fake labelled value
  (`hatch_sess=FAKEPLACEHOLDER123`). The scanner must count it (>= 1)
  or the scan itself FAILs, proving the scanner can detect.

Honest residual: a bare (unlabelled) secret — a lone key, token, or
cookie value with no label — cannot be proven absent by scanning,
because no pattern matches it. A PASS here means "no labelled/value
pattern matched in Scope A", not "no secret anywhere". The defence
for bare secrets is procedural: values are never fed into log text,
error text, send text, URLs, or command lines in the first place.

## Running it on the box

From the repo checkout, with a config copy the operator prepared
(the script never touches the live config):

```sh
scripts/e2e.sh --config /path/to/test-config/config.json <profile>
scripts/e2e.sh --config /path/to/test-config/config.json <profile> <profile> --live-send
scripts/e2e.sh --config /path/to/test-config/config.json <profile> --binary /path/to/castctl
scripts/e2e.sh --config /path/to/test-config/config.json <profile> --live-keeper
```

`<profile>` is a placeholder for a real profile name passed in by
the operator. The operator reviews the `--live-send` probe text in
`scripts/e2e.sh` before running with that flag, and passes
`--live-keeper` only when keeper rewrites of the cookies originals
are acceptable (a resulting change is then recorded as expected).

Expected: a verdict line per check, then a summary with PASS / FAIL /
SKIP counts, the SKIP list with reasons, and the secret-scan counts.
Exit 0 means no FAIL (SKIPs may remain); exit 1 means at least one
FAIL. A dry run against a scratch config with no cookies, no blocks
and no tokens completes with mostly SKIP + offline PASS verdicts and
exit 0; a deliberately mutated config (unknown top-level key) must
produce FAIL and a non-zero exit — the script runs that negative
control itself at the end of every run.

## Known traps (from Phase 1 research, all verified at `2a3c1fa`)

- `profile list` synthesises an extra `"default"` row; never assert
  the row count equals the configured profile count.
- `watch` timeout is a clean exit 0, never 124.
- `auto-approve on` rewrites the config file (re-indented, resolved
  `cookies_file` added, mode stays 0600); never assert file identity
  across a toggle. The script runs it only on a throwaway copy.
- A failing run's log file may legitimately be 0 bytes; assert
  creation + mode, not content, without a live success.
- `update` on an unstamped build refuses in every mode before any
  network access; that refusal is the check, not a failure.
- `CASTCTL_TELEGRAM_TOKEN` does not exist in castctl (see above).
- `local` DNS servers: leak-freedom through a detour is unproven;
  the script never claims it.
- The `dns.timeout` default and the exact error for an unreachable
  DNS server are unpinned; the script asserts failure + bound +
  no-secret, and records what it observed.

## Gaps — [NEEDS-MEASUREMENT] (live box or manual step)

1. Live `profile test` phases and live exit codes with real cookies.
2. Live `send`/`wait` outcomes, exit 5 (no ack), `--wait 0`,
   `--until-done`, `--download`, cancel to 130.
3. A real pending approval end-to-end (list/decide/`--approve-all`
   skip, auto-approve during a turn). Never invent an approval id.
4. Live `watch` row shape, `--all`, `--n`, `--thread` scoping.
5. Logging content on a live successful run (trace volume, last-line
   JSON with stderr logging, `stdout` output, `timestamp: true`).
6. `update` on a stamped build (dry-run report, replace-on-copy,
   lock, policy refusals, already-latest no-op).
7. Real CDP re-export against a running browser; screencast session
   start; keeper `run` single-flight refusal; keeper notice delivery
   to the first allowlist id.
8. `telegram run` live (GetMe/poll, a real streamed turn reply
   to a real message, one approval allow and one deny,
   `/autoapprove` persistence across a restart, no token in
   logs).
9. Web UI `PUT /config`, `PUT /dns`, `PUT /settings/telegram`
   (sentinel keep, empty-token unchanged, 409 guard), login/endpoint
   import echo checks, create/patch response echo checks,
   non-loopback connect attempt.
10. `keeper check`/`run` against a live profile (cheap-chain outcome,
    expiry detection, state-file contents).

Nothing in this document claims any of the above as proven. Each is
either SKIP with reason in the script or a manual step for the
operator's live run.

## Rust E2E results (M7c, base `dev-rust` `0173436`, 2026-11-06; fix loop 1)

The Rust port was put through the same 9-item proof on cue against the
Go binary (`castctl 0.9.0 (1396697 2026-11-04T21:38:36Z)`, sha256
`c8ea009e…`). Rust binary (fix loop 1): `/tmp/m7c-fl1-target/release/castctl-rs`,
22,026,632 B, sha256 `729e9af5…`, `--version` → `castctl 0.9.0`
(unstamped). Live profile `no.0`. Full verbatim evidence: local working
notes (not published; raw captures beside them). Every claim below names
its base: M7b PR-1 #76 is merged at this base (`0173436`), so 36 commands
are wired; `telegram run`, `keeper run` and `update` are still CLI stubs
in the Rust binary (exit 1, `castctl: not ported yet in the Rust port`).

| # | Item | Verdict |
|---|------|---------|
| 1 | CLI surface (46 cmd `--help` + 34 sub `--help` + dispatch) | **PASS** (help) / status recorded — 82 stems, only `--version` stamp differs; 36 wired / 10 stub (live, isolated env); command total 46, not 47; M7b PR-2 commands (`fs`/`send`/`watch`/`chat`) marked chưa wire / PR-2 pending |
| 2 | Live read-only (`no.0`, 18 labels) | **PASS** — 16/18 RAW-MATCH; 2 usage diffs = live drift fields only (`bonus_tokens.balance_units`, `topupBalance`), JSON-EQUAL after dropping exactly those; the normalisation is now calibrated by a Go×Go control (drift -24,139 / -23,496 over ~83 s, an order of magnitude larger than the Go-vs-Rust diffs) |
| 3 | wait + subscribe | **PASS** (narrowed) — exit codes + shapes match Go, incl. the shared replies-exclusion quirk in the wait-before-send scenario; subscribe proven by a temporary `eprintln!` probe through `on_record` (15 lines, reverted after; `grep M7C-PROBE` returns 0 files in the current tree) — the probe proves the instrumented build's handler only; all three turns returned `replies: []` on both sides, so reply delivery is NOT proven by this item |
| 4 | Telegram bot | **PASS (library level)** — CLI `telegram run` is a stub; driver test `rust/castctl-telegram/tests/m7c_bot_e2e.rs` green (1 passed) vs fake Bot API + real Go gateway; getMe, 30-entry menu, streamed text turn, photo, auto-decide + button decide, inbound media, clean shutdown; Go comparison: 5/5 Go telegram tests PASS on cue; resume leg repaired in fix loop 1 (strengthened assertion FAILED first at `after_seq` 42, then PASSED at `after_seq` 15 — the resume now delivers the completed reply; scope: resume of an already-completed turn, not a live post-decision continuation) |
| 5 | Keeper | **PASS (library level)** — CLI `keeper run` is a stub; driver example `rust/castctl-keeper/examples/m7c_keeper_e2e.rs`, 2 ticks `ok`, `cookies_seen=10`, original `cookies.txt` byte-identical before/after (scratch copy only); Go `keeper check` on the same scratch copy matches exactly; the tick dials direct, which IS the profile-outbound path for `no.0` (no outbound configured; Go synthesises a direct outbound); CDP export leg proven in fix loop 1 with a seeded fake `hatch_sess` cookie (direct probe `exported=1`) after fixing the bootstrap's `Runtime.evaluate("self", returnByValue: true)` (-32000); transfer of a real session cookie remains unmeasured. `castctl-keeper` is not linked into any shipped binary, so this fix is library-level only (exercised by library tests/probe, not by the `castctl-rs` binary). The export→file write-back seam has never run end-to-end: the probe prints what `export()` returns and writes no file, and no driver tick has executed a successful export post-fix (pre-fix run RED `export_failed`; run2 stopped at `auth_error`, `exported=0`). |
| 6 | WebUI | **PASS** — 21/21 request matrix MATCH normalised (raw 19/21; the 2 raw diffs are exactly the rule-covered normalisations; the verdict now rests on the smoke's fresh re-run matrix + the separate verdict file — fresh servers and fresh bcrypt salts, but the same plaintext tokens as the writer's run (tokens sha `5cafacd3…`), so a fresh re-run of the same inputs, not an independent run; the writer's original raw matrix file was lost, overwritten during the smoke tarball extraction, and can no longer be re-checked); rate-limit mini-run identical both sides; Rust reports `go_version`/`singbox_version` "unknown" — a real divergence laundered by the presence+type normalisation, recorded explicitly |
| 7 | Plugin | **PASS** — echo `plugin check` byte-identical both sides; crash fixtures segfault in call/init: Go host DIES with a SIGSEGV dump (in-process loader), Rust host survives and reports `plugin crashed with signal 11` (subprocess worker), exit 2 both sides — **[DEVIATION]** deliberate architectural divergence in Rust's favour, not byte-parity with Go's crash behaviour |
| 8 | Update | **FAIL (still a stub)** — `--check --json` flags do not exist in Go either (both sides reject identically, exit 2); Rust `update --dry-run` is a stub (exit 1) vs Go exit 0 `castctl is up to date: 0.9.0`; M7b PR-1 #76 merged but did NOT wire `update` (`cmd_update` still `Err(stub(ctx))` at `0173436`); crate-level unstamped refusal proven (`dev_build_refuses_before_network`, `dev_build_refuses_with_zero_requests`); all 43 `castctl-update` tests pass incl. `dry_run_writes_nothing` |
| 9 | Perf (full-surface `castctl-rs`) | **PASS** — run11: stripped 21,552,104 B (0.448× Go, 2.23× smaller); startup band ~3.5–4.8× across methods (driver 3.55×/4.35×, hyperfine 4.44×/4.72×); RSS `--version` 6.312 MiB vs 47.742 MiB (Go high bimodal mode; low mode 30.37 MiB in run10); pure logic 2.1–6.8× faster; see `rust/perf/README.md` "Bảng số (run11)" |

Gaps carried forward (not claimed as proven): item 8 real `--dry-run`
comparison (`update` still a stub at `0173436` — needs PR-2 wiring);
item 7 fuse behaviour at CLI level; item 6 traversal
coverage weaker than M6b's encoded variants; item 5 transfer of a real
session cookie via CDP export (fake-cookie transfer proven); item 3
M7a's claimed reply-seq-26704 observation not reproduced on either side;
item 3 reply delivery by wait; item 4 resume of a live post-decision
continuation.

### Rebase-2 (base `dev-rust` `2ae2f14`, 2026-11-06 — M7b PR-2 #78 + PR #79 merged)

Rebased cleanly (`git rebase origin/dev-rust`, 6/6, zero conflicts; head
`e864c7b`, diff 28 files, only `rust/**` + `docs/e2e.md`). Go tree
unchanged between `0173436` and `2ae2f14` (empty diff on `internal/`,
`cmd/`, `go.mod`), so the Go reference is still `castctl 0.9.0 (1396697
2026-11-04T21:38:36Z)`, sha256 `c8ea009e…`. Rust release binary rebuilt on
cue: 29,716,256 B, sha256 `d666c335…` (deleted after the run to free disk;
captures kept locally, not published).

- **Item 1 — PASS (help) / status updated.** 82 stems, only `--version`
  differs (stamp); diff-out=1, diff-err=0, diff-code=0. Help-only stdout
  sha256 identical both sides: `bc527db3…` — the same hash as fix loop 1,
  so the help surface is unchanged across the rebase. `not ported yet`
  lines in help: 0 both sides. Command total still **46** (Go
  `commandOrder` recount at the new base), not 47. Dispatch (live,
  isolated env, 46 probes + 3 extra): **40 wired / 1 partial (`auth`) / 5 stub top-level**
  (`update`, `telegram`, `keeper`, `profile`, `config`; `auth` partial:
  `list`/`import`/`status` stub, `export`/`login`/`observe-login` are
  Go-faithful terminal behaviours, not stubs). PR-2 commands `chat`,
  `send`, `watch`, `fs` are now wired (exit 2 `cookies_missing` in the
  isolated env, no stub line) — the "PR-2 pending" label from fix loop 1
  no longer applies to them. Static count still **10 `stub(ctx)`
  call-sites** (`run.rs`: 618 `history --download` — the only allowed
  stub; 626 `cmd_plain` fall-through — unreachable, all 37 plain commands
  are covered by the wired branches 5 + 13 + 19; 804 `cmd_update`; 868 /
  883 / 918 `auth list` / `import` / `status`; 1009 `cmd_profile`
  fall-through — all profile subcommands; 1054 `config migrate`; 1097
  `telegram`; 1147 `keeper`). Live probes cover 9 of the 10 call-sites
  (all exit 1 with the stub line); only the unreachable 626 is
  static-only.
- **Item 8 — still FAIL (stub).** PR-2 did NOT wire `update`
  (`cmd_update` still `Err(stub(ctx))`, `run.rs:801-806`); its scope was
  `fs`/`send`/`watch`/`chat`. Re-verified live: Go `update --dry-run`
  exit 0 `castctl is up to date: 0.9.0`; Rust `update --dry-run` exit 1
  stub, binary sha256 unchanged before/after; `--check --json` rejected
  identically both sides (exit 2). The flip now needs a dedicated wiring
  change for `update` (no milestone owns it yet), not another merge.
- **Gates (cue, `cargo +1.99.1`, `CARGO_TARGET_DIR=/tmp/m7c-rb2-target`,
  deleted after): fmt 0; build 0; test 0 — 1471 passed, 0 failed
  (66 suites; PR-2's 1470 + the M7c bot e2e's 1 test, `m7c_bot_e2e.rs`
  `1 passed`); clippy `--all-targets -- -D warnings` 0.**
- **Smoke re-run (no rebase regression):** item 2 subset (`status` /
  `usage` / `threads` / `feed`, debug binary) all MATCH, exits 0/0;
  item 3 idle control A: Go 124, Rust 124, stdout IDENTICAL; item 6
  matrix 21/21 MATCH; item 7 `plugin check` echo byte-identical,
  crashcall/crashinit exit 2 both sides, control echo-after exit 0.
  Smoke used the debug binary (same code as the release binary used for
  item 1) — behaviour smoke only, not a perf re-measurement.
- **Incidents:** (1) the release build's SSH session broke after ~15 min
  (broken pipe) — the build had already finished; binary verified by
  sha256 on reconnect. (2) Disk fell to 4.2G free during the test gate
  (concurrent M7d + PR-3 writer target dirs, 13G + growing); freed 1.2G
  by deleting the release profile dir (binary already measured) and
  finished the gate; target dir deleted after, cue back to 20G free.
  (3) The item-6 script's `kill $PID` missed the webui servers (`$!`
  was the `cd &&` subshell, not the server) — both servers (Go 18317,
  Rust 18318) were killed by direct PID afterwards, ports verified
  closed. (4) `/tmp/m7c-plugin/` fixtures were gone on cue — rebuilt
  from source (`examples/plugin/echo`, `/tmp/m7c-crash-src/crashcall` /
  `crashinit`) into `/tmp/m7c-rb2-plugin/`; echo sha256 `f80d065a…`,
  crashcall `e1246664…`, crashinit `6dc4f2d6…`.

### Rebase-3 (base `dev-rust` `3532d02`, 2026-11-06 — PR #80 docs-only `rust/README.md`)

Rebased cleanly (`git rebase origin/dev-rust`, 7/7, zero conflicts; head
`1266ceb`, diff 28 files, only `rust/**` + `docs/e2e.md`). PR #80 is
docs-only (1 file `rust/README.md`, +83, no code — verified by
`git log` + `git diff --stat 2ae2f14..3532d02`), so no M7c code changed
and no item re-measurement was needed beyond the confirmations below.

- **Item 1 — confirmed unchanged (spot-check, debug binary).** Static:
  still 10 `stub(ctx)` call-sites in `run.rs` at the same lines as
  rebase-2 (618, 626, 804, 868, 883, 918, 1009, 1054, 1097, 1147), so
  dispatch stays **40 wired / 1 partial (`auth`) / 5 stub top-level**. Live spot-check (cue,
  debug binary sha256 `c3ff2000…`): top-level `--help` stdout + stderr
  byte-identical to Go; `--version` differs stamp-only (`castctl 0.9.0`
  vs `castctl 0.9.0 (1396697 2026-11-04T21:38:36Z)`); 9 subcommand
  `--help` (`status`, `send`, `chat`, `watch`, `fs`, `profile`,
  `telegram`, `keeper`, `update`) all exit 0; `not ported yet` lines in
  help: 0.
- **Item 8 — still FAIL (stub).** `cmd_update` still `Err(stub(ctx))`;
  live: Rust `update --dry-run` exit 1 with the stub line on stderr, vs
  Go exit 0 `up to date`. PR #80 touched no code, so no wiring change
  was expected.
- **Gates (cue, `cargo +1.99.1`, `CARGO_TARGET_DIR=/tmp/m7c-rb3-target`,
  deleted after): fmt 0; build 0; test 0 — 1471 passed, 0 failed
  (66 suites); clippy `--all-targets -- -D warnings` 0.**
- **Incidents:** (1) My round-1 gates script used the default PATH `go`
  (wrapper 1.26.8, `GOTOOLCHAIN=local`), so `loader_live` failed 22/22
  (`go.mod requires go >= 1.27.3`) and `cargo test`'s default fail-fast
  stopped the run at `castctl-pluginhost` (743 passed at that point) —
  the same env mistake as the writer's fix-loop-1 incident, not a code
  regression. Re-ran with the correct env (`PATH=/usr/local/go/bin`,
  `GOTOOLCHAIN=auto`, `--no-fail-fast`): **1471 passed, 0 failed**,
  identical to rebase-2. (2) Disk fell to 1.4G free (99%) during the
  round-1 gate — my 17G target dir plus two other sessions' stale
  13G + 17G target dirs; no other session's files were touched, and
  disk recovered to 18G then 33G free as other sessions cleaned up.
  Target + source deleted after the gate; cue left clean, no M7c
  processes or listeners.


## Rust E2E results — binary level (M7e, base `dev-rust` `9afa04c`, 2026-11-06/07)

M7c proved items 4/5/6 at library level because the CLI was still a stub.
M7e re-proves three of them through the shipped `castctl-rs` binary itself,
against the Go binary `castctl 0.9.0 (1396697 2026-11-04T21:38:36Z)`, sha256
`c8ea009e49c5bffce3c6b971db0f9f86948ab3904f478da33d43b6b60a9bc374`, on cue.
Live profile `no.0`; Chrome CDP `127.0.0.1:9226` live throughout (never
closed/opened/killed). Rust release binary built on cue with
`cargo +1.99.1 build --release -p castctl-rs`,
`CARGO_TARGET_DIR=/tmp/m7e-target`: items 1–2 and the pre-fix probe ran
`8042ce24368ceee49b46b20315095f9c67a7fbc0526b9aa833c3eb64571e65e0`
(37,034,792 B, `--version` → `castctl 0.9.0` unstamped); the post-fix probe
and the final gates ran the fixed binary
`3a890ff65730663f54575d01afba4fbd10e9c96c8384166da89d4bd0ae285f0c`.
Toolchain note: a bare `cargo --version` on cue reads 1.97.1 (the rustup
default), but the repo pins 1.99.1 in `rust/rust-toolchain.toml` and rustup
has 1.99.1 installed — all M7e builds/gates used `cargo +1.99.1`.
Full verbatim evidence: working notes in the M7e writer's run logs on cue
(`/tmp/m7e-webui/`, `/tmp/m7e-keeper/`, `/tmp/m7e-tg/`); key outputs are
quoted below. No token, cookie value, or key appears anywhere in this
section; shas are of files, never of secrets.

| # | Item | Verdict |
|---|------|---------|
| 1 | `webui serve` (21-request matrix + rate-limit + negatives) | **PASS** — 21/21 normalised (raw 18/21); the 3 raw diffs are exactly the rule-covered normalisations — 2 normalised fields (`go_version`, `singbox_version`, presence+type only) + `/status` version-stamp strip + listen-port normalisation + stored-file `sha256` presence+format + key-order-insensitive JSON compare (rule source: r1-webui.md §5); rate-limit sequence identical; negative probes identical; both servers exit 130 on SIGINT |
| 2 | `keeper run` (60 s + SIGTERM, sha256, `status`/`check`) | **PASS** — Go 2 ticks `ok cookies_seen=10 wrote=true`; Rust ≥1 `ok` tick proven by state (tick count unrecoverable under SIGTERM — stdout 0 bytes), `keeper check` 1 tick `ok cookies_seen=10 wrote=true`; SIGTERM wait 143 both; what passed is the real-check set — `wrote=true` every tick, identical cookie sets (10 names), each side's state `cookies_sha256` equal to its own written file, `status`/`check`/single-flight match; cross-run byte-equality of `cookies.txt` is NOT claimed (unsatisfiable: every tick stamps `last_seen=now`); live files unchanged; plus one real bug found and fixed (tick ignored configured `cookies_file`, pre/post probe); the SIGINT divergence recorded at `9afa04c` is CLOSED at the rebased head — re-verified live at `acb2aa7`, Rust SIGINT exits 130 with the tick line flushed (see rebase note) |
| 3 | `telegram run` (fake Bot API + 1 turn via fake gateway) | **PASS (library-level ONLY — no binary telegram parity) + blocker documented** — no stock-binary mechanism points either binary at a fake Bot API server or fake gateway (verified at binary level); the 1-turn leg was not run as a binary comparison. The library-level telegram evidence (M7c, `docs/e2e.md:302`) stands; the binary-level blocker is documented below. Fix loop 1 (F8 probe, 2026-11-07): the Go DNS leg IS closable — a top-level `dns` `hosts` mapping for `api.telegram.org` → `127.0.0.1` routes Go `telegram run` to the TLS fake (getMe 200 in the fake log); the blocker now rests SOLELY on the Rust TLS-trust leg (webpki roots only, `SSL_CERT_FILE` ignored). Binary comparison is still impossible; the verdict is unchanged. |

### Item 1 — `webui serve`: PASS (21/21 normalised, 18/21 raw)

Method: r1 matrix, driver Python stdlib (`http.client`, no redirect
following, verbatim paths). Two config copies of the live `no.0` config
(mode 0600), each with `webui.listen` `127.0.0.1:18317` (Go) /
`127.0.0.1:18318` (Rust), a fresh random test token per side, and
`login_rate_limit {"attempts": 100, "window": "5m"}` for the matrix.
Cookies never copied or read. Readiness: unauthenticated
`GET /api/v1/status` until 401. Comparison per M6b/M7c rules (rule source: r1-webui.md §5 — the full set actually applied is the 2 normalised fields `go_version`/`singbox_version` + `/status` version-stamp strip + listen-port normalisation + stored-file `sha256` presence+format + key-order-insensitive JSON compare; the summary-table headline now lists all of them): status exact;
headers `Content-Type`/`Cache-Control`/`X-Content-Type-Options` exact
(case-insensitive names), `Retry-After` only on 429,
`Access-Control-Allow-*`/`Set-Cookie` must be absent, `Date`/`Connection`/
`Content-Length` not compared; JSON bodies canonical (sorted keys, numbers
as literals) with normalisations `go_version`/`singbox_version`
(presence+type only), `listen_addr`/port/config-dir, bcrypt → `<BCRYPT>`,
stored-file `sha256` presence+format (except strict `bundle_sha256`),
`/status` `version` stamp stripped.

| Row | Method + path | Go | Rust | Verdict (raw) |
|---|---|---|---|---|
| 1 | `GET /` | 200 | 200 | MATCH (shell byte-identical both sides and to `webui/dist/index.html`, sha256 `cd11d39afd03f48a8a96a576a03b2f2891963a1f56773ba2cf3745b4720c6cc7`) |
| 2 | `GET /api/v1/status` (good token) | 200 | 200 | MATCH normalised / DIFF raw (see below) |
| 3 | `GET /api/v1/status` (no token) | 401 | 401 | MATCH |
| 4 | `GET /api/v1/status` (wrong token) | 401 | 401 | MATCH |
| 5 | `GET /api/v1/status` (Basic) | 401 | 401 | MATCH |
| 6 | `GET /api/v1/status` (bare `Bearer`) | 401 | 401 | MATCH |
| 7 | `GET /api/v1/config` (good token) | 200 | 200 | MATCH normalised / DIFF raw (see below) |
| 8 | `GET /api/v1/profiles` | 200 | 200 | MATCH |
| 9 | `GET /api/v1/profiles/no.0` | 200 | 200 | MATCH normalised / DIFF raw (key order only) |
| 10 | `GET /api/v1/profiles/nosuch` | 404 | 404 | MATCH |
| 11 | `GET /api/v1/settings/telegram` | 200 | 200 | MATCH (`configured: false`, `masked: ""` — mask check SKIP per rule, copy has no `telegram` block) |
| 12 | `GET /api/v1/logs` | 200 | 200 | MATCH (`disabled: true`, `entries: []`, `reason: "logging_disabled"`) |
| 13 | `GET /api/v1/keeper` | 200 | 200 | MATCH (`[]`) |
| 14 | `GET /api/v1/screencast/status` | 200 | 200 | MATCH (`available: false`, `reason` STRICT-identical: `screencast unavailable in this build (rebuild with -tags with_chromedp)`) |
| 15 | `GET /api/v1/plugins` | 200 | 200 | MATCH (`available: false`, `plugins: []`) |
| 16 | `GET /api/v1/chats/nosuch` | 404 | 404 | MATCH |
| 17 | `GET /api/v1/chats/no.0/nosuch-session` | 502 | 502 | MATCH (`upstream_error` both sides — the live `no.0` profile behaves as the fixture did; a 501 would have been FAIL) |
| 18 | `POST /api/v1/status` (no body) | 405 | 405 | MATCH (`method_not_allowed`) |
| 19 | `GET /ui/../config.json` (`--path-as-is`) | 200 | 200 | MATCH (shell both sides — NOT traversal proof, per r1) |
| 20 | `GET /api/v1/definitely-not-a-route` (good token) | 200 | 200 | MATCH (shell fallthrough) |
| 20b | `GET /api/v1/definitely-not-a-route` (no token) | 401 | 401 | MATCH |

The three raw diffs are exactly the rule-covered normalisations: row 2
(`go_version` Go `go1.27.3` vs Rust `unknown`, `singbox_version` Go
`v1.14.4` vs Rust `unknown`, `version` stamp
`0.9.0 (1396697 2026-11-04T21:38:36Z)` vs unstamped `0.9.0`, listen port)
— the `go_version`/`singbox_version` "unknown" divergence is REAL and is
laundered by the presence+type normalisation, recorded explicitly as in
M7c; row 7 (listen port + stored-file `sha256`, differing by bcrypt salt);
row 9 (JSON key order only — canonical bodies identical, both 479 B).
`bundle_sha256` is STRICT and identical:
`cd11d39afd03f48a8a96a576a03b2f2891963a1f56773ba2cf3745b4720c6cc7`.
`/status` counts on the real copy: `profile_count: 1`,
`outbound_count: 0`, `endpoint_count: 0`, `default_profile: "no.0"`,
`config_source: "single-file"`, `remote_exposure: false`,
`session_idle_timeout_seconds: 43200` — identical both sides.

Negative pre-checks (identical both sides, all exit 2): no `webui` block →
`castctl: webui serve: no "webui" block in config.json: add one (see
docs/config.md) or use the CLI`; no token →
`castctl: webui serve: no token configured: add a "token" to the "webui"
block`; non-loopback listen →
`castctl: profile: "webui.listen" host must be loopback`.

Rate-limit mini-run (separate servers, default limiter, ports
18327/18328): after the readiness poll (which consumes 1 attempt), both
sides `[(401, None)×4, (429, "300")×3]`, exit 130 on SIGINT — identical.

Post-run: both servers exit 130 on SIGINT, ports 18317/18318 verified
closed; live config sha unchanged (`b748366c…`), live cookies sha unchanged
(`aa667a83…`); plaintext-token grep count 0 in both saved configs, stored
token is bcrypt, mode 0600 both. Startup lines (both servers):
`castctl: web UI listening on 127.0.0.1:18317 (loopback only, token auth)`
and `…:18318 …` (Rust's line is flushed at exit — buffered CLI output —
so readiness was polled via 401, not via the log line).

### Item 2 — `keeper run`: PASS (with one bug fixed in M7e, one known finding)

Method: r2 recipe. Fresh scratch dir per binary, live `no.0` entry copied
with the `cookies_file` key DROPPED (see incident below) so the default
`$T/profiles/no.0/cookies.txt` is used; one keeper entry
(`tag: "no.0"`, `profile: "no.0"`, `browser: "http://127.0.0.1:9226"`,
`interval: "30s"`, `wake_on_gateway_failure: false`); cookie copy of the
live file (mode 0600). Run ≤60 s, then the planned signal.

Clean re-run (run 2, after the driver fix):

| Check | Go | Rust |
|---|---|---|
| `keeper run` 60 s, ticks | 2 ticks, `keeper: no.0 (no.0): ok cookies_seen=10 wrote=true next_delay=30s` (×2) | ticks ran (state proves ≥1 `ok` tick) but stdout 0 bytes — Rust buffers all tick lines until exit, so SIGTERM loses them (r2 prediction, confirmed live) |
| Kill signal / wait status | SIGTERM → **143** | SIGINT at 60 s → **still alive after 10 s** (known bug, see finding below); then SIGTERM → **143** |
| `keeper status` (after) | exit 0, `last_tick_outcome: "ok"` | exit 0, `last_tick_outcome: "ok"` (times render UTC `Z` vs Go `+07:00` — known, instants equal) [M7g fixed the render — Rust now matches Go; row kept as the M7e-era evidence] |
| `keeper check` (1 tick) | exit 0, `ok`, `cookies_seen: 10`, `wrote_cookies: true` | exit 0, `ok`, `cookies_seen: 10`, `wrote_cookies: true` |
| Single-flight (2nd `run`, same dir, while 1st alive) | exit 2, `keeper entry "no.0" is already running (pid 3046906)` | exit 2, `keeper entry "no.0" is already running (pid 3047119)` |
| Scratch cookies sha | `aa667a83…` → `0628ecd2…` (run) → `dcdd05d4…` (check); state `cookies_sha256` equals the file sha after each side's own check | `aa667a83…` → `5b352850…` (run) → `fa4624ec…` (check); state `cookies_sha256` equals the file sha after each side's own check |
| Live files | config + cookies sha UNCHANGED (`b748366c…` / `aa667a83…`), live dir listing clean (no `session-state.json`, no `keeper-*.owner`, no `.bak`) | same |

Sha reading: the two sides' new shas differ because every tick stamps
`last_seen=now` into the rewritten jar — byte equality across runs at
different times is impossible by construction. Cross-run byte-equality of
`cookies.txt` is NOT claimed. What matches identically:
both changed on every tick (`wrote=true`), the cookie SET is identical
(10 names; 8 expiries byte-identical; the 2 CDP-refreshed expiries
`hatch_sess`/`hatch_vml` track tick time, Go `21:00:24Z`/`21:00:54Z` vs
Rust `21:01:31Z`/`21:02:31Z`, deltas +67 s/+97 s ≈ the tick gap — the CDP
export leg ran on both sides; corrected in fix loop 1 from the quoted +76 s
pair — the `21:01:30Z`/`21:02:46Z` values appear in no surviving log,
re-parsed from `/tmp/m7e-keeper/run2.log` on cue), and each side's state `cookies_sha256`
equals its own written file. Go SIGINT probe (separate fresh scratch,
15 s): wait status **130**, 1 tick line — Go's Ctrl-C path is correct.

Incident — run 1 (VOID sha comparison, contained and repaired): the
first driver copied the live entry VERBATIM, including its absolute
`cookies_file` (`/root/.config/castctl/profiles/no.0/cookies.txt`). Go
honours an absolute `cookies_file` outside the config dir, so its 4 ticks
wrote the LIVE cookies file (sha `aa667a83…` → `e3b9775e…`, plus a
`cookies.txt.bak` and a 0-byte `cookies.txt.lock` in the live dir). The
live file was restored byte-for-byte from the untouched scratch copy
(sha `aa667a83…`, 5300 B, Nov 6 15:19, dir listing diff empty) and the
artifacts removed; the driver was fixed to drop `cookies_file` and item 2
was re-run clean (run 2 above). Traceability limit (fix loop 1): the live
file today matches the pre-run record on sha/size/mtime/listing, but the
restore source file (the untouched scratch copy) no longer exists for
re-hashing, so the restore chain rests on the writer's contemporaneous
record — no independent pre-run hash exists. Run 1's tick/exit/signal evidence stands;
its sha comparison is void.

Bug found and FIXED in M7e — tick ignores configured `cookies_file`:
run 1 also proved a real Rust divergence: Go wrote the configured absolute
path while Rust wrote the scratch DEFAULT path. Code ground truth: Rust
`tick()` built `Store::new(&deps.base_dir, &deps.profile_name, "", …)`
(`rust/castctl-keeper/src/tick.rs:301`, empty path → default) and `TickDeps`
had no cookies-path field; Go's `saveJar` writes the store's resolved
`cookiesPath` (`internal/keeper/tick.go:490-500`). Targeted probe
(`keeper check` ×1 per side, absolute `cookies_file` pointing OUTSIDE the
config dir): pre-fix Go wrote the configured file (default unchanged)
while Rust wrote the default (configured file unchanged) — same `ok`,
`cookies_seen=10`, `wrote=true` both sides, so the divergence is invisible
in the check output and only the file shas expose it. (Fix loop 1: the
original pre-fix probe shas appear in no surviving cue artifact and are
removed here; the divergence itself is independently established by run 1,
the code ground truth, and the RED→GREEN `case_18`.) (A first probe
attempt with the configured file INSIDE the config dir correctly failed
exit 2 on BOTH sides with the identical inside-dir message — bonus parity
evidence for that rule.) Fix (5 files, +18/−1, `rust/**` only): new
`TickDeps.cookies_path`, `tick()` passes it to `Store::new`, the CLI
`factory` sets it to `rt.profile.cookies_file`, test/example construction
sites pass `""` (default behaviour unchanged). Post-fix probe: BOTH sides
write the configured file (Go configured-after
`727bbc7dce938ea8373f634b6a8526dbe09a63fe89f590a4cfad5281890dd44f`, Rust
configured-after
`c67967dfba88b1af74305fe78061ef54037594427655389e545029c2da414403`, both
from `aa667a83…`, defaults never created), state shas match their written
files. (Fix loop 1: these are the red-team probe-B shas at the final head,
review3-redteam.md Check 2; the originally quoted post-fix shas appear in
no surviving artifact and are removed.) RED→GREEN regression
test added in the fix loop (Pi requires it in this PR):
`case_18_tick_writes_configured_cookies_file`
(`rust/castctl-keeper/tests/tick_table.rs`) — jar ONLY at a configured
path, default file absent; PASS with the fix, FAIL with the fix neutered
(`tick()` back to `""`: `assertion failed: r.wrote_cookies`,
`tick_table.rs:566`, exit 101 — the neutered tick creates the default
file instead, and `save_jar` reports `wrote=false` on first-time
creation, S-10), PASS again after the fix is restored byte-identical;
see Gates below for the three verbatim outputs. NOT fixed here (recorded
follow-up): `LoginSession::run`/`finish`
(`rust/castctl-keeper/src/login.rs:222,358`) pass `""` to `Store::new` too
— same latent pattern on the re-login save path, unproven live (no
credentials configured in any M7e test); proposal: same one-field
threading, proven by a credentials-configured re-login run. The same `""`
pattern also survives in the fix's own file — `tick.rs:1368`
(`notify_stopped`) and `tick.rs:1406` (`reset_after_login`), both
state-only (warn flag / stopped-flag reset; no jar read/write), taking the
same `TickDeps` that now carries `cookies_path` yet ignoring it; impact is
lock identity only — these paths lock the DEFAULT cookies file while the
tick locks the configured one, and `lock_cookies_file` creates a stray
`<default>.lock` in the profile dir when no default file exists.
Follow-up acceptance criterion: after this fix, tick honours a configured
`cookies_file` while re-login still writes the default, so a
custom-`cookies_file` profile that re-logs in would split its jar across
two files — the follow-up must thread the path through login AND the two
`tick.rs` sites and prove no split.

Finding (not a run failure) — Rust SIGINT swallowed [CLOSED at the
rebased head, see rebase note]: `keeper run` at `9afa04c` does not stop
on SIGINT (alive after 10 s; the ctrl-C watcher cancels a child flag
nothing reads, so the 130 arm is unreachable — r2 §6). The fix is
commit `33055de`, carried by separate PR #85 (OPEN at the time,
cherry-pick, gates 1597/0) — NOT imported into M7e. Per r2 §3.3 this
was recorded as a finding, not a run failure. PR #85 has since MERGED
(`acb2aa7`); the rebase note below records the live re-verification
at the new head (SIGINT exits 130, tick line flushed).

### Item 3 — `telegram run`: PASS (library-level ONLY — no binary telegram parity) + blocker documented

What was verified at binary level (all on cue, fake token
`123456:FAKE-TOKEN-…`, never a real token, never a real message):

- Unknown telegram config key `api_url` is rejected IDENTICALLY, exit 2,
  same message both sides:
  `castctl: profile: unknown telegram config key "api_url"`.
  There is no `api_url`/`base_url`/`server_url` field (r3 §0.1).
- `telegram status` is byte-identical, exit 0, both sides
  (`configured: true`, `profile: "muse01"`, `allowed_user_ids: 1`,
  `auto_approve: true`, `auto_allow_once: false`, `token_valid: true`,
  `owner_configured: true`) — the test config parses identically.
- Stock binaries both dial the REAL `api.telegram.org`: fake token →
  exit 1, `castctl: telegram: bot construction failed: error call getMe,
  unauthorized, Unauthorized` (Go and Rust, identical text) — a 401 only
  the real Bot API returns for `getMe`.
- NEW (fix loop, 2026-11-06/07) — `telegram run` with a CORRUPT
  `telegram-state.json` (`{not json`, temp config dir, fake token):
  both sides exit 1 and proceed past the corrupt state to `getMe`; the
  state file is left byte-identical (`{not json`) on both sides. Go
  stderr (first run + retry 1):
  `castctl: telegram: bot construction failed: error call getMe, error do
  request for method getMe, Post "https://api.telegram.org/bot***/getMe":
  context deadline exceeded` (~5.09 s); Go retry 2 then returned the
  identical 401 (`error call getMe, unauthorized, Unauthorized`, 2.36 s)
  — the two timeouts were a transient stall on the Go outbound path, not
  a state-handling difference. Rust stderr (both runs):
  `telegram state file corrupt; starting with fresh state (offset reset
  to 0; stored chat mappings, watermarks, and runtime toggles discarded)`
  followed by the identical 401. Reporting difference, recorded as a
  finding: Rust prints an explicit corrupt-state notice; Go prints none
  in its captured stdout/stderr. The state half of the probe behaves
  identically (corrupt state never blocks startup on either side).

What was probed and FAILED — mechanism B (hosts redirect + TLS fake +
`SSL_CERT_FILE`), time-boxed per the task: `/etc/hosts`
`127.0.0.1 api.telegram.org` + a TLS-terminating fake on 443 (cert SAN
`api.telegram.org`, test CA) + `SSL_CERT_FILE=<test CA>`. The fake itself
was smoke-proven with curl (`--cacert` + `--resolve` → `getMe` 200).
- Go (via `/etc/hosts` only): never reaches the fake. A TCP listener on 443 saw NO CONNECTION in
  15 s while Go still failed 401 Unauthorized (real API). The OS resolver
  DOES return 127.0.0.1 (`getaddrinfo` → `127.0.0.1` only, nsswitch
  `files dns`), so the Go outbound (sing-box/honk direct) resolves via its
  own DNS path, bypassing `/etc/hosts`. The `/etc/hosts` redirect dies at DNS;
  `SSL_CERT_FILE` is never even tested on the Go side. — Fix loop 1 (F8
  probe, 2026-11-07): the sing-box `dns` `hosts` avenue was NOT tried in
  mechanism B and IS closable on the Go side (see below).
- Rust: DNS honoured — the TCP probe ACCEPTed a connection from
  127.0.0.1 with a TLS ClientHello carrying SNI `api.telegram.org`, ALPN
  `http/1.1` — but the handshake fails:
  `castctl: telegram: bot construction failed: transport error: conn:
  connection down` (the numeric suffix varied, 17/39), fake HTTP log empty
  (0 requests). Code ground truth: `tls_client_config` builds roots from
  `webpki_roots` ONLY — "No client auth, no native certs"
  (`rust/castctl-transport/src/tls.rs:21-26,56-58`) — so rustls ignores
  `SSL_CERT_FILE` by construction. The redirect dies at TLS trust.
- `/etc/hosts` was restored after each probe (`diff` vs backup empty;
  `getent` back to the real IPv6 address). The live cue Telegram bot
  (polling `api.telegram.org`) was never touched; redirect windows were
  minutes, and its polls could only fail transiently (TLS verify against
  the test CA fails) with no message loss.

NEW (fix loop 1, 2026-11-07) — F8 probe: sing-box `dns` `hosts` mapping
for Go. Temp config only (fake token `123456:FAKE-TOKEN-…`, never a real
token): top-level `dns` section with a `hosts` server (`tag: hosts-map`,
`predefined: {api.telegram.org: [127.0.0.1]}`), rule `{domain:
[api.telegram.org], server: hosts-map}`, `final: local-dns`; the same TLS
fake on 443 (cert SAN `api.telegram.org`, test CA) with
`SSL_CERT_FILE=<test CA>`; `/etc/hosts` untouched (no `api.telegram.org`
entry). Two config facts found while setting it up: a PER-PROFILE `dns`
block CANNOT carry a `hosts` server — castctl's G2 validation demands a
detour on every server in a profile block
(`internal/profile/dns.go:570-572`) while sing-box rejects `detour` on a
`hosts` server (`json: unknown field "detour"`); the TOP-LEVEL section
accepts it (its validation only checks detours when present,
`internal/profile/config.go:768-779`), so the probe used the top-level
section (compat branch, with the deprecation warning on stderr). Result:
Go REACHES the fake. Fake log: `getMe` ×1, `setMyCommands` ×1,
`getUpdates` ×11279 (hot spin — the probe fake answered empty
`getUpdates` instantly with no sleep; probe artifact, not a Go finding);
Go stdout: `telegram: polling for profile "muse01" (1 allowed users);
Ctrl-C to stop` — construction succeeded on the fake's getMe 200 and
polling ran until the 40 s `timeout` ended the run. The Go run's exit code
was not separately captured; the fake log is the evidence. Go therefore trusts
the test CA via `SSL_CERT_FILE` (system store) and honours the sing-box
`hosts` mapping. The Go DNS leg is closable; the blocker now rests SOLELY
on the Rust TLS-trust leg. Verbatim evidence: probe logs on cue,
`/tmp/m7e-fix1-tg/fake.log`, `go-run.out`, `go-run.err`; live
cookies/config unchanged after (sha `aa667a83…` / `b748366c…`),
`/etc/hosts` untouched.

Not run as a binary comparison: the `/help` comparison (no redirection
exists to run it through) and the 1-turn gateway leg. The gateway leg is
not feasible in scope: it needs the same redirection for
`hatch.metaaivm.com` + the muse.ai 3-step HTTPS auth chain (which runs
before the wss dial) + canned auth, and the fake gateway
(`gateway_server serve-e2e`) implements none of the auth chain.

Library-level PASS (the verdict's basis — M7c, `docs/e2e.md:302`): driver
test `rust/castctl-telegram/tests/m7c_bot_e2e.rs` green (1 passed) vs a
fake Bot API + the real Go gateway — getMe, 30-entry menu, streamed text
turn, photo, auto-decide + button decide, inbound media, clean shutdown;
Go comparison: 5/5 Go telegram tests PASS on cue. The menu is a 30-entry
`setMyCommands` list (names + order, `rust/castctl-telegram/src/router.rs`
`COMMAND_MENU`, asserted `menu.len() == 30` in the M7c test at
`m7c_bot_e2e.rs:527`); the request shapes the binary leg would have
compared are specified per method in the R3 brief
(`r3-telegram.md` §2.1–§2.2, decoded-field comparison §3.2 — Go
multipart vs Rust JSON, so raw bytes were never the criterion). Note on
wording: no source claims "30/30 commands compared" — the evidence is a
30-entry menu asserted on the Rust side plus the 5/5 Go telegram tests,
and it is worded exactly that way here.

Root cause + trust basis (mechanism A REJECTED — Pi's decision, acting
for Boss with full authority, 2026-11-06): the stock binaries expose no
Bot API base-URL or gateway WS-URL override (config, flag, or env), and
no Go production-code change to add one will be made — mechanism A (a
test-only env override in BOTH binaries) is rejected; there is no new
seam in the Go binary under test. Binary-level interception of
api.telegram.org is impossible for the Rust build without changing its
trust basis; the trust-basis difference is recorded in PORTING
(webpki-roots vs Go system store). Operative ground truth for the telegram
client is `rust/castctl-transport/src/tls.rs:21-26,56-58`
(`tls_client_config` builds roots from `webpki_roots` only, "No client
auth, no native certs" — verified by direct read; the telegram production
path uses it via `api.rs:181-189` → `HttpClient::request_tls`). PORTING
`rust/PORTING.md:1634` records the same webpki-only principle generally,
but it is about the honk/QUIC stack, not the telegram rustls client — it
is cited here only as the earlier note of the same principle, not as the
telegram ground truth. (Fix loop 1: the F8 probe closes the Go DNS leg —
the Go side reaches the fake through the sing-box `dns` `hosts` mapping —
so the blocker now rests SOLELY on the Rust TLS-trust leg above.) The TLS
block is therefore a known limitation, not a bug to fix by changing Go.
No telegram binary parity is claimed from this run; the verdict is PASS
(library-level ONLY — no binary telegram parity) + blocker documented —
never FAIL, never full binary PASS.

### Gates (cue, `cargo +1.99.1`, `CARGO_TARGET_DIR=/tmp/m7e-target`, `PATH=/usr/local/go/bin`, `GOTOOLCHAIN=auto`)

- `cargo fmt --check`: exit 0 (one formatting fix applied by `cargo fmt`
  to the long `Store::new` call in the fix, then re-checked clean).
- `cargo build --workspace`: exit 0.
- `cargo test --workspace --no-fail-fast`: exit 0 — **1595 passed, 0 failed**
  (66 suites), exactly the 9afa04c baseline. One transient failure on the
  FIRST full run: `castctl-update --test update_flow` 41 passed / 2 failed
  (one named failure visible in the tail: `install_newer_version_end_to_end`;
  the second name was cut off by the tail) — `rust/castctl-update/` is
  untouched by this diff, and the target passed 43/43 in the full re-run
  and 43/43 in 3 further isolated runs. Recorded as a flake under
  full-workspace load, not a regression.
- `cargo clippy --workspace --all-targets -- -D warnings`: exit 0.
- `git diff --stat origin/dev-rust` at the final head: 8 files, +598/−6 — only allowed paths (`docs/e2e.md` + 7 under `rust/**`: the `cookies_file` fix +18/−1, `case_18` +31, `parity.rs` comment-only +5/−5, perf README +24). (Fix loop 1: this line quoted the pre-fix-loop 5-file snapshot; corrected to the final count. The gates in this paragraph ran at `9afa04c`, when the diff was the 5-file fix + this section.) No `NOTICE` / `docs/provenance.md` change: no new upstream behaviour was ported.
- Disk: `df -h /` checked before each build; `/tmp/m7e-target` deleted
  after the final gate (see below).

### Fix-loop gates (cue, `cargo +1.99.1`, `CARGO_TARGET_DIR=/tmp/m7e-target`, 2026-11-06/07, working tree on `a318206` + uncommitted `case_18` — i.e. the tree committed as `b94895c` — on base `acb2aa7`, no rebase — `git ls-remote origin dev-rust` still `acb2aa7` at finish)

> Attribution corrected in fix loop 1: the 1600-pass run below is
> attributed here to the `b94895c` tree, NOT to commit `a318206` itself.
> `case_18` did not exist at `a318206` (`git show
> a318206:rust/castctl-keeper/tests/tick_table.rs | grep -c case_18` → 0;
> the test was committed in `b94895c`, a child of `a318206`), so the run
> must have been on the `a318206` working tree + the uncommitted test —
> the `b94895c` tree. The release binary stamp still reads `a318206`
> (built from that working tree); the counts are unchanged.

- `cargo fmt --check`: exit 0. `cargo build --workspace`: exit 0.
  `cargo test --workspace --no-fail-fast`: exit 0 — **1600 passed,
  0 failed** (baseline 1599 at `acb2aa7`; delta +1 = exactly the new
  `case_18` test; no flake this run, no isolated re-runs needed).
  `cargo clippy --workspace --all-targets -- -D warnings`: exit 0.
  Release binary rebuilt: `castctl 0.9.0 (a318206 2026-11-06T22:37:46Z)`,
  37,038,792 B, sha256
  `fa70d08c4b2a952ddc8e3ec7630aaa3adb28cbcb927559ce401832228c9be3e4`
  (same sha as the pre-gate probe build — no source change between).
- RED→GREEN verbatim (isolated `tick_table` runs on cue, same
  commands): with the fix — `test case_18_tick_writes_configured_cookies_file ... ok`,
  `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 17 filtered out`;
  with the fix neutered (`tick()` back to `""`, cue copy only, restored
  byte-identical afterwards) — `test case_18_tick_writes_configured_cookies_file ... FAILED`,
  `thread 'case_18_tick_writes_configured_cookies_file' panicked at castctl-keeper/tests/tick_table.rs:566:5: assertion failed: r.wrote_cookies`,
  `test result: FAILED. 0 passed; 1 failed`, exit 101; after restore —
  `... ok`, `1 passed`, exit 0.
- `git diff --stat origin/dev-rust`: 8 files, all allowed
  (`docs/e2e.md` + 7 under `rust/**`). `/tmp/m7e-target` deleted after
  the final gate; probe scratch (`/tmp/m7e-tg2*`) removed; live
  cookies/config shas re-verified unchanged
  (`aa667a83…` / `b748366c…`).

### Fix-loop-1 gates (cue, `cargo +1.99.1`, `CARGO_TARGET_DIR=/tmp/m7e-fix1-target`, 2026-11-07, head `f341096` on base `acb2aa7`, no rebase — `git ls-remote origin dev-rust` still `acb2aa7` at finish)

- `cargo fmt --check`: exit 0. `cargo build --workspace`: exit 0.
  `cargo test --workspace --no-fail-fast`: exit 0 — **1600 passed,
  0 failed** (66 suites; baseline 1599 at `acb2aa7` + 1 `case_18`; no flake
  this run, no isolated re-runs needed).
  `cargo clippy --workspace --all-targets -- -D warnings`: exit 0.
- Round-2 re-review re-ran the full gates at final head `b1e3a5c` (full
  checkout with `.git`): exit 0 — **1600 passed, 0 failed** (66 suites),
  `case_18` ok.
- `df -h /` before: 40G free (>6G rule).
- Harness note (void first run, recorded so it is not mistaken for a
  regression): the first full run used a `git archive` copy (no `.git`)
  and failed 1599/1 — `run::tests::test_update_invalid_version_no_network`
  panicked at `castctl-cli/src/run.rs:2149` with "cannot determine running
  version: this build was not stamped with commit and build date".
  `rust/castctl-cli/build.rs` stamps commit/date from git and yields EMPTY
  stamps without git metadata, so the unstamped build refuses `update`
  before version parsing. Re-run from a full checkout copy (with `.git`,
  head `f341096`, clean) passes 1600/0, including that test. The diff is
  docs-only and cannot affect any test; the 1599/1 run is a transfer-method
  artifact, not a code result.
- `git diff --stat origin/dev-rust`: 8 files, all allowed
  (`docs/e2e.md` + 7 under `rust/**`; docs-only delta vs `68b54f5` —
  exact counts in the Gates scope line above).

### Rebase onto `dev-rust` `acb2aa7` (PR #85 merged) — 2026-11-06/07

- Rebase in two steps, both onto the newest head at the time: first
  onto `57fc7be` (PR #84, clean, no conflicts; writer's commit
  `709262c`), then onto `acb2aa7` (PR #85 merged). The second rebase
  had exactly one conflict, in `rust/castctl-rs/tests/parity.rs`:
  the M7e reconciliation commit `fb84734` and PR #85's test-only
  `d33920c` make the same functional change (strip the optional
  `--version` stamp per D-M2-7) and their doc comments collided;
  resolved to the merged upstream (`d33920c`) text, keeping only
  M7e's `golden_parity()` comment fix (`ea0996f`, 3 lines). No
  forbidden file touched; `git diff --stat origin/dev-rust`: 7 files,
  all allowed (`docs/e2e.md` + 6 under `rust/**`). Nothing from PR
  #85 was cherry-picked or imported by M7e — its contents arrive
  via the base, which is the point of the rebase.
- Intermediate `57fc7be` rounds (superseded by the `acb2aa7` rebase,
  kept for the record): plain `57fc7be` fails `golden_parity` —
  `--version stdout (unstripped)`: left
  `"castctl 0.9.0 (709262c 2026-11-06T21:32:00Z)\n"` vs right
  `"castctl 0.9.0\n"` (`parity.rs:599`); round-1 gates at `709262c`:
  fmt 0, build 0, test 101 (1595 passed, 1 failed — only
  `golden_parity`), clippy 0, release 0. Reconciliation `fb84734`
  (test-only, same D-M2-7 strip as `d33920c`, re-applied in M7e
  scope) brought round-2 gates at `fb84734` to **1596 passed, 0
  failed** (1595 at `9afa04c` + 1 from PR #84's `version_string`
  test). At the docs head `2e06fdd` one full run hit the known
  `castctl-update` flake (`install_newer_version_end_to_end`,
  `update: download failed`, same test the writer saw flake at
  `9afa04c`; crate untouched by this diff); full re-run green
  **1596/0** and 3/3 isolated runs green, 43/43 each.
- Gates at the new head `8db72d8` (cue, `cargo +1.99.1`,
  `CARGO_TARGET_DIR=/tmp/m7e-target`, `PATH=/usr/local/go/bin`,
  `GOTOOLCHAIN=auto`): fmt 0, build 0,
  `cargo test --workspace --no-fail-fast` 0 — **1599 passed, 0
  failed** (1596 + 3 from PR #85's fix-loop tests), clippy 0,
  release 0. No `castctl-update` flake in this round. Release binary
  sha256 `b72788872a35e533169713989735394e83aac2e93a8ee2aef32758de6211f649`,
  37,038,912 B, `--version` →
  `castctl 0.9.0 (8db72d8 2026-11-06T22:23:00Z)`.
- PR #84 changed Rust `--version` to render the git build stamp like Go
  (`rust/castctl-cli/src/run.rs` only). The new-head release binary
  reports `castctl 0.9.0 (8db72d8 2026-11-06T22:23:00Z)` vs Go
  `castctl 0.9.0 (1396697 2026-11-04T21:38:36Z)` — same shape, so the
  CLI `--version` divergence recorded at `9afa04c` is CLOSED. The
  `/status` `version` field is NOT stamped by #84 (`Server::new`
  still gets `version: VERSION.to_string()`, the bare const), so the
  row-2 raw diff is unchanged.
- Focused row-2 re-run at the new head (Go 18337 / Rust 18338, fresh
  config copies, same method): Go `version:
  "0.9.0 (1396697 2026-11-04T21:38:36Z)"`, `go_version: "go1.27.3"`,
  `singbox_version: "v1.14.4"`; Rust `version: "0.9.0"`,
  `go_version: "unknown"`, `singbox_version: "unknown"`; both 200,
  raw bodies still differ, normalised comparison still MATCH (version
  stamp stripped, go/singbox presence+type, listen port). Both servers
  exit 130 on SIGINT, ports closed, live config/cookies unchanged.
  Row 2's verdict stands; no other matrix row is affected (the stamp
  touches only the CLI `--version` line and the already-stripped
  `/status` `version` field), so the full 21-row matrix was NOT re-run.
- SIGINT re-verification at the new head (focused probe only, Rust
  binary `8db72d8`, same r2 §2–§3 recipe: fresh scratch dir, live
  `no.0` entry minus `cookies_file`, one keeper entry, CDP 9226,
  live cookies copied): `keeper status` exit 0 (`last_tick_outcome:
  "never"`); `keeper run --profile no.0` pid 3855103, ≥1 tick proven
  by the state file (`last_tick_outcome: "ok"`,
  `last_checked_at: "2026-11-06T22:36:26.552104806Z"`,
  `cookies_seen=10`, `wrote=true`); SIGINT → **exit 130**.
  Stdout (66 bytes, flushed on the 130 path — unlike the SIGTERM
  path at `9afa04c`, where stdout was 0 bytes):
  `keeper: no.0 (no.0): ok cookies_seen=10 wrote=true next_delay=30s`;
  stderr 0 bytes. Scratch cookies sha `aa667a83…` →
  `f84c6908…`, state `cookies_sha256` equals the written file; live
  config/cookies unchanged (`b748366c…` / `aa667a83…`). The 9afa04c
  SIGINT finding is CLOSED: the Rust run now stops on SIGINT exactly
  like Go. No other keeper row was re-run (the probe contradicts
  none of the writer's other item-2 numbers).
- `/tmp/m7e-target` deleted after the final gate; `df -h /`
  verified after.

### Cleanup on cue

- Test webui servers (Go 18317 / Rust 18318, rate-limit 18327/18328) killed;
  ports verified closed. Test keeper dirs and telegram fake/configs are
  scratch under `/tmp/m7e-*` (no live files). Live `no.0` cookies/config
  verified unchanged at the end of every item. `/etc/hosts` restored.
  `/tmp/m7e-target` deleted after the final gate; `df -h /` verified after.

## Rust E2E results — `update --apply` (item 8) with real assets (Pi, `dev-rust` `459b9fa`, 2026-11-07)

M7c item 8 verified only `--dry-run`; the *apply* path (download →
checksum → extract → replace the running executable) had never run
against real release assets. Leg 9 of `scripts/e2e.sh` still says "a
non-dry-run update is never run" — that is a deliberate policy for the
harness on a **live install** and stays unchanged. This run was safe
because each binary updated **a throwaway copy of itself** in its own
temp directory, so the live install (`/usr/local/bin/castctl`) and the
live profile were never in the path.

Recipe (cue, one script, both binaries, Go first):

```sh
cp <binary> /tmp/upd/rs/castctl ; cp <go binary> /tmp/upd/go/castctl
cd /tmp/upd/<side> && ./castctl update --version 0.8.0 --allow-downgrade
```

Both sides target the real GitHub release asset
`castctl_0.8.0_linux_amd64.tar.gz` (17.4 MB) over the public network;
both binaries are stamped, so the version gate opens.

| Check | Go `0.9.0` (`1396697`) | Rust (`459b9fa`) |
|---|---|---|
| exit code | 0 | 0 |
| stdout | `castctl updated: 0.9.0 -> 0.8.0 (castctl_0.8.0_linux_amd64.tar.gz)` | identical |
| replaced file sha256 | `28ec8a798ed679c0…` | `28ec8a798ed679c0…` |
| replaced file size | 47,946,368 B | 47,946,368 B |
| `--version` after | `castctl 0.8.0 (d3efec4 2026-11-02T11:08:14Z)` | identical |
| normalised stdout diff | — | **IDENTICAL** (paths + durations normalised) |

Verdict: **PASS** — the Rust apply path produces a byte-identical
result to Go's on the same asset: same message, same exit code, same
replaced file, same reported version. Rollback-on-failure was not
re-run here (it is covered by the crate's unit tests over fake
binaries, `rust/castctl-update`); what this run adds is the real
download/verify/replace leg on a running process.

Both temp trees (`/tmp/upd`, `/tmp/upd-target`) were deleted after the
run; `df -h /` verified afterwards. No secret appears in this section.
