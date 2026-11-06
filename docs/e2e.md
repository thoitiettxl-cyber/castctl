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

