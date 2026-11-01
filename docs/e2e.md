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
| 8 | Telegram | `telegram status` offline JSON (`configured`, `token_valid`); bounded `telegram run` until SIGINT (exit 130). Message delivery / placeholder reply is manual, [NEEDS-MEASUREMENT]. See the token-source rule below. |
| 9 | Update | Unstamped refusal (exit 2, fixed message) is the PASS-able check for a script-built binary. A stamped `--dry-run` is SKIP with reason when unstamped. A non-dry-run update is never run. |
| 10 | Keeper | `keeper status` (state files only). `keeper check` can rewrite cookies, so it stays dry/SKIP on real profiles unless `--live-keeper` is given; exit 3 (entry stopped) is a distinct SKIP outcome, never a healthy PASS. `session-state.json` is checked at the per-profile path the keeper actually writes, `profiles/<name>/session-state.json`, mode 0600 when present. Real CDP re-export and single-flight refusal are [NEEDS-MEASUREMENT]. |
| 11 | Web UI | Loopback bind verified via `ss` (supplementary evidence; castctl itself validates loopback); non-loopback `--listen` exits 2 naming the loopback rule, without echoing the address (the listen check runs before the token check when a `webui` block exists; without a block the block gate fires first and the probe SKIPs); no-token and wrong-token both 401, good token 200 with `data.remote_exposure: false` (all success bodies are read under the `data` envelope); `GET /config` carries `<redacted>` markers at secret positions; `GET /settings/telegram` masked exactly `***` only when `data.configured` is true (unconfigured → SKIP); `/logs` gate `reason` compared against the config (closed enum: `logging_disabled`, `log_output_not_file`, `log_output_refused`); the server process itself (not a wrapper subshell) is killed and the port is verified closed after the leg. External-connect refusal is [NEEDS-MEASUREMENT]. |
| 12 | Module | `module/build.sh` with output/cache under the temp dir; `unzip -t`; member names via `unzip -Z1` (no `config.json` at any depth, no `*.key`); per-member counts-only secret scan (never extracted): label patterns FAIL only in text members — the payload binary legitimately embeds field-name/code strings, so in `payload/bin`/`payload/lib` only a private-key header is FAIL; `runtime.version` presence with the `loader_preflight` outcome recorded, never claimed as executed. ZIP SHA-256 is recorded, never asserted cross-host. On this VM, `build.sh` fails when its stage dir lands on the `/home` filesystem (`cp: failed to preserve ownership`); it succeeds with the default `/tmp` stage. |
| 13 | Secret scan | Counts only over captured outputs (Scope A). See below. |

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
- Tokens come only from the environment: `CASTCTL_TELEGRAM_TOKEN`
  and `CASTCTL_WEBUI_KEY`. They are never taken from argv and never
  embedded in the script or this document.
- Exit code is non-zero if any check FAILs. SKIP alone does not fail
  the run; the summary lists every SKIP with its reason.

## Prerequisites

| Prerequisite | If missing |
|---|---|
| `bash`, `python3`, `sha256sum`, `stat` | **Required.** The script fails fast (exit 2) with a clear message before creating anything. `python3` is stdlib only: the config tool and the Telegram injector use exactly one method, python3 stdlib — there is no `jq` fallback anywhere in the script or this document. |
| `go` (only when building), `curl` (web UI leg), `unzip` (module leg), `ss` (bind leg) | The affected checks SKIP with a reason naming the missing tool. Runs are bounded internally by the script; no external `timeout` command is needed. |
| A config file whose profiles have cookies files | Legs needing a live profile SKIP per profile with reason `no cookies file for profile`. Cookies presence is read from `profile list` (`cookies` field), never by reading a cookies file. |
| A running Chrome with remote debugging, for CDP re-export | The re-export sub-check SKIP with reason. Never faked with a stub CDP server. |
| Network to the release API, for a stamped `update --dry-run` | SKIP with reason. |
| `rg` and the other `module/build.sh` tools, for the module leg | SKIP with reason naming the missing tools. A build failure on a `curl:` download SKIP as network/cache; any other build failure is FAIL. |

Run with a normal environment: a warm Go build cache and the usual
proxy variables. A sterile environment (cold cache, no proxy vars)
makes the module leg SKIP on a `curl:` download and can make live
legs behave differently; headline counts are environment-dependent
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

## Secret scan (leg 13, counts only)

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
- ZIP SHA-256 is not cross-host reproducible; assert self-verification
  only (`unzip -t`, member list, per-member scan), never a cross-host SHA.
- The payload binary embeds field-name strings, so the module ZIP
  scan must not FAIL on label patterns inside `payload/bin`/`payload/lib`
  (measured 2026-11-01: all label hits inside `payload/bin/castctl`).
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
8. `telegram run` live (GetMe/poll, placeholder reply to a real
   message, approval fail-closed, no token in logs).
9. Web UI `PUT /config`, `PUT /dns`, `PUT /settings/telegram`
   (sentinel keep, empty-token unchanged, 409 guard), login/endpoint
   import echo checks, create/patch response echo checks,
   non-loopback connect attempt.
10. `keeper check`/`run` against a live profile (cheap-chain outcome,
    expiry detection, state-file contents).
11. Same-host repeat-build ZIP equality for `module/build.sh`.

Nothing in this document claims any of the above as proven. Each is
either SKIP with reason in the script or a manual step for the
operator's live run.
