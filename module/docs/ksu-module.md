# castctl KernelSU module

KernelSU module that runs castctl on a rooted Android phone. Base:
castctl `origin/main` `8cb361f` (v0.6.4 + PR #19 session keeper,
rebased from `6d3baac`); template:
cli-proxy-api at commit `f912a733f84a3157e6570d84c05e5a02439d3ff0`.
Structure and conventions mirror the template; every deviation is
listed in §9 with a reason. Nothing in this document is claimed
live-tested on a phone: all device behaviour is tagged
`[NEEDS-MEASUREMENT]` and gated in §11.

## 1. Install / flash

Build the ZIP on any Linux host (see §8), then flash it in the
KernelSU manager. Install requirements, enforced by `customize.sh`
(install aborts loudly on failure; nothing half-installed starts):

- ARM64 device only (`ro.product.cpu.abi` must be `arm64-v8a` or
  `aarch64`).
- Manager install only (`BOOTMODE` must be true); recovery installs
  are refused.
- Payload checksum verification from the embedded manifest
  (`payload/checksums.sha256`); content-addressed release
  publication under `releases/<id>-<sha>/` with an atomic `current`
  symlink swap, exactly as in the template.

> **Trust boundary:** the embedded manifest defeats corruption and
> partial writes only; it does not prove the ZIP is authentic —
> authenticity comes from the release download checksum, verified
> before flashing.

After flashing, reboot (or hot-install if the manager supports it;
the module does not request hot install — see §11, gate 18).
`customize.sh` never starts the daemon.

## 2. Data layout (verified against the base tree)

`DATA_DIR` is `/data/local/castctl`, overridable via the
`CASTCTL_DATA_DIR` environment variable (see §2.1). The module dir
`/data/adb/modules/castctl` holds ONLY scripts (`customize.sh`,
`service.sh`, `action.sh`, `uninstall.sh`, `scripts/castctl-ctl`)
plus static module files — no payload, no config, no data. Data
survives module updates AND uninstall.

```
DATA_DIR/                              (0711)
  releases/<release_id>-<sha>/        (0755 dirs, 0644 files, bin+lib 0755)
    bin/castctl                       (the v0.6.4 glibc binary)
    lib/ld-linux-aarch64.so.1, libc.so.6, libdl.so.2,
        libresolv.so.2, libpthread.so.0
    ca/cert.pem
    runtime.version, checksums.sha256
  current -> releases/<release_id>-<sha>/   (symlink, atomic swap)
  config/
    config.json                       (0600; never auto-created)
    config.json.example               (example copy, never activated)
    profiles/                         (0700)
      <name>/cookies.txt              (0600; created by castctl)
      <name>/chat.json                (created by castctl)
      <name>/telegram.json, telegram-state.json (via Profile.Dir)
      <name>/session-state.json       (0600; keeper observed state,
                                       created by the keeper — see §4)
      <name>/keeper-<tag>.owner       (keeper single-flight heartbeat,
                                       created by the keeper — see §4)
  plugins/                            (0700)
    linux/arm64/                      (0700; reserved, see §6)
  run/                                (0700; castctl.pid, enabled, tmp/)
  logs/                               (0700; castctl.log, controller.log + rotations)
  backups/                            (0700; state archives, 0600)
  .controller/                        (0700; lifecycle workspaces)
DATA_DIR.lifecycle.lock               (0600; OUTSIDE the data tree, so
                                       purge cannot replace the locked inode)
```

Default-profile exception: for the default profile, `cookies.txt`,
`chat.json`, `telegram.json`, `telegram-state.json`, and
`session-state.json` live directly under `config/` (per
`ProfilePaths`), not under `config/profiles/default/` — the
`<name>/` lines above describe named profiles.

Layout verification (base tree, `internal/profile/`):

- `configlocation.go`: the directory of the `--config` file is
  `CONFIG_DIR` for the whole invocation; `--config` (else
  `CASTCTL_CONFIG`) always names the config file explicitly here,
  so no home/XDG resolution is relied on.
- `profile.go` `ProfilePaths(baseDir, name)`: named profiles live
  at `baseDir/profiles/<name>/` with `cookies.txt` (default),
  `chat.json`, and a legacy `config.json`; the default profile
  uses `baseDir` itself (`cookies.txt` directly under the config
  dir). With `--config $DATA_DIR/config/config.json`, `baseDir`
  is `$DATA_DIR/config`, hence `config/profiles/<name>/cookies.txt`.
  `EnsureProfileDir` creates `profiles/` and per-profile dirs at
  `0700`. The module creates the empty `config/profiles/` dir at
  install (0700) and creates no profile dirs or cookies files.
- Keeper state filename: VERIFIED on the 8cb361f tree (PR #19
  merged). `internal/keeper/state.go:40`:
  `StateFileName = "session-state.json"`, mode 0600, in the
  profile directory — one file per profile, observed state only
  (names and expiry dates, never cookie values). With
  `--config $DATA_DIR/config/config.json`, named profiles keep
  it at `config/profiles/<name>/session-state.json`; the default
  profile keeps it directly under `config/` (per `ProfilePaths`).
  The keeper's single-flight owner file is
  `keeper-<tag>.owner` in the same profile directory
  (`internal/keeper/run.go:144-151`), heartbeat 60 s, stale
  after 120 s; a second `keeper run` for the same entry refuses
  with exit 2 while the first is alive. The module creates
  neither file; the keeper creates and owns both. State/owner
  files are inside `config/`, so `backup` archives them and
  `purge-data` removes them with the rest of the data dir.
- `telegram.json` / `telegram-state.json` live under the active
  profile's `Dir` (`internal/commands/profilecmd.go`), i.e. under
  `config/profiles/<name>/` for named profiles, directly under
  `config/` for the default profile.

### 2.1 `CASTCTL_DATA_DIR` override and the template discrepancy

The template implements its data-dir override (`CPA_DATA_DIR`) in
the controller (`scripts/cpactl`) only; its `customize.sh`
hardcodes `/data/local/cli-proxy-api` and does not honour the
override (verified by grep: `CPA_DATA_DIR` occurs only in
`cpactl`). This module implements `CASTCTL_DATA_DIR` in BOTH
`customize.sh` and `scripts/castctl-ctl` (Boss-directed), requiring
an absolute path. The override exists for testing; on a real
device it should be left unset. `CASTCTL_MODULE_DIR` and
`CASTCTL_LIFECYCLE_LOCK` mirror the template's controller
overrides in the same way.

Uninstall resolves the data dir from an explicit
`CASTCTL_DATA_DIR` first, then the install-time record
`$MODPATH/.castctl-data-dir` written by `customize.sh`, then the
default. An explicit override that differs from the install-time
dir still wins and can orphan the daemon: the override must
match the install-time value (or be unset) at uninstall time.

## 3. Config

Write `config/config.json` by hand (mode 0600). The module never
creates it and never writes into it. The example is copied only as
`config.json.example`, and only when neither a real config nor an
example exists yet: a user-placed example is never overwritten.

Minimal valid example (`config.example.json` in the module):

```json
{"default_profile":"default","log":{"level":"info"},"profiles":{"default":{}}}
```

Config rules that matter here (base tree, strict parser):

- Exactly 9 top-level keys; unknown keys are rejected (exit 2).
  The `keeper` key exists on this HEAD (PR #19 merged); there is
  still NO `webui` or `plugins` key — adding one makes every
  castctl command fail. See §4.
- Cookies live only in a separate cookies file (`cookies_file`
  resolves relative to `CONFIG_DIR`); inline `cookies` keys are
  rejected. Use `auth import` (stdin-only) to populate cookies;
  the module never echoes cookie material.
- `telegram` block keys (exactly 5): `profile`, `token`,
  `allowed_user_ids`, `auto_approve`, `auto_allow_once`. The
  config block is the only token source on this HEAD. Never put
  the token anywhere else, never log it.
- `keeper` block (verified, `internal/profile/keeper.go`): an
  ARRAY of entries, each with exactly the keys `tag`, `profile`,
  `browser`, `interval`, `notify` — unknown keys rejected, exit 2.
  `tag` required (unique; names the `keeper-<tag>.owner` file);
  `profile` required (must name a key of `profiles`; one entry
  per profile); `browser` required (loopback-only CDP debug URL,
  `http`/`ws`, port required, no query/fragment/userinfo);
  `interval` optional (duration string, default 24 h, max 1 y);
  `notify` optional (only `"telegram"`, which requires the
  `telegram` block to exist). Absent block = keeper off, no
  behaviour change. An empty array (`"keeper": []`) is valid and
  means no entries. A present block is preserved verbatim on
  save; the module never writes config.

## 4. Gating: what starts, and when

The controller manages up to TWO foreground processes, each with
its own PID file and log, started only when the config gates
them in. All command names, flags, and shapes below were verified
against the 8cb361f tree (PR #19 merged), not assumed:

- `castctl --config <path> telegram run` — only when a
  `telegram` top-level OBJECT block is present. Foreground,
  blocking, SIGINT-only; exit 130 on an intentional stop is
  normal. (`internal/commands/` telegram command; no listener:
  it listens on no port.)
- `castctl --config <path> keeper run` — only when a `keeper`
  top-level ARRAY block is present AND non-empty. Foreground,
  one goroutine per entry, immediate tick then the entry
  interval (±20% jitter, default 24 h); SIGINT ends it (exit
  130 via the main contract); it returns when every entry
  stops sticky or the context ends
  (`internal/commands/keeper.go:22-28`, `internal/keeper/run.go:21-31`).
  An empty array (`"keeper": []`) prints `keeper: no entries
  configured` and exits 0 — the controller treats it as
  "keeper off" and does not start the process. A second
  `keeper run` for the same entry refuses (exit 2) via the
  single-flight owner file while the first is alive
  (`internal/keeper/run.go:119-151`); the controller's own
  PID-file + cmdline check is the first guard, the owner file
  the second. If a stale owner heartbeat (≤120 s) refuses a
  restart right after a kill, the watchdog retries with
  backoff — self-healing, `[NEEDS-MEASUREMENT]` on device.
- Web UI: NEVER started. No `webui` config key and no web UI
  command exist on this HEAD. If any `webui` key is present,
  the controller starts NOTHING and logs why: the strict
  parser rejects the whole file, so no command can run against
  it. Re-survey after item 2 lands; its command name and flags
  must be taken from the tree, never assumed.

Detection uses the module's own lexical top-level key probe
(`probe_top_key` in `scripts/castctl-ctl`): depth-1 keys, with
string escapes decoded (`\uXXXX` for ASCII keys) and nested keys
ignored, in four modes
(object value, non-empty array, empty array, any value). Limits,
stated honestly:

- The probe is presence-and-shape-only, not validation. Entry
  fields, browser URLs, profile references, token shape, and
  allowed-user rules are castctl's job; an invalid block makes
  the child exit 2 quickly and the controller logs that
  (fail-soft). A malformed `keeper` shape (key present, not an
  array) or `telegram` shape (key present, not an object) is
  logged as a warning and that service is not started — but
  the strict parser rejects the whole file, so the OTHER
  service's start will fail too; the child exit is the arbiter.
- The probe is a lexical scan, not a JSON parser. Malformed JSON
  may still report presence; castctl's parser is the final
  arbiter. A key spelled inside a top-level string value with
  the exact `"key": {` / `"key": [` shape could false-positive;
  the child exit is again the arbiter. `[NEEDS-MEASUREMENT]`
  for adversarial configs on device (none expected in practice).
- Probe decoding limits (loop-1 fixes, fixtures f15–f20): an
  escaped quote inside a key reconstructs correctly, so
  `"tele\"gram"` is NOT `telegram`; `\uXXXX` escapes in keys
  decode for ASCII code points (`"tele\u0067ram"` IS
  `telegram`), while code points ≥ U+0080 decode to a
  placeholder that never equals a wanted key (documented
  limit: non-ASCII keys are not recognised); a top-level array
  wrapper (`[{"telegram": ...}]`) is ignored — its contents
  never count as top-level keys; a valueless key
  (`{"telegram":}`) counts as present for `any` mode only, not
  for object/array modes. Comment-like array content
  (`{"keeper": [ /*x*/]}`) still counts as a non-empty array:
  fail-soft, the parser is the arbiter.
- The keeper needs an already-running Chrome holding the
  profile's login, reachable at the entry's loopback CDP URL
  (`internal/profile/keeper.go`, `browser` rule). The module
  NEVER launches a browser: with no browser attached, ticks
  fail/export-fail and entries stop sticky, and `keeper run`
  returns; the watchdog re-runs it at backoff cadence. Whether
  a phone Chrome can even expose a CDP port is
  `[NEEDS-MEASUREMENT]` (live gate 12) — the keeper is
  unproven on device until then.
- Neither block present → start is a successful no-op: nothing
  is started, no enabled marker is written, the watchdog stays
  idle.

`castctl update` is never invoked by the module (user-invoked
only; it would replace the pinned binary from the network and
fight the checksum-pinned install).

## 5. Service lifecycle

- `service.sh` is the single late-start hook (see §10 for the
  bootloop-safety proof). It waits for `sys.boot_completed`
  (bounded getprop polling, 120 s cap), checks the `disable`
  file, starts via the controller, then watchdogs with
  exponential backoff (30 s base, doubling, 300 s cap; counter
  resets on success). The backoff sleep is interruptible: it
  runs in 5 s chunks re-checking `disable` each chunk, so
  disabling the module stops the daemon within seconds rather
  than after a full backoff delay. Each watchdog iteration runs
  `castctl-ctl start --watchdog` (idempotent per service:
  running services are left alone, missing wanted services
  are restarted — so one dead service is repaired while the
  other lives). The watchdog only runs while the `run/enabled`
  marker exists. The marker means "a start was requested and
  not explicitly stopped": it is written even when a start
  fails (so a later config fix recovers without a reboot) and
  removed only by an explicit stop. The watchdog loop never
  exits on repeated failure alone, by design (backoff-capped):
  a later config fix recovers without a reboot.
- Each child runs under the bundled glibc loader:
  `ld-linux-aarch64.so.1 --library-path <lib> castctl --config
  <path> telegram run` (log `logs/castctl.log`, PID file
  `run/castctl.pid`) or `keeper run` (log `logs/keeper.log`,
  PID file `run/keeper.pid`), each wrapped in busybox
  `timeout` with a 86400 s lifetime bound
  (`CASTCTL_CHILD_LIFETIME`), because castctl provides no
  lifetime bound of its own. When the bound fires, the
  watchdog restarts the service. Whether busybox `timeout`
  forwards signals to the child on this device is
  `[NEEDS-MEASUREMENT]` — and stop does not rely on it: after
  the wrapper PID is gone, stop always re-scans `/proc` for
  remaining processes matching the service pattern and
  signals them too, so a non-forwarding timeout cannot leave
  an orphan that `is-running` reports as stopped. Before
  starting, the controller likewise scans for an
  already-running match and refuses to start a duplicate.
  Readiness matching assumes the device busybox `timeout`
  preserves the full argv in `/proc/<pid>/cmdline` —
  `[NEEDS-MEASUREMENT]` (live gates 3, 12, 13). The keeper's own cadence (24 h default) is
  independent of the lifetime bound; a keeper whose entries
  all stop sticky exits on its own and is re-run at watchdog
  backoff cadence (bounded, logged).
- Stop signals SIGINT first (castctl handles SIGINT; exit 130 from
  an intentional stop is normal), signals SIGINT again after a
  re-scan, then escalates SIGTERM then SIGKILL with bounded
  waits (5 s + 5 s + 3 s + 1 s ≈ 14 s at defaults, plus scan
  time), and stops BOTH services. Whether SIGINT reaches the
  Go binary when backgrounded is unproven: a non-interactive
  shell ignores SIGINT/SIGQUIT for `&`-launched jobs, and
  whether castctl's `signal.NotifyContext` resets an inherited
  SIG_IGN is a live gate (gate 24) — TERM/KILL termination is
  what the probes prove, so no claim here relies on SIGINT
  delivery. Stop removes the enabled marker so the watchdog does not
  restart. Each PID file is validated against the live process
  cmdline including the service subcommand (`telegram run` /
  `keeper run`, never a bare PID, never the other service's
  process); stop signals the recorded PID AND every `/proc`
  match for the pattern, re-scanning after the wrapper exits,
  so an orphaned child is stopped even when the PID file is
  gone or the wrapper did not forward the signal.
  `/proc/<pid>/exe` is deliberately not checked: the recorded
  PID is the `timeout` wrapper (whose exe is the timeout
  binary) and the child exe is the loader, so an exe allowlist
  would admit the wrapper's exe class and add nothing beyond
  cmdline matching; spoofing still requires root-equivalent
  write access to the PID file or `/proc`.
- `action.sh` toggles start/stop, prints status, and shows the
  last 10 controller log lines. `castctl-ctl log [telegram|keeper]
  [N]` tails a service log explicitly (default telegram).
  `castctl-ctl doctor` re-runs the runtime check plus gating
  checks (it never runs `keeper check`: that does network and
  browser work). `castctl-ctl backup` archives `config/` +
  `plugins/` (0600); the archive contains cookies and keeper
  state — treat it as secret material, never share it.
- Every controller write path refuses symlinks (PID files,
  enabled marker, controller/service logs, backup archive):
  a planted symlink never redirects a write outside the data
  tree. The refusal covers parent dirs too: a symlinked data
  dir, `releases/` dir, or logs dir is refused, and `log()`
  never appends through a symlinked logs dir (a guard refusal
  is reported to stderr only, never written through the link).
  The `current` symlink must resolve to exactly one directory
  component under `releases/` (a trailing `/`, `/.`, or
  multi-component remainder is refused — `[ -L ]` resolves
  through such suffixes), and every file under a release must be
  listed in its checksum manifest — an unlisted file refuses
  the start (and the install). The service-log symlink check is
  re-run immediately after launch: a link swapped in between
  the pre-launch check and the redirect is caught and the
  child killed, but that check-then-open window (milliseconds)
  cannot be closed in shell and is a documented residual.
  Numeric environment overrides
  are validated and clamped to sane ranges (garbage falls back
  to defaults), so a bad override cannot defeat a bound; the
  bootloop proof in §10 holds with overrides set, not only
  under defaults.
- The daemon runs as root in module context. The template drops
  to UID:GID 9999:3003; this module deliberately does NOT copy
  that: castctl creates and owns profile/cookie files under
  root-owned 0700/0600 dirs, and no UID/GID on this device has
  been verified to work for it. `[NEEDS-MEASUREMENT]` — revisit
  only with device evidence.

## 6. Plugins: reserved, never loaded

`DATA_DIR/plugins/linux/arm64/` (0700) is created at install and
preserved across module updates and uninstall, exactly like the
template's mechanism (verified in the template clone):

- Plugins live in persistent `$DATA_DIR/plugins`, OUTSIDE
  `releases/`; a release symlink swap therefore never touches
  them. `customize.sh` never deletes the directory; the build
  never stages a `plugins/` payload dir.
- If a previous layout kept plugins under the old release dir
  (`$DATA_DIR/current/plugins`), `customize.sh` copies them
  forward to `$DATA_DIR/plugins/` before swapping `current`
  (the template's v1.1 migration, mirrored). Before the
  forward-copy, an existing `current` symlink is validated to
  resolve under `releases/`; the payload manifest records
  `plugins=reserved-external` — the payload itself contains no
  plugins, the reservation is the external `DATA_DIR/plugins/`
  dir, preserved across updates.
- The checksum manifest covers only the payload; no plugin files
  are checksummed or verified by the module.

Castctl plugins are NOT built yet (they come after phase 2). This
module writes NO loader code: no plugin discovery, loading, or
invocation of any kind. The controller counts files in the dir
for `status` display only and never executes them.

Standing future invariant (from the 2026-10-29 plugin contract):
plugins must NEVER receive raw WireGuard keys or cookies —
outbounds reach plugins via a per-session local proxy and cookies
stay scoped. No part of that contract is implemented here; the
invariant is recorded so the future loader work inherits it.

## 7. Logs and rotation

- Controller log: `logs/controller.log`. Telegram log:
  `logs/castctl.log` (the daemon's stdout/stderr). Keeper log:
  `logs/keeper.log` (one summary line per tick, names/counts/
  outcomes only — the keeper never prints values). Rotation is
  checked whenever the controller logs or a service starts:
  each log rotates at 1 MiB
  (`CASTCTL_LOG_MAX_BYTES`), keeping 3 rotated files
  (`CASTCTL_LOG_KEEP`). A service log can therefore exceed
  1 MiB within one 86400 s lifetime, since rotation is only
  checked at those boundaries. Rotation renames only; the
  running daemon keeps its open file descriptor and a fresh
  file is used on the next start. Fresh log files are created
  owner-only (`umask 077` in the controller and in the
  `service.sh` background body) before any chmod pass.
- The module scripts never log config contents, tokens, cookies,
  or secret-bearing command lines. `status` prints paths and
  presence/absence only. The core log is castctl's own output:
  whether castctl itself ever logs secrets is a property of the
  core binary, not of these scripts, and is a live gate (§11).
- Harness proof: a fake secret planted in the test config must
  appear in NO log after exercising every controller path (see
  §8). On the device, re-check after the first real run.

## 8. Build and harness

Build (host-side, any Linux host with the tools listed in
`build.sh`):

```sh
CASTCTL_MODULE_OUT_DIR=/path/to/out ./module/build.sh
# default output: module/dist/castctl_ksu_v0.6.4.zip + .sha256
```

`build.sh` downloads the pinned castctl tarball, glibc `.deb`,
and Alpine CA `.apk`, verifies every hash, validates ELF/AArch64,
the 5-library subset, and max GLIBC ≤ 2.17, stages the payload,
writes and self-verifies `payload/checksums.sha256`, refuses
secrets, and writes a deterministic ZIP. Secret refusal is
filename + private-key-header + unexpected-JSON only: it refuses
`config.json`/`*.key` filenames, unexpected `.json` files, and
any `BEGIN ... PRIVATE KEY` header anywhere in the stage. It is
NOT general secret scanning; the shipped tree is verified
secret-free by grep (see the harness secrets case). The glibc-loader
execution preflight (`--list`, `--version`) runs only on an
AArch64 host or under `qemu-aarch64`; on other hosts it is
skipped with a recorded warning (`loader_preflight=skipped` in
`runtime.version`) and the device-side `runtime_check()`
`--version` preflight is the execution proof. `shellcheck` was
not available on the build host; scripts were checked with
`sh -n`/`bash -n` and by execution in the harness.

Simulated harness (scratch only, never shipped):
`~/workspace/tmp/castctl-ksu/writer/harness/` — stubbed KernelSU
env (`MODPATH`, busybox shim, `getprop`/`resetprop` stubs),
a fake `castctl` (argv logging, SIGINT → exit 130), and a fake
release tree. The busybox shim delegates applets to host GNU
tools and the fake loader `exec`s the child, so harness
evidence proves GNU-tool semantics; busybox `flock`/`timeout`/
`nohup`/awk dialect on the device remains
`[NEEDS-MEASUREMENT]`. 41 cases, all passing (run serially,
twice): install success +
checksum-fail install; unlisted-payload-file install refused;
disable present → no start; missing binary → log + exit 0; bad
config → no start + exit 0; telegram absent → no start, present
→ start; keeper absent → no start, present-but-empty (`[]`) →
no start, present non-empty → start with the verified
`keeper run` invocation (fake castctl records argv, including
the `--config` flag and no selector flags); keeper present with
a non-array shape → no keeper start + warning; webui present →
no start; `has_top_block`/`has_top_nonempty_array`/
`has_top_empty_array` fixtures f1–f20 (nested keys, string
traps, malformed JSON, multi-line arrays, empty vs non-empty,
escaped quotes, `\u` keys, top-level arrays, valueless keys);
stop-kills-only-matching-service (keeper stop must not signal
the telegram process when the keeper PID file is missing);
non-forwarding-`timeout` stop (orphan killed by the `/proc`
scan, `is-running` reports stopped, restart creates no
duplicate); symlink refusal for PID/enabled/log/backup paths
(victims untouched); `current`-outside-`releases/` refused;
`current` escape variants refused (`/.`, trailing `/`, `//`,
multi-component, `..`, absolute outside — victims untouched,
good release still passes); symlinked data dir / `releases/`
refused (victims untouched); symlinked logs dir refused (no
file in the victim, including from a dispatch-level refusal);
symlinked install-time data-dir record refused (victim
untouched, install aborts);
pre-placed example preserved; stale quarantine cleaned;
env-override clamping; fresh-log 0600 modes; uninstall
data-dir record; interruptible watchdog sleep (disable stops
promptly); relative data-dir refused; status version
unavailable; process matching in the harness is scoped to the
case's own directory, so concurrent harness runs cannot
pollute each other's orphan/duplicate assertions (runs are
serial); action toggle; uninstall keeps data; purge guard
refuses a wrong path and runs only with `--yes`; plugin file
survives update + uninstall; log rotation cap; boot_completed
timeout; flock timeout; watchdog backoff; fake-secret grep
proof. The
arm64 binary cannot execute on the x86_64 build host:
`castctl --version` on device is `[NEEDS-MEASUREMENT]`
(live gate 22).

Test-only environment overrides (documented here so reviewers
can tell them from device behaviour; never set on the device):
`CASTCTL_TEST_MODE`, `CASTCTL_BUSYBOX`, `CASTCTL_MODULE_DIR`,
`CASTCTL_DATA_DIR`, `CASTCTL_LIFECYCLE_LOCK`,
`CASTCTL_FLOCK_TIMEOUT`, `CASTCTL_READY_TIMEOUT`,
`CASTCTL_BOOT_WAIT_TIMEOUT`, `CASTCTL_BOOT_POLL_INTERVAL`,
`CASTCTL_WATCHDOG_BASE`, `CASTCTL_WATCHDOG_MAX`,
`CASTCTL_CHILD_LIFETIME`, `CASTCTL_STOP_INT_WAIT`,
`CASTCTL_STOP_TERM_WAIT`, `CASTCTL_LOG_MAX_BYTES`,
`CASTCTL_LOG_KEEP`, `CASTCTL_MODULE_OUT_DIR`,
`CASTCTL_BUILD_CACHE_DIR`, `CASTCTL_ALLOW_UNATTESTED_INPUTS`,
`CASTCTL_SOURCES_LOCK` (rejected when set, as in the template).
Numeric overrides in the controller and `service.sh` are
validated and clamped to sane ranges (garbage falls back to
defaults); the remaining overrides are paths/modes and are
validated for absoluteness where a relative value would be
ambiguous. Old releases under `releases/` are never pruned
(template parity): one release dir per update, a few tens of
MB each; remove old `releases/<id>-<sha>/` dirs by hand (except
the one `current` points at, while the daemon is stopped)
when disk space matters.

## 9. Deviations from the template (each with a reason)

| # | Template behaviour | This module | Reason |
|---|---|---|---|
| D1 | BusyBox/PATH Magisk-first everywhere | KernelSU-first (`/data/adb/ksu/bin`), Magisk fallback | Boss decision; target is KernelSU |
| D2 | Bundled glibc used as-is (template) | Same mechanism (bundled glibc + loader) | Boss glibc decision: follow the template; do not depend on any other module. Supersedes the old glibc-module plan note |
| D3 | `SKIPMOUNT=false` + `PROPFILE=true`, no `system.prop` | `SKIPMOUNT=true`, no `PROPFILE` line | No `system/` dir exists to mount and no prop file to load; the template's flag combination is unresolved in research |
| D4 | No `system/` content except `system/bin/cpactl` shim | No `system/` dir at all | Nothing to mount; with no overlay the metamodule mounting path is irrelevant to this module's files. No convenience shim (nothing may depend on it) |
| D5 | Unbounded `boot_completed` wait (`resetprop -w` loop) | Bounded getprop polling, 120 s cap, no `resetprop -w` | Hard rule: timeouts. `resetprop -w` semantics on KernelSU 32680-5 are unconfirmed |
| D6 | Unbounded `flock` wait in boot start | `flock -w 30` (env-overridable) for boot/doctor/backup; `-n` ignore for watchdog | Hard rule: timeouts |
| D7 | Infinite watchdog, fixed 30 s, no backoff | Exponential backoff 30 s → 300 s cap, failure counter; backoff sleep interruptible in 5 s chunks re-checking `disable`; numeric overrides clamped | Hard rule: a broken config must not spin; recovery without reboot is preserved; disable stops the daemon within seconds |
| D8 | No log rotation, no redaction | 1 MiB rotation, 3 kept; module never logs secrets | Boss decision (rotation + no secrets). Template log() prints verbatim |
| D9 | Daemon dropped to 9999:3003 | Runs as root; no chown to 9999:3003 | No verified UID/GID for castctl on this device; root-owned 0700/0600 dirs are the secret boundary. `[NEEDS-MEASUREMENT]` |
| D10 | `update-core` follows `releases/latest` with rollback | No updater at all (no `update-core` command) | Pinned-only installs (Boss); `castctl update` must never run unattended and would fight the pinned install |
| D11 | Listener-based readiness + foreign-listener fail-closed | Process + cmdline readiness per service (subcommand pattern distinguishes telegram/keeper); no port logic | `telegram run` and `keeper run` listen on no port; there is no listener to check or protect |
| D12 | `config_is_safe` enforces host/port/plugins.dir | Gating probe only (presence + shape of `telegram`/`keeper`/`webui` blocks; keeper = non-empty array) | Castctl has no host/port config keys; its strict parser is the validator. No castctl key is invented; keeper shape verified on 8cb361f |
| D13 | `customize.sh` hardcodes the data dir; only the controller honours `CPA_DATA_DIR` | `CASTCTL_DATA_DIR` honoured in both scripts | Boss-directed override; discrepancy recorded in §2.1 |
| D14 | CA bundle read from the Alpine build host file | CA bundle downloaded as a pinned `.apk`, cert.pem extracted + verified | Host independence: `build.sh` must run on any Linux host, not only Alpine |
| D15 | CA pin `20260611-r0` / sha `b8d83784…` | CA pin `20261020-r0` / apk + cert.pem hashes verified by download | Template pin is not in the Alpine index (404); the current bundle was verified instead. See `sources.lock` |
| D16 | `action.sh` shows the last 10 core-log lines | `action.sh` shows the last 10 controller-log lines; core log via explicit `castctl-ctl log` | Controller log is secret-free by construction; core output is shown only on explicit request |
| D17 | `system/bin/cpactl` shim + `update-core`/`doctor` plugin checks | No shim; `doctor` has no plugin/listener checks; `status` counts plugin-dir files only | No system overlay; no plugins exist yet; no loader code by design |
| D18 | Legacy controller quarantine + v1.1 lock + plugin-path migration | Quarantine kept; legacy lock and config-path migration dropped; plugin forward-copy kept; stale quarantine removed (not fatal) when the live controller exists; example copied only when neither config nor example exists | First module release: no legacy castctl controller/layout exists. The forward-copy is kept as the same defensive shape as the template |
| D19 | `allow-root-core` marker opts into root | No marker; root is the only mode (see D9) | Single documented mode; no silent identity switch |
| D20 | `set_perm_recursive` covers the whole module dir | `webroot/` excluded from permission setting | KernelSU sets webroot permissions/SELinux itself and warns against setting them by hand |
| D21 | Controller writes follow symlinks (PID files, markers, logs) | Every controller write path refuses symlinks, including a symlinked data dir, `releases/` dir, or logs dir (`log()` never appends through one); `current` target must be exactly one component under `releases/`; sensitive data dirs refused when symlinked | Hardening beyond the template: a planted symlink must never redirect a write outside the data tree (loop-1 F1; loop-2 F2/B1) |
| D22 | Checksum check covers listed files only | Install and start refuse a release containing files not listed in `checksums.sha256` (manifest allowlist) | An unlisted executable planted in the release tree must not survive install (loop-1 red-team N4) |

## 10. Bootloop safety — proof table

Review check name: **bootloop safety**. Each row must be tickable
from the scripts as written; static review alone does not close
the case — the live gates in §11 are part of the proof. Safe mode
is a recovery procedure for Boss, never a design argument.

| Script path | Cannot block | Cannot loop | Failure exits 0 | Proof required |
|---|---|---|---|---|
| `customize.sh` (install-time, not boot) | No unbounded wait: downloads happen only in `build.sh`, never here; `flock -n` fails fast; `abort` is the only failure exit | No `while` loop without a bound (the only loop scans quarantine candidates, a finite glob) | Install failure exits via `abort` (installer cleanup), never bare `exit 1` | Static: read the file. Live: install completes or aborts cleanly; phone reboots normally. `[NEEDS-MEASUREMENT]`. Lock parent is created before the lock check; a stale quarantine is removed (not fatal) when the live controller exists; the example is copied only when neither config nor example exists; the payload allowlist is enforced; an existing `current` target is validated under `releases/` before the plugin forward-copy; a symlinked data dir or `releases/` dir aborts the install before anything is written below it; the install-time data-dir record refuses a symlink |
| `post-fs-data.sh` | — (must not ship) | — | — | Proof is absence: file must not exist in the ZIP or module dir. Any future addition reopens this section |
| `post-mount.sh` | — (must not ship) | — | — | Proof is absence, as above |
| `boot-completed.sh` | — (must not ship) | — | — | Proof is absence, as above |
| `service.sh` (foreground) | Foreground contains only variable setup + one background launch `(...) &` + `exit 0`. No `sleep`, `wait`, `flock`, or daemon invocation | Foreground contains no loop | Foreground exits 0 unconditionally; no `set -e` | Static: read the file. Live: boot-completed time with module enabled vs disabled. `[NEEDS-MEASUREMENT]` |
| `service.sh` (background body) | Runs parallel with boot (backgrounded). `boot_completed` wait is bounded polling (120 s cap). `start --boot` uses `flock -w 30`. Readiness wait is 10 s. Stop escalation is ≈14 s (2×5 s INT + 3 s TERM + 1 s, at defaults, plus scan time). All four env-overridable bounds are validated and clamped, so the bounds hold with overrides set | Watchdog sleeps (30 s → 300 s backoff) between iterations, in 5 s chunks re-checking `disable` with exit; consecutive-failure counter caps the rate; no respawn without sleep | Every start/stop invocation ends `|| true`; disable/missing-controller exits are `exit 0`; no `set -e`, no bare failing command as the body's last word | Static: read the file; count sleeps, bounds, `|| true`s. Live: boots with config removed, binary removed, and `disable` created mid-boot. `[NEEDS-MEASUREMENT]` |
| `action.sh` (manager button, not boot) | Returns promptly; no wait loops; controller readiness wait is bounded (10 s) | No loop | Exits 0 even when start/stop fails (`|| true` everywhere) | Static: read the file. Live: tap Action running and stopped. `[NEEDS-MEASUREMENT]` |
| `uninstall.sh` | Returns promptly; stop is best-effort (`|| true`); no waits; stop resolves the data dir from an explicit env, then the install-time record, then the default | No loop | Exits 0 unconditionally | Static: read the file. Live: uninstall + reboot, no orphan daemon. `[NEEDS-MEASUREMENT]` |
| `scripts/castctl-ctl` (invoked by the above) | Every wait bounded: flock 30 s, readiness 10 s, version probe 10 s, stop ≈14 s (2×5 s INT + 3 s TERM + 1 s, at defaults, plus scan time), child lifetime 86400 s (all env-overridable values validated and clamped). Stop always re-scans `/proc` after the wrapper exits, so a non-forwarding `timeout` cannot orphan a child; readiness-failure and mid-start symlink kills go through the same scan | No unbounded loop: watchdog backoff lives in `service.sh`; controller loops are all iteration-capped | Controller exit codes never propagate to boot: `service.sh` swallows them with `|| true`; manual invocation reports failures honestly (non-zero) | Static: read the file. Live: as for `service.sh` background body. Every write path refuses symlinks (including symlinked data dir / `releases/` / logs dir); `current` target must be a single component under `releases/` and the manifest allowlist is validated on every runtime check |
| `initrc/`, `preinit/`, `system/`, `system.prop`, `sepolicy.rule`, `/data/adb/*.d/` scripts | — (must not ship) | — | — | Proof is absence in the ZIP listing. `initrc` content would still run in safe mode, so absence is load-bearing, not cosmetic |

Additional hard-rule properties, verified by grep over the tree:

- No `setprop`, `mount`, `umount`, `resetprop`, or sepolicy tool
  invocation in any shipped script (reads via `getprop` only, in
  `customize.sh` ABI check and `service.sh` boot polling).
- No write outside the module folder, `DATA_DIR`, and the
  lifecycle-lock sibling file `${DATA_DIR}.lifecycle.lock`
  (0600, symlink-refused, created only after its parent
  exists). Every other write path refuses symlinks, so no
  write can be redirected outside the tree via a planted
  link. No general scripts installed under `/data/adb/*.d/`.
  (Plus the manager-owned `disable`/`remove` flag files, which
  scripts only read.)
- `disable` is honoured before the first start and on every
  5 s chunk of the watchdog sleep (stop + exit). `remove` is a manager-level
  flag (module removed next reboot); `uninstall.sh` handles the
  removal path. Whether the manager skips `service.sh` for a
  disabled module is manager behaviour `[NEEDS-MEASUREMENT]`.
- No `post-fs-data` work of any kind; no early-boot setup is
  assumed anywhere.

## 11. Needs from item 2 (web UI) + live gates

What the module needs from phase 2 item 2 (stub TODO in
`webroot/index.html`; nothing invented):

1. Server start command + flags; foreground process or not.
2. Listen address/port confirmation (`127.0.0.1` only) + exact
   `--port` spelling.
3. Token/auth handoff: stdout vs file, format, rotation, and
   whether `CASTCTL_WEBUI_KEY` becomes a real input.
4. Health/status URL: exact path, what counts as "up".
5. Config gating: whether a `webui` block will exist (name,
   keys, presence semantics).
6. Shutdown semantics (SIGINT vs SIGTERM) for the server process.
7. WebView fetch/CORS behaviour vs `kernelsu` `exec()`, and the
   browser fallback URL.

Live gates — phone-only proof, adapted from the environment pack
(24 gates). None is passed by this work; check each off only with
an observed result on the device:

1. Flash/install via the KernelSU manager: succeeds or aborts
   cleanly with a readable message.
2. Reboot: lock screen reached; daemon autostarts; boot time
   with module enabled vs disabled (no material regression).
3. `service.sh` foreground returns immediately; no boot stall
   attributable to the module.
4. `disable` flag: scripts do not run; daemon stops without a
   reboot for the stop itself.
5. `remove`/uninstall: removed next reboot; daemon stopped; data
   kept (per §5/`uninstall.sh`).
6. Action button: toggles, shows status + log tail, returns
   promptly running and stopped.
7. BusyBox resolution on device: which candidate path is used;
   all required applets present (`flock`, `sha256sum`, `nohup`,
   `timeout`, `awk`, `tr`, `sed`, `readlink`, `id`).
8. Permissions: config 0600, sensitive dirs 0700, scripts 0755,
   `webroot/` untouched by module permission code.
9. Gating: webui block absent → no web UI listener; present
   (after item 2) → loopback-only listener.
10. Webroot stub opens in the manager, shows the item-2 TODO,
    calls no endpoint, renders on KernelSU 32680-5 / ColorOS
    WebView.
11. Webroot → `127.0.0.1` fetch works (once item 2 supplies the
    URL/token mechanism), without logging/displaying secrets.
12. Gating: keeper block absent → keeper not started; present
    non-empty → `keeper run` runs per its schedule, state file
    `session-state.json` appears in the profile dir, and a
    phone Chrome with a CDP port is reachable (or the tick
    failures are understood and logged); empty array → keeper
    not started.
13. Gating: telegram block absent → no Telegram traffic;
    present → bot runs, no secrets in any log.
14. Coexistence with `meta-hybrid_mount` in Magic Mount mode;
    isolation reboot with castctl disabled identifies the cause
    if a boot problem appears.
15. Coexistence with SUSFS, ZygiskNext, LSPosed as-is; no
    castctl dependence on any of them.
16. Screen-off/overnight survival; watchdog restarts if the
    daemon dies; battery impact noted.
17. Log behaviour over time: growth, rotation confirmed, no
    secret values in any log line including after errors.
18. Update/reinstall: config and data preserved; old daemon
    stopped before the new one starts; plugins preserved.
19. Uninstall cleanup: no orphan daemon, no leftover general
    scripts in `/data/adb/*.d/`.
20. Safe-mode drill practised while healthy (Volume-Down ×3).
21. ColorOS specifics: WebUI renders, Action works, no
    ColorOS battery/background setting blocks the daemon in a
    way the module must handle.
22. Binary execution on device: pinned binary runs under the
    bundled loader and `castctl --version` reports `0.6.4`;
    `runtime_check()` preflight passes.
23. Stop under the device busybox leaves no orphan: after
    `stop`, no process matching a service pattern remains,
    `is-running` reports stopped, and the next start creates
    no duplicate (covers non-forwarding `timeout` behaviour
    on device).
24. Signal delivery to the backgrounded Go binary: whether
    `signal.NotifyContext` in `cmd/castctl/main.go` resets an
    inherited SIG_IGN for SIGINT, i.e. whether the SIGINT step
    of the stop escalation actually reaches castctl on device
    (TERM/KILL termination is the proven path; do not claim
    "SIGINT-first" operates until this gate passes).

## 12. Static fallback (manual only, never automatic)

If the bundled loader fails at runtime, `service.sh` logs it and
exits 0 — there is NO automatic fallback switching at boot (Boss
decision). The documented manual fallback is the static
`_no-plugin` build:

1. Download `castctl_0.6.4_linux_arm64_no-plugin.tar.gz` and
   verify sha256
   `e9b286a2c5575ee3b3d96aa5f571ae164395770bfcd85e67316fe8b7a64c73f7`
   against the release `checksums.txt`.
2. Replace `payload/bin/castctl` in a locally built ZIP with the
   static binary, regenerate `payload/checksums.sha256`, and
   rebuild — or, equivalently, update `sources.lock` to pin the
   static asset and rebuild with `build.sh` after a Boss decision
   to change the pin. Do NOT mix a static binary with the glibc
   payload's `lib/` files in an ad-hoc way; the payload must stay
   self-consistent and checksum-verified.
3. Record the switch in the module docs; the glibc build remains
   the pinned primary.

The static build has no plugin loader (no plugins are implemented
yet in either build), so the fallback loses nothing that exists
today. `[NEEDS-MEASUREMENT]` on device.
