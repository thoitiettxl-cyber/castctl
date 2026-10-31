# castctl KernelSU module

KernelSU module that runs castctl on a rooted Android phone. Base:
castctl `origin/main` `6d3baac` (v0.6.4); template:
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
  plugins/                            (0700)
    linux/arm64/                      (0700; reserved, see §6)
  run/                                (0700; castctl.pid, enabled, tmp/)
  logs/                               (0700; castctl.log, controller.log + rotations)
  backups/                            (0700; state archives, 0600)
  .controller/                        (0700; lifecycle workspaces)
DATA_DIR.lifecycle.lock               (0600; OUTSIDE the data tree, so
                                       purge cannot replace the locked inode)
```

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
- Keeper state filename: there is NO `internal/keeper/` package on
  the base HEAD and no keeper state filename is stated anywhere in
  the tree. `session-state.json` (or any other keeper filename) is
  therefore PROVISIONAL and is deliberately NOT named as a keeper
  file anywhere in the module: the directory shape above is what is
  implemented, and the filename must be re-surveyed after PR #19
  merges. `[NEEDS-MEASUREMENT]` / re-survey-after-PR-#19.
- `telegram.json` / `telegram-state.json` live under the active
  profile's `Dir` (`internal/commands/profilecmd.go`), i.e. under
  `config/profiles/<name>/` for named profiles.

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

## 3. Config

Write `config/config.json` by hand (mode 0600). The module never
creates it and never writes into it. The example is copied only as
`config.json.example`, and only when no real config exists yet.

Minimal valid example (`config.example.json` in the module):

```json
{"default_profile":"default","log":{"level":"info"},"profiles":{"default":{}}}
```

Config rules that matter here (base tree, strict parser):

- Exactly 8 top-level keys; unknown keys are rejected (exit 2).
  There is NO `keeper`, `webui`, or `plugins` key on this HEAD —
  adding one makes every castctl command fail. See §4.
- Cookies live only in a separate cookies file (`cookies_file`
  resolves relative to `CONFIG_DIR`); inline `cookies` keys are
  rejected. Use `auth import` (stdin-only) to populate cookies;
  the module never echoes cookie material.
- `telegram` block keys (exactly 5): `profile`, `token`,
  `allowed_user_ids`, `auto_approve`, `auto_allow_once`. The
  config block is the only token source on this HEAD. Never put
  the token anywhere else, never log it.

## 4. Gating: what starts, and when

The controller starts ONE process: `castctl --config <path>
telegram run` (foreground, blocking), and only when a `telegram`
top-level object block is present in `config.json`. Detection uses
the module's own lexical top-level key probe (`has_top_block` in
`scripts/castctl-ctl`): a depth-1 key whose value starts with `{`,
with strings/escapes skipped and nested keys ignored. Limits,
stated honestly:

- The probe is presence-only, not validation. Token shape,
  profile existence, and allowed-user rules are castctl's job;
  an invalid block makes the child exit 2 quickly and the
  controller logs that and starts nothing (fail-soft).
- The probe is a lexical scan, not a JSON parser. Malformed JSON
  may still report presence; castctl's parser is the final
  arbiter. A key spelled inside a top-level string value with
  the exact `"key": {` shape could false-positive; the child
  exit is again the arbiter. `[NEEDS-MEASUREMENT]` for adversarial
  configs on device (none expected in practice).
- If a `keeper` or `webui` top-level block is present, the
  controller starts NOTHING and logs why: this castctl build's
  strict parser rejects the whole file, so no command can run
  against it. This is a sequencing consequence of items 1/2 not
  being merged, not a bug to work around in shell. Re-survey
  after PR #19 (keeper) and item 2 (web UI) land; their command
  names and flags must be taken from the tree, never assumed.
- No `telegram` block → start is a successful no-op: nothing is
  started, no enabled marker is written, the watchdog does not
  restart anything.

`castctl update` is never invoked by the module (user-invoked
only; it would replace the pinned binary from the network and
fight the checksum-pinned install).

## 5. Service lifecycle

- `service.sh` is the single late-start hook (see §10 for the
  bootloop-safety proof). It waits for `sys.boot_completed`
  (bounded getprop polling, 120 s cap), checks the `disable`
  file, starts via the controller, then watchdogs with
  exponential backoff (30 s base, doubling, 300 s cap; counter
  resets on success). The watchdog only restarts while the
  `run/enabled` marker exists (i.e. the service was started and
  not explicitly stopped).
- The child runs under the bundled glibc loader:
  `ld-linux-aarch64.so.1 --library-path <lib> castctl --config
  <path> telegram run`, wrapped in busybox `timeout` with a
  86400 s lifetime bound (`CASTCTL_CHILD_LIFETIME`), because
  castctl provides no lifetime bound of its own. When the bound
  fires, the watchdog restarts the service. `[NEEDS-MEASUREMENT]`
  whether busybox `timeout` forwards SIGINT to the child on this
  device.
- Stop prefers SIGINT (castctl handles SIGINT only; exit 130 from
  an intentional stop is normal), escalates SIGTERM then SIGKILL
  with bounded waits (5 s / 3 s). Stop removes the enabled
  marker so the watchdog does not restart. The PID file is
  validated against the live process cmdline (never trusted
  bare); if it is gone, stop scans `/proc` for a matching
  cmdline as a fallback and never signals an unmatched PID.
- `action.sh` toggles start/stop, prints status, and shows the
  last 10 controller log lines. `castctl-ctl log [N]` tails the
  core log explicitly. `castctl-ctl doctor` re-runs the runtime
  check plus gating checks. `castctl-ctl backup` archives
  `config/` + `plugins/` (0600); the archive contains cookies —
  treat it as secret material, never share it.
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
  (the template's v1.1 migration, mirrored).
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

- Controller log: `logs/controller.log`. Core log: `logs/castctl.log`
  (the daemon's stdout/stderr). Both rotate at 1 MiB
  (`CASTCTL_LOG_MAX_BYTES`), keeping 3 rotated files
  (`CASTCTL_LOG_KEEP`). Rotation renames only; the running daemon
  keeps its open file descriptor and a fresh file is used on the
  next start.
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
secrets, and writes a deterministic ZIP. The glibc-loader
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
release tree. Cases: install success + checksum-fail install;
disable present → no start; missing binary → log + exit 0; bad
config → no start + exit 0; telegram absent → no start, present
→ start; keeper/webui absent → no start (and present-but-
unparseable → no start with a logged reason); action toggle;
uninstall keeps data; purge guard refuses a wrong path and runs
only with `--yes`; plugin file survives update + uninstall;
log rotation cap; boot_completed timeout; flock timeout;
watchdog backoff; fake-secret grep proof. The arm64 binary
cannot execute on the x86_64 build host: `castctl --version` on
device is `[NEEDS-MEASUREMENT]` (live gate 22).

Test-only environment overrides (documented here so reviewers
can tell them from device behaviour; never set on the device):
`CASTCTL_TEST_MODE`, `CASTCTL_BUSYBOX`, `CASTCTL_MODULE_DIR`,
`CASTCTL_DATA_DIR`, `CASTCTL_LIFECYCLE_LOCK`,
`CASTCTL_FLOCK_TIMEOUT`, `CASTCTL_READY_TIMEOUT`,
`CASTCTL_BOOT_WAIT_TIMEOUT`, `CASTCTL_BOOT_POLL_INTERVAL`,
`CASTCTL_WATCHDOG_BASE`, `CASTCTL_WATCHDOG_MAX`,
`CASTCTL_CHILD_LIFETIME`, `CASTCTL_LOG_MAX_BYTES`,
`CASTCTL_LOG_KEEP`, `CASTCTL_MODULE_OUT_DIR`,
`CASTCTL_BUILD_CACHE_DIR`, `CASTCTL_ALLOW_UNATTESTED_INPUTS`,
`CASTCTL_SOURCES_LOCK` (rejected when set, as in the template).

## 9. Deviations from the template (each with a reason)

| # | Template behaviour | This module | Reason |
|---|---|---|---|
| D1 | BusyBox/PATH Magisk-first everywhere | KernelSU-first (`/data/adb/ksu/bin`), Magisk fallback | Boss decision; target is KernelSU |
| D2 | Bundled glibc used as-is (template) | Same mechanism (bundled glibc + loader) | Boss glibc decision: follow the template; do not depend on any other module. Supersedes the old glibc-module plan note |
| D3 | `SKIPMOUNT=false` + `PROPFILE=true`, no `system.prop` | `SKIPMOUNT=true`, no `PROPFILE` line | No `system/` dir exists to mount and no prop file to load; the template's flag combination is unresolved in research |
| D4 | No `system/` content except `system/bin/cpactl` shim | No `system/` dir at all | Nothing to mount; with no overlay the metamodule mounting path is irrelevant to this module's files. No convenience shim (nothing may depend on it) |
| D5 | Unbounded `boot_completed` wait (`resetprop -w` loop) | Bounded getprop polling, 120 s cap, no `resetprop -w` | Hard rule: timeouts. `resetprop -w` semantics on KernelSU 32680-5 are unconfirmed |
| D6 | Unbounded `flock` wait in boot start | `flock -w 30` (env-overridable) for boot/doctor/backup; `-n` ignore for watchdog | Hard rule: timeouts |
| D7 | Infinite watchdog, fixed 30 s, no backoff | Exponential backoff 30 s → 300 s cap, failure counter | Hard rule: a broken config must not spin; recovery without reboot is preserved |
| D8 | No log rotation, no redaction | 1 MiB rotation, 3 kept; module never logs secrets | Boss decision (rotation + no secrets). Template log() prints verbatim |
| D9 | Daemon dropped to 9999:3003 | Runs as root; no chown to 9999:3003 | No verified UID/GID for castctl on this device; root-owned 0700/0600 dirs are the secret boundary. `[NEEDS-MEASUREMENT]` |
| D10 | `update-core` follows `releases/latest` with rollback | No updater at all (no `update-core` command) | Pinned-only installs (Boss); `castctl update` must never run unattended and would fight the pinned install |
| D11 | Listener-based readiness + foreign-listener fail-closed | Process + cmdline readiness; no port logic | `telegram run` listens on no port; there is no listener to check or protect |
| D12 | `config_is_safe` enforces host/port/plugins.dir | Gating probe only (presence of `telegram`/`keeper`/`webui` blocks) | Castctl has no host/port config keys; its strict parser is the validator. No castctl key is invented |
| D13 | `customize.sh` hardcodes the data dir; only the controller honours `CPA_DATA_DIR` | `CASTCTL_DATA_DIR` honoured in both scripts | Boss-directed override; discrepancy recorded in §2.1 |
| D14 | CA bundle read from the Alpine build host file | CA bundle downloaded as a pinned `.apk`, cert.pem extracted + verified | Host independence: `build.sh` must run on any Linux host, not only Alpine |
| D15 | CA pin `20260611-r0` / sha `b8d83784…` | CA pin `20261020-r0` / apk + cert.pem hashes verified by download | Template pin is not in the Alpine index (404); the current bundle was verified instead. See `sources.lock` |
| D16 | `action.sh` shows the last 10 core-log lines | `action.sh` shows the last 10 controller-log lines; core log via explicit `castctl-ctl log` | Controller log is secret-free by construction; core output is shown only on explicit request |
| D17 | `system/bin/cpactl` shim + `update-core`/`doctor` plugin checks | No shim; `doctor` has no plugin/listener checks; `status` counts plugin-dir files only | No system overlay; no plugins exist yet; no loader code by design |
| D18 | Legacy controller quarantine + v1.1 lock + plugin-path migration | Quarantine kept; legacy lock and config-path migration dropped; plugin forward-copy kept | First module release: no legacy castctl controller/layout exists. The forward-copy is kept as the same defensive shape as the template |
| D19 | `allow-root-core` marker opts into root | No marker; root is the only mode (see D9) | Single documented mode; no silent identity switch |
| D20 | `set_perm_recursive` covers the whole module dir | `webroot/` excluded from permission setting | KernelSU sets webroot permissions/SELinux itself and warns against setting them by hand |

## 10. Bootloop safety — proof table

Review check name: **bootloop safety**. Each row must be tickable
from the scripts as written; static review alone does not close
the case — the live gates in §11 are part of the proof. Safe mode
is a recovery procedure for Boss, never a design argument.

| Script path | Cannot block | Cannot loop | Failure exits 0 | Proof required |
|---|---|---|---|---|
| `customize.sh` (install-time, not boot) | No unbounded wait: downloads happen only in `build.sh`, never here; `flock -n` fails fast; `abort` is the only failure exit | No `while` loop without a bound (the only loop scans quarantine candidates, a finite glob) | Install failure exits via `abort` (installer cleanup), never bare `exit 1` | Static: read the file. Live: install completes or aborts cleanly; phone reboots normally. `[NEEDS-MEASUREMENT]` |
| `post-fs-data.sh` | — (must not ship) | — | — | Proof is absence: file must not exist in the ZIP or module dir. Any future addition reopens this section |
| `post-mount.sh` | — (must not ship) | — | — | Proof is absence, as above |
| `boot-completed.sh` | — (must not ship) | — | — | Proof is absence, as above |
| `service.sh` (foreground) | Foreground contains only variable setup + one background launch `(...) &` + `exit 0`. No `sleep`, `wait`, `flock`, or daemon invocation | Foreground contains no loop | Foreground exits 0 unconditionally; no `set -e` | Static: read the file. Live: boot-completed time with module enabled vs disabled. `[NEEDS-MEASUREMENT]` |
| `service.sh` (background body) | Runs parallel with boot (backgrounded). `boot_completed` wait is bounded polling (120 s cap). `start --boot` uses `flock -w 30`. Readiness wait is 10 s. Stop escalation is 5 s + 3 s | Watchdog sleeps (30 s → 300 s backoff) between iterations; `disable` checked every iteration with exit; consecutive-failure counter caps the rate; no respawn without sleep | Every start/stop invocation ends `|| true`; disable/missing-controller exits are `exit 0`; no `set -e`, no bare failing command as the body's last word | Static: read the file; count sleeps, bounds, `|| true`s. Live: boots with config removed, binary removed, and `disable` created mid-boot. `[NEEDS-MEASUREMENT]` |
| `action.sh` (manager button, not boot) | Returns promptly; no wait loops; controller readiness wait is bounded (10 s) | No loop | Exits 0 even when start/stop fails (`|| true` everywhere) | Static: read the file. Live: tap Action running and stopped. `[NEEDS-MEASUREMENT]` |
| `uninstall.sh` | Returns promptly; stop is best-effort (`|| true`); no waits | No loop | Exits 0 unconditionally | Static: read the file. Live: uninstall + reboot, no orphan daemon. `[NEEDS-MEASUREMENT]` |
| `scripts/castctl-ctl` (invoked by the above) | Every wait bounded: flock 30 s, readiness 10 s, version probe 10 s, stop 5 s + 3 s, child lifetime 86400 s | No unbounded loop: watchdog backoff lives in `service.sh`; controller loops are all iteration-capped | Controller exit codes never propagate to boot: `service.sh` swallows them with `|| true`; manual invocation reports failures honestly (non-zero) | Static: read the file. Live: as for `service.sh` background body |
| `initrc/`, `preinit/`, `system/`, `system.prop`, `sepolicy.rule`, `/data/adb/*.d/` scripts | — (must not ship) | — | — | Proof is absence in the ZIP listing. `initrc` content would still run in safe mode, so absence is load-bearing, not cosmetic |

Additional hard-rule properties, verified by grep over the tree:

- No `setprop`, `mount`, `umount`, `resetprop`, or sepolicy tool
  invocation in any shipped script (reads via `getprop` only, in
  `customize.sh` ABI check and `service.sh` boot polling).
- No write outside the module folder and `DATA_DIR` (plus the
  manager-owned `disable`/`remove` flag files, which scripts only
  read). No general scripts installed under `/data/adb/*.d/`.
- `disable` is honoured before the first start and on every
  watchdog iteration (stop + exit). `remove` is a manager-level
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
(22 gates). None is passed by this work; check each off only with
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
   `timeout`, `awk`, `tr`, `sed`, `readlink`).
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
    (after PR #19) → keeper runs per its schedule.
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
