# module — castctl KernelSU module

This folder holds the KernelSU module that runs castctl on a rooted
Android phone (KernelSU plus the meta-hybrid_mount metamodule, with
Magisk paths as a fallback).

The module ships the linux_arm64 glibc 2.17 castctl release binary
(v0.6.4), run through a glibc + loader bundled inside the module
exactly as the cli-proxy-api template does. It does not depend on any
other module on the device. (This supersedes the earlier plan note
that the binary would run through the user's glibc module; see the
Boss glibc decision recorded in `docs/ksu-module.md`.)

"Module" here means a KernelSU module. It is not a Go module, and
it is not a release target.

## Layout

- `module.prop`, `META-INF/` — module identity and installer entry.
- `customize.sh` — install-time only (checksum verification, release
  publication). Never starts the daemon.
- `service.sh` — the single late-start boot hook (backgrounded,
  bounded waits, watchdog with backoff).
- `action.sh` — manager Action button (start/stop toggle + status).
- `uninstall.sh` — stops the daemon, keeps all data.
- `scripts/castctl-ctl` — lifecycle controller (start/stop/restart/
  status/doctor/version/log/backup/purge-data).
- `build.sh` — host-side packager; produces the flashable ZIP from
  checksum-pinned inputs in `sources.lock`.
- `sources.lock`, `payload-manifest.txt` — pins and payload contract.
- `config.example.json` — example config; copied only as
  `config.json.example`, never auto-activated.
- `webroot/index.html` — static WebUI placeholder (TODO tied to
  phase 2 item 2; no endpoint, no token handling).
- `docs/ksu-module.md` — install, config, gating, logs, bootloop
  safety proof, deviations from the template, live gates.

## Data on the device

- Data dir: `/data/local/castctl` (overridable via `CASTCTL_DATA_DIR`
  for testing; see the docs). Config: `config/config.json` (0600).
  Per-profile state: `config/profiles/<name>/cookies.txt` and friends,
  created by castctl itself — never by the module, never shipped.
- Releases: `releases/<id>-<sha>/`, selected via the atomic `current`
  symlink. Plugins: `plugins/linux/arm64/` is reserved (0700) and
  preserved across updates and uninstall; no plugin loader exists
  yet — plugins come after phase 2.
- Logs: `logs/` with rotation (1 MiB cap, 3 kept). No secrets are
  ever logged by the module scripts.

## Build

```sh
./module/build.sh
```

Produces `module/dist/castctl_ksu_v0.6.4.zip` plus a `.sha256`
sidecar. Set `CASTCTL_MODULE_OUT_DIR` to choose another output
directory. Every input hash is verified; any mismatch fails the
build loudly. The loader execution preflight runs on AArch64 hosts
or under qemu-aarch64; on other hosts it is skipped with a recorded
warning and the device-side `--version` preflight is the proof.

## Status

Implemented (phase 2 item 4). Live device gates (flash, boot,
disable/remove, gating, uninstall) are Boss-side only and are
listed, none claimed passed, in `docs/ksu-module.md`.
