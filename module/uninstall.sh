#!/system/bin/sh

# uninstall.sh — runs when the manager removes the module. Stops the
# daemon best-effort and deliberately preserves all persistent data
# under /data/local/castctl (config, profiles, plugins, logs,
# backups, releases). Destructive erasure exists only as the explicit
# `castctl-ctl purge-data --yes` command. Removal of the module's own
# files is left to the manager. Always exits 0.

MODULE_DIR=${0%/*}
CTL=$MODULE_DIR/scripts/castctl-ctl

# Resolve the data dir the same way the install recorded it:
# an explicit CASTCTL_DATA_DIR wins, then the install-time
# record written by customize.sh, then the default. Without
# this, uninstall under a custom data dir would stop the
# default dir's (absent) daemon and orphan the real one.
DATA_DIR=${CASTCTL_DATA_DIR:-}
if [ -z "$DATA_DIR" ] && [ -f "$MODULE_DIR/.castctl-data-dir" ] && [ ! -L "$MODULE_DIR/.castctl-data-dir" ]; then
  DATA_DIR=$(cat "$MODULE_DIR/.castctl-data-dir" 2>/dev/null || true)
fi
case "$DATA_DIR" in /*) ;; *) DATA_DIR=/data/local/castctl ;; esac
export CASTCTL_DATA_DIR="$DATA_DIR"

[ -x "$CTL" ] && "$CTL" stop >/dev/null 2>&1 || true

# Deliberately preserve the persistent data dir. Use castctl-ctl
# purge-data --yes only after explicit confirmation when the
# config, cookies, and history should be erased.
exit 0
