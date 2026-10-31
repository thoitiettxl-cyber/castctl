#!/system/bin/sh

# uninstall.sh — runs when the manager removes the module. Stops the
# daemon best-effort and deliberately preserves all persistent data
# under /data/local/castctl (config, profiles, plugins, logs,
# backups, releases). Destructive erasure exists only as the explicit
# `castctl-ctl purge-data --yes` command. Removal of the module's own
# files is left to the manager. Always exits 0.

MODULE_DIR=${0%/*}
CTL=$MODULE_DIR/scripts/castctl-ctl
[ -x "$CTL" ] && "$CTL" stop >/dev/null 2>&1 || true

# Deliberately preserve /data/local/castctl. Use castctl-ctl
# purge-data --yes only after explicit confirmation when the
# config, cookies, and history should be erased.
exit 0
