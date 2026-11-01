#!/system/bin/sh

# action.sh — manager Action button: start/stop toggle + status +
# web UI URL + controller log tail. The status output carries the
# web UI URL (no token) when the webui service is running; the
# token is never printed, and no browser is launched from here
# (the webroot controller page holds the open-URL button). The
# log tail shows the module controller log (secret-free by
# construction), not the core log: the core log is shown only by
# an explicit `castctl-ctl log` invocation. Every step is
# fail-soft. Toggle rule: want marker present OR any service
# running -> stop, else start (starting records the want marker,
# so the choice survives reboot).

export PATH="/data/adb/ksu/bin:/data/adb/magisk:/data/adb/ap/bin:$PATH:/system/bin"
MODULE_DIR=${0%/*}
CTL=$MODULE_DIR/scripts/castctl-ctl
DATA_DIR=${CASTCTL_DATA_DIR:-/data/local/castctl}

if { [ -f "$DATA_DIR/state/want" ] && [ ! -L "$DATA_DIR/state/want" ]; } || "$CTL" is-running >/dev/null 2>&1; then
  echo "Stopping castctl..."
  "$CTL" stop || true
else
  echo "Starting castctl..."
  "$CTL" start || true
fi

echo
echo "=== Status ==="
"$CTL" status || true
echo
echo "=== Last controller log lines ==="
if [ -f "$DATA_DIR/logs/controller.log" ]; then
  tail -n 10 "$DATA_DIR/logs/controller.log" || true
else
  echo "(no controller log yet)"
fi
exit 0
