#!/system/bin/sh

# action.sh — manager Action button: start/stop toggle + status +
# controller log tail. No URL, no token, no browser launch. The log
# tail shows the module controller log (secret-free by construction),
# not the core log: the core log is shown only by an explicit
# `castctl-ctl log` invocation. Every step is fail-soft.

export PATH="/data/adb/ksu/bin:/data/adb/magisk:/data/adb/ap/bin:$PATH:/system/bin"
MODULE_DIR=${0%/*}
CTL=$MODULE_DIR/scripts/castctl-ctl
DATA_DIR=${CASTCTL_DATA_DIR:-/data/local/castctl}

if "$CTL" is-running >/dev/null 2>&1; then
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
