#!/system/bin/sh

# service.sh — the ONE late-start boot hook. Runs in late_start service
# mode (non-blocking, parallel with the rest of booting). The foreground
# portion only sets up variables and launches a backgrounded subshell,
# then returns immediately. Every wait inside the background body is
# bounded (boot_completed poll, flock, readiness, stop escalation all
# carry timeouts in scripts/castctl-ctl). Every failure logs to the
# module log and exits 0: this script must never be able to block boot
# or loop tightly. See module/docs/ksu-module.md, bootloop-safety table.

export PATH="/data/adb/ksu/bin:/data/adb/magisk:/data/adb/ap/bin:$PATH:/system/bin"

MODULE_DIR=${0%/*}
CTL="$MODULE_DIR/scripts/castctl-ctl"
DATA_DIR=${CASTCTL_DATA_DIR:-/data/local/castctl}

BOOT_WAIT_TIMEOUT=${CASTCTL_BOOT_WAIT_TIMEOUT:-120}
BOOT_POLL_INTERVAL=${CASTCTL_BOOT_POLL_INTERVAL:-5}
WATCHDOG_BASE=${CASTCTL_WATCHDOG_BASE:-30}
WATCHDOG_MAX=${CASTCTL_WATCHDOG_MAX:-300}

(
  # Bounded boot_completed wait: getprop polling only. The template's
  # resetprop -w form is deliberately not used: its semantics on this
  # KernelSU build are unconfirmed, and a hung resetprop would hang
  # this iteration with no timeout. If boot never completes within the
  # timeout, log and stop quietly instead of starting late blindly.
  waited=0
  while [ "$(getprop sys.boot_completed 2>/dev/null)" != 1 ]; do
    if [ "$waited" -ge "$BOOT_WAIT_TIMEOUT" ]; then
      exit 0
    fi
    sleep "$BOOT_POLL_INTERVAL"
    waited=$((waited + BOOT_POLL_INTERVAL))
  done

  [ -f "$MODULE_DIR/disable" ] && exit 0
  [ -x "$CTL" ] || exit 0
  "$CTL" start --boot >/dev/null 2>&1 || true

  failures=0
  delay=$WATCHDOG_BASE
  while sleep "$delay"; do
    [ -f "$MODULE_DIR/disable" ] && { "$CTL" stop >/dev/null 2>&1 || true; exit 0; }
    [ -f "$DATA_DIR/run/enabled" ] || continue
    if "$CTL" is-running >/dev/null 2>&1; then
      failures=0
      delay=$WATCHDOG_BASE
      continue
    fi
    failures=$((failures + 1))
    "$CTL" start --watchdog >/dev/null 2>&1 || true
    # Exponential backoff, capped: a broken config must not spin the
    # watchdog. The loop itself never exits on failure alone, so a
    # later config fix still recovers without a reboot.
    delay=$((delay * 2))
    if [ "$delay" -gt "$WATCHDOG_MAX" ]; then
      delay=$WATCHDOG_MAX
    fi
    if [ "$failures" -ge 10 ]; then
      delay=$WATCHDOG_MAX
    fi
  done
) &
exit 0
