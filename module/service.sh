#!/system/bin/sh

# service.sh — the ONE late-start boot hook. Runs in late_start service
# mode (non-blocking, parallel with the rest of booting). The foreground
# portion only sets up variables and launches a backgrounded subshell,
# then returns immediately. Every wait inside the background body is
# bounded (boot_completed poll, flock, readiness, stop escalation all
# carry timeouts in scripts/castctl-ctl). Every failure logs to the
# module log and exits 0: this script must never be able to block boot
# or loop tightly. See module/docs/ksu-module.md, bootloop-safety table.
# The persistent want marker ($DATA_DIR/state/want) gates both the
# boot start and the watchdog: no marker means the user stopped the
# module (or never started it), so a reboot must not resurrect it.
# The KernelSU module disable switch still wins: it is checked
# before the marker, and on every watchdog sleep chunk.

export PATH="/data/adb/ksu/bin:/data/adb/magisk:/data/adb/ap/bin:$PATH:/system/bin"

MODULE_DIR=${0%/*}
CTL="$MODULE_DIR/scripts/castctl-ctl"
DATA_DIR=${CASTCTL_DATA_DIR:-/data/local/castctl}

# clamp_int VALUE DEFAULT MIN MAX (builtins only): numeric
# overrides are validated and clamped, garbage falls back to the
# default, so a bad override can never defeat a bound (a zero
# poll interval must not spin the boot wait).
clamp_int() {
  _v=$1; _d=$2; _lo=$3; _hi=$4
  case "$_v" in ''|*[!0-9]*) printf '%s\n' "$_d"; return 0 ;; esac
  while [ "${#_v}" -gt 1 ]; do case "$_v" in 0*) _v=${_v#0} ;; *) break ;; esac; done
  [ "${#_v}" -gt 10 ] && { printf '%s\n' "$_hi"; return 0; }
  if [ "$_v" -lt "$_lo" ]; then printf '%s\n' "$_lo"; return 0; fi
  if [ "$_v" -gt "$_hi" ]; then printf '%s\n' "$_hi"; return 0; fi
  printf '%s\n' "$_v"
}

BOOT_WAIT_TIMEOUT=$(clamp_int "${CASTCTL_BOOT_WAIT_TIMEOUT:-120}" 120 1 3600)
BOOT_POLL_INTERVAL=$(clamp_int "${CASTCTL_BOOT_POLL_INTERVAL:-5}" 5 1 60)
WATCHDOG_BASE=$(clamp_int "${CASTCTL_WATCHDOG_BASE:-30}" 30 1 3600)
WATCHDOG_MAX=$(clamp_int "${CASTCTL_WATCHDOG_MAX:-300}" 300 1 3600)

(
  # Files the background body creates (none today beyond what the
  # controller owns) start owner-only.
  umask 077
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
  # The want marker is the boot gate: a pure existence test
  # ([ -f ] + [ ! -L ]), inside the background body only, before
  # start --boot. The controller re-checks the marker under the
  # lifecycle lock. A symlinked marker counts as absent
  # (fail-safe OFF). Without the marker the watchdog below idles.
  if [ -f "$DATA_DIR/state/want" ] && [ ! -L "$DATA_DIR/state/want" ]; then
    "$CTL" start --boot >/dev/null 2>&1 || true
  fi

  failures=0
  delay=$WATCHDOG_BASE
  while :; do
    # Interruptible sleep: the backoff delay is slept in 5 s
    # chunks, re-checking `disable` each chunk, so disabling the
    # module stops the daemon within seconds instead of waiting
    # out a full (up to 300 s) backoff delay.
    remaining=$delay
    disabled=0
    while [ "$remaining" -gt 0 ]; do
      chunk=5
      [ "$remaining" -lt "$chunk" ] && chunk=$remaining
      sleep "$chunk"
      remaining=$((remaining - chunk))
      if [ -f "$MODULE_DIR/disable" ]; then disabled=1; break; fi
    done
    if [ "$disabled" = 1 ]; then "$CTL" stop >/dev/null 2>&1 || true; exit 0; fi
    # The want marker gates the watchdog: a stop removes it, so
    # the loop idles until the next manual start. run/enabled is
    # retained as a start-request record but is no longer the
    # gate (a pre-want enabled marker alone never starts the
    # module: the user must press Action once after updating).
    if [ ! -f "$DATA_DIR/state/want" ] || [ -L "$DATA_DIR/state/want" ]; then continue; fi
    # start is idempotent per service: running services are left
    # alone, missing wanted services are (re)started. A failed
    # start backs off; a good one resets the delay. The want
    # marker is written by a manual start (so a later config fix
    # recovers) and removed only by an explicit stop.
    if "$CTL" start --watchdog >/dev/null 2>&1; then
      failures=0
      delay=$WATCHDOG_BASE
      continue
    fi
    failures=$((failures + 1))
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
