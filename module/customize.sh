#!/system/bin/sh

# customize.sh — install-time only. Sourced (not executed) by the
# KernelSU/Magisk manager installer. Mirrors cli-proxy-api customize.sh
# (template commit f912a733) in structure; deviations are listed in
# module/docs/ksu-module.md. It never starts the daemon and never
# blocks on the network: a failed checksum/ABI check aborts the
# install loudly instead of installing a half-working module.

SKIPUNZIP=1
SKIPMOUNT=true
POSTFSDATA=false
LATESTARTSERVICE=true
# NOTE: no PROPFILE line. The template sets PROPFILE=true with no
# system.prop file in the tree (unresolved in the research packs);
# this module ships no system.prop, so no prop file is declared.

DATA_DIR=${CASTCTL_DATA_DIR:-/data/local/castctl}
MODULE_ID=castctl

say() { ui_print "- $*"; }
fail() { abort "! castctl module: $*"; }

verify_runtime_checksums() {
  runtime_dir=$1
  [ -f "$runtime_dir/checksums.sha256" ] || return 1
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$runtime_dir" && sha256sum -c checksums.sha256 >/dev/null)
  else
    (cd "$runtime_dir" && "$BUSYBOX" sha256sum -c checksums.sha256 >/dev/null 2>&1)
  fi
}

restore_old_controller() {
  [ -n "${old_ctl_quarantine:-}" ] || return 0
  if [ -e "$old_ctl_quarantine" ] && [ ! -e "$old_ctl_original" ]; then
    mv "$old_ctl_quarantine" "$old_ctl_original" || return 1
  fi
  old_ctl_quarantine=
}

[ "${BOOTMODE:-false}" = true ] || fail "install from KernelSU Manager, not recovery"
case "$DATA_DIR" in
  /*) ;;
  *) fail "module data dir must be absolute" ;;
esac
case "$(getprop ro.product.cpu.abi 2>/dev/null)" in
  arm64-v8a|aarch64) ;;
  *) fail "this release requires ARM64 Android" ;;
esac

# KernelSU-first busybox resolution (the template is Magisk-first;
# Boss decision inverts the order). Magisk is the fallback.
BUSYBOX=/data/adb/ksu/bin/busybox
[ -x "$BUSYBOX" ] || BUSYBOX=/data/adb/magisk/busybox
[ -x "$BUSYBOX" ] || BUSYBOX=/data/adb/ap/bin/busybox
[ -x "$BUSYBOX" ] || BUSYBOX=busybox

LOCK_FILE=${CASTCTL_LIFECYCLE_LOCK:-${DATA_DIR}.lifecycle.lock}
case "$LOCK_FILE" in /*) ;; *) fail "lifecycle lock path must be absolute" ;; esac
lock_parent=${LOCK_FILE%/*}
[ -d "$lock_parent" ] || fail "lifecycle lock parent is missing"
[ ! -L "$LOCK_FILE" ] || fail "lifecycle lock must not be a symlink"
{ [ ! -e "$LOCK_FILE" ] || [ -f "$LOCK_FILE" ]; } || fail "lifecycle lock must be a regular file"
exec 9>"$LOCK_FILE" || fail "unable to create lifecycle lock"
chmod 0600 "$LOCK_FILE" || fail "unable to protect lifecycle lock"
chown 0:0 "$LOCK_FILE" 2>/dev/null || fail "unable to own lifecycle lock"
"$BUSYBOX" flock -n 9 || fail "another lifecycle or install operation is in progress"
export CASTCTL_LIFECYCLE_LOCK="$LOCK_FILE"
export CASTCTL_LIFECYCLE_LOCK_HELD=1

old_ctl_original=/data/adb/modules/${MODULE_ID}/scripts/castctl-ctl
old_ctl_quarantine=
stale_quarantine=
for candidate in "$old_ctl_original".installing.*; do
  [ -e "$candidate" ] || continue
  [ -z "$stale_quarantine" ] || fail "multiple quarantined legacy controllers require recovery"
  stale_quarantine=$candidate
done
if [ -n "$stale_quarantine" ]; then
  [ ! -e "$old_ctl_original" ] || fail "a quarantined legacy controller requires recovery"
  mv "$stale_quarantine" "$old_ctl_original" || fail "unable to recover the legacy controller"
fi

if [ -e "$old_ctl_original" ]; then
  [ -x "$old_ctl_original" ] || fail "existing controller is not executable"
  old_ctl_quarantine=$old_ctl_original.installing.$$
  [ ! -e "$old_ctl_quarantine" ] || fail "legacy controller quarantine already exists"
  mv "$old_ctl_original" "$old_ctl_quarantine" || fail "unable to quarantine the legacy controller"
  trap 'restore_old_controller || true' EXIT
  trap 'restore_old_controller || true; exit 1' HUP INT TERM
  "$old_ctl_quarantine" stop >/dev/null 2>&1 || fail "unable to stop the existing runtime"
fi

say "extracting module controller"
unzip -o "$ZIPFILE" -x 'META-INF/*' -x 'payload/*' -d "$MODPATH" >&2 || fail "module extraction failed"
[ -f "$MODPATH/payload-manifest.txt" ] || fail "payload manifest is missing"

mkdir -p "$DATA_DIR/releases" "$DATA_DIR/config" "$DATA_DIR/config/profiles" \
  "$DATA_DIR/plugins" "$DATA_DIR/plugins/linux/arm64" "$DATA_DIR/run" \
  "$DATA_DIR/logs" "$DATA_DIR/backups"

stage="$DATA_DIR/releases/.staging.$$.${RANDOM:-0}"
rm -rf "$stage"
mkdir -p "$stage"
unzip -o "$ZIPFILE" 'payload/*' -d "$stage" >&2 || fail "payload extraction failed"
runtime="$stage/payload"
[ -f "$runtime/runtime.version" ] || fail "runtime version is missing"
[ -f "$runtime/checksums.sha256" ] || fail "runtime checksum manifest is missing"
[ ! -e "$runtime/plugins" ] || fail "payload must not contain a plugins directory"

verify_runtime_checksums "$runtime" || fail "payload checksum mismatch or sha256sum unavailable"
payload_manifest_sha=$("$BUSYBOX" sha256sum "$runtime/checksums.sha256" | "$BUSYBOX" awk '{print $1}')
case "$payload_manifest_sha" in ''|*[!0-9a-f]*) fail "unable to identify payload content" ;; esac
[ "${#payload_manifest_sha}" -eq 64 ] || fail "unexpected payload identifier length"

release_id=$(sed -n 's/^release_id=//p' "$runtime/runtime.version" | head -1)
case "$release_id" in
  ''|*[!A-Za-z0-9._-]*) fail "runtime release id is unsafe" ;;
esac

release="$DATA_DIR/releases/$release_id-$payload_manifest_sha"
if [ -e "$release" ] || [ -L "$release" ]; then
  [ -d "$release" ] && [ ! -L "$release" ] || fail "existing release target is unsafe"
  existing_manifest_sha=$("$BUSYBOX" sha256sum "$release/checksums.sha256" 2>/dev/null | "$BUSYBOX" awk '{print $1}')
  [ "$existing_manifest_sha" = "$payload_manifest_sha" ] || fail "existing release identity does not match payload"
  verify_runtime_checksums "$release" || fail "existing release failed checksum validation"
  rm -rf "$stage"
else
  mv "$runtime" "$release" || fail "unable to publish runtime release"
  rm -rf "$stage"
fi

# Plugins live in persistent $DATA_DIR/plugins, outside releases/, so a
# release swap never touches them. If a previous layout kept plugins
# under the old release dir, copy them forward (template migration).
old_plugins="$DATA_DIR/current/plugins"
if [ -d "$old_plugins" ]; then
  cp -a "$old_plugins/." "$DATA_DIR/plugins/" 2>/dev/null || fail "unable to preserve installed plugins"
  say "preserved runtime-installed plugins"
fi

rm -f "$DATA_DIR/current.new.$$"
ln -s "$release" "$DATA_DIR/current.new.$$" || fail "unable to stage runtime selection"
"$BUSYBOX" mv -fT "$DATA_DIR/current.new.$$" "$DATA_DIR/current" || fail "unable to select runtime release"
[ "$(readlink "$DATA_DIR/current" 2>/dev/null)" = "$release" ] || fail "runtime release selection did not persist"

# The real config is NEVER auto-created. The example is copied only as
# config.json.example, and only when no real config exists yet.
if [ ! -f "$DATA_DIR/config/config.json" ] && [ -f "$MODPATH/config.example.json" ]; then
  cp -p "$MODPATH/config.example.json" "$DATA_DIR/config/config.json.example"
fi

find "$release" -type d -exec chmod 0755 {} \; 2>/dev/null || true
find "$release" -type f -exec chmod 0644 {} \; 2>/dev/null || true
find "$release/bin" -type f -exec chmod 0755 {} \; 2>/dev/null || true
find "$release/lib" -type f -exec chmod 0755 {} \; 2>/dev/null || true

chmod 0711 "$DATA_DIR"
chmod 0700 "$DATA_DIR/config" "$DATA_DIR/config/profiles" \
  "$DATA_DIR/plugins" "$DATA_DIR/plugins/linux/arm64" \
  "$DATA_DIR/run" "$DATA_DIR/logs" "$DATA_DIR/backups"
# The daemon runs as root in module context (see docs: no 9999:3003
# privilege drop). Data stays root-owned; modes below are the secret
# boundary, not ownership.
find "$DATA_DIR/config" "$DATA_DIR/run" \
  "$DATA_DIR/logs" -type d -exec chmod 0700 {} \; 2>/dev/null || true
find "$DATA_DIR/config" "$DATA_DIR/run" \
  "$DATA_DIR/logs" -type f -exec chmod 0600 {} \; 2>/dev/null || true
find "$DATA_DIR/plugins" -type d -exec chmod 0700 {} \; 2>/dev/null || true
find "$DATA_DIR/plugins" -type f -exec chmod 0600 {} \; 2>/dev/null || true

# Permissions for module files. webroot/ is deliberately excluded:
# KernelSU sets its permissions and SELinux context automatically
# and warns against setting them by hand (Module WebUI guide).
for entry in "$MODPATH"/*; do
  case "$entry" in
    */webroot) continue ;;
  esac
  if [ -d "$entry" ]; then
    set_perm_recursive "$entry" 0 0 0755 0644
  elif [ -f "$entry" ]; then
    set_perm "$entry" 0 0 0644
  fi
done
set_perm "$MODPATH/customize.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
set_perm "$MODPATH/scripts/castctl-ctl" 0 0 0755

restore_old_controller || fail "unable to restore the legacy controller"
trap - EXIT HUP INT TERM

say "runtime release: $release_id"
if [ -f "$DATA_DIR/config/config.json" ]; then
  say "config found; reboot or run castctl-ctl start"
else
  say "config not found; copy config.json manually before starting"
fi
say "installation complete; persistent data was preserved"
