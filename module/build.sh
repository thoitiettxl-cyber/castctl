#!/usr/bin/env bash

# build.sh — host-side packager for the castctl KernelSU module.
#
# Mirrors cli-proxy-api build.sh (template commit f912a733) in structure:
# checksum-pinned downloads, ELF/glibc validation, staged payload with a
# self-verified checksums manifest, secret refusal, deterministic ZIP.
# Adaptations are listed in module/docs/ksu-module.md (deviations table).
# Notably: the CA bundle is downloaded as a pinned Alpine .apk and its
# cert.pem extracted (the template reads it from the Alpine build host),
# and the glibc-loader execution preflight runs only on an AArch64 host
# or under qemu-aarch64; on other hosts it is skipped with a recorded
# warning and the device-side runtime_check() --version preflight is the
# execution proof. See runtime.version loader_preflight.

set -euo pipefail
umask 022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ "${CASTCTL_SOURCES_LOCK+x}" = x ]; then
  echo "custom source locks are not supported; edit the tracked sources.lock" >&2
  exit 1
fi
LOCK_FILE=$ROOT/sources.lock
[ -f "$LOCK_FILE" ] || { echo "missing sources lock: $LOCK_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
. "$LOCK_FILE"

: "${LOCK_CASTCTL_VERSION:?missing LOCK_CASTCTL_VERSION}"
: "${LOCK_CASTCTL_ARCHIVE:?missing LOCK_CASTCTL_ARCHIVE}"
: "${LOCK_CASTCTL_URL:?missing LOCK_CASTCTL_URL}"
: "${LOCK_CASTCTL_SHA256:?missing LOCK_CASTCTL_SHA256}"
: "${LOCK_CASTCTL_MAX_GLIBC:?missing LOCK_CASTCTL_MAX_GLIBC}"
: "${LOCK_GLIBC_VERSION:?missing LOCK_GLIBC_VERSION}"
: "${LOCK_GLIBC_PACKAGE:?missing LOCK_GLIBC_PACKAGE}"
: "${LOCK_GLIBC_URL:?missing LOCK_GLIBC_URL}"
: "${LOCK_GLIBC_SHA256:?missing LOCK_GLIBC_SHA256}"
: "${LOCK_CA_PACKAGE:?missing LOCK_CA_PACKAGE}"
: "${LOCK_CA_APK_URL:?missing LOCK_CA_APK_URL}"
: "${LOCK_CA_APK_SHA256:?missing LOCK_CA_APK_SHA256}"
: "${LOCK_CA_FILE:?missing LOCK_CA_FILE}"
: "${LOCK_CA_SHA256:?missing LOCK_CA_SHA256}"

OUT_DIR=${CASTCTL_MODULE_OUT_DIR:-$ROOT/dist}
case "$OUT_DIR" in
  /*) ;;
  *) OUT_DIR=$ROOT/$OUT_DIR ;;
esac
CACHE_DIR=${CASTCTL_BUILD_CACHE_DIR:-$OUT_DIR/cache}
case "$CACHE_DIR" in
  /*) ;;
  *) CACHE_DIR=$ROOT/$CACHE_DIR ;;
esac
TMP_BASE=${TMPDIR:-/tmp}
ZIP_TIMESTAMP=${CASTCTL_ZIP_TIMESTAMP:-202610310000}
CASTCTL_RUNTIME_DIR=${CASTCTL_RUNTIME_DIR:-}
CASTCTL_BINARY=${CASTCTL_BINARY:-}
GLIBC_LIB_DIR=${GLIBC_LIB_DIR:-}
CA_PEM_OVERRIDE=${CASTCTL_CA_PEM:-}
ALLOW_UNATTESTED=${CASTCTL_ALLOW_UNATTESTED_INPUTS:-0}

fail() {
  echo "build failed: $*" >&2
  exit 1
}

for command in ar curl find grep readelf rg sed sha256sum sort tar touch uname unzip zip; do
  command -v "$command" >/dev/null 2>&1 || fail "missing build command: $command"
done

mkdir -p "$OUT_DIR" "$CACHE_DIR"

work=$(mktemp -d "$TMP_BASE/castctl-module-build.XXXXXX")
download_part=
cleanup() {
  [ -z "$download_part" ] || rm -f "$download_part"
  rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

verify_sha256() {
  file=$1
  expected=$2
  actual=$(sha256sum "$file")
  actual=${actual%% *}
  [ "$actual" = "$expected" ]
}

fetch_locked() {
  target=$1
  url=$2
  expected=$3
  case "$url" in
    https://*) ;;
    *) fail "source URL must use HTTPS: $url" ;;
  esac
  if [ -f "$target" ]; then
    verify_sha256 "$target" "$expected" || fail "cached source checksum mismatch: $target"
    printf 'Using cached source: %s\n' "$target"
    return 0
  fi
  download_part=$target.part.$$
  rm -f "$download_part"
  if ! curl -fL --proto '=https' --tlsv1.2 --connect-timeout 15 \
    --max-time 300 --retry 3 --retry-delay 2 --output "$download_part" "$url"; then
    rm -f "$download_part"
    download_part=
    fail "unable to download: $url"
  fi
  if ! verify_sha256 "$download_part" "$expected"; then
    rm -f "$download_part"
    download_part=
    fail "downloaded source checksum mismatch: $url"
  fi
  mv "$download_part" "$target"
  download_part=
  printf 'Downloaded and verified: %s\n' "$target"
}

# --- CA bundle: pinned Alpine .apk -> verified cert.pem (host-independent) ---
ca_apk=$CACHE_DIR/$LOCK_CA_PACKAGE.apk
ca_extract=$work/ca
mkdir -p "$ca_extract"
if [ -n "$CA_PEM_OVERRIDE" ]; then
  [ -f "$CA_PEM_OVERRIDE" ] || fail "missing CA override file: $CA_PEM_OVERRIDE"
  CA_FILE=$CA_PEM_OVERRIDE
  ca_version=external
else
  fetch_locked "$ca_apk" "$LOCK_CA_APK_URL" "$LOCK_CA_APK_SHA256"
  # LOCK_CA_FILE is an absolute path (/etc/ssl/cert.pem); the .apk
  # member path is relative (etc/ssl/cert.pem). Strip the leading
  # slash for matching. The `|| true` keeps a no-match from
  # exiting silently under pipefail+errexit before the check below.
  ca_rel=${LOCK_CA_FILE#/}
  ca_member=$(tar -tzf "$ca_apk" | grep -E "(^|/)$ca_rel\$" | head -1 || true)
  # The .apk member path is etc/ssl/cert.pem (no leading ./); accept either form.
  [ -n "$ca_member" ] || fail "CA package is missing $LOCK_CA_FILE"
  tar -xzf "$ca_apk" -C "$ca_extract" "$ca_member"
  CA_FILE=$ca_extract/$ca_member
  # etc/ssl/cert.pem is a symlink to certs/ca-certificates.crt in
  # the .apk: extracting the link alone leaves it dangling, so
  # extract the link target too (single level; the -f check
  # below still fails loudly on a deeper chain).
  if [ -L "$CA_FILE" ]; then
    link_target=$(readlink "$CA_FILE")
    case "$link_target" in
      /*) target_member=${link_target#/} ;;
      *) target_member=$(dirname "$ca_member")/$link_target ;;
    esac
    tar -xzf "$ca_apk" -C "$ca_extract" "$target_member" || fail "CA link target missing: $target_member"
  fi
  [ -f "$CA_FILE" ] || fail "CA extraction failed: $CA_FILE"
  ca_version=$LOCK_CA_PACKAGE
fi
ca_sha256=$(sha256sum "$CA_FILE")
ca_sha256=${ca_sha256%% *}
[ "$ca_sha256" = "$LOCK_CA_SHA256" ] || fail "CA bundle checksum mismatch: $CA_FILE"

input_mode=locked
if [ -n "$CASTCTL_RUNTIME_DIR" ]; then
  [ -n "$CASTCTL_BINARY" ] || CASTCTL_BINARY=$CASTCTL_RUNTIME_DIR/bin/castctl
  [ -n "$GLIBC_LIB_DIR" ] || GLIBC_LIB_DIR=$CASTCTL_RUNTIME_DIR/lib
  input_mode=runtime
elif [ -n "$CASTCTL_BINARY" ] || [ -n "$GLIBC_LIB_DIR" ]; then
  [ -n "$CASTCTL_BINARY" ] && [ -n "$GLIBC_LIB_DIR" ] || \
    fail "CASTCTL_BINARY and GLIBC_LIB_DIR must be supplied together"
  input_mode=local
else
  castctl_archive=$CACHE_DIR/$LOCK_CASTCTL_ARCHIVE
  glibc_package=$CACHE_DIR/$LOCK_GLIBC_PACKAGE
  fetch_locked "$castctl_archive" "$LOCK_CASTCTL_URL" "$LOCK_CASTCTL_SHA256"
  fetch_locked "$glibc_package" "$LOCK_GLIBC_URL" "$LOCK_GLIBC_SHA256"

  castctl_extract=$work/castctl
  mkdir -p "$castctl_extract"
  tar -tzf "$castctl_archive" >"$work/castctl-members"
  core_members=0
  while IFS= read -r member; do
    case "$member" in
      ''|/*|..|../*|*/../*|*/..) fail "unsafe castctl archive member: $member" ;;
    esac
    [ "$member" != castctl ] || core_members=$((core_members + 1))
    case "$member" in
      castctl|LICENSE|LICENSE.sing-box|NOTICE|README.md) ;;
      *) fail "unexpected castctl archive member: $member" ;;
    esac
  done <"$work/castctl-members"
  [ "$core_members" -eq 1 ] || fail "castctl archive must contain one root-level castctl"
  tar -o --no-same-permissions -xzf "$castctl_archive" \
    -C "$castctl_extract" castctl
  CASTCTL_BINARY=$castctl_extract/castctl
  [ -f "$CASTCTL_BINARY" ] && [ ! -L "$CASTCTL_BINARY" ] || fail "extracted core is not a regular file"
  chmod 0755 "$CASTCTL_BINARY"

  deb_extract=$work/deb
  control_extract=$work/control
  GLIBC_LIB_DIR=$work/glibc-lib
  mkdir -p "$deb_extract" "$control_extract" "$GLIBC_LIB_DIR"
  ar t "$glibc_package" >"$work/deb-members"
  grep -Fxq debian-binary "$work/deb-members" || fail "glibc package is missing debian-binary"
  grep -Fxq control.tar.xz "$work/deb-members" || fail "glibc package is missing control.tar.xz"
  grep -Fxq data.tar.xz "$work/deb-members" || fail "glibc package is missing data.tar.xz"
  ar x --output="$deb_extract" "$glibc_package" control.tar.xz data.tar.xz
  tar -o --no-same-permissions -xJf "$deb_extract/control.tar.xz" \
    -C "$control_extract" ./control
  grep -Fxq 'Package: glibc' "$control_extract/control" || fail "unexpected glibc package name"
  grep -Fxq 'Architecture: aarch64' "$control_extract/control" || fail "glibc package is not AArch64"
  grep -Fxq "Version: $LOCK_GLIBC_VERSION" "$control_extract/control" || fail "unexpected glibc package version"

  : >"$work/glibc-members"
  for library in ld-linux-aarch64.so.1 libc.so.6 libdl.so.2 libresolv.so.2 libpthread.so.0; do
    printf './data/data/com.termux/files/usr/glibc/lib/%s\n' "$library" >>"$work/glibc-members"
  done
  tar -tJf "$deb_extract/data.tar.xz" -T "$work/glibc-members" >/dev/null || \
    fail "glibc package is missing required runtime libraries"
  tar -o --no-same-permissions --no-recursion --strip-components=8 \
    -xJf "$deb_extract/data.tar.xz" -C "$GLIBC_LIB_DIR" -T "$work/glibc-members"
fi

if [ "$ca_version" = external ]; then
  case "$input_mode" in
    locked) input_mode=custom-ca ;;
  esac
fi

if [ "$input_mode" != locked ] && [ "$ALLOW_UNATTESTED" != 1 ]; then
  fail "non-default inputs require CASTCTL_ALLOW_UNATTESTED_INPUTS=1"
fi

for file in "$CASTCTL_BINARY" "$GLIBC_LIB_DIR/ld-linux-aarch64.so.1" \
  "$GLIBC_LIB_DIR/libc.so.6" "$GLIBC_LIB_DIR/libdl.so.2" \
  "$GLIBC_LIB_DIR/libresolv.so.2" "$GLIBC_LIB_DIR/libpthread.so.0"; do
  [ -f "$file" ] || fail "missing payload file: $file"
done

readelf -h "$CASTCTL_BINARY" >"$work/core-elf-header"
grep -Eq 'Class:[[:space:]]+ELF64' "$work/core-elf-header" || fail "core is not ELF64"
grep -Eq 'Machine:[[:space:]]+AArch64' "$work/core-elf-header" || fail "core is not AArch64"
readelf -l "$CASTCTL_BINARY" >"$work/core-program-headers"
grep -Fq '/lib/ld-linux-aarch64.so.1' "$work/core-program-headers" || fail "unexpected core interpreter"

allowed_libs='^(libc\.so\.6|libdl\.so\.2|libresolv\.so\.2|libpthread\.so\.0)$'
readelf -d "$CASTCTL_BINARY" >"$work/core-dynamic"
sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' "$work/core-dynamic" >"$work/core-needed"
[ -s "$work/core-needed" ] || fail "core has no declared shared-library dependencies"
while IFS= read -r needed; do
  grep -Eq "$allowed_libs" <<<"$needed" || fail "unapproved core dependency: $needed"
  [ -f "$GLIBC_LIB_DIR/$needed" ] || fail "unresolved core dependency: $needed"
done <"$work/core-needed"

readelf --version-info "$CASTCTL_BINARY" >"$work/core-version-info"
sed -n 's/.*Name: GLIBC_\([0-9.]*\).*/\1/p' "$work/core-version-info" |
  sort -Vu >"$work/core-glibc-versions"
max_core_glibc=$(tail -1 "$work/core-glibc-versions")
[ -n "$max_core_glibc" ] || fail "unable to determine core GLIBC baseline"
max_allowed=$(printf '%s\n%s\n' "$LOCK_CASTCTL_MAX_GLIBC" "$max_core_glibc" | sort -V | tail -1)
[ "$max_allowed" = "$LOCK_CASTCTL_MAX_GLIBC" ] || \
  fail "core requires GLIBC_$max_core_glibc, maximum allowed is GLIBC_$LOCK_CASTCTL_MAX_GLIBC"

loader=$GLIBC_LIB_DIR/ld-linux-aarch64.so.1
elf_index=0
for elf in "$loader" "$GLIBC_LIB_DIR/libc.so.6" "$GLIBC_LIB_DIR/libdl.so.2" \
  "$GLIBC_LIB_DIR/libresolv.so.2" "$GLIBC_LIB_DIR/libpthread.so.0"; do
  elf_index=$((elf_index + 1))
  readelf -h "$elf" >"$work/glibc-elf-header-$elf_index"
  grep -Eq 'Machine:[[:space:]]+AArch64' "$work/glibc-elf-header-$elf_index" || \
    fail "non-AArch64 glibc payload: $elf"
done

# Loader execution preflight: only possible on AArch64 or under qemu.
# On other hosts the static checks above are the proof available here;
# the device-side runtime_check() --version preflight is the execution
# proof and is mandatory before the first start. Never claim a run
# that did not happen.
host_arch=$(uname -m)
loader_preflight=skipped
core_version=$LOCK_CASTCTL_VERSION
version_line="castctl $LOCK_CASTCTL_VERSION (unverified by execution on $host_arch)"
if [ "$host_arch" = aarch64 ] || [ "$host_arch" = arm64 ] || \
  command -v qemu-aarch64-static >/dev/null 2>&1 || command -v qemu-aarch64 >/dev/null 2>&1; then
  if [ "$host_arch" = aarch64 ] || [ "$host_arch" = arm64 ]; then
    run_loader() { "$loader" "$@"; }
  elif command -v qemu-aarch64-static >/dev/null 2>&1; then
    run_loader() { qemu-aarch64-static "$loader" "$@"; }
  else
    run_loader() { qemu-aarch64 "$loader" "$@"; }
  fi
  loader_list=$({ run_loader --library-path "$GLIBC_LIB_DIR" --list "$CASTCTL_BINARY" 2>&1; } || true)
  [ -n "$loader_list" ] || fail "glibc loader dependency preflight produced no output"
  grep -Fq 'not found' <<<"$loader_list" && fail "glibc loader reported an unresolved dependency"
  version_output=$({ run_loader --library-path "$GLIBC_LIB_DIR" "$CASTCTL_BINARY" --version 2>&1; } || true)
  version_line=$(printf '%s\n' "$version_output" | head -1)
  case "$version_line" in
    "castctl $LOCK_CASTCTL_VERSION"*) ;;
    *) fail "core version preflight failed: ${version_line:-empty}" ;;
  esac
  core_version=$LOCK_CASTCTL_VERSION
  loader_preflight=executed
else
  printf 'WARNING: glibc loader execution preflight skipped (host arch %s, no qemu-aarch64); device runtime_check() must run the --version preflight before the first start.\n' "$host_arch" >&2
fi
if [ "$input_mode" != locked ]; then
  printf 'WARNING: building from %s inputs; official release provenance does not attest to this payload.\n' "$input_mode" >&2
fi

module_version=$(sed -n 's/^version=//p' "$ROOT/module.prop")
[ -n "$module_version" ] || fail "module version is missing"
release_id="module-${module_version#v}-core-$core_version"
stage=$work/stage
mkdir -p "$stage"

for path in module.prop customize.sh service.sh action.sh uninstall.sh \
  config.example.json payload-manifest.txt META-INF webroot scripts docs; do
  cp -a "$ROOT/$path" "$stage/"
done
cp -a "$ROOT/licenses" "$stage/"
cp -a "$ROOT/THIRD_PARTY_NOTICES.md" "$stage/"
# Castctl license files live at the repo root (not in module/).
cp -p "$ROOT/../LICENSE" "$ROOT/../LICENSE.sing-box" "$ROOT/../NOTICE" "$stage/"
if [ "$input_mode" = locked ]; then
  cp -p "$LOCK_FILE" "$stage/sources.lock"
else
  printf 'UNATTESTED DEVELOPMENT BUILD\n\nOne or more release inputs or provenance sources were customized.\nTheir origin, licensing, and source correspondence are not attested by this package.\nKnown license texts are included for reference but may not cover customized inputs; preserve all upstream notices.\nDo not publish this archive as an official release.\n' \
    >"$stage/UNATTESTED_INPUTS.txt"
fi

mkdir -p "$stage/payload/bin" "$stage/payload/lib" "$stage/payload/ca"
cp -p "$CASTCTL_BINARY" "$stage/payload/bin/castctl"
for library in ld-linux-aarch64.so.1 libc.so.6 libdl.so.2 libresolv.so.2 libpthread.so.0; do
  cp -L -p "$GLIBC_LIB_DIR/$library" "$stage/payload/lib/$library"
done
cp -p "$CA_FILE" "$stage/payload/ca/cert.pem"

glibc_version=$LOCK_GLIBC_VERSION
[ "$input_mode" = locked ] || glibc_version=external
printf 'release_id=%s\ncore_version=%s\nmodule_version=%s\nglibc_version=%s\nglibc_baseline=%s\nca_bundle=%s\nca_sha256=%s\nbuild_input=%s\nloader_preflight=%s\ncore_asset=%s\ncore_asset_sha256=%s\n' \
  "$release_id" "$core_version" "$module_version" "$glibc_version" \
  "$max_core_glibc" "$ca_version" "$ca_sha256" "$input_mode" \
  "$loader_preflight" "$LOCK_CASTCTL_ARCHIVE" "$LOCK_CASTCTL_SHA256" \
  >"$stage/payload/runtime.version"

(
  cd "$stage/payload"
  find . -type f ! -name checksums.sha256 -print | LC_ALL=C sort | while read -r path; do
    sha256sum "${path#./}"
  done >checksums.sha256
  sha256sum -c checksums.sha256 >/dev/null
)

find "$stage" -type d -exec chmod 0755 {} \;
find "$stage" -type f -exec chmod 0644 {} \;
chmod 0755 "$stage/META-INF/com/google/android/update-binary" \
  "$stage/customize.sh" "$stage/service.sh" "$stage/action.sh" \
  "$stage/uninstall.sh" "$stage/scripts/castctl-ctl" \
  "$stage/payload/bin/castctl" "$stage/payload/lib/ld-linux-aarch64.so.1"
find "$stage/payload/lib" -type f -exec chmod 0755 {} \;
# webroot/ permissions are set by KernelSU at install time; the ZIP
# carries the file but customize.sh must never chmod it (see docs).

if find "$stage" -type f \( -name config.json -o -name '*.key' \) | grep -q .; then
  fail "refusing to package config or private-key files"
fi
# config.example.json is the only .json file allowed in the package.
if find "$stage" -type f -name '*.json' ! -name config.example.json | grep -q .; then
  fail "refusing to package unexpected JSON files"
fi
if rg -l 'BEGIN [A-Z ]*PRIVATE KEY' "$stage/payload" "$stage/scripts" \
  "$stage/customize.sh" "$stage/service.sh" "$stage/action.sh" \
  "$stage/uninstall.sh" "$stage/config.example.json" >/dev/null 2>&1; then
  fail "refusing to package private keys"
fi
if find "$stage/payload/lib" -type l | grep -q .; then
  fail "refusing to package glibc symlinks"
fi

archive_qualifier=
[ "$input_mode" = locked ] || archive_qualifier=_UNATTESTED
archive=$OUT_DIR/castctl_ksu_${module_version}${archive_qualifier}.zip
rm -f "$archive" "$archive.sha256"
find "$stage" -exec touch -t "$ZIP_TIMESTAMP" {} +
(
  cd "$stage"
  find . -mindepth 1 -print | LC_ALL=C sort | zip -qX "$archive" -@
)
unzip -tq "$archive" >/dev/null
(
  cd "$OUT_DIR"
  sha256sum "$(basename "$archive")" >"$(basename "$archive").sha256"
  sha256sum -c "$(basename "$archive").sha256" >/dev/null
)

printf 'Built: %s\n' "$archive"
printf 'Core: %s\n' "$version_line"
printf 'GLIBC: %s (core baseline GLIBC_%s)\n' "$glibc_version" "$max_core_glibc"
printf 'CA: %s\n' "$ca_version"
printf 'Loader preflight: %s\n' "$loader_preflight"
printf 'Plugins: reserved at /data/local/castctl/plugins (no loader; see docs)\n'
cat "$archive.sha256"
