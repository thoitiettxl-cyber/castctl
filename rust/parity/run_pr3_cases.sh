#!/bin/bash
# PR-3 parity harness (M7b PR-3): offline Go-vs-Rust cases for
# `auth list` / `auth status` / `auth import` (+ parser-level
# `update` cases that need no network), comparing stdout bytes
# + stderr bytes + exit code, and for import the resulting
# cookies file bytes + mode + `.bak` state.
#
# The `update --dry-run` / apply paths are NOT here: they hit
# api.github.com, so they are live probes (see the writer
# report); `--dry-run` is included as an opt-in case below.
#
# Usage:
#   run_pr3_cases.sh [out-dir]
#
# Env (defaults are the cue layout):
#   PR3_GO   golden Go binary (default /usr/local/bin/castctl)
#   PR3_RS   Rust binary (default /tmp/pr3-writer-target/debug/castctl-rs)
#   PR3_LIVE=1  also run the live `update --dry-run` case
#               (hits api.github.com; off by default, so the
#               harness stays offline)
#
# Outputs in <out-dir>: <case>.{go,rs}.{out,err,exit} and, for
# import cases, <case>.{go,rs}.cookies (+ .cookies.bak when
# present), and a PASS/FAIL table on stdout. Exit 0 iff every
# case passes. No `set -e`: exit 1/2/3 are EXPECTED outcomes
# for error cases, not script failures.
set -u

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GO=${PR3_GO:-/usr/local/bin/castctl}
RS=${PR3_RS:-/tmp/pr3-writer-target/debug/castctl-rs}
OUT=${1:-/tmp/pr3-cases}
mkdir -p "$OUT" || exit 1

for bin in "$GO" "$RS"; do
    [ -x "$bin" ] || { echo "missing executable: $bin" >&2; exit 1; }
done

PASS=0
FAIL=0

# make_fixture DIR: config with default profile no1 (jar cookies,
# hatch_sess expiring 2030-01-01) + profile no2 (directory, no
# cookies file) + profile no3 (no directory at all).
make_fixture() {
    local home="$1"
    local cfg="$home/.config/castctl"
    mkdir -p "$cfg/profiles/no1" "$cfg/profiles/no2"
    printf '%s' '{"default_profile":"no1","profiles":{"no1":{},"no2":{},"no3":{}}}' \
        > "$cfg/config.json"
    printf '.muse.ai\tTRUE\t/\tTRUE\t1893456000\thatch_sess\tFAKE-SESSION\n' \
        > "$cfg/profiles/no1/cookies.txt"
}

# run_side SIDE HOME STDIN_FILE ARGS... : run one binary with an
# isolated HOME, capture out/err/exit under $OUT/<case>.<side>.*.
# CASE must be set by the caller.
run_side() {
    local side="$1" home="$2" stdin="$3" bin
    shift 3
    if [ "$side" = go ]; then bin="$GO"; else bin="$RS"; fi
    env -i HOME="$home" XDG_CONFIG_HOME="$home/.config" PATH=/usr/bin:/bin \
        "$bin" "$@" \
        < "$stdin" \
        > "$OUT/$CASE.$side.out" 2> "$OUT/$CASE.$side.err"
    echo "$?" > "$OUT/$CASE.$side.exit"
}

# compare_case CASE: stdout + stderr + exit must be byte-identical
# after normalising each side's fixture-home path to HOME (the
# two sides run in different homes by design, and `auth list` /
# `auth import` echo absolute paths).
compare_case() {
    local case="$1"
    local go_home="$OUT/$case.go-home" rs_home="$OUT/$case.rs-home"
    if cmp -s <(sed "s|$go_home|HOME|g" "$OUT/$case.go.out") \
              <(sed "s|$rs_home|HOME|g" "$OUT/$case.rs.out") \
        && cmp -s <(sed "s|$go_home|HOME|g" "$OUT/$case.go.err") \
                 <(sed "s|$rs_home|HOME|g" "$OUT/$case.rs.err") \
        && cmp -s "$OUT/$case.go.exit" "$OUT/$case.rs.exit"; then
        echo "PASS $case"
        PASS=$((PASS + 1))
    else
        echo "FAIL $case"
        echo "  go exit=$(cat "$OUT/$case.go.exit") rs exit=$(cat "$OUT/$case.rs.exit")"
        diff <(sed "s|$go_home|HOME|g" "$OUT/$case.go.out") \
             <(sed "s|$rs_home|HOME|g" "$OUT/$case.rs.out") | head -10 | sed 's/^/  out: /'
        diff <(sed "s|$go_home|HOME|g" "$OUT/$case.go.err") \
             <(sed "s|$rs_home|HOME|g" "$OUT/$case.rs.err") | head -10 | sed 's/^/  err: /'
        FAIL=$((FAIL + 1))
    fi
}

# read_case CASE STDIN_FILE ARGS... : read-only case on fresh
# identical fixtures (nothing is written, but each side gets
# its own home so a stray write cannot cross-contaminate).
read_case() {
    CASE="$1"; local stdin="$2"; shift 2
    local go_home="$OUT/$CASE.go-home" rs_home="$OUT/$CASE.rs-home"
    rm -rf "$go_home" "$rs_home"
    make_fixture "$go_home"
    make_fixture "$rs_home"
    run_side go "$go_home" "$stdin" "$@"
    run_side rs "$rs_home" "$stdin" "$@"
    compare_case "$CASE"
}

# import_case CASE STDIN_FILE: import case on fresh identical
# fixtures; compares out/err/exit AND the resulting cookies
# file (bytes + mode) AND the .bak file (presence + bytes).
import_case() {
    CASE="$1"; local stdin="$2"
    local go_home="$OUT/$CASE.go-home" rs_home="$OUT/$CASE.rs-home"
    rm -rf "$go_home" "$rs_home"
    make_fixture "$go_home"
    make_fixture "$rs_home"
    run_side go "$go_home" "$stdin" auth import
    run_side rs "$rs_home" "$stdin" auth import
    local ok=1
    # Out/err compare home-normalised (same reason as compare_case);
    # cookies/mode/.bak are path-free already.
    cmp -s <(sed "s|$go_home|HOME|g" "$OUT/$CASE.go.out") \
           <(sed "s|$rs_home|HOME|g" "$OUT/$CASE.rs.out") || ok=0
    cmp -s <(sed "s|$go_home|HOME|g" "$OUT/$CASE.go.err") \
           <(sed "s|$rs_home|HOME|g" "$OUT/$CASE.rs.err") || ok=0
    cmp -s "$OUT/$CASE.go.exit" "$OUT/$CASE.rs.exit" || ok=0
    for side in go rs; do
        cp "$OUT/$CASE.$side-home/.config/castctl/profiles/no1/cookies.txt" \
            "$OUT/$CASE.$side.cookies" 2>/dev/null || : > "$OUT/$CASE.$side.cookies"
        stat -c '%a' "$OUT/$CASE.$side-home/.config/castctl/profiles/no1/cookies.txt" \
            > "$OUT/$CASE.$side.cookies.mode" 2>/dev/null || echo "missing" > "$OUT/$CASE.$side.cookies.mode"
        if [ -e "$OUT/$CASE.$side-home/.config/castctl/profiles/no1/cookies.txt.bak" ]; then
            cp "$OUT/$CASE.$side-home/.config/castctl/profiles/no1/cookies.txt.bak" \
                "$OUT/$CASE.$side.cookies.bak"
        else
            : > "$OUT/$CASE.$side.cookies.bak"
        fi
    done
    cmp -s "$OUT/$CASE.go.cookies" "$OUT/$CASE.rs.cookies" || ok=0
    cmp -s "$OUT/$CASE.go.cookies.mode" "$OUT/$CASE.rs.cookies.mode" || ok=0
    cmp -s "$OUT/$CASE.go.cookies.bak" "$OUT/$CASE.rs.cookies.bak" || ok=0
    if [ "$ok" = 1 ]; then
        echo "PASS $CASE"
        PASS=$((PASS + 1))
    else
        echo "FAIL $CASE"
        echo "  go exit=$(cat "$OUT/$CASE.go.exit") rs exit=$(cat "$OUT/$CASE.rs.exit")"
        diff <(sed "s|$go_home|HOME|g" "$OUT/$CASE.go.out") \
             <(sed "s|$rs_home|HOME|g" "$OUT/$CASE.rs.out") | head -10 | sed 's/^/  out: /'
        diff <(sed "s|$go_home|HOME|g" "$OUT/$CASE.go.err") \
             <(sed "s|$rs_home|HOME|g" "$OUT/$CASE.rs.err") | head -10 | sed 's/^/  err: /'
        cmp -s "$OUT/$CASE.go.cookies" "$OUT/$CASE.rs.cookies" \
            || diff "$OUT/$CASE.go.cookies" "$OUT/$CASE.rs.cookies" | head -5 | sed 's/^/  cookies: /'
        FAIL=$((FAIL + 1))
    fi
}

EMPTY="$OUT/empty.stdin"
: > "$EMPTY"

# --- auth list / auth status (read-only) ---
read_case auth-list "$EMPTY" auth list
read_case auth-list-json "$EMPTY" auth list --json
read_case auth-status "$EMPTY" auth status
read_case auth-status-profile "$EMPTY" auth status --profile no2
read_case auth-status-all "$EMPTY" auth status --all
read_case auth-status-nosuch "$EMPTY" auth status --profile nosuch
read_case auth-observe-login "$EMPTY" auth observe-login

# --- auth status with no config at all (empty HOME) ---
CASE=auth-status-no-config
rm -rf "$OUT/$CASE.go-home" "$OUT/$CASE.rs-home"
mkdir -p "$OUT/$CASE.go-home" "$OUT/$CASE.rs-home"
run_side go "$OUT/$CASE.go-home" "$EMPTY" auth status
run_side rs "$OUT/$CASE.rs-home" "$EMPTY" auth status
compare_case "$CASE"

# --- auth import (stdin fixtures; FAKE values only) ---
printf 'hatch_sess=FAKE-ONE; datr=FAKE-DATR' > "$OUT/in-jar.stdin"
import_case auth-import-jar "$OUT/in-jar.stdin"
printf '{"hatch_sess": "FAKE-JSON"}' > "$OUT/in-json.stdin"
import_case auth-import-json "$OUT/in-json.stdin"
printf 'hatch_sess=FAKE-CRLF\r\ndatr=X\r\n' > "$OUT/in-crlf.stdin"
import_case auth-import-crlf "$OUT/in-crlf.stdin"
import_case auth-import-empty "$EMPTY"
printf 'datr=FAKE; foo=bar' > "$OUT/in-nohatch.stdin"
import_case auth-import-nohatch "$OUT/in-nohatch.stdin"
printf '\xff\xfe' > "$OUT/in-badutf8.stdin"
import_case auth-import-badutf8 "$OUT/in-badutf8.stdin"

# --- update parser-level cases (no network) ---
read_case update-check "$EMPTY" update --check
read_case update-bad-version "$EMPTY" update --version bogus

# --- live: update --dry-run (opt-in, hits api.github.com) ---
if [ "${PR3_LIVE:-0}" = 1 ]; then
    read_case update-dry-run "$EMPTY" update --dry-run
fi

echo "pr3: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
