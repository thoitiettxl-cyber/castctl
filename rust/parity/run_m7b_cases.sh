#!/bin/bash
# M7b Phase A parity harness (D-M7b-2, Tier A).
#
# For each case in rust/parity/m7b_cases/*.json: start FRESH
# scripted servers (gateway_server serve-m7b + the Python fake
# muse.ai HTTP server) per driver run (script state — HTTP
# stages, request counts — is per-process, so a fresh server
# is the reset), run the Go m7b_driver and the Rust m7b_driver
# example with the case argv against the same script, and
# compare stdout bytes + stderr bytes + exit code + the
# gateway request log (M7B lines) + the HTTP request log
# (M7B-HTTP lines) + the downloaded file trees. A case with
# per-side expected stderr in rust/parity/known_diff/
# (<name>.go.err / <name>.rs.err) is a KNOWN DIFFERENCE
# (D1): each side's stderr is pinned against its own file
# instead of compared side-to-side; everything else still
# compares byte-identical.
#
# Usage:
#   run_m7b_cases.sh [out-dir] [case-glob ...]
#
# Env (defaults are the cue layout):
#   M7B_SERVER    gateway_server binary (default /tmp/m7b-gateway_server)
#   M7B_GO_DRIVER Go m7b_driver binary (default /tmp/m7b-m7b_driver)
#   M7B_RS_DRIVER Rust m7b_driver example (default
#                 /tmp/m7b-target/debug/examples/m7b_driver)
#   M7B_HTTP      Python fake HTTP server (default
#                 rust/parity/m7b_http_server.py)
#
# Outputs in <out-dir>: <case>.{go,rs}.{out,err,exit},
# <case>.{go,rs}.http.err, <case>.server-{go,rs}.err,
# <case>.{go,rs}.dl/ (download dirs), and a PASS/FAIL table
# on stdout. Exit 0 iff every case passes.
#
# The Go driver's HTTP handler is in-process, so its M7B-HTTP
# lines land in the driver's stderr; the Rust side's land in
# the Python server's stderr. The harness splits the Go
# driver's stderr into .err (CLI output) and .http.err
# (M7B-HTTP lines) before comparing.
#
# No `set -e`: driver exit 1/2/3 are EXPECTED outcomes for
# error cases, not script failures. Setup failures exit 1.
set -u

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CASES="$DIR/m7b_cases"
SERVER=${M7B_SERVER:-/tmp/m7b-gateway_server}
GO=${M7B_GO_DRIVER:-/tmp/m7b-m7b_driver}
RS=${M7B_RS_DRIVER:-/tmp/m7b-target/debug/examples/m7b_driver}
HTTP=${M7B_HTTP:-$DIR/m7b_http_server.py}
OUT=${1:-/tmp/m7b-tier-a}
shift || true
mkdir -p "$OUT" || exit 1

for bin in "$SERVER" "$GO" "$RS"; do
    [ -x "$bin" ] || { echo "missing executable: $bin" >&2; exit 1; }
done
[ -f "$HTTP" ] || { echo "missing HTTP server: $HTTP" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

# start_gw <case> <tag> : start a fresh scripted gateway server,
# wait for its READY line, print "PID ADDR" on stdout.
start_gw() {
    local case=$1 tag=$2
    "$SERVER" serve-m7b "$case" >"$OUT/$tag.server.log" 2>"$OUT/$tag.server.err" &
    local pid=$!
    local addr=""
    for _ in $(seq 1 50); do
        if grep -q '^READY addr=' "$OUT/$tag.server.log" 2>/dev/null; then
            addr=$(sed -n 's/^READY addr=//p' "$OUT/$tag.server.log" | head -1)
            break
        fi
        sleep 0.1
    done
    if [ -z "$addr" ]; then
        echo "gateway server for $tag never became READY" >&2
        kill $pid 2>/dev/null
        return 1
    fi
    echo "$pid $addr"
}

# start_http <case> <tag> : start a fresh fake HTTP server,
# wait for its READY line, print "PID ADDR" on stdout.
start_http() {
    local case=$1 tag=$2
    python3 "$HTTP" "$case" >"$OUT/$tag.http.log" 2>"$OUT/$tag.http.err" &
    local pid=$!
    local addr=""
    for _ in $(seq 1 50); do
        if grep -q '^READY addr=' "$OUT/$tag.http.log" 2>/dev/null; then
            addr=$(sed -n 's/^READY addr=//p' "$OUT/$tag.http.log" | head -1)
            break
        fi
        sleep 0.1
    done
    if [ -z "$addr" ]; then
        echo "HTTP server for $tag never became READY" >&2
        kill $pid 2>/dev/null
        return 1
    fi
    echo "$pid $addr"
}

stop_servers() {
    for pid in "$@"; do
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null || true
    done
}

pass=0
fail=0
failed_cases=""
if [ "$#" -gt 0 ]; then
    case_files="$*"
else
    case_files="$CASES"/*.json
fi
for case in $case_files; do
    [ -f "$case" ] || { echo "no such case: $case" >&2; exit 1; }
    name=$(basename "$case" .json)
    cp "$case" "$OUT/$name.case.json"
    readarray -t ARGS < <(python3 -c "import json,sys; [print(a) for a in json.load(open(sys.argv[1]))['args']]" "$case")
    start=$(date +%s)

    # --- Go side ---
    # Fresh download dirs every run: a stale file from an
    # earlier run would turn a fresh download into a
    # skip-exists and mask the real path.
    rm -rf "$OUT/$name.go.dl" "$OUT/$name.rs.dl"
    mkdir -p "$OUT/$name.go.dl"
    read -r gw_pid gw_addr < <(start_gw "$case" "$name-go") || exit 1
    read -r http_pid http_addr < <(start_http "$case" "$name-go") || { stop_servers "$gw_pid"; exit 1; }
    timeout 60 "$GO" --addr "$gw_addr" --script "$case" --download-dir "$OUT/$name.go.dl" "${ARGS[@]}" >"$OUT/$name.go.out" 2>"$OUT/$name.go.err.raw"
    echo $? >"$OUT/$name.go.exit"
    stop_servers "$gw_pid" "$http_pid"
    # Split the Go driver's stderr: M7B-HTTP lines are the HTTP
    # request log; the rest is CLI output.
    grep '^M7B-HTTP ' "$OUT/$name.go.err.raw" >"$OUT/$name.go.http.err" || true
    grep -v '^M7B-HTTP ' "$OUT/$name.go.err.raw" >"$OUT/$name.go.err" || true
    rm -f "$OUT/$name.go.err.raw"
    sed -i "s|$OUT/$name.go.dl|DLDIR|g" "$OUT/$name.go.out" "$OUT/$name.go.err"

    # --- Rust side ---
    mkdir -p "$OUT/$name.rs.dl"
    read -r gw_pid gw_addr < <(start_gw "$case" "$name-rs") || exit 1
    read -r http_pid http_addr < <(start_http "$case" "$name-rs") || { stop_servers "$gw_pid"; exit 1; }
    timeout 60 "$RS" --addr "$gw_addr" --http-addr "$http_addr" --download-dir "$OUT/$name.rs.dl" "${ARGS[@]}" >"$OUT/$name.rs.out" 2>"$OUT/$name.rs.err"
    echo $? >"$OUT/$name.rs.exit"
    stop_servers "$gw_pid" "$http_pid"
    sed -i "s|$OUT/$name.rs.dl|DLDIR|g" "$OUT/$name.rs.out" "$OUT/$name.rs.err"
    # The Rust side's HTTP request log is the Python server's stderr.
    cp "$OUT/$name-rs.http.err" "$OUT/$name.rs.http.err"
    # The gateway request log is the gateway server's stderr
    # (M7B lines + M7B SUMMARY); the READY line is on stdout
    # and carries a per-run port, so it is never compared.

    elapsed=$(( $(date +%s) - start ))
    ok=1
    cmp -s "$OUT/$name.go.out" "$OUT/$name.rs.out" || ok=0
    if [ -f "$DIR/known_diff/$name.go.err" ] && [ -f "$DIR/known_diff/$name.rs.err" ]; then
        # Known difference (D1): the two sides intentionally
        # differ in this one stderr line (Go vs serde JSON
        # decoder text); pin each side's exact text instead
        # of comparing them to each other. Everything else
        # (stdout, exit, logs, downloads) still compares
        # byte-identical.
        cmp -s "$OUT/$name.go.err" "$DIR/known_diff/$name.go.err" || ok=0
        cmp -s "$OUT/$name.rs.err" "$DIR/known_diff/$name.rs.err" || ok=0
    else
        cmp -s "$OUT/$name.go.err" "$OUT/$name.rs.err" || ok=0
    fi
    [ "$(cat "$OUT/$name.go.exit")" = "$(cat "$OUT/$name.rs.exit")" ] || ok=0
    cmp -s "$OUT/$name-go.server.err" "$OUT/$name-rs.server.err" || ok=0
    cmp -s "$OUT/$name.go.http.err" "$OUT/$name.rs.http.err" || ok=0
    diff -r -q "$OUT/$name.go.dl" "$OUT/$name.rs.dl" >/dev/null 2>&1 || ok=0
    if [ "$ok" = 1 ]; then
        pass=$((pass + 1))
        echo "PASS $name (exit=$(cat "$OUT/$name.go.exit"), ${elapsed}s)"
    else
        fail=$((fail + 1))
        failed_cases="$failed_cases $name"
        echo "FAIL $name (go exit=$(cat "$OUT/$name.go.exit") rs exit=$(cat "$OUT/$name.rs.exit"), ${elapsed}s)"
        echo "--- stdout diff ($name) ---"
        diff "$OUT/$name.go.out" "$OUT/$name.rs.out" | head -20 || true
        echo "--- stderr diff ($name) ---"
        if [ -f "$DIR/known_diff/$name.go.err" ] && [ -f "$DIR/known_diff/$name.rs.err" ]; then
            diff "$OUT/$name.go.err" "$DIR/known_diff/$name.go.err" | head -20 || true
            diff "$OUT/$name.rs.err" "$DIR/known_diff/$name.rs.err" | head -20 || true
        else
            diff "$OUT/$name.go.err" "$OUT/$name.rs.err" | head -20 || true
        fi
        echo "--- gateway-log diff ($name) ---"
        diff "$OUT/$name-go.server.err" "$OUT/$name-rs.server.err" | head -20 || true
        echo "--- http-log diff ($name) ---"
        diff "$OUT/$name.go.http.err" "$OUT/$name.rs.http.err" | head -20 || true
        echo "--- download-tree diff ($name) ---"
        diff -r "$OUT/$name.go.dl" "$OUT/$name.rs.dl" | head -10 || true
    fi
done

echo "tier-a: pass=$pass fail=$fail failed=[$failed_cases ]"
[ "$fail" = 0 ]
