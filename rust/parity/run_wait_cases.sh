#!/bin/bash
# M7a wait Tier A golden harness (parity-live.md §3-§4).
#
# For each case in rust/parity/wait_cases/*.json: start a FRESH
# scripted server (gateway_server serve-wait) per driver run
# (script state is per-process, so a fresh server is the reset),
# run the Go wait_driver and the Rust wait_driver example with
# the case argv against the same script, and compare stdout
# bytes + stderr bytes + exit code.
#
# Usage:
#   run_wait_cases.sh [out-dir]
#
# Env (defaults are the cue layout):
#   M7A_SERVER      gateway_server binary (default /tmp/m7a-gateway_server)
#   M7A_GO_DRIVER   Go wait_driver binary (default /tmp/m7a-wait_driver)
#   M7A_RS_DRIVER   Rust wait_driver example (default
#                   /tmp/m7a-target/debug/examples/wait_driver)
#
# Outputs in <out-dir>: <case>.{go,rs}.{out,err,exit},
# <case>.server-{go,rs}.{log,err}, and a PASS/FAIL table on
# stdout. Exit 0 iff every case passes.
#
# No `set -e`: driver exit 124 (timeout cases) is an EXPECTED
# outcome, not a script failure. Setup failures exit 1.
set -u

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CASES="$DIR/wait_cases"
SERVER=${M7A_SERVER:-/tmp/m7a-gateway_server}
GO=${M7A_GO_DRIVER:-/tmp/m7a-wait_driver}
RS=${M7A_RS_DRIVER:-/tmp/m7a-target/debug/examples/wait_driver}
OUT=${1:-/tmp/m7a-tier-a}
mkdir -p "$OUT" || exit 1

for bin in "$SERVER" "$GO" "$RS"; do
    [ -x "$bin" ] || { echo "missing executable: $bin" >&2; exit 1; }
done
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

# start_server <case> <tag> : start a fresh scripted server,
# wait for its READY line, print "PID ADDR" on stdout.
start_server() {
    local case=$1 tag=$2
    "$SERVER" serve-wait "$case" >"$OUT/$tag.server.log" 2>"$OUT/$tag.server.err" &
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
        echo "server for $tag never became READY" >&2
        kill $pid 2>/dev/null
        return 1
    fi
    echo "$pid $addr"
}

pass=0
fail=0
failed_cases=""
for case in "$CASES"/*.json; do
    name=$(basename "$case" .json)
    cp "$case" "$OUT/$name.case.json"
    readarray -t ARGS < <(python3 -c "import json,sys; [print(a) for a in json.load(open(sys.argv[1]))['args']]" "$case")
    start=$(date +%s)

    read -r srv_pid addr < <(start_server "$case" "$name-go") || exit 1
    timeout 60 "$GO" --addr "$addr" "${ARGS[@]}" >"$OUT/$name.go.out" 2>"$OUT/$name.go.err"
    echo $? >"$OUT/$name.go.exit"
    kill $srv_pid 2>/dev/null
    wait $srv_pid 2>/dev/null || true

    read -r srv_pid addr < <(start_server "$case" "$name-rs") || exit 1
    timeout 60 "$RS" --addr "$addr" "${ARGS[@]}" >"$OUT/$name.rs.out" 2>"$OUT/$name.rs.err"
    echo $? >"$OUT/$name.rs.exit"
    kill $srv_pid 2>/dev/null
    wait $srv_pid 2>/dev/null || true

    elapsed=$(( $(date +%s) - start ))
    ok=1
    cmp -s "$OUT/$name.go.out" "$OUT/$name.rs.out" || ok=0
    cmp -s "$OUT/$name.go.err" "$OUT/$name.rs.err" || ok=0
    [ "$(cat "$OUT/$name.go.exit")" = "$(cat "$OUT/$name.rs.exit")" ] || ok=0
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
        diff "$OUT/$name.go.err" "$OUT/$name.rs.err" | head -20 || true
    fi
done

echo "tier-a: pass=$pass fail=$fail failed=[$failed_cases ]"
[ "$fail" = 0 ]
