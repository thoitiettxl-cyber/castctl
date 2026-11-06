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
# Outputs in <out-dir>: <case>-{go,rs}.{out,err,exit},
# <case>-{go,rs}.{timeout,elapsed_ms},
# <case>-{go,rs}.server.{log,err}, and a PASS/FAIL table on
# stdout. Exit 0 iff every case passes.
#
# Verdict per case (fix loop 1, red-team F3/F4/F5;
# fix loop 2, round-2 R2-2/R2-3):
# stdout bytes + stderr bytes + exit code must match, AND
# the two server logs must agree on the WAIT SUMMARY
# counts (history_calls/subscribes) — a read-count
# divergence is a behaviour difference even when the
# outputs match — AND the per-call WAIT log lines
# (history call limit/session_id/events, subscribe
# delay/frames/drop) must match line for line — the
# SUMMARY counts alone cannot see a `limit`
# derivation difference, because the handler returns
# the whole stage regardless of limit — AND neither
# driver may have been killed by the 60 s watchdog (a
# watchdog kill is a harness timeout, never a
# legitimate wait 124: the two are recorded
# separately, see `run_driver`), AND each server must
# have printed its WAIT SUMMARY with at least one call
# (a server that died after READY prints no summary
# and saw no calls; both drivers failing identically
# on it would otherwise PASS). The >=1-call rule
# applies only to cases that dial: a case with
# `"dial": false` in its JSON (e.g. a parse-error-only
# case) never reaches a server, so 0 0 is its correct
# outcome.
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

# run_driver <tag> <bin> <addr> <args...>: run one driver
# under a 60 s watchdog and record, SEPARATELY, the
# driver's own exit code ($tag.exit) and whether the
# watchdog killed it ($tag.timeout: ok|killed), plus the
# wall time ($tag.elapsed_ms). `timeout(1)` cannot do
# this: it returns 124 both when it kills a hung driver
# and when the driver itself exits 124, so a mutual hang
# used to PASS as a legitimate wait timeout (red-team
# F4). A real wait-124 run finishes in seconds (the
# timeout cases e1/e4/e5 run their 5 s timeout; the
# done-turn cases finish in <1 s despite larger
# --timeout values), so a kill at 60 s is always a
# harness timeout, never a wait outcome.
run_driver() {
    local tag=$1 bin=$2 addr=$3
    shift 3
    local start end waited pid
    start=$(date +%s%N)
    "$bin" --addr "$addr" "$@" >"$OUT/$tag.out" 2>"$OUT/$tag.err" &
    pid=$!
    waited=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$waited" -ge 300 ]; then
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null || true
            echo 124 >"$OUT/$tag.exit"
            echo killed >"$OUT/$tag.timeout"
            end=$(date +%s%N)
            echo $(( (end - start) / 1000000 )) >"$OUT/$tag.elapsed_ms"
            return 0
        fi
        sleep 0.2
        waited=$((waited + 1))
    done
    wait "$pid"
    echo $? >"$OUT/$tag.exit"
    echo ok >"$OUT/$tag.timeout"
    end=$(date +%s%N)
    echo $(( (end - start) / 1000000 )) >"$OUT/$tag.elapsed_ms"
}

# summary_counts <server-err-file>: print "history_calls
# subscribes" from the server's WAIT SUMMARY line, or
# nothing when the server never printed one (it died
# before shutdown). The summary is the server's own
# accounting of what the driver asked for.
summary_counts() {
    sed -n 's/^WAIT SUMMARY history_calls=\([0-9][0-9]*\) subscribes=\([0-9][0-9]*\)$/\1 \2/p' "$1" | tail -1
}

# wait_lines <server-err-file>: the per-call WAIT log
# lines (history calls + subscribes), in order. No
# timestamps exist on these lines, so they diff
# directly (round-2 R2-2).
wait_lines() {
    grep -h '^WAIT history \|^WAIT subscribe ' "$1" || true
}

for case in "$CASES"/*.json; do
    name=$(basename "$case" .json)
    cp "$case" "$OUT/$name.case.json"
    # NUL-separated arg passing (fix loop 2, N-R2R1): the old
    # `print(a)` form split any arg containing a newline into
    # two argv elements, so a newline case silently tested only
    # its first line. `readarray -d ''` (bash 4.4+) + NUL bytes
    # carry each arg verbatim (argv cannot contain NUL anyway,
    # so the delimiter is exact).
    readarray -t -d '' ARGS < <(python3 -c "import json,sys; [sys.stdout.buffer.write((a + '\0').encode('utf-8')) for a in json.load(open(sys.argv[1]))['args']]" "$case")
    # "dial": false marks a case that never dials (e.g.
    # parse-error-only); default true. The >=1-call
    # rule is skipped for such cases (round-2 R2-3).
    dial=$(python3 -c "import json,sys; print(str(json.load(open(sys.argv[1])).get('dial', True)).lower())" "$case")
    start=$(date +%s)

    read -r srv_pid addr < <(start_server "$case" "$name-go") || exit 1
    run_driver "$name-go" "$GO" "$addr" "${ARGS[@]}"
    kill $srv_pid 2>/dev/null
    wait $srv_pid 2>/dev/null || true

    read -r srv_pid addr < <(start_server "$case" "$name-rs") || exit 1
    run_driver "$name-rs" "$RS" "$addr" "${ARGS[@]}"
    kill $srv_pid 2>/dev/null
    wait $srv_pid 2>/dev/null || true

    elapsed=$(( $(date +%s) - start ))
    ok=1
    reason=""
    cmp -s "$OUT/$name-go.out" "$OUT/$name-rs.out" || { ok=0; reason="$reason stdout;"; }
    cmp -s "$OUT/$name-go.err" "$OUT/$name-rs.err" || { ok=0; reason="$reason stderr;"; }
    [ "$(cat "$OUT/$name-go.exit")" = "$(cat "$OUT/$name-rs.exit")" ] || { ok=0; reason="$reason exit go=$(cat "$OUT/$name-go.exit") rs=$(cat "$OUT/$name-rs.exit");"; }
    # F4: a watchdog kill is a harness failure, whatever
    # the exit codes say (both drivers hanging yields
    # 124 + empty output on both sides, which used to
    # PASS). Belt and braces: elapsed >= 59 s also
    # fails, in case the marker write ever races.
    [ "$(cat "$OUT/$name-go.timeout")" = ok ] || { ok=0; reason="$reason go-driver-watchdog-kill;"; }
    [ "$(cat "$OUT/$name-rs.timeout")" = ok ] || { ok=0; reason="$reason rs-driver-watchdog-kill;"; }
    [ "$(cat "$OUT/$name-go.elapsed_ms")" -lt 59000 ] || { ok=0; reason="$reason go-driver-elapsed>=59s;"; }
    [ "$(cat "$OUT/$name-rs.elapsed_ms")" -lt 59000 ] || { ok=0; reason="$reason rs-driver-elapsed>=59s;"; }
    # F3: the server logs must agree on read counts.
    go_sum=$(summary_counts "$OUT/$name-go.server.err")
    rs_sum=$(summary_counts "$OUT/$name-rs.server.err")
    # F5: a server that died after READY prints no WAIT
    # SUMMARY; a live server the driver never reached
    # prints 0 0. Both used to PASS (identical
    # connection-refused failures on both sides).
    # The >=1-call rule applies only when the case
    # dials: a case with "dial": false in its JSON
    # never reaches a server, so 0 0 is its correct
    # outcome (round-2 R2-3).
    [ -n "$go_sum" ] || { ok=0; reason="$reason go-server-summary-missing;"; }
    [ -n "$rs_sum" ] || { ok=0; reason="$reason rs-server-summary-missing;"; }
    if [ "$dial" = true ]; then
        [ "$go_sum" != "0 0" ] || { ok=0; reason="$reason go-server-saw-no-calls;"; }
        [ "$rs_sum" != "0 0" ] || { ok=0; reason="$reason rs-server-saw-no-calls;"; }
    fi
    [ "$go_sum" = "$rs_sum" ] || { ok=0; reason="$reason server-counts go=[$go_sum] rs=[$rs_sum];"; }
    # R2-2: the per-call WAIT lines must match too —
    # a limit/session_id difference is invisible in
    # the SUMMARY counts (the handler returns the
    # whole stage regardless of limit).
    go_wait=$(wait_lines "$OUT/$name-go.server.err")
    rs_wait=$(wait_lines "$OUT/$name-rs.server.err")
    [ "$go_wait" = "$rs_wait" ] || { ok=0; reason="$reason server-wait-lines-differ;"; }
    if [ "$ok" = 1 ]; then
        pass=$((pass + 1))
        echo "PASS $name (exit=$(cat "$OUT/$name-go.exit"), ${elapsed}s, server history_calls/subscribes=[$go_sum])"
    else
        fail=$((fail + 1))
        failed_cases="$failed_cases $name"
        echo "FAIL $name (go exit=$(cat "$OUT/$name-go.exit") rs exit=$(cat "$OUT/$name-rs.exit"), ${elapsed}s, reason: $reason)"
        echo "--- stdout diff ($name) ---"
        diff "$OUT/$name-go.out" "$OUT/$name-rs.out" | head -20 || true
        echo "--- stderr diff ($name) ---"
        diff "$OUT/$name-go.err" "$OUT/$name-rs.err" | head -20 || true
        echo "--- server summaries ($name): go=[$go_sum] rs=[$rs_sum] ---"
        echo "--- server WAIT lines diff ($name) ---"
        diff <(wait_lines "$OUT/$name-go.server.err") <(wait_lines "$OUT/$name-rs.server.err") | head -20 || true
    fi
done

echo "tier-a: pass=$pass fail=$fail failed=[$failed_cases ]"
[ "$fail" = 0 ]
