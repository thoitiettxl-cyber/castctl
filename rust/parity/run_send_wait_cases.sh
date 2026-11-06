#!/bin/bash
# M7b PR-2 send Tier A golden harness.
#
# For each case in rust/parity/send_wait_cases/*.json: start a
# FRESH scripted server (gateway_server serve-wait) per driver
# run (script state is per-process, so a fresh server is the
# reset), run the Go send_wait_driver and the Rust
# send_wait_driver example with the case argv against the same
# script, and compare stdout bytes + stderr bytes + exit code.
#
# Usage:
#   run_send_wait_cases.sh [out-dir]
#
# Env (defaults are the cue layout):
#   M7B_SEND_SERVER    gateway_server binary (default
#                      /tmp/m7b-pr2-gateway_server)
#   M7B_SEND_GO_DRIVER Go send_wait_driver binary (default
#                      /tmp/m7b-pr2-send_wait_driver)
#   M7B_SEND_RS_DRIVER Rust send_wait_driver example (default
#                      /tmp/m7b-pr2-target/debug/examples/send_wait_driver)
#
# Outputs in <out-dir>: <case>-{go,rs}.{out,err,exit},
# <case>-{go,rs}.{timeout,elapsed_ms},
# <case>-{go,rs}.server.{log,err}, <case>-{go,rs}.dl/ (the
# download dir when the case sets --download), and a PASS/FAIL
# table on stdout. Exit 0 iff every case passes.
#
# Verdict per case (same rules as run_wait_cases.sh, plus the
# send additions): stdout bytes + stderr bytes + exit code
# must match, AND the two server logs must agree on the WAIT
# SUMMARY counts (history_calls/subscribes) — a read-count
# divergence is a behaviour difference even when the outputs
# match — AND the per-call WAIT log lines (history calls +
# subscribes + stream opens + media gets) must match line for
# line, AND each server must have opened at least one stream
# (WAIT SUMMARY streams>=1: a send that never opens
# chat.stream cannot pass as a send turn, even if both
# drivers fail identically), AND the chat.stream request-body
# bytes the fixture logged (WAIT stream-body) must match on
# both sides AND equal the case file's stream_body literal
# (round-1 N-R1: a byte-level escaping difference in the sent
# text would otherwise be invisible), AND neither driver may have been
# killed by the 60 s watchdog, AND each server must have
# printed its WAIT SUMMARY with at least one call (a server
# that died after READY prints no summary and saw no calls;
# both drivers failing identically on it would otherwise
# PASS). The >=1-call rule applies only to cases that dial.
#
# Cases that set --download pass __DLDIR__ in argv; the
# runner substitutes a fresh per-driver dir, normalizes the
# dir path to DLDIR in .out/.err before comparing, and diffs
# the two download trees (file names + bytes).
#
# No `set -e`: driver exit 124 (timeout cases) and 5
# (no-ack) are EXPECTED outcomes, not script failures. Setup
# failures exit 1.
set -u

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CASES="$DIR/send_wait_cases"
SERVER=${M7B_SEND_SERVER:-/tmp/m7b-pr2-gateway_server}
GO=${M7B_SEND_GO_DRIVER:-/tmp/m7b-pr2-send_wait_driver}
RS=${M7B_SEND_RS_DRIVER:-/tmp/m7b-pr2-target/debug/examples/send_wait_driver}
OUT=${1:-/tmp/m7b-pr2-tier-send}
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

# run_driver <tag> <bin> <addr> <dl-dir> <args...>: run one
# driver under a 60 s watchdog and record, SEPARATELY, the
# driver's own exit code ($tag.exit) and whether the watchdog
# killed it ($tag.timeout: ok|killed), plus the wall time
# ($tag.elapsed_ms). `timeout(1)` cannot do this: it returns
# 124 both when it kills a hung driver and when the driver
# itself exits 124, so a mutual hang used to PASS as a
# legitimate wait timeout (red-team F4, run_wait_cases.sh).
# A real wait-124 run finishes in seconds (the timeout cases
# run their 2 s wait; the done-turn cases finish in <1 s
# despite larger --wait values), so a kill at 60 s is always
# a harness timeout, never a wait outcome.
run_driver() {
    local tag=$1 bin=$2 addr=$3 dldir=$4
    shift 4
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
    # Normalize the download dir in the outputs (the two
    # drivers download to different dirs by construction).
    if [ -n "$dldir" ]; then
        sed -i "s|$dldir|DLDIR|g" "$OUT/$tag.out" "$OUT/$tag.err"
    fi
}

# summary_counts <server-err-file>: print "history_calls
# subscribes" from the server's WAIT SUMMARY line, or
# nothing when the server never printed one (it died
# before shutdown). The summary is the server's own
# accounting of what the driver asked for.
summary_counts() {
    sed -n 's/^WAIT SUMMARY history_calls=\([0-9][0-9]*\) subscribes=\([0-9][0-9]*\)$/\1 \2/p' "$1" | tail -1
}

# streams_count <server-err-file>: the stream opens from
# the second WAIT SUMMARY line, or nothing.
streams_count() {
    sed -n 's/^WAIT SUMMARY streams=\([0-9][0-9]*\) media=.*$/\1/p' "$1" | tail -1
}

# wait_lines <server-err-file>: the per-call WAIT log
# lines (history calls + subscribes + stream opens +
# media gets), in order. No timestamps exist on these
# lines, so they diff directly.
wait_lines() {
    grep -h '^WAIT history \|^WAIT subscribe \|^WAIT stream \|^WAIT media ' "$1" || true
}

# stream_body <server-err-file>: the chat.stream request-body
# bytes the serve-wait fixture logged (one line per stream
# open), or nothing when the fixture never logged one.
stream_body() {
    sed -n 's/^WAIT stream-body //p' "$1" || true
}

for case in "$CASES"/*.json; do
    name=$(basename "$case" .json)
    cp "$case" "$OUT/$name.case.json"
    readarray -t ARGS < <(python3 -c "import json,sys; [print(a) for a in json.load(open(sys.argv[1]))['args']]" "$case")
    # "dial": false marks a case that never dials (e.g.
    # parse-error-only); default true. The >=1-call and
    # streams>=1 rules are skipped for such cases.
    dial=$(python3 -c "import json,sys; print(str(json.load(open(sys.argv[1])).get('dial', True)).lower())" "$case")
    # __DLDIR__ in argv marks a download case: each driver
    # gets a fresh dir, substituted here.
    has_dl=0
    for a in "${ARGS[@]}"; do
        [ "$a" = "__DLDIR__" ] && has_dl=1
    done
    go_args=()
    rs_args=()
    for a in "${ARGS[@]}"; do
        if [ "$a" = "__DLDIR__" ]; then
            go_args+=("$OUT/$name-go.dl")
            rs_args+=("$OUT/$name-rs.dl")
        else
            go_args+=("$a")
            rs_args+=("$a")
        fi
    done
    [ "$has_dl" = 1 ] && mkdir -p "$OUT/$name-go.dl" "$OUT/$name-rs.dl"
    start=$(date +%s)

    read -r srv_pid addr < <(start_server "$case" "$name-go") || exit 1
    run_driver "$name-go" "$GO" "$addr" "$OUT/$name-go.dl" "${go_args[@]}"
    kill $srv_pid 2>/dev/null
    wait $srv_pid 2>/dev/null || true

    read -r srv_pid addr < <(start_server "$case" "$name-rs") || exit 1
    run_driver "$name-rs" "$RS" "$addr" "$OUT/$name-rs.dl" "${rs_args[@]}"
    kill $srv_pid 2>/dev/null
    wait $srv_pid 2>/dev/null || true

    elapsed=$(( $(date +%s) - start ))
    ok=1
    reason=""
    cmp -s "$OUT/$name-go.out" "$OUT/$name-rs.out" || { ok=0; reason="$reason stdout;"; }
    cmp -s "$OUT/$name-go.err" "$OUT/$name-rs.err" || { ok=0; reason="$reason stderr;"; }
    [ "$(cat "$OUT/$name-go.exit")" = "$(cat "$OUT/$name-rs.exit")" ] || { ok=0; reason="$reason exit go=$(cat "$OUT/$name-go.exit") rs=$(cat "$OUT/$name-rs.exit");"; }
    # F4: a watchdog kill is a harness failure, whatever
    # the exit codes say.
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
    [ -n "$go_sum" ] || { ok=0; reason="$reason go-server-summary-missing;"; }
    [ -n "$rs_sum" ] || { ok=0; reason="$reason rs-server-summary-missing;"; }
    if [ "$dial" = true ]; then
        [ "$go_sum" != "0 0" ] || { ok=0; reason="$reason go-server-saw-no-calls;"; }
        [ "$rs_sum" != "0 0" ] || { ok=0; reason="$reason rs-server-saw-no-calls;"; }
    fi
    [ "$go_sum" = "$rs_sum" ] || { ok=0; reason="$reason server-counts go=[$go_sum] rs=[$rs_sum];"; }
    # R2-2: the per-call WAIT lines must match too.
    go_wait=$(wait_lines "$OUT/$name-go.server.err")
    rs_wait=$(wait_lines "$OUT/$name-rs.server.err")
    [ "$go_wait" = "$rs_wait" ] || { ok=0; reason="$reason server-wait-lines-differ;"; }
    # Send addition: the stream must have opened (a send
    # that never opens chat.stream cannot pass as a send
    # turn, even if both drivers fail identically).
    go_streams=""
    rs_streams=""
    if [ "$dial" = true ]; then
        go_streams=$(streams_count "$OUT/$name-go.server.err")
        rs_streams=$(streams_count "$OUT/$name-rs.server.err")
        [ -n "$go_streams" ] || { ok=0; reason="$reason go-server-streams-missing;"; }
        [ -n "$rs_streams" ] || { ok=0; reason="$reason rs-server-streams-missing;"; }
        [ "$go_streams" != "0" ] || { ok=0; reason="$reason go-server-opened-no-stream;"; }
        [ "$rs_streams" != "0" ] || { ok=0; reason="$reason rs-server-opened-no-stream;"; }
        [ "$go_streams" = "$rs_streams" ] || { ok=0; reason="$reason server-streams go=[$go_streams] rs=[$rs_streams];"; }
        # N-R1: the stream request body must be byte-identical
        # on both sides AND equal the expected literal in the
        # case file (the serve-wait fixture logs the raw body
        # bytes; the old fixture logged only the open count).
        go_body=$(stream_body "$OUT/$name-go.server.err")
        rs_body=$(stream_body "$OUT/$name-rs.server.err")
        expected_body=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('stream_body',''))" "$case")
        [ -n "$go_body" ] || { ok=0; reason="$reason go-server-stream-body-missing;"; }
        [ -n "$rs_body" ] || { ok=0; reason="$reason rs-server-stream-body-missing;"; }
        [ "$go_body" = "$rs_body" ] || { ok=0; reason="$reason server-stream-body-differ;"; }
        [ "$go_body" = "$expected_body" ] || { ok=0; reason="$reason go-stream-body-mismatch-expected;"; }
        [ "$rs_body" = "$expected_body" ] || { ok=0; reason="$reason rs-stream-body-mismatch-expected;"; }
    fi
    # Download cases: the two download trees must match
    # (file names + bytes).
    if [ "$has_dl" = 1 ]; then
        if [ -d "$OUT/$name-go.dl" ] && [ -d "$OUT/$name-rs.dl" ]; then
            diff -r "$OUT/$name-go.dl" "$OUT/$name-rs.dl" >"$OUT/$name.dl.diff" 2>&1 || { ok=0; reason="$reason download-trees-differ;"; }
        else
            ok=0; reason="$reason download-dir-missing;"
        fi
    fi
    if [ "$ok" = 1 ]; then
        pass=$((pass + 1))
        echo "PASS $name (exit=$(cat "$OUT/$name-go.exit"), ${elapsed}s, server history_calls/subscribes=[$go_sum] streams=[$go_streams])"
    else
        fail=$((fail + 1))
        failed_cases="$failed_cases $name"
        echo "FAIL $name (go exit=$(cat "$OUT/$name-go.exit") rs exit=$(cat "$OUT/$name-rs.exit"), ${elapsed}s, reason: $reason)"
        echo "--- stdout diff ($name) ---"
        diff "$OUT/$name-go.out" "$OUT/$name-rs.out" | head -20 || true
        echo "--- stderr diff ($name) ---"
        diff "$OUT/$name-go.err" "$OUT/$name-rs.err" | head -20 || true
        echo "--- server summaries ($name): go=[$go_sum] rs=[$rs_sum] streams go=[$go_streams] rs=[$rs_streams] ---"
        echo "--- server WAIT lines diff ($name) ---"
        diff <(wait_lines "$OUT/$name-go.server.err") <(wait_lines "$OUT/$name-rs.server.err") | head -20 || true
        echo "--- server stream-body diff ($name) ---"
        diff <(stream_body "$OUT/$name-go.server.err") <(stream_body "$OUT/$name-rs.server.err") | head -20 || true
        echo "--- expected stream-body ($name): [$expected_body] ---"
        if [ "$has_dl" = 1 ]; then
            echo "--- download tree diff ($name) ---"
            cat "$OUT/$name.dl.diff" | head -20 || true
        fi
    fi
done

echo "tier-a: pass=$pass fail=$fail failed=[$failed_cases ]"
[ "$fail" = 0 ]
