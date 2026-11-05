#!/bin/sh
# M-perf-0 one-command rerun (on cue, from the repo root):
#   sh rust/perf/run.sh [--skip-build] [--skip-item5]
# Builds the Rust release binary (plain, then RUSTFLAGS=-C strip=symbols),
# runs items 1-5, writes rust/perf/data/*.json + summary.json, prints the
# summary table. Requires: cargo +1.99.1, Go (PATH=/usr/local/go/bin),
# python3, /usr/bin/time (required for RSS — see measure.py).
# No network needed after the first cargo build (deps in lock).
# --skip-item5 really skips item 5 (status "skipped" in summary.json).
set -eu
cd "$(dirname "$0")/../.."
python3 rust/perf/measure_all.py "$@"
# Advisory read-only SPDX check (never fails the run): TestSPDXHeaders
# scans .go files repo-wide. This script never creates .go files and never
# runs a cargo workspace build, so the boring-sys trap (SPDX failures from
# generated .go files under rust/target/ after a workspace build) cannot
# be triggered by this rerun; this check only reports.
if command -v go >/dev/null 2>&1; then
  _spdx_log="$(mktemp /tmp/perf0-spdx-check-XXXXXX.log)"
  if PATH="/usr/local/go/bin:$PATH" GOTOOLCHAIN=auto GOFLAGS=-mod=readonly \
      timeout 300 go test -run TestSPDXHeaders -count=1 . >"$_spdx_log" 2>&1; then
    echo "SPDX check: PASS"
    rm -f "$_spdx_log"
  else
    echo "SPDX check: FAIL (advisory only, rerun unaffected; see $_spdx_log)"
  fi
fi
