#!/bin/sh
# M-perf-0 one-command rerun (on cue, from the repo root):
#   sh rust/perf/run.sh [--skip-build] [--skip-item5]
# Builds the Rust release binary (plain, then RUSTFLAGS=-C strip=symbols),
# runs items 1-5, writes rust/perf/data/*.json + summary.json, prints the
# summary table. Requires: cargo +1.99.1, Go (PATH=/usr/local/go/bin),
# python3. No network needed after the first cargo build (deps in lock).
set -eu
cd "$(dirname "$0")/../.."
python3 rust/perf/measure_all.py "$@"
