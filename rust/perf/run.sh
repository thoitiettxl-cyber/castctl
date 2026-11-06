#!/bin/sh
# M-perf-0 one-command rerun (on cue, from the repo root):
#   sh rust/perf/run.sh [--skip-build] [--skip-item5] [--skip-full]
# --skip-full (M7c run11): skip the castctl-full legacy builds/columns;
# run11 headline is go vs castctl-rs (full surface at this head).
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
# scans .go files repo-wide. This script never creates .go files UNDER
# THE REPO and never runs a cargo workspace build, so the boring-sys
# trap (SPDX failures from generated .go files under rust/target/ after
# a workspace build) cannot be triggered by this rerun; this check only
# reports. NOTE (M-perf-1): the full-bin build DOES compile boring-sys,
# but its target dir is outside the repo — the driver refuses an
# in-repo target dir before any build (measure_all.py:
# _check_full_target_outside_repo; the guard does not fire under
# --skip-build, where no .go-generating build runs — the workspace,
# full-bin and LTO builds are skipped, and the bench build that still
# runs has no boring-sys in its closure) and defaults to the system temp
# dir when CARGO_TARGET_DIR is unset — so no generated .go file can land
# under the repo from this rerun either.
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
