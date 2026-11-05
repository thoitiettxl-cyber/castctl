#!/bin/sh
# Regenerate the M2 parity golden files (one command, overwrites
# the whole golden dir). Runs on cue with the installed Go binary.
# Usage: sh rust/parity/gen_golden.sh [from the repo root on cue]
# Env: GO_BIN (default /usr/local/bin/castctl).
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$SCRIPT_DIR/gen_golden.py"
