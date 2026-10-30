#!/bin/sh
# Regenerate noise_transport.pb.go and noise_envelope.pb.go into
# go/internal/proto/ from the .proto sources in this directory.
#
# Route (no protoc, no buf on the VM):
#   protocompile v0.14.1 (pure Go, pinned in this directory's go.mod)
#     + the real protoc-gen-go v1.36.12 binary via the plugin protocol,
#   driven by compile.go in this directory.
#
# The driver is built and run from a CLEAN COPY under /tmp; only the two
# generated .pb.go files are copied back into the tree. The main module's
# go.mod/go.sum are never touched by this script.
#
# Usage:
#   ./generate.sh [PATH-TO-protoc-gen-go]
#
# If no path is given, the script reuses the PR0 binary at
# ~/workspace/tmp/goport-pr0/proto-probe/bin/protoc-gen-go when it runs
# and reports v1.36.12, then falls back to a protoc-gen-go on PATH.
# If neither exists, it builds protoc-gen-go v1.36.12 into a temp dir
# with `go install` (module proxy) and uses that build.
# PROTOC_GEN_GO, if set, overrides the search above.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROTO_DIR=$SCRIPT_DIR
OUT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

# --- locate protoc-gen-go v1.36.12 -------------------------------------
PLUGIN=${1:-${PROTOC_GEN_GO:-}}
if [ -z "$PLUGIN" ]; then
	PR0_BIN="$HOME/workspace/tmp/goport-pr0/proto-probe/bin/protoc-gen-go"
	if [ -x "$PR0_BIN" ]; then
		PLUGIN=$PR0_BIN
	elif command -v protoc-gen-go >/dev/null 2>&1; then
		PLUGIN=$(command -v protoc-gen-go)
	fi
fi
TMPBIN=""
if [ -z "$PLUGIN" ]; then
	TMPBIN=$(mktemp -d)
	PLUGIN="$TMPBIN/protoc-gen-go"
	echo "protoc-gen-go not found; building v1.36.12 with: go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12" >&2
	GOBIN="$TMPBIN" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
fi
PLUGIN_VERSION=$("$PLUGIN" --version)
echo "protoc-gen-go: $PLUGIN ($PLUGIN_VERSION)"
case "$PLUGIN_VERSION" in
	*"v1.36.12"*) ;;
	*) echo "generate.sh: expected protoc-gen-go v1.36.12, got: $PLUGIN_VERSION" >&2; exit 1 ;;
esac

# --- clean copy ----------------------------------------------------------
WORK=$(mktemp -d)
trap 'rm -rf "$WORK" ${TMPBIN:+$TMPBIN}' EXIT
cp "$PROTO_DIR/noise_transport.proto" "$PROTO_DIR/noise_envelope.proto" \
	"$PROTO_DIR/compile.go" "$PROTO_DIR/go.mod" "$PROTO_DIR/go.sum" "$WORK/"
mkdir -p "$WORK/out" "$WORK/desc"

# --- build driver + generate ---------------------------------------------
cd "$WORK"
go build -o "$WORK/compile" compile.go
"$WORK/compile" -proto-dir "$WORK" -plugin "$PLUGIN" -out "$WORK/out" \
	-strip-prefix "github.com/thoitiettxl-cyber/muse-cli/go/" \
	-desc-out "$WORK/desc" \
	noise_transport.proto noise_envelope.proto

# --- copy only the generated files back -----------------------------------
cp "$WORK/out/internal/proto/noise_transport.pb.go" \
	"$WORK/out/internal/proto/noise_envelope.pb.go" "$OUT_DIR/"

# --- inject the SPDX header into the generated files ---------------------
# protoc-gen-go emits no licence header. The SPDX header is injected
# here, on every regeneration, so the committed .pb.go files always
# carry it and go/spdx_test.go keeps passing. Idempotent: a file
# already starting with the header is left untouched. Never hand-edit
# a .pb.go file to add or restore the header; re-run this script.
for f in "$OUT_DIR/noise_transport.pb.go" "$OUT_DIR/noise_envelope.pb.go"; do
	if [ "$(head -n 1 "$f")" != "// Copyright (c) 2026 muse-cli contributors" ]; then
		{
			printf '%s\n' "// Copyright (c) 2026 muse-cli contributors" "// SPDX-License-Identifier: GPL-3.0-or-later" "// Licensed under the GNU General Public License v3.0 or later." ""
			cat "$f"
		} > "$WORK/spdx.tmp"
		mv "$WORK/spdx.tmp" "$f"
	fi
done

if [ -n "$(gofmt -l "$OUT_DIR/noise_transport.pb.go" "$OUT_DIR/noise_envelope.pb.go")" ]; then
	echo "generate.sh: generated files are not gofmt-clean" >&2
	exit 1
fi
echo "wrote:"
sha256sum "$OUT_DIR/noise_transport.pb.go" "$OUT_DIR/noise_envelope.pb.go"
echo "compiled descriptors (comparison only, NOT committed): $WORK/desc"
echo "regeneration done; verify with: go test -race -tags with_utls,with_quic,with_wireguard,with_gvisor ./internal/proto/ (from go/)"
