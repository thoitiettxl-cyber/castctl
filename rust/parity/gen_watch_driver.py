"""Assemble rust/parity/watch_driver/main.go on cue.

Copies byte-level (no retyping) from:
- rust/parity/send_wait_driver/main.go: the fakeCookie const,
  the plainDialer type + methods, and run()'s connect block
  (auth -> defer gw.Close(), including the WS URL line).
- internal/commands/read.go: printWatchRow, writeWatchField,
  truthyJSON, pythonStr (verbatim helpers).
- internal/commands/commands.go: marshalJSONLine, truncRunes,
  decodeJSONNumber (verbatim helpers).
Fresh text: the doc comment, imports, run()/main() (flag
parsing + SubscribeRaw + classifyWatchErr).
"""
import re
import sys

ROOT = "/tmp/m7b-rb-castctl"
SRC = ROOT + "/rust/parity/send_wait_driver/main.go"
READ_GO = ROOT + "/internal/commands/read.go"
CMDS_GO = ROOT + "/internal/commands/commands.go"
DST = ROOT + "/rust/parity/watch_driver/main.go"


def match_braces(src, open_idx):
    """End index (exclusive) of the brace block opened at
    open_idx, skipping strings / raw strings / rune
    literals / comments."""
    depth = 0
    j = open_idx
    n = len(src)
    state = None
    while j < n:
        c = src[j]
        nxt = src[j + 1] if j + 1 < n else ""
        if state is None:
            if c == "/" and nxt == "/":
                state = "line"
                j += 2
                continue
            if c == "/" and nxt == "*":
                state = "block"
                j += 2
                continue
            if c == '"':
                state = "str"
                j += 1
                continue
            if c == "`":
                state = "raw"
                j += 1
                continue
            if c == "'":
                state = "rune"
                j += 1
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        elif state == "str":
            if c == "\\":
                j += 2
                continue
            if c == '"':
                state = None
            j += 1
        elif state == "raw":
            if c == "`":
                state = None
            j += 1
        elif state == "rune":
            if c == "\\":
                j += 2
                continue
            if c == "'":
                state = None
            j += 1
        elif state == "line":
            if c == "\n":
                state = None
            j += 1
        elif state == "block":
            if c == "*" and nxt == "/":
                state = None
                j += 2
                continue
            j += 1
    raise AssertionError("unbalanced braces")


def extract_func(src, name):
    """Extract a top-level `func name...` body by brace matching."""
    m = re.search(r"(?m)^func " + re.escape(name) + r"\b", src)
    assert m, "func %s not found" % name
    i = src.index("{", m.start())
    return src[m.start(): match_braces(src, i)]


send_src = open(SRC).read()
read_src = open(READ_GO).read()
cmds_src = open(CMDS_GO).read()

# 1. fakeCookie + plainDialer (const at line ~77 through the
# HTTPClient method). The const line and the type/methods are
# copied verbatim; nothing in them is retyped.
start = send_src.index('const fakeCookie = ')
end_marker = "func (d *plainDialer) HTTPClient() *http.Client {"
mstart = send_src.index(end_marker)
mend = match_braces(send_src, send_src.index("{", mstart))
dialer_block = send_src[start:mend]
assert "plainDialer" in dialer_block and "WebSocketDial" in dialer_block

# 2. Connect block inside run(): auth -> defer gw.Close().
cstart = send_src.index("\tauth := &gatewaytest.CannedAuth")
cend = send_src.index("\tdefer gw.Close()", cstart) + len("\tdefer gw.Close()")
connect_block = send_src[cstart:cend]
connect_block = connect_block.replace(
    "send_wait_driver: connect:", "watch_driver: connect:"
)
connect_block = connect_block.replace(
    "send-wait-driver-cookies-*.txt", "watch-driver-cookies-*.txt"
)
connect_block = connect_block.replace(
    '"send_wait_driver:", err', '"watch_driver:", err'
)
assert "send_wait_driver" not in connect_block
assert "auth_token=" in connect_block, "WS URL line must survive the copy"

# 3. Verbatim helpers from Go source.
helpers = []
for name in ["printWatchRow", "writeWatchField", "truthyJSON", "pythonStr"]:
    helpers.append(extract_func(read_src, name))
for name in ["marshalJSONLine", "truncRunes", "decodeJSONNumber"]:
    helpers.append(extract_func(cmds_src, name))
helpers_text = "\n\n".join(helpers)

header = """// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Command watch_driver is the Go side of the M7b PR-2 watch
// Tier A parity gate: run Go's `cmdWatch` shape
// (SubscribeRaw + printWatchRow) against a scripted
// gateway_server (serve-wait mode) and print the CLI row
// shape + exit code, so the gate can diff it byte-for-byte
// against the Rust watch_driver example run with the same
// script and argv.
//
// It CANNOT import internal/commands (unexported cmdWatch),
// so it re-encodes the subscribe call and duplicates the
// row helpers verbatim from internal/commands/read.go
// (printWatchRow / writeWatchField / truthyJSON /
// pythonStr) and commands.go (marshalJSONLine /
// truncRunes / decodeJSONNumber). The connection mirrors
// the send_wait_driver (plain TCP dialer + canned auth;
// Connect returns a SharedConn lease).
//
// Usage:
//
//\twatch_driver --addr 127.0.0.1:PORT [--timeout SECONDS]
//\t    [--n N] [--all] [--thread ID]
//
// Defaults: --timeout 60, --n 50. Rows stream to stdout
// as they arrive (one compact JSON row per record);
// errors classify per commands.go classifyError.
//
// All credentials here are fake (hatch_sess=FAKE, AT-FAKE,
// HT-FAKE); nothing real is ever read.
package main

import (
\t"context"
\t"encoding/json"
\t"errors"
\t"flag"
\t"fmt"
\t"io"
\t"log/slog"
\t"net"
\t"net/http"
\t"os"
\t"strconv"
\t"strings"
\t"time"
\t"unicode/utf8"

\t"github.com/sagernet/sing-box/option"
\t"github.com/thoitiettxl-cyber/castctl/internal/conn"
\t"github.com/thoitiettxl-cyber/castctl/internal/gateway"
\t"github.com/thoitiettxl-cyber/castctl/internal/gateway/gatewaytest"
\t"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

"""

body = """
// classifyWatchErr mirrors commands.go classifyError for
// the error types a subscription can produce (auth 2 with
// the typed JSON line, gateway 3, timeout 4, cancel 130,
// validation 2, everything else 1; all through
// logging.SummarizeErr).
func classifyWatchErr(err error) (int, string) {
\tvar auth *conn.AuthError
\tif errors.As(err, &auth) {
\t\tb, _ := json.Marshal(map[string]string{"type": "auth_failed", "error": logging.SummarizeErr(err)})
\t\treturn 2, string(b)
\t}
\tvar gw *conn.GatewayError
\tif errors.As(err, &gw) {
\t\treturn 3, "castctl: " + logging.SummarizeErr(err)
\t}
\tvar timeout *conn.TimeoutError
\tif errors.As(err, &timeout) {
\t\treturn 4, "castctl: " + logging.SummarizeErr(err)
\t}
\tif errors.Is(err, context.DeadlineExceeded) {
\t\treturn 4, "castctl: timeout: " + logging.SummarizeErr(err)
\t}
\tif errors.Is(err, context.Canceled) {
\t\treturn 130, ""
\t}
\tvar verr *gateway.ValidationError
\tif errors.As(err, &verr) {
\t\treturn 2, "castctl: " + logging.SummarizeErr(err)
\t}
\treturn 1, "castctl: " + logging.SummarizeErr(err)
}

func run() int {
\taddr := flag.String("addr", "", "serve-wait server address (required)")
\ttimeout := flag.Int64("timeout", 60, "idle and overall timeout in seconds")
\tn := flag.Int64("n", 50, "maximum records")
\tall := flag.Bool("all", false, "include agent.status events")
\tthread := flag.String("thread", "", "side chat session id")
\tflag.Parse()
\tif *addr == "" {
\t\tfmt.Fprintln(os.Stderr, "watch_driver: --addr is required")
\t\treturn 2
\t}
\tif len(flag.Args()) != 0 {
\t\tfmt.Fprintln(os.Stderr, "watch_driver: watch takes no positional arguments")
\t\treturn 2
\t}

""" + connect_block + """

\ttimeoutDur := time.Duration(*timeout) * time.Second
\tbody := map[string]any{"capabilities": []any{"chat_cancel", "delta_stream"}}
\tif *thread != "" {
\t\tbody["session_id"] = *thread
\t}
\t_, err = gw.SubscribeRaw(ctx, "chat.subscribe", conn.SubscribeOptions{
\t\tBody:           body,
\t\tMaxRecords:     int(*n),
\t\tIdleTimeout:    timeoutDur,
\t\tOverallTimeout: timeoutDur,
\t\tOnRecord: func(line []byte) bool {
\t\t\tprintWatchRow(os.Stdout, line, *all)
\t\t\treturn false // false = keep going (true stops)
\t\t},
\t})
\tif err != nil {
\t\tcode, text := classifyWatchErr(err)
\t\tif text != "" {
\t\t\tfmt.Fprintln(os.Stderr, text)
\t\t}
\t\treturn code
\t}
\treturn 0
}

func main() {
\tos.Exit(run())
}

"""

out = header + dialer_block + "\n" + body + helpers_text + "\n"
open(DST, "w").write(out)
print("wrote %s (%d bytes)" % (DST, len(out)))
