// Copyright (c) 2026 muse-cli contributors
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
//	watch_driver --addr 127.0.0.1:PORT [--timeout SECONDS]
//	    [--n N] [--all] [--thread ID]
//
// Defaults: --timeout 60, --n 50. Rows stream to stdout
// as they arrive (one compact JSON row per record);
// errors classify per commands.go classifyError.
//
// All credentials here are fake (hatch_sess=FAKE, AT-FAKE,
// HT-FAKE); nothing real is ever read.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sagernet/sing-box/option"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway/gatewaytest"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

const fakeCookie = "hatch_sess=FAKE; datr=FAKE"

// plainDialer is the minimal gateway.OutboundDialer for the
// fake server: plain TCP to the host:port the WS URL names
// (the fake server is loopback, no TLS), and the canned auth
// chain for the HTTPS steps. Copied from
// rust/parity/gateway_server/main.go (plainDialer); that file
// is the source of truth — keep the two in sync.
type plainDialer struct {
	auth http.Handler
}

func (d *plainDialer) WebSocketDial(ctx context.Context, network, host string, port uint16, secure bool, _ option.OutboundTLSOptions) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
}

func (d *plainDialer) HTTPClient() *http.Client {
	return &http.Client{Transport: gatewaytest.HandlerRoundTripper(d.auth)}
}

// classifyWatchErr mirrors commands.go classifyError for
// the error types a subscription can produce (auth 2 with
// the typed JSON line, gateway 3, timeout 4, cancel 130,
// validation 2, everything else 1; all through
// logging.SummarizeErr).
func classifyWatchErr(err error) (int, string) {
	var auth *conn.AuthError
	if errors.As(err, &auth) {
		b, _ := json.Marshal(map[string]string{"type": "auth_failed", "error": logging.SummarizeErr(err)})
		return 2, string(b)
	}
	var gw *conn.GatewayError
	if errors.As(err, &gw) {
		return 3, "castctl: " + logging.SummarizeErr(err)
	}
	var timeout *conn.TimeoutError
	if errors.As(err, &timeout) {
		return 4, "castctl: " + logging.SummarizeErr(err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return 4, "castctl: timeout: " + logging.SummarizeErr(err)
	}
	if errors.Is(err, context.Canceled) {
		return 130, ""
	}
	var verr *gateway.ValidationError
	if errors.As(err, &verr) {
		return 2, "castctl: " + logging.SummarizeErr(err)
	}
	return 1, "castctl: " + logging.SummarizeErr(err)
}

func run() int {
	addr := flag.String("addr", "", "serve-wait server address (required)")
	timeout := flag.Int64("timeout", 60, "idle and overall timeout in seconds")
	n := flag.Int64("n", 50, "maximum records")
	all := flag.Bool("all", false, "include agent.status events")
	thread := flag.String("thread", "", "side chat session id")
	flag.Parse()
	if *addr == "" {
		fmt.Fprintln(os.Stderr, "watch_driver: --addr is required")
		return 2
	}
	if len(flag.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "watch_driver: watch takes no positional arguments")
		return 2
	}

	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT-FAKE", HatchToken: "HT-FAKE"}
	dialer := &plainDialer{auth: auth}
	cookiesTmp, err := os.CreateTemp("", "watch-driver-cookies-*.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, "watch_driver:", err)
		return 1
	}
	cookiesFile := cookiesTmp.Name()
	if _, err := cookiesTmp.Write([]byte(fakeCookie)); err != nil {
		cookiesTmp.Close()
		os.Remove(cookiesFile)
		fmt.Fprintln(os.Stderr, "watch_driver:", err)
		return 1
	}
	if err := cookiesTmp.Close(); err != nil {
		os.Remove(cookiesFile)
		fmt.Fprintln(os.Stderr, "watch_driver:", err)
		return 1
	}
	defer os.Remove(cookiesFile)

	connect := gateway.NewConnector(
		dialer,
		gateway.WithWebSocketSecure(false),
		gateway.WithWSURL(func(vmID, token string) string {
			return fmt.Sprintf("ws://%s/v1/noise?vm_id=%s&auth_token=%s", *addr, vmID, token)
		}),
	)
	muse := conn.New(connect,
		conn.WithConfig(conn.Config{CookiesFile: cookiesFile}),
		conn.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	ctx := context.Background()
	gw, err := muse.Connect(ctx, &conn.Config{CookiesFile: cookiesFile})
	if err != nil {
		fmt.Fprintln(os.Stderr, "watch_driver: connect:", err)
		return 1
	}
	defer gw.Close()

	timeoutDur := time.Duration(*timeout) * time.Second
	body := map[string]any{"capabilities": []any{"chat_cancel", "delta_stream"}}
	if *thread != "" {
		body["session_id"] = *thread
	}
	_, err = gw.SubscribeRaw(ctx, "chat.subscribe", conn.SubscribeOptions{
		Body:           body,
		MaxRecords:     int(*n),
		IdleTimeout:    timeoutDur,
		OverallTimeout: timeoutDur,
		OnRecord: func(line []byte) bool {
			printWatchRow(os.Stdout, line, *all)
			return false // false = keep going (true stops)
		},
	})
	if err != nil {
		code, text := classifyWatchErr(err)
		if text != "" {
			fmt.Fprintln(os.Stderr, text)
		}
		return code
	}
	return 0
}

func main() {
	os.Exit(run())
}

func printWatchRow(w io.Writer, line []byte, showAll bool) {
	ev, err := decodeJSONNumber(line)
	if err != nil {
		return
	}
	m, ok := ev.(map[string]any)
	if !ok {
		return
	}
	etVal := m["event"]
	if etVal == nil {
		etVal = m["type"]
	}
	if etStr, ok := etVal.(string); ok && etStr == "agent.status" && !showAll {
		return
	}
	p, _ := m["payload"].(map[string]any)
	// Ordered row: event, seq, then the text keys in Python order.
	var b strings.Builder
	b.WriteString("{")
	etJSON, _ := marshalJSONLine(etVal)
	b.WriteString("\"event\":")
	b.Write(etJSON)
	seqJSON, _ := marshalJSONLine(m["seq"])
	b.WriteString(",\"seq\":")
	b.Write(seqJSON)
	for _, k := range []string{"display_text", "content", "text", "activity_text", "status"} {
		if p == nil {
			break
		}
		v, ok := p[k]
		if !ok || !truthyJSON(v) {
			continue
		}
		b.WriteString(",")
		writeWatchField(&b, k, truncRunes(pythonStr(v), 300))
	}
	b.WriteString("}\n")
	_, _ = io.WriteString(w, b.String())
}

func writeWatchField(b *strings.Builder, key string, val string) {
	kb, _ := json.Marshal(key)
	vb, _ := json.Marshal(val)
	b.Write(kb)
	b.WriteString(":")
	b.Write(vb)
}

func truthyJSON(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case json.Number:
		return t.String() != "0"
	case float64:
		return t != 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return true
	}
}

func pythonStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case nil:
		return "None"
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		b, err := marshalJSONLine(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

func marshalJSONLine(v any) ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(buf.String(), "\n")), nil
}

func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

func decodeJSONNumber(data []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
