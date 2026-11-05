// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Command gateway_server is the M4a cross-language parity
// harness: one binary, two modes, no production code touched
// (this file is the ONLY new Go file in the PR; it builds on
// the existing internal/gateway/gatewaytest.Server and the Go
// gateway Connector — no Go file is modified).
//
//	serve  — start a fake gateway server (gatewaytest.Server)
//	         with canned JSON per path, print READY addr=<addr>
//	         and serve until SIGINT/SIGTERM.
//	client — connect the GO gateway client to a running server
//	         (serve mode, or any gatewaytest server) and call
//	         the methods given on the command line, printing one
//	         line per method: "<method>\t<compact JSON result>".
//
// The Rust parity client (castctl-gateway example
// parity_client) prints the same lines against the same
// server; the parity gate diffs the two outputs. All
// credentials here are fake (hatch_sess=FAKE, AT-FAKE,
// HT-FAKE); nothing real is ever read.
//
// Usage:
//
//	gateway_server serve
//	gateway_server client <addr> <method> [method ...]
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway/gatewaytest"
	pb "github.com/thoitiettxl-cyber/castctl/internal/proto"
)

const fakeCookie = "hatch_sess=FAKE; datr=FAKE"

// cannedResult is the "result" field the fake server returns
// for each route path (the envelope is always
// {"ok":true,"result":<here>}). The Rust fake server in
// castctl-gateway/tests/common returns the same bodies.
// Paths are the REAL routes from internal/proto/routes.json:
// connection.ping -> POST /api/ping, sessions.list -> GET
// /api/session/list, chat.history -> GET /chat/history,
// feed.list -> GET /api/feed, goals.list -> GET /goals.
func cannedResult(path string) string {
	switch path {
	case "/api/ping":
		return `{"pong":true}`
	case "/api/session/list":
		return `{"sessions":[{"id":"s1","title":"t1"}]}`
	case "/chat/history":
		return `{"messages":[{"role":"user","text":"hi"}]}`
	case "/api/feed":
		return `{"items":[{"id":"f1"}]}`
	case "/goals":
		return `{"goals":[{"id":"g1","title":"goal"}]}`
	default:
		return `{}`
	}
}

func handler() gatewaytest.Handler {
	return gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		body := `{"ok":true,"result":` + cannedResult(req.Path) + `}`
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte(body), true),
		}}
	})
}

// plainDialer is the minimal gateway.OutboundDialer for the
// client mode: plain TCP to the host:port the WS URL names
// (the fake server is loopback, no TLS), and the canned auth
// chain for the HTTPS steps.
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

func runServe() error {
	server, err := gatewaytest.NewServer(handler())
	if err != nil {
		return err
	}
	defer server.Close()
	fmt.Printf("READY addr=%s\n", server.Addr())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	return nil
}

func runClient(addr string, methods []string) error {
	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT-FAKE", HatchToken: "HT-FAKE"}
	dialer := &plainDialer{auth: auth}
	// Unique temp file (0600), not a fixed name: two parity
	// runs must never share — or clobber — each other's
	// cookie file.
	cookiesTmp, err := os.CreateTemp("", "parity-cookies-*.txt")
	if err != nil {
		return err
	}
	cookiesFile := cookiesTmp.Name()
	if _, err := cookiesTmp.Write([]byte(fakeCookie)); err != nil {
		cookiesTmp.Close()
		os.Remove(cookiesFile)
		return err
	}
	if err := cookiesTmp.Close(); err != nil {
		os.Remove(cookiesFile)
		return err
	}
	defer os.Remove(cookiesFile)
	connect := gateway.NewConnector(
		dialer,
		gateway.WithWebSocketSecure(false),
		gateway.WithWSURL(func(vmID, token string) string {
			return fmt.Sprintf("ws://%s/v1/noise?vm_id=%s&auth_token=%s", addr, vmID, token)
		}),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gw, err := connect(ctx, conn.Config{CookiesFile: cookiesFile, VMID: "vm-test"})
	if err != nil {
		return fmt.Errorf("go connector: %w", err)
	}
	defer gw.Close()
	for _, method := range methods {
		out, err := gw.CallJSON(ctx, method, conn.RequestOptions{})
		if err != nil {
			return fmt.Errorf("go CallJSON %s: %w", method, err)
		}
		raw, err := json.Marshal(out)
		if err != nil {
			return fmt.Errorf("go marshal %s: %w", method, err)
		}
		fmt.Printf("%s\t%s\n", method, raw)
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gateway_server serve | client <addr> <method> [method ...]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe()
	case "client":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: gateway_server client <addr> <method> [method ...]")
			os.Exit(2)
		}
		err = runClient(os.Args[2], os.Args[3:])
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gateway_server:", err)
		os.Exit(1)
	}
}
