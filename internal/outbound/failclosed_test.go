// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// Fail-closed regression tests (Boss decision (a), CLIProxyAPI notes
// §7 item 1). Every path below must ERROR, never dial direct, and
// never fall back to proxy.Direct or the environment proxy. Each test
// asserts BOTH the error AND zero direct dials, via two counters:
//
//   - a loopback "direct target" canary listener: any accepted
//     connection means something dialled direct, and the test fails;
//   - a counting HTTP proxy named by the proxy environment variables:
//     any CONNECT means the env proxy was consulted, and the test fails.
//
// All servers bind 127.0.0.1 only; no test dials a real address. The
// ambient process environment on this VM sets HTTP(S)_PROXY/ALL_PROXY
// to a real egress proxy, so every test overrides all six proxy
// variables (plus NO_PROXY) with t.Setenv before doing anything, and
// asserts the fake proxy saw zero CONNECTs — hermetic against both
// the ambient env and any future env-proxy shim.
//
// The pre-existing dead-proxy test (TestDialerDeadProxyFailsClosed,
// socks to a refusing port) and the recording-outbound tests are NOT
// duplicated here; these tests add the bad-URL, build-error, and
// env-proxy paths that PR1 did not pin.

// failClosedDNSRouter is a DNS router whose lookups always fail. It
// models "DNS is configured, but this hostname does not resolve":
// sing-box's resolve dialer needs a non-nil DNSRouter to resolve an
// outbound's domain-like server address, and with no router at all
// that dial panics inside sing-box (nil router dereference, measured
// 2026-10-29 — see the report; wiring a router before creating
// domain-server outbounds is the gateway writer's path, not a test
// fixture). Registering this router before CreateOutbound keeps the
// dial on the error path, where fail-closed can be asserted.
type failClosedDNSRouter struct{}

var _ adapter.DNSRouter = failClosedDNSRouter{}

func (failClosedDNSRouter) Start(adapter.StartStage, *adapter.Scope) error { return nil }

func (failClosedDNSRouter) Exchange(context.Context, *dns.Msg, adapter.DNSQueryOptions) (*dns.Msg, error) {
	return nil, errors.New("fail-closed test dns: exchange refused")
}

func (failClosedDNSRouter) ExchangeAsync(context.Context, *dns.Msg, adapter.DNSQueryOptions, func(*dns.Msg, error)) {
}

func (failClosedDNSRouter) Lookup(context.Context, string, adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return nil, errors.New("fail-closed test dns: lookup refused")
}

func (failClosedDNSRouter) ClearCache()                                    {}
func (failClosedDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }
func (failClosedDNSRouter) ResetNetwork()                                  {}

// countingCanary is a loopback TCP listener that counts every accepted
// connection and replies "ok" to one read, like startFakeTCP. Any
// accept in a fail-closed test is a direct dial and fails the test.
type countingCanary struct {
	addr    string
	port    int
	accepts atomic.Int64
}

func startCountingCanary(t *testing.T) *countingCanary {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	c := &countingCanary{addr: ln.Addr().String(), port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.accepts.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("ok"))
			}(conn)
		}
	}()
	return c
}

func (c *countingCanary) dials() int64 { return c.accepts.Load() }

// countingHTTPProxy is a CONNECT proxy on 127.0.0.1 that counts every
// CONNECT request and tunnels only 127.0.0.1/localhost targets. Any
// CONNECT in a fail-closed test means the env proxy was consulted.
type countingHTTPProxy struct {
	addr     string
	connects atomic.Int64
}

func startCountingHTTPProxy(t *testing.T) *countingHTTPProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &countingHTTPProxy{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveCountingProxy(conn, &p.connects)
		}
	}()
	return p
}

func serveCountingProxy(conn net.Conn, connects *atomic.Int64) {
	defer conn.Close()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}
	connects.Add(1)
	host, _, err := net.SplitHostPort(req.Host)
	if err != nil || (host != "127.0.0.1" && host != "localhost") {
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return
	}
	up, err := net.DialTimeout("tcp", req.Host, 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer up.Close()
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, up); done <- struct{}{} }()
	<-done
}

func (p *countingHTTPProxy) connectCount() int64 { return p.connects.Load() }

// countingHTTPServer is a loopback HTTP server that counts requests
// and answers "pong" on /ping. A request here proves a dial reached
// the target; combined with a zero CONNECT count it proves the dial
// went direct through the configured outbound, not via the env proxy.
type countingHTTPServer struct {
	addr     string
	requests atomic.Int64
}

func startCountingHTTPServer(t *testing.T) *countingHTTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &countingHTTPServer{addr: ln.Addr().String()}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		_, _ = w.Write([]byte("pong"))
	})
	srv := &http.Server{Handler: mux}
	t.Cleanup(func() { srv.Close() })
	go srv.Serve(ln)
	return s
}

func (s *countingHTTPServer) requestCount() int64 { return s.requests.Load() }

// setEnvProxy points every proxy environment variable (both cases,
// plus the NO_PROXY bypass list emptied so loopback targets would
// NOT be bypassed if code consulted the env) at the counting proxy.
// t.Setenv restores the ambient values when the test ends. Tests that
// set env must not call t.Parallel.
func setEnvProxy(t *testing.T, proxyAddr string) {
	t.Helper()
	url := "http://" + proxyAddr
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, url)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
}

// assertNoFallback fails the test unless both counters are zero: no
// direct dial to the canary and no CONNECT to the env proxy.
func assertNoFallback(t *testing.T, canary *countingCanary, proxy *countingHTTPProxy) {
	t.Helper()
	if got := canary.dials(); got != 0 {
		t.Errorf("canary accepted %d connection(s): a direct dial happened, want 0", got)
	}
	if got := proxy.connectCount(); got != 0 {
		t.Errorf("env proxy received %d CONNECT(s): the env proxy was consulted, want 0", got)
	}
}

// parseOutboundRaw parses one option.Outbound JSON object through the
// manager's registry context, returning the error instead of failing
// the test (unlike parseOutbound in manager_test.go), so parse-error
// paths can be asserted.
func parseOutboundRaw(m *Manager, raw string) (option.Outbound, error) {
	var out option.Outbound
	if err := json.UnmarshalContext(m.Context(), []byte(raw), &out); err != nil {
		return out, err
	}
	return out, nil
}

func TestFailClosedMalformedHTTPProxyServer(t *testing.T) {
	// sing-box's http outbound has no URL field: the proxy address is
	// server/server_port. These malformed server values are all
	// accepted at parse/build time (measured); the error surfaces at
	// dial time, through the configured DNS path refusing the
	// domain-like server address. The dial must error and must never
	// reach the canary directly or consult the env proxy.
	cases := []struct {
		name          string
		server        string
		serverPort    int
		wantErrSubstr string
	}{
		{name: "scheme in server", server: "http://127.0.0.1", serverPort: 8080, wantErrSubstr: "lookup refused"},
		{name: "scheme only", server: "://bad", serverPort: 8080, wantErrSubstr: "lookup refused"},
		{name: "empty server", server: "", serverPort: 8080, wantErrSubstr: "invalid address"},
		{name: "spaces in server", server: "bad host with spaces", serverPort: 8080, wantErrSubstr: "lookup refused"},
		{name: "invalid ipv4", server: "256.256.256.256", serverPort: 8080, wantErrSubstr: "lookup refused"},
		{name: "unresolvable domain", server: "nonexistent.invalid", serverPort: 8080, wantErrSubstr: "lookup refused"},
		{name: "port zero", server: "127.0.0.1", serverPort: 0, wantErrSubstr: "connection refused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			canary := startCountingCanary(t)
			proxy := startCountingHTTPProxy(t)
			setEnvProxy(t, proxy.addr)

			m := newTestManager(t)
			m.RegisterDNSRouter(failClosedDNSRouter{})
			raw := fmt.Sprintf(`{"type":"http","tag":"proxy","server":%q,"server_port":%d}`, tc.server, tc.serverPort)
			out, err := parseOutboundRaw(m, raw)
			if err != nil {
				t.Fatalf("parse %s: %v", raw, err)
			}
			if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
				t.Fatalf("CreateOutbound %s: %v", raw, err)
			}
			if err := m.Start(); err != nil {
				t.Fatalf("Start %s: %v", raw, err)
			}
			d, err := m.Dialer(out.Tag)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(canary.port))
			if err == nil {
				conn.Close()
				t.Fatalf("dial through malformed http proxy (%s) = nil, want error containing %q", raw, tc.wantErrSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Errorf("dial error = %v, want it to contain %q", err, tc.wantErrSubstr)
			}
			assertNoFallback(t, canary, proxy)
		})
	}
}

func TestFailClosedMalformedHTTPProxyPort(t *testing.T) {
	// server_port is uint16: 70000 cannot even parse. No outbound is
	// ever created, so no dialer exists and nothing can dial.
	canary := startCountingCanary(t)
	proxy := startCountingHTTPProxy(t)
	setEnvProxy(t, proxy.addr)

	m := newTestManager(t)
	raw := `{"type":"http","tag":"badport","server":"127.0.0.1","server_port":70000}`
	if _, err := parseOutboundRaw(m, raw); err == nil {
		t.Fatalf("parse %s = nil, want server_port error", raw)
	} else if !strings.Contains(err.Error(), "server_port") {
		t.Errorf("parse error = %v, want it to name server_port", err)
	}
	if _, err := m.Dialer("badport"); err == nil {
		t.Fatal("Dialer(badport) = nil after a parse failure, want error (no outbound must exist)")
	}
	assertNoFallback(t, canary, proxy)
}

func TestFailClosedUnbuildableOutbound(t *testing.T) {
	// Each case must fail at build time (parse or CreateOutbound),
	// before any dial: no dialer exists for the tag afterwards.
	cases := []struct {
		name          string
		raw           string
		stage         string // "parse" or "create"
		wantErrSubstr string
	}{
		{name: "unknown type", raw: `{"type":"bogus-type","tag":"bad"}`, stage: "parse", wantErrSubstr: "unknown outbound type"},
		{name: "socks bad version", raw: `{"type":"socks","tag":"bad","server":"127.0.0.1","server_port":1,"version":"9"}`, stage: "create", wantErrSubstr: "unknown socks version"},
		{name: "shadowsocks bad method", raw: `{"type":"shadowsocks","tag":"bad","server":"127.0.0.1","server_port":1,"method":"bogus-method","password":"FAKE"}`, stage: "create", wantErrSubstr: "unknown method"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			canary := startCountingCanary(t)
			proxy := startCountingHTTPProxy(t)
			setEnvProxy(t, proxy.addr)

			m := newTestManager(t)
			out, perr := parseOutboundRaw(m, tc.raw)
			switch tc.stage {
			case "parse":
				if perr == nil {
					t.Fatalf("parse %s = nil, want error containing %q", tc.raw, tc.wantErrSubstr)
				}
				if !strings.Contains(perr.Error(), tc.wantErrSubstr) {
					t.Errorf("parse error = %v, want it to contain %q", perr, tc.wantErrSubstr)
				}
			case "create":
				if perr != nil {
					t.Fatalf("parse %s: %v (want parse to succeed, error at create)", tc.raw, perr)
				}
				if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err == nil {
					t.Fatalf("CreateOutbound %s = nil, want error containing %q", tc.raw, tc.wantErrSubstr)
				} else if !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Errorf("create error = %v, want it to contain %q", err, tc.wantErrSubstr)
				}
			}
			if _, err := m.Dialer("bad"); err == nil {
				t.Fatal("Dialer(bad) = nil after a build failure, want error (no outbound must exist to dial through)")
			}
			assertNoFallback(t, canary, proxy)
		})
	}
}

func TestFailClosedEnvProxyNeverConsulted(t *testing.T) {
	t.Run("dead http outbound plus env proxy", func(t *testing.T) {
		// The env proxy would tunnel to the canary successfully if
		// consulted; the configured http outbound points at a
		// closed port and must fail instead. The GET must error,
		// the env proxy must see zero CONNECTs, and the canary
		// server must see zero requests.
		proxy := startCountingHTTPProxy(t)
		setEnvProxy(t, proxy.addr)
		target := startCountingHTTPServer(t)

		m := newTestManager(t)
		raw := fmt.Sprintf(`{"type":"http","tag":"proxy","server":"127.0.0.1","server_port":%d}`, closedPort(t))
		out, err := parseOutboundRaw(m, raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
			t.Fatal(err)
		}
		if err := m.Start(); err != nil {
			t.Fatal(err)
		}
		d, err := m.Dialer(out.Tag)
		if err != nil {
			t.Fatal(err)
		}
		client := d.HTTPClient()
		client.Timeout = 5 * time.Second
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("HTTPClient transport = %T, want *http.Transport", client.Transport)
		}
		if tr.Proxy != nil {
			t.Error("HTTP transport Proxy is set; it must be nil so no env proxy is ever consulted")
		}
		resp, err := client.Get("http://" + target.addr + "/ping")
		if err == nil {
			resp.Body.Close()
			t.Fatal("GET through dead http outbound = nil, want error (no env-proxy fallback)")
		}
		if got := proxy.connectCount(); got != 0 {
			t.Errorf("env proxy received %d CONNECT(s), want 0", got)
		}
		if got := target.requestCount(); got != 0 {
			t.Errorf("canary HTTP server received %d request(s), want 0: the request must never arrive", got)
		}
	})

	t.Run("valid direct outbound plus env proxy stays direct", func(t *testing.T) {
		// Env set (and NO_PROXY emptied, so a ProxyFromEnvironment
		// lookup would use the proxy even for loopback): the GET
		// must still succeed directly, with zero CONNECTs.
		// TestDialerHTTPClient already pins Proxy == nil without
		// env set; this pins it WITH env set.
		proxy := startCountingHTTPProxy(t)
		setEnvProxy(t, proxy.addr)
		target := startCountingHTTPServer(t)

		m := newTestManager(t)
		out, err := parseOutboundRaw(m, `{"type":"direct","tag":"direct"}`)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
			t.Fatal(err)
		}
		if err := m.Start(); err != nil {
			t.Fatal(err)
		}
		d, err := m.Dialer("direct")
		if err != nil {
			t.Fatal(err)
		}
		client := d.HTTPClient()
		client.Timeout = 5 * time.Second
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("HTTPClient transport = %T, want *http.Transport", client.Transport)
		}
		if tr.Proxy != nil {
			t.Error("HTTP transport Proxy is set with env proxy present; it must stay nil")
		}
		resp, err := client.Get("http://" + target.addr + "/ping")
		if err != nil {
			t.Fatalf("GET through direct outbound with env proxy set: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "pong" {
			t.Errorf("HTTP body = %q, want %q", string(body), "pong")
		}
		if got := proxy.connectCount(); got != 0 {
			t.Errorf("env proxy received %d CONNECT(s) for a direct dial, want 0", got)
		}
		if got := target.requestCount(); got != 1 {
			t.Errorf("canary HTTP server received %d request(s), want exactly 1", got)
		}
	})

	t.Run("unbuildable outbound plus env proxy", func(t *testing.T) {
		// Build failure + env proxy: error, no dialer, no dial of
		// any kind — neither direct nor via the env proxy.
		canary := startCountingCanary(t)
		proxy := startCountingHTTPProxy(t)
		setEnvProxy(t, proxy.addr)

		m := newTestManager(t)
		if _, err := parseOutboundRaw(m, `{"type":"bogus-type","tag":"bad"}`); err == nil {
			t.Fatal("parse unknown outbound type = nil, want error")
		}
		if _, err := m.Dialer("bad"); err == nil {
			t.Fatal("Dialer(bad) = nil after a build failure, want error")
		}
		assertNoFallback(t, canary, proxy)
	})
}
