// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// F3 nil-router guard tests. sing-box's resolve dialer captures the
// DNS router from the registry context at outbound construction
// time (common/dialer/resolve.go: NewResolveDialer) and dereferences
// it on the first domain dial (resolve.go:103). A Manager without a
// registered DNS router must therefore refuse a domain-server
// outbound at CreateOutbound time — cleanly, with an error, never a
// panic — and registering a router AFTER CreateOutbound must not
// resurrect the refused outbound. IP-server outbounds and IP
// destinations are unaffected: they never touch the resolve dialer.
//
// Detour exception (probed 2026-10-29, loopback fakes only): a
// domain-server outbound whose detour chain provably forwards the
// domain address verbatim to a remote proxy needs no local router
// (sing-box skips the resolve dialer when a detour is set and no
// domain_resolver is present, common/dialer/dialer.go:65). The
// exception is an allow-list — http/socks5/selector chains
// terminating in an IP-server forwarder, created detour-first —
// and every other detour shape stays refused. The
// TestSingBoxNilRouterPanic* tests below bypass CreateOutbound
// deliberately, through the raw sing-box manager, to pin the
// hazard the guard prevents; all other tests use the public API.

// TestCreateOutboundDomainServerWithoutDNSRouter is Case A: a
// domain-server http outbound with no DNS router registered must
// error at CreateOutbound (no panic, no outbound created).
func TestCreateOutboundDomainServerWithoutDNSRouter(t *testing.T) {
	m := newTestManager(t)
	out := parseOutbound(t, m, `{"type":"http","tag":"proxy","server":"proxy.invalid","server_port":8080}`)
	err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options)
	if err == nil {
		t.Fatal("CreateOutbound(domain server, no DNS router) = nil, want error")
	}
	if !strings.Contains(err.Error(), "DNS router") {
		t.Errorf("CreateOutbound error = %v, want it to name the missing DNS router", err)
	}
	if _, ok := m.Outbound("proxy"); ok {
		t.Error("domain-server outbound exists after refused CreateOutbound")
	}
	if _, err := m.Dialer("proxy"); err == nil {
		t.Error("Dialer(proxy) = nil after refused CreateOutbound, want error")
	}
}

// TestCreateOutboundDomainServerWithResolverWithoutDNSRouter is
// the R3 negative control for the local domain_resolver default:
// an explicit domain_resolver does NOT bypass the F3 guard —
// with no DNS router registered, creation is still refused.
// (The default applied by createOutbounds is only ever used
// after RegisterDNS, so this refusal shape is unchanged.)
func TestCreateOutboundDomainServerWithResolverWithoutDNSRouter(t *testing.T) {
	m := newTestManager(t)
	out := parseOutbound(t, m, `{"type":"http","tag":"proxy","server":"proxy.invalid","server_port":8080,"domain_resolver":"dns1"}`)
	err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options)
	if err == nil {
		t.Fatal("CreateOutbound(domain server + domain_resolver, no DNS router) = nil, want error")
	}
	if !strings.Contains(err.Error(), "DNS router") {
		t.Errorf("CreateOutbound error = %v, want it to name the missing DNS router", err)
	}
	if _, ok := m.Outbound("proxy"); ok {
		t.Error("domain-server outbound exists after refused CreateOutbound")
	}
}

// TestCreateOutboundDomainServerRouterRegisteredAfter is Case C:
// registering a DNS router AFTER the (refused) CreateOutbound does
// not repair anything — the outbound still does not exist and
// dialling still errors cleanly — but creating it again AFTER
// registration succeeds (the PR3 wiring rule: RegisterDNS BEFORE
// CreateOutbound).
func TestCreateOutboundDomainServerRouterRegisteredAfter(t *testing.T) {
	m := newTestManager(t)
	raw := `{"type":"http","tag":"proxy","server":"proxy.invalid","server_port":8080}`
	out := parseOutbound(t, m, raw)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err == nil {
		t.Fatal("CreateOutbound before RegisterDNSRouter = nil, want error")
	}
	m.RegisterDNSRouter(failClosedDNSRouter{})
	if _, ok := m.Outbound("proxy"); ok {
		t.Error("outbound exists after late router registration: the refused creation must not be repaired retroactively")
	}
	if _, err := m.Dialer("proxy"); err == nil {
		t.Error("Dialer(proxy) = nil after late router registration, want error (no outbound was created)")
	}
	out2 := parseOutbound(t, m, raw)
	if err := m.CreateOutbound(context.Background(), out2.Tag, out2.Type, out2.Options); err != nil {
		t.Fatalf("CreateOutbound after RegisterDNSRouter = %v, want nil", err)
	}
}

// TestCreateOutboundDomainServerWithDNSRouterFirst is the positive
// control for Cases A/C: a router registered BEFORE CreateOutbound
// lets a domain-server outbound be created (dialling it then fails
// through the router, with the router's error — no panic).
func TestCreateOutboundDomainServerWithDNSRouterFirst(t *testing.T) {
	m := newTestManager(t)
	m.RegisterDNSRouter(failClosedDNSRouter{})
	out := parseOutbound(t, m, `{"type":"http","tag":"proxy","server":"proxy.invalid","server_port":8080}`)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("CreateOutbound(domain server, router first) = %v, want nil", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	d, err := m.Dialer("proxy")
	if err != nil {
		t.Fatalf("Dialer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// The dial must return the router's refusal as an error, never panic.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("dial through domain-server outbound panicked: %v", r)
			}
		}()
		conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", 1)
		if err == nil {
			conn.Close()
			t.Fatal("dial = nil, want the DNS router's refusal")
		}
		if !strings.Contains(err.Error(), "lookup refused") {
			t.Errorf("dial error = %v, want the DNS router's refusal", err)
		}
	}()
}

// TestCreateOutboundIPServerWithoutDNSRouter is Case D: an
// IP-literal server needs no resolution, so no DNS router is
// required and creation succeeds.
func TestCreateOutboundIPServerWithoutDNSRouter(t *testing.T) {
	m := newTestManager(t)
	out := parseOutbound(t, m, `{"type":"http","tag":"proxy","server":"127.0.0.1","server_port":1}`)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("CreateOutbound(IP server, no DNS router) = %v, want nil", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := m.Dialer("proxy"); err != nil {
		t.Fatalf("Dialer: %v", err)
	}
}

// TestDirectDialIPTargetWithoutDNSRouter is Case E: an IP
// destination through a direct outbound works with no DNS router
// at all.
func TestDirectDialIPTargetWithoutDNSRouter(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	m := newTestManager(t)
	out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("CreateOutbound direct = %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	d, err := m.Dialer("direct")
	if err != nil {
		t.Fatalf("Dialer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(tcpPort))
	if err != nil {
		t.Fatalf("direct IP dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf[:2]) != "ok" {
		t.Errorf("echo = %q, want ok", buf)
	}
}

// createRawOutbound creates one outbound through the raw sing-box
// outbound manager, bypassing Manager.CreateOutbound's F3 guard.
// It exists only for the TestSingBox* hazard probes, which must
// observe what sing-box itself does with no DNS router; production
// and guard tests always go through CreateOutbound.
func createRawOutbound(t *testing.T, m *Manager, raw string) {
	t.Helper()
	var out option.Outbound
	if err := json.UnmarshalContext(m.Context(), []byte(raw), &out); err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	if err := m.outbounds.Create(m.registryContext(), m.router, m.logger, out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("raw Create %s: %v", raw, err)
	}
}

// createRawOutboundErr is createRawOutbound reporting the creation
// error instead of failing, for probes of clean construction errors.
func createRawOutboundErr(t *testing.T, m *Manager, raw string) error {
	t.Helper()
	var out option.Outbound
	if err := json.UnmarshalContext(m.Context(), []byte(raw), &out); err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return m.outbounds.Create(m.registryContext(), m.router, m.logger, out.Tag, out.Type, out.Options)
}

// dialEchoRecovered dials an IP target through the Manager's Dialer
// for tag and reports whether the dial panicked. A panic is
// recovered here (and its stack logged) so a hazard probe fails
// the test instead of crashing the suite; reply is the first two
// bytes read from the echo server ("ok" on success).
func dialEchoRecovered(t *testing.T, m *Manager, tag string, port int) (panicked any, reply string, err error) {
	t.Helper()
	d, derr := m.Dialer(tag)
	if derr != nil {
		t.Fatalf("Dialer(%s): %v", tag, derr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			panicked = r
			t.Logf("dial panicked: %v\n%s", r, debug.Stack())
		}
	}()
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(port))
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		return nil, "", err
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		return nil, "", err
	}
	return nil, string(buf[:2]), nil
}

// dialEchoOK asserts an end-to-end dial through tag reaches the
// fake echo server: no panic, no error, reply "ok".
func dialEchoOK(t *testing.T, m *Manager, tag string, port int) {
	t.Helper()
	panicked, reply, err := dialEchoRecovered(t, m, tag, port)
	if panicked != nil {
		t.Fatalf("dial through %s panicked: %v", tag, panicked)
	}
	if err != nil {
		t.Fatalf("dial through %s: %v", tag, err)
	}
	if reply != "ok" {
		t.Fatalf("dial through %s reply = %q, want ok", tag, reply)
	}
}

// startFakeHTTPProxyGateway is a CONNECT proxy like
// startFakeHTTPProxy, but it also accepts the fake-only hostname
// gateway.test, mapping it to 127.0.0.1. Loopback only; the system
// resolver is never consulted. It models the second HTTP proxy in
// a detour chain whose server address is a domain.
func startFakeHTTPProxyGateway(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil || n == 0 {
					return
				}
				var method, target string
				_, _ = fmt.Sscanf(string(buf[:n]), "%s %s", &method, &target)
				host, port, err := net.SplitHostPort(target)
				if err != nil || method != "CONNECT" || (host != "127.0.0.1" && host != "gateway.test") {
					_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
					return
				}
				up, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 5*time.Second)
				if err != nil {
					_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer up.Close()
				_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
				go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
				<-done
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestCreateOutboundDetourSocks5WithoutDNSRouter is the proven
// detour case: an http outbound with a domain server and a socks5
// (IP-server) detour, no DNS router registered. Creation must
// succeed and a dial must reach the echo server through the chain:
// the domain server address is forwarded verbatim by the detour
// proxy, never resolved locally.
func TestCreateOutboundDetourSocks5WithoutDNSRouter(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	socksPort := startFakeSOCKS5(t)
	httpPort := startFakeHTTPProxy(t)
	m := newTestManager(t)
	detour := parseOutbound(t, m, fmt.Sprintf(`{"type":"socks","tag":"socks","server":"127.0.0.1","server_port":%d,"version":"5"}`, socksPort))
	if err := m.CreateOutbound(context.Background(), detour.Tag, detour.Type, detour.Options); err != nil {
		t.Fatalf("CreateOutbound detour socks: %v", err)
	}
	out := parseOutbound(t, m, fmt.Sprintf(`{"type":"http","tag":"proxy","server":"gateway.test","server_port":%d,"detour":"socks"}`, httpPort))
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("CreateOutbound http via socks5 detour, no DNS router: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	dialEchoOK(t, m, "proxy", tcpPort)
}

// TestCreateOutboundDetourSelectorWithoutDNSRouter: a selector
// detour whose only member is a socks5 IP-server outbound also
// self-resolves; the domain-server http outbound is allowed and
// dials end-to-end.
func TestCreateOutboundDetourSelectorWithoutDNSRouter(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	socksPort := startFakeSOCKS5(t)
	httpPort := startFakeHTTPProxy(t)
	m := newTestManager(t)
	detour := parseOutbound(t, m, fmt.Sprintf(`{"type":"socks","tag":"socks","server":"127.0.0.1","server_port":%d,"version":"5"}`, socksPort))
	if err := m.CreateOutbound(context.Background(), detour.Tag, detour.Type, detour.Options); err != nil {
		t.Fatalf("CreateOutbound detour socks: %v", err)
	}
	sel := parseOutbound(t, m, `{"type":"selector","tag":"sel","outbounds":["socks"],"default":"socks"}`)
	if err := m.CreateOutbound(context.Background(), sel.Tag, sel.Type, sel.Options); err != nil {
		t.Fatalf("CreateOutbound selector: %v", err)
	}
	out := parseOutbound(t, m, fmt.Sprintf(`{"type":"http","tag":"proxy","server":"gateway.test","server_port":%d,"detour":"sel"}`, httpPort))
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("CreateOutbound http via selector detour, no DNS router: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	dialEchoOK(t, m, "proxy", tcpPort)
}

// TestCreateOutboundDetourTwoHopWithoutDNSRouter: http ->
// socks5(domain server) -> socks5(IP server). Each hop forwards
// the domain address verbatim; no link dereferences a DNS router.
func TestCreateOutboundDetourTwoHopWithoutDNSRouter(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	termPort := startFakeSOCKS5(t)
	midPort := startFakeSOCKS5(t)
	httpPort := startFakeHTTPProxy(t)
	m := newTestManager(t)
	term := parseOutbound(t, m, fmt.Sprintf(`{"type":"socks","tag":"term","server":"127.0.0.1","server_port":%d,"version":"5"}`, termPort))
	if err := m.CreateOutbound(context.Background(), term.Tag, term.Type, term.Options); err != nil {
		t.Fatalf("CreateOutbound term socks: %v", err)
	}
	mid := parseOutbound(t, m, fmt.Sprintf(`{"type":"socks","tag":"mid","server":"gateway.test","server_port":%d,"version":"5","detour":"term"}`, midPort))
	if err := m.CreateOutbound(context.Background(), mid.Tag, mid.Type, mid.Options); err != nil {
		t.Fatalf("CreateOutbound mid socks via term: %v", err)
	}
	out := parseOutbound(t, m, fmt.Sprintf(`{"type":"http","tag":"proxy","server":"gateway.test","server_port":%d,"detour":"mid"}`, httpPort))
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("CreateOutbound http via two-hop detour, no DNS router: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	dialEchoOK(t, m, "proxy", tcpPort)
}

// TestCreateOutboundDetourSocksOuterWithoutDNSRouter: a socks5
// outbound with a domain server and a socks5 (IP-server) detour
// is allowed and dials end-to-end.
func TestCreateOutboundDetourSocksOuterWithoutDNSRouter(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	detourPort := startFakeSOCKS5(t)
	outerPort := startFakeSOCKS5(t)
	m := newTestManager(t)
	detour := parseOutbound(t, m, fmt.Sprintf(`{"type":"socks","tag":"detour","server":"127.0.0.1","server_port":%d,"version":"5"}`, detourPort))
	if err := m.CreateOutbound(context.Background(), detour.Tag, detour.Type, detour.Options); err != nil {
		t.Fatalf("CreateOutbound detour socks: %v", err)
	}
	out := parseOutbound(t, m, fmt.Sprintf(`{"type":"socks","tag":"outer","server":"gateway.test","server_port":%d,"version":"5","detour":"detour"}`, outerPort))
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("CreateOutbound socks5 via socks5 detour, no DNS router: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	dialEchoOK(t, m, "outer", tcpPort)
}

// TestCreateOutboundDetourHTTPTerminalWithoutDNSRouter: an http
// outbound with a domain server and an http (IP-server) detour
// is allowed and dials end-to-end; the detour proxy forwards the
// domain server address to the second HTTP proxy.
func TestCreateOutboundDetourHTTPTerminalWithoutDNSRouter(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	termPort := startFakeHTTPProxyGateway(t)
	outerPort := startFakeHTTPProxy(t)
	m := newTestManager(t)
	term := parseOutbound(t, m, fmt.Sprintf(`{"type":"http","tag":"term","server":"127.0.0.1","server_port":%d}`, termPort))
	if err := m.CreateOutbound(context.Background(), term.Tag, term.Type, term.Options); err != nil {
		t.Fatalf("CreateOutbound term http: %v", err)
	}
	out := parseOutbound(t, m, fmt.Sprintf(`{"type":"http","tag":"proxy","server":"gateway.test","server_port":%d,"detour":"term"}`, outerPort))
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("CreateOutbound http via http detour, no DNS router: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	dialEchoOK(t, m, "proxy", tcpPort)
}

// TestCreateOutboundDetourRefusedWithoutDNSRouter pins the
// refusal side of the detour exception: every detour shape that
// was not proven to self-resolve (or that cannot be checked at
// creation time) is refused with the DNS-router error, never
// left to panic at dial time.
func TestCreateOutboundDetourRefusedWithoutDNSRouter(t *testing.T) {
	newDetourSocks := func(t *testing.T, m *Manager) {
		t.Helper()
		detour := parseOutbound(t, m, fmt.Sprintf(`{"type":"socks","tag":"socks","server":"127.0.0.1","server_port":%d,"version":"5"}`, startFakeSOCKS5(t)))
		if err := m.CreateOutbound(context.Background(), detour.Tag, detour.Type, detour.Options); err != nil {
			t.Fatalf("CreateOutbound detour socks: %v", err)
		}
	}
	newDirect := func(t *testing.T, m *Manager, raw string) {
		t.Helper()
		direct := parseOutbound(t, m, raw)
		if err := m.CreateOutbound(context.Background(), direct.Tag, direct.Type, direct.Options); err != nil {
			t.Fatalf("CreateOutbound %s: %v", raw, err)
		}
	}
	tests := []struct {
		name  string
		setup func(t *testing.T, m *Manager)
		raw   string
	}{
		{
			name:  "direct empty detour",
			setup: func(t *testing.T, m *Manager) { newDirect(t, m, `{"type":"direct","tag":"direct"}`) },
			raw:   `{"type":"http","tag":"proxy","server":"gateway.test","server_port":8080,"detour":"direct"}`,
		},
		{
			name: "direct non-empty detour",
			setup: func(t *testing.T, m *Manager) {
				newDirect(t, m, `{"type":"direct","tag":"direct","domain_strategy":"prefer_ipv4"}`)
			},
			raw: `{"type":"http","tag":"proxy","server":"gateway.test","server_port":8080,"detour":"direct"}`,
		},
		{
			name: "socks4 detour",
			setup: func(t *testing.T, m *Manager) {
				detour := parseOutbound(t, m, fmt.Sprintf(`{"type":"socks","tag":"socks4","server":"127.0.0.1","server_port":%d,"version":"4"}`, startFakeSOCKS5(t)))
				if err := m.CreateOutbound(context.Background(), detour.Tag, detour.Type, detour.Options); err != nil {
					t.Fatalf("CreateOutbound socks4: %v", err)
				}
			},
			raw: `{"type":"http","tag":"proxy","server":"gateway.test","server_port":8080,"detour":"socks4"}`,
		},
		{
			name: "socks4a detour unproven",
			setup: func(t *testing.T, m *Manager) {
				detour := parseOutbound(t, m, fmt.Sprintf(`{"type":"socks","tag":"socks4a","server":"127.0.0.1","server_port":%d,"version":"4a"}`, startFakeSOCKS5(t)))
				if err := m.CreateOutbound(context.Background(), detour.Tag, detour.Type, detour.Options); err != nil {
					t.Fatalf("CreateOutbound socks4a: %v", err)
				}
			},
			raw: `{"type":"http","tag":"proxy","server":"gateway.test","server_port":8080,"detour":"socks4a"}`,
		},
		{
			name:  "missing detour",
			setup: func(t *testing.T, m *Manager) {},
			raw:   `{"type":"http","tag":"proxy","server":"gateway.test","server_port":8080,"detour":"nope"}`,
		},
		{
			name:  "self detour",
			setup: func(t *testing.T, m *Manager) {},
			raw:   `{"type":"http","tag":"proxy","server":"gateway.test","server_port":8080,"detour":"proxy"}`,
		},
		{
			name:  "domain_resolver on detour chain",
			setup: newDetourSocks,
			raw:   `{"type":"http","tag":"proxy","server":"gateway.test","server_port":8080,"detour":"socks","domain_resolver":"dns1"}`,
		},
		{
			name: "selector with one unproven member",
			setup: func(t *testing.T, m *Manager) {
				newDetourSocks(t, m)
				newDirect(t, m, `{"type":"direct","tag":"direct","domain_strategy":"prefer_ipv4"}`)
				sel := parseOutbound(t, m, `{"type":"selector","tag":"sel","outbounds":["socks","direct"],"default":"socks"}`)
				if err := m.CreateOutbound(context.Background(), sel.Tag, sel.Type, sel.Options); err != nil {
					t.Fatalf("CreateOutbound selector: %v", err)
				}
			},
			raw: `{"type":"http","tag":"proxy","server":"gateway.test","server_port":8080,"detour":"sel"}`,
		},
		{
			name: "block detour other protocol",
			setup: func(t *testing.T, m *Manager) {
				blk := parseOutbound(t, m, `{"type":"block","tag":"blk"}`)
				if err := m.CreateOutbound(context.Background(), blk.Tag, blk.Type, blk.Options); err != nil {
					t.Fatalf("CreateOutbound block: %v", err)
				}
			},
			raw: `{"type":"http","tag":"proxy","server":"gateway.test","server_port":8080,"detour":"blk"}`,
		},
		{
			name: "detour created after outer is refused",
			setup: func(t *testing.T, m *Manager) {
				// The detour is deliberately NOT created here: the
				// outer outbound is attempted before its detour
				// exists, so the chain cannot be checked.
			},
			raw: `{"type":"http","tag":"proxy","server":"gateway.test","server_port":8080,"detour":"late"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestManager(t)
			tt.setup(t, m)
			out := parseOutbound(t, m, tt.raw)
			err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options)
			if err == nil {
				t.Fatalf("CreateOutbound(%s, no DNS router) = nil, want DNS-router refusal", tt.name)
			}
			if !strings.Contains(err.Error(), "DNS router") {
				t.Errorf("CreateOutbound error = %v, want it to name the missing DNS router", err)
			}
			if _, ok := m.Outbound(out.Tag); ok {
				t.Errorf("outbound %q exists after refused CreateOutbound", out.Tag)
			}
		})
	}
}

// TestRegisterDNSOrderingPinned (NB13) pins the ORDER itself on a
// single Manager, in one sequence: a domain-server outbound
// attempted before any DNS registration is refused and leaves
// nothing behind; the SAME tag attempted after registration
// succeeds; a detour chain attempted before its detour exists is
// refused, and the same outer tag succeeds once the detour was
// created first; registration is sticky, not consumed by one
// creation. If the guard stopped enforcing order, this test fails
// at the step whose outcome flipped.
func TestRegisterDNSOrderingPinned(t *testing.T) {
	m := newTestManager(t)
	raw := `{"type":"http","tag":"proxy","server":"proxy.invalid","server_port":8080}`

	// Step 1: before registration — refused, nothing created.
	out := parseOutbound(t, m, raw)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err == nil {
		t.Fatal("step 1: CreateOutbound before RegisterDNSRouter = nil, want guarded error")
	}
	if _, ok := m.Outbound("proxy"); ok {
		t.Fatal("step 1: outbound exists after refused CreateOutbound")
	}

	// Step 2: registration first, same tag — succeeds.
	m.RegisterDNSRouter(failClosedDNSRouter{})
	out = parseOutbound(t, m, raw)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("step 2: CreateOutbound after RegisterDNSRouter = %v, want nil", err)
	}

	// Step 3: registration is sticky, not consumed — a second
	// domain-server outbound succeeds without re-registering.
	out2 := parseOutbound(t, m, `{"type":"http","tag":"proxy2","server":"proxy2.invalid","server_port":8080}`)
	if err := m.CreateOutbound(context.Background(), out2.Tag, out2.Type, out2.Options); err != nil {
		t.Fatalf("step 3: second CreateOutbound after RegisterDNSRouter = %v, want nil", err)
	}
	if _, err := m.Dialer("proxy"); err != nil {
		t.Fatalf("step 3: Dialer(proxy) = %v, want a dialer for the step-2 outbound", err)
	}
}

// TestRegisterDNSOrderingPinnedDetour pins detour-creation order
// on a Manager with NO DNS router: outer-before-detour is refused,
// detour-before-outer succeeds, for the same tags in sequence.
func TestRegisterDNSOrderingPinnedDetour(t *testing.T) {
	m := newTestManager(t)
	outerRaw := fmt.Sprintf(`{"type":"http","tag":"proxy","server":"gateway.test","server_port":%d,"detour":"late"}`, startFakeHTTPProxy(t))

	// Outer before its detour exists: refused.
	out := parseOutbound(t, m, outerRaw)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err == nil {
		t.Fatal("CreateOutbound before detour exists = nil, want guarded error")
	}
	if _, ok := m.Outbound("proxy"); ok {
		t.Fatal("outbound exists after refused CreateOutbound")
	}

	// Detour first, then the same outer tag: succeeds.
	detour := parseOutbound(t, m, fmt.Sprintf(`{"type":"socks","tag":"late","server":"127.0.0.1","server_port":%d,"version":"5"}`, startFakeSOCKS5(t)))
	if err := m.CreateOutbound(context.Background(), detour.Tag, detour.Type, detour.Options); err != nil {
		t.Fatalf("CreateOutbound detour: %v", err)
	}
	out = parseOutbound(t, m, outerRaw)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("CreateOutbound after detour created = %v, want nil", err)
	}
}

// TestSingBoxNilRouterPanicDetourDirectNonEmpty pins the hazard:
// bypassing the guard, an http outbound with a domain server and
// a non-empty direct detour PANICS on dial (nil DNS router
// dereference in sing-box resolve.go:103). The guard exists so
// this path is never reachable through CreateOutbound.
func TestSingBoxNilRouterPanicDetourDirectNonEmpty(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	m := newTestManager(t)
	createRawOutbound(t, m, `{"type":"direct","tag":"direct","domain_strategy":"prefer_ipv4"}`)
	createRawOutbound(t, m, `{"type":"http","tag":"proxy","server":"gateway.test","server_port":8080,"detour":"direct"}`)
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	panicked, _, _ := dialEchoRecovered(t, m, "proxy", tcpPort)
	if panicked == nil {
		t.Fatal("dial via direct detour, no DNS router: no panic, want nil-router dereference (guard premise changed?)")
	}
	if !strings.Contains(fmt.Sprint(panicked), "nil pointer dereference") {
		t.Errorf("panic = %v, want nil pointer dereference", panicked)
	}
}

// TestSingBoxNilRouterPanicDetourSocks4 pins the second hazard: a
// socks version-4 detour dereferences the nil DNS router in
// sing-box protocol/socks/outbound.go:87 on dial.
func TestSingBoxNilRouterPanicDetourSocks4(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	m := newTestManager(t)
	createRawOutbound(t, m, fmt.Sprintf(`{"type":"socks","tag":"socks4","server":"127.0.0.1","server_port":%d,"version":"4"}`, startFakeSOCKS5(t)))
	createRawOutbound(t, m, `{"type":"http","tag":"proxy","server":"gateway.test","server_port":8080,"detour":"socks4"}`)
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	panicked, _, _ := dialEchoRecovered(t, m, "proxy", tcpPort)
	if panicked == nil {
		t.Fatal("dial via socks4 detour, no DNS router: no panic, want nil-router dereference (guard premise changed?)")
	}
	if !strings.Contains(fmt.Sprint(panicked), "nil pointer dereference") {
		t.Errorf("panic = %v, want nil pointer dereference", panicked)
	}
}

// TestSingBoxNilRouterPanicReverseChain pins the transitive
// hazard: an IP-server socks outbound whose detour is a
// domain-server http outbound panics at resolve.go:103 when
// dialled, because the detour itself captured a nil router. The
// guard must therefore apply to the detour's own creation too —
// which it does, since the detour is itself a domain-server
// outbound refused by CreateOutbound without a router.
func TestSingBoxNilRouterPanicReverseChain(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	m := newTestManager(t)
	createRawOutbound(t, m, fmt.Sprintf(`{"type":"http","tag":"httpp","server":"gateway.test","server_port":%d}`, startFakeHTTPProxy(t)))
	createRawOutbound(t, m, `{"type":"socks","tag":"socks","server":"127.0.0.1","server_port":1,"version":"5","detour":"httpp"}`)
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	panicked, _, _ := dialEchoRecovered(t, m, "socks", tcpPort)
	if panicked == nil {
		t.Fatal("dial via reverse chain, no DNS router: no panic, want nil-router dereference (guard premise changed?)")
	}
	if !strings.Contains(fmt.Sprint(panicked), "nil pointer dereference") {
		t.Errorf("panic = %v, want nil pointer dereference", panicked)
	}
}

// TestSingBoxDomainResolverConstructionError pins the clean-error
// branch: a detour chain with a domain_resolver fails at
// construction ("domain resolver not found") with no DNS
// transports, instead of panicking. The guard refuses this shape
// anyway (a domain_resolver link is never self-resolving).
func TestSingBoxDomainResolverConstructionError(t *testing.T) {
	m := newTestManager(t)
	createRawOutbound(t, m, fmt.Sprintf(`{"type":"socks","tag":"socks","server":"127.0.0.1","server_port":%d,"version":"5"}`, startFakeSOCKS5(t)))
	err := createRawOutboundErr(t, m, `{"type":"http","tag":"proxy","server":"gateway.test","server_port":8080,"detour":"socks","domain_resolver":"dns1"}`)
	if err == nil {
		t.Fatal("raw Create with domain_resolver, no DNS transports = nil, want domain resolver not found")
	}
	if !strings.Contains(err.Error(), "domain resolver not found") {
		t.Errorf("raw Create error = %v, want domain resolver not found", err)
	}
}
