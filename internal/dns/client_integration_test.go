// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package dns

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Minimal no-auth SOCKS5 CONNECT proxy for the detour / domain_resolver
// integration tests. Only 127.0.0.1 targets are allowed; the system
// resolver is never consulted.

type countingSOCKS5 struct {
	t     *testing.T
	ln    net.Listener
	port  int
	mu    sync.Mutex
	dials int
}

func startCountingSOCKS5(t *testing.T) *countingSOCKS5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &countingSOCKS5{t: t, ln: ln, port: ln.Addr().(*net.TCPAddr).Port}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	return s
}

func (s *countingSOCKS5) handle(client net.Conn) {
	defer client.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(client, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(client, pb); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])
	if host != "127.0.0.1" && host != "gateway.test" {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 5*time.Second)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	s.mu.Lock()
	s.dials++
	s.mu.Unlock()
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, target); done <- struct{}{} }()
	<-done
}

func (s *countingSOCKS5) dialCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dials
}

// Minimal no-auth HTTP CONNECT proxy for the domain_resolver
// integration tests. Only 127.0.0.1 CONNECT targets are allowed;
// the system resolver is never consulted by the proxy itself.
// Counts CONNECT requests and records their authorities so tests
// can prove a proxy hostname was resolved before the CONNECT and
// that the CONNECT authority carried the resolved address.

type countingHTTPProxy struct {
	t           *testing.T
	ln          net.Listener
	port        string
	mu          sync.Mutex
	connects    int
	authorities []string
}

func startCountingHTTPProxy(t *testing.T) *countingHTTPProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &countingHTTPProxy{t: t, ln: ln, port: fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	return s
}

func (s *countingHTTPProxy) handle(client net.Conn) {
	defer client.Close()
	br := bufio.NewReader(client)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(line)
	if len(parts) < 2 || parts[0] != "CONNECT" {
		return
	}
	authority := parts[1]
	// Consume headers to the blank line.
	for {
		h, err := br.ReadString('\n')
		if err != nil || h == "\r\n" || h == "\n" {
			break
		}
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil || host != "127.0.0.1" {
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return
	}
	target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 5*time.Second)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer target.Close()
	s.mu.Lock()
	s.connects++
	s.authorities = append(s.authorities, authority)
	s.mu.Unlock()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, target); done <- struct{}{} }()
	<-done
}

func (s *countingHTTPProxy) connectCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connects
}

func (s *countingHTTPProxy) connectAuthorities() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.authorities...)
}

func startFakeTCPInDNS(t *testing.T) int {
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
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("ok"))
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestDNSDetourThroughSocks(t *testing.T) {
	server := startFakeDNSServer(t)
	proxy := startCountingSOCKS5(t)
	dnsHost, dnsPortStr, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}
	var dnsPort int
	fmt.Sscanf(dnsPortStr, "%d", &dnsPort)

	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()

	// Socks outbound first (the detour target).
	rawSocks := fmt.Sprintf(`{"type":"socks","tag":"socks","server":"127.0.0.1","server_port":%d,"version":"5"}`, proxy.port)
	var socksOut option.Outbound
	if err := json.UnmarshalContext(m.Context(), []byte(rawSocks), &socksOut); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateOutbound(context.Background(), socksOut.Tag, socksOut.Type, socksOut.Options); err != nil {
		t.Fatal(err)
	}

	// DNS transport with detour socks.
	rawDNS := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d,"detour":"socks"}],"final":"dns1"}`, dnsHost, dnsPort)
	var dnsOpts option.DNSOptions
	if err := json.UnmarshalContext(m.Context(), []byte(rawDNS), &dnsOpts); err != nil {
		t.Fatal(err)
	}
	client, err := New(m.Context(), dnsOpts, m.OutboundManager())
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	defer func() { _ = client.Close() }()
	m.RegisterDNS(client.Router(), client.TransportManager())
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := client.Lookup(ctx, "gateway.test")
	if err != nil {
		t.Fatalf("Lookup via detour: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("Lookup = %v, want [127.0.0.1]", addrs)
	}
	if proxy.dialCount() == 0 {
		t.Error("socks proxy saw no dials; DNS did not go through the detour")
	}
	if server.queryCount() == 0 {
		t.Error("fake DNS server saw no queries")
	}
}

func TestDomainResolverEndToEnd(t *testing.T) {
	server := startFakeDNSServer(t)
	proxy := startCountingSOCKS5(t)
	tcpPort := startFakeTCPInDNS(t)
	dnsHost, dnsPortStr, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}
	var dnsPort int
	fmt.Sscanf(dnsPortStr, "%d", &dnsPort)

	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()

	// DNS client first: the socks outbound's domain_resolver refers to
	// the "dns1" server tag.
	rawDNS := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d}],"final":"dns1"}`, dnsHost, dnsPort)
	var dnsOpts option.DNSOptions
	if err := json.UnmarshalContext(m.Context(), []byte(rawDNS), &dnsOpts); err != nil {
		t.Fatal(err)
	}
	client, err := New(m.Context(), dnsOpts, m.OutboundManager())
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	defer func() { _ = client.Close() }()
	m.RegisterDNS(client.Router(), client.TransportManager())

	// Socks outbound whose server is the fake-only hostname gateway.test,
	// resolved through the configured DNS server tag dns1.
	rawSocks := fmt.Sprintf(`{"type":"socks","tag":"socks","server":"gateway.test","server_port":%d,"version":"5","domain_resolver":"dns1"}`, proxy.port)
	var socksOut option.Outbound
	if err := json.UnmarshalContext(m.Context(), []byte(rawSocks), &socksOut); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateOutbound(context.Background(), socksOut.Tag, socksOut.Type, socksOut.Options); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	d, err := m.Dialer("socks")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(tcpPort))
	if err != nil {
		t.Fatalf("dial via domain-resolved socks: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ok" {
		t.Errorf("echo = %q, want %q", string(buf[:n]), "ok")
	}
	if server.queryCount() == 0 {
		t.Error("fake DNS server saw no queries; socks server hostname was not resolved through configured DNS")
	}
}

// TestLocalServerDoesNotHijackTargetLookups (probe NM2): a DNS
// options set whose final is the fake TCP transport PLUS an
// unreferenced synthesised "local" server and no rules must answer
// target lookups from the fake transport. The local server exists
// only as a domain_resolver target for outbound server addresses;
// its mere presence must not rewrite or reject target resolution.
func TestLocalServerDoesNotHijackTargetLookups(t *testing.T) {
	server := startFakeDNSServer(t)
	dnsHost, dnsPortStr, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}
	var dnsPort int
	fmt.Sscanf(dnsPortStr, "%d", &dnsPort)

	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()

	rawDNS := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d},{"tag":"local","type":"local","prefer_go":false}],"final":"dns1"}`, dnsHost, dnsPort)
	var dnsOpts option.DNSOptions
	if err := json.UnmarshalContext(m.Context(), []byte(rawDNS), &dnsOpts); err != nil {
		t.Fatal(err)
	}
	client, err := New(m.Context(), dnsOpts, m.OutboundManager())
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Start(); err != nil {
		t.Fatalf("client.Start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := client.Lookup(ctx, "gateway.test")
	if err != nil {
		t.Fatalf("Lookup(gateway.test): %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
		t.Fatalf("Lookup(gateway.test) = %v, want [127.0.0.1]", addrs)
	}
	if server.queryCount() == 0 {
		t.Error("fake DNS server saw no queries; target lookup was not answered by the fake transport")
	}
}

// TestHostnameProxyWithoutDomainResolverLoops (R4 negative control):
// the 665e769 fixture — an http outbound whose server is the
// hostname "localhost", built by OutboundFromEnv, with NO
// domain_resolver, detouring the only DNS transport — must fail
// with the sing-box loopback error. This pins the bug the fix
// removes; the positive half (R1) asserts the same fixture
// succeeds once the local default is applied.
func TestHostnameProxyWithoutDomainResolverLoops(t *testing.T) {
	server := startFakeDNSServer(t)
	dnsHost, dnsPortStr, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}
	var dnsPort int
	fmt.Sscanf(dnsPortStr, "%d", &dnsPort)

	proxy := startCountingHTTPProxy(t)

	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()

	// DNS client first: the fake TCP server detours through
	// env-proxy, the only transport, so resolving the proxy
	// hostname re-enters it.
	rawDNS := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d,"detour":"env-proxy"}],"final":"dns1"}`, dnsHost, dnsPort)
	var dnsOpts option.DNSOptions
	if err := json.UnmarshalContext(m.Context(), []byte(rawDNS), &dnsOpts); err != nil {
		t.Fatal(err)
	}
	client, err := New(m.Context(), dnsOpts, m.OutboundManager())
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	defer func() { _ = client.Close() }()
	m.RegisterDNS(client.Router(), client.TransportManager())

	t.Setenv("HTTPS_PROXY", "http://localhost:"+proxy.port)
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	ob, err := profile.OutboundFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if ob == nil {
		t.Fatal("OutboundFromEnv returned nil with HTTPS_PROXY set")
	}
	if err := m.CreateOutbound(context.Background(), ob.Tag, ob.Type, ob.Options); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.Lookup(ctx, "gateway.test")
	if err == nil {
		t.Fatal("Lookup(gateway.test) succeeded without a domain_resolver default; want the loopback error")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("Lookup error = %v; want an error containing \"loopback\"", err)
	}
}

// TestHostnameProxyResolvesViaLocalDomainResolver (R1, red-first):
// the same fixture as the negative control, but with the local
// domain_resolver default applied to the env-proxy outbound (the
// Seam B behaviour createOutbounds performs at runtime). The proxy
// hostname "localhost" must resolve through the system resolver
// (the synthesised "local" transport), never through the fake
// remote transport, and the target lookup must be answered by the
// fake DNS server through the proxy. RED on 665e769: the helper
// did not exist, so this fixture could only loop.
func TestHostnameProxyResolvesViaLocalDomainResolver(t *testing.T) {
	server := startFakeDNSServer(t)
	dnsHost, dnsPortStr, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}
	var dnsPort int
	fmt.Sscanf(dnsPortStr, "%d", &dnsPort)

	proxy := startCountingHTTPProxy(t)

	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()

	// Effective DNS options after Seam A synthesis: the fake TCP
	// transport (final, detouring through env-proxy) plus the
	// dedicated "local" server, never final.
	rawDNS := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d,"detour":"env-proxy"},{"tag":"local","type":"local","prefer_go":false}],"final":"dns1"}`, dnsHost, dnsPort)
	var dnsOpts option.DNSOptions
	if err := json.UnmarshalContext(m.Context(), []byte(rawDNS), &dnsOpts); err != nil {
		t.Fatal(err)
	}
	client, err := New(m.Context(), dnsOpts, m.OutboundManager())
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	defer func() { _ = client.Close() }()
	m.RegisterDNS(client.Router(), client.TransportManager())

	t.Setenv("HTTPS_PROXY", "http://localhost:"+proxy.port)
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	ob, err := profile.OutboundFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if ob == nil {
		t.Fatal("OutboundFromEnv returned nil with HTTPS_PROXY set")
	}
	resolved := profile.ApplyDomainResolverDefault(*ob, profile.LocalBootstrapServerTag)
	if err := m.CreateOutbound(context.Background(), resolved.Tag, resolved.Type, resolved.Options); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := client.Lookup(ctx, "gateway.test")
	if err != nil {
		t.Fatalf("Lookup(gateway.test): %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
		t.Fatalf("Lookup(gateway.test) = %v, want [127.0.0.1]", addrs)
	}
	if server.queryCount() == 0 {
		t.Error("fake DNS server saw no queries; target lookup did not go through the proxy")
	}
	if proxy.connectCount() == 0 {
		t.Error("fake HTTP proxy saw no CONNECT; DNS transport did not dial through the proxy")
	}
	for _, q := range server.questionNames() {
		if q == "localhost." {
			t.Errorf("fake DNS server was asked for the proxy hostname %q; it must resolve via the local transport only", q)
		}
	}
}

// newManagerWithDNS builds a manager and a DNS client from raw
// DNS options JSON, registers the client, and arranges cleanup.
// It does not Start either: callers Start the manager and then
// the client, mirroring the production order in
// internal/commands/runtime.go.
func newManagerWithDNS(t *testing.T, rawDNS string) (*outbound.Manager, *Client) {
	t.Helper()
	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	var dnsOpts option.DNSOptions
	if err := json.UnmarshalContext(m.Context(), []byte(rawDNS), &dnsOpts); err != nil {
		t.Fatal(err)
	}
	client, err := New(m.Context(), dnsOpts, m.OutboundManager())
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	m.RegisterDNS(client.Router(), client.TransportManager())
	return m, client
}

// fakeDNSDirectOptions returns DNS options JSON with the fake TCP
// server as the final transport (direct dial, no detour) plus
// the synthesised "local" server, for tests where the remote
// transport itself needs no proxy.
func fakeDNSDirectOptions(t *testing.T, server *fakeDNSServer) string {
	t.Helper()
	dnsHost, dnsPortStr, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}
	var dnsPort int
	fmt.Sscanf(dnsPortStr, "%d", &dnsPort)
	return fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d},{"tag":"local","type":"local","prefer_go":false}],"final":"dns1"}`, dnsHost, dnsPort)
}

func parseOutboundJSON(t *testing.T, m *outbound.Manager, raw string) option.Outbound {
	t.Helper()
	var ob option.Outbound
	if err := json.UnmarshalContext(m.Context(), []byte(raw), &ob); err != nil {
		t.Fatal(err)
	}
	return ob
}

func startManagerAndClient(t *testing.T, m *outbound.Manager, client *Client) {
	t.Helper()
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
}

func dialEchoThrough(t *testing.T, m *outbound.Manager, tag string, echoPort int) {
	t.Helper()
	d, err := m.Dialer(tag)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(echoPort))
	if err != nil {
		t.Fatalf("dial via %s: %v", tag, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ok" {
		t.Errorf("echo = %q, want %q", string(buf[:n]), "ok")
	}
}

// TestDetourChainHostnameOuter (R3a): outer http outbound with a
// hostname server, defaulted to the local resolver, detouring to
// a terminal socks5 outbound with an IP server. Each hop
// resolves via its own domain_resolver; the outer hop's
// hostname must resolve via local, never via the fake DNS.
func TestDetourChainHostnameOuter(t *testing.T) {
	server := startFakeDNSServer(t)
	proxy := startCountingHTTPProxy(t)
	socks := startCountingSOCKS5(t)
	echoPort := startFakeTCPInDNS(t)
	m, client := newManagerWithDNS(t, fakeDNSDirectOptions(t, server))

	terminal := parseOutboundJSON(t, m, fmt.Sprintf(`{"type":"socks","tag":"socks","server":"127.0.0.1","server_port":%d,"version":"5"}`, socks.port))
	if err := m.CreateOutbound(context.Background(), terminal.Tag, terminal.Type, terminal.Options); err != nil {
		t.Fatal(err)
	}
	outer := parseOutboundJSON(t, m, fmt.Sprintf(`{"type":"http","tag":"outer","server":"localhost","server_port":%s,"detour":"socks"}`, proxy.port))
	outer = profile.ApplyDomainResolverDefault(outer, profile.LocalBootstrapServerTag)
	if err := m.CreateOutbound(context.Background(), outer.Tag, outer.Type, outer.Options); err != nil {
		t.Fatal(err)
	}
	startManagerAndClient(t, m, client)
	dialEchoThrough(t, m, "outer", echoPort)
	if socks.dialCount() == 0 {
		t.Error("terminal socks saw no dials; the chain did not forward through it")
	}
	if proxy.connectCount() == 0 {
		t.Error("HTTP proxy saw no CONNECT; the outer hop did not dial through it")
	}
	for _, q := range server.questionNames() {
		if q == "localhost." {
			t.Errorf("fake DNS server was asked for %q; the outer hop must resolve via local", q)
		}
	}
}

// TestDetourChainHostnameTerminal (R3b): terminal socks5 outbound
// with a hostname server, defaulted to the local resolver, fed
// by an outer http outbound with an IP server. The terminal hop
// resolves its own hostname via local.
func TestDetourChainHostnameTerminal(t *testing.T) {
	server := startFakeDNSServer(t)
	proxy := startCountingHTTPProxy(t)
	socks := startCountingSOCKS5(t)
	echoPort := startFakeTCPInDNS(t)
	m, client := newManagerWithDNS(t, fakeDNSDirectOptions(t, server))

	terminal := parseOutboundJSON(t, m, fmt.Sprintf(`{"type":"socks","tag":"socks","server":"localhost","server_port":%d,"version":"5"}`, socks.port))
	terminal = profile.ApplyDomainResolverDefault(terminal, profile.LocalBootstrapServerTag)
	if err := m.CreateOutbound(context.Background(), terminal.Tag, terminal.Type, terminal.Options); err != nil {
		t.Fatal(err)
	}
	outer := parseOutboundJSON(t, m, fmt.Sprintf(`{"type":"http","tag":"outer","server":"127.0.0.1","server_port":%s,"detour":"socks"}`, proxy.port))
	if err := m.CreateOutbound(context.Background(), outer.Tag, outer.Type, outer.Options); err != nil {
		t.Fatal(err)
	}
	startManagerAndClient(t, m, client)
	dialEchoThrough(t, m, "outer", echoPort)
	if socks.dialCount() == 0 {
		t.Error("terminal socks saw no dials; the chain did not forward through it")
	}
	if proxy.connectCount() == 0 {
		t.Error("HTTP proxy saw no CONNECT; the chain did not reach it")
	}
}

// TestSelectorMixedMembersHostnameMember (R3c): a selector whose
// default member is a hostname http outbound (defaulted to
// local) dials through that member; the IP-literal member is
// present but unused.
func TestSelectorMixedMembersHostnameMember(t *testing.T) {
	server := startFakeDNSServer(t)
	proxy := startCountingHTTPProxy(t)
	socks := startCountingSOCKS5(t)
	echoPort := startFakeTCPInDNS(t)
	m, client := newManagerWithDNS(t, fakeDNSDirectOptions(t, server))

	member := parseOutboundJSON(t, m, fmt.Sprintf(`{"type":"http","tag":"member-http","server":"localhost","server_port":%s}`, proxy.port))
	member = profile.ApplyDomainResolverDefault(member, profile.LocalBootstrapServerTag)
	if err := m.CreateOutbound(context.Background(), member.Tag, member.Type, member.Options); err != nil {
		t.Fatal(err)
	}
	spare := parseOutboundJSON(t, m, fmt.Sprintf(`{"type":"socks","tag":"member-socks","server":"127.0.0.1","server_port":%d,"version":"5"}`, socks.port))
	if err := m.CreateOutbound(context.Background(), spare.Tag, spare.Type, spare.Options); err != nil {
		t.Fatal(err)
	}
	sel := parseOutboundJSON(t, m, `{"type":"selector","tag":"sel","outbounds":["member-http","member-socks"],"default":"member-http"}`)
	if err := m.CreateOutbound(context.Background(), sel.Tag, sel.Type, sel.Options); err != nil {
		t.Fatal(err)
	}
	startManagerAndClient(t, m, client)
	dialEchoThrough(t, m, "sel", echoPort)
	if proxy.connectCount() == 0 {
		t.Error("HTTP proxy saw no CONNECT; the selector did not dial through its hostname member")
	}
}

// TestExplicitDomainResolverString (R5a): an explicitly authored
// string domain_resolver "local" is honoured exactly; the
// fixture succeeds without the default being involved.
func TestExplicitDomainResolverString(t *testing.T) {
	server := startFakeDNSServer(t)
	proxy := startCountingHTTPProxy(t)
	dnsHost, dnsPortStr, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}
	var dnsPort int
	fmt.Sscanf(dnsPortStr, "%d", &dnsPort)
	rawDNS := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d,"detour":"env-proxy"},{"tag":"local","type":"local","prefer_go":false}],"final":"dns1"}`, dnsHost, dnsPort)
	m, client := newManagerWithDNS(t, rawDNS)
	ob := parseOutboundJSON(t, m, fmt.Sprintf(`{"type":"http","tag":"env-proxy","server":"localhost","server_port":%s,"domain_resolver":"local"}`, proxy.port))
	if err := m.CreateOutbound(context.Background(), ob.Tag, ob.Type, ob.Options); err != nil {
		t.Fatal(err)
	}
	startManagerAndClient(t, m, client)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := client.Lookup(ctx, "gateway.test")
	if err != nil {
		t.Fatalf("Lookup(gateway.test): %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
		t.Fatalf("Lookup(gateway.test) = %v, want [127.0.0.1]", addrs)
	}
	if proxy.connectCount() == 0 {
		t.Error("HTTP proxy saw no CONNECT")
	}
}

// TestExplicitDomainResolverObject (R5b): the object form is
// honoured with its fields intact (timeout preserved through
// construction; behaviourally identical to the string form).
func TestExplicitDomainResolverObject(t *testing.T) {
	server := startFakeDNSServer(t)
	proxy := startCountingHTTPProxy(t)
	dnsHost, dnsPortStr, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}
	var dnsPort int
	fmt.Sscanf(dnsPortStr, "%d", &dnsPort)
	rawDNS := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d,"detour":"env-proxy"},{"tag":"local","type":"local","prefer_go":false}],"final":"dns1"}`, dnsHost, dnsPort)
	m, client := newManagerWithDNS(t, rawDNS)
	ob := parseOutboundJSON(t, m, fmt.Sprintf(`{"type":"http","tag":"env-proxy","server":"localhost","server_port":%s,"domain_resolver":{"server":"local","timeout":"5s"}}`, proxy.port))
	if err := m.CreateOutbound(context.Background(), ob.Tag, ob.Type, ob.Options); err != nil {
		t.Fatal(err)
	}
	startManagerAndClient(t, m, client)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Lookup(ctx, "gateway.test"); err != nil {
		t.Fatalf("Lookup(gateway.test): %v", err)
	}
}

// TestExplicitDomainResolverNonLocal (R5c): an explicit resolver
// naming the fake transport resolves a fake-only proxy hostname
// ("proxy.test") through that transport — the resolver choice
// is the author's, and the fake transport answers it.
func TestExplicitDomainResolverNonLocal(t *testing.T) {
	server := startFakeDNSServer(t)
	proxy := startCountingSOCKS5(t)
	echoPort := startFakeTCPInDNS(t)
	m, client := newManagerWithDNS(t, fakeDNSDirectOptions(t, server))
	ob := parseOutboundJSON(t, m, fmt.Sprintf(`{"type":"socks","tag":"socks","server":"proxy.test","server_port":%d,"version":"5","domain_resolver":"dns1"}`, proxy.port))
	if err := m.CreateOutbound(context.Background(), ob.Tag, ob.Type, ob.Options); err != nil {
		t.Fatal(err)
	}
	startManagerAndClient(t, m, client)
	dialEchoThrough(t, m, "socks", echoPort)
	found := false
	for _, q := range server.questionNames() {
		if q == "proxy.test." {
			found = true
		}
	}
	if !found {
		t.Errorf("fake DNS questions = %v; want a query for proxy.test.", server.questionNames())
	}
}

// TestExplicitDomainResolverLoopByChoice (R5d): pointing
// domain_resolver at the looping transport is the author's
// choice and still loops after the fix — the default never
// overrides an explicit value.
func TestExplicitDomainResolverLoopByChoice(t *testing.T) {
	server := startFakeDNSServer(t)
	proxy := startCountingHTTPProxy(t)
	dnsHost, dnsPortStr, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}
	var dnsPort int
	fmt.Sscanf(dnsPortStr, "%d", &dnsPort)
	rawDNS := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d,"detour":"env-proxy"},{"tag":"local","type":"local","prefer_go":false}],"final":"dns1"}`, dnsHost, dnsPort)
	m, client := newManagerWithDNS(t, rawDNS)
	ob := parseOutboundJSON(t, m, fmt.Sprintf(`{"type":"http","tag":"env-proxy","server":"localhost","server_port":%s,"domain_resolver":"dns1"}`, proxy.port))
	if err := m.CreateOutbound(context.Background(), ob.Tag, ob.Type, ob.Options); err != nil {
		t.Fatal(err)
	}
	startManagerAndClient(t, m, client)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.Lookup(ctx, "gateway.test")
	if err == nil {
		t.Fatal("Lookup succeeded with an explicit looping domain_resolver; want the loopback error")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("Lookup error = %v; want an error containing \"loopback\"", err)
	}
}

// TestExplicitDomainResolverMissingTag (R5e): a dangling
// domain_resolver fails closed at construction, naming the
// missing tag; there is no fallback to direct or profile DNS.
func TestExplicitDomainResolverMissingTag(t *testing.T) {
	server := startFakeDNSServer(t)
	m, client := newManagerWithDNS(t, fakeDNSDirectOptions(t, server))
	_ = client
	ob := parseOutboundJSON(t, m, `{"type":"socks","tag":"socks","server":"proxy.test","server_port":1080,"version":"5","domain_resolver":"no-such-server"}`)
	err := m.CreateOutbound(context.Background(), ob.Tag, ob.Type, ob.Options)
	if err == nil {
		t.Fatal("CreateOutbound with a dangling domain_resolver = nil, want an error")
	}
	if !strings.Contains(err.Error(), "no-such-server") {
		t.Fatalf("CreateOutbound error = %v; want it to name the missing tag", err)
	}
}

// TestExplicitDomainResolverEmptyObject (R5f): an authored
// empty-object domain_resolver parses (the stdlib
// UnmarshalJSON "empty domain_resolver.server" check is
// bypassed by the UnmarshalJSONContext parse path) and behaves
// as unset at dial time: the hostname resolves through the
// default transport. Here proxy.test resolves to 127.0.0.1 via
// the fake transport and the dial fails only on the refused
// connection — proving resolution used the default transport,
// not the system resolver (which would answer a wildcard
// address on this VM).
func TestExplicitDomainResolverEmptyObject(t *testing.T) {
	server := startFakeDNSServer(t)
	m, client := newManagerWithDNS(t, fakeDNSDirectOptions(t, server))
	_ = client
	ob := parseOutboundJSON(t, m, `{"type":"socks","tag":"socks","server":"proxy.test","server_port":1080,"version":"5","domain_resolver":{}}`)
	if err := m.CreateOutbound(context.Background(), ob.Tag, ob.Type, ob.Options); err != nil {
		t.Fatalf("CreateOutbound empty-object resolver: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	d, err := m.Dialer("socks")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = d.DialContext(ctx, "tcp", "127.0.0.1", 1)
	if err == nil {
		t.Fatal("dial succeeded unexpectedly (nothing listens on 1080)")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1080") {
		t.Fatalf("dial error = %v; want a refused connection to 127.0.0.1:1080 (fake-transport answer)", err)
	}
}
