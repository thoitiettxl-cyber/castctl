package dns

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/outbound"
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
