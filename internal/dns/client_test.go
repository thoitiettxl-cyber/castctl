package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/outbound"
)

// testSetup builds an outbound Manager plus a DNS Client wired to a fake
// TCP DNS server. It mirrors the product assembly order: managers,
// DNS client, register DNS router, create outbounds, start all.
type testSetup struct {
	manager *outbound.Manager
	client  *Client
	server  *fakeDNSServer
}

func newTestSetup(t *testing.T, dnsOpts func(host string, port uint16) option.DNSOptions) *testSetup {
	t.Helper()
	server := startFakeDNSServer(t)
	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	host, portStr, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	opts := dnsOpts(host, uint16(port))
	client, err := New(m.Context(), opts, m.OutboundManager())
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	m.RegisterDNS(client.Router(), client.TransportManager())
	// Mirror the production assembly: at least one outbound exists
	// before Start, so the manager never needs its (refused)
	// implicit-direct fallback.
	var direct option.Outbound
	if err := json.UnmarshalContext(m.Context(), []byte(`{"type":"direct","tag":"direct"}`), &direct); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateOutbound(context.Background(), direct.Tag, direct.Type, direct.Options); err != nil {
		t.Fatal(err)
	}
	return &testSetup{manager: m, client: client, server: server}
}

func tcpDNSOptions(host string, port uint16) option.DNSOptions {
	return option.DNSOptions{
		Servers: []option.DNSServerOptions{
			{
				Tag:  "dns1",
				Type: "tcp",
				Options: &option.RemoteDNSServerOptions{
					DNSServerAddressOptions: option.DNSServerAddressOptions{
						Server:     host,
						ServerPort: port,
					},
				},
			},
		},
		Final: "dns1",
	}
}

func parseDNSOptions(t *testing.T, ctx context.Context, raw string) option.DNSOptions {
	t.Helper()
	var opts option.DNSOptions
	if err := json.UnmarshalContext(ctx, []byte(raw), &opts); err != nil {
		t.Fatalf("parse DNS options: %v", err)
	}
	return opts
}

func TestClientLookupThroughConfiguredDNS(t *testing.T) {
	s := newTestSetup(t, tcpDNSOptions)
	if err := s.client.Start(); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	if err := s.manager.Start(); err != nil {
		t.Fatalf("manager Start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := s.client.Lookup(ctx, "gateway.test")
	if err != nil {
		t.Fatalf("Lookup(gateway.test): %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("Lookup = %v, want [127.0.0.1]", addrs)
	}
	if s.server.queryCount() == 0 {
		t.Error("fake DNS server saw no queries; resolution did not go through the configured DNS")
	}
}

func TestClientNXDOMAINIsError(t *testing.T) {
	s := newTestSetup(t, tcpDNSOptions)
	if err := s.client.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.client.Lookup(ctx, "missing.test"); err == nil {
		t.Fatal("Lookup(missing.test) = nil, want NXDOMAIN error")
	}
}

func TestClientNoSystemFallbackForLocalhost(t *testing.T) {
	// The system resolver knows localhost, but the configured fake DNS
	// returns NXDOMAIN for it. A successful localhost lookup would
	// prove a system-resolver fallback; it must fail instead.
	s := newTestSetup(t, tcpDNSOptions)
	if err := s.client.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if addrs, err := s.client.Lookup(ctx, "localhost"); err == nil {
		t.Fatalf("Lookup(localhost) = %v, want error (no system fallback)", addrs)
	}
}

func TestClientNoServersIsError(t *testing.T) {
	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	_, err = New(m.Context(), option.DNSOptions{}, m.OutboundManager())
	if err == nil {
		t.Fatal("New with no servers = nil, want error (no local/system fallback transport)")
	}
}

func TestClientDNSFailureIsError(t *testing.T) {
	// DNS server on a refusing port: lookup must error, never fall back.
	closed := closedPort(t)
	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	opts := option.DNSOptions{
		Servers: []option.DNSServerOptions{
			{
				Tag:  "dead",
				Type: "tcp",
				Options: &option.RemoteDNSServerOptions{
					DNSServerAddressOptions: option.DNSServerAddressOptions{
						Server:     "127.0.0.1",
						ServerPort: uint16(closed),
					},
				},
			},
		},
		Final: "dead",
	}
	client, err := New(m.Context(), opts, m.OutboundManager())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Lookup(ctx, "gateway.test"); err == nil {
		t.Fatal("Lookup through dead DNS = nil, want error")
	}
}

func TestClientBootstrapForServerHostname(t *testing.T) {
	// The DNS server's own hostname is resolved once via the injected
	// bootstrap func; the bootstrap must never be called for other
	// hostnames. The fake bootstrap maps dns.test -> 127.0.0.1 and the
	// server listens on 127.0.0.1, so the substituted address reaches
	// the fake server.
	server := startFakeDNSServer(t)
	_, portStr, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	bootstrapCalls := 0
	bootstrap := func(ctx context.Context, host string) ([]netip.Addr, error) {
		bootstrapCalls++
		if host != "dns.test" {
			return nil, fmt.Errorf("bootstrap called for unexpected host %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	raw := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":"dns.test","server_port":%d}],"final":"dns1"}`, port)
	opts := parseDNSOptions(t, m.Context(), raw)
	client, err := New(m.Context(), opts, m.OutboundManager(), WithBootstrap(bootstrap))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()
	if bootstrapCalls != 1 {
		t.Fatalf("bootstrap calls = %d, want exactly 1 (at construction)", bootstrapCalls)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := client.Lookup(ctx, "gateway.test")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("Lookup = %v, want [127.0.0.1]", addrs)
	}
	if bootstrapCalls != 1 {
		t.Errorf("bootstrap calls after lookup = %d, want still 1 (never for other hosts)", bootstrapCalls)
	}
	if server.queryCount() == 0 {
		t.Error("fake DNS server saw no queries")
	}
}

func TestClientBootstrapFailureIsError(t *testing.T) {
	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	raw := `{"servers":[{"tag":"dns1","type":"tcp","server":"dns.test","server_port":5353}],"final":"dns1"}`
	opts := parseDNSOptions(t, m.Context(), raw)
	bootstrap := func(ctx context.Context, host string) ([]netip.Addr, error) {
		return nil, errors.New("bootstrap failed")
	}
	if _, err := New(m.Context(), opts, m.OutboundManager(), WithBootstrap(bootstrap)); err == nil {
		t.Fatal("New with failing bootstrap = nil, want error")
	}
}

func TestClientLifecycle(t *testing.T) {
	s := newTestSetup(t, tcpDNSOptions)
	if err := s.client.Start(); err != nil {
		t.Fatal(err)
	}
	if err := s.client.Start(); err == nil {
		t.Fatal("second Start = nil, want error")
	}
	if err := s.client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.client.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := s.client.Lookup(ctx, "gateway.test"); err == nil {
		t.Fatal("Lookup after Close = nil, want error")
	}
}

func TestClientTransportAccess(t *testing.T) {
	s := newTestSetup(t, tcpDNSOptions)
	tr, ok := s.client.Transport("dns1")
	if !ok || tr == nil {
		t.Fatal("Transport(dns1) missing")
	}
	if _, ok := s.client.Transport("missing"); ok {
		t.Fatal("Transport(missing) found, want missing")
	}
	var _ adapter.DNSTransport = tr
}

func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}
