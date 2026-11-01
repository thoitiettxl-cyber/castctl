// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// Wiring test (R6) for the domain_resolver default at the
// production seam: createOutbounds must apply the "local"
// default to a hostname outbound (Seam B), using the DNS
// client registered before it. A minimal HTTP CONNECT proxy
// and echo listener keep the test hermetic; no fake DNS server
// is needed because the proxy hostname is "localhost", which
// the local transport resolves from the system resolver.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/thoitiettxl-cyber/castctl/internal/dns"
	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

type cmdCONNECTProxy struct {
	t        *testing.T
	ln       net.Listener
	port     int
	mu       sync.Mutex
	connects int
}

func startCmdCONNECTProxy(t *testing.T) *cmdCONNECTProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &cmdCONNECTProxy{t: t, ln: ln, port: ln.Addr().(*net.TCPAddr).Port}
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

func (s *cmdCONNECTProxy) connectCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connects
}

func (s *cmdCONNECTProxy) handle(client net.Conn) {
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
	s.mu.Unlock()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, target); done <- struct{}{} }()
	<-done
}

func startCmdEcho(t *testing.T) int {
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

func TestCreateOutboundsAppliesLocalDomainResolver(t *testing.T) {
	proxy := startCmdCONNECTProxy(t)
	echoPort := startCmdEcho(t)

	mgr, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	// Local-only DNS client: the "local" transport is the only
	// server, so the defaulted outbound can only resolve via
	// the system resolver.
	var dnsOpts option.DNSOptions
	if err := json.UnmarshalContext(mgr.Context(), []byte(`{"servers":[{"tag":"local","type":"local"}],"final":"local"}`), &dnsOpts); err != nil {
		t.Fatal(err)
	}
	client, err := dns.New(mgr.Context(), dnsOpts, mgr.OutboundManager())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	mgr.RegisterDNS(client.Router(), client.TransportManager())

	var ob option.Outbound
	if err := json.UnmarshalContext(mgr.Context(), []byte(fmt.Sprintf(`{"type":"http","tag":"proxy","server":"localhost","server_port":%d}`, proxy.port)), &ob); err != nil {
		t.Fatal(err)
	}
	prof := &profile.Profile{Name: "alice", Outbound: profile.OutboundRef{Kind: profile.OutboundTag, Tag: "proxy", Type: "http", From: "outbound"}}
	single := &profile.SingleConfig{
		Profiles:  map[string]*profile.Profile{"alice": prof},
		Outbounds: []option.Outbound{ob},
	}
	if err := createOutbounds(context.Background(), mgr, single, prof, "", profile.LocalBootstrapServerTag); err != nil {
		t.Fatalf("createOutbounds with the local default = %v, want nil", err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	d, err := mgr.Dialer("proxy")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(echoPort))
	if err != nil {
		t.Fatalf("dial via defaulted hostname proxy: %v", err)
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
		t.Fatalf("echo = %q, want %q", string(buf[:n]), "ok")
	}
	if proxy.connectCount() == 0 {
		t.Error("CONNECT proxy saw no requests; the dial did not go through the proxy")
	}
}

// Negative control: without the local tag (and without a
// registered DNS router) the same hostname outbound is
// refused by the F3 guard — the default is what makes
// creation succeed in the positive test, and the ordering
// (RegisterDNS before CreateOutbound) is load-bearing.
func TestCreateOutboundsHostnameWithoutResolverOrRouterRefused(t *testing.T) {
	mgr, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	var ob option.Outbound
	if err := json.UnmarshalContext(mgr.Context(), []byte(`{"type":"http","tag":"proxy","server":"localhost","server_port":8080}`), &ob); err != nil {
		t.Fatal(err)
	}
	prof := &profile.Profile{Name: "alice", Outbound: profile.OutboundRef{Kind: profile.OutboundTag, Tag: "proxy", Type: "http", From: "outbound"}}
	single := &profile.SingleConfig{
		Profiles:  map[string]*profile.Profile{"alice": prof},
		Outbounds: []option.Outbound{ob},
	}
	err = createOutbounds(context.Background(), mgr, single, prof, "", "")
	if err == nil {
		t.Fatal("createOutbounds(hostname, no DNS router, no local tag) = nil, want the F3 refusal")
	}
	if !strings.Contains(err.Error(), "DNS router") {
		t.Fatalf("createOutbounds error = %v; want it to name the missing DNS router", err)
	}
}

// TestDefaultBuildRuntimeJoinsLocalBootstrap (F3, fix loop 1)
// is the joining test: Seam A synthesis (ResolveProfileDNS
// appends "local" to the profile's own dns block) composed
// with Seam B defaulting (createOutbounds applies
// domain_resolver: "local" to the hostname proxy), driven
// through the production path defaultBuildRuntime with no
// manual helper application and no hand-built DNS options.
// The profile's dns block is a fake TCP transport detouring
// through a "localhost" http outbound. Three assertions on
// the one built runtime: (1) a target lookup through
// rt.DNS is answered by the fake DNS server through the
// proxy; (2) a dial through the proxy succeeds — the proxy
// hostname "localhost" must resolve via the system resolver
// for the dial to reach the proxy at all; (3) the fake DNS
// was never asked for the proxy hostname. The dial target
// is an IP literal on purpose: sing-box HTTP CONNECT
// forwards a domain destination verbatim for the proxy to
// resolve, so a domain dial would not exercise the local
// target path; the target lookup is asserted via rt.DNS on
// the same runtime instead. If localServerTag were dropped
// in defaultBuildRuntime, the dial would resolve
// "localhost" through the router and fail; if synthesis
// were dropped, the default would name a missing transport
// and construction would fail.
func TestDefaultBuildRuntimeJoinsLocalBootstrap(t *testing.T) {
	srv := startFakeDNSServerCmd(t)
	proxy := startCmdCONNECTProxy(t)
	echoPort := startCmdEcho(t)
	home := t.TempDir()
	configJSON := fmt.Sprintf(`{"profiles":{"alice":{"outbound":"proxy","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":%d,"detour":"proxy"}],"final":"dns1"}}},"outbounds":[{"type":"http","tag":"proxy","server":"localhost","server_port":%d}]}`,
		srv.port, proxy.port)
	configFile := filepath.Join(home, "config.json")
	if err := os.WriteFile(configFile, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "cookies.txt"), []byte(fakeCookie), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	prof, err := profile.LoadProfile(home, "alice", env.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	loc := &profile.ConfigLocation{ConfigFile: configFile, ConfigDir: home, Explicit: true}
	rt, err := defaultBuildRuntime(context.Background(), loc, prof, env)
	if err != nil {
		t.Fatalf("defaultBuildRuntime = %v; want a running runtime", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := rt.DNS.Lookup(ctx, "gateway.test")
	if err != nil {
		t.Fatalf("Lookup(gateway.test) via defaultBuildRuntime = %v; want [127.0.0.1] from the fake DNS through the proxy", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
		t.Fatalf("Lookup(gateway.test) = %v, want [127.0.0.1]", addrs)
	}
	conn, err := rt.Dialer.DialContext(ctx, "tcp", "127.0.0.1", uint16(echoPort))
	if err != nil {
		t.Fatalf("dial via defaultBuildRuntime = %v; want success through the hostname proxy", err)
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
		t.Fatalf("echo = %q, want %q", string(buf[:n]), "ok")
	}
	if proxy.connectCount() == 0 {
		t.Error("CONNECT proxy saw no requests; the dial did not go through the proxy")
	}
	names := srv.queryNames()
	sawTarget := false
	for _, name := range names {
		if strings.EqualFold(name, "localhost.") {
			t.Errorf("fake DNS was asked for %q; the proxy hostname must resolve via the system resolver only (questions: %v)", name, names)
		}
		if strings.EqualFold(name, "gateway.test.") {
			sawTarget = true
		}
	}
	if !sawTarget {
		t.Errorf("fake DNS saw no gateway.test. question; the target lookup must go through the configured transport (questions: %v)", names)
	}
}
