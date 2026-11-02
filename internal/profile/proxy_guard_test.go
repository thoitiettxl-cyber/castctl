// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
)

// configPathOutbound dials the test listener for every
// destination, recording what it was asked for — the same
// shape as the keeper mock outbound, local to this package
// so the config-path guard test needs no chromedp build tag.
type configPathOutbound struct {
	dials  []M.Socksaddr
	target string
}

func (f *configPathOutbound) Type() string           { return "fake" }
func (f *configPathOutbound) Tag() string            { return "fake" }
func (f *configPathOutbound) Network() []string      { return []string{N.NetworkTCP} }
func (f *configPathOutbound) Dependencies() []string { return nil }
func (f *configPathOutbound) DialContext(ctx context.Context, nw string, dest M.Socksaddr) (net.Conn, error) {
	f.dials = append(f.dials, dest)
	var d net.Dialer
	return d.DialContext(ctx, nw, f.target)
}
func (f *configPathOutbound) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("fake: ListenPacket not implemented")
}

var _ adapter.Outbound = (*configPathOutbound)(nil)

// configPathResolver satisfies outbound.HostResolver without
// ever resolving: the guard test dials literal IPs only, and
// the Dialer never calls it for those.
type configPathResolver struct{}

func (configPathResolver) Lookup(_ context.Context, _ string, _ adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return nil, fmt.Errorf("fake: no DNS in guard test")
}

func configPathCONNECT(t *testing.T, proxyURL, authority string) int {
	t.Helper()
	ln, err := net.DialTimeout("tcp", proxyURL, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, err := fmt.Fprintf(ln, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(ln)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var code int
	if _, err := fmt.Sscanf(status, "HTTP/1.1 %d", &code); err != nil {
		t.Fatalf("CONNECT status line = %q", status)
	}
	return code
}

// TestKeeperExoticAllowlistEntryRefusedThroughProxy is the
// D12 config-path test: an exotic entry spelling travels the
// REAL config path — ParseSingleConfig, Effective* accessors,
// proxy construction — and requests in every spelling of the
// same refused-range address must still be refused, never
// dialled. It covers all four combinations: exotic entry +
// exotic request (multi-dot), exotic entry + canonical
// request, canonical entry + exotic request (shorthand),
// and shorthand entry + shorthand request.
func TestKeeperExoticAllowlistEntryRefusedThroughProxy(t *testing.T) {
	t.Parallel()
	raw := keeperTestConfig(t, `[{"tag": "k1", "profile": "muse01", "browser": "http://127.0.0.1:9226/", "proxy_allowed_hosts": ["127.0.0.1....", "127.1"]}]`)
	cfg, err := ParseSingleConfig([]byte(raw), t.TempDir())
	if err != nil {
		t.Fatalf("ParseSingleConfig: %v", err)
	}
	entry := cfg.Keeper.KeeperEntryForProfile("muse01")
	if entry == nil {
		t.Fatal("no keeper entry for muse01")
	}
	// The parse pass collapses every trailing dot; the
	// shorthand spelling survives verbatim as an entry (it is
	// the proxy's canonicalising range check, not the parse,
	// that refuses it at dial time).
	hosts := entry.EffectiveProxyAllowedHosts()
	if len(hosts) != 2 || hosts[0] != "127.0.0.1" || hosts[1] != "127.1" {
		t.Fatalf("EffectiveProxyAllowedHosts = %v; want [127.0.0.1 127.1]", hosts)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	fake := &configPathOutbound{target: ln.Addr().String()}
	dialer := outbound.NewDialer(fake, &configPathResolver{}, option.OutboundTLSOptions{})
	opts := outbound.ProxyOptions{
		DialTimeout:    entry.EffectiveProxyDialTimeout(),
		MaxHeaderBytes: entry.EffectiveProxyMaxHeaderBytes(),
		MaxBodyBytes:   entry.EffectiveProxyMaxBodyBytes(),
		AllowedHosts:   hosts,
	}
	var refused []string
	opts.OnRefused = func(host string) { refused = append(refused, host) }
	proxy, proxyURL, err := outbound.NewLoopbackProxy(dialer, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	proxyHost := proxyURL[len("http://"):]

	for _, authority := range []string{"127.0.0.1..:443", "127.0.0.1:443", "127.1:443", "0x7f.0.0.1:443"} {
		if code := configPathCONNECT(t, proxyHost, authority); code != 403 {
			t.Fatalf("CONNECT %s: status = %d; want 403", authority, code)
		}
	}
	if len(fake.dials) != 0 {
		t.Fatalf("outbound dials = %d; want 0 (refused before dialling)", len(fake.dials))
	}
	if len(refused) != 4 {
		t.Fatalf("refusals = %v; want 4 host-only entries", refused)
	}
}
