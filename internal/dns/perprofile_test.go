// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package dns

// Per-profile DNS from ONE parsed config (per-profile DNS PR):
// two profiles, different proxy outbounds, same server tag
// "dns1", built through the production path (ParseSingleConfig
// -> ResolveProfileDNS -> dns.New), must never cross traffic.
// Assertion method reused from isolation_traffic_test.go: ANSWER
// VALUE (not exact query counters, which flaked), positive
// CONNECT-arrival at the owning proxy, cache isolation via
// ClearCache, and close-A-leaves-B. No live hosts; all fakes
// bind 127.0.0.1 only.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

type configStack struct {
	name string

	manager    *outbound.Manager
	client     *Client
	dialer     *outbound.Dialer
	httpClient *http.Client

	dnsServer *answerDNSServer
	dnsPort   int
	wantAddr  string
	proxy     *recordingHTTPProxy
	upstream  *recordingUpstream
}

func (s *configStack) close() {
	if tr, ok := s.httpClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
	_ = s.client.Close()
	_ = s.manager.Close()
}

func (s *configStack) get(url string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Profile", s.name)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d, body %q", url, resp.StatusCode, string(body))
	}
	return string(body), nil
}

// buildConfigStack builds one stack from the parsed config for
// the named profile, following the production assembly order:
// ResolveProfileDNS -> dns.New -> RegisterDNS -> CreateOutbound
// (the profile's own outbound only) -> Start. It returns an
// error instead of calling t.Fatal so callers may build stacks
// concurrently.
func buildConfigStack(cfg *profile.SingleConfig, name string, dnsServer *answerDNSServer, proxy *recordingHTTPProxy, upstream *recordingUpstream) (*configStack, error) {
	prof := cfg.Profiles[name]
	if prof == nil {
		return nil, fmt.Errorf("profile %q missing from config", name)
	}
	resolved, err := profile.ResolveProfileDNS(prof, cfg)
	if err != nil {
		return nil, fmt.Errorf("ResolveProfileDNS %s: %w", name, err)
	}
	if resolved.Source != profile.DNSSourceProfile {
		return nil, fmt.Errorf("profile %s: DNS source = %q, want profile (the fixture carries an own block)", name, resolved.Source)
	}
	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*configStack, error) {
		_ = m.Close()
		return nil, err
	}
	client, err := New(m.Context(), *resolved.Options, m.OutboundManager())
	if err != nil {
		return fail(err)
	}
	m.RegisterDNS(client.Router(), client.TransportManager())
	// Create only this profile's own outbound (tag reference).
	var own *option.Outbound
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i].Tag == prof.Outbound.Tag {
			own = &cfg.Outbounds[i]
			break
		}
	}
	if own == nil {
		_ = client.Close()
		return fail(fmt.Errorf("profile %s: own outbound %q not found in config", name, prof.Outbound.Tag))
	}
	if err := m.CreateOutbound(context.Background(), own.Tag, own.Type, own.Options); err != nil {
		_ = client.Close()
		return fail(err)
	}
	if err := m.Start(); err != nil {
		_ = client.Close()
		return fail(err)
	}
	if err := client.Start(); err != nil {
		_ = client.Close()
		return fail(err)
	}
	d, err := m.Dialer(prof.Outbound.Tag)
	if err != nil {
		_ = client.Close()
		return fail(err)
	}
	httpClient := d.HTTPClient()
	httpClient.Timeout = 10 * time.Second
	_, dnsPortStr, err := net.SplitHostPort(dnsServer.addr)
	if err != nil {
		_ = client.Close()
		return fail(err)
	}
	var dnsPort int
	fmt.Sscanf(dnsPortStr, "%d", &dnsPort)
	return &configStack{
		name: name, manager: m, client: client, dialer: d,
		httpClient: httpClient, dnsServer: dnsServer, dnsPort: dnsPort,
		wantAddr: dnsServer.answer.String(), proxy: proxy, upstream: upstream,
	}, nil
}

func TestPerProfileDNSFromConfig(t *testing.T) {
	dnsA := startAnswerDNSServer(t, "127.0.0.1")
	dnsB := startAnswerDNSServer(t, "127.0.0.2")
	proxyA := startRecordingHTTPProxy(t)
	proxyB := startRecordingHTTPProxy(t)
	upA := startRecordingUpstream(t, "A")
	upB := startRecordingUpstream(t, "B")
	_, portAStr, _ := net.SplitHostPort(dnsA.addr)
	_, portBStr, _ := net.SplitHostPort(dnsB.addr)
	var portA, portB int
	fmt.Sscanf(portAStr, "%d", &portA)
	fmt.Sscanf(portBStr, "%d", &portB)

	// ONE config, two profiles, same server tag "dns1" in both
	// blocks (tag scoping is per TransportManager), different
	// proxies, different fake DNS answers.
	data := fmt.Sprintf(`{
		"profiles": {
			"a": {"outbound": "proxy-A", "dns": {"servers": [{"tag": "dns1", "type": "tcp", "server": "127.0.0.1", "server_port": %d, "detour": "proxy-A"}], "final": "dns1"}},
			"b": {"outbound": "proxy-B", "dns": {"servers": [{"tag": "dns1", "type": "tcp", "server": "127.0.0.1", "server_port": %d, "detour": "proxy-B"}], "final": "dns1"}}
		},
		"outbounds": [
			{"type": "http", "tag": "proxy-A", "server": "127.0.0.1", "server_port": %d},
			{"type": "http", "tag": "proxy-B", "server": "127.0.0.1", "server_port": %d}
		]
	}`, portA, portB, proxyA.port, proxyB.port)
	cfg, err := profile.ParseSingleConfig([]byte(data), "/base")
	if err != nil {
		t.Fatal(err)
	}

	stA, err := buildConfigStack(cfg, "a", dnsA, proxyA, upA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stA.close)
	stB, err := buildConfigStack(cfg, "b", dnsB, proxyB, upB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stB.close)

	// 1. Answer value + CONNECT-arrival, per stack. The
	// CONNECT proof is asserted ONLY on the first lookup per
	// stack: the TCP transport may reuse its existing
	// connection for later lookups, so a repeat lookup needs
	// no new CONNECT (the same reuse lesson as the
	// query-counter flake in isolation_traffic_test.go).
	// Later phases assert answer value + query-count growth
	// only.
	lookup := func(st *configStack, wantConnect bool) {
		t.Helper()
		st.client.Router().ClearCache()
		before := st.dnsServer.queryCount()
		proxyBefore := len(st.proxy.targetsSnapshot())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addrs, err := st.client.Lookup(ctx, "gateway.test")
		if err != nil {
			t.Fatalf("stack %s Lookup: %v", st.name, err)
		}
		if len(addrs) != 1 || addrs[0].String() != st.wantAddr {
			t.Fatalf("stack %s Lookup = %v, want [%s]: the answer came from the other stack's DNS (or nowhere)", st.name, addrs, st.wantAddr)
		}
		if st.dnsServer.queryCount() <= before {
			t.Errorf("stack %s: own fake DNS saw no new queries for its lookup", st.name)
		}
		if !wantConnect {
			return
		}
		found := false
		for _, target := range st.proxy.targetsSnapshot()[proxyBefore:] {
			_, portStr, err := net.SplitHostPort(target)
			if err != nil {
				continue
			}
			var port int
			fmt.Sscanf(portStr, "%d", &port)
			if port == st.dnsPort {
				found = true
			}
		}
		if !found {
			t.Errorf("stack %s: own proxy saw no CONNECT to its own DNS server during its first lookup", st.name)
		}
	}
	lookup(stA, true)
	lookup(stB, true)

	// 2. No proxy target may name the other stack's ports.
	for _, pair := range []struct {
		st, other *configStack
	}{{stA, stB}, {stB, stA}} {
		for _, target := range pair.st.proxy.targetsSnapshot() {
			_, portStr, err := net.SplitHostPort(target)
			if err != nil {
				t.Errorf("stack %s: unparsable CONNECT target %q", pair.st.name, target)
				continue
			}
			var port int
			fmt.Sscanf(portStr, "%d", &port)
			if port != pair.st.dnsPort && port != pair.st.upstream.port {
				t.Errorf("stack %s: proxy CONNECT target %q names a foreign port (own DNS %d, own upstream %d; other DNS %d, upstream %d)",
					pair.st.name, target, pair.st.dnsPort, pair.st.upstream.port, pair.other.dnsPort, pair.other.upstream.port)
			}
		}
	}

	// 3. Cache isolation: clearing A's cache must not change
	// either stack's answers (answer value only: see the
	// connection-reuse note above).
	stA.client.Router().ClearCache()
	lookup(stA, false)
	lookup(stB, false)

	// 4. Concurrent lookups under -race.
	var wg sync.WaitGroup
	for _, st := range []*configStack{stA, stB} {
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func(st *configStack) {
				defer wg.Done()
				st.client.Router().ClearCache()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				addrs, err := st.client.Lookup(ctx, "gateway.test")
				if err != nil {
					t.Errorf("stack %s concurrent Lookup: %v", st.name, err)
					return
				}
				if len(addrs) != 1 || addrs[0].String() != st.wantAddr {
					t.Errorf("stack %s concurrent Lookup = %v, want [%s]", st.name, addrs, st.wantAddr)
				}
			}(st)
		}
	}
	wg.Wait()

	// 5. Domain dial: A resolves gateway.test through A's DNS
	// and arrives at A's upstream; B's upstream sees nothing new.
	stA.client.Router().ClearCache()
	upBBefore := len(stB.upstream.arrivalsSnapshot())
	body, err := stA.get(fmt.Sprintf("http://gateway.test:%d/domain", stA.upstream.port))
	if err != nil {
		t.Fatalf("stack A GET via gateway.test: %v", err)
	}
	if body != "pong-A" {
		t.Fatalf("stack A GET via gateway.test: body = %q, want pong-A", body)
	}
	if got := len(stB.upstream.arrivalsSnapshot()); got != upBBefore {
		t.Errorf("upstream B arrivals changed %d -> %d during stack A's gateway.test dial", upBBefore, got)
	}

	// 6. Close-A-leaves-B.
	stA.close()
	body, err = stB.get(fmt.Sprintf("http://127.0.0.1:%d/after", stB.upstream.port))
	if err != nil {
		t.Errorf("stack B GET after closing stack A: %v", err)
	} else if body != "pong-B" {
		t.Errorf("stack B GET after closing stack A: body = %q, want pong-B", body)
	}
	addrs, err := stB.client.Lookup(context.Background(), "gateway.test")
	if err != nil || len(addrs) != 1 || addrs[0].String() != "127.0.0.2" {
		t.Errorf("stack B Lookup after closing stack A = %v, %v, want [127.0.0.2]", addrs, err)
	}
}
