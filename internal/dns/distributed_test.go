// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package dns

// G4 distribution, end to end through the production path: one
// legacy top-level dns section (no detour) is distributed by
// `config migrate` into two profiles, each detouring through its
// own fake HTTP proxy to the SAME fake DNS server. A lookup in
// each stack must arrive at the fake DNS through its OWN proxy
// only. No live hosts; all fakes bind 127.0.0.1 only. Reuses the
// stack builder and fake servers from perprofile_test.go /
// isolation_traffic_test.go.

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

func TestDistributedDNSPerProfileIsolation(t *testing.T) {
	dnsServer := startAnswerDNSServer(t, "127.0.0.2")
	proxyA := startRecordingHTTPProxy(t)
	proxyB := startRecordingHTTPProxy(t)
	_, dnsPortStr, _ := net.SplitHostPort(dnsServer.addr)
	var dnsPort int
	fmt.Sscanf(dnsPortStr, "%d", &dnsPort)

	// ONE legacy file: a shared top-level section with NO
	// detour. Distribution must fill proxy-A for profile a
	// and proxy-B for profile b.
	data := fmt.Sprintf(`{
		"profiles": {
			"a": {"outbound": "proxy-A"},
			"b": {"outbound": "proxy-B"}
		},
		"outbounds": [
			{"type": "http", "tag": "proxy-A", "server": "127.0.0.1", "server_port": %d},
			{"type": "http", "tag": "proxy-B", "server": "127.0.0.1", "server_port": %d}
		],
		"dns": {"servers": [{"tag": "dns1", "type": "tcp", "server": "127.0.0.1", "server_port": %d}], "final": "dns1"}
	}`, proxyA.port, proxyB.port, dnsPort)
	base := profile.BaseDir(t.TempDir())
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "config.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := profile.Migrate(base, true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Migrated || result.Reason != "dns-distributed" || !result.DNSDistributed {
		t.Fatalf("Migrate = %+v; want migrated + dns-distributed", result)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := profile.ParseSingleConfig(written, base)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS != nil {
		t.Fatal("distributed config still carries a top-level dns section")
	}
	for name, want := range map[string]string{"a": "proxy-A", "b": "proxy-B"} {
		resolved, err := profile.ResolveProfileDNS(cfg.Profiles[name], cfg)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.Source != profile.DNSSourceProfile {
			t.Fatalf("profile %q source = %q; want profile", name, resolved.Source)
		}
		if len(resolved.Options.Servers) != 1 || resolved.Options.Servers[0].Tag != "dns1" {
			t.Fatalf("profile %q servers = %+v; want one server dns1", name, resolved.Options.Servers)
		}
		w, ok := resolved.Options.Servers[0].Options.(option.DialerOptionsWrapper)
		if !ok || w.TakeDialerOptions().Detour != want {
			t.Fatalf("profile %q detour = %v; want %q", name, resolved.Options.Servers[0].Options, want)
		}
	}

	stA, err := buildConfigStack(cfg, "a", dnsServer, proxyA, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stA.close)
	stB, err := buildConfigStack(cfg, "b", dnsServer, proxyB, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stB.close)

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
		if len(addrs) != 1 || addrs[0].String() != "127.0.0.2" {
			t.Fatalf("stack %s Lookup = %v, want [127.0.0.2]", st.name, addrs)
		}
		if st.dnsServer.queryCount() <= before {
			t.Errorf("stack %s: fake DNS saw no new queries for its lookup", st.name)
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

	// Isolation: every CONNECT through either proxy names
	// only the shared fake DNS port (no other stack's port
	// exists here, and no target may name anything else).
	for _, st := range []*configStack{stA, stB} {
		for _, target := range st.proxy.targetsSnapshot() {
			_, portStr, err := net.SplitHostPort(target)
			if err != nil {
				t.Errorf("stack %s: unparsable CONNECT target %q", st.name, target)
				continue
			}
			var port int
			fmt.Sscanf(portStr, "%d", &port)
			if port != st.dnsPort {
				t.Errorf("stack %s: proxy CONNECT target %q names port %d, want only the fake DNS port %d", st.name, target, port, st.dnsPort)
			}
		}
	}

	// Cache isolation: clearing A's cache must not change
	// either stack's answers.
	stA.client.Router().ClearCache()
	lookup(stA, false)
	lookup(stB, false)

	// Concurrent lookups under -race.
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
				if len(addrs) != 1 || addrs[0].String() != "127.0.0.2" {
					t.Errorf("stack %s concurrent Lookup = %v, want [127.0.0.2]", st.name, addrs)
				}
			}(st)
		}
	}
	wg.Wait()
}
