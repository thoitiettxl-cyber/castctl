// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package dns

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
)

// Per-profile isolation, bullet 1: two FULL stacks (Manager + DNS +
// Dialer) built concurrently must share no mutable state. The only
// process-global state is the immutable sing-box constructor
// registries behind outbound.RegistryContext (one sync.Once; see
// outbound/context.go). Everything mutable is per-stack; this test
// proves it behaviourally against fake in-process servers only.

// settleGoroutineCount waits until the goroutine count is stable and
// returns it. Fake servers spawn their accept loops asynchronously,
// so a baseline taken immediately after starting them undercounts.
func settleGoroutineCount() int {
	prev := runtime.NumGoroutine()
	stable := 0
	for i := 0; i < 50 && stable < 3; i++ {
		time.Sleep(20 * time.Millisecond)
		cur := runtime.NumGoroutine()
		if cur == prev {
			stable++
		} else {
			stable = 0
			prev = cur
		}
	}
	return prev
}

// waitGoroutinesBackToBaseline fails the test unless the goroutine
// count returns to baseline within 5s. Closing a stack must not
// leave goroutines behind.
func waitGoroutinesBackToBaseline(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("goroutines = %d, want <= baseline %d after closing both stacks: a stack leaked goroutines", runtime.NumGoroutine(), baseline)
}

// directStack is one full profile stack with a direct outbound and a
// TCP DNS transport to its own fake DNS server.
type directStack struct {
	manager *outbound.Manager
	client  *Client
	dialer  *outbound.Dialer
}

// buildDirectStack builds a stack without touching *testing.T, so it
// is safe to call from worker goroutines; the caller registers
// cleanup. It mirrors the production assembly order in
// client_test.go: managers, DNS client, register DNS, create
// outbound, start all.
func buildDirectStack(dnsServer *fakeDNSServer) (*directStack, error) {
	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(dnsServer.addr)
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	raw := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d}],"final":"dns1"}`, host, port)
	var opts option.DNSOptions
	if err := json.UnmarshalContext(m.Context(), []byte(raw), &opts); err != nil {
		_ = m.Close()
		return nil, fmt.Errorf("parse DNS options: %w", err)
	}
	client, err := New(m.Context(), opts, m.OutboundManager())
	if err != nil {
		_ = m.Close()
		return nil, fmt.Errorf("dns.New: %w", err)
	}
	m.RegisterDNS(client.Router(), client.TransportManager())
	var direct option.Outbound
	if err := json.UnmarshalContext(m.Context(), []byte(`{"type":"direct","tag":"direct"}`), &direct); err != nil {
		_ = client.Close()
		_ = m.Close()
		return nil, err
	}
	if err := m.CreateOutbound(context.Background(), direct.Tag, direct.Type, direct.Options); err != nil {
		_ = client.Close()
		_ = m.Close()
		return nil, err
	}
	if err := m.Start(); err != nil {
		_ = client.Close()
		_ = m.Close()
		return nil, err
	}
	if err := client.Start(); err != nil {
		_ = client.Close()
		_ = m.Close()
		return nil, err
	}
	d, err := m.Dialer("direct")
	if err != nil {
		_ = client.Close()
		_ = m.Close()
		return nil, err
	}
	return &directStack{manager: m, client: client, dialer: d}, nil
}

func (s *directStack) close() {
	_ = s.client.Close()
	_ = s.manager.Close()
}

func dialEcho(d *outbound.Dialer, port int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(port))
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != "ok" {
		return fmt.Errorf("echo = %q, want %q", string(buf[:n]), "ok")
	}
	return nil
}

func TestTwoProfileStacksIsolatedConcurrent(t *testing.T) {
	// Fakes first, sequentially: their goroutines belong in the
	// baseline, not in the stacks under test.
	dnsA := startFakeDNSServer(t)
	dnsB := startFakeDNSServer(t)
	targetA := startFakeTCPInDNS(t)
	targetB := startFakeTCPInDNS(t)
	baseline := settleGoroutineCount()

	// Build both FULL stacks concurrently. The same tag ("direct")
	// is created in both managers independently: tag namespaces
	// are per-Manager, so no "<profile>/<tag>" prefixing is needed.
	type built struct {
		stack *directStack
		err   error
	}
	results := make([]built, 2)
	var wg sync.WaitGroup
	servers := []*fakeDNSServer{dnsA, dnsB}
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i].stack, results[i].err = buildDirectStack(servers[i])
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("concurrent stack %d construction: %v", i, r.err)
		}
	}
	stA, stB := results[0].stack, results[1].stack
	t.Cleanup(stA.close)
	t.Cleanup(stB.close)

	// Distinct instances: managers, DNS clients, routers, transport
	// managers, dialers, outbound managers, and registry clones.
	if stA.manager == stB.manager {
		t.Error("two profiles share one outbound.Manager")
	}
	if stA.client == stB.client {
		t.Error("two profiles share one dns.Client")
	}
	if stA.client.Router() == stB.client.Router() {
		t.Error("two profiles share one DNS router")
	}
	if stA.client.TransportManager() == stB.client.TransportManager() {
		t.Error("two profiles share one DNS transport manager")
	}
	if stA.dialer == stB.dialer {
		t.Error("two profiles share one outbound.Dialer")
	}
	if stA.manager.OutboundManager() == stB.manager.OutboundManager() {
		t.Error("two profiles share one sing-box outbound manager")
	}
	regA := service.RegistryFromContext(stA.manager.Context())
	regB := service.RegistryFromContext(stB.manager.Context())
	if regA == nil || regB == nil {
		t.Fatal("a manager context carries no service registry")
	}
	if regA == regB {
		t.Error("manager service registries are the same object: NewContext must clone the global registry per manager")
	}
	// The constructor registries themselves ARE shared — by design,
	// read-only: include.Context builds them once, and no code
	// registers constructors after that. Sharing immutable
	// registries is not sharing mutable state.
	obRegA := service.FromContext[adapter.OutboundRegistry](stA.manager.Context())
	obRegB := service.FromContext[adapter.OutboundRegistry](stB.manager.Context())
	if obRegA == nil || obRegB == nil {
		t.Fatal("a manager context carries no outbound registry")
	}
	if obRegA != obRegB {
		t.Error("outbound constructor registries differ: they must be the single shared read-only registry from include.Context")
	}
	// Each manager registered its own (stateless) stub Router; the
	// stub refuses inbound routing instead of sharing a global one.
	for i, st := range []*directStack{stA, stB} {
		router := service.FromContext[adapter.Router](st.manager.Context())
		if router == nil {
			t.Errorf("stack %d: no Router in the manager context", i)
			continue
		}
		if err := router.RouteConnection(context.Background(), nil, adapter.InboundContext{}); err == nil {
			t.Errorf("stack %d: stub Router accepted a routed connection, want the no-router error", i)
		}
	}
	// Per-stack DNS transports are distinct objects.
	trA, okA := stA.client.Transport("dns1")
	trB, okB := stB.client.Transport("dns1")
	if !okA || !okB {
		t.Fatal("a stack is missing its dns1 transport")
	}
	if trA == trB {
		t.Error("two profiles share one DNS transport")
	}

	// Concurrent dials and lookups on both stacks do not interfere.
	var dwg sync.WaitGroup
	var errsMu sync.Mutex
	var errs []error
	record := func(err error) {
		if err != nil {
			errsMu.Lock()
			errs = append(errs, err)
			errsMu.Unlock()
		}
	}
	for i := 0; i < 8; i++ {
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			record(dialEcho(stA.dialer, targetA))
		}()
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			record(dialEcho(stB.dialer, targetB))
		}()
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			addrs, err := stA.client.Lookup(ctx, "gateway.test")
			if err != nil {
				record(err)
				return
			}
			if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
				record(fmt.Errorf("stack A lookup = %v, want [127.0.0.1]", addrs))
			}
		}()
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			addrs, err := stB.client.Lookup(ctx, "gateway.test")
			if err != nil {
				record(err)
				return
			}
			if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
				record(fmt.Errorf("stack B lookup = %v, want [127.0.0.1]", addrs))
			}
		}()
	}
	dwg.Wait()
	for _, err := range errs {
		t.Error(err)
	}
	if dnsA.queryCount() == 0 || dnsB.queryCount() == 0 {
		t.Errorf("fake DNS query counts = A:%d B:%d, want both > 0 (each stack resolved through its own DNS server)", dnsA.queryCount(), dnsB.queryCount())
	}

	// Closing stack A leaves stack B fully working.
	stA.close()
	if err := dialEcho(stB.dialer, targetB); err != nil {
		t.Errorf("stack B dial after closing stack A: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if addrs, err := stB.client.Lookup(ctx, "gateway.test"); err != nil {
		t.Errorf("stack B lookup after closing stack A: %v", err)
	} else if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
		t.Errorf("stack B lookup after closing stack A = %v, want [127.0.0.1]", addrs)
	}

	// Close stack B, then prove no goroutines leaked.
	stB.close()
	waitGoroutinesBackToBaseline(t, baseline)
}
