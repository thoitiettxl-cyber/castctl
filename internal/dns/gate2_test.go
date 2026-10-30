// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package dns

// Gate-2 repro (per-profile DNS PR): a DNS detour naming an empty
// direct outbound must fail at client.Start(), while the same
// fixture without a detour (and with a proxy detour) starts fine.
// This test is the RED baseline for the gate-2 clearance: it pins
// the sing-box empty-direct rejection before any synthesis lands,
// and stays as the regression control afterwards (the empty-direct
// case must keep failing; only the synthesized non-empty direct
// detour introduced by the PR may pass).

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
)

func TestGate2EmptyDirectDetourFailsAtStart(t *testing.T) {
	srv := startFakeDNSServer(t)
	host, portStr, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })

	raw := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d,"detour":"direct"}],"final":"dns1"}`, host, port)
	opts := parseDNSOptions(t, m.Context(), raw)

	// dns.New alone must NOT fail: DetourDialer init is lazy.
	client, err := New(m.Context(), opts, m.OutboundManager())
	if err != nil {
		t.Fatalf("dns.New with detour to empty direct must not fail at construction (lazy detour init), got: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	m.RegisterDNS(client.Router(), client.TransportManager())

	// The load-bearing step: create the "direct" outbound with EMPTY
	// options, exactly as runtime createOutbounds does. Omitting it
	// reproduces the different "outbound detour not found" error.
	var direct option.Outbound
	if err := json.UnmarshalContext(m.Context(), []byte(`{"type":"direct","tag":"direct"}`), &direct); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateOutbound(context.Background(), direct.Tag, direct.Type, direct.Options); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	err = client.Start()
	if err == nil {
		t.Fatal("client.Start with detour to an empty direct outbound must fail, got nil")
	}
	if !strings.Contains(err.Error(), "detour to an empty direct outbound makes no sense") {
		t.Fatalf("client.Start error = %q, want it to contain %q", err.Error(), "detour to an empty direct outbound makes no sense")
	}
	t.Logf("measured gate-2 error: %v", err)
}

// TestGate2SynthesizedDirectDetourStarts is the gate-2 GREEN
// test: a direct outbound made non-empty by exactly one explicit
// field (UDPFragment=false, the shape production's
// SynthesizedDirectOutbound builds) clears the gate — Start
// succeeds and the lookup goes through. The plain empty "direct"
// outbound in TestGate2EmptyDirectDetourFailsAtStart must keep
// failing: the clearance is the new outbound, never a weakened
// guard.
func TestGate2SynthesizedDirectDetourStarts(t *testing.T) {
	srv := startFakeDNSServer(t)
	host, portStr, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })

	raw := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d,"detour":"castctl-direct:test"}],"final":"dns1"}`, host, port)
	opts := parseDNSOptions(t, m.Context(), raw)
	client, err := New(m.Context(), opts, m.OutboundManager())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	m.RegisterDNS(client.Router(), client.TransportManager())

	// Non-empty direct: the JSON form of production's
	// SynthesizedDirectOutbound (udp_fragment=false). The
	// commands package pins the Go helper itself; this test
	// pins the sing-box mechanism it relies on.
	var synth option.Outbound
	if err := json.UnmarshalContext(m.Context(), []byte(`{"type":"direct","tag":"castctl-direct:test","udp_fragment":false}`), &synth); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateOutbound(context.Background(), synth.Tag, synth.Type, synth.Options); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatalf("synthesized non-empty direct detour client.Start must succeed, got: %v", err)
	}
	addrs, err := client.Lookup(context.Background(), "gateway.test")
	if err != nil {
		t.Fatalf("synthesized direct detour Lookup must succeed, got: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
		t.Fatalf("synthesized direct detour Lookup = %v, want [127.0.0.1]", addrs)
	}
}

func TestGate2NoDetourControlStarts(t *testing.T) {
	srv := startFakeDNSServer(t)
	host, portStr, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })

	raw := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d}],"final":"dns1"}`, host, port)
	opts := parseDNSOptions(t, m.Context(), raw)
	client, err := New(m.Context(), opts, m.OutboundManager())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	m.RegisterDNS(client.Router(), client.TransportManager())
	var direct option.Outbound
	if err := json.UnmarshalContext(m.Context(), []byte(`{"type":"direct","tag":"direct"}`), &direct); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateOutbound(context.Background(), direct.Tag, direct.Type, direct.Options); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatalf("no-detour control client.Start must succeed, got: %v", err)
	}
	addrs, err := client.Lookup(context.Background(), "gateway.test")
	if err != nil {
		t.Fatalf("no-detour control Lookup must succeed, got: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
		t.Fatalf("no-detour control Lookup = %v, want [127.0.0.1]", addrs)
	}
}

func TestGate2ProxyDetourControlStarts(t *testing.T) {
	// Reuses the PR3 proxy-stack proof: a detour to a non-empty
	// proxy outbound starts fine, so the gate is direct-specific.
	// buildProxyStack already started manager + client; only the
	// Lookup assertion belongs here.
	st := buildProxyStack(t, "gate2", "127.0.0.1")
	addrs, err := st.client.Lookup(context.Background(), "gateway.test")
	if err != nil {
		t.Fatalf("proxy-detour control Lookup must succeed, got: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
		t.Fatalf("proxy-detour control Lookup = %v, want [127.0.0.1]", addrs)
	}
}
