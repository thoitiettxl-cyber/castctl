// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// Gate-2 clearance at the production seam: the helper
// SynthesizedDirectOutbound (used by createOutbounds for a
// direct profile's default DNS detour) must clear sing-box's
// empty-direct gate at client.Start, with no fake server needed
// (the gate fires at Start, before any dial). The plain empty
// direct outbound must keep failing — see the dns package's
// gate2_test.go for that control.

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/thoitiettxl-cyber/castctl/internal/dns"
	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

func TestSynthesizedDirectOutboundClearsGate(t *testing.T) {
	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })

	// No fake server: port 1 is unreachable, but the gate fires
	// at Start before any dial, so Start success alone proves
	// the clearance.
	raw := `{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":1,"detour":"castctl-direct:default"}],"final":"dns1"}`
	var dnsOpts option.DNSOptions
	if err := json.UnmarshalContext(m.Context(), []byte(raw), &dnsOpts); err != nil {
		t.Fatal(err)
	}
	client, err := dns.New(m.Context(), dnsOpts, m.OutboundManager())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	m.RegisterDNS(client.Router(), client.TransportManager())
	if err := m.CreateOutbound(context.Background(), "castctl-direct:default", "direct", SynthesizedDirectOutbound()); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatalf("client.Start with detour to SynthesizedDirectOutbound must succeed, got: %v", err)
	}
}

// TestCreateOutboundsRefusesSynthesizedTagCollision pins the
// defence-in-depth half of the synthesised-tag reservation:
// even a SingleConfig built without going through parse (so the
// parse-time reservation cannot fire) must fail loudly when the
// synthesised tag is already taken by a config outbound, never
// silently skip creation and let the DNS detour dial that
// outbound. The colliding outbound is a socks proxy on
// 127.0.0.1:1080 (the red-team repro shape); creation only, no
// Start, no dial.
func TestCreateOutboundsRefusesSynthesizedTagCollision(t *testing.T) {
	mgr, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	var ob option.Outbound
	if err := json.UnmarshalContext(mgr.Context(), []byte(`{"type":"socks","tag":"castctl-direct:alice","server":"127.0.0.1","server_port":1080,"version":"5"}`), &ob); err != nil {
		t.Fatal(err)
	}
	prof := &profile.Profile{Name: "alice", Outbound: profile.OutboundRef{Kind: profile.OutboundDirect, Type: "direct"}}
	single := &profile.SingleConfig{
		Profiles:  map[string]*profile.Profile{"alice": prof},
		Outbounds: []option.Outbound{ob},
	}
	err = createOutbounds(context.Background(), mgr, single, prof, profile.SynthesizedDirectTag("alice"), "")
	if err == nil {
		t.Fatal("createOutbounds with a colliding synthesised tag must fail loudly, got nil error")
	}
	if !strings.Contains(err.Error(), "castctl-direct:alice") {
		t.Fatalf("collision error = %v, want it to name the colliding tag", err)
	}
	if _, ok := mgr.Outbound("castctl-direct:alice"); !ok {
		t.Error("colliding socks outbound must still be registered (the error, not a silent skip, is what stops the runtime)")
	}
}

// Regression half of the same test: a non-colliding config still
// gets its synthesised direct outbound created.
func TestCreateOutboundsCreatesSynthesizedTagWhenFree(t *testing.T) {
	mgr, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	prof := &profile.Profile{Name: "alice", Outbound: profile.OutboundRef{Kind: profile.OutboundDirect, Type: "direct"}}
	single := &profile.SingleConfig{Profiles: map[string]*profile.Profile{"alice": prof}}
	if err := createOutbounds(context.Background(), mgr, single, prof, profile.SynthesizedDirectTag("alice"), ""); err != nil {
		t.Fatalf("createOutbounds with a free synthesised tag = %v, want nil", err)
	}
	if _, ok := mgr.Outbound("castctl-direct:alice"); !ok {
		t.Error("synthesised direct outbound missing after createOutbounds")
	}
}
