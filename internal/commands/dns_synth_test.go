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
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/thoitiettxl-cyber/castctl/internal/dns"
	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
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
