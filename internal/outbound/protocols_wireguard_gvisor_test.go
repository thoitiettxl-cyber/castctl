//go:build with_wireguard && with_gvisor

// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/option"
	badoption "github.com/sagernet/sing/common/json/badoption"
)

// Build + Start + Close of a WireGuard endpoint, only when the gVisor
// device stack is compiled in. Peer dial/handshake is [UNVERIFIED]:
// it needs a real WireGuard peer and live UDP (see final report).

func TestWireGuardEndpointBuildStartClose(t *testing.T) {
	m := newTestManager(t)
	// A direct outbound must exist before Start: the outbound
	// manager refuses its implicit-direct fallback (fail closed).
	// The WireGuard endpoint is dialled via the outbound manager's
	// endpoint fallback (Outbound(tag) -> endpoint.Get(tag)).
	out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatal(err)
	}
	opts := &option.WireGuardEndpointOptions{
		PrivateKey: generateWGKey(t),
		Address: badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix("10.0.0.2/32"),
			netip.MustParsePrefix("fd00::2/128"),
		},
		MTU: 1280,
		Peers: []option.WireGuardPeer{
			{
				Address:   "127.0.0.1",
				Port:      51820,
				PublicKey: generateWGKey(t),
				AllowedIPs: badoption.Listable[netip.Prefix]{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
				PersistentKeepaliveInterval: 25,
			},
		},
	}
	if err := m.CreateEndpoint(context.Background(), "wg", "wireguard", opts); err != nil {
		t.Fatalf("CreateEndpoint wireguard: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start wireguard endpoint: %v", err)
	}
	ep, ok := m.Endpoint("wg")
	if !ok || ep == nil {
		t.Fatal("Endpoint(wg) missing after Start")
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
