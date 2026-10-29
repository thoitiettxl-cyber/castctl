//go:build with_wireguard && !with_gvisor

package outbound

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	badoption "github.com/sagernet/sing/common/json/badoption"
)

func TestWireGuardEndpointRequiresGVisor(t *testing.T) {
	m := newTestManager(t)
	opts := &option.WireGuardEndpointOptions{
		PrivateKey: generateWGKey(t),
		Address: badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix("10.0.0.2/32"),
		},
		Peers: []option.WireGuardPeer{
			{
				Address:   "127.0.0.1",
				Port:      51820,
				PublicKey: generateWGKey(t),
				AllowedIPs: badoption.Listable[netip.Prefix]{
					netip.MustParsePrefix("0.0.0.0/0"),
				},
			},
		},
	}
	err := m.CreateEndpoint(context.Background(), "wg", "wireguard", opts)
	if err == nil {
		t.Fatal("CreateEndpoint wireguard without with_gvisor = nil, want gVisor-not-included error")
	}
	if !strings.Contains(err.Error(), "gVisor") {
		t.Fatalf("CreateEndpoint error = %v, want it to name gVisor", err)
	}
}

func TestWireGuardEndpointSystemRejected(t *testing.T) {
	m := newTestManager(t)
	opts := &option.WireGuardEndpointOptions{System: true, PrivateKey: generateWGKey(t)}
	if err := m.CreateEndpoint(context.Background(), "wg", "wireguard", opts); err == nil {
		t.Fatal("CreateEndpoint system:true = nil, want userspace-only rejection")
	}
}

func TestWireGuardEndpointMissingPrivateKeyRejected(t *testing.T) {
	m := newTestManager(t)
	opts := &option.WireGuardEndpointOptions{}
	if err := m.CreateEndpoint(context.Background(), "wg", "wireguard", opts); err == nil {
		t.Fatal("CreateEndpoint without private key = nil, want error")
	}
}
