//go:build with_wireguard && with_gvisor

// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

// WireGuard endpoint log tests: sing-box's device logs reach
// castctl's factory (through the redacting writer), and key
// material must never appear in full.
//
// IpcSet-failure scope, stated honestly: the IpcSet-failure
// error path itself is NOT exercised here. Bad key material is
// rejected by sing-box's option decode ("decode private key")
// BEFORE any device exists, so no options shape reaches
// IpcSet with bad material; valid material starts cleanly.
// What IS exercised: (a) the decode-error path through the
// manager's WrapErr boundary (error text + capture carry no
// key), and (b) a valid Start, whose device lines flow through
// the factory. The WrapErr boundary itself is what would
// redact an IpcSet error's IPC text if one ever surfaced.
// These tests run only under with_wireguard+with_gvisor; the
// CI legs (untagged, with_utls) do not run them.

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	badoption "github.com/sagernet/sing/common/json/badoption"

	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

func wgWiredManager(t *testing.T, buf *bytes.Buffer) *Manager {
	t.Helper()
	h, err := logging.NewFactory(context.Background(), logging.Settings{Level: "trace"}, buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	m, err := NewManager(context.Background(), h.Logger("castctl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestWireGuardInvalidKeyErrorCarriesNoKey: an invalid private
// key (a fixture string, not valid base64) fails endpoint
// creation at decode. The error text and the factory capture
// must carry no key material — the decode error passes through
// the manager's WrapErr boundary on its way out.
func TestWireGuardInvalidKeyErrorCarriesNoKey(t *testing.T) {
	var buf bytes.Buffer
	m := wgWiredManager(t, &buf)
	opts := &option.WireGuardEndpointOptions{
		PrivateKey: "LOGFIX-WGPRIV-6e19d0",
		Address: badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix("10.0.0.2/32"),
		},
		MTU: 1280,
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
		t.Fatal("CreateEndpoint(invalid private key) = nil, want a decode error")
	}
	if !strings.Contains(err.Error(), "decode private key") {
		t.Errorf("error %q, want the sing-box decode error (wrong failure point)", err.Error())
	}
	if strings.Contains(err.Error(), "LOGFIX-WGPRIV-6e19d0") {
		t.Errorf("error contains the fixture private key: %v", err)
	}
	if strings.Contains(buf.String(), "LOGFIX-WGPRIV-6e19d0") {
		t.Errorf("capture contains the fixture private key:\n%s", buf.String())
	}
}

// TestWireGuardDeviceLinesCarryNoFullKey: a valid endpoint
// Start emits wireguard-go device lines through the factory.
// No full key (private or public) may appear; the peer line
// the device itself emits carries only its own 4-char
// abbreviation (peer(ABCD…)), within Boss's at-most-8-chars
// rule. Keys here are freshly generated per test run, never
// fixtures and never secrets.
func TestWireGuardDeviceLinesCarryNoFullKey(t *testing.T) {
	var buf bytes.Buffer
	m := wgWiredManager(t, &buf)
	priv := generateWGKey(t)
	pub := generateWGKey(t)
	opts := &option.WireGuardEndpointOptions{
		PrivateKey: priv,
		Address: badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix("10.0.0.2/32"),
		},
		MTU: 1280,
		Peers: []option.WireGuardPeer{
			{
				Address:   "127.0.0.1",
				Port:      51820,
				PublicKey: pub,
				AllowedIPs: badoption.Listable[netip.Prefix]{
					netip.MustParsePrefix("0.0.0.0/0"),
				},
			},
		},
	}
	if err := m.CreateEndpoint(context.Background(), "wg", "wireguard", opts); err != nil {
		t.Fatalf("CreateEndpoint: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_ = m.Close()
	got := buf.String()
	if got == "" {
		t.Fatal("capture empty: the device lines never reached the factory (positive control failed)")
	}
	for _, v := range []string{priv, pub} {
		if strings.Contains(got, v) {
			t.Errorf("capture contains a full key")
		}
	}
	if !strings.Contains(got, "peer(") {
		t.Errorf("capture %q, want a device peer line (proves the WG emission path was exercised)", got)
	}
	// The device's own abbreviation is 4 chars + ellipsis:
	// assert exactly that, and that no longer prefix of the
	// public key survives anywhere in the capture.
	if !strings.Contains(got, "peer("+pub[:4]+"…)") {
		t.Errorf("capture %q, want peer(<first 4 chars>…) for the fixture peer", got)
	}
	if strings.Contains(got, pub[:8]) {
		t.Errorf("capture contains an 8-char public-key prefix; the device emits 4, want no longer form")
	}
}
