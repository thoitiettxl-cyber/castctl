//go:build with_wireguard && with_gvisor

// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/log"

	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// TestCreateOutboundsSocksDetourToWireGuardEndpoint pins RT-F8: a
// socks outbound whose detour names a WireGuard endpoint tag is a
// valid chain — the topological sort must know endpoint tags, as
// sing-box's Outbound() falls back to endpoint lookup. Creation
// only: no Start, no dial, no WireGuard handshake.
func TestCreateOutboundsSocksDetourToWireGuardEndpoint(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub := make([]byte, 32)
	if _, err := rand.Read(pub); err != nil {
		t.Fatal(err)
	}
	privB64 := base64.StdEncoding.EncodeToString(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	configJSON := `{"default_profile":"default","profiles":{"default":{"outbound":"px"}},
		"outbounds":[{"type":"socks","tag":"px","server":"127.0.0.1","server_port":1080,"detour":"wg1"}],
		"endpoints":[{"type":"wireguard","tag":"wg1","address":["10.0.0.2/32"],"private_key":"` + privB64 + `",
		"peers":[{"address":"127.0.0.1","port":51820,"public_key":"` + pubB64 + `","allowed_ips":["0.0.0.0/0"]}]}]}`
	home := t.TempDir()
	configFile := filepath.Join(home, "config.json")
	if err := os.WriteFile(configFile, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "cookies.txt"), []byte(fakeCookie), 0o600); err != nil {
		t.Fatal(err)
	}
	single, found, err := profile.LoadSingleConfig(home)
	if err != nil || !found {
		t.Fatalf("LoadSingleConfig = %v, %v", single, err)
	}
	prof, err := profile.LoadProfile(home, "default", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("castctl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Close() }()
	if err := createOutbounds(context.Background(), mgr, single, prof, ""); err != nil {
		t.Fatalf("createOutbounds(socks->wireguard detour) = %v, want nil", err)
	}
	if _, ok := mgr.Outbound("px"); !ok {
		t.Error("outbound px missing after createOutbounds")
	}
	if _, ok := mgr.Endpoint("wg1"); !ok {
		t.Error("endpoint wg1 missing after createOutbounds")
	}
}
