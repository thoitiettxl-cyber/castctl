// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// R2 (G4 loop 3, RED first): a profile's own inline outbound
// must be materialised in the profile's own outbound manager
// under its tag (profile:<name>), or every inline profile's
// runtime — DNS Start first, then the dialer — fails closed
// on a detour/outbound that was never created. These tests
// drive the production assembly (defaultBuildRuntime /
// createOutbounds), never a validation-only seam: the
// loop-2 reachable-set fix is not evidence the outbound
// exists at runtime.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/log"

	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// TestCreateOutboundsCreatesOwnInlineOutbound pins creation:
// the active profile's inline socks outbound appears under
// profile:rt2a; a second profile's inline outbound is NOT
// created in this manager (per-profile scoping); global
// outbounds and the explicit direct outbound are unaffected.
func TestCreateOutboundsCreatesOwnInlineOutbound(t *testing.T) {
	home := t.TempDir()
	configJSON := `{"profiles":{"rt2a":{"outbound":{"type":"socks","server":"127.0.0.1","server_port":1080,"version":"5"}},"rt2b":{"outbound":{"type":"socks","server":"127.0.0.1","server_port":1081,"version":"5"}}},"outbounds":[{"type":"socks","tag":"rt2-sg","server":"127.0.0.1","server_port":1082,"version":"5"}]}`
	if err := os.WriteFile(filepath.Join(home, "config.json"), []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	single, found, err := profile.LoadSingleConfig(home)
	if err != nil || !found {
		t.Fatalf("LoadSingleConfig = %v, %v", single, err)
	}
	prof, err := profile.LoadProfile(home, "rt2a", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Close() }()
	if err := createOutbounds(context.Background(), mgr, single, prof, ""); err != nil {
		t.Fatalf("createOutbounds(inline profile) = %v, want nil", err)
	}
	if _, ok := mgr.Outbound("profile:rt2a"); !ok {
		t.Error("own inline outbound profile:rt2a missing after createOutbounds")
	}
	if _, ok := mgr.Outbound("profile:rt2b"); ok {
		t.Error("other profile's inline outbound profile:rt2b must not be created in this profile's manager")
	}
	if _, ok := mgr.Outbound("rt2-sg"); !ok {
		t.Error("global outbound rt2-sg missing after createOutbounds")
	}
	if _, ok := mgr.Outbound("direct"); !ok {
		t.Error("explicit direct outbound missing after createOutbounds")
	}
}

// TestInlineOutboundDNSDetourStartsAndTraversesFakeUpstream is
// the R2 reproduction at the production seam: an inline socks
// profile whose own dns block detours to profile:rt2a, driven
// through defaultBuildRuntime (DNS register -> createOutbounds
// -> DNS Start -> manager Start) with a fake SOCKS5 forwarder
// and a fake TCP DNS server. Before the fix, DNS Start fails
// with "outbound detour not found: profile:rt2a"; after it,
// the lookup traverses the inline outbound to the fake server.
func TestInlineOutboundDNSDetourStartsAndTraversesFakeUpstream(t *testing.T) {
	srv := startFakeDNSServerCmd(t)
	proxy := startFakeSOCKS5Cmd(t)
	home := t.TempDir()
	configJSON := fmt.Sprintf(`{"profiles":{"rt2a":{"outbound":{"type":"socks","server":"127.0.0.1","server_port":%d,"version":"5"},"dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":%d,"detour":"profile:rt2a"}],"final":"dns1"}}}}`,
		proxy.port, srv.port)
	configFile := filepath.Join(home, "config.json")
	if err := os.WriteFile(configFile, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "cookies.txt"), []byte(fakeCookie), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	prof, err := profile.LoadProfile(home, "rt2a", env.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	loc := &profile.ConfigLocation{ConfigFile: configFile, ConfigDir: home, Explicit: true}
	rt, err := defaultBuildRuntime(context.Background(), loc, prof, env)
	if err != nil {
		t.Fatalf("defaultBuildRuntime(inline profile, own dns detour) = %v; want a running runtime (red-team R2: DNS Start failed on the unmaterialised profile:rt2a detour)", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	if _, ok := rt.Manager.Outbound("profile:rt2a"); !ok {
		t.Fatal("inline outbound profile:rt2a missing from the built runtime's manager")
	}
	if rt.DNS == nil {
		t.Fatal("runtime DNS client is nil; want the own-block resolver")
	}
	addrs, err := rt.DNS.Lookup(context.Background(), "gateway.test")
	if err != nil {
		t.Fatalf("Lookup through inline detour = %v, want [127.0.0.1]", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
		t.Fatalf("Lookup = %v, want [127.0.0.1]", addrs)
	}
	if n := srv.queryCount(); n < 1 {
		t.Errorf("fake DNS server saw %d queries; want >= 1 (the lookup must traverse the inline outbound)", n)
	}
}
