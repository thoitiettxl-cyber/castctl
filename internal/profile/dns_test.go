// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

// Per-profile DNS: parse, save round-trip, validation, and
// resolver precedence (own > WireGuard-imported >
// global-compat fallback > DoH default). All fixtures are fake; no live config
// is read. Secrets below are FAKE placeholders only.

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

const fakeSocksOutbound = `{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1080,"version":"5"}`
const fakeWGEndpoint = `{"type":"wireguard","tag":"wg-home","address":["10.0.0.2/32"],"private_key":"FAKE-PRIVKEY","peers":[{"address":"203.0.113.10","port":51820,"public_key":"FAKE-PUBKEY","allowed_ips":["0.0.0.0/0"]}]}`

func TestPerProfileDNSParseAndRoundTrip(t *testing.T) {
	data := singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"dns1"}}}`,
		`[`+fakeSocksOutbound+`]`, "", "",
	)
	cfg, err := ParseSingleConfig([]byte(data), "/base")
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Profiles["muse01"]
	if p == nil || !p.HasDNS() {
		t.Fatal("muse01 must carry a parsed per-profile dns block")
	}
	opts, err := p.ParsedDNS()
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Servers) != 1 || opts.Servers[0].Tag != "dns1" || opts.Final != "dns1" {
		t.Fatalf("ParsedDNS = %+v, want one server dns1 final dns1", opts)
	}
	// Save must preserve the raw block verbatim and never invent
	// one for a profile that did not carry it.
	entry, err := buildProfileEntry(p)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := entry.get("dns")
	if !ok {
		t.Fatal("buildProfileEntry must emit dns when present")
	}
	raw, err := rawOf(v)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"dns1"`) {
		t.Fatalf("saved dns block = %s, want it to name dns1", raw)
	}
	// A profile without dns stays without it on save.
	cfg2, err := ParseSingleConfig([]byte(`{"profiles":{"default":{}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	entry2, err := buildProfileEntry(cfg2.Profiles["default"])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := entry2.get("dns"); ok {
		t.Error("buildProfileEntry must not invent a dns key for a profile that did not carry one")
	}
}

func TestPerProfileDNSEmptyDetourRejected(t *testing.T) {
	data := singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353}],"final":"dns1"}}}`,
		`[`+fakeSocksOutbound+`]`, "", "",
	)
	if _, err := ParseSingleConfig([]byte(data), "/base"); err == nil {
		t.Fatal("per-profile dns server with an empty detour must be rejected (G2), got nil error")
	} else if !strings.Contains(err.Error(), "detour") {
		t.Fatalf("empty-detour error = %v, want it to name the detour", err)
	}
}

func TestPerProfileDNSCrossProfileDetourRejected(t *testing.T) {
	// Profile B's dns must not detour through profile A's inline
	// outbound tag: the reachable set is per-profile.
	data := singleFileJSON(
		`{"a":{"outbound":{"type":"socks","tag":"profile:a","server":"127.0.0.1","server_port":1080,"version":"5"}},"b":{"dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"profile:a"}],"final":"dns1"}}}`,
		``, "", "",
	)
	if _, err := ParseSingleConfig([]byte(data), "/base"); err == nil {
		t.Fatal("per-profile dns detour naming another profile's inline tag must be rejected, got nil error")
	}
}

func TestPerProfileDNSSelectorMemberOtherInlineDetourRejected(t *testing.T) {
	// F2 (loop 2, RED first): the same cross-profile detour,
	// reached only as a selector member of the profile's own
	// outbound, must also be rejected. The member tag resolves
	// to no global node (it is another profile's inline
	// outbound), so it must not enter the reachable set merely
	// by being queued as a member.
	data := singleFileJSON(
		`{"a":{"outbound":"sel","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"profile:b"}],"final":"dns1"}},"b":{"outbound":{"type":"socks","tag":"profile:b","server":"127.0.0.1","server_port":1082,"version":"5"}}}`,
		`[{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1080,"version":"5"},{"type":"selector","tag":"sel","outbounds":["proxy-sg","profile:b"]}]`, "", "",
	)
	if _, err := ParseSingleConfig([]byte(data), "/base"); err == nil {
		t.Fatal("per-profile dns detour naming another profile's inline tag via a selector member must be rejected, got nil error")
	}
}

func TestPerProfileDNSCoexistenceRejected(t *testing.T) {
	data := singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"dns1"}}}`,
		`[`+fakeSocksOutbound+`]`, "",
		`{"servers":[{"tag":"gdns","type":"tcp","server":"127.0.0.1","server_port":5354,"detour":"proxy-sg"}],"final":"gdns"}`,
	)
	if _, err := ParseSingleConfig([]byte(data), "/base"); err == nil {
		t.Fatal("profile dns + top-level dns coexistence must exit 2 (G1), got nil error")
	} else if ExitCode(err) != 2 {
		t.Fatalf("coexistence error exit code = %d, want 2", ExitCode(err))
	} else if !strings.Contains(err.Error(), "by hand") || strings.Contains(err.Error(), "config migrate") {
		t.Fatalf("coexistence error = %v, want 'by hand' and no 'config migrate' pointer", err)
	}
}

func TestResolveProfileDNSPrecedence(t *testing.T) {
	// (i) Own block wins over everything, including WG state and
	// the global section (global is refused at parse with own
	// present, so the own-wins case is built by hand here).
	own, err := parseDNS([]byte(`{"servers":[{"tag":"own","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"own"}`))
	if err != nil {
		t.Fatal(err)
	}
	prof := &Profile{Name: "muse01", Outbound: OutboundRef{Kind: OutboundTag, Tag: "proxy-sg", Type: "socks", From: "outbound"}, DNS: own, dnsPresent: true}
	ownSingle := &SingleConfig{Profiles: map[string]*Profile{"muse01": prof}}
	res, err := ResolveProfileDNS(prof, ownSingle)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != DNSSourceProfile || res.Options.Servers[0].Tag != "own" {
		t.Fatalf("own branch: source=%q server=%q, want profile/own", res.Source, res.Options.Servers[0].Tag)
	}

	// (ii) WireGuard-imported DNS beats the DoH default.
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"wg-home"}}`,
		``, `[`+fakeWGEndpoint+`]`, "",
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	cfg.WireGuardDNS = map[string][]string{"wg-home": {"10.2.0.1"}}
	res, err = ResolveProfileDNS(cfg.Profiles["muse01"], cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != DNSSourceWireGuard {
		t.Fatalf("WG branch: source=%q, want wireguard", res.Source)
	}
	if len(res.Options.Servers) != 2 || res.Options.Servers[0].Tag == "" {
		t.Fatalf("WG branch servers = %+v, want the WG server plus the appended local bootstrap server", res.Options.Servers)
	}
	if res.Options.Servers[1].Tag != LocalBootstrapServerTag || res.Options.Servers[1].Type != "local" {
		t.Fatalf("WG branch second server = %+v, want the synthesised local bootstrap server", res.Options.Servers[1])
	}
	if d := detourOf(res.Options.Servers[0].Options); d != "wg-home" {
		t.Fatalf("WG branch detour = %q, want wg-home", d)
	}

	// (iii) Default DoH for a direct profile: detour is the
	// synthesized per-profile direct tag, never the empty "direct".
	cfg2, err := ParseSingleConfig([]byte(`{"profiles":{"default":{}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	res, err = ResolveProfileDNS(cfg2.Profiles["default"], cfg2)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != DNSSourceDefault {
		t.Fatalf("default branch: source=%q, want default", res.Source)
	}
	if res.SynthesizedDirectTag == "" || res.SynthesizedDirectTag == "direct" {
		t.Fatalf("default branch synthesized tag = %q, want a non-empty per-profile tag", res.SynthesizedDirectTag)
	}
	if d := detourOf(res.Options.Servers[0].Options); d != res.SynthesizedDirectTag {
		t.Fatalf("default branch detour = %q, want synthesized tag %q", d, res.SynthesizedDirectTag)
	}
	if len(res.Options.Servers) != 2 || res.Options.Servers[0].Type != "https" {
		t.Fatalf("default branch server = %+v, want the https server plus the appended local bootstrap server", res.Options.Servers)
	}
	if res.Options.Servers[1].Tag != LocalBootstrapServerTag || res.Options.Servers[1].Type != "local" {
		t.Fatalf("default branch second server = %+v, want the synthesised local bootstrap server", res.Options.Servers[1])
	}
	if res.Options.Final != defaultDNSServerTag {
		t.Fatalf("default branch final = %q, want %q (the local server is never final)", res.Options.Final, defaultDNSServerTag)
	}

	// (iii-b) Default DoH for a tag profile detours to its own tag.
	res, err = ResolveProfileDNS(cfg.Profiles["muse01"], cfgWithNoWG(t, cfg))
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != DNSSourceDefault || detourOf(res.Options.Servers[0].Options) != "wg-home" {
		t.Fatalf("tag default branch: source=%q detour=%q, want default/wg-home", res.Source, detourOf(res.Options.Servers[0].Options))
	}

	// (iv) Global-compat fallback only when no per-profile dns
	// exists, with a warning naming `config migrate --write`
	// as the distributing tool (since G4).
	cfg3, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "",
		`{"servers":[{"tag":"gdns","type":"tcp","server":"127.0.0.1","server_port":5354,"detour":"proxy-sg"}],"final":"gdns"}`,
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	res, err = ResolveProfileDNS(cfg3.Profiles["muse01"], cfg3)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != DNSSourceGlobalCompat || res.Options.Servers[0].Tag != "gdns" {
		t.Fatalf("compat branch: source=%q server=%q, want global-compat/gdns", res.Source, res.Options.Servers[0].Tag)
	}
	if !strings.Contains(res.Warning, "config migrate") || strings.Contains(res.Warning, "by hand") {
		t.Fatalf("compat warning = %q, want a 'config migrate' pointer and no 'by hand'", res.Warning)
	}
}

// TestResolveProfileDNSSynthesisesLocalBootstrapServer (Seam A,
// R6): every precedence branch appends exactly one dedicated
// "local" server — type local, no detour, prefer_go=false,
// never final, never rule-targeted — and reports it via
// LocalServerTag. A clean user-defined "local" server is
// reused; a wrong-type or detouring one fails closed; no
// resolver means no synthesis.
func TestResolveProfileDNSSynthesisesLocalBootstrapServer(t *testing.T) {
	assertLocalServer := func(t *testing.T, res *ResolvedDNS, wantFinal string) {
		t.Helper()
		if res.LocalServerTag != LocalBootstrapServerTag {
			t.Fatalf("LocalServerTag = %q, want %q", res.LocalServerTag, LocalBootstrapServerTag)
		}
		if res.Options.Final == LocalBootstrapServerTag {
			t.Fatalf("final = %q; the local server must never be final", res.Options.Final)
		}
		if wantFinal != "" && res.Options.Final != wantFinal {
			t.Fatalf("final = %q, want %q", res.Options.Final, wantFinal)
		}
		var local *option.DNSServerOptions
		for i := range res.Options.Servers {
			if res.Options.Servers[i].Tag == LocalBootstrapServerTag {
				local = &res.Options.Servers[i]
			}
		}
		if local == nil {
			t.Fatalf("no server tagged %q in %+v", LocalBootstrapServerTag, res.Options.Servers)
		}
		if local.Type != "local" {
			t.Fatalf("local server type = %q, want local", local.Type)
		}
		if d := detourOf(local.Options); d != "" {
			t.Fatalf("local server detour = %q, want none", d)
		}
		lo, ok := local.Options.(*option.LocalDNSServerOptions)
		if !ok {
			t.Fatalf("local server options = %T, want *option.LocalDNSServerOptions", local.Options)
		}
		if lo.PreferGo {
			t.Fatalf("local server prefer_go = true, want false (sing-box default)")
		}
		if len(res.Options.Rules) != 0 {
			// These fixtures define no rules; synthesis must
			// add none (the local server is never
			// rule-targeted).
			t.Fatalf("rules = %+v, want none: synthesis must not add rules", res.Options.Rules)
		}
	}

	// (1) Own block.
	own, err := parseDNS([]byte(`{"servers":[{"tag":"own","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"own"}`))
	if err != nil {
		t.Fatal(err)
	}
	prof := &Profile{Name: "muse01", Outbound: OutboundRef{Kind: OutboundTag, Tag: "proxy-sg", Type: "socks", From: "outbound"}, DNS: own, dnsPresent: true}
	res, err := ResolveProfileDNS(prof, &SingleConfig{Profiles: map[string]*Profile{"muse01": prof}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Options.Servers) != 2 {
		t.Fatalf("own branch servers = %d, want 2 (own + local)", len(res.Options.Servers))
	}
	assertLocalServer(t, res, "own")
	// Re-resolving must not accumulate local servers, and the
	// profile value must not have been mutated.
	res2, err := ResolveProfileDNS(prof, &SingleConfig{Profiles: map[string]*Profile{"muse01": prof}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Options.Servers) != 2 {
		t.Fatalf("second resolve servers = %d, want 2", len(res2.Options.Servers))
	}
	if again, err := prof.ParsedDNS(); err != nil || len(again.Servers) != 1 {
		t.Fatalf("profile DNS mutated by resolve: servers=%d err=%v", len(again.Servers), err)
	}

	// (2) WireGuard branch.
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"wg-home"}}`,
		``, `[`+fakeWGEndpoint+`]`, "",
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	cfg.WireGuardDNS = map[string][]string{"wg-home": {"10.2.0.1"}}
	res, err = ResolveProfileDNS(cfg.Profiles["muse01"], cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Options.Servers) != 2 {
		t.Fatalf("WG branch servers = %d, want 2", len(res.Options.Servers))
	}
	assertLocalServer(t, res, "castctl-doh-1")

	// (3) Global-compat branch.
	cfg3, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "",
		`{"servers":[{"tag":"gdns","type":"tcp","server":"127.0.0.1","server_port":5354,"detour":"proxy-sg"}],"final":"gdns"}`,
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	res, err = ResolveProfileDNS(cfg3.Profiles["muse01"], cfg3)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Options.Servers) != 2 {
		t.Fatalf("compat branch servers = %d, want 2", len(res.Options.Servers))
	}
	assertLocalServer(t, res, "gdns")

	// (4) Default branch.
	cfg2, err := ParseSingleConfig([]byte(`{"profiles":{"default":{}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	res, err = ResolveProfileDNS(cfg2.Profiles["default"], cfg2)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Options.Servers) != 2 {
		t.Fatalf("default branch servers = %d, want 2", len(res.Options.Servers))
	}
	assertLocalServer(t, res, defaultDNSServerTag)

	// No resolver at all: no synthesis.
	res, err = ResolveProfileDNS(cfg2.Profiles["default"], nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != DNSSourceNone || res.Options != nil || res.LocalServerTag != "" {
		t.Fatalf("none branch = %+v, want DNSSourceNone with no options and no local tag", res)
	}
}

func TestResolveProfileDNSLocalTagReconciliation(t *testing.T) {
	// Clean user-defined "local" server (global section, which
	// has no detour requirement): reused as-is, not duplicated.
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "",
		`{"servers":[{"tag":"local","type":"local"},{"tag":"gdns","type":"tcp","server":"127.0.0.1","server_port":5354,"detour":"proxy-sg"}],"final":"gdns"}`,
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ResolveProfileDNS(cfg.Profiles["muse01"], cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Options.Servers) != 2 || res.LocalServerTag != LocalBootstrapServerTag {
		t.Fatalf("reuse: servers=%+v localTag=%q, want 2 servers reusing the user-defined local server", res.Options.Servers, res.LocalServerTag)
	}
	if res.Options.Final != "gdns" {
		t.Fatalf("reuse: final = %q, want gdns", res.Options.Final)
	}

	// Wrong type under the "local" tag: fail closed.
	cfgBad, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "",
		`{"servers":[{"tag":"local","type":"tcp","server":"127.0.0.1","server_port":5354,"detour":"proxy-sg"}],"final":"local"}`,
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveProfileDNS(cfgBad.Profiles["muse01"], cfgBad); err == nil || !strings.Contains(err.Error(), `tag "local" is type "tcp"`) {
		t.Fatalf("wrong-type local tag: err=%v, want a fail-closed error naming the tag and type", err)
	}

	// Detouring "local" server: fail closed.
	cfgDetour, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "",
		`{"servers":[{"tag":"local","type":"local","detour":"proxy-sg"},{"tag":"gdns","type":"tcp","server":"127.0.0.1","server_port":5354,"detour":"proxy-sg"}],"final":"gdns"}`,
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveProfileDNS(cfgDetour.Profiles["muse01"], cfgDetour); err == nil || !strings.Contains(err.Error(), "detour") {
		t.Fatalf("detouring local tag: err=%v, want a fail-closed error naming the detour", err)
	}

	// Hand-built profile block with a clean local server
	// (parse-time validation requires detours in profile
	// blocks, so this shape is only reachable hand-built):
	// reused, not duplicated.
	own, err := parseDNS([]byte(`{"servers":[{"tag":"local","type":"local"},{"tag":"own","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"own"}`))
	if err != nil {
		t.Fatal(err)
	}
	prof := &Profile{Name: "muse01", Outbound: OutboundRef{Kind: OutboundTag, Tag: "proxy-sg", Type: "socks", From: "outbound"}, DNS: own, dnsPresent: true}
	res, err = ResolveProfileDNS(prof, &SingleConfig{Profiles: map[string]*Profile{"muse01": prof}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Options.Servers) != 2 {
		t.Fatalf("hand-built reuse: servers = %d, want 2", len(res.Options.Servers))
	}
}

func TestResolveProfileDNSNoWarningForPerProfileOnly(t *testing.T) {
	// ResolveProfileDNS sets Warning only when the legacy
	// (top-level) form is present: a per-profile-only config
	// resolves silently, as does a config with no resolver
	// at all (synthesised default). The warning itself is
	// printed only when a runtime is built (see
	// internal/commands/runtime.go), never on read paths
	// such as profile show/list.
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"dns1"}}}`,
		`[`+fakeSocksOutbound+`]`, "", "",
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ResolveProfileDNS(cfg.Profiles["muse01"], cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != DNSSourceProfile || res.Warning != "" {
		t.Fatalf("per-profile-only: source=%q warning=%q; want profile and no warning", res.Source, res.Warning)
	}

	cfg2, err := ParseSingleConfig([]byte(`{"profiles":{"default":{}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	res, err = ResolveProfileDNS(cfg2.Profiles["default"], cfg2)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != DNSSourceDefault || res.Warning != "" {
		t.Fatalf("no-resolver: source=%q warning=%q; want default and no warning", res.Source, res.Warning)
	}
}

func TestSynthesizedDirectTagReserved(t *testing.T) {
	// The synthesised tag castctl-direct:<profile> is reserved:
	// no config outbound, endpoint, or inline outbound may carry
	// it, or the synthesised DoH default would detour through a
	// config-defined outbound instead of the direct path.
	collidingWG := `{"type":"wireguard","tag":"castctl-direct:alice","address":["10.0.0.2/32"],"private_key":"FAKE-PRIVKEY","peers":[{"address":"203.0.113.10","port":51820,"public_key":"FAKE-PUBKEY","allowed_ips":["0.0.0.0/0"]}]}`
	cases := []struct {
		name string
		data string
	}{
		{
			name: "endpoint collision",
			data: singleFileJSON(`{"alice":{}}`, "", `[`+collidingWG+`]`, ""),
		},
		{
			name: "socks outbound collision",
			data: singleFileJSON(`{"alice":{}}`, `[{"type":"socks","tag":"castctl-direct:alice","server":"127.0.0.1","server_port":1080,"version":"5"}]`, "", ""),
		},
		{
			name: "inline outbound collision",
			data: singleFileJSON(`{"alice":{"outbound":{"type":"socks","tag":"castctl-direct:alice","server":"127.0.0.1","server_port":1080,"version":"5"}}}`, "", "", ""),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSingleConfig([]byte(tc.data), "/base")
			if err == nil {
				t.Fatal("config tag castctl-direct:alice must be rejected, got nil error")
			}
			for _, want := range []string{"castctl-direct:alice", "reserved"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %v, want it to name %q", err, want)
				}
			}
			if ExitCode(err) != 2 {
				t.Errorf("ExitCode = %d, want 2", ExitCode(err))
			}
		})
	}
}

func TestSynthesizedDirectTagKeySharingCollision(t *testing.T) {
	// Direct profile alice + a colliding endpoint sharing a key
	// with another profile's endpoint: the reservation must fail
	// the config at parse, before any key-sharing or runtime
	// lookup could dial the colliding outbound.
	ep := func(tag, key string) string {
		return `{"type":"wireguard","tag":"` + tag + `","address":["10.0.0.2/32"],"private_key":"` + key + `","peers":[{"address":"203.0.113.10","port":51820,"public_key":"FAKE-PUBKEY","allowed_ips":["0.0.0.0/0"]}]}`
	}
	data := singleFileJSON(
		`{"alice":{},"beta":{"outbound":"wg-b"}}`, "",
		`[`+ep("castctl-direct:alice", "FAKE-KEY")+`,`+ep("wg-b", "FAKE-KEY")+`]`, "",
	)
	_, err := ParseSingleConfig([]byte(data), "/base")
	if err == nil {
		t.Fatal("colliding endpoint tag must be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "castctl-direct:alice") || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("error = %v, want it to name the reserved colliding tag", err)
	}
	if strings.Contains(err.Error(), "FAKE-KEY") {
		t.Error("error contains the private key value")
	}
}

func TestWireGuardBranchWarnsWhenGlobalSectionShadowed(t *testing.T) {
	// WG branch shadowing a PRESENT global section must be
	// observable: a warning on the same stderr channel as the
	// compat warning (ResolvedDNS.Warning, printed by the
	// runtime), never written into the config file.
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"wg-home"},"other":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, `[`+fakeWGEndpoint+`]`,
		`{"servers":[{"tag":"gdns","type":"tcp","server":"127.0.0.1","server_port":5354,"detour":"proxy-sg"}],"final":"gdns"}`,
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	cfg.WireGuardDNS = map[string][]string{"wg-home": {"10.2.0.1"}}
	res, err := ResolveProfileDNS(cfg.Profiles["muse01"], cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != DNSSourceWireGuard {
		t.Fatalf("WG branch: source=%q, want wireguard", res.Source)
	}
	if res.Warning == "" || !strings.Contains(res.Warning, "top-level dns") ||
		!strings.Contains(res.Warning, "WireGuard DNS takes precedence") ||
		!strings.Contains(res.Warning, "by hand") || strings.Contains(res.Warning, "config migrate") {
		t.Fatalf("WG branch warning = %q, want it to name the shadowed top-level dns section, note WireGuard precedence, and direct hand-removal without prescribing config migrate", res.Warning)
	}
	// A non-WG profile in the same file still gets the compat
	// warning as before (naming `config migrate --write`).
	res, err = ResolveProfileDNS(cfg.Profiles["other"], cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != DNSSourceGlobalCompat {
		t.Fatalf("non-WG branch: source=%q, want global-compat", res.Source)
	}
	if !strings.Contains(res.Warning, "config migrate") || strings.Contains(res.Warning, "by hand") {
		t.Fatalf("compat warning = %q, want a 'config migrate' pointer and no 'by hand'", res.Warning)
	}
}

func TestPerProfileDNSWireGuardKeySharingReachable(t *testing.T) {
	// Reachable second tag: alpha's outbound is a selector over
	// wg-a and wg-b (same fake key), and its own dns detours to
	// wg-a — reachable, so the failure must be the key-sharing
	// error itself, not an earlier dangling-reference refusal.
	ep := func(tag, key string) string {
		return `{"type":"wireguard","tag":"` + tag + `","address":["10.0.0.2/32"],"private_key":"` + key + `","peers":[{"address":"203.0.113.10","port":51820,"public_key":"FAKE-PUBKEY","allowed_ips":["0.0.0.0/0"]}]}`
	}
	data := singleFileJSON(
		`{"alpha":{"outbound":"sel","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"wg-a"}],"final":"dns1"}}}`,
		`[{"type":"selector","tag":"sel","outbounds":["wg-a","wg-b"]}]`,
		`[`+ep("wg-a", "FAKE-KEY")+`,`+ep("wg-b", "FAKE-KEY")+`]`, "",
	)
	_, err := ParseSingleConfig([]byte(data), "/base")
	if err == nil {
		t.Fatal("reachable dns detour sharing a WireGuard key with the profile outbound must be rejected, got nil error")
	}
	msg := err.Error()
	for _, want := range []string{"wireguard private key shared", "alpha", "dns", "wg-a", "wg-b"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error = %q, want it to name %q", msg, want)
		}
	}
	if strings.Contains(msg, "dangling") {
		t.Errorf("error = %q, want the key-sharing error, not a dangling-reference refusal", msg)
	}
	if strings.Contains(msg, "FAKE-KEY") {
		t.Error("error contains the private key value")
	}
}

func TestRedactProfileIncludesPerProfileDNS(t *testing.T) {
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"dns1"}}}`,
		`[`+fakeSocksOutbound+`]`, "", "",
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := RedactProfile(cfg.Profiles["muse01"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(redacted), `"dns"`) || !strings.Contains(string(redacted), `"dns1"`) {
		t.Fatalf("profile show rendering must include the per-profile dns block, got: %s", redacted)
	}
}

func TestWireGuardDNSMapParseAndSave(t *testing.T) {
	data := singleFileJSON(
		`{"muse01":{"outbound":"wg-home"}}`,
		``, `[`+fakeWGEndpoint+`]`, "",
	)
	// wireguard_dns is a top-level key alongside the others.
	data = strings.TrimSuffix(data, "}") + `,"wireguard_dns":{"wg-home":["10.2.0.1","10.2.0.2"]}}`
	cfg, err := ParseSingleConfig([]byte(data), "/base")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.WireGuardDNS["wg-home"]) != 2 {
		t.Fatalf("WireGuardDNS = %v, want 2 servers for wg-home", cfg.WireGuardDNS)
	}
	// Save preserves it verbatim.
	root, err := buildSingleFileOrdered(cfg)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := root.get("wireguard_dns")
	if !ok {
		t.Fatal("buildSingleFileOrdered must emit wireguard_dns when present")
	}
	raw, err := rawOf(v)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "10.2.0.1") {
		t.Fatalf("saved wireguard_dns = %s, want it to carry 10.2.0.1", raw)
	}
	// Unknown endpoint tag is rejected.
	bad := strings.Replace(data, `"wg-home":["10.2.0.1","10.2.0.2"]`, `"wg-nope":["10.2.0.1"]`, 1)
	if _, err := ParseSingleConfig([]byte(bad), "/base"); err == nil {
		t.Fatal("wireguard_dns naming a missing endpoint must be rejected, got nil error")
	}
}

// TestWireGuardKeySharingGlobalVsDistributedDifferential (F5f,
// loop 2, TEST-ONLY): the same WireGuard key-sharing fixture
// must give the same accept/reject verdict in the global form
// (top-level dns detour) and in the distributed form (the
// per-profile block distribution would write). The fail-closed
// direction is what matters: whenever the global form rejects,
// the distributed form must reject too, with the key-sharing
// error, never echoing the key value. Validation semantics are
// NOT changed to force equivalence.
func TestWireGuardKeySharingGlobalVsDistributedDifferential(t *testing.T) {
	ep := func(tag, key string) string {
		return `{"type":"wireguard","tag":"` + tag + `","address":["10.0.0.2/32"],"private_key":"` + key + `","peers":[{"address":"203.0.113.10","port":51820,"public_key":"FAKE-PUBKEY","allowed_ips":["0.0.0.0/0"]}]}`
	}
	outbounds := `[{"type":"selector","tag":"sel","outbounds":["wg-a","wg-b"]}]`
	for _, tc := range []struct {
		name   string
		keyA   string
		keyB   string
		reject bool
	}{
		{name: "shared key rejects both forms", keyA: "FAKE-KEY", keyB: "FAKE-KEY", reject: true},
		{name: "distinct keys accept both forms", keyA: "FAKE-KEY-A", keyB: "FAKE-KEY-B", reject: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoints := `[` + ep("wg-a", tc.keyA) + `,` + ep("wg-b", tc.keyB) + `]`
			global := singleFileJSON(
				`{"alpha":{"outbound":"sel"}}`,
				outbounds, endpoints,
				`{"servers":[{"tag":"gdns","type":"tcp","server":"127.0.0.1","server_port":5354,"detour":"wg-a"}],"final":"gdns"}`,
			)
			distributed := singleFileJSON(
				`{"alpha":{"outbound":"sel","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"wg-a"}],"final":"dns1"}}}`,
				outbounds, endpoints, "",
			)
			for _, form := range []struct {
				name string
				data string
			}{
				{name: "global", data: global},
				{name: "distributed", data: distributed},
			} {
				_, err := ParseSingleConfig([]byte(form.data), "/base")
				if tc.reject && err == nil {
					t.Errorf("%s form must reject the shared-key fixture, got nil error", form.name)
					continue
				}
				if !tc.reject && err != nil {
					t.Errorf("%s form must accept the distinct-key fixture, got: %v", form.name, err)
					continue
				}
				if tc.reject {
					msg := err.Error()
					for _, want := range []string{"wireguard private key shared", "alpha", "dns", "wg-a", "wg-b"} {
						if !strings.Contains(msg, want) {
							t.Errorf("%s form error = %q; want it to name %q", form.name, msg, want)
						}
					}
					if strings.Contains(msg, tc.keyA) {
						t.Errorf("%s form error echoes the private key value", form.name)
					}
				}
			}
		})
	}
}

func TestPerProfileDNSWireGuardKeySharing(t *testing.T) {
	// Same key via the profile's outbound (wg-a) and its own dns
	// detour (wg-b) is an error naming the profile and "dns".
	ep := func(tag, key string) string {
		return `{"type":"wireguard","tag":"` + tag + `","address":["10.0.0.2/32"],"private_key":"` + key + `","peers":[{"address":"203.0.113.10","port":51820,"public_key":"FAKE-PUBKEY","allowed_ips":["0.0.0.0/0"]}]}`
	}
	data := singleFileJSON(
		`{"alpha":{"outbound":"wg-a","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"wg-b"}],"final":"dns1"}}}`,
		``, `[`+ep("wg-a", "FAKE-KEY")+`,`+ep("wg-b", "FAKE-KEY")+`]`, "",
	)
	if _, err := ParseSingleConfig([]byte(data), "/base"); err == nil {
		t.Fatal("per-profile dns detour sharing a WireGuard key with the profile outbound must be rejected, got nil error")
	}
	// Same tag for outbound and dns detour is one config, not
	// an error.
	data2 := singleFileJSON(
		`{"alpha":{"outbound":"wg-a","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"wg-a"}],"final":"dns1"}}}`,
		``, `[`+ep("wg-a", "FAKE-KEY")+`]`, "",
	)
	if _, err := ParseSingleConfig([]byte(data2), "/base"); err != nil {
		t.Fatalf("dns detour naming the profile's own endpoint tag must be allowed, got: %v", err)
	}
}

func TestAuthorInterimDNSRefusesWhenPerProfileDNSExists(t *testing.T) {
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"dns1"}}}`,
		`[`+fakeSocksOutbound+`]`, "", "",
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	authored, refusal := authorInterimDNS(cfg, nil)
	if authored {
		t.Fatal("authorInterimDNS must not author a global section when a profile already has its own dns block")
	}
	if refusal == "" {
		t.Error("authorInterimDNS refusal must name the reason, got empty refusal")
	}
}

func cfgWithNoWG(t *testing.T, cfg *SingleConfig) *SingleConfig {
	t.Helper()
	out := *cfg
	out.WireGuardDNS = nil
	return &out
}

// TestCompatWarningTextVerbatim (N-b, loop 3): the compat
// warning text (dns.go:201) is pinned VERBATIM, not just by
// presence/trigger — a wording drift that re-prescribes a
// refusing action or drops the distributing tool must fail
// here. The text itself is unchanged by loop 3.
func TestCompatWarningTextVerbatim(t *testing.T) {
	t.Parallel()
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "",
		`{"servers":[{"tag":"gdns","type":"tcp","server":"127.0.0.1","server_port":5354,"detour":"proxy-sg"}],"final":"gdns"}`,
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ResolveProfileDNS(cfg.Profiles["muse01"], cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := `castctl: top-level dns section is deprecated and will become an error in a later release: run "config migrate --write" to distribute it into profile entries (see docs/config.md)`
	if res.Warning != want {
		t.Errorf("compat warning = %q; want verbatim %q", res.Warning, want)
	}
}
