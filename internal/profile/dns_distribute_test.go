// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

// G4 DNS distribution: `config migrate` copies the top-level dns
// section verbatim into every profile's own dns block (detours
// filled/kept/refused per profile) and removes the top-level key
// in the same atomic write. All fixtures are fake; no live config
// is read. No secret values appear below (FAKE placeholders only).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// distributedGlobalDNS is a multi-field global section: two
// servers (one https with TLS/path fields, one tcp with a dialer
// field), one rule routing by domain suffix to dns1, and client
// options. Both servers carry NO detour, so distribution must
// fill each profile's own detour tag.
const distributedGlobalDNS = `{"servers":[{"tag":"dns1","type":"https","server":"1.1.1.1","server_port":443,"path":"/dns-query","tls":{"enabled":true,"server_name":"one.one.one.one"}},{"tag":"dns2","type":"tcp","server":"127.0.0.1","server_port":5353,"connect_timeout":"2s"}],"rules":[{"domain_suffix":["example.com"],"action":"route","server":"dns1"}],"final":"dns1","reverse_mapping":true,"strategy":"prefer_ipv4","timeout":"5s","disable_cache":true,"cache_capacity":100}`

func writeDistributedFixture(t *testing.T, base, profiles, outbounds, endpoints, dns string) string {
	t.Helper()
	path := filepath.Join(base, "config.json")
	doc := `{"profiles":` + profiles + `,"outbounds":` + outbounds
	if endpoints != "" {
		doc += `,"endpoints":` + endpoints
	}
	if dns != "" {
		doc += `,"dns":` + dns
	}
	doc += `}`
	writeFile(t, path, doc, 0o600)
	return path
}

func profileDoc(t *testing.T, path, name string) map[string]any {
	t.Helper()
	doc := readJSONFile(t, path)
	profiles, _ := doc["profiles"].(map[string]any)
	if profiles == nil {
		t.Fatalf("file %s has no profiles: %v", path, doc)
	}
	entry, _ := profiles[name].(map[string]any)
	if entry == nil {
		t.Fatalf("file %s has no profile %q: %v", path, name, doc)
	}
	return entry
}

func profileDNSDoc(t *testing.T, path, name string) map[string]any {
	t.Helper()
	entry := profileDoc(t, path, name)
	dnsDoc, _ := entry["dns"].(map[string]any)
	if dnsDoc == nil {
		t.Fatalf("profile %q in %s has no dns block: %v", name, path, entry)
	}
	return dnsDoc
}

func dnsServers(t *testing.T, dnsDoc map[string]any) []map[string]any {
	t.Helper()
	raw, _ := dnsDoc["servers"].([]any)
	if len(raw) == 0 {
		t.Fatalf("dns block has no servers: %v", dnsDoc)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, s := range raw {
		srv, _ := s.(map[string]any)
		if srv == nil {
			t.Fatalf("dns server is not an object: %v", s)
		}
		out = append(out, srv)
	}
	return out
}

func TestMigrateDistributesTopLevelDNSVerbatimMultiProfile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	profiles := `{"p1":{"outbound":"proxy-sg"},"p2":{"outbound":"proxy-sg"},"p3":{"outbound":{"type":"socks","tag":"profile:p3","server":"127.0.0.1","server_port":1082,"version":"5"}},"p4":{}}`
	path := writeDistributedFixture(t, base, profiles, `[`+fakeSocksOutbound+`]`, "", distributedGlobalDNS)
	before, _ := os.ReadFile(path)

	// Dry-run: plan reports distribution, writes nothing.
	dry, err := Migrate(base, false)
	if err != nil {
		t.Fatal(err)
	}
	if !dry.WouldWrite || !dry.DNSDistributed {
		t.Errorf("dry-run = %+v; want would_write + dns_distributed", dry)
	}
	if dry.Migrated {
		t.Error("dry-run Migrated = true; want false")
	}
	afterDry, _ := os.ReadFile(path)
	if string(before) != string(afterDry) {
		t.Error("dry-run modified the file")
	}

	// --write: atomic mode 0600, distribution landed.
	written, err := Migrate(base, true)
	if err != nil {
		t.Fatal(err)
	}
	if !written.Migrated || written.Reason != "dns-distributed" || !written.DNSDistributed {
		t.Errorf("write = %+v; want migrated + dns-distributed + dns_distributed", written)
	}
	if mode := fileMode(t, path); mode != 0o600 {
		t.Errorf("distributed config mode = %o; want 600", mode)
	}
	doc := readJSONFile(t, path)
	if _, ok := doc["dns"]; ok {
		t.Errorf("distributed config still carries a top-level dns section: %v", doc)
	}
	// Outbounds carried verbatim: the one socks outbound, same tag/server.
	outbounds, _ := doc["outbounds"].([]any)
	if len(outbounds) != 1 {
		t.Fatalf("outbounds = %v; want exactly the one socks outbound", doc["outbounds"])
	}
	ob, _ := outbounds[0].(map[string]any)
	if ob["tag"] != "proxy-sg" || ob["server"] != "127.0.0.1" || ob["server_port"] != float64(1080) {
		t.Errorf("outbound carried = %v; want proxy-sg 127.0.0.1:1080", ob)
	}

	// Each profile: whole block copied, detour = own tag
	// (synthesised direct tag for the direct profile).
	wantDetour := map[string]string{
		"p1": "proxy-sg",
		"p2": "proxy-sg",
		"p3": "profile:p3",
		"p4": "castctl-direct:p4",
	}
	for name, detour := range wantDetour {
		dnsDoc := profileDNSDoc(t, path, name)
		servers := dnsServers(t, dnsDoc)
		if len(servers) != 2 {
			t.Fatalf("profile %q servers = %d; want 2", name, len(servers))
		}
		for _, srv := range servers {
			if srv["detour"] != detour {
				t.Errorf("profile %q server %v detour = %v; want %q", name, srv["tag"], srv["detour"], detour)
			}
		}
		if servers[0]["tag"] != "dns1" || servers[0]["type"] != "https" ||
			servers[0]["server"] != "1.1.1.1" || servers[0]["server_port"] != float64(443) ||
			servers[0]["path"] != "/dns-query" {
			t.Errorf("profile %q dns1 = %v; want https 1.1.1.1:443 /dns-query", name, servers[0])
		}
		tlsDoc, _ := servers[0]["tls"].(map[string]any)
		if tlsDoc["server_name"] != "one.one.one.one" {
			t.Errorf("profile %q dns1 tls = %v; want server_name one.one.one.one", name, tlsDoc)
		}
		if servers[1]["tag"] != "dns2" || servers[1]["type"] != "tcp" ||
			servers[1]["connect_timeout"] != "2s" {
			t.Errorf("profile %q dns2 = %v; want tcp with connect_timeout 2s", name, servers[1])
		}
		if dnsDoc["final"] != "dns1" || dnsDoc["reverse_mapping"] != true ||
			dnsDoc["strategy"] != "prefer_ipv4" || dnsDoc["timeout"] != "5s" ||
			dnsDoc["disable_cache"] != true || dnsDoc["cache_capacity"] != float64(100) {
			t.Errorf("profile %q client options = %v; want final dns1, reverse_mapping, prefer_ipv4, 5s, disable_cache, cache_capacity 100", name, dnsDoc)
		}
		rules, _ := dnsDoc["rules"].([]any)
		if len(rules) != 1 {
			t.Fatalf("profile %q rules = %v; want 1 rule", name, dnsDoc["rules"])
		}
		rule, _ := rules[0].(map[string]any)
		if rule["server"] != "dns1" || rule["action"] != "route" {
			t.Errorf("profile %q rule = %v; want route to dns1", name, rule)
		}
	}

	// The distributed file loads, and each profile resolves
	// from its own block with its own detour.
	cfg, found, err := LoadSingleConfig(base)
	if err != nil || !found {
		t.Fatalf("LoadSingleConfig = found=%v err=%v; want the distributed file to load", found, err)
	}
	for name, detour := range wantDetour {
		res, err := ResolveProfileDNS(cfg.Profiles[name], cfg)
		if err != nil {
			t.Fatal(err)
		}
		if res.Source != DNSSourceProfile {
			t.Errorf("profile %q source = %q; want profile", name, res.Source)
		}
		if res.Warning != "" {
			t.Errorf("profile %q warning = %q; want none after distribution", name, res.Warning)
		}
		for _, srv := range res.Options.Servers {
			if d := detourOf(srv.Options); d != detour {
				t.Errorf("profile %q resolved detour = %q; want %q", name, d, detour)
			}
		}
	}
}

func TestMigrateDistributeDetourKeepOwnAndReachableOther(t *testing.T) {
	t.Parallel()
	// Own-tag detour is kept verbatim.
	home := t.TempDir()
	base := BaseDir(home)
	path := writeDistributedFixture(t, base,
		`{"p1":{"outbound":"proxy-sg"},"p2":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "",
		`{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"dns1"}`)
	if _, err := Migrate(base, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"p1", "p2"} {
		servers := dnsServers(t, profileDNSDoc(t, path, name))
		if servers[0]["detour"] != "proxy-sg" {
			t.Errorf("profile %q detour = %v; want own tag proxy-sg kept", name, servers[0]["detour"])
		}
	}

	// Reachable-but-different detour is kept verbatim: p1
	// selects through a selector whose members include
	// proxy-other; p2's own outbound IS proxy-other.
	home2 := t.TempDir()
	base2 := BaseDir(home2)
	otherSocks := `{"type":"socks","tag":"proxy-other","server":"127.0.0.1","server_port":1081,"version":"5"}`
	selector := `{"type":"selector","tag":"sel","outbounds":["proxy-sg","proxy-other"]}`
	path2 := writeDistributedFixture(t, base2,
		`{"p1":{"outbound":"sel"},"p2":{"outbound":"proxy-other"}}`,
		`[`+fakeSocksOutbound+`,`+otherSocks+`,`+selector+`]`, "",
		`{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-other"}],"final":"dns1"}`)
	if _, err := Migrate(base2, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"p1", "p2"} {
		servers := dnsServers(t, profileDNSDoc(t, path2, name))
		if servers[0]["detour"] != "proxy-other" {
			t.Errorf("profile %q detour = %v; want reachable proxy-other kept verbatim", name, servers[0]["detour"])
		}
	}
}

func TestMigrateDistributeDetourUnreachableRefuses(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	otherSocks := `{"type":"socks","tag":"proxy-other","server":"127.0.0.1","server_port":1081,"version":"5"}`
	path := writeDistributedFixture(t, base,
		`{"p1":{"outbound":"proxy-sg"},"p2":{"outbound":"proxy-other"}}`,
		`[`+fakeSocksOutbound+`,`+otherSocks+`]`, "",
		`{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"dns1"}`)
	before, _ := os.ReadFile(path)
	st1, _ := os.Stat(path)

	for _, write := range []bool{false, true} {
		result, err := Migrate(base, write)
		if err == nil {
			t.Fatalf("Migrate(write=%v) over an unreachable detour must refuse, got result %+v", write, result)
		}
		if ExitCode(err) != 2 {
			t.Errorf("Migrate(write=%v) exit code = %d; want 2", write, ExitCode(err))
		}
		if result == nil || !strings.Contains(result.DNSDistributionRefusal, `"p2"`) ||
			!strings.Contains(result.DNSDistributionRefusal, "proxy-sg") {
			t.Errorf("Migrate(write=%v) refusal = %+v; want it to name profile p2 and detour proxy-sg", write, result)
		}
		// Never silently rewrite: no detour value, no server
		// address, and no other value from the block is echoed.
		if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(result.DNSDistributionRefusal, "127.0.0.1") {
			t.Errorf("refusal echoes a server address value: err=%v refusal=%q", err, result.DNSDistributionRefusal)
		}
		after, _ := os.ReadFile(path)
		if string(before) != string(after) {
			t.Errorf("Migrate(write=%v) rewrote the file on refusal", write)
		}
	}
	st2, _ := os.Stat(path)
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Error("refused migrate rewrote the file; want no write (mtime changed)")
	}
}

func TestMigrateDistributeHostsAndFakeIPRefuse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		dns  string
		tag  string
	}{
		{
			name: "hosts",
			dns:  `{"servers":[{"tag":"hosts1","type":"hosts","path":["/etc/hosts"]},{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353}],"final":"dns1"}`,
			tag:  "hosts1",
		},
		{
			name: "fakeip",
			dns:  `{"servers":[{"tag":"fake1","type":"fakeip","inet4_range":"198.18.0.0/15"},{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353}],"final":"dns1"}`,
			tag:  "fake1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			base := BaseDir(home)
			path := writeDistributedFixture(t, base,
				`{"p1":{"outbound":"proxy-sg"}}`,
				`[`+fakeSocksOutbound+`]`, "", tc.dns)
			before, _ := os.ReadFile(path)
			result, err := Migrate(base, true)
			if err == nil {
				t.Fatalf("%s block must refuse distribution, got result %+v", tc.name, result)
			}
			if ExitCode(err) != 2 {
				t.Errorf("%s refusal exit code = %d; want 2", tc.name, ExitCode(err))
			}
			if !strings.Contains(err.Error(), tc.tag) {
				t.Errorf("%s refusal = %v; want it to name server %q", tc.name, err, tc.tag)
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Errorf("%s refusal rewrote the file", tc.name)
			}
		})
	}
}

func TestMigrateDistributeRefusesWireGuardShadowedProfile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	doc := `{"profiles":{"muse01":{"outbound":"wg-home"},"other":{"outbound":"proxy-sg"}},"outbounds":[` + fakeSocksOutbound + `],"endpoints":[` + fakeWGEndpoint + `],"wireguard_dns":{"wg-home":["10.2.0.1"]},"dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"dns1"}}`
	path := filepath.Join(base, "config.json")
	writeFile(t, path, doc, 0o600)
	before, _ := os.ReadFile(path)

	result, err := Migrate(base, true)
	if err == nil {
		t.Fatalf("distribution onto a WireGuard-shadowed profile must refuse, got result %+v", result)
	}
	if ExitCode(err) != 2 {
		t.Errorf("refusal exit code = %d; want 2", ExitCode(err))
	}
	if result == nil || !strings.Contains(result.DNSDistributionRefusal, `"muse01"`) ||
		!strings.Contains(result.DNSDistributionRefusal, "wg-home") {
		t.Errorf("refusal = %+v; want it to name profile muse01 and endpoint wg-home", result)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("refused migrate rewrote the file")
	}
}

func TestMigrateDistributeEmptyDNSRefuses(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	path := writeDistributedFixture(t, base,
		`{"p1":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "", `{}`)
	before, _ := os.ReadFile(path)
	result, err := Migrate(base, true)
	if err == nil {
		t.Fatalf("distributing an empty dns section must refuse, got result %+v", result)
	}
	if ExitCode(err) != 2 {
		t.Errorf("refusal exit code = %d; want 2", ExitCode(err))
	}
	if result == nil || result.DNSDistributionRefusal == "" {
		t.Errorf("refusal = %+v; want a recorded distribution refusal", result)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("refused migrate rewrote the file")
	}
}

func TestDistributeRefusesExistingPerProfileDNSBlock(t *testing.T) {
	t.Parallel()
	// A file with both forms cannot parse (G1), so this guard
	// is pinned at the distribution function itself, on a
	// hand-built config: an existing own block must refuse,
	// never be overwritten or merged.
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"dns1"}}}`,
		`[`+fakeSocksOutbound+`]`, "", "",
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	globalRaw := []byte(`{"servers":[{"tag":"gdns","type":"tcp","server":"127.0.0.1","server_port":5354,"detour":"proxy-sg"}],"final":"gdns"}`)
	global, err := parseDNS(globalRaw)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DNS = global
	cfg.rawDNS = globalRaw
	distributed, refusal, derr := distributeTopLevelDNS(cfg, "/base")
	if derr == nil {
		t.Fatalf("distributeTopLevelDNS with an existing own block must refuse, got distributed=%v refusal=%q", distributed, refusal)
	}
	if !strings.Contains(refusal, `"muse01"`) {
		t.Errorf("refusal = %q; want it to name profile muse01", refusal)
	}
	if distributed {
		t.Error("distributed = true on refusal; want false")
	}
	if cfg.Profiles["muse01"].DNS.Servers[0].Tag != "dns1" {
		t.Error("refused distribution mutated the existing own block")
	}
}

func TestMigrateDistributeDuplicateServerTagsRefuse(t *testing.T) {
	t.Parallel()
	// Duplicate server tags pass global validation (the global
	// check does not reject them) but fail per-profile
	// validation: the distributed candidate must refuse.
	home := t.TempDir()
	base := BaseDir(home)
	path := writeDistributedFixture(t, base,
		`{"p1":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "",
		`{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353},{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5354}],"final":"dns1"}`)
	before, _ := os.ReadFile(path)
	result, err := Migrate(base, true)
	if err == nil {
		t.Fatalf("duplicate server tags must refuse distribution, got result %+v", result)
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("refusal = %v; want it to name the duplicate-tag failure", err)
	}
	if result == nil || result.DNSDistributionRefusal == "" {
		t.Errorf("refusal = %+v; want a recorded distribution refusal", result)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("refused migrate rewrote the file")
	}
}

func TestMigrateDistributeIdempotentAndNoop(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	path := writeDistributedFixture(t, base,
		`{"p1":{"outbound":"proxy-sg"},"p2":{}}`,
		`[`+fakeSocksOutbound+`]`, "", distributedGlobalDNS)
	if _, err := Migrate(base, true); err != nil {
		t.Fatal(err)
	}
	distributedBytes, _ := os.ReadFile(path)
	st1, _ := os.Stat(path)

	// Second run, write and dry-run: already-migrated, no
	// rewrite, byte-identical, no distribution reported.
	for _, write := range []bool{true, false} {
		result, err := Migrate(base, write)
		if err != nil {
			t.Fatal(err)
		}
		if result.Migrated || result.Reason != "already-migrated" || result.DNSDistributed {
			t.Errorf("second Migrate(write=%v) = %+v; want already-migrated, no distribution", write, result)
		}
		if result.WouldWrite {
			t.Errorf("second Migrate(write=%v) WouldWrite = true; want false", write)
		}
	}
	after, _ := os.ReadFile(path)
	if string(distributedBytes) != string(after) {
		t.Error("second migrate changed the distributed file bytes")
	}
	st2, _ := os.Stat(path)
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Error("second migrate rewrote the file; want no write (mtime changed)")
	}

	// No-op: a per-profile-only config (no legacy form) is
	// already-migrated and untouched.
	home2 := t.TempDir()
	base2 := BaseDir(home2)
	path2 := writeDistributedFixture(t, base2,
		`{"p1":{"outbound":"proxy-sg","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"dns1"}}}`,
		`[`+fakeSocksOutbound+`]`, "", "")
	before2, _ := os.ReadFile(path2)
	result, err := Migrate(base2, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Migrated || result.Reason != "already-migrated" || result.DNSDistributed {
		t.Errorf("per-profile-only Migrate = %+v; want already-migrated no-op", result)
	}
	after2, _ := os.ReadFile(path2)
	if string(before2) != string(after2) {
		t.Error("per-profile-only migrate rewrote the file")
	}
}

func TestMigrateDistributeFromCrossDir(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	dest := filepath.Join(home, "dest")
	src := filepath.Join(home, "src")
	// The source carries legacy files for exactly the profiles
	// the destination already has, with identical settings, so
	// the destination is otherwise already-migrated and the
	// distribution gate passes (the cross-dir collision check
	// stands on identical settings; a bare source dir would
	// contribute a synthetic default entry and refuse).
	writeFile(t, filepath.Join(src, "config.json"), `{"auto_approve":"always","node_id":"MAIN-NODE","vm_id":"FAKE-VM"}`, 0o600)
	writeFile(t, filepath.Join(src, "profiles", "p1", "config.json"), `{"auto_approve":"off","node_id":"P1-NODE"}`, 0o600)
	srcBefore := snapshotDir(t, src)
	destProfiles := `{"default":{"cookies_file":` + quoteJSON(filepath.Join(src, "cookies.txt")) + `,"node_id":"MAIN-NODE","vm_id":"FAKE-VM","auto_approve":"always","outbound":"proxy-sg"},"p1":{"cookies_file":` + quoteJSON(filepath.Join(src, "profiles", "p1", "cookies.txt")) + `,"node_id":"P1-NODE","auto_approve":"off","outbound":"proxy-sg"}}`
	path := writeDistributedFixture(t, dest, destProfiles, `[`+fakeSocksOutbound+`]`, "", distributedGlobalDNS)

	// Dry-run through --from plumbing: plan only, nothing written.
	dry, err := MigrateFrom(src, dest, false)
	if err != nil {
		t.Fatal(err)
	}
	if !dry.WouldWrite || !dry.DNSDistributed {
		t.Errorf("--from dry-run = %+v; want would_write + dns_distributed", dry)
	}
	if dry.SourceDir != src || dry.DestinationDir != dest {
		t.Errorf("--from dry-run dirs = %q/%q; want %q/%q", dry.SourceDir, dry.DestinationDir, src, dest)
	}
	assertSameSnapshot(t, srcBefore, snapshotDir(t, src))

	// --write distributes into the destination only; the
	// source stays byte-identical.
	written, err := MigrateFrom(src, dest, true)
	if err != nil {
		t.Fatal(err)
	}
	if !written.Migrated || !written.DNSDistributed {
		t.Errorf("--from write = %+v; want migrated + dns_distributed", written)
	}
	assertSameSnapshot(t, srcBefore, snapshotDir(t, src))
	doc := readJSONFile(t, path)
	if _, ok := doc["dns"]; ok {
		t.Errorf("--from distributed config still carries a top-level dns section: %v", doc)
	}
	servers := dnsServers(t, profileDNSDoc(t, path, "p1"))
	if servers[0]["detour"] != "proxy-sg" {
		t.Errorf("--from distributed detour = %v; want proxy-sg", servers[0]["detour"])
	}
}

func TestMigrateDistributeWithPendingLegacyAdditionRefusesOverwrite(t *testing.T) {
	t.Parallel()
	// Distribution runs only onto an otherwise already-migrated
	// config (the authorInterimDNS gate): a pending legacy
	// profile addition keeps the run at refuse-overwrite, and
	// no distribution is attempted or reported.
	home := t.TempDir()
	base := BaseDir(home)
	path := writeDistributedFixture(t, base,
		`{"p1":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "", distributedGlobalDNS)
	writeFile(t, filepath.Join(base, "profiles", "work", "config.json"), `{"auto_approve":"off"}`, 0o600)
	before, _ := os.ReadFile(path)

	result, err := Migrate(base, true)
	if err == nil {
		t.Fatalf("migrate with a pending legacy addition must refuse-overwrite, got result %+v", result)
	}
	if ExitCode(err) != 2 {
		t.Errorf("refusal exit code = %d; want 2", ExitCode(err))
	}
	if result != nil && result.DNSDistributed {
		t.Errorf("result = %+v; distribution must not be reported when the gate refuses", result)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("refused migrate rewrote the file")
	}
}

// TestMigrateDistributeResultJSONShape pins the new result
// fields in the marshalled plan JSON (the CLI prints this
// shape): dns_distributed present when distributed, absent
// otherwise; dns_distribution_refusal present only on refusal.
func TestMigrateDistributeResultJSONShape(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	writeDistributedFixture(t, base,
		`{"p1":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "", distributedGlobalDNS)
	dry, err := Migrate(base, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(dry)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["dns_distributed"] != true {
		t.Errorf("dry-run JSON = %s; want dns_distributed true", raw)
	}
	if _, ok := doc["dns_distribution_refusal"]; ok {
		t.Errorf("dry-run JSON = %s; want no dns_distribution_refusal on success", raw)
	}
}

// TestMigrateDistributeZeroProfilesRefuses (F1a, loop 2, RED
// first): a non-empty top-level dns section with zero profiles
// must refuse, never silently delete the section. Both dry-run
// and --write refuse with exit 2 and leave the file
// byte-identical.
func TestMigrateDistributeZeroProfilesRefuses(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	path := writeDistributedFixture(t, base,
		`{}`,
		`[`+fakeSocksOutbound+`]`, "", distributedGlobalDNS)
	before, _ := os.ReadFile(path)
	for _, write := range []bool{false, true} {
		result, err := Migrate(base, write)
		if err == nil {
			t.Fatalf("Migrate(write=%v) over zero profiles + a dns section must refuse, got result %+v", write, result)
		}
		if ExitCode(err) != 2 {
			t.Errorf("Migrate(write=%v) exit code = %d; want 2", write, ExitCode(err))
		}
		if result == nil || result.DNSDistributed {
			t.Errorf("Migrate(write=%v) result = %+v; want no distribution reported", write, result)
		}
		if result == nil || result.DNSDistributionRefusal == "" ||
			!strings.Contains(result.DNSDistributionRefusal, "no profile") {
			t.Errorf("Migrate(write=%v) refusal = %+v; want a recorded refusal naming that no profile would receive a block", write, result)
		}
		after, _ := os.ReadFile(path)
		if string(before) != string(after) {
			t.Errorf("Migrate(write=%v) rewrote the file on refusal", write)
		}
	}
}

// TestMigrateDistributeZeroProfilesEmptySectionRefuses (F1b,
// loop 2, RED first): an empty ({}) top-level dns section with
// zero profiles must refuse too — the empty-section guard must
// not be the only guard, and no-profile deletion must not slip
// past it.
func TestMigrateDistributeZeroProfilesEmptySectionRefuses(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	path := writeDistributedFixture(t, base,
		`{}`,
		`[`+fakeSocksOutbound+`]`, "", `{}`)
	before, _ := os.ReadFile(path)
	result, err := Migrate(base, true)
	if err == nil {
		t.Fatalf("distributing an empty dns section over zero profiles must refuse, got result %+v", result)
	}
	if ExitCode(err) != 2 {
		t.Errorf("refusal exit code = %d; want 2", ExitCode(err))
	}
	if result == nil || result.DNSDistributionRefusal == "" {
		t.Errorf("refusal = %+v; want a recorded distribution refusal", result)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("refused migrate rewrote the file")
	}
}

// TestMigrateZeroProfilesNoDNSSectionIsNoop (F1c, loop 2, RED
// first): zero profiles and NO top-level dns section keeps the
// existing no-op behaviour — already-migrated, no refusal, no
// write.
func TestMigrateZeroProfilesNoDNSSectionIsNoop(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	path := writeDistributedFixture(t, base,
		`{}`,
		`[`+fakeSocksOutbound+`]`, "", "")
	before, _ := os.ReadFile(path)
	result, err := Migrate(base, true)
	if err != nil {
		t.Fatalf("zero profiles with no dns section must be a no-op, got error %v (result %+v)", err, result)
	}
	if result.Migrated || result.Reason != "already-migrated" || result.DNSDistributed || result.DNSDistributionRefusal != "" {
		t.Errorf("no-op Migrate = %+v; want already-migrated, no distribution, no refusal", result)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("no-op migrate rewrote the file")
	}
}

// TestDistributeRefusesAllNilProfileEntries (F1d, loop 2, RED
// first): when every profile entry is nil, no profile would
// receive a block, so distribution must refuse at the function
// level and leave the candidate's dns section untouched.
// Parsed configs cannot produce nil entries (see the F5d test),
// so this guard is pinned at the distribution function itself,
// like the existing-block guard.
func TestDistributeRefusesAllNilProfileEntries(t *testing.T) {
	t.Parallel()
	globalRaw := []byte(`{"servers":[{"tag":"gdns","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"gdns"}`)
	global, err := parseDNS(globalRaw)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &SingleConfig{
		Profiles: map[string]*Profile{"ghost": nil},
		DNS:      global,
		rawDNS:   globalRaw,
	}
	distributed, refusal, derr := distributeTopLevelDNS(cfg, "/base")
	if derr == nil {
		t.Fatalf("distributeTopLevelDNS with only nil profile entries must refuse, got distributed=%v refusal=%q", distributed, refusal)
	}
	if ExitCode(derr) != 2 {
		t.Errorf("refusal exit code = %d; want 2", ExitCode(derr))
	}
	if refusal == "" || !strings.Contains(refusal, "no profile") {
		t.Errorf("refusal = %q; want it to name that no profile would receive a block", refusal)
	}
	if distributed {
		t.Error("distributed = true on refusal; want false")
	}
	if cfg.DNS != global || string(cfg.rawDNS) != string(globalRaw) {
		t.Error("refused distribution mutated or removed the top-level dns section")
	}
	if cfg.Profiles["ghost"] != nil {
		t.Error("refused distribution materialised the nil profile entry")
	}
}

// TestMigrateDistributeSingleProfile (F1e, loop 2, RED first):
// one real profile + a section distributes as before — the
// no-recipient guard must not refuse a config that has a
// recipient.
func TestMigrateDistributeSingleProfile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	path := writeDistributedFixture(t, base,
		`{"p1":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "", distributedGlobalDNS)
	written, err := Migrate(base, true)
	if err != nil {
		t.Fatal(err)
	}
	if !written.Migrated || written.Reason != "dns-distributed" || !written.DNSDistributed {
		t.Errorf("write = %+v; want migrated + dns-distributed + dns_distributed", written)
	}
	doc := readJSONFile(t, path)
	if _, ok := doc["dns"]; ok {
		t.Errorf("distributed config still carries a top-level dns section: %v", doc)
	}
	servers := dnsServers(t, profileDNSDoc(t, path, "p1"))
	if servers[0]["detour"] != "proxy-sg" {
		t.Errorf("profile p1 detour = %v; want proxy-sg", servers[0]["detour"])
	}
}

// TestMigrateDistributeSelectorMemberOtherInlineDetourRefuses
// (F2, loop 2, RED first): a detour naming another profile's
// inline outbound, reached only as a selector member, must
// refuse distribution. The tag resolves to no global node, so
// it is not in the profile's reachable set; keeping it would
// write a file that fails closed at runtime ("outbound detour
// not found").
func TestMigrateDistributeSelectorMemberOtherInlineDetourRefuses(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	selector := `{"type":"selector","tag":"sel","outbounds":["proxy-sg","profile:b"]}`
	path := writeDistributedFixture(t, base,
		`{"a":{"outbound":"sel"},"b":{"outbound":{"type":"socks","tag":"profile:b","server":"127.0.0.1","server_port":1082,"version":"5"}}}`,
		`[`+fakeSocksOutbound+`,`+selector+`]`, "",
		`{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"profile:b"}],"final":"dns1"}`)
	before, _ := os.ReadFile(path)
	result, err := Migrate(base, true)
	if err == nil {
		t.Fatalf("distribution of a detour naming another profile's inline outbound must refuse, got result %+v", result)
	}
	if ExitCode(err) != 2 {
		t.Errorf("refusal exit code = %d; want 2", ExitCode(err))
	}
	if result == nil || !strings.Contains(result.DNSDistributionRefusal, `"a"`) ||
		!strings.Contains(result.DNSDistributionRefusal, "profile:b") {
		t.Errorf("refusal = %+v; want it to name profile a and detour profile:b", result)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("refused migrate rewrote the file")
	}
}

// TestMigrateDistributeDetourChainKeep (F5b, loop 2): a detour
// reachable only through another outbound's `detour` field is
// kept verbatim, like a selector-member detour.
func TestMigrateDistributeDetourChainKeep(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	otherSocks := `{"type":"socks","tag":"proxy-other","server":"127.0.0.1","server_port":1081,"version":"5"}`
	chain := `{"type":"socks","tag":"chain","server":"127.0.0.1","server_port":1080,"version":"5","detour":"proxy-other"}`
	path := writeDistributedFixture(t, base,
		`{"p1":{"outbound":"chain"}}`,
		`[`+chain+`,`+otherSocks+`]`, "",
		`{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-other"}],"final":"dns1"}`)
	if _, err := Migrate(base, true); err != nil {
		t.Fatal(err)
	}
	servers := dnsServers(t, profileDNSDoc(t, path, "p1"))
	if servers[0]["detour"] != "proxy-other" {
		t.Errorf("detour = %v; want proxy-other kept verbatim (reachable only through chain's detour field)", servers[0]["detour"])
	}
}

// TestMigrateDistributeRefusalHasNoDoubledProfilePrefix (F5c,
// loop 2): a validation-path refusal must not read
// "profile: profile ...": the embedded validation error's
// standard "profile: " prefix must be stripped once when it is
// quoted inside the distribution refusal.
func TestMigrateDistributeRefusalHasNoDoubledProfilePrefix(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	path := writeDistributedFixture(t, base,
		`{"p1":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "",
		`{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353},{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5354}],"final":"dns1"}`)
	before, _ := os.ReadFile(path)
	result, err := Migrate(base, true)
	if err == nil {
		t.Fatalf("duplicate server tags must refuse distribution, got result %+v", result)
	}
	if result == nil || result.DNSDistributionRefusal == "" {
		t.Fatalf("refusal = %+v; want a recorded distribution refusal", result)
	}
	for _, s := range []string{result.DNSDistributionRefusal, err.Error()} {
		if strings.Contains(s, "profile: profile") {
			t.Errorf("refusal string = %q; want no doubled \"profile: profile\" prefix", s)
		}
	}
	if !strings.Contains(result.DNSDistributionRefusal, `"p1"`) ||
		!strings.Contains(result.DNSDistributionRefusal, "duplicate") {
		t.Errorf("refusal = %q; want it to still name profile p1 and the duplicate-tag failure", result.DNSDistributionRefusal)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("refused migrate rewrote the file")
	}
}

// TestDistributeSkipsNilProfileEntryInGuards (F5d, loop 2):
// the c22b818 nil-profile skip, pinned at the distribution
// function like the existing-block guard. A nil entry among
// real profiles must be skipped by the guard loops: with a
// real profile carrying its own dns block, distribution
// refuses naming that profile, never panics on the nil entry,
// and leaves both entries untouched. (Parsed configs cannot
// produce nil entries, so no Migrate-level form of this test
// exists; the full mixed success path is NOT pinned here —
// validateTagGraph and the save encoding dereference profile
// entries, so a nil entry mixed with a distributable profile
// cannot reach the validation gate. See the writer report.)
func TestDistributeSkipsNilProfileEntryInGuards(t *testing.T) {
	t.Parallel()
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"outbound":"proxy-sg","dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353,"detour":"proxy-sg"}],"final":"dns1"}}}`,
		`[`+fakeSocksOutbound+`]`, "", "",
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Profiles["ghost"] = nil
	globalRaw := []byte(`{"servers":[{"tag":"gdns","type":"tcp","server":"127.0.0.1","server_port":5354,"detour":"proxy-sg"}],"final":"gdns"}`)
	global, err := parseDNS(globalRaw)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DNS = global
	cfg.rawDNS = globalRaw
	distributed, refusal, derr := distributeTopLevelDNS(cfg, "/base")
	if derr == nil {
		t.Fatalf("distributeTopLevelDNS with an existing own block must refuse, got distributed=%v refusal=%q", distributed, refusal)
	}
	if !strings.Contains(refusal, `"muse01"`) {
		t.Errorf("refusal = %q; want it to name profile muse01", refusal)
	}
	if distributed {
		t.Error("distributed = true on refusal; want false")
	}
	if cfg.Profiles["ghost"] != nil {
		t.Error("refused distribution materialised the nil profile entry")
	}
	if cfg.Profiles["muse01"].DNS.Servers[0].Tag != "dns1" {
		t.Error("refused distribution mutated the existing own block")
	}
	if cfg.DNS != global {
		t.Error("refused distribution removed the top-level dns section")
	}
}

// TestMigrateRefusesProfilesAbsentSingleFormatBaseFile (R1,
// loop 3, RED first): the red-team fixture — a base file with
// outbounds + a dns section and NO profiles key — must refuse
// in both modes, exit 2, byte-identical. Before the guard the
// fresh-migration path overwrote it with a synthetic direct
// profile, deleting the dns section and the outbounds.
func TestMigrateRefusesProfilesAbsentSingleFormatBaseFile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	doc := `{"outbounds":[` + fakeSocksOutbound + `],"dns":{"servers":[{"tag":"rt2dns","type":"tcp","server":"127.0.0.99","server_port":5599}],"final":"rt2dns"}}`
	path := filepath.Join(base, "config.json")
	writeFile(t, path, doc, 0o600)
	before, _ := os.ReadFile(path)
	for _, write := range []bool{false, true} {
		result, err := Migrate(base, write)
		if err == nil {
			t.Fatalf("Migrate(write=%v) over a profiles-absent single-format file must refuse, got result %+v", write, result)
		}
		if ExitCode(err) != 2 {
			t.Errorf("Migrate(write=%v) exit code = %d; want 2", write, ExitCode(err))
		}
		if result == nil || result.Migrated || result.WouldWrite {
			t.Errorf("Migrate(write=%v) result = %+v; want no write reported", write, result)
		}
		// The in-memory node_id generated for the candidate
		// must never be reported: nothing was written, so no
		// id was persisted (RT-2 rule).
		if len(result.Generated) != 0 {
			t.Errorf("Migrate(write=%v) generated = %v; want none on a refused run", write, result.Generated)
		}
		for _, mp := range result.Profiles {
			if mp.NodeIDGenerated {
				t.Errorf("Migrate(write=%v) profile %q reports node_id_generated; want false on a refused run", write, mp.Name)
			}
			for _, w := range mp.Warnings {
				if w == "node_id generated" {
					t.Errorf("Migrate(write=%v) profile %q warning %q; want no generated claim on a refused run", write, mp.Name, w)
				}
			}
		}
		if !strings.Contains(err.Error(), `"profiles"`) || !strings.Contains(err.Error(), `"dns"`) || !strings.Contains(err.Error(), `"outbounds"`) {
			t.Errorf("refusal = %q; want it to name the missing profiles key and the dns/outbounds sections at risk", err.Error())
		}
		after, _ := os.ReadFile(path)
		if string(before) != string(after) {
			t.Errorf("Migrate(write=%v) rewrote the file on refusal", write)
		}
	}
}

// TestMigrateProfilesAbsentSingleFormatShapes (R1, loop 3,
// RED first): the guard discriminates by SHAPE — each
// well-shaped single-format section in a profiles-absent file
// refuses a dry-run and leaves the file unchanged — while
// genuinely legacy files and non-shaped junk keep migrating.
// The dns:{} case refuses: an object is the section shape, and
// an empty section is a section (loop-2 empty guard); an empty
// outbounds array carries nothing and does not refuse.
func TestMigrateProfilesAbsentSingleFormatShapes(t *testing.T) {
	t.Parallel()
	refusing := []struct{ name, doc string }{
		{"endpoints", `{"endpoints":[{"type":"wireguard","tag":"wg1"}]}`},
		{"wireguard_dns", `{"wireguard_dns":{"wg1":["10.2.0.1"]}}`},
		{"log", `{"log":{"level":"warning"}}`},
		{"default_profile", `{"default_profile":"work"}`},
		{"empty dns object", `{"dns":{}}`},
		{"dns with servers", `{"dns":{"servers":[{"tag":"d1","type":"tcp","server":"127.0.0.1","server_port":5353}],"final":"d1"}}`},
		{"mixed outbounds", `{"outbounds":[{"type":"direct","tag":"d"},{"tag":"px"}]}`},
		{"mixed endpoints", `{"endpoints":[{"type":"wireguard","tag":"wg1"},{"tag":"px"}]}`},
		{"mixed wireguard_dns", `{"wireguard_dns":{"wg1":["10.2.0.1",123]}}`},
	}
	for _, tc := range refusing {
		t.Run(tc.name+"/refuses", func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			base := BaseDir(home)
			path := filepath.Join(base, "config.json")
			writeFile(t, path, tc.doc, 0o600)
			before, _ := os.ReadFile(path)
			_, err := Migrate(base, false)
			if err == nil {
				t.Fatalf("Migrate dry-run over %s must refuse, got nil error", tc.name)
			}
			if ExitCode(err) != 2 {
				t.Errorf("exit code = %d; want 2", ExitCode(err))
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Error("refused dry-run rewrote the file")
			}
		})
	}
	// An outbound object without a "type" is NOT a shaped
	// outbound, so an array with no shaped outbound (see the
	// migrating control below) does not trigger the guard:
	// shape, not key presence alone, triggers it — but one
	// shaped element in a mixed array does.
	migrating := []struct{ name, doc string }{
		{"legacy only", `{"auto_approve":"always","node_id":"N1"}`},
		{"empty outbounds array", `{"outbounds":[]}`},
		{"non-shaped keys", `{"dns":"junk","outbounds":"junk"}`},
		{"outbound object without type", `{"outbounds":[{"tag":"px"}]}`},
		{"empty file object", `{}`},
	}
	for _, tc := range migrating {
		t.Run(tc.name+"/migrates", func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			base := BaseDir(home)
			path := filepath.Join(base, "config.json")
			writeFile(t, path, tc.doc, 0o600)
			result, err := Migrate(base, true)
			if err != nil {
				t.Fatalf("Migrate --write over %s must succeed (legacy path), got %v", tc.name, err)
			}
			if !result.Migrated {
				t.Errorf("Migrate --write over %s = %+v; want migrated", tc.name, result)
			}
			doc := readJSONFile(t, path)
			if _, ok := doc["profiles"]; !ok {
				t.Errorf("migrated file has no profiles key: %v", doc)
			}
		})
	}
}

// TestMigrateRefusesMixedOutboundsSingleFormatBaseFile: a
// profiles-absent base file whose outbounds array mixes one
// shaped outbound with one unshaped object must refuse in both
// modes, exit 2, byte-identical — the shaped element must not
// be deleted by a fresh migration.
func TestMigrateRefusesMixedOutboundsSingleFormatBaseFile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	doc := `{"outbounds":[{"type":"direct","tag":"d"},{"tag":"px"}]}`
	path := filepath.Join(base, "config.json")
	writeFile(t, path, doc, 0o600)
	before, _ := os.ReadFile(path)
	for _, write := range []bool{false, true} {
		result, err := Migrate(base, write)
		if err == nil {
			t.Fatalf("Migrate(write=%v) over a mixed outbounds file must refuse, got result %+v", write, result)
		}
		if ExitCode(err) != 2 {
			t.Errorf("Migrate(write=%v) exit code = %d; want 2", write, ExitCode(err))
		}
		if result == nil || result.Migrated || result.WouldWrite {
			t.Errorf("Migrate(write=%v) result = %+v; want no write reported", write, result)
		}
		// The in-memory node_id generated for the candidate
		// must never be reported: nothing was written, so no
		// id was persisted (RT-2 rule).
		if len(result.Generated) != 0 {
			t.Errorf("Migrate(write=%v) generated = %v; want none on a refused run", write, result.Generated)
		}
		for _, mp := range result.Profiles {
			if mp.NodeIDGenerated {
				t.Errorf("Migrate(write=%v) profile %q reports node_id_generated; want false on a refused run", write, mp.Name)
			}
			for _, w := range mp.Warnings {
				if w == "node_id generated" {
					t.Errorf("Migrate(write=%v) profile %q warning %q; want no generated claim on a refused run", write, mp.Name, w)
				}
			}
		}
		if !strings.Contains(err.Error(), `"profiles"`) || !strings.Contains(err.Error(), `"outbounds"`) {
			t.Errorf("refusal = %q; want it to name the missing profiles key and the outbounds section at risk", err.Error())
		}
		after, _ := os.ReadFile(path)
		if string(before) != string(after) {
			t.Errorf("Migrate(write=%v) rewrote the file on refusal", write)
		}
	}
}

// TestMigrateFromRefusesProfilesAbsentSingleFormatDestination
// (R1, loop 3, RED first): the guard protects the DESTINATION
// file under --from too — a single-format destination is
// refused, unchanged, and the source directory is untouched.
func TestMigrateFromRefusesProfilesAbsentSingleFormatDestination(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	src := filepath.Join(home, "muse-cli")
	writeFile(t, filepath.Join(src, "config.json"), `{"auto_approve":"always","node_id":"MAIN-NODE"}`, 0o600)
	srcBefore, _ := os.ReadFile(filepath.Join(src, "config.json"))
	dest := filepath.Join(home, "castctl")
	destDoc := `{"outbounds":[` + fakeSocksOutbound + `],"dns":{"servers":[{"tag":"rt2dns","type":"tcp","server":"127.0.0.99","server_port":5599}],"final":"rt2dns"}}`
	destPath := filepath.Join(dest, "config.json")
	writeFile(t, destPath, destDoc, 0o600)
	destBefore, _ := os.ReadFile(destPath)
	result, err := MigrateFrom(src, dest, true)
	if err == nil {
		t.Fatalf("MigrateFrom over a profiles-absent single-format destination must refuse, got result %+v", result)
	}
	if ExitCode(err) != 2 {
		t.Errorf("exit code = %d; want 2", ExitCode(err))
	}
	if after, _ := os.ReadFile(destPath); string(destBefore) != string(after) {
		t.Error("refused --from migrate rewrote the destination file")
	}
	if after, _ := os.ReadFile(filepath.Join(src, "config.json")); string(srcBefore) != string(after) {
		t.Error("refused --from migrate modified the source file")
	}
}

// TestDistributeParseErrorRefusalHasSingleProfilePrefix (N-a,
// loop 3, RED first): the PARSE-error strip site
// (dns_distribute.go:182) must render one "profile: " prefix
// like the validation site (:253, pinned in loop 2). The
// candidate is hand-built: a valid parsed section whose
// preserved raw bytes carry an unparseable server type, so
// only the re-parse fails.
func TestDistributeParseErrorRefusalHasSingleProfilePrefix(t *testing.T) {
	t.Parallel()
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"p1":{"outbound":"proxy-sg"}}`,
		`[`+fakeSocksOutbound+`]`, "",
		`{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353}],"final":"dns1"}`,
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	savedDNS := cfg.DNS
	cfg.rawDNS = []byte(`{"servers":[{"tag":"dns1","type":"bogus-type","server":"127.0.0.1","server_port":5353}],"final":"dns1"}`)
	distributed, refusal, derr := distributeTopLevelDNS(cfg, "/base")
	if derr == nil {
		t.Fatalf("distributeTopLevelDNS with an unparseable raw section must refuse, got distributed=%v refusal=%q", distributed, refusal)
	}
	if distributed {
		t.Error("distributed = true on refusal; want false")
	}
	if !strings.Contains(refusal, "does not parse") || !strings.Contains(refusal, "parse dns") {
		t.Errorf("refusal = %q; want it to report the parse failure", refusal)
	}
	if strings.Contains(refusal, "does not parse: profile:") {
		t.Errorf("refusal = %q; want the embedded parse error's profile: prefix stripped once", refusal)
	}
	if cfg.DNS != savedDNS {
		t.Error("refused distribution removed the top-level dns section from the candidate")
	}
}
