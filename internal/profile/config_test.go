// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validOutbounds: one valid paste-JSON per protocol type in the delta, plus
// the wireguard endpoint. All secrets are FAKE placeholders.
var validOutbounds = map[string]string{
	"direct":       `{"type":"direct","tag":"direct"}`,
	"socks":        `{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1080,"version":"5","username":"FAKE-USER","password":"FAKE-PW"}`,
	"http":         `{"type":"http","tag":"http-1","server":"127.0.0.1","server_port":8080,"username":"FAKE-USER","password":"FAKE-PW"}`,
	"shadowsocks":  `{"type":"shadowsocks","tag":"ss-1","server":"203.0.113.10","server_port":8388,"method":"aes-256-gcm","password":"FAKE-PW"}`,
	"vmess":        `{"type":"vmess","tag":"vmess-1","server":"203.0.113.11","server_port":443,"uuid":"FAKE-UUID","security":"auto"}`,
	"vless":        `{"type":"vless","tag":"vless-1","server":"203.0.113.20","server_port":443,"uuid":"FAKE-UUID","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"FAKE-PUB","short_id":"FAKE-SHORT"}}}`,
	"trojan":       `{"type":"trojan","tag":"trojan-1","server":"203.0.113.12","server_port":443,"password":"FAKE-PW"}`,
	"hysteria2":    `{"type":"hysteria2","tag":"hy2-1","server":"203.0.113.13","server_port":443,"password":"FAKE-PW","obfs":{"type":"salamander","password":"FAKE-OBFS"}}`,
	"tuic":         `{"type":"tuic","tag":"tuic-1","server":"203.0.113.14","server_port":443,"uuid":"FAKE-UUID","password":"FAKE-PW"}`,
	"anytls":       `{"type":"anytls","tag":"anytls-1","server":"203.0.113.15","server_port":443,"password":"FAKE-PW"}`,
	"ssh":          `{"type":"ssh","tag":"ssh-1","server":"203.0.113.16","server_port":22,"user":"FAKE-USER","password":"FAKE-PW"}`,
	"snell":        `{"type":"snell","tag":"snell-1","server":"203.0.113.17","server_port":8388,"version":4,"psk":"FAKE-PSK"}`,
	"shadowtls":    `{"type":"shadowtls","tag":"stls-1","server":"203.0.113.18","server_port":443,"version":3,"password":"FAKE-PW"}`,
	"naive":        `{"type":"naive","tag":"naive-1","server":"203.0.113.19","server_port":443,"username":"FAKE-USER","password":"FAKE-PW"}`,
	"tor":          `{"type":"tor","tag":"tor-1"}`,
	"block":        `{"type":"block","tag":"block-1"}`,
	"selector":     `{"type":"selector","tag":"sel-1","outbounds":["proxy-sg","direct"]}`,
	"urltest":      `{"type":"urltest","tag":"ut-1","outbounds":["proxy-sg"],"url":"https://example.com/","interval":"1m"}`,
	"wireguard-ep": `{"type":"wireguard","tag":"wg-home","address":["10.0.0.2/32"],"private_key":"FAKE-PRIVKEY","peers":[{"address":"203.0.113.10","port":51820,"public_key":"FAKE-PUBKEY","allowed_ips":["0.0.0.0/0"]}]}`,
}

func singleFileJSON(profiles, outbounds, endpoints, dns string) string {
	var b strings.Builder
	b.WriteString("{")
	if profiles != "" {
		b.WriteString(`"profiles":` + profiles + ",")
	}
	if outbounds != "" {
		b.WriteString(`"outbounds":` + outbounds + ",")
	}
	if endpoints != "" {
		b.WriteString(`"endpoints":` + endpoints + ",")
	}
	if dns != "" {
		b.WriteString(`"dns":` + dns + ",")
	}
	s := strings.TrimSuffix(b.String(), ",") + "}"
	if s == "}" {
		return "{}"
	}
	return s
}

func TestParseSingleConfigMinimal(t *testing.T) {
	t.Parallel()
	cfg, err := ParseSingleConfig([]byte(`{"profiles":{"default":{}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultProfile != "" {
		t.Errorf("DefaultProfile = %q; want empty (unset)", cfg.DefaultProfile)
	}
	p, ok := cfg.Profiles["default"]
	if !ok || p == nil {
		t.Fatal("profiles[default] missing")
	}
	if p.Outbound.Kind != OutboundDirect || p.Outbound.Type != "direct" {
		t.Errorf("default outbound = %+v; want direct", p.Outbound)
	}
	if p.CookiesFile != filepath.Join("/base", "cookies.txt") {
		t.Errorf("CookiesFile = %q; want default path", p.CookiesFile)
	}
}

func TestParseSingleConfigDeltaExample(t *testing.T) {
	t.Parallel()
	data := singleFileJSON(
		`{"muse01":{"auto_approve":"off","auto_allow_once":false,"node_id":"0123456789abcdef","vm_id":"FAKE-VMID","subscription_action_id":"FAKE-ACTION","cookies_file":"/base/profiles/muse01/cookies.txt","outbound":"wg-home"},"direct-profile":{"auto_approve":"off","auto_allow_once":false,"outbound":{"type":"direct","tag":"direct"}}}`,
		`[`+validOutbounds["socks"]+`]`,
		`[`+validOutbounds["wireguard-ep"]+`]`,
		`{"servers":[{"type":"https","tag":"dns-remote","server":"1.1.1.1","server_port":443,"path":"/dns-query","detour":"proxy-sg"}],"final":"dns-remote"}`,
	)
	cfg, err := ParseSingleConfig([]byte(data), "/base")
	if err != nil {
		t.Fatal(err)
	}
	muse01 := cfg.Profiles["muse01"]
	if muse01.Outbound.Kind != OutboundTag || muse01.Outbound.Tag != "wg-home" ||
		muse01.Outbound.Type != "wireguard" || muse01.Outbound.From != "endpoint" {
		t.Errorf("muse01 outbound = %+v; want tag wg-home wireguard endpoint", muse01.Outbound)
	}
	dp := cfg.Profiles["direct-profile"]
	if dp.Outbound.Kind != OutboundInline || dp.Outbound.Type != "direct" {
		t.Errorf("direct-profile outbound = %+v; want inline direct", dp.Outbound)
	}
	if cfg.DNS == nil {
		t.Error("DNS = nil; want parsed DNSOptions")
	}
	outs, err := cfg.ParsedOutbounds()
	if err != nil || len(outs) != 1 || outs[0].Type != "socks" {
		t.Errorf("ParsedOutbounds = %v, %v; want 1 socks", outs, err)
	}
	eps, err := cfg.ParsedEndpoints()
	if err != nil || len(eps) != 1 || eps[0].Type != "wireguard" {
		t.Errorf("ParsedEndpoints = %v, %v; want 1 wireguard", eps, err)
	}
}

func TestParseSingleConfigEveryProtocolValid(t *testing.T) {
	t.Parallel()
	for name, raw := range validOutbounds {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var data string
			if name == "wireguard-ep" {
				data = singleFileJSON(`{"p":{"outbound":"wg-home"}}`, "", `[`+raw+`]`, "")
			} else if name == "selector" || name == "urltest" {
				// selector/urltest reference proxy-sg; include it. The
				// selector fixture's member list is trimmed to proxy-sg so
				// every referenced tag exists in this file.
				tag := map[string]string{"selector": "sel-1", "urltest": "ut-1"}[name]
				trimmed := strings.Replace(raw, `"outbounds":["proxy-sg","direct"]`, `"outbounds":["proxy-sg"]`, 1)
				trimmed = strings.Replace(trimmed, `"tag":"`+tag+`"`, `"tag":"`+name+`-tag"`, 1)
				data = singleFileJSON(`{"p":{"outbound":"`+name+`-tag"}}`, `[`+validOutbounds["socks"]+`,`+trimmed+`]`, "", "")
			} else {
				data = singleFileJSON(`{"p":{"outbound":`+raw+`}}`, "", "", "")
			}
			if _, err := ParseSingleConfig([]byte(data), "/base"); err != nil {
				t.Errorf("ParseSingleConfig(%s) error: %v", name, err)
			}
		})
	}
}

func TestParseSingleConfigWrongTypesFail(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"socks port string":   `{"profiles":{"p":{"outbound":{"type":"socks","tag":"x","server":"127.0.0.1","server_port":"1080"}}}}`,
		"vless uuid number":   `{"profiles":{"p":{"outbound":{"type":"vless","tag":"x","server":"203.0.113.20","server_port":443,"uuid":123}}}}`,
		"trojan password num": `{"profiles":{"p":{"outbound":{"type":"trojan","tag":"x","server":"203.0.113.12","server_port":443,"password":42}}}}`,
		// NOTE: enum constraints (e.g. shadowsocks "method") are schema
		// metadata only; sing-box option parsing does not validate
		// them. A bad enum value parses here and must be rejected by
		// outbound construction in internal/outbound. Validating enums
		// here would mean a hand-written copy of the outbound schema,
		// which the delta forbids.
		"http port bool":      `{"profiles":{"p":{"outbound":{"type":"http","tag":"x","server":"127.0.0.1","server_port":true}}}}`,
		"auto_approve number": `{"profiles":{"p":{"auto_approve":1}}}`,
		"auto_allow_once str": `{"profiles":{"p":{"auto_allow_once":"maybe"}}}`,
		"profiles not object": `{"profiles":[]}`,
		"profile not object":  `{"profiles":{"p":"x"}}`,
		"outbounds not array": `{"profiles":{},"outbounds":{}}`,
		"dns bad type":        `{"profiles":{},"dns":{"servers":[{"type":"nope","tag":"d","server":"1.1.1.1"}]}}`,
		"endpoint bad type":   `{"profiles":{},"endpoints":[{"type":"nope","tag":"e"}]}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseSingleConfig([]byte(data), "/base"); err == nil {
				t.Errorf("ParseSingleConfig(%s) = nil error; want error", name)
			} else if ExitCode(err) != 2 {
				t.Errorf("ParseSingleConfig(%s) ExitCode = %d; want 2", name, ExitCode(err))
			}
		})
	}
}

func TestOutboundUnknownFieldRejected(t *testing.T) {
	// Probe, named for its measured outcome: sing-box badjson IS strict, so
	// an unknown field inside an outbound object must be rejected here.
	// If this test ever fails, the pre-validation described in the plan
	// (DisallowUnknownFields) must be implemented instead of relying on badjson.
	t.Parallel()
	data := `{"profiles":{"p":{"outbound":{"type":"socks","tag":"x","server":"127.0.0.1","server_port":1080,"bogus_field_xyz":1}}}}`
	if _, err := ParseSingleConfig([]byte(data), "/base"); err == nil {
		t.Error("unknown outbound field accepted; badjson is lenient, pre-validation required")
	}
	// Same probe for endpoints and DNS servers.
	ep := `{"profiles":{},"endpoints":[{"type":"wireguard","tag":"wg","address":["10.0.0.2/32"],"private_key":"FAKE-K","bogus_field_xyz":1}]}`
	if _, err := ParseSingleConfig([]byte(ep), "/base"); err == nil {
		t.Error("unknown endpoint field accepted")
	}
	dns := `{"profiles":{},"dns":{"servers":[{"type":"https","tag":"d","server":"1.1.1.1","bogus_field_xyz":1}]}}`
	if _, err := ParseSingleConfig([]byte(dns), "/base"); err == nil {
		t.Error("unknown dns server field accepted")
	}
}

func TestParseSingleConfigTagRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{
			name:    "duplicate tag outbound+endpoint",
			data:    singleFileJSON(`{"p":{"outbound":"dup"}}`, `[`+validOutbounds["socks"]+`]`, `[{"type":"wireguard","tag":"proxy-sg","address":["10.0.0.2/32"],"private_key":"FAKE-K"}]`, ""),
			wantErr: true,
		},
		{
			name:    "duplicate tag two outbounds",
			data:    singleFileJSON(`{"p":{"outbound":"x"}}`, `[`+validOutbounds["socks"]+`,{"type":"http","tag":"proxy-sg","server":"127.0.0.1","server_port":8080}]`, "", ""),
			wantErr: true,
		},
		{
			name:    "duplicate tag inline vs list",
			data:    singleFileJSON(`{"p":{"outbound":{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1080}}}`, `[`+validOutbounds["socks"]+`]`, "", ""),
			wantErr: true,
		},
		{
			name:    "dangling tag reference",
			data:    singleFileJSON(`{"p":{"outbound":"missing-tag"}}`, "", "", ""),
			wantErr: true,
		},
		{
			name:    "unknown outbound type",
			data:    singleFileJSON(`{"p":{"outbound":{"type":"nope-protocol","tag":"x"}}}`, "", "", ""),
			wantErr: true,
		},
		{
			name:    "wireguard as outbound rejected",
			data:    singleFileJSON(`{"p":{"outbound":{"type":"wireguard","tag":"x","address":["10.0.0.2/32"],"private_key":"FAKE-K"}}}`, "", "", ""),
			wantErr: true,
		},
		{
			name:    "dns outbound deprecated rejected",
			data:    singleFileJSON(`{"p":{"outbound":{"type":"dns","tag":"x"}}}`, "", "", ""),
			wantErr: true,
		},
		{
			name:    "empty tag outbound object gets profile auto-tag",
			data:    singleFileJSON(`{"p":{"outbound":{"type":"direct"}}}`, "", "", ""),
			wantErr: false,
		},
		{
			name:    "detour to existing tag ok",
			data:    singleFileJSON(`{"p":{"outbound":"x"}}`, `[{"type":"socks","tag":"x","server":"127.0.0.1","server_port":1080,"detour":"y"},{"type":"http","tag":"y","server":"127.0.0.1","server_port":8080}]`, "", ""),
			wantErr: false,
		},
		{
			name:    "detour to missing tag errors",
			data:    singleFileJSON(`{"p":{"outbound":"x"}}`, `[{"type":"socks","tag":"x","server":"127.0.0.1","server_port":1080,"detour":"ghost"}]`, "", ""),
			wantErr: true,
		},
		{
			name:    "selector outbounds reference checked",
			data:    singleFileJSON(`{"p":{"outbound":"sel"}}`, `[{"type":"selector","tag":"sel","outbounds":["ghost"]}]`, "", ""),
			wantErr: true,
		},
		{
			name:    "untagged list outbound errors",
			data:    singleFileJSON(`{"p":{"outbound":"x"}}`, `[{"type":"socks","server":"127.0.0.1","server_port":1080}]`, "", ""),
			wantErr: true,
		},
		{
			name:    "untagged endpoint errors",
			data:    singleFileJSON(`{"p":{"outbound":"wg"}}`, "", `[{"type":"wireguard","address":["10.0.0.2/32"],"private_key":"FAKE-K"}]`, ""),
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := ParseSingleConfig([]byte(tc.data), "/base")
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseSingleConfig = nil error; want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSingleConfig error: %v", err)
			}
			if tc.name == "empty tag outbound object gets profile auto-tag" {
				if got := cfg.Profiles["p"].Outbound.Tag; got != "profile:p" {
					t.Errorf("auto-tag = %q; want profile:p", got)
				}
			}
		})
	}
}

func TestParseSingleConfigCookiesKeyRejected(t *testing.T) {
	t.Parallel()
	cases := []string{
		`{"cookies":{"hatch_sess":"FAKE"},"profiles":{}}`,
		`{"cookie":"FAKE","profiles":{}}`,
		`{"profiles":{"p":{"cookies":{"hatch_sess":"FAKE"}}}}`,
		`{"profiles":{"p":{"cookie":"FAKE"}}}`,
	}
	for _, data := range cases {
		if _, err := ParseSingleConfig([]byte(data), "/base"); err == nil {
			t.Errorf("ParseSingleConfig(%s) = nil error; want cookies-key error", data)
		}
	}
	// Legitimate sing-box `cookie` field inside an OpenConnect endpoint is
	// NOT a muse-cli inline-cookies key and must be accepted.
	data := singleFileJSON(`{"p":{"outbound":"oc"}}`, "", `[{"type":"openconnect","tag":"oc","server":"203.0.113.23","cookie":"FAKE-OC-COOKIE"}]`, "")
	if _, err := ParseSingleConfig([]byte(data), "/base"); err != nil {
		t.Errorf("openconnect endpoint cookie rejected: %v", err)
	}
}

func TestParseSingleConfigUnknownKeysRejected(t *testing.T) {
	t.Parallel()
	if _, err := ParseSingleConfig([]byte(`{"profiles":{},"surprise":1}`), "/base"); err == nil {
		t.Error("unknown top-level key accepted; want error")
	}
	if _, err := ParseSingleConfig([]byte(`{"profiles":{"p":{"surprise":1}}}`), "/base"); err == nil {
		t.Error("unknown profile key accepted; want error")
	}
	if _, err := ParseSingleConfig([]byte(`not json`), "/base"); err == nil {
		t.Error("malformed JSON accepted; want error")
	}
	if _, err := ParseSingleConfig([]byte(`[1,2]`), "/base"); err == nil {
		t.Error("top-level array accepted; want error")
	}
}

func TestHasProfilesMarker(t *testing.T) {
	t.Parallel()
	yes, err := HasProfilesMarker([]byte(`{"profiles":{}}`))
	if err != nil || !yes {
		t.Errorf("HasProfilesMarker = %v, %v; want true, nil", yes, err)
	}
	yes, err = HasProfilesMarker([]byte(`{"auto_approve":"always"}`))
	if err != nil || yes {
		t.Errorf("HasProfilesMarker = %v, %v; want false, nil", yes, err)
	}
	yes, err = HasProfilesMarker([]byte(`{"profiles":[]}`))
	if err != nil || !yes {
		t.Errorf("HasProfilesMarker(profiles array) = %v, %v; want true (parse rejects later)", yes, err)
	}
	if _, err := HasProfilesMarker([]byte(`{bad`)); err == nil {
		t.Error("HasProfilesMarker(malformed) = nil error; want error")
	}
}

func TestLoadProfileLegacyAndSingle(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)

	// Legacy default: flat config, env fills vm_id only when absent.
	writeFile(t, filepath.Join(base, "config.json"), `{"auto_approve":"always","node_id":"LEGACY-NODE"}`, 0o600)
	p, err := LoadProfile(base, "default", lookupEnv(map[string]string{"MUSE_VM_ID": "FAKE-VM"}))
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != SourceLegacy || p.AutoApprove != "always" || p.NodeID != "LEGACY-NODE" || p.VMID != "FAKE-VM" {
		t.Errorf("legacy default = %+v; want legacy/always/LEGACY-NODE/FAKE-VM", p)
	}
	if !p.ConfigFound {
		t.Error("legacy default ConfigFound = false; want true")
	}

	// Load must not write: node_id absent + no env => stays empty, file untouched.
	home2 := t.TempDir()
	base2 := BaseDir(home2)
	writeFile(t, filepath.Join(base2, "config.json"), `{"auto_approve":"off"}`, 0o600)
	before, _ := os.ReadFile(filepath.Join(base2, "config.json"))
	p2, err := LoadProfile(base2, "default", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if p2.NodeID != "" {
		t.Errorf("Load generated node_id %q; Load must be read-only", p2.NodeID)
	}
	after, _ := os.ReadFile(filepath.Join(base2, "config.json"))
	if string(before) != string(after) {
		t.Error("Load modified config.json; want read-only")
	}

	// Legacy named profile: fresh defaults, no borrowing from default.
	p3, err := LoadProfile(base, "work", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if p3.AutoApprove != "off" || p3.Source != SourceNone || p3.ConfigFound {
		t.Errorf("fresh named = %+v; want off/none/not-found", p3)
	}
	if p3.CookiesFile != filepath.Join(base, "profiles", "work", "cookies.txt") {
		t.Errorf("fresh named CookiesFile = %q", p3.CookiesFile)
	}
	if p3.Dir != filepath.Join(base, "profiles", "work") {
		t.Errorf("fresh named Dir = %q", p3.Dir)
	}
	// Loading a fresh profile creates nothing.
	if _, err := os.Stat(filepath.Join(base, "profiles")); !os.IsNotExist(err) {
		t.Error("Load created profiles dir; want no side effects")
	}
}

func TestLoadProfileCoercion(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	// Copied config pointing inside the base dir is coerced to the profile's own file.
	workDir := filepath.Join(base, "profiles", "work")
	writeFile(t, filepath.Join(workDir, "config.json"),
		`{"cookies_file":`+quote(filepath.Join(base, "cookies.txt"))+`,"node_id":"n1"}`, 0o600)
	p, err := LoadProfile(base, "work", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if p.CookiesFile != filepath.Join(workDir, "cookies.txt") {
		t.Errorf("coerced CookiesFile = %q; want own file", p.CookiesFile)
	}
	// A cookies_file outside the base dir is kept (Python keeps it).
	workDir2 := filepath.Join(base, "profiles", "other")
	writeFile(t, filepath.Join(workDir2, "config.json"),
		`{"cookies_file":"/tmp/outside-cookies.txt","node_id":"n1"}`, 0o600)
	p2, err := LoadProfile(base, "other", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if p2.CookiesFile != "/tmp/outside-cookies.txt" {
		t.Errorf("outside CookiesFile = %q; want kept", p2.CookiesFile)
	}
	// Relative cookies_file resolves under the base dir, then coercion applies.
	workDir3 := filepath.Join(base, "profiles", "rel")
	writeFile(t, filepath.Join(workDir3, "config.json"),
		`{"cookies_file":"cookies.txt","node_id":"n1"}`, 0o600)
	p3, err := LoadProfile(base, "rel", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if p3.CookiesFile != filepath.Join(workDir3, "cookies.txt") {
		t.Errorf("relative CookiesFile = %q; want own file via base resolution", p3.CookiesFile)
	}
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestLoadProfileSingleFileWinsNoMerge(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	// Single file says work is off; legacy work file says always. Single wins wholly.
	writeFile(t, filepath.Join(base, "config.json"),
		`{"profiles":{"work":{"auto_approve":"off","node_id":"SINGLE-NODE"}}}`, 0o600)
	writeFile(t, filepath.Join(base, "profiles", "work", "config.json"),
		`{"auto_approve":"always","node_id":"LEGACY-NODE","vm_id":"LEGACY-VM"}`, 0o600)
	p, err := LoadProfile(base, "work", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != SourceSingle || p.AutoApprove != "off" || p.NodeID != "SINGLE-NODE" || p.VMID != "" {
		t.Errorf("single-file profile = %+v; want single/off/SINGLE-NODE/empty vm (no merge)", p)
	}
	if p.ConfigFile != filepath.Join(base, "config.json") {
		t.Errorf("single profile ConfigFile = %q; want single file", p.ConfigFile)
	}

	// Fallback: profile absent from single file loads from its legacy file.
	writeFile(t, filepath.Join(base, "profiles", "alt", "config.json"),
		`{"auto_approve":"always","node_id":"ALT-NODE"}`, 0o600)
	p2, err := LoadProfile(base, "alt", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if p2.Source != SourceLegacy || p2.AutoApprove != "always" || p2.NodeID != "ALT-NODE" {
		t.Errorf("fallback profile = %+v; want legacy/always/ALT-NODE", p2)
	}

	// Unparseable single file: error, NO silent fallback to legacy.
	writeFile(t, filepath.Join(base, "config.json"), `{"profiles":`, 0o600)
	if _, err := LoadProfile(base, "work", lookupEnv(map[string]string{})); err == nil {
		t.Error("unparseable single file fell back silently; want error")
	}
}

func TestLoadProfileInvalidName(t *testing.T) {
	t.Parallel()
	if _, err := LoadProfile("/base", "../evil", lookupEnv(map[string]string{})); err == nil {
		t.Error("LoadProfile(invalid) = nil error; want error")
	}
}

func TestResolveActiveProfile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	// No single file: flag > env > "default".
	p, err := ResolveActiveProfile(base, strptr("work"), lookupEnv(map[string]string{}))
	if err != nil || p.Name != "work" {
		t.Errorf("flag resolve = %+v, %v; want work", p, err)
	}
	p, err = ResolveActiveProfile(base, nil, lookupEnv(map[string]string{"MUSE_CLI_PROFILE": "envname"}))
	if err != nil || p.Name != "envname" {
		t.Errorf("env resolve = %+v, %v; want envname", p, err)
	}
	p, err = ResolveActiveProfile(base, nil, lookupEnv(map[string]string{}))
	if err != nil || p.Name != "default" {
		t.Errorf("default resolve = %+v, %v; want default", p, err)
	}

	// Single file default_profile used when no flag/env.
	writeFile(t, filepath.Join(base, "config.json"),
		`{"default_profile":"muse01","profiles":{"muse01":{"node_id":"N1"}}}`, 0o600)
	p, err = ResolveActiveProfile(base, nil, lookupEnv(map[string]string{}))
	if err != nil || p.Name != "muse01" {
		t.Errorf("default_profile resolve = %+v, %v; want muse01", p, err)
	}
	// Flag overrides default_profile.
	p, err = ResolveActiveProfile(base, strptr("other"), lookupEnv(map[string]string{}))
	if err != nil || p.Name != "other" {
		t.Errorf("flag over default_profile = %+v, %v; want other", p, err)
	}

	// default_profile pointing at a missing profile: error, no silent fallback.
	writeFile(t, filepath.Join(base, "config.json"),
		`{"default_profile":"ghost","profiles":{"muse01":{"node_id":"N1"}}}`, 0o600)
	if _, err := ResolveActiveProfile(base, nil, lookupEnv(map[string]string{})); err == nil {
		t.Error("dangling default_profile resolved silently; want error")
	}
	// ...but an explicit flag still works even with a dangling default_profile.
	p, err = ResolveActiveProfile(base, strptr("muse01"), lookupEnv(map[string]string{}))
	if err != nil || p.Name != "muse01" {
		t.Errorf("flag with dangling default_profile = %+v, %v; want muse01", p, err)
	}
	// default_profile naming a legacy-only profile is not dangling.
	writeFile(t, filepath.Join(base, "profiles", "legacyone", "config.json"), `{"node_id":"L1"}`, 0o600)
	writeFile(t, filepath.Join(base, "config.json"),
		`{"default_profile":"legacyone","profiles":{"muse01":{"node_id":"N1"}}}`, 0o600)
	p, err = ResolveActiveProfile(base, nil, lookupEnv(map[string]string{}))
	if err != nil || p.Name != "legacyone" || p.Source != SourceLegacy {
		t.Errorf("legacy default_profile = %+v, %v; want legacyone/legacy", p, err)
	}
}

func TestSaveSingleConfig(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"muse01":{"auto_approve":"always","auto_allow_once":true,"node_id":"0123456789abcdef","vm_id":"FAKE-VM","outbound":"proxy-sg"},"plain":{"auto_approve":"off"}}`,
		`[`+validOutbounds["socks"]+`]`, "", "")), base)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DefaultProfile = "muse01"
	if err := SaveSingleConfig(base, cfg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "config.json")
	if mode := fileMode(t, path); mode != 0o600 {
		t.Errorf("saved config mode = %o; want 600", mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\n  \"profiles\"") {
		t.Errorf("saved config not indent-2: %s", data)
	}
	// Round-trip: re-parse and compare the resolved model.
	cfg2, err := ParseSingleConfig(data, base)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.DefaultProfile != "muse01" {
		t.Errorf("round-trip DefaultProfile = %q", cfg2.DefaultProfile)
	}
	if cfg2.Profiles["muse01"].AutoApprove != "always" || !cfg2.Profiles["muse01"].AutoAllowOnce {
		t.Errorf("round-trip muse01 = %+v", cfg2.Profiles["muse01"])
	}
	if cfg2.Profiles["muse01"].Outbound.Tag != "proxy-sg" || cfg2.Profiles["muse01"].Outbound.Type != "socks" {
		t.Errorf("round-trip outbound = %+v", cfg2.Profiles["muse01"].Outbound)
	}
	// Inline outbound survives with its tag.
	cfg3, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"p":{"outbound":{"type":"direct"}}}`, "", "", "")), base)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSingleConfig(base, cfg3); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if !strings.Contains(string(data), `"tag": "profile:p"`) {
		t.Errorf("saved inline outbound missing auto-tag: %s", data)
	}
	if strings.Contains(string(data), "FAKE") {
		t.Errorf("saved config contains test secret marker unexpectedly: %s", data)
	}
}

func TestSaveSingleConfigCreatesDir(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	cfg := &SingleConfig{Profiles: map[string]*Profile{}}
	if err := SaveSingleConfig(base, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "config.json")); err != nil {
		t.Errorf("save did not create config: %v", err)
	}
}
