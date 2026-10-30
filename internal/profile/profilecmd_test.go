// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seedSingleFile(t *testing.T, base, json string) {
	t.Helper()
	cfg, err := ParseSingleConfig([]byte(json), base)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSingleConfig(base, cfg); err != nil {
		t.Fatal(err)
	}
}

func loadProfiles(t *testing.T, base string) *SingleConfig {
	t.Helper()
	cfg, found, err := LoadSingleConfig(base)
	if err != nil || !found {
		t.Fatalf("LoadSingleConfig = %+v, %v, %v", cfg, found, err)
	}
	return cfg
}

func TestAddProfileFresh(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	p, err := AddProfile(base, "work", AddProfileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "work" || p.AutoApprove != "off" || p.AutoAllowOnce {
		t.Errorf("profile = %+v; want off/false", p)
	}
	if len(p.NodeID) != 16 || !isHex(p.NodeID) {
		t.Errorf("NodeID = %q; want fresh 16 hex chars", p.NodeID)
	}
	if p.CookiesFile != filepath.Join(base, "profiles", "work", "cookies.txt") {
		t.Errorf("CookiesFile = %q", p.CookiesFile)
	}
	if p.ConfigFile != filepath.Join(base, "config.json") {
		t.Errorf("ConfigFile = %q", p.ConfigFile)
	}
	if !p.Outbound.IsDirect() {
		t.Errorf("Outbound = %+v; want direct", p.Outbound)
	}
	// Creates NO cookies file and NO profile directory.
	if _, err := os.Stat(p.CookiesFile); !os.IsNotExist(err) {
		t.Errorf("cookies file created (stat err %v); AddProfile creates none", err)
	}
	if _, err := os.Stat(filepath.Join(base, "profiles", "work")); !os.IsNotExist(err) {
		t.Errorf("profile directory created; AddProfile creates none (stat err %v)", err)
	}
	cfg := loadProfiles(t, base)
	if _, ok := cfg.Profiles["work"]; !ok {
		t.Error("work missing from saved single file")
	}
	if mode := fileMode(t, filepath.Join(base, "config.json")); mode != 0o600 {
		t.Errorf("config mode = %o; want 600", mode)
	}
}

func TestAddProfileDuplicateAndSetDefault(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	if _, err := AddProfile(base, "a", AddProfileOptions{SetDefault: true}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if _, err := AddProfile(base, "a", AddProfileOptions{}); err == nil {
		t.Fatal("duplicate AddProfile = nil error; want error")
	}
	after, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if string(before) != string(after) {
		t.Error("duplicate AddProfile modified the file")
	}
	if _, err := AddProfile(base, "b", AddProfileOptions{}); err != nil {
		t.Fatal(err)
	}
	cfg := loadProfiles(t, base)
	if cfg.DefaultProfile != "a" {
		t.Errorf("DefaultProfile = %q; want a (second add without --set-default keeps it)", cfg.DefaultProfile)
	}
	// Fresh node_ids differ.
	if cfg.Profiles["a"].NodeID == cfg.Profiles["b"].NodeID {
		t.Error("two fresh node_ids are equal; want crypto/rand per profile")
	}
	if _, err := AddProfile(base, "c", AddProfileOptions{SetDefault: true}); err != nil {
		t.Fatal(err)
	}
	if got := loadProfiles(t, base).DefaultProfile; got != "c" {
		t.Errorf("DefaultProfile = %q; want c after --set-default", got)
	}
}

func TestAddProfileCookiesFileAndOutboundTag(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	seedSingleFile(t, base, singleFileJSON(`{"p":{"outbound":"proxy-sg"}}`, `[`+validOutbounds["socks"]+`]`, "", ""))

	p, err := AddProfile(base, "tagged", AddProfileOptions{OutboundTag: "proxy-sg"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Outbound.Kind != OutboundTag || p.Outbound.Tag != "proxy-sg" || p.Outbound.Type != "socks" {
		t.Errorf("Outbound = %+v; want tag/proxy-sg/socks", p.Outbound)
	}
	p2, err := AddProfile(base, "custom", AddProfileOptions{CookiesFile: filepath.Join(t.TempDir(), "elsewhere", "cookies.txt")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p2.CookiesFile, filepath.Join("elsewhere", "cookies.txt")) || strings.HasPrefix(p2.CookiesFile, base) {
		t.Errorf("CookiesFile = %q; want the absolute path outside baseDir preserved", p2.CookiesFile)
	}
	// A cookies_file inside baseDir but at another profile's file is
	// coerced to the profile's own file (the Python rule).
	p3, err := AddProfile(base, "coerced", AddProfileOptions{CookiesFile: "elsewhere/cookies.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if p3.CookiesFile != filepath.Join(base, "profiles", "coerced", "cookies.txt") {
		t.Errorf("CookiesFile = %q; want coercion to the profile's own file", p3.CookiesFile)
	}
	// Dangling tag: error, nothing written.
	before, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if _, err := AddProfile(base, "bad", AddProfileOptions{OutboundTag: "ghost"}); err == nil {
		t.Fatal("AddProfile with dangling tag = nil error; want error")
	}
	after, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if string(before) != string(after) {
		t.Error("failed AddProfile modified the file")
	}
}

func TestAddProfileRefusesSharedWireGuardPrivateKey(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	// wg-b carries the same key as wg-a but is unreferenced, so
	// the seed parses; adding beta -> wg-b must be refused at
	// write time (R-F2), leaving the file byte-identical and
	// still loadable. Before the fix AddProfile succeeded and
	// poisoned the file for every later load.
	seedSingleFile(t, base, singleFileJSON(`{"alpha":{"outbound":"wg-a"}}`, "", `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`,`+wgEndpointJSON("wg-b", fakeWGKeyAlpha)+`]`, ""))
	before, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AddProfile(base, "beta", AddProfileOptions{OutboundTag: "wg-b"}); err == nil {
		t.Fatal("AddProfile beta -> wg-b = nil error; want shared wireguard key error")
	} else {
		if ExitCode(err) != 2 {
			t.Errorf("ExitCode = %d; want 2", ExitCode(err))
		}
		if strings.Contains(err.Error(), fakeWGKeyAlpha) {
			t.Error("error contains the private key value")
		}
		if !strings.Contains(err.Error(), "alpha") || !strings.Contains(err.Error(), "beta") {
			t.Errorf("error %q; want it to name both profiles", err.Error())
		}
	}
	after, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("refused AddProfile modified the file")
	}
	if _, _, err := LoadSingleConfig(base); err != nil {
		t.Errorf("file no longer loads after refused AddProfile: %v", err)
	}
	// The file stays usable: an unrelated add still succeeds.
	if _, err := AddProfile(base, "gamma", AddProfileOptions{}); err != nil {
		t.Errorf("AddProfile gamma after refused add: %v; want success", err)
	}
}

func TestAddProfileRefusesUnmigrated(t *testing.T) {
	t.Parallel()
	// Legacy-flat base config.
	base := BaseDir(t.TempDir())
	writeFile(t, filepath.Join(base, "config.json"), `{"auto_approve":"always","node_id":"N1"}`, 0o600)
	if _, err := AddProfile(base, "work", AddProfileOptions{}); err == nil || !strings.Contains(err.Error(), "run config migrate first") {
		t.Errorf("AddProfile over legacy-flat = %v; want 'run config migrate first'", err)
	}
	before, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if string(before) != `{"auto_approve":"always","node_id":"N1"}` {
		t.Error("refused AddProfile modified the legacy file")
	}

	// Named legacy profiles only, no base config.
	base2 := BaseDir(t.TempDir())
	writeFile(t, filepath.Join(base2, "profiles", "work", "config.json"), `{"node_id":"W1"}`, 0o600)
	if _, err := AddProfile(base2, "new", AddProfileOptions{}); err == nil || !strings.Contains(err.Error(), "run config migrate first") {
		t.Errorf("AddProfile over named legacy layout = %v; want 'run config migrate first'", err)
	}

	// Single file exists + leftover legacy dir: adding a NEW name is
	// fine; adding the legacy name is a duplicate.
	base3 := BaseDir(t.TempDir())
	seedSingleFile(t, base3, singleFileJSON(`{"other":{}}`, "", "", ""))
	writeFile(t, filepath.Join(base3, "profiles", "work", "config.json"), `{"node_id":"W1"}`, 0o600)
	if _, err := AddProfile(base3, "fresh", AddProfileOptions{}); err != nil {
		t.Errorf("AddProfile with single file present = %v; want success", err)
	}
	if _, err := AddProfile(base3, "work", AddProfileOptions{}); err == nil {
		t.Error("AddProfile shadowing a legacy profile = nil error; want duplicate error")
	}
}

// TestAddProfileRefusesStrayDefaultLegacyFile (R4):
// profiles/default/config.json is the default profile's legacy
// file: adding "default" must never silently shadow it — with no
// single file the unmigrated-layout guard refuses, and with a
// single file present (but no default entry) the same-name legacy
// check refuses.
func TestAddProfileRefusesStrayDefaultLegacyFile(t *testing.T) {
	t.Parallel()
	stray := func(base string) string {
		return filepath.Join(base, "profiles", "default", "config.json")
	}

	// No single file: the stray file blocks adding "default".
	base := BaseDir(t.TempDir())
	writeFile(t, stray(base), `{"node_id":"S1"}`, 0o600)
	if _, err := AddProfile(base, "default", AddProfileOptions{}); err == nil || !strings.Contains(err.Error(), "run config migrate first") {
		t.Errorf("AddProfile(default) over stray-only layout = %v; want 'run config migrate first'", err)
	}
	if _, err := os.Stat(filepath.Join(base, "config.json")); err == nil {
		t.Error("refused AddProfile created a base config.json; want nothing written")
	}

	// Single file exists, no default entry: adding "default"
	// must refuse rather than shadow the stray file.
	base2 := BaseDir(t.TempDir())
	seedSingleFile(t, base2, singleFileJSON(`{"other":{}}`, "", "", ""))
	writeFile(t, stray(base2), `{"node_id":"S1"}`, 0o600)
	if _, err := AddProfile(base2, "default", AddProfileOptions{}); err == nil {
		t.Error("AddProfile(default) shadowing the stray file = nil error; want a refusal")
	}
	cfg, found, err := LoadSingleConfig(base2)
	if err != nil || !found {
		t.Fatalf("LoadSingleConfig = found=%v err=%v", found, err)
	}
	if _, ok := cfg.Profiles["default"]; ok {
		t.Error("refused AddProfile wrote a default entry shadowing the stray file")
	}

	// Adding an unrelated name with a single file present is
	// still fine: the stray file belongs to "default" only.
	if _, err := AddProfile(base2, "fresh", AddProfileOptions{}); err != nil {
		t.Errorf("AddProfile(fresh) with stray default file = %v; want success", err)
	}
}

// TestAddProfileBareDirectoryOnlySucceeds (F5): a bare profile
// directory with NO config file is not a legacy layout. Adding a
// profile must succeed, and legacyProfileExists must report false
// for a bare directory (true only for an actual config file).
func TestAddProfileBareDirectoryOnlySucceeds(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	bareDir := filepath.Join(base, "profiles", "work")
	if err := os.MkdirAll(bareDir, 0o700); err != nil {
		t.Fatal(err)
	}
	paths, err := ProfilePaths(base, "work")
	if err != nil {
		t.Fatal(err)
	}
	if legacyProfileExists(paths) {
		t.Error("legacyProfileExists(bare dir) = true; want false (no config file)")
	}
	if _, err := AddProfile(base, "new", AddProfileOptions{}); err != nil {
		t.Errorf("AddProfile over bare-directory-only layout = %v; want success", err)
	}
	if _, err := AddProfile(base, "work", AddProfileOptions{}); err != nil {
		t.Errorf("AddProfile(work) over its own bare directory = %v; want success", err)
	}
	// Control: an actual legacy config file still blocks the add
	// and is reported by legacyProfileExists.
	base2 := BaseDir(t.TempDir())
	writeFile(t, filepath.Join(base2, "profiles", "work", "config.json"), `{"node_id":"W1"}`, 0o600)
	paths2, err := ProfilePaths(base2, "work")
	if err != nil {
		t.Fatal(err)
	}
	if !legacyProfileExists(paths2) {
		t.Error("legacyProfileExists(config file) = false; want true")
	}
	if _, err := AddProfile(base2, "new", AddProfileOptions{}); err == nil || !strings.Contains(err.Error(), "run config migrate first") {
		t.Errorf("AddProfile over legacy file = %v; want 'run config migrate first'", err)
	}
}

func TestRemoveProfile(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	seedSingleFile(t, base, `{"default_profile":"work","profiles":{"default":{"cookies_file":"`+filepath.Join(base, "cookies.txt")+`","node_id":"N0","auto_approve":"off","auto_allow_once":false},"work":{"cookies_file":"`+filepath.Join(base, "profiles", "work", "cookies.txt")+`","node_id":"N1","auto_approve":"off","auto_allow_once":false}},"outbounds":[`+validOutbounds["socks"]+`]}`)
	// Files RemoveProfile must never touch.
	writeFile(t, filepath.Join(base, "profiles", "work", "cookies.txt"), "hatch_sess=FAKE\n", 0o600)
	writeFile(t, filepath.Join(base, "profiles", "work", "chat.json"), `[]`, 0o600)
	writeFile(t, filepath.Join(base, "profiles", "old", "config.json"), `{"node_id":"OLD"}`, 0o600)
	cookiesBefore, _ := os.ReadFile(filepath.Join(base, "profiles", "work", "cookies.txt"))
	legacyBefore, _ := os.ReadFile(filepath.Join(base, "profiles", "old", "config.json"))

	res, err := RemoveProfile(base, "work")
	if err != nil {
		t.Fatal(err)
	}
	if res.Warning == "" {
		t.Error("removing default_profile produced no warning; want a fallback warning")
	}
	if res.DefaultProfile != "default" {
		t.Errorf("DefaultProfile = %q; want fallback to default", res.DefaultProfile)
	}
	cfg := loadProfiles(t, base)
	if _, ok := cfg.Profiles["work"]; ok {
		t.Error("work still in single file after rm")
	}
	if len(cfg.Outbounds) != 1 {
		t.Errorf("outbounds = %d; removing a profile must not remove shared outbounds", len(cfg.Outbounds))
	}
	cookiesAfter, _ := os.ReadFile(filepath.Join(base, "profiles", "work", "cookies.txt"))
	if string(cookiesBefore) != string(cookiesAfter) {
		t.Error("RemoveProfile touched the cookies file")
	}
	legacyAfter, _ := os.ReadFile(filepath.Join(base, "profiles", "old", "config.json"))
	if string(legacyBefore) != string(legacyAfter) {
		t.Error("RemoveProfile touched the legacy file")
	}

	// Removing the last profile clears default_profile with warning.
	res2, err := RemoveProfile(base, "default")
	if err != nil {
		t.Fatal(err)
	}
	if res2.DefaultProfile != "" || res2.Warning == "" {
		t.Errorf("last rm = %+v; want DefaultProfile empty + warning", res2)
	}
	if got := loadProfiles(t, base); len(got.Profiles) != 0 {
		t.Errorf("profiles = %d; want 0", len(got.Profiles))
	}

	// Unknown name: error, nothing written.
	before, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if _, err := RemoveProfile(base, "ghost"); err == nil {
		t.Error("RemoveProfile unknown = nil error; want error")
	}
	after, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if string(before) != string(after) {
		t.Error("failed RemoveProfile modified the file")
	}
}

func TestRemoveProfileStrandingRefused(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	seedSingleFile(t, base, singleFileJSON(
		`{"a":{"outbound":{"type":"socks","tag":"shared-x","server":"127.0.0.1","server_port":1080}},"b":{"outbound":"shared-x"}}`, "", "", ""))
	before, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if _, err := RemoveProfile(base, "a"); err == nil {
		t.Fatal("removing a profile whose inline tag is referenced = nil error; want refusal")
	}
	after, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if string(before) != string(after) {
		t.Error("refused RemoveProfile modified the file")
	}
}

func TestRemoveProfileNoSingleFile(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	if _, err := RemoveProfile(base, "work"); err == nil {
		t.Error("RemoveProfile with no single file = nil error; want error")
	}
	writeFile(t, filepath.Join(base, "config.json"), `{"node_id":"N1"}`, 0o600)
	if _, err := RemoveProfile(base, "default"); err == nil || !strings.Contains(err.Error(), "config migrate") {
		t.Errorf("RemoveProfile over legacy layout = %v; want migrate guidance", err)
	}
}

func TestSetOutboundUntaggedInline(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	seedSingleFile(t, base, singleFileJSON(`{"p":{}}`, "", "", ""))
	p, err := SetOutbound(base, "p", []byte(`{"type":"http","server":"127.0.0.1","server_port":8080}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Outbound.Kind != OutboundInline || p.Outbound.Tag != "profile:p" || p.Outbound.Type != "http" {
		t.Errorf("Outbound = %+v; want inline/profile:p/http", p.Outbound)
	}
	cfg := loadProfiles(t, base)
	if got := cfg.Profiles["p"].Outbound; got.Kind != OutboundInline || got.Tag != "profile:p" {
		t.Errorf("reloaded Outbound = %+v", got)
	}
	if len(cfg.Outbounds) != 0 {
		t.Errorf("untagged object stored in outbounds (%d); want inline only", len(cfg.Outbounds))
	}
}

func TestSetOutboundTaggedAndWireGuard(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	seedSingleFile(t, base, singleFileJSON(`{"p":{},"q":{}}`, "", "", ""))

	p, err := SetOutbound(base, "p", []byte(`{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1080}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Outbound.Kind != OutboundTag || p.Outbound.Tag != "proxy-sg" || p.Outbound.Type != "socks" {
		t.Errorf("Outbound = %+v; want tag/proxy-sg/socks", p.Outbound)
	}
	cfg := loadProfiles(t, base)
	if len(cfg.Outbounds) != 1 || cfg.Outbounds[0].Tag != "proxy-sg" {
		t.Errorf("outbounds = %+v; want the tagged object stored", cfg.Outbounds)
	}
	if raw := cfg.RawOutbounds(); len(raw) != 1 || !strings.Contains(string(raw[0]), "127.0.0.1") {
		t.Errorf("raw outbounds = %q; want the original JSON preserved", raw)
	}

	// Untagged WireGuard goes to endpoints, auto-tagged.
	q, err := SetOutbound(base, "q", []byte(`{"type":"wireguard","address":["10.0.0.2/32"],"private_key":"FAKE-K","peers":[{"address":"203.0.113.10","port":51820,"public_key":"FAKE-PUB","allowed_ips":["0.0.0.0/0"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if q.Outbound.Kind != OutboundTag || q.Outbound.Tag != "profile:q" || q.Outbound.Type != "wireguard" {
		t.Errorf("Outbound = %+v; want tag/profile:q/wireguard", q.Outbound)
	}
	cfg = loadProfiles(t, base)
	if len(cfg.Endpoints) != 1 || cfg.Endpoints[0].Tag != "profile:q" {
		t.Errorf("endpoints = %+v; want the auto-tagged wireguard endpoint", cfg.Endpoints)
	}
}

func TestSetOutboundRejectsWrapperAndBadInput(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	seedSingleFile(t, base, singleFileJSON(`{"p":{}}`, "", "", ""))
	before, _ := os.ReadFile(filepath.Join(base, "config.json"))
	cases := map[string]string{
		"wrapper":          `{"outbound":{"type":"direct"}}`,
		"array":            `[{"type":"direct"}]`,
		"unknown type":     `{"type":"bogus-xyz"}`,
		"no type":          `{"server":"127.0.0.1"}`,
		"wireguard system": `{"type":"wireguard","tag":"wg","system":true,"address":["10.0.0.2/32"],"private_key":"FAKE-K","peers":[]}`,
		"not json":         `{oops}`,
		"empty":            ``,
	}
	for name, data := range cases {
		if _, err := SetOutbound(base, "p", []byte(data)); err == nil {
			t.Errorf("SetOutbound(%s) = nil error; want error", name)
		} else if ExitCode(err) != 2 {
			t.Errorf("SetOutbound(%s) ExitCode = %d; want 2", name, ExitCode(err))
		}
	}
	after, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if string(before) != string(after) {
		t.Error("rejected SetOutbound modified the file")
	}
	if _, err := SetOutbound(base, "ghost", []byte(`{"type":"direct"}`)); err == nil {
		t.Error("SetOutbound unknown profile = nil error; want error")
	}
}

func TestSetOutboundSameTagRules(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	seedSingleFile(t, base, singleFileJSON(
		`{"a":{"outbound":"proxy-sg"},"b":{},"c":{}}`,
		`[`+validOutbounds["socks"]+`]`, "", ""))

	// Same tag, same type, used by another profile: overwrite allowed.
	if _, err := SetOutbound(base, "b", []byte(`{"type":"socks","tag":"proxy-sg","server":"127.0.0.2","server_port":1081}`)); err != nil {
		t.Fatalf("same-type overwrite = %v; want success", err)
	}
	cfg := loadProfiles(t, base)
	if cfg.Outbounds[0].Tag != "proxy-sg" {
		t.Fatalf("outbounds = %+v", cfg.Outbounds)
	}
	if raw := cfg.RawOutbounds(); !strings.Contains(string(raw[0]), "127.0.0.2") {
		t.Errorf("overwrite did not replace raw json: %s", raw[0])
	}
	if got := cfg.Profiles["a"].Outbound.Type; got != "socks" {
		t.Errorf("profile a type = %q after overwrite; want socks", got)
	}

	// Same tag, different type, used by another profile: refused.
	before, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if _, err := SetOutbound(base, "c", []byte(`{"type":"http","tag":"proxy-sg","server":"127.0.0.1","server_port":8080}`)); err == nil {
		t.Fatal("different-type overwrite of a used tag = nil error; want refusal")
	}
	after, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if string(before) != string(after) {
		t.Error("refused SetOutbound modified the file")
	}

	// Duplicate tag across sections: refused.
	if _, err := SetOutbound(base, "c", []byte(`{"type":"wireguard","tag":"proxy-sg","address":["10.0.0.2/32"],"private_key":"FAKE-K","peers":[]}`)); err == nil {
		t.Error("endpoint reusing an outbound tag = nil error; want refusal")
	}

	// Unreferenced tag, different type: overwrite allowed.
	seedSingleFile(t, base, singleFileJSON(
		`{"a":{},"b":{}}`,
		`[`+validOutbounds["socks"]+`]`, "", ""))
	if _, err := SetOutbound(base, "b", []byte(`{"type":"http","tag":"proxy-sg","server":"127.0.0.1","server_port":8080}`)); err != nil {
		t.Fatalf("overwrite of unreferenced tag = %v; want success", err)
	}
	if got := loadProfiles(t, base).Outbounds[0].Type; got != "http" {
		t.Errorf("outbound type = %q; want http after overwrite", got)
	}
}

func TestSetOutboundNoSingleFile(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	if _, err := SetOutbound(base, "p", []byte(`{"type":"direct"}`)); err == nil {
		t.Error("SetOutbound with no single file = nil error; want error")
	}
}

// TestRedactedDisplayAfterSetOutbound pins task 6: RedactProfile /
// RedactConfig behaviour is unchanged for entries created through
// the new library API — identity fields and the password never
// appear in display output.
func TestRedactedDisplayAfterSetOutbound(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	if _, err := AddProfile(base, "p", AddProfileOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := SetOutbound(base, "p", []byte(`{"type":"socks","server":"127.0.0.1","server_port":1080,"username":"FAKE-USER","password":"FAKE-PW"}`)); err != nil {
		t.Fatal(err)
	}
	cfg := loadProfiles(t, base)
	shown, err := RedactProfile(cfg.Profiles["p"])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(shown), "FAKE-PW") {
		t.Errorf("RedactProfile leaks password: %s", shown)
	}
	if strings.Contains(string(shown), cfg.Profiles["p"].NodeID) {
		t.Errorf("RedactProfile leaks node_id: %s", shown)
	}
	shownCfg, err := RedactConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(shownCfg), "FAKE-PW") {
		t.Errorf("RedactConfig leaks password: %s", shownCfg)
	}
}
