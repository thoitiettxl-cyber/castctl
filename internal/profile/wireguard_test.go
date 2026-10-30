// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Fake WireGuard private keys for fixtures only. They are redacted
// placeholders in the PR1 style, never real key material. Tests assert
// these strings never appear in any error produced by the validator.
const (
	fakeWGKeyAlpha = "FAKE-PRIVATE-KEY-ALPHA"
	fakeWGKeyBeta  = "FAKE-PRIVATE-KEY-BETA"
)

func wgEndpointJSON(tag, key string) string {
	return `{"type":"wireguard","tag":"` + tag + `","address":["10.0.0.2/32"],"private_key":"` + key + `","peers":[{"address":"203.0.113.10","port":51820,"public_key":"FAKE-PUBKEY","allowed_ips":["0.0.0.0/0"]}]}`
}

func TestWireGuardPrivateKeySharedByTwoProfiles(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		data    string
		wantTag []string
	}{
		{
			name:    "two endpoints same key",
			data:    singleFileJSON(`{"alpha":{"outbound":"wg-a"},"beta":{"outbound":"wg-b"}}`, "", `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`,`+wgEndpointJSON("wg-b", fakeWGKeyAlpha)+`]`, ""),
			wantTag: []string{"wg-a", "wg-b"},
		},
		{
			name:    "shared endpoint tag same key",
			data:    singleFileJSON(`{"alpha":{"outbound":"wg"},"beta":{"outbound":"wg"}}`, "", `[`+wgEndpointJSON("wg", fakeWGKeyAlpha)+`]`, ""),
			wantTag: []string{"wg"},
		},
		{
			name:    "detour chain same key",
			data:    singleFileJSON(`{"alpha":{"outbound":"proxy-sg"},"beta":{"outbound":"wg-b"}}`, `[{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1080,"detour":"wg-a"}]`, `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`,`+wgEndpointJSON("wg-b", fakeWGKeyAlpha)+`]`, ""),
			wantTag: []string{"wg-a", "wg-b"},
		},
		{
			name:    "selector member same key",
			data:    singleFileJSON(`{"alpha":{"outbound":"sel"},"beta":{"outbound":"wg-b"}}`, `[{"type":"selector","tag":"sel","outbounds":["wg-a"]}]`, `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`,`+wgEndpointJSON("wg-b", fakeWGKeyAlpha)+`]`, ""),
			wantTag: []string{"wg-a", "wg-b"},
		},
		{
			name:    "inline outbound detour same key",
			data:    singleFileJSON(`{"alpha":{"outbound":{"type":"socks","server":"127.0.0.1","server_port":1080,"detour":"wg-a"}},"beta":{"outbound":"wg-b"}}`, "", `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`,`+wgEndpointJSON("wg-b", fakeWGKeyAlpha)+`]`, ""),
			wantTag: []string{"wg-a", "wg-b"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseSingleConfig([]byte(tc.data), "/base")
			if err == nil {
				t.Fatal("ParseSingleConfig = nil error; want shared wireguard key error")
			}
			if ExitCode(err) != 2 {
				t.Errorf("ExitCode = %d; want 2", ExitCode(err))
			}
			if !errors.Is(err, ErrConfigParse) {
				t.Errorf("error %v; want errors.Is ErrConfigParse", err)
			}
			msg := err.Error()
			for _, name := range []string{"alpha", "beta"} {
				if !strings.Contains(msg, name) {
					t.Errorf("error %q; want it to name profile %q", msg, name)
				}
			}
			for _, tag := range tc.wantTag {
				if !strings.Contains(msg, tag) {
					t.Errorf("error %q; want it to name endpoint %q", msg, tag)
				}
			}
			if strings.Contains(msg, fakeWGKeyAlpha) {
				t.Error("error contains the private key value; the key must never appear in errors")
			}
		})
	}
}

func TestWireGuardPrivateKeyDistinctOrUnreferenced(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		data string
	}{
		{
			name: "different keys",
			data: singleFileJSON(`{"alpha":{"outbound":"wg-a"},"beta":{"outbound":"wg-b"}}`, "", `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`,`+wgEndpointJSON("wg-b", fakeWGKeyBeta)+`]`, ""),
		},
		{
			name: "single profile",
			data: singleFileJSON(`{"alpha":{"outbound":"wg-a"}}`, "", `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`]`, ""),
		},
		{
			name: "unreferenced duplicate out of scope",
			data: singleFileJSON(`{"alpha":{"outbound":"wg-a"},"beta":{}}`, "", `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`,`+wgEndpointJSON("wg-b", fakeWGKeyAlpha)+`]`, ""),
		},
		{
			name: "same profile two endpoints same key out of scope",
			data: singleFileJSON(`{"alpha":{"outbound":"sel"}}`, `[{"type":"selector","tag":"sel","outbounds":["wg-a","wg-b"]}]`, `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`,`+wgEndpointJSON("wg-b", fakeWGKeyAlpha)+`]`, ""),
		},
		{
			name: "empty keys are not a shared key",
			data: singleFileJSON(`{"alpha":{"outbound":"wg-a"},"beta":{"outbound":"wg-b"}}`, "", `[`+wgEndpointJSON("wg-a", "")+`,`+wgEndpointJSON("wg-b", "")+`]`, ""),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseSingleConfig([]byte(tc.data), "/base"); err != nil {
				t.Errorf("ParseSingleConfig error: %v; want no error", err)
			}
		})
	}
}

// TestWireGuardPrivateKeyLoadSingleConfig pins the check on the file
// load path (LoadSingleConfig -> ParseSingleConfig) and the
// LoadProfile path that every consumer uses.
func TestWireGuardPrivateKeyLoadSingleConfig(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	duplicate := singleFileJSON(`{"alpha":{"outbound":"wg-a"},"beta":{"outbound":"wg-b"}}`, "", `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`,`+wgEndpointJSON("wg-b", fakeWGKeyAlpha)+`]`, "")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "config.json"), []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadSingleConfig(base); err == nil {
		t.Error("LoadSingleConfig = nil error; want shared wireguard key error")
	} else {
		if ExitCode(err) != 2 {
			t.Errorf("LoadSingleConfig ExitCode = %d; want 2", ExitCode(err))
		}
		if strings.Contains(err.Error(), fakeWGKeyAlpha) {
			t.Error("load error contains the private key value")
		}
	}
	if _, err := LoadProfile(base, "alpha", nil); err == nil {
		t.Error("LoadProfile = nil error; want shared wireguard key error")
	}

	distinct := singleFileJSON(`{"alpha":{"outbound":"wg-a"},"beta":{"outbound":"wg-b"}}`, "", `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`,`+wgEndpointJSON("wg-b", fakeWGKeyBeta)+`]`, "")
	if err := os.WriteFile(filepath.Join(base, "config.json"), []byte(distinct), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, found, err := LoadSingleConfig(base)
	if err != nil || !found {
		t.Fatalf("LoadSingleConfig = %+v, %v, %v; want config", cfg, found, err)
	}
	if _, err := LoadProfile(base, "beta", nil); err != nil {
		t.Errorf("LoadProfile error: %v; want no error", err)
	}
}

// TestSetOutboundRefusesSharedWireGuardPrivateKey pins the write-time
// refusal: SetOutbound must not persist a file that every later load
// would reject.
func TestSetOutboundRefusesSharedWireGuardPrivateKey(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	seedSingleFile(t, base, singleFileJSON(`{"a":{"outbound":"wg-a"},"b":{}}`, "", `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`]`, ""))
	before, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Untagged: ensureInlineTag auto-tags it profile:b.
	duplicate := []byte(`{"type":"wireguard","address":["10.0.0.2/32"],"private_key":"` + fakeWGKeyAlpha + `","peers":[{"address":"203.0.113.10","port":51820,"public_key":"FAKE-PUBKEY","allowed_ips":["0.0.0.0/0"]}]}`)
	if _, err := SetOutbound(base, "b", duplicate); err == nil {
		t.Error("SetOutbound = nil error; want shared wireguard key error")
	} else {
		if ExitCode(err) != 2 {
			t.Errorf("SetOutbound ExitCode = %d; want 2", ExitCode(err))
		}
		if strings.Contains(err.Error(), fakeWGKeyAlpha) {
			t.Error("SetOutbound error contains the private key value")
		}
		if !strings.Contains(err.Error(), "a") || !strings.Contains(err.Error(), "b") {
			t.Errorf("SetOutbound error %q; want it to name both profiles", err.Error())
		}
	}
	after, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("refused SetOutbound modified the file")
	}
	// A distinct key succeeds and persists.
	distinct := []byte(`{"type":"wireguard","address":["10.0.0.2/32"],"private_key":"` + fakeWGKeyBeta + `","peers":[{"address":"203.0.113.10","port":51820,"public_key":"FAKE-PUBKEY","allowed_ips":["0.0.0.0/0"]}]}`)
	p, err := SetOutbound(base, "b", distinct)
	if err != nil {
		t.Fatal(err)
	}
	if p.Outbound.Kind != OutboundTag || p.Outbound.Tag != "profile:b" {
		t.Errorf("Outbound = %+v; want tag/profile:b", p.Outbound)
	}
	if _, _, err := LoadSingleConfig(base); err != nil {
		t.Errorf("reloaded config error: %v; want no error", err)
	}
}

// TestLoadSingleConfigConcurrentIsolation pins that concurrent loads
// return independent values with no shared mutable state: loads run
// in parallel under -race, and mutating one result never affects a
// fresh load.
func TestLoadSingleConfigConcurrentIsolation(t *testing.T) {
	base := BaseDir(t.TempDir())
	data := singleFileJSON(`{"alpha":{"outbound":"wg-a"},"beta":{"outbound":"wg-b"}}`, "", `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`,`+wgEndpointJSON("wg-b", fakeWGKeyBeta)+`]`, "")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "config.json"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	const workers = 16
	const iters = 25
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				if _, found, err := LoadSingleConfig(base); err != nil || !found {
					errs <- err
					return
				}
				name := "alpha"
				if j%2 == 0 {
					name = "beta"
				}
				if _, err := LoadProfile(base, name, nil); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent load error: %v", err)
	}

	cfg1, _, err := LoadSingleConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	cfg1.Profiles["alpha"].VMID = "MUTATED-VMID"
	cfg1.Endpoints[0].Tag = "MUTATED-TAG"
	cfg2, _, err := LoadSingleConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Profiles["alpha"].VMID == "MUTATED-VMID" {
		t.Error("fresh load shares mutated profile state with an earlier load")
	}
	if cfg2.Endpoints[0].Tag == "MUTATED-TAG" {
		t.Error("fresh load shares mutated endpoint state with an earlier load")
	}

	p1, err := LoadProfile(base, "alpha", nil)
	if err != nil {
		t.Fatal(err)
	}
	p1.VMID = "MUTATED-VMID"
	p2, err := LoadProfile(base, "alpha", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p2.VMID == "MUTATED-VMID" {
		t.Error("fresh LoadProfile shares mutated state with an earlier load")
	}
}

// TestWireGuardPrivateKeySharedViaDNSDetour pins RT-F6: the global
// dns section's detour chains are part of every profile's resolved
// set, so a profile key equal to a dns-detour key is the same
// sharing violation, naming the profile and "dns".
func TestWireGuardPrivateKeySharedViaDNSDetour(t *testing.T) {
	t.Parallel()
	dnsDirect := `{"servers":[{"type":"https","tag":"dns-remote","server":"1.1.1.1","server_port":443,"path":"/dns-query","detour":"wg-b"}],"final":"dns-remote"}`
	dnsChain := `{"servers":[{"type":"https","tag":"dns-remote","server":"1.1.1.1","server_port":443,"path":"/dns-query","detour":"proxy-sg"}],"final":"dns-remote"}`
	socksChain := `[{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1080,"detour":"wg-b"}]`
	endpoints := `[` + wgEndpointJSON("wg-a", fakeWGKeyAlpha) + `,` + wgEndpointJSON("wg-b", fakeWGKeyAlpha) + `]`
	endpointsDistinct := `[` + wgEndpointJSON("wg-a", fakeWGKeyAlpha) + `,` + wgEndpointJSON("wg-b", fakeWGKeyBeta) + `]`
	cases := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{
			name:    "direct dns detour same key",
			data:    singleFileJSON(`{"alpha":{"outbound":"wg-a"}}`, "", endpoints, dnsDirect),
			wantErr: true,
		},
		{
			name:    "dns detour via outbound chain same key",
			data:    singleFileJSON(`{"alpha":{"outbound":"wg-a"}}`, socksChain, endpoints, dnsChain),
			wantErr: true,
		},
		{
			name:    "dns detour is the profile endpoint itself (same tag)",
			data:    singleFileJSON(`{"alpha":{"outbound":"wg-a"}}`, "", `[`+wgEndpointJSON("wg-a", fakeWGKeyAlpha)+`]`, `{"servers":[{"type":"https","tag":"dns-remote","server":"1.1.1.1","server_port":443,"path":"/dns-query","detour":"wg-a"}],"final":"dns-remote"}`),
			wantErr: false,
		},
		{
			name:    "dns detour distinct key",
			data:    singleFileJSON(`{"alpha":{"outbound":"wg-a"}}`, "", endpointsDistinct, dnsDirect),
			wantErr: false,
		},
		{
			name:    "dns detour same key but no profile uses wireguard",
			data:    singleFileJSON(`{"alpha":{}}`, "", endpoints, dnsDirect),
			wantErr: false,
		},
		{
			name:    "dns server without detour, dormant duplicate out of scope",
			data:    singleFileJSON(`{"alpha":{"outbound":"wg-a"}}`, "", endpoints, `{"servers":[{"type":"https","tag":"dns-remote","server":"1.1.1.1","server_port":443,"path":"/dns-query"}],"final":"dns-remote"}`),
			wantErr: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseSingleConfig([]byte(tc.data), "/base")
			if tc.wantErr {
				if err == nil {
					t.Fatal("ParseSingleConfig = nil error; want shared wireguard key error (profile vs dns)")
				}
				msg := err.Error()
				for _, want := range []string{"alpha", "dns", "wg-a", "wg-b"} {
					if !strings.Contains(msg, want) {
						t.Errorf("error %q; want it to name %q", msg, want)
					}
				}
				if strings.Contains(msg, fakeWGKeyAlpha) {
					t.Error("error contains the private key value")
				}
				return
			}
			if err != nil {
				t.Errorf("ParseSingleConfig error: %v; want no error", err)
			}
		})
	}
}

// TestWireGuardPrivateKeyCanonicalComparison pins RT-F7: keys
// compare by decoded bytes when both base64-decode, and by exact
// string otherwise.
func TestWireGuardPrivateKeyCanonicalComparison(t *testing.T) {
	t.Parallel()
	// Padding-bit variants: both decode (StdEncoding) to 32
	// zero bytes. Verified with stdlib base64 before writing
	// this test.
	zeroKeyA := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	zeroKeyB := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB="
	if a, _ := base64.StdEncoding.DecodeString(zeroKeyA); len(a) != 32 {
		t.Fatalf("fixture zeroKeyA decodes to %d bytes, want 32", len(a))
	}
	if b, _ := base64.StdEncoding.DecodeString(zeroKeyB); len(b) != 32 {
		t.Fatalf("fixture zeroKeyB decodes to %d bytes, want 32", len(b))
	}
	ones := base64.StdEncoding.EncodeToString(make([]byte, 32))
	twos := base64.StdEncoding.EncodeToString(func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = 2
		}
		return b
	}())
	cases := []struct {
		name    string
		keyA    string
		keyB    string
		wantErr bool
	}{
		{name: "padding-bit variants same bytes", keyA: zeroKeyA, keyB: zeroKeyB, wantErr: true},
		{name: "distinct decodable keys", keyA: ones, keyB: twos, wantErr: false},
		{name: "identical decodable keys", keyA: ones, keyB: ones, wantErr: true},
		{name: "undecodable identical strings", keyA: fakeWGKeyAlpha, keyB: fakeWGKeyAlpha, wantErr: true},
		{name: "undecodable distinct strings", keyA: fakeWGKeyAlpha, keyB: fakeWGKeyBeta, wantErr: false},
		{name: "one decodable one undecodable", keyA: ones, keyB: fakeWGKeyAlpha, wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := singleFileJSON(`{"alpha":{"outbound":"wg-a"},"beta":{"outbound":"wg-b"}}`, "", `[`+wgEndpointJSON("wg-a", tc.keyA)+`,`+wgEndpointJSON("wg-b", tc.keyB)+`]`, "")
			_, err := ParseSingleConfig([]byte(data), "/base")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("keys %q/%q: nil error; want shared wireguard key error", tc.keyA, tc.keyB)
				}
				if strings.Contains(err.Error(), tc.keyA) || strings.Contains(err.Error(), tc.keyB) {
					t.Errorf("error contains key material: %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Errorf("keys %q/%q: error %v; want no error", tc.keyA, tc.keyB, err)
			}
		})
	}
}
