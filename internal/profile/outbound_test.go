// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"testing"
)

func TestOutboundRefResolution(t *testing.T) {
	t.Parallel()
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"tagged":{"outbound":"proxy-sg"},"endpointed":{"outbound":"wg-home"},"inlined":{"outbound":{"type":"http","tag":"inline-http","server":"127.0.0.1","server_port":8080}},"untagged":{"outbound":{"type":"direct"}},"absent":{}}`,
		`[`+validOutbounds["socks"]+`]`,
		`[`+validOutbounds["wireguard-ep"]+`]`, "")), "/base")
	if err != nil {
		t.Fatal(err)
	}
	tagged := cfg.Profiles["tagged"].Outbound
	if tagged.Kind != OutboundTag || tagged.Tag != "proxy-sg" || tagged.Type != "socks" || tagged.From != "outbound" {
		t.Errorf("tagged = %+v; want tag/proxy-sg/socks/outbound", tagged)
	}
	ep := cfg.Profiles["endpointed"].Outbound
	if ep.Kind != OutboundTag || ep.Tag != "wg-home" || ep.Type != "wireguard" || ep.From != "endpoint" {
		t.Errorf("endpointed = %+v; want tag/wg-home/wireguard/endpoint", ep)
	}
	inl := cfg.Profiles["inlined"].Outbound
	if inl.Kind != OutboundInline || inl.Type != "http" || inl.Tag != "inline-http" {
		t.Errorf("inlined = %+v; want inline/http/inline-http", inl)
	}
	ob, err := inl.InlineOutbound()
	if err != nil || ob == nil || ob.Type != "http" {
		t.Errorf("InlineOutbound = %+v, %v; want http outbound", ob, err)
	}
	untagged := cfg.Profiles["untagged"].Outbound
	if untagged.Kind != OutboundInline || untagged.Tag != "profile:untagged" {
		t.Errorf("untagged inline = %+v; want auto-tag profile:untagged", untagged)
	}
	absent := cfg.Profiles["absent"].Outbound
	if absent.Kind != OutboundDirect || absent.Type != "direct" {
		t.Errorf("absent = %+v; want direct", absent)
	}
	if ob2, err := absent.InlineOutbound(); err != nil || ob2 != nil {
		t.Errorf("direct InlineOutbound = %+v, %v; want nil, nil", ob2, err)
	}
	if ob3, err := tagged.InlineOutbound(); err != nil || ob3 != nil {
		t.Errorf("tag InlineOutbound = %+v, %v; want nil, nil", ob3, err)
	}
}

func TestSingleConfigAccessors(t *testing.T) {
	t.Parallel()
	cfg, err := ParseSingleConfig([]byte(singleFileJSON(
		`{"p":{"outbound":"proxy-sg"}}`,
		`[`+validOutbounds["socks"]+`]`,
		`[`+validOutbounds["wireguard-ep"]+`]`,
		`{"servers":[{"type":"https","tag":"dns-remote","server":"1.1.1.1","server_port":443}],"final":"dns-remote"}`,
	)), "/base")
	if err != nil {
		t.Fatal(err)
	}
	if names := cfg.ProfileNames(); len(names) != 1 || names[0] != "p" {
		t.Errorf("ProfileNames = %v; want [p]", names)
	}
	dns, err := cfg.ParsedDNS()
	if err != nil || dns == nil {
		t.Errorf("ParsedDNS = %+v, %v; want non-nil", dns, err)
	}
	raw := cfg.RawOutbounds()
	if len(raw) != 1 {
		t.Fatalf("RawOutbounds len = %d; want 1", len(raw))
	}
	// Mutating the returned copy must not affect the stored raw bytes.
	raw[0][0] = 'X'
	if raw2 := cfg.RawOutbounds(); len(raw2) == 0 || raw2[0][0] == 'X' {
		t.Error("RawOutbounds returned shared bytes; want defensive copy")
	}
	if got := cfg.RawDNS(); len(got) == 0 {
		t.Error("RawDNS empty; want dns bytes")
	}
}

func TestInlineOutboundRawRoundTrip(t *testing.T) {
	t.Parallel()
	cfg, err := ParseSingleConfig([]byte(`{"profiles":{"p":{"outbound":{"type":"socks","tag":"x","server":"127.0.0.1","server_port":1080,"password":"FAKE-PW"}}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	ref := cfg.Profiles["p"].Outbound
	if len(ref.RawJSON()) == 0 {
		t.Fatal("inline RawJSON empty")
	}
	redacted, err := RedactOutboundJSON(ref.RawJSON())
	if err != nil {
		t.Fatal(err)
	}
	if containsStr(string(redacted), "FAKE-PW") {
		t.Errorf("redacted inline raw contains secret: %s", redacted)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
