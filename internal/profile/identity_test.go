// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestOutboundIdentityDirect(t *testing.T) {
	t.Parallel()
	p := &Profile{Name: "p", Outbound: OutboundRef{Kind: OutboundDirect, Type: "direct"}}
	tag, hash, err := OutboundIdentity(p)
	if err != nil {
		t.Fatal(err)
	}
	if tag != "direct" {
		t.Errorf("tag = %q; want direct", tag)
	}
	sum := sha256.Sum256([]byte(`{"type":"direct","tag":"direct"}`))
	if hash != hex.EncodeToString(sum[:]) {
		t.Errorf("hash = %q; want sha256 of the fixed direct bytes", hash)
	}
	if _, _, err := OutboundIdentity(nil); err == nil {
		t.Error("OutboundIdentity(nil) = nil error; want error")
	}
}

func TestOutboundIdentityInline(t *testing.T) {
	t.Parallel()
	cfg1, err := ParseSingleConfig([]byte(`{"profiles":{"p":{"outbound":{"type":"socks","server":"127.0.0.1","server_port":1080}}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	cfg2, err := ParseSingleConfig([]byte(`{"profiles":{"p":{"outbound":{ "type" : "socks" , "server" : "127.0.0.1" , "server_port" : 1080 }}}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	tag1, hash1, err := OutboundIdentity(cfg1.Profiles["p"])
	if err != nil {
		t.Fatal(err)
	}
	tag2, hash2, err := OutboundIdentity(cfg2.Profiles["p"])
	if err != nil {
		t.Fatal(err)
	}
	if tag1 != "profile:p" || tag2 != "profile:p" {
		t.Errorf("tags = %q, %q; want profile:p", tag1, tag2)
	}
	// Whitespace-only differences canonicalise to the same hash.
	if hash1 != hash2 {
		t.Errorf("hashes differ for whitespace-only variants: %q vs %q", hash1, hash2)
	}
	// A different server changes the identity.
	cfg3, err := ParseSingleConfig([]byte(`{"profiles":{"p":{"outbound":{"type":"socks","server":"127.0.0.2","server_port":1080}}}}`), "/base")
	if err != nil {
		t.Fatal(err)
	}
	_, hash3, err := OutboundIdentity(cfg3.Profiles["p"])
	if err != nil {
		t.Fatal(err)
	}
	if hash3 == hash1 {
		t.Error("hash unchanged after server change; want a new identity (reconnect key)")
	}
}

func TestOutboundIdentityTagVsConfig(t *testing.T) {
	t.Parallel()
	jsonA := singleFileJSON(`{"p":{"outbound":"proxy-sg"}}`, `[`+validOutbounds["socks"]+`]`, "", "")
	jsonB := singleFileJSON(`{"p":{"outbound":"proxy-sg"}}`, `[{"type":"socks","tag":"proxy-sg","server":"127.0.0.2","server_port":1080}]`, "", "")
	cfgA, err := ParseSingleConfig([]byte(jsonA), "/base")
	if err != nil {
		t.Fatal(err)
	}
	cfgB, err := ParseSingleConfig([]byte(jsonB), "/base")
	if err != nil {
		t.Fatal(err)
	}
	// Profile-only identity is blind to edits of the referenced
	// object (pinned limitation): same tag/type, same hash.
	_, hashA, err := OutboundIdentity(cfgA.Profiles["p"])
	if err != nil {
		t.Fatal(err)
	}
	_, hashB, err := OutboundIdentity(cfgB.Profiles["p"])
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashB {
		t.Errorf("Profile-only tag identities differ: %q vs %q (must be equal; the config form carries the change)", hashA, hashB)
	}
	// Config-aware identity sees the edit: different hash, same tag.
	tagA, cfgHashA, err := OutboundIdentityForConfig(cfgA, "p")
	if err != nil {
		t.Fatal(err)
	}
	tagB, cfgHashB, err := OutboundIdentityForConfig(cfgB, "p")
	if err != nil {
		t.Fatal(err)
	}
	if tagA != "proxy-sg" || tagB != "proxy-sg" {
		t.Errorf("tags = %q, %q; want proxy-sg", tagA, tagB)
	}
	if cfgHashA == cfgHashB {
		t.Error("config-aware identities equal after server change; want a new identity (reconnect key)")
	}
	// Endpoint references resolve through endpoints.
	cfgE, err := ParseSingleConfig([]byte(singleFileJSON(`{"p":{"outbound":"wg-home"}}`, "", `[`+validOutbounds["wireguard-ep"]+`]`, "")), "/base")
	if err != nil {
		t.Fatal(err)
	}
	if tag, _, err := OutboundIdentityForConfig(cfgE, "p"); err != nil || tag != "wg-home" {
		t.Errorf("endpoint identity = %q, %v; want wg-home", tag, err)
	}
	// Unknown profile / dangling tag: errors.
	if _, _, err := OutboundIdentityForConfig(cfgA, "ghost"); err == nil {
		t.Error("OutboundIdentityForConfig unknown profile = nil error; want error")
	}
	dangling := &SingleConfig{Profiles: map[string]*Profile{
		"p": {Name: "p", Outbound: OutboundRef{Kind: OutboundTag, Tag: "ghost", Type: "socks"}},
	}}
	if _, _, err := OutboundIdentityForConfig(dangling, "p"); err == nil {
		t.Error("OutboundIdentityForConfig dangling tag = nil error; want error")
	}
	if _, _, err := OutboundIdentityForConfig(nil, "p"); err == nil {
		t.Error("OutboundIdentityForConfig nil config = nil error; want error")
	}
}
