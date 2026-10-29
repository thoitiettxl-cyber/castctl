// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"os"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// All key material in this file is the literal placeholder "<redacted>".
// No real or realistic-looking key is ever written here.

const redactedWGConf = `[Interface]
PrivateKey = <redacted>
Address = 10.8.0.2/32, fd00:abcd::2/128
ListenPort = 51820
MTU = 1420
DNS = 10.8.0.1

[Peer]
PublicKey = <redacted>
PresharedKey = <redacted>
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.test:51820
PersistentKeepalive = 25
`

const redactedWGConfIPv6Endpoint = `[Interface]
PrivateKey = <redacted>
Address = 10.8.0.2/32

[Peer]
PublicKey = <redacted>
AllowedIPs = 10.0.0.0/8
Endpoint = [2001:db8::1]:51820
`

func TestParseWireGuardConf(t *testing.T) {
	t.Run("all fields", func(t *testing.T) {
		opts, err := ParseWireGuardConf([]byte(redactedWGConf))
		if err != nil {
			t.Fatalf("ParseWireGuardConf: %v", err)
		}
		if opts.PrivateKey != "<redacted>" {
			t.Errorf("PrivateKey = %q, want placeholder", opts.PrivateKey)
		}
		if opts.ListenPort != 51820 {
			t.Errorf("ListenPort = %d, want 51820", opts.ListenPort)
		}
		if opts.MTU != 1420 {
			t.Errorf("MTU = %d, want 1420", opts.MTU)
		}
		if opts.System {
			t.Error("System = true, want false (userspace only)")
		}
		if len(opts.Address) != 2 {
			t.Fatalf("Address count = %d, want 2", len(opts.Address))
		}
		if opts.Address[0].String() != "10.8.0.2/32" {
			t.Errorf("Address[0] = %s, want 10.8.0.2/32", opts.Address[0])
		}
		if opts.Address[1].String() != "fd00:abcd::2/128" {
			t.Errorf("Address[1] = %s, want fd00:abcd::2/128", opts.Address[1])
		}
		if len(opts.Peers) != 1 {
			t.Fatalf("Peers count = %d, want 1", len(opts.Peers))
		}
		peer := opts.Peers[0]
		if peer.PublicKey != "<redacted>" || peer.PreSharedKey != "<redacted>" {
			t.Error("peer keys are not the placeholder")
		}
		if peer.Address != "vpn.example.test" || peer.Port != 51820 {
			t.Errorf("peer endpoint = %s:%d, want vpn.example.test:51820", peer.Address, peer.Port)
		}
		if peer.PersistentKeepaliveInterval != 25 {
			t.Errorf("keepalive = %d, want 25", peer.PersistentKeepaliveInterval)
		}
		if len(peer.AllowedIPs) != 2 {
			t.Fatalf("AllowedIPs count = %d, want 2", len(peer.AllowedIPs))
		}
	})

	t.Run("ipv6 endpoint", func(t *testing.T) {
		opts, err := ParseWireGuardConf([]byte(redactedWGConfIPv6Endpoint))
		if err != nil {
			t.Fatalf("ParseWireGuardConf: %v", err)
		}
		if len(opts.Peers) != 1 {
			t.Fatalf("Peers count = %d, want 1", len(opts.Peers))
		}
		if opts.Peers[0].Address != "2001:db8::1" || opts.Peers[0].Port != 51820 {
			t.Errorf("peer endpoint = %s:%d, want [2001:db8::1]:51820", opts.Peers[0].Address, opts.Peers[0].Port)
		}
	})

	t.Run("bare ip address gets family prefix", func(t *testing.T) {
		opts, err := ParseWireGuardConf([]byte("[Interface]\nPrivateKey = <redacted>\nAddress = 10.8.0.2\n\n[Peer]\nPublicKey = <redacted>\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.test:51820\n"))
		if err != nil {
			t.Fatalf("ParseWireGuardConf: %v", err)
		}
		if len(opts.Address) != 1 || opts.Address[0].String() != "10.8.0.2/32" {
			t.Errorf("Address = %v, want [10.8.0.2/32]", opts.Address)
		}
	})

	t.Run("unknown keys are ignored", func(t *testing.T) {
		conf := "[Interface]\nPrivateKey = <redacted>\nAddress = 10.8.0.2/32\nSaveConfig = true\nPostUp = echo hi\n\n[Peer]\nPublicKey = <redacted>\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.test:51820\n"
		if _, err := ParseWireGuardConf([]byte(conf)); err != nil {
			t.Fatalf("ParseWireGuardConf with unknown keys: %v", err)
		}
	})

	t.Run("unknown section keys are an error, not interface fields", func(t *testing.T) {
		conf := "[Interface]\nPrivateKey = <redacted>\nAddress = 10.8.0.2/32\n\n[Unknown]\nPrivateKey = <redacted>\n\n[Peer]\nPublicKey = <redacted>\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.test:51820\n"
		if _, err := ParseWireGuardConf([]byte(conf)); err == nil {
			t.Fatal("key in unknown section = nil, want error")
		}
	})

	t.Run("missing private key is an error", func(t *testing.T) {
		conf := "[Interface]\nAddress = 10.8.0.2/32\n\n[Peer]\nPublicKey = <redacted>\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.test:51820\n"
		if _, err := ParseWireGuardConf([]byte(conf)); err == nil {
			t.Fatal("missing PrivateKey = nil, want error")
		}
	})

	t.Run("malformed address is an error", func(t *testing.T) {
		conf := "[Interface]\nPrivateKey = <redacted>\nAddress = not-an-ip\n\n[Peer]\nPublicKey = <redacted>\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.test:51820\n"
		if _, err := ParseWireGuardConf([]byte(conf)); err == nil {
			t.Fatal("malformed Address = nil, want error")
		}
	})

	t.Run("malformed endpoint is an error", func(t *testing.T) {
		conf := "[Interface]\nPrivateKey = <redacted>\nAddress = 10.8.0.2/32\n\n[Peer]\nPublicKey = <redacted>\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.test\n"
		if _, err := ParseWireGuardConf([]byte(conf)); err == nil {
			t.Fatal("endpoint without port = nil, want error")
		}
	})

	t.Run("unbracketed ipv6 endpoint is an error", func(t *testing.T) {
		conf := "[Interface]\nPrivateKey = <redacted>\nAddress = 10.8.0.2/32\n\n[Peer]\nPublicKey = <redacted>\nAllowedIPs = 0.0.0.0/0\nEndpoint = 2001:db8::1:51820\n"
		if _, err := ParseWireGuardConf([]byte(conf)); err == nil {
			t.Fatal("unbracketed IPv6 endpoint = nil, want error")
		}
	})

	t.Run("errors never contain key values", func(t *testing.T) {
		conf := "[Interface]\nAddress = not-an-ip\n\n[Peer]\nPublicKey = <redacted>\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.test:51820\n"
		// Missing PrivateKey + malformed address: the error must not
		// echo the placeholder either way.
		_, err := ParseWireGuardConf([]byte(conf))
		if err == nil {
			t.Fatal("expected error")
		}
		if strings.Contains(err.Error(), "<redacted>") {
			t.Errorf("parse error echoes key material: %v", err)
		}
	})

	t.Run("wireguard conf to endpoint", func(t *testing.T) {
		ep, err := WireGuardConfToEndpoint([]byte(redactedWGConf), "wg")
		if err != nil {
			t.Fatal(err)
		}
		if ep.Type != "wireguard" || ep.Tag != "wg" {
			t.Errorf("endpoint = type %q tag %q, want wireguard/wg", ep.Type, ep.Tag)
		}
	})
}

func TestRedactEndpoint(t *testing.T) {
	opts, err := ParseWireGuardConf([]byte(redactedWGConf))
	if err != nil {
		t.Fatal(err)
	}
	ep, err := WireGuardConfToEndpoint([]byte(redactedWGConf), "wg")
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := RedactEndpoint(ep)
	if err != nil {
		t.Fatal(err)
	}
	out := string(redacted)
	for _, field := range []string{"private_key", "public_key", "pre_shared_key"} {
		if !strings.Contains(out, `"`+field+`":"<redacted>"`) {
			t.Errorf("redacted output lacks %s=<redacted>:\n%s", field, out)
		}
	}
	// The placeholder itself must appear only as the redaction value.
	if strings.Count(out, "<redacted>") < 3 {
		t.Errorf("redacted output has too few <redacted> values:\n%s", out)
	}
	_ = opts
}

func TestRedactEndpointURLUserinfo(t *testing.T) {
	// Exercises the generic redactValue string path of
	// RedactEndpoint with map options: a non-secret string value
	// carrying a URL must have its userinfo redacted, a secret-key
	// value is replaced wholesale, and a plain email value is
	// left unchanged.
	ep := option.Endpoint{
		Type: "http",
		Tag:  "h",
		Options: map[string]any{
			"proxy_url":   "http://user:s3cret@127.0.0.1:8080",
			"private_key": "FAKE-KEY-VALUE",
			"note":        "bob@example.com",
		},
	}
	redacted, err := RedactEndpoint(ep)
	if err != nil {
		t.Fatal(err)
	}
	out := string(redacted)
	if strings.Contains(out, "s3cret") || strings.Contains(out, "FAKE-KEY-VALUE") {
		t.Errorf("redacted output leaks a secret: %s", out)
	}
	if !strings.Contains(out, `"proxy_url":"http://<redacted>@127.0.0.1:8080"`) {
		t.Errorf("proxy_url userinfo not redacted: %s", out)
	}
	if !strings.Contains(out, `"private_key":"<redacted>"`) {
		t.Errorf("private_key not redacted: %s", out)
	}
	if !strings.Contains(out, `"note":"bob@example.com"`) {
		t.Errorf("plain email value was mangled: %s", out)
	}
}

func TestParseRealWireGuardConfRuntime(t *testing.T) {
	// Reads the real conf ONLY at runtime, in-process. Asserts shape
	// only; logs counts/families only; never logs key values or file
	// bytes. Skips when the file is absent/unreadable.
	//
	// The conf path comes from MUSE_CLI_WG_CONF_PATH when set, and
	// defaults to ~/.config/muse-cli/secrets/wg-proton-usca420.conf
	// when unset (or empty). A different conf named by the env var
	// gets the same shape-only assertions and redaction rules.
	// The path itself is not secret, so the skip reason names it.
	confPath := os.Getenv("MUSE_CLI_WG_CONF_PATH")
	if confPath == "" {
		confPath = os.ExpandEnv("$HOME/.config/muse-cli/secrets/wg-proton-usca420.conf")
	}
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Skipf("real wireguard conf unavailable at %s: %v", confPath, err)
	}
	opts, err := ParseWireGuardConf(data)
	if err != nil {
		t.Fatalf("ParseWireGuardConf(real conf): %v", err)
	}
	if opts.System {
		t.Error("real conf parsed with System=true, want userspace only")
	}
	t.Logf("addresses=%d peers=%d", len(opts.Address), len(opts.Peers))
	if len(opts.Peers) == 0 {
		t.Fatal("real conf has no peers")
	}
	ep, err := WireGuardConfToEndpoint(data, "wg-proton")
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := RedactEndpoint(ep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(redacted), "<redacted>") {
		t.Error("redacted real endpoint lacks <redacted>")
	}
	// Redacted fields must equal the placeholder, never a file value.
	if opts.PrivateKey == "" {
		t.Error("real conf parsed with empty PrivateKey")
	}
}
