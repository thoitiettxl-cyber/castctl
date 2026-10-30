// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// Per-protocol build tests without with_quic/with_wireguard tags.
// Dial-through-fake-server tests cover direct, socks, and http. For
// protocols that need a real peer (shadowsocks, vmess, vless, trojan),
// PR1 tests build + Start + a dial attempt that must fail against a
// plain fake TCP server; a successful peer dial is [UNVERIFIED] pending
// a real peer (see the final report for the verifying command).

func TestProtocolDirectThroughFakeTCP(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	m := newTestManager(t)
	out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	d, err := m.Dialer("direct")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(tcpPort))
	if err != nil {
		t.Fatalf("direct dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ok" {
		t.Errorf("echo = %q, want %q", string(buf[:n]), "ok")
	}
}

func TestProtocolSocksThroughFakeProxy(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	proxyPort := startFakeSOCKS5(t)
	m := newTestManager(t)
	raw := fmt.Sprintf(`{"type":"socks","tag":"socks","server":"127.0.0.1","server_port":%d,"version":"5"}`, proxyPort)
	out := parseOutbound(t, m, raw)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	d, err := m.Dialer("socks")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Domain target: resolution must go through the DNS seam path, not
	// the system resolver. Without a registered DNS router the dial
	// must fail closed rather than resolve gateway.test via the system.
	_, err = d.DialContext(ctx, "tcp", "gateway.test", uint16(tcpPort))
	if err == nil {
		t.Fatal("socks domain dial without DNS router = nil, want error")
	}
	// IP-literal target through the proxy.
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(tcpPort))
	if err != nil {
		t.Fatalf("socks dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ok" {
		t.Errorf("echo = %q, want %q", string(buf[:n]), "ok")
	}
}

func TestProtocolHTTPThroughFakeProxy(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	proxyPort := startFakeHTTPProxy(t)
	m := newTestManager(t)
	raw := fmt.Sprintf(`{"type":"http","tag":"http","server":"127.0.0.1","server_port":%d}`, proxyPort)
	out := parseOutbound(t, m, raw)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	d, err := m.Dialer("http")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(tcpPort))
	if err != nil {
		t.Fatalf("http proxy dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ok" {
		t.Errorf("echo = %q, want %q", string(buf[:n]), "ok")
	}
}

func TestProtocolPeerDialFailsAgainstPlainServer(t *testing.T) {
	// [UNVERIFIED] peer dial: no real peer exists in PR1. These cases
	// prove build + Start work and that a handshake against a plain
	// server fails instead of leaking a raw connection.
	_, tcpPort := startFakeTCP(t)
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "shadowsocks",
			raw:  fmt.Sprintf(`{"type":"shadowsocks","tag":"ss","server":"127.0.0.1","server_port":%d,"method":"aes-128-gcm","password":"FAKE"}`, tcpPort),
		},
		{
			name: "vmess",
			raw:  fmt.Sprintf(`{"type":"vmess","tag":"vmess","server":"127.0.0.1","server_port":%d,"uuid":"123e4567-e89b-12d3-a456-426614174000","security":"auto"}`, tcpPort),
		},
		{
			name: "vless",
			raw:  fmt.Sprintf(`{"type":"vless","tag":"vless","server":"127.0.0.1","server_port":%d,"uuid":"123e4567-e89b-12d3-a456-426614174000"}`, tcpPort),
		},
		{
			name: "trojan",
			raw:  fmt.Sprintf(`{"type":"trojan","tag":"trojan","server":"127.0.0.1","server_port":%d,"password":"FAKE","tls":{"enabled":true,"insecure":true}}`, tcpPort),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t)
			out := parseOutbound(t, m, tc.raw)
			if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
				t.Fatalf("CreateOutbound %s: %v", tc.name, err)
			}
			if err := m.Start(); err != nil {
				t.Fatalf("Start %s: %v", tc.name, err)
			}
			d, err := m.Dialer(out.Tag)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(tcpPort))
			if err != nil {
				// Handshake failed at dial time: acceptable.
				return
			}
			defer conn.Close()
			// VMess/VLESS return the conn after writing the
			// handshake; the failure surfaces when the plain
			// server's garbage reply fails decryption.
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write([]byte("ping")); err == nil {
				buf := make([]byte, 64)
				if _, err := conn.Read(buf); err == nil {
					t.Fatalf("%s: read from plain server succeeded, want decryption/handshake error", tc.name)
				}
			}
		})
	}
}

func TestProtocolQUICWithoutTagIsStubError(t *testing.T) {
	// Without with_quic, hysteria2/tuic registrations are stubs that
	// return ErrQUICNotIncluded at construction.
	cases := []string{
		`{"type":"hysteria2","tag":"h2","server":"127.0.0.1","server_port":443,"password":"FAKE"}`,
		`{"type":"tuic","tag":"tuic","server":"127.0.0.1","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000","password":"FAKE"}`,
	}
	for _, raw := range cases {
		m := newTestManager(t)
		out := parseOutbound(t, m, raw)
		err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options)
		if err == nil {
			t.Fatalf("CreateOutbound %s without with_quic = nil, want QUIC-not-included error", out.Type)
		}
	}
}

func TestEndpointSystemWireGuardRejectedWithoutTag(t *testing.T) {
	m := newTestManager(t)
	opts := &option.WireGuardEndpointOptions{System: true, PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	err := m.CreateEndpoint(context.Background(), "wg", "wireguard", opts)
	if err == nil {
		t.Fatal("CreateEndpoint system:true = nil, want userspace-only rejection")
	}
}

func TestEnumValidationAtConstruction(t *testing.T) {
	// W-PROFILE finding: `enum:` struct tags are NOT validated at parse
	// time. Enum validation, if any, must happen at outbound
	// construction. These cases document what construction does with
	// invalid enum values; a case that builds successfully here means
	// the invalid value is only rejected at dial time (or never).
	_, tcpPort := startFakeTCP(t)
	cases := []struct {
		name      string
		raw       string
		wantError bool
	}{
		{
			name:      "shadowsocks bad method",
			raw:       fmt.Sprintf(`{"type":"shadowsocks","tag":"ss","server":"127.0.0.1","server_port":%d,"method":"bogus-method","password":"FAKE"}`, tcpPort),
			wantError: true,
		},
		{
			name:      "socks bad version",
			raw:       fmt.Sprintf(`{"type":"socks","tag":"socks","server":"127.0.0.1","server_port":%d,"version":"9"}`, tcpPort),
			wantError: true,
		},
		{
			name:      "vmess bad security",
			raw:       fmt.Sprintf(`{"type":"vmess","tag":"vmess","server":"127.0.0.1","server_port":%d,"uuid":"123e4567-e89b-12d3-a456-426614174000","security":"bogus"}`, tcpPort),
			wantError: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t)
			out := parseOutbound(t, m, tc.raw)
			err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options)
			if tc.wantError && err == nil {
				t.Errorf("CreateOutbound %s = nil, want construction-time enum error", tc.name)
			}
			if !tc.wantError && err != nil {
				t.Errorf("CreateOutbound %s = %v, want nil", tc.name, err)
			}
		})
	}
}
