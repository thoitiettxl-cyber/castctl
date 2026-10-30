// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func testLogger() log.ContextLogger {
	return log.NewNOPFactory().NewLogger("test")
}

func TestGatewayTLSOptions(t *testing.T) {
	t.Run("empty options default to utls chrome", func(t *testing.T) {
		effective := GatewayTLSOptions(option.OutboundTLSOptions{Enabled: true})
		if effective.UTLS == nil || !effective.UTLS.Enabled {
			t.Fatalf("effective UTLS = %+v, want enabled", effective.UTLS)
		}
		if effective.UTLS.Fingerprint != "chrome" {
			t.Errorf("effective fingerprint = %q, want %q", effective.UTLS.Fingerprint, "chrome")
		}
	})

	t.Run("explicit fingerprint is kept", func(t *testing.T) {
		effective := GatewayTLSOptions(option.OutboundTLSOptions{
			Enabled: true,
			UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "firefox"},
		})
		if effective.UTLS.Fingerprint != "firefox" {
			t.Errorf("effective fingerprint = %q, want %q", effective.UTLS.Fingerprint, "firefox")
		}
	})

	t.Run("enabled utls without fingerprint defaults to chrome", func(t *testing.T) {
		effective := GatewayTLSOptions(option.OutboundTLSOptions{
			Enabled: true,
			UTLS:    &option.OutboundUTLSOptions{Enabled: true},
		})
		if effective.UTLS.Fingerprint != "chrome" {
			t.Errorf("effective fingerprint = %q, want %q", effective.UTLS.Fingerprint, "chrome")
		}
	})

	t.Run("input is not mutated", func(t *testing.T) {
		input := option.OutboundTLSOptions{Enabled: true}
		_ = GatewayTLSOptions(input)
		if input.UTLS != nil {
			t.Error("GatewayTLSOptions mutated its input")
		}
	})
}

func TestBuildTLSConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("disabled returns nil config", func(t *testing.T) {
		cfg, _, err := BuildTLSConfig(ctx, testLogger(), "gateway.test", option.OutboundTLSOptions{})
		if err != nil {
			t.Fatalf("BuildTLSConfig disabled = %v", err)
		}
		if cfg != nil {
			t.Error("BuildTLSConfig disabled returned a non-nil config")
		}
	})

	t.Run("default chrome server name and alpn passthrough", func(t *testing.T) {
		skipUnlessUTLS(t)
		cfg, effective, err := BuildTLSConfig(ctx, testLogger(), "gateway.test", option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "gateway.test",
			ALPN:       []string{"h2"},
		})
		if err != nil {
			t.Fatalf("BuildTLSConfig = %v", err)
		}
		if cfg == nil {
			t.Fatal("BuildTLSConfig returned nil config")
		}
		if cfg.ServerName() != "gateway.test" {
			t.Errorf("config ServerName = %q, want %q", cfg.ServerName(), "gateway.test")
		}
		// sing-box uTLS appends http/1.1 after a lone h2 (see
		// UTLSClientConfig.SetNextProtos); assert h2 is offered first.
		protos := cfg.NextProtos()
		if len(protos) == 0 || protos[0] != "h2" {
			t.Errorf("config NextProtos = %v, want h2 first", protos)
		}
		if effective.UTLS == nil || effective.UTLS.Fingerprint != "chrome" {
			t.Errorf("effective fingerprint = %+v, want chrome", effective.UTLS)
		}
	})

	t.Run("server name falls back to server address", func(t *testing.T) {
		skipUnlessUTLS(t)
		cfg, _, err := BuildTLSConfig(ctx, testLogger(), "fallback.test", option.OutboundTLSOptions{Enabled: true})
		if err != nil {
			t.Fatalf("BuildTLSConfig = %v", err)
		}
		if cfg.ServerName() != "fallback.test" {
			t.Errorf("config ServerName = %q, want %q", cfg.ServerName(), "fallback.test")
		}
	})

	t.Run("unknown fingerprint is an error", func(t *testing.T) {
		_, _, err := BuildTLSConfig(ctx, testLogger(), "gateway.test", option.OutboundTLSOptions{
			Enabled: true,
			UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "bogus-fingerprint"},
		})
		if err == nil {
			t.Fatal("BuildTLSConfig with unknown fingerprint = nil, want error")
		}
	})

	t.Run("reality options pass through untouched", func(t *testing.T) {
		skipUnlessUTLS(t)
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		opts := option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "example.com",
			UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
			Reality: &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: base64.RawURLEncoding.EncodeToString(key),
				ShortID:   "0102030405060708",
			},
		}
		cfg, effective, err := BuildTLSConfig(ctx, testLogger(), "example.com", opts)
		if err != nil {
			t.Fatalf("BuildTLSConfig reality = %v", err)
		}
		if cfg == nil {
			t.Fatal("BuildTLSConfig reality returned nil config")
		}
		if effective.Reality == nil || effective.Reality.PublicKey != opts.Reality.PublicKey || effective.Reality.ShortID != opts.Reality.ShortID {
			t.Errorf("effective reality = %+v, want %+v", effective.Reality, opts.Reality)
		}
		if cfg.ServerName() != "example.com" {
			t.Errorf("config ServerName = %q, want %q", cfg.ServerName(), "example.com")
		}
	})

	t.Run("reality without utls is an error", func(t *testing.T) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		// GatewayTLSOptions defaults UTLS on, so reality without an
		// explicit UTLS block still builds; an explicitly disabled UTLS
		// block must fail inside sing-box instead. Build directly via
		// the effective-options path with UTLS disabled.
		opts := option.OutboundTLSOptions{
			Enabled: true,
			UTLS:    &option.OutboundUTLSOptions{Enabled: false, Fingerprint: "chrome"},
			Reality: &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: base64.RawURLEncoding.EncodeToString(key),
				ShortID:   "01",
			},
		}
		// Bypass the chrome default: call the builder with UTLS already
		// present-but-disabled; sing-box must reject reality then.
		_, _, err := BuildTLSConfig(ctx, testLogger(), "example.com", opts)
		if err == nil {
			t.Fatal("reality with disabled utls = nil, want error")
		}
	})

	t.Run("handshake against fake tls server", func(t *testing.T) {
		skipUnlessUTLS(t)
		addr := startFakeTLSServer(t)
		cfg, _, err := BuildTLSConfig(ctx, testLogger(), "gateway.test", option.OutboundTLSOptions{
			Enabled:  true,
			Insecure: true,
		})
		if err != nil {
			t.Fatalf("BuildTLSConfig = %v", err)
		}
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		tlsConn, err := HandshakeTLS(ctx, raw, cfg)
		if err != nil {
			t.Fatalf("HandshakeTLS = %v", err)
		}
		defer tlsConn.Close()
		if _, err := tlsConn.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 16)
		n, err := tlsConn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "tls-ok" {
			t.Errorf("tls echo = %q, want %q", string(buf[:n]), "tls-ok")
		}
	})
}
