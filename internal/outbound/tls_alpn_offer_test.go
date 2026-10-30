// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

// Shape (v): ALPN-offer proof for the gateway TLS path.
//
// BuildTLSConfig with the production input (empty ALPN) must offer
// the uTLS Chrome-preset list ["h2", "http/1.1"] — the offer the
// live gateway handshake carried when the "malformed HTTP status
// code" failure was reported — and an explicit ALPN ["http/1.1"]
// (the WS-scoped pin) must offer exactly ["http/1.1"]. The offer
// is read server-side from the ClientHello (SupportedProtos), not
// from the pre-handshake config, whose NextProtos stays nil for
// the empty case: the preset list materialises inside the uTLS
// handshake state. Requires -tags with_utls (skipUnlessUTLS).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestBuildTLSConfigALPNOffer(t *testing.T) {
	skipUnlessUTLS(t)
	ctx := t.Context()

	cases := []struct {
		name           string
		alpn           []string
		wantOffer      []string
		wantNegotiated string
	}{
		{
			name:           "empty-alpn-offers-chrome-preset",
			alpn:           nil,
			wantOffer:      []string{"h2", "http/1.1"},
			wantNegotiated: "h2",
		},
		{
			name:           "explicit-http11-offers-http11-only",
			alpn:           []string{"http/1.1"},
			wantOffer:      []string{"http/1.1"},
			wantNegotiated: "http/1.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var offered []string
			var sni string
			cert := alpnOfferTestCert(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				raw, err := ln.Accept()
				if err != nil {
					return
				}
				defer raw.Close()
				cfg := &tls.Config{
					Certificates: []tls.Certificate{cert},
					NextProtos:   []string{"h2", "http/1.1"},
					GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
						mu.Lock()
						offered = append([]string(nil), hello.SupportedProtos...)
						sni = hello.ServerName
						mu.Unlock()
						return nil, nil
					},
				}
				server := tls.Server(raw, cfg)
				_ = server.SetDeadline(time.Now().Add(10 * time.Second))
				if err := server.Handshake(); err != nil {
					return
				}
				// Hold briefly so the client handshake can
				// complete before the server side closes.
				buf := make([]byte, 1)
				_, _ = server.Read(buf)
			}()

			opts := option.OutboundTLSOptions{Enabled: true, Insecure: true}
			if tc.alpn != nil {
				opts.ALPN = tc.alpn
			}
			config, _, err := BuildTLSConfig(ctx, testLogger(), "gateway.test", opts)
			if err != nil {
				t.Fatalf("BuildTLSConfig = %v", err)
			}
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			tlsConn, err := HandshakeTLS(ctx, raw, config)
			if err != nil {
				t.Fatalf("HandshakeTLS = %v", err)
			}
			defer tlsConn.Close()
			negotiated := tlsConn.ConnectionState().NegotiatedProtocol
			_ = tlsConn.Close()
			<-done

			mu.Lock()
			defer mu.Unlock()
			if !reflect.DeepEqual(offered, tc.wantOffer) {
				t.Errorf("ClientHello ALPN offer = %v, want %v", offered, tc.wantOffer)
			}
			if sni != "gateway.test" {
				t.Errorf("SNI = %q, want %q", sni, "gateway.test")
			}
			if negotiated != tc.wantNegotiated {
				t.Errorf("negotiated ALPN = %q, want %q", negotiated, tc.wantNegotiated)
			}
		})
	}
}

func alpnOfferTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gateway.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"gateway.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
