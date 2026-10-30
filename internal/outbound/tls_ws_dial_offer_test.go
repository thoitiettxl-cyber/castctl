// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

// Junction test for the gateway WebSocket ALPN pin: the REAL
// Dialer.WebSocketDial -> DialTLS -> BuildTLSConfig path, against a
// loopback TLS server that records the ClientHello ALPN offer
// (SupportedProtos) server-side. The offer is read from the wire,
// never from a config field and never from a stdlib simulator.
//
// The WebSocketDial options literal below mirrors the production
// call site (internal/gateway/connector.go:240): Enabled + ALPN
// ["http/1.1"]. Insecure is added here ONLY so the self-signed
// fixture certificate is accepted (the same test-only trust shape
// (v) and the secure Dialer tests use); it is not part of the
// production call. This test proves the pinned literal survives
// DialTLS/BuildTLSConfig and reaches the wire as ["http/1.1"]
// only, so a DialTLS regression that dropped or overrode the pin
// fails here. It does NOT prove connector.go passes the pin —
// the gateway shapes (internal/gateway/ws_handshake_test.go)
// assert the literal connector.go passes — and it does not
// observe ALPS or any live peer negotiation.
//
// Requires -tags with_utls (skipUnlessUTLS): without uTLS the
// real path fails closed before any handshake.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	singtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

func TestWebSocketDialOffersHTTP11Only(t *testing.T) {
	skipUnlessUTLS(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// Loopback TLS server recording the ClientHello. NextProtos
	// offers h2 first, so an unpinned offer ["h2", "http/1.1"]
	// would negotiate h2 here; the pinned offer must negotiate
	// "http/1.1".
	var mu sync.Mutex
	var offered []string
	var sni string
	var serverNegotiated string
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
		mu.Lock()
		serverNegotiated = server.ConnectionState().NegotiatedProtocol
		mu.Unlock()
		// Hold briefly so the client handshake can complete
		// before the server side closes.
		buf := make([]byte, 1)
		_, _ = server.Read(buf)
	}()

	// Real outbound + real Dialer, as in the secure Dialer
	// tests: a direct outbound dialling the loopback address.
	m := newTestManager(t)
	out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
	if err := m.CreateOutbound(ctx, out.Tag, out.Type, out.Options); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	direct, _ := m.Outbound("direct")
	d := NewDialer(direct, nil, option.OutboundTLSOptions{Enabled: true, Insecure: true})

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatal(err)
	}
	conn, err := d.WebSocketDial(ctx, "tcp", host, uint16(port), true, option.OutboundTLSOptions{Enabled: true, Insecure: true, ALPN: []string{"http/1.1"}})
	if err != nil {
		t.Fatalf("WebSocketDial: %v", err)
	}
	defer conn.Close()

	// Record the negotiated protocol from the returned conn:
	// the sing-box tls.Conn exposes ConnectionState.
	tlsConn, ok := conn.(singtls.Conn)
	if !ok {
		t.Fatalf("WebSocketDial returned %T, want a sing-box tls.Conn exposing ConnectionState", conn)
	}
	negotiated := tlsConn.ConnectionState().NegotiatedProtocol
	_ = conn.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	t.Logf("WebSocketDial offer=%v negotiated(client)=%q negotiated(server)=%q sni=%q", offered, negotiated, serverNegotiated, sni)
	if !reflect.DeepEqual(offered, []string{"http/1.1"}) {
		t.Errorf("WebSocketDial ClientHello ALPN offer = %v, want [http/1.1]: the WS dial must offer only http/1.1 (pin at internal/gateway/connector.go:240)", offered)
	}
	if sni != "" {
		// No SNI is expected: the test dials the IP literal
		// 127.0.0.1, and SNI must not carry an IP literal
		// (RFC 6066); the uTLS client omits the extension.
		t.Errorf("SNI = %q, want empty for an IP-literal dial", sni)
	}
	if negotiated != "http/1.1" {
		t.Errorf("client negotiated ALPN = %q (offer was %v), want %q", negotiated, offered, "http/1.1")
	}
	if serverNegotiated != "http/1.1" {
		t.Errorf("server negotiated ALPN = %q (offer was %v), want %q", serverNegotiated, offered, "http/1.1")
	}
}
