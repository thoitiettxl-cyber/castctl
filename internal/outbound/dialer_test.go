// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

func TestDialerDelegationAndResolverSeam(t *testing.T) {
	t.Run("dial delegates to the outbound with the original socksaddr", func(t *testing.T) {
		fake := &recordingOutbound{}
		resolver := &fakeResolver{addrs: map[string][]netip.Addr{
			"gateway.test": {netip.MustParseAddr("127.0.0.1")},
		}}
		d := NewDialer(fake, resolver, option.OutboundTLSOptions{})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := d.DialContext(ctx, "tcp", "gateway.test", 443)
		if err != nil {
			t.Fatalf("DialContext: %v", err)
		}
		defer conn.Close()
		dials := fake.dialsSnapshot()
		if len(dials) != 1 {
			t.Fatalf("recorded dials = %v, want exactly one", dials)
		}
		if dials[0].Fqdn != "gateway.test" || dials[0].Port != 443 {
			t.Errorf("recorded dial = %+v, want Fqdn=gateway.test Port=443", dials[0])
		}
	})

	t.Run("domain dial without a resolver fails closed", func(t *testing.T) {
		fake := &recordingOutbound{}
		d := NewDialer(fake, nil, option.OutboundTLSOptions{})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := d.DialContext(ctx, "tcp", "gateway.test", 443)
		if !errors.Is(err, ErrNoResolver) {
			t.Fatalf("DialContext without resolver = %v, want ErrNoResolver", err)
		}
		if len(fake.dialsSnapshot()) != 0 {
			t.Error("dial reached the outbound despite no resolver")
		}
	})

	t.Run("ip dial without a resolver succeeds", func(t *testing.T) {
		fake := &recordingOutbound{}
		d := NewDialer(fake, nil, option.OutboundTLSOptions{})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", 443)
		if err != nil {
			t.Fatalf("DialContext IP: %v", err)
		}
		conn.Close()
	})

	t.Run("resolve uses the injected seam and nothing else", func(t *testing.T) {
		resolver := &fakeResolver{addrs: map[string][]netip.Addr{
			"gateway.test": {netip.MustParseAddr("127.0.0.1")},
		}}
		d := NewDialer(&recordingOutbound{}, resolver, option.OutboundTLSOptions{})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addrs, err := d.Resolve(ctx, "gateway.test")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("Resolve = %v, want [127.0.0.1]", addrs)
		}
		if names := resolver.lookupNames(); len(names) != 1 || names[0] != "gateway.test" {
			t.Errorf("resolver lookups = %v, want [gateway.test]", names)
		}
	})

	t.Run("resolve without a resolver fails closed", func(t *testing.T) {
		d := NewDialer(&recordingOutbound{}, nil, option.OutboundTLSOptions{})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := d.Resolve(ctx, "gateway.test"); !errors.Is(err, ErrNoResolver) {
			t.Fatalf("Resolve without resolver = %v, want ErrNoResolver", err)
		}
	})

	t.Run("context cancellation mid dial", func(t *testing.T) {
		fake := &recordingOutbound{blocking: true}
		d := NewDialer(fake, nil, option.OutboundTLSOptions{})
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := d.DialContext(ctx, "tcp", "127.0.0.1", 443)
		if err == nil {
			t.Fatal("blocked dial = nil, want error")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("blocked dial took %v, want it bounded by the context deadline", elapsed)
		}
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Errorf("blocked dial error = %v, want context deadline/cancel", err)
		}
	})
}

func TestDialerHTTPClient(t *testing.T) {
	t.Run("http through direct outbound and no env proxy", func(t *testing.T) {
		_, tcpPort := startFakeTCP(t)
		// The fake TCP server replies "ok" to any bytes; an HTTP GET
		// through it returns "ok" as the body only if the client does
		// not treat it as a proxy response. Use a real HTTP server
		// instead: httptest-style, bound to 127.0.0.1.
		_ = tcpPort
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		mux := http.NewServeMux()
		mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("pong"))
		})
		srv := &http.Server{Handler: mux}
		go srv.Serve(ln)
		defer srv.Close()

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
		client := d.HTTPClient()
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("HTTPClient transport = %T, want *http.Transport", client.Transport)
		}
		if tr.Proxy != nil {
			t.Error("HTTP transport Proxy is set; it must be nil so no env proxy is ever consulted")
		}
		resp, err := client.Get("http://" + ln.Addr().String() + "/ping")
		if err != nil {
			t.Fatalf("HTTP GET through dialer: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "pong" {
			t.Errorf("HTTP body = %q, want %q", string(body), "pong")
		}
	})

	t.Run("https through dialer tls uses insecure fake server", func(t *testing.T) {
		addr := startFakeTLSServer(t)
		m := newTestManager(t)
		out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
		if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
			t.Fatal(err)
		}
		if err := m.Start(); err != nil {
			t.Fatal(err)
		}
		// DialTLS directly: the fake TLS server echoes "tls-ok".
		fake := &recordingOutbound{}
		_ = fake
		d, err := m.Dialer("direct")
		if err != nil {
			t.Fatal(err)
		}
		_ = d
		// Use a Dialer whose TLS options are insecure so the
		// self-signed fake cert is accepted.
		direct, _ := m.Outbound("direct")
		tlsDialer := NewDialer(direct, nil, option.OutboundTLSOptions{Enabled: true, Insecure: true})
		u, err := url.Parse("https://" + addr)
		if err != nil {
			t.Fatal(err)
		}
		host := u.Hostname()
		port := 443
		fmt.Sscanf(u.Port(), "%d", &port)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := tlsDialer.DialTLS(ctx, "tcp", host, uint16(port), option.OutboundTLSOptions{Enabled: true, Insecure: true})
		if err != nil {
			t.Fatalf("DialTLS: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "tls-ok" {
			t.Errorf("tls echo = %q, want %q", string(buf[:n]), "tls-ok")
		}
	})
}

func TestDialerWebSocketDial(t *testing.T) {
	t.Run("plain websocket dial returns a raw conn", func(t *testing.T) {
		_, tcpPort := startFakeTCP(t)
		fake := &recordingOutbound{}
		d := NewDialer(fake, nil, option.OutboundTLSOptions{})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := d.WebSocketDial(ctx, "tcp", "127.0.0.1", uint16(tcpPort), false, option.OutboundTLSOptions{})
		if err != nil {
			t.Fatalf("WebSocketDial: %v", err)
		}
		defer conn.Close()
		// The recording outbound echoes written bytes: the conn is
		// ready for a WS handshake because raw bytes round-trip.
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "ping" {
			t.Errorf("websocket-dial echo = %q, want %q", string(buf[:n]), "ping")
		}
	})

	t.Run("secure websocket dial handshakes tls", func(t *testing.T) {
		addr := startFakeTLSServer(t)
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal(err)
		}
		var port int
		fmt.Sscanf(portStr, "%d", &port)
		m := newTestManager(t)
		out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
		if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
			t.Fatal(err)
		}
		if err := m.Start(); err != nil {
			t.Fatal(err)
		}
		direct, _ := m.Outbound("direct")
		d := NewDialer(direct, nil, option.OutboundTLSOptions{Enabled: true, Insecure: true})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := d.WebSocketDial(ctx, "tcp", host, uint16(port), true, option.OutboundTLSOptions{Enabled: true, Insecure: true})
		if err != nil {
			t.Fatalf("WebSocketDial secure: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "tls-ok" {
			t.Errorf("secure websocket-dial echo = %q, want %q", string(buf[:n]), "tls-ok")
		}
	})
}

func TestDialerDeadProxyFailsClosed(t *testing.T) {
	// The proxy refuses; the target local server is reachable. The dial
	// MUST fail: no direct fallback is ever allowed.
	_, tcpPort := startFakeTCP(t)
	closed := closedPort(t)
	m := newTestManager(t)
	raw := fmt.Sprintf(`{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":%d,"version":"5"}`, closed)
	out := parseOutbound(t, m, raw)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	d, err := m.Dialer("proxy")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = d.DialContext(ctx, "tcp", "127.0.0.1", uint16(tcpPort))
	if err == nil {
		t.Fatal("dial through dead proxy = nil, want error (no direct fallback)")
	}
	if strings.Contains(err.Error(), "ok") {
		t.Errorf("dial error looks like a successful fallback: %v", err)
	}
	var _ adapter.Outbound
}

func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}
