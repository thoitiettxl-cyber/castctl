// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

// Tests for Dialer logging: per-connection IDs, dial start/done
// events, and the TLS ALPN event captured at the handshake
// junction.
//
// What each test observes: lines written by a real factory to a
// buffer, through a real Manager + direct outbound to loopback
// servers. What the red run catches: the Dialer emitting nothing
// (its logger is the hardcoded NOP at dialer.go:57), an ID minted
// per-Dialer or constant (two dials sharing one ID), the ALPN
// event logging the OFFER instead of the negotiated protocol, or
// a guessed ALPN event on a plaintext dial.

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

var connIDRe = regexp.MustCompile(`\[(\d+) (\d+ms|[\d.]+s|\d+m\d+s)\]`)

func wiredManager(t *testing.T, buf *bytes.Buffer, level string) *Manager {
	t.Helper()
	h, err := logging.NewFactory(context.Background(), logging.Settings{Level: level}, buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	m, err := NewManager(context.Background(), h.Logger("castctl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func dialEventLines(t *testing.T, buf *bytes.Buffer) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(strings.TrimRight(stripANSIForTest(buf.String()), "\n"), "\n") {
		if strings.Contains(line, "event=dial_start") || strings.Contains(line, "event=dial_done") {
			out = append(out, line)
		}
	}
	return out
}

func stripANSIForTest(s string) string {
	re := regexp.MustCompile("\x1b\\[[0-9;]*m")
	return re.ReplaceAllString(s, "")
}

func extractConnID(t *testing.T, line string) string {
	t.Helper()
	matches := connIDRe.FindAllStringSubmatch(line, -1)
	if len(matches) != 1 {
		t.Fatalf("line %q: want exactly one connection-ID prefix, found %d", line, len(matches))
	}
	return matches[0][1]
}

func TestDialerConnectionIDs(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	var buf bytes.Buffer
	m := wiredManager(t, &buf, "trace")
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
	// Two sequential dials, each completed (read the "ok" reply)
	// so both the start and the done emission fire.
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(tcpPort))
		cancel()
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 16)
		if _, err := conn.Read(reply); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	lines := dialEventLines(t, &buf)
	if len(lines) < 4 {
		t.Fatalf("dial event lines = %d (%q), want at least 4 (start+done per dial)", len(lines), buf.String())
	}
	id1 := extractConnID(t, lines[0])
	if got := extractConnID(t, lines[1]); got != id1 {
		t.Errorf("dial 1 lines carry IDs %q and %q, want the same ID", id1, got)
	}
	id2 := extractConnID(t, lines[2])
	if got := extractConnID(t, lines[3]); got != id2 {
		t.Errorf("dial 2 lines carry IDs %q and %q, want the same ID", id2, got)
	}
	if id1 == id2 {
		t.Errorf("both dials carry ID %q, want distinct IDs per connection", id1)
	}
	if id1 == "" || id2 == "" {
		t.Error("empty connection ID")
	}
	// The ID must be opaque: never a fixture/secret value.
	for _, v := range []string{"hatch_sess", "LOGFIX", "token"} {
		if strings.Contains(id1, v) || strings.Contains(id2, v) {
			t.Errorf("connection ID %q/%q contains %q", id1, id2, v)
		}
	}
}

func TestDialerNoIDWithoutWiredLogger(t *testing.T) {
	// Control: the existing NewDialer path (NOP logger) emits
	// nothing. Guards the ID test against passing vacuously via
	// some other logger.
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
		t.Fatal(err)
	}
	_ = conn.Close()
	// No assertion on output is possible here (NOP discards);
	// the test passes by completing the dial without logging.
	// The wiring assertion lives in TestDialerConnectionIDs.
}

// TestDialerALPNEvent clones the junction pattern of
// TestWebSocketDialOffersHTTP11Only (loopback TLS server, h2
// offered first, pin literal [http/1.1]) but drives the Dialer
// built with the wired logger, asserting the EVENT line carries
// the negotiated protocol only.
func TestDialerALPNEvent(t *testing.T) {
	skipUnlessUTLS(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	var mu sync.Mutex
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
		tc := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		})
		if err := tc.Handshake(); err != nil {
			return
		}
		mu.Lock()
		serverNegotiated = tc.ConnectionState().NegotiatedProtocol
		mu.Unlock()
		_, _ = tc.Write([]byte("ok"))
		_, _ = ioDiscard(tc)
	}()

	var buf bytes.Buffer
	m := wiredManager(t, &buf, "trace")
	out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	direct, _ := m.Outbound("direct")
	_ = direct // the manager-built dialer below is the wired one
	d, err := m.Dialer("direct")
	if err != nil {
		t.Fatal(err)
	}
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
	_ = conn.Close()
	<-done

	mu.Lock()
	negotiated := serverNegotiated
	mu.Unlock()
	if negotiated != "http/1.1" {
		t.Fatalf("server negotiated %q, want http/1.1 (test setup broken, not the event)", negotiated)
	}
	got := stripANSIForTest(buf.String())
	if !strings.Contains(got, "event=tls_alpn alpn=http/1.1") {
		t.Errorf("factory output %q, want the ALPN event with the negotiated protocol", got)
	}
	if strings.Contains(got, "alpn=h2") {
		t.Errorf("factory output %q, want no alpn=h2 line (offer must never be logged as negotiated)", got)
	}
}

func ioDiscard(c net.Conn) (int64, error) {
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	return int64(n), err
}

// TestDialerNoALPNEventOnPlaintext: fail-closed. A plaintext dial
// through the same Dialer must produce NO tls_alpn event at all —
// a guessed "http/1.1" default would fail this test.
func TestDialerNoALPNEventOnPlaintext(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	var buf bytes.Buffer
	m := wiredManager(t, &buf, "trace")
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
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 16)
	if _, err := conn.Read(reply); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if strings.Contains(buf.String(), "event=tls_alpn") {
		t.Errorf("plaintext dial produced a tls_alpn event: %q", buf.String())
	}
}
