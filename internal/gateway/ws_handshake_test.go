// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

// Regression test for the gateway WebSocket handshake failure
// reported live as:
//
//	conn: connection error: gateway: websocket handshake:
//	  malformed HTTP status code "error"
//
// The test drives dialWebSocket — the exact code that produced the
// live error — against scripted loopback servers. No real network,
// no real cookies/tokens: the URL carries fixture values only.
//
// Why the negotiated protocol matters: gorilla's Dialer always
// writes an HTTP/1.1 upgrade and parses the reply with
// http.ReadResponse. The production TLS offer (uTLS Chrome preset)
// is ["h2", "http/1.1"], so a server that prefers h2 negotiates h2
// while gorilla still speaks HTTP/1.1 over the same conn — a
// combination that can never upgrade. The fix pins ALPN to
// ["http/1.1"] for the WebSocket dial only (WS-scoped; the HTTPS
// auth chain keeps negotiating h2). These tests pin both halves:
// the dialer must RECEIVE the ["http/1.1"] offer, and the
// negotiated protocol on every TLS shape must be "http/1.1".
//
// The scriptDialer is a stdlib-TLS SIMULATOR of the production
// outbound's ALPN behaviour, not the production outbound: an
// explicit ALPN list in the passed TLS options is offered
// verbatim; empty ALPN offers the Chrome-preset list
// ["h2", "http/1.1"]. As committed (pinned), NO shape negotiates
// h2: every TLS shape negotiates "http/1.1", the scriptH2Speaker
// h2-frames branch is dead code under the pin, and the
// scriptDialer empty-offer branch never runs. The true wire offer
// of the real outbound is proven separately at the outbound seam
// (internal/outbound: shape (v) and the DialTLS junction test),
// never by this simulator.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	singlog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

const wsHandshakeLiveError = `malformed HTTP status code "error"`

// scriptDialer is a minimal OutboundDialer for scripted loopback
// servers. It dials one fixed listener address, ignoring the
// requested host/port, and — when secure — performs a stdlib TLS
// client handshake offering the ALPN list from the passed TLS
// options (or the simulated Chrome-preset list when empty).
type scriptDialer struct {
	addr string

	mu         sync.Mutex
	received   []string // ALPN list received in WebSocketDial options
	negotiated string   // negotiated ALPN of the last TLS dial
}

func (d *scriptDialer) WebSocketDial(ctx context.Context, network, host string, port uint16, secure bool, tlsOptions option.OutboundTLSOptions) (net.Conn, error) {
	return d.dial(ctx, secure, tlsOptions)
}

func (d *scriptDialer) HTTPClient() *http.Client { return http.DefaultClient }

func (d *scriptDialer) dial(ctx context.Context, secure bool, tlsOptions option.OutboundTLSOptions) (net.Conn, error) {
	d.mu.Lock()
	d.received = append([]string(nil), tlsOptions.ALPN...)
	d.mu.Unlock()

	var nd net.Dialer
	raw, err := nd.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	if !secure {
		return raw, nil
	}
	offer := tlsOptions.ALPN
	if len(offer) == 0 {
		// Simulated Chrome-preset offer (see file header).
		offer = []string{"h2", "http/1.1"}
	}
	tlsConn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, // test-only: self-signed fixture cert
		ServerName:         "gateway.test",
		NextProtos:         offer,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	d.mu.Lock()
	d.negotiated = tlsConn.ConnectionState().NegotiatedProtocol
	d.mu.Unlock()
	return tlsConn, nil
}

func (d *scriptDialer) receivedALPN() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.received...)
}

func (d *scriptDialer) negotiatedALPN() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.negotiated
}

// scriptServer is a one-connection loopback server. It records the
// ClientHello (offered ALPN, SNI) and the upgrade request, then runs
// one scripted response shape.
type scriptServer struct {
	t          *testing.T
	ln         net.Listener
	secure     bool
	serverCert tls.Certificate

	mu         sync.Mutex
	offered    []string
	sni        string
	negotiated string
	reqLine    string
	reqHeader  http.Header

	done chan struct{}
}

type scriptKind int

const (
	script101 scriptKind = iota
	scriptPlaintextError
	scriptNoSpace
	scriptWellFormed502
	scriptBadCode
	scriptImmediateClose
	scriptH2Speaker
	scriptSilent
	scriptH2ThenPlaintextError
)

func startScriptServer(t *testing.T, secure bool, serverProtos []string, kind scriptKind) *scriptServer {
	t.Helper()
	cert := wsHandshakeTestCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &scriptServer{t: t, ln: ln, secure: secure, serverCert: cert, done: make(chan struct{})}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve(serverProtos, kind)
	return s
}

func (s *scriptServer) addr() string { return s.ln.Addr().String() }

func (s *scriptServer) serve(serverProtos []string, kind scriptKind) {
	defer close(s.done)
	c, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	if s.secure {
		cfg := &tls.Config{
			Certificates: []tls.Certificate{s.serverCert},
			NextProtos:   serverProtos,
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				s.mu.Lock()
				s.offered = append([]string(nil), hello.SupportedProtos...)
				s.sni = hello.ServerName
				s.mu.Unlock()
				return nil, nil
			},
		}
		tc := tls.Server(c, cfg)
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.Handshake(); err != nil {
			return
		}
		s.mu.Lock()
		s.negotiated = tc.ConnectionState().NegotiatedProtocol
		s.mu.Unlock()
		c = tc
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if kind == scriptSilent {
		// Hold the conn open, sending nothing: the client must
		// time out on its own bound.
		_, _ = io.Copy(io.Discard, c)
		return
	}
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.reqLine = req.Method + " " + req.URL.RequestURI() + " " + req.Proto
	s.reqHeader = req.Header.Clone()
	negotiated := s.negotiated
	s.mu.Unlock()
	switch kind {
	case script101:
		key := req.Header.Get("Sec-WebSocket-Key")
		// RFC 6455 §4.2.2 accept computation (same GUID gorilla
		// uses in computeAcceptKey): SHA-1(key + GUID), base64.
		sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		accept := base64.StdEncoding.EncodeToString(sum[:])
		_, _ = fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
		// Hold for the client (Noise is out of scope); the
		// client closing the ws conn unblocks this copy.
		_, _ = io.Copy(io.Discard, c)
	case scriptPlaintextError, scriptH2ThenPlaintextError:
		_, _ = c.Write([]byte("HTTP/1.1 error\r\n\r\n"))
	case scriptNoSpace:
		_, _ = c.Write([]byte("error\r\n\r\n"))
	case scriptWellFormed502:
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
	case scriptBadCode:
		_, _ = c.Write([]byte("HTTP/1.1 abc\r\n\r\n"))
	case scriptImmediateClose:
		// Close with zero bytes: nothing to write.
	case scriptH2Speaker:
		if negotiated == "h2" {
			// Minimal h2 speaker: SETTINGS then GOAWAY, no
			// HTTP/1.1 text at all. Frame bytes contain no
			// 0x0A, so the HTTP/1.1 status-line parser cannot
			// find a status line in them.
			_, _ = c.Write([]byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00})
			_, _ = c.Write([]byte{0x00, 0x00, 0x08, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		} else {
			// With http/1.1 negotiated the peer speaks
			// HTTP/1.1: a well-formed error, not a WS upgrade.
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		}
	}
}

func (s *scriptServer) waitDone(t *testing.T) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("script server did not finish within 10s")
	}
}

func (s *scriptServer) snapshot() (offered []string, sni, negotiated, reqLine string, hdr http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.offered...), s.sni, s.negotiated, s.reqLine, s.reqHeader.Clone()
}

func wsHandshakeTestCert(t *testing.T) tls.Certificate {
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

// innermostErr unwraps the full error chain (ConnectionError,
// redactedError, fmt %w) to the innermost message. Assertions use
// this, never a substring of the outer message, so a different
// innermost error cannot hide behind identical wrapping.
func innermostErr(err error) string {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err.Error()
		}
		err = next
	}
}

func TestDialWebSocketHandshakeShapes(t *testing.T) {
	cases := []struct {
		name           string
		secure         bool
		serverProtos   []string
		kind           scriptKind
		wsTimeout      time.Duration
		wantSuccess    bool
		wantInnermost  string // exact innermost error; "" = any non-live error (logged)
		wantNegotiated string // TLS only; "" = not asserted
	}{
		{
			name:        "baseline-101-plain",
			secure:      false,
			kind:        script101,
			wsTimeout:   2 * time.Second,
			wantSuccess: true,
		},
		{
			name:          "plaintext-error-plain",
			secure:        false,
			kind:          scriptPlaintextError,
			wsTimeout:     2 * time.Second,
			wantInnermost: wsHandshakeLiveError,
		},
		{
			name:           "plaintext-error-tls-http11",
			secure:         true,
			serverProtos:   []string{"http/1.1"},
			kind:           scriptPlaintextError,
			wsTimeout:      2 * time.Second,
			wantInnermost:  wsHandshakeLiveError,
			wantNegotiated: "http/1.1",
		},
		{
			name:          "discriminator-no-space",
			secure:        false,
			kind:          scriptNoSpace,
			wsTimeout:     2 * time.Second,
			wantInnermost: `malformed HTTP response "error"`,
		},
		{
			name:          "discriminator-well-formed-502",
			secure:        false,
			kind:          scriptWellFormed502,
			wsTimeout:     2 * time.Second,
			wantInnermost: "websocket: bad handshake",
		},
		{
			name:          "discriminator-bad-code",
			secure:        false,
			kind:          scriptBadCode,
			wsTimeout:     2 * time.Second,
			wantInnermost: `malformed HTTP status code "abc"`,
		},
		{
			name:          "discriminator-immediate-close",
			secure:        false,
			kind:          scriptImmediateClose,
			wsTimeout:     2 * time.Second,
			wantInnermost: "unexpected EOF",
		},
		{
			name:           "h2-capable-server-http11-negotiated-bad-handshake",
			secure:         true,
			serverProtos:   []string{"h2", "http/1.1"},
			kind:           scriptH2Speaker,
			wsTimeout:      2 * time.Second,
			wantInnermost:  "websocket: bad handshake",
			wantNegotiated: "http/1.1",
		},
		{
			name:           "h2-capable-server-http11-negotiated-silent",
			secure:         true,
			serverProtos:   []string{"h2", "http/1.1"},
			kind:           scriptSilent,
			wsTimeout:      200 * time.Millisecond,
			wantNegotiated: "http/1.1",
		},
		{
			name:           "h2-capable-server-http11-negotiated-plaintext-error",
			secure:         true,
			serverProtos:   []string{"h2", "http/1.1"},
			kind:           scriptH2ThenPlaintextError,
			wsTimeout:      2 * time.Second,
			wantInnermost:  wsHandshakeLiveError,
			wantNegotiated: "http/1.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startScriptServer(t, tc.secure, tc.serverProtos, tc.kind)
			dialer := &scriptDialer{addr: srv.addr()}
			scheme := "ws"
			if tc.secure {
				scheme = "wss"
			}
			wsURL := scheme + "://" + srv.addr() + "/v1/noise?vm_id=FAKEVM&auth_token=FAKETOKEN"

			start := time.Now()
			ws, _, _, err := dialWebSocket(t.Context(), dialer, wsURL, tc.secure, tc.wsTimeout, singlog.NewNOPFactory().NewLogger("gateway"))
			elapsed := time.Since(start)
			// Close a successful ws conn before waiting for the
			// server: the 101 script holds its copy until the
			// client closes.
			if ws != nil {
				defer ws.Close()
			}

			// The WS-scoped ALPN pin must reach the dialer on
			// every shape: the dialer offers exactly
			// ["http/1.1"], never the preset ["h2", ...].
			if got := dialer.receivedALPN(); len(got) != 1 || got[0] != "http/1.1" {
				t.Errorf("dialer received ALPN = %v, want [http/1.1]", got)
			}

			if tc.wantSuccess {
				if err != nil {
					t.Fatalf("dialWebSocket = %v, want success", err)
				}
				if ws == nil {
					t.Fatal("dialWebSocket returned nil conn, nil error")
				}
				_ = ws.Close()
				srv.waitDone(t)
				return
			}
			if err == nil {
				t.Fatal("dialWebSocket = nil error, want an error")
			}
			var connErr *conn.ConnectionError
			if !errors.As(err, &connErr) {
				t.Errorf("error type: %T (%v), want *conn.ConnectionError", err, err)
			}
			innermost := innermostErr(err)
			t.Logf("shape %s: innermost=%q negotiated(client)=%q elapsed=%v", tc.name, innermost, dialer.negotiatedALPN(), elapsed)
			if tc.wantInnermost != "" && innermost != tc.wantInnermost {
				t.Errorf("innermost error = %q, want %q", innermost, tc.wantInnermost)
			}
			if tc.wantInnermost == "" && innermost == wsHandshakeLiveError {
				t.Errorf("innermost error = live string %q, want a different error family", innermost)
			}
			if tc.wantNegotiated != "" {
				if got := dialer.negotiatedALPN(); got != tc.wantNegotiated {
					t.Errorf("client negotiated ALPN = %q, want %q", got, tc.wantNegotiated)
				}
				if _, _, serverNeg, _, _ := srv.snapshot(); serverNeg != tc.wantNegotiated {
					t.Errorf("server negotiated ALPN = %q, want %q", serverNeg, tc.wantNegotiated)
				}
			}
			if tc.kind == scriptSilent && elapsed > 5*time.Second {
				t.Errorf("silent shape took %v, want the 200ms bound to fire", elapsed)
			}
			srv.waitDone(t)

			// Where the server read the upgrade request, it
			// must be the HTTP/1.1 gorilla request: correct
			// target, Upgrade headers, castctl Origin/UA, and
			// no Cookie or subprotocol (both absent, as in
			// Python).
			if tc.kind != scriptSilent && tc.kind != scriptImmediateClose {
				_, sni, _, reqLine, hdr := srv.snapshot()
				if tc.secure && sni != "gateway.test" {
					t.Errorf("SNI = %q, want %q", sni, "gateway.test")
				}
				wantLine := "GET /v1/noise?vm_id=FAKEVM&auth_token=FAKETOKEN HTTP/1.1"
				if reqLine != wantLine {
					t.Errorf("request line = %q, want %q", reqLine, wantLine)
				}
				if got := hdr.Get("Upgrade"); !strings.EqualFold(got, "websocket") {
					t.Errorf("Upgrade header = %q, want websocket", got)
				}
				if got := hdr.Get("Sec-WebSocket-Version"); got != "13" {
					t.Errorf("Sec-WebSocket-Version = %q, want 13", got)
				}
				if got := hdr.Get("Origin"); got != "https://muse.ai" {
					t.Errorf("Origin = %q, want https://muse.ai", got)
				}
				if got := hdr.Get("User-Agent"); got != UserAgent {
					t.Errorf("User-Agent = %q, want the Chrome/153 constant", got)
				}
				if got := hdr.Get("Cookie"); got != "" {
					t.Errorf("Cookie header = %q, want absent", got)
				}
				if got := hdr.Get("Sec-WebSocket-Protocol"); got != "" {
					t.Errorf("Sec-WebSocket-Protocol = %q, want absent", got)
				}
			}
		})
	}
}
