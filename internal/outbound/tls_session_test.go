// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_utls

package outbound

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// recordingTLSServer is a stdlib TLS server recording, per accepted
// connection, whether the handshake resumed a previous session.
type recordingTLSServer struct {
	addr string

	mu      sync.Mutex
	resumed []bool
}

func startRecordingTLSServer(t *testing.T) *recordingTLSServer {
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
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	s := &recordingTLSServer{addr: ln.Addr().String()}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	return s
}

func (s *recordingTLSServer) handle(conn net.Conn) {
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	if err := tc.Handshake(); err != nil {
		return
	}
	s.mu.Lock()
	s.resumed = append(s.resumed, tc.ConnectionState().DidResume)
	s.mu.Unlock()
	buf := make([]byte, 64)
	if _, err := tc.Read(buf); err != nil {
		return
	}
	_, _ = tc.Write([]byte("tls-ok"))
}

func (s *recordingTLSServer) resumedSnapshot() []bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]bool, len(s.resumed))
	copy(out, s.resumed)
	return out
}

func TestTLSNoSessionResumption(t *testing.T) {
	// Both TLS engines the Dialer can build must resume nothing:
	// uTLS chrome (the default) and the stdlib engine (UTLS
	// explicitly disabled). Two successive handshakes to the same
	// server must both be full handshakes.
	cases := []struct {
		name string
		opts option.OutboundTLSOptions
	}{
		{name: "utls-chrome", opts: option.OutboundTLSOptions{Enabled: true, Insecure: true}},
		{name: "stdlib", opts: option.OutboundTLSOptions{Enabled: true, Insecure: true, UTLS: &option.OutboundUTLSOptions{Enabled: false}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startRecordingTLSServer(t)
			host, portStr, err := net.SplitHostPort(srv.addr)
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
			d := NewDialer(direct, nil, tc.opts)
			for i := 0; i < 2; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				conn, err := d.DialTLS(ctx, "tcp", host, uint16(port), tc.opts)
				cancel()
				if err != nil {
					t.Fatalf("DialTLS %d: %v", i, err)
				}
				if _, err := conn.Write([]byte("hello")); err != nil {
					conn.Close()
					t.Fatal(err)
				}
				buf := make([]byte, 16)
				n, err := conn.Read(buf)
				conn.Close()
				if err != nil {
					t.Fatal(err)
				}
				if string(buf[:n]) != "tls-ok" {
					t.Fatalf("handshake %d echo = %q, want %q", i, string(buf[:n]), "tls-ok")
				}
			}
			got := srv.resumedSnapshot()
			if len(got) != 2 {
				t.Fatalf("recorded handshakes = %d, want 2", len(got))
			}
			if got[0] || got[1] {
				t.Errorf("DidResume = %v, want [false false]: a TLS session was resumed, so a session cache exists somewhere on this path", got)
			}
		})
	}
}
