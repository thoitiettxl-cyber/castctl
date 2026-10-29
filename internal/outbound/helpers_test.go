// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

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
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Fake servers and fake outbounds for tests. Everything binds 127.0.0.1
// only. No test in this package dials a real network address.

// startFakeTCP returns a listener that reads once and replies "ok".
func startFakeTCP(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("ok"))
			}(conn)
		}
	}()
	return ln.Addr().String(), ln.Addr().(*net.TCPAddr).Port
}

// startFakeSOCKS5 returns a minimal no-auth SOCKS5 CONNECT proxy on
// 127.0.0.1. It maps the fake-only hostname gateway.test to 127.0.0.1 and
// rejects everything else without ever touching the system resolver.
func startFakeSOCKS5(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFakeSOCKS5(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func handleFakeSOCKS5(client net.Conn) {
	defer client.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		return
	}
	if req[1] != 0x01 {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(client, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(client, pb); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])
	if host != "gateway.test" && host != "127.0.0.1" {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 5*time.Second)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, target); done <- struct{}{} }()
	<-done
}

// startFakeHTTPProxy returns a CONNECT proxy on 127.0.0.1 that only
// connects to 127.0.0.1 targets.
func startFakeHTTPProxy(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil || n == 0 {
					return
				}
				var method, target string
				_, _ = fmt.Sscanf(string(buf[:n]), "%s %s", &method, &target)
				host, port, err := net.SplitHostPort(target)
				if err != nil || method != "CONNECT" || (host != "127.0.0.1" && host != "localhost") {
					_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
					return
				}
				up, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 5*time.Second)
				if err != nil {
					_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer up.Close()
				_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
				go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
				<-done
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// startFakeTLSServer returns a TLS echo server on 127.0.0.1 with a
// self-signed certificate for gateway.test. It reads once and replies
// "tls-ok". The certificate is generated fresh per test; nothing here is
// a real credential.
func startFakeTLSServer(t *testing.T) string {
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
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("tls-ok"))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// recordingOutbound is a fake adapter.Outbound that records every dial
// destination and returns a net.Pipe pair that echoes written bytes.
type recordingOutbound struct {
	mu       sync.Mutex
	dials    []M.Socksaddr
	blocking bool
}

var _ adapter.Outbound = (*recordingOutbound)(nil)

func (f *recordingOutbound) Type() string           { return "fake" }
func (f *recordingOutbound) Tag() string            { return "fake" }
func (f *recordingOutbound) Network() []string      { return []string{N.NetworkTCP} }
func (f *recordingOutbound) Dependencies() []string { return nil }

func (f *recordingOutbound) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, dest)
	f.mu.Unlock()
	if f.blocking {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	client, server := net.Pipe()
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			if _, err := server.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	return client, nil
}

func (f *recordingOutbound) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("fake: ListenPacket not implemented")
}

func (f *recordingOutbound) dialsSnapshot() []M.Socksaddr {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]M.Socksaddr, len(f.dials))
	copy(out, f.dials)
	return out
}

// fakeResolver is a fake HostResolver backed by a fixed map. It records
// every lookup so tests can prove resolution went through the seam.
type fakeResolver struct {
	mu      sync.Mutex
	addrs   map[string][]netip.Addr
	lookups []string
	err     error
}

func (f *fakeResolver) Lookup(ctx context.Context, domain string, _ adapter.DNSQueryOptions) ([]netip.Addr, error) {
	f.mu.Lock()
	f.lookups = append(f.lookups, domain)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	addrs, ok := f.addrs[domain]
	if !ok {
		return nil, fmt.Errorf("fake resolver: no entry for %s", domain)
	}
	return addrs, nil
}

func (f *fakeResolver) lookupNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.lookups))
	copy(out, f.lookups)
	return out
}
