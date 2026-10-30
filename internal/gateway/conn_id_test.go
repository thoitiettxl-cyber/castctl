// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

// Shared connection-ID test: ONE connection's dial_start,
// tls_alpn, and ws_handshake lines must carry the SAME ID.
//
// The test drives the production path end to end: the real
// outbound Manager/Dialer (wired logger), the production
// dialWebSocket (which mints the ID and passes the ctx to
// WebSocketDial), and a fake TLS WebSocket gateway on loopback
// that answers the upgrade with 101. The gateway URL carries
// fixture values only (vm_id + auth_token), and the capture is
// scanned for them: no fixture value may reach a log line.
// The fake gateway's certificate is signed by a fixture CA
// whose PEM is trusted via SSL_CERT_FILE for this test process
// only (t.Setenv); no production trust behaviour changes.
//
// Requires -tags with_utls (skipUnlessUTLS): the production
// dial defaults to the uTLS chrome fingerprint, which the
// untagged stub build rejects before any handshake.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
)

var connIDLineRe = regexp.MustCompile(`\[(\d+) (\d+ms|[\d.]+s|\d+m\d+s)\]`)
var connIDANSIRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSIConnID(s string) string { return connIDANSIRe.ReplaceAllString(s, "") }

func connIDFromLine(t *testing.T, line string) string {
	t.Helper()
	matches := connIDLineRe.FindAllStringSubmatch(line, -1)
	if len(matches) != 1 {
		t.Fatalf("line %q: want exactly one connection-ID prefix, found %d", line, len(matches))
	}
	return matches[0][1]
}

func fixtureCA(t *testing.T) (ca *x509.Certificate, caKey *ecdsa.PrivateKey, caPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fixture-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return ca, key, caPEM
}

func fixtureLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "gateway.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"gateway.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveOneWSUpgrade accepts one TLS connection, completes the
// handshake, answers the WebSocket upgrade with 101, then reads
// until EOF. It reports completion on done.
func serveOneWSUpgrade(t *testing.T, ln net.Listener, cert tls.Certificate, done chan<- struct{}) {
	t.Helper()
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
		br := bufio.NewReader(tc)
		var wsKey string
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
				wsKey = strings.TrimSpace(line[len("sec-websocket-key:"):])
			}
			if line == "\r\n" {
				break
			}
		}
		if wsKey == "" {
			return
		}
		h := sha1.Sum([]byte(wsKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		accept := base64.StdEncoding.EncodeToString(h[:])
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		if _, err := tc.Write([]byte(resp)); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, tc)
	}()
}

func TestDialWebSocketSharedConnectionID(t *testing.T) {
	skipUnlessUTLS(t)
	// Trust the fixture CA for this test process only. Not
	// t.Parallel: t.Setenv is process-scoped.
	ca, caKey, caPEM := fixtureCA(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", caPath)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	serveOneWSUpgrade(t, ln, fixtureLeaf(t, ca, caKey), done)

	var buf bytes.Buffer
	h, err := logging.NewFactory(context.Background(), logging.Settings{Level: "trace"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	logger := h.Logger("castctl")
	m, err := outbound.NewManager(context.Background(), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	var out option.Outbound
	if err := json.UnmarshalContext(m.Context(), []byte(`{"type":"direct","tag":"direct"}`), &out); err != nil {
		t.Fatal(err)
	}
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

	wsURL := "wss://127.0.0.1:" + strings.Split(ln.Addr().String(), ":")[1] + "/v1/noise?vm_id=LOGFIX-VMID-22d9f0&auth_token=LOGFIX-HT-2c6e88"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, _, err := dialWebSocket(ctx, d, wsURL, true, 5*time.Second, logger)
	if err != nil {
		t.Fatalf("dialWebSocket: %v", err)
	}
	_ = ws.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("fake gateway did not finish after the client closed")
	}

	got := stripANSIConnID(buf.String())
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	var start, alpn, handshake string
	for _, line := range lines {
		switch {
		case strings.Contains(line, "event=dial_start"):
			if start != "" {
				t.Fatalf("two dial_start lines:\n%s", got)
			}
			start = line
		case strings.Contains(line, "event=tls_alpn"):
			if alpn != "" {
				t.Fatalf("two tls_alpn lines:\n%s", got)
			}
			alpn = line
		case strings.Contains(line, "event=ws_handshake"):
			if handshake != "" {
				t.Fatalf("two ws_handshake lines:\n%s", got)
			}
			handshake = line
		}
	}
	if start == "" || alpn == "" || handshake == "" {
		t.Fatalf("missing event lines (start=%q alpn=%q handshake=%q):\n%s", start, alpn, handshake, got)
	}
	if !strings.Contains(handshake, "status_code=101") {
		t.Errorf("ws_handshake line %q, want status_code=101", handshake)
	}
	idStart := connIDFromLine(t, start)
	idALPN := connIDFromLine(t, alpn)
	idHS := connIDFromLine(t, handshake)
	if idStart != idALPN || idStart != idHS {
		t.Errorf("connection IDs differ: dial_start=%q tls_alpn=%q ws_handshake=%q, want one shared ID", idStart, idALPN, idHS)
	}
	for _, v := range []string{"LOGFIX-VMID-22d9f0", "LOGFIX-HT-2c6e88"} {
		if strings.Contains(got, v) {
			t.Errorf("capture contains fixture value %q:\n%s", v, got)
		}
	}
}
