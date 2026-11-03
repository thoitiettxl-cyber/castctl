// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/remote"
)

// TestHarvestRealChromeScopedVsForeign promotes the probe-4
// discrimination to a committed test: on real Chrome 155, the
// harvest of a tab on an in-list host returns the in-list
// host-only hatch_sess and NOT a different hatch_sess that
// lives only on an out-of-list host — in a session where the
// browser-level Storage read provably holds the foreign
// value, so the harvested set can only be the target-level
// scoped read. ExportURLs is NOT swapped: the local server
// answers TLS for the real Muse origins via
// host-resolver-rules, and Chrome ignores the synthetic
// certificate. The test skips cleanly when no Chrome binary
// is available (the chromeTestPath pattern). All cookie
// values are synthetic FAKE-* values.
func TestHarvestRealChromeScopedVsForeign(t *testing.T) {
	chromePath := chromeTestPath(t)
	_, port := harvestRealChromeServer(t)
	rules := fmt.Sprintf("MAP muse.ai 127.0.0.1:%d, MAP auth.muse.ai 127.0.0.1:%d, MAP www.muse.ai 127.0.0.1:%d, MAP other.test 127.0.0.1:%d", port, port, port, port)

	dir, err := os.MkdirTemp("", "castctl-harvest-realchrome-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Headless,
		remote.WebSocket,
		chromedp.Flag("enable-automation", false),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("host-resolver-rules", rules),
		chromedp.UserDataDir(dir),
		chromedp.ExecPath(chromePath),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocOpts...)
	tctx, cancelTarget := chromedp.NewContext(allocCtx)
	t.Cleanup(func() {
		cancelTarget()
		cancelAlloc()
		// Let the browser process exit before the profile
		// dir is removed: Chrome can still hold it at
		// cancel time, which wedges TempDir-style
		// cleanup.
		time.Sleep(time.Second)
		if err := os.RemoveAll(dir); err != nil {
			t.Logf("profile dir cleanup: %v", err)
		}
	})

	// Set the foreign cookie first, then the in-list one,
	// leaving the tab on the in-list host.
	if _, err := chromedp.Run(tctx, chromedp.Navigate("https://other.test/")); err != nil {
		t.Fatalf("navigate foreign host: %v", err)
	}
	if _, err := chromedp.Run(tctx, chromedp.Navigate("https://auth.muse.ai/")); err != nil {
		t.Fatalf("navigate in-list host: %v", err)
	}

	// Evidence, logged not asserted: the browser-level
	// Storage read in this session, and the browser-level
	// Network error shape (-32601 on Chrome 155).
	if sres, serr := chromedp.CallBrowser(tctx, storage.GetCookies, storage.GetCookiesParams{}); serr == nil {
		var rows []string
		for _, c := range sres.Cookies {
			rows = append(rows, c.Name+"@"+c.Domain+"="+c.Value)
		}
		t.Logf("browser Storage: %v", rows)
	} else {
		t.Logf("browser Storage error: %v", serr)
	}
	if _, berr := chromedp.CallBrowser(tctx, network.GetCookies, network.GetCookiesParams{URLs: ExportURLs}); berr != nil {
		t.Logf("browser Network scoped error: %v (want -32601 on Chrome 155)", berr)
	} else {
		t.Logf("browser Network scoped: no error in this session")
	}

	cookies, err := (&chromedpReloginDriver{}).harvest(tctx)
	if err != nil {
		t.Fatalf("harvest: %v", err)
	}
	sawAuth, sawOther := false, false
	for _, c := range cookies {
		if c.Name == "hatch_sess" && c.Value == "FAKE-AUTH-SESS" {
			sawAuth = true
		}
		if c.Name == "hatch_sess" && c.Value == "FAKE-OTHER-SESS" {
			sawOther = true
		}
	}
	if !sawAuth {
		t.Fatalf("harvest = %+v; want the in-list FAKE-AUTH-SESS", cookies)
	}
	if sawOther {
		t.Fatalf("harvest = %+v; want no out-of-list FAKE-OTHER-SESS", cookies)
	}
}

// harvestRealChromeServer serves TLS for the synthetic Muse
// origins and the foreign host, setting a host-only
// hatch_sess per host (no Domain attribute). It returns the
// server and its loopback port; host-resolver-rules maps the
// test hosts onto that port.
func harvestRealChromeServer(t *testing.T) (*http.Server, int) {
	t.Helper()
	cert := harvestTestCertificate(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		switch host {
		case "other.test":
			http.SetCookie(w, &http.Cookie{Name: "hatch_sess", Value: "FAKE-OTHER-SESS", Path: "/", HttpOnly: true})
		case "auth.muse.ai":
			http.SetCookie(w, &http.Cookie{Name: "hatch_sess", Value: "FAKE-AUTH-SESS", Path: "/", HttpOnly: true})
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><title>synthetic</title><p>synthetic</p>"))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	addr := ln.Addr().(*net.TCPAddr)
	return srv, addr.Port
}

// harvestTestCertificate builds a synthetic CA + leaf for the
// test hosts. Chrome runs with ignore-certificate-errors, so
// the CA is never trusted; the certificate only needs the
// right SANs for a well-formed handshake.
func harvestTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "castctl synthetic test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "muse.ai"},
		DNSNames:              []string{"muse.ai", "auth.muse.ai", "www.muse.ai", "other.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert
}
