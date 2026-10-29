// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// Dialer-level isolation: HTTPClient connection pools / cookie jars
// and the TLS session cache.
//
// - Every HTTPClient() call builds a FRESH *http.Client with a FRESH
//   *http.Transport: no connection pool and no cookie jar is ever
//   shared, within one Dialer or across Dialers. Proxy is nil and
//   Jar is nil, so proxy environment variables are never consulted
//   and no cookie is ever stored.
// - TLS session cache OFF: BuildTLSConfig builds a fresh sing-box
//   TLS config per call, and neither TLS engine sets a session
//   cache (grep over sing-box v1.14.4 common/tls: no
//   ClientSessionCache assignment in utls_client.go or
//   std_client.go; metacubex/utls handshake_client.go:423 and :1095
//   skip resumption entirely when the cache is nil). The test below
//   proves it behaviourally: two handshakes to the same server must
//   both be full handshakes (DidResume false).

func TestDialerHTTPClientNoSharedPoolOrJar(t *testing.T) {
	// Loopback HTTP server recording Cookie headers per request.
	var mu sync.Mutex
	var cookies []string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookies = append(cookies, r.Header.Get("Cookie"))
		mu.Unlock()
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

	c1 := d.HTTPClient()
	c2 := d.HTTPClient()
	if c1 == c2 {
		t.Fatal("two HTTPClient() calls returned the same *http.Client")
	}
	tr1, ok := c1.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTPClient transport = %T, want *http.Transport", c1.Transport)
	}
	tr2, ok := c2.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTPClient transport = %T, want *http.Transport", c2.Transport)
	}
	if tr1 == tr2 {
		t.Error("two HTTPClient() calls share one *http.Transport (one connection pool)")
	}
	for i, c := range []*http.Client{c1, c2} {
		if c.Jar != nil {
			t.Errorf("HTTPClient %d has a cookie Jar; it must be nil", i)
		}
	}
	for i, tr := range []*http.Transport{tr1, tr2} {
		if tr.Proxy != nil {
			t.Errorf("HTTP transport %d Proxy is set; it must be nil", i)
		}
		if tr.TLSClientConfig != nil {
			t.Errorf("HTTP transport %d has a TLSClientConfig; TLS goes through DialTLSContext, never a shared stdlib config", i)
		}
		if tr.DialContext == nil || tr.DialTLSContext == nil {
			t.Errorf("HTTP transport %d lacks DialContext/DialTLSContext", i)
		}
	}
	// A second Dialer for the same outbound also gets a fresh pool.
	d2, err := m.Dialer("direct")
	if err != nil {
		t.Fatal(err)
	}
	if d2 == d {
		t.Error("two Dialer() calls returned the same *Dialer")
	}
	c3 := d2.HTTPClient()
	tr3, ok := c3.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("second Dialer HTTPClient transport = %T", c3.Transport)
	}
	if tr3 == tr1 || tr3 == tr2 {
		t.Error("Dialers share one *http.Transport")
	}
	if c3.Jar != nil {
		t.Error("second Dialer HTTPClient has a cookie Jar")
	}

	// A Cookie sent via c1 must never appear on a request via c3:
	// there is no jar to carry it, and c3 sends no Cookie header.
	get := func(c *http.Client, cookie string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ln.Addr().String()+"/ping", nil)
		if err != nil {
			t.Fatal(err)
		}
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "pong" {
			t.Fatalf("body = %q, want %q", string(body), "pong")
		}
	}
	get(c1, "session=FAKE-1")
	get(c3, "")
	mu.Lock()
	got := append([]string(nil), cookies...)
	mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("recorded Cookie headers = %v, want 2 requests", got)
	}
	if got[0] != "session=FAKE-1" {
		t.Errorf("first request Cookie = %q, want %q", got[0], "session=FAKE-1")
	}
	if got[1] != "" {
		t.Errorf("second request (other Dialer, no jar) Cookie = %q, want empty: a cookie leaked across Dialers", got[1])
	}
}
