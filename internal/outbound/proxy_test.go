// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

// loopbackOutbound is a fake adapter.Outbound that dials the
// loopback address the test server listens on, whatever
// destination it is asked for — while recording the requested
// destinations, so tests prove the proxy asked the outbound
// for the right host:port and never dialled directly.
type loopbackOutbound struct {
	dials  []metadata.Socksaddr
	target string
}

func (f *loopbackOutbound) Type() string           { return "fake" }
func (f *loopbackOutbound) Tag() string            { return "fake" }
func (f *loopbackOutbound) Network() []string      { return []string{network.NetworkTCP} }
func (f *loopbackOutbound) Dependencies() []string { return nil }
func (f *loopbackOutbound) DialContext(ctx context.Context, nw string, dest metadata.Socksaddr) (net.Conn, error) {
	f.dials = append(f.dials, dest)
	var d net.Dialer
	return d.DialContext(ctx, nw, f.target)
}
func (f *loopbackOutbound) ListenPacket(ctx context.Context, dest metadata.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("fake: ListenPacket not implemented")
}

var _ adapter.Outbound = (*loopbackOutbound)(nil)

func proxyTestDialer(t *testing.T, target string) (*Dialer, *loopbackOutbound) {
	t.Helper()
	fake := &loopbackOutbound{target: target}
	// A resolver must be registered or DialContext fails
	// closed on domain destinations before the outbound is
	// touched; the fake outbound never calls it.
	return NewDialer(fake, &fakeResolver{}, option.OutboundTLSOptions{}), fake
}

// proxyTestOpts builds explicit proxy options for tests: the
// production defaults as literals, plus exactly the hosts the
// test dials. Tests never rely on a zero-value default.
func proxyTestOpts(hosts ...string) ProxyOptions {
	return ProxyOptions{
		DialTimeout:    30 * time.Second,
		MaxHeaderBytes: 64 << 10,
		MaxBodyBytes:   16 << 20,
		AllowedHosts:   hosts,
	}
}

func TestLoopbackProxyCONNECT(t *testing.T) {
	t.Parallel()
	// TLS server on loopback: the CONNECT tunnel must carry
	// a real TLS handshake end to end, with the proxy seeing
	// only bytes.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunnel-ok")
	}))
	srv.StartTLS()
	defer srv.Close()
	srvURL, _ := url.Parse(srv.URL)
	_, port, _ := net.SplitHostPort(srvURL.Host)

	dialer, fake := proxyTestDialer(t, srv.Listener.Addr().String())
	proxy, proxyURL, err := NewLoopbackProxy(dialer, proxyTestOpts("proxy-target.test"))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if !strings.HasPrefix(proxyURL, "http://127.0.0.1:") {
		t.Fatalf("proxy URL = %q; want loopback", proxyURL)
	}
	pu, _ := url.Parse(proxyURL)
	transport := &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test server only
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	// The requested host is fake: only the fake outbound's
	// loopback mapping makes it reachable, proving the
	// request went through the Dialer.
	resp, err := client.Get("https://proxy-target.test:" + port + "/x")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "tunnel-ok" {
		t.Fatalf("body = %q; want tunnel-ok", body)
	}
	if len(fake.dials) != 1 {
		t.Fatalf("outbound dials = %d; want 1", len(fake.dials))
	}
	if fake.dials[0].String() != "proxy-target.test:"+port {
		t.Fatalf("outbound dial dest = %v; want proxy-target.test:%s", fake.dials[0], port)
	}
}

func mustPort(t *testing.T, s string) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLoopbackProxyPlainHTTP(t *testing.T) {
	t.Parallel()
	var gotMethod, gotPath, gotBody string
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.RequestURI()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotHeader = r.Header.Get("X-Test")
		fmt.Fprint(w, "plain-ok")
	}))
	defer srv.Close()
	srvURL, _ := url.Parse(srv.URL)
	_, port, _ := net.SplitHostPort(srvURL.Host)

	dialer, fake := proxyTestDialer(t, srv.Listener.Addr().String())
	proxy, proxyURL, err := NewLoopbackProxy(dialer, proxyTestOpts("plain-target.test"))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	pu, _ := url.Parse(proxyURL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 10 * time.Second}
	req, _ := http.NewRequest("POST", "http://plain-target.test:"+port+"/submit?q=1", strings.NewReader("field=value"))
	req.Header.Set("X-Test", "yes")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "plain-ok" || gotMethod != "POST" || gotPath != "/submit?q=1" || gotBody != "field=value" || gotHeader != "yes" {
		t.Fatalf("upstream saw method=%q path=%q body=%q header=%q body=%q", gotMethod, gotPath, gotBody, gotHeader, body)
	}
	if len(fake.dials) != 1 || fake.dials[0].String() != "plain-target.test:"+port {
		t.Fatalf("outbound dials = %v; want one plain-target.test dial", fake.dials)
	}
}

func TestLoopbackProxyDialFailureIs502(t *testing.T) {
	t.Parallel()
	fake := &loopbackOutbound{target: "127.0.0.1:1"} // closed port: dial fails
	dialer := NewDialer(fake, &fakeResolver{}, option.OutboundTLSOptions{})
	proxy, proxyURL, err := NewLoopbackProxy(dialer, proxyTestOpts("unreachable.test"))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	pu, _ := url.Parse(proxyURL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 10 * time.Second}
	// A proxy 502 surfaces as a response, not a transport
	// error: assert the status, not err.
	resp, err := client.Get("http://unreachable.test/")
	if err != nil {
		t.Fatalf("GET via failing proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d; want 502", resp.StatusCode)
	}
}

func TestLoopbackProxyCloseStopsListening(t *testing.T) {
	t.Parallel()
	dialer, _ := proxyTestDialer(t, "127.0.0.1:1")
	proxy, proxyURL, err := NewLoopbackProxy(dialer, proxyTestOpts("example.test"))
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(proxyURL)
	if err := proxy.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := proxy.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	conn, err := net.DialTimeout("tcp", pu.Host, 2*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatal("listener still accepting after Close")
	}
}

func TestLoopbackProxyNilDialer(t *testing.T) {
	t.Parallel()
	if _, _, err := NewLoopbackProxy(nil, proxyTestOpts("example.test")); err == nil {
		t.Fatal("NewLoopbackProxy(nil) = nil error; want fail-closed")
	}
}

// TestLoopbackProxyCONNECTClosesUpstream (D1): when the
// client side of a CONNECT tunnel closes, the upstream
// connection must be closed too — a leaked upstream socket
// per tunnel would accumulate across re-logins in a
// long-lived process. The upstream server proves it by
// seeing EOF.
func TestLoopbackProxyCONNECTClosesUpstream(t *testing.T) {
	t.Parallel()
	upstreamEOF := make(chan struct{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, _ = io.Copy(io.Discard, conn)
		close(upstreamEOF)
	}()

	dialer, _ := proxyTestDialer(t, ln.Addr().String())
	proxy, proxyURL, err := NewLoopbackProxy(dialer, proxyTestOpts("upstream.test"))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	pu, _ := url.Parse(proxyURL)

	conn, err := net.DialTimeout("tcp", pu.Host, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT upstream.test:443 HTTP/1.1\r\nHost: upstream.test:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status = %q; want 200", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-upstreamEOF:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream connection was not closed after the tunnel client closed (leaked upstream socket)")
	}
}

// TestLoopbackProxyChunkedBody (S8): a chunked plain-HTTP
// request body must arrive decoded at the upstream with a
// single Content-Length and no Transfer-Encoding — the
// proxy must not drop the body, and must not forward a
// chunked stream it did not re-chunk.
func TestLoopbackProxyChunkedBody(t *testing.T) {
	t.Parallel()
	var gotBody string
	var gotTE []string
	var gotCL int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody, gotTE, gotCL = string(body), r.TransferEncoding, r.ContentLength
		fmt.Fprint(w, "chunked-ok")
	}))
	defer srv.Close()
	srvURL, _ := url.Parse(srv.URL)

	dialer, _ := proxyTestDialer(t, srv.Listener.Addr().String())
	proxy, proxyURL, err := NewLoopbackProxy(dialer, proxyTestOpts("chunked-target.test"))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	pu, _ := url.Parse(proxyURL)
	transport := &http.Transport{Proxy: http.ProxyURL(pu)}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", "http://chunked-target.test:"+srvURL.Port()+"/x", io.NopCloser(strings.NewReader("chunked-payload")))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1 // forces chunked request encoding
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "chunked-ok" {
		t.Fatalf("body = %q; want chunked-ok", body)
	}
	if gotBody != "chunked-payload" {
		t.Fatalf("upstream body = %q; want chunked-payload", gotBody)
	}
	if len(gotTE) != 0 {
		t.Fatalf("upstream Transfer-Encoding = %v; want none (proxy re-framed with Content-Length)", gotTE)
	}
	if gotCL != int64(len("chunked-payload")) {
		t.Fatalf("upstream Content-Length = %d; want %d", gotCL, len("chunked-payload"))
	}
}

// TestLoopbackProxyDuplicateContentLength (S8): duplicate
// Content-Length headers with differing values must be
// rejected (400) without dialling the upstream — the last
// value must never silently govern the body copy.
func TestLoopbackProxyDuplicateContentLength(t *testing.T) {
	t.Parallel()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	srvURL, _ := url.Parse(srv.URL)

	dialer, fake := proxyTestDialer(t, srv.Listener.Addr().String())
	proxy, proxyURL, err := NewLoopbackProxy(dialer, proxyTestOpts("dup.test"))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	pu, _ := url.Parse(proxyURL)

	conn, err := net.DialTimeout("tcp", pu.Host, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Two differing Content-Length headers over the same
	// 5-byte body.
	raw := "POST http://dup.test:" + srvURL.Port() + "/x HTTP/1.1\r\n" +
		"Host: dup.test:" + srvURL.Port() + "\r\n" +
		"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "400") {
		t.Fatalf("status = %q; want 400 for differing duplicate Content-Length", status)
	}
	if hits != 0 || len(fake.dials) != 0 {
		t.Fatalf("upstream hits = %d, outbound dials = %d; want 0/0 (rejected before dialling)", hits, len(fake.dials))
	}
}

// TestLoopbackProxyOptionsValidation: zero timeouts/caps, an
// empty allowlist, and an invalid allowlist entry all fail
// closed before listening.
func TestLoopbackProxyOptionsValidation(t *testing.T) {
	t.Parallel()
	dialer, _ := proxyTestDialer(t, "127.0.0.1:1")
	for name, opts := range map[string]ProxyOptions{
		"zero":          {},
		"zero timeout":  {DialTimeout: 30 * time.Second, MaxHeaderBytes: 64 << 10, MaxBodyBytes: 16 << 20},
		"zero caps":     {DialTimeout: 30 * time.Second, AllowedHosts: []string{"a.test"}},
		"bad host":      proxyTestOpts("http://a.test"),
		"wildcard host": proxyTestOpts("*.a.test"),
		"port host":     proxyTestOpts("a.test:443"),
	} {
		if _, _, err := NewLoopbackProxy(dialer, opts); err == nil {
			t.Fatalf("%s: NewLoopbackProxy = nil error; want fail-closed", name)
		}
	}
}

// guardTestProxy starts a proxy whose fake outbound dials a
// listener regardless of destination, recording dials and
// refusals. The listener accepts and immediately closes, so
// an allowed CONNECT gets a 200.
func guardTestProxy(t *testing.T, target string, opts ProxyOptions) (*LoopbackProxy, string, *loopbackOutbound, *[]string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	dialer, fake := proxyTestDialer(t, ln.Addr().String())
	var refused []string
	opts.OnRefused = func(host string) { refused = append(refused, host) }
	proxy, proxyURL, err := NewLoopbackProxy(dialer, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	_ = target
	return proxy, proxyURL, fake, &refused
}

func guardCONNECT(t *testing.T, proxyURL, authority string) int {
	t.Helper()
	pu, _ := url.Parse(proxyURL)
	conn, err := net.DialTimeout("tcp", pu.Host, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var code int
	if _, err := fmt.Sscanf(status, "HTTP/1.1 %d", &code); err != nil {
		t.Fatalf("CONNECT status line = %q", status)
	}
	return code
}

func TestLoopbackProxyGuardRefusesLiteralIPs(t *testing.T) {
	t.Parallel()
	// Even an explicitly listed loopback literal is refused:
	// the range rule is absolute, not overridable by listing.
	opts := proxyTestOpts("127.0.0.1", "10.0.0.0", "allowed.test")
	_, proxyURL, fake, refused := guardTestProxy(t, "", opts)
	for _, authority := range []string{"127.0.0.1:443", "10.1.2.3:443", "169.254.1.2:443", "192.168.0.5:443", "0.0.0.0:443", "[::1]:443", "100.64.0.9:443"} {
		if code := guardCONNECT(t, proxyURL, authority); code != 403 {
			t.Fatalf("CONNECT %s: status = %d; want 403", authority, code)
		}
	}
	if len(fake.dials) != 0 {
		t.Fatalf("outbound dials = %d; want 0 (refused before dialling)", len(fake.dials))
	}
	if len(*refused) != 7 {
		t.Fatalf("refusals logged = %v; want 7 host-only entries", *refused)
	}
	want := map[string]bool{"127.0.0.1": true, "10.1.2.3": true, "169.254.1.2": true, "192.168.0.5": true, "0.0.0.0": true, "::1": true, "100.64.0.9": true}
	for _, h := range *refused {
		if !want[h] || strings.ContainsAny(h, "/?#@") {
			t.Fatalf("refused host = %q; want a host only, no port/query/userinfo", h)
		}
	}
}

func TestLoopbackProxyGuardRefusesNonAllowlistedHost(t *testing.T) {
	t.Parallel()
	opts := proxyTestOpts("allowed.test")
	_, proxyURL, fake, refused := guardTestProxy(t, "", opts)
	if code := guardCONNECT(t, proxyURL, "not-listed.example:443"); code != 403 {
		t.Fatalf("CONNECT status = %d; want 403", code)
	}
	if len(fake.dials) != 0 {
		t.Fatalf("outbound dials = %d; want 0", len(fake.dials))
	}
	if len(*refused) != 1 || (*refused)[0] != "not-listed.example" {
		t.Fatalf("refusals = %v; want [not-listed.example]", *refused)
	}
}

func TestLoopbackProxyGuardAllowsListedHost(t *testing.T) {
	t.Parallel()
	opts := proxyTestOpts("allowed.test")
	_, proxyURL, fake, refused := guardTestProxy(t, "", opts)
	// Case + trailing dot normalise to the listed host.
	if code := guardCONNECT(t, proxyURL, "ALLOWED.test.:443"); code != 200 {
		t.Fatalf("CONNECT status = %d; want 200", code)
	}
	if len(fake.dials) != 1 {
		t.Fatalf("outbound dials = %d; want 1", len(fake.dials))
	}
	if len(*refused) != 0 {
		t.Fatalf("refusals = %v; want none", *refused)
	}
}

func TestLoopbackProxyGuardPlainHTTP(t *testing.T) {
	t.Parallel()
	opts := proxyTestOpts("allowed.test")
	_, proxyURL, fake, refused := guardTestProxy(t, "", opts)
	pu, _ := url.Parse(proxyURL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 10 * time.Second}
	for _, rawurl := range []string{"http://127.0.0.1:9/x?token=SECRET", "http://not-listed.example/x?token=SECRET"} {
		resp, err := client.Get(rawurl)
		if err != nil {
			t.Fatalf("GET %s via proxy: %v", rawurl, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("GET %s: status = %d; want 403", rawurl, resp.StatusCode)
		}
	}
	if len(fake.dials) != 0 {
		t.Fatalf("outbound dials = %d; want 0", len(fake.dials))
	}
	if len(*refused) != 2 || (*refused)[0] != "127.0.0.1" || (*refused)[1] != "not-listed.example" {
		t.Fatalf("refusals = %v; want host-only [127.0.0.1 not-listed.example], no query", *refused)
	}
}

func TestLoopbackProxyGuardListedPublicIPLiteral(t *testing.T) {
	t.Parallel()
	// A listed PUBLIC IP literal is dialled: the range rule
	// refuses only the refused ranges, the allowlist gates
	// everything else.
	opts := proxyTestOpts("8.8.8.8")
	_, proxyURL, fake, _ := guardTestProxy(t, "", opts)
	if code := guardCONNECT(t, proxyURL, "8.8.8.8:443"); code != 200 {
		t.Fatalf("CONNECT status = %d; want 200 (dial spent)", code)
	}
	if len(fake.dials) != 1 {
		t.Fatalf("outbound dials = %d; want 1", len(fake.dials))
	}
}
