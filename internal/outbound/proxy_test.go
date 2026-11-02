// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
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
	proxy, proxyURL, err := NewLoopbackProxy(dialer)
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
	proxy, proxyURL, err := NewLoopbackProxy(dialer)
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
	proxy, proxyURL, err := NewLoopbackProxy(dialer)
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
	proxy, proxyURL, err := NewLoopbackProxy(dialer)
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
	if _, _, err := NewLoopbackProxy(nil); err == nil {
		t.Fatal("NewLoopbackProxy(nil) = nil error; want fail-closed")
	}
}
