// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginhost"
)

type recordingRoundTripper struct {
	last *http.Request
	body string
}

func (r *recordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.last = req.Clone(req.Context())
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Header:     http.Header{"X-Upstream": []string{"yes"}},
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Request:    req,
	}
	return resp, nil
}

func proxyAuth(t *testing.T, username, password string) string {
	t.Helper()
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

func proxyURLWithCreds(t *testing.T, p *pluginhost.EgressProxy, username, password string) *url.URL {
	t.Helper()
	u := *p.URL()
	u.User = url.UserPassword(username, password)
	return &u
}

func TestEgressProxyAuthRequired(t *testing.T) {
	upstream := &recordingRoundTripper{body: "ok"}
	proxy, err := pluginhost.NewEgressProxy(upstream, nil, "session-cookie")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	for _, tc := range []struct {
		name string
		url  *url.URL
	}{
		{"no credentials", proxy.URL()},
		{"wrong credentials", proxyURLWithCreds(t, proxy, "mallory", "wrong")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Credentials travel in the proxy URL userinfo:
			// http.Transport strips a hand-set
			// Proxy-Authorization header and re-adds it
			// from the URL.
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(tc.url)}}
			req, _ := http.NewRequest("GET", "http://example.invalid/path", nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != 407 {
				t.Fatalf("status = %d, want 407", resp.StatusCode)
			}
			if got := resp.Header.Get("Proxy-Authenticate"); got != "Basic" {
				t.Fatalf("Proxy-Authenticate = %q, want Basic", got)
			}
		})
	}
	if upstream.last != nil {
		t.Fatal("upstream must not be reached without valid credentials")
	}
}

func TestEgressProxyForwardsAndInjectsCookie(t *testing.T) {
	upstream := &recordingRoundTripper{body: "upstream-ok"}
	proxy, err := pluginhost.NewEgressProxy(upstream, nil, "injected-cookie-value")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURLWithCreds(t, proxy, proxy.Username(), proxy.Password()))}}
	req, _ := http.NewRequest("GET", "http://example.invalid/path?q=1", nil)
	req.Header.Set("Cookie", "plugin-cookie")
	req.Header.Set("X-Custom", "keep-me")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "upstream-ok" {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Upstream"); got != "yes" {
		t.Fatalf("X-Upstream = %q", got)
	}
	if upstream.last == nil {
		t.Fatal("upstream not reached")
	}
	if got := upstream.last.Header.Get("Cookie"); got != "injected-cookie-value" {
		t.Fatalf("forwarded Cookie = %q, want injected value only", got)
	}
	if got := upstream.last.Header.Get("Proxy-Authorization"); got != "" {
		t.Fatalf("Proxy-Authorization forwarded: %q", got)
	}
	if got := upstream.last.Header.Get("X-Custom"); got != "keep-me" {
		t.Fatalf("X-Custom = %q", got)
	}
	if upstream.last.URL.String() != "http://example.invalid/path?q=1" {
		t.Fatalf("forwarded URL = %s", upstream.last.URL)
	}
}

func TestEgressProxyCredentialsAreEphemeralAndLoopback(t *testing.T) {
	upstream := &recordingRoundTripper{}
	a, err := pluginhost.NewEgressProxy(upstream, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := pluginhost.NewEgressProxy(upstream, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if a.Username() == "" || a.Password() == "" || b.Username() == "" || b.Password() == "" {
		t.Fatal("ephemeral credentials must be non-empty")
	}
	if a.Username() == b.Username() || a.Password() == b.Password() {
		t.Fatal("two proxies must not share credentials")
	}
	for _, p := range []*pluginhost.EgressProxy{a, b} {
		if !strings.HasPrefix(p.URL().Host, "127.0.0.1:") {
			t.Fatalf("proxy URL = %s, want loopback", p.URL())
		}
		if p.URL().Scheme != "http" {
			t.Fatalf("proxy scheme = %s, want http", p.URL().Scheme)
		}
	}
}

func TestEgressProxyConnectWithoutDialer(t *testing.T) {
	upstream := &recordingRoundTripper{}
	proxy, err := pluginhost.NewEgressProxy(upstream, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	conn, err := net.Dial("tcp", proxy.URL().Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT example.invalid:443 HTTP/1.1\r\nProxy-Authorization: %s\r\nHost: example.invalid:443\r\n\r\n", proxyAuth(t, proxy.Username(), proxy.Password()))
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "502") {
		t.Fatalf("CONNECT status line = %q, want 502 without a dialer", line)
	}
}

func TestEgressProxyConnectTunnels(t *testing.T) {
	upstream := &recordingRoundTripper{}
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "example.invalid:443" {
			return nil, fmt.Errorf("unexpected dial addr %s", addr)
		}
		return serverSide, nil
	}
	proxy, err := pluginhost.NewEgressProxy(upstream, dial, "")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	conn, err := net.Dial("tcp", proxy.URL().Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT example.invalid:443 HTTP/1.1\r\nProxy-Authorization: %s\r\nHost: example.invalid:443\r\n\r\n", proxyAuth(t, proxy.Username(), proxy.Password()))
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT status line = %q, want 200", line)
	}
	// Drain headers, then verify bytes flow both ways.
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" {
			break
		}
	}
	// The handler copies client->target itself (via the
	// hijacked bufio); the test must NOT also read from the
	// same conn or the two readers race for tunnel bytes.
	// Only the pipe echo side runs here.
	go func() {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(clientSide, buf); err == nil {
			_, _ = clientSide.Write([]byte("pong!"))
		}
	}()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "pong!" {
		t.Fatalf("tunnel reply = %q, want pong!", got)
	}
}

func TestEgressProxyCloseRefuses(t *testing.T) {
	upstream := &recordingRoundTripper{}
	proxy, err := pluginhost.NewEgressProxy(upstream, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	addr := proxy.URL().Host
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", addr)
	if err == nil {
		_ = conn.Close()
		t.Fatal("dial after Close succeeded, want refused")
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("dial err = %v, want OpError", err)
	}
}
