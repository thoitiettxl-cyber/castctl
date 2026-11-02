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
	"time"

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
	proxy.SetCookieHosts([]string{"example.invalid"})
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

// TestEgressProxyCloseAbortsTunnels: Close refuses new
// connections AND aborts in-flight CONNECT tunnels by
// closing their connections (revocation is not
// new-connections-only).
func TestEgressProxyCloseAbortsTunnels(t *testing.T) {
	upstream := &recordingRoundTripper{}
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return serverSide, nil
	}
	proxy, err := pluginhost.NewEgressProxy(upstream, dial, "")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", proxy.URL().Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT example.invalid:443 HTTP/1.1\r\nProxy-Authorization: %s\r\nHost: example.invalid:443\r\n\r\n", proxyAuth(t, proxy.Username(), proxy.Password()))
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		t.Fatalf("CONNECT status = %q, err = %v", line, err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" {
			break
		}
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	// The tunnel must abort PROMPTLY on Close (connection
	// closed), not merely time out on the read deadline.
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = br.Read(buf)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("tunnel read after Close succeeded, want EOF/closed")
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("tunnel read after Close took %s (err %v): Close did not abort the tunnel", elapsed, err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("tunnel read after Close timed out (%s): Close did not abort the tunnel", elapsed)
	}
}

// TestEgressProxyCloseIgnoresDoubleClose: Close closes the
// listener explicitly AND via http.Server.Close, which
// re-closes the tracked onceCloseListener and returns the
// stored "use of closed network connection" error when the
// listener is still tracked — a race, not a failure: the
// end state (listener closed) is what Close promises. The
// loop amplifies the race window (CONNECT + immediate
// Close); Close must return nil on every iteration.
func TestEgressProxyCloseIgnoresDoubleClose(t *testing.T) {
	for i := 0; i < 10; i++ {
		upstream := &recordingRoundTripper{}
		serverSide, clientSide := net.Pipe()
		dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return serverSide, nil
		}
		proxy, err := pluginhost.NewEgressProxy(upstream, dial, "")
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.Dial("tcp", proxy.URL().Host)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "CONNECT example.invalid:443 HTTP/1.1\r\nProxy-Authorization: %s\r\nHost: example.invalid:443\r\n\r\n", proxyAuth(t, proxy.Username(), proxy.Password()))
		br := bufio.NewReader(conn)
		line, err := br.ReadString('\n')
		if err != nil || !strings.Contains(line, "200") {
			t.Fatalf("iter %d: CONNECT status = %q, err = %v", i, line, err)
		}
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if l == "\r\n" {
				break
			}
		}
		if err := proxy.Close(); err != nil {
			t.Fatalf("iter %d: Close = %v, want nil", i, err)
		}
		_ = conn.Close()
		_ = clientSide.Close()
	}
}

func TestEgressProxyCookieScope(t *testing.T) {
	upstream := &recordingRoundTripper{body: "ok"}
	proxy, err := pluginhost.NewEgressProxy(upstream, nil, "injected-cookie-value")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxy.SetCookieHosts([]string{"declared.invalid"})
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURLWithCreds(t, proxy, proxy.Username(), proxy.Password()))}}
	req, _ := http.NewRequest("GET", "http://declared.invalid/a", nil)
	req.Header.Set("Cookie", "plugin-cookie")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if got := upstream.last.Header.Get("Cookie"); got != "injected-cookie-value" {
		t.Fatalf("declared host Cookie = %q, want injected value", got)
	}
	req, _ = http.NewRequest("GET", "http://other.invalid/b", nil)
	req.Header.Set("Cookie", "plugin-cookie")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if got := upstream.last.Header.Get("Cookie"); got != "" {
		t.Fatalf("undeclared host Cookie = %q, want empty", got)
	}
	proxy.SetCookieHosts(nil)
	req, _ = http.NewRequest("GET", "http://declared.invalid/c", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if got := upstream.last.Header.Get("Cookie"); got != "" {
		t.Fatalf("no-declaration Cookie = %q, want empty", got)
	}
	proxy.SetCookieHosts([]string{"not a host", "EXAMPLE.INVALID:443", "*.invalid", "ok.invalid"})
	req, _ = http.NewRequest("GET", "http://ok.invalid/d", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if got := upstream.last.Header.Get("Cookie"); got != "injected-cookie-value" {
		t.Fatalf("valid host after invalid declarations Cookie = %q, want injected value", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestEgressProxyStripsSetCookieAndHopTokens(t *testing.T) {
	upstream := &recordingRoundTripper{body: "ok"}
	upstreamWithCookie := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := upstream.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		resp.Header.Set("Set-Cookie", "hatch_sess=SECRETVALUE; Path=/")
		resp.Header.Set("Connection", "X-Hop")
		resp.Header.Set("X-Hop", "hop-value")
		return resp, nil
	})
	proxy, err := pluginhost.NewEgressProxy(upstreamWithCookie, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURLWithCreds(t, proxy, proxy.Username(), proxy.Password()))}}
	req, _ := http.NewRequest("GET", "http://example.invalid/path", nil)
	req.Header.Set("Connection", "X-Req-Hop")
	req.Header.Set("X-Req-Hop", "must-not-forward")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if got := resp.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("Set-Cookie forwarded to plugin: %q", got)
	}
	if got := resp.Header.Get("X-Hop"); got != "" {
		t.Fatalf("hop-by-hop response header forwarded: %q", got)
	}
	if upstream.last != nil {
		if got := upstream.last.Header.Get("X-Req-Hop"); got != "" {
			t.Fatalf("hop-by-hop request token header forwarded: %q", got)
		}
		if got := upstream.last.Header.Get("Connection"); got != "" {
			t.Fatalf("Connection header forwarded: %q", got)
		}
	}
}

func TestEgressProxyConnectAddsNoCookie(t *testing.T) {
	upstream := &recordingRoundTripper{}
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return serverSide, nil
	}
	proxy, err := pluginhost.NewEgressProxy(upstream, dial, "injected-cookie-value")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxy.SetCookieHosts([]string{"example.invalid"})
	conn, err := net.Dial("tcp", proxy.URL().Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT example.invalid:443 HTTP/1.1\r\nProxy-Authorization: %s\r\nHost: example.invalid:443\r\n\r\n", proxyAuth(t, proxy.Username(), proxy.Password()))
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" {
			break
		}
	}
	payload := "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(clientSide, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != payload {
		t.Fatalf("tunnel bytes = %q, want verbatim %q", buf, payload)
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

// TestEgressProxyDuplicateConnectionHeaders: hop-by-hop
// stripping must honour tokens named in EVERY Connection
// header line, in both directions. A token-named header
// carried only by a second Connection line must not leak
// upstream (request) or to the plugin (response). Raw TCP
// on both sides: Go's client/server transports strip
// hop-by-hop headers themselves, which would mask a proxy
// stripping failure.
func TestEgressProxyDuplicateConnectionHeaders(t *testing.T) {
	upstream := &recordingRoundTripper{body: "ok"}
	upstreamDup := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := upstream.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		resp.Header.Add("Connection", "keep-alive")
		resp.Header.Add("Connection", "X-Resp-Leak")
		resp.Header.Set("X-Resp-Leak", "RESPLEAK")
		resp.Header.Set("Set-Cookie", "hatch_sess=SECRETVALUE; Path=/")
		return resp, nil
	})
	proxy, err := pluginhost.NewEgressProxy(upstreamDup, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	conn, err := net.Dial("tcp", proxy.URL().Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw := "GET http://example.invalid/path HTTP/1.1\r\n" +
		"Host: example.invalid\r\n" +
		"Proxy-Authorization: " + proxyAuth(t, proxy.Username(), proxy.Password()) + "\r\n" +
		"Connection: keep-alive\r\n" +
		"Connection: X-Leak\r\n" +
		"X-Leak: LEAKME\r\n" +
		"X-Keep: yes\r\n\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	var headLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
		headLines = append(headLines, line)
	}
	for _, line := range headLines {
		if strings.Contains(line, "X-Resp-Leak") || strings.Contains(line, "RESPLEAK") {
			t.Fatalf("response header leaked to plugin: %q (headers %q)", line, headLines)
		}
		if strings.Contains(line, "Set-Cookie") {
			t.Fatalf("Set-Cookie leaked to plugin: %q", line)
		}
	}
	if upstream.last == nil {
		t.Fatal("upstream not reached")
	}
	if got := upstream.last.Header.Get("X-Leak"); got != "" {
		t.Fatalf("X-Leak forwarded upstream: %q (second Connection line ignored)", got)
	}
	if got := upstream.last.Header.Get("X-Keep"); got != "yes" {
		t.Fatalf("X-Keep = %q, want ordinary header preserved", got)
	}
	if got := upstream.last.Header.Get("Proxy-Authorization"); got != "" {
		t.Fatalf("Proxy-Authorization forwarded: %q", got)
	}
}
