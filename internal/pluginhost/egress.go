// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
)

// EgressProxy is the per-session loopback HTTP proxy through
// which plugins reach the network (BQ5). It listens on
// 127.0.0.1 only, requires ephemeral Basic credentials that
// are generated per proxy and never equal any real proxy
// credentials, forwards absolute-form requests through a
// caller-supplied upstream RoundTripper (in real wiring, the
// core-owned client derived from the profile's outbound), and
// injects the session Cookie header inside core for declared
// hosts only, so the plugin never sees it. Proxy use by
// plugins is by CONTRACT and code review for first-party
// plugins, not an enforcement boundary: an in-process native
// plugin can still net.Dial, read the environment, or read
// process memory. The enforceable guarantees are only the
// handed surface (no secret in the request the plugin
// builds), redaction on output, and per-plugin isolation.
// CONNECT tunneling is served only when the caller supplies
// a Dial function, and returns 502 otherwise. pluginhost
// never imports internal/outbound and never builds its own
// http.Client for profile traffic; the upstream transport
// and the dial function are injected by the wiring that owns
// the profile.
type EgressProxy struct {
	listener  net.Listener
	server    *http.Server
	upstream  http.RoundTripper
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	cookie    string
	username  string
	password  string
	url       *url.URL
	closeOnce sync.Once
	// cookieHosts is the set of hostnames the session
	// cookie may be injected for, declared by the plugin
	// in its registration (cookie_hosts). Empty means NO
	// injection for any host (fail-closed). Guarded by
	// cookieMu: registration updates it while requests
	// read it.
	cookieMu    sync.RWMutex
	cookieHosts map[string]bool
	// tunnels tracks live CONNECT tunnel connections so
	// Close can abort them. Guarded by tunnelMu; closed
	// is set under tunnelMu before the snapshot in Close,
	// so a tunnel starting concurrently with Close is
	// closed immediately instead of surviving revocation.
	tunnelMu sync.Mutex
	tunnels  map[net.Conn]struct{}
	closed   bool
}

// NewEgressProxy starts a loopback proxy. upstream must not
// be nil. cookie is injected as the Cookie header ONLY for
// hosts declared via SetCookieHosts; with no declaration
// nothing is injected. An empty cookie injects nothing.
// Credentials live exactly as long as the proxy instance:
// Close revokes them, and there is no rotation in v1.
//
// Timeouts: only ReadHeaderTimeout (10s) and IdleTimeout
// (120s) are set, deliberately. A Read/Write timeout would
// abort slow-but-legitimate streaming transfers through
// the proxy (CONNECT tunnels, large forwarded bodies);
// transfer timeouts belong to the wiring-owned upstream
// transport and dial function, not to this loopback hop.
// Header + idle timeouts bound connection setup and idle
// retention instead.
func NewEgressProxy(upstream http.RoundTripper, dial func(ctx context.Context, network, addr string) (net.Conn, error), cookie string) (*EgressProxy, error) {
	if upstream == nil {
		return nil, fmt.Errorf("egress proxy requires an upstream round tripper")
	}
	username, err := randomCredential()
	if err != nil {
		return nil, err
	}
	password, err := randomCredential()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen egress proxy: %w", err)
	}
	p := &EgressProxy{
		listener:    ln,
		upstream:    upstream,
		dial:        dial,
		cookie:      cookie,
		username:    username,
		password:    password,
		url:         &url.URL{Scheme: "http", Host: ln.Addr().String()},
		cookieHosts: make(map[string]bool),
		tunnels:     make(map[net.Conn]struct{}),
	}
	p.server = &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() { _ = p.server.Serve(ln) }()
	return p, nil
}

// SetCookieHosts replaces the declared cookie hosts (the
// plugin's registration cookie_hosts). Invalid entries are
// ignored; an empty list means no injection. The host
// applies this after each registration/reconfiguration.
func (p *EgressProxy) SetCookieHosts(hosts []string) {
	next := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if pluginabi.ValidCookieHost(h) {
			next[h] = true
		}
	}
	p.cookieMu.Lock()
	p.cookieHosts = next
	p.cookieMu.Unlock()
}

func (p *EgressProxy) cookieAllowed(host string) bool {
	p.cookieMu.RLock()
	defer p.cookieMu.RUnlock()
	return p.cookieHosts[strings.ToLower(host)]
}

func randomCredential() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate egress credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// URL is the proxy URL plugins configure (loopback only).
// It returns a copy: callers must not mutate the proxy's
// own URL value.
func (p *EgressProxy) URL() *url.URL {
	u := *p.url
	return &u
}

// Username and Password are the ephemeral credentials handed
// to the plugin in its RegisterRequest egress block. They are
// valid only for this proxy instance's lifetime.
func (p *EgressProxy) Username() string { return p.username }
func (p *EgressProxy) Password() string { return p.password }

// Addr is the listener address (host:port).
func (p *EgressProxy) Addr() string { return p.listener.Addr().String() }

// Close stops the proxy. Credentials die with it. The
// listener is closed directly as well as through the
// server: http.Server.Close only closes listeners the
// Serve goroutine has already registered, so a Close
// racing Serve startup would otherwise leave the
// listener accepting (the TestEgressProxyCloseRefuses
// flake). Close also aborts in-flight CONNECT tunnels by
// closing their connections: http.Server.Close does NOT
// close hijacked connections, so without tunnel tracking
// revocation would block new connections only and a live
// tunnel would keep flowing. Close does not wait for
// tunnel copy goroutines to return; closing the
// connections unblocks them promptly.
func (p *EgressProxy) Close() error {
	var err error
	p.closeOnce.Do(func() {
		_ = p.listener.Close()
		err = p.server.Close()
		// server.Close re-closes the tracked listener
		// (http.Server wraps it in onceCloseListener and
		// returns the stored close error). The listener
		// was already closed above, so "use of closed
		// network connection" is the promised end state,
		// not a failure: it must not surface as a Close
		// error (it races with the Serve goroutine
		// untracking the listener). Any other error is
		// real and is returned.
		if errors.Is(err, net.ErrClosed) {
			err = nil
		}
		p.tunnelMu.Lock()
		p.closed = true
		var conns []net.Conn
		for c := range p.tunnels {
			conns = append(conns, c)
		}
		p.tunnelMu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return err
}

// trackTunnel registers a tunnel connection for Close
// abort. It returns false when the proxy is already
// closed: the caller must close the connection itself.
func (p *EgressProxy) trackTunnel(c net.Conn) bool {
	p.tunnelMu.Lock()
	defer p.tunnelMu.Unlock()
	if p.closed {
		return false
	}
	p.tunnels[c] = struct{}{}
	return true
}

func (p *EgressProxy) untrackTunnel(c net.Conn) {
	p.tunnelMu.Lock()
	defer p.tunnelMu.Unlock()
	delete(p.tunnels, c)
}

// ServeHTTP implements the proxy protocol: Basic-auth gate,
// CONNECT tunneling, absolute-form forwarding.
func (p *EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.authorized(r) {
		w.Header().Set("Proxy-Authenticate", "Basic")
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	p.serveForward(w, r)
}

func (p *EgressProxy) authorized(r *http.Request) bool {
	// Proxy credentials arrive in Proxy-Authorization, not
	// Authorization: r.BasicAuth reads only the latter.
	raw := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(raw, "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw[len("Basic "):]))
	if err != nil {
		return false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(p.username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(p.password)) == 1
	return userOK && passOK
}

var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopByHop(h http.Header) {
	// Read the Connection tokens FIRST: deleting the
	// Connection header first would make the token list
	// unreadable and the stripping dead code. Iterate
	// EVERY Connection value: Header.Get returns only
	// the first line, so tokens named in a second (or
	// later) Connection header would otherwise survive
	// in both directions.
	var tokens []string
	for _, value := range h.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if token = strings.TrimSpace(token); token != "" {
				tokens = append(tokens, token)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
	for _, token := range tokens {
		h.Del(token)
	}
}

func (p *EgressProxy) serveForward(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "proxy requires an absolute-form request URI", http.StatusBadRequest)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	u := *r.URL
	out.URL = &u
	// URL userinfo in an absolute-form request is never
	// forwarded: credentials in the URL must not reach the
	// upstream through the proxy.
	out.URL.User = nil
	stripHopByHop(out.Header)
	// The session cookie is injected inside core ONLY for
	// declared hosts, and always wins over anything the
	// plugin sent. For every other host the plugin's
	// Cookie header is removed: an undeclared host must
	// never receive the session cookie.
	if p.cookie != "" && p.cookieAllowed(out.URL.Hostname()) {
		out.Header.Set("Cookie", p.cookie)
	} else {
		out.Header.Del("Cookie")
	}
	resp, err := p.upstream.RoundTrip(out)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	// Set-Cookie (and hop-by-hop headers) from the upstream
	// are never forwarded to the plugin: a session cookie
	// set by the upstream must not leak into plugin hands.
	stripHopByHop(resp.Header)
	resp.Header.Del("Set-Cookie")
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// serveConnect serves a raw CONNECT tunnel. The tunnel is
// OPAQUE: core neither injects the session cookie nor
// inspects anything inside the TLS stream (the plugin sets
// and reads Cookie/Set-Cookie inside TLS itself). Cookie
// scoping therefore does not apply to CONNECT traffic; the
// residual is a trusted-model limit (see docs/plugins.md).
// No body limit is applied to the tunnel (it is a byte
// stream, not a rendered document).

func (p *EgressProxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	if p.dial == nil {
		http.Error(w, "CONNECT not available", http.StatusBadGateway)
		return
	}
	target, err := p.dial(r.Context(), "tcp", r.Host)
	if err != nil {
		http.Error(w, "dial error", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = target.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, bufrw, err := hijacker.Hijack()
	if err != nil {
		_ = target.Close()
		return
	}
	_, _ = bufrw.WriteString("HTTP/1.1 200 OK\r\n\r\n")
	if err := bufrw.Flush(); err != nil {
		_ = target.Close()
		_ = clientConn.Close()
		return
	}
	// Track both tunnel ends so Close aborts the tunnel.
	// A tunnel that starts concurrently with Close sees
	// closed and is shut down immediately.
	if !p.trackTunnel(clientConn) {
		_ = target.Close()
		_ = clientConn.Close()
		return
	}
	defer p.untrackTunnel(clientConn)
	if !p.trackTunnel(target) {
		_ = target.Close()
		_ = clientConn.Close()
		return
	}
	defer p.untrackTunnel(target)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, bufrw)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, target)
		if tcp, ok := clientConn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	wg.Wait()
	_ = target.Close()
	_ = clientConn.Close()
}
