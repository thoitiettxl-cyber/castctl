// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The S2 loopback proxy: the minimal inbound that lets a
// castctl-launched browser's egress go through a profile's
// outbound (Boss decision G3, option B; AGENTS.md rule 2:
// all network traffic of a profile goes through that
// profile's outbound).
//
// It is a loopback-only HTTP proxy, stdlib only:
//
//   - CONNECT host:port: dial through the Dialer, reply 200,
//     then copy bytes both ways (the TLS handshake and HTTP/2
//     inside the tunnel are the browser's and the origin's
//     business; the proxy never inspects them).
//   - Absolute-form HTTP requests (http://host[:port]/path):
//     dial through the Dialer, rewrite to origin form, forward
//     headers and a bounded body, copy the response back.
//     The upstream leg uses Connection: close, so no
//     keep-alive state is kept.
//
// It NEVER dials directly, NEVER resolves via the system
// resolver, and NEVER logs a URL, header, or body byte: a
// request line may carry credentials in a query string, and
// the proxy is not a place that records traffic. Errors are
// fixed strings. The listener binds 127.0.0.1 only; cleanup
// closes the listener and every open connection.

// proxyDialTimeout bounds one upstream dial through the
// outbound. Chrome's own timeouts bound the rest; the proxy
// adds no read/write deadlines (a slow page load must not be
// killed by the proxy).
const proxyDialTimeout = 30 * time.Second

// maxProxyHeaderBytes bounds one request's header block
// (request line + headers). Chrome's proxy requests are
// small; a hostile local client cannot grow memory through
// the proxy.
const maxProxyHeaderBytes = 64 << 10

// maxProxyBodyBytes bounds a forwarded plain-HTTP request
// body (login forms are small; a file upload through the
// proxy is not a castctl use case).
const maxProxyBodyBytes = 16 << 20

// LoopbackProxy is a running S2 proxy. Close is idempotent.
type LoopbackProxy struct {
	listener net.Listener
	dialer   *Dialer

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closed  bool
	done    chan struct{}
	serveWG sync.WaitGroup
}

// NewLoopbackProxy starts a loopback HTTP proxy whose upstream
// dials go through dialer. It returns the proxy URL to hand
// to Chrome (--proxy-server) and a cleanup function. A nil
// dialer fails closed before listening.
func NewLoopbackProxy(dialer *Dialer) (*LoopbackProxy, string, error) {
	if dialer == nil {
		return nil, "", errors.New("outbound: loopback proxy requires a dialer")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("outbound: loopback proxy listen: %w", err)
	}
	p := &LoopbackProxy{
		listener: ln,
		dialer:   dialer,
		conns:    map[net.Conn]struct{}{},
		done:     make(chan struct{}),
	}
	p.serveWG.Add(1)
	go p.serve()
	addr := ln.Addr().(*net.TCPAddr)
	return p, fmt.Sprintf("http://127.0.0.1:%d", addr.Port), nil
}

// ProxyURL returns the proxy URL for --proxy-server.
func (p *LoopbackProxy) ProxyURL() string {
	addr := p.listener.Addr().(*net.TCPAddr)
	return fmt.Sprintf("http://127.0.0.1:%d", addr.Port)
}

// Close stops accepting and closes every open connection.
// It is idempotent and safe to call concurrently with Serve
// activity.
func (p *LoopbackProxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.done)
	for c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
	_ = p.listener.Close()
	p.serveWG.Wait()
	return nil
}

func (p *LoopbackProxy) serve() {
	defer p.serveWG.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			_ = conn.Close()
			return
		}
		p.conns[conn] = struct{}{}
		p.mu.Unlock()
		p.serveWG.Add(1)
		go func() {
			defer p.serveWG.Done()
			defer p.forget(conn)
			defer conn.Close()
			_ = p.handle(conn)
		}()
	}
}

func (p *LoopbackProxy) forget(conn net.Conn) {
	p.mu.Lock()
	delete(p.conns, conn)
	p.mu.Unlock()
}

func (p *LoopbackProxy) trackUpstream(conn net.Conn) func() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.Close()
		return func() {}
	}
	p.conns[conn] = struct{}{}
	p.mu.Unlock()
	return func() { p.forget(conn) }
}

// handle serves one client connection: exactly one request
// (Connection: close semantics on both legs), then return.
// Chrome opens a fresh proxy connection per request stream
// when the proxy closes, which is correct, if slower than
// keep-alive — and keeps the proxy stateless.
func (p *LoopbackProxy) handle(client net.Conn) error {
	br := bufio.NewReaderSize(client, 4096)
	method, target, headers, err := readProxyRequest(br)
	if err != nil {
		return err
	}
	switch method {
	case "CONNECT":
		return p.handleConnect(client, br, target, headers)
	default:
		return p.handleHTTP(client, br, method, target, headers)
	}
}

type proxyHeader struct {
	key, value string
}

// readProxyRequest reads one request line + headers. It
// returns the method, request target, and headers in order.
// The body is left unread in br for the caller.
func readProxyRequest(br *bufio.Reader) (string, string, []proxyHeader, error) {
	line, err := readHeaderLine(br, maxProxyHeaderBytes)
	if err != nil {
		return "", "", nil, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return "", "", nil, errors.New("outbound: proxy: malformed request line")
	}
	method, target := parts[0], parts[1]
	if method == "" || target == "" {
		return "", "", nil, errors.New("outbound: proxy: malformed request line")
	}
	var headers []proxyHeader
	total := len(line)
	for {
		hline, err := readHeaderLine(br, maxProxyHeaderBytes)
		if err != nil {
			return "", "", nil, err
		}
		total += len(hline)
		if total > maxProxyHeaderBytes {
			return "", "", nil, errors.New("outbound: proxy: header block too large")
		}
		if hline == "" {
			break
		}
		k, v, ok := strings.Cut(hline, ":")
		if !ok {
			return "", "", nil, errors.New("outbound: proxy: malformed header")
		}
		headers = append(headers, proxyHeader{key: strings.TrimSpace(k), value: strings.TrimSpace(v)})
	}
	return method, target, headers, nil
}

// readHeaderLine reads one CRLF/LF-terminated line without
// the terminator, bounded by limit bytes including the
// terminator.
func readHeaderLine(br *bufio.Reader, limit int) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		// A line without its terminator (EOF mid-line) is
		// not a line: refuse it rather than serving a
		// truncated request.
		return "", errors.New("outbound: proxy: request read failed")
	}
	if len(line) > limit {
		return "", errors.New("outbound: proxy: header line too long")
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

func headerValue(headers []proxyHeader, key string) (string, bool) {
	for _, h := range headers {
		if strings.EqualFold(h.key, key) {
			return h.value, true
		}
	}
	return "", false
}

// handleConnect serves a CONNECT tunnel.
func (p *LoopbackProxy) handleConnect(client net.Conn, br *bufio.Reader, target string, headers []proxyHeader) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return p.proxyError(client, 400)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || host == "" {
		return p.proxyError(client, 400)
	}
	ctx, cancel := context.WithTimeout(context.Background(), proxyDialTimeout)
	defer cancel()
	up, err := p.dialer.DialContext(ctx, "tcp", host, uint16(port))
	if err != nil {
		return p.proxyError(client, 502)
	}
	defer p.trackUpstream(up)()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\nProxy-Connection: close\r\n\r\n"); err != nil {
		return err
	}
	// Any bytes already buffered past the header block belong
	// to the tunnel (pipelined TLS ClientHello): forward
	// exactly the buffered bytes first — never io.Copy on
	// the reader, which would block waiting for EOF.
	if n := br.Buffered(); n > 0 {
		if _, err := io.CopyN(up, br, int64(n)); err != nil {
			return err
		}
	}
	return p.pipe(client, up)
}

// handleHTTP serves an absolute-form plain HTTP request.
func (p *LoopbackProxy) handleHTTP(client net.Conn, br *bufio.Reader, method, target string, headers []proxyHeader) error {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" || (u.Scheme != "" && u.Scheme != "http") {
		return p.proxyError(client, 400)
	}
	host := u.Hostname()
	portStr := u.Port()
	port := 80
	if portStr != "" {
		pn, err := strconv.Atoi(portStr)
		if err != nil || pn < 1 || pn > 65535 {
			return p.proxyError(client, 400)
		}
		port = pn
	}
	if host == "" {
		return p.proxyError(client, 400)
	}
	ctx, cancel := context.WithTimeout(context.Background(), proxyDialTimeout)
	defer cancel()
	up, err := p.dialer.DialContext(ctx, "tcp", host, uint16(port))
	if err != nil {
		return p.proxyError(client, 502)
	}
	defer p.trackUpstream(up)()
	// Rebuild the request in origin form. Hop-by-hop and
	// proxy headers never cross: Connection,
	// Proxy-Connection, Proxy-Authorization, Keep-Alive, TE,
	// Trailer, and any header named by Connection. The
	// upstream leg is Connection: close.
	origin := u.RequestURI()
	var sb strings.Builder
	sb.WriteString(method + " " + origin + " HTTP/1.1\r\n")
	sb.WriteString("Host: " + u.Host + "\r\n")
	skip := map[string]bool{
		"connection": true, "proxy-connection": true,
		"proxy-authorization": true, "keep-alive": true,
		"te": true, "trailer": true, "transfer-encoding": true,
		"host": true,
	}
	if connVal, ok := headerValue(headers, "Connection"); ok {
		for _, tok := range strings.Split(connVal, ",") {
			skip[strings.ToLower(strings.TrimSpace(tok))] = true
		}
	}
	contentLength := 0
	for _, h := range headers {
		lk := strings.ToLower(h.key)
		if skip[lk] {
			continue
		}
		if lk == "content-length" {
			n, err := strconv.Atoi(strings.TrimSpace(h.value))
			if err != nil || n < 0 || n > maxProxyBodyBytes {
				return p.proxyError(client, 400)
			}
			contentLength = n
		}
		sb.WriteString(h.key + ": " + h.value + "\r\n")
	}
	sb.WriteString("Connection: close\r\n\r\n")
	if _, err := io.WriteString(up, sb.String()); err != nil {
		return err
	}
	if contentLength > 0 {
		if _, err := io.CopyN(up, br, int64(contentLength)); err != nil {
			return err
		}
	}
	// Response: copy until the upstream closes (Connection:
	// close was requested). No parsing, no logging.
	_, err = io.Copy(client, up)
	return err
}

// proxyError writes a fixed, body-free error response. No
// detail: the cause (dial failure, bad target) must not leak
// upstream behaviour to the browser beyond the status.
func (p *LoopbackProxy) proxyError(client net.Conn, status int) error {
	reason := "Bad Gateway"
	if status == 400 {
		reason = "Bad Request"
	}
	_, err := fmt.Fprintf(client, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, reason)
	return err
}

// pipe copies both directions until one side ends, then
// closes the write side of the other via full close (both
// conns are closed by their owners; half-close is unnecessary
// for a CONNECT tunnel whose peers close after their last
// byte).
func (p *LoopbackProxy) pipe(a, b net.Conn) error {
	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(a, b); errCh <- err }()
	go func() { _, err := io.Copy(b, a); errCh <- err }()
	<-errCh
	return nil
}
