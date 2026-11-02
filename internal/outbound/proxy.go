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
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
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
// fixed strings, except the guard refusal (403), which is
// also a fixed string. The listener binds 127.0.0.1 only;
// cleanup closes the listener and every open connection.
// (This file logs nothing at all except a refused target's
// HOST, via the OnRefused callback when one is configured;
// the Dialer it dials through may emit debug-level dial
// metadata — network, bare host via SafeHost, port, no
// URLs/headers/values — see internal/outbound/dialer.go.
// The no-logging claim here is scoped to this file's code.)
//
// GUARD. Before dialling, every target is gated (Boss
// decision S8): the host must be on the configured
// allowlist (ProxyOptions.AllowedHosts, exact match on the
// lowercased host), and a literal IP in a loopback,
// link-local, private, CGNAT, unspecified, or multicast
// range is refused even if it is listed — an allowlist
// entry naming such an address does not permit it; list
// the hostname instead (resolution happens at the egress,
// where a listed hostname may legitimately resolve to a
// private address, e.g. through a VPN outbound). The range
// rule recognises canonical literals, trailing dots in any
// number, and inet_aton-style shorthand (see
// refusedIPLiteral); other spellings match exactly as
// hostnames. A refused
// target gets a fixed 403 and no dial is spent. Hostnames
// are never resolved locally to apply the range check: the
// range refusal applies to literal IP targets only.

// ProxyOptions configures one S2 loopback proxy. Every
// field is required: NewLoopbackProxy fails closed on a
// zero value, so no proxy ever runs on hidden defaults.
// Production callers build these from the keeper entry's
// Effective* accessors (internal/profile), whose zero
// values are the documented S10 defaults. Tests build them
// explicitly.
type ProxyOptions struct {
	// DialTimeout bounds one upstream dial through the
	// outbound. Chrome's own timeouts bound the rest; the
	// proxy adds no read/write deadlines (a slow page load
	// must not be killed by the proxy).
	DialTimeout time.Duration
	// MaxHeaderBytes bounds one request's header block
	// (request line + headers). A hostile local client
	// cannot grow memory through the proxy.
	MaxHeaderBytes int
	// MaxBodyBytes bounds a forwarded plain-HTTP request
	// body (login forms are small; a file upload through
	// the proxy is not a castctl use case).
	MaxBodyBytes int
	// AllowedHosts is the guard allowlist: the only hosts
	// the proxy dials, matched exactly on the lowercased
	// host (trailing dots ignored). Entries are
	// hostnames or IPv4 literals: no scheme, port,
	// userinfo, path, query, wildcard, or IPv6 literal.
	// At least one entry is required.
	AllowedHosts []string
	// OnRefused, when non-nil, is called with the refused
	// HOST ONLY (no URL, query, port, or headers) when
	// the guard refuses a target. It runs on the
	// connection handler goroutine and must not block.
	// When nil, refusals are answered 403 and not logged.
	OnRefused func(host string)
}

// normalizeGuardHost returns a host's match form:
// lowercased, all trailing dots removed. Every
// normalisation pass in the guard and the config parse
// strips ALL trailing dots (D12): stripping one per pass
// lets a multi-dot literal survive as a distinct match
// form the range check cannot parse.
func normalizeGuardHost(host string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
}

// validateGuardHost reports whether s is a usable
// allowlist entry: non-empty, no scheme/port/userinfo/
// path/query/fragment/wildcard/bracket/whitespace/control
// characters.
func validateGuardHost(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r == '/' || r == ':' || r == '@' || r == '?' || r == '#' || r == '[' || r == ']' || r == '*' || unicode.IsSpace(r) || unicode.IsControl(r):
			return false
		}
	}
	return true
}

// connectHostOK reports whether host is a bare host as a
// CONNECT authority or URL host may carry it: no scheme,
// path, query, fragment, userinfo, whitespace, or control
// characters. A zone suffix ("%eth0") and ':' (IPv6
// literals, brackets already stripped by the caller) are
// allowed: they are host syntax, not smuggled content.
func connectHostOK(host string) bool {
	if strings.ContainsAny(host, "/?#@") {
		return false
	}
	return strings.IndexFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) < 0
}

// cgnatPrefix is the shared-address (CGNAT) range,
// refused like the private ranges: a browser must not
// reach it as a literal target through the proxy.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// parseIPLiteral parses a literal IP address: a canonical
// literal accepted by netip.ParseAddr, or an inet_aton-style
// IPv4 shorthand (1-4 dot-separated parts, each decimal,
// octal with a leading 0, or hexadecimal with a 0x prefix).
// Anything else is not an IP literal here: it falls through
// to exact allowlist matching.
func parseIPLiteral(host string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, true
	}
	return parseIPv4Shorthand(host)
}

// parseIPv4Shorthand parses an inet_aton-style IPv4 literal:
// 1-4 parts whose values compose big-endian (a, a.b, a.b.c,
// a.b.c.d). A part with a digit invalid for its base, an
// empty part, more than four parts, or a value out of range
// for its position is not an address.
func parseIPv4Shorthand(host string) (netip.Addr, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		v, ok := parseInetAtonPart(p)
		if !ok {
			return netip.Addr{}, false
		}
		vals[i] = v
	}
	var ip uint32
	switch len(vals) {
	case 1:
		if vals[0] > 0xFFFFFFFF {
			return netip.Addr{}, false
		}
		ip = uint32(vals[0])
	case 2:
		if vals[0] > 0xFF || vals[1] > 0xFFFFFF {
			return netip.Addr{}, false
		}
		ip = uint32(vals[0])<<24 | uint32(vals[1])
	case 3:
		if vals[0] > 0xFF || vals[1] > 0xFF || vals[2] > 0xFFFF {
			return netip.Addr{}, false
		}
		ip = uint32(vals[0])<<24 | uint32(vals[1])<<16 | uint32(vals[2])
	case 4:
		for _, v := range vals {
			if v > 0xFF {
				return netip.Addr{}, false
			}
		}
		ip = uint32(vals[0])<<24 | uint32(vals[1])<<16 | uint32(vals[2])<<8 | uint32(vals[3])
	}
	return netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}), true
}

// parseInetAtonPart parses one inet_aton number: a 0x/0X
// prefix means hexadecimal, a leading 0 with more digits
// means octal, otherwise decimal. No sign, no underscores,
// no binary prefix: anything else is not a number here.
func parseInetAtonPart(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	digits := s
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		base, digits = 16, s[2:]
		if digits == "" {
			return 0, false
		}
	} else if len(s) > 1 && s[0] == '0' {
		base, digits = 8, s[1:]
	}
	var v uint64
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		var d uint64
		switch {
		case '0' <= c && c <= '9':
			d = uint64(c - '0')
		case base == 16 && 'a' <= c && c <= 'f':
			d = uint64(c-'a') + 10
		case base == 16 && 'A' <= c && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, false
		}
		if d >= uint64(base) {
			return 0, false
		}
		v = v*uint64(base) + d
		if v > 0xFFFFFFFF {
			return 0, false
		}
	}
	return v, true
}

// refusedIPLiteral reports whether host is a literal IP
// address in a range the guard never dials: loopback,
// link-local (unicast and multicast), private (RFC 1918 /
// ULA), CGNAT, unspecified, or multicast. A zone suffix
// ("fe80::1%eth0") is stripped before parsing. A hostname
// never refuses here: hostnames are gated by the allowlist
// only, and resolution happens at the egress.
//
// The range check canonicalises the literal before parsing
// (D12): all trailing dots are stripped, and inet_aton-style
// shorthand (127.1, 0x7f.0.0.1, 0177.0.0.1, 2130706433) is
// parsed to its canonical address, so no recognised spelling
// of a refused-range address can pass the range check and
// match a listing of another spelling. The recognised set
// is exactly: canonical literals, any number of trailing
// dots, and strict inet_aton shorthand (see parseIPLiteral).
// A spelling outside that set is matched exactly as a
// hostname; whether any egress resolver interprets such a
// form (e.g. a part with digits invalid for its implied
// base, like 08 as octal) as an address is unmeasured.
func refusedIPLiteral(host string) bool {
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimRight(strings.TrimSpace(host), ".")
	addr, ok := parseIPLiteral(host)
	if !ok {
		return false
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsPrivate() || addr.IsUnspecified() || addr.IsMulticast() {
		return true
	}
	return cgnatPrefix.Contains(addr)
}

// LoopbackProxy is a running S2 proxy. Close is idempotent.
type LoopbackProxy struct {
	listener net.Listener
	dialer   *Dialer
	opts     ProxyOptions
	allowed  map[string]struct{}

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closed  bool
	done    chan struct{}
	serveWG sync.WaitGroup
}

// NewLoopbackProxy starts a loopback HTTP proxy whose upstream
// dials go through dialer, gated by opts. It returns the proxy
// URL to hand to Chrome (--proxy-server) and a cleanup
// function. A nil dialer, a zero dial timeout or cap, or an
// empty/invalid allowlist fails closed before listening.
func NewLoopbackProxy(dialer *Dialer, opts ProxyOptions) (*LoopbackProxy, string, error) {
	if dialer == nil {
		return nil, "", errors.New("outbound: loopback proxy requires a dialer")
	}
	if opts.DialTimeout <= 0 {
		return nil, "", errors.New("outbound: loopback proxy requires a positive dial timeout")
	}
	if opts.MaxHeaderBytes <= 0 || opts.MaxBodyBytes <= 0 {
		return nil, "", errors.New("outbound: loopback proxy requires positive header/body caps")
	}
	if len(opts.AllowedHosts) == 0 {
		return nil, "", errors.New("outbound: loopback proxy requires a non-empty host allowlist")
	}
	allowed := make(map[string]struct{}, len(opts.AllowedHosts))
	for _, h := range opts.AllowedHosts {
		norm := normalizeGuardHost(h)
		if !validateGuardHost(norm) {
			return nil, "", fmt.Errorf("outbound: loopback proxy: invalid allowlist host %q", h)
		}
		allowed[norm] = struct{}{}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("outbound: loopback proxy listen: %w", err)
	}
	p := &LoopbackProxy{
		listener: ln,
		dialer:   dialer,
		opts:     opts,
		allowed:  allowed,
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

// targetRefused reports whether host must not be dialled:
// a literal IP in a refused range is refused outright, and
// any host not on the allowlist is refused. Only an
// allowlisted hostname (or a listed public IP literal) is
// dialled.
func (p *LoopbackProxy) targetRefused(host string) bool {
	if refusedIPLiteral(host) {
		return true
	}
	_, ok := p.allowed[normalizeGuardHost(host)]
	return !ok
}

// logRefused reports a refused target's host ONLY to the
// configured callback: no URL, query, port, or headers.
// The logged host is the normalized match form, truncated
// to DNS-name length. Defence in depth for the HOST ONLY
// contract: trailing query/fragment/path junk is cut, a
// userinfo/whitespace/control shape is not logged at all,
// and truncation never splits a multi-byte rune (S22) —
// so no malformed-authority content can reach the callback
// even if a caller forgets to validate the host first.
func (p *LoopbackProxy) logRefused(host string) {
	if p.opts.OnRefused == nil {
		return
	}
	h := normalizeGuardHost(host)
	if i := strings.IndexAny(h, "?#/"); i >= 0 {
		h = h[:i]
	}
	if !connectHostOK(h) {
		return
	}
	if len(h) > 253 {
		h = h[:253]
		for len(h) > 0 && !utf8.ValidString(h) {
			h = h[:len(h)-1]
		}
	}
	p.opts.OnRefused(h)
}

// refuseTarget answers a fixed 403 for a guard-refused
// target and logs its host only. No dial is spent.
func (p *LoopbackProxy) refuseTarget(client net.Conn, host string) error {
	p.logRefused(host)
	return p.proxyError(client, 403)
}

// handle serves one client connection: exactly one request
// (Connection: close semantics on both legs), then return.
// Chrome opens a fresh proxy connection per request stream
// when the proxy closes, which is correct, if slower than
// keep-alive — and keeps the proxy stateless.
func (p *LoopbackProxy) handle(client net.Conn) error {
	br := bufio.NewReaderSize(client, 4096)
	method, target, headers, err := readProxyRequest(br, p.opts.MaxHeaderBytes)
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
// The body is left unread in br for the caller. limit bounds
// the header block.
func readProxyRequest(br *bufio.Reader, limit int) (string, string, []proxyHeader, error) {
	line, err := readHeaderLine(br, limit)
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
		hline, err := readHeaderLine(br, limit)
		if err != nil {
			return "", "", nil, err
		}
		total += len(hline)
		if total > limit {
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
	// A CONNECT authority is host:port only. A host carrying
	// a query, fragment, path, or userinfo is malformed:
	// reject it (400) BEFORE the guard, so no query/fragment
	// content can reach the refusal log (R-12).
	if !connectHostOK(host) {
		return p.proxyError(client, 400)
	}
	if p.targetRefused(host) {
		return p.refuseTarget(client, host)
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.opts.DialTimeout)
	defer cancel()
	up, err := p.dialer.DialContext(ctx, "tcp", host, uint16(port))
	if err != nil {
		return p.proxyError(client, 502)
	}
	defer p.trackUpstream(up)()
	// The tunnel owns the upstream socket: closing it here
	// (and in pipe) is what reclaims it. The deferred
	// trackUpstream forget runs after this close (LIFO) and
	// only drops the set entry.
	defer up.Close()
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
	if p.targetRefused(host) {
		return p.refuseTarget(client, host)
	}
	// Body plan, decided (and the body read) BEFORE the
	// outbound dial: a malformed body framing must be
	// refused without spending a dial on it. At most one
	// of Content-Length / chunked Transfer-Encoding (both
	// together is a smuggling shape: refuse), duplicate
	// Content-Length values must agree (differing values:
	// refuse), any other Transfer-Encoding is refused. A
	// chunked body is decoded fully (bounded) before
	// forwarding, so the upstream request carries one
	// Content-Length and no Transfer-Encoding.
	contentLength := -1 // -1: no body framing present
	chunked := false
	for _, h := range headers {
		switch strings.ToLower(h.key) {
		case "content-length":
			n, err := strconv.Atoi(strings.TrimSpace(h.value))
			if err != nil || n < 0 || n > p.opts.MaxBodyBytes {
				return p.proxyError(client, 400)
			}
			if contentLength >= 0 && contentLength != n {
				return p.proxyError(client, 400)
			}
			contentLength = n
		case "transfer-encoding":
			if chunked || strings.ToLower(strings.TrimSpace(h.value)) != "chunked" {
				return p.proxyError(client, 400)
			}
			chunked = true
		}
	}
	if chunked && contentLength >= 0 {
		return p.proxyError(client, 400)
	}
	var decodedBody []byte
	if chunked {
		decodedBody, err = readChunkedBody(br, p.opts.MaxBodyBytes, p.opts.MaxHeaderBytes)
		if err != nil {
			return p.proxyError(client, 400)
		}
		contentLength = len(decodedBody)
	}
	// Dial only after the body framing was validated (and a
	// chunked body fully read): malformed requests never
	// spend an outbound dial.
	ctx, cancel := context.WithTimeout(context.Background(), p.opts.DialTimeout)
	defer cancel()
	up, err := p.dialer.DialContext(ctx, "tcp", host, uint16(port))
	if err != nil {
		return p.proxyError(client, 502)
	}
	defer p.trackUpstream(up)()
	defer up.Close()
	// Rebuild the request in origin form. Hop-by-hop and
	// proxy headers never cross: Connection,
	// Proxy-Connection, Proxy-Authorization, Keep-Alive, TE,
	// Trailer, and any header named by Connection. The
	// upstream leg is Connection: close. Content-Length is
	// rewritten as a single header (the agreed value, or the
	// decoded chunked length); Transfer-Encoding never
	// crosses (chunked bodies are de-chunked above).
	origin := u.RequestURI()
	var sb strings.Builder
	sb.WriteString(method + " " + origin + " HTTP/1.1\r\n")
	sb.WriteString("Host: " + u.Host + "\r\n")
	skip := map[string]bool{
		"connection": true, "proxy-connection": true,
		"proxy-authorization": true, "keep-alive": true,
		"te": true, "trailer": true, "transfer-encoding": true,
		"host": true, "content-length": true,
	}
	if connVal, ok := headerValue(headers, "Connection"); ok {
		for _, tok := range strings.Split(connVal, ",") {
			skip[strings.ToLower(strings.TrimSpace(tok))] = true
		}
	}
	for _, h := range headers {
		lk := strings.ToLower(h.key)
		if skip[lk] {
			continue
		}
		sb.WriteString(h.key + ": " + h.value + "\r\n")
	}
	if contentLength >= 0 {
		sb.WriteString("Content-Length: " + strconv.Itoa(contentLength) + "\r\n")
	}
	sb.WriteString("Connection: close\r\n\r\n")
	if _, err := io.WriteString(up, sb.String()); err != nil {
		return err
	}
	if chunked {
		if _, err := up.Write(decodedBody); err != nil {
			return err
		}
	} else if contentLength > 0 {
		if _, err := io.CopyN(up, br, int64(contentLength)); err != nil {
			return err
		}
	}
	// Response: copy until the upstream closes (Connection:
	// close was requested). No parsing, no logging.
	_, err = io.Copy(client, up)
	return err
}

// readChunkedBody decodes one chunked request body from br,
// bounded by limit total bytes. Chunk extensions are ignored;
// trailers are read and discarded. Any malformed framing or
// over-limit body is an error (the caller answers 400).
func readChunkedBody(br *bufio.Reader, limit int, headerLimit int) ([]byte, error) {
	var out []byte
	for {
		line, err := readHeaderLine(br, headerLimit)
		if err != nil {
			return nil, err
		}
		sizeStr := line
		if i := strings.IndexByte(sizeStr, ';'); i >= 0 {
			sizeStr = sizeStr[:i]
		}
		size, err := strconv.ParseUint(strings.TrimSpace(sizeStr), 16, 63)
		if err != nil {
			return nil, errors.New("outbound: proxy: malformed chunk size")
		}
		if size == 0 {
			for {
				trailer, err := readHeaderLine(br, headerLimit)
				if err != nil {
					return nil, err
				}
				if trailer == "" {
					return out, nil
				}
			}
		}
		if size > uint64(limit-len(out)) {
			return nil, errors.New("outbound: proxy: chunked body too large")
		}
		chunk := make([]byte, size)
		if _, err := io.ReadFull(br, chunk); err != nil {
			return nil, errors.New("outbound: proxy: truncated chunked body")
		}
		out = append(out, chunk...)
		end, err := readHeaderLine(br, headerLimit)
		if err != nil {
			return nil, err
		}
		if end != "" {
			return nil, errors.New("outbound: proxy: malformed chunk ending")
		}
	}
}

// proxyError writes a fixed, body-free error response. No
// detail: the cause (dial failure, bad target, guard
// refusal) must not leak upstream behaviour to the browser
// beyond the status. A guard refusal is 403, not 502: the
// target was refused by policy, not unreachable.
func (p *LoopbackProxy) proxyError(client net.Conn, status int) error {
	reason := "Bad Gateway"
	switch status {
	case 400:
		reason = "Bad Request"
	case 403:
		reason = "Forbidden"
	}
	_, err := fmt.Fprintf(client, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, reason)
	return err
}

// pipe copies both directions until one side ends, then
// closes BOTH connections: the first direction to end
// unblocks the other copy, and closing here is what
// reclaims the upstream socket — neither the serve loop
// (which closes only the client side) nor the deferred
// trackUpstream forget (which only drops the set entry)
// closes it. Closing a conn its owner also closes is safe.
func (p *LoopbackProxy) pipe(a, b net.Conn) error {
	defer a.Close()
	defer b.Close()
	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(a, b); errCh <- err }()
	go func() { _, err := io.Copy(b, a); errCh <- err }()
	<-errCh
	return nil
}
