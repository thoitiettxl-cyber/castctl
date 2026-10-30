// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package dns

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
)

// Per-profile isolation, bullets 3 and 5: two stacks through
// DIFFERENT outbounds must never cross traffic, DNS must stay
// within the owning profile (and travel through its own outbound),
// the two stacks must share no cookie jar, and hostile proxy
// environment variables must change nothing. Fake in-process
// servers only; no live hosts, no secrets in fixtures.
//
// DNS isolation is proved by ANSWER VALUE, not by exact query
// counters: each stack's fake DNS server answers gateway.test with
// a different loopback address (A: 127.0.0.1, B: 127.0.0.2), so a
// lookup that leaked into the other stack's DNS would return the
// wrong address and fail. Exact "other stack's counters unchanged"
// assertions were tried first and flaked under -count=5: a stack's
// own DNS transport can land late/retried exchanges on its own
// server after its Lookup returned, moving the idle stack's
// counters without any cross-stack traffic. The answer-value proof
// plus the positive "own proxy saw a CONNECT to own DNS" proof do
// not depend on that timing.

// recordingUpstream is a loopback HTTP server recording every
// arrival: method, Host/authority, path, and the headers that
// distinguish profiles (X-Profile, Cookie).
type upstreamArrival struct {
	method    string
	host      string
	path      string
	profile   string
	cookie    string
	userAgent string
}

type recordingUpstream struct {
	name string
	srv  *httptest.Server
	port int

	mu       sync.Mutex
	arrivals []upstreamArrival
}

func startRecordingUpstream(t *testing.T, name string) *recordingUpstream {
	t.Helper()
	u := &recordingUpstream{name: name}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.arrivals = append(u.arrivals, upstreamArrival{
			method:    r.Method,
			host:      r.Host,
			path:      r.URL.Path,
			profile:   r.Header.Get("X-Profile"),
			cookie:    r.Header.Get("Cookie"),
			userAgent: r.Header.Get("User-Agent"),
		})
		u.mu.Unlock()
		_, _ = w.Write([]byte("pong-" + name))
	})
	srv := httptest.NewServer(mux)
	u.srv = srv
	u.port = srv.Listener.Addr().(*net.TCPAddr).Port
	t.Cleanup(srv.Close)
	return u
}

func (u *recordingUpstream) arrivalsSnapshot() []upstreamArrival {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]upstreamArrival, len(u.arrivals))
	copy(out, u.arrivals)
	return out
}

// answerDNSServer is a fake TCP DNS server answering gateway.test
// with one configured loopback address (A record) and empty NOERROR
// for AAAA, NXDOMAIN for everything else. Each stack gets its own
// instance with a DIFFERENT answer address, so a lookup's answer
// proves which stack's DNS served it.
type answerDNSServer struct {
	t      *testing.T
	ln     net.Listener
	addr   string
	answer net.IP

	mu      sync.Mutex
	queries int
}

func startAnswerDNSServer(t *testing.T, answer string) *answerDNSServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &answerDNSServer{t: t, ln: ln, addr: ln.Addr().String(), answer: net.ParseIP(answer)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	return s
}

func (s *answerDNSServer) handle(conn net.Conn) {
	defer conn.Close()
	for {
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		buf := make([]byte, n)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		var req mdns.Msg
		if err := req.Unpack(buf); err != nil {
			return
		}
		s.mu.Lock()
		s.queries++
		s.mu.Unlock()
		resp := new(mdns.Msg)
		resp.SetReply(&req)
		if len(req.Question) == 1 && req.Question[0].Name == "gateway.test." {
			q := req.Question[0]
			if q.Qtype == mdns.TypeA {
				rr := &mdns.A{
					Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
					A:   s.answer,
				}
				resp.Answer = []mdns.RR{rr}
			}
			// AAAA: NOERROR, no answers.
		} else {
			resp.Rcode = mdns.RcodeNameError
		}
		out, err := resp.Pack()
		if err != nil {
			return
		}
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(out)))
		if _, err := conn.Write(hdr[:]); err != nil {
			return
		}
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

func (s *answerDNSServer) queryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries
}

// recordingHTTPProxy is a minimal CONNECT proxy recording every
// CONNECT target. It forwards only 127.0.0.1 targets, mapping the
// fake-only hostname gateway.test to 127.0.0.1 itself, and never
// touches the system resolver.
type recordingHTTPProxy struct {
	ln   net.Listener
	port int

	mu       sync.Mutex
	connects int
	targets  []string
}

func startRecordingHTTPProxy(t *testing.T) *recordingHTTPProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &recordingHTTPProxy{ln: ln, port: ln.Addr().(*net.TCPAddr).Port}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(conn)
		}
	}()
	return p
}

func (p *recordingHTTPProxy) handle(conn net.Conn) {
	defer conn.Close()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil || req.Method != http.MethodConnect {
		_, _ = conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}
	p.mu.Lock()
	p.connects++
	p.targets = append(p.targets, req.Host)
	p.mu.Unlock()
	host, portStr, err := net.SplitHostPort(req.Host)
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	targetHost := host
	if host == "gateway.test" {
		targetHost = "127.0.0.1"
	}
	if targetHost != "127.0.0.1" {
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, portStr), 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer up.Close()
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	go func() { _, _ = io.Copy(up, conn); _ = up.Close() }()
	_, _ = io.Copy(conn, up)
}

func (p *recordingHTTPProxy) connectCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connects
}

func (p *recordingHTTPProxy) targetsSnapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.targets))
	copy(out, p.targets)
	return out
}

// proxyStack is one full profile stack whose egress is a dedicated
// http (CONNECT proxy) outbound and whose DNS transport detours
// through that same outbound, so DNS queries also travel through
// the owning profile's proxy.
type proxyStack struct {
	name string

	manager    *outbound.Manager
	client     *Client
	dialer     *outbound.Dialer
	httpClient *http.Client

	dnsServer *answerDNSServer
	dnsPort   int
	wantAddr  string
	proxy     *recordingHTTPProxy
	upstream  *recordingUpstream
}

func buildProxyStack(t *testing.T, name, answerIP string) *proxyStack {
	t.Helper()
	dnsServer := startAnswerDNSServer(t, answerIP)
	proxy := startRecordingHTTPProxy(t)
	upstream := startRecordingUpstream(t, name)

	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	fail := func(err error) *proxyStack {
		_ = m.Close()
		t.Fatal(err)
		return nil
	}
	var proxyOut option.Outbound
	rawProxy := fmt.Sprintf(`{"type":"http","tag":"proxy","server":"127.0.0.1","server_port":%d}`, proxy.port)
	if err := json.UnmarshalContext(m.Context(), []byte(rawProxy), &proxyOut); err != nil {
		return fail(err)
	}
	if err := m.CreateOutbound(context.Background(), proxyOut.Tag, proxyOut.Type, proxyOut.Options); err != nil {
		return fail(err)
	}
	dnsHost, dnsPortStr, err := net.SplitHostPort(dnsServer.addr)
	if err != nil {
		return fail(err)
	}
	var dnsPort int
	fmt.Sscanf(dnsPortStr, "%d", &dnsPort)
	rawDNS := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":%q,"server_port":%d,"detour":"proxy"}],"final":"dns1"}`, dnsHost, dnsPort)
	opts := parseDNSOptions(t, m.Context(), rawDNS)
	client, err := New(m.Context(), opts, m.OutboundManager())
	if err != nil {
		return fail(err)
	}
	m.RegisterDNS(client.Router(), client.TransportManager())
	if err := m.Start(); err != nil {
		_ = client.Close()
		return fail(err)
	}
	if err := client.Start(); err != nil {
		_ = client.Close()
		return fail(err)
	}
	d, err := m.Dialer("proxy")
	if err != nil {
		_ = client.Close()
		return fail(err)
	}
	httpClient := d.HTTPClient()
	httpClient.Timeout = 10 * time.Second
	st := &proxyStack{
		name: name, manager: m, client: client, dialer: d,
		httpClient: httpClient, dnsServer: dnsServer, dnsPort: dnsPort,
		wantAddr: answerIP, proxy: proxy, upstream: upstream,
	}
	t.Cleanup(st.close)
	return st
}

func (s *proxyStack) close() {
	if tr, ok := s.httpClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
	_ = s.client.Close()
	_ = s.manager.Close()
}

// get issues one GET through the stack's own HTTP client. withCookie
// sends an explicit Cookie header; the client must never add,
// remove, or share cookies of its own (its Jar is nil). It takes no
// *testing.T so it is safe to call from worker goroutines.
func (s *proxyStack) get(url string, withCookie bool) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Profile", s.name)
	if withCookie {
		req.Header.Set("Cookie", "session=FAKE-"+s.name)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d, body %q", url, resp.StatusCode, string(body))
	}
	return string(body), nil
}

func (s *proxyStack) upstreamURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", s.upstream.port, path)
}

// assertTransportIsolation pins the Dialer-level facts: each
// HTTPClient is a fresh client with a fresh transport, no proxy
// function, and no cookie jar.
func assertTransportIsolation(t *testing.T, s *proxyStack) {
	t.Helper()
	if s.httpClient.Jar != nil {
		t.Errorf("stack %s: HTTPClient has a cookie Jar; it must be nil (no shared jar, no jar at all)", s.name)
	}
	tr, ok := s.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("stack %s: HTTPClient transport = %T, want *http.Transport", s.name, s.httpClient.Transport)
	}
	if tr.Proxy != nil {
		t.Errorf("stack %s: HTTP transport Proxy is set; it must be nil so proxy env is never consulted", s.name)
	}
	if tr.TLSClientConfig != nil {
		t.Errorf("stack %s: HTTP transport has a TLSClientConfig; TLS goes through DialTLSContext, never a shared stdlib config", s.name)
	}
	if tr.DialTLSContext == nil || tr.DialContext == nil {
		t.Errorf("stack %s: HTTP transport lacks DialContext/DialTLSContext", s.name)
	}
	// A second HTTPClient() from the same Dialer is a different
	// client with a different transport: connection pools are
	// never shared, even within one profile.
	other := s.dialer.HTTPClient()
	if other == s.httpClient {
		t.Errorf("stack %s: two HTTPClient() calls returned the same client", s.name)
	}
	otherTr, ok := other.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("stack %s: second HTTPClient transport = %T", s.name, other.Transport)
	}
	if otherTr == tr {
		t.Errorf("stack %s: two HTTPClient() calls share one Transport (one connection pool)", s.name)
	}
	if other.Jar != nil {
		t.Errorf("stack %s: second HTTPClient has a cookie Jar", s.name)
	}
}

func TestTwoStacksNeverCrossTraffic(t *testing.T) {
	stA := buildProxyStack(t, "A", "127.0.0.1")
	stB := buildProxyStack(t, "B", "127.0.0.2")
	assertTransportIsolation(t, stA)
	assertTransportIsolation(t, stB)

	// Concurrent requests through different outbounds. Stack A
	// sends a Cookie header on every request; stack B sends none.
	const workers, iters = 4, 5
	var wg sync.WaitGroup
	var errsMu sync.Mutex
	var errs []error
	record := func(err error) {
		if err != nil {
			errsMu.Lock()
			errs = append(errs, err)
			errsMu.Unlock()
		}
	}
	for _, st := range []*proxyStack{stA, stB} {
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(st *proxyStack) {
				defer wg.Done()
				for i := 0; i < iters; i++ {
					body, err := st.get(st.upstreamURL("/echo"), st.name == "A")
					if err != nil {
						record(err)
						continue
					}
					if body != "pong-"+st.name {
						record(fmt.Errorf("stack %s: body = %q, want %q", st.name, body, "pong-"+st.name))
					}
				}
			}(st)
		}
	}
	wg.Wait()
	for _, err := range errs {
		t.Error(err)
	}

	// Every arrival at fake A came from A (with A's cookie), every
	// arrival at fake B came from B (with no cookie at all), and
	// neither fake saw the other's profile.
	const want = workers * iters
	arrA := stA.upstream.arrivalsSnapshot()
	arrB := stB.upstream.arrivalsSnapshot()
	if len(arrA) != want {
		t.Errorf("upstream A arrivals = %d, want %d", len(arrA), want)
	}
	if len(arrB) != want {
		t.Errorf("upstream B arrivals = %d, want %d", len(arrB), want)
	}
	for _, a := range arrA {
		if a.profile != "A" {
			t.Errorf("upstream A saw profile %q, want only A", a.profile)
		}
		if a.cookie != "session=FAKE-A" {
			t.Errorf("upstream A arrival cookie = %q, want %q", a.cookie, "session=FAKE-A")
		}
	}
	for _, a := range arrB {
		if a.profile != "B" {
			t.Errorf("upstream B saw profile %q, want only B", a.profile)
		}
		if a.cookie != "" {
			t.Errorf("upstream B arrival carries cookie %q: a Cookie header sent via stack A leaked into stack B (or a shared jar added one)", a.cookie)
		}
	}
	// Each proxy saw only its own stack's CONNECT targets: its own
	// upstream port (HTTP phase) and, after the DNS phases below,
	// its own DNS port. No target may name the other stack's ports.
	for _, pair := range []struct {
		st    *proxyStack
		other *proxyStack
	}{{stA, stB}, {stB, stA}} {
		for _, target := range pair.st.proxy.targetsSnapshot() {
			_, portStr, err := net.SplitHostPort(target)
			if err != nil {
				t.Errorf("stack %s: proxy recorded unparsable CONNECT target %q", pair.st.name, target)
				continue
			}
			var port int
			fmt.Sscanf(portStr, "%d", &port)
			if port != pair.st.upstream.port && port != pair.st.dnsPort {
				t.Errorf("stack %s: proxy CONNECT target %q names a foreign port (own upstream %d, own DNS %d; other stack upstream %d, DNS %d)",
					pair.st.name, target, pair.st.upstream.port, pair.st.dnsPort, pair.other.upstream.port, pair.other.dnsPort)
			}
		}
	}
	if stA.proxy.connectCount() == 0 || stB.proxy.connectCount() == 0 {
		t.Errorf("proxy CONNECT counts = A:%d B:%d, want both > 0 (each stack's egress went through its own outbound)", stA.proxy.connectCount(), stB.proxy.connectCount())
	}

	// DNS stays within the owning profile, through its own
	// outbound. Each phase asserts the ANSWER VALUE (only the
	// owning stack's DNS server serves that address) and the
	// positive fact that the owning proxy saw a CONNECT to the
	// owning DNS server.
	lookup := func(st *proxyStack) {
		t.Helper()
		st.client.Router().ClearCache()
		before := st.dnsServer.queryCount()
		proxyBefore := len(st.proxy.targetsSnapshot())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addrs, err := st.client.Lookup(ctx, "gateway.test")
		if err != nil {
			t.Fatalf("stack %s Lookup: %v", st.name, err)
		}
		if len(addrs) != 1 || addrs[0].String() != st.wantAddr {
			t.Fatalf("stack %s Lookup = %v, want [%s]: the answer came from the other stack's DNS (or nowhere)", st.name, addrs, st.wantAddr)
		}
		if st.dnsServer.queryCount() <= before {
			t.Errorf("stack %s: own fake DNS saw no new queries for its lookup", st.name)
		}
		foundDNSConnect := false
		for _, target := range st.proxy.targetsSnapshot()[proxyBefore:] {
			_, portStr, err := net.SplitHostPort(target)
			if err != nil {
				continue
			}
			var port int
			fmt.Sscanf(portStr, "%d", &port)
			if port == st.dnsPort {
				foundDNSConnect = true
			}
		}
		if !foundDNSConnect {
			t.Errorf("stack %s: own proxy saw no CONNECT to its own DNS server during its lookup: the lookup did not route through its own outbound", st.name)
		}
	}
	lookup(stA)
	lookup(stB)

	// Domain dial behaviour: an HTTP GET to the fake-only hostname
	// gateway.test through stack A resolves through A's DNS and
	// arrives at A's upstream with the gateway.test authority.
	// Stack B's upstream observes nothing new.
	stA.client.Router().ClearCache()
	upBBefore := len(stB.upstream.arrivalsSnapshot())
	body, err := stA.get(fmt.Sprintf("http://gateway.test:%d/domain", stA.upstream.port), false)
	if err != nil {
		t.Fatalf("stack A GET via gateway.test: %v", err)
	}
	if body != "pong-A" {
		t.Fatalf("stack A GET via gateway.test: body = %q, want %q", body, "pong-A")
	}
	foundDomainArrival := false
	for _, a := range stA.upstream.arrivalsSnapshot() {
		if a.path == "/domain" {
			foundDomainArrival = true
			if a.host != fmt.Sprintf("gateway.test:%d", stA.upstream.port) {
				t.Errorf("upstream A /domain arrival Host = %q, want the gateway.test authority", a.host)
			}
			if a.profile != "A" {
				t.Errorf("upstream A /domain arrival profile = %q, want A", a.profile)
			}
		}
	}
	if !foundDomainArrival {
		t.Error("upstream A saw no /domain arrival: the gateway.test dial did not reach A's upstream")
	}
	if got := len(stB.upstream.arrivalsSnapshot()); got != upBBefore {
		t.Errorf("upstream B arrivals changed %d -> %d during stack A's gateway.test dial", upBBefore, got)
	}

	// Closing stack A leaves stack B fully working.
	stA.close()
	body, err = stB.get(stB.upstreamURL("/after"), false)
	if err != nil {
		t.Errorf("stack B GET after closing stack A: %v", err)
	} else if body != "pong-B" {
		t.Errorf("stack B GET after closing stack A: body = %q, want %q", body, "pong-B")
	}
}

func TestTwoStacksIgnoreHostileProxyEnv(t *testing.T) {
	// Hostile environment: every proxy variable (both cases, plus
	// an emptied NO_PROXY so loopback would NOT be bypassed by any
	// env-proxy lookup) points at a dead address. If any dial path
	// consulted the environment, every request below would fail.
	dead := "http://127.0.0.1:9/"
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, dead)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	if got := os.Getenv("HTTP_PROXY"); got != dead {
		t.Fatalf("HTTP_PROXY = %q during the test, want the hostile value %q (the env was not actually hostile)", got, dead)
	}

	stA := buildProxyStack(t, "A", "127.0.0.1")
	stB := buildProxyStack(t, "B", "127.0.0.2")
	assertTransportIsolation(t, stA)
	assertTransportIsolation(t, stB)

	// Egress is unchanged: same fakes hit, same bodies, DNS works.
	var wg sync.WaitGroup
	var errsMu sync.Mutex
	var errs []error
	for _, st := range []*proxyStack{stA, stB} {
		wg.Add(1)
		go func(st *proxyStack) {
			defer wg.Done()
			body, err := st.get(st.upstreamURL("/echo"), false)
			if err != nil {
				errsMu.Lock()
				errs = append(errs, fmt.Errorf("stack %s GET under hostile env: %w", st.name, err))
				errsMu.Unlock()
				return
			}
			if body != "pong-"+st.name {
				errsMu.Lock()
				errs = append(errs, fmt.Errorf("stack %s body = %q, want %q", st.name, body, "pong-"+st.name))
				errsMu.Unlock()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			addrs, err := st.client.Lookup(ctx, "gateway.test")
			if err != nil {
				errsMu.Lock()
				errs = append(errs, fmt.Errorf("stack %s Lookup under hostile env: %w", st.name, err))
				errsMu.Unlock()
				return
			}
			if len(addrs) != 1 || addrs[0].String() != st.wantAddr {
				errsMu.Lock()
				errs = append(errs, fmt.Errorf("stack %s Lookup = %v, want [%s]", st.name, addrs, st.wantAddr))
				errsMu.Unlock()
			}
		}(st)
	}
	wg.Wait()
	for _, err := range errs {
		t.Error(err)
	}
	if stA.dnsServer.queryCount() == 0 || stB.dnsServer.queryCount() == 0 {
		t.Errorf("fake DNS query counts under hostile env = A:%d B:%d, want both > 0", stA.dnsServer.queryCount(), stB.dnsServer.queryCount())
	}
	for _, pair := range []struct {
		st   *proxyStack
		want string
	}{{stA, "A"}, {stB, "B"}} {
		arr := pair.st.upstream.arrivalsSnapshot()
		if len(arr) == 0 {
			t.Errorf("upstream %s saw no arrivals under hostile env", pair.want)
		}
		for _, a := range arr {
			if a.profile != pair.want {
				t.Errorf("upstream %s saw profile %q under hostile env", pair.want, a.profile)
			}
		}
	}
}
