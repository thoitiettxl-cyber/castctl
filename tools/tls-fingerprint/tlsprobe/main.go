// Command tlsprobe is a SCRATCH-ONLY probe (NOT product code) for PR0 stage E.
//
// It answers, per TLS implementation (stdlib crypto/tls vs sing-box uTLS
// fingerprint chrome), whether: (E1) a TLS handshake to muse.ai:443 and
// hatch.metaaivm.com:443 succeeds; (E2) the gateway.py HTTPS auth chain
// (GET /api/session, POST /api/auth/check, POST /api/hatch/token) succeeds
// with --profile muse01 cookies (read-only); (E3) a WebSocket upgrade +
// Noise XX handshake to wss://hatch.metaaivm.com/v1/noise succeeds, after
// which it CLOSES immediately: no ServiceRequest, no subscription, no
// chat.stream, no chat send.
//
// PROBE-ONLY proxy code: -use-proxy adds an HTTP CONNECT tunnel dialled
// from the proxy env vars (HTTPS_PROXY/ALL_PROXY/HTTP_PROXY, honouring
// NO_PROXY) for this VM's TLS-intercepting egress proxy. The CONNECT code
// in this file is probe-only and MUST NOT be presented as product code:
// product code models an egress proxy as an explicit sing-box outbound,
// never as a hidden env shim on `direct`.
//
// Stages: -stage e1 (DEFAULT) runs E1 only and NEVER touches any cookies
// file (no stat, no read, no home-dir default). -stage all runs E1->E2->E3
// and requires an explicit -cookies-file flag pointing at the operator's
// own cookies.txt; the file must have mode 0600 or the probe refuses.
// Cookie/token values are NEVER printed, logged, or embedded in any
// output: only status codes, booleans, and byte lengths are reported.
// Errors are passed through a scrubber that replaces every secret value
// and any auth_token/vm_id query parameter with [REDACTED].
//
// Echo mode (-mode echo) is separate: it TLS-dials a public JA3/JA4 echo
// service (default https://tls.peet.ws/api/all, overridable with
// -echo-url), sends ONE HTTPS GET with no cookies and no auth headers,
// and prints the JA3/JA4 fingerprints the echo reports, per TLS
// implementation. Echo mode never touches any cookies file and sends no
// Muse traffic. WARNING: when dialled through a TLS-intercepting proxy
// (-use-proxy), the echo reports the PROXY's ClientHello, not this
// client's; the decisive fingerprint comparison requires a direct dial
// from a non-intercepted machine.
//
// Safety: only --profile muse01 on this VM. The cookies path must be
// passed explicitly and have mode 0600, verified before any read;
// otherwise the probe refuses (exit 2) without reading.
//
// Usage: tlsprobe -impl stdlib|singbox|all [-stage e1|all] [-use-proxy] [-cookies-file PATH]
//
//	tlsprobe -mode echo -impl stdlib|singbox|all [-echo-url URL] [-use-proxy]
//
// Exit 0: every stage attempted passed. Exit 1: a stage failed (stage name
// in output; later stages not attempted for that impl). Exit 2:
// usage/safety refusal. -h/--help prints usage and exits 0 without dialling.
// Build with: go build -tags with_utls (sing-box uTLS is a stub without it).
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/flynn/noise"
	"github.com/gorilla/websocket"

	sbTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
)

const (
	ua          = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
	gatewayHost = "hatch.metaaivm.com"
	stageTO     = 20 * time.Second // mirrors gateway.py timeout=20 / HANDSHAKE_TIMEOUT=20
	maxBody     = 1 << 20
)

var secrets []string // values that must never appear in output

func scrub(s string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[REDACTED]")
		}
	}
	s = regexp.MustCompile(`auth_token=[^&\s]*`).ReplaceAllString(s, "auth_token=[REDACTED]")
	s = regexp.MustCompile(`vm_id=[^&\s]*`).ReplaceAllString(s, "vm_id=[REDACTED]")
	// Never emit a Cookie/Authorization header line even in scrubbed form.
	for _, line := range strings.Split(s, "\n") {
		lower := strings.ToLower(line)
		if strings.HasPrefix(strings.TrimSpace(lower), "cookie:") || strings.HasPrefix(strings.TrimSpace(lower), "authorization:") {
			s = strings.ReplaceAll(s, line, "[HEADER REDACTED]")
		}
	}
	return s
}

func out(format string, args ...any) {
	// fmt.Print, not Printf: scrubbed content must never be interpreted as
	// a format string.
	fmt.Print(scrub(fmt.Sprintf(format, args...)) + "\n")
}

func fail(stage, format string, args ...any) {
	out("STAGE %s result=FAIL %s", stage, fmt.Sprintf(format, args...))
	os.Exit(1)
}

func usage() {
	fmt.Println("usage: tlsprobe -impl stdlib|singbox|all [-stage e1|all] [-use-proxy] [-cookies-file PATH]")
	fmt.Println("       tlsprobe -mode echo -impl stdlib|singbox|all [-echo-url URL] [-use-proxy]")
	fmt.Println("  -impl stdlib|singbox|all   TLS implementation to probe (all runs both, sequentially)")
	fmt.Println("  -stage e1|all             e1 (default): TLS handshake only, no cookie access at all")
	fmt.Println("                            all: E1->E2->E3, requires explicit -cookies-file")
	fmt.Println("  -mode probe|echo            probe (default): E1/E2/E3 stages; echo: JA3/JA4 echo mode, no cookies, no Muse traffic")
	fmt.Println("  -echo-url URL               JA3/JA4 echo endpoint for -mode echo (default https://tls.peet.ws/api/all; must be https, port 443)")
	fmt.Println("  -use-proxy                dial via HTTP CONNECT tunnel from proxy env (HTTPS_PROXY/ALL_PROXY/HTTP_PROXY, honouring NO_PROXY); default is direct dial")
	fmt.Println("  -cookies-file PATH        cookies.txt path, required for -stage all; never defaults to any profile; file must be mode 0600")
	fmt.Println("  -cookies PATH             alias of -cookies-file")
	fmt.Println("Exit 0: every stage attempted passed. Exit 1: a stage failed. Exit 2: usage/safety refusal.")
	fmt.Println("E1 only: no credentials are read. E2/E3: cookies are read-only, tokens stay in memory, handshake closes immediately; no chat, no messages, no files written.")
	fmt.Println("Echo mode: prints a proxy warning on every run; values from a proxied run reflect the proxy's ClientHello, not this client's.")
}

func main() {
	// -h/--help must exit 0 without dialling anything.
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "-help" || arg == "--help" {
			usage()
			os.Exit(0)
		}
	}
	implFlag := flag.String("impl", "", "stdlib | singbox | all")
	stageFlag := flag.String("stage", "e1", "e1 | all")
	modeFlag := flag.String("mode", "probe", "probe | echo")
	echoURLFlag := flag.String("echo-url", defaultEchoURL, "JA3/JA4 echo endpoint for -mode echo")
	useProxy := flag.Bool("use-proxy", false, "dial via HTTP CONNECT tunnel from proxy env")
	cookiesFile := flag.String("cookies-file", "", "cookies.txt path, required for -stage all")
	cookiesAlias := flag.String("cookies", "", "alias of -cookies-file")
	flag.Usage = usage
	flag.Parse()
	if *implFlag != "stdlib" && *implFlag != "singbox" && *implFlag != "all" {
		usage()
		os.Exit(2)
	}
	if *stageFlag != "e1" && *stageFlag != "all" {
		usage()
		os.Exit(2)
	}
	if *modeFlag != "probe" && *modeFlag != "echo" {
		usage()
		os.Exit(2)
	}
	cookiesPath := *cookiesFile
	if cookiesPath == "" {
		cookiesPath = *cookiesAlias
	}
	var impls []string
	if *implFlag == "all" {
		impls = []string{"stdlib", "singbox"}
	} else {
		impls = []string{*implFlag}
	}

	// Echo mode: JA3/JA4 fingerprints only. No cookies file is ever
	// touched, no Muse traffic is sent, and -stage is meaningless here.
	if *modeFlag == "echo" {
		if *stageFlag == "all" {
			out("SAFETY REFUSAL: -mode echo takes no -stage; echo mode never touches cookies")
			os.Exit(2)
		}
		if cookiesPath != "" {
			out("SAFETY REFUSAL: -mode echo takes no -cookies-file; refusing to touch any credentials")
			os.Exit(2)
		}
		echoURL, err := url.Parse(*echoURLFlag)
		if err != nil || echoURL.Scheme != "https" || echoURL.Hostname() == "" {
			out("SAFETY REFUSAL: -echo-url must be an https URL with a host: %q", *echoURLFlag)
			os.Exit(2)
		}
		if port := echoURL.Port(); port != "" && port != "443" {
			out("SAFETY REFUSAL: -echo-url must use port 443 (this probe dials :443 only): %q", *echoURLFlag)
			os.Exit(2)
		}
		out("WARNING: echo mode reports the ClientHello the echo server saw. Via a TLS-intercepting proxy (-use-proxy) that is the PROXY's ClientHello, NOT this client's; only a DIRECT dial gives decisive stdlib-vs-uTLS values. PROXY=%v URL=%s", *useProxy, echoURL.String())
		anyFail := false
		for _, impl := range impls {
			out("IMPL=%s MODE=echo STAGE_TIMEOUT=20s PROXY=%v", impl, *useProxy)
			if err := stageEcho(impl, echoURL.String(), *useProxy); err != nil {
				out("ECHO impl=%s result=FAIL %v", impl, err)
				anyFail = true
			} else {
				out("RESULT impl=%s ECHO=PASS", impl)
			}
		}
		if anyFail {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// E1 for every impl, before any credential is touched. In -stage e1
	// mode the cookies file is never statted or read at all.
	e1Passed := map[string]bool{}
	anyFail := false
	for _, impl := range impls {
		out("IMPL=%s STAGES=E1 STAGE_TIMEOUT=20s PROXY=%v", impl, *useProxy)
		failed := false
		for _, host := range []string{"muse.ai", gatewayHost} {
			if err := stageE1(impl, host, *useProxy); err != nil {
				out("STAGE E1 impl=%s result=FAIL host=%s err=%v", impl, host, err)
				failed = true
				break
			}
		}
		if failed {
			anyFail = true
			e1Passed[impl] = false
		} else {
			e1Passed[impl] = true
			out("RESULT impl=%s E1=PASS", impl)
		}
	}
	if *stageFlag == "e1" {
		if anyFail {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// -stage all: E2/E3 need an explicitly supplied cookies file. There
	// is no default path; the probe never guesses a profile.
	if cookiesPath == "" {
		out("SAFETY REFUSAL: -stage all requires an explicit -cookies-file; refusing to default to any profile")
		os.Exit(2)
	}
	if !anyE1Passed(e1Passed) {
		out("STAGE E2 skipped: E1 failed for every impl; not reading cookies")
		os.Exit(1)
	}
	// Verify the cookies file mode BEFORE reading any credential.
	absPath, err := filepath.Abs(cookiesPath)
	if err != nil {
		out("SAFETY REFUSAL: cannot resolve cookies path: %v", err)
		os.Exit(2)
	}
	profDir := filepath.Dir(absPath)
	if st, err := os.Stat(profDir); err != nil || !st.IsDir() {
		out("SAFETY REFUSAL: cookies dir check failed: %v", err)
		os.Exit(2)
	}
	st, err := os.Stat(absPath)
	if err != nil {
		out("SAFETY REFUSAL: cannot stat cookies file: %v", err)
		os.Exit(2)
	}
	mode := st.Mode().Perm()
	out("PROFILE dir=%s cookies_mode=%04o (required 0600)", profDir, mode)
	if mode != 0o600 {
		out("SAFETY REFUSAL: cookies.txt mode is %04o, not 0600; refusing to read", mode)
		os.Exit(2)
	}
	cookies, err := loadCookies(absPath)
	if err != nil {
		out("STAGE E2 result=FAIL load_cookies: %v", err)
		os.Exit(1)
	}
	// E2/E3 per impl that passed E1. Tokens stay in memory only.
	for _, impl := range impls {
		if !e1Passed[impl] {
			continue
		}
		out("IMPL=%s STAGES=E2->E3 STAGE_TIMEOUT=20s PROXY=%v", impl, *useProxy)
		vmID, accessToken, hatchToken, err := stageE2(impl, cookies, *useProxy)
		if err != nil {
			out("STAGE E2 impl=%s result=FAIL %v", impl, err)
			anyFail = true
			continue
		}
		// Register secrets for scrubbing from here on (vmID too: it appears in URLs).
		secrets = append(secrets, cookies, accessToken, hatchToken, vmID)
		if err := stageE3(impl, vmID, hatchToken, *useProxy); err != nil {
			out("STAGE E3 impl=%s result=FAIL %v", impl, err)
			anyFail = true
			continue
		}
		out("RESULT PASS impl=%s E1=PASS E2=PASS E3=PASS", impl)
	}
	if anyFail {
		os.Exit(1)
	}
	os.Exit(0)
}

func anyE1Passed(m map[string]bool) bool {
	for _, v := range m {
		if v {
			return true
		}
	}
	return false
}

// loadCookies replicates gateway.py load_cookies. It reports only the
// detected format and presence booleans, never any cookie value.
func loadCookies(path string) (string, error) {
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	raw := strings.TrimSpace(string(rawBytes))
	format := "unknown"
	var cookie string
	switch {
	case strings.HasPrefix(raw, "{"):
		format = "json"
		var d map[string]any
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			return "", fmt.Errorf("unparseable JSON cookies file")
		}
		if inner, ok := d["cookies"].(map[string]any); ok {
			parts := make([]string, 0, len(inner))
			for k, v := range inner {
				parts = append(parts, k+"="+fmt.Sprint(v))
			}
			cookie = strings.Join(parts, "; ")
		} else {
			parts := make([]string, 0, len(d))
			for k, v := range d {
				parts = append(parts, k+"="+fmt.Sprint(v))
			}
			cookie = strings.Join(parts, "; ")
		}
	case strings.Contains(raw, "hatch_sess=") || strings.Contains(raw, "datr="):
		format = "one-line"
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && strings.Contains(line, "=") && strings.Contains(line, ";") {
				cookie = line
				break
			}
		}
		if cookie == "" {
			cookie = strings.Join(strings.Fields(raw), " ")
		}
	default:
		format = "netscape"
		var parts []string
		for _, line := range strings.Split(raw, "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			cols := strings.Split(line, "\t")
			if len(cols) >= 7 {
				parts = append(parts, cols[5]+"="+cols[6])
			}
		}
		if len(parts) == 0 {
			return "", fmt.Errorf("could not parse cookies file")
		}
		cookie = strings.Join(parts, "; ")
	}
	if cookie == "" {
		return "", fmt.Errorf("empty cookie header")
	}
	out("COOKIES format=%s hatch_sess_present=%v datr_present=%v", format,
		strings.Contains(cookie, "hatch_sess="), strings.Contains(cookie, "datr="))
	return cookie, nil
}

// ---- TLS dialing (implementation-specific, secrets-free) ----

func tlsStateString(state tls.ConnectionState) string {
	return fmt.Sprintf("tls_version=0x%04x cipher=0x%04x negotiated_proto=%q handshake_complete=%v peer_certs=%d verified_chains=%d",
		state.Version, state.CipherSuite, state.NegotiatedProtocol, state.HandshakeComplete,
		len(state.PeerCertificates), len(state.VerifiedChains))
}

// ---- PROBE-ONLY proxy CONNECT tunnel (not product code) ----
//
// proxyTunnel dials the proxy from the environment and issues one HTTP
// CONNECT for host:443. Proxy credentials come from the proxy URL userinfo
// in-process only: Proxy-Authorization appears ONLY in the CONNECT request
// and is never logged. Only the proxy host:port and the env var NAME that
// supplied it are ever printed; proxy env VALUES are never printed.

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// proxyForHost resolves the proxy for an https target exactly as Go's
// ProxyFromEnvironment does, so NO_PROXY is honoured. It returns nil (no
// error) when no proxy applies: the caller must then STOP, never fall
// back to a direct dial in proxy mode.
func proxyForHost(host string) (proxyHostPort, envName string, err error) {
	req, err := http.NewRequest("GET", "https://"+host+"/", nil)
	if err != nil {
		return "", "", err
	}
	u, err := http.ProxyFromEnvironment(req)
	if err != nil {
		return "", "", err
	}
	if u == nil {
		return "", "", nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", fmt.Errorf("unsupported proxy scheme %q (only http/https CONNECT)", u.Scheme)
	}
	// Env var NAME only, never the value. Order mirrors Go's https lookup.
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"} {
		if _, present := os.LookupEnv(name); present {
			envName = name
			break
		}
	}
	if envName == "" {
		envName = "proxy env"
	}
	proxyHostPort = u.Host
	if _, _, err := net.SplitHostPort(proxyHostPort); err != nil {
		if u.Scheme == "https" {
			proxyHostPort = net.JoinHostPort(proxyHostPort, "443")
		} else {
			proxyHostPort = net.JoinHostPort(proxyHostPort, "80")
		}
	}
	return proxyHostPort, envName, nil
}

func proxyTunnel(ctx context.Context, host string) (net.Conn, error) {
	proxyHostPort, envName, err := proxyForHost(host)
	if err != nil {
		return nil, err
	}
	if proxyHostPort == "" {
		return nil, fmt.Errorf("proxy mode: no proxy configured for host (NO_PROXY or no proxy env); refusing direct dial")
	}
	out("PROXY target_host=%s proxy_host_port=%s env_var_name=%s", host, proxyHostPort, envName)
	// Re-resolve the proxy URL for userinfo (credentials, in-process only).
	req, _ := http.NewRequest("GET", "https://"+host+"/", nil)
	proxyURL, _ := http.ProxyFromEnvironment(req)
	dialer := &net.Dialer{Timeout: stageTO}
	dialCtx, cancel := context.WithTimeout(ctx, stageTO)
	defer cancel()
	proxyConn, err := dialer.DialContext(dialCtx, "tcp", proxyHostPort)
	if err != nil {
		return nil, fmt.Errorf("proxy tcp dial: %w", err)
	}
	target := net.JoinHostPort(host, "443")
	var sb strings.Builder
	sb.WriteString("CONNECT " + target + " HTTP/1.1\r\n")
	sb.WriteString("Host: " + target + "\r\n")
	if proxyURL != nil && proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		// Credentials only in the CONNECT request, never logged.
		sb.WriteString("Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password)) + "\r\n")
	}
	sb.WriteString("Proxy-Connection: Keep-Alive\r\n\r\n")
	_ = proxyConn.SetDeadline(time.Now().Add(stageTO))
	if _, err := io.WriteString(proxyConn, sb.String()); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT write: %w", err)
	}
	br := bufio.NewReader(proxyConn)
	connectReq, _ := http.NewRequest("CONNECT", "http://"+target, nil)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT response: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT status=%d (want 200)", resp.StatusCode)
	}
	_ = proxyConn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: proxyConn, r: br}, nil
}

// dialRaw returns a plain TCP connection to host:443, directly or through
// the proxy CONNECT tunnel when useProxy is set.
func dialRaw(ctx context.Context, host string, useProxy bool) (net.Conn, error) {
	if useProxy {
		return proxyTunnel(ctx, host)
	}
	dialer := &net.Dialer{Timeout: stageTO}
	dialCtx, cancel := context.WithTimeout(ctx, stageTO)
	defer cancel()
	return dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(host, "443"))
}

// handshakeOverConn runs the impl-specific TLS handshake over an already
// connected plain conn (direct TCP or proxy tunnel).
func handshakeOverConn(ctx context.Context, impl, host string, raw net.Conn) (net.Conn, error) {
	hsCtx, cancel := context.WithTimeout(ctx, stageTO)
	defer cancel()
	if impl == "stdlib" {
		tc := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(hsCtx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		return tc, nil
	}
	cfg, err := sbTLS.NewClientWithOptions(sbTLS.ClientOptions{
		Context:       hsCtx,
		Logger:        logger.NOP(),
		ServerAddress: host,
		Options: option.OutboundTLSOptions{
			Enabled: true,
			// ALPN http/1.1 only: the HTTP/WS paths in this probe are
			// HTTP/1.1 (upgrade). The uTLS preset would otherwise offer
			// h2, which the intercepting proxy negotiates and then
			// rejects HTTP/1.1 bytes on. The Chrome fingerprint
			// (HelloChrome_Auto) is unchanged; only ALPN is pinned.
			ALPN: badoption.Listable[string]{"http/1.1"},
			UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		},
	})
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("sing-box NewClientWithOptions: %w", err)
	}
	if cfg == nil {
		raw.Close()
		return nil, fmt.Errorf("sing-box returned nil TLS config")
	}
	tlsConn, err := sbTLS.ClientHandshake(hsCtx, raw, cfg)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("sing-box uTLS handshake: %w", err)
	}
	return tlsConn, nil
}

// dialTLS returns a handshaked TLS connection to host:443. The returned
// conn is a plain net.Conn; handshake errors are returned verbatim (callers
// scrub them before printing).
func dialTLS(ctx context.Context, impl, host string, useProxy bool) (net.Conn, error) {
	raw, err := dialRaw(ctx, host, useProxy)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	return handshakeOverConn(ctx, impl, host, raw)
}

// connState extracts tls.ConnectionState from either a *tls.Conn or a
// sing-box Conn (both expose ConnectionState() tls.ConnectionState).
func connState(conn net.Conn) (tls.ConnectionState, bool) {
	if cs, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return cs.ConnectionState(), true
	}
	return tls.ConnectionState{}, false
}

func stageE1(impl, host string, useProxy bool) error {
	ctx := context.Background()
	conn, err := dialTLS(ctx, impl, host, useProxy)
	if err != nil {
		return err
	}
	defer conn.Close()
	state, ok := connState(conn)
	if !ok {
		out("STAGE E1 host=%s result=PASS (handshake ok, ConnectionState unavailable via interface)", host)
		return nil
	}
	out("STAGE E1 host=%s result=PASS %s", host, tlsStateString(state))
	return nil
}

// ---- Echo mode: JA3/JA4 fingerprint via a public TLS echo ----

const defaultEchoURL = "https://tls.peet.ws/api/all"

// echoClientFor mirrors httpClientFor but NEVER consults the proxy
// environment in direct mode: echo mode's "direct" must be a true direct
// dial, so Proxy is nil unless -use-proxy owns the tunnel end-to-end.
func echoClientFor(impl string, useProxy bool) *http.Client {
	dialer := &net.Dialer{Timeout: stageTO}
	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   stageTO,
		ResponseHeaderTimeout: stageTO,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	if useProxy {
		tr.Proxy = nil
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return proxyTunnel(ctx, host)
		}
		tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			raw, err := proxyTunnel(ctx, host)
			if err != nil {
				return nil, err
			}
			return handshakeOverConn(ctx, impl, host, raw)
		}
		return &http.Client{Transport: tr}
	}
	tr.Proxy = nil
	if impl == "singbox" {
		tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return dialTLS(ctx, "singbox", host, false)
		}
		// TLSClientConfig must stay nil: the custom DialTLSContext owns TLS.
	} else {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr}
}

// echoField looks up key in m, then in m["tls"] when that is an object.
// This accepts both echo shapes: tls.peet.ws nests fingerprints under
// "tls" (ja3/ja4/ja3_hash/ja4_r), tls.browserleaks.com is flat
// (ja3_text/ja3_hash/ja4/ja4_r).
func echoField(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	if tlsObj, ok := m["tls"].(map[string]any); ok {
		if v, ok := tlsObj[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func stageEcho(impl, echoURL string, useProxy bool) error {
	u, err := url.Parse(echoURL)
	if err != nil {
		return err
	}
	host := u.Hostname()
	// 1. Handshake-only dial first: reports our own negotiated state,
	// mirroring stageE1, over a connection built exactly like the echo
	// GET's (same TLS config, SNI, pinned ALPN). Both connections use
	// the same deterministic ClientHello construction per impl.
	ctx := context.Background()
	hsConn, err := dialTLS(ctx, impl, host, useProxy)
	if err != nil {
		return fmt.Errorf("echo handshake: %w", err)
	}
	if state, ok := connState(hsConn); ok {
		out("ECHO impl=%s handshake host=%s %s", impl, host, tlsStateString(state))
	}
	hsConn.Close()

	// 2. ONE HTTPS GET, profile-consistent headers, no cookies, no auth.
	client := echoClientFor(impl, useProxy)
	defer client.CloseIdleConnections()
	h := http.Header{}
	h.Set("User-Agent", ua)
	h.Set("Referer", "https://muse.ai/")
	h.Set("Origin", "https://muse.ai")
	h.Set("Sec-Fetch-Site", "same-origin")
	h.Set("Sec-Fetch-Mode", "cors")
	h.Set("Sec-Fetch-Dest", "empty")
	h.Set("Accept", "application/json")
	reqCtx, cancel := context.WithTimeout(context.Background(), stageTO)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", echoURL, nil)
	if err != nil {
		return err
	}
	req.Header = h
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("echo GET: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("echo read: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("echo status=%d body_len=%d (want 200)", resp.StatusCode, len(raw))
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("echo body is not JSON (body_len=%d): %w", len(raw), err)
	}
	ja3 := echoField(parsed, "ja3")
	if ja3 == "" {
		ja3 = echoField(parsed, "ja3_text")
	}
	ja3Hash := echoField(parsed, "ja3_hash")
	ja4 := echoField(parsed, "ja4")
	ja4r := echoField(parsed, "ja4_r")
	version := echoField(parsed, "tls_version_negotiated")
	if version == "" {
		version = echoField(parsed, "tls_version")
	}
	if ja3 == "" && ja3Hash == "" {
		return fmt.Errorf("echo returned no JA3 field (body_len=%d); try another -echo-url", len(raw))
	}
	if ja4 == "" {
		return fmt.Errorf("echo returned no JA4 field (body_len=%d); try another -echo-url", len(raw))
	}
	out("ECHO impl=%s ja3=%s", impl, ja3)
	out("ECHO impl=%s ja3_hash=%s", impl, ja3Hash)
	out("ECHO impl=%s ja4=%s", impl, ja4)
	out("ECHO impl=%s ja4_r=%s", impl, ja4r)
	if version != "" {
		out("ECHO impl=%s tls_version_negotiated=%s", impl, version)
	}
	// Raw offered-lists when the echo reports them (peet shape): counts
	// only — the full lists are long and add nothing beyond the hashes.
	if tlsObj, ok := parsed["tls"].(map[string]any); ok {
		nCiphers, nExt := 0, 0
		if c, ok := tlsObj["ciphers"].([]any); ok {
			nCiphers = len(c)
		}
		if e, ok := tlsObj["extensions"].([]any); ok {
			nExt = len(e)
		}
		out("ECHO impl=%s offered_ciphers=%d offered_extensions=%d", impl, nCiphers, nExt)
		if pp, ok := tlsObj["peetprint"].(string); ok && pp != "" {
			out("ECHO impl=%s peetprint=%s", impl, pp)
		}
	}
	out("ECHO impl=%s result=PASS body_len=%d", impl, len(raw))
	return nil
}

// ---- E2: HTTPS auth chain ----

func hatchHeaders(cookies, accessToken string) http.Header {
	h := http.Header{}
	h.Set("User-Agent", ua)
	h.Set("Referer", "https://muse.ai/")
	h.Set("Origin", "https://muse.ai")
	h.Set("Sec-Fetch-Site", "same-origin")
	h.Set("Sec-Fetch-Mode", "cors")
	h.Set("Sec-Fetch-Dest", "empty")
	h.Set("Accept", "application/json")
	h.Set("Content-Type", "application/json")
	h.Set("Cookie", cookies)
	if accessToken != "" {
		h.Set("Authorization", "Bearer "+accessToken)
	}
	return h
}

func httpClientFor(impl string, useProxy bool) *http.Client {
	dialer := &net.Dialer{Timeout: stageTO}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   stageTO,
		ResponseHeaderTimeout: stageTO,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	if useProxy {
		// Proxy mode owns the tunnel end-to-end: Transport must not also
		// apply ProxyFromEnvironment (that would double-tunnel). The
		// tunnel itself honours NO_PROXY via proxyForHost.
		tr.Proxy = nil
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return proxyTunnel(ctx, host)
		}
		tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			raw, err := proxyTunnel(ctx, host)
			if err != nil {
				return nil, err
			}
			return handshakeOverConn(ctx, impl, host, raw)
		}
		// TLSClientConfig must stay nil: the custom DialTLSContext owns TLS.
		return &http.Client{Transport: tr}
	}
	if impl == "singbox" {
		tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			// TCP dial + sing-box uTLS handshake for this hostname.
			return dialTLS(ctx, "singbox", host, false)
		}
		// TLSClientConfig must stay nil: the custom DialTLSContext owns TLS.
	} else {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr}
}

func doJSON(client *http.Client, method, url string, headers http.Header, body []byte) (int, int, map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), stageTO)
	defer cancel()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return 0, 0, nil, err
	}
	req.Header = headers
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, 0, nil, err
	}
	var parsed map[string]any
	_ = json.Unmarshal(raw, &parsed) // non-JSON -> nil map; caller decides
	return resp.StatusCode, len(raw), parsed, nil
}

func stageE2(impl, cookies string, useProxy bool) (vmID, accessToken, hatchToken string, err error) {
	client := httpClientFor(impl, useProxy)
	defer client.CloseIdleConnections()

	// 1. GET /api/session -> vm_id (gateway.py fetch_session_info).
	status, bodyLen, parsed, err := doJSON(client, "GET", "https://muse.ai/api/session", hatchHeaders(cookies, ""), nil)
	if err != nil {
		return "", "", "", fmt.Errorf("api/session request: %w", err)
	}
	if status != 200 {
		return "", "", "", fmt.Errorf("api/session status=%d body_len=%d (want 200)", status, bodyLen)
	}
	vmRaw, ok := parsed["vm_id"]
	vmID, _ = vmRaw.(string)
	out("STAGE E2 step=api/session status=%d body_len=%d vm_id_obtained=%v", status, bodyLen, ok && vmID != "")
	if !ok || vmID == "" {
		return "", "", "", fmt.Errorf("api/session status=200 but vm_id absent (VM unavailable shape)")
	}

	// 2. POST /api/auth/check, empty body -> access_token (fetch_access_token).
	status, bodyLen, parsed, err = doJSON(client, "POST", "https://muse.ai/api/auth/check", hatchHeaders(cookies, ""), []byte{})
	if err != nil {
		return "", "", "", fmt.Errorf("api/auth/check request: %w", err)
	}
	if status != 200 {
		return "", "", "", fmt.Errorf("api/auth/check status=%d body_len=%d (want 200)", status, bodyLen)
	}
	atRaw, ok := parsed["access_token"]
	accessToken, _ = atRaw.(string)
	out("STAGE E2 step=api/auth/check status=%d body_len=%d access_token_obtained=%v", status, bodyLen, ok && accessToken != "")
	if !ok || accessToken == "" {
		return "", "", "", fmt.Errorf("api/auth/check status=200 but access_token absent")
	}

	// 3. POST /api/hatch/token {vmAddress, vmName} -> token (fetch_hatch_token).
	reqBody, _ := json.Marshal(map[string]string{
		"vmAddress": "wss://" + vmID + ".metaaivm.com/",
		"vmName":    vmID,
	})
	status, bodyLen, parsed, err = doJSON(client, "POST", "https://muse.ai/api/hatch/token", hatchHeaders(cookies, accessToken), reqBody)
	if err != nil {
		return "", "", "", fmt.Errorf("api/hatch/token request: %w", err)
	}
	if status != 200 {
		return "", "", "", fmt.Errorf("api/hatch/token status=%d body_len=%d (want 200)", status, bodyLen)
	}
	tokRaw, ok := parsed["token"]
	hatchToken, _ = tokRaw.(string)
	out("STAGE E2 step=api/hatch/token status=%d body_len=%d hatch_token_obtained=%v", status, bodyLen, ok && hatchToken != "")
	if !ok || hatchToken == "" {
		return "", "", "", fmt.Errorf("api/hatch/token status=200 but token absent")
	}
	out("STAGE E2 result=PASS session=PASS auth_check=PASS hatch_token=PASS")
	return vmID, accessToken, hatchToken, nil
}

// ---- E3: WebSocket upgrade + Noise XX handshake, then CLOSE ----

func stageE3(impl, vmID, hatchToken string, useProxy bool) error {
	ctx := context.Background()
	conn, err := dialTLS(ctx, impl, gatewayHost, useProxy)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()
	// Bound the WS handshake: gorilla NewClient blocks on the upgrade.
	_ = conn.SetDeadline(time.Now().Add(stageTO))

	// Build the URL in memory only; NEVER log it (it carries auth_token).
	wsURLStr := "wss://" + gatewayHost + "/v1/noise?vm_id=" + url.QueryEscape(vmID) +
		"&auth_token=" + url.QueryEscape(hatchToken)
	if _, err := url.Parse(wsURLStr); err != nil {
		return fmt.Errorf("parse ws url: %w", err)
	}
	header := http.Header{}
	header.Set("User-Agent", ua)
	header.Set("Origin", "https://muse.ai")
	// gorilla NewClient re-runs the TLS handshake itself via Dial, which
	// double-handshakes an already-TLS conn. Use a Dialer whose
	// NetDialTLSContext returns the pre-handshaked conn: Dial then
	// assumes the handshake is done and only performs the WS upgrade.
	wsDialer := websocket.Dialer{
		HandshakeTimeout: stageTO,
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	wsConn, resp, err := wsDialer.DialContext(ctx, wsURLStr, header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		return fmt.Errorf("websocket upgrade: %w (http_status=%d)", err, status)
	}
	defer wsConn.Close()
	_ = conn.SetDeadline(time.Time{}) // handshake deadlines below govern from here

	// Noise XX initiator, ephemeral static keypair, empty payloads (gateway.py).
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	static, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		return fmt.Errorf("noise GenerateKeypair: %w", err)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		StaticKeypair: static,
	})
	if err != nil {
		return fmt.Errorf("noise NewHandshakeState: %w", err)
	}

	_ = wsConn.SetWriteDeadline(time.Now().Add(stageTO))
	msg1, _, _, err := hs.WriteMessage(nil, []byte{})
	if err != nil {
		return fmt.Errorf("noise write msg1: %w", err)
	}
	out("STAGE E3 ws_upgrade=PASS msg1_len=%d (expect 32)", len(msg1))
	if err := wsConn.WriteMessage(websocket.BinaryMessage, msg1); err != nil {
		return fmt.Errorf("ws send msg1: %w", err)
	}

	_ = wsConn.SetReadDeadline(time.Now().Add(stageTO))
	msgType, msg2, err := wsConn.ReadMessage()
	if err != nil {
		return fmt.Errorf("ws recv msg2: %w", err)
	}
	if msgType != websocket.BinaryMessage {
		return fmt.Errorf("ws msg2: message type %d, want binary", msgType)
	}
	out("STAGE E3 msg2_len=%d (expect 96)", len(msg2))
	payload, _, _, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return fmt.Errorf("noise read msg2: %w", err)
	}
	// The gateway sends a non-empty handshake payload in msg2 (36 bytes
	// measured via the proxy). Python's gateway.py discards the return
	// value of read_message, so any length is accepted here; only the
	// length is reported, the content is never logged or used.
	out("STAGE E3 msg2_payload_len=%d (content never logged)", len(payload))

	_ = wsConn.SetWriteDeadline(time.Now().Add(stageTO))
	msg3, cs1, cs2, err := hs.WriteMessage(nil, []byte{})
	if err != nil {
		return fmt.Errorf("noise write msg3: %w", err)
	}
	out("STAGE E3 msg3_len=%d (expect 64) handshake_finished=%v", len(msg3), cs1 != nil && cs2 != nil)
	if cs1 == nil || cs2 == nil {
		return fmt.Errorf("noise handshake not finished after msg3")
	}
	if err := wsConn.WriteMessage(websocket.BinaryMessage, msg3); err != nil {
		return fmt.Errorf("ws send msg3: %w", err)
	}

	// CLOSE immediately: no ServiceRequest, no subscription, no chat.stream.
	_ = wsConn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	_ = wsConn.Close()
	out("STAGE E3 result=PASS ws_url=wss://%s/v1/noise?vm_id=[REDACTED]&auth_token=[REDACTED] handshake=PASS closed_immediately=true", gatewayHost)
	return nil
}
