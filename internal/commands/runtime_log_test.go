// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// Runtime logging tests: the production wiring path
// (defaultBuildRuntime) must emit sing-box logs and castctl's own
// events through the ONE resolved factory, at the resolved level,
// to the resolved destination. These tests deliberately do NOT use
// Env.BuildRuntime (which replaces defaultBuildRuntime wholesale
// and therefore cannot prove wiring) and do NOT use the fakeStack
// harness.
//
// What each test observes: bytes in Env.Stderr (or a log file)
// after a real DNS lookup through a loopback fake DNS server.
// What the red run catches: the three NOP sites still in place
// (capture empty while the lookup succeeds), events emitted
// before resolution or from re-derived config (wrong source /
// wrong chain), and level/destination settings ignored by the
// runtime builder.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

var ansiReCmd = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSICmd(s string) string { return ansiReCmd.ReplaceAllString(s, "") }

// fakeDNSServerCmd is a TCP-only loopback DNS server (this VM
// blocks loopback UDP sendto; see internal/dns helpers). It
// answers gateway.test with A 127.0.0.1 and everything else with
// NXDOMAIN, counting queries so tests prove the configured DNS
// path was used.
type fakeDNSServerCmd struct {
	t       *testing.T
	ln      net.Listener
	addr    string
	port    int
	mu      sync.Mutex
	queries int
}

func startFakeDNSServerCmd(t *testing.T) *fakeDNSServerCmd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeDNSServerCmd{t: t, ln: ln, addr: ln.Addr().String(), port: ln.Addr().(*net.TCPAddr).Port}
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

func (s *fakeDNSServerCmd) handle(conn net.Conn) {
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
		var req dns.Msg
		if err := req.Unpack(buf); err != nil {
			return
		}
		s.mu.Lock()
		s.queries++
		s.mu.Unlock()
		resp := new(dns.Msg)
		resp.SetReply(&req)
		if len(req.Question) == 1 && req.Question[0].Name == "gateway.test." && req.Question[0].Qtype == dns.TypeA {
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1"),
			}}
		} else if len(req.Question) == 1 && req.Question[0].Name == "gateway.test." {
			// AAAA: NOERROR, no answers.
		} else {
			resp.Rcode = dns.RcodeNameError
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

func (s *fakeDNSServerCmd) queryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries
}

// fakeSOCKS5Cmd is a minimal no-auth / user-pass SOCKS5 CONNECT
// forwarder on loopback, used so DNS and dials can travel
// through a credential-bearing socks outbound whose traffic
// stays on this machine. It accepts any credentials (the test
// never asserts on them; the hard-rule scan asserts they never
// appear in logs).
type fakeSOCKS5Cmd struct {
	ln   net.Listener
	port int
}

func startFakeSOCKS5Cmd(t *testing.T) *fakeSOCKS5Cmd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSOCKS5Cmd{ln: ln, port: ln.Addr().(*net.TCPAddr).Port}
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

func (s *fakeSOCKS5Cmd) handle(conn net.Conn) {
	defer conn.Close()
	// Greeting: VER NMETHODS METHODS.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	method := byte(0x00)
	for _, m := range methods {
		if m == 0x02 {
			method = 0x02
		}
	}
	if _, err := conn.Write([]byte{0x05, method}); err != nil {
		return
	}
	if method == 0x02 {
		// RFC 1929 subnegotiation: VER ULEN UNAME PLEN PASSWD.
		auth := make([]byte, 2)
		if _, err := io.ReadFull(conn, auth); err != nil {
			return
		}
		uname := make([]byte, int(auth[1]))
		if _, err := io.ReadFull(conn, uname); err != nil {
			return
		}
		plen := make([]byte, 1)
		if _, err := io.ReadFull(conn, plen); err != nil {
			return
		}
		passwd := make([]byte, int(plen[0]))
		if _, err := io.ReadFull(conn, passwd); err != nil {
			return
		}
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	}
	// Request: VER CMD RSV ATYP ADDR PORT.
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[1] != 0x01 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return
	}
	target := net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(portBytes)))
	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(up, conn) }()
	go func() { defer wg.Done(); _, _ = io.Copy(conn, up) }()
	wg.Wait()
}

// loggedRuntime builds a real runtime from configJSON in a temp
// home, returning the runtime, the Env buffers, and the fake DNS
// server's port for config construction (callers build the JSON
// with the port). The runtime is closed by cleanup.
func loggedRuntime(t *testing.T, srv *fakeDNSServerCmd, configJSON string, env *Env) (*Runtime, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	configFile := filepath.Join(home, "config.json")
	if err := os.WriteFile(configFile, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "cookies.txt"), []byte(fakeCookie), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	if env == nil {
		env = &Env{}
	}
	env.Stdout, env.Stderr = out, errb
	if env.Getenv == nil {
		env.Getenv = mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})
	}
	prof, err := profile.LoadProfile(home, "default", env.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	loc := &profile.ConfigLocation{ConfigFile: configFile, ConfigDir: home, Explicit: true}
	rt, err := defaultBuildRuntime(context.Background(), loc, prof, env)
	if err != nil {
		t.Fatalf("defaultBuildRuntime: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	_ = srv
	return rt, out, errb
}

func dnsConfigJSON(port int, logBlock string, extraProfiles string, outbounds string) string {
	// The DNS server detours to the synthesised per-profile
	// direct tag (castctl-direct:<profile>): per-profile DNS
	// validation rejects a server with no detour, and for a
	// direct profile only the synthesised tag is reachable.
	dnsBlock := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":%d,"detour":"castctl-direct:default"}],"final":"dns1"}`, port)
	profiles := `{"default":{"dns":` + dnsBlock + `}}`
	if extraProfiles != "" {
		profiles = `{"default":{"dns":` + dnsBlock + `},` + extraProfiles + `}`
	}
	cfg := `{"profiles":` + profiles
	if outbounds != "" {
		cfg += `,"outbounds":` + outbounds
	}
	cfg += `,"log":` + logBlock + `}`
	return cfg
}

func lookupGatewayTest(t *testing.T, rt *Runtime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := rt.Resolve(ctx, "gateway.test")
	if err != nil {
		t.Fatalf("Resolve(gateway.test): %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("Resolve = %v, want [127.0.0.1]", addrs)
	}
}

// TestRuntimeFactoryWiring: sing-box DNS logs actually appear
// through the wired factory (paired control: the same trigger
// with disabled:true emits nothing, while the lookup still
// succeeds — proving the trigger, not the suppression).
func TestRuntimeFactoryWiring(t *testing.T) {
	srv := startFakeDNSServerCmd(t)
	rt, _, errb := loggedRuntime(t, srv, dnsConfigJSON(srv.port, `{"level":"trace","output":"stderr"}`, "", ""), nil)
	lookupGatewayTest(t, rt)
	_ = rt.Close()
	got := stripANSICmd(errb.String())
	if srv.queryCount() == 0 {
		t.Fatal("fake DNS server saw no queries; the lookup did not use the configured DNS")
	}
	if got == "" {
		t.Fatalf("stderr capture empty after a successful lookup at trace level; factory not wired (got %q)", errb.String())
	}
	// Sing-box's own DNS transport/router line, tagged dns1.
	if !strings.Contains(got, "dns1") {
		t.Errorf("stderr capture %q, want a sing-box line tagged dns1", got)
	}

	// Paired control: disabled suppresses everything.
	srv2 := startFakeDNSServerCmd(t)
	rt2, _, errb2 := loggedRuntime(t, srv2, dnsConfigJSON(srv2.port, `{"disabled":true,"level":"trace","output":"stderr"}`, "", ""), nil)
	lookupGatewayTest(t, rt2)
	_ = rt2.Close()
	if srv2.queryCount() == 0 {
		t.Fatal("disabled-control lookup did not reach the fake server")
	}
	if errb2.Len() != 0 {
		t.Errorf("disabled capture %q, want empty", errb2.String())
	}
}

// TestRuntimeDNSSourceAndChainEvents pins both events, their
// levels (debug), their exact fields, and per-profile isolation
// (a second profile's chain must not be reported for the active
// profile).
func TestRuntimeDNSSourceAndChainEvents(t *testing.T) {
	srv := startFakeDNSServerCmd(t)
	proxy := startFakeSOCKS5Cmd(t)
	outbounds := fmt.Sprintf(`[{"type":"direct","tag":"direct","udp_fragment":false},`+
		`{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":%d,"version":"5","detour":"direct"},`+
		`{"type":"socks","tag":"other-px","server":"127.0.0.1","server_port":%d,"version":"5","detour":"direct"}]`, proxy.port, proxy.port)
	// The default profile must reference proxy-sg for the chain
	// event; rebuild the config with the outbound reference.
	// The DNS server detours through the profile's outbound,
	// as per-profile DNS validation requires.
	dnsBlock := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":%d,"detour":"proxy-sg"}],"final":"dns1"}`, srv.port)
	cfg := `{"profiles":{"default":{"outbound":"proxy-sg","dns":` + dnsBlock + `},"other":{"outbound":"other-px"}},"outbounds":` + outbounds + `,"log":{"level":"trace","output":"stderr"}}`
	rt, _, errb := loggedRuntime(t, srv, cfg, nil)
	lookupGatewayTest(t, rt)
	_ = rt.Close()
	got := stripANSICmd(errb.String())
	if !strings.Contains(got, "event=dns_source source=profile server=dns1") {
		t.Errorf("capture %q, want the dns_source event with source=profile server=dns1", got)
	}
	if !strings.Contains(got, "event=outbound_chain profile=default chain=proxy-sg,direct") {
		t.Errorf("capture %q, want the outbound_chain event chain=proxy-sg,direct", got)
	}
	if strings.Contains(got, "profile=other") {
		t.Errorf("capture %q, want no event for the inactive profile", got)
	}
	if strings.Contains(got, "127.0.0.1") && strings.Contains(got, "event=outbound_chain") {
		// Chain lines must carry tags only; addresses belong to
		// sing-box's own lines, not to castctl's chain event.
		for _, line := range strings.Split(got, "\n") {
			if strings.Contains(line, "event=outbound_chain") && strings.Contains(line, "127.0.0.1") {
				t.Errorf("chain event line carries an address: %q", line)
			}
			if strings.Contains(line, "event=outbound_chain") && strings.Contains(line, "1080") {
				t.Errorf("chain event line carries a port: %q", line)
			}
		}
	}
}

// TestRuntimeLevelFilteringEndToEnd: the resolved level governs
// castctl's debug events through the real runtime build.
func TestRuntimeLevelFilteringEndToEnd(t *testing.T) {
	srv := startFakeDNSServerCmd(t)
	rt, _, errb := loggedRuntime(t, srv, dnsConfigJSON(srv.port, `{"level":"warn","output":"stderr"}`, "", ""), nil)
	lookupGatewayTest(t, rt)
	_ = rt.Close()
	if strings.Contains(stripANSICmd(errb.String()), "event=dns_source") {
		t.Errorf("warn-level capture %q, want the debug dns_source event suppressed", errb.String())
	}

	srv2 := startFakeDNSServerCmd(t)
	rt2, _, errb2 := loggedRuntime(t, srv2, dnsConfigJSON(srv2.port, `{"level":"trace","output":"stderr"}`, "", ""), nil)
	lookupGatewayTest(t, rt2)
	_ = rt2.Close()
	if !strings.Contains(stripANSICmd(errb2.String()), "event=dns_source") {
		t.Errorf("trace-level capture %q, want the dns_source event visible", errb2.String())
	}
}

// TestRuntimeCLIOverrideEndToEnd: --log-level (threaded through
// Env by runInner) beats the config block in both directions.
func TestRuntimeCLIOverrideEndToEnd(t *testing.T) {
	srv := startFakeDNSServerCmd(t)
	env := &Env{LogLevelOverride: "trace", LogLevelSet: true}
	rt, _, errb := loggedRuntime(t, srv, dnsConfigJSON(srv.port, `{"level":"error","output":"stderr"}`, "", ""), env)
	lookupGatewayTest(t, rt)
	_ = rt.Close()
	if !strings.Contains(stripANSICmd(errb.String()), "event=dns_source") {
		t.Errorf("CLI trace over config error: capture %q, want the event visible", errb.String())
	}

	srv2 := startFakeDNSServerCmd(t)
	env2 := &Env{LogLevelOverride: "warn", LogLevelSet: true}
	rt2, _, errb2 := loggedRuntime(t, srv2, dnsConfigJSON(srv2.port, `{"level":"trace","output":"stderr"}`, "", ""), env2)
	lookupGatewayTest(t, rt2)
	_ = rt2.Close()
	if strings.Contains(stripANSICmd(errb2.String()), "event=dns_source") {
		t.Errorf("CLI warn over config trace: capture %q, want the event suppressed", errb2.String())
	}
}

// TestRuntimeLogFileOutput: file destination receives the lines,
// stderr receives none of them, and the file mode is 0600.
func TestRuntimeLogFileOutput(t *testing.T) {
	srv := startFakeDNSServerCmd(t)
	logPath := filepath.Join(t.TempDir(), "castctl.log")
	rt, _, errb := loggedRuntime(t, srv, dnsConfigJSON(srv.port, `{"level":"trace","output":`+quoteJSON(logPath)+`}`, "", ""), nil)
	lookupGatewayTest(t, rt)
	_ = rt.Close()
	if strings.Contains(errb.String(), "event=dns_source") {
		t.Errorf("stderr %q, want no log lines when output is a file", errb.String())
	}
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("log file mode = %o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "event=dns_source source=profile server=dns1") {
		t.Errorf("log file %q, want the dns_source event", data)
	}
	if !strings.Contains(string(data), "dns1") {
		t.Errorf("log file %q, want sing-box DNS lines", data)
	}
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// TestRuntimeHardRuleCapture drives fixture-loaded configs
// through succeeding AND failing operations at trace level and
// scans the WHOLE capture (stderr and file) for every fixture
// value that ENTERS this process: the socks username/password,
// which sing-box sends in the SOCKS5 handshake to the fake
// server (the fake reads both fields, so they genuinely travel
// through the outbound). The other fixture kinds do NOT enter
// this runtime path and are deliberately NOT scanned here —
// scanning them would be hollow. Each enters elsewhere, with
// its own measured capture: session/datr/token/vm_id through
// the slog bridge (internal/logging/factory_test.go,
// TestSlogBridgeFilteringAndRedaction), the WS URL with
// vm_id+auth_token through dialWebSocket (internal/gateway),
// WG private/public keys through SafeString and the sink test
// (internal/logging/safe_test.go, factory_test.go
// TestFactorySinkRedactsSingBoxLines). Sing-box's own lines
// are in the capture too — the scan catches an unenumerated
// sing-box line echoing config material without needing its
// name.
func TestRuntimeHardRuleCapture(t *testing.T) {
	fixtures := []string{
		"LOGFIX-USER-55aa01", "LOGFIX-PW-31c7aa",
	}
	scan := func(t *testing.T, capture, path string) {
		t.Helper()
		if capture == "" {
			t.Fatalf("%s capture empty: positive control failed (suppression, not redaction)", path)
		}
		for _, v := range fixtures {
			if strings.Contains(capture, v) {
				t.Errorf("%s capture contains fixture value %q:\n%s", path, v, capture)
			}
		}
		if !strings.Contains(capture, "event=dns_source") {
			t.Errorf("%s capture %q, want the dns_source event (positive control)", path, capture)
		}
	}

	srv := startFakeDNSServerCmd(t)
	proxy := startFakeSOCKS5Cmd(t)
	outbounds := fmt.Sprintf(`[{"type":"direct","tag":"direct","udp_fragment":false},{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":%d,"version":"5","username":"LOGFIX-USER-55aa01","password":"LOGFIX-PW-31c7aa","detour":"direct"}]`, proxy.port)
	dnsBlock := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":%d,"detour":"proxy-sg"}],"final":"dns1"}`, srv.port)
	cfg := `{"profiles":{"default":{"outbound":"proxy-sg","dns":` + dnsBlock + `}},"outbounds":` + outbounds + `,"log":{"level":"trace","output":"stderr"}}`
	rt, _, errb := loggedRuntime(t, srv, cfg, nil)
	lookupGatewayTest(t, rt)
	// Failing lookup: NXDOMAIN error path through the router.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, _ = rt.Resolve(ctx, "missing.test")
	cancel()
	// Failing dial through the credential-bearing outbound to a
	// closed port: sing-box error paths that echo config run here.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	_, _ = rt.Dialer.DialContext(ctx2, "tcp", "127.0.0.1", 1)
	cancel2()
	_ = rt.Close()
	scan(t, stripANSICmd(errb.String()), "stderr")

	// File variant: same triggers, file capture scanned.
	srv2 := startFakeDNSServerCmd(t)
	proxy2 := startFakeSOCKS5Cmd(t)
	logPath := filepath.Join(t.TempDir(), "castctl.log")
	outbounds2 := fmt.Sprintf(`[{"type":"direct","tag":"direct","udp_fragment":false},{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":%d,"version":"5","username":"LOGFIX-USER-55aa01","password":"LOGFIX-PW-31c7aa","detour":"direct"}]`, proxy2.port)
	dnsBlock2 := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":%d,"detour":"proxy-sg"}],"final":"dns1"}`, srv2.port)
	cfg2 := `{"profiles":{"default":{"outbound":"proxy-sg","dns":` + dnsBlock2 + `}},"outbounds":` + outbounds2 + `,"log":{"level":"trace","output":` + quoteJSON(logPath) + `}}`
	rt2, _, _ := loggedRuntime(t, srv2, cfg2, nil)
	lookupGatewayTest(t, rt2)
	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	_, _ = rt2.Resolve(ctx3, "missing.test")
	cancel3()
	_ = rt2.Close()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	scan(t, string(data), "file")
}

// TestRuntimeLogRefusedPaths drives defaultBuildRuntime
// against a scratch home whose config names the home's own
// config/cookies file as the log output, and asserts the
// refusal (exit 2, before opening) and the untouched protected
// file. Scratch config locations only, never live paths.
func TestRuntimeLogRefusedPaths(t *testing.T) {
	for _, pick := range []string{"config", "cookies"} {
		t.Run(pick, func(t *testing.T) {
			home := t.TempDir()
			configFile := filepath.Join(home, "config.json")
			cookieFile := filepath.Join(home, "cookies.txt")
			protected := configFile
			if pick == "cookies" {
				protected = cookieFile
			}
			origConfig := `{"profiles":{"default":{}},"log":{"level":"trace","output":` + quoteJSON(protected) + `}}`
			if err := os.WriteFile(configFile, []byte(origConfig), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cookieFile, []byte(fakeCookie), 0o600); err != nil {
				t.Fatal(err)
			}
			env := &Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
			env.Getenv = mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})
			prof, err := profile.LoadProfile(home, "default", env.Getenv)
			if err != nil {
				t.Fatal(err)
			}
			loc := &profile.ConfigLocation{ConfigFile: configFile, ConfigDir: home, Explicit: true}
			rt, err := defaultBuildRuntime(context.Background(), loc, prof, env)
			if err == nil {
				_ = rt.Close()
				t.Fatalf("defaultBuildRuntime(output=%s) = nil, want refusal", protected)
			}
			if !strings.Contains(err.Error(), "refusing") {
				t.Errorf("error %q, want the refusal message", err.Error())
			}
			data, err := os.ReadFile(protected)
			if err != nil {
				t.Fatal(err)
			}
			want := origConfig
			if pick == "cookies" {
				want = fakeCookie
			}
			if string(data) != want {
				t.Errorf("protected file = %q, want untouched %q", data, want)
			}
		})
	}
}

// TestRuntimeLoggingOffByDefault: a config with NO log block and
// no --log-level flag emits NOTHING on stderr (Boss decision,
// loop 3: the castctl off-gate), while the lookup still
// succeeds — proving silence is the gate, not a broken lookup.
func TestRuntimeLoggingOffByDefault(t *testing.T) {
	srv := startFakeDNSServerCmd(t)
	rt, _, errb := loggedRuntime(t, srv, dnsConfigJSONNoLog(srv.port, "", ""), nil)
	lookupGatewayTest(t, rt)
	_ = rt.Close()
	if srv.queryCount() == 0 {
		t.Fatal("fake DNS server saw no queries; the lookup did not run")
	}
	if errb.Len() != 0 {
		t.Errorf("stderr %q, want empty when no log block and no --log-level flag", errb.String())
	}
}

// TestRuntimeEmptyLogBlockTurnsLoggingOn: an empty {} log block
// is PRESENT, so sing-box defaults apply (trace/stderr) and the
// dns_source event appears — the absent-vs-present-empty
// distinction, end to end.
func TestRuntimeEmptyLogBlockTurnsLoggingOn(t *testing.T) {
	srv := startFakeDNSServerCmd(t)
	rt, _, errb := loggedRuntime(t, srv, dnsConfigJSON(srv.port, `{}`, "", ""), nil)
	lookupGatewayTest(t, rt)
	_ = rt.Close()
	if !strings.Contains(stripANSICmd(errb.String()), "event=dns_source") {
		t.Errorf("empty-block capture %q, want the dns_source event visible", errb.String())
	}
}

// TestRuntimeCLILevelTurnsLoggingOnWhenAbsent: --log-level with
// no log block turns logging ON at that level (output stderr
// per the sing-box empty-output default).
func TestRuntimeCLILevelTurnsLoggingOnWhenAbsent(t *testing.T) {
	srv := startFakeDNSServerCmd(t)
	env := &Env{LogLevelOverride: "trace", LogLevelSet: true}
	rt, _, errb := loggedRuntime(t, srv, dnsConfigJSONNoLog(srv.port, "", ""), env)
	lookupGatewayTest(t, rt)
	_ = rt.Close()
	if !strings.Contains(stripANSICmd(errb.String()), "event=dns_source") {
		t.Errorf("CLI-trace capture %q, want the dns_source event visible", errb.String())
	}
}

// dnsConfigJSONNoLog is dnsConfigJSON without the log block:
// the off-gate case. The DNS detour/comment contract is the
// same as dnsConfigJSON's.
func dnsConfigJSONNoLog(port int, extraProfiles string, outbounds string) string {
	dnsBlock := fmt.Sprintf(`{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":%d,"detour":"castctl-direct:default"}],"final":"dns1"}`, port)
	profiles := `{"default":{"dns":` + dnsBlock + `}}`
	if extraProfiles != "" {
		profiles = `{"default":{"dns":` + dnsBlock + `},` + extraProfiles + `}`
	}
	cfg := `{"profiles":` + profiles
	if outbounds != "" {
		cfg += `,"outbounds":` + outbounds
	}
	cfg += `}`
	return cfg
}
