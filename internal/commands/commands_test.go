// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway/gatewaytest"
	pb "github.com/thoitiettxl-cyber/castctl/internal/proto"
)

const fakeCookie = "hatch_sess=FAKE; datr=FAKE"

// testHome writes a single-file config (direct profile) plus a fake
// cookies file into a temp dir, and returns the dir and the config
// file path.
func testHome(t *testing.T, configJSON string) (string, string) {
	t.Helper()
	home := t.TempDir()
	if configJSON == "" {
		configJSON = `{"default_profile":"default","profiles":{"default":{}}}`
	}
	configFile := filepath.Join(home, "config.json")
	if err := os.WriteFile(configFile, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "cookies.txt"), []byte(fakeCookie), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, configFile
}

func mapGetenv(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// fakeStack is the hermetic end-to-end harness: a real runtime
// wiring (manager + direct outbound) with the gateway connector and
// the HTTPS client replaced by gatewaytest fakes. No live network,
// no real home, no proxy env.
type fakeStack struct {
	env    *Env
	out    *bytes.Buffer
	errb   *bytes.Buffer
	server *gatewaytest.Server
	dialer *gatewaytest.FakeDialer
	auth   *gatewaytest.CannedAuth
}

func newFakeStack(t *testing.T, handler gatewaytest.Handler, httpExtra http.Handler) *fakeStack {
	t.Helper()
	if handler == nil {
		handler = gatewaytest.JSONHandler(200, []byte(`{"ok":true,"result":{}}`))
	}
	server, err := gatewaytest.NewServer(handler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT-FAKE", HatchToken: "HT-FAKE"}
	combined := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/session", "/api/auth/check", "/api/hatch/token":
			auth.ServeHTTP(w, r)
		default:
			if httpExtra != nil {
				httpExtra.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
		}
	})
	dialer := gatewaytest.NewFakeDialer(server, combined)
	_, configFile := testHome(t, "")
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{
		Stdout: out,
		Stderr: errb,
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile}),
		// The connector hook ignores the real dialer and uses the
		// fake one: the Noise handshake runs against the fake
		// server on loopback, never the live gateway.
		NewConnector: func(gateway.OutboundDialer, ...gateway.ConnectorOption) conn.Connector {
			return gateway.NewConnector(dialer, gateway.WithWebSocketSecure(false))
		},
		HTTPClient: func() *http.Client { return dialer.HTTPClient() },
	}
	return &fakeStack{env: env, out: out, errb: errb, server: server, dialer: dialer, auth: auth}
}

// run invokes Run and returns the exit code.
func (s *fakeStack) run(args ...string) int {
	s.out.Reset()
	s.errb.Reset()
	return Run(context.Background(), args, s.env)
}

// routeHandler answers gateway calls by route path, returning the
// given JSON as {"ok":true,"result":<json>}. GET bodies become
// query strings on the wire path, so the query is stripped before
// matching.
func routeHandler(routes map[string]string) gatewaytest.Handler {
	return gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		path, _, _ := strings.Cut(req.GetPath(), "?")
		body, ok := routes[path]
		if !ok {
			body = `{}`
		}
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte(`{"ok":true,"result":`+body+`}`), true),
		}}
	})
}

func mustJSON(t *testing.T, data []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("unmarshal %q: %v", data, err)
	}
}

func TestDeferredCommands(t *testing.T) {
	_, configFile := testHome(t, "")
	env := &Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	cases := map[string]string{
		"telegram": "PR5", "update": "PR5",
	}
	for cmd, pr := range cases {
		out, errb := &bytes.Buffer{}, &bytes.Buffer{}
		env.Stdout, env.Stderr = out, errb
		code := Run(context.Background(), []string{cmd}, env)
		if code != 2 || !strings.Contains(errb.String(), pr) {
			t.Errorf("%s: code=%d err=%q, want 2 naming %s", cmd, code, errb.String(), pr)
		}
	}
	// --help still exits 0 for deferred commands.
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env.Stdout, env.Stderr = out, errb
	if code := Run(context.Background(), []string{"telegram", "--help"}, env); code != 0 {
		t.Errorf("telegram --help: code=%d, want 0", code)
	}
	if !strings.Contains(out.String(), "PR5") {
		t.Errorf("telegram --help: %q, want PR5 note", out.String())
	}
	// Wired PR4 commands no longer carry a deferred note.
	out, errb = &bytes.Buffer{}, &bytes.Buffer{}
	env.Stdout, env.Stderr = out, errb
	if code := Run(context.Background(), []string{"send", "--help"}, env); code != 0 {
		t.Errorf("send --help: code=%d, want 0", code)
	}
	if strings.Contains(out.String(), "PR4") || !strings.Contains(out.String(), "usage: castctl send") {
		t.Errorf("send --help: %q, want usage without a PR4 note", out.String())
	}
	// Truly unknown commands are distinguished from deferred ones.
	out, errb = &bytes.Buffer{}, &bytes.Buffer{}
	env.Stdout, env.Stderr = out, errb
	if code := Run(context.Background(), []string{"nope"}, env); code != 2 || strings.Contains(errb.String(), "is not implemented") {
		t.Errorf("unknown: code=%d err=%q", code, errb.String())
	}
}

func TestParserRejections(t *testing.T) {
	s := newFakeStack(t, nil, nil)
	for _, args := range [][]string{
		{"status", "--bogus"},
		{"status", "--json=true"},
		{"history", "--limit", "abc"},
		{"history", "--limit"},
		{"threads", "extra"},
		{"redeem"},
		{"feed-react"},
		{"raw"},
		{"raw", "sessions.list", "--param", "nokey"},
		{"--bogus"},
		{"-x"},
		{"--profile"},
		{"--config", ""},
	} {
		if code := s.run(args...); code != 2 {
			t.Errorf("%v: code=%d, want 2 (out=%q err=%q)", args, code, s.out.String(), s.errb.String())
		}
	}
}

func TestHelpMentions(t *testing.T) {
	_, configFile := testHome(t, "")
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	if code := Run(context.Background(), []string{"--help"}, env); code != 0 {
		t.Fatalf("--help: code=%d", code)
	}
	for _, want := range []string{"--config", "CASTCTL_CONFIG", "XDG", "fingerprint", "tls_engine", "browser"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("global help missing %q", want)
		}
	}
	// Per-command help: profile set-fingerprint states storage-only.
	out.Reset()
	if code := Run(context.Background(), []string{"profile", "set-fingerprint", "--help"}, env); code != 0 {
		t.Fatalf("set-fingerprint --help: code=%d", code)
	}
	if !strings.Contains(out.String(), "STORAGE ONLY") {
		t.Errorf("set-fingerprint help must state storage-only: %q", out.String())
	}
	out.Reset()
	if code := Run(context.Background(), []string{"profile", "set-tls-engine", "--help"}, env); code != 0 {
		t.Fatalf("set-tls-engine --help: code=%d", code)
	}
	if !strings.Contains(out.String(), "utls") || !strings.Contains(out.String(), "cronet") {
		t.Errorf("set-tls-engine help must state the TLS-engine decision: %q", out.String())
	}
}

func TestConfigLocationPrecedence(t *testing.T) {
	home := t.TempDir()
	// Three candidate homes: default (XDG), env, flag.
	defaultDir := filepath.Join(home, "xdg", "castctl")
	envDir := filepath.Join(home, "envdir")
	flagDir := filepath.Join(home, "flagdir")
	for _, dir := range []string{defaultDir, envDir, flagDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(fmt.Sprintf(`{"default_profile":"default","profiles":{"default":{"vm_id":%q}}}`, dir)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runWith := func(t *testing.T, getenv map[string]string, args ...string) (int, string, string) {
		t.Helper()
		out, errb := &bytes.Buffer{}, &bytes.Buffer{}
		env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(getenv)}
		// `profile show` prints the resolved profile's paths; the
		// cookies_file path reveals which home won.
		code := Run(context.Background(), args, env)
		return code, out.String(), errb.String()
	}
	// XDG beats the built-in default.
	code, out, _ := runWith(t, map[string]string{"XDG_CONFIG_HOME": filepath.Join(home, "xdg"), "HOME": home}, "profile", "show")
	if code != 0 {
		t.Fatalf("xdg: code=%d out=%q", code, out)
	}
	if !strings.Contains(out, filepath.Join(defaultDir, "cookies.txt")) {
		t.Errorf("XDG home not used: %q", out)
	}
	// Env beats XDG.
	code, out, _ = runWith(t, map[string]string{"XDG_CONFIG_HOME": filepath.Join(home, "xdg"), "HOME": home, "CASTCTL_CONFIG": filepath.Join(envDir, "config.json")}, "profile", "show")
	if code != 0 || !strings.Contains(out, filepath.Join(envDir, "cookies.txt")) {
		t.Errorf("env-beats-XDG: code=%d out=%q", code, out)
	}
	// Flag beats env.
	code, out, _ = runWith(t, map[string]string{"XDG_CONFIG_HOME": filepath.Join(home, "xdg"), "HOME": home, "CASTCTL_CONFIG": filepath.Join(envDir, "config.json")}, "--config", filepath.Join(flagDir, "config.json"), "profile", "show")
	if code != 0 || !strings.Contains(out, filepath.Join(flagDir, "cookies.txt")) {
		t.Errorf("flag-beats-env: code=%d out=%q", code, out)
	}
	// --config pointing at a directory exits 2.
	if code, _, _ := runWith(t, map[string]string{"HOME": home}, "--config", flagDir, "profile", "show"); code != 2 {
		t.Errorf("config-is-dir: code=%d, want 2", code)
	}
	// Missing explicit file exits 2.
	if code, _, _ := runWith(t, map[string]string{"HOME": home}, "--config", filepath.Join(home, "nope", "config.json"), "profile", "show"); code != 2 {
		t.Errorf("config-missing: code=%d, want 2", code)
	}
	// Missing default location: profile show still works (defaults).
	code, out, _ = runWith(t, map[string]string{"XDG_CONFIG_HOME": filepath.Join(home, "empty"), "HOME": home}, "profile", "show")
	if code != 0 {
		t.Errorf("missing-default: code=%d out=%q", code, out)
	}
}

func TestConfigLocationXDGEdgeCases(t *testing.T) {
	home := t.TempDir()
	runShow := func(getenv map[string]string) (int, string, string) {
		out, errb := &bytes.Buffer{}, &bytes.Buffer{}
		env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(getenv)}
		code := Run(context.Background(), []string{"profile", "show"}, env)
		return code, out.String(), errb.String()
	}
	// Relative XDG_CONFIG_HOME warns and falls back to $HOME/.config.
	code, out, errb := runShow(map[string]string{"XDG_CONFIG_HOME": "relative/path", "HOME": home})
	if code != 0 {
		t.Fatalf("relative XDG: code=%d", code)
	}
	if !strings.Contains(errb, "warning") {
		t.Errorf("relative XDG: no warning on stderr: %q", errb)
	}
	if !strings.Contains(out, filepath.Join(home, ".config", "castctl", "cookies.txt")) {
		t.Errorf("relative XDG: fallback not used: %q", out)
	}
	// Empty XDG_CONFIG_HOME means default.
	code, out, _ = runShow(map[string]string{"XDG_CONFIG_HOME": "", "HOME": home})
	if code != 0 || !strings.Contains(out, filepath.Join(home, ".config", "castctl", "cookies.txt")) {
		t.Errorf("empty XDG: code=%d out=%q", code, out)
	}
	// Relative explicit --config resolves under the CWD.
	cwd := t.TempDir()
	relDir := filepath.Join(cwd, "cfg")
	if err := os.MkdirAll(relDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(relDir, "config.json"), []byte(`{"profiles":{"default":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	outb, errb2 := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: outb, Stderr: errb2, Getenv: mapGetenv(map[string]string{"HOME": home})}
	if code := Run(context.Background(), []string{"--config", "cfg/config.json", "profile", "show"}, env); code != 0 {
		t.Fatalf("relative --config: code=%d err=%q", code, errb2.String())
	}
	if !strings.Contains(outb.String(), filepath.Join("cfg", "cookies.txt")) {
		t.Errorf("relative --config: dir not CWD-relative: %q", outb.String())
	}
}

func TestTypedAuthErrors(t *testing.T) {
	// Auth-check failure (401) -> typed JSON, exit 2, never 0.
	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT", HatchToken: "HT", AuthCheckStatus: 401}
	server, err := gatewaytest.NewServer(gatewaytest.JSONHandler(200, []byte(`{"ok":true,"result":{}}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	dialer := gatewaytest.NewFakeDialer(server, auth)
	_, configFile := testHome(t, "")
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{
		Stdout: out, Stderr: errb,
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile}),
		NewConnector: func(d gateway.OutboundDialer, opts ...gateway.ConnectorOption) conn.Connector {
			return gateway.NewConnector(dialer, gateway.WithWebSocketSecure(false))
		},
		HTTPClient: func() *http.Client { return dialer.HTTPClient() },
	}
	code := Run(context.Background(), []string{"status"}, env)
	if code != 2 {
		t.Fatalf("auth-check 401: code=%d, want 2 (out=%q err=%q)", code, out.String(), errb.String())
	}
	var typed map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(errb.String())), &typed); err != nil {
		t.Fatalf("stderr is not typed JSON: %q: %v", errb.String(), err)
	}
	if typed["type"] != "auth_check_failed" {
		t.Errorf("type=%q, want auth_check_failed", typed["type"])
	}
	if strings.Contains(errb.String(), "FAKE") {
		t.Errorf("stderr leaked a cookie value: %q", errb.String())
	}

	// Missing cookies file -> cookies_missing, exit 2.
	home := t.TempDir()
	configFile2 := filepath.Join(home, "config.json")
	if err := os.WriteFile(configFile2, []byte(`{"profiles":{"default":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	env.Getenv = mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile2})
	code = Run(context.Background(), []string{"status"}, env)
	if code != 2 {
		t.Fatalf("missing cookies: code=%d, want 2", code)
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(errb.String())), &typed); err != nil || typed["type"] != "cookies_missing" {
		t.Errorf("missing cookies: type=%v err=%q", typed, errb.String())
	}

	// Session without vm_id -> session_unavailable, exit 2.
	auth2 := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT", HatchToken: "HT", SessionNoVMID: true}
	dialer2 := gatewaytest.NewFakeDialer(server, auth2)
	env.NewConnector = func(d gateway.OutboundDialer, opts ...gateway.ConnectorOption) conn.Connector {
		return gateway.NewConnector(dialer2, gateway.WithWebSocketSecure(false))
	}
	env.HTTPClient = func() *http.Client { return dialer2.HTTPClient() }
	env.Getenv = mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})
	out.Reset()
	errb.Reset()
	code = Run(context.Background(), []string{"status"}, env)
	if code != 2 {
		t.Fatalf("no vm_id: code=%d, want 2 (err=%q)", code, errb.String())
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(errb.String())), &typed); err != nil || typed["type"] != "session_unavailable" {
		t.Errorf("no vm_id: type=%v err=%q", typed, errb.String())
	}
}

func TestPromptSeam(t *testing.T) {
	// The Prompt seam injects answers without touching stdin: no
	// PR3 command prompts, so this pins the seam itself (default
	// reads stdin, injected func wins).
	asked := ""
	env := &Env{
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
		Stdin: strings.NewReader("from-stdin\n"),
		Prompt: func(prompt string) (string, error) {
			asked = prompt
			return "injected-answer", nil
		},
	}
	ans, err := env.prompt("Token? ")
	if err != nil || ans != "injected-answer" || asked != "Token? " {
		t.Fatalf("prompt seam: ans=%q asked=%q err=%v", ans, asked, err)
	}
	// Default prompt reads one line from stdin.
	env2 := &Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Stdin: strings.NewReader("hello\n")}
	ans, err = env2.prompt("P: ")
	if err != nil || ans != "hello" {
		t.Fatalf("default prompt: ans=%q err=%v", ans, err)
	}
}
