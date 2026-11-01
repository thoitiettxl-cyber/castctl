// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const webuiTestConfig = `{"default_profile":"default","profiles":{"default":{}},"webui":{"listen":"127.0.0.1:8317","token":"BLOCK-TOKEN-UNUSED"}}`

func runWebUICmd(t *testing.T, configJSON string, envExtra map[string]string, args ...string) (int, string, string) {
	t.Helper()
	_, configFile := testHome(t, configJSON)
	envMap := map[string]string{"CASTCTL_CONFIG": configFile}
	for k, v := range envExtra {
		envMap[k] = v
	}
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(envMap)}
	code := Run(context.Background(), args, env)
	return code, out.String(), errb.String()
}

func TestWebUIRequiredSubcommand(t *testing.T) {
	code, _, errb := runWebUICmd(t, webuiTestConfig, nil, "webui")
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(errb, "subcommand") {
		t.Fatalf("stderr = %q, want required-subcommand error", errb)
	}
}

func TestWebUIUnknownSubcommand(t *testing.T) {
	code, _, errb := runWebUICmd(t, webuiTestConfig, nil, "webui", "bogus")
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(errb, "invalid choice") {
		t.Fatalf("stderr = %q, want invalid-choice error", errb)
	}
}

func TestWebUIServeHelp(t *testing.T) {
	code, out, _ := runWebUICmd(t, webuiTestConfig, nil, "webui", "serve", "--help")
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(out, "CASTCTL_WEBUI_KEY") {
		t.Fatalf("help = %q, want token source documented", out)
	}
}

func TestWebUIServeAbsentBlockFailsClosed(t *testing.T) {
	code, _, errb := runWebUICmd(t, `{"default_profile":"default","profiles":{"default":{}}}`, nil, "webui", "serve")
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(errb, "webui") {
		t.Fatalf("stderr = %q, want webui-block message", errb)
	}
}

func TestWebUIServeMissingTokenFailsClosed(t *testing.T) {
	cfg := `{"default_profile":"default","profiles":{"default":{}},"webui":{}}`
	code, _, errb := runWebUICmd(t, cfg, nil, "webui", "serve")
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(errb, "no token") {
		t.Fatalf("stderr = %q, want no-token message", errb)
	}
}

func TestWebUIServeNonLoopbackListenRejected(t *testing.T) {
	code, _, errb := runWebUICmd(t, webuiTestConfig, nil, "webui", "serve", "--listen", "0.0.0.0:8317")
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if strings.Contains(errb, "0.0.0.0") {
		t.Fatalf("stderr = %q, must not echo the rejected address", errb)
	}
}

func TestWebUIServeListenAndPortTogetherRejected(t *testing.T) {
	code, _, _ := runWebUICmd(t, webuiTestConfig, nil, "webui", "serve", "--listen", "127.0.0.1:8317", "--port", "9000")
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
}

func TestWebUIServeEnvTokenPrecedenceAndStartup(t *testing.T) {
	// The env token wins over the block token; the server binds
	// loopback, answers authed /status, rejects unauthenticated
	// and wrong-token requests, and exits 130 on interrupt. The
	// token value must appear nowhere in stderr or responses.
	const envToken = "ENV-TOKEN-TEST-ONLY-1234"
	_, configFile := testHome(t, webuiTestConfig)

	// Pick an ephemeral loopback port to bind.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{
		Stdout: out,
		Stderr: errb,
		Getenv: mapGetenv(map[string]string{
			"CASTCTL_CONFIG":    configFile,
			"CASTCTL_WEBUI_KEY": envToken,
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"webui", "serve", "--port", fmt.Sprint(port)}, env)
	}()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	var statusOK bool
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/api/v1/status", nil)
		req.Header.Set("Authorization", "Bearer "+envToken)
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var decoded struct {
					Data struct {
						RemoteExposure bool `json:"remote_exposure"`
					} `json:"data"`
				}
				if err := json.Unmarshal(body, &decoded); err != nil {
					t.Fatalf("status body = %q: %v", body, err)
				}
				if decoded.Data.RemoteExposure {
					t.Fatalf("status remote_exposure = true, want false (loopback-only)")
				}
				if strings.Contains(string(body), envToken) || strings.Contains(string(body), "BLOCK-TOKEN-UNUSED") {
					t.Fatalf("status body leaks a token: %q", body)
				}
				statusOK = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !statusOK {
		cancel()
		<-done
		t.Fatalf("server did not answer authed /status; stderr = %q", errb.String())
	}
	// Unauthenticated and wrong-token (block token) requests: 401.
	for name, tok := range map[string]string{"none": "", "block": "BLOCK-TOKEN-UNUSED"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/api/v1/status", nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", name, resp.StatusCode)
		}
	}
	if strings.Contains(errb.String(), envToken) || strings.Contains(errb.String(), "BLOCK-TOKEN-UNUSED") {
		t.Fatalf("stderr leaks a token: %q", errb.String())
	}
	if !strings.Contains(errb.String(), addr) {
		t.Fatalf("stderr = %q, want the listen address named", errb.String())
	}
	cancel()
	select {
	case code := <-done:
		if code != 130 {
			t.Fatalf("code = %d, want 130 on interrupt", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down on context cancel")
	}
}

func TestWebUIServeWhitespaceEnvTokenCountsAsUnset(t *testing.T) {
	// A whitespace-only CASTCTL_WEBUI_KEY must count as unset:
	// it can never authenticate (the token is compared exactly),
	// so with no block token the serve must fail closed.
	cfg := `{"default_profile":"default","profiles":{"default":{}},"webui":{}}`
	code, _, errb := runWebUICmd(t, cfg, map[string]string{"CASTCTL_WEBUI_KEY": "   "}, "webui", "serve")
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(errb, "no token") {
		t.Fatalf("stderr = %q, want no-token message", errb)
	}
}

// --- ui_dir (webui serve from an on-disk frontend) -----------

func webuiConfigWithUIDir(t *testing.T, uiDir string) string {
	t.Helper()
	uiJSON, err := json.Marshal(uiDir)
	if err != nil {
		t.Fatal(err)
	}
	return `{"default_profile":"default","profiles":{"default":{}},"webui":{"listen":"127.0.0.1:8317","token":"BLOCK-TOKEN-TEST","ui_dir":` + string(uiJSON) + `}}`
}

func writeUIDirFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// startWebUIServer starts a real loopback server for the given
// config and waits until authed /status answers. It returns the
// test home (the config directory), the listen address, the
// stderr buffer, and a cancel/done pair; the caller cancels and
// expects exit 130.
func startWebUIServer(t *testing.T, configJSON string, envExtra map[string]string, statusToken string) (string, string, *bytes.Buffer, context.CancelFunc, chan int) {
	t.Helper()
	home, configFile := testHome(t, configJSON)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	envMap := map[string]string{"CASTCTL_CONFIG": configFile}
	for k, v := range envExtra {
		envMap[k] = v
	}
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(envMap)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"webui", "serve", "--port", fmt.Sprint(port)}, env)
	}()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/api/v1/status", nil)
		req.Header.Set("Authorization", "Bearer "+statusToken)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return home, addr, errb, cancel, done
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatalf("server did not answer authed /status; stderr = %q", errb.String())
	return "", "", nil, nil, nil
}

func stopWebUIServer(t *testing.T, cancel context.CancelFunc, done chan int) {
	t.Helper()
	cancel()
	select {
	case code := <-done:
		if code != 130 {
			t.Fatalf("code = %d, want 130 on interrupt", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down on context cancel")
	}
}

func TestWebUIServeUIDirServesOnDiskUI(t *testing.T) {
	uiDir := t.TempDir()
	const shellMarker = "<html>MARKER-UIDIR-SHELL</html>"
	writeUIDirFiles(t, uiDir, map[string]string{
		"index.html": shellMarker,
		"app.js":     "MARKER-UIDIR-JS",
	})
	_, addr, errb, cancel, done := startWebUIServer(t, webuiConfigWithUIDir(t, uiDir), nil, "BLOCK-TOKEN-TEST")
	defer stopWebUIServer(t, cancel, done)
	client := &http.Client{Timeout: 5 * time.Second}
	// The on-disk shell and assets, unauthenticated.
	for path, want := range map[string]string{"/": shellMarker, "/app.js": "MARKER-UIDIR-JS"} {
		resp, err := client.Get("http://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != want {
			t.Fatalf("GET %s: %d %q, want %q", path, resp.StatusCode, body, want)
		}
	}
	resp, err := client.Get("http://" + addr + "/app.js")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Fatalf("app.js Content-Type = %q", ct)
	}
	// Status bundle hash is the ON-DISK shell's hash.
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer BLOCK-TOKEN-TEST")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var decoded struct {
		Data struct {
			BundleSHA256 string `json:"bundle_sha256"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("status body = %q: %v", body, err)
	}
	wantHash := sha256HexForTest(t, filepath.Join(uiDir, "index.html"))
	if decoded.Data.BundleSHA256 != wantHash {
		t.Fatalf("bundle_sha256 = %q, want on-disk hash %q", decoded.Data.BundleSHA256, wantHash)
	}
	// Unauthenticated fetch of a config path: shell fallback,
	// never config content (the token is in the config file).
	resp, err = client.Get("http://" + addr + "/config.json")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != shellMarker {
		t.Fatalf("GET /config.json: %d %q, want the shell fallback", resp.StatusCode, body)
	}
	if strings.Contains(errb.String(), "BLOCK-TOKEN-TEST") {
		t.Fatalf("stderr leaks the token: %q", errb.String())
	}
}

func sha256HexForTest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestWebUIServeUIDirFailsClosed(t *testing.T) {
	home, _ := testHome(t, webuiTestConfig)
	_ = home
	cases := []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{"missing", func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "MARKER-UIDIR-MISSING")
		}},
		{"file not dir", func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "afile")
			if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"no index.html", func(t *testing.T) string {
			return t.TempDir()
		}},
		{"symlinked index.html", func(t *testing.T) string {
			secret := filepath.Join(t.TempDir(), "secret.txt")
			if err := os.WriteFile(secret, []byte("MARKER-CMD-SECRET"), 0o600); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if err := os.Symlink(secret, filepath.Join(dir, "index.html")); err != nil {
				t.Fatal(err)
			}
			return dir
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uiDir := tc.setup(t)
			code, _, errb := runWebUICmd(t, webuiConfigWithUIDir(t, uiDir), nil, "webui", "serve")
			if code != 2 {
				t.Fatalf("code = %d, want 2", code)
			}
			if !strings.Contains(errb, "ui_dir") {
				t.Fatalf("stderr = %q, want a ui_dir rule message", errb)
			}
			if strings.Contains(errb, "MARKER-UIDIR") || strings.Contains(errb, uiDir) {
				t.Fatalf("stderr echoes the value: %q", errb)
			}
		})
	}
}

func TestWebUIServeUIDirOverlapFailsClosed(t *testing.T) {
	home, configFile := testHome(t, webuiTestConfig)
	inside := filepath.Join(home, "ui")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "MARKER-UIDIR-LINK")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	for name, uiDir := range map[string]string{
		"equal":    home,
		"inside":   inside,
		"ancestor": filepath.Dir(home),
		"symlink":  link,
		"relative": "ui",
		"dot":      ".",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := webuiConfigWithUIDir(t, uiDir)
			// Rewrite the config file in place: the config
			// directory is home, so relative values resolve
			// against it exactly as on a real host.
			if err := os.WriteFile(configFile, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			out, errb := &bytes.Buffer{}, &bytes.Buffer{}
			env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
			code := Run(context.Background(), []string{"webui", "serve"}, env)
			if code != 2 {
				t.Fatalf("ui_dir %q: code = %d, want 2 (stderr %q)", uiDir, code, errb.String())
			}
			if strings.Contains(errb.String(), "MARKER-UIDIR") {
				t.Fatalf("stderr echoes the value: %q", errb.String())
			}
		})
	}
}

func TestWebUIServeUIDirRelativeOutsideServes(t *testing.T) {
	home, configFile := testHome(t, webuiTestConfig)
	// A sibling of the config directory, reached relatively.
	uiDir := filepath.Join(filepath.Dir(home), "shared-ui")
	if err := os.MkdirAll(uiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const shellMarker = "<html>MARKER-RELATIVE-UIDIR</html>"
	if err := os.WriteFile(filepath.Join(uiDir, "index.html"), []byte(shellMarker), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := webuiConfigWithUIDir(t, "../shared-ui")
	if err := os.WriteFile(configFile, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"webui", "serve", "--port", fmt.Sprint(port)}, env)
	}()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + addr + "/")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				got = string(body)
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got != shellMarker {
		cancel()
		<-done
		t.Fatalf("GET /: %q, want the relative ui_dir shell; stderr = %q", got, errb.String())
	}
	stopWebUIServer(t, cancel, done)
}

func TestWebUIServeUIDirExposesCookiesFailsClosed(t *testing.T) {
	uiDir := t.TempDir()
	writeUIDirFiles(t, uiDir, map[string]string{"index.html": "<html>x</html>"})
	cookiesFile := filepath.Join(uiDir, "cookies.txt")
	if err := os.WriteFile(cookiesFile, []byte("MARKER-COOKIE-CONTENT"), 0o600); err != nil {
		t.Fatal(err)
	}
	cookiesJSON, _ := json.Marshal(cookiesFile)
	uiJSON, _ := json.Marshal(uiDir)
	cfg := `{"default_profile":"default","profiles":{"default":{"cookies_file":` + string(cookiesJSON) + `}},"webui":{"listen":"127.0.0.1:8317","token":"BLOCK-TOKEN-TEST","ui_dir":` + string(uiJSON) + `}}`
	code, _, errb := runWebUICmd(t, cfg, nil, "webui", "serve")
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if strings.Contains(errb, "MARKER-COOKIE") || strings.Contains(errb, uiDir) {
		t.Fatalf("stderr echoes a value: %q", errb)
	}
	content, err := os.ReadFile(cookiesFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "MARKER-COOKIE-CONTENT" {
		t.Fatalf("cookies file changed: %q", content)
	}
}

func TestWebUIServeUIDirEscalationViaAPI(t *testing.T) {
	// B-1 escalation: an authenticated user sets ui_dir to the
	// config directory via PUT /config, then fetches config.json
	// unauthenticated. The PUT must fail and the fetch must
	// return the shell, never config content.
	uiDir := t.TempDir()
	const shellMarker = "<html>MARKER-ESCALATION-SHELL</html>"
	writeUIDirFiles(t, uiDir, map[string]string{"index.html": shellMarker})
	home, addr, _, cancel, done := startWebUIServer(t, webuiConfigWithUIDir(t, uiDir), nil, "BLOCK-TOKEN-TEST")
	defer stopWebUIServer(t, cancel, done)
	configFile := filepath.Join(home, "config.json")
	before, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	// GET the redacted view, set ui_dir to the config dir, PUT.
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/api/v1/config", nil)
	req.Header.Set("Authorization", "Bearer BLOCK-TOKEN-TEST")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var env struct {
		Data struct {
			Content string `json:"content"`
			SHA256  string `json:"sha256"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("GET config body = %q: %v", body, err)
	}
	doc := map[string]any{}
	if err := json.Unmarshal([]byte(env.Data.Content), &doc); err != nil {
		t.Fatal(err)
	}
	doc["webui"].(map[string]any)["ui_dir"] = home
	edited, _ := json.Marshal(doc)
	putBody, _ := json.Marshal(map[string]any{"content": string(edited), "base_sha256": env.Data.SHA256})
	req, _ = http.NewRequest(http.MethodPut, "http://"+addr+"/api/v1/config", strings.NewReader(string(putBody)))
	req.Header.Set("Authorization", "Bearer BLOCK-TOKEN-TEST")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	putResp, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT escalation: %d, want 400: %s", resp.StatusCode, putResp)
	}
	after, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("config file changed:\n%s", after)
	}
	// Unauthenticated fetch: shell fallback, no config content.
	resp, err = client.Get("http://" + addr + "/config.json")
	if err != nil {
		t.Fatal(err)
	}
	fetchBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(fetchBody) != shellMarker {
		t.Fatalf("GET /config.json: %d %q, want the shell", resp.StatusCode, fetchBody)
	}
	if strings.Contains(string(fetchBody), "BLOCK-TOKEN-TEST") {
		t.Fatal("token leaked into unauthenticated fetch")
	}
}
