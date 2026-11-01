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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"golang.org/x/crypto/bcrypt"
)

const webuiTestConfig = `{"default_profile":"default","profiles":{"default":{}},"webui":{"listen":"127.0.0.1:8317","token":"BLOCK-TOKEN-UNUSED"}}`

// webuiConfigWithListen returns configJSON with webui.listen set
// to addr, preserving the other keys. The config must carry a
// webui block: after the flag removal, the block's listen key is
// the only way to choose a bind address in tests.
func webuiConfigWithListen(t *testing.T, configJSON, addr string) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(configJSON), &doc); err != nil {
		t.Fatal(err)
	}
	block, ok := doc["webui"].(map[string]any)
	if !ok {
		t.Fatalf("config has no webui block: %s", configJSON)
	}
	block["listen"] = addr
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

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
	// Block-only: no flag or env source is documented anymore.
	if strings.Contains(out, "CASTCTL_WEBUI_KEY") || strings.Contains(out, "--listen") || strings.Contains(out, "--port") {
		t.Fatalf("help = %q, must not mention removed flag/env sources", out)
	}
	if !strings.Contains(out, `"webui" block`) || !strings.Contains(out, `"token"`) {
		t.Fatalf("help = %q, want block-only token source documented", out)
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
	// Exact wording: block-only, no env alternative. (The
	// D-N1 literal "no token: set a ..." is unrenderable: the
	// SafeString backstop redacts `token: <value>` fragments,
	// so this spelling is the verbatim-rendering equivalent.)
	if !strings.Contains(errb, `webui serve: no token configured: add a "token" to the "webui" block`) {
		t.Fatalf("stderr = %q, want the exact no-token message", errb)
	}
	if strings.Contains(errb, "CASTCTL_WEBUI_KEY") {
		t.Fatalf("stderr = %q, must not name the removed env source", errb)
	}
}

func TestWebUIServeNonLoopbackListenRejected(t *testing.T) {
	// Non-loopback refusal is parse-time now: the config listen
	// key is the only listen source.
	cfg := `{"default_profile":"default","profiles":{"default":{}},"webui":{"listen":"0.0.0.0:8317","token":"BLOCK-TOKEN-UNUSED"}}`
	code, _, errb := runWebUICmd(t, cfg, nil, "webui", "serve")
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if strings.Contains(errb, "0.0.0.0") {
		t.Fatalf("stderr = %q, must not echo the rejected address", errb)
	}
	if !strings.Contains(errb, "host must be loopback") {
		t.Fatalf("stderr = %q, want the loopback rule named", errb)
	}
}

// TestWebUIServeRemovedFlagsRejected pins the removal: the old
// --listen/--port flags are unknown arguments now and exit 2
// via the shared parser, in both spellings.
func TestWebUIServeRemovedFlagsRejected(t *testing.T) {
	for _, args := range [][]string{
		{"webui", "serve", "--listen", "127.0.0.1:9000"},
		{"webui", "serve", "--port", "9000"},
		{"webui", "serve", "--listen=127.0.0.1:9000"},
		{"webui", "serve", "--port=9000"},
	} {
		t.Run(strings.Join(args[2:], " "), func(t *testing.T) {
			code, _, errb := runWebUICmd(t, webuiTestConfig, nil, args...)
			if code != 2 {
				t.Fatalf("code = %d, want 2", code)
			}
			if !strings.Contains(errb, "unrecognized argument") {
				t.Fatalf("stderr = %q, want the parser's unknown-flag message", errb)
			}
		})
	}
}

func TestWebUIServeBlockTokenStartupAndWriteBack(t *testing.T) {
	// The block token is the only token source; the server binds
	// loopback, answers authed /status, rejects unauthenticated
	// and wrong-token requests, and exits 130 on interrupt. The
	// token value must appear nowhere in stderr or responses.
	// An env token, if present, is ignored entirely. On startup
	// the plaintext block token is hashed with bcrypt and
	// written back into the config file (atomic, 0600); the
	// file keeps the other keys and their order.
	const envToken = "ENV-TOKEN-TEST-ONLY-1234"
	home, configFile := testHome(t, webuiTestConfig)

	// Pick an ephemeral loopback port to bind, via the config
	// listen key (the only listen source).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	cfg := webuiConfigWithListen(t, webuiTestConfig, fmt.Sprintf("127.0.0.1:%d", port))
	if err := os.WriteFile(configFile, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

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
		done <- Run(ctx, []string{"webui", "serve"}, env)
	}()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	// Generous timeouts: one bcrypt DefaultCost compare takes
	// ~4.2s under -race on this VM (measured 2026-11-01;
	// ~0.3s without the race detector), and serve start pays
	// one generate before listening. The 5s/10s windows the
	// SHA-256 era used cannot survive that under load.
	client := &http.Client{Timeout: 15 * time.Second}
	deadline := time.Now().Add(45 * time.Second)
	var statusOK bool
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/api/v1/status", nil)
		req.Header.Set("Authorization", "Bearer BLOCK-TOKEN-UNUSED")
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
	// Unauthenticated and wrong-token (env token) requests: 401.
	for name, tok := range map[string]string{"none": "", "env": envToken} {
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
	// Write-back: the stored token is now a bcrypt hash, the
	// other keys are untouched, and the file kept mode 0600.
	stored, err := os.ReadFile(filepath.Join(home, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(stored, &doc); err != nil {
		t.Fatal(err)
	}
	block, ok := doc["webui"].(map[string]any)
	if !ok {
		t.Fatalf("stored config has no webui block: %s", stored)
	}
	storedToken, _ := block["token"].(string)
	if !profile.LooksLikeBcryptHash(storedToken) {
		t.Fatalf("stored token is not a bcrypt hash: %s", stored)
	}
	if storedToken == "BLOCK-TOKEN-UNUSED" || storedToken == envToken {
		t.Fatalf("stored token is still plaintext: %s", stored)
	}
	if block["listen"] != addr {
		t.Fatalf("stored listen = %v, want %q", block["listen"], addr)
	}
	if st, err := os.Stat(filepath.Join(home, "config.json")); err != nil {
		t.Fatal(err)
	} else if st.Mode().Perm() != 0o600 {
		t.Errorf("config mode after write-back = %o, want 600", st.Mode().Perm())
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

// TestWebUIServeAlreadyHashedTokenNotRewritten pins the
// already-hashed path: a stored bcrypt hash is used as-is and
// the file is byte-identical after a serve start (no re-hash,
// no rewrite).
func TestWebUIServeAlreadyHashedTokenNotRewritten(t *testing.T) {
	hashBytes, err := bcrypt.GenerateFromPassword([]byte("BLOCK-TOKEN-UNUSED"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := `{"default_profile":"default","profiles":{"default":{}},"webui":{"token":` + strconv.Quote(string(hashBytes)) + `}}`
	home, addr, _, cancel, done := startWebUIServer(t, cfg, nil, "BLOCK-TOKEN-UNUSED")
	defer stopWebUIServer(t, cancel, done)
	stored, err := os.ReadFile(filepath.Join(home, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The helper wrote exactly the listen-injected config; any
	// write-back would have re-encoded it canonically.
	if want := webuiConfigWithListen(t, cfg, addr); string(stored) != want {
		t.Fatalf("config changed after serve start with a hashed token:\nstored: %s\nwant:   %s", stored, want)
	}
}

func TestWebUIServeEnvTokenIgnored(t *testing.T) {
	// CASTCTL_WEBUI_KEY is no longer a token source: with no
	// block token the serve fails closed even when the env var
	// is set, and the env value never authenticates.
	cfg := `{"default_profile":"default","profiles":{"default":{}},"webui":{}}`
	code, _, errb := runWebUICmd(t, cfg, map[string]string{"CASTCTL_WEBUI_KEY": "ENV-TOKEN-TEST-ONLY-1234"}, "webui", "serve")
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(errb, `webui serve: no token configured: add a "token" to the "webui" block`) {
		t.Fatalf("stderr = %q, want the exact no-token message", errb)
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
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	// The listen key is the only bind source: inject the
	// ephemeral address into the config copy before starting.
	if err := os.WriteFile(configFile, []byte(webuiConfigWithListen(t, configJSON, addr)), 0o600); err != nil {
		t.Fatal(err)
	}
	envMap := map[string]string{"CASTCTL_CONFIG": configFile}
	for k, v := range envExtra {
		envMap[k] = v
	}
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(envMap)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"webui", "serve"}, env)
	}()
	client := &http.Client{Timeout: 15 * time.Second}
	deadline := time.Now().Add(45 * time.Second)
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
	client := &http.Client{Timeout: 15 * time.Second}
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	cfg = webuiConfigWithListen(t, cfg, addr)
	if err := os.WriteFile(configFile, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"webui", "serve"}, env)
	}()
	client := &http.Client{Timeout: 15 * time.Second}
	deadline := time.Now().Add(45 * time.Second)
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
	client := &http.Client{Timeout: 15 * time.Second}
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

// TestResolveWebUIUIDirRelativeConfigDir is the serve-time half
// of the relative --config defect: resolveWebUIUIDir receives
// the config directory as given (relative for a relative
// --config path). An unrelated absolute ui_dir must resolve;
// every overlapping spelling must still fail closed.
func TestResolveWebUIUIDirRelativeConfigDir(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	// The accepted ui_dir must live OUTSIDE root: with a "."
	// config directory, root itself is the config directory
	// and anything under it overlaps.
	ui := filepath.Join(t.TempDir(), "ui")
	writeUIDirFiles(t, ui, map[string]string{"index.html": "<html>MARKER-REL-CFG</html>"})
	cfgDir := filepath.Join(root, "cfg")
	if err := os.MkdirAll(filepath.Join(cfgDir, "ui"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "ui", "index.html"), []byte("<html>x</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(ui)
	if err != nil {
		t.Fatal(err)
	}
	// Accept: unrelated absolute ui_dir, relative config dirs.
	for _, base := range []string{".", "cfg"} {
		got, err := resolveWebUIUIDir(&profile.WebUIConfig{UIDir: ui}, base)
		if err != nil {
			t.Fatalf("configDir %q ui_dir %q: unexpected error: %v", base, ui, err)
		}
		if got != want {
			t.Fatalf("configDir %q: resolved = %q, want %q", base, got, want)
		}
	}
	// Refuse: every overlapping spelling.
	for name, tc := range map[string]struct {
		base, uiDir string
	}{
		"relative inside":   {"cfg", "ui"},
		"dot":               {"cfg", "."},
		"equal absolute":    {"cfg", cfgDir},
		"ancestor absolute": {"cfg", root},
		"dot base equal":    {".", root},
		"dot base inside":   {".", "cfg/ui"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolveWebUIUIDir(&profile.WebUIConfig{UIDir: tc.uiDir}, tc.base); err == nil {
				t.Fatalf("configDir %q ui_dir %q: accepted, want rejection", tc.base, tc.uiDir)
			}
		})
	}
}

// serveRelativeConfig starts `webui serve` under a relative
// CASTCTL_CONFIG value from the test's working directory and
// waits for GET / to return wantBody. It fails fast (with the
// server's stderr) if the server exits before serving — the
// signature of the relative --config false refusal.
func serveRelativeConfig(t *testing.T, configValue string, port int, wantBody string) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	// Inject the ephemeral listen address into the on-disk
	// config (the only bind source): resolve configValue
	// against the test's working directory, as CASTCTL_CONFIG
	// resolution does.
	configPath := configValue
	if !filepath.IsAbs(configPath) {
		wd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		configPath = filepath.Join(wd, configValue)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(webuiConfigWithListen(t, string(raw), addr)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configValue})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"webui", "serve"}, env)
	}()
	client := &http.Client{Timeout: 15 * time.Second}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case code := <-done:
			t.Fatalf("server exited early with code %d (stderr %q), want it to serve", code, errb.String())
		default:
		}
		resp, err := client.Get("http://" + addr + "/")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(body) == wantBody {
				stopWebUIServer(t, cancel, done)
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatalf("GET / never returned the ui_dir shell; stderr = %q", errb.String())
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func writeRelativeConfigLayout(t *testing.T) (root, ui string) {
	t.Helper()
	root = t.TempDir()
	ui = filepath.Join(root, "ui")
	writeUIDirFiles(t, ui, map[string]string{"index.html": "<html>MARKER-REL-CONFIG</html>"})
	if err := os.MkdirAll(filepath.Join(root, "cfg"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`{"profiles":{},"webui":{"token":"FAKE-TOKEN-ONLY","ui_dir":%q}}`, ui)
	if err := os.WriteFile(filepath.Join(root, "cfg", "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, ui
}

// TestWebUIServeRelativeConfigCWD reproduces the live defect
// end to end: cd into the config directory, --config
// config.json (relative), unrelated absolute ui_dir.
func TestWebUIServeRelativeConfigCWD(t *testing.T) {
	root, _ := writeRelativeConfigLayout(t)
	t.Chdir(filepath.Join(root, "cfg"))
	serveRelativeConfig(t, "config.json", freeLoopbackPort(t), "<html>MARKER-REL-CONFIG</html>")
}

// TestWebUIServeRelativeConfigSubdir reproduces the live
// defect with a relative path naming a subdirectory:
// --config cfg/config.json from the parent directory.
func TestWebUIServeRelativeConfigSubdir(t *testing.T) {
	root, _ := writeRelativeConfigLayout(t)
	t.Chdir(root)
	serveRelativeConfig(t, "cfg/config.json", freeLoopbackPort(t), "<html>MARKER-REL-CONFIG</html>")
}

// TestWebUIServeRelativeConfigAbsoluteControl is the control
// for the two relative tests: the same layout with an
// absolute --config path must serve identically.
func TestWebUIServeRelativeConfigAbsoluteControl(t *testing.T) {
	root, _ := writeRelativeConfigLayout(t)
	t.Chdir(root)
	serveRelativeConfig(t, filepath.Join(root, "cfg", "config.json"), freeLoopbackPort(t), "<html>MARKER-REL-CONFIG</html>")
}

// TestWebUIServeRelativeConfigUIDirOverlapStillRefused guards
// the fix against over-loosening: under a relative --config,
// overlapping ui_dir spellings must still exit 2.
func TestWebUIServeRelativeConfigUIDirOverlapStillRefused(t *testing.T) {
	root := t.TempDir()
	cfgDir := filepath.Join(root, "cfg")
	if err := os.MkdirAll(filepath.Join(cfgDir, "ui"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cfgDir)
	for name, uiDir := range map[string]string{
		"relative inside": "ui",
		"dot":             ".",
		"equal absolute":  cfgDir,
		"ancestor":        root,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := fmt.Sprintf(`{"profiles":{},"webui":{"token":"FAKE-TOKEN-ONLY","ui_dir":%q}}`, uiDir)
			if err := os.WriteFile("config.json", []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			out, errb := &bytes.Buffer{}, &bytes.Buffer{}
			env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": "config.json"})}
			code := Run(context.Background(), []string{"webui", "serve"}, env)
			if code != 2 {
				t.Fatalf("ui_dir %q: code = %d, want 2 (stderr %q)", uiDir, code, errb.String())
			}
			if !strings.Contains(errb.String(), "ui_dir") {
				t.Fatalf("stderr = %q, want a ui_dir rule message", errb.String())
			}
		})
	}
}
