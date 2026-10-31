// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
