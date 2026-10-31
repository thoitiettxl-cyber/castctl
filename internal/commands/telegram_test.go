// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// Command-level tests for `telegram run` / `telegram status`.
// The bot's HTTP client is the fake runtime's client, whose
// transport redirects every request to a loopback fake Telegram
// server: this proves the command wires the bot to the runtime
// client (the linked profile's outbound in production), never
// to a default client. Fixture token only; no live network.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

const telegramTestToken = "123456:FAKE-TOKEN-0123456789ABCD"

func telegramTestConfig() string {
	return `{"default_profile":"default","profiles":{"default":{},"muse01":{}},"telegram":{"profile":"muse01","token":"` + telegramTestToken + `","allowed_user_ids":[111],"auto_approve":true}}`
}

func telegramTestEnv(t *testing.T, configJSON string) (*Env, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	_, configFile := testHome(t, configJSON)
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	return env, out, errb
}

// cmdFakeTelegram is a minimal Bot API fake: getMe, getUpdates
// (one message batch, then empty), sendMessage. It records
// method names only; the request path (token-bearing) is never
// stored.
type cmdFakeTelegram struct {
	mu      sync.Mutex
	methods []string
	sends   []string
	served  bool
}

func (f *cmdFakeTelegram) handler(w http.ResponseWriter, r *http.Request) {
	method := strings.TrimPrefix(r.URL.Path, "/bot"+telegramTestToken+"/")
	method = strings.Trim(method, "/")
	f.mu.Lock()
	f.methods = append(f.methods, method)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch method {
	case "getMe":
		fmt.Fprint(w, `{"ok":true,"result":{"id":1,"is_bot":true,"first_name":"Fake","username":"fakebot"}}`)
	case "getUpdates":
		f.mu.Lock()
		served := f.served
		f.served = true
		f.mu.Unlock()
		if !served {
			fmt.Fprint(w, `{"ok":true,"result":[{"update_id":1,"message":{"message_id":1,"date":1700000000,"chat":{"id":500,"type":"private"},"from":{"id":111,"is_bot":false,"first_name":"Tester"},"text":"hello"}}]}`)
			return
		}
		time.Sleep(5 * time.Millisecond)
		fmt.Fprint(w, `{"ok":true,"result":[]}`)
	case "sendMessage":
		text := ""
		if err := r.ParseMultipartForm(1 << 20); err == nil && r.MultipartForm != nil {
			text = r.MultipartForm.Value["text"][0]
		} else if err := r.ParseForm(); err == nil {
			text = r.Form.Get("text")
		}
		f.mu.Lock()
		f.sends = append(f.sends, text)
		f.mu.Unlock()
		fmt.Fprint(w, `{"ok":true,"result":{"message_id":100,"chat":{"id":500,"type":"private"},"date":0,"text":"ok"}}`)
	default:
		fmt.Fprint(w, `{"ok":false,"error_code":404,"description":"Not Found"}`)
	}
}

func (f *cmdFakeTelegram) saw(method string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.methods {
		if m == method {
			return true
		}
	}
	return false
}

// The fake client below is a plain *http.Transport whose dial
// functions dial the fake server's listener whatever address
// the Bot API URL names (BoundClient rejects delegating
// RoundTrippers, so the fake cannot rewrite URLs at the
// RoundTripper layer). DialTLSContext returns the plain
// connection: the fake is plain HTTP, and the transport must
// not TLS-handshake to it. The token-bearing path is kept
// intact for the fake's own method extraction, but is never
// stored.

func TestTelegramStatus(t *testing.T) {
	t.Parallel()
	env, out, errb := telegramTestEnv(t, telegramTestConfig())
	if code := Run(context.Background(), []string{"telegram", "status"}, env); code != 0 {
		t.Fatalf("status: code=%d err=%q, want 0", code, errb.String())
	}
	var st telegramStatus
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		t.Fatalf("status output is not JSON: %v (%q)", err, out.String())
	}
	if !st.Configured || st.Profile != "muse01" || st.AllowedUsers != 1 || !st.AutoApprove || st.AutoAllowOnce || !st.TokenValid {
		t.Errorf("status = %+v; want configured/muse01/1/auto-approve on/once off/valid", st)
	}
	if strings.Contains(out.String(), telegramTestToken) || strings.Contains(errb.String(), telegramTestToken) {
		t.Error("token value appears in status output")
	}
}

func TestTelegramStatusAbsentBlock(t *testing.T) {
	t.Parallel()
	env, _, errb := telegramTestEnv(t, `{"default_profile":"default","profiles":{"default":{}}}`)
	if code := Run(context.Background(), []string{"telegram", "status"}, env); code != 2 {
		t.Fatalf("status without a block: code=%d, want 2", code)
	}
	if !strings.Contains(errb.String(), "telegram") {
		t.Errorf("stderr = %q; want a telegram note", errb.String())
	}
}

func TestTelegramStatusMalformedBlockNoTokenUse(t *testing.T) {
	t.Parallel()
	bad := `{"default_profile":"default","profiles":{"default":{},"muse01":{}},"telegram":{"profile":"muse01","token":"` + telegramTestToken + `","allowed_user_ids":[]}}`
	env, out, errb := telegramTestEnv(t, bad)
	if code := Run(context.Background(), []string{"telegram", "status"}, env); code != 2 {
		t.Fatalf("status with an empty allowlist: code=%d, want 2", code)
	}
	combined := out.String() + errb.String()
	if strings.Contains(combined, telegramTestToken) {
		t.Error("token value appears in output for a malformed block")
	}
	if !strings.Contains(errb.String(), "allowed_user_ids") {
		t.Errorf("stderr = %q; want the allowlist rule named", errb.String())
	}
}

func TestTelegramProfileMismatch(t *testing.T) {
	t.Parallel()
	// --profile naming a different profile than the block: exit
	// 2 naming both tags, for run and status alike.
	env, _, errb := telegramTestEnv(t, telegramTestConfig())
	if code := Run(context.Background(), []string{"--profile", "default", "telegram", "run"}, env); code != 2 {
		t.Fatalf("run --profile default: code=%d, want 2", code)
	}
	if !strings.Contains(errb.String(), `"default"`) || !strings.Contains(errb.String(), `"muse01"`) {
		t.Errorf("stderr = %q; want both tags named", errb.String())
	}
	// CASTCTL_PROFILE naming a different profile: same refusal.
	_, configFile := testHome(t, telegramTestConfig())
	out2, errb2 := &bytes.Buffer{}, &bytes.Buffer{}
	env2 := &Env{Stdout: out2, Stderr: errb2, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile, "CASTCTL_PROFILE": "default"})}
	if code := Run(context.Background(), []string{"telegram", "status"}, env2); code != 2 {
		t.Fatalf("status CASTCTL_PROFILE=default: code=%d, want 2", code)
	}
	if !strings.Contains(errb2.String(), `"default"`) || !strings.Contains(errb2.String(), `"muse01"`) {
		t.Errorf("stderr = %q; want both tags named", errb2.String())
	}
}

func TestTelegramRunPollsFakeServerThroughRuntimeClient(t *testing.T) {
	t.Parallel()
	fake := &cmdFakeTelegram{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	fakeAddr := srv.Listener.Addr().String()
	dialFake := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, fakeAddr)
	}
	fakeClient := &http.Client{Transport: &http.Transport{
		Proxy:       nil,
		DialContext: dialFake,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialFake(ctx, network, addr)
		},
	}}

	env, out, errb := telegramTestEnv(t, telegramTestConfig())
	var gotProfile string
	env.BuildRuntime = func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, env *Env) (*Runtime, error) {
		gotProfile = prof.Name
		return &Runtime{Profile: prof, httpClientOverride: fakeClient}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	codeCh := make(chan int, 1)
	go func() { codeCh <- Run(ctx, []string{"telegram", "run"}, env) }()

	// Wait for the placeholder notice: proves GetMe + polling +
	// the message handler ran through the runtime client.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		fake.mu.Lock()
		n := len(fake.sends)
		fake.mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	var code int
	select {
	case code = <-codeCh:
	case <-time.After(5 * time.Second):
		t.Fatal("telegram run did not return after cancel")
	}
	if code != 130 {
		t.Errorf("run code = %d; want 130 (interrupted)", code)
	}
	if gotProfile != "muse01" {
		t.Errorf("runtime built for profile %q; want the linked tag muse01", gotProfile)
	}
	if !fake.saw("getMe") || !fake.saw("getUpdates") {
		t.Errorf("fake methods = %v; want getMe + getUpdates", fake.methods)
	}
	fake.mu.Lock()
	sends := append([]string(nil), fake.sends...)
	fake.mu.Unlock()
	if len(sends) != 1 || !strings.Contains(sends[0], "does not run Muse turns yet") {
		t.Errorf("placeholder sends = %q; want one placeholder notice", sends)
	}
	combined := out.String() + errb.String()
	if strings.Contains(combined, telegramTestToken) {
		t.Error("token value appears in run output")
	}
	if !strings.Contains(out.String(), `"muse01"`) {
		t.Errorf("stdout = %q; want the linked profile named", out.String())
	}
}

func TestTelegramHelpAndDispatch(t *testing.T) {
	t.Parallel()
	env, out, errb := telegramTestEnv(t, telegramTestConfig())
	if code := Run(context.Background(), []string{"telegram", "--help"}, env); code != 0 {
		t.Fatalf("telegram --help: code=%d, want 0", code)
	}
	if !strings.Contains(out.String(), "usage: castctl telegram") || !strings.Contains(out.String(), "run") || strings.Contains(out.String(), "PR5") {
		t.Errorf("telegram --help = %q; want real help, no PR5 note", out.String())
	}
	env, _, errb = telegramTestEnv(t, telegramTestConfig())
	if code := Run(context.Background(), []string{"telegram"}, env); code != 2 {
		t.Fatalf("bare telegram: code=%d, want 2", code)
	}
	if !strings.Contains(errb.String(), "subcommand") {
		t.Errorf("bare telegram stderr = %q; want the subcommand requirement", errb.String())
	}
	env, _, errb = telegramTestEnv(t, telegramTestConfig())
	if code := Run(context.Background(), []string{"telegram", "setup"}, env); code != 2 {
		t.Fatalf("telegram setup: code=%d, want 2 (not wired in item 4)", code)
	}
	if !strings.Contains(errb.String(), "invalid choice") {
		t.Errorf("telegram setup stderr = %q; want invalid choice", errb.String())
	}
}
