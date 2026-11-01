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

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

const telegramTestToken = "123456:FAKE-TOKEN-0123456789ABCD"

func telegramTestConfig() string {
	return `{"default_profile":"default","profiles":{"default":{},"muse01":{}},"telegram":{"profile":"muse01","token":"` + telegramTestToken + `","allowed_user_ids":[111],"auto_approve":true}}`
}

// telegramTestConfigNoAuto is telegramTestConfig with
// auto_approve off: approvals surface as buttons instead of
// being auto-decided, so a test can tap them.
func telegramTestConfigNoAuto() string {
	return `{"default_profile":"default","profiles":{"default":{},"muse01":{}},"telegram":{"profile":"muse01","token":"` + telegramTestToken + `","allowed_user_ids":[111]}}`
}

func telegramTestEnv(t *testing.T, configJSON string) (*Env, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	_, configFile := testHome(t, configJSON)
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	return env, out, errb
}

// cmdFakeTelegram is a minimal Bot API fake: getMe, getUpdates
// (one message batch, then empty), sendMessage, editMessageText.
// It records method names and sent/edited texts only; the
// request path (token-bearing) is never stored. When batches is
// set, getUpdates serves them in order instead of the default
// single message.
type cmdFakeTelegram struct {
	mu      sync.Mutex
	methods []string
	sends   []string
	edits   []string
	// sendMarkups/editMarkups parallel sends/edits: whether a
	// reply_markup was attached (button presence, not content).
	sendMarkups []bool
	editMarkups []bool
	// sendMarkupJSON/editMarkupJSON carry the raw reply_markup
	// JSON per send/edit ("" when none), for button assertions.
	sendMarkupJSON []string
	editMarkupJSON []string
	served         bool
	batches        []string
	batchIdx       int
	// gates, parallel to batches: batch i is served only once
	// gates[i] reports true (nil = always). A gated batch that
	// is not ready yet yields an empty result without
	// advancing, so the bot re-polls until it is.
	gates []func(*cmdFakeTelegram) bool
}

func (f *cmdFakeTelegram) editTexts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.edits...)
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
		// The gate is evaluated WITHOUT holding f.mu: gates
		// inspect the fake (editTexts locks f.mu), so
		// evaluating one under the lock deadlocks the
		// handler.
		f.mu.Lock()
		idx := f.batchIdx
		var gate func(*cmdFakeTelegram) bool
		hasBatches := f.batches != nil
		if hasBatches && idx < len(f.gates) {
			gate = f.gates[idx]
		}
		f.mu.Unlock()
		if hasBatches && gate != nil && !gate(f) {
			time.Sleep(5 * time.Millisecond)
			fmt.Fprint(w, `{"ok":true,"result":[]}`)
			return
		}
		f.mu.Lock()
		var body string
		if hasBatches {
			if f.batchIdx != idx {
				// Another poll served this batch while the
				// gate was evaluated: yield empty.
				f.mu.Unlock()
				time.Sleep(5 * time.Millisecond)
				fmt.Fprint(w, `{"ok":true,"result":[]}`)
				return
			}
			if f.batchIdx < len(f.batches) {
				body = f.batches[f.batchIdx]
				f.batchIdx++
			} else {
				body = `{"ok":true,"result":[]}`
			}
			f.mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			fmt.Fprint(w, body)
			return
		}
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
		markup := false
		markupJSON := ""
		if err := r.ParseMultipartForm(1 << 20); err == nil && r.MultipartForm != nil {
			text = r.MultipartForm.Value["text"][0]
			markupJSON = firstFormValue(r.MultipartForm.Value["reply_markup"])
			markup = markupJSON != "" && markupJSON != "null"
		} else if err := r.ParseForm(); err == nil {
			text = r.Form.Get("text")
			markupJSON = r.Form.Get("reply_markup")
			markup = markupJSON != "" && markupJSON != "null"
		}
		f.mu.Lock()
		f.sends = append(f.sends, text)
		f.sendMarkups = append(f.sendMarkups, markup)
		f.sendMarkupJSON = append(f.sendMarkupJSON, markupJSON)
		f.mu.Unlock()
		fmt.Fprint(w, `{"ok":true,"result":{"message_id":100,"chat":{"id":500,"type":"private"},"date":0,"text":"ok"}}`)
	case "editMessageText":
		text := ""
		markup := false
		markupJSON := ""
		if err := r.ParseMultipartForm(1 << 20); err == nil && r.MultipartForm != nil {
			text = r.MultipartForm.Value["text"][0]
			markupJSON = firstFormValue(r.MultipartForm.Value["reply_markup"])
			markup = markupJSON != "" && markupJSON != "null"
		} else if err := r.ParseForm(); err == nil {
			text = r.Form.Get("text")
			markupJSON = r.Form.Get("reply_markup")
			markup = markupJSON != "" && markupJSON != "null"
		}
		f.mu.Lock()
		f.edits = append(f.edits, text)
		f.editMarkups = append(f.editMarkups, markup)
		f.editMarkupJSON = append(f.editMarkupJSON, markupJSON)
		f.mu.Unlock()
		fmt.Fprint(w, `{"ok":true,"result":{"message_id":100,"chat":{"id":500,"type":"private"},"date":0,"text":"ok"}}`)
	case "answerCallbackQuery":
		fmt.Fprint(w, `{"ok":true,"result":true}`)
	default:
		fmt.Fprint(w, `{"ok":false,"error_code":404,"description":"Not Found"}`)
	}
}

func firstFormValue(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

// setBatches replaces the pending getUpdates batches under the
// lock (the poller reads them concurrently; direct assignment
// would race under -race). The batch index restarts at 0.
func (f *cmdFakeTelegram) setBatches(batches []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = batches
	f.batchIdx = 0
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

	// The turn runs against a scripted in-memory gateway: the
	// fake Telegram server proves the bot polls through the
	// runtime client, the gateway proves a real turn ran.
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "Hello back", deltas: []string{"Hel"}}}
	muse := conn.New(func(context.Context, conn.Config) (conn.Gateway, error) { return gw, nil })

	env, out, errb := telegramTestEnv(t, telegramTestConfig())
	var gotProfile string
	env.BuildRuntime = func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, env *Env) (*Runtime, error) {
		gotProfile = prof.Name
		return &Runtime{Profile: prof, Muse: muse, httpClientOverride: fakeClient}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	codeCh := make(chan int, 1)
	go func() { codeCh <- Run(ctx, []string{"telegram", "run"}, env) }()

	// Wait for the final edit: proves GetMe + polling + the
	// message handler ran a real turn through the runtime
	// client and the fake gateway.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		found := false
		for _, e := range fake.editTexts() {
			if strings.Contains(e, "Hello back") {
				found = true
			}
		}
		if found {
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
	if len(sends) < 1 || !strings.Contains(sends[0], "Sending to Muse") {
		t.Errorf("sends = %q; want the streaming bubble", sends)
	}
	for _, s := range sends {
		if strings.Contains(s, "does not run Muse turns yet") {
			t.Errorf("placeholder notice still sent: %q", s)
		}
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
