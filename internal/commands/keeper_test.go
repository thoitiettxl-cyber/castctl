// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/keeper"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

const keeperTestToken = "123456:FAKE-TOKEN-0123456789ABCD"

// lockedBuffer is a bytes.Buffer safe for concurrent Write +
// String: the cancel test polls output while the run goroutine
// writes tick lines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// keeperTestConfig returns a config with a default profile, a
// muse01 profile, a telegram block linked to muse01, and one
// keeper entry for the default profile. The browser URL points
// at a loopback port with nothing listening: the attach path
// is only exercised when a test needs it.
func keeperTestConfig() string {
	return `{"default_profile":"default","profiles":{"default":{},"muse01":{}},` +
		`"telegram":{"profile":"muse01","token":"` + keeperTestToken + `","allowed_user_ids":[111],"auto_approve":true},` +
		`"keeper":[{"tag":"k1","profile":"default","browser":"http://127.0.0.1:9226","interval":"1h","notify":"telegram"}]}`
}

// keeperFakeGateway is a fake muse.ai cheap chain: /api/session
// and /api/auth/check. sessionStatus/authStatus control the
// responses; sessionCookies are Set-Cookie values on the
// session step (RECONSTRUCTED K.7 shapes, fake values).
// sessionScript, when non-empty, drives /api/session per
// call instead: the nth call uses
// sessionScript[min(n-1, len(sessionScript)-1)], so one test
// can drive multi-round tick paths (e.g. AuthError, then a
// re-check GatewayError) through the real cheap chain. A
// step's empty body means the default healthy body.
type keeperFakeGateway struct {
	mu             sync.Mutex
	sessionStatus  int
	authStatus     int
	sessionCookies []string
	sessionScript  []keeperFakeSessionStep
	sessionSeen    int
	authSeen       int
	cookieHeaders  []string
}

// keeperFakeSessionStep is one scripted /api/session response.
type keeperFakeSessionStep struct {
	status  int
	body    string
	cookies []string
}

func (f *keeperFakeGateway) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/api/session":
		f.sessionSeen++
		f.cookieHeaders = append(f.cookieHeaders, r.Header.Get("Cookie"))
		status, body, cookies := f.sessionStatus, "", f.sessionCookies
		if len(f.sessionScript) > 0 {
			step := f.sessionScript[min(f.sessionSeen-1, len(f.sessionScript)-1)]
			status, body, cookies = step.status, step.body, step.cookies
		}
		for _, c := range cookies {
			w.Header().Add("Set-Cookie", c)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		switch {
		case body != "":
			fmt.Fprint(w, body)
		case status == 200:
			fmt.Fprint(w, `{"vm_id":"vm-test"}`)
		}
	case "/api/auth/check":
		f.authSeen++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.authStatus)
		if f.authStatus == 200 {
			fmt.Fprint(w, `{"access_token":"tok-test"}`)
		}
	default:
		// Telegram sendMessage + anything else: a generic ok.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{"ok":true}`)
	}
}

// keeperFakeClient returns an HTTP client that dials every host
// (muse.ai, api.telegram.org) to the fake TLS server. TLS
// verification is skipped: the test server's cert is not for
// those names, and the point is request shape, not TLS.
func keeperFakeClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	addr := srv.Listener.Addr().String()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	base := srv.Client().Transport.(*http.Transport).Clone()
	tlsCfg := base.TLSClientConfig.Clone()
	tlsCfg.InsecureSkipVerify = true
	base.TLSClientConfig = tlsCfg
	base.Proxy = nil
	base.DialContext = dial
	// DialTLSContext must return a handshaken TLS connection:
	// returning the raw dial (as a first cut did) makes the
	// transport write plaintext HTTP at a TLS server.
	base.DialTLSContext = func(_ context.Context, network, _ string) (net.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{}, network, addr, &tls.Config{InsecureSkipVerify: true})
	}
	return &http.Client{Transport: base}
}

// keeperTestEnv wires env with a BuildRuntime override that
// returns a Runtime for any profile with the fake client.
// No real outbound, no live network. It returns the env, the
// stdout/stderr buffers, and the config home dir.
func keeperTestEnv(t *testing.T, configJSON string, fake *keeperFakeGateway) (*Env, *bytes.Buffer, *bytes.Buffer, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(fake.handler))
	t.Cleanup(srv.Close)
	client := keeperFakeClient(t, srv)
	home, configFile := testHome(t, configJSON)
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{
		Stdout: out, Stderr: errb,
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile}),
	}
	env.BuildRuntime = func(_ context.Context, _ *profile.ConfigLocation, prof *profile.Profile, _ *Env) (*Runtime, error) {
		return &Runtime{Profile: prof, httpClientOverride: client}, nil
	}
	return env, out, errb, home
}

func TestKeeperCheckNoBlock(t *testing.T) {
	t.Parallel()
	fake := &keeperFakeGateway{sessionStatus: 200, authStatus: 200}
	env, _, errb, _ := keeperTestEnv(t, `{"default_profile":"default","profiles":{"default":{}}}`, fake)
	if code := Run(context.Background(), []string{"keeper", "check"}, env); code != 2 {
		t.Fatalf("check without keeper block: code=%d, want 2", code)
	}
	if !strings.Contains(errb.String(), "keeper") {
		t.Errorf("stderr = %q; want the keeper block named", errb.String())
	}
}

func TestKeeperCheckHealthy(t *testing.T) {
	t.Parallel()
	fake := &keeperFakeGateway{
		sessionStatus: 200, authStatus: 200,
		// RECONSTRUCTED K.7 shape: host-only, Max-Age 30d.
		sessionCookies: []string{"hatch_sess=FAKE-RENEWED; Max-Age=2592000; Path=/; Secure; HttpOnly; SameSite=Lax"},
	}
	env, out, errb, _ := keeperTestEnv(t, keeperTestConfig(), fake)
	if code := Run(context.Background(), []string{"keeper", "check"}, env); code != 0 {
		t.Fatalf("check healthy: code=%d, stderr=%q", code, errb.String())
	}
	var res keeperCheckResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("check output is not one JSON object: %v (%q)", err, out.String())
	}
	if res.Outcome != keeper.OutcomeOK {
		t.Errorf("outcome = %q, want %q", res.Outcome, keeper.OutcomeOK)
	}
	if res.WroteCookies {
		t.Error("non-jar stored file: Set-Cookie capture must skip the write")
	}
	if fake.sessionSeen != 1 || fake.authSeen != 1 {
		t.Errorf("chain calls: session=%d auth=%d, want 1/1", fake.sessionSeen, fake.authSeen)
	}
	if strings.Contains(out.String(), "FAKE-RENEWED") || strings.Contains(errb.String(), "FAKE-RENEWED") {
		t.Error("renewed cookie value leaked into output")
	}
}

func TestKeeperCheckAuthExpiredStops(t *testing.T) {
	t.Parallel()
	fake := &keeperFakeGateway{sessionStatus: 401, authStatus: 200}
	env, out, errb, _ := keeperTestEnv(t, keeperTestConfig(), fake)
	if code := Run(context.Background(), []string{"keeper", "check"}, env); code != 3 {
		t.Fatalf("check expired: code=%d, want 3; stderr=%q", code, errb.String())
	}
	var res keeperCheckResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("check output: %v (%q)", err, out.String())
	}
	if !keeper.CDPAvailable() {
		// Tag off: no exporter, so the stop is sticky.
		if !res.Stopped || res.Outcome != keeper.OutcomeAuthError {
			t.Errorf("tag-off: outcome=%q stopped=%v, want auth_error/stopped", res.Outcome, res.Stopped)
		}
	} else {
		// Tag on: the CDP attach to a dead port fails, so the
		// export recovery fails transiently (no browser).
		if res.Outcome != keeper.OutcomeExportFailed {
			t.Errorf("tag-on, no browser: outcome=%q, want export_failed", res.Outcome)
		}
	}
	if strings.Contains(out.String(), "FAKE") {
		t.Error("cookie value leaked into output")
	}
}

func TestKeeperCheckSelection(t *testing.T) {
	t.Parallel()
	fake := &keeperFakeGateway{sessionStatus: 200, authStatus: 200}
	env, _, errb, _ := keeperTestEnv(t, keeperTestConfig(), fake)
	if code := Run(context.Background(), []string{"keeper", "check", "--tag", "nope"}, env); code != 2 {
		t.Fatalf("check --tag nope: code=%d, want 2", code)
	}
	if code := Run(context.Background(), []string{"keeper", "check", "--tag", "k1", "--profile", "default"}, env); code != 2 {
		t.Fatalf("check --tag+--profile: code=%d, want 2; stderr=%q", code, errb.String())
	}
	env2, out2, errb2, _ := keeperTestEnv(t, keeperTestConfig(), fake)
	if code := Run(context.Background(), []string{"keeper", "check", "--profile", "default"}, env2); code != 0 {
		t.Fatalf("check --profile default: code=%d, stderr=%q", code, errb2.String())
	}
	var res keeperCheckResult
	if err := json.Unmarshal(out2.Bytes(), &res); err != nil {
		t.Fatalf("check output: %v", err)
	}
	if res.Tag != "k1" || res.Profile != "default" {
		t.Errorf("selected = %+v, want k1/default", res)
	}
}

func TestKeeperStatusNoNetwork(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	configFile := filepath.Join(home, "config.json")
	if err := os.WriteFile(configFile, []byte(keeperTestConfig()), 0o600); err != nil {
		t.Fatal(err)
	}
	// Hand-write a logged-out state; status must report it
	// with no runtime and no network.
	now := time.Now().UTC().Truncate(time.Second)
	if err := keeper.SaveState(home, &keeper.SessionState{
		Version: 1, LoggedOut: true, KeeperStopped: true,
		KeeperStoppedReason: "auth_error", LastCheckedAt: &now,
		LastTickOutcome: keeper.OutcomeAuthError,
		WarnPending:     true,
	}); err != nil {
		t.Fatal(err)
	}
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	// No BuildRuntime override: any network attempt fails.
	if code := Run(context.Background(), []string{"keeper", "status"}, env); code != 0 {
		t.Fatalf("status: code=%d, stderr=%q", code, errb.String())
	}
	var statuses []keeper.Status
	if err := json.Unmarshal(out.Bytes(), &statuses); err != nil {
		t.Fatalf("status output: %v (%q)", err, out.String())
	}
	if len(statuses) != 1 || !statuses[0].LoggedOut || !statuses[0].KeeperStopped || !statuses[0].WarnPending {
		t.Fatalf("statuses = %+v, want one logged-out stopped entry with warn pending", statuses)
	}
}

func TestKeeperRunSecondRefuses(t *testing.T) {
	t.Parallel()
	fake := &keeperFakeGateway{sessionStatus: 200, authStatus: 200}
	env, _, errb, home := keeperTestEnv(t, keeperTestConfig(), fake)
	// Hold the single-flight owner file ourselves: the
	// command's run must refuse.
	release, err := keeper.AcquireSingleFlight(home, "k1", keeper.RealClock)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if code := Run(context.Background(), []string{"keeper", "run"}, env); code != 2 {
		t.Fatalf("second run: code=%d, want 2; stderr=%q", code, errb.String())
	}
	if !strings.Contains(errb.String(), "k1") {
		t.Errorf("stderr = %q; want the entry tag named", errb.String())
	}
}

func TestKeeperRunCancelled(t *testing.T) {
	t.Parallel()
	fake := &keeperFakeGateway{sessionStatus: 200, authStatus: 200}
	// The run goroutine writes tick lines while this goroutine
	// polls for the first one: the output buffer must be safe
	// for concurrent use (bytes.Buffer is not).
	out := &lockedBuffer{}
	env, _, _, _ := keeperTestEnv(t, keeperTestConfig(), fake)
	env.Stdout = out
	ctx, cancel := context.WithCancel(context.Background())
	codeCh := make(chan int, 1)
	go func() { codeCh <- Run(ctx, []string{"keeper", "run"}, env) }()
	// Let at least one tick print, then interrupt.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), "keeper: k1") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-codeCh:
		if code != 130 {
			t.Errorf("run cancelled: code=%d, want 130", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
	}
	if !strings.Contains(out.String(), "keeper: k1 (default): ok") {
		t.Errorf("stdout = %q; want one ok tick line", out.String())
	}
}

func TestKeeperNotifierSendsFixedNotice(t *testing.T) {
	t.Parallel()
	if keeper.CDPAvailable() {
		// Tag-on: with no browser listening, the export
		// recovery fails transiently instead of stopping,
		// so the stopped-notice path never fires. The
		// notifier's request shape is proven tag-off; the
		// stopped-notice wiring is proven in the keeper
		// package's tick tests.
		t.Skip("tag-on build: no browser, no stopped tick")
	}
	var mu sync.Mutex
	var sends []url.Values
	fake := &keeperFakeGateway{sessionStatus: 401, authStatus: 200}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/bot") && strings.HasSuffix(r.URL.Path, "/sendMessage") {
			body, _ := io.ReadAll(r.Body)
			v, _ := url.ParseQuery(string(body))
			mu.Lock()
			sends = append(sends, v)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		fake.handler(w, r)
	}))
	t.Cleanup(srv.Close)
	client := keeperFakeClient(t, srv)
	_, configFile := testHome(t, keeperTestConfig())
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{
		Stdout: out, Stderr: errb,
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile}),
	}
	env.BuildRuntime = func(_ context.Context, _ *profile.ConfigLocation, prof *profile.Profile, _ *Env) (*Runtime, error) {
		return &Runtime{Profile: prof, httpClientOverride: client}, nil
	}
	if code := Run(context.Background(), []string{"keeper", "check"}, env); code != 3 {
		t.Fatalf("check expired: code=%d, want 3; stderr=%q", code, errb.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sends) != 1 {
		t.Fatalf("sendMessage calls = %d, want 1", len(sends))
	}
	if got := sends[0].Get("chat_id"); got != "111" {
		t.Errorf("chat_id = %q, want first allowed_user_ids entry 111", got)
	}
	text := sends[0].Get("text")
	if !strings.Contains(text, "default") || !strings.Contains(text, "No action was taken automatically.") {
		t.Errorf("notice text = %q; want profile name + no-action line", text)
	}
	if strings.Contains(text, keeperTestToken) || strings.Contains(text, "FAKE") {
		t.Errorf("notice text leaks a secret: %q", text)
	}
}

func TestKeeperCheckSession500StopsWithExit3(t *testing.T) {
	t.Parallel()
	// 500 on the session step is an AuthError, not a
	// GatewayError: fetchSessionInfoRaw maps any non-200 to
	// AuthError, so check stops the entry and exits 3 through
	// the stopped branch. (Micro-loop N-B rename: the old
	// name/comment misdescribed this as transient/GatewayError
	// coverage; the assertion is unchanged.)
	fake := &keeperFakeGateway{sessionStatus: 500, authStatus: 200}
	env, out, errb, _ := keeperTestEnv(t, keeperTestConfig(), fake)
	code := Run(context.Background(), []string{"keeper", "check"}, env)
	if code != 3 {
		t.Fatalf("check session 500: code=%d, want 3 (stopped AuthError); stderr=%q out=%q", code, errb.String(), out.String())
	}
}

func TestAuthLoginFlagOff(t *testing.T) {
	t.Parallel()
	_, configFile := testHome(t, keeperTestConfig())
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Stdin: strings.NewReader(""),
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	if code := Run(context.Background(), []string{"auth", "login"}, env); code != 2 {
		t.Fatalf("auth login without flag: code=%d, want 2", code)
	}
	if !strings.Contains(errb.String(), "--experimental-login") || !strings.Contains(errb.String(), "auth import") {
		t.Errorf("stderr = %q; want flag + import alternative named", errb.String())
	}
}

func TestAuthLoginTagOff(t *testing.T) {
	t.Parallel()
	if keeper.CDPAvailable() {
		t.Skip("tag-on build: covered by TestAuthLoginUnreachableBrowser")
	}
	_, configFile := testHome(t, keeperTestConfig())
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Stdin: strings.NewReader("cancel\n"),
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	if code := Run(context.Background(), []string{"auth", "login", "--experimental-login"}, env); code != 2 {
		t.Fatalf("auth login tag-off: code=%d, want 2", code)
	}
	if !strings.Contains(errb.String(), "with_chromedp") {
		t.Errorf("stderr = %q; want the build-tag message", errb.String())
	}
}

func TestAuthLoginUnreachableBrowser(t *testing.T) {
	t.Parallel()
	if !keeper.CDPAvailable() {
		t.Skip("tag-off build: covered by TestAuthLoginTagOff")
	}
	// The keeper entry names a loopback browser with nothing
	// listening: attach fails, and the command must NOT fall
	// back to a launched browser silently.
	fake := &keeperFakeGateway{sessionStatus: 200, authStatus: 200}
	env, out, errb, _ := keeperTestEnv(t, keeperTestConfig(), fake)
	env.Stdin = strings.NewReader("cancel\n")
	if code := Run(context.Background(), []string{"auth", "login", "--experimental-login"}, env); code != 1 {
		t.Fatalf("auth login unreachable browser: code=%d, want 1; stderr=%q out=%q", code, errb.String(), out.String())
	}
	var res struct {
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("login output: %v (%q)", err, out.String())
	}
	if res.Outcome != string(keeper.LoginFailed) {
		t.Errorf("outcome = %q, want failed", res.Outcome)
	}
}

func TestAuthLoginTimeoutRange(t *testing.T) {
	t.Parallel()
	_, configFile := testHome(t, keeperTestConfig())
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Stdin: strings.NewReader(""),
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	code := Run(context.Background(), []string{"auth", "login", "--experimental-login", "--timeout", "30s"}, env)
	if !keeper.CDPAvailable() {
		if code != 2 || !strings.Contains(errb.String(), "with_chromedp") {
			t.Fatalf("tag-off: code=%d stderr=%q, want 2 + build-tag message", code, errb.String())
		}
		return
	}
	if code != 2 {
		t.Fatalf("auth login --timeout 30s: code=%d, want 2", code)
	}
	if !strings.Contains(errb.String(), "out of range") {
		t.Errorf("stderr = %q; want the range named", errb.String())
	}
}

// TestStdinTransportNeverEchoesInput (loop-2 safety F2): an
// unrecognised stdin line is never echoed to stderr — it may
// be a pasted password or 2FA code. RED on the old code: the
// %q echo printed the line verbatim.
func TestStdinTransportNeverEchoesInput(t *testing.T) {
	t.Parallel()
	errb := &bytes.Buffer{}
	tr := newStdinTransport(strings.NewReader("MARKER-SECRET-XYZ-12345\n"), errb)
	select {
	case <-tr.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("stdin transport did not reach EOF")
	}
	if strings.Contains(errb.String(), "MARKER-SECRET-XYZ-12345") {
		t.Fatalf("stderr echoes stdin input: %q", errb.String())
	}
	if !strings.Contains(errb.String(), "ignoring unrecognised input") {
		t.Fatalf("stderr = %q; want the fixed ignoring message", errb.String())
	}
}

// TestKeeperRunFactoryFailureSurfaced (loop-2 red-team F5):
// a factory that fails for every entry must exit 2 with a
// line naming the entry, never exit 0 silently. RED on the
// old code: exit 0, no output.
func TestKeeperRunFactoryFailureSurfaced(t *testing.T) {
	t.Parallel()
	_, configFile := testHome(t, keeperTestConfig())
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{
		Stdout: out, Stderr: errb,
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile}),
	}
	env.BuildRuntime = func(_ context.Context, _ *profile.ConfigLocation, _ *profile.Profile, _ *Env) (*Runtime, error) {
		return nil, errors.New("runtime build boom")
	}
	if code := Run(context.Background(), []string{"keeper", "run"}, env); code != 2 {
		t.Fatalf("run with failing factory: code=%d, want 2; stdout=%q stderr=%q", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "k1") || !strings.Contains(out.String(), "factory error") {
		t.Fatalf("stdout = %q; want a line naming entry k1 and the factory error", out.String())
	}
}

// TestKeeperCheckPrintsAllEntriesWhenFirstStops: check
// prints one JSON object per selected entry even when an
// early entry stops. Characterization test: this held on the
// old code too for stopped outcomes — it guards the entry
// loop against regressions from the N20 rework (continue
// past a transient-error return). The transient-error return
// itself is covered by the fast regression test
// TestKeeperCheckContinuesPastRecheckTransient (the re-check
// transient path takes no backoff sleep); the first-check
// backoff-ladder path still has no fast test (RealClock is
// hardcoded in the commands factory) and remains a follow-up.
func TestKeeperCheckPrintsAllEntriesWhenFirstStops(t *testing.T) {
	t.Parallel()
	config := `{"default_profile":"default","profiles":{"default":{},"muse01":{}},` +
		`"telegram":{"profile":"muse01","token":"` + keeperTestToken + `","allowed_user_ids":[111],"auto_approve":true},` +
		`"keeper":[{"tag":"k1","profile":"default","browser":"http://127.0.0.1:9226","interval":"1h"},{"tag":"k2","profile":"muse01","browser":"http://127.0.0.1:9227","interval":"1h"}]}`
	fake := &keeperFakeGateway{sessionStatus: 500, authStatus: 200}
	env, out, errb, _ := keeperTestEnv(t, config, fake)
	code := Run(context.Background(), []string{"keeper", "check"}, env)
	if code != 3 {
		t.Fatalf("check stopped entries: code=%d, want 3; stderr=%q out=%q", code, errb.String(), out.String())
	}
	lines := strings.Count(out.String(), `"tag":`)
	if lines != 2 {
		t.Fatalf("check printed %d JSON objects; want 2 (one per entry): %q", lines, out.String())
	}
	if !strings.Contains(out.String(), `"tag": "k1"`) || !strings.Contains(out.String(), `"tag": "k2"`) {
		t.Fatalf("check output = %q; want both entry tags", out.String())
	}
}

// TestKeeperCheckInterrupted (loop-2 technical N4): a
// cancelled context ends `keeper check` with the interrupt
// code instead of being swallowed as a skipped tick. RED on
// the old code: exit 0.
func TestKeeperCheckInterrupted(t *testing.T) {
	t.Parallel()
	fake := &keeperFakeGateway{sessionStatus: 200, authStatus: 200}
	env, _, _, _ := keeperTestEnv(t, keeperTestConfig(), fake)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := Run(ctx, []string{"keeper", "check"}, env); code != 130 {
		t.Fatalf("interrupted check: code=%d, want 130", code)
	}
}

// TestKeeperStatusCorruptState (loop-2 red-team F6): status
// reports a corrupt state file distinctly (state_corrupt +
// reason) with exit 0, instead of erroring. RED on the old
// code: status errored.
func TestKeeperStatusCorruptState(t *testing.T) {
	t.Parallel()
	fake := &keeperFakeGateway{sessionStatus: 200, authStatus: 200}
	env, out, _, home := keeperTestEnv(t, keeperTestConfig(), fake)
	paths, err := profile.ProfilePaths(home, "default")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.Dir, keeper.StateFileName), []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := Run(context.Background(), []string{"keeper", "status"}, env); code != 0 {
		t.Fatalf("status with corrupt state: code=%d, want 0", code)
	}
	if !strings.Contains(out.String(), `"state_corrupt": true`) || !strings.Contains(out.String(), "state_corrupt") {
		t.Fatalf("status output = %q; want state_corrupt flagged with the reason", out.String())
	}
}

// TestKeeperCheckCorruptState (loop-2 red-team F6): check
// still ticks with a corrupt state file and flags it in the
// JSON. RED on the old code: skipped tick, no flag.
func TestKeeperCheckCorruptState(t *testing.T) {
	t.Parallel()
	fake := &keeperFakeGateway{sessionStatus: 200, authStatus: 200}
	env, out, _, home := keeperTestEnv(t, keeperTestConfig(), fake)
	paths, err := profile.ProfilePaths(home, "default")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.Dir, keeper.StateFileName), []byte(`{"version": 99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := Run(context.Background(), []string{"keeper", "check"}, env); code != 0 {
		t.Fatalf("check with corrupt state: code=%d, want 0", code)
	}
	if !strings.Contains(out.String(), `"state_corrupt": true`) {
		t.Fatalf("check output = %q; want state_corrupt flagged", out.String())
	}
}

// TestKeeperCheckFreshConfigOutsideCookies (K-LIVE-1): the real
// `keeper check` path on a fresh config dir (no profiles/
// subdir) whose profile's cookies file lives outside the config
// dir must tick healthy and write the state file (dir 0700),
// not report "skipped" with exit 0 and no state. RED on
// e4ef8c5: outcome "skipped", no state file.
func TestKeeperCheckFreshConfigOutsideCookies(t *testing.T) {
	t.Parallel()
	outside := t.TempDir()
	cookiesPath, _ := json.Marshal(filepath.Join(outside, "cookies.txt"))
	cfg := `{"default_profile":"muse01","profiles":{"muse01":{"cookies_file":` + string(cookiesPath) + `}},` +
		`"keeper":[{"tag":"k1","profile":"muse01","browser":"http://127.0.0.1:9226","interval":"1h"}]}`
	fake := &keeperFakeGateway{sessionStatus: 200, authStatus: 200}
	env, out, errb, home := keeperTestEnv(t, cfg, fake)
	if _, err := os.Stat(filepath.Join(home, "profiles")); !os.IsNotExist(err) {
		t.Fatalf("fresh config has a profiles/ entry (err=%v)", err)
	}
	if code := Run(context.Background(), []string{"keeper", "check"}, env); code != 0 {
		t.Fatalf("check fresh config: code=%d, stderr=%q", code, errb.String())
	}
	var res keeperCheckResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("check output is not one JSON object: %v (%q)", err, out.String())
	}
	if res.Outcome != keeper.OutcomeOK {
		t.Errorf("outcome = %q, want %q (never skipped)", res.Outcome, keeper.OutcomeOK)
	}
	paths, err := profile.ProfilePaths(home, "muse01")
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(paths.Dir)
	if err != nil {
		t.Fatalf("profile dir missing after check: %v", err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Errorf("profile dir mode=%o, want 0700", st.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(paths.Dir, keeper.StateFileName)); err != nil {
		t.Errorf("state file missing after check: %v", err)
	}
}

// TestKeeperCheckStateDirFailure (K-LIVE-1): when the state dir
// cannot be created (a file sits where profiles/ must be),
// `keeper check` must exit non-zero with outcome "error" and a
// stderr message naming the state directory — never exit 0
// with "skipped". RED on e4ef8c5: code 0, outcome "skipped".
func TestKeeperCheckStateDirFailure(t *testing.T) {
	t.Parallel()
	outside := t.TempDir()
	cookiesPath, _ := json.Marshal(filepath.Join(outside, "cookies.txt"))
	cfg := `{"default_profile":"muse01","profiles":{"muse01":{"cookies_file":` + string(cookiesPath) + `}},` +
		`"keeper":[{"tag":"k1","profile":"muse01","browser":"http://127.0.0.1:9226","interval":"1h"}]}`
	fake := &keeperFakeGateway{sessionStatus: 200, authStatus: 200}
	env, out, errb, home := keeperTestEnv(t, cfg, fake)
	if err := os.WriteFile(filepath.Join(home, "profiles"), []byte("not a directory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code := Run(context.Background(), []string{"keeper", "check"}, env)
	var res keeperCheckResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("check output is not one JSON object: %v (%q)", err, out.String())
	}
	if res.Outcome == keeper.OutcomeSkipped {
		t.Errorf("outcome = %q; a state-dir failure must never be skipped", res.Outcome)
	}
	if res.Outcome != "error" {
		t.Errorf("outcome = %q, want \"error\"", res.Outcome)
	}
	if code == 0 {
		t.Errorf("check state-dir failure: code=0, want non-zero")
	}
	if !strings.Contains(errb.String(), "state director") {
		t.Errorf("stderr = %q; want the state directory named", errb.String())
	}
}
