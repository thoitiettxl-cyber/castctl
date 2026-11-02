// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Loop-1 mock tests: slow/async forms (D2), mid-fill
// blockers (S1), prefilled fields (S2), blocker keywords
// (T2), attach fallback (T1), redirect URL stripping (D6),
// and failure cleanup of the chromium-profile dir (R-1).
// Same harness as relogin_mock_test.go: fake login page on
// loopback through the S2 proxy, fake sentinels only.

const mockFormBody = `<form action="/login" method="post">
<input id="user" name="username" type="text">
<input id="pass" name="password" type="password">
<button id="submit" type="submit">Log in</button>
</form>`

func mockLoginPageHTML(inner string) string {
	return `<!doctype html><html><body>` + inner + `</body></html>`
}

// mockFormServer serves loginHTML for GET /login and the
// standard record-cookies-redirect behaviour for POST,
// unless postHandler is given (it receives the posts
// counter and the recorded values to update itself).
func mockFormServer(t *testing.T, loginHTML string, postHandler func(w http.ResponseWriter, r *http.Request, posts *int, gotUser, gotPass *string)) (*httptest.Server, *int, *string, *string) {
	t.Helper()
	posts := 0
	var gotUser, gotPass string
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if postHandler != nil {
				postHandler(w, r, &posts, &gotUser, &gotPass)
				return
			}
			posts++
			_ = r.ParseForm()
			gotUser = r.FormValue("username")
			gotPass = r.FormValue("password")
			http.SetCookie(w, &http.Cookie{Name: "hatch_sess", Value: "FAKE-HARVEST", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "other", Value: "FAKE-OTHER", Path: "/"})
			http.Redirect(w, r, "/done", http.StatusFound)
			return
		}
		fmt.Fprint(w, loginHTML)
	})
	mux.HandleFunc("/done", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "done")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &posts, &gotUser, &gotPass
}

func mockContractSignals(loginURL string, blockers []LoginBlockerSignal) LoginContract {
	return LoginContract{
		Version:  1,
		Observed: true,
		LoginURL: loginURL,
		Steps: []LoginContractStep{
			{Action: "fill", Selector: "#user", Field: "username"},
			{Action: "fill", Selector: "#pass", Field: "password"},
			{Action: "click", Selector: "#submit"},
		},
		Blockers: blockers,
	}
}

// mockBaseDir is a scratch base dir for mock-driver tests.
// It must NOT be t.TempDir(): Chrome child processes can
// outlive the main browser process briefly and keep writing
// into chromium-profile/ after the test returns, which
// makes TempDir's RemoveAll cleanup fail the test with
// "directory not empty" (flaky, environmental — the test's
// own assertions already passed). Removal retries for up
// to 10s and never fails the test: leftover scratch under
// the OS temp dir is harmless.
func mockBaseDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "castctl-mock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for i := 0; i < 50; i++ {
			if err := os.RemoveAll(dir); err == nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		_ = os.RemoveAll(dir)
	})
	return dir
}

// proxy to srv, defaulting the contract's LoginURL to the
// fake host. browserURL "" means launch; a dead-port URL
// exercises the attach-fallback path.
func mockReloginDriver(t *testing.T, srv *httptest.Server, contract LoginContract, browserURL string) (ReloginDriver, *mockOutbound, string) {
	t.Helper()
	host := strings.TrimPrefix(srv.URL, "http://")
	_, port, _ := net.SplitHostPort(host)
	fake := &mockOutbound{target: host}
	baseDir := mockBaseDir(t)
	if contract.LoginURL == "" {
		contract.LoginURL = "http://fake-login.test:" + port + "/login"
	}
	driver := NewReloginDriver(ReloginOptions{
		BrowserURL:  browserURL,
		BaseDir:     baseDir,
		Inbound:     mockInbound{dialer: outbound.NewDialer(fake, &mockResolver{}, option.OutboundTLSOptions{})},
		Profile:     &profile.Profile{Name: "muse01"},
		Contract:    contract,
		MaxAttempts: 1,
	})
	return driver, fake, baseDir
}

func mockReloginCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// TestMockReloginSlowForm (D2): the form is injected by
// JavaScript 1.5s after load. A first-poll mismatch must
// NOT stop the attempt: the driver polls to the deadline
// and logs in once the form appears.
func TestMockReloginSlowForm(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	// The form HTML must be a single line: a raw newline
	// inside a JS string literal is a syntax error and the
	// injection would never run.
	formJS := strings.ReplaceAll(mockFormBody, "\n", " ")
	slowHTML := mockLoginPageHTML(`<script>setTimeout(function(){document.body.insertAdjacentHTML('beforeend', '` + formJS + `');},1500);</script>`)
	srv, posts, gotUser, gotPass := mockFormServer(t, slowHTML, nil)
	driver, _, _ := mockReloginDriver(t, srv, mockContractSignals("", []LoginBlockerSignal{{Keyword: "captcha", Kind: NoticeCaptcha}}), "")
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	cookies, err := driver.Relogin(ctx, profile.LoginCredential{Username: "SENTINEL-USER", Password: "SENTINEL-PASS"})
	if err != nil {
		t.Fatalf("Relogin (slow form): %v", err)
	}
	if *posts != 1 {
		t.Fatalf("form posts = %d; want 1", *posts)
	}
	if *gotUser != "SENTINEL-USER" || *gotPass != "SENTINEL-PASS" {
		t.Fatal("server did not see the sentinels")
	}
	found := false
	for _, c := range cookies {
		if c.Name == "hatch_sess" && c.Value == "FAKE-HARVEST" {
			found = true
		}
	}
	if !found {
		t.Fatalf("harvest = %+v; want the fake hatch_sess", cookies)
	}
}

// TestMockReloginMidFillBlocker (S1/T2): a captcha notice
// is inserted synchronously on the first input event. The
// re-match before the submit click must stop the attempt
// with a captcha blocker and zero posts.
func TestMockReloginMidFillBlocker(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	midFillHTML := mockLoginPageHTML(mockFormBody + `<script>
document.getElementById('user').addEventListener('input', function handler() {
  document.getElementById('user').removeEventListener('input', handler);
  var p = document.createElement('p'); p.textContent = 'Please complete the captcha to continue';
  document.body.appendChild(p);
});
</script>`)
	srv, posts, _, _ := mockFormServer(t, midFillHTML, nil)
	driver, _, _ := mockReloginDriver(t, srv, mockContractSignals("", []LoginBlockerSignal{{Keyword: "captcha", Kind: NoticeCaptcha}}), "")
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	_, err := driver.Relogin(ctx, profile.LoginCredential{Username: "u", Password: "p"})
	var blocker *ReloginBlocker
	if !errors.As(err, &blocker) || blocker.Kind != NoticeCaptcha {
		t.Fatalf("Relogin = %v; want a captcha blocker", err)
	}
	if *posts != 0 {
		t.Fatalf("form posts = %d; want 0 (blocker appeared mid-fill, before submit)", *posts)
	}
}

// TestMockReloginPrefilledFields (S2/T3): the fields carry
// stale values. Clearing before typing must leave exactly
// the sentinels on the wire — no stale prefix appended.
func TestMockReloginPrefilledFields(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	prefillHTML := mockLoginPageHTML(`<form action="/login" method="post">
<input id="user" name="username" type="text" value="stale-user">
<input id="pass" name="password" type="password" value="stale-pass">
<button id="submit" type="submit">Log in</button>
</form>`)
	srv, posts, gotUser, gotPass := mockFormServer(t, prefillHTML, nil)
	driver, _, _ := mockReloginDriver(t, srv, mockContractSignals("", []LoginBlockerSignal{{Keyword: "captcha", Kind: NoticeCaptcha}}), "")
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	if _, err := driver.Relogin(ctx, profile.LoginCredential{Username: "SENTINEL-USER", Password: "SENTINEL-PASS"}); err != nil {
		t.Fatalf("Relogin (prefilled): %v", err)
	}
	if *posts != 1 {
		t.Fatalf("form posts = %d; want 1", *posts)
	}
	if *gotUser != "SENTINEL-USER" || *gotPass != "SENTINEL-PASS" {
		t.Fatalf("server saw user=%q pass=%q; want exactly the sentinels (prefill must be cleared)", *gotUser, *gotPass)
	}
}

// TestMockReloginBlockerKeywords (T2) pins the 2FA,
// checkpoint, and locked keyword signals: each stops before
// submit with its own kind and zero posts.
func TestMockReloginBlockerKeywords(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	cases := []struct {
		name    string
		text    string
		keyword string
		kind    NoticeKind
	}{
		{"two-factor", "Two-factor authentication required", "two-factor", NoticeTwoFactor},
		{"checkpoint", "Account checkpoint: verify your identity", "checkpoint", NoticeCheckpoint},
		{"locked", "Your account is locked", "locked", NoticeLocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			html := mockLoginPageHTML("<p>" + tc.text + "</p>" + mockFormBody)
			srv, posts, _, _ := mockFormServer(t, html, nil)
			driver, _, _ := mockReloginDriver(t, srv, mockContractSignals("", []LoginBlockerSignal{{Keyword: tc.keyword, Kind: tc.kind}}), "")
			ctx, cancel := mockReloginCtx(t)
			defer cancel()
			_, err := driver.Relogin(ctx, profile.LoginCredential{Username: "u", Password: "p"})
			var blocker *ReloginBlocker
			if !errors.As(err, &blocker) || blocker.Kind != tc.kind {
				t.Fatalf("Relogin = %v; want a %s blocker", err, tc.kind)
			}
			if *posts != 0 {
				t.Fatalf("form posts = %d; want 0", *posts)
			}
		})
	}
}

// TestMockReloginBlockerAfterSubmit (T2): the POST returns
// a captcha page with no cookies and no redirect. The
// cookie wait must stop on the blocker immediately (not
// spin to the deadline), with the post recorded.
func TestMockReloginBlockerAfterSubmit(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	srv, posts, _, _ := mockFormServer(t, mockLoginPageHTML(mockFormBody), func(w http.ResponseWriter, r *http.Request, posts *int, _, _ *string) {
		*posts++
		_ = r.ParseForm()
		fmt.Fprint(w, mockLoginPageHTML("<p>Please complete the captcha to continue</p>"))
	})
	driver, _, _ := mockReloginDriver(t, srv, mockContractSignals("", []LoginBlockerSignal{{Keyword: "captcha", Kind: NoticeCaptcha}}), "")
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	_, err := driver.Relogin(ctx, profile.LoginCredential{Username: "u", Password: "p"})
	var blocker *ReloginBlocker
	if !errors.As(err, &blocker) || blocker.Kind != NoticeCaptcha {
		t.Fatalf("Relogin = %v; want a captcha blocker after submit", err)
	}
	if *posts != 1 {
		t.Fatalf("form posts = %d; want 1", *posts)
	}
}

// TestMockReloginAttachFallbackDeadPort (T1): a configured
// browser URL with nothing listening must fall back to the
// headless launch (the attach probe fails fast) and log in.
func TestMockReloginAttachFallbackDeadPort(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	srv, posts, _, _ := mockFormServer(t, mockLoginPageHTML(mockFormBody), nil)
	driver, _, _ := mockReloginDriver(t, srv, mockContractSignals("", []LoginBlockerSignal{{Keyword: "captcha", Kind: NoticeCaptcha}}), "http://127.0.0.1:1/")
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	cookies, err := driver.Relogin(ctx, profile.LoginCredential{Username: "SENTINEL-USER", Password: "SENTINEL-PASS"})
	if err != nil {
		t.Fatalf("Relogin (dead-port attach fallback): %v", err)
	}
	if *posts != 1 {
		t.Fatalf("form posts = %d; want 1", *posts)
	}
	found := false
	for _, c := range cookies {
		if c.Name == "hatch_sess" {
			found = true
		}
	}
	if !found {
		t.Fatalf("harvest = %+v; want hatch_sess", cookies)
	}
}

// TestObserveLoginRedirectStripsQuery (D6/R-5): the login
// page redirects through a tokenised URL. The observation
// must report the final URL with query and fragment
// stripped, and no token substring anywhere in the
// marshalled observation.
func TestObserveLoginRedirectStripsQuery(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login?code=FAKE-CODE-123&state=x#frag", http.StatusFound)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, mockLoginPageHTML(mockFormBody))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	_, port, _ := net.SplitHostPort(host)
	fake := &mockOutbound{target: host}
	baseDir := mockBaseDir(t)
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	obs, err := ObserveLoginPage(ctx, ObserveOptions{
		BaseDir:  baseDir,
		Inbound:  mockInbound{dialer: outbound.NewDialer(fake, &mockResolver{}, option.OutboundTLSOptions{})},
		Profile:  &profile.Profile{Name: "muse01"},
		LoginURL: "http://fake-login.test:" + port + "/start",
	})
	if err != nil {
		t.Fatalf("ObserveLoginPage: %v", err)
	}
	wantURL := "http://fake-login.test:" + port + "/login"
	if obs.URL != wantURL {
		t.Fatalf("observed URL = %q; want %q (query/fragment stripped)", obs.URL, wantURL)
	}
	raw, _ := json.Marshal(obs)
	if strings.Contains(string(raw), "FAKE-CODE") {
		t.Fatalf("token leaked into marshalled observation: %q", raw)
	}
	if len(obs.Elements) == 0 {
		t.Fatal("no form elements inventoried")
	}
}

// TestReloginFailureRemovesCreatedProfileDir (R-1): a
// failed launch (no Chrome binary) must fail fast with a
// clear error and create nothing — and must never wedge
// the attempt past context cancellation (chromedp's cancel
// waits forever for a process that never started).
func TestReloginFailureRemovesCreatedProfileDir(t *testing.T) {
	t.Setenv("CASTCTL_CHROMIUM_PATH", "/nonexistent/chrome-for-test")
	srv, _, _, _ := mockFormServer(t, mockLoginPageHTML(mockFormBody), nil)
	driver, _, baseDir := mockReloginDriver(t, srv, mockContractSignals("", []LoginBlockerSignal{{Keyword: "captcha", Kind: NoticeCaptcha}}), "")
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	_, err := driver.Relogin(ctx, profile.LoginCredential{Username: "u", Password: "p"})
	if err == nil {
		t.Fatal("Relogin with no Chrome binary succeeded; want an error")
	}
	if !strings.Contains(err.Error(), "chrome binary not found") {
		t.Fatalf("Relogin error = %v; want the fail-fast missing-binary error", err)
	}
	dir, err := browserProfileDir(baseDir, &profile.Profile{Name: "muse01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("profile dir %q still exists after failed launch; want it removed", dir)
	}
}

// TestReloginMismatchRemovesCreatedProfileDir (R-1):
// with a real browser, a page that never matches the
// contract (30s mismatch deadline) is a failed attempt:
// the profile dir the launch created must be removed.
func TestReloginMismatchRemovesCreatedProfileDir(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<!doctype html><html><body><p>no form here</p></body></html>")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	driver, _, baseDir := mockReloginDriver(t, srv, mockContractSignals("", []LoginBlockerSignal{{Keyword: "captcha", Kind: NoticeCaptcha}}), "")
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	_, err := driver.Relogin(ctx, profile.LoginCredential{Username: "u", Password: "p"})
	var blocker *ReloginBlocker
	if !errors.As(err, &blocker) || blocker.Detail != "contract_mismatch" {
		t.Fatalf("Relogin = %v; want a contract_mismatch blocker", err)
	}
	dir, err := browserProfileDir(baseDir, &profile.Profile{Name: "muse01"})
	if err != nil {
		t.Fatal(err)
	}
	// D9: settle-poll for absence. A lingering Chrome child
	// can recreate (part of) the dir after RemoveAll, so an
	// immediate Stat assertion flakes. Poll for absence
	// over a settle window; if the dir is still present
	// afterwards, it must hold no cookie store — the
	// recreated skeleton holds lock/empty files only.
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, statErr := os.Stat(dir)
		if os.IsNotExist(statErr) {
			return
		}
		if statErr != nil {
			t.Fatal(statErr)
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	var cookieStore bool
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && (d.Name() == "Cookies" || d.Name() == "Cookies-journal") {
			cookieStore = true
		}
		return nil
	})
	if cookieStore {
		t.Fatalf("profile dir %q still holds a cookie store after failed attempt; want it removed", dir)
	}
}

// TestReloginFailurePreservesExistingProfileDir (R-1): a
// pre-existing profile dir (possibly the screencast login's
// Chrome state) must never be deleted from the re-login
// path, even on failure.
func TestReloginFailurePreservesExistingProfileDir(t *testing.T) {
	t.Setenv("CASTCTL_CHROMIUM_PATH", "/nonexistent/chrome-for-test")
	srv, _, _, _ := mockFormServer(t, mockLoginPageHTML(mockFormBody), nil)
	driver, _, baseDir := mockReloginDriver(t, srv, mockContractSignals("", []LoginBlockerSignal{{Keyword: "captcha", Kind: NoticeCaptcha}}), "")
	dir, err := browserProfileDir(baseDir, &profile.Profile{Name: "muse01"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "marker.txt")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	if _, err := driver.Relogin(ctx, profile.LoginCredential{Username: "u", Password: "p"}); err == nil {
		t.Fatal("Relogin with no Chrome binary succeeded; want an error")
	}
	if raw, err := os.ReadFile(marker); err != nil || string(raw) != "keep" {
		t.Fatalf("marker = %q err=%v; want the pre-existing dir preserved", raw, err)
	}
}

// TestObserveFailureRemovesCreatedProfileDir (R-1): a
// failed observation (no Chrome binary) must fail fast and
// leave no profile dir behind.
func TestObserveFailureRemovesCreatedProfileDir(t *testing.T) {
	t.Setenv("CASTCTL_CHROMIUM_PATH", "/nonexistent/chrome-for-test")
	srv, _, _, _ := mockFormServer(t, mockLoginPageHTML(mockFormBody), nil)
	host := strings.TrimPrefix(srv.URL, "http://")
	fake := &mockOutbound{target: host}
	baseDir := mockBaseDir(t)
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	if _, err := ObserveLoginPage(ctx, ObserveOptions{
		BaseDir:  baseDir,
		Inbound:  mockInbound{dialer: outbound.NewDialer(fake, &mockResolver{}, option.OutboundTLSOptions{})},
		Profile:  &profile.Profile{Name: "muse01"},
		LoginURL: srv.URL + "/login",
	}); err == nil {
		t.Fatal("ObserveLoginPage with no Chrome binary succeeded; want an error")
	}
	dir, err := browserProfileDir(baseDir, &profile.Profile{Name: "muse01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("profile dir %q still exists after failed observation; want it removed", dir)
	}
}
