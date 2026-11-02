// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"errors"
	"fmt"
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

// Loop-2 mock tests: S8 guard exercised through a real
// headless login (default allowlist refuses, explicit
// allowlist succeeds), S17 pre-existing-dir preservation
// through a REAL failed launch, and the driver match-timeout
// override. Same harness as relogin_mock_test.go: fake login
// page on loopback through the S2 proxy, fake sentinels only.

func (f *mockOutbound) dialCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dials)
}

// mockEntryDriver builds a driver wired to a keeper entry:
// the entry's Effective* timeouts tune the driver and the
// entry's allowlist gates the S2 proxy — with NO extra host
// listed, so the entry's allowlist is exactly what the
// guard sees.
func mockEntryDriver(t *testing.T, srv *httptest.Server, contract LoginContract, entry *profile.KeeperEntry) (ReloginDriver, *mockOutbound, string) {
	t.Helper()
	host := strings.TrimPrefix(srv.URL, "http://")
	_, port, _ := net.SplitHostPort(host)
	fake := &mockOutbound{target: host}
	baseDir := mockBaseDir(t)
	if contract.LoginURL == "" {
		contract.LoginURL = "http://fake-login.test:" + port + "/login"
	}
	opts := mockProxyOptsForEntry(entry)
	driver := NewReloginDriver(ReloginOptions{
		BaseDir:     baseDir,
		Inbound:     mockInbound{dialer: outbound.NewDialer(fake, &mockResolver{}, option.OutboundTLSOptions{}), opts: &opts},
		Profile:     &profile.Profile{Name: "muse01"},
		Contract:    contract,
		MaxAttempts: 1,
		Entry:       entry,
	})
	return driver, fake, baseDir
}

// TestMockReloginGuardRefusesDefaultAllowlist (S8): with
// the default allowlist (no fake-login.test), the guard
// must refuse the mock login host: zero dials spent, and
// the login fails. The sibling success test proves the
// same flow succeeds when the host is listed, so the
// refusal is the guard's, not the harness's.
func TestMockReloginGuardRefusesDefaultAllowlist(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	srv, _, _, _ := mockFormServer(t, mockLoginPageHTML(mockFormBody), nil)
	entry := &profile.KeeperEntry{ReloginMatchSet: true, ReloginMatchTimeout: 5 * time.Second}
	driver, fake, _ := mockEntryDriver(t, srv, mockContractSignals("", []LoginBlockerSignal{{Keyword: "captcha", Kind: NoticeCaptcha}}), entry)
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	if _, err := driver.Relogin(ctx, profile.LoginCredential{Username: "SENTINEL-USER", Password: "SENTINEL-PASS"}); err == nil {
		t.Fatal("Relogin through a refusing guard succeeded; want an error")
	}
	if got := fake.dialCount(); got != 0 {
		t.Fatalf("outbound dials = %d; want 0 (guard refuses before dialling)", got)
	}
}

// TestMockReloginGuardAllowsListedMockHost (S8): the same
// entry-wired driver succeeds when the mock host is on the
// entry's allowlist — the allowlist is the mechanism, and
// entry timeouts/allowlist reach the driver and proxy.
func TestMockReloginGuardAllowsListedMockHost(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	srv, posts, gotUser, gotPass := mockFormServer(t, mockLoginPageHTML(mockFormBody), nil)
	entry := &profile.KeeperEntry{
		ProxyHostsSet:       true,
		ProxyAllowedHosts:   []string{"auth.muse.ai", "muse.ai", "fake-login.test"},
		ReloginMatchSet:     true,
		ReloginMatchTimeout: 10 * time.Second,
	}
	driver, fake, _ := mockEntryDriver(t, srv, mockContractSignals("", []LoginBlockerSignal{{Keyword: "captcha", Kind: NoticeCaptcha}}), entry)
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	cookies, err := driver.Relogin(ctx, profile.LoginCredential{Username: "SENTINEL-USER", Password: "SENTINEL-PASS"})
	if err != nil {
		t.Fatalf("Relogin: %v", err)
	}
	if *posts != 1 || *gotUser != "SENTINEL-USER" || *gotPass != "SENTINEL-PASS" {
		t.Fatalf("posts=%d user=%q pass=%q; want 1/SENTINEL-USER/SENTINEL-PASS", *posts, *gotUser, *gotPass)
	}
	if !hasHatchSess(cookies) {
		t.Fatalf("harvested cookies = %v; want a hatch_sess cookie", cookies)
	}
	if got := fake.dialCount(); got == 0 {
		t.Fatal("outbound dials = 0; want dials spent (guard allowed the host)")
	}
}

// TestReloginMismatchPreservesPreExistingDirRealLaunch
// (S17): a pre-existing profile dir must survive a REAL
// failed launch (real browser + mismatch page), not only
// the missing-binary path.
func TestReloginMismatchPreservesPreExistingDirRealLaunch(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<!doctype html><html><body><p>no form here</p></body></html>")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
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
	_, err = driver.Relogin(ctx, profile.LoginCredential{Username: "u", Password: "p"})
	var blocker *ReloginBlocker
	if !errors.As(err, &blocker) || blocker.Detail != "contract_mismatch" {
		t.Fatalf("Relogin = %v; want a contract_mismatch blocker", err)
	}
	if raw, err := os.ReadFile(marker); err != nil || string(raw) != "keep" {
		t.Fatalf("marker = %q err=%v; want the pre-existing dir preserved through a real failed launch", raw, err)
	}
}

// TestMockReloginMatchTimeoutHonoured (S10): an entry
// match timeout of 3s bounds a never-matching page far
// below the 30s default — the override reaches the driver.
func TestMockReloginMatchTimeoutHonoured(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<!doctype html><html><body><p>no form here</p></body></html>")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	entry := &profile.KeeperEntry{
		ProxyHostsSet:       true,
		ProxyAllowedHosts:   []string{"fake-login.test"},
		ReloginMatchSet:     true,
		ReloginMatchTimeout: 3 * time.Second,
	}
	driver, _, _ := mockEntryDriver(t, srv, mockContractSignals("", []LoginBlockerSignal{{Keyword: "captcha", Kind: NoticeCaptcha}}), entry)
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	start := time.Now()
	_, err := driver.Relogin(ctx, profile.LoginCredential{Username: "u", Password: "p"})
	elapsed := time.Since(start)
	var blocker *ReloginBlocker
	if !errors.As(err, &blocker) || blocker.Detail != "contract_mismatch" {
		t.Fatalf("Relogin = %v; want a contract_mismatch blocker", err)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("mismatch took %v; want well below the 30s default (3s timeout honoured)", elapsed)
	}
}

// TestObserveFailureErrorHasNoToken (R-7 error path): a
// failed observation against a tokenised URL must not echo
// the token in its error — the error path is an output
// surface too.
func TestObserveFailureErrorHasNoToken(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	// Closed target: the dial fails, the page cannot load.
	fake := &mockOutbound{target: "127.0.0.1:1"}
	baseDir := mockBaseDir(t)
	ctx, cancel := mockReloginCtx(t)
	defer cancel()
	_, err := ObserveLoginPage(ctx, ObserveOptions{
		BaseDir:  baseDir,
		Inbound:  mockInbound{dialer: outbound.NewDialer(fake, &mockResolver{}, option.OutboundTLSOptions{})},
		Profile:  &profile.Profile{Name: "muse01"},
		LoginURL: "http://fake-login.test:9/login?code=SENTINEL-CODE-999#frag",
	})
	if err == nil {
		t.Fatal("ObserveLoginPage against a closed target succeeded; want an error")
	}
	if strings.Contains(err.Error(), "SENTINEL-CODE-999") {
		t.Fatalf("observation error echoes the tokenised URL: %v", err)
	}
}
