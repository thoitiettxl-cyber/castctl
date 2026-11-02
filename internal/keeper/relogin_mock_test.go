// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Mock-server headless re-login test: a fake login page on
// loopback, reached ONLY through the S2 loopback proxy and a
// fake outbound that dials the test server whatever host it
// is asked for. No real network, no real Chrome profile, no
// credentials against a live page — the submitted values are
// test sentinels, and the harvested cookies are fake.
//
// The test needs a real Chrome binary: CASTCTL_CHROMIUM_PATH
// (Playwright build) or the PATH search. It skips when no
// binary exists, and fails loudly (not silently) when the
// binary exists but the launch fails.

// mockOutbound dials the test server for every destination,
// recording what it was asked for.
type mockOutbound struct {
	mu     sync.Mutex
	dials  []M.Socksaddr
	target string
}

func (f *mockOutbound) Type() string           { return "fake" }
func (f *mockOutbound) Tag() string            { return "fake" }
func (f *mockOutbound) Network() []string      { return []string{N.NetworkTCP} }
func (f *mockOutbound) Dependencies() []string { return nil }
func (f *mockOutbound) DialContext(ctx context.Context, nw string, dest M.Socksaddr) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, dest)
	f.mu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, nw, f.target)
}
func (f *mockOutbound) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("fake: ListenPacket not implemented")
}

var _ adapter.Outbound = (*mockOutbound)(nil)

type mockInbound struct{ dialer *outbound.Dialer }

func (m mockInbound) BuildInbound(_ context.Context, _ *profile.Profile) (string, func(), error) {
	proxy, proxyURL, err := outbound.NewLoopbackProxy(m.dialer)
	if err != nil {
		return "", nil, err
	}
	return proxyURL, func() { _ = proxy.Close() }, nil
}

func chromeTestPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("CASTCTL_CHROMIUM_PATH"); p != "" {
		return p
	}
	candidates := []string{
		os.ExpandEnv("$HOME/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome"),
		os.ExpandEnv("$HOME/.cache/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skip("no Chrome binary available for the headless re-login mock test")
	return ""
}

func mockLoginServer(t *testing.T, captcha bool) (*httptest.Server, *int, *string, *string) {
	t.Helper()
	posts := 0
	var gotUser, gotPass string
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			_ = r.ParseForm()
			gotUser = r.FormValue("username")
			gotPass = r.FormValue("password")
			http.SetCookie(w, &http.Cookie{Name: "hatch_sess", Value: "FAKE-HARVEST", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "other", Value: "FAKE-OTHER", Path: "/"})
			http.Redirect(w, r, "/done", http.StatusFound)
			return
		}
		captchaText := ""
		if captcha {
			captchaText = "<p>Please complete the captcha to continue</p>"
		}
		fmt.Fprintf(w, `<!doctype html><html><body>%s
<form action="/login" method="post">
<input id="user" name="username" type="text">
<input id="pass" name="password" type="password">
<button id="submit" type="submit">Log in</button>
</form></body></html>`, captchaText)
	})
	mux.HandleFunc("/done", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "done")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &posts, &gotUser, &gotPass
}

func mockContract(loginURL string) LoginContract {
	return LoginContract{
		Version:  1,
		Observed: true,
		LoginURL: loginURL,
		Steps: []LoginContractStep{
			{Action: "fill", Selector: "#user", Field: "username"},
			{Action: "fill", Selector: "#pass", Field: "password"},
			{Action: "click", Selector: "#submit"},
		},
		Blockers: []LoginBlockerSignal{
			{Keyword: "captcha", Kind: NoticeCaptcha},
		},
	}
}

func TestMockReloginHarvest(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	srv, posts, gotUser, gotPass := mockLoginServer(t, false)
	srvURL := srv.URL // http://127.0.0.1:port
	host := strings.TrimPrefix(srvURL, "http://")
	_, port, _ := net.SplitHostPort(host)

	fake := &mockOutbound{target: host}
	baseDir := t.TempDir()
	driver := NewReloginDriver(ReloginOptions{
		BaseDir:     baseDir,
		Inbound:     mockInbound{dialer: outbound.NewDialer(fake, &mockResolver{}, option.OutboundTLSOptions{})},
		Profile:     &profile.Profile{Name: "muse01"},
		Contract:    mockContract("http://fake-login.test:" + port + "/login"),
		MaxAttempts: 1,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cookies, err := driver.Relogin(ctx, profile.LoginCredential{Username: "SENTINEL-USER", Password: "SENTINEL-PASS"})
	if err != nil {
		t.Fatalf("Relogin: %v", err)
	}
	if *posts != 1 {
		t.Fatalf("form posts = %d; want 1", *posts)
	}
	if *gotUser != "SENTINEL-USER" || *gotPass != "SENTINEL-PASS" {
		t.Fatalf("server saw user=%q pass-set=%v; want the sentinels submitted", *gotUser, *gotPass != "")
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
	if len(fake.dials) == 0 {
		t.Fatal("fake outbound saw no dials: the browser did not go through the S2 proxy")
	}
	// Chrome also dials its own services on startup
	// (component update, variations): every dial goes
	// through the proxy, and at least one must be the
	// login host itself.
	sawLogin := false
	for _, d := range fake.dials {
		if d.String() == "fake-login.test:"+port {
			sawLogin = true
		}
	}
	if !sawLogin {
		t.Fatalf("outbound dials = %v; want at least one fake-login.test:%s (proxy-routed)", fake.dials, port)
	}
}

// mockResolver satisfies outbound.HostResolver without
// resolving anything: the fake outbound dials the test
// server directly.
type mockResolver struct{}

func (mockResolver) Lookup(_ context.Context, _ string, _ adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return nil, nil
}

func TestMockReloginCaptchaStopsBeforeSubmit(t *testing.T) {
	chromePath := chromeTestPath(t)
	t.Setenv("CASTCTL_CHROMIUM_PATH", chromePath)
	srv, posts, _, _ := mockLoginServer(t, true)
	host := strings.TrimPrefix(srv.URL, "http://")
	_, port, _ := net.SplitHostPort(host)

	fake := &mockOutbound{target: host}
	baseDir := t.TempDir()
	driver := NewReloginDriver(ReloginOptions{
		BaseDir:     baseDir,
		Inbound:     mockInbound{dialer: outbound.NewDialer(fake, &mockResolver{}, option.OutboundTLSOptions{})},
		Profile:     &profile.Profile{Name: "muse01"},
		Contract:    mockContract("http://fake-login.test:" + port + "/login"),
		MaxAttempts: 1,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := driver.Relogin(ctx, profile.LoginCredential{Username: "u", Password: "p"})
	var blocker *ReloginBlocker
	if !errors.As(err, &blocker) || blocker.Kind != NoticeCaptcha {
		t.Fatalf("Relogin = %v; want a captcha blocker", err)
	}
	if *posts != 0 {
		t.Fatalf("form posts = %d; want 0 (never submitted past a captcha)", *posts)
	}
}
