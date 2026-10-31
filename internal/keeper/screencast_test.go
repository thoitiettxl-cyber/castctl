// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

func TestResolveScreencastTarget(t *testing.T) {
	list := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Exactly one Muse page: resolved.
	srv := list(`[{"id":"T1","type":"page","url":"https://muse.ai/","title":"SYNTHETIC"},{"id":"T2","type":"page","url":"https://example.com/","title":"other"}]`)
	id, err := ResolveScreencastTarget(ctx, srv.URL)
	srv.Close()
	if err != nil || string(id) != "T1" {
		t.Fatalf("id = %q, err = %v; want T1", id, err)
	}
	// Zero Muse pages: error.
	srv = list(`[{"id":"T2","type":"page","url":"https://example.com/","title":"other"}]`)
	if _, err := ResolveScreencastTarget(ctx, srv.URL); err == nil {
		t.Fatal("zero matches accepted")
	}
	srv.Close()
	// Several Muse pages: error, never a guess.
	srv = list(`[{"id":"T1","type":"page","url":"https://muse.ai/"},{"id":"T3","type":"page","url":"https://auth.muse.ai/login"}]`)
	if _, err := ResolveScreencastTarget(ctx, srv.URL); err == nil {
		t.Fatal("several matches accepted")
	}
	srv.Close()
	// Non-page targets ignored; malformed JSON errors.
	srv = list(`[{"id":"T9","type":"background_page","url":"https://muse.ai/"}]`)
	if _, err := ResolveScreencastTarget(ctx, srv.URL); err == nil {
		t.Fatal("background_page matched")
	}
	srv.Close()
	srv = list(`not json`)
	if _, err := ResolveScreencastTarget(ctx, srv.URL); err == nil {
		t.Fatal("malformed /json/list accepted")
	}
	srv.Close()
}

func TestResolveScreencastTargetWwwHost(t *testing.T) {
	// Red-team N15: www.muse.ai is the same app host; a tab
	// open there must resolve, not fail closed with "no Muse
	// page".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"T1","type":"page","url":"https://www.muse.ai/","title":"SYNTHETIC"}]`))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	id, err := ResolveScreencastTarget(ctx, srv.URL)
	if err != nil || string(id) != "T1" {
		t.Fatalf("id = %q, err = %v; want T1", id, err)
	}
}

func TestLaunchRunnerFailsClosedWithoutInbound(t *testing.T) {
	// S2 verdict: no inbound builder exists at this base, so
	// the launch path must refuse BEFORE spawning anything.
	// No browser process is started: the error is immediate
	// and typed, and the runner never touches the transport.
	runner := NewLaunchRunner(t.TempDir(), &profile.Profile{Name: "muse01"}, "", nil)
	tr := NewFakeTransport(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := runner.Run(ctx, tr)
	if !errors.Is(res.Err, ErrLaunchUnavailable) {
		t.Fatalf("launch result = %+v; want ErrLaunchUnavailable", res)
	}
	if res.Outcome != LoginFailed {
		t.Fatalf("launch outcome = %q; want failed", res.Outcome)
	}
}

func TestResolveBrowserPathOrder(t *testing.T) {
	if got := resolveBrowserPath("/flag/chrome"); got != "/flag/chrome" {
		t.Fatalf("flag path = %q", got)
	}
	t.Setenv(ChromiumPathEnv, "/env/chrome")
	if got := resolveBrowserPath(""); got != "/env/chrome" {
		t.Fatalf("env path = %q", got)
	}
	t.Setenv(ChromiumPathEnv, "")
	if got := resolveBrowserPath(""); got != "" {
		t.Fatalf("empty path = %q; want empty (chromedp PATH search)", got)
	}
}

func TestBrowserProfileDir(t *testing.T) {
	dir, err := browserProfileDir(t.TempDir(), &profile.Profile{Name: "muse01"})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(dir) != "chromium-profile" {
		t.Fatalf("dir = %q", dir)
	}
}

func TestPortFileExporterRejectsSymlink(t *testing.T) {
	// Red-team N16: a symlinked DevToolsActivePort must not
	// redirect the debug-port read outside the profile dir.
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "DevToolsActivePort")
	if err := os.WriteFile(target, []byte("9226\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "DevToolsActivePort")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := (portFileExporter{dir: dir}).Export(ctx); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Export with symlinked port file = %v; want a symlink error", err)
	}
}
