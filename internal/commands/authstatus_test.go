// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/keeper"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// jarCookies renders a minimal Netscape jar whose
// hatch_sess expires at exp (unix seconds). Values are fake.
func jarCookies(exp int64) string {
	return "# Netscape HTTP Cookie File\n.muse.ai\tTRUE\t/\tTRUE\t" + strconv.Itoa(int(exp)) + "\thatch_sess\tFAKE-VALUE\n"
}

// stringWriter adapts a strings.Builder to io.Writer for the
// Env's Stdout/Stderr fields (which accept any io.Writer).
type stringWriter struct{ b *strings.Builder }

func (w stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }

func TestAuthStatusOK(t *testing.T) {
	t.Parallel()
	exp := time.Now().Add(30 * 24 * time.Hour).Unix()
	home, configFile := testHome(t, `{"default_profile":"muse01","profiles":{"muse01":{}}}`)
	dir := filepath.Join(home, "profiles", "muse01")
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "cookies.txt"), []byte(jarCookies(exp)), 0o600)
	var outBuf, errBuf strings.Builder
	env2 := &Env{Stdout: stringWriter{&outBuf}, Stderr: stringWriter{&errBuf},
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	if code := Run(context.Background(), []string{"auth", "status"}, env2); code != 0 {
		t.Fatalf("status ok: code=%d stderr=%q", code, errBuf.String())
	}
	var res authStatusJSON
	if err := json.Unmarshal([]byte(outBuf.String()), &res); err != nil {
		t.Fatalf("status output: %v (%q)", err, outBuf.String())
	}
	if res.Status != "ok" || res.DrivingCookie != "hatch_sess" || res.NeedsAction {
		t.Fatalf("status = %+v; want ok/hatch_sess/no-action", res)
	}
	if strings.Contains(outBuf.String(), "FAKE-VALUE") {
		t.Fatal("cookie value leaked into auth status output")
	}
}

func TestAuthStatusExpiringAndExpired(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		exp  int64
		code int
		want string
	}{
		{"expiring", time.Now().Add(48 * time.Hour).Unix(), 1, "expiring"},
		{"expired", time.Now().Add(-time.Hour).Unix(), 3, "expired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, configFile := testHome(t, `{"default_profile":"muse01","profiles":{"muse01":{}}}`)
			dir := filepath.Join(home, "profiles", "muse01")
			_ = os.MkdirAll(dir, 0o700)
			_ = os.WriteFile(filepath.Join(dir, "cookies.txt"), []byte(jarCookies(tc.exp)), 0o600)
			var outBuf, errBuf strings.Builder
			env := &Env{Stdout: stringWriter{&outBuf}, Stderr: stringWriter{&errBuf},
				Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
			if code := Run(context.Background(), []string{"auth", "status"}, env); code != tc.code {
				t.Fatalf("status %s: code=%d want %d stderr=%q", tc.name, code, tc.code, errBuf.String())
			}
			var res authStatusJSON
			if err := json.Unmarshal([]byte(outBuf.String()), &res); err != nil {
				t.Fatalf("status output: %v", err)
			}
			if res.Status != tc.want || !res.NeedsAction {
				t.Fatalf("status = %+v; want %s/needs-action", res, tc.want)
			}
		})
	}
}

func TestAuthStatusMissingCookiesExpired(t *testing.T) {
	t.Parallel()
	home, configFile := testHome(t, `{"default_profile":"muse01","profiles":{"muse01":{}}}`)
	// No cookies file in the profile dir at all.
	_ = os.MkdirAll(filepath.Join(home, "profiles", "muse01"), 0o700)
	var outBuf, errBuf strings.Builder
	env := &Env{Stdout: stringWriter{&outBuf}, Stderr: stringWriter{&errBuf},
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	if code := Run(context.Background(), []string{"auth", "status"}, env); code != 3 {
		t.Fatalf("missing cookies: code=%d want 3 stderr=%q", code, errBuf.String())
	}
	var res authStatusJSON
	if err := json.Unmarshal([]byte(outBuf.String()), &res); err != nil {
		t.Fatalf("status output: %v", err)
	}
	if res.Status != "expired" || res.CookiesSeen != 0 {
		t.Fatalf("status = %+v; want expired/0", res)
	}
}

func TestAuthStatusAllWorstWins(t *testing.T) {
	t.Parallel()
	home, configFile := testHome(t, `{"default_profile":"muse01","profiles":{"muse01":{},"other":{}}}`)
	for _, name := range []string{"muse01", "other"} {
		dir := filepath.Join(home, "profiles", name)
		_ = os.MkdirAll(dir, 0o700)
		exp := time.Now().Add(30 * 24 * time.Hour).Unix()
		if name == "other" {
			exp = time.Now().Add(-time.Hour).Unix()
		}
		_ = os.WriteFile(filepath.Join(dir, "cookies.txt"), []byte(jarCookies(exp)), 0o600)
	}
	var outBuf, errBuf strings.Builder
	env := &Env{Stdout: stringWriter{&outBuf}, Stderr: stringWriter{&errBuf},
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	if code := Run(context.Background(), []string{"auth", "status", "--all"}, env); code != 3 {
		t.Fatalf("--all: code=%d want 3 stderr=%q", code, errBuf.String())
	}
	var res []authStatusJSON
	if err := json.Unmarshal([]byte(outBuf.String()), &res); err != nil {
		t.Fatalf("--all output: %v (%q)", err, outBuf.String())
	}
	if len(res) != 2 {
		t.Fatalf("--all returned %d profiles; want 2", len(res))
	}
}

func TestAuthStatusHeadlessReasons(t *testing.T) {
	t.Parallel()
	exp := time.Now().Add(30 * 24 * time.Hour).Unix()
	// No keeper entry at all: no_keeper_entry.
	home, configFile := testHome(t, `{"default_profile":"muse01","profiles":{"muse01":{}}}`)
	dir := filepath.Join(home, "profiles", "muse01")
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "cookies.txt"), []byte(jarCookies(exp)), 0o600)
	var outBuf, errBuf strings.Builder
	env := &Env{Stdout: stringWriter{&outBuf}, Stderr: stringWriter{&errBuf},
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	if code := Run(context.Background(), []string{"auth", "status"}, env); code != 0 {
		t.Fatalf("status: code=%d", code)
	}
	var res authStatusJSON
	_ = json.Unmarshal([]byte(outBuf.String()), &res)
	if res.HeadlessReason != "no_keeper_entry" || res.HeadlessAvailable {
		t.Fatalf("headless = %v/%q; want false/no_keeper_entry", res.HeadlessAvailable, res.HeadlessReason)
	}
	// Keeper entry, no credentials: no_chromedp (tag off)
	// or no_credentials (tag on).
	home2, configFile2 := testHome(t, `{"default_profile":"muse01","profiles":{"muse01":{}},"keeper":[{"tag":"k1","profile":"muse01","interval":"1h"}]}`)
	dir2 := filepath.Join(home2, "profiles", "muse01")
	_ = os.MkdirAll(dir2, 0o700)
	_ = os.WriteFile(filepath.Join(dir2, "cookies.txt"), []byte(jarCookies(exp)), 0o600)
	outBuf.Reset()
	errBuf.Reset()
	env2 := &Env{Stdout: stringWriter{&outBuf}, Stderr: stringWriter{&errBuf},
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile2})}
	if code := Run(context.Background(), []string{"auth", "status"}, env2); code != 0 {
		t.Fatalf("status: code=%d stderr=%q", code, errBuf.String())
	}
	_ = json.Unmarshal([]byte(outBuf.String()), &res)
	want := "no_credentials"
	if !keeper.ReloginAvailable() {
		want = "no_chromedp"
	}
	if res.HeadlessReason != want || res.HeadlessAvailable {
		t.Fatalf("headless = %v/%q; want false/%s", res.HeadlessAvailable, res.HeadlessReason, want)
	}
}

// TestSentinelNeverLeavesConfig pins the Q8 probe at the
// command layer: a sentinel credential in config.json must
// never appear in auth status output, stderr, keeper check
// output, or the session-state file.
func TestSentinelNeverLeavesConfig(t *testing.T) {
	t.Parallel()
	const sentinelUser = "SENTINEL-USER-9f3a7c"
	const sentinelPass = "SENTINEL-PASS-9f3a7c"
	cfg := `{"default_profile":"muse01","profiles":{"muse01":{}},` +
		`"credentials":[{"tag":"c1","profile":"muse01","username":"` + sentinelUser + `","password":"` + sentinelPass + `"}],` +
		`"keeper":[{"tag":"k1","profile":"muse01","interval":"1h","credentials":"c1"}]}`
	fake := &keeperFakeGateway{sessionStatus: 200, authStatus: 200}
	env, out, errb, home := keeperTestEnv(t, cfg, fake)
	// auth status (state-only).
	if code := Run(context.Background(), []string{"auth", "status"}, env); code != 0 && code != 3 {
		t.Fatalf("auth status: code=%d stderr=%q", code, errb.String())
	}
	// keeper check (fake gateway, no browser).
	out.Reset()
	errb.Reset()
	if code := Run(context.Background(), []string{"keeper", "check"}, env); code != 0 {
		t.Fatalf("keeper check: code=%d stderr=%q", code, errb.String())
	}
	for _, hay := range []string{out.String(), errb.String()} {
		if strings.Contains(hay, sentinelUser) || strings.Contains(hay, sentinelPass) {
			t.Fatalf("sentinel leaked into command output: %q", hay)
		}
	}
	// State file on disk.
	statePath := filepath.Join(home, "profiles", "muse01", "session-state.json")
	if raw, err := os.ReadFile(statePath); err == nil {
		if strings.Contains(string(raw), sentinelUser) || strings.Contains(string(raw), sentinelPass) {
			t.Fatal("sentinel leaked into session-state.json")
		}
	}
	// The config file itself still holds the values (it
	// must: the keeper reads them), but a redacted view
	// must not.
	single, found, err := profile.LoadSingleConfig(home)
	if err != nil || !found {
		t.Fatalf("load config: found=%v err=%v", found, err)
	}
	redactedJSON, rerr := profile.RedactConfig(single)
	if rerr != nil {
		t.Fatalf("RedactConfig: %v", rerr)
	}
	if strings.Contains(string(redactedJSON), sentinelUser) || strings.Contains(string(redactedJSON), sentinelPass) {
		t.Fatal("sentinel leaked into RedactConfig output")
	}
}

// testLogger records Info/Warn lines for the embedded
// keeper test.
type testLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *testLogger) Info(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, "INFO "+msg)
}

func (l *testLogger) Warn(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, "WARN "+msg)
}

func (l *testLogger) has(substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

// TestEmbeddedKeeperCoRun pins G5 composition: the embedded
// keeper ticks inside the host process, a second start for
// the same entry is refused by single-flight (never stolen),
// and release frees the flight.
func TestEmbeddedKeeperCoRun(t *testing.T) {
	t.Parallel()
	fake := &keeperFakeGateway{sessionStatus: 200, authStatus: 200}
	env, _, _, home := keeperTestEnv(t, keeperTestConfig(), fake)
	g := &globalOpts{}
	logger := &testLogger{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := startEmbeddedKeeper(ctx, env, g, logger)
	// Wait for the first tick to be logged (bounded).
	deadline := time.Now().Add(5 * time.Second)
	for !logger.has("keeper tick") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !logger.has("keeper tick") {
		t.Fatalf("embedded keeper never ticked; log=%v", logger.lines)
	}
	// Second start must skip the entry (already running),
	// never steal it.
	logger2 := &testLogger{}
	release2 := startEmbeddedKeeper(ctx, env, g, logger2)
	release2()
	if !logger2.has("already running") {
		t.Fatalf("second start did not report already-running; log=%v", logger2.lines)
	}
	// Release, then the flight must be free again.
	cancel()
	release()
	paths, err := profile.ProfilePaths(home, "default")
	if err != nil {
		t.Fatal(err)
	}
	rel, err := keeper.AcquireSingleFlight(paths.Dir, "k1", keeper.RealClock)
	if err != nil {
		t.Fatalf("flight not released after embedded keeper stop: %v", err)
	}
	rel()
}
