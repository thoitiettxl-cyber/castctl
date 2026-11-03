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
	// or no_credentials_ref (tag on — the contract gate now
	// passes, the embedded fixture is observed, so the
	// credentials gates report first).
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
	want := "no_credentials_ref"
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
	// The raw-bytes redaction (the web UI GET /api/v1/config
	// path) must not leak either.
	rawCfg, rerr := os.ReadFile(filepath.Join(home, "config.json"))
	if rerr != nil {
		t.Fatalf("read config: %v", rerr)
	}
	rawRedacted, rerr := profile.RedactRawConfig(rawCfg)
	if rerr != nil {
		t.Fatalf("RedactRawConfig: %v", rerr)
	}
	if strings.Contains(string(rawRedacted), sentinelUser) || strings.Contains(string(rawRedacted), sentinelPass) {
		t.Fatal("sentinel leaked into RedactRawConfig output")
	}
	// Display surfaces: profile show and keeper status.
	out.Reset()
	errb.Reset()
	if code := Run(context.Background(), []string{"profile", "show"}, env); code != 0 {
		t.Fatalf("profile show: code=%d stderr=%q", code, errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := Run(context.Background(), []string{"keeper", "status"}, env); code != 0 {
		t.Fatalf("keeper status: code=%d stderr=%q", code, errb.String())
	}
	for _, hay := range []string{out.String(), errb.String()} {
		if strings.Contains(hay, sentinelUser) || strings.Contains(hay, sentinelPass) {
			t.Fatalf("sentinel leaked into display output: %q", hay)
		}
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

// TestHeadlessCapability (D3/T6) pins the pure capability
// decision: an unobserved contract reports headless
// unavailable with reason no_contract even when a keeper
// entry, a driver, and credentials are all present; the
// observed-contract case reports available.
func TestHeadlessCapability(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name            string
		entry, driver   bool
		creds, observed bool
		ref             bool
		wantAvail       bool
		wantReason      string
	}{
		{"no entry", false, false, false, false, false, false, "no_keeper_entry"},
		{"entry no driver", true, false, false, false, false, false, "no_chromedp"},
		{"entry driver no creds unobserved", true, true, false, false, false, false, "no_contract"},
		{"creds unobserved no ref", true, true, true, false, false, false, "no_contract"},
		{"observed no ref", true, true, true, true, false, false, "no_credentials_ref"},
		{"observed ref no creds", true, true, false, true, true, false, "no_credentials"},
		{"all present observed", true, true, true, true, true, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			avail, reason := headlessCapability(tc.entry, tc.driver, tc.creds, tc.observed, tc.ref)
			if avail != tc.wantAvail || reason != tc.wantReason {
				t.Fatalf("headlessCapability = %v/%q; want %v/%q", avail, reason, tc.wantAvail, tc.wantReason)
			}
		})
	}
}

// TestValidateObserveLoginURL (S7) pins the --login-url
// validation: https with a host only; the error never echoes
// the supplied URL.
func TestValidateObserveLoginURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw string
		ok  bool
	}{
		{"https://auth.muse.ai/login", true},
		{"https://auth.muse.ai:8443/a/b", true},
		{"http://auth.muse.ai/login", false},
		{"https://", false},
		{"https:///path", false},
		{"", false},
		{"auth.muse.ai/login", false},
		{"ftp://auth.muse.ai/login", false},
		{"https://auth.muse.ai/login?code=SECRET", true},
	}
	for _, tc := range cases {
		if err := validateObserveLoginURL(tc.raw); (err == nil) != tc.ok {
			t.Errorf("validateObserveLoginURL(%q) err=%v; want ok=%v", tc.raw, err, tc.ok)
		}
	}
	if err := validateObserveLoginURL("http://x/?token=SENTINEL-TOKEN-123"); err == nil {
		t.Fatal("http URL accepted")
	} else if strings.Contains(err.Error(), "SENTINEL-TOKEN-123") {
		t.Fatalf("validation error echoes the URL: %q", err.Error())
	}
}

// jarCookiesValue renders a minimal Netscape jar like jarCookies
// but with the given hatch_sess value. Values are fake.
func jarCookiesValue(exp int64, value string) string {
	return "# Netscape HTTP Cookie File\n.muse.ai\tTRUE\t/\tTRUE\t" + strconv.Itoa(int(exp)) + "\thatch_sess\t" + value + "\n"
}

// runAuthStatus runs `auth status` against configFile and returns
// its exit code and raw stdout.
func runAuthStatus(t *testing.T, configFile string) (int, string) {
	t.Helper()
	var outBuf, errBuf strings.Builder
	env := &Env{Stdout: stringWriter{&outBuf}, Stderr: stringWriter{&errBuf},
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	code := Run(context.Background(), []string{"auth", "status"}, env)
	if code != 0 && code != 1 && code != 3 {
		t.Fatalf("auth status: code=%d stderr=%q", code, errBuf.String())
	}
	return code, outBuf.String()
}

func TestAuthStatusLivenessNeverChecked(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		exp  int64
		code int
		want string
	}{
		{"ok", time.Now().Add(30 * 24 * time.Hour).Unix(), 0, "ok"},
		{"expiring", time.Now().Add(48 * time.Hour).Unix(), 1, "expiring"},
		{"expired", time.Now().Add(-time.Hour).Unix(), 3, "expired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, configFile := testHome(t, `{"default_profile":"muse01","profiles":{"muse01":{}}}`)
			dir := filepath.Join(home, "profiles", "muse01")
			_ = os.MkdirAll(dir, 0o700)
			_ = os.WriteFile(filepath.Join(dir, "cookies.txt"), []byte(jarCookies(tc.exp)), 0o600)
			code, raw := runAuthStatus(t, configFile)
			if code != tc.code {
				t.Fatalf("code=%d want %d", code, tc.code)
			}
			var res authStatusJSON
			if err := json.Unmarshal([]byte(raw), &res); err != nil {
				t.Fatalf("status output: %v", err)
			}
			if res.Status != tc.want {
				t.Fatalf("status = %q, want %q", res.Status, tc.want)
			}
			if res.LivenessChecked {
				t.Fatalf("liveness_checked = true; auth status never performs a live check")
			}
			// The field must serialize explicitly: a missing
			// field would unmarshal to the same false.
			if !strings.Contains(raw, `"liveness_checked": false`) {
				t.Fatalf("raw output lacks liveness_checked:false: %q", raw)
			}
		})
	}
}

func TestAuthStatusValueBlind(t *testing.T) {
	t.Parallel()
	// Same expiry, different hatch_sess values: the report reads
	// expiry metadata only, so both outputs are identical, neither
	// contains a cookie value, and both say the session was not
	// live-checked. A dead cookie and a live one are
	// indistinguishable here by design; keeper check is the live
	// verdict.
	exp := time.Now().Add(30 * 24 * time.Hour).Unix()
	var raws []string
	for _, value := range []string{"FAKE-VALUE-A", "FAKE-VALUE-B"} {
		home, configFile := testHome(t, `{"default_profile":"muse01","profiles":{"muse01":{}}}`)
		dir := filepath.Join(home, "profiles", "muse01")
		_ = os.MkdirAll(dir, 0o700)
		_ = os.WriteFile(filepath.Join(dir, "cookies.txt"), []byte(jarCookiesValue(exp, value)), 0o600)
		code, raw := runAuthStatus(t, configFile)
		if code != 0 {
			t.Fatalf("value %q: code=%d want 0", value, code)
		}
		if strings.Contains(raw, value) {
			t.Fatalf("cookie value leaked into auth status output: %q", raw)
		}
		raws = append(raws, raw)
	}
	if raws[0] != raws[1] {
		t.Fatalf("outputs differ by cookie value:\n%s\n%s", raws[0], raws[1])
	}
}
