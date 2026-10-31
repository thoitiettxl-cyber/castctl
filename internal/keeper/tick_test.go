// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

type fakeChecker struct {
	mu      sync.Mutex
	scripts []checkScript
	calls   int
	headers []string
}

type checkScript struct {
	updates []CookieUpdate
	err     error
}

func (f *fakeChecker) Check(_ context.Context, header string) ([]CookieUpdate, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headers = append(f.headers, header)
	f.calls++
	idx := f.calls - 1
	if idx >= len(f.scripts) {
		idx = len(f.scripts) - 1
	}
	s := f.scripts[idx]
	return s.updates, 0, s.err
}

func (f *fakeChecker) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeExporter struct {
	mu      sync.Mutex
	cookies []ExportedCookie
	err     error
	calls   int
}

func (f *fakeExporter) Export(_ context.Context) ([]ExportedCookie, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.cookies, f.err
}

type fakeNotifier struct {
	mu    sync.Mutex
	kinds []NoticeKind
	err   error
}

func (f *fakeNotifier) Notify(_ context.Context, kind NoticeKind, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kinds = append(f.kinds, kind)
	return f.err
}

func (f *fakeNotifier) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.kinds)
}

var tickNow = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func tickFixture(t *testing.T, initial []StoredCookie) (baseDir, cookiesPath, profileDir string) {
	t.Helper()
	baseDir = t.TempDir()
	paths, err := profile.ProfilePaths(baseDir, "muse01")
	if err != nil {
		t.Fatal(err)
	}
	cookiesPath = paths.Cookies
	profileDir = paths.Dir
	if initial != nil {
		data, err := SerializeJar(initial)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := profile.WriteCookiesFile(baseDir, "muse01", cookiesPath, data); err != nil {
			t.Fatalf("WriteCookiesFile: %v", err)
		}
	}
	return baseDir, cookiesPath, profileDir
}

func tickDeps(clock Clock, checker Checker, exporter Exporter, notifier Notifier) TickDeps {
	return TickDeps{
		Clock:       clock,
		Entry:       &profile.KeeperEntry{Tag: "k1", Profile: "muse01", Browser: "http://127.0.0.1:9226/", Interval: time.Hour, IntervalSet: true},
		Profile:     &profile.Profile{Name: "muse01"},
		Checker:     checker,
		Exporter:    exporter,
		Notifier:    notifier,
		Jitter:      func() float64 { return 0.5 },
		LockTimeout: 5 * time.Second,
	}
}

func readJar(t *testing.T, cookiesPath string) []StoredCookie {
	t.Helper()
	raw, err := os.ReadFile(cookiesPath)
	if err != nil {
		t.Fatal(err)
	}
	cookies, err := ParseJar(raw)
	if err != nil {
		t.Fatalf("ParseJar(result): %v", err)
	}
	return cookies
}

func readState(t *testing.T, profileDir string) *SessionState {
	t.Helper()
	st, err := LoadState(profileDir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	return st
}

// tickRun runs Tick with the fixture baseDir wired in.
func tickRun(t *testing.T, baseDir string, deps TickDeps) TickResult {
	t.Helper()
	deps.BaseDir = baseDir
	return Tick(context.Background(), deps)
}

func TestTickOKNoChangeWritesNothing(t *testing.T) {
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Secure: true, Expires: tickNow.Add(30 * 24 * time.Hour).Unix()},
	}
	baseDir, cookiesPath, profileDir := tickFixture(t, initial)
	before, _ := os.ReadFile(cookiesPath)
	checker := &fakeChecker{scripts: []checkScript{{}}}
	deps := tickDeps(&fakeClock{now: tickNow}, checker, nil, nil)
	res := tickRun(t, baseDir, deps)
	if res.Outcome != OutcomeOK || res.Stopped || res.WroteCookies {
		t.Fatalf("result = %+v; want ok, no write", res)
	}
	after, _ := os.ReadFile(cookiesPath)
	if string(after) != string(before) {
		t.Fatalf("cookies file changed on a no-op tick")
	}
	if _, err := os.Stat(cookiesPath + ".bak"); !os.IsNotExist(err) {
		t.Fatalf(".bak exists after a no-op tick")
	}
	st := readState(t, profileDir)
	if st.LastTickOutcome != OutcomeOK || st.EarliestExpiry == nil || st.DrivingCookie != "hatch_sess" {
		t.Fatalf("state = %+v", st)
	}
	// Driving expiry 30d: remaining/4 clamps to 7d, min with
	// the 1h entry base wins -> next check in 1h.
	if st.NextCheckAt == nil || !st.NextCheckAt.Equal(tickNow.Add(time.Hour)) {
		t.Fatalf("next_check_at = %v; want +1h", st.NextCheckAt)
	}
}

func TestTickSetCookieRenewal(t *testing.T) {
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Secure: true, Expires: tickNow.Add(time.Hour).Unix()},
	}
	baseDir, cookiesPath, profileDir := tickFixture(t, initial)
	renewal := []CookieUpdate{{Cookie: StoredCookie{Name: "hatch_sess", Value: "FAKE-NEW", Domain: ".muse.ai", Path: "/", Secure: true, Expires: tickNow.Add(30 * 24 * time.Hour).Unix()}}}
	checker := &fakeChecker{scripts: []checkScript{{updates: renewal}}}
	res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, nil, nil))
	if res.Outcome != OutcomeOK || !res.WroteCookies {
		t.Fatalf("result = %+v; want ok + write", res)
	}
	cookies := readJar(t, cookiesPath)
	if len(cookies) != 1 || cookies[0].Value != "FAKE-NEW" {
		t.Fatalf("jar = %+v", cookies)
	}
	st := readState(t, profileDir)
	if st.DrivingCookie != "hatch_sess" || st.CookiesSHA256 == "" {
		t.Fatalf("state = %+v", st)
	}
	// State file must not contain the cookie value.
	raw, _ := os.ReadFile(filepath.Join(profileDir, StateFileName))
	if strings.Contains(string(raw), "FAKE-NEW") || strings.Contains(string(raw), "FAKE-OLD") {
		t.Fatalf("state file leaks a cookie value:\n%s", raw)
	}
}

func TestTickAuthErrorStopsAndWarnsOnce(t *testing.T) {
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Secure: true, Expires: tickNow.Add(time.Hour).Unix()},
	}
	baseDir, _, profileDir := tickFixture(t, initial)
	authErr := conn.NewAuthError("api/session -> 401 (cookies expired? re-export)")
	checker := &fakeChecker{scripts: []checkScript{{err: authErr}}}
	notifier := &fakeNotifier{}
	deps := tickDeps(&fakeClock{now: tickNow}, checker, nil, notifier)
	deps.BaseDir = baseDir
	res := tickRun(t, baseDir, deps)
	if res.Outcome != OutcomeAuthError || !res.Stopped {
		t.Fatalf("result = %+v; want auth_error + stopped", res)
	}
	st := readState(t, profileDir)
	if !st.LoggedOut || !st.KeeperStopped || st.KeeperStoppedReason != StoppedAuthError || !st.WarnPending {
		t.Fatalf("state = %+v", st)
	}
	// The notice is sent by the caller after Tick returns.
	NotifyStopped(context.Background(), deps, notifier)
	if notifier.count() != 1 || notifier.kinds[0] != NoticeLoggedOut {
		t.Fatalf("notices = %v; want one logged_out", notifier.kinds)
	}
	// A second tick must not touch the network and must not
	// re-notify: the stop is sticky.
	callsBefore := checker.callCount()
	res2 := tickRun(t, baseDir, deps)
	if !res2.Stopped || checker.callCount() != callsBefore {
		t.Fatalf("second tick = %+v, checker calls %d; want stopped, no new calls", res2, checker.callCount())
	}
	NotifyStopped(context.Background(), deps, notifier)
	if notifier.count() != 1 {
		t.Fatalf("notices after second tick = %d; want exactly 1 (warn-once)", notifier.count())
	}
	st = readState(t, profileDir)
	if !st.WarnSent || st.WarnPending {
		t.Fatalf("warn markers = %+v; want sent, not pending", st)
	}
}

func TestTickAuthErrorExportRecovery(t *testing.T) {
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Secure: true, Expires: tickNow.Add(time.Hour).Unix()},
		{Name: "stale", Value: "FAKE-STALE", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	}
	baseDir, cookiesPath, profileDir := tickFixture(t, initial)
	authErr := conn.NewAuthError("api/session -> 401")
	exported := []ExportedCookie{
		{Name: "hatch_sess", Value: "FAKE-EXPORTED", Domain: ".muse.ai", Path: "/", Expires: float64(tickNow.Add(30 * 24 * time.Hour).Unix()), Secure: true, HTTPOnly: true},
		{Name: "hatch_gw", Value: "FAKE-GW", Domain: ".muse.ai", Path: "/", Expires: float64(tickNow.Add(365 * 24 * time.Hour).Unix()), Secure: true},
		{Name: "tracker", Value: "FAKE-TRACK", Domain: ".example.com", Path: "/", Expires: float64(tickNow.Add(time.Hour).Unix())},
	}
	exporter := &fakeExporter{cookies: exported}
	checker := &fakeChecker{scripts: []checkScript{{err: authErr}, {}}}
	res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, exporter, nil))
	if res.Outcome != OutcomeOK || !res.Recovered || res.Dropped != 2 || res.CDPDropped != 1 || res.Exported != 2 {
		t.Fatalf("result = %+v; want ok+recovered, dropped 2, cdp-dropped 1, exported 2", res)
	}
	cookies := readJar(t, cookiesPath)
	if len(cookies) != 2 {
		t.Fatalf("jar = %+v; want the 2 exported Muse cookies", cookies)
	}
	for _, c := range cookies {
		if c.Domain == ".example.com" {
			t.Fatalf("non-filtered cookie survived export: %+v", cookies)
		}
	}
	st := readState(t, profileDir)
	if st.LoggedOut || st.KeeperStopped {
		t.Fatalf("state still stopped after recovery: %+v", st)
	}
}

func TestTickExportValidationGate(t *testing.T) {
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Secure: true, Expires: tickNow.Add(time.Hour).Unix()},
	}
	baseDir, cookiesPath, _ := tickFixture(t, initial)
	authErr := conn.NewAuthError("api/session -> 401")
	// Export without hatch_sess: the browser session is dead
	// too. No write, entry stops.
	exporter := &fakeExporter{cookies: []ExportedCookie{
		{Name: "hatch_gw", Value: "FAKE-GW", Domain: ".muse.ai", Path: "/", Expires: float64(tickNow.Add(time.Hour).Unix())},
	}}
	checker := &fakeChecker{scripts: []checkScript{{err: authErr}}}
	before, _ := os.ReadFile(cookiesPath)
	res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, exporter, nil))
	if res.Outcome != OutcomeAuthError || !res.Stopped {
		t.Fatalf("result = %+v; want stopped", res)
	}
	after, _ := os.ReadFile(cookiesPath)
	if string(after) != string(before) {
		t.Fatal("invalid export was written")
	}
}

func TestTickExportUnavailableStops(t *testing.T) {
	baseDir, _, _ := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	checker := &fakeChecker{scripts: []checkScript{{err: conn.NewAuthError("401")}}}
	exporter := &fakeExporter{err: ErrReexportUnavailable}
	res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, exporter, nil))
	if res.Outcome != OutcomeAuthError || !res.Stopped {
		t.Fatalf("result = %+v; want stopped (tag-off)", res)
	}
}

func TestTickExportFailureIsTransient(t *testing.T) {
	baseDir, _, profileDir := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	checker := &fakeChecker{scripts: []checkScript{{err: conn.NewAuthError("401")}}}
	exporter := &fakeExporter{err: errors.New("cdp dial failed")}
	res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, exporter, nil))
	if res.Outcome != OutcomeExportFailed || res.Stopped {
		t.Fatalf("result = %+v; want export_failed, not stopped", res)
	}
	st := readState(t, profileDir)
	if st.KeeperStopped || st.LastTickOutcome != OutcomeExportFailed {
		t.Fatalf("state = %+v", st)
	}
}

func TestTickTransientBackoffExhaustion(t *testing.T) {
	baseDir, _, profileDir := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	checker := &fakeChecker{scripts: []checkScript{{err: errors.New("transient boom")}}}
	res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, nil, nil))
	if res.Outcome != OutcomeTransientError || res.Stopped {
		t.Fatalf("result = %+v; want transient_error", res)
	}
	if checker.callCount() != 4 {
		t.Fatalf("checker calls = %d; want 1 + 3 retries", checker.callCount())
	}
	st := readState(t, profileDir)
	if st.LastTickOutcome != OutcomeTransientError || st.LastTickStage != "session" {
		t.Fatalf("state = %+v", st)
	}
	// The error text never carries values: assert the
	// returned error is the scripted one, unmodified.
	if res.Err == nil || res.Err.Error() != "transient boom" {
		t.Fatalf("result error = %v", res.Err)
	}
}

func TestTickNonJarSkipsWrite(t *testing.T) {
	baseDir, cookiesPath, profileDir := tickFixture(t, nil)
	// One-line form: readable, never rewritten from captures.
	oneLine := []byte("hatch_sess=FAKE-OLD; hatch_gw=FAKE-GW\n")
	paths, _ := profile.ProfilePaths(baseDir, "muse01")
	if _, err := profile.WriteCookiesFile(baseDir, "muse01", paths.Cookies, oneLine); err != nil {
		t.Fatal(err)
	}
	renewal := []CookieUpdate{{Cookie: StoredCookie{Name: "hatch_sess", Value: "FAKE-NEW", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(30 * 24 * time.Hour).Unix()}}}
	checker := &fakeChecker{scripts: []checkScript{{updates: renewal}}}
	res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, nil, nil))
	if res.Outcome != OutcomeOK || res.WroteCookies {
		t.Fatalf("result = %+v; want ok, no write (freeze a)", res)
	}
	after, _ := os.ReadFile(cookiesPath)
	if string(after) != string(oneLine) {
		t.Fatalf("non-jar file rewritten: %q", after)
	}
	// State still records the observed (merged) expiry.
	st := readState(t, profileDir)
	if st.Cookies["hatch_sess"].ExpiresAt == nil || !st.Cookies["hatch_sess"].ExpiresAt.Equal(tickNow.Add(30*24*time.Hour)) {
		t.Fatalf("state cookies = %+v", st.Cookies)
	}
}

func TestTickMissingFile(t *testing.T) {
	// No cookies file + no exporter: stopped, cookies_missing.
	baseDir, _, profileDir := tickFixture(t, nil)
	checker := &fakeChecker{scripts: []checkScript{{err: conn.NewAuthError("401")}}}
	res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, nil, nil))
	if res.Outcome != OutcomeAuthError || !res.Stopped {
		t.Fatalf("result = %+v; want stopped", res)
	}
	st := readState(t, profileDir)
	if st.KeeperStoppedReason != StoppedCookiesMissing {
		t.Fatalf("reason = %q; want cookies_missing", st.KeeperStoppedReason)
	}
	// No cookies file + exporter: recovered, file created.
	baseDir2, cookiesPath2, _ := tickFixture(t, nil)
	exporter := &fakeExporter{cookies: []ExportedCookie{
		{Name: "hatch_sess", Value: "FAKE-EXP", Domain: ".muse.ai", Path: "/", Expires: float64(tickNow.Add(30 * 24 * time.Hour).Unix()), Secure: true},
	}}
	checker2 := &fakeChecker{scripts: []checkScript{{err: conn.NewAuthError("401")}, {}}}
	res2 := tickRun(t, baseDir2, tickDeps(&fakeClock{now: tickNow}, checker2, exporter, nil))
	if res2.Outcome != OutcomeOK || !res2.Recovered {
		t.Fatalf("result = %+v; want recovered", res2)
	}
	if _, err := os.Stat(cookiesPath2); err != nil {
		t.Fatalf("cookies file not created: %v", err)
	}
}

func TestTickLockTimeoutSkips(t *testing.T) {
	baseDir, cookiesPath, _ := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	release, err := profile.LockCookiesFile(baseDir, "muse01", cookiesPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	checker := &fakeChecker{scripts: []checkScript{{}}}
	deps := tickDeps(&fakeClock{now: tickNow}, checker, nil, nil)
	deps.LockTimeout = 50 * time.Millisecond
	res := tickRun(t, baseDir, deps)
	if res.Outcome != OutcomeSkipped || res.Stage != "lock" {
		t.Fatalf("result = %+v; want skipped/lock", res)
	}
	if checker.callCount() != 0 {
		t.Fatal("checker ran while the lock was held")
	}
}

func TestTickLoginPauseAndStaleRecovery(t *testing.T) {
	baseDir, _, profileDir := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	// Fresh login flag: skip, no network.
	paths, _ := profile.ProfilePaths(baseDir, "muse01")
	st := NewSessionState()
	st.LoginActive = true
	st.LoginSessionID = "login-1"
	started := tickNow.Add(-5 * time.Minute)
	st.LoginStartedAt = &started
	if err := SaveState(paths.Dir, st); err != nil {
		t.Fatal(err)
	}
	checker := &fakeChecker{scripts: []checkScript{{}}}
	res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, nil, nil))
	if res.Outcome != OutcomeSkipped || checker.callCount() != 0 {
		t.Fatalf("fresh login: result = %+v, calls = %d; want skipped, 0 calls", res, checker.callCount())
	}
	// Stale flag (>70m): recovered, tick runs.
	st.LoginStartedAt = func() *time.Time { s := tickNow.Add(-71 * time.Minute); return &s }()
	if err := SaveState(paths.Dir, st); err != nil {
		t.Fatal(err)
	}
	res = tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, nil, nil))
	if res.Outcome != OutcomeOK || checker.callCount() != 1 {
		t.Fatalf("stale login: result = %+v, calls = %d", res, checker.callCount())
	}
	st = readState(t, profileDir)
	if st.LoginActive {
		t.Fatal("stale login flag not cleared")
	}
}

func TestTickConcurrentSerialised(t *testing.T) {
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	}
	baseDir, cookiesPath, _ := tickFixture(t, initial)
	renewal := []CookieUpdate{{Cookie: StoredCookie{Name: "hatch_sess", Value: "FAKE-NEW", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(30 * 24 * time.Hour).Unix()}}}
	checker := &fakeChecker{scripts: []checkScript{{updates: renewal}}}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, nil, nil))
			if res.Outcome != OutcomeOK {
				t.Errorf("concurrent tick = %+v", res)
			}
		}()
	}
	wg.Wait()
	cookies := readJar(t, cookiesPath)
	if len(cookies) != 1 || cookies[0].Value != "FAKE-NEW" {
		t.Fatalf("jar after concurrent ticks = %+v", cookies)
	}
}

// rewriteTransport redirects every request to a test server
// while keeping the original URL path: the gateway code keeps
// its fixed muse.ai URLs, and the fake server observes the
// exact requests (headers, order, merged Cookie header).
type rewriteTransport struct {
	target string
	base   http.RoundTripper
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	u, err := url.Parse(rt.target)
	if err != nil {
		return nil, err
	}
	clone.URL.Scheme = u.Scheme
	clone.URL.Host = u.Host
	return rt.base.RoundTrip(clone)
}

func TestGatewayCheckerFakeServer(t *testing.T) {
	var sessionHeader, checkHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/session":
			sessionHeader = r.Header.Get("Cookie")
			w.Header().Add("Set-Cookie", "hatch_sess=FAKE-RENEWED; Path=/; Max-Age=2592000; Secure; HttpOnly; SameSite=Lax")
			w.Header().Add("Set-Cookie", "tracker=FAKE-TRACK; Domain=example.com; Path=/; Max-Age=60")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"vm_id": "FAKE-VM"}`))
		case "/api/auth/check":
			checkHeader = r.Header.Get("Cookie")
			w.Header().Add("Set-Cookie", "hatch_gw=FAKE-GW; Path=/; Max-Age=31536000; Secure; HttpOnly")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token": "FAKE-TOKEN"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	client := &http.Client{Transport: &rewriteTransport{target: srv.URL, base: http.DefaultTransport}}
	checker := &GatewayChecker{Client: client, Clock: &fakeClock{now: tickNow}}
	updates, skipped, err := checker.Check(context.Background(), "hatch_sess=FAKE-OLD; hatch_gw=FAKE-OLDGW")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("skipped = %d; want 0", skipped)
	}
	if len(updates) != 2 {
		t.Fatalf("updates = %+v; want hatch_sess + hatch_gw (tracker filtered)", updates)
	}
	if updates[0].Cookie.Name != "hatch_sess" || updates[0].Cookie.Expires != tickNow.Add(2592000*time.Second).Unix() {
		t.Fatalf("session update = %+v", updates[0])
	}
	if updates[1].Cookie.Name != "hatch_gw" || updates[1].Cookie.Expires != tickNow.Add(31536000*time.Second).Unix() {
		t.Fatalf("auth/check update = %+v", updates[1])
	}
	if sessionHeader != "hatch_sess=FAKE-OLD; hatch_gw=FAKE-OLDGW" {
		t.Fatalf("session Cookie header = %q", sessionHeader)
	}
	// The auth/check step runs with the session step's renewal
	// merged in: the renewed value must reach the second call.
	if !strings.Contains(checkHeader, "hatch_sess=FAKE-RENEWED") {
		t.Fatalf("auth/check Cookie header = %q; want the renewed hatch_sess", checkHeader)
	}
}

func TestGatewayCheckerAuthErrorWithDeletion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "hatch_sess=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error": "unauthorized"}`))
	}))
	defer srv.Close()
	client := &http.Client{Transport: &rewriteTransport{target: srv.URL, base: http.DefaultTransport}}
	checker := &GatewayChecker{Client: client, Clock: &fakeClock{now: tickNow}}
	updates, _, err := checker.Check(context.Background(), "hatch_sess=FAKE-OLD")
	if err == nil {
		t.Fatal("Check succeeded on a 401; want AuthError")
	}
	var authErr *conn.AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error = %T %v; want *conn.AuthError", err, err)
	}
	// Per-response rule: the deletion is returned with the error.
	if len(updates) != 1 || !updates[0].Delete || updates[0].Cookie.Name != "hatch_sess" {
		t.Fatalf("updates = %+v; want one hatch_sess deletion", updates)
	}
	if strings.Contains(err.Error(), "FAKE-OLD") {
		t.Fatalf("error leaks a cookie value: %v", err)
	}
}

// TestMergeCookieHeaderDomainScopedRenewal (loop-2 B1): a
// Domain-scoped Set-Cookie renewal must REPLACE the stored
// pair in the second chain step's header, not append a second
// pair. The stored rebuild uses a bare domain ("muse.ai");
// EffectiveSetCookie normalizes the update's Domain to
// ".muse.ai". The merge key is dot-insensitive, so the update
// hits the stored entry. RED on the old code: the header
// carried hatch_sess=FAKE-NEW; hatch_sess=FAKE-OLD.
func TestMergeCookieHeaderDomainScopedRenewal(t *testing.T) {
	raw := "hatch_sess=FAKE-NEW; Domain=.muse.ai; Path=/; Max-Age=2592000; Secure; HttpOnly"
	c, err := http.ParseSetCookie(raw)
	if err != nil {
		t.Fatal(err)
	}
	upd := EffectiveSetCookie(c, &url.URL{Scheme: "https", Host: "muse.ai", Path: "/api/session"}, tickNow)
	if upd.Delete {
		t.Fatalf("renewal parsed as deletion: %+v", upd)
	}
	got := mergeCookieHeader("hatch_sess=FAKE-OLD", []CookieUpdate{upd}, tickNow)
	if got != "hatch_sess=FAKE-NEW" {
		t.Fatalf("merged header = %q; want exactly one renewed pair", got)
	}
}

// TestMergeCookieHeaderDomainScopedDeletion (loop-2 B1): a
// Domain-scoped deletion update must remove the stored pair
// from the second chain step's header. RED on the old code:
// the stale pair survived.
func TestMergeCookieHeaderDomainScopedDeletion(t *testing.T) {
	raw := "hatch_sess=; Domain=.muse.ai; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly"
	c, err := http.ParseSetCookie(raw)
	if err != nil {
		t.Fatal(err)
	}
	upd := EffectiveSetCookie(c, &url.URL{Scheme: "https", Host: "muse.ai", Path: "/api/session"}, tickNow)
	if !upd.Delete {
		t.Fatalf("deletion parsed as upsert: %+v", upd)
	}
	got := mergeCookieHeader("hatch_sess=FAKE-OLD", []CookieUpdate{upd}, tickNow)
	if got != "" {
		t.Fatalf("merged header = %q; want empty", got)
	}
}

// TestTickDomainScopedRenewalPersisted (loop-2 B1, persisted
// path): a host-only stored entry (bare domain, as ParseJar
// keeps it from a jar row) renewed by a Domain-scoped
// Set-Cookie update must persist as ONE entry with the new
// value. RED on the old code: the jar held both values.
func TestTickDomainScopedRenewalPersisted(t *testing.T) {
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: "muse.ai", Path: "/", Secure: true, Expires: tickNow.Add(time.Hour).Unix()},
	}
	baseDir, cookiesPath, _ := tickFixture(t, initial)
	raw := "hatch_sess=FAKE-NEW; Domain=.muse.ai; Path=/; Max-Age=2592000; Secure; HttpOnly"
	c, err := http.ParseSetCookie(raw)
	if err != nil {
		t.Fatal(err)
	}
	upd := EffectiveSetCookie(c, &url.URL{Scheme: "https", Host: "muse.ai", Path: "/api/session"}, tickNow)
	checker := &fakeChecker{scripts: []checkScript{{updates: []CookieUpdate{upd}}}}
	res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, nil, nil))
	if res.Outcome != OutcomeOK || !res.WroteCookies {
		t.Fatalf("result = %+v; want ok + write", res)
	}
	cookies := readJar(t, cookiesPath)
	if len(cookies) != 1 || cookies[0].Value != "FAKE-NEW" || cookies[0].Domain != ".muse.ai" {
		t.Fatalf("jar = %+v; want one renewed domain-scoped entry", cookies)
	}
}

// TestGatewayCheckerDomainScopedRenewalHeader (loop-2 B1,
// wire path): the full cheap chain through real
// http.ParseSetCookie must send the renewed value exactly
// once to the second step when the renewal is Domain-scoped.
// RED on the old code: the auth/check header duplicated the
// pair (stale value validated second).
func TestGatewayCheckerDomainScopedRenewalHeader(t *testing.T) {
	var checkHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/session":
			w.Header().Add("Set-Cookie", "hatch_sess=FAKE-RENEWED; Domain=.muse.ai; Path=/; Max-Age=2592000; Secure; HttpOnly")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"vm_id": "FAKE-VM"}`))
		case "/api/auth/check":
			checkHeader = r.Header.Get("Cookie")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token": "FAKE-TOKEN"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	client := &http.Client{Transport: &rewriteTransport{target: srv.URL, base: http.DefaultTransport}}
	checker := &GatewayChecker{Client: client, Clock: &fakeClock{now: tickNow}}
	if _, _, err := checker.Check(context.Background(), "hatch_sess=FAKE-OLD"); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if checkHeader != "hatch_sess=FAKE-RENEWED" {
		t.Fatalf("auth/check Cookie header = %q; want exactly one renewed pair", checkHeader)
	}
}

// TestTickExportGateIgnoresExpiredUnrelatedCookie (loop-2
// red-team F2): one expired cookie from an unrelated domain
// must not veto a valid re-export. The gate scopes to
// filtered-domain expiries; the unrelated row is preserved
// verbatim by the merge. RED on the old code: the tick
// stopped with auth_error and wrote nothing.
func TestTickExportGateIgnoresExpiredUnrelatedCookie(t *testing.T) {
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Secure: true, Expires: tickNow.Add(time.Hour).Unix()},
		{Name: "stale", Value: "FAKE-STALE", Domain: ".example.com", Path: "/", Expires: tickNow.Add(-time.Hour).Unix()},
	}
	baseDir, cookiesPath, _ := tickFixture(t, initial)
	authErr := conn.NewAuthError("api/session -> 401")
	exported := []ExportedCookie{
		{Name: "hatch_sess", Value: "FAKE-EXPORTED", Domain: ".muse.ai", Path: "/", Expires: float64(tickNow.Add(30 * 24 * time.Hour).Unix()), Secure: true, HTTPOnly: true},
	}
	exporter := &fakeExporter{cookies: exported}
	checker := &fakeChecker{scripts: []checkScript{{err: authErr}, {}}}
	res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, exporter, nil))
	if res.Outcome != OutcomeOK || !res.Recovered || res.Stopped {
		t.Fatalf("result = %+v; want ok+recovered, not stopped", res)
	}
	cookies := readJar(t, cookiesPath)
	var sess, stale *StoredCookie
	for i := range cookies {
		switch cookies[i].Name {
		case "hatch_sess":
			sess = &cookies[i]
		case "stale":
			stale = &cookies[i]
		}
	}
	if sess == nil || sess.Value != "FAKE-EXPORTED" {
		t.Fatalf("jar = %+v; want the exported hatch_sess", cookies)
	}
	if stale == nil || stale.Value != "FAKE-STALE" {
		t.Fatalf("jar = %+v; want the unrelated row preserved verbatim", cookies)
	}
}

// TestCDPSnapshotFaithfulEmptyValue (loop-2 red-team F3,
// decision-text correction): a CDP snapshot is recorded
// faithfully — an empty value with a future expiry is
// written verbatim, and deletion happens by absence from
// the snapshot. This pins the corrected semantics; the old
// code already behaved this way, the PR body did not say so.
func TestCDPSnapshotFaithfulEmptyValue(t *testing.T) {
	exp := FromExportedCookie(ExportedCookie{Name: "victim", Value: "", Domain: ".muse.ai", Path: "/", Expires: float64(tickNow.Add(time.Hour).Unix())})
	if exp.Value != "" || exp.Name != "victim" {
		t.Fatalf("FromExportedCookie = %+v; want the empty value preserved", exp)
	}
	stored := []StoredCookie{
		{Name: "victim", Value: "FAKE-REAL", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
		{Name: "keeper", Value: "FAKE-KEEP", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	}
	merged, _ := ReplaceWithExport(stored, []StoredCookie{exp, stored[1]})
	var victim *StoredCookie
	for i := range merged {
		if merged[i].Name == "victim" {
			victim = &merged[i]
		}
	}
	if victim == nil || victim.Value != "" {
		t.Fatalf("merged = %+v; want the empty-value row written verbatim", merged)
	}
	// Absence deletes: a filtered cookie missing from the
	// snapshot is dropped.
	merged2, _ := ReplaceWithExport(stored, []StoredCookie{stored[1]})
	for _, c := range merged2 {
		if c.Name == "victim" {
			t.Fatalf("merged2 = %+v; want victim dropped by absence", merged2)
		}
	}
}

// TestTickCorruptStateRecovers (loop-2 red-team F6): a tick
// whose state file is corrupt or an unknown version still
// runs the cheap chain (the cookies file decides), reports
// StateCorrupt, and replaces the corrupt file with a fresh
// state on save. RED on the old code: OutcomeSkipped, zero
// checker calls, corrupt file untouched.
func TestTickCorruptStateRecovers(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"corrupt json", `{not json`},
		{"unknown version", `{"version":99,"last_tick_outcome":"ok"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initial := []StoredCookie{
				{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Secure: true, Expires: tickNow.Add(time.Hour).Unix()},
			}
			baseDir, _, profileDir := tickFixture(t, initial)
			if err := os.WriteFile(filepath.Join(profileDir, StateFileName), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			checker := &fakeChecker{scripts: []checkScript{{}}}
			res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, nil, nil))
			if res.Outcome != OutcomeOK || !res.StateCorrupt {
				t.Fatalf("result = %+v; want ok + StateCorrupt", res)
			}
			if checker.callCount() != 1 {
				t.Fatalf("checker calls = %d; want 1 (tick ran)", checker.callCount())
			}
			st, err := LoadState(profileDir)
			if err != nil {
				t.Fatalf("LoadState after tick: %v", err)
			}
			if st.Version != StateVersion || st.LastTickOutcome != OutcomeOK {
				t.Fatalf("state after tick = %+v; want fresh v1 with ok outcome", st)
			}
		})
	}
}

// TestTickCorruptStateStopSurfacesFlag (loop-2 red-team F6):
// when a corrupt-state tick stops, the stop result still
// carries StateCorrupt (the stop path locks separately).
func TestTickCorruptStateStopSurfacesFlag(t *testing.T) {
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Secure: true, Expires: tickNow.Add(time.Hour).Unix()},
	}
	baseDir, _, profileDir := tickFixture(t, initial)
	if err := os.WriteFile(filepath.Join(profileDir, StateFileName), []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	checker := &fakeChecker{scripts: []checkScript{{err: conn.NewAuthError("401")}}}
	exporter := &fakeExporter{err: ErrReexportUnavailable}
	res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, exporter, nil))
	if res.Outcome != OutcomeAuthError || !res.Stopped || !res.StateCorrupt {
		t.Fatalf("result = %+v; want auth_error + stopped + StateCorrupt", res)
	}
}

// TestTickFreshConfigOutsideCookiesWritesState (K-LIVE-1): a
// fresh config dir with NO profiles/ subdir, and a cookies file
// OUTSIDE the config dir (the legacy layout: the lock's parent
// creation never creates the profile dir for an outside path),
// must still tick to completion and write the state file. The
// state dir is created at 0700. RED on e4ef8c5: OutcomeSkipped,
// no state file.
func TestTickFreshConfigOutsideCookiesWritesState(t *testing.T) {
	baseDir := t.TempDir()
	paths, err := profile.ProfilePaths(baseDir, "muse01")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(baseDir, "profiles")); !os.IsNotExist(err) {
		t.Fatalf("fresh config has a profiles/ entry (err=%v); the fixture is not fresh", err)
	}
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Secure: true, Expires: tickNow.Add(30 * 24 * time.Hour).Unix()},
	}
	data, err := SerializeJar(initial)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	cookiesPath := filepath.Join(outside, "cookies.txt")
	if err := os.WriteFile(cookiesPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cookiesPath)
	checker := &fakeChecker{scripts: []checkScript{{}}}
	deps := tickDeps(&fakeClock{now: tickNow}, checker, nil, nil)
	deps.Profile = &profile.Profile{Name: "muse01", CookiesFile: cookiesPath}
	res := tickRun(t, baseDir, deps)
	if res.Outcome != OutcomeOK || res.Err != nil {
		t.Fatalf("result = %+v; want ok with no error (never skipped)", res)
	}
	if mode := dirMode(t, filepath.Join(baseDir, "profiles")); mode != 0o700 {
		t.Errorf("profiles/ mode=%o, want 0700", mode)
	}
	if mode := dirMode(t, paths.Dir); mode != 0o700 {
		t.Errorf("profile dir mode=%o, want 0700", mode)
	}
	if _, err := os.Stat(filepath.Join(paths.Dir, StateFileName)); err != nil {
		t.Fatalf("state file missing after tick: %v", err)
	}
	st := readState(t, paths.Dir)
	if st.LastTickOutcome != OutcomeOK {
		t.Fatalf("state last_tick_outcome = %q; want ok", st.LastTickOutcome)
	}
	after, _ := os.ReadFile(cookiesPath)
	if string(after) != string(before) {
		t.Fatalf("cookies file changed on a no-op tick")
	}
}

func dirMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// TestTickStateDirCreationFailureIsLoud (K-LIVE-1): when the
// state dir cannot be created — here a regular file sits where
// profiles/ must be, so MkdirAll fails on the real filesystem —
// the tick must fail loudly: outcome "error" (never "skipped"),
// an error naming the state directory, no state file, and the
// cookies file untouched. RED on e4ef8c5: OutcomeSkipped with a
// bare "no such file or directory" / "not a directory" error.
func TestTickStateDirCreationFailureIsLoud(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(baseDir, "profiles"), []byte("not a directory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	paths, err := profile.ProfilePaths(baseDir, "muse01")
	if err != nil {
		t.Fatal(err)
	}
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Secure: true, Expires: tickNow.Add(30 * 24 * time.Hour).Unix()},
	}
	data, err := SerializeJar(initial)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	cookiesPath := filepath.Join(outside, "cookies.txt")
	if err := os.WriteFile(cookiesPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	checker := &fakeChecker{scripts: []checkScript{{}}}
	deps := tickDeps(&fakeClock{now: tickNow}, checker, nil, nil)
	deps.Profile = &profile.Profile{Name: "muse01", CookiesFile: cookiesPath}
	res := tickRun(t, baseDir, deps)
	if res.Outcome == OutcomeSkipped {
		t.Fatalf("result = %+v; a state-dir creation failure must never be skipped", res)
	}
	if res.Outcome != "error" {
		t.Fatalf("result outcome = %q; want \"error\"", res.Outcome)
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "state director") {
		t.Fatalf("result error = %v; want an error naming the state directory", res.Err)
	}
	if _, err := os.Stat(filepath.Join(paths.Dir, StateFileName)); !os.IsNotExist(err) {
		t.Fatalf("state file unexpectedly present (err=%v)", err)
	}
	if got, _ := os.ReadFile(cookiesPath); string(got) != string(data) {
		t.Fatalf("cookies file changed on a failed tick")
	}
	if st, err := os.Stat(filepath.Join(baseDir, "profiles")); err != nil || st.IsDir() {
		t.Fatalf("profiles file clobbered or removed (stat err=%v, isDir=%v)", err, st != nil && st.IsDir())
	}
}
