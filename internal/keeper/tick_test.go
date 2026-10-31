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
		Clock: clock,
		Entry: &profile.KeeperEntry{Tag: "k1", Profile: "muse01", Browser: "http://127.0.0.1:9226/", Interval: time.Hour, IntervalSet: true},
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
