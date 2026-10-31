// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

type fakeRunner struct {
	version   BrowserVersion
	sendFrame *Frame
	mu        sync.Mutex
	calls     int
}

func (f *fakeRunner) Run(ctx context.Context, tr Transport) RunnerResult {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.sendFrame != nil {
		_ = tr.SendFrame(ctx, *f.sendFrame)
	}
	for {
		select {
		case <-ctx.Done():
			return RunnerResult{Version: f.version, Outcome: LoginCancelled}
		case ev := <-tr.Inputs():
			switch ev.Kind {
			case InputDone:
				return RunnerResult{Version: f.version, Outcome: DoneOutcome}
			case InputCancel:
				return RunnerResult{Version: f.version, Outcome: LoginCancelled}
			}
		case <-tr.Done():
			return RunnerResult{Version: f.version, Outcome: LoginFailed, Err: errors.New("transport died")}
		}
	}
}

func (f *fakeRunner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// controlledClock: After returns a fresh buffered channel per
// call, in order; tests fire them explicitly. The first After
// call in a session is the poll timer, the second is the
// timeout.
type controlledClock struct {
	now   time.Time
	mu    sync.Mutex
	chans []chan time.Time
}

func (c *controlledClock) Now() time.Time { return c.now }
func (c *controlledClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.chans = append(c.chans, ch)
	return ch
}
func (c *controlledClock) fire(i int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chans[i] <- c.now
}

func loginFixture(t *testing.T, initial []StoredCookie) string {
	t.Helper()
	baseDir := t.TempDir()
	paths, err := profile.ProfilePaths(baseDir, "muse01")
	if err != nil {
		t.Fatal(err)
	}
	if initial != nil {
		data, err := SerializeJar(initial)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := profile.WriteCookiesFile(baseDir, "muse01", paths.Cookies, data); err != nil {
			t.Fatalf("WriteCookiesFile: %v", err)
		}
	}
	return baseDir
}

func loginSession(baseDir string, clock Clock, tr Transport, checker Checker, exporter Exporter, runner ScreencastRunner) *LoginSession {
	return &LoginSession{
		Clock: clock, BaseDir: baseDir,
		Profile:      &profile.Profile{Name: "muse01"},
		Timeout:      60 * time.Second,
		PollInterval: 10 * time.Millisecond,
		Transport:    tr, Checker: checker, Exporter: exporter, Runner: runner,
		SessionID: "login-test-1", LockTimeout: 5 * time.Second,
	}
}

func TestLoginDoneSavesValidatedCookies(t *testing.T) {
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	}
	baseDir := loginFixture(t, initial)
	paths, _ := profile.ProfilePaths(baseDir, "muse01")
	exporter := &fakeExporter{cookies: []ExportedCookie{
		{Name: "hatch_sess", Value: "FAKE-LOGIN-VALUE", Domain: ".muse.ai", Path: "/", Expires: float64(tickNow.Add(30 * 24 * time.Hour).Unix()), Secure: true, HTTPOnly: true},
		{Name: "hatch_gw", Value: "FAKE-LOGIN-GW", Domain: ".muse.ai", Path: "/", Expires: float64(tickNow.Add(365 * 24 * time.Hour).Unix()), Secure: true},
	}}
	checker := &fakeChecker{scripts: []checkScript{{}}}
	tr := NewFakeTransport(4)
	runner := &fakeRunner{
		version:   BrowserVersion{Product: "Chrome/140.0.0.0", UserAgent: "SYNTHETIC-UA"},
		sendFrame: &Frame{Data: []byte("MARKER-FRAME-BYTES"), SessionID: 1, Width: 780, Height: 1400},
	}
	sess := loginSession(baseDir, RealClock, tr, checker, exporter, runner)
	done := make(chan LoginResult, 1)
	go func() { done <- sess.Run(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	tr.SendInput(InputEvent{Kind: InputDone})
	res := <-done
	if res.Outcome != LoginSaved || !res.CookiesSaved {
		t.Fatalf("result = %+v; want saved", res)
	}
	if len(res.SavedNames) != 2 || res.EarliestExpiry == nil {
		t.Fatalf("result names/expiry = %+v", res)
	}
	cookies := readJar(t, paths.Cookies)
	// Deterministic sort: hatch_gw sorts before hatch_sess
	// (same domain/path, name order). The HttpOnly bit is
	// not preserved across a jar round-trip by design (the
	// format has no column for it).
	if len(cookies) != 2 {
		t.Fatalf("jar = %+v", cookies)
	}
	byName := map[string]StoredCookie{}
	for _, c := range cookies {
		byName[c.Name] = c
	}
	if byName["hatch_sess"].Value != "FAKE-LOGIN-VALUE" || byName["hatch_gw"].Value != "FAKE-LOGIN-GW" {
		t.Fatalf("jar = %+v", cookies)
	}
	st := readState(t, paths.Dir)
	if st.LoginActive || st.LoggedOut || st.KeeperStopped {
		t.Fatalf("state flags = %+v", st)
	}
	if st.LoginUserAgent != "SYNTHETIC-UA" || st.LoginChromiumVersion != "Chrome/140.0.0.0" || st.LoginAt == nil {
		t.Fatalf("provenance = %+v", st)
	}
	// Audit: one record, outcome saved, names + expiry only.
	// Marker frame bytes and cookie values appear nowhere.
	raw, err := os.ReadFile(filepath.Join(paths.Dir, LoginAuditFileName))
	if err != nil {
		t.Fatalf("audit read: %v", err)
	}
	if !strings.Contains(string(raw), `"outcome":"saved"`) || !strings.Contains(string(raw), "hatch_sess") {
		t.Fatalf("audit = %s", raw)
	}
	if strings.Contains(string(raw), "MARKER-FRAME-BYTES") || strings.Contains(string(raw), "FAKE-LOGIN-VALUE") {
		t.Fatalf("audit leaks sensitive bytes:\n%s", raw)
	}
	// State file: no frame bytes, no values.
	rawState, _ := os.ReadFile(filepath.Join(paths.Dir, StateFileName))
	if strings.Contains(string(rawState), "MARKER-FRAME-BYTES") || strings.Contains(string(rawState), "FAKE-LOGIN-VALUE") {
		t.Fatalf("state leaks sensitive bytes:\n%s", rawState)
	}
	if phases := tr.Phases(); len(phases) < 2 || phases[0] != PhaseLoading {
		t.Fatalf("phases = %v", phases)
	}
}

func TestLoginCancelWritesNothing(t *testing.T) {
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	}
	baseDir := loginFixture(t, initial)
	paths, _ := profile.ProfilePaths(baseDir, "muse01")
	before, _ := os.ReadFile(paths.Cookies)
	exporter := &fakeExporter{cookies: []ExportedCookie{
		{Name: "hatch_sess", Value: "FAKE-LOGIN-VALUE", Domain: ".muse.ai", Path: "/", Expires: float64(tickNow.Add(30 * 24 * time.Hour).Unix())},
	}}
	tr := NewFakeTransport(4)
	runner := &fakeRunner{}
	sess := loginSession(baseDir, RealClock, tr, &fakeChecker{scripts: []checkScript{{}}}, exporter, runner)
	done := make(chan LoginResult, 1)
	go func() { done <- sess.Run(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	tr.SendInput(InputEvent{Kind: InputCancel})
	res := <-done
	if res.Outcome != LoginCancelled || res.CookiesSaved {
		t.Fatalf("result = %+v; want cancelled, nothing saved", res)
	}
	after, _ := os.ReadFile(paths.Cookies)
	if string(after) != string(before) {
		t.Fatal("cancelled login rewrote the cookies file")
	}
	st := readState(t, paths.Dir)
	if st.LoginActive {
		t.Fatal("login flag left set after cancel")
	}
	raw, _ := os.ReadFile(filepath.Join(paths.Dir, LoginAuditFileName))
	if !strings.Contains(string(raw), `"outcome":"cancelled"`) || strings.Contains(string(raw), `"cookies_saved":true`) {
		t.Fatalf("audit = %s", raw)
	}
}

func TestLoginTimeoutViaControlledClock(t *testing.T) {
	baseDir := loginFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	clock := &controlledClock{now: tickNow}
	tr := NewFakeTransport(4)
	runner := &fakeRunner{}
	sess := loginSession(baseDir, clock, tr, &fakeChecker{scripts: []checkScript{{}}}, &fakeExporter{}, runner)
	sess.Timeout = 15 * time.Minute
	done := make(chan LoginResult, 1)
	go func() { done <- sess.Run(context.Background()) }()
	// Wait until both timers are armed, then fire the timeout
	// (the second After call).
	deadline := time.Now().Add(2 * time.Second)
	for {
		clock.mu.Lock()
		n := len(clock.chans)
		clock.mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	clock.fire(1)
	res := <-done
	if res.Outcome != LoginTimeout {
		t.Fatalf("result = %+v; want timeout", res)
	}
}

func TestLoginDoneWithInvalidExportFails(t *testing.T) {
	initial := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	}
	baseDir := loginFixture(t, initial)
	paths, _ := profile.ProfilePaths(baseDir, "muse01")
	before, _ := os.ReadFile(paths.Cookies)
	// Export without hatch_sess: the browser session is dead.
	exporter := &fakeExporter{cookies: []ExportedCookie{
		{Name: "hatch_gw", Value: "FAKE-GW", Domain: ".muse.ai", Path: "/", Expires: float64(tickNow.Add(time.Hour).Unix())},
	}}
	tr := NewFakeTransport(4)
	sess := loginSession(baseDir, RealClock, tr, &fakeChecker{scripts: []checkScript{{}}}, exporter, &fakeRunner{})
	done := make(chan LoginResult, 1)
	go func() { done <- sess.Run(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	tr.SendInput(InputEvent{Kind: InputDone})
	res := <-done
	if res.Outcome != LoginFailed || res.CookiesSaved {
		t.Fatalf("result = %+v; want failed, nothing saved", res)
	}
	after, _ := os.ReadFile(paths.Cookies)
	if string(after) != string(before) {
		t.Fatal("invalid export was written")
	}
}

func TestLoginSecondLoginRefuses(t *testing.T) {
	baseDir := loginFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	paths, _ := profile.ProfilePaths(baseDir, "muse01")
	st := NewSessionState()
	st.LoginActive = true
	st.LoginSessionID = "login-other"
	started := tickNow.Add(-time.Minute)
	st.LoginStartedAt = &started
	if err := SaveState(paths.Dir, st); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	sess := loginSession(baseDir, RealClock, NewFakeTransport(4), &fakeChecker{scripts: []checkScript{{}}}, &fakeExporter{}, runner)
	res := sess.Run(context.Background())
	if !errors.Is(res.Err, ErrLoginInProgress) {
		t.Fatalf("result = %+v; want ErrLoginInProgress", res)
	}
	if runner.callCount() != 0 {
		t.Fatal("runner ran despite the login flag")
	}
}

func TestLoginClearsStickyStopOnSave(t *testing.T) {
	baseDir := loginFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	paths, _ := profile.ProfilePaths(baseDir, "muse01")
	st := NewSessionState()
	st.LoggedOut = true
	st.KeeperStopped = true
	st.KeeperStoppedReason = StoppedAuthError
	st.WarnPending = true
	st.WarnKind = string(NoticeLoggedOut)
	if err := SaveState(paths.Dir, st); err != nil {
		t.Fatal(err)
	}
	exporter := &fakeExporter{cookies: []ExportedCookie{
		{Name: "hatch_sess", Value: "FAKE-NEW", Domain: ".muse.ai", Path: "/", Expires: float64(tickNow.Add(30 * 24 * time.Hour).Unix())},
	}}
	tr := NewFakeTransport(4)
	sess := loginSession(baseDir, RealClock, tr, &fakeChecker{scripts: []checkScript{{}}}, exporter, &fakeRunner{})
	done := make(chan LoginResult, 1)
	go func() { done <- sess.Run(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	tr.SendInput(InputEvent{Kind: InputDone})
	res := <-done
	if res.Outcome != LoginSaved {
		t.Fatalf("result = %+v", res)
	}
	st = readState(t, paths.Dir)
	if st.LoggedOut || st.KeeperStopped || st.WarnPending {
		t.Fatalf("sticky stop not cleared: %+v", st)
	}
	// ResetAfterLogin clears the same markers for the import path.
	if err := ResetAfterLogin(baseDir, &profile.Profile{Name: "muse01"}, RealClock); err != nil {
		t.Fatalf("ResetAfterLogin: %v", err)
	}
}
