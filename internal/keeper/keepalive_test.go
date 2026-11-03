// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// fakeRelogin is a ReloginDriver fake: scripted cookies,
// blocker, or error, with a call count. The credential it
// receives is recorded only as a boolean (seen/non-empty):
// values are never asserted on or retained.
type fakeRelogin struct {
	mu       sync.Mutex
	cookies  []ExportedCookie
	blocker  *ReloginBlocker
	err      error
	calls    int
	credSeen bool
}

func (f *fakeRelogin) Relogin(_ context.Context, cred profile.LoginCredential) ([]ExportedCookie, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.credSeen = cred.Username != "" && cred.Password != ""
	if f.blocker != nil {
		return nil, f.blocker
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.cookies, nil
}

func (f *fakeRelogin) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func keepaliveDeps(entry *profile.KeeperEntry, checker Checker) TickDeps {
	deps := tickDeps(&fakeClock{now: tickNow}, checker, nil, nil)
	deps.Entry = entry
	return deps
}

func reloginEntry() *profile.KeeperEntry {
	return &profile.KeeperEntry{Tag: "k1", Profile: "muse01", Credentials: "cred1", Interval: time.Hour, IntervalSet: true}
}

func reloginCookies() []ExportedCookie {
	return []ExportedCookie{
		{Name: "hatch_sess", Value: "FAKE-RELOGIN", Domain: ".muse.ai", Path: "/", Expires: float64(tickNow.Add(30 * 24 * time.Hour).Unix()), Secure: true, HTTPOnly: true},
	}
}

// TestTickReloginRecovery pins the full chain: cheap chain
// AuthError -> headless re-login -> re-check OK -> jar write
// -> recovered, exactly one driver call, credential seen.
func TestTickReloginRecovery(t *testing.T) {
	baseDir, cookiesPath, _ := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	checker := &fakeChecker{scripts: []checkScript{
		{err: conn.NewAuthError("401")},
		{},
	}}
	driver := &fakeRelogin{cookies: reloginCookies()}
	deps := keepaliveDeps(reloginEntry(), checker)
	deps.Relogin = driver
	deps.CredentialProvider = func() (profile.LoginCredential, bool) {
		return profile.LoginCredential{Username: "u", Password: "p"}, true
	}
	res := tickRun(t, baseDir, deps)
	if res.Outcome != OutcomeOK || !res.Recovered || res.Stopped || !res.WroteCookies {
		t.Fatalf("result = %+v; want ok/recovered/wrote", res)
	}
	if driver.callCount() != 1 || !driver.credSeen {
		t.Fatalf("driver calls = %d credSeen = %v; want 1/true", driver.callCount(), driver.credSeen)
	}
	after := readJar(t, cookiesPath)
	found := false
	for _, c := range after {
		if c.Name == "hatch_sess" && c.Value == "FAKE-RELOGIN" {
			found = true
		}
	}
	if !found {
		t.Fatalf("jar = %+v; want harvested value persisted", after)
	}
}

// TestTickReloginBlockerStops pins the stop-and-alert path
// for every blocker kind: stopped, warn kind = blocker kind,
// exactly one notice, driver called once, never retried.
func TestTickReloginBlockerStops(t *testing.T) {
	for _, kind := range []NoticeKind{NoticeCaptcha, NoticeTwoFactor, NoticeCheckpoint, NoticeLocked, NoticeBlocked} {
		t.Run(string(kind), func(t *testing.T) {
			baseDir, _, profileDir := tickFixture(t, []StoredCookie{
				{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
			})
			checker := &fakeChecker{scripts: []checkScript{{err: conn.NewAuthError("401")}}}
			notifier := &fakeNotifier{}
			driver := &fakeRelogin{blocker: &ReloginBlocker{Kind: kind, Detail: "test"}}
			deps := keepaliveDeps(reloginEntry(), checker)
			deps.Relogin = driver
			deps.Notifier = notifier
			deps.CredentialProvider = func() (profile.LoginCredential, bool) {
				return profile.LoginCredential{Username: "u", Password: "p"}, true
			}
			res := tickRun(t, baseDir, deps)
			if res.Outcome != OutcomeAuthError || !res.Stopped {
				t.Fatalf("result = %+v; want stopped", res)
			}
			if driver.callCount() != 1 {
				t.Fatalf("driver calls = %d; want 1", driver.callCount())
			}
			st := readState(t, profileDir)
			if st.WarnKind != string(kind) || !st.WarnPending {
				t.Fatalf("warn = kind %q pending %v; want %q/true", st.WarnKind, st.WarnPending, kind)
			}
			// tickRun wires BaseDir on its own copy of
			// deps; NotifyStopped needs it on this one.
			deps.BaseDir = baseDir
			NotifyStopped(context.Background(), deps, notifier)
			if notifier.count() != 1 || notifier.kinds[0] != kind {
				t.Fatalf("notices = %v; want exactly one %q", notifier.kinds, kind)
			}
			st = readState(t, profileDir)
			if st.WarnPending || !st.WarnedKindSent(kind) {
				t.Fatalf("after send: pending=%v sent-marker=%v; want false/true", st.WarnPending, st.WarnedKindSent(kind))
			}
		})
	}
}

// TestTickReloginUnavailableStops pins the tag-off path:
// the driver reports unavailable, the entry stops with the
// blocked kind (not logged_out).
func TestTickReloginUnavailableStops(t *testing.T) {
	baseDir, _, profileDir := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	checker := &fakeChecker{scripts: []checkScript{{err: conn.NewAuthError("401")}}}
	driver := &fakeRelogin{err: ErrReloginUnavailable}
	deps := keepaliveDeps(reloginEntry(), checker)
	deps.Relogin = driver
	deps.CredentialProvider = func() (profile.LoginCredential, bool) {
		return profile.LoginCredential{Username: "u", Password: "p"}, true
	}
	res := tickRun(t, baseDir, deps)
	if res.Outcome != OutcomeAuthError || !res.Stopped {
		t.Fatalf("result = %+v; want stopped", res)
	}
	st := readState(t, profileDir)
	if st.WarnKind != string(NoticeBlocked) {
		t.Fatalf("warn kind = %q; want blocked", st.WarnKind)
	}
}

// TestTickReloginFailedStops pins attempt exhaustion: a
// plain driver error stops with relogin_failed.
func TestTickReloginFailedStops(t *testing.T) {
	baseDir, _, profileDir := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	checker := &fakeChecker{scripts: []checkScript{{err: conn.NewAuthError("401")}}}
	driver := &fakeRelogin{err: errors.New("launch boom")}
	deps := keepaliveDeps(reloginEntry(), checker)
	deps.Relogin = driver
	deps.CredentialProvider = func() (profile.LoginCredential, bool) {
		return profile.LoginCredential{Username: "u", Password: "p"}, true
	}
	res := tickRun(t, baseDir, deps)
	if !res.Stopped {
		t.Fatalf("result = %+v; want stopped", res)
	}
	st := readState(t, profileDir)
	if st.WarnKind != string(NoticeReloginFailed) {
		t.Fatalf("warn kind = %q; want relogin_failed", st.WarnKind)
	}
}

// TestTickReloginNoCredentialStops pins the missing
// credential path: the provider reports none, the tick
// stops with the blocked kind and the driver is never
// invoked.
func TestTickReloginNoCredentialStops(t *testing.T) {
	baseDir, _, profileDir := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	checker := &fakeChecker{scripts: []checkScript{{err: conn.NewAuthError("401")}}}
	driver := &fakeRelogin{cookies: reloginCookies()}
	deps := keepaliveDeps(reloginEntry(), checker)
	deps.Relogin = driver
	deps.CredentialProvider = func() (profile.LoginCredential, bool) {
		return profile.LoginCredential{}, false
	}
	res := tickRun(t, baseDir, deps)
	if !res.Stopped {
		t.Fatalf("result = %+v; want stopped", res)
	}
	if driver.callCount() != 0 {
		t.Fatalf("driver calls = %d; want 0", driver.callCount())
	}
	st := readState(t, profileDir)
	if st.WarnKind != string(NoticeBlocked) {
		t.Fatalf("warn kind = %q; want blocked", st.WarnKind)
	}
}

// TestTickWakeSuccess pins the auto-wake leg: cheap chain
// OK, gateway probe fails, wake runs, probe succeeds —
// outcome OK, wake called exactly until success, and the
// gateway probe ran.
func TestTickWakeSuccess(t *testing.T) {
	baseDir, _, _ := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(30 * 24 * time.Hour).Unix()},
	})
	checker := &fakeChecker{scripts: []checkScript{{}}}
	probeCalls, wakeCalls := 0, 0
	probeResults := []error{errors.New("handshake boom"), errors.New("handshake boom"), nil}
	deps := keepaliveDeps(&profile.KeeperEntry{Tag: "k1", Profile: "muse01", Interval: time.Hour, IntervalSet: true, WakeAttempts: 3, WakeAttemptsSet: true}, checker)
	deps.GatewayProbe = func(ctx context.Context) error {
		err := probeResults[probeCalls]
		probeCalls++
		return err
	}
	deps.Wake = func(ctx context.Context) error {
		wakeCalls++
		return nil
	}
	res := tickRun(t, baseDir, deps)
	if res.Outcome != OutcomeOK || res.Stopped {
		t.Fatalf("result = %+v; want ok", res)
	}
	if probeCalls != 3 || wakeCalls != 2 {
		t.Fatalf("probe=%d wake=%d; want 3/2", probeCalls, wakeCalls)
	}
}

// TestTickWakeExhaustedIsTransient pins wake exhaustion:
// probe always fails, wake runs to the cap, outcome
// transient, no stop, no notice, updates still persisted.
func TestTickWakeExhaustedIsTransient(t *testing.T) {
	baseDir, cookiesPath, profileDir := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(30 * 24 * time.Hour).Unix()},
	})
	renewal := []CookieUpdate{{Cookie: StoredCookie{Name: "hatch_sess", Value: "FAKE-NEW", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(30 * 24 * time.Hour).Unix()}}}
	checker := &fakeChecker{scripts: []checkScript{{updates: renewal}}}
	wakeCalls := 0
	deps := keepaliveDeps(&profile.KeeperEntry{Tag: "k1", Profile: "muse01", Interval: time.Hour, IntervalSet: true, WakeAttempts: 2, WakeAttemptsSet: true}, checker)
	deps.GatewayProbe = func(ctx context.Context) error { return errors.New("handshake boom") }
	deps.Wake = func(ctx context.Context) error { wakeCalls++; return nil }
	notifier := &fakeNotifier{}
	deps.Notifier = notifier
	res := tickRun(t, baseDir, deps)
	if res.Outcome != OutcomeTransientError || res.Stopped {
		t.Fatalf("result = %+v; want transient, unstopped", res)
	}
	if wakeCalls != 2 {
		t.Fatalf("wake calls = %d; want 2 (the cap)", wakeCalls)
	}
	if notifier.count() != 0 {
		t.Fatalf("notices = %d; want 0 (wake exhaustion never alerts)", notifier.count())
	}
	st := readState(t, profileDir)
	if st.LastTickOutcome != OutcomeTransientError || st.LastTickStage != "gateway" {
		t.Fatalf("state = %+v", st)
	}
	after := readJar(t, cookiesPath)
	for _, c := range after {
		if c.Name == "hatch_sess" && c.Value != "FAKE-NEW" {
			t.Fatalf("rotation not persisted on wake exhaustion: %+v", after)
		}
	}
}

// TestTickWakeAuthErrorFallsToStop pins the auth-died
// mid-probe path: the probe returns AuthError, the tick
// goes to export/stop (no exporter, no relogin) and stops.
func TestTickWakeAuthErrorFallsToStop(t *testing.T) {
	baseDir, _, profileDir := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	checker := &fakeChecker{scripts: []checkScript{{}}}
	deps := keepaliveDeps(&profile.KeeperEntry{Tag: "k1", Profile: "muse01", Interval: time.Hour, IntervalSet: true}, checker)
	deps.GatewayProbe = func(ctx context.Context) error { return conn.NewAuthError("401 mid-probe") }
	res := tickRun(t, baseDir, deps)
	if res.Outcome != OutcomeAuthError || !res.Stopped {
		t.Fatalf("result = %+v; want stopped", res)
	}
	st := readState(t, profileDir)
	if !st.KeeperStopped {
		t.Fatalf("state not stopped: %+v", st)
	}
}

// TestTickWakeDisabledSkipsProbe pins the opt-out: with
// wake_on_gateway_failure=false the probe is never called,
// even when configured.
func TestTickWakeDisabledSkipsProbe(t *testing.T) {
	baseDir, _, _ := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(30 * 24 * time.Hour).Unix()},
	})
	checker := &fakeChecker{scripts: []checkScript{{}}}
	probeCalls := 0
	entry := &profile.KeeperEntry{Tag: "k1", Profile: "muse01", Interval: time.Hour, IntervalSet: true, WakeOnGatewayFailure: false, WakeSet: true}
	deps := keepaliveDeps(entry, checker)
	deps.GatewayProbe = func(ctx context.Context) error { probeCalls++; return errors.New("boom") }
	res := tickRun(t, baseDir, deps)
	if res.Outcome != OutcomeOK {
		t.Fatalf("result = %+v; want ok", res)
	}
	if probeCalls != 0 {
		t.Fatalf("probe calls = %d; want 0", probeCalls)
	}
}

// TestTickWakeNeverOnAuthFailure pins the guard: when the
// cheap chain itself fails with AuthError, no probe and no
// wake run.
func TestTickWakeNeverOnAuthFailure(t *testing.T) {
	baseDir, _, _ := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	checker := &fakeChecker{scripts: []checkScript{{err: conn.NewAuthError("401")}}}
	probeCalls, wakeCalls := 0, 0
	deps := keepaliveDeps(&profile.KeeperEntry{Tag: "k1", Profile: "muse01", Interval: time.Hour, IntervalSet: true}, checker)
	deps.GatewayProbe = func(ctx context.Context) error { probeCalls++; return nil }
	deps.Wake = func(ctx context.Context) error { wakeCalls++; return nil }
	res := tickRun(t, baseDir, deps)
	if !res.Stopped {
		t.Fatalf("result = %+v; want stopped", res)
	}
	if probeCalls != 0 || wakeCalls != 0 {
		t.Fatalf("probe=%d wake=%d; want 0/0", probeCalls, wakeCalls)
	}
}

// TestTickConfigBackoffLadder pins the configured ladder:
// with retry_backoff ["1ms","1ms"] and a fake clock (After
// fires immediately), the checker runs 1 + 2 times, not
// the default 1 + 3.
func TestTickConfigBackoffLadder(t *testing.T) {
	baseDir, _, _ := tickFixture(t, []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-OLD", Domain: ".muse.ai", Path: "/", Expires: tickNow.Add(time.Hour).Unix()},
	})
	checker := &fakeChecker{scripts: []checkScript{{err: errors.New("transient boom")}}}
	entry := &profile.KeeperEntry{Tag: "k1", Profile: "muse01", Interval: time.Hour, IntervalSet: true,
		RetryBackoff: []time.Duration{time.Millisecond, time.Millisecond}, RetryBackoffSet: true}
	res := tickRun(t, baseDir, keepaliveDeps(entry, checker))
	if res.Outcome != OutcomeTransientError {
		t.Fatalf("result = %+v; want transient", res)
	}
	if checker.callCount() != 3 {
		t.Fatalf("checker calls = %d; want 1 + 2 configured retries", checker.callCount())
	}
}

// TestTickNonJarNoRotationWritesNothing pins the other side
// of G5: a non-jar file with NO rotation keeps its form.
func TestTickNonJarNoRotationWritesNothing(t *testing.T) {
	baseDir, cookiesPath, _ := tickFixture(t, nil)
	oneLine := []byte("hatch_sess=FAKE-OLD; hatch_gw=FAKE-GW\n")
	paths, _ := profile.ProfilePaths(baseDir, "muse01")
	if _, err := profile.WriteCookiesFile(baseDir, "muse01", paths.Cookies, oneLine); err != nil {
		t.Fatal(err)
	}
	checker := &fakeChecker{scripts: []checkScript{{}}}
	res := tickRun(t, baseDir, tickDeps(&fakeClock{now: tickNow}, checker, nil, nil))
	if res.Outcome != OutcomeOK || res.WroteCookies {
		t.Fatalf("result = %+v; want ok, no write", res)
	}
	after, _ := os.ReadFile(cookiesPath)
	if string(after) != string(oneLine) {
		t.Fatalf("non-jar file rewritten without a rotation: %q", after)
	}
}

// TestWarnEpisodeDedup pins per-(episode, kind) dedup at
// the state level: a sent kind does not re-pend in the same
// episode, a new kind does, and recovery clears the slate.
func TestWarnEpisodeDedup(t *testing.T) {
	st := NewSessionState()
	now := tickNow
	if !st.MarkWarnPending(NoticeCaptcha, now) {
		t.Fatal("first MarkWarnPending(captcha) = false")
	}
	// A failed send leaves it pending; a second stop in
	// the same episode must not duplicate it — but the
	// pending marker already exists, so MarkWarnPending
	// returning true again is fine; the dedup that matters
	// is after a SEND.
	st.MarkWarnSent(NoticeCaptcha, now)
	if st.MarkWarnPending(NoticeCaptcha, now) {
		t.Fatal("MarkWarnPending(captcha) after send = true; want false (already alerted this episode)")
	}
	if !st.MarkWarnPending(NoticeTwoFactor, now) {
		t.Fatal("MarkWarnPending(two_factor) = false; want true (new kind)")
	}
	if st.WarnKind != string(NoticeTwoFactor) || !st.WarnPending {
		t.Fatalf("legacy fields = kind %q pending %v; want two_factor/true", st.WarnKind, st.WarnPending)
	}
	st.ClearWarnEpisode()
	if !st.MarkWarnPending(NoticeCaptcha, now) {
		t.Fatal("MarkWarnPending(captcha) after recovery = false; want true (new episode)")
	}
}

// TestNoticeKindsClosed pins the closed set and the fixed
// texts: every kind renders with the profile name only, no
// error text, and an unknown kind degrades to logged_out.
func TestNoticeKindsClosed(t *testing.T) {
	for _, kind := range AllNoticeKinds {
		if !ValidNoticeKind(kind) {
			t.Fatalf("ValidNoticeKind(%q) = false", kind)
		}
		text := NoticeText(kind, "muse01")
		if !strings.Contains(text, "muse01") {
			t.Fatalf("NoticeText(%q) lacks the profile name: %q", kind, text)
		}
		if strings.Contains(text, "SENTINEL") {
			t.Fatalf("NoticeText(%q) contains a sentinel", kind)
		}
	}
	if ValidNoticeKind("surprise") {
		t.Fatal("ValidNoticeKind(surprise) = true")
	}
	if got := NoticeText("surprise", "muse01"); !strings.Contains(got, "logged out") {
		t.Fatalf("unknown kind text = %q; want logged_out degradation", got)
	}
}

// TestMatchContract pins the matcher: observed contract,
// exactly-one selectors pass; a missing or duplicated
// selector mismatches; a keyword hit blocks with its kind;
// an unobserved contract refuses outright.
func TestMatchContract(t *testing.T) {
	contract := LoginContract{
		Version:  1,
		Observed: true,
		LoginURL: "https://auth.example.test/login",
		Steps: []LoginContractStep{
			{Action: "fill", Selector: "#user", Field: "username"},
			{Action: "fill", Selector: "#pass", Field: "password"},
			{Action: "click", Selector: "#submit"},
		},
		Blockers: []LoginBlockerSignal{
			{Keyword: "captcha", Kind: NoticeCaptcha},
			{Selector: ".two-factor", Kind: NoticeTwoFactor},
		},
	}
	ok := PageSnapshot{Counts: map[string]int{"#user": 1, "#pass": 1, "#submit": 1}}
	if err := MatchContract(contract, ok); err != nil {
		t.Fatalf("MatchContract(ok) = %v", err)
	}
	missing := PageSnapshot{Counts: map[string]int{"#user": 1, "#pass": 1}}
	var blocker *ReloginBlocker
	if err := MatchContract(contract, missing); !errors.As(err, &blocker) || blocker.Kind != NoticeBlocked {
		t.Fatalf("MatchContract(missing) = %v; want blocked", err)
	}
	keyword := PageSnapshot{Counts: map[string]int{"#user": 1, "#pass": 1, "#submit": 1}, VisibleText: "Please solve this CAPTCHA to continue"}
	duplicate := PageSnapshot{Counts: map[string]int{"#user": 2, "#pass": 1, "#submit": 1}}
	if err := MatchContract(contract, duplicate); !errors.As(err, &blocker) || blocker.Detail != "contract_mismatch" {
		t.Fatalf("MatchContract(duplicate) = %v; want contract_mismatch", err)
	}
	if err := MatchContract(contract, keyword); !errors.As(err, &blocker) || blocker.Kind != NoticeCaptcha {
		t.Fatalf("MatchContract(keyword) = %v; want captcha", err)
	}
	selHit := PageSnapshot{Counts: map[string]int{"#user": 1, "#pass": 1, "#submit": 1, ".two-factor": 1}}
	if err := MatchContract(contract, selHit); !errors.As(err, &blocker) || blocker.Kind != NoticeTwoFactor {
		t.Fatalf("MatchContract(selector) = %v; want two_factor", err)
	}
	unobserved := contract
	unobserved.Observed = false
	if err := MatchContract(unobserved, ok); !errors.Is(err, ErrContractNotEstablished) {
		t.Fatalf("MatchContract(unobserved) = %v; want ErrContractNotEstablished", err)
	}
}

// TestValidateContract pins the up-front contract check:
// the version and EVERY step are validated before any
// browser launches, so a bad action or field in a LATER
// step fails without the first step's fill ever running.
func TestValidateContract(t *testing.T) {
	t.Parallel()
	good := LoginContract{
		Version:  1,
		Observed: true,
		LoginURL: "https://auth.example.test/login",
		Steps: []LoginContractStep{
			{Action: "fill", Selector: "#user", Field: "username"},
			{Action: "fill", Selector: "#pass", Field: "password"},
			{Action: "click", Selector: "#submit"},
		},
	}
	if b := validateContract(good); b != nil {
		t.Fatalf("validateContract(good) = %v; want nil", b)
	}
	cases := []struct {
		name   string
		mutate func(*LoginContract)
		want   string
	}{
		{"bad version", func(c *LoginContract) { c.Version = 2 }, "contract_bad_version"},
		{"bad action in later step", func(c *LoginContract) { c.Steps[2].Action = "clik" }, "contract_unknown_action"},
		{"bad field in later step", func(c *LoginContract) { c.Steps[1].Field = "usernam" }, "contract_unknown_field"},
		{"field on click step", func(c *LoginContract) { c.Steps[2].Field = "username" }, "contract_click_field"},
		{"empty selector", func(c *LoginContract) { c.Steps[1].Selector = "" }, "contract_step_no_selector"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			c.Steps = append([]LoginContractStep(nil), good.Steps...)
			tc.mutate(&c)
			b := validateContract(c)
			if b == nil || b.Kind != NoticeBlocked || b.Detail != tc.want {
				t.Fatalf("validateContract = %+v; want blocked/%s", b, tc.want)
			}
		})
	}
}

// TestDefaultContractObserved pins the recorded contract:
// the 2026-11-03 read-only observation leg filled the v1
// fixture from the live login page at https://muse.ai/.
// The steps are the first screen only (identifier + Continue);
// the code-challenge screen is unobserved by design (see the
// fixture notes). Any re-observation must update this test
// to pin the new recorded selectors.
func TestDefaultContractObserved(t *testing.T) {
	c, err := DefaultLoginContract()
	if err != nil {
		t.Fatalf("DefaultLoginContract: %v", err)
	}
	if !c.Observed {
		t.Fatal("embedded contract is unobserved; the observation leg must record it")
	}
	if c.Version != 1 {
		t.Fatalf("contract version = %d; want 1", c.Version)
	}
	if c.LoginURL != "https://muse.ai/" {
		t.Fatalf("contract login_url = %q; want https://muse.ai/", c.LoginURL)
	}
	if len(c.Steps) != 2 {
		t.Fatalf("contract steps = %d; want 2 (identifier fill + Continue click)", len(c.Steps))
	}
	if c.Steps[0] != (LoginContractStep{Action: "fill", Selector: "form input[aria-label]", Field: "username"}) {
		t.Fatalf("contract step 0 = %+v; want the identifier fill", c.Steps[0])
	}
	if c.Steps[1] != (LoginContractStep{Action: "click", Selector: "form button[type=\"submit\"]"}) {
		t.Fatalf("contract step 1 = %+v; want the Continue click", c.Steps[1])
	}
	if len(c.Blockers) != 0 {
		t.Fatalf("contract blockers = %d; want 0 (none observed)", len(c.Blockers))
	}
	if b := validateContract(c); b != nil {
		t.Fatalf("embedded contract fails up-front validation: %v", b)
	}
}

// TestDeriveAuthStatus pins the state-only derivation:
// stopped-auth beats file dates, expiring uses the window,
// no expiry metadata is ok, headless fields pass through.
func TestDeriveAuthStatus(t *testing.T) {
	now := tickNow
	future := now.Add(30 * 24 * time.Hour)
	near := now.Add(48 * time.Hour)
	past := now.Add(-time.Hour)
	cases := []struct {
		name    string
		expiry  *time.Time
		missing bool
		st      *SessionState
		want    AuthStatusValue
		action  bool
	}{
		{"future ok", &future, false, nil, AuthStatusOK, false},
		{"near expiring", &near, false, nil, AuthStatusExpiring, true},
		{"past expired", &past, false, nil, AuthStatusExpired, true},
		{"no metadata ok", nil, false, nil, AuthStatusOK, false},
		{"stopped beats future", &future, false, &SessionState{KeeperStopped: true, KeeperStoppedReason: StoppedAuthError}, AuthStatusExpired, true},
		{"stopped export-failed uses dates", &future, false, &SessionState{KeeperStopped: true, KeeperStoppedReason: "export_failed"}, AuthStatusOK, false},
		{"missing file expired", nil, true, nil, AuthStatusExpired, true},
		{"missing file beats healthy state", &future, true, &SessionState{LastTickOutcome: OutcomeOK}, AuthStatusExpired, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveAuthStatus("muse01", "hatch_sess", tc.expiry, 2, tc.missing, tc.st, 72*time.Hour, false, "no_chromedp", now)
			if got.Status != tc.want || got.NeedsAction != tc.action {
				t.Fatalf("status = %q action=%v; want %q/%v", got.Status, got.NeedsAction, tc.want, tc.action)
			}
			if got.HeadlessReason != "no_chromedp" {
				t.Fatalf("headless reason = %q", got.HeadlessReason)
			}
		})
	}
}

// TestSnapshotDecisionMatchesContract (D2) pins that the
// count-snapshot decision (chromedp driver) and the
// text-snapshot decision (MatchContract) agree on every
// input: same nil, same blocker kind+detail, same
// not-established error. A drift between them would let
// the driver act on a page the contract rejects, or refuse
// a page the contract accepts.
func TestSnapshotDecisionMatchesContract(t *testing.T) {
	t.Parallel()
	contract := LoginContract{
		Version:  1,
		Observed: true,
		Steps: []LoginContractStep{
			{Action: "fill", Selector: "#user", Field: "username"},
			{Action: "fill", Selector: "#pass", Field: "password"},
			{Action: "click", Selector: "#submit"},
		},
		Blockers: []LoginBlockerSignal{
			{Kind: NoticeCaptcha, Selector: ".captcha-box", Keyword: "captcha"},
			{Kind: NoticeTwoFactor, Selector: ".two-factor", Keyword: "two-factor"},
		},
	}
	counts := map[string]int{"#user": 1, "#pass": 1, "#submit": 1}
	emptyKind := LoginContract{
		Version:  1,
		Observed: true,
		Steps:    []LoginContractStep{{Action: "fill", Selector: "#user", Field: "username"}},
		Blockers: []LoginBlockerSignal{{Kind: "", Keyword: "surprise"}},
	}
	noSelector := LoginContract{
		Version:  1,
		Observed: true,
		Steps:    []LoginContractStep{{Action: "fill", Selector: "", Field: "username"}},
	}
	cases := []struct {
		name     string
		contract LoginContract
		snap     PageSnapshot
		res      snapshotResult
	}{
		{"all present", contract,
			PageSnapshot{Counts: counts, VisibleText: "sign in"},
			snapshotResult{Counts: counts, Hits: map[string]string{}}},
		{"missing submit", contract,
			PageSnapshot{Counts: map[string]int{"#user": 1, "#pass": 1}, VisibleText: "sign in"},
			snapshotResult{Counts: map[string]int{"#user": 1, "#pass": 1}, Hits: map[string]string{}}},
		{"captcha keyword", contract,
			PageSnapshot{Counts: counts, VisibleText: "please solve the captcha"},
			snapshotResult{Counts: counts, Hits: map[string]string{string(NoticeCaptcha): "keyword"}}},
		{"two-factor selector", contract,
			PageSnapshot{Counts: map[string]int{"#user": 1, "#pass": 1, "#submit": 1, ".two-factor": 1}, VisibleText: "sign in"},
			snapshotResult{Counts: map[string]int{"#user": 1, "#pass": 1, "#submit": 1, ".two-factor": 1}, Hits: map[string]string{string(NoticeTwoFactor): "selector"}}},
		{"blocker beats missing step", contract,
			PageSnapshot{Counts: map[string]int{"#user": 1}, VisibleText: "captcha required"},
			snapshotResult{Counts: map[string]int{"#user": 1}, Hits: map[string]string{string(NoticeCaptcha): "keyword"}}},
		{"unobserved", LoginContract{Version: 1},
			PageSnapshot{Counts: counts},
			snapshotResult{Counts: counts, Hits: map[string]string{}}},
		{"empty-kind signal falls through", emptyKind,
			PageSnapshot{Counts: map[string]int{}, VisibleText: "surprise check"},
			snapshotResult{Counts: map[string]int{}, Hits: map[string]string{"": "keyword"}}},
		{"step without selector", noSelector,
			PageSnapshot{Counts: map[string]int{}, VisibleText: "sign in"},
			snapshotResult{Counts: map[string]int{}, Hits: map[string]string{}}},
		{"duplicate selector", contract,
			PageSnapshot{Counts: map[string]int{"#user": 2, "#pass": 1, "#submit": 1}, VisibleText: "sign in"},
			snapshotResult{Counts: map[string]int{"#user": 2, "#pass": 1, "#submit": 1}, Hits: map[string]string{}}},
		{"zero selector", contract,
			PageSnapshot{Counts: map[string]int{"#user": 1, "#pass": 1, "#submit": 0}, VisibleText: "sign in"},
			snapshotResult{Counts: map[string]int{"#user": 1, "#pass": 1, "#submit": 0}, Hits: map[string]string{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := MatchContract(tc.contract, tc.snap)
			got := snapshotDecision(tc.contract, tc.res)
			if !sameContractDecision(want, got) {
				t.Fatalf("MatchContract = %v; snapshotDecision = %v; want agreement", want, got)
			}
		})
	}
}

// TestSnapshotDecisionBadSelector pins that a selector the
// browser could not evaluate is a distinct stop, not a
// mismatch: the driver must surface the malformed recorded
// selector instead of polling the page as "not the recorded
// form". The syntax error outranks a blocker hit and a
// mismatch (the snapshot is unreliable once any recorded
// selector threw), and it outranks nothing else: an
// unobserved contract still refuses outright. MatchContract
// has no syntax-error channel — the Go-side snapshot only
// ever sees counts — so these cases are deliberately NOT
// part of the equivalence table above.
func TestSnapshotDecisionBadSelector(t *testing.T) {
	t.Parallel()
	contract := LoginContract{
		Version:  1,
		Observed: true,
		Steps: []LoginContractStep{
			{Action: "fill", Selector: "#user", Field: "username"},
			{Action: "fill", Selector: "#pass", Field: "password"},
			{Action: "click", Selector: "#submit"},
		},
		Blockers: []LoginBlockerSignal{
			{Kind: NoticeCaptcha, Selector: ".captcha-box", Keyword: "captcha"},
		},
	}
	counts := map[string]int{"#user": 1, "#pass": 1, "#submit": 1}
	cases := []struct {
		name string
		res  snapshotResult
	}{
		{"step selector bad", snapshotResult{Counts: counts, Hits: map[string]string{}, BadSelectors: []string{"#user"}}},
		{"blocker selector bad", snapshotResult{Counts: counts, Hits: map[string]string{}, BadSelectors: []string{".captcha-box"}}},
		{"bad selector beats blocker hit", snapshotResult{Counts: counts, Hits: map[string]string{string(NoticeCaptcha): "keyword"}, BadSelectors: []string{"#pass"}}},
		{"bad selector beats mismatch counts", snapshotResult{Counts: map[string]int{"#user": 0, "#pass": 1, "#submit": 1}, Hits: map[string]string{}, BadSelectors: []string{"#user"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := snapshotDecision(contract, tc.res)
			var blocker *ReloginBlocker
			if !errors.As(err, &blocker) || blocker.Kind != NoticeBlocked || blocker.Detail != "contract_bad_selector" {
				t.Fatalf("snapshotDecision = %v; want blocked/contract_bad_selector", err)
			}
			if !isBlockerSignal(blocker) {
				t.Fatalf("isBlockerSignal(%+v) = false; want the bad-selector stop to halt the driver like a blocker signal", blocker)
			}
		})
	}
	unobserved := LoginContract{Version: 1}
	if err := snapshotDecision(unobserved, snapshotResult{Counts: counts, Hits: map[string]string{}, BadSelectors: []string{"#user"}}); !errors.Is(err, ErrContractNotEstablished) {
		t.Fatalf("snapshotDecision(unobserved, bad selector) = %v; want ErrContractNotEstablished", err)
	}
}

func sameContractDecision(a, b error) bool {
	if a == nil || b == nil {
		return a == b
	}
	if errors.Is(a, ErrContractNotEstablished) || errors.Is(b, ErrContractNotEstablished) {
		return errors.Is(a, ErrContractNotEstablished) && errors.Is(b, ErrContractNotEstablished)
	}
	ab, aok := a.(*ReloginBlocker)
	bb, bok := b.(*ReloginBlocker)
	return aok && bok && ab.Kind == bb.Kind && ab.Detail == bb.Detail
}

// TestStripObservationURL (D6/R-5) pins that the observed
// URL printed by `auth observe-login` never carries a query
// or fragment — auth redirects tokenise both.
func TestStripObservationURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"https://auth.muse.ai/login?code=SECRET123&state=x#frag", "https://auth.muse.ai/login"},
		{"https://auth.muse.ai/login#only-fragment", "https://auth.muse.ai/login"},
		{"https://auth.muse.ai/login", "https://auth.muse.ai/login"},
		{"https://auth.muse.ai/a/b?x=1", "https://auth.muse.ai/a/b"},
		{"http://127.0.0.1:9/login?next=/", "http://127.0.0.1:9/login"},
		// R-7: userinfo is stripped too — a pasted URL
		// carrying credentials must never survive.
		{"https://user:pass@auth.muse.ai/login?code=SECRET123#frag", "https://auth.muse.ai/login"},
		{"https://user@auth.muse.ai/login", "https://auth.muse.ai/login"},
		{"not a url ::", ""},
		{"", ""},
		{"/relative/path?x=1", ""},
	}
	for _, tc := range cases {
		if got := StripObservationURL(tc.in); got != tc.want {
			t.Errorf("StripObservationURL(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// TestDeriveAuthStatusCarriesStateOnMissingFile (S3) pins
// that a missing cookies file still reports the keeper stop
// that likely explains it: LastCheckedAt, KeeperStopped,
// and KeeperStoppedReason pass through the missing-file
// return, while the status stays expired.
func TestDeriveAuthStatusCarriesStateOnMissingFile(t *testing.T) {
	t.Parallel()
	checked := tickNow.Add(-time.Hour)
	st := &SessionState{
		LastCheckedAt:       &checked,
		KeeperStopped:       true,
		KeeperStoppedReason: StoppedAuthError,
		LastTickOutcome:     OutcomeError,
	}
	got := DeriveAuthStatus("muse01", "hatch_sess", nil, 0, true, st, 72*time.Hour, false, "no_chromedp", tickNow)
	if got.Status != AuthStatusExpired || !got.NeedsAction {
		t.Fatalf("status = %q action=%v; want expired/true", got.Status, got.NeedsAction)
	}
	if got.LastCheckedAt == nil || !got.LastCheckedAt.Equal(checked) {
		t.Fatalf("LastCheckedAt = %v; want %v", got.LastCheckedAt, checked)
	}
	if !got.KeeperStopped || got.KeeperStoppedReason != StoppedAuthError {
		t.Fatalf("KeeperStopped = %v reason = %q; want true/%q", got.KeeperStopped, got.KeeperStoppedReason, StoppedAuthError)
	}
}
