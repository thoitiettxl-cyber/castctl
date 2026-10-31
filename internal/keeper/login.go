// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Screencast login session core (R3): Done trigger only, human
// completes the login, nothing is ever auto-saved, captcha/2FA
// are never auto-solved. The core owns the flag, the poll hint,
// the final export + validate + save, and the audit record.
// The browser side is a ScreencastRunner, injected: attach
// (user's Chrome) or launch (castctl-owned Chrome) runners live
// in the with_chromedp files, and the tag-off stubs refuse.
// The transport is injected too (stdin driver locally, relay
// in item 2). No HTTP/WS listener, no viewer page, no Telegram
// relay lives in this package.

// Login timeouts: 15m default, 60s–60min accepted range.
// Out of range is a configuration error (exit 2), enforced by
// the command layer and re-checked here.
const (
	DefaultLoginTimeout = 15 * time.Minute
	MinLoginTimeout     = 60 * time.Second
	MaxLoginTimeout     = 60 * time.Minute
	// LoginPollInterval is the hint-only cookie poll cadence.
	// It never auto-saves: it only flips the phase notice to
	// logged_in_detected when the session already works.
	LoginPollInterval = 5 * time.Second
	// LoginAuditFileName is the bounded per-profile audit file.
	LoginAuditFileName = "login-audit.jsonl"
	// LoginAuditMaxRecords bounds the audit file.
	LoginAuditMaxRecords = 50
)

// LoginOutcome is the closed set of session outcomes. Runners
// report DoneOutcome, LoginCancelled, or LoginFailed; the
// core adds LoginTimeout for its own deadline.
type LoginOutcome string

const (
	// DoneOutcome: the user pressed Done. The save path runs.
	DoneOutcome LoginOutcome = "done"
	// LoginSaved: the save path wrote validated cookies.
	LoginSaved LoginOutcome = "saved"
	// LoginCancelled: the user pressed Cancel, or the context
	// ended (SIGINT).
	LoginCancelled LoginOutcome = "cancelled"
	// LoginTimeout: the core deadline elapsed.
	LoginTimeout LoginOutcome = "timeout"
	// LoginFailed: the runner failed, the transport died, or
	// the final export failed validation.
	LoginFailed LoginOutcome = "failed"
)

// ErrLoginInProgress reports a fresh login flag for the
// profile: a second login refuses (single-flight per profile).
var ErrLoginInProgress = errors.New("a login is already in progress for this profile")

// BrowserVersion is the browser's own identity, recorded as
// login provenance in the state file. Both fields come from
// Browser.getVersion on the attached/launched browser; nothing
// is invented, and attach exports never write these fields.
type BrowserVersion struct {
	Product   string
	UserAgent string
}

// RunnerResult is a ScreencastRunner's terminal report.
type RunnerResult struct {
	Version BrowserVersion
	Outcome LoginOutcome
	Err     error
}

// ScreencastRunner serves one login session: frames out,
// inputs in, until its context ends or the user sends Done or
// Cancel through the transport. It must never close, kill, or
// navigate an attached user browser; a launch runner owns its
// browser and cleans it up.
type ScreencastRunner interface {
	Run(ctx context.Context, transport Transport) RunnerResult
}

// LoginSession is one `auth login` run's core state.
type LoginSession struct {
	Clock        Clock
	BaseDir      string
	Profile      *profile.Profile
	Timeout      time.Duration
	PollInterval time.Duration
	Transport    Transport
	Checker      Checker
	Exporter     Exporter
	Runner       ScreencastRunner
	SessionID    string
	LockTimeout  time.Duration
}

// LoginResult is the session's terminal report. CookiesSaved
// is false for every non-saved outcome: nothing is written
// unless the user pressed Done AND the final export validates.
type LoginResult struct {
	Outcome        LoginOutcome
	CookiesSaved   bool
	SavedNames     []string
	EarliestExpiry *time.Time
	Version        BrowserVersion
	Duration       time.Duration
	Err            error
}

// Run executes the session. It returns a LoginResult for every
// terminal path; Err is set only for infrastructure failures
// (flag contention, export failure on the save path, timeout
// validation). A cancelled/timeout/failed outcome is a normal
// result, not an error.
func (s *LoginSession) Run(ctx context.Context) LoginResult {
	clock := s.Clock
	if clock == nil {
		clock = RealClock
	}
	started := clock.Now()
	finish := func(outcome LoginOutcome, runnerRes RunnerResult) LoginResult {
		return s.finish(ctx, started, outcome, runnerRes)
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = DefaultLoginTimeout
	}
	if timeout < MinLoginTimeout || timeout > MaxLoginTimeout {
		return LoginResult{Outcome: LoginFailed, Duration: clock.Now().Sub(started),
			Err: fmt.Errorf("login timeout %v out of range [%v, %v]", timeout, MinLoginTimeout, MaxLoginTimeout)}
	}
	if s.Transport == nil || s.Checker == nil || s.Exporter == nil || s.Runner == nil {
		return LoginResult{Outcome: LoginFailed, Duration: clock.Now().Sub(started),
			Err: errors.New("login session missing transport, checker, exporter, or runner")}
	}
	sessionID := s.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("login-%d", started.UnixNano())
	}
	s.SessionID = sessionID
	store, err := NewStore(s.BaseDir, s.Profile, s.LockTimeout)
	if err != nil {
		return LoginResult{Outcome: LoginFailed, Duration: clock.Now().Sub(started), Err: err}
	}
	paths, err := profile.ProfilePaths(s.BaseDir, s.Profile.Name)
	if err != nil {
		return LoginResult{Outcome: LoginFailed, Duration: clock.Now().Sub(started), Err: err}
	}
	// Single-flight per profile: the owner file refuses a
	// second login for the same profile.
	releaseFlight, err := AcquireSingleFlight(paths.Dir, "login", clock)
	if err != nil {
		return LoginResult{Outcome: LoginFailed, Duration: clock.Now().Sub(started), Err: err}
	}
	defer releaseFlight()
	// Login pause flag: the keeper skips ticks while set.
	// A fresh flag refuses; a stale one is recovered.
	if err := s.setLoginFlag(store, sessionID, started); err != nil {
		return LoginResult{Outcome: LoginFailed, Duration: clock.Now().Sub(started), Err: err}
	}
	defer s.clearLoginFlag(store)

	_ = s.Transport.SendPhase(ctx, PhaseLoading, "")
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	runnerDone := make(chan RunnerResult, 1)
	go func() { runnerDone <- s.Runner.Run(runCtx, s.Transport) }()
	_ = s.Transport.SendPhase(ctx, PhaseReady, "")

	pollInterval := s.PollInterval
	if pollInterval <= 0 {
		pollInterval = LoginPollInterval
	}
	pollCh := clock.After(pollInterval)
	timeoutCh := clock.After(timeout)
	hintSent := false
	for {
		select {
		case <-ctx.Done():
			cancelRun()
			return finish(LoginCancelled, RunnerResult{})
		case <-timeoutCh:
			cancelRun()
			return finish(LoginTimeout, RunnerResult{})
		case res := <-runnerDone:
			switch res.Outcome {
			case DoneOutcome:
				return finish(DoneOutcome, res)
			case LoginCancelled:
				return finish(LoginCancelled, res)
			default:
				return finish(LoginFailed, res)
			}
		case <-pollCh:
			pollCh = clock.After(pollInterval)
			if !hintSent && s.loggedInHint(runCtx) {
				hintSent = true
				_ = s.Transport.SendPhase(ctx, PhaseLoggedInHint, "")
			}
		}
	}
}

// finish resolves a terminal outcome: the save path for Done,
// audit + phase for everything else. It never runs the save
// path for a non-Done outcome.
func (s *LoginSession) finish(ctx context.Context, started time.Time, outcome LoginOutcome, runnerRes RunnerResult) LoginResult {
	clock := s.Clock
	if clock == nil {
		clock = RealClock
	}
	duration := clock.Now().Sub(started)
	store, _ := NewStore(s.BaseDir, s.Profile, s.LockTimeout)
	audit := func(final LoginOutcome, saved bool, names []string, earliest *time.Time) {
		if store == nil {
			return
		}
		s.writeAudit(store, auditRecord{
			SessionID: s.SessionID, Profile: s.Profile.Name, Outcome: string(final),
			CookiesSaved: saved, SavedNames: names, EarliestExpiry: earliest,
			StartedAt: started, DurationMS: duration.Milliseconds(),
		})
	}
	if outcome != DoneOutcome {
		phase := PhaseFailed
		if outcome == LoginCancelled {
			phase = PhaseCancelled
		}
		_ = s.Transport.SendPhase(ctx, phase, "")
		audit(outcome, false, nil, nil)
		return LoginResult{Outcome: outcome, Version: runnerRes.Version, Duration: duration, Err: runnerRes.Err}
	}
	// Save path: final export, validate, write under lock.
	exported, _, exportErr := runExport(ctx, s.Exporter)
	if exportErr != nil {
		_ = s.Transport.SendPhase(ctx, PhaseFailed, "")
		audit(LoginFailed, false, nil, nil)
		return LoginResult{Outcome: LoginFailed, Version: runnerRes.Version, Duration: duration, Err: exportErr}
	}
	saved, saveErr := s.saveLoginCookies(store, exported, runnerRes.Version)
	if saveErr != nil {
		_ = s.Transport.SendPhase(ctx, PhaseFailed, "")
		audit(LoginFailed, false, nil, nil)
		return LoginResult{Outcome: LoginFailed, Version: runnerRes.Version, Duration: duration, Err: saveErr}
	}
	_ = s.Transport.SendPhase(ctx, PhaseDone, "")
	audit(LoginSaved, true, saved.names, saved.earliest)
	return LoginResult{
		Outcome: LoginSaved, CookiesSaved: true, SavedNames: saved.names,
		EarliestExpiry: saved.earliest, Version: runnerRes.Version, Duration: duration,
	}
}

type savedCookies struct {
	names    []string
	earliest *time.Time
}

// saveLoginCookies validates the final export and writes it
// under the cookies lock, clearing the sticky stop and
// recording provenance. It re-reads the stored file under the
// lock (ReplaceWithExport against the fresh read), so a
// concurrent keeper write is not silently dropped.
func (s *LoginSession) saveLoginCookies(store *Store, exported []StoredCookie, version BrowserVersion) (savedCookies, error) {
	clock := s.Clock
	if clock == nil {
		clock = RealClock
	}
	ls, err := store.lock()
	if err != nil {
		return savedCookies{}, err
	}
	defer ls.unlock()
	merged, _ := ReplaceWithExport(ls.cookies, exported)
	if !validateExportedSet(merged, clock.Now()) {
		return savedCookies{}, errors.New("final export failed validation: no usable hatch_sess in the browser session")
	}
	data, err := SerializeJar(merged)
	if err != nil {
		return savedCookies{}, err
	}
	if _, err := ls.saveJar(data); err != nil {
		return savedCookies{}, err
	}
	st := ls.state
	now := clock.Now()
	st.LoggedOut = false
	st.KeeperStopped = false
	st.KeeperStoppedReason = ""
	st.WarnPending = false
	st.WarnSent = false
	st.WarnKind = ""
	st.LastCheckedAt = &now
	st.LastTickOutcome = OutcomeOK
	st.RefreshCookieRecords(merged, now)
	st.CookiesSHA256 = SHA256Hex(data)
	st.LoginUserAgent = version.UserAgent
	st.LoginChromiumVersion = version.Product
	loginAt := now
	st.LoginAt = &loginAt
	if err := SaveState(store.profileDir, st); err != nil {
		return savedCookies{}, err
	}
	var names []string
	for _, c := range merged {
		if InFilteredDomain(c) {
			names = append(names, c.Name)
		}
	}
	return savedCookies{names: names, earliest: EarliestExpiry(merged)}, nil
}

// loggedInHint exports the browser cookies and runs the cheap
// chain against them: true means the session already works.
// Hint only: errors are ignored and nothing is saved.
func (s *LoginSession) loggedInHint(ctx context.Context) bool {
	exported, _, err := runExport(ctx, s.Exporter)
	if err != nil || len(exported) == 0 {
		return false
	}
	hasHatch := false
	for _, c := range exported {
		if c.Name == "hatch_sess" && c.Value != "" {
			hasHatch = true
		}
	}
	if !hasHatch {
		return false
	}
	clock := s.Clock
	if clock == nil {
		clock = RealClock
	}
	header := CookieHeader(exported, clock.Now())
	_, _, err = s.Checker.Check(ctx, header)
	return err == nil
}

// setLoginFlag sets the keeper-pause flag. A fresh flag from
// another session refuses with ErrLoginInProgress; a stale
// flag is recovered.
func (s *LoginSession) setLoginFlag(store *Store, sessionID string, now time.Time) error {
	ls, err := store.lock()
	if err != nil {
		return err
	}
	defer ls.unlock()
	st := ls.state
	if st.LoginActive {
		stale := st.LoginStartedAt == nil || now.Sub(*st.LoginStartedAt) > LoginFlagStaleAfter
		if !stale {
			return ErrLoginInProgress
		}
	}
	st.LoginActive = true
	st.LoginSessionID = sessionID
	st.LoginStartedAt = &now
	return SaveState(store.profileDir, st)
}

// clearLoginFlag clears the keeper-pause flag. Best-effort:
// a failure here must not mask the session outcome.
func (s *LoginSession) clearLoginFlag(store *Store) {
	ls, err := store.lock()
	if err != nil {
		return
	}
	defer ls.unlock()
	st := ls.state
	st.LoginActive = false
	st.LoginSessionID = ""
	st.LoginStartedAt = nil
	_ = SaveState(store.profileDir, st)
}

type auditRecord struct {
	SessionID      string     `json:"session_id"`
	Profile        string     `json:"profile"`
	Outcome        string     `json:"outcome"`
	CookiesSaved   bool       `json:"cookies_saved"`
	SavedNames     []string   `json:"saved_cookie_names,omitempty"`
	EarliestExpiry *time.Time `json:"earliest_expiry,omitempty"`
	StartedAt      time.Time  `json:"started_at"`
	DurationMS     int64      `json:"duration_ms"`
}

// writeAudit appends one bounded audit record (0600, last 50
// kept). Contents rule: session id, profile, outcome enum,
// cookies_saved, saved names + earliest expiry, duration.
// Never values, frames, or keys. Best-effort.
func (s *LoginSession) writeAudit(store *Store, rec auditRecord) {
	paths, err := profile.ProfilePaths(s.BaseDir, s.Profile.Name)
	if err != nil {
		return
	}
	path := filepath.Join(paths.Dir, LoginAuditFileName)
	ls, err := store.lock()
	if err != nil {
		return
	}
	defer ls.unlock()
	var records []auditRecord
	if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
		for _, line := range splitAuditLines(raw) {
			var r auditRecord
			if json.Unmarshal(line, &r) == nil {
				records = append(records, r)
			}
		}
	}
	records = append(records, rec)
	if len(records) > LoginAuditMaxRecords {
		records = records[len(records)-LoginAuditMaxRecords:]
	}
	var sb []byte
	for _, r := range records {
		line, err := json.Marshal(r)
		if err != nil {
			continue
		}
		sb = append(sb, line...)
		sb = append(sb, '\n')
	}
	tmp, err := os.CreateTemp(paths.Dir, ".login-audit-*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(sb); err != nil {
		_ = tmp.Close()
		return
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	_ = os.Rename(tmpName, path)
}

func splitAuditLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if line := data[start:i]; len(line) > 0 {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, data[start:])
	}
	return out
}
