// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Cheap-chain endpoints for expiry detection. The keeper runs
// ONLY this chain: GET /api/session -> POST /api/auth/check.
// No hatch/token, no WebSocket, no chat.
const (
	SessionCheckURL = "https://muse.ai/api/session"
	AuthCheckURL    = "https://muse.ai/api/auth/check"
)

// Checker runs the cheap chain with a Cookie header and returns
// the ordered Set-Cookie updates observed, in step order
// (session response first, then auth/check). Updates are
// returned alongside errors whenever a response header was
// received, so a tick persists a server-issued deletion even
// when the step then reports AuthError. The error classes are
// the conn contracts: AuthError = expired/invalid (stop),
// GatewayError/transport = transient (backoff). Callers
// distinguish with errors.As, never message text. The skipped
// count counts unparseable Set-Cookie values.
type Checker interface {
	Check(ctx context.Context, cookieHeader string) (updates []CookieUpdate, skipped int, err error)
}

// GatewayChecker is the production Checker: the cheap chain
// through the profile's HTTP client (built by the command layer
// from the profile outbound), with the profile identity.
type GatewayChecker struct {
	Client *http.Client
	Clock  Clock
}

// Check implements Checker. The auth/check step runs with the
// session step's updates merged into the header (jar-like
// behaviour); the original header is used for the session step.
func (g *GatewayChecker) Check(ctx context.Context, cookieHeader string) ([]CookieUpdate, int, error) {
	clock := g.Clock
	if clock == nil {
		clock = RealClock
	}
	now := clock.Now()
	var all []CookieUpdate
	skipped := 0
	_, cookies, skip1, err := gateway.FetchSessionInfoWithCookies(ctx, g.Client, cookieHeader)
	skipped += skip1
	all = append(all, toUpdates(cookies, SessionCheckURL, now)...)
	if err != nil {
		return all, skipped, err
	}
	header2 := mergeCookieHeader(cookieHeader, all, now)
	_, cookies2, skip2, err2 := gateway.FetchAccessTokenWithCookies(ctx, g.Client, header2)
	skipped += skip2
	all = append(all, toUpdates(cookies2, AuthCheckURL, now)...)
	return all, skipped, err2
}

func toUpdates(cookies []*http.Cookie, rawURL string, now time.Time) []CookieUpdate {
	u, _ := url.Parse(rawURL)
	out := make([]CookieUpdate, 0, len(cookies))
	for _, c := range cookies {
		upd := EffectiveSetCookie(c, u, now)
		if !InFilteredDomain(upd.Cookie) {
			continue
		}
		out = append(out, upd)
	}
	return out
}

// mergeCookieHeader applies updates to a one-line Cookie header
// for the second chain step. Domain/path do not matter for the
// wire header, only name=value pairs.
func mergeCookieHeader(header string, updates []CookieUpdate, now time.Time) string {
	var stored []StoredCookie
	for _, pair := range strings.Split(header, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		stored = append(stored, StoredCookie{Name: name, Value: value, Domain: "muse.ai", Path: "/"})
	}
	return CookieHeader(ApplyUpdates(stored, updates), now)
}

// ExportedCookie is one cookie read from the browser over CDP,
// in transport-neutral form (the chromedp conversion lives in
// the with_chromedp file). Expires is a float64 epoch, -1 or
// <= 0 for a session cookie, matching network.Cookie.
type ExportedCookie struct {
	Name     string
	Value    string // SECRET MATERIAL: never log or print.
	Domain   string
	Path     string
	Expires  float64
	Secure   bool
	HTTPOnly bool
	Session  bool
}

// FromExportedCookie resolves an exported cookie to merge form.
// The CDP Domain is taken as given (Chromium reports domain
// cookies with the leading dot); a session cookie has expiry 0.
//
// CDP snapshots are FAITHFUL: an exported cookie is recorded
// exactly as the browser holds it, including an empty value
// with a future expiry, which is written verbatim — it is NOT
// a deletion. Deletion in the CDP path happens by ABSENCE:
// ReplaceWithExport drops every stored filtered-domain entry
// not present in the snapshot. (Freeze (c)'s empty-value
// rule applies to Set-Cookie updates via EffectiveSetCookie
// only, never to snapshots.)
func FromExportedCookie(c ExportedCookie) StoredCookie {
	expires := int64(0)
	if !c.Session && c.Expires > 0 {
		expires = int64(c.Expires)
	}
	path := c.Path
	if path == "" {
		path = "/"
	}
	return StoredCookie{
		Name: c.Name, Value: c.Value, Domain: c.Domain, Path: path,
		Secure: c.Secure, HTTPOnly: c.HTTPOnly, Expires: expires,
	}
}

// ErrReexportUnavailable is returned by the tag-off stub
// exporter: the build cannot re-export, so an expired session
// stops the entry (reported) instead of retrying forever.
var ErrReexportUnavailable = errors.New("re-export unavailable in this build (rebuild with -tags with_chromedp)")

// Exporter reads the live session cookies from the attached
// browser. Implementations live in the with_chromedp file (real
// CDP) and the stub file (tag-off). Export must never navigate,
// dispatch input, or enable Runtime/JS.
type Exporter interface {
	Export(ctx context.Context) ([]ExportedCookie, error)
}

// TickDeps wires one entry's tick. Checker is required;
// Exporter and Notifier may be nil (no export attempt, no
// notices). Clock nil means RealClock.
//
// BeforeStateSave is a TEST SEAM, nil by default: when set, it
// is invoked synchronously by the state-save path after the
// state directory is re-ensured and before the state file is
// written, so a test can fault the save deterministically
// (e.g. remove the directory). Production code must leave it
// nil; when nil it changes nothing.
type TickDeps struct {
	Clock           Clock
	Entry           *profile.KeeperEntry
	BaseDir         string
	Profile         *profile.Profile
	Checker         Checker
	Exporter        Exporter
	Notifier        Notifier
	Jitter          func() float64
	LockTimeout     time.Duration
	BeforeStateSave func()
}

// TickResult is one tick's observable outcome. Outcome uses the
// state outcome enum; OutcomeError is a hard failure — the tick
// could not run or persist because of a lock, state-directory,
// or save error other than a held lock (see classifyLockError).
// Err is the underlying typed error for command-layer exit
// mapping and is never printed directly.
// Recovered reports a CDP re-export recovery: the command layer
// sends the re-exported notice after Tick returns (never under
// the file lock). StateCorrupt reports that the state file was
// corrupt or an unknown version when this tick read it: the
// tick substituted a fresh state and re-observed from the
// cookies file, and the next successful save replaces the
// corrupt file. The corruption is surfaced, never silent.
type TickResult struct {
	Outcome      string
	Stage        string
	Stopped      bool
	Recovered    bool
	WroteCookies bool
	Dropped      int
	CDPDropped   int
	Exported     int
	CookiesSeen  int
	Skipped      int
	NextDelay    time.Duration
	StateCorrupt bool
	Err          error
}

// Store serialises one profile's cookies file + state file
// access behind the cookies-file lock. A Store holds no lock
// itself: lock() acquires it for one short window.
// beforeStateSave is the TickDeps test seam, copied by Tick;
// it is nil for every other Store user.
type Store struct {
	baseDir         string
	profileName     string
	cookiesPath     string
	profileDir      string
	lockTimeout     time.Duration
	beforeStateSave func()
}

// NewStore resolves the profile's cookies path and state dir.
// The cookies path comes from the parsed profile (already
// resolved against baseDir); a relative value is resolved
// under baseDir so LockCookiesFile's absolute-path rule holds.
func NewStore(baseDir string, prof *profile.Profile, lockTimeout time.Duration) (*Store, error) {
	paths, err := profile.ProfilePaths(baseDir, prof.Name)
	if err != nil {
		return nil, err
	}
	cookiesPath := prof.CookiesFile
	if cookiesPath == "" {
		cookiesPath = paths.Cookies
	}
	if !filepath.IsAbs(cookiesPath) {
		abs, err := filepath.Abs(filepath.Join(baseDir, cookiesPath))
		if err != nil {
			return nil, err
		}
		cookiesPath = abs
	}
	if lockTimeout <= 0 {
		lockTimeout = DefaultLockTimeout
	}
	return &Store{
		baseDir: baseDir, profileName: prof.Name,
		cookiesPath: cookiesPath, profileDir: paths.Dir,
		lockTimeout: lockTimeout,
	}, nil
}

type lockedStore struct {
	store       *Store
	release     func()
	state       *SessionState
	cookies     []StoredCookie
	jarForm     bool
	fileMissing bool
	raw         []byte
	// stateCorrupt reports that LoadState found a corrupt or
	// unknown-version state file and a fresh state was
	// substituted (loop-2 red-team F6). The corruption is
	// recoverable observed state, not a reason to brick the
	// tick: the cookies file is still authoritative, and the
	// next successful save replaces the corrupt file.
	stateCorrupt bool
}

// ensureStateDir creates the profile (state) directory when it
// is missing, with the existing profile-dir semantics
// (EnsureProfileDir: 0700 for named profiles and for the
// default profile's config dir). It runs BEFORE the
// cookies-file lock is taken, so a creation failure is
// classified as ErrStateDir on every route — including the
// default cookies path, where LockCookiesFile's own parent
// creation would otherwise return the failure unwrapped
// (K-LIVE-1/B1). A creation failure is wrapped in ErrStateDir
// so callers fail loudly instead of skipping.
func (s *Store) ensureStateDir() error {
	if _, err := profile.EnsureProfileDir(s.baseDir, s.profileName); err != nil {
		return fmt.Errorf("%w: %q: %w", ErrStateDir, s.profileDir, err)
	}
	return nil
}

// classifyLockError is the ONE mapping from a lock-acquisition
// (or lock-window load/parse) failure to a Tick outcome: only
// a held lock — the exact ErrCookiesLockTimeout sentinel,
// matched with errors.Is, never message text — is "skipped".
// A state-directory failure and every other error is a hard
// failure (OutcomeError). No other site in Tick or its helpers
// may map a lock error to OutcomeSkipped.
func classifyLockError(err error) (outcome, stage string) {
	if errors.Is(err, profile.ErrCookiesLockTimeout) {
		return OutcomeSkipped, "lock"
	}
	return OutcomeError, "save"
}

// saveState is the one state-save path used by Tick and its
// helpers: re-ensure the state directory (it may have been
// removed after the lock was taken), fire the BeforeStateSave
// test seam (nil in production), then SaveState. Any error
// from it is a hard failure for the caller: it must never be
// swallowed into a "skipped" or primary outcome. The
// ensure-step error is already wrapped as ErrStateDir; a
// SaveState error is returned unwrapped and the caller maps
// it to OutcomeError regardless of kind.
func (s *Store) saveState(st *SessionState) error {
	if err := s.ensureStateDir(); err != nil {
		return err
	}
	if s.beforeStateSave != nil {
		s.beforeStateSave()
	}
	return SaveState(s.profileDir, st)
}

func (s *Store) lock() (*lockedStore, error) {
	// State dir first: a creation failure must surface as
	// ErrStateDir before any lock error can mask it, and the
	// lock's own parent creation (default path) must not be
	// the only route that creates the directory.
	if err := s.ensureStateDir(); err != nil {
		return nil, err
	}
	release, err := profile.LockCookiesFile(s.baseDir, s.profileName, s.cookiesPath, s.lockTimeout)
	if err != nil {
		// Defence in depth for the ensure→lock window: a
		// profile-dir failure raised inside LockCookiesFile
		// (default path) carries the profile sentinel.
		if errors.Is(err, profile.ErrProfileDir) {
			return nil, fmt.Errorf("%w: %q: %w", ErrStateDir, s.profileDir, err)
		}
		return nil, err
	}
	ls := &lockedStore{store: s, release: release, jarForm: true}
	st, err := LoadState(s.profileDir)
	if err != nil {
		if IsStateCorrupt(err) {
			// Recoverable: observed state is lost, the
			// cookies file still decides the session.
			// The tick records StateCorrupt and the next
			// save replaces the corrupt file.
			ls.state = NewSessionState()
			ls.stateCorrupt = true
		} else {
			release()
			return nil, err
		}
	} else {
		ls.state = st
	}
	raw, err := os.ReadFile(s.cookiesPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			ls.fileMissing = true
			return ls, nil
		}
		release()
		return nil, err
	}
	ls.raw = raw
	cookies, jarForm, err := classifyCookiesFile(raw, s.cookiesPath)
	if err != nil {
		release()
		return nil, err
	}
	ls.cookies = cookies
	ls.jarForm = jarForm
	return ls, nil
}

func (ls *lockedStore) unlock() { ls.release() }

// lockStateOnly acquires the cookies-file lock and loads the
// state file, without reading or parsing the cookies file
// itself. ResetAfterLogin uses it: a fresh import may hold any
// accepted form (including forms the strict jar parser
// rejects, such as extra-column jars), and clearing sticky
// markers must never fail on the cookies bytes. The lock
// still serialises against keeper ticks.
func (s *Store) lockStateOnly() (*lockedStore, error) {
	// Same order as lock(): state dir first, then the lock,
	// with the profile-dir wrap for the ensure→lock window.
	if err := s.ensureStateDir(); err != nil {
		return nil, err
	}
	release, err := profile.LockCookiesFile(s.baseDir, s.profileName, s.cookiesPath, s.lockTimeout)
	if err != nil {
		if errors.Is(err, profile.ErrProfileDir) {
			return nil, fmt.Errorf("%w: %q: %w", ErrStateDir, s.profileDir, err)
		}
		return nil, err
	}
	st, err := LoadState(s.profileDir)
	if err != nil {
		if IsStateCorrupt(err) {
			// Same tolerance as lock(): a corrupt state
			// file must never brick the login/import
			// reset that clears the sticky stop.
			return &lockedStore{store: s, release: release, state: NewSessionState(), stateCorrupt: true}, nil
		}
		release()
		return nil, err
	}
	return &lockedStore{store: s, release: release, state: st}, nil
}

// classifyCookiesFile decides the stored file's form. A file
// that LOOKS like a jar (any tab, or the Netscape header) is
// parsed strictly: a malformed row fails closed with its line
// number. A file with no tabs is tried as the one-line/JSON
// forms via gateway.ParseCookies (which returns the Cookie
// header); success means non-jar form. Anything else is
// corrupt: fail closed. An empty file is an empty jar.
func classifyCookiesFile(raw []byte, path string) ([]StoredCookie, bool, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, true, nil
	}
	if strings.Contains(trimmed, "\t") || strings.HasPrefix(trimmed, "# Netscape") {
		cookies, err := ParseJar(raw)
		if err != nil {
			return nil, false, err
		}
		return cookies, true, nil
	}
	header, err := gateway.ParseCookies(string(raw), path)
	if err != nil {
		return nil, false, fmt.Errorf("cookies file is neither a jar nor a readable one-line/JSON form: %w", err)
	}
	// Rebuild stored cookies from the header for the check's
	// Cookie header construction; domain/path are unknown in
	// this form, so they are placeholders that never reach a
	// write (non-jar files are never rewritten from Set-Cookie
	// captures).
	var cookies []StoredCookie
	for _, pair := range strings.Split(header, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		cookies = append(cookies, StoredCookie{Name: strings.TrimSpace(name), Value: value, Domain: "muse.ai", Path: "/"})
	}
	return cookies, false, nil
}

// saveJar writes data when it differs from the locked snapshot's
// bytes, via the atomic writer. The lock is held by the caller.
func (ls *lockedStore) saveJar(data []byte) (bool, error) {
	if string(data) == string(ls.raw) {
		return false, nil
	}
	changed, err := profile.WriteCookiesFile(ls.store.baseDir, ls.store.profileName, ls.store.cookiesPath, data)
	if err != nil {
		return false, err
	}
	ls.raw = data
	return changed, nil
}

// Tick runs one keeper tick for one entry. The lock is held
// only for short read/write windows, never across network
// calls or backoff sleeps. The full flow:
//
//  1. Locked snapshot: honour a fresh login pause (skip), a
//     stale login flag (recover), or a sticky stop (report,
//     retry a pending notice, no network to muse.ai).
//  2. Cheap chain with backoff on transient errors. AuthError
//     goes to the export/stop path; updates received alongside
//     an error are still persisted (per-response rule).
//  3. Locked merge + validate + write + state save. CDP
//     exports replace the filtered set with the hatch_sess
//     gate; Set-Cookie captures merge into jar files only and
//     skip the write for non-jar files (freeze (a)).
//  4. Notices outside the lock: warn-once on the false->true
//     logged_out transition, re-exported on recovery.
func Tick(ctx context.Context, deps TickDeps) TickResult {
	clock := deps.Clock
	if clock == nil {
		clock = RealClock
	}
	now := clock.Now()
	base := deps.Entry.EffectiveInterval()
	// corruptSeen accumulates the state-corruption flag
	// across this tick's lock windows; fail() reads it so
	// every failure return carries it.
	corruptSeen := false
	fail := func(outcome, stage string, err error) TickResult {
		return TickResult{Outcome: outcome, Stage: stage, Err: err, NextDelay: base, StateCorrupt: corruptSeen}
	}
	// failSave is fail() for save-path failures: the outcome is
	// always the hard OutcomeError, and WroteCookies carries
	// whether the cookies file was already rewritten, so the
	// JSON never claims "wrote=false" for a file that changed.
	failSave := func(stage string, err error, wrote bool) TickResult {
		return TickResult{Outcome: OutcomeError, Stage: stage, Err: err, NextDelay: base, StateCorrupt: corruptSeen, WroteCookies: wrote}
	}

	store, err := NewStore(deps.BaseDir, deps.Profile, deps.LockTimeout)
	if err != nil {
		return fail(OutcomeError, "save", err)
	}
	store.beforeStateSave = deps.BeforeStateSave

	// Phase 1: locked snapshot.
	ls, err := store.lock()
	if err != nil {
		outcome, stage := classifyLockError(err)
		return fail(outcome, stage, err)
	}
	corruptSeen = ls.stateCorrupt
	state := ls.state
	if state.LoginActive {
		stale := state.LoginStartedAt == nil || now.Sub(*state.LoginStartedAt) > LoginFlagStaleAfter
		if !stale {
			next := now.Add(base)
			state.LastTickOutcome = OutcomeSkipped
			state.LastTickStage = ""
			state.NextCheckAt = &next
			if err := store.saveState(state); err != nil {
				ls.unlock()
				return failSave("save", err, false)
			}
			ls.unlock()
			return TickResult{Outcome: OutcomeSkipped, NextDelay: base, StateCorrupt: corruptSeen}
		}
		// Stale flag: the login process is assumed dead.
		state.LoginActive = false
		state.LoginSessionID = ""
		state.LoginStartedAt = nil
		if err := store.saveState(state); err != nil {
			ls.unlock()
			return failSave("save", err, false)
		}
	}
	if state.KeeperStopped {
		pending := state.WarnPending
		kind := NoticeKind(state.WarnKind)
		ls.unlock()
		if pending && deps.Notifier != nil {
			// Best-effort retry: only a successful send
			// clears the marker; a failed send stays
			// pending for a later tick.
			if err := deps.Notifier.Notify(ctx, kind, deps.Profile.Name); err == nil {
				if ls2, err := store.lock(); err == nil {
					ls2.state.WarnPending = false
					ls2.state.WarnSent = true
					warned := clock.Now()
					ls2.state.WarnedAt = &warned
					// Best-effort marker clear: a failed
					// save leaves the marker pending for
					// a later tick; it cannot change the
					// stopped outcome already determined.
					_ = store.saveState(ls2.state)
					ls2.unlock()
				}
			}
		}
		return TickResult{Outcome: state.LastTickOutcome, Stopped: true, NextDelay: 0, StateCorrupt: corruptSeen}
	}
	snapshotCookies := ls.cookies
	jarForm := ls.jarForm
	fileMissing := ls.fileMissing
	ls.unlock()

	header := CookieHeader(snapshotCookies, now)

	// Phase 2: cheap chain with backoff on transient errors.
	backoff := NewBackoff(clock, deps.Jitter)
	var updates []CookieUpdate
	var skipped int
	var checkErr error
	for {
		updates, skipped, checkErr = deps.Checker.Check(ctx, header)
		if checkErr == nil {
			break
		}
		var authErr *conn.AuthError
		if errors.As(checkErr, &authErr) {
			break
		}
		if ctx.Err() != nil {
			// A cancelled context is a hard failure, never
			// a skip: the outcome is surfaced as-is, so a
			// tick timeout prints outcome "error" with
			// exit 4 (classifyError maps the carried
			// DeadlineExceeded), and a parent interrupt
			// returns before any JSON is printed (exit
			// 130).
			return fail(OutcomeError, "session", ctx.Err())
		}
		delay, ok := backoff.NextDelay()
		if !ok {
			// Ladder exhausted: record the transient outcome.
			return recordTransient(clock, store, base, checkErr, "session")
		}
		if !backoff.Sleep(ctx, delay) {
			return fail(OutcomeError, "session", ctx.Err())
		}
	}
	// skipped counts unparseable Set-Cookie values; it is a
	// diagnostic count only and never carries values.

	// Phase 2b: AuthError -> export-or-stop.
	recovered := false
	var exportErr error
	var exported []StoredCookie
	var exportDropped int
	if checkErr != nil {
		var authErr *conn.AuthError
		if !errors.As(checkErr, &authErr) {
			return fail(OutcomeTransientError, "session", checkErr)
		}
		if deps.Exporter != nil {
			exported, exportDropped, exportErr = runExport(ctx, deps.Exporter)
			switch {
			case exportErr == nil:
				// Validate the merged set, then re-check
				// once with the new cookies.
				merged, _ := ReplaceWithExport(snapshotCookies, exported)
				if !validateExportedSet(merged, now) {
					return stopEntry(clock, store, base, updates, jarForm, fileMissing, StoppedAuthError, checkErr)
				}
				header2 := CookieHeader(merged, now)
				updates2, _, err2 := deps.Checker.Check(ctx, header2)
				updates = append(updates, updates2...)
				if err2 == nil {
					recovered = true
					checkErr = nil
				} else {
					var authErr2 *conn.AuthError
					if !errors.As(err2, &authErr2) {
						return recordTransient(clock, store, base, err2, "auth_check")
					}
					checkErr = err2
				}
			case errors.Is(exportErr, ErrReexportUnavailable):
				// Tag-off build: no recovery possible.
				return stopEntry(clock, store, base, updates, jarForm, fileMissing, StoppedAuthError, checkErr)
			default:
				// CDP unreachable etc.: transient, do not stop.
				return recordExportFailed(clock, store, base, exportErr)
			}
		}
		if checkErr != nil {
			return stopEntry(clock, store, base, updates, jarForm, fileMissing, stopReason(fileMissing), checkErr)
		}
	}

	// Phase 3: locked merge + write + state.
	ls, err = store.lock()
	if err != nil {
		outcome, stage := classifyLockError(err)
		return fail(outcome, stage, err)
	}
	corruptSeen = corruptSeen || ls.stateCorrupt
	defer ls.unlock()
	st := ls.state
	// Re-check the login pause under the fresh lock: a login
	// that started during the network phase wins.
	if st.LoginActive {
		st.LastTickOutcome = OutcomeSkipped
		st.LastTickStage = ""
		next := clock.Now().Add(base)
		st.NextCheckAt = &next
		if err := store.saveState(st); err != nil {
			return failSave("save", err, false)
		}
		return TickResult{Outcome: OutcomeSkipped, NextDelay: base, StateCorrupt: corruptSeen}
	}
	now2 := clock.Now()
	merged := ls.cookies
	dropped := 0
	wrote := false
	var written []byte
	// A missing cookies file stays missing when there is
	// nothing to write: a successful tick with no cookies must
	// not conjure an empty jar into existence.
	shouldWrite := !ls.fileMissing || len(merged) > 0
	if recovered {
		merged, dropped = ReplaceWithExport(ls.cookies, exported)
		shouldWrite = !ls.fileMissing || len(merged) > 0
		data, err := SerializeJar(merged)
		if err != nil {
			return failSave("save", err, false)
		}
		if shouldWrite {
			wrote, err = ls.saveJar(data)
			if err != nil {
				return failSave("save", err, false)
			}
			written = data
		}
	} else if ls.jarForm {
		merged = ApplyUpdates(ls.cookies, updates)
		shouldWrite = !ls.fileMissing || len(merged) > 0
		data, err := SerializeJar(merged)
		if err != nil {
			return failSave("save", err, false)
		}
		if shouldWrite {
			wrote, err = ls.saveJar(data)
			if err != nil {
				return failSave("save", err, false)
			}
			written = data
		}
	} else {
		// Non-jar file: Set-Cookie capture SKIPS the rewrite
		// (freeze (a)); the tick still ran and the state
		// still records the observed expiry.
		merged = ApplyUpdates(ls.cookies, updates)
	}
	st.LoggedOut = false
	st.KeeperStopped = false
	st.KeeperStoppedReason = ""
	st.LastCheckedAt = &now2
	st.LastTickOutcome = OutcomeOK
	st.LastTickStage = ""
	st.RefreshCookieRecords(merged, now2)
	switch {
	case wrote:
		st.CookiesSHA256 = SHA256Hex(written)
	case ls.raw != nil:
		st.CookiesSHA256 = SHA256Hex(ls.raw)
	default:
		st.CookiesSHA256 = ""
	}
	delay := NextDelayAfter(base, st.DrivingExpiry, now2)
	next := now2.Add(delay)
	st.NextCheckAt = &next
	if err := store.saveState(st); err != nil {
		return failSave("save", err, wrote)
	}
	return TickResult{
		Outcome: OutcomeOK, Recovered: recovered,
		CookiesSeen: len(merged), Skipped: skipped,
		WroteCookies: wrote, Dropped: dropped, CDPDropped: exportDropped,
		Exported: len(exported), NextDelay: delay, StateCorrupt: corruptSeen,
	}
}

func stopReason(fileMissing bool) string {
	if fileMissing {
		return StoppedCookiesMissing
	}
	return StoppedAuthError
}

// validateExportedSet enforces the pre-write gate for CDP
// exports: hatch_sess present + non-empty in the MERGED set,
// and the earliest FILTERED-domain expiry not already past.
// Non-filtered cookies are excluded from both checks (loop-2
// F2 fix): an expired cookie from an unrelated domain must
// never veto a valid re-export and sticky-stop the entry.
// The empty-export stop is unchanged: an export that yields
// no usable filtered set still stops (P1 decides otherwise).
func validateExportedSet(merged []StoredCookie, now time.Time) bool {
	hasHatch := false
	var filtered []StoredCookie
	for _, c := range merged {
		if !InFilteredDomain(c) {
			continue
		}
		filtered = append(filtered, c)
		if c.Name == "hatch_sess" && c.Value != "" {
			hasHatch = true
		}
	}
	if !hasHatch {
		return false
	}
	if earliest := EarliestExpiry(filtered); earliest != nil && !earliest.After(now) {
		return false
	}
	return true
}

// runExport calls the exporter, filters to the Muse domains,
// and converts to merge form. Non-filtered cookies are dropped
// with a count only.
func runExport(ctx context.Context, exp Exporter) ([]StoredCookie, int, error) {
	raw, err := exp.Export(ctx)
	if err != nil {
		return nil, 0, err
	}
	out := make([]StoredCookie, 0, len(raw))
	dropped := 0
	for _, c := range raw {
		sc := FromExportedCookie(c)
		if !InFilteredDomain(sc) {
			dropped++
			continue
		}
		out = append(out, sc)
	}
	return out, dropped, nil
}

// recordTransient persists a transient-error outcome (backoff
// ladder exhausted or a non-auth error after the export
// re-check) and returns the result. No stop, no notice.
// Updates received alongside the failed check are
// intentionally NOT persisted here (loop-2 technical N9 /
// red-team N1-N2 disposition): a failed step's Set-Cookie
// values are partial/untrusted, and the next tick
// re-observes from the cookies file. The stop path
// (stopEntry) DOES persist per-response updates: an
// AuthError's last word is the server's verdict, not a
// transient failure.
func recordTransient(clock Clock, store *Store, base time.Duration, err error, stage string) TickResult {
	ls, lerr := store.lock()
	if lerr != nil {
		if errors.Is(lerr, profile.ErrCookiesLockTimeout) {
			return TickResult{Outcome: OutcomeTransientError, Stage: stage, Err: err, NextDelay: base}
		}
		return TickResult{Outcome: OutcomeError, Stage: "save", Err: errors.Join(lerr, err), NextDelay: base}
	}
	defer ls.unlock()
	st := ls.state
	now2 := clock.Now()
	st.LastCheckedAt = &now2
	st.LastTickOutcome = OutcomeTransientError
	st.LastTickStage = stage
	st.RefreshCookieRecords(ls.cookies, now2)
	next := now2.Add(base)
	st.NextCheckAt = &next
	if serr := store.saveState(st); serr != nil {
		return TickResult{Outcome: OutcomeError, Stage: "save", Err: errors.Join(serr, err), NextDelay: base, StateCorrupt: ls.stateCorrupt}
	}
	return TickResult{Outcome: OutcomeTransientError, Stage: stage, Err: err, NextDelay: base, StateCorrupt: ls.stateCorrupt}
}

// recordExportFailed persists an export-failure outcome: the
// browser could not be reached, but the session is not proven
// dead, so the entry keeps ticking. No stop, no notice.
func recordExportFailed(clock Clock, store *Store, base time.Duration, err error) TickResult {
	ls, lerr := store.lock()
	if lerr != nil {
		if errors.Is(lerr, profile.ErrCookiesLockTimeout) {
			return TickResult{Outcome: OutcomeExportFailed, Stage: "export", Err: err, NextDelay: base}
		}
		return TickResult{Outcome: OutcomeError, Stage: "save", Err: errors.Join(lerr, err), NextDelay: base}
	}
	defer ls.unlock()
	st := ls.state
	now2 := clock.Now()
	st.LastCheckedAt = &now2
	st.LastTickOutcome = OutcomeExportFailed
	st.LastTickStage = "export"
	st.RefreshCookieRecords(ls.cookies, now2)
	next := now2.Add(base)
	st.NextCheckAt = &next
	if serr := store.saveState(st); serr != nil {
		return TickResult{Outcome: OutcomeError, Stage: "save", Err: errors.Join(serr, err), NextDelay: base, StateCorrupt: ls.stateCorrupt}
	}
	return TickResult{Outcome: OutcomeExportFailed, Stage: "export", Err: err, NextDelay: base, StateCorrupt: ls.stateCorrupt}
}

// stopEntry persists the sticky stop: logged_out, stopped with
// reason, warn-once marker on the false->true transition, and
// the per-response updates merged for jar files (the server's
// last word is still recorded). The notice itself is sent by
// the caller after Tick returns — see NotifyStopped — because
// a network send must never happen under the file lock.
// Durability note (loop-2 red-team N3): if the stop-path lock
// fails, the returned result still stops THIS run's goroutine
// (in-memory), but no marker is persisted; the next run
// re-ticks and re-stops. The marker's durability depends on
// the lock like every other state write — no separate
// mechanism is added for it.
func stopEntry(clock Clock, store *Store, base time.Duration, updates []CookieUpdate, jarForm bool, fileMissing bool, reason string, cause error) TickResult {
	ls, lerr := store.lock()
	if lerr != nil {
		if errors.Is(lerr, profile.ErrCookiesLockTimeout) {
			return TickResult{Outcome: OutcomeAuthError, Stage: "session", Stopped: true, Err: cause, NextDelay: 0}
		}
		return TickResult{Outcome: OutcomeError, Stage: "save", Stopped: true, Err: errors.Join(lerr, cause), NextDelay: 0}
	}
	defer ls.unlock()
	st := ls.state
	now2 := clock.Now()
	wasLoggedOut := st.LoggedOut
	merged := ls.cookies
	wrote := false
	if jarForm {
		merged = ApplyUpdates(ls.cookies, updates)
		if !fileMissing || len(merged) > 0 {
			data, err := SerializeJar(merged)
			if err == nil {
				var serr error
				wrote, serr = ls.saveJar(data)
				if serr != nil {
					return TickResult{Outcome: OutcomeError, Stage: "save", Stopped: true, Err: errors.Join(serr, cause), NextDelay: 0, StateCorrupt: ls.stateCorrupt}
				}
			}
		}
	} else {
		merged = ApplyUpdates(ls.cookies, updates)
	}
	st.LoggedOut = true
	st.KeeperStopped = true
	st.KeeperStoppedReason = reason
	st.LastCheckedAt = &now2
	st.LastTickOutcome = OutcomeAuthError
	st.LastTickStage = "session"
	st.RefreshCookieRecords(merged, now2)
	st.NextCheckAt = nil
	if !wasLoggedOut {
		st.WarnPending = true
		st.WarnSent = false
		if reason == StoppedAuthError {
			st.WarnKind = string(NoticeLoggedOut)
		} else {
			st.WarnKind = string(NoticeFailed)
		}
	}
	if serr := store.saveState(st); serr != nil {
		return TickResult{Outcome: OutcomeError, Stage: "save", Stopped: true, Err: errors.Join(serr, cause), NextDelay: 0, StateCorrupt: ls.stateCorrupt, WroteCookies: wrote}
	}
	return TickResult{Outcome: OutcomeAuthError, Stage: "session", Stopped: true, Err: cause, NextDelay: 0, StateCorrupt: ls.stateCorrupt, WroteCookies: wrote}
}

// NotifyStopped sends the pending warn-once notice for a
// stopped entry and records the attempt. It is called by the
// command layer AFTER Tick returns (never under the lock).
// A failed send leaves the marker pending for a later tick.
func NotifyStopped(ctx context.Context, deps TickDeps, notifier Notifier) {
	if notifier == nil {
		return
	}
	store, err := NewStore(deps.BaseDir, deps.Profile, deps.LockTimeout)
	if err != nil {
		return
	}
	ls, err := store.lock()
	if err != nil {
		return
	}
	pending := ls.state.WarnPending
	kind := NoticeKind(ls.state.WarnKind)
	profileName := deps.Profile.Name
	ls.unlock()
	if !pending {
		return
	}
	clock := deps.Clock
	if clock == nil {
		clock = RealClock
	}
	if err := notifier.Notify(ctx, kind, profileName); err != nil {
		return
	}
	ls2, err := store.lock()
	if err != nil {
		return
	}
	defer ls2.unlock()
	ls2.state.WarnPending = false
	ls2.state.WarnSent = true
	warned := clock.Now()
	ls2.state.WarnedAt = &warned
	// Best-effort marker clear (same disclosed exception as
	// the Tick retry path): a failed save leaves the marker
	// pending; it cannot change a notification outcome.
	_ = store.saveState(ls2.state)
}

// ResetAfterLogin clears a sticky stop after a successful login
// or import, so the keeper resumes on its next tick. Called by
// the login/import flows, never by the tick itself. A corrupt
// or unknown-version state file is tolerated (fresh state is
// written): the import half must never fail after the cookies
// file was already written (loop-2 red-team F6).
func ResetAfterLogin(baseDir string, prof *profile.Profile, clock Clock) error {
	if clock == nil {
		clock = RealClock
	}
	store, err := NewStore(baseDir, prof, DefaultLockTimeout)
	if err != nil {
		return err
	}
	ls, err := store.lockStateOnly()
	if err != nil {
		return err
	}
	defer ls.unlock()
	st := ls.state
	st.LoggedOut = false
	st.KeeperStopped = false
	st.KeeperStoppedReason = ""
	st.WarnPending = false
	st.WarnSent = false
	st.WarnKind = ""
	st.LoginActive = false
	st.LoginSessionID = ""
	st.LoginStartedAt = nil
	return store.saveState(st)
}
