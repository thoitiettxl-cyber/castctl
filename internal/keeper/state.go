// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Per-profile session state: session-state.json, mode 0600, NEXT
// TO (never inside) config.json — in the profile directory — one
// file per profile. Schema v1, frozen here and in docs/config.md.
// The state file is OBSERVED state, not configuration: it records
// what the keeper last saw so `keeper status` (item 2's future
// status endpoint data source) works with no network, and so a
// sticky stop survives restarts. It never feeds back into config
// parsing.
//
// Values NEVER appear here: the Cookies map carries names,
// expiry dates, and session flags only. The file hash of the
// cookies file is recorded for change detection; the hash itself
// is never logged (it is a fingerprint of secret material, and
// there is no reason to print it).
//
// Unknown JSON fields are ignored on load (forward tolerance);
// an unknown `version` refuses the tick rather than guessing.

const (
	// StateVersion is the frozen schema version.
	StateVersion = 1
	// StateFileName is the state file name within a profile dir.
	StateFileName = "session-state.json"
	// LoginFlagStaleAfter bounds a login pause: a LoginActive
	// flag older than this is recovered by the next tick.
	LoginFlagStaleAfter = 70 * time.Minute
	// DefaultLockTimeout bounds one cookies-file lock hold
	// attempt: past it, the tick is skipped, never forced.
	DefaultLockTimeout = 5 * time.Second
)

// Stopped reasons: the closed enum for KeeperStoppedReason.
const (
	StoppedAuthError      = "auth_error"
	StoppedCookiesMissing = "cookies_missing"
	StoppedStateCorrupt   = "state_corrupt"
)

// Tick outcomes: the closed enum for LastTickOutcome.
// OutcomeError is tick-result-only: a tick that could not run or
// persist because the profile state directory could not be
// created. It is never written to the state file (no state file
// can be written when its directory does not exist) and never
// "skipped": "skipped" is reserved for a login in progress or a
// held lock.
const (
	OutcomeNever          = "never"
	OutcomeOK             = "ok"
	OutcomeAuthError      = "auth_error"
	OutcomeTransientError = "transient_error"
	OutcomeExportFailed   = "export_failed"
	OutcomeSkipped        = "skipped"
	OutcomeError          = "error"
)

// CookieState is the per-cookie observed record: name is the map
// key; values never appear.
type CookieState struct {
	// ExpiresAt is nil for a session cookie.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Session   bool       `json:"session"`
	LastSeen  time.Time  `json:"last_seen"`
}

// SessionState is the v1 state file body.
type SessionState struct {
	Version int `json:"version"`

	LoggedOut           bool       `json:"logged_out"`
	KeeperStopped       bool       `json:"keeper_stopped"`
	KeeperStoppedReason string     `json:"keeper_stopped_reason,omitempty"`
	LastCheckedAt       *time.Time `json:"last_checked_at,omitempty"`
	LastTickOutcome     string     `json:"last_tick_outcome"`
	// LastTickStage names the tick stage of the last outcome:
	// "", "session", "auth_check", "export", or "save".
	LastTickStage string `json:"last_tick_stage,omitempty"`

	Cookies        map[string]CookieState `json:"cookies,omitempty"`
	EarliestExpiry *time.Time             `json:"earliest_expiry,omitempty"`
	DrivingCookie  string                 `json:"driving_cookie,omitempty"`
	DrivingExpiry  *time.Time             `json:"driving_expiry,omitempty"`
	CookiesSHA256  string                 `json:"cookies_sha256,omitempty"`
	NextCheckAt    *time.Time             `json:"next_check_at,omitempty"`

	// LoginActive marks a screencast login in progress for this
	// profile; the keeper pauses while it is set. LoginSessionID
	// is the login session's opaque id (not a secret).
	// LoginStartedAt bounds the pause: a flag older than
	// LoginFlagStaleAfter is recovered by the next tick (the
	// login process is assumed dead) instead of pausing the
	// keeper forever.
	LoginActive    bool       `json:"login_active,omitempty"`
	LoginSessionID string     `json:"login_session_id,omitempty"`
	LoginStartedAt *time.Time `json:"login_started_at,omitempty"`
	// Login provenance, written ONLY by the login flow from
	// the browser's own values. Attach exports never write
	// these: nothing is invented for them.
	LoginUserAgent       string     `json:"login_user_agent,omitempty"`
	LoginChromiumVersion string     `json:"login_chromium_version,omitempty"`
	LoginAt              *time.Time `json:"login_at,omitempty"`

	// Warn markers for the durable warn-once dedup: at most one
	// notice per false->true logged_out transition.
	// At-least-once across crashes (loop-2 red-team N18,
	// documented): a crash between a successful send and the
	// marker-clear may re-send once; no exactly-once
	// mechanism is claimed.
	WarnKind    string     `json:"warn_kind,omitempty"`
	WarnPending bool       `json:"warn_pending,omitempty"`
	WarnSent    bool       `json:"warn_sent,omitempty"`
	WarnedAt    *time.Time `json:"warned_at,omitempty"`
}

// NewSessionState returns a fresh v1 state.
func NewSessionState() *SessionState {
	return &SessionState{Version: StateVersion, LastTickOutcome: OutcomeNever, Cookies: map[string]CookieState{}}
}

// StatePath returns the state file path for a profile directory.
func StatePath(profileDir string) string {
	return filepath.Join(profileDir, StateFileName)
}

// LoadState reads the state file. A missing file is a fresh
// state, not an error. A present file with an unknown version,
// or unparseable JSON, is an ErrStateCorrupt error: callers
// that can recover (the tick, the login/import reset, status)
// substitute a fresh state and record the corruption; nothing
// silently overwrites state it cannot understand without
// saying so. Unknown fields are ignored.
func LoadState(profileDir string) (*SessionState, error) {
	data, err := os.ReadFile(StatePath(profileDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewSessionState(), nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return NewSessionState(), nil
	}
	var st SessionState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateCorrupt, err)
	}
	if st.Version != StateVersion {
		return nil, fmt.Errorf("%w: version %d is not supported (want %d)", ErrStateCorrupt, st.Version, StateVersion)
	}
	if st.Cookies == nil {
		st.Cookies = map[string]CookieState{}
	}
	if st.LastTickOutcome == "" {
		st.LastTickOutcome = OutcomeNever
	}
	return &st, nil
}

// ErrStateCorrupt marks a state file that is present but
// unreadable (corrupt JSON or an unknown schema version).
// IsStateCorrupt distinguishes it from I/O errors: a corrupt
// state file is recoverable observed state, a missing
// profile directory is not.
var ErrStateCorrupt = errors.New("session state corrupt")

// ErrStateDir marks a failure to create the profile state
// directory. Unlike a corrupt state file it is not recoverable
// by substituting a fresh state: without the directory no
// state can be written at all, so the tick fails loudly
// (OutcomeError) instead of reporting "skipped". The wrapped
// error names the directory and the underlying cause; it
// never carries secret material.
var ErrStateDir = errors.New("cannot create state directory")

// IsStateDirError reports whether err is (or wraps)
// ErrStateDir.
func IsStateDirError(err error) bool {
	return errors.Is(err, ErrStateDir)
}

// IsStateCorrupt reports whether err is (or wraps)
// ErrStateCorrupt.
func IsStateCorrupt(err error) bool {
	return errors.Is(err, ErrStateCorrupt)
}

// SaveState writes the state atomically (temp file + rename in
// the same directory), mode 0600. Callers hold the cookies-file
// lock for the whole read-modify-write window; SaveState itself
// takes no lock. The write is byte-stable for equal content:
// the JSON encoder writes keys in struct order with no map
// iteration (Cookies is a map — Go's encoder sorts map keys).
func SaveState(profileDir string, st *SessionState) error {
	if st == nil {
		return fmt.Errorf("cannot save a nil session state")
	}
	st.Version = StateVersion
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := StatePath(profileDir)
	tmp, err := os.CreateTemp(profileDir, ".session-state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	// Sync before rename, like the cookie writer: a crash
	// between write and rename must not leave a torn state
	// file behind (loop-2 red-team N8).
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}

// SHA256Hex returns the hex SHA-256 of data, for the
// CookiesSHA256 state field. It is a change-detection fingerprint
// of secret material: record it, never log it.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// RefreshCookieRecords rebuilds the state's per-cookie records
// from the merged set: names and expiry dates only, last_seen =
// now for every cookie present. Cookies absent from the set are
// dropped from the map.
func (st *SessionState) RefreshCookieRecords(cookies []StoredCookie, now time.Time) {
	st.Cookies = make(map[string]CookieState, len(cookies))
	for _, c := range cookies {
		rec := CookieState{Session: c.Session(), LastSeen: now}
		if !c.Session() {
			exp := time.Unix(c.Expires, 0).UTC()
			rec.ExpiresAt = &exp
		}
		st.Cookies[c.Name] = rec
	}
	st.EarliestExpiry = EarliestExpiry(cookies)
	name, exp := DrivingCookie(cookies)
	st.DrivingCookie = name
	st.DrivingExpiry = exp
}
