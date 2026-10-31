// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeClock: Now is fixed; After fires immediately (backoff
// sleeps and run waits complete at once). Tests that need
// waiting behaviour use the real clock with short durations.
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	ch <- c.now.Add(d)
	return ch
}

func TestStateSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	st := NewSessionState()
	st.LoggedOut = true
	st.KeeperStopped = true
	st.KeeperStoppedReason = StoppedAuthError
	st.LastCheckedAt = &now
	st.LastTickOutcome = OutcomeAuthError
	st.Cookies = map[string]CookieState{
		"hatch_sess": {ExpiresAt: &now, Session: false, LastSeen: now},
	}
	st.EarliestExpiry = &now
	st.DrivingCookie = "hatch_sess"
	st.DrivingExpiry = &now
	st.CookiesSHA256 = "deadbeef"
	st.WarnPending = true
	st.WarnKind = string(NoticeLoggedOut)
	if err := SaveState(dir, st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	path := StatePath(dir)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o; want 600", info.Mode().Perm())
	}
	loaded, err := LoadState(dir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !loaded.LoggedOut || loaded.KeeperStoppedReason != StoppedAuthError ||
		loaded.DrivingCookie != "hatch_sess" || !loaded.WarnPending ||
		loaded.Cookies["hatch_sess"].ExpiresAt == nil {
		t.Fatalf("loaded state = %+v", loaded)
	}
	// No cookie VALUE may appear in the state file: only names
	// and dates. (The value is never stored; assert the
	// negative with a marker that would appear if it were.)
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "deadbeef") {
		// The SHA is a fingerprint, not a value: it IS stored
		// by design. This assertion documents that the only
		// hash-like content is the named field.
		if !strings.Contains(string(raw), `"cookies_sha256": "deadbeef"`) {
			t.Fatalf("sha appears outside its field:\n%s", raw)
		}
	}
}

func TestStateLoadErrors(t *testing.T) {
	dir := t.TempDir()
	// Missing file: fresh state.
	st, err := LoadState(dir)
	if err != nil || st.Version != StateVersion || st.LastTickOutcome != OutcomeNever {
		t.Fatalf("missing state: %+v, %v", st, err)
	}
	// Corrupt JSON: error, never a guessed state. The error
	// is ErrStateCorrupt, so recoverable callers can tell it
	// from an I/O error (loop-2 red-team F6).
	if err := os.WriteFile(StatePath(dir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err == nil || !IsStateCorrupt(err) {
		t.Fatalf("corrupt state err = %v; want ErrStateCorrupt", err)
	}
	// Unknown version: refuse, same sentinel.
	if err := os.WriteFile(StatePath(dir), []byte(`{"version": 99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err == nil || !IsStateCorrupt(err) {
		t.Fatalf("unknown version err = %v; want ErrStateCorrupt", err)
	}
	// Unknown fields are ignored (forward tolerance).
	if err := os.WriteFile(StatePath(dir), []byte(`{"version": 1, "future_field": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err != nil {
		t.Fatalf("unknown field rejected: %v", err)
	}
}

func TestRefreshCookieRecordsHasNoValues(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	st := NewSessionState()
	st.RefreshCookieRecords([]StoredCookie{
		{Name: "hatch_sess", Value: "MARKER-SECRET-VALUE", Domain: ".muse.ai", Path: "/", Expires: now.Add(time.Hour).Unix()},
		{Name: "sess", Value: "MARKER-SECRET-2", Domain: "muse.ai", Path: "/"},
	}, now)
	dir := t.TempDir()
	if err := SaveState(dir, st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, StateFileName))
	if strings.Contains(string(raw), "MARKER-SECRET") {
		t.Fatalf("state file contains a cookie value:\n%s", raw)
	}
	if st.Cookies["sess"].Session != true || st.Cookies["hatch_sess"].ExpiresAt == nil {
		t.Fatalf("records = %+v", st.Cookies)
	}
}

func TestBackoffLadder(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	// Deterministic jitter: 0.0 -> -20%, 0.5 -> exact, 1.0 -> +20%.
	seq := []float64{0.0, 0.5, 0.99}
	i := 0
	jitter := func() float64 { v := seq[i%len(seq)]; i++; return v }
	b := NewBackoff(clock, jitter)
	bases := []time.Duration{5 * time.Minute, 15 * time.Minute, 45 * time.Minute}
	for k, base := range bases {
		d, ok := b.NextDelay()
		if !ok {
			t.Fatalf("delay %d exhausted early", k)
		}
		lo := time.Duration(float64(base) * 0.8)
		hi := time.Duration(float64(base) * 1.2)
		if d < lo || d > hi {
			t.Fatalf("delay %d = %v; want within [%v, %v]", k, d, lo, hi)
		}
	}
	if _, ok := b.NextDelay(); ok {
		t.Fatal("4th retry delay granted; want ladder exhausted at 3")
	}
	if b.Attempts() != 3 {
		t.Fatalf("attempts = %d; want 3", b.Attempts())
	}
	// Zero jitter source means exact bases (jitter 0.5).
	b2 := NewBackoff(clock, func() float64 { return 0.5 })
	d, _ := b2.NextDelay()
	if d != 5*time.Minute {
		t.Fatalf("exact delay = %v; want 5m", d)
	}
}

func TestNextDelayAfter(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	base := 24 * time.Hour
	if got := NextDelayAfter(base, nil, now); got != base {
		t.Fatalf("no driving expiry: %v; want %v", got, base)
	}
	// Driving expiry in 12h: remaining/4 = 3h < base.
	exp := now.Add(12 * time.Hour)
	if got := NextDelayAfter(base, &exp, now); got != 3*time.Hour {
		t.Fatalf("12h driving: %v; want 3h", got)
	}
	// Driving expiry in 30d: remaining/4 = 7.5d clamps to 7d,
	// then min with base 24h wins.
	exp = now.Add(30 * 24 * time.Hour)
	if got := NextDelayAfter(base, &exp, now); got != base {
		t.Fatalf("30d driving: %v; want %v", got, base)
	}
	// Driving expiry in 2h: remaining/4 = 30m floors at 1h.
	exp = now.Add(2 * time.Hour)
	if got := NextDelayAfter(base, &exp, now); got != time.Hour {
		t.Fatalf("2h driving: %v; want 1h", got)
	}
	// Past expiry: floor at 1h, never a spin.
	exp = now.Add(-time.Hour)
	if got := NextDelayAfter(base, &exp, now); got != time.Hour {
		t.Fatalf("past driving: %v; want 1h", got)
	}
}

func TestNoticeTextHasNoSecrets(t *testing.T) {
	for _, kind := range []NoticeKind{NoticeLoggedOut, NoticeReexported, NoticeFailed} {
		text := NoticeText(kind, "muse01")
		if !strings.Contains(text, "muse01") || !strings.Contains(text, "No action was taken automatically.") {
			t.Fatalf("notice %q: %q", kind, text)
		}
		if strings.Contains(text, "http") {
			t.Fatalf("notice %q contains a URL: %q", kind, text)
		}
	}
}
