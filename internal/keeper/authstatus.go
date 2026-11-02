// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"os"
	"time"
)

// Auth status: the state-only, no-network report behind
// `castctl auth status`. It reads only the profile's cookies
// file (expiry metadata: names and dates, never values) and
// its keeper state file. It performs no network I/O, contacts
// no browser, and never prints a cookie name beyond the
// driving cookie's NAME (which names the expiry that drives
// the status, not a value).

// AuthStatusValue is the closed status enum for one profile.
type AuthStatusValue string

const (
	// AuthStatusOK: the driving cookie is not expiring
	// within the entry's window, or no expiry metadata
	// exists to judge by (non-jar file with no keeper
	// state, session-only cookies).
	AuthStatusOK AuthStatusValue = "ok"
	// AuthStatusExpiring: the driving expiry falls within
	// the entry's expiring_within window.
	AuthStatusExpiring AuthStatusValue = "expiring"
	// AuthStatusExpired: the driving expiry is past, or the
	// keeper stopped the entry for a dead session.
	AuthStatusExpired AuthStatusValue = "expired"
)

// AuthStatus is one profile's state-only auth report.
type AuthStatus struct {
	Profile             string
	Status              AuthStatusValue
	DrivingCookie       string     // NAME only, "" when unknown.
	DrivingExpiry       *time.Time // nil when no dated cookie exists.
	LastCheckedAt       *time.Time
	KeeperStopped       bool
	KeeperStoppedReason string
	HeadlessAvailable   bool
	HeadlessReason      string // closed enum: "", "no_chromedp", "no_credentials", "no_credentials_ref", "no_keeper_entry", "no_contract"
	NeedsAction         bool
	CookiesSeen         int
}

// CookieExpiryMetadata reads a cookies file and returns its
// driving cookie (name only), driving expiry, cookie count,
// and whether the file is missing. A missing file returns
// missing=true and no error: absence is itself the report
// (expired — there is nothing to authenticate with). A
// corrupt file returns an error naming the file only, never
// its bytes.
func CookieExpiryMetadata(cookiesPath string, now time.Time) (drivingName string, drivingExpiry *time.Time, count int, missing bool, err error) {
	raw, rerr := os.ReadFile(cookiesPath)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return "", nil, 0, true, nil
		}
		return "", nil, 0, false, rerr
	}
	cookies, _, cerr := classifyCookiesFile(raw, cookiesPath)
	if cerr != nil {
		return "", nil, 0, false, cerr
	}
	name, exp := DrivingCookie(cookies)
	return name, exp, len(cookies), false, nil
}

// DeriveAuthStatus combines cookies-file expiry metadata
// with keeper state into one AuthStatus. expiringWithin is
// the entry's window (DefaultExpiringWithin when the entry
// is absent). A stopped entry whose reason names a dead
// session (auth_error, cookies_missing) is expired
// regardless of the file's dates: the keeper already proved
// the session dead. headlessAvailable/headlessReason are
// computed by the caller (build capability + credentials
// presence + contract establishment) and carried through
// verbatim; they do not by themselves set NeedsAction (an
// unavailable re-login is not "needs action" while the
// session is ok).
func DeriveAuthStatus(profileName string, drivingName string, drivingExpiry *time.Time, cookiesSeen int, fileMissing bool, st *SessionState, expiringWithin time.Duration, headlessAvailable bool, headlessReason string, now time.Time) AuthStatus {
	out := AuthStatus{
		Profile:           profileName,
		Status:            AuthStatusOK,
		DrivingCookie:     drivingName,
		DrivingExpiry:     drivingExpiry,
		HeadlessAvailable: headlessAvailable,
		HeadlessReason:    headlessReason,
		CookiesSeen:       cookiesSeen,
	}
	if st != nil {
		out.LastCheckedAt = st.LastCheckedAt
		out.KeeperStopped = st.KeeperStopped
		out.KeeperStoppedReason = st.KeeperStoppedReason
	}
	// A missing cookies file is expired outright: there is
	// nothing to authenticate with, whatever the state file
	// last recorded. The keeper-stop fields above are still
	// carried through: the stop is the likeliest explanation
	// for the missing file, and hiding it would hide the
	// diagnosis.
	if fileMissing {
		out.Status = AuthStatusExpired
		out.NeedsAction = true
		return out
	}
	if st != nil {
		if st.KeeperStopped && (st.KeeperStoppedReason == StoppedAuthError || st.KeeperStoppedReason == StoppedCookiesMissing) {
			out.Status = AuthStatusExpired
			out.NeedsAction = true
			return out
		}
		// State expiry metadata wins when the file has
		// none (e.g. the file was replaced since the
		// last tick): prefer the state's driving record.
		if drivingExpiry == nil && st.DrivingExpiry != nil {
			out.DrivingCookie = st.DrivingCookie
			out.DrivingExpiry = st.DrivingExpiry
		}
	}
	switch {
	case out.DrivingExpiry == nil:
		out.Status = AuthStatusOK
	case !out.DrivingExpiry.After(now):
		out.Status = AuthStatusExpired
		out.NeedsAction = true
	case out.DrivingExpiry.Sub(now) <= expiringWithin:
		out.Status = AuthStatusExpiring
		out.NeedsAction = true
	default:
		out.Status = AuthStatusOK
	}
	return out
}
