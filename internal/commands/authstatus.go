// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/keeper"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// `castctl auth status`: the state-only, no-network session
// report. It reads only each profile's cookies file (expiry
// metadata: names and dates, never values) and its keeper
// state file. It performs no network I/O, contacts no
// browser, and never prints a cookie value: the driving
// cookie appears by NAME only. The `liveness_checked` output
// field is always false: nothing in the report says whether
// the session is alive.
//
// Output: one JSON object for a single profile, a JSON array
// for --all. Exit codes: 0 ok, 1 expiring, 2 config error,
// 3 expired. With --all the worst status wins (expired >
// expiring > ok). --profile and --all are mutually exclusive;
// with neither, the active profile is reported.

const authStatusHelpText = `usage: castctl auth status [--profile NAME | --all]

Show the session status for a profile from state files only:
no network, no browser contact. The status is ok, expiring
(the driving cookie expires within the keeper entry's
expiring_within window, default 72h), or expired (the
driving expiry is past, or the keeper stopped the entry for
a dead session).

Prints one JSON object (or a JSON array with --all) with:
profile, status, liveness_checked, driving_cookie (name only),
driving_expiry, last_checked_at, keeper_stopped,
keeper_stopped_reason, headless_available, headless_reason,
needs_action.

The report never verifies the session is alive: a revoked
cookie still reports expiring until its expiry passes or the
keeper stops the entry, so liveness_checked is always false.
Use "keeper check" for a live verdict.

headless_reason is "" when headless re-login is available,
or one of: no_keeper_entry, no_chromedp, no_credentials,
no_contract (the login-form contract is not yet established).

Exit codes: 0 ok, 1 expiring, 2 config error, 3 expired.
`

type authStatusJSON struct {
	Profile             string     `json:"profile"`
	Status              string     `json:"status"`
	LivenessChecked     bool       `json:"liveness_checked"`
	DrivingCookie       string     `json:"driving_cookie,omitempty"`
	DrivingExpiry       *time.Time `json:"driving_expiry,omitempty"`
	LastCheckedAt       *time.Time `json:"last_checked_at,omitempty"`
	KeeperStopped       bool       `json:"keeper_stopped"`
	KeeperStoppedReason string     `json:"keeper_stopped_reason,omitempty"`
	HeadlessAvailable   bool       `json:"headless_available"`
	HeadlessReason      string     `json:"headless_reason,omitempty"`
	NeedsAction         bool       `json:"needs_action"`
	CookiesSeen         int        `json:"cookies_seen"`
}

func cmdAuthStatus(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	ap := &argParser{defs: []flagDef{{name: "profile", kind: flagString}, {name: "all", kind: flagBool}}, helpText: authStatusHelpText, prog: "castctl auth status"}
	p, helpShown, err := ap.parse(args, env.stdout())
	if err != nil {
		if pe, ok := err.(*parserError); ok {
			fmt.Fprintf(env.stderr(), "castctl: %s\n", pe.msg)
			return errCode(2, pe)
		}
		return err
	}
	if helpShown {
		return errHelpShown
	}
	if err := checkPositionals(p, nil, "auth status"); err != nil {
		return usageErr(err)
	}
	all := p.bool("all")
	profileName := ""
	if p.strIsSet("profile") {
		profileName = p.str("profile")
	}
	if all && profileName != "" {
		return errCodef(2, "auth status: --profile and --all are mutually exclusive")
	}
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
	if err != nil {
		return err
	}
	if !found {
		return errCodef(2, "auth status: no config.json found")
	}
	kcfg, err := profile.ResolveKeeper(single)
	if err != nil {
		return err
	}
	creds, err := profile.ResolveCredentials(single)
	if err != nil {
		return err
	}
	var names []string
	switch {
	case all:
		names = single.ProfileNames()
		if len(names) == 0 {
			return errCodef(2, "auth status: no profiles configured")
		}
	case profileName != "":
		if _, ok := single.Profiles[profileName]; !ok {
			return errCodef(2, "auth status: profile %q does not exist", profileName)
		}
		names = []string{profileName}
	default:
		active, err := resolveActive(loc, g, env)
		if err != nil {
			return err
		}
		names = []string{active.Name}
	}
	now := time.Now()
	worst := 0
	out := make([]authStatusJSON, 0, len(names))
	for _, name := range names {
		prof := single.Profiles[name]
		st, err := authStatusForProfile(loc.ConfigDir, name, prof, kcfg, creds, now)
		if err != nil {
			return err
		}
		out = append(out, st)
		switch st.Status {
		case string(keeper.AuthStatusExpired):
			worst = 3
		case string(keeper.AuthStatusExpiring):
			if worst < 1 {
				worst = 1
			}
		}
	}
	if len(out) == 1 {
		if err := writeJSON(env.stdout(), out[0]); err != nil {
			return err
		}
	} else {
		if err := writeJSON(env.stdout(), out); err != nil {
			return err
		}
	}
	switch worst {
	case 3:
		return errCode(3, errors.New("auth status: session expired"))
	case 1:
		return errCode(1, errors.New("auth status: session expiring"))
	default:
		return nil
	}
}

// authStatusForProfile derives one profile's state-only
// report. A corrupt state file is treated as no state (the
// cookies file still decides); any other state read error
// fails the command. An unreadable cookies file is a config
// error naming the profile only, never file bytes.
func authStatusForProfile(baseDir, name string, prof *profile.Profile, kcfg *profile.KeeperConfig, creds *profile.CredentialsConfig, now time.Time) (authStatusJSON, error) {
	var entry *profile.KeeperEntry
	if kcfg != nil {
		entry = kcfg.KeeperEntryForProfile(name)
	}
	paths, err := profile.ProfilePaths(baseDir, name)
	if err != nil {
		return authStatusJSON{}, err
	}
	st, err := keeper.LoadState(paths.Dir)
	if err != nil {
		if keeper.IsStateCorrupt(err) {
			st = keeper.NewSessionState()
		} else {
			return authStatusJSON{}, err
		}
	}
	cookiesPath := prof.CookiesFile
	if cookiesPath == "" {
		cookiesPath = paths.Cookies
	}
	drivingName, drivingExpiry, seen, fileMissing, err := keeper.CookieExpiryMetadata(cookiesPath, now)
	if err != nil {
		return authStatusJSON{}, errCodef(2, "auth status: profile %q cookies file is unreadable", name)
	}
	expiringWithin := profile.DefaultExpiringWithin
	if entry != nil {
		expiringWithin = entry.EffectiveExpiringWithin()
	}
	headlessAvailable, headlessReason := authHeadlessCapability(entry, creds, name)
	derived := keeper.DeriveAuthStatus(name, drivingName, drivingExpiry, seen, fileMissing, st, expiringWithin, headlessAvailable, headlessReason, now)
	// LivenessChecked is always false: this command performs no
	// live check, so the status is expiry metadata only and says
	// nothing about whether the session is alive.
	return authStatusJSON{
		Profile:             derived.Profile,
		Status:              string(derived.Status),
		LivenessChecked:     false,
		DrivingCookie:       derived.DrivingCookie,
		DrivingExpiry:       derived.DrivingExpiry,
		LastCheckedAt:       derived.LastCheckedAt,
		KeeperStopped:       derived.KeeperStopped,
		KeeperStoppedReason: derived.KeeperStoppedReason,
		HeadlessAvailable:   derived.HeadlessAvailable,
		HeadlessReason:      derived.HeadlessReason,
		NeedsAction:         derived.NeedsAction,
		CookiesSeen:         derived.CookiesSeen,
	}, nil
}

// authHeadlessCapability reports whether headless re-login
// could run for this profile, with a closed-enum reason. The
// gates, in order: a keeper entry must exist (re-login only
// runs from a tick), this build must have the driver, the
// versioned login-form contract must be established (an
// unobserved contract makes the driver refuse, so the
// report must say so), the keeper entry must reference
// credentials, and stored credentials must exist for the
// profile. The contract gate precedes the credentials gates:
// with the fixture unobserved, the reason is no_contract
// even when credentials are also missing. No network is
// involved: a build without the driver reports no_chromedp
// even though the binary runs. Presence is checked without
// materialising a credential value.
func authHeadlessCapability(entry *profile.KeeperEntry, creds *profile.CredentialsConfig, profileName string) (bool, string) {
	hasCreds := creds != nil && creds.HasCredentialForProfile(profileName)
	hasRef := entry != nil && entry.Credentials != ""
	contract, err := keeper.DefaultLoginContract()
	observed := err == nil && contract.Observed
	return headlessCapability(entry != nil, keeper.ReloginAvailable(), hasCreds, observed, hasRef)
}

// headlessCapability is the pure gate order behind
// authHeadlessCapability, unit-testable for every branch
// (including the observed-contract case, which the embedded
// fixture cannot express while it stays unobserved).
func headlessCapability(hasEntry, driverAvailable, hasCredentials, contractObserved, hasCredentialsRef bool) (bool, string) {
	if !hasEntry {
		return false, "no_keeper_entry"
	}
	if !driverAvailable {
		return false, "no_chromedp"
	}
	if !contractObserved {
		return false, "no_contract"
	}
	if !hasCredentialsRef {
		return false, "no_credentials_ref"
	}
	if !hasCredentials {
		return false, "no_credentials"
	}
	return true, ""
}
