// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Headless re-login: the keeper-internal driver seam.
//
// The driver submits stored credentials to the provider login
// form in a headless browser, through the profile's outbound,
// and returns the harvested session cookies. It is a keeper
// seam, not a plugin API: the credential value reaches the
// driver only through TickDeps.CredentialProvider, the driver
// holds it only for the attempt (and clears its copy after
// use — see LoginCredential.Clear), and the value-carrying
// LoginCredential type is keeper-internal: it is never
// marshalled, never logged, and never handed to a plugin.
//
// The real driver lives behind the with_chromedp build tag
// (relogin_chromedp.go); the tag-off stub (relogin_stub.go)
// returns ErrReloginUnavailable. A build without the driver
// can never re-log in: the tick stops and alerts instead of
// retrying forever.

// ErrReloginUnavailable is returned when this build has no
// headless re-login driver (the with_chromedp tag was not
// set). The release build omits with_chromedp (see
// .github/workflows/release.yaml), so shipped binaries report
// re-login as unavailable and `auth status` says so.
var ErrReloginUnavailable = errors.New("headless re-login unavailable in this build (rebuild with -tags with_chromedp)")

// ReloginBlocker is the stop-and-alert error for a login page
// that must never be bypassed: captcha, second factor,
// checkpoint, account lock, or a page that does not match the
// recorded login-form contract. Kind is a closed NoticeKind;
// Detail is a fixed enum string (never page text, never a
// value). The tick maps Kind to the notice and stops the
// entry; it never retries a blocker.
type ReloginBlocker struct {
	Kind   NoticeKind
	Detail string
}

func (e *ReloginBlocker) Error() string {
	if e == nil {
		return "re-login blocked"
	}
	return fmt.Sprintf("re-login blocked: %s", e.Kind)
}

// ReloginDriver submits cred to the provider login form and
// returns the harvested session cookies in export form (the
// same shape as the CDP exporter: values are SECRET MATERIAL).
// It must:
//
//   - attach to the already-running Chrome first, and only
//     launch headless through the S2 profile-routed inbound
//     when no attachable browser exists;
//   - match the page against the versioned LoginContract
//     BEFORE entering anything, and stop with a
//     *ReloginBlocker on any mismatch or blocker signal;
//   - never enter a credential, submit, or navigate past a
//     captcha, second-factor, checkpoint, or lock signal;
//   - honour ctx cancellation and the per-incident attempt
//     cap it was constructed with (one Relogin call is one
//     incident: the tick never calls it twice per tick).
//
// A non-blocker error means the attempt failed without a
// proven blocker (launch failure, navigation failure,
// attempts exhausted): the tick stops with the
// relogin_failed notice. ErrReloginUnavailable means this
// build has no driver.
type ReloginDriver interface {
	Relogin(ctx context.Context, cred profile.LoginCredential) ([]ExportedCookie, error)
}

// ReloginDriverFunc adapts a function to a ReloginDriver
// (tests and the command-layer wiring).
type ReloginDriverFunc func(ctx context.Context, cred profile.LoginCredential) ([]ExportedCookie, error)

func (f ReloginDriverFunc) Relogin(ctx context.Context, cred profile.LoginCredential) ([]ExportedCookie, error) {
	return f(ctx, cred)
}

// ReloginOptions wires one headless re-login driver: the
// attach-first browser URL ("" when the entry has none), the
// S2 inbound builder that routes a launched browser through
// the profile's outbound, the profile, the recorded
// login-form contract, and the per-incident attempt cap.
// Entry, when non-nil, is the keeper entry whose
// Effective* timeouts tune the driver (match/cookie waits,
// poll cadence, attach/cancel bounds, observation settle
// and inventory cap); a nil entry means the documented
// defaults. The Chrome binary path is resolved inside the
// driver by resolveBrowserPath (--browser-path >
// CASTCTL_CHROMIUM_PATH > PATH search); there is no option
// for it because the driver never invents a browser location.
type ReloginOptions struct {
	BrowserURL  string
	BaseDir     string
	Inbound     InboundBuilder
	Profile     *profile.Profile
	Contract    LoginContract
	MaxAttempts int
	Entry       *profile.KeeperEntry
}

// ReloginAvailable reports whether this build has a headless
// re-login driver. Defined per build tag: the stub file
// returns false, the chromedp file returns true.

// ObservedElement is one redacted form-control element from a
// read-only login-page observation: tag, type, name, id, and
// class list only. No value, placeholder, label text, href,
// or page text is ever recorded: the observation proves the
// form's STRUCTURE, and selectors are derived from it.
type ObservedElement struct {
	Tag          string   `json:"tag"`
	Type         string   `json:"type,omitempty"`
	Name         string   `json:"name,omitempty"`
	ID           string   `json:"id,omitempty"`
	Classes      []string `json:"classes,omitempty"`
	HasAriaLabel bool     `json:"has_aria_label,omitempty"`
}

// LoginPageObservation is the redacted result of one
// automated, read-only load of the login page: the final URL
// (after redirects, query, fragment, and userinfo stripped
// — auth redirects routinely carry codes/tokens there) and
// the form-control inventory. It is the input the fixture
// author encodes into the versioned LoginContract; it is
// never used at re-login runtime.
type LoginPageObservation struct {
	URL      string            `json:"url"`
	Elements []ObservedElement `json:"elements"`
}

// StripObservationURL strips the query string, fragment,
// and userinfo from an observed URL, keeping
// scheme/host/path only. A redirect target carrying
// ?code=… or #token=…, or a userinfo-bearing URL, must
// never reach an output that gets pasted into reports. An
// unparseable URL is dropped outright rather than echoed.
// It is exported so the observe command can strip the
// operator-supplied --login-url the same way before
// printing it: the same echo class, the same fix.
func StripObservationURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// ObserveOptions wires one read-only login-page observation:
// the attach-first browser URL, the S2 inbound builder for
// the headless launch fallback, the profile, and the login
// URL to load. No credentials are involved: the observation
// never enters or submits anything. Entry, when non-nil, is
// the keeper entry whose Effective* timeouts tune the
// observation (settle wait, whole-run bound, inventory
// cap); a nil entry means the documented defaults.
// BrowserURL is accepted for callers that attach, but the
// `auth observe-login` command never sets it: observation
// through the command always launches (launch-only in
// practice).
type ObserveOptions struct {
	BrowserURL string
	BaseDir    string
	Inbound    InboundBuilder
	Profile    *profile.Profile
	LoginURL   string
	Entry      *profile.KeeperEntry
}

// ObserveLoginPage loads the login page headless (attach
// first, launch fallback) and returns its redacted
// form-control inventory. Defined per build tag.
