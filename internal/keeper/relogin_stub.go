// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build !with_chromedp

package keeper

import (
	"context"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Tag-off headless re-login: the keeper detects and reports
// expiry, but cannot re-log in. This file imports NO chromedp:
// the default binary stays chromedp-free, and the release
// build (which omits with_chromedp) reports re-login as
// unavailable instead of failing silently.

// NewReloginDriver returns a driver that always reports
// re-login unavailable in this build.
func NewReloginDriver(_ ReloginOptions) ReloginDriver {
	return stubReloginDriver{}
}

type stubReloginDriver struct{}

func (stubReloginDriver) Relogin(_ context.Context, _ profile.LoginCredential) ([]ExportedCookie, error) {
	return nil, ErrReloginUnavailable
}

// ReloginAvailable reports whether this build has a headless
// re-login driver. Tag-off: never.
func ReloginAvailable() bool { return false }

// ObserveLoginPage is unavailable without the chromedp build.
func ObserveLoginPage(_ context.Context, _ ObserveOptions) (LoginPageObservation, error) {
	return LoginPageObservation{}, ErrReloginUnavailable
}
