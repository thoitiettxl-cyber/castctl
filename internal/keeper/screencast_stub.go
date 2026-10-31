// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build !with_chromedp

package keeper

import (
	"context"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Tag-off screencast/launch runners: login is unavailable in
// this build. Both constructors return runners that refuse
// with the typed unavailable outcome; nothing is dialled, no
// browser is spawned. This file imports NO chromedp.

type refusingRunner struct{ err error }

func (r refusingRunner) Run(_ context.Context, _ Transport) RunnerResult {
	return RunnerResult{Outcome: LoginFailed, Err: r.err}
}

// NewAttachRunner returns a runner that refuses: screencast
// login needs -tags with_chromedp.
func NewAttachRunner(_ string) ScreencastRunner {
	return refusingRunner{err: ErrReexportUnavailable}
}

// NewLaunchRunner returns a runner that refuses: screencast
// login needs -tags with_chromedp (and, even tagged, the
// launch fallback needs the S2 inbound plumbing).
func NewLaunchRunner(_ string, _ *profile.Profile, _ string, _ InboundBuilder) ScreencastRunner {
	return refusingRunner{err: ErrReexportUnavailable}
}
