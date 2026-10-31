// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"context"
	"errors"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Launch types shared by both builds: the fail-closed refusal
// and the inbound-builder interface the S2 work will
// implement. The runners themselves are tag-gated.

// ErrLaunchUnavailable is the fail-closed launch refusal: no
// inbound builder, no browser spawn, no direct egress.
var ErrLaunchUnavailable = errors.New("launch fallback unavailable: no profile-inbound plumbing at this base (S2 gate); attach to an already-running Chrome via the keeper browser URL, or use auth import")

// InboundBuilder builds the profile-routed inbound a launched
// browser must proxy through. It returns the proxy URL for
// --proxy-server and a cleanup for everything it started.
// The S2 work supplies the production implementation; until
// then the command layer passes nil and launches fail closed.
type InboundBuilder interface {
	BuildInbound(ctx context.Context, prof *profile.Profile) (proxyURL string, cleanup func(), err error)
}
