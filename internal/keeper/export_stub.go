// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build !with_chromedp

package keeper

import "context"

// Tag-off CDP export: the keeper detects and reports expiry, but
// cannot re-export. This file imports NO chromedp: the default
// binary stays chromedp-free (proven by `go list` in the final
// matrix). Rebuild with -tags with_chromedp for the real
// exporter in export_cdp.go.

// CDPAvailable reports whether this build can re-export cookies
// from a browser over CDP.
func CDPAvailable() bool { return false }

type stubExporter struct{ browserURL string }

// NewCDPExporter returns an exporter that always reports
// re-export unavailable. The browser URL is accepted for API
// symmetry and never used, never dialled.
func NewCDPExporter(browserURL string) Exporter { return stubExporter{browserURL: browserURL} }

// Export implements Exporter: always the typed unavailable
// outcome, so the tick stops the entry (reported) instead of
// retrying a recovery this build cannot perform.
func (stubExporter) Export(_ context.Context) ([]ExportedCookie, error) {
	return nil, ErrReexportUnavailable
}
