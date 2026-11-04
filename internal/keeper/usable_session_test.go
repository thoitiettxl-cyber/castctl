// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import "testing"

// A set holding hatch_sess only outside the filtered domains
// (muse.ai, auth.muse.ai) is not a usable session: the gate in
// validateExportedSet ignores non-filtered cookies, so it must
// find no filtered hatch_sess and reject the set.
func TestUsableSessionRejectsOutsideFilteredDomainOnlySet(t *testing.T) {
	cookies := []ExportedCookie{
		{Name: "hatch_sess", Value: "FAKE-OUTSIDE-SESS", Domain: "example.com", Path: "/", Session: true},
	}
	if usableSession(cookies) {
		t.Fatalf("usableSession(...) = true; want false for a set holding hatch_sess only outside the filtered domains")
	}
}
