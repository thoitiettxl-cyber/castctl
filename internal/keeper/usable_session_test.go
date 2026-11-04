// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import "testing"

// TestUsableSessionOutsideFilteredDomainOnly pins the gate in
// usableSession: a set holding only cookies outside the filtered
// domains (muse.ai, auth.muse.ai, and their subdomains) must
// return false, even when it holds a non-empty hatch_sess with
// a future expiry on an outside domain. Only a hatch_sess on a
// filtered domain counts; cookies outside the filter never
// gate the set.
func TestUsableSessionOutsideFilteredDomainOnly(t *testing.T) {
	cookies := []ExportedCookie{
		{
			Name:     "hatch_sess",
			Value:    "FAKE-OUTSIDE-SESS",
			Domain:   "example.com",
			Path:     "/",
			Expires:  2051222400,
			Secure:   true,
			HTTPOnly: true,
		},
		{
			Name:    "other",
			Value:   "FAKE-OUTSIDE-OTHER",
			Domain:  ".example.org",
			Path:    "/",
			Expires: 2051222400,
		},
	}
	if usableSession(cookies) {
		t.Fatalf("usableSession(...) = true; want false for a set holding only cookies outside the filtered domains")
	}
}
