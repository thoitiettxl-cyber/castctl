// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import "testing"

// TestUsableSessionOutsideFilteredDomainOnly pins the domain
// filter in usableSession: a set holding only cookies outside
// the filtered domains must not pass, even when it holds a
// non-empty hatch_sess with a future expiry — the name, value
// and expiry that would pass on a filtered domain. The
// outside domain below (example.com) is neither muse.ai nor
// auth.muse.ai nor a subdomain of either, and the future
// expiry rules out the expiry gate as the reason for false.
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
			Session:  false,
		},
	}
	if InFilteredDomain(FromExportedCookie(cookies[0])) {
		t.Fatalf("premise: example.com must be outside the filtered domains")
	}
	if usableSession(cookies) {
		t.Fatalf("usableSession(...) = true; want false for a set holding only a cookie outside the filtered domains")
	}
}
