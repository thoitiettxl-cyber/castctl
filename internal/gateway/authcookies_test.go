// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"net/http"
	"testing"
	"time"
)

// RECONSTRUCTED deletion+set pairs (K.7 probe structure, FAKE
// values): the keeper's renewal plumbing parses exactly these
// shapes with the real stdlib parser.
func TestParseSetCookieHeaderReconstructed(t *testing.T) {
	hdr := http.Header{}
	hdr.Add("Set-Cookie", "hatch_sess=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax")
	hdr.Add("Set-Cookie", "hatch_sess=FAKE-NEW-VALUE; Path=/; Max-Age=2592000; Secure; HttpOnly; SameSite=Lax")
	hdr.Add("Set-Cookie", "hatch_gw=FAKE-GW-VALUE; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax")
	hdr.Add("Set-Cookie", "not-a-cookie;;;")
	cookies, skipped := ParseSetCookieHeader(hdr)
	if skipped < 1 {
		t.Fatalf("skipped = %d; want >= 1 for the malformed value", skipped)
	}
	if len(cookies) != 3 {
		t.Fatalf("parsed %d cookies; want 3", len(cookies))
	}
	if cookies[0].Name != "hatch_sess" || cookies[0].Value != "" || cookies[0].Expires.IsZero() {
		t.Fatalf("deletion cookie = %+v", cookies[0])
	}
	if cookies[1].Name != "hatch_sess" || cookies[1].Value != "FAKE-NEW-VALUE" || cookies[1].MaxAge != 2592000 {
		t.Fatalf("renewal cookie = %+v", cookies[1])
	}
	if cookies[2].Name != "hatch_gw" || cookies[2].MaxAge != 31536000 {
		t.Fatalf("gw cookie = %+v", cookies[2])
	}
	// Max-Age is preserved as parsed: the merge computes the
	// expiry from the receipt time, not from here.
	if cookies[1].Expires.After(time.Now().Add(24 * time.Hour)) {
		t.Fatalf("ParseSetCookie synthesised an expiry from Max-Age: %+v", cookies[1])
	}
	if _, skipped := ParseSetCookieHeader(nil); skipped != 0 {
		t.Fatalf("nil header skipped = %d; want 0", skipped)
	}
}
