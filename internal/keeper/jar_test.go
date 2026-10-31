// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
)

// RECONSTRUCTED Set-Cookie fixtures: shapes rebuilt from the
// K.7 probe structure (names, Max-Age values, attributes),
// never captured bytes. Values are FAKE. Parsed with the real
// stdlib parser, exactly as the tick parses them.

const reconstructedSessionSetCookie = "hatch_sess=FAKE-SESSION-VALUE; Path=/; Max-Age=2592000; Secure; HttpOnly; SameSite=Lax"

func parseReconstructed(t *testing.T, line string) *http.Cookie {
	t.Helper()
	c, err := http.ParseSetCookie(line)
	if err != nil {
		t.Fatalf("ParseSetCookie(%q): %v", line, err)
	}
	return c
}

func TestJarRoundTripViaParseCookies(t *testing.T) {
	// Writer-produced jars must round-trip through the repo's
	// real ParseCookies (the reader every other command uses).
	cookies := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE-HATCH-VALUE", Domain: ".muse.ai", Path: "/", Secure: true, HTTPOnly: true, Expires: 1790000000},
		{Name: "hatch_gw", Value: "FAKE-GW-VALUE", Domain: ".muse.ai", Path: "/", Secure: true, Expires: 1820000000},
		{Name: "session_only", Value: "FAKE-SESSION", Domain: "muse.ai", Path: "/", Secure: true},
	}
	data, err := SerializeJar(cookies)
	if err != nil {
		t.Fatalf("SerializeJar: %v", err)
	}
	header, err := gateway.ParseCookies(string(data), "cookies.txt")
	if err != nil {
		t.Fatalf("ParseCookies(writer jar): %v", err)
	}
	for _, want := range []string{"hatch_sess=FAKE-HATCH-VALUE", "hatch_gw=FAKE-GW-VALUE", "session_only=FAKE-SESSION"} {
		if !strings.Contains(header, want) {
			t.Fatalf("header %q missing %q", header, want)
		}
	}
	parsed, err := ParseJar(data)
	if err != nil {
		t.Fatalf("ParseJar: %v", err)
	}
	if len(parsed) != len(cookies) {
		t.Fatalf("ParseJar returned %d cookies; want %d", len(parsed), len(cookies))
	}
	// Deterministic order: (domain, path, name).
	if parsed[0].Domain != ".muse.ai" || parsed[2].Domain != "muse.ai" {
		t.Fatalf("sort order wrong: %+v", parsed)
	}
}

func TestParseJarErrors(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"six fields", "a\tFALSE\t/\tFALSE\t0\tname\n"},
		{"bad secure", ".muse.ai\tTRUE\t/\tYES\t0\thatch_sess\tv\n"},
		{"bad expiry", ".muse.ai\tTRUE\t/\tTRUE\ts soon\thatch_sess\tv\n"},
		{"negative expiry", ".muse.ai\tTRUE\t/\tTRUE\t-5\thatch_sess\tv\n"},
		{"empty name", ".muse.ai\tTRUE\t/\tTRUE\t0\t\tv\n"},
		{"tab in value", ".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tva\tl\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseJar([]byte(tc.data)); err == nil {
				t.Fatalf("ParseJar(%q) succeeded; want error", tc.data)
			}
		})
	}
	// #HttpOnly_ rows are comments and are dropped, like
	// ParseCookies drops # lines. The jar never writes them.
	data := "#HttpOnly_.muse.ai\tTRUE\t/\tTRUE\t1790000000\thatch_sess\tFAKE\n.muse.ai\tTRUE\t/\tTRUE\t1790000000\tother\tFAKE2\n"
	parsed, err := ParseJar([]byte(data))
	if err != nil {
		t.Fatalf("ParseJar: %v", err)
	}
	if len(parsed) != 1 || parsed[0].Name != "other" {
		t.Fatalf("parsed = %+v; want only 'other'", parsed)
	}
	// Duplicate keys: last row wins.
	dup := ".muse.ai\tTRUE\t/\tTRUE\t1790000000\thatch_sess\tFIRST\n.muse.ai\tTRUE\t/\tTRUE\t1790000001\thatch_sess\tSECOND\n"
	parsed, err = ParseJar([]byte(dup))
	if err != nil {
		t.Fatalf("ParseJar: %v", err)
	}
	if len(parsed) != 1 || parsed[0].Value != "SECOND" || parsed[0].Expires != 1790000001 {
		t.Fatalf("duplicate merge = %+v", parsed)
	}
	// Serialize rejects tab/newline/CR in fields.
	if _, err := SerializeJar([]StoredCookie{{Name: "x", Value: "a\tb", Domain: "muse.ai", Path: "/"}}); err == nil {
		t.Fatal("SerializeJar accepted a tab in a value")
	}
	if _, err := SerializeJar([]StoredCookie{{Name: "x", Value: "a\nb", Domain: "muse.ai", Path: "/"}}); err == nil {
		t.Fatal("SerializeJar accepted a newline in a value")
	}
}

func TestEffectiveSetCookieReconstructed(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	sessionURL, _ := url.Parse(SessionCheckURL)

	// Renewal: Max-Age 30d, expiry = now + Max-Age. The real
	// Set-Cookie carries no Domain attribute (K.7 probe), so
	// the cookie is host-only: bare "muse.ai", no leading dot.
	// That is distinct from a CDP-exported domain cookie
	// ".muse.ai" by design (RFC 6265: separate cookies).
	c := parseReconstructed(t, reconstructedSessionSetCookie)
	upd := EffectiveSetCookie(c, sessionURL, now)
	if upd.Delete || upd.Cookie.Domain != "muse.ai" || upd.Cookie.Path != "/" ||
		upd.Cookie.Expires != now.Add(2592000*time.Second).Unix() || !upd.Cookie.Secure || !upd.Cookie.HTTPOnly {
		t.Fatalf("renewal update = %+v", upd)
	}

	// Max-Age beats Expires: Expires says 2030, Max-Age says 1h.
	c = parseReconstructed(t, "hatch_sess=FAKE; Path=/; Expires=Wed, 01 Jan 2030 00:00:00 GMT; Max-Age=3600; Secure")
	upd = EffectiveSetCookie(c, sessionURL, now)
	if upd.Delete || upd.Cookie.Expires != now.Add(time.Hour).Unix() {
		t.Fatalf("Max-Age precedence update = %+v", upd)
	}

	// Deletion pairs: past Expires deletes; Max-Age=0 shape
	// (empty value, no expiry) deletes.
	c = parseReconstructed(t, "hatch_sess=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly")
	upd = EffectiveSetCookie(c, sessionURL, now)
	if !upd.Delete {
		t.Fatalf("past-Expires update = %+v; want Delete", upd)
	}
	c = parseReconstructed(t, "hatch_sess=; Path=/; Max-Age=0; Secure")
	upd = EffectiveSetCookie(c, sessionURL, now)
	if !upd.Delete {
		t.Fatalf("Max-Age=0 shape update = %+v; want Delete", upd)
	}
	c = parseReconstructed(t, "hatch_sess=; Path=/; Max-Age=-1; Secure")
	upd = EffectiveSetCookie(c, sessionURL, now)
	if !upd.Delete {
		t.Fatalf("negative Max-Age update = %+v; want Delete", upd)
	}

	// Freeze (c): empty value + FUTURE expiry REPLACES, it does
	// not delete.
	c = parseReconstructed(t, "hatch_sess=; Path=/; Expires=Wed, 01 Jan 2030 00:00:00 GMT; Secure")
	upd = EffectiveSetCookie(c, sessionURL, now)
	if upd.Delete || upd.Cookie.Value != "" || upd.Cookie.Expires != time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("empty+future update = %+v; want replace with empty value", upd)
	}

	// Host-only vs domain-scoped: no Domain attribute means the
	// request host, bare (no leading dot).
	c = parseReconstructed(t, "hatch_vml=FAKE-VML; Path=/; Max-Age=172800; Secure; HttpOnly; SameSite=Lax")
	upd = EffectiveSetCookie(c, sessionURL, now)
	if upd.Cookie.Domain != "muse.ai" {
		t.Fatalf("host-only domain = %q; want muse.ai", upd.Cookie.Domain)
	}
	// Domain attribute without a dot is stored dotted.
	c = parseReconstructed(t, "x=FAKE; Domain=muse.ai; Path=/; Max-Age=60")
	upd = EffectiveSetCookie(c, sessionURL, now)
	if upd.Cookie.Domain != ".muse.ai" {
		t.Fatalf("domain attribute = %q; want .muse.ai", upd.Cookie.Domain)
	}

	// Default-path rule (RFC 6265 §5.1.4): up to the
	// right-most "/", "/" when at most one slash is present.
	for raw, want := range map[string]string{
		"https://muse.ai/api/session": "/api",
		"https://muse.ai/":             "/",
		"https://muse.ai/a/b/c":        "/a/b",
		"https://muse.ai/a":            "/",
	} {
		u, _ := url.Parse(raw)
		c = parseReconstructed(t, "x=FAKE; Max-Age=60")
		upd = EffectiveSetCookie(c, u, now)
		if upd.Cookie.Path != want {
			t.Fatalf("default path for %s = %q; want %q", raw, upd.Cookie.Path, want)
		}
	}
}

func TestApplyUpdatesAndReplace(t *testing.T) {
	stored := []StoredCookie{
		{Name: "hatch_sess", Value: "OLD", Domain: ".muse.ai", Path: "/", Expires: 1000},
		{Name: "hatch_sess", Value: "HOSTONLY", Domain: "muse.ai", Path: "/", Expires: 1000},
		{Name: "other", Value: "KEEP", Domain: ".example.com", Path: "/", Expires: 1000},
	}
	// Domain-scoped update touches only the domain-scoped row.
	merged := ApplyUpdates(stored, []CookieUpdate{
		{Cookie: StoredCookie{Name: "hatch_sess", Value: "NEW", Domain: ".muse.ai", Path: "/", Expires: 2000}},
	})
	if merged[0].Value != "NEW" || merged[1].Value != "HOSTONLY" {
		t.Fatalf("keyed update = %+v", merged)
	}
	// Deletion removes only its key.
	merged = ApplyUpdates(merged, []CookieUpdate{
		{Cookie: StoredCookie{Name: "hatch_sess", Domain: ".muse.ai", Path: "/"}, Delete: true},
	})
	if len(merged) != 2 || merged[0].Name != "hatch_sess" || merged[0].Domain != "muse.ai" {
		t.Fatalf("deletion = %+v", merged)
	}
	// Replace: outside-filter entries kept, filtered dropped,
	// export set in place, dropped count exact.
	exported := []StoredCookie{{Name: "hatch_sess", Value: "EXP", Domain: ".muse.ai", Path: "/", Expires: 3000}}
	replaced, dropped := ReplaceWithExport(stored, exported)
	if dropped != 2 {
		t.Fatalf("dropped = %d; want 2", dropped)
	}
	if len(replaced) != 2 || replaced[0].Name != "other" || replaced[1].Value != "EXP" {
		t.Fatalf("replaced = %+v", replaced)
	}
}

func TestCookieHeaderAndDriving(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	cookies := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE", Domain: ".muse.ai", Path: "/", Expires: now.Add(12 * time.Hour).Unix()},
		{Name: "hatch_gw", Value: "FAKE", Domain: ".muse.ai", Path: "/", Expires: now.Add(30 * 24 * time.Hour).Unix()},
		{Name: "expired", Value: "FAKE", Domain: ".muse.ai", Path: "/", Expires: now.Add(-time.Hour).Unix()},
		{Name: "sess", Value: "FAKE", Domain: "muse.ai", Path: "/"},
	}
	header := CookieHeader(cookies, now)
	if strings.Contains(header, "expired=") {
		t.Fatalf("header includes an expired cookie: %q", header)
	}
	for _, want := range []string{"hatch_sess=FAKE", "hatch_gw=FAKE", "sess=FAKE"} {
		if !strings.Contains(header, want) {
			t.Fatalf("header %q missing %q", header, want)
		}
	}
	name, exp := DrivingCookie(cookies)
	if name != "hatch_sess" || exp == nil || !exp.Equal(now.Add(12 * time.Hour)) {
		t.Fatalf("driving = %q %v; want hatch_sess +12h", name, exp)
	}
	// Without hatch_sess, the earliest dated cookie drives
	// (the expired cookie is excluded from this case: earliest
	// means earliest, past or not, and it would win).
	noHatch := []StoredCookie{cookies[1], cookies[3]}
	name, exp = DrivingCookie(noHatch)
	if name != "hatch_gw" || exp == nil {
		t.Fatalf("driving without hatch_sess = %q %v", name, exp)
	}
	// Session-only hatch_sess falls back to earliest.
	sessHatch := []StoredCookie{
		{Name: "hatch_sess", Value: "FAKE", Domain: "muse.ai", Path: "/"},
		{Name: "hatch_gw", Value: "FAKE", Domain: ".muse.ai", Path: "/", Expires: now.Add(time.Hour).Unix()},
	}
	name, _ = DrivingCookie(sessHatch)
	if name != "hatch_gw" {
		t.Fatalf("session hatch_sess driving = %q; want hatch_gw", name)
	}
	if name, exp := DrivingCookie(nil); name != "" || exp != nil {
		t.Fatalf("empty driving = %q %v", name, exp)
	}
	// Domain filter: subdomains in, neighbours out.
	if !InFilteredDomain(StoredCookie{Domain: ".auth.muse.ai"}) ||
		!InFilteredDomain(StoredCookie{Domain: "muse.ai"}) ||
		!InFilteredDomain(StoredCookie{Domain: ".x.muse.ai"}) ||
		InFilteredDomain(StoredCookie{Domain: ".notmuse.ai"}) ||
		InFilteredDomain(StoredCookie{Domain: ".muse.ai.evil.com"}) {
		t.Fatal("domain filter mismatch")
	}
}
