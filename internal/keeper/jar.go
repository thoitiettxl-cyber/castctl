// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Netscape jar handling: parse, serialise, and merge.
//
// The cookies file is a Netscape HTTP Cookie File (7 tab-separated
// columns). This is the ONLY form the keeper writes. Reading
// tolerates the other two forms the repo's ParseCookies accepts
// (one-line `a=b; c=d`, JSON object) only for building the Cookie
// header of a tick — see LoadCookiesSnapshot — and never writes
// them back: a Set-Cookie capture against a non-jar file SKIPS
// the file rewrite (freeze (a)), while a validated CDP export
// REPLACES the file with the jar set.
//
// Serialisation rules (research-cdp §4.2, frozen):
//   - 7 columns: domain, flag, path, secure, expires, name,
//     value; LF endings; a single trailing newline; the
//     conventional `# Netscape HTTP Cookie File` header line.
//   - flag is TRUE iff the domain has a leading dot
//     (domain-scoped), FALSE for host-only.
//   - secure is TRUE/FALSE.
//   - expires is an integer epoch, 0 for session cookies.
//   - HttpOnly cookies are plain rows: no `#HttpOnly_` prefix
//     is ever written, and the HttpOnly bit is not preserved
//     across a jar round-trip (the jar format has no column for
//     it; ParseCookies in internal/gateway has the same
//     limitation). A `#HttpOnly_` row read from a foreign file
//     is a comment and is dropped, exactly as ParseCookies
//     drops `#` lines.
//   - Rows sort deterministically by (domain, path, name).
//   - Tab, newline, or CR in any field is rejected: a value
//     containing one cannot round-trip through the format.
//   - Values are verbatim: no quoting, no escaping.
//
// Strictness divergence (documented, intentional): ParseJar
// below requires EXACTLY 7 columns per row, while the legacy
// reader gateway.ParseCookies accepts >= 7 (extra columns
// ignored). The keeper is strict because it rewrites the
// file: silently dropping an extra column on rewrite would
// destroy data the reader preserved. The gateway reader is
// lenient because it only builds a Cookie header and must
// keep reading files other tools wrote (including the
// 8-column jars `auth import` accepts). The two parsers are
// deliberately NOT aligned; the strictness boundary is
// bridged by lockStateOnly (ResetAfterLogin never parses the
// cookies bytes) and by classifyCookiesFile failing closed
// on a jar-shaped file ParseJar rejects.

// FilteredDomains is the CDP/Set-Cookie domain filter: only
// cookies belonging to the Muse session are ever merged or
// written by the keeper. Everything else is dropped with a
// count only. The set is a named constant so a fake-server test
// that needs a wider set fails loudly here instead of silently
// widening the filter in a merge function.
var FilteredDomains = []string{"muse.ai", "auth.muse.ai"}

// StoredCookie is one explicit cookie: the merge unit for
// Set-Cookie updates and CDP exports. No cookiejar, no
// http.Cookie smuggling: every field is explicit, including the
// host-only vs domain-scoped distinction carried by the leading
// dot on Domain. The dot is preserved in the stored Domain
// string (it decides the jar flag on write), but the MERGE key
// is dot-insensitive: see cookieKey.
type StoredCookie struct {
	Name     string
	Value    string // SECRET MATERIAL: never log or print.
	Domain   string // Leading dot = domain-scoped; bare = host-only.
	Path     string
	Secure   bool
	HTTPOnly bool
	// Expires is the epoch expiry, 0 for a session cookie.
	Expires int64
}

// Session reports whether the cookie has no expiry.
func (c StoredCookie) Session() bool { return c.Expires == 0 }

// cookieKey is the merge identity: (name, domain, path), domain
// compared case-insensitively and WITHOUT its leading dot.
// The dot is deliberately insignificant here (loop-2 fix for
// the B1 duplication): a stored host-only entry ("muse.ai")
// and a Domain-scoped update (".muse.ai", as EffectiveSetCookie
// normalizes it) are the same cookie for merge purposes, on
// both the header-rebuild path (mergeCookieHeader rebuilds
// stored pairs with a bare domain) and the persisted path
// (ParseJar keeps the jar's domain verbatim). The keeper never
// does domain matching on the wire, so collapsing the
// host-only/domain-scoped distinction in the key loses
// nothing it uses; the stored Domain string itself still
// carries the dot, and an upsert replaces it with the
// update's form. A jar that holds both forms of one cookie
// deduplicates to the last row (ParseJar) / the update's form
// (ApplyUpdates).
type cookieKey struct {
	name, domain, path string
}

func (c StoredCookie) key() cookieKey {
	return cookieKey{name: c.Name, domain: strings.ToLower(strings.TrimPrefix(c.Domain, ".")), path: c.Path}
}

// InFilteredDomain reports whether the cookie belongs to the
// Muse session: its domain is muse.ai or auth.muse.ai, or a
// subdomain of one of them (domain-scoped or host-only).
func InFilteredDomain(c StoredCookie) bool {
	d := strings.ToLower(strings.TrimPrefix(c.Domain, "."))
	for _, base := range FilteredDomains {
		if d == base || strings.HasSuffix(d, "."+base) {
			return true
		}
	}
	return false
}

func rejectCookieField(field, value string) error {
	if strings.ContainsAny(value, "\t\n\r") {
		return fmt.Errorf("cookie %s contains a tab, newline, or carriage return", field)
	}
	return nil
}

func validateStoredCookie(c StoredCookie) error {
	if c.Name == "" {
		return fmt.Errorf("cookie with an empty name")
	}
	if c.Domain == "" {
		return fmt.Errorf("cookie %q with an empty domain", c.Name)
	}
	if c.Expires < 0 {
		return fmt.Errorf("cookie %q with a negative expiry", c.Name)
	}
	for field, value := range map[string]string{
		"name": c.Name, "domain": c.Domain, "path": c.Path, "value": c.Value,
	} {
		if err := rejectCookieField(field, value); err != nil {
			return err
		}
	}
	return nil
}

// ParseJar parses Netscape jar bytes. `#` lines (including
// `#HttpOnly_` rows) are comments and are dropped. A malformed
// row fails closed with its line number only — never the row
// contents, which may carry a cookie value.
func ParseJar(data []byte) ([]StoredCookie, error) {
	var out []StoredCookie
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 7 {
			return nil, fmt.Errorf("jar line %d: want 7 tab-separated fields, got %d", i+1, len(fields))
		}
		secure, err := parseJarBool(fields[3])
		if err != nil {
			return nil, fmt.Errorf("jar line %d: invalid secure flag", i+1)
		}
		if _, err := parseJarBool(fields[1]); err != nil {
			return nil, fmt.Errorf("jar line %d: invalid domain flag", i+1)
		}
		expires, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil || expires < 0 {
			return nil, fmt.Errorf("jar line %d: invalid expiry", i+1)
		}
		c := StoredCookie{
			Domain: fields[0], Path: fields[2], Secure: secure,
			Expires: expires, Name: fields[5], Value: fields[6],
		}
		if err := validateStoredCookie(c); err != nil {
			return nil, fmt.Errorf("jar line %d: %v", i+1, err)
		}
		out = append(out, c)
	}
	// Duplicate keys: last row wins, matching file-order merge
	// semantics elsewhere in the repo.
	seen := make(map[cookieKey]int)
	uniq := make([]StoredCookie, 0, len(out))
	for _, c := range out {
		if idx, ok := seen[c.key()]; ok {
			uniq[idx] = c
			continue
		}
		seen[c.key()] = len(uniq)
		uniq = append(uniq, c)
	}
	return uniq, nil
}

func parseJarBool(s string) (bool, error) {
	switch {
	case strings.EqualFold(s, "TRUE"):
		return true, nil
	case strings.EqualFold(s, "FALSE"):
		return false, nil
	default:
		return false, fmt.Errorf("not TRUE/FALSE")
	}
}

// SerializeJar renders cookies in deterministic
// (domain, path, name) order. An empty set renders the header
// line only. Values are verbatim.
func SerializeJar(cookies []StoredCookie) ([]byte, error) {
	sorted := make([]StoredCookie, len(cookies))
	copy(sorted, cookies)
	for _, c := range sorted {
		if err := validateStoredCookie(c); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if strings.ToLower(a.Domain) != strings.ToLower(b.Domain) {
			return strings.ToLower(a.Domain) < strings.ToLower(b.Domain)
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Name < b.Name
	})
	var sb strings.Builder
	sb.WriteString("# Netscape HTTP Cookie File\n")
	for _, c := range sorted {
		flag := "FALSE"
		if strings.HasPrefix(c.Domain, ".") {
			flag = "TRUE"
		}
		secure := "FALSE"
		if c.Secure {
			secure = "TRUE"
		}
		fmt.Fprintf(&sb, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			c.Domain, flag, c.Path, secure, c.Expires, c.Name, c.Value)
	}
	return []byte(sb.String()), nil
}

// CookieUpdate is one parsed Set-Cookie or CDP cookie after
// effective domain/path/expiry resolution. Delete marks an
// explicit server deletion (past expiry, Max-Age <= 0, or the
// empty-value no-expiry shape); a Delete update removes the
// matching stored entry.
type CookieUpdate struct {
	Cookie StoredCookie
	Delete bool
}

// EffectiveSetCookie resolves one parsed Set-Cookie value to its
// merge form against the request URL, per RFC 6265 §5.1.3/§5.1.4
// and the frozen deletion rules:
//
//   - Domain attribute present: domain-scoped, stored with a
//     leading dot when the attribute has none (Domain=muse.ai
//     means .muse.ai); absent: host-only, the request host.
//   - Path attribute present: as given; absent: the RFC
//     default-path of the request URL.
//   - Max-Age > 0 wins over Expires; expiry = receivedAt + Max-Age.
//   - Max-Age < 0, or an Expires at/past receivedAt, deletes.
//   - Empty value + future expiry REPLACES (freeze (c)):
//     expiry-only deletion is not assumed from an empty value.
//   - Empty value + no expiry information deletes: net/http's
//     parser cannot distinguish Max-Age=0 from an absent Max-Age
//     (both read MaxAge 0), and the Max-Age=0 clear-cookie shape
//     is exactly empty value + no expiry. This is the one place
//     the merge inspects absence, and it is documented here
//     rather than hidden in a helper.
func EffectiveSetCookie(c *http.Cookie, reqURL *url.URL, receivedAt time.Time) CookieUpdate {
	domain := ""
	if c.Domain != "" {
		domain = c.Domain
		if !strings.HasPrefix(domain, ".") {
			domain = "." + domain
		}
	} else if reqURL != nil {
		domain = strings.ToLower(reqURL.Hostname())
	}
	path := c.Path
	if path == "" {
		path = defaultPath(reqURL)
	}
	upd := CookieUpdate{Cookie: StoredCookie{
		Name: c.Name, Value: c.Value, Domain: domain, Path: path,
		Secure: c.Secure, HTTPOnly: c.HttpOnly,
	}}
	switch {
	case c.MaxAge < 0:
		upd.Delete = true
	case c.MaxAge > 0:
		upd.Cookie.Expires = receivedAt.Add(time.Duration(c.MaxAge) * time.Second).Unix()
	case !c.Expires.IsZero():
		if !c.Expires.After(receivedAt) {
			upd.Delete = true
		} else {
			upd.Cookie.Expires = c.Expires.Unix()
		}
	default:
		// No expiry information at all: session cookie, unless
		// the value is empty (the Max-Age=0 clear shape).
		if c.Value == "" {
			upd.Delete = true
		}
	}
	return upd
}

// defaultPath implements RFC 6265 §5.1.4 for the request URL.
func defaultPath(reqURL *url.URL) string {
	if reqURL == nil || reqURL.Path == "" || !strings.HasPrefix(reqURL.Path, "/") {
		return "/"
	}
	if strings.Count(reqURL.Path, "/") <= 1 {
		return "/"
	}
	return reqURL.Path[:strings.LastIndex(reqURL.Path, "/")]
}

// ApplyUpdates applies ordered Set-Cookie updates to the stored
// set, in order, keyed by (name, domain, path). Deletions remove;
// anything else upserts. Entries outside the updates are kept
// verbatim. Callers filter by domain BEFORE calling: updates
// outside the filtered set must never reach this function.
func ApplyUpdates(stored []StoredCookie, updates []CookieUpdate) []StoredCookie {
	idx := make(map[cookieKey]int, len(stored))
	out := make([]StoredCookie, len(stored))
	copy(out, stored)
	for i, c := range out {
		idx[c.key()] = i
	}
	for _, u := range updates {
		k := u.Cookie.key()
		if u.Delete {
			if i, ok := idx[k]; ok {
				out = append(out[:i], out[i+1:]...)
				idx = rebuildIndex(out)
			}
			continue
		}
		if i, ok := idx[k]; ok {
			out[i] = u.Cookie
		} else {
			idx[k] = len(out)
			out = append(out, u.Cookie)
		}
	}
	return out
}

func rebuildIndex(cookies []StoredCookie) map[cookieKey]int {
	idx := make(map[cookieKey]int, len(cookies))
	for i, c := range cookies {
		idx[c.key()] = i
	}
	return idx
}

// ReplaceWithExport replaces the filtered domain set with the
// validated CDP export: stored entries outside the filter are
// kept verbatim (including expired ones: their expiries never
// gate the session, see validateExportedSet), every stored
// entry inside the filter is dropped, and the export set takes
// its place — the snapshot is faithful, so absence from the
// snapshot IS the deletion signal for filtered cookies. It
// returns the new set and the number of stored entries dropped
// (0 when the previous file was not jar form — the whole file
// was replaced, and there were no jar entries to count).
func ReplaceWithExport(stored []StoredCookie, exported []StoredCookie) ([]StoredCookie, int) {
	kept := make([]StoredCookie, 0, len(stored))
	dropped := 0
	for _, c := range stored {
		if InFilteredDomain(c) {
			dropped++
			continue
		}
		kept = append(kept, c)
	}
	return append(kept, exported...), dropped
}

// EarliestExpiry returns the earliest non-session expiry in the
// set, or nil when the set has no dated cookie. Past expiries
// count: callers decide what "already past" means.
func EarliestExpiry(cookies []StoredCookie) *time.Time {
	var earliest *time.Time
	for _, c := range cookies {
		if c.Session() {
			continue
		}
		exp := time.Unix(c.Expires, 0).UTC()
		if earliest == nil || exp.Before(*earliest) {
			e := exp
			earliest = &e
		}
	}
	return earliest
}

// EarliestFilteredExpiry is EarliestExpiry over the filtered
// domains only. Non-filtered cookies are operator data the
// keeper preserves verbatim (ReplaceWithExport keeps them);
// their expiries must never gate the session. Used by the
// CDP-export validation gate (validateExportedSet).
func EarliestFilteredExpiry(cookies []StoredCookie) *time.Time {
	var filtered []StoredCookie
	for _, c := range cookies {
		if InFilteredDomain(c) {
			filtered = append(filtered, c)
		}
	}
	return EarliestExpiry(filtered)
}

// DrivingCookie resolves the adaptive-interval driver (freeze
// (b)): hatch_sess when present with a non-session expiry, else
// the earliest dated cookie. It returns the cookie name and its
// expiry, or ("", nil) when no dated cookie exists.
func DrivingCookie(cookies []StoredCookie) (string, *time.Time) {
	for _, c := range cookies {
		if c.Name == "hatch_sess" && !c.Session() {
			exp := time.Unix(c.Expires, 0).UTC()
			return c.Name, &exp
		}
	}
	earliest := EarliestExpiry(cookies)
	if earliest == nil {
		return "", nil
	}
	for _, c := range cookies {
		if !c.Session() && time.Unix(c.Expires, 0).UTC().Equal(*earliest) {
			return c.Name, earliest
		}
	}
	return "", earliest
}

// CookieHeader builds the Cookie request header from stored
// cookies: non-expired entries only (session cookies included),
// deterministic order, `name=value` pairs. It mirrors the
// one-line form ParseCookies accepts. Values are verbatim.
func CookieHeader(cookies []StoredCookie, now time.Time) string {
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if !c.Session() && !time.Unix(c.Expires, 0).After(now) {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}
