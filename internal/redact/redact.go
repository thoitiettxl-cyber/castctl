// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package redact provides the single redaction implementation used
// by the whole tree. Every redaction site — profile display output,
// outbound endpoint display, and error strings — is implemented on
// top of the functions here, so the secret-key set, the URL-userinfo
// pattern, and the markers live in exactly one place. It has no
// imports from the rest of the port, so internal/profile,
// internal/gateway, and internal/outbound can all use it without
// creating import cycles or breaking their disjointness from each
// other.
//
// The frozen API:
//
//   - RedactURLUserinfo(s string) string: strip the userinfo from
//     every URL embedded in s, keeping scheme, host, and the rest
//     byte-identical.
//   - Value(v any) any: recursively redact a JSON-shaped value.
//     A value whose map key is secret (see IsSecretKey) is replaced
//     wholesale with Marker, whatever its type; every other string
//     value keeps everything except embedded URL userinfo. Under a
//     "headers" or "extra_headers" key every header value is
//     replaced with Marker, whatever the header name. Value
//     returns a new value and never mutates its input.
//   - String(s string) string: redact an error string. It applies
//     RedactURLUserinfo plus the token query-parameter, cookie
//     fragment, and Bearer-token steps of internal/gateway's error
//     redactor, re-implemented here so gateway can adopt it without
//     importing another package's internals.
//   - IsSecretKey(key string) bool: report whether a map key names
//     secret material (case-insensitive, exact match after
//     lowercasing).
//   - Marker: the replacement for redacted structured values,
//     "<redacted>".
//   - OrderedMap: the interface an order-preserving JSON object type
//     implements so Value can redact it without knowing the concrete
//     type (and without importing its owner package, which would
//     cycle: the owner imports redact).
//
// Boundaries, pinned by tests:
//
//   - Value redacts by KEY, not by value shape: a secret-looking
//     string under a non-secret key is kept (except for embedded
//     URL userinfo), and a non-secret value under a secret key is
//     replaced wholesale. Key matching is exact after lowercasing:
//     "Password" and "AUTHORIZATION" match, "my_token", "vmid",
//     and "obfs_password" do not.
//   - Value applies ONLY URL-userinfo redaction inside strings. It
//     does not strip token query parameters, cookie fragments, or
//     Bearer tokens from a string value; that is String's job.
//     Conversely, String does not redact by key: a JSON
//     {"password": "..."} fragment inside an error string survives
//     String unchanged.
//   - String uses TWO markers, matching internal/gateway's error
//     redactor as it stands today: "<redacted>" for URL userinfo
//     and "[redacted]" for query/fragment/cookie/Bearer values.
//     The two markers are not unified here; unifying them is a
//     gateway-owned decision (gateway tests pin "[redacted]").
//     Value always uses Marker ("<redacted>").
//   - Struct values are returned unchanged by Value: it never
//     walks struct fields, so it can neither drop nor leak one
//     silently. Marshal a struct to a map or JSON shape first,
//     as RedactEndpoint does.
//   - Value never echoes a secret into an error: it returns no
//     error at all, and callers must not log its input.
package redact

import "regexp"

var (
	// reURLUserinfo matches a URL's userinfo greedily to the LAST
	// '@' before the first '/', '?', or '#' after "://": a
	// password may itself contain '@' (NB-R1), and only the last
	// '@' in the authority delimits the userinfo from the host.
	// The userinfo itself must be non-empty and contain no
	// whitespace, slash, '?' or '#', so an empty userinfo
	// ("scheme://@host"), a plain email with no scheme, and an
	// '@' in a path/query/fragment are all left unchanged.
	reURLUserinfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/\s?#]+@`)
)

// RedactURLUserinfo replaces the userinfo of every URL embedded in s
// with "<redacted>", keeping the scheme, host, and everything after
// the host byte-identical:
//
//	scheme://user:pass@host/path -> scheme://<redacted>@host/path
//	scheme://user@host/path      -> scheme://<redacted>@host/path
//
// Boundary (precise): only a `scheme://...@` pattern is redacted,
// where scheme matches `[a-z][a-z0-9+.-]*` (case-insensitive, the
// original scheme spelling is preserved) and the userinfo is the
// run up to the LAST `@` before the first `/`, `?`, or `#` after
// `://`, containing no whitespace. In particular:
//
//   - a URL without userinfo is returned unchanged;
//   - plain email-like text with no scheme ("user@example.com",
//     "contact bob@example.com") is returned unchanged — there is no
//     `://` before the `@`, so no pattern matches;
//   - an `@` in a URL path or query after the first slash
//     ("https://example.com/@user") is unchanged: userinfo must
//     appear before the first slash after `://`;
//   - an empty userinfo ("scheme://@host") is unchanged: it carries
//     no credential;
//   - any scheme is matched, not an allowlist: the boundary is
//     syntactic, so a proxy URL such as "socks5://user:pass@host"
//     is redacted exactly like an "https://" URL.
//
// The replacement is idempotent: applying it to already-redacted
// text yields the same text. It redacts only URL userinfo; query
// tokens, cookie fragments, and Bearer tokens in a free-form string
// are String's concern, not this function's.
func RedactURLUserinfo(s string) string {
	if s == "" {
		return s
	}
	return reURLUserinfo.ReplaceAllString(s, "${1}<redacted>@")
}
