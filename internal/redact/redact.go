// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package redact provides the single string-level URL-userinfo
// redactor shared by every redaction site in the Go port. The two
// URL patterns are the PR2 gateway error-string patterns, with the
// marker unified to "<redacted>" (see the PR2 follow-ups report).
// It has no imports from the rest of the port, so internal/profile,
// internal/gateway, and internal/outbound can all use it without
// creating import cycles or breaking their disjointness from each
// other. The key-based redaction helpers (profile.redactValue and
// outbound.redactValue) are NOT unified here; that unification is a
// separate PR3 item, and their key logic is untouched.
package redact

import "regexp"

var (
	reURLUserinfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`)
	reURLUser     = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@`)
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
// original scheme spelling is preserved) and the userinfo contains
// no whitespace, slash, or `@` before the delimiting `@`. In
// particular:
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
// tokens, cookie fragments, and Bearer tokens are the caller's
// concern (see internal/gateway's redactErrorString).
func RedactURLUserinfo(s string) string {
	if s == "" {
		return s
	}
	s = reURLUserinfo.ReplaceAllString(s, "${1}<redacted>@")
	s = reURLUser.ReplaceAllString(s, "${1}<redacted>@")
	return s
}
