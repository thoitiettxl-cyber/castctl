// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package redact

import "regexp"

var (
	// reQueryToken matches the value of a token-like query
	// parameter: auth_token, access_token, hatch_token, token, or
	// session, after '?' or '&', up to the next '&' or whitespace.
	// A vm_id parameter is deliberately not matched: it is an
	// identifier, not a credential in an error string, and
	// gateway tests pin it surviving redaction.
	reQueryToken = regexp.MustCompile(`(?i)([?&](?:auth_token|access_token|hatch_token|token|session)=)[^&\s]*`)
	// reFragmentToken matches the same keys in a URL fragment.
	reFragmentToken = regexp.MustCompile(`(?i)(#(?:auth_token|access_token|hatch_token|token|session)=)[^&\s]*`)
	// reCookieToken matches a cookie-like fragment
	// (hatch_sess, datr, session) up to the next ';' or
	// whitespace, in plain or JSON-adjacent text.
	reCookieToken = regexp.MustCompile(`(?i)\b(hatch_sess|datr|session)=[^;\s]*`)
	// reJSONCookie matches the value of a cookie-like key in JSON
	// form: {"hatch_sess": "..."}.
	reJSONCookie = regexp.MustCompile(`(?i)("(?:hatch_sess|datr|session)"\s*:\s*")[^"]*`)
	// reBearer matches a Bearer token after an "Authorization:"
	// label, whatever follows the label.
	reBearer = regexp.MustCompile(`(?i)(Authorization:\s*Bearer\s+)\S+`)
	// reBareBearer matches a Bearer token with no "Authorization:"
	// label. The token must look token-like (at least 8 chars
	// from the base64/URL-safe alphabet) so ordinary prose ("the
	// bearer of bad news") is never redacted. It runs after
	// reBearer, so an already-redacted "[redacted]" value
	// (brackets are outside the alphabet) is left alone.
	reBareBearer = regexp.MustCompile(`(?i)\b(Bearer\s+)[A-Za-z0-9_\-.~+/=]{8,}`)
)

// String strips credentials from a free-form error string: URL
// userinfo, token query parameters (including in fragments),
// cookie fragments (including JSON form), and Bearer tokens,
// labelled or bare. The patterns and their order are the
// behaviour of internal/gateway's error-string redactor,
// re-implemented here so the two sites cannot drift apart
// silently; String does not import gateway.
//
// Markers: URL userinfo is replaced with "<redacted>" (via
// RedactURLUserinfo); every other step uses "[redacted]", exactly
// as the gateway redactor does today. The split is deliberate and
// pinned by tests: unifying the markers is a gateway-owned
// decision, not one this package makes unilaterally.
//
// Everything else is left byte-identical: plain email text, a
// vm_id query value, prose mentioning a bearer, and server
// payload text carrying no credential all survive. String is
// idempotent. It does not redact by key: a JSON
// {"password": "..."} fragment survives unchanged, because an
// error string has no key/value structure to trust; use Value
// for structured values.
func String(s string) string {
	if s == "" {
		return s
	}
	s = RedactURLUserinfo(s)
	s = reQueryToken.ReplaceAllString(s, "${1}[redacted]")
	s = reFragmentToken.ReplaceAllString(s, "${1}[redacted]")
	s = reCookieToken.ReplaceAllString(s, "${1}=[redacted]")
	s = reJSONCookie.ReplaceAllString(s, "${1}[redacted]")
	s = reBearer.ReplaceAllString(s, "${1}[redacted]")
	s = reBareBearer.ReplaceAllString(s, "${1}[redacted]")
	return s
}
