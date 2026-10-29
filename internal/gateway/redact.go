// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"regexp"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/redact"
)

// redactErrorString strips credentials from an error string
// (item (c), Boss-approved for PR2). The URL-userinfo step is the
// shared string-level redactor from internal/redact
// (RedactURLUserinfo): it replaces userinfo in any embedded URL
// with "<redacted>", keeping scheme, host and path. The remaining
// steps are gateway-local:
//
//   - values of token-like query parameters (auth_token,
//     access_token, token, hatch_token, session);
//   - values of cookie-like fragments (hatch_sess, datr, session);
//   - Bearer tokens after an "Authorization:" label.
//
// Everything else is left byte-identical, so server payload text
// that carries no credential survives redaction. The PR3
// unification (one shared redaction helper for the key-based
// helpers) is a separate, carried item; until then this package
// keeps its own query/cookie/Bearer patterns and does NOT import
// internal/profile.
var (
	reQueryToken  = regexp.MustCompile(`(?i)([?&](?:auth_token|access_token|hatch_token|token|session)=)[^&\s]*`)
	reCookieToken = regexp.MustCompile(`(?i)\b(hatch_sess|datr|session)=[^;\s]*`)
	reBearer      = regexp.MustCompile(`(?i)(Authorization:\s*Bearer\s+)\S+`)
)

func redactErrorString(s string) string {
	if s == "" {
		return s
	}
	s = redact.RedactURLUserinfo(s)
	s = reQueryToken.ReplaceAllString(s, "${1}[redacted]")
	s = reCookieToken.ReplaceAllString(s, "${1}=[redacted]")
	s = reBearer.ReplaceAllString(s, "${1}[redacted]")
	return s
}

// redactedError wraps an error so its printed form is redacted
// while errors.As/errors.Is still see the original chain. Use it
// where an external error string (dialer, HTTP transport) may
// embed a proxy URL or credential: the cause is preserved for
// classification, the text is safe for logs.
type redactedError struct{ err error }

// Error returns the redacted error text.
func (e *redactedError) Error() string { return redactErrorString(e.err.Error()) }

// Unwrap exposes the original error.
func (e *redactedError) Unwrap() error { return e.err }

// redactErr wraps err for safe printing, unless err is nil.
func redactErr(err error) error {
	if err == nil {
		return nil
	}
	return &redactedError{err: err}
}
