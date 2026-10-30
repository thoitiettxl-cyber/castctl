// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"net/http"
	"regexp"
	"strconv"
)

// malformedStatusRe extracts the status token from gorilla's
// "malformed HTTP status code" error. The token is the ONLY part
// of a malformed status line that may be summarised: it is
// validated token-shaped (short, no spaces/slashes) so a
// peer-controlled status line cannot smuggle a URL, header
// value, or credential into the log, and only a 3-digit code
// is ever emitted as a token (loop 7, item R4) — anything
// else renders as its length only.
var malformedStatusRe = regexp.MustCompile(`malformed HTTP status code "([^"]*)"`)

// handshakeFailureError renders a WebSocket handshake failure
// for output without peer text (loop-5 allowlist rule): the
// validated 3-digit status code (or the token length, when
// the token is not a 3-digit code) only, or a fixed message
// when no parseable status exists. The original error chain
// is preserved via Unwrap, so classification (errors.As /
// IsTransient) is unchanged — only the rendered text is
// summarised. A gorilla handshake error's text may embed the
// peer's status line verbatim; that TEXT never reaches an
// error string, a log line, or stderr output — only the
// derived code/length does.
type handshakeFailureError struct {
	err      error
	token    string
	kind     string
	hasToken bool
}

func (e *handshakeFailureError) Error() string {
	if e.hasToken {
		return "gateway: websocket handshake: " + e.kind + "=" + e.token
	}
	return "gateway: websocket handshake failed"
}

func (e *handshakeFailureError) Unwrap() error { return e.err }

// newHandshakeFailureError builds the handshake-failure error
// from gorilla's raw result, before any redaction wrapping:
// the status token is extracted from the raw result only
// (handshakeStatusToken), never from redacted text.
func newHandshakeFailureError(resp *http.Response, err error) error {
	token, kind, ok := handshakeStatusToken(resp, err)
	if !ok {
		return &handshakeFailureError{err: err}
	}
	return &handshakeFailureError{err: err, token: token, kind: kind, hasToken: true}
}

// isThreeDigitCode reports whether s is exactly three ASCII
// digits: the only token shape emitted as a status token.
func isThreeDigitCode(s string) bool {
	if len(s) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// tokenShapeRe matches a token-shaped fragment: ASCII
// letters, digits, dot, underscore, or hyphen, of any
// length. Such a fragment is summarised by its length only,
// never emitted — its bytes are peer-controlled text, and
// only a 3-digit code is a status.
var tokenShapeRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// handshakeStatusToken derives the loggable status from a
// WebSocket upgrade result. A non-nil response wins with its
// numeric status code when it is a 3-digit code, else with
// the code's length. Otherwise the error text is scanned for
// the malformed-status-code pattern: a 3-digit token is
// returned as a status_token; a token-shaped but
// non-conforming token (non-numeric, wrong length) is
// returned as its length under status_token_length, never
// its bytes. Anything else returns ok=false: no event is
// emitted and the failure error renders the fixed message.
// resp and err are the RAW gorilla results, before any
// redaction wrapping — the extractor sees the status line
// shape, never a URL or header.
func handshakeStatusToken(resp *http.Response, err error) (token, kind string, ok bool) {
	if resp != nil {
		code := strconv.Itoa(resp.StatusCode)
		if isThreeDigitCode(code) {
			return code, "status_code", true
		}
		return strconv.Itoa(len(code)), "status_code_length", true
	}
	if err == nil {
		return "", "", false
	}
	m := malformedStatusRe.FindStringSubmatch(err.Error())
	if m == nil {
		return "", "", false
	}
	token = m[1]
	if len(token) == 0 {
		return "", "", false
	}
	if isThreeDigitCode(token) {
		return token, "status_token", true
	}
	if tokenShapeRe.MatchString(token) {
		return strconv.Itoa(len(token)), "status_token_length", true
	}
	return "", "", false
}
