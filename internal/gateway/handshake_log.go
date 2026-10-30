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
// of a malformed status line that may be logged: it is validated
// token-shaped (short, no spaces/slashes) so a peer-controlled
// status line cannot smuggle a URL, header value, or credential
// into the log.
var malformedStatusRe = regexp.MustCompile(`malformed HTTP status code "([^"]*)"`)

// handshakeFailureError renders a WebSocket handshake failure
// for output without peer text (loop-5 allowlist rule): the
// validated status token or numeric status code only, or a
// fixed message when no parseable status exists. The original
// error chain is preserved via Unwrap, so classification
// (errors.As / IsTransient) is unchanged — only the rendered
// text is summarised. A gorilla handshake error's text may
// embed the peer's status line verbatim; it must never reach
// an error string, a log line, or stderr output.
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

// handshakeStatusToken derives the loggable status from a
// WebSocket upgrade result. A non-nil response wins with its
// numeric status code; otherwise the error text is scanned for
// the malformed-status-code pattern and the token is accepted
// only if it matches ^[A-Za-z0-9._-]{1,32}$. Anything else
// returns ok=false: no event is emitted. resp and err are the
// RAW gorilla results, before any redaction wrapping — the
// extractor sees the status line shape, never a URL or header.
func handshakeStatusToken(resp *http.Response, err error) (token, kind string, ok bool) {
	if resp != nil {
		return strconv.Itoa(resp.StatusCode), "status_code", true
	}
	if err == nil {
		return "", "", false
	}
	m := malformedStatusRe.FindStringSubmatch(err.Error())
	if m == nil {
		return "", "", false
	}
	token = m[1]
	if len(token) == 0 || len(token) > 32 {
		return "", "", false
	}
	for _, r := range token {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return "", "", false
		}
	}
	return token, "status_token", true
}
