// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package logging

import (
	"errors"

	singlog "github.com/sagernet/sing-box/log"
)

// Level-gated error rendering (loop 4, (d)): a server response
// body must never reach a log emission above trace. Error
// values that may carry a body (conn.GatewayError,
// conn.AuthError) render above trace as status code + error
// class + body length only, and at trace as the
// redacted-then-truncated body. The gate lives here, at the
// log boundary — the error values themselves keep their
// Python-parity payloads for callers and CLI output, which
// are not log emissions and carry no level.
//
// logSummary is satisfied STRUCTURALLY by error types whose
// printed form may carry a server body: they implement
// LogSummary() returning the above-trace summary. It is
// defined here, not shared, because conn imports logging
// (for SafeString) and logging cannot import conn back; a
// shared interface type would be an import cycle. errors.As
// finds the summary through wrappers, so a GatewayError
// wrapped in a ConnectionError still summarises.

// logSummary is the structural contract for body-carrying
// errors: LogSummary returns status/class/length only, with
// no body bytes.
type logSummary interface {
	LogSummary() string
}

// SummarizeErr renders err for a log line above trace: the
// LogSummary of the first body-carrying error in the chain,
// or SafeString(err.Error()) for errors that carry no body.
// A nil error renders as "".
func SummarizeErr(err error) string {
	if err == nil {
		return ""
	}
	var s logSummary
	if errors.As(err, &s) {
		return s.LogSummary()
	}
	return SafeString(err.Error())
}

// traceErrLimit bounds a trace-level error rendering: the
// redacted body, truncated to 500 runes after redaction,
// mirroring the gateway's 500-byte payload cap.
const traceErrLimit = 500

// SafeErrForLevel renders err for a log line at level: at
// trace, the redacted-then-truncated body (redact first,
// truncate second); at every level above trace, the summary
// only (SummarizeErr). A nil error renders as "".
func SafeErrForLevel(err error, level singlog.Level) string {
	if err == nil {
		return ""
	}
	if level == singlog.LevelTrace {
		return truncateRunes(SafeErr(err), traceErrLimit)
	}
	return SummarizeErr(err)
}

// truncateRunes truncates s to at most n runes.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}
