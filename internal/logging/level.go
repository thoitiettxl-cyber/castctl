// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package logging

import (
	"errors"

	singlog "github.com/sagernet/sing-box/log"
)

// Error rendering at the log boundary (loop 5, Boss ruling
// 2026-10-30): a server response body must never reach a log
// emission at ANY level, including trace. Error values that
// may carry a body (conn.GatewayError, conn.AuthError)
// render at every level as status code + error class + body
// length only (plus validated content-type / error-enum
// fields). The loop-4 trace allowance for the
// redacted-then-truncated body is SUPERSEDED: trace gets the
// same summary. The gate lives here, at the log boundary —
// the error values themselves keep their (allowlist-summary)
// payloads for callers and CLI output, which are not log
// emissions.
//
// logSummary is satisfied STRUCTURALLY by error types whose
// printed form may carry a server body: they implement
// LogSummary() returning the summary. It is defined here,
// not shared, because conn imports logging (for SafeString)
// and logging cannot import conn back; a shared interface
// type would be an import cycle. errors.As finds the summary
// through wrappers, so a GatewayError wrapped in a
// ConnectionError still summarises.

// logSummary is the structural contract for body-carrying
// errors: LogSummary returns status/class/length only, with
// no body bytes.
type logSummary interface {
	LogSummary() string
}

// SummarizeErr renders err for a log line at any level: the
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

// SafeErrForLevel renders err for a log line at level. Under
// the loop-5 ruling every level renders the summary only
// (SummarizeErr) — there is no trace exception. A nil error
// renders as "".
func SafeErrForLevel(err error, level singlog.Level) string {
	if err == nil {
		return ""
	}
	_ = level
	return SummarizeErr(err)
}
