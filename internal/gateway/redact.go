// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/redact"
)

// redactFreeText strips credentials from peer/server-controlled
// free text (a WebSocket close reason, a panic value, a server
// payload) using the logging boundary, which is STRICTER than
// redact.String: it also strips every query value of a URL
// (including vm_id and unknown keys), JSON values under
// secret-looking keys, and bare secret key=value fragments.
// redactErrorString's redact.String semantics are pinned by
// gateway tests (vm_id survives it) and are kept for error
// chains; free text that may reach a log line gets the
// stricter boundary at the producer, before it is stored in
// an error or a struct field.
func redactFreeText(s string) string {
	return logging.SafeString(s)
}

// redactTruncateText redacts the FULL text first (SafeString),
// then truncates the redacted text to n runes. The order is
// load-bearing: truncating first can leave a fragment of a
// secret too short for the redaction floors (a bare fragment
// under 16 characters, a Basic tail under 8) or a shape no
// pattern matches once cut (a label split by the cut). Every
// call site that truncates server response text must use
// this helper (or redactTruncatePayload), never
// truncateText/truncatePayload on raw text.
func redactTruncateText(text string, n int) string {
	return truncateText(redactFreeText(text), n)
}

// redactTruncatePayload is redactTruncateText for byte
// payloads: redact the full payload first, then truncate to
// n bytes with UTF-8 validation, mirroring Python's
// payload[:n].decode("utf-8", "replace").
func redactTruncatePayload(payload []byte, n int) string {
	return truncatePayload([]byte(redactFreeText(string(payload))), n)
}

// redactErrorString strips credentials from an error string
// (item (c), Boss-approved for PR2). It is the shared string
// redactor from internal/redact (redact.String): URL userinfo
// ("<redacted>"), token-like query/fragment parameters,
// cookie-like fragments (including JSON form), and Bearer
// tokens (labelled or bare, token-like values only, so prose
// is untouched). Everything else is left byte-identical, so
// server payload text that carries no credential survives
// redaction. The patterns live in internal/redact only — this
// package keeps no copy, so the two sites cannot drift apart.
// Behaviour is pinned by TestRedactErrorString in this package
// and by TestString in internal/redact.
func redactErrorString(s string) string {
	return redact.String(s)
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
