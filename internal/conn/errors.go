// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package conn

import (
	"context"
	"errors"
	"fmt"
)

// AuthError reports an authentication failure: expired or unparseable
// cookies, a rejected auth/check or hatch/token call. It passes through
// BoundedConnect, Muse.Live and SharedConn retry unwrapped-typed:
// errors.As must find *AuthError in the returned chain, and it is never
// retried and never counted as a down notice. Connectors MUST return
// *AuthError (via NewAuthError) for auth failures, not a profile or
// transport error type, or the pass-through contract breaks.
//
// This mirrors Python's gateway.AuthError.
//
// Loop 5 (allowlist rule): Message is an allowlist summary ONLY
// (endpoint, status, body length, content-type, parsed enum
// fields) — never server body bytes. Producers construct it
// through the gateway's allowlist summary or from constants.
// Error() renders Message VERBATIM: it is not itself a
// summary, and a Message built elsewhere with body bytes
// WOULD leak through a direct Error() print. Safety rests on
// both halves: producer discipline (allowlist summaries /
// constants only) AND every output rendering (classifyError,
// logs) going through logging.SummarizeErr, which prefers
// LogSummary (class + message length, no message bytes)
// whenever the AuthError is reachable in the error chain.
// Direct printing of an AuthError is forbidden; the CLI
// boundary is pinned by TestLoop6ClassifyErrorAuthBoundary
// (loop 6, item 6d), which drives a marker-carrying Message
// through classifyError and asserts marker-free output.
type AuthError struct {
	// Message is the human-readable cause. It must not contain a
	// cookie, token, or auth-bearing URL — and, under the
	// loop-5 allowlist rule, no server body bytes either.
	Message string
}

// NewAuthError builds an *AuthError. Prefer it over constructing the
// struct so call sites stay greppable.
func NewAuthError(message string) *AuthError { return &AuthError{Message: message} }

func (e *AuthError) Error() string {
	if e == nil {
		return "conn: auth error"
	}
	return "conn: " + e.Message
}

// LogSummary renders the error for log lines at EVERY level
// including trace (loop-5 ruling: no body bytes at trace
// either): the error class plus the length of the message
// carried by the error, and no message bytes at all.
// AuthError carries no separate status field or body-length
// field (its message embeds the endpoint and status in prose),
// so the summary carries the class and the message length.
// This satisfies the logging.LogSummary interface
// structurally — logging must not import conn (conn imports
// logging), so no shared interface type exists.
func (e *AuthError) LogSummary() string {
	if e == nil {
		return "conn: auth_failed message_length=0"
	}
	return fmt.Sprintf("conn: auth_failed message_length=%d", len(e.Message))
}

// GatewayError reports a server-side failure: a non-2xx status, a
// stream reset, a non-JSON or {"ok":false} response. Status is the
// HTTP-like status, or -1 when there is none (reset, non-JSON).
//
// Loop 5 (allowlist rule): Payload is an allowlist SUMMARY
// string only (class label, body length, content-type, parsed
// enum fields) — never raw server body bytes. Producers build
// it through the gateway's allowlist summary. Payload is
// internal state: it is NEVER rendered. The only renderings
// are Error() and LogSummary(), both allowlist summaries.
// BodyLength is the wire byte length of the body summarized,
// when the producer knows it; BodyLengthKnown says whether
// BodyLength is known at all (loop 8, F1): a known 0-byte
// body renders body_length=0, while an unknown length
// renders NO body_length field — never the length of the
// summary text. ContentType is the validated media type
// (parameters stripped) when known, "" when not.
// ErrorCode is a validated short error enum parsed by key
// from a known response schema, "" when none was extracted.
// ContentType/ErrorCode are validated AGAIN at render time:
// a value that fails the allowlist shape is omitted, so a
// hand-built struct cannot smuggle body text into a rendering.
//
// This mirrors Python's gateway.GatewayError(status, payload);
// Python parity on the raw payload bytes is EXPLICITLY WAIVED
// by the loop-5 ruling (only the bytes are removed — the
// status, the error kind, and retry semantics are unchanged).
type GatewayError struct {
	Status          int
	Payload         string
	BodyLength      int
	BodyLengthKnown bool
	ContentType     string
	ErrorCode       string
}

// lengthField renders the body_length field for Error() /
// LogSummary(): " body_length=N" when the wire length is
// known (including a known 0), "" when it is unknown. There
// is no fallback to the summary-text length (loop 8, F1):
// an unknown length is absent, not mislabelled.
func (e *GatewayError) lengthField() string {
	if e.BodyLengthKnown {
		return fmt.Sprintf(" body_length=%d", e.BodyLength)
	}
	return ""
}

// isAllowlistEnum reports whether s is an emittable enum
// value: 1-64 runes of letters, digits, underscore, dot, or
// hyphen — the same shape the gateway's allowlist extraction
// enforces at construction (see internal/gateway/summary.go).
func isAllowlistEnum(s string) bool {
	n := 0
	for _, r := range s {
		n++
		if n > 64 {
			return false
		}
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return n > 0
}

// isAllowlistContentType reports whether s is an emittable
// media type: type/subtype, each side token characters, no
// parameters, no whitespace, no controls, and at most 64 runes
// in total — the SAME cap the gateway's construction-side
// validation enforces (loop 6, item 6a: one cap everywhere;
// the old 129-byte render-time bound would have emitted a
// 65–129 byte media type the constructor had replaced with
// the placeholder).
func isAllowlistContentType(s string) bool {
	slash := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '/' {
			if slash >= 0 {
				return false
			}
			slash = i
			continue
		}
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '!' || c == '#' || c == '$' || c == '&' || c == '^' || c == '_' || c == '.' || c == '+' || c == '-' || c == '|' || c == '~') {
			return false
		}
	}
	if slash <= 0 || slash >= len(s)-1 || len([]rune(s)) > 64 {
		return false
	}
	return true
}

func (e *GatewayError) Error() string {
	if e == nil {
		return "conn: gateway status=0 body_length=0"
	}
	out := fmt.Sprintf("conn: gateway status=%d", e.Status) + e.lengthField()
	if isAllowlistContentType(e.ContentType) {
		out += " content_type=" + e.ContentType
	}
	if isAllowlistEnum(e.ErrorCode) {
		out += " error=" + e.ErrorCode
	}
	return out
}

// LogSummary renders the error for log lines at EVERY level
// including trace (loop-5 ruling): the status code, the error
// class, the body length when known (no field when unknown —
// loop 8, F1), and the validated content-type /
// error-enum fields when present — and no payload bytes at
// all. It is identical to Error() by construction: both are
// the allowlist summary. This satisfies the logging.LogSummary
// interface structurally; see AuthError's LogSummary for why
// no shared interface type exists.
func (e *GatewayError) LogSummary() string {
	if e == nil {
		return "conn: gateway status=0 body_length=0"
	}
	return e.Error()
}

// ConnectionDown reports that the connection was already down when a
// request was made: nothing was sent, so the request is safe to repeat
// on a new connection. Gateway implementations MUST return
// *ConnectionDown (possibly wrapped with %w) only for failures that
// happened before anything was sent on the wire, and MUST NOT return
// it for failures after a stream opened. SharedConn retries a
// ConnectionDown for every method, safe or not.
//
// This mirrors Python's gateway.ConnectionDown.
type ConnectionDown struct {
	// Err is the underlying cause, or nil when unknown.
	Err error
}

// NewConnectionDown builds a *ConnectionDown wrapping err (nil allowed).
func NewConnectionDown(err error) *ConnectionDown { return &ConnectionDown{Err: err} }

func (e *ConnectionDown) Error() string {
	if e == nil || e.Err == nil {
		return "conn: connection down"
	}
	return fmt.Sprintf("conn: connection down: %v", e.Err)
}

// Unwrap exposes the underlying cause for errors.Is/As.
func (e *ConnectionDown) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ConnectionError reports a transport failure after a request was
// sent or a stream opened: the reply may have been lost, so repeating
// the request may double-apply it. SharedConn retries a
// *ConnectionError only when the request is safe to repeat (see
// safeToRepeat). Gateway implementations MUST map in-flight transport
// failures to *ConnectionError and MUST NOT return bare net errors
// from Gateway methods, or retry classification is lost.
//
// This mirrors Python's builtin ConnectionError as raised by
// Gateway._next/_write after a send.
type ConnectionError struct {
	// Err is the underlying cause, or nil when unknown.
	Err error
}

func (e *ConnectionError) Error() string {
	if e == nil || e.Err == nil {
		return "conn: connection error"
	}
	return fmt.Sprintf("conn: connection error: %v", e.Err)
}

// LogSummary renders the error for log lines at EVERY level
// including trace (loop-6 ruling, item 1): a body-carrying
// error in the chain renders as its LogSummary, and every
// other cause renders as the class plus the byte length of
// its text only — never the cause's prose, which may be
// peer-controlled (a WebSocket close reason reaches this
// type through the gateway reader). This satisfies the
// logging.LogSummary interface structurally; see
// AuthError's LogSummary for why no shared interface type
// exists. Error() is unchanged: it still renders the cause
// for callers that need it, and producers that wrap
// peer-controlled causes (the gateway's close summary) keep
// Error() marker-free too.
func (e *ConnectionError) LogSummary() string {
	if e == nil || e.Err == nil {
		return "conn: connection error"
	}
	var s interface{ LogSummary() string }
	if errors.As(e.Err, &s) {
		return s.LogSummary()
	}
	return fmt.Sprintf("conn: connection error error_length=%d", len(e.Err.Error()))
}

// Unwrap exposes the underlying cause for errors.Is/As.
func (e *ConnectionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// TimeoutError reports an expired wait for a response: the gateway
// opened a stream but no response arrived before the deadline, and
// BoundedConnect reports a connect that exceeded its bound. It unwraps
// to context.DeadlineExceeded so errors.Is(err,
// context.DeadlineExceeded) works. It is never retried by SharedConn.
//
// This mirrors Python's TimeoutError as raised by Gateway.request and
// bounded_connect.
type TimeoutError struct {
	// Message describes what timed out. It must not contain a secret.
	Message string
}

func (e *TimeoutError) Error() string {
	if e == nil {
		return "conn: timeout"
	}
	return "conn: " + e.Message
}

// Unwrap exposes context.DeadlineExceeded for errors.Is.
func (e *TimeoutError) Unwrap() error { return context.DeadlineExceeded }

// errHeartbeatFailed is the mark-down cause when the heartbeat ping
// fails. It carries no detail on purpose: the ping error is logged at
// the drop site, not in the down state.
var errHeartbeatFailed = errors.New("heartbeat failed")

// errGatewayClosed is the mark-down cause when a shared gateway is
// found closed with no fatal error recorded.
var errGatewayClosed = errors.New("closed")

// errNoConnector is returned when a Muse has no Connector configured.
var errNoConnector = errors.New("conn: no connector configured")
