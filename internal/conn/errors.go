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
type AuthError struct {
	// Message is the human-readable cause. It must not contain a
	// cookie, token, or auth-bearing URL.
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

// GatewayError reports a server-side failure: a non-2xx status, a
// stream reset, a non-JSON or {"ok":false} response. Status is the
// HTTP-like status, or -1 when there is none (reset, non-JSON).
// Payload is the server payload, truncated by the gateway to 500
// bytes before construction (Python: payload[:500]); it must never
// contain a credential.
//
// This mirrors Python's gateway.GatewayError(status, payload).
type GatewayError struct {
	Status  int
	Payload string
}

func (e *GatewayError) Error() string {
	return fmt.Sprintf("conn: gateway status=%d payload=%q", e.Status, e.Payload)
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
