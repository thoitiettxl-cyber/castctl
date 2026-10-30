// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"net/url"
	"os"
	"syscall"
)

// Typed transport-error summary (loop 6, item 2). A transport
// error's printed form must carry NO peer text: Go's HTTP stack
// embeds the offending wire bytes in its errors (a malformed
// header line, a malformed status line, a TLS alert), and the
// old redactErr/SafeString fallback passed that text through
// verbatim to error strings and log lines. The fallback is
// replaced, at the HTTP transport sites, by a typed summary:
// operation, error class, and net-error kind only.
//
// The original error stays reachable through Unwrap, so
// classification is unchanged: errors.As/Is still find
// *url.Error, *net.OpError, syscall.Errno, context deadline /
// cancellation, and net.Error timeouts, and IsTransient keeps
// working. Only the rendered text is summarised. Local
// (non-transport) errors keep redactErr: their text is
// producer-controlled constants, not peer bytes.

// transportError is a transport failure rendered as a typed
// summary. op names the operation (method + host + path, never
// a query string or fragment); class/kind come from
// classifyTransportError.
type transportError struct {
	op    string
	class string
	kind  string
	err   error
}

func (e *transportError) Error() string {
	return fmt.Sprintf("gateway: %s failed (class=%s kind=%s)", e.op, e.class, e.kind)
}

// Unwrap exposes the original transport error for classification.
func (e *transportError) Unwrap() error { return e.err }

// wrapTransportError wraps a transport error in its typed
// summary. A nil error stays nil.
func wrapTransportError(op string, err error) error {
	if err == nil {
		return nil
	}
	class, kind := classifyTransportError(err)
	return &transportError{op: op, class: class, kind: kind, err: err}
}

// transportOp derives the operation label for an HTTP call from
// its method and URL: method + host + path, with the query
// string, fragment, and userinfo dropped (a URL in an error
// string is itself a leak vector when it carries credentials).
func transportOp(method, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return method + " request"
	}
	return method + " " + u.Host + u.EscapedPath()
}

// classifyTransportError maps a transport error to (class,
// kind) from its TYPE only — never from its text, which may
// embed peer bytes. Order matters: *url.Error itself
// satisfies net.Error, so the timeout check must come before
// any generic net.Error branch, and the OpError/errno checks
// must come before the response-parse check.
func classifyTransportError(err error) (class, kind string) {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled", "context"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout", "deadline"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout", "net_timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return "dns", "dns_timeout"
		}
		return "dns", "dns"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "network", opErrorKind(opErr.Op)
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errnoClassKind(errno)
	}
	var protoErr textproto.ProtocolError
	if errors.As(err, &protoErr) {
		return "transport", "response_parse"
	}
	var recErrPtr *tls.RecordHeaderError
	if errors.As(err, &recErrPtr) {
		return "tls", "tls"
	}
	var certErrPtr *tls.CertificateVerificationError
	if errors.As(err, &certErrPtr) {
		return "tls", "tls"
	}
	if errors.As(err, &ne) {
		return "network", "net_error"
	}
	return "transport", "unknown"
}

// opErrorKind reduces a *net.OpError Op to a stable kind label.
func opErrorKind(op string) string {
	switch op {
	case "dial", "read", "write", "accept", "listen", "connect":
		return op
	default:
		return "network_op"
	}
}

// errnoClassKind maps a syscall errno to (class, kind).
func errnoClassKind(errno syscall.Errno) (string, string) {
	switch errno {
	case syscall.ETIMEDOUT:
		return "timeout", "etimedout"
	case syscall.ECONNREFUSED:
		return "network", "connection_refused"
	case syscall.ECONNRESET:
		return "network", "connection_reset"
	case syscall.EPIPE:
		return "network", "broken_pipe"
	case syscall.EHOSTUNREACH:
		return "network", "host_unreachable"
	case syscall.ENETUNREACH:
		return "network", "network_unreachable"
	default:
		return "network", "syscall"
	}
}
