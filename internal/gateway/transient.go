package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// IsTransient classifies an error as a transient transport
// failure (S9): the operation may succeed if retried on a fresh
// connection. It is the ONE classification for this decision in
// the gateway; conn.SharedConn's retryCall has its own, narrower
// rule (see doc.go for the recorded unification proposal — conn
// code is not changed here).
//
// Transient: EOF / unexpected EOF, ECONNRESET, ECONNREFUSED,
// ECONNABORTED, ETIMEDOUT, EHOSTUNREACH, ENETUNREACH, EPIPE,
// network timeouts (net.Error Timeout, including os.ErrDeadlineExceeded),
// and temporary/timeout DNS errors.
//
// NEVER transient: nil, context cancellation/deadline (including
// conn.TimeoutError, which unwraps to context.DeadlineExceeded),
// conn.AuthError, and conn.GatewayError (status errors). The
// context check runs first, so a timeout that is really a ctx
// deadline is never misclassified as transient.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var authErr *conn.AuthError
	if errors.As(err, &authErr) {
		return false
	}
	var gwErr *conn.GatewayError
	if errors.As(err, &gwErr) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTemporary || dnsErr.IsTimeout
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNRESET, syscall.ECONNREFUSED, syscall.ECONNABORTED,
			syscall.ETIMEDOUT, syscall.EHOSTUNREACH, syscall.ENETUNREACH,
			syscall.EPIPE:
			return true
		}
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}
