// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// retryableToday simulates the classification line of
// conn.retryCall (read-only): an AuthError is never retried; a
// *ConnectionDown is retried for every method; a
// *ConnectionError is retried only when the method is safe to
// repeat. Budget, pauses and the reconnect path are not part of
// this simulation — only the error classification, which is what
// an IsTransient unification would replace.
func retryableToday(err error, safe bool) bool {
	var ae *conn.AuthError
	if errors.As(err, &ae) {
		return false
	}
	var down *conn.ConnectionDown
	var connErr *conn.ConnectionError
	return errors.As(err, &down) || (safe && errors.As(err, &connErr))
}

// TestIsTransientUnificationDiverges is the PR3 decision table
// for the S9 unification proposal (one classifier,
// gateway.IsTransient, used by conn.retryCall). VERDICT: DO NOT
// UNIFY — the tables diverge in both directions, so replacing
// retryCall's type check with IsTransient is a behaviour change,
// not a refactor:
//
//   - NARROWING: a safe-method *ConnectionError whose cause is
//     not in IsTransient's list (EINVAL, a plain "connection
//     closed", a WebSocket close error including 1006, a decrypt
//     or parse failure, a permanent DNS error, a wrapped
//     context cancellation) is retried today and would stop
//     being retried. The 1006 row is the S2 loss case itself:
//     unifying would stop retrying safe reads after an
//     abnormal closure.
//   - WIDENING if the type gate were dropped: a bare EOF or
//     net timeout (not a *ConnectionError) is transient by
//     IsTransient but is not retried by retryCall's type check
//     at all.
//   - CONNECTIONDOWN: IsTransient on a *ConnectionDown depends
//     on its cause (generic cause: false; EOF cause: true),
//     while retryCall retries every *ConnectionDown for every
//     method. The Down branch must stay verbatim under any
//     unification.
//   - THE SAFE GATE MUST STAY: IsTransient alone would retry
//     egress.approval.decide (safe=false) on a transient
//     *ConnectionError; only the safe-to-repeat gate keeps
//     decide never-retried. Any future unification must keep
//     both the Down branch and the safe gate byte-identical in
//     behaviour, and must get explicit approval for the
//     narrowing above. Until then this table pins the
//     divergence so a unification attempt fails loudly here
//     instead of silently changing retries.
func TestIsTransientUnificationDiverges(t *testing.T) {
	t.Parallel()
	decide := false // egress.approval.decide is never safe to repeat
	cases := []struct {
		name        string
		err         error
		transient   bool
		todaySafe   bool
		todayUnsafe bool
	}{
		{"nil", nil, false, false, false},
		{"ctx canceled", context.Canceled, false, false, false},
		{"ctx deadline", context.DeadlineExceeded, false, false, false},
		{"timeout error type", &conn.TimeoutError{Message: "slow"}, false, false, false},
		{"auth error", conn.NewAuthError("expired"), false, false, false},
		{"gateway status error", &conn.GatewayError{Status: 500, Payload: "boom"}, false, false, false},
		{"bare eof", io.EOF, true, false, false},
		{"bare net timeout", fakeNetError{timeout: true}, true, false, false},
		{"connerr eof", &conn.ConnectionError{Err: io.EOF}, true, true, false},
		{"connerr reset", &conn.ConnectionError{Err: syscall.ECONNRESET}, true, true, false},
		{"connerr einval", &conn.ConnectionError{Err: syscall.EINVAL}, false, true, false},
		{"connerr plain closed", &conn.ConnectionError{Err: errors.New("gateway connection closed")}, false, true, false},
		{"connerr close 1006", &conn.ConnectionError{Err: &websocket.CloseError{Code: websocket.CloseAbnormalClosure, Text: ""}}, false, true, false},
		{"connerr close 1000", &conn.ConnectionError{Err: &websocket.CloseError{Code: websocket.CloseNormalClosure, Text: "bye"}}, false, true, false},
		{"connerr decrypt failure", &conn.ConnectionError{Err: fmt.Errorf("gateway decrypt failed: %w", errors.New("bad tag"))}, false, true, false},
		{"connerr permanent dns", &conn.ConnectionError{Err: &net.DNSError{Err: "no such host"}}, false, true, false},
		{"connerr temporary dns", &conn.ConnectionError{Err: &net.DNSError{Err: "temp", IsTemporary: true}}, true, true, false},
		{"connerr wrapped ctx canceled", &conn.ConnectionError{Err: context.Canceled}, false, true, false},
		{"connerr os deadline", &conn.ConnectionError{Err: os.ErrDeadlineExceeded}, true, true, false},
		{"connerr phased reset", withPhase(&conn.ConnectionError{Err: fmt.Errorf("recv: %w", syscall.ECONNRESET)}, PhaseStreaming), true, true, false},
		{"connection down generic", conn.NewConnectionDown(errors.New("closed")), false, true, true},
		{"connection down eof cause", conn.NewConnectionDown(io.EOF), true, true, true},
		{"connerr reset unsafe (decide)", &conn.ConnectionError{Err: syscall.ECONNRESET}, true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsTransient(tc.err); got != tc.transient {
				t.Errorf("IsTransient(%v) = %v, want %v", tc.err, got, tc.transient)
			}
			if got := retryableToday(tc.err, true); got != tc.todaySafe {
				t.Errorf("retryableToday(%v, safe=true) = %v, want %v", tc.err, got, tc.todaySafe)
			}
			if got := retryableToday(tc.err, decide); got != tc.todayUnsafe {
				t.Errorf("retryableToday(%v, safe=false) = %v, want %v", tc.err, got, tc.todayUnsafe)
			}
		})
	}
	// The decide row, stated plainly: a transient transport
	// error on egress.approval.decide is never retried, under
	// today's rule or any unification that keeps the gate.
	if retryableToday(&conn.ConnectionError{Err: syscall.ECONNRESET}, decide) {
		t.Error("egress.approval.decide (safe=false) would be retried: the safe gate must never be dropped")
	}
}
