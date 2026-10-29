// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"syscall"

	"github.com/gorilla/websocket"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// ErrConnectionLost reports that the transport died mid-flight
// (S2, CLIProxyAPI's turn-loss error): the socket went away, the
// turn did NOT get replayed, and the caller must re-observe state
// (resubscribe + server_check in wait, PR4) rather than treat the
// loss as a request rejection. It is built ONLY from EOF,
// ECONNRESET, and WebSocket close code 1006 (abnormal closure):
// status/policy close codes and gateway status errors stay fatal
// and are never classified here, and AuthError is never a
// connection loss. It wraps the *conn.ConnectionError that killed
// the reader, so errors.As still finds ConnectionError (and
// conn.SharedConn's retry classification is unchanged); use
// AsConnectionLost to recover this type.
type ErrConnectionLost struct {
	// NotSent is true only when the gateway died before any
	// frame send was attempted on it. A send that was
	// attempted but failed counts as sent: the frame may
	// already be on the wire, and the reader can classify
	// the death before the writer's post-write bookkeeping
	// runs, so only a pre-write mark is race-free (see
	// sendEnvelope).
	NotSent bool
	// StreamIDs are the streams that were open when the
	// connection died.
	StreamIDs []int64
	// CloseCode/CloseReason are the WebSocket close code and
	// reason recorded by the close handler, when the peer sent
	// a close frame (0/"", false, when it did not).
	CloseCode   int
	CloseReason string
	CloseSeen   bool
	// Cause is the reader error that killed the connection
	// (a *conn.ConnectionError).
	Cause error
}

// Error renders the loss, including the affected stream ids.
func (e *ErrConnectionLost) Error() string {
	return fmt.Sprintf("gateway connection lost (streams %v, notSent=%v): %v", e.StreamIDs, e.NotSent, e.Cause)
}

// Unwrap exposes the underlying *conn.ConnectionError.
func (e *ErrConnectionLost) Unwrap() error { return e.Cause }

// AsConnectionLost reports whether err is (or wraps) an
// ErrConnectionLost.
func AsConnectionLost(err error) (*ErrConnectionLost, bool) {
	var lost *ErrConnectionLost
	if errors.As(err, &lost) {
		return lost, true
	}
	return nil, false
}

// classifyConnectionLost inspects a reader error and reports
// whether it is a connection loss, with the close code/reason
// when a WebSocket close frame carried them. Only EOF (including
// io.ErrUnexpectedEOF, the EOF family gorilla surfaces when the
// peer's TCP socket vanishes), ECONNRESET, and close 1006
// qualify; every other error, including close 1000 and decrypt
// or parse failures, returns ok=false.
func classifyConnectionLost(err error) (closeCode int, closeReason string, ok bool) {
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		if ce.Code == websocket.CloseAbnormalClosure {
			return ce.Code, ce.Text, true
		}
		return 0, "", false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return 0, "", true
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return 0, "", true
	}
	return 0, "", false
}

// classifyDeadLocked builds the gateway's dead error from a
// reader error. It must be called with g.mu held: it snapshots
// the open stream ids and the recorded close info. A connection
// loss becomes an ErrConnectionLost wrapping the original
// *conn.ConnectionError; anything else is returned unchanged.
func (g *Gateway) classifyDeadLocked(err error) error {
	code, reason, ok := classifyConnectionLost(err)
	if !ok {
		return err
	}
	ids := make([]int64, 0, len(g.streams))
	for sid := range g.streams {
		ids = append(ids, sid)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if g.closeSeen {
		code, reason = g.closeCode, g.closeReason
		// A recorded close frame with a non-1006 code means
		// the peer closed cleanly: not a loss. The handler
		// only records codes the peer actually sent, and a
		// 1006 is never sent as a frame (it is synthesized
		// by the library), so a recorded code other than 0
		// (no frame) or 1006 overrides the EOF/ECONNRESET
		// classification.
		if code != 0 && code != websocket.CloseAbnormalClosure {
			return err
		}
	}
	// Preserve the ConnectionError type for conn's retry
	// classification: err is already a *conn.ConnectionError
	// from readFrame (or a panic wrapper); if it is not one,
	// wrap it so Unwrap always yields a ConnectionError.
	cause := err
	var connErr *conn.ConnectionError
	if !errors.As(err, &connErr) {
		cause = &conn.ConnectionError{Err: err}
	}
	return &ErrConnectionLost{
		NotSent:     !g.sentAny,
		StreamIDs:   ids,
		CloseCode:   code,
		CloseReason: reason,
		CloseSeen:   g.closeSeen,
		Cause:       cause,
	}
}
