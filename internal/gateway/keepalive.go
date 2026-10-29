// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"time"

	"github.com/gorilla/websocket"
)

// Transport-level WS ping/pong (S4/S5).
//
// The reader goroutine keeps reading, so control frames are
// handled as they arrive. The ping handler below answers every
// ping with a pong through gorilla's WriteControl, which bypasses
// the gateway's ioMu data lock: gorilla serializes all writes on
// its own internal mutex, so a pong waits at most for the single
// frame currently being written, never for a whole multi-chunk
// sendEnvelope. The close handler records the close code/reason
// on the gateway (see LastClose, used by ErrConnectionLost).
//
// Whether the real gateway sends pings, and whether libcurl
// auto-replied to them in Python, is [UNVERIFIED]: it is a
// live-phase measurement (frame log, no secrets), not a claim
// made here. The fake-gateway test uses a fake server that sends
// pings and asserts pongs are answered.
//
// Client-initiated keep-alive pings (StartKeepAlive) are OFF by
// default and are never started by the Connector: sending pings
// would change wire behaviour relative to Python 0.6.1. The
// ticker comes from the gateway's Clock seam, so tests drive it
// with a fake clock.

// controlConn is the control-frame surface of a WebSocket
// connection. gorilla's *websocket.Conn satisfies it; test fakes
// may implement it to observe control traffic. A wsConn that does
// not implement it gets no handlers (pings are then unanswered
// until the connection is read by something that handles them).
type controlConn interface {
	wsConn
	WriteControl(messageType int, data []byte, deadline time.Time) error
	SetPingHandler(h func(appData string) error)
	SetPongHandler(h func(appData string) error)
	SetCloseHandler(h func(code int, text string) error)
}

func (g *Gateway) installControlHandlers(cc controlConn) {
	cc.SetPingHandler(func(appData string) error {
		g.mu.Lock()
		g.lastPingAt = g.clk().Now()
		g.lastPingData = appData
		g.mu.Unlock()
		err := cc.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(5*time.Second))
		if err == websocket.ErrCloseSent {
			return nil
		}
		return err
	})
	cc.SetPongHandler(func(appData string) error {
		g.mu.Lock()
		g.lastPongAt = g.clk().Now()
		g.lastPongData = appData
		g.mu.Unlock()
		return nil
	})
	cc.SetCloseHandler(func(code int, text string) error {
		g.mu.Lock()
		g.closeCode, g.closeReason, g.closeSeen = code, text, true
		g.mu.Unlock()
		// Echo the close frame, as the default gorilla handler
		// does; errors (socket already gone) are ignored.
		_ = cc.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, ""), time.Now().Add(2*time.Second))
		return nil
	})
}

// LastPing returns when the last ping frame arrived and its
// payload, or the zero time when none has arrived.
func (g *Gateway) LastPing() (time.Time, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastPingAt, g.lastPingData
}

// LastPong returns when the last pong frame arrived and its
// payload, or the zero time when none has arrived.
func (g *Gateway) LastPong() (time.Time, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastPongAt, g.lastPongData
}

// LastClose returns the close code and reason recorded by the
// close handler, and whether a close frame was received at all.
// A peer that vanishes without a close frame leaves ok=false;
// ErrConnectionLost then carries the EOF/ECONNRESET/1006
// classification instead.
func (g *Gateway) LastClose() (code int, reason string, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closeCode, g.closeReason, g.closeSeen
}

// StartKeepAlive sends transport-level ping frames every
// interval until ctx ends, the gateway closes, or the reader
// exits. The ticker comes from the gateway's Clock (injectable
// via WithClock), so tests use a fake clock. It is opt-in only:
// the Connector never starts it, and interval <= 0 is a no-op.
// Pings go through WriteControl directly (the S5 control path),
// never through the data/encrypt locks.
func (g *Gateway) StartKeepAlive(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cc, ok := g.ws.(controlConn)
	if !ok {
		return
	}
	go func() {
		ticker := g.clk().NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-g.readerDone:
				return
			case <-ticker.C():
				if g.isClosed() {
					return
				}
				if err := cc.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
					return
				}
				g.mu.Lock()
				g.pingsSent++
				g.mu.Unlock()
			}
		}
	}()
}

// PingsSent returns how many keep-alive pings StartKeepAlive has
// sent on this gateway.
func (g *Gateway) PingsSent() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pingsSent
}
