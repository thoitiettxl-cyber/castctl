// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package conn is the shared, self-healing gateway connection manager.
//
// One multiplexed gateway connection carries every request, download and
// subscription of a process. Muse keeps that connection warm, pings it
// when it has been quiet, and reopens it transparently when it drops.
// Callers get a SharedConn that always uses the current connection and
// repeats a request on a new one when that is safe.
//
// Boundary with internal/gateway (read before writing either package):
//
//   - internal/conn owns connection lifecycle only: the shared slot,
//     bounded connect, the stale-connection probe, the heartbeat
//     goroutine, down/up notices, retry across reconnects, and the
//     safe-to-repeat decision. It never dials, never performs TLS or
//     Noise handshakes, never frames or parses protobuf envelopes, and
//     never reads bytes from a socket.
//   - internal/gateway owns the wire: it receives already-dialled
//     net.Conn values from internal/outbound's Dialer, performs the
//     WebSocket/Noise handshake on them, and owns the ONE reader
//     goroutine that demultiplexes frames into per-stream queues.
//     No other package may read frames from a gateway connection.
//     internal/conn must never start a second reader: it observes a
//     gateway only through the Gateway interface (Alive, Dead,
//     LastRecv, LastUsed, Ping).
//   - The Gateway interface in this package is the CONSUMER-side
//     contract. internal/gateway implements it; internal/conn consumes
//     it. W-gateway must implement every method, including LookupRoute
//     (backed by routes.json) and the ConnectionDown-only-before-open
//     rule for SubscribeRaw, or retry parity silently degrades (see
//     Gateway and safeToRepeat).
//
// All deadlines, backoffs, watchdogs and heartbeat intervals use the
// monotonic clock (time.Now / context.WithTimeout). Wall-clock time is
// never used for a duration. No network I/O happens while holding a
// conn lock: _open runs outside the shared lock, gateway Close calls
// happen outside locks, and the stale probe pings outside the lock
// (a deliberate, documented difference from Python's in-lock probe;
// see Live).
//
// No secrets (cookies, tokens, auth URLs) are ever logged or put in
// error strings by this package. Error values from a Connector may
// carry a server payload snippet; this package logs them verbatim
// only in the down notice, exactly as Python does, and never logs a
// Config.
package conn
