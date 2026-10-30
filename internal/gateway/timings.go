// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import "time"

// HandshakeTimings reports how long each connect phase took, in
// whole milliseconds (item (b), per-phase timeouts). The phases
// are timed separately so PR3's `profile test` can surface the
// first stuck phase:
//
//   - DialMS: the outbound dialer's WebSocketDial call. DNS, proxy
//     connect and TLS happen inside the dialer, which exposes no
//     sub-phase timings, so they are reported combined here and
//     DNSMS/TLSMS are -1 (unavailable), never 0-as-measured.
//   - WSMS: the WebSocket upgrade over the dialled conn, bounded
//     separately by WSUpgradeTimeout.
//   - NoiseMS: the Noise XX handshake, bounded separately by
//     HandshakeTimeout (the Noise bound, 20s as in Python).
//
// A zero DialMS/WSMS/NoiseMS means the gateway was not built
// through the Connector (e.g. constructed directly in a test).
// TLS session resumption is OFF by default (Boss decision (d)):
// no session cache is configured anywhere in this package — TLS
// lives inside the outbound dialer, and the dialer's cache state
// is recorded in the report, not configured here.
type HandshakeTimings struct {
	DialMS  int64
	WSMS    int64
	NoiseMS int64
	DNSMS   int64
	TLSMS   int64
}

// HandshakeTimings returns the per-phase connect timings recorded
// when the Connector built this gateway.
func (g *Gateway) HandshakeTimings() HandshakeTimings {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.timings
}

// WSUpgradeTimeout bounds the WebSocket upgrade separately from
// the Noise handshake (20s, the same bound Python's ws.connect
// uses, but a separate constant so each phase is observable and
// tunable on its own).
const WSUpgradeTimeout = 20 * time.Second
