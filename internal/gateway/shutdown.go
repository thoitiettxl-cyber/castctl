// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"sync"
	"time"

	pb "github.com/thoitiettxl-cyber/castctl/internal/proto"
)

// CloseBound bounds the best-effort reset sends in Shutdown: 2s,
// the same bound Close allows for the I/O lock.
const CloseBound = 2 * time.Second

// Shutdown cancels every open stream and then closes the gateway
// (S11). It is the gateway-local half of root-ctx cancellation:
// one root ctx per CLI invocation (signal.NotifyContext) is
// cmd/PR4 wiring, not this package's. On ctx cancellation, the
// caller calls Shutdown: each open stream gets a stream-level
// Reset{CANCELLED} (Python _cancel), best-effort within
// CloseBound (or the ctx deadline when it is sooner and still in
// the future — an already-cancelled ctx still gets the full
// bound, best-effort), and then the socket closes.
//
// Shutdown NEVER sends chat.cancel: the repo rule is explicit
// (Ctrl-C in wait must not send chat.cancel; only `stop` does).
// Python's close() itself sends no resets; Shutdown is an
// addition for explicit cancellation paths only, and must not be
// called from normal teardown. Send failures are swallowed, as
// in Python's _cancel, and Shutdown is safe to call on a dead
// gateway (it just closes). Best-effort limit: the resets are
// written to the socket, but if unread inbound data is still
// buffered when the socket closes, the kernel may send RST
// instead of FIN and the peer may never read them. Production
// wait paths drain inbound continuously, so this bites only
// callers that opened streams and never read; tests drain
// explicitly before asserting server-side receipt.
func (g *Gateway) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if g.Alive() {
		streams := g.openStreams()
		if len(streams) > 0 {
			bound := CloseBound
			if dl, ok := ctx.Deadline(); ok {
				if remain := time.Until(dl); remain > 0 && remain < bound {
					bound = remain
				}
			}
			done := make(chan struct{})
			go func() {
				var wg sync.WaitGroup
				for _, s := range streams {
					wg.Add(1)
					go func(s openStreamInfo) {
						defer wg.Done()
						g.cancelStream(s.id, s.service)
					}(s)
				}
				wg.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-g.clk().After(bound):
			}
		}
	}
	return g.Close()
}

// openStreamInfo is one open stream, for Shutdown's snapshot.
type openStreamInfo struct {
	id      int64
	service pb.ServiceType
}

// openStreams snapshots the currently open streams with their
// services.
func (g *Gateway) openStreams() []openStreamInfo {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]openStreamInfo, 0, len(g.streams))
	for sid, svc := range g.services {
		if _, ok := g.streams[sid]; ok {
			out = append(out, openStreamInfo{id: sid, service: svc})
		}
	}
	return out
}
