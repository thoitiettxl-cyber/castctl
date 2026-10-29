// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
	pb "github.com/thoitiettxl-cyber/muse-cli/go/internal/proto"
	"google.golang.org/protobuf/proto"
)

// queuedItem is one delivery to a stream queue: a frame, or the
// fatal error that killed the reader. generation tags the frame
// with the gateway generation at delivery time (S6); error items
// carry generation 0 and are never filtered.
type queuedItem struct {
	frame      *pb.ServiceFrame
	err        error
	generation uint64
}

// streamQueue is an unbounded per-stream queue. Python's
// queue.Queue never blocks its producer (the reader); a bounded
// Go channel would stall the single reader when a tracked stream
// is abandoned, so the queue is a slice guarded by a condition
// variable instead. get waits until an item arrives, the deadline
// passes, or ctx is done.
type streamQueue struct {
	mu    sync.Mutex
	cond  *sync.Cond
	items []queuedItem
}

func newStreamQueue() *streamQueue {
	q := &streamQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *streamQueue) put(item queuedItem) {
	q.mu.Lock()
	q.items = append(q.items, item)
	q.mu.Unlock()
	q.cond.Broadcast()
}

func (q *streamQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// errQueueEmpty reports that get waited until its deadline with no
// item. It is an internal sentinel, never returned from a Gateway
// method.
var errQueueEmpty = errors.New("gateway: stream queue empty")

// get waits for one item until deadline, or until ctx is done. It
// returns (item, nil), (zero, errQueueEmpty) on deadline expiry, or
// (zero, ctx.Err()) when ctx ends first. Frames tagged with a
// generation OLDER than the current generation are dropped: they
// belong to a replaced gateway incarnation (S6). Error items are
// never dropped.
//
// generation is a provider, re-read on every wait iteration —
// never a snapshot taken at entry: a bump that lands while the
// wait is in flight must not strand the waiter dropping the new
// incarnation's frames (F7). Only strictly older generations are
// dropped, so a frame tagged with a newer generation than the
// provider's current value is delivered. A nil provider, or a
// zero current/item generation, disables filtering.
func (q *streamQueue) get(ctx context.Context, deadline time.Time, generation func() uint64) (queuedItem, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	// Wake the waiter when ctx ends, without holding the lock in
	// the callback (Broadcast does not require it).
	stop := context.AfterFunc(ctx, func() { q.cond.Broadcast() })
	defer stop()
	var timer *time.Timer
	if !deadline.IsZero() {
		if d := time.Until(deadline); d > 0 {
			timer = time.AfterFunc(d, func() { q.cond.Broadcast() })
			defer timer.Stop()
		}
	}
	for {
		if len(q.items) > 0 {
			item := q.items[0]
			q.items = q.items[1:]
			var current uint64
			if generation != nil {
				current = generation()
			}
			if item.frame != nil && current != 0 && item.generation != 0 && item.generation < current {
				continue
			}
			return item, nil
		}
		if err := ctx.Err(); err != nil {
			return queuedItem{}, err
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return queuedItem{}, errQueueEmpty
		}
		q.cond.Wait()
	}
}

// --- stream bookkeeping -----------------------------------------------

func (g *Gateway) isClosed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed
}

func (g *Gateway) queueFor(sid int64) *streamQueue {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.streams[sid]
}

func (g *Gateway) forget(sid int64) {
	g.mu.Lock()
	delete(g.streams, sid)
	delete(g.services, sid)
	g.mu.Unlock()
}

func (g *Gateway) touchUsed() {
	g.mu.Lock()
	g.lastUsed = time.Now()
	g.mu.Unlock()
}

func (g *Gateway) touchRecv() {
	g.mu.Lock()
	g.lastRecv = time.Now()
	g.mu.Unlock()
}

// downError reports why the gateway is down, preserving the
// dead error's chain (so errors.As can still find an
// ErrConnectionLost behind a ConnectionDown) instead of
// stringifying it away.
func (g *Gateway) downError() error {
	if dead := g.Dead(); dead != nil {
		return fmt.Errorf("gateway connection is down: %w", dead)
	}
	return errors.New("gateway connection is down (closed)")
}

func (g *Gateway) isDown() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed || g.dead != nil
}

// uuidV4 renders a random UUID (x-request-id header), using
// crypto/rand only — no extra dependency.
func uuidV4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read on crypto/rand effectively never fails; fall
		// back to a time-based value rather than an empty id.
		n := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(n >> (uint(i%8) * 8))
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// buildPath substitutes {k} path params (URL-quoted with safe="",
// so "/" is escaped too) and appends the query string.
func buildPath(template string, pathParams map[string]string, query map[string]string) string {
	path := template
	for k, v := range pathParams {
		path = strings.ReplaceAll(path, "{"+k+"}", quotePython(v, ""))
	}
	if len(query) > 0 {
		vals := url.Values{}
		for k, v := range query {
			vals.Set(k, v)
		}
		qs := vals.Encode()
		if qs != "" {
			if strings.Contains(path, "?") {
				path += "&" + qs
			} else {
				path += "?" + qs
			}
		}
	}
	return path
}

// resolveRoute picks the route for a call: an explicit Route wins;
// otherwise the table lookup; unknown methods are a
// *ValidationError.
func (g *Gateway) resolveRoute(method string, override *conn.Route) (conn.Route, error) {
	if override != nil {
		return *override, nil
	}
	if r, ok := g.routes.LookupRoute(method); ok {
		return r, nil
	}
	return conn.Route{}, &ValidationError{Message: fmt.Sprintf("unknown method: %q", method)}
}

// open starts a stream: it checks the connection is up BEFORE
// building or sending anything (Python N5: OpenStream returns
// *ConnectionDown when dead or closed), allocates the stream id,
// registers the queue when track is true, and sends the
// ApplicationRequest envelope. On send failure the stream is
// forgotten and the send error is returned.
func (g *Gateway) open(method string, pathParams map[string]string, body any, query map[string]string, routeOverride *conn.Route, track bool) (int64, conn.Route, error) {
	if g.isDown() {
		return 0, conn.Route{}, conn.NewConnectionDown(g.downError())
	}
	route, err := g.resolveRoute(method, routeOverride)
	if err != nil {
		return 0, conn.Route{}, err
	}
	raw, err := encodeBody(body)
	if err != nil {
		return 0, conn.Route{}, err
	}
	req := &pb.ApplicationRequest{
		Verb:    route.HTTP,
		Path:    buildPath(route.Path, pathParams, query),
		Body:    raw,
		EndBody: true,
		Headers: []*pb.Header{
			{Key: "x-request-id", Value: uuidV4()},
		},
	}
	if len(raw) > 0 {
		req.Headers = append(req.Headers, &pb.Header{Key: "content-type", Value: "application/json"})
	}
	g.mu.Lock()
	sid := g.nextStream
	g.nextStream++
	if track {
		g.streams[sid] = newStreamQueue()
	}
	if g.services == nil {
		g.services = make(map[int64]pb.ServiceType)
	}
	g.services[sid] = serviceID(route.Service)
	g.mu.Unlock()
	frameBytes, err := proto.Marshal(&pb.ServiceFrame{
		StreamId: sid,
		Kind:     &pb.ServiceFrame_Request{Request: req},
	})
	if err != nil {
		g.forget(sid)
		return 0, conn.Route{}, &conn.ConnectionError{Err: fmt.Errorf("gateway: marshal service frame: %w", err)}
	}
	g.touchUsed()
	if err := g.sendEnvelope(serviceID(route.Service), frameBytes); err != nil {
		g.forget(sid)
		return 0, conn.Route{}, err
	}
	return sid, route, nil
}

// next waits for the next frame on a stream. A missing queue is a
// ConnectionError ("stream is not open"); a dead gateway with an
// empty queue is a ConnectionError before waiting; a queued fatal
// error is a ConnectionError wrapping it; a deadline expiry is
// errQueueEmpty; ctx cancellation returns ctx.Err().
func (g *Gateway) next(ctx context.Context, sid int64, timeout time.Duration) (*pb.ServiceFrame, error) {
	q := g.queueFor(sid)
	if q == nil {
		return nil, &conn.ConnectionError{Err: errors.New("stream is not open")}
	}
	if g.Dead() != nil && q.len() == 0 {
		// Preserve the dead error's chain: stringifying it
		// here would hide an ErrConnectionLost from
		// errors.As (the queued error item may not have
		// been delivered yet when Dead is already set).
		return nil, &conn.ConnectionError{Err: fmt.Errorf("gateway connection is down: %w", g.Dead())}
	}
	item, err := q.get(ctx, time.Now().Add(timeout), g.currentGeneration)
	if err != nil {
		return nil, err
	}
	if item.err != nil {
		return nil, &conn.ConnectionError{Err: fmt.Errorf("gateway connection lost: %w", item.err)}
	}
	return item.frame, nil
}

// cancelStream forgets a stream and, when the gateway is alive,
// sends the CANCELLED reset (code 1). Send failures are swallowed,
// as in Python's _cancel. It never returns *ConnectionDown.
func (g *Gateway) cancelStream(sid int64, service pb.ServiceType) {
	g.forget(sid)
	if !g.Alive() {
		return
	}
	frameBytes, err := proto.Marshal(&pb.ServiceFrame{
		StreamId: sid,
		Kind:     &pb.ServiceFrame_Reset_{Reset_: &pb.Reset{Code: pb.Reset_CANCELLED}},
	})
	if err != nil {
		return
	}
	_ = g.sendEnvelope(service, frameBytes)
}

// serviceFor returns the service stored for sid at open() time, or
// false when the stream was never opened (or was already
// forgotten). The read happens before forget: cancelStream
// deletes the entry, so callers must read first.
func (g *Gateway) serviceFor(sid int64) (pb.ServiceType, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	svc, ok := g.services[sid]
	return svc, ok
}

// cancelStreamFor forgets a stream and sends its CANCELLED reset
// on the service stored at open(); an unknown stream id defaults
// to daemon, as Python's _cancel(service=0) does.
func (g *Gateway) cancelStreamFor(sid int64) {
	svc, ok := g.serviceFor(sid)
	if !ok {
		svc = pb.ServiceType_SERVICE_DAEMON
	}
	g.cancelStream(sid, svc)
}

// --- conn.Gateway state methods --------------------------------------

// LookupRoute returns the route for a method from routes.json, or
// false when the method is unknown.
func (g *Gateway) LookupRoute(method string) (conn.Route, bool) {
	return g.routes.LookupRoute(method)
}

// Alive reports whether the connection is up: not closed and no
// fatal reader error.
func (g *Gateway) Alive() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.closed && g.dead == nil
}

// Dead returns the fatal error that killed the reader goroutine, or
// nil when the gateway is healthy or was closed cleanly.
func (g *Gateway) Dead() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.dead
}

// LastRecv returns the monotonic time of the last frame received.
func (g *Gateway) LastRecv() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastRecv
}

// LastUsed returns the monotonic time of the last send.
func (g *Gateway) LastUsed() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastUsed
}

// Close closes the connection. It is idempotent and safe to call
// concurrently with a blocked call: it marks the gateway closed,
// delivers a ConnectionError to every live stream queue, and closes
// the socket (which unblocks the reader promptly), waits up to 1s
// for the reader goroutine, then waits up to 2s for the I/O lock
// before returning anyway.
func (g *Gateway) Close() error {
	g.closeOnce.Do(func() {
		g.mu.Lock()
		g.closed = true
		queues := make([]*streamQueue, 0, len(g.streams))
		for _, q := range g.streams {
			queues = append(queues, q)
		}
		g.mu.Unlock()
		closedErr := &conn.ConnectionError{Err: errors.New("gateway connection closed")}
		for _, q := range queues {
			q.put(queuedItem{err: closedErr})
		}
		_ = g.ws.Close()
		select {
		case <-g.readerDone:
		case <-g.clk().After(time.Second):
		}
		done := make(chan struct{})
		go func() {
			g.ioMu.Lock()
			g.ioMu.Unlock()
			close(done)
		}()
		select {
		case <-done:
		case <-g.clk().After(2 * time.Second):
		}
	})
	return nil
}

// Lease returns a no-op-close view of this gateway, so code that
// calls Close when done leaves a shared warm connection up.
func (g *Gateway) Lease() conn.Gateway {
	return &leaseGateway{gw: g}
}
