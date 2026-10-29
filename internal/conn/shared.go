// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package conn

import (
	"context"
	"errors"
	"strings"
	"time"
)

// readMethods is the explicit set of POST reads known to be safe to
// repeat after a lost reply (Python _READ_METHODS, ported verbatim).
// Everything else defaults to NOT repeated: repeating a write (or a
// route with unknown semantics) after a lost reply can double-apply
// it. In particular egress.approval.decide is NOT in this set and is
// never repeated on a ConnectionError (see retryCall: a
// ConnectionDown — nothing sent — is still repeated for every
// method, including decide).
var readMethods = map[string]bool{
	"connection.ping":        true,
	"custom_connectors.list": true,
	"fs.list":                true,
	"fs.read":                true,
	"fs.reads":               true,
	"fs.stat":                true,
	"fs.stats":               true,
	"memory.get":             true,
	"node.list":              true,
}

// safeToRepeat reports whether a request only reads, so repeating it
// after a lost reply is harmless: all GET routes, plus the named
// POST reads above. Anything else is NOT repeated — including
// writes whose names merely contain a read word (state.update,
// messenger-read.unlock, widgets.state.*) and routes with unknown
// repeat semantics (shopping.events, subscriptions). When route is
// nil, only the explicit set applies: a GET method whose route is
// unknown to the caller is conservatively treated as unsafe, and
// SharedConn resolves the route through the gateway's LookupRoute
// before deciding (see safeFor). This mirrors Python's
// _safe_to_repeat(method, route), which looks the route up in
// ROUTES when none is passed.
func safeToRepeat(method string, route *Route) bool {
	if route != nil && strings.ToUpper(route.HTTP) == "GET" {
		return true
	}
	return readMethods[method]
}

// SharedConn is what Muse.Connect hands out: the shared connection
// as it is at each call (Python SharedConn). A request on a
// connection that just dropped is repeated on the new one when
// nothing was sent yet or it only reads; subscriptions are opened
// on the current connection (their callers resubscribe on a drop).
//
// SharedConn implements Gateway and Leaser. Lease returns itself;
// Close is a no-op, so a shared warm connection stays up. Alive,
// Dead, LastRecv, LastUsed and LookupRoute observe the CURRENT
// shared gateway without opening a connection.
type SharedConn struct {
	muse *Muse
	cfg  *Config
}

var (
	_ Gateway = (*SharedConn)(nil)
	_ Leaser  = (*SharedConn)(nil)
)

// gw returns the current live gateway, opening (or reopening) it
// when needed.
func (s *SharedConn) gw(ctx context.Context) (Gateway, error) {
	return s.muse.Live(ctx, s.cfg)
}

// Alive reports whether a shared gateway is currently up, without
// opening a connection (Python alive property).
func (s *SharedConn) Alive() bool {
	g := s.muse.sharedSnapshot()
	return g != nil && g.Alive()
}

// Dead returns the current shared gateway's fatal error, or nil.
func (s *SharedConn) Dead() error {
	g := s.muse.sharedSnapshot()
	if g == nil {
		return nil
	}
	return g.Dead()
}

// LastRecv returns the current shared gateway's last-receive stamp,
// or the zero time when there is none.
func (s *SharedConn) LastRecv() time.Time {
	g := s.muse.sharedSnapshot()
	if g == nil {
		return time.Time{}
	}
	return g.LastRecv()
}

// LastUsed returns the current shared gateway's last-send stamp, or
// the zero time when there is none.
func (s *SharedConn) LastUsed() time.Time {
	g := s.muse.sharedSnapshot()
	if g == nil {
		return time.Time{}
	}
	return g.LastUsed()
}

// LookupRoute delegates to the current shared gateway when there is
// one, without opening a connection.
func (s *SharedConn) LookupRoute(method string) (Route, bool) {
	g := s.muse.sharedSnapshot()
	if g == nil {
		return Route{}, false
	}
	return g.LookupRoute(method)
}

// Lease returns itself: a SharedConn already is the no-op-close view.
func (s *SharedConn) Lease() Gateway { return s }

// Close is a no-op: it leaves the shared connection up.
func (s *SharedConn) Close() error { return nil }

// safeFor resolves the safe-to-repeat decision for one call against
// the gateway that will run it, mirroring Python's
// _safe_to_repeat(method, kw.get("route")) with the ROUTES lookup:
// an explicit Route wins; otherwise the gateway's LookupRoute
// supplies it; otherwise only the explicit POST-read set applies.
func (s *SharedConn) safeFor(g Gateway, method string, route *Route) bool {
	if route != nil {
		return safeToRepeat(method, route)
	}
	if r, ok := g.LookupRoute(method); ok {
		return safeToRepeat(method, &r)
	}
	return safeToRepeat(method, nil)
}

// retryCall repeats fn on a new connection while it is safe and time
// remains (Python SharedConn._retry, ported verbatim in structure).
// The retry budget is the sooner of RetryFor and the caller's
// deadline (the absolute deadline in opts.Deadline, or ctx's
// deadline when earlier), so a retry storm cannot push a bounded
// wait past its own bound. Pauses start at 250ms and double to a
// 4s cap. fn is retried when it returns *ConnectionDown (nothing
// was sent), or when safeFor reports the request safe and fn
// returns *ConnectionError (reply possibly lost, but the request
// only reads). *AuthError is never retried: it propagates
// immediately, whether it comes from the reconnect or from fn.
// Every other error type (GatewayError, TimeoutError, ...) is
// returned immediately. Pauses respect ctx cancellation.
func retryCall[T any](ctx context.Context, s *SharedConn, what string, safeFor func(Gateway) bool, deadline time.Time, fn func(context.Context, Gateway) (T, error)) (T, error) {
	var zero T
	m := s.muse
	budget := time.Now().Add(m.retryFor)
	if !deadline.IsZero() && deadline.Before(budget) {
		budget = deadline
	}
	if dl, ok := ctx.Deadline(); ok && dl.Before(budget) {
		budget = dl
	}
	pause := RetryPauseInitial
	for {
		g, err := s.gw(ctx)
		if err != nil {
			var ae *AuthError
			if errors.As(err, &ae) {
				return zero, err
			}
			if time.Now().Add(pause).After(budget) {
				return zero, err
			}
			m.logger.Info("reconnect failed; retrying", "what", what, "err", err)
		} else {
			result, err := fn(ctx, g)
			if err == nil {
				return result, nil
			}
			var ae *AuthError
			if errors.As(err, &ae) {
				return zero, err
			}
			var down *ConnectionDown
			var connErr *ConnectionError
			retryable := errors.As(err, &down) || (safeFor(g) && errors.As(err, &connErr))
			if !retryable || time.Now().Add(pause).After(budget) {
				return zero, err
			}
			m.logger.Info("retrying on a new connection", "what", what, "err", err)
		}
		if !sleepOrDone(ctx, pause) {
			return zero, ctx.Err()
		}
		pause = min(pause*2, RetryPauseMax)
	}
}

// sleepOrDone sleeps for d, returning false when ctx is done first.
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// CallJSON performs one call_json, retried per retryCall when the
// method is safe to repeat (Python SharedConn.call_json). The
// _deadline equivalent is opts.Deadline.
func (s *SharedConn) CallJSON(ctx context.Context, method string, opts RequestOptions) (any, error) {
	return retryCall(ctx, s, method,
		func(g Gateway) bool { return s.safeFor(g, method, opts.Route) },
		opts.Deadline,
		func(ctx context.Context, g Gateway) (any, error) { return g.CallJSON(ctx, method, opts) })
}

// Request performs one request, retried per retryCall when the
// method is safe to repeat (Python SharedConn.request). The
// _deadline equivalent is opts.Deadline.
func (s *SharedConn) Request(ctx context.Context, method string, opts RequestOptions) ([]byte, error) {
	return retryCall(ctx, s, method,
		func(g Gateway) bool { return s.safeFor(g, method, opts.Route) },
		opts.Deadline,
		func(ctx context.Context, g Gateway) ([]byte, error) { return g.Request(ctx, method, opts) })
}

// OpenStream starts a stream, retried per retryCall with safe=false:
// only a ConnectionDown (nothing sent) repeats it (Python
// SharedConn._open, which calls _retry(method, False, ...)).
func (s *SharedConn) OpenStream(ctx context.Context, method string, opts OpenStreamOptions) (int64, error) {
	return retryCall(ctx, s, method,
		func(Gateway) bool { return false },
		time.Time{},
		func(ctx context.Context, g Gateway) (int64, error) { return g.OpenStream(ctx, method, opts) })
}

// DownloadFile downloads a file, retried per retryCall with
// safe=true: downloads are idempotent reads (Python
// SharedConn.download_file, _retry("download", True, ...)). The
// _deadline equivalent is opts.Deadline.
func (s *SharedConn) DownloadFile(ctx context.Context, ref any, opts DownloadOptions) ([]byte, error) {
	return retryCall(ctx, s, "download",
		func(Gateway) bool { return true },
		opts.Deadline,
		func(ctx context.Context, g Gateway) ([]byte, error) { return g.DownloadFile(ctx, ref, opts) })
}

// Ping performs one ping on the current connection, with no retry:
// Python reaches ping through SharedConn.__getattr__ forwarding,
// which does not retry. The caller (heartbeat / stale probe) owns
// reconnect decisions.
func (s *SharedConn) Ping(ctx context.Context, timeout time.Duration) (any, error) {
	g, err := s.gw(ctx)
	if err != nil {
		return nil, err
	}
	return g.Ping(ctx, timeout)
}

// CancelStream ends a stream opened by OpenStream, with no retry
// (Python reaches _cancel through __getattr__ forwarding).
func (s *SharedConn) CancelStream(ctx context.Context, streamID int64) error {
	g, err := s.gw(ctx)
	if err != nil {
		return err
	}
	return g.CancelStream(ctx, streamID)
}

// SubscribeRaw opens a subscription on the current connection. Only
// a connection that is down before the stream opens is retried
// here, at most MaxSubscribeAttempts attempts in total, with a
// fixed SubscribeRetryPause between attempts (Python
// SharedConn.subscribe_raw). Any other error — including a
// ConnectionDown raised after the stream opened, which the gateway
// must surface as *ConnectionError instead — propagates at once.
// An AuthError from opening the connection propagates at once.
func (s *SharedConn) SubscribeRaw(ctx context.Context, method string, opts SubscribeOptions) ([][]byte, error) {
	var lastErr error
	for attempt := 0; attempt < MaxSubscribeAttempts; attempt++ {
		if attempt > 0 && !sleepOrDone(ctx, SubscribeRetryPause) {
			return nil, ctx.Err()
		}
		g, err := s.gw(ctx)
		if err != nil {
			// AuthError first, mirroring retryCall: an
			// AuthError wrapped in a ConnectionDown must
			// propagate at once, never retry.
			var ae *AuthError
			if errors.As(err, &ae) {
				return nil, err
			}
			var down *ConnectionDown
			if errors.As(err, &down) && attempt < MaxSubscribeAttempts-1 {
				lastErr = err
				continue
			}
			return nil, err
		}
		records, err := g.SubscribeRaw(ctx, method, opts)
		if err == nil {
			return records, nil
		}
		var ae *AuthError
		if errors.As(err, &ae) {
			return nil, err
		}
		var down *ConnectionDown
		if errors.As(err, &down) && attempt < MaxSubscribeAttempts-1 {
			lastErr = err
			continue
		}
		return nil, err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, NewConnectionDown(nil)
}

// SubscribeJSON opens a subscription and returns decoded records,
// with no conn-level retry: Python reaches subscribe_json through
// SharedConn.__getattr__ forwarding, which does not retry (the
// gateway's own subscribe_json drops bad JSON lines).
func (s *SharedConn) SubscribeJSON(ctx context.Context, method string, opts SubscribeOptions) ([]any, error) {
	g, err := s.gw(ctx)
	if err != nil {
		return nil, err
	}
	return g.SubscribeJSON(ctx, method, opts)
}
