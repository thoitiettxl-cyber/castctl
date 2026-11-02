// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Login rate limiting (Design A): a stdlib fixed-window counter,
// in-memory and bounded, over failed Bearer token verifications
// per remote address. There is no login endpoint: the "login" is
// any /api/v1 request presenting a token, and a failed
// verification is any 401 from requireAuth. chi's
// middleware.Throttle is NOT a rate limiter (it bounds
// concurrency, not attempts over time) and is never used here.
//
// Behaviour: `attempts` failed verifications inside one `window`
// (both from the effective `webui.login_rate_limit` config, see
// profile.EffectiveLoginRateLimit) put the address over the
// limit: further requests get a fixed 429 with
// Retry-After set to the window in seconds (300 at the 5m
// default) until the window expires. A successful verification
// resets the address's counter immediately. The counter is
// keyed by the host part of RemoteAddr (the port varies per
// connection); on a loopback-only server every browser client
// shares 127.0.0.1/::1, so the limit is effectively per server,
// which is the intended shape: a local brute-force prober and
// the operator share the loopback, and the window is short.
//
// The store is bounded (maxRateLimitEntries addresses) and fails
// closed at the cap: recording a failure for a new address when
// the store is full first evicts only entries whose window has
// expired; when none has expired the failure is dropped without
// inserting, so a flood of distinct addresses can never evict a
// limited address's entry and reset its budget. Entries are
// pruned lazily on each check: an expired window is dropped,
// never counted. No failure or address is ever logged: this
// package never logs.

const maxRateLimitEntries = 1024

// rateWindow is one address's fixed window: the failures counted
// since windowStart.
type rateWindow struct {
	count       int
	windowStart time.Time
}

// loginRateLimiter is the fixed-window store. The zero value is
// usable; now is overridable in tests.
type loginRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateWindow
	now     func() time.Time
}

func (l *loginRateLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// exceeded reports whether addr is currently over the limit: at
// least `attempts` failures inside the current window. An
// expired window is pruned and does not count. Exceeded never
// mutates the count: the 429 itself is not a failed verification.
func (l *loginRateLimiter) exceeded(addr string, attempts int, window time.Duration) bool {
	if attempts < 1 || window <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.entries[addr]
	if !ok {
		return false
	}
	if l.clock().Sub(w.windowStart) >= window {
		delete(l.entries, addr)
		return false
	}
	return w.count >= attempts
}

// recordFailure counts one failed verification for addr. A
// failure outside the current window starts a fresh window
// with count 1. When addr is new and the store is full, only
// expired entries are evicted; if none has expired the failure
// is dropped without inserting, so the store fails closed at
// the cap instead of evicting a limited address's entry (see
// the package note).
func (l *loginRateLimiter) recordFailure(addr string, window time.Duration) {
	if window <= 0 {
		return
	}
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = map[string]*rateWindow{}
	}
	w, ok := l.entries[addr]
	if !ok {
		if len(l.entries) >= maxRateLimitEntries {
			l.pruneExpiredLocked(now, window)
			if len(l.entries) >= maxRateLimitEntries {
				return
			}
		}
		l.entries[addr] = &rateWindow{count: 1, windowStart: now}
		return
	}
	if now.Sub(w.windowStart) >= window {
		w.count = 1
		w.windowStart = now
		return
	}
	w.count++
}

// pruneExpiredLocked drops entries whose window ended at or
// before now. The caller holds the mutex.
func (l *loginRateLimiter) pruneExpiredLocked(now time.Time, window time.Duration) {
	for addr, w := range l.entries {
		if now.Sub(w.windowStart) >= window {
			delete(l.entries, addr)
		}
	}
}

// recordSuccess resets addr's counter: one good token proves
// the address is not probing.
func (l *loginRateLimiter) recordSuccess(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, addr)
}

// clientKey is the rate-limit key for a request: the host part
// of RemoteAddr, or the whole value when it has no port.
func clientKey(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// loginLimits resolves the effective rate-limit pair from the
// currently stored config, so an edit through the API takes
// effect without restart. Any load or parse failure falls back
// to the documented defaults: the limit is defence in depth
// and must never break authentication when the config file is
// unreadable (requireAuth still gates on the live comparator).
func (s *Server) loginLimits() (attempts int, window time.Duration) {
	return profile.EffectiveLoginRateLimit(s.currentWebUIConfig())
}

// loginRateLimit is the outermost /api/v1 middleware (pinned
// order: rate-limit → auth → Origin → timeout). An over-limit
// address gets a fixed 429 with Retry-After; every other
// request passes through untouched. It never records anything:
// requireAuth records failures and resets on success, so the
// 429 and the screencast WebSocket (which has no Bearer check)
// never feed the counter. The WebSocket upgrade does pass
// through this middleware, so an over-limit address gets a
// 429 on the upgrade too until its window expires; that is
// the documented Design A shape (docs/security.md), not an
// exemption.
func (s *Server) loginRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts, window := s.loginLimits()
		if s.rateLimiter.exceeded(clientKey(r), attempts, window) {
			w.Header().Set("Retry-After", retryAfterSeconds(window))
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many failed login attempts")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// retryAfterSeconds renders a window as whole seconds for
// Retry-After, at least 1: a sub-second configured window
// still tells the client to wait.
func retryAfterSeconds(window time.Duration) string {
	secs := int(window / time.Second)
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}
