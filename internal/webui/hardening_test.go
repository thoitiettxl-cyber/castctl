// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// doReq is do with explicit headers (Origin, RemoteAddr) for the
// hardening tests. httptest.NewRequest defaults RemoteAddr to
// 192.0.2.1:1234; tests that need a distinct client set it.
func (ts *testServer) doReq(t *testing.T, method, path, body string, authed bool, headers map[string]string, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, reader)
	}
	if authed {
		req.Header.Set("Authorization", "Bearer "+testToken)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)
	return rec
}

func TestOriginAllowlist(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	cases := []struct {
		name    string
		origin  string
		host    string
		allowed bool
	}{
		{"absent origin (non-browser)", "", "", true},
		{"loopback origin", "http://127.0.0.1:8317", "", true},
		{"loopback localhost origin", "http://localhost:9999", "", true},
		{"loopback ipv6 origin", "http://[::1]:8317", "", true},
		{"same-host origin", "http://127.0.0.1:8317", "127.0.0.1:8317", true},
		{"same-host other port", "http://127.0.0.1:4000", "127.0.0.1:8317", true},
		{"remote origin", "https://evil.example", "", false},
		{"remote ip origin", "http://203.0.113.10:8317", "", false},
		{"userinfo loopback origin", "http://evil.com@127.0.0.1:8317", "", false},
		{"userinfo same-host origin", "http://user@127.0.0.1:8317", "127.0.0.1:8317", false},
		{"opaque null origin", "null", "", false},
		{"malformed origin", "://bad", "", false},
		{"origin without host", "http://", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.origin != "" {
				headers["Origin"] = tc.origin
			}
			// POST /config/validate with a valid body: an
			// allowed request reaches the handler (200); a
			// rejected one stops at the middleware (403).
			rec := ts.doReq(t, "POST", "/api/v1/config/validate", `{"default_profile":"muse01","profiles":{"muse01":{}}}`, true, headers, "")
			if tc.host != "" {
				// Same-host cases need the request Host to
				// match: re-run with Host set. doReq builds
				// the request from the path, so Host comes
				// from the URL; use a full-URL request here.
				req := httptest.NewRequest("POST", "http://"+tc.host+"/api/v1/config/validate", strings.NewReader(`{"default_profile":"muse01","profiles":{"muse01":{}}}`))
				req.Header.Set("Authorization", "Bearer "+testToken)
				req.Header.Set("Origin", tc.origin)
				rec = httptest.NewRecorder()
				ts.handler.ServeHTTP(rec, req)
			}
			if tc.allowed && rec.Code == http.StatusForbidden {
				t.Fatalf("origin %q: got 403, want allowed (status %d, body %s)", tc.origin, rec.Code, rec.Body.String())
			}
			if !tc.allowed && rec.Code != http.StatusForbidden {
				t.Fatalf("origin %q: got %d, want 403 (body %s)", tc.origin, rec.Code, rec.Body.String())
			}
			if !tc.allowed {
				if strings.Contains(rec.Body.String(), tc.origin) && tc.origin != "" {
					t.Fatalf("403 body echoes the origin: %s", rec.Body.String())
				}
			}
		})
	}
	// Reads are exempt: a remote Origin on GET passes the
	// middleware (auth still gates).
	rec := ts.doReq(t, "GET", "/api/v1/status", "", true, map[string]string{"Origin": "https://evil.example"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET with remote origin: got %d, want 200", rec.Code)
	}
}

func TestOriginRunsAfterAuth(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	// A cross-origin request WITHOUT a valid token gets 401,
	// not 403: auth runs first, so the Origin check never leaks
	// anything to an unauthenticated caller.
	rec := ts.doReq(t, "POST", "/api/v1/config/validate", `{}`, false, map[string]string{"Origin": "https://evil.example"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated cross-origin POST: got %d, want 401", rec.Code)
	}
}

func TestAPISecurityHeaders(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/status"},
		{"POST", "/api/v1/config/validate"},
		{"GET", "/api/v1/nope"},
	} {
		body := ""
		if tc.method == "POST" {
			body = `{}`
		}
		rec := ts.doReq(t, tc.method, tc.path, body, true, nil, "")
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s %s: Cache-Control = %q, want no-store", tc.method, tc.path, got)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s %s: X-Content-Type-Options = %q, want nosniff", tc.method, tc.path, got)
		}
	}
	// The unauthenticated shell carries the same headers.
	rec := ts.doReq(t, "GET", "/", "", false, nil, "")
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("shell: Cache-Control = %q, want no-store", got)
	}
}

func TestStatusIdleTimeoutField(t *testing.T) {
	// Default when the webui block carries no key: the
	// fixture config has no webui block at all.
	ts := newTestServer(t, fixtureConfig, nil)
	rec := ts.do(t, "GET", "/api/v1/status", "", true)
	env := decodeEnvelope(t, rec)
	data, ok := env["data"].(map[string]any)
	if !ok {
		t.Fatalf("status envelope: %s", rec.Body.String())
	}
	secs, ok := data["session_idle_timeout_seconds"].(float64)
	if !ok || secs != 43200 {
		t.Fatalf("session_idle_timeout_seconds = %v, want 43200 (12h)", data["session_idle_timeout_seconds"])
	}
	// Configured value wins.
	cfg := strings.Replace(fixtureConfig, `"dns":`, `"webui":{"token":"MARKER-WEBUI-TOKEN","session_idle_timeout":"6h"},"dns":`, 1)
	ts2 := newTestServer(t, cfg, nil)
	rec2 := ts2.do(t, "GET", "/api/v1/status", "", true)
	data2 := decodeEnvelope(t, rec2)["data"].(map[string]any)
	if secs, ok := data2["session_idle_timeout_seconds"].(float64); !ok || secs != 21600 {
		t.Fatalf("configured session_idle_timeout_seconds = %v, want 21600 (6h)", data2["session_idle_timeout_seconds"])
	}
}

func TestLoginRateLimiterUnit(t *testing.T) {
	now := time.Now()
	l := &loginRateLimiter{now: func() time.Time { return now }}
	attempts, window := 3, 5*time.Minute
	addr := "127.0.0.1"
	if l.exceeded(addr, attempts, window) {
		t.Fatal("empty limiter reports exceeded")
	}
	l.recordFailure(addr, window)
	l.recordFailure(addr, window)
	if l.exceeded(addr, attempts, window) {
		t.Fatal("2 failures report exceeded at a budget of 3")
	}
	l.recordFailure(addr, window)
	if !l.exceeded(addr, attempts, window) {
		t.Fatal("3 failures do not report exceeded at a budget of 3")
	}
	// A further failure does not change the verdict, and the
	// 429 check itself never counts: exceeded is read-only.
	if !l.exceeded(addr, attempts, window) {
		t.Fatal("exceeded flipped after a read-only check")
	}
	// Success resets.
	l.recordSuccess(addr)
	if l.exceeded(addr, attempts, window) {
		t.Fatal("success did not reset the counter")
	}
	// Window expiry resets.
	l.recordFailure(addr, window)
	now = now.Add(5 * time.Minute)
	if l.exceeded(addr, attempts, window) {
		t.Fatal("expired window still counts")
	}
	l.recordFailure(addr, window)
	if l.exceeded(addr, attempts, window) {
		t.Fatal("one failure in a fresh window reports exceeded")
	}
	// A failure after expiry starts a fresh window (count 1,
	// not 1 + stale count).
	now = now.Add(5 * time.Minute)
	l.recordFailure(addr, window)
	l.recordFailure(addr, window)
	if l.exceeded(addr, attempts, window) {
		t.Fatal("stale failures leaked into the fresh window")
	}
}

func TestLoginRateLimiterFailClosedAtCap(t *testing.T) {
	// The cap fails closed (F1 regression): a flood of distinct
	// addresses inside the window must never evict a limited
	// address's entry and reset its budget. Only expired
	// entries are evicted to make room.
	now := time.Now()
	l := &loginRateLimiter{now: func() time.Time { return now }}
	attempts, window := 5, 5*time.Minute
	victim := "192.0.2.1"
	for i := 0; i < attempts; i++ {
		l.recordFailure(victim, window)
	}
	if !l.exceeded(victim, attempts, window) {
		t.Fatal("victim not limited after 5 failures")
	}
	for i := 0; i < maxRateLimitEntries*2; i++ {
		l.recordFailure("10.0.0."+strconv.Itoa(i), window)
	}
	l.mu.Lock()
	n := len(l.entries)
	_, victimKept := l.entries[victim]
	l.mu.Unlock()
	if n > maxRateLimitEntries {
		t.Fatalf("entries = %d, want at most %d", n, maxRateLimitEntries)
	}
	if !victimKept {
		t.Fatal("victim entry was evicted at the cap: the flood reset its budget")
	}
	if !l.exceeded(victim, attempts, window) {
		t.Fatal("victim no longer limited after the flood: still 429 within the window")
	}
	// Expired entries ARE evicted to make room for a new
	// address once the window passes.
	now = now.Add(window)
	l.recordFailure("203.0.113.1", window)
	l.mu.Lock()
	_, newKept := l.entries["203.0.113.1"]
	l.mu.Unlock()
	if !newKept {
		t.Fatal("new address was not inserted after expired entries were evicted")
	}
}

func TestLoginRateLimitHTTP(t *testing.T) {
	// Configured 2 attempts / 1s window, so the test runs in
	// ~1s of real time.
	cfg := strings.Replace(fixtureConfig, `"dns":`, `"webui":{"token":"MARKER-WEBUI-TOKEN","login_rate_limit":{"attempts":2,"window":"1s"}},"dns":`, 1)
	ts := newTestServer(t, cfg, nil)
	bad := func() *httptest.ResponseRecorder {
		return ts.doToken(t, "GET", "/api/v1/status", "", "WRONG-TOKEN")
	}
	if rec := bad(); rec.Code != http.StatusUnauthorized {
		t.Fatalf("failure 1: got %d, want 401", rec.Code)
	}
	if rec := bad(); rec.Code != http.StatusUnauthorized {
		t.Fatalf("failure 2: got %d, want 401", rec.Code)
	}
	rec := bad()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("failure 3: got %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1 (the 1s window)", got)
	}
	if !strings.Contains(rec.Body.String(), "rate_limited") {
		t.Fatalf("429 body lacks the rate_limited type: %s", rec.Body.String())
	}
	// A good token is still gated while over the limit...
	if rec := ts.do(t, "GET", "/api/v1/status", "", true); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("good token while limited: got %d, want 429", rec.Code)
	}
	// ...until the window expires, after which it succeeds
	// and resets the counter.
	time.Sleep(1100 * time.Millisecond)
	if rec := ts.do(t, "GET", "/api/v1/status", "", true); rec.Code != http.StatusOK {
		t.Fatalf("good token after window: got %d, want 200", rec.Code)
	}
	if rec := bad(); rec.Code != http.StatusUnauthorized {
		t.Fatalf("failure after reset: got %d, want 401 (counter reset)", rec.Code)
	}
	// A distinct remote address has its own budget.
	rec = ts.doReq(t, "GET", "/api/v1/status", "", false, nil, "198.51.100.7:9999")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("other address failure: got %d, want 401", rec.Code)
	}
}
