// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// apiTimeout is the 30s context-timeout middleware on non-WS API
// handlers (loop-2 F4). The screencast WebSocket is excluded: a
// context timeout would kill live login sessions.

func TestAPIHandlerTimeoutDefault(t *testing.T) {
	if apiHandlerTimeout != 30*time.Second {
		t.Fatalf("apiHandlerTimeout = %v, want 30s", apiHandlerTimeout)
	}
}

func TestAPIHandlerTimeoutCutsOffSlowHandler(t *testing.T) {
	old := apiHandlerTimeout
	apiHandlerTimeout = 20 * time.Millisecond
	defer func() { apiHandlerTimeout = old }()

	// Handler that waits for cancellation, then writes 200.
	waiting := (&Server{}).apiTimeout(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	start := time.Now()
	waiting.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("slow handler took %v", elapsed)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "timeout") {
		t.Fatalf("body = %s, want a timeout envelope", rec.Body.String())
	}

	// Handler that ignores its context entirely.
	ignoring := (&Server{}).apiTimeout(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	rec = httptest.NewRecorder()
	start = time.Now()
	ignoring.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("ignoring handler took %v", elapsed)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503: %s", rec.Code, rec.Body.String())
	}
}

func TestAPIHandlerTimeoutSkipsScreencastWS(t *testing.T) {
	old := apiHandlerTimeout
	apiHandlerTimeout = 20 * time.Millisecond
	defer func() { apiHandlerTimeout = old }()
	slow := (&Server{}).apiTimeout(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("live"))
	}))
	rec := httptest.NewRecorder()
	slow.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/screencast/ws", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "live" {
		t.Fatalf("WS path: code = %d, body = %q, want 200/live", rec.Code, rec.Body.String())
	}
}

func TestAPIHandlerTimeoutPassesThroughFastHandler(t *testing.T) {
	h := (&Server{}).apiTimeout(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("fast"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if rec.Code != http.StatusCreated || rec.Body.String() != "fast" || rec.Header().Get("X-Test") != "yes" {
		t.Fatalf("fast handler: code = %d, body = %q, headers = %v", rec.Code, rec.Body.String(), rec.Header())
	}
}

func TestAPIHandlerTimeoutPropagatesPanic(t *testing.T) {
	h := (&Server{}).apiTimeout(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("panic not propagated to the outer recoverer")
		} else if !strings.Contains(fmt.Sprint(r), "boom") {
			t.Fatalf("recovered %v, want boom", r)
		}
	}()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
}
