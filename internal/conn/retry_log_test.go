// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package conn

// Retry-event tests: retryCall must log each retry ONCE, at
// debug, with a 1-based attempt counter, the method name, and the
// error redacted at the emission site. An AuthError must produce
// zero retry lines and exactly one call.
//
// What the test observes: slog text output captured through
// WithLogger, driven by a fake gateway under a fake clock
// (synctest), so the 250ms-doubling pause ladder costs no wall
// time. What the red run catches: Info-level lines (visible at
// the default level), a missing/0-based attempt counter, and a
// fixture-carrying error reaching the capture unredacted.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

const (
	retryLogVMID  = "LOGFIX-VMID-22d9f0"
	retryLogToken = "LOGFIX-HT-2c6e88"
)

func retryFixtureErr() error {
	return fmt.Errorf("down: wss://gateway.example.invalid/v1/noise?vm_id=%s&auth_token=%s", retryLogVMID, retryLogToken)
}

func TestRetryCallLogsAttemptCounterRedacted(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		gw := newFakeGateway()
		gw.routes = fakeRoutes()
		calls := 0
		gw.callFn = func(method string, opts RequestOptions) (any, error) {
			calls++
			if calls <= 2 {
				return nil, NewConnectionDown(retryFixtureErr())
			}
			return map[string]any{"ok": true}, nil
		}
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		m := New(connectorReturning(gw), WithConfig(Config{}), WithLogger(logger))
		sc := &SharedConn{muse: m}
		got, err := sc.CallJSON(context.Background(), "fs.read",
			RequestOptions{Deadline: time.Now().Add(30 * time.Second), Route: &Route{Method: "fs.read", HTTP: "POST"}})
		if err != nil {
			t.Fatalf("CallJSON() error = %v", err)
		}
		if got.(map[string]any)["ok"] != true {
			t.Fatalf("CallJSON() = %v, want ok", got)
		}
		if calls != 3 {
			t.Fatalf("calls = %d, want 3", calls)
		}
		out := buf.String()
		// Exactly two retry lines, attempts 1 then 2, in order.
		if n := strings.Count(out, "retrying on a new connection"); n != 2 {
			t.Fatalf("capture %q: %d retry lines, want 2", out, n)
		}
		i1 := strings.Index(out, "attempt=1")
		i2 := strings.Index(out, "attempt=2")
		if i1 < 0 || i2 < 0 || i1 > i2 {
			t.Errorf("capture %q, want attempt=1 before attempt=2", out)
		}
		if !strings.Contains(out, "what=fs.read") {
			t.Errorf("capture %q, want what=fs.read", out)
		}
		// The retry lines themselves must be DEBUG, not INFO
		// (other lifecycle lines, e.g. "gateway connected",
		// keep their own levels and are out of scope here).
		for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
			if strings.Contains(line, "retrying on a new connection") && !strings.Contains(line, "level=DEBUG") {
				t.Errorf("retry line not at DEBUG: %q", line)
			}
		}
		// Hard rule: no fixture value from the wrapped error.
		for _, v := range []string{retryLogVMID, retryLogToken} {
			if strings.Contains(out, v) {
				t.Errorf("capture contains fixture value %q:\n%s", v, out)
			}
		}
	})
}

func TestRetryCallAuthErrorLogsNothing(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		gw := newFakeGateway()
		gw.routes = fakeRoutes()
		calls := 0
		gw.callFn = func(method string, opts RequestOptions) (any, error) {
			calls++
			return nil, NewAuthError("expired")
		}
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		m := New(connectorReturning(gw), WithConfig(Config{}), WithLogger(logger))
		sc := &SharedConn{muse: m}
		_, err := sc.CallJSON(context.Background(), "fs.read",
			RequestOptions{Deadline: time.Now().Add(30 * time.Second), Route: &Route{Method: "fs.read", HTTP: "POST"}})
		var ae *AuthError
		if !errors.As(err, &ae) {
			t.Fatalf("CallJSON() error = %v, want *AuthError", err)
		}
		if calls != 1 {
			t.Fatalf("calls = %d, want 1 (no retry)", calls)
		}
		if strings.Contains(buf.String(), "retrying") {
			t.Errorf("capture %q, want zero retry lines for AuthError", buf.String())
		}
	})
}
