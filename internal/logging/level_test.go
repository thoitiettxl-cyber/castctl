// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package logging_test

// Loop-4 (d) level-gated body tests: server response bodies
// never reach a log emission above trace. Above trace an error
// carrying a body renders as status code + error class + body
// length only; at trace it renders as the redacted-then-truncated
// body. The seams are the production ones: the slog bridge
// (NewSlogLogger + factory capture) and the level-aware error
// renderer (SummarizeErr / SafeErrForLevel). Fixture values are
// literals here, never recomputed from the code under test.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	singlog "github.com/sagernet/sing-box/log"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

const levelBodyPayload = "plain body words BODYFIX-9d2e41 with no secret label" // 52 bytes

// TestSummarizeErr renders the above-trace summary for each
// body-carrying error kind, plus the fallback for other errors
// and the errors.As walk through wrappers.
func TestSummarizeErr(t *testing.T) {
	t.Parallel()
	gw := &conn.GatewayError{Status: 500, Payload: levelBodyPayload}
	if got := logging.SummarizeErr(gw); got != "conn: gateway status=500 body_length=52" {
		t.Errorf("SummarizeErr(GatewayError) = %q, want the status/class/length literal", got)
	}
	ae := conn.NewAuthError("hatch/token -> 403 " + levelBodyPayload)
	if got := logging.SummarizeErr(ae); got != "conn: auth_failed message_length=71" {
		t.Errorf("SummarizeErr(AuthError) = %q, want the class/length literal", got)
	}
	wrapped := fmt.Errorf("outer: %w", gw)
	if got := logging.SummarizeErr(wrapped); got != "conn: gateway status=500 body_length=52" {
		t.Errorf("SummarizeErr(wrapped GatewayError) = %q, want the summary through the wrapper", got)
	}
	connWrapped := &conn.ConnectionError{Err: gw}
	if got := logging.SummarizeErr(connWrapped); got != "conn: gateway status=500 body_length=52" {
		t.Errorf("SummarizeErr(ConnectionError wrapping GatewayError) = %q, want the inner summary", got)
	}
	plain := errors.New("connection refused")
	if got := logging.SummarizeErr(plain); got != "connection refused" {
		t.Errorf("SummarizeErr(plain) = %q, want the redacted plain text", got)
	}
	if got := logging.SummarizeErr(nil); got != "" {
		t.Errorf("SummarizeErr(nil) = %q, want empty", got)
	}
}

// TestSafeErrForLevel: at EVERY level including trace, an
// error carrying a body renders the summary only (loop-5
// ruling supersedes the loop-4 trace allowance for the
// redacted-then-truncated body).
func TestSafeErrForLevel(t *testing.T) {
	t.Parallel()
	gw := &conn.GatewayError{Status: 500, Payload: `{"token": "LOGFIX-LEVEL-83af10"} and ` + strings.Repeat("tailword ", 200)}
	for _, level := range []singlog.Level{singlog.LevelTrace, singlog.LevelDebug, singlog.LevelInfo, singlog.LevelWarn, singlog.LevelError} {
		got := logging.SafeErrForLevel(gw, level)
		if strings.Contains(got, "tailword") || strings.Contains(got, "LOGFIX-LEVEL") {
			t.Errorf("level %v rendering %q carries body bytes", level, got)
		}
		if !strings.Contains(got, "status=500") || !strings.Contains(got, "body_length=") {
			t.Errorf("level %v rendering %q, want status + class + length only", level, got)
		}
	}
}

// TestSlogBridgeAboveTraceSummarizesBody drives a GatewayError
// through the real slog bridge at info level: the captured line
// carries status + class + length and no body bytes.
func TestSlogBridgeAboveTraceSummarizesBody(t *testing.T) {
	var buf bytes.Buffer
	h, err := logging.NewFactory(context.Background(), logging.Settings{Level: "info"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	logger := h.SlogLogger("castctl")
	gw := &conn.GatewayError{Status: 500, Payload: levelBodyPayload}
	logger.Info("gateway probe", "err", gw)
	got := buf.String()
	if got == "" {
		t.Fatal("capture empty: positive control failed (line suppressed, not summarised)")
	}
	if strings.Contains(got, "BODYFIX-9d2e41") || strings.Contains(got, "plain body words") {
		t.Errorf("info capture %q carries server body bytes above trace", got)
	}
	if !strings.Contains(got, "status=500") || !strings.Contains(got, "body_length=52") {
		t.Errorf("info capture %q, want status=500 and body_length=52", got)
	}
}

// TestSlogBridgeTraceSummarizesBody drives the same shape
// through the bridge at trace level (a slog level below Debug
// maps to sing-box trace): the captured line carries the
// allowlist summary, exactly as above trace — no body bytes
// at trace either (loop-5 ruling).
func TestSlogBridgeTraceSummarizesBody(t *testing.T) {
	var buf bytes.Buffer
	h, err := logging.NewFactory(context.Background(), logging.Settings{Level: "trace"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	logger := h.SlogLogger("castctl")
	payload := `{"token": "LOGFIX-LEVELTRACE-83af10"} and ` + strings.Repeat("tailword ", 200)
	gw := &conn.GatewayError{Status: 500, Payload: payload}
	logger.Log(context.Background(), slog.LevelDebug-4, "trace-body-probe", "err", gw)
	got := buf.String()
	if !strings.Contains(got, "trace-body-probe") {
		t.Fatalf("capture %q, want the trace probe line (level mapping or suppression?)", got)
	}
	if strings.Contains(got, "LOGFIX-LEVELTRACE-83af10") || strings.Contains(got, "tailword") {
		t.Errorf("trace capture %q carries body bytes", got)
	}
	if !strings.Contains(got, "status=500") || !strings.Contains(got, "body_length=") {
		t.Errorf("trace capture %q, want status + class + length only", got)
	}
}

// TestSlogBridgeWarnSummarizesAuthError: an AuthError at warn
// level renders class + length only, with no body bytes.
func TestSlogBridgeWarnSummarizesAuthError(t *testing.T) {
	var buf bytes.Buffer
	h, err := logging.NewFactory(context.Background(), logging.Settings{Level: "warn"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	logger := h.SlogLogger("castctl")
	ae := conn.NewAuthError("hatch/token -> 403 " + levelBodyPayload)
	logger.Warn("auth probe", "err", ae)
	got := buf.String()
	if got == "" {
		t.Fatal("capture empty: positive control failed")
	}
	if strings.Contains(got, "BODYFIX-9d2e41") || strings.Contains(got, "plain body words") {
		t.Errorf("warn capture %q carries server body bytes above trace", got)
	}
	if !strings.Contains(got, "auth_failed") || !strings.Contains(got, "message_length=") {
		t.Errorf("warn capture %q, want class + length only", got)
	}
}
