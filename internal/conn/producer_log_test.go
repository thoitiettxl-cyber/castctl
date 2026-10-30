// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package conn

// Producer-redaction tests for conn's slog lines: the error and
// panic values must be redacted AT THE PRODUCER (slogErr /
// slogPanic), because these lines go through a plain slog
// logger — not the logging bridge — in production wiring. The
// fixture error/panic actually enters the producer functions;
// the capture is scanned for every fixture value on a plain
// text handler, which applies no redaction of its own.

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

const (
	connProducerVMID  = "LOGFIX-VMID-22d9f0"
	connProducerToken = "LOGFIX-HT-2c6e88"
)

func connProducerErr() error {
	return errors.New("down: wss://gateway.example.invalid/v1/noise?vm_id=" + connProducerVMID + "&auth_token=" + connProducerToken)
}

func assertConnProducerRedacted(t *testing.T, got string) {
	t.Helper()
	if got == "" {
		t.Fatal("capture empty: positive control failed")
	}
	for _, v := range []string{connProducerVMID, connProducerToken} {
		if strings.Contains(got, v) {
			t.Errorf("capture contains fixture value %q:\n%s", v, got)
		}
	}
	if !strings.Contains(got, "[redacted]") {
		t.Errorf("capture %q, want a [redacted] marker (positive control)", got)
	}
}

func TestMarkDownLogsRedactedError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m := New(connectorReturning(newFakeGateway()), WithConfig(Config{}), WithLogger(logger))
	// Force the notify branch: the first failure notifies.
	m.downFailLimit = 1
	m.downNotice = 0
	m.markDown(connProducerErr(), true)
	got := buf.String()
	if !strings.Contains(got, "gateway down") {
		t.Fatalf("capture %q, want the gateway-down line (producer not reached)", got)
	}
	assertConnProducerRedacted(t, got)
}

func TestCallNoticeLogsRedactedPanic(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	callNotice(func() {
		panic("notice blew up: " + connProducerErr().Error())
	}, logger, "down notice")
	got := buf.String()
	if !strings.Contains(got, "panicked") {
		t.Fatalf("capture %q, want the panicked-notice line (producer not reached)", got)
	}
	assertConnProducerRedacted(t, got)
}
