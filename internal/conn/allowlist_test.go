// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package conn

// Loop-5 allowlist tests for slogPanic: a recovered panic
// value is arbitrary (possibly peer/server) text. It must
// render as class + length only — never verbatim — whether
// it is a string, an error carrying a body, or any other
// value, and the callNotice slog line carrying it must be
// free of the marker too.

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

const panicMarker = "ALLOW5PANIC-9d2e41"

func TestSlogPanicAllowlist(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		r    any
	}{
		{"string marker", "plain panic words " + panicMarker},
		{"gateway error panic", &GatewayError{Status: 500, Payload: "plain body words " + panicMarker}},
		{"plain error panic", errPanicPlain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := slogPanic(tc.r)
			if got == "" {
				t.Fatal("slogPanic empty: positive control failed")
			}
			if strings.Contains(got, panicMarker) || strings.Contains(got, "plain body words") || strings.Contains(got, "plain panic words") {
				t.Errorf("slogPanic(%#v) = %q carries panic/body bytes", tc.r, got)
			}
		})
	}
	// Positive controls: class + length are present.
	if got := slogPanic("plain panic words " + panicMarker); !strings.Contains(got, "panic_length=") {
		t.Errorf("slogPanic(string) = %q, want panic_length", got)
	}
	if got := slogPanic(&GatewayError{Status: 500, Payload: "x"}); !strings.Contains(got, "status=500") {
		t.Errorf("slogPanic(GatewayError) = %q, want the gateway summary", got)
	}
}

var errPanicPlain = &plainPanicError{msg: "plain panic words " + panicMarker}

type plainPanicError struct{ msg string }

func (e *plainPanicError) Error() string { return e.msg }

func TestCallNoticePanicLineAllowlist(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	callNotice(func() { panic("plain panic words " + panicMarker) }, logger, "probe")
	got := buf.String()
	if got == "" {
		t.Fatal("capture empty: positive control failed (no panic line logged)")
	}
	if strings.Contains(got, panicMarker) || strings.Contains(got, "plain panic words") {
		t.Errorf("callNotice line %q carries panic bytes", got)
	}
	if !strings.Contains(got, "panic_length=") {
		t.Errorf("callNotice line %q, want panic_length", got)
	}
}
