// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package conn

// Loop-8 RED test (F1): a GatewayError built without a known
// body length must render NO body_length field in Error()
// or LogSummary() — never the summary-text fallback length.
// This FAILS on the loop-7 renderer, which fell back to
// len(Payload).

import (
	"strings"
	"testing"
)

func TestLoop8GatewayErrorUnknownLengthOmitsField(t *testing.T) {
	ge := &GatewayError{Status: 500, Payload: "fetchSubscriptionAction failed; error=denied"}
	if ge.Payload == "" {
		t.Fatal("Payload is empty: positive control failed")
	}
	if strings.Contains(ge.Payload, "body_length") {
		t.Fatalf("Payload = %q, fixture carries body_length", ge.Payload)
	}
	for _, what := range []struct {
		name string
		got  string
	}{
		{"Error()", ge.Error()},
		{"LogSummary()", ge.LogSummary()},
	} {
		if what.got == "" {
			t.Fatalf("%s is empty: positive control failed", what.name)
		}
		if !strings.Contains(what.got, "status=500") {
			t.Errorf("%s = %q, want status=500", what.name, what.got)
		}
		if strings.Contains(what.got, "body_length") {
			t.Errorf("%s = %q, want NO body_length field for an unknown length", what.name, what.got)
		}
	}
	if ge.Error() != ge.LogSummary() {
		t.Errorf("Error() = %q, LogSummary() = %q, want the renderings identical", ge.Error(), ge.LogSummary())
	}
}

// TestLoop8GatewayErrorKnownLength renders the known flag:
// a known length (including a known 0) appears as
// body_length=N in both renderings, identically.
func TestLoop8GatewayErrorKnownLength(t *testing.T) {
	cases := []struct {
		name   string
		ge     *GatewayError
		length string
	}{
		{"known 52", &GatewayError{Status: 500, Payload: "summary text", BodyLength: 52, BodyLengthKnown: true}, "body_length=52"},
		{"known 0", &GatewayError{Status: 500, Payload: "summary text", BodyLength: 0, BodyLengthKnown: true}, "body_length=0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(tc.ge.Error(), tc.length) || !strings.Contains(tc.ge.LogSummary(), tc.length) {
				t.Errorf("Error() = %q, LogSummary() = %q, want %s in both", tc.ge.Error(), tc.ge.LogSummary(), tc.length)
			}
			if tc.ge.Error() != tc.ge.LogSummary() {
				t.Errorf("Error() = %q, LogSummary() = %q, want the renderings identical", tc.ge.Error(), tc.ge.LogSummary())
			}
		})
	}
}
