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
