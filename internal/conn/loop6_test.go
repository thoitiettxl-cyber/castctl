// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package conn

// Loop-6 tests: ConnectionError LogSummary (item 1) and the
// content-type cap alignment (item 6a).

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

const loop6Marker = "LOOP6MARKER7f3a91"

func TestLoop6ConnectionErrorLogSummary(t *testing.T) {
	plain := errors.New("plain transport words " + loop6Marker)
	ce := &ConnectionError{Err: plain}
	sum := logging.SummarizeErr(ce)
	if strings.Contains(sum, loop6Marker) {
		t.Errorf("SummarizeErr(ConnectionError) = %q, carries peer/plain prose", sum)
	}
	want := fmt.Sprintf("conn: connection error error_length=%d", len(plain.Error()))
	if sum != want {
		t.Errorf("SummarizeErr(ConnectionError) = %q, want %q", sum, want)
	}
	// Inner summaries still win through the wrapper.
	inner := &GatewayError{Status: 500, Payload: "summary text", BodyLength: 52}
	if got := logging.SummarizeErr(&ConnectionError{Err: inner}); got != inner.LogSummary() {
		t.Errorf("SummarizeErr(ConnectionError wrapping GatewayError) = %q, want the inner summary %q", got, inner.LogSummary())
	}
	// Nil cause renders the class only.
	if got := logging.SummarizeErr(&ConnectionError{}); got != "conn: connection error" {
		t.Errorf("SummarizeErr(ConnectionError{}) = %q, want the class only", got)
	}
	if got := (&ConnectionError{}).LogSummary(); got != "conn: connection error" {
		t.Errorf("ConnectionError{}.LogSummary() = %q, want the class only", got)
	}
}

func TestLoop6ContentTypeCapAlignment(t *testing.T) {
	// Construction (gateway summarizeContentType) caps at 64
	// runes; render-time re-validation must use the SAME cap:
	// a 65-rune media type must be omitted, a 64-rune one emitted.
	over := strings.Repeat("a", 60) + "/json" // 65 runes, valid shape
	if len([]rune(over)) != 65 {
		t.Fatalf("fixture length = %d runes, want 65", len([]rune(over)))
	}
	ge := &GatewayError{Status: 500, BodyLength: 10, ContentType: over}
	if strings.Contains(ge.Error(), over) {
		t.Errorf("GatewayError.Error() = %q, emits an over-cap content-type", ge.Error())
	}
	if !strings.Contains(ge.Error(), "body_length=10") {
		t.Errorf("GatewayError.Error() = %q, want body_length=10", ge.Error())
	}
	at := strings.Repeat("b", 59) + "/json" // 64 runes
	ge2 := &GatewayError{Status: 500, BodyLength: 10, ContentType: at}
	if !strings.Contains(ge2.Error(), "content_type="+at) {
		t.Errorf("GatewayError.Error() = %q, want the at-cap content-type emitted", ge2.Error())
	}
	// A 100-rune media type is omitted too (the old 129-byte
	// render-time bound would have emitted it).
	long := strings.Repeat("c", 95) + "/json"
	ge3 := &GatewayError{Status: 500, BodyLength: 10, ContentType: long}
	if strings.Contains(ge3.Error(), long) {
		t.Errorf("GatewayError.Error() = %q, emits a 100-rune content-type", ge3.Error())
	}
}
