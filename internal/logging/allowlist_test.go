// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package logging_test

// Loop-5 allowlist tests for the log boundary: trace renders
// the SAME allowlist summary as every other level (the loop-4
// trace allowance for redacted-then-truncated bodies is
// superseded), and SafeString carries exactly the listed
// vocabulary as a backstop — no more scanner rework.

import (
	"strings"
	"testing"

	singlog "github.com/sagernet/sing-box/log"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

const allowlistTraceMarker = "ALLOW5TRACE-9d2e41"

// TestSafeErrForLevelTraceIsSummary: at trace, a
// body-carrying error renders status + class + length only —
// no body bytes, redacted or otherwise.
func TestSafeErrForLevelTraceIsSummary(t *testing.T) {
	t.Parallel()
	gw := &conn.GatewayError{Status: 500, Payload: "plain body words " + allowlistTraceMarker}
	for _, level := range []singlog.Level{singlog.LevelTrace, singlog.LevelDebug, singlog.LevelInfo, singlog.LevelWarn, singlog.LevelError} {
		got := logging.SafeErrForLevel(gw, level)
		if strings.Contains(got, allowlistTraceMarker) || strings.Contains(got, "plain body words") {
			t.Errorf("level %v rendering %q carries body bytes", level, got)
		}
		if !strings.Contains(got, "status=500") || !strings.Contains(got, "body_length=") {
			t.Errorf("level %v rendering %q, want status + class + length only", level, got)
		}
	}
	ae := conn.NewAuthError("hatch/token -> 403 plain body words " + allowlistTraceMarker)
	got := logging.SafeErrForLevel(ae, singlog.LevelTrace)
	if strings.Contains(got, allowlistTraceMarker) {
		t.Errorf("trace AuthError rendering %q carries body bytes", got)
	}
	if !strings.Contains(got, "auth_failed") || !strings.Contains(got, "message_length=") {
		t.Errorf("trace AuthError rendering %q, want class + length only", got)
	}
}

// TestSafeStringListedVocabulary pins exactly the loop-5
// listed vocabulary in the SafeString backstop: each listed
// form, in JSON (double- and single-quoted keys/values),
// colon, and equals spellings. The fixture value must be
// absent from every output; the label survives. Forms are
// literals, never recomputed from the code under test.
func TestSafeStringListedVocabulary(t *testing.T) {
	t.Parallel()
	const val = "ALLOW5VOCAB-7f3a91"
	cases := []struct {
		name string
		in   string
	}{
		{"session_key JSON", `{"session_key": "` + val + `"}`},
		{"session_key single-quote JSON", `{'session_key': '` + val + `'}`},
		{"session_key colon", "session_key: " + val},
		{"session_key equals", "session_key=" + val},
		{"api_key JSON", `{"api_key": "` + val + `"}`},
		{"api_key single-quote JSON", `{'api_key': '` + val + `'}`},
		{"api_key colon", "api_key: " + val},
		{"api_key equals", "api_key=" + val},
		{"access_key JSON", `{"access_key": "` + val + `"}`},
		{"access_key single-quote JSON", `{'access_key': '` + val + `'}`},
		{"access_key colon", "access_key: " + val},
		{"access_key equals", "access_key=" + val},
		{"generic _key JSON", `{"encryption_key": "` + val + `"}`},
		{"generic _key single-quote JSON", `{'signing_key': '` + val + `'}`},
		{"generic _key colon", "encryption_key: " + val},
		{"generic _key equals", "signing_key=" + val},
		{"private-key JSON", `{"private-key": "` + val + `"}`},
		{"private-key colon", "private-key: " + val},
		{"private-key equals", "private-key=" + val},
		{"bearer JSON", `{"bearer": "` + val + `"}`},
		{"bearer single-quote JSON", `{'bearer': '` + val + `'}`},
		{"bearer colon", "bearer: " + val},
		{"bearer equals", "bearer=" + val},
		{"x-api-key JSON", `{"x-api-key": "` + val + `"}`},
		{"x-api-key single-quote JSON", `{'x-api-key': '` + val + `'}`},
		{"x-api-key colon", "x-api-key: " + val},
		{"x-api-key equals", "x-api-key=" + val},
		{"preshared_key JSON", `{"preshared_key": "` + val + `"}`},
		{"preshared_key colon", "preshared_key: " + val},
		{"preshared_key equals", "preshared_key=" + val},
		{"pre_shared_key JSON", `{"pre_shared_key": "` + val + `"}`},
		{"pre_shared_key colon", "pre_shared_key: " + val},
		{"pre_shared_key equals", "pre_shared_key=" + val},
		{"session JSON", `{"session": "` + val + `"}`},
		{"session single-quote JSON", `{'session': '` + val + `'}`},
		{"session colon", "session: " + val},
		{"session equals", "session=" + val},
		{"hatch_sess JSON", `{"hatch_sess": "` + val + `"}`},
		{"hatch_sess single-quote JSON", `{'hatch_sess': '` + val + `'}`},
		{"hatch_sess colon", "hatch_sess: " + val},
		{"hatch_sess equals", "hatch_sess=" + val},
		{"datr JSON", `{"datr": "` + val + `"}`},
		{"datr single-quote JSON", `{'datr': '` + val + `'}`},
		{"datr colon", "datr: " + val},
		{"datr equals", "datr=" + val},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := logging.SafeString(tc.in)
			if got == "" {
				t.Fatalf("SafeString(%q) empty: positive control failed", tc.in)
			}
			if strings.Contains(got, val) {
				t.Errorf("SafeString(%q) = %q, want the fixture value stripped", tc.in, got)
			}
			if !strings.Contains(got, "[redacted]") {
				t.Errorf("SafeString(%q) = %q, want a [redacted] marker", tc.in, got)
			}
		})
	}
}
