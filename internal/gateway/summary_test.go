// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

// Loop-5 allowlist extraction tests: the closed key list,
// the enum shape gate, the length cap (over-cap values are
// REPLACED by a placeholder, never emitted truncated), and
// content-type handling (parameters stripped, odd values
// replaced). Keys and evidence are documented in summary.go;
// fixtures are literals.

import (
	"fmt"
	"strings"
	"testing"
)

func TestExtractAllowlistField(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		decoded   map[string]any
		key       string
		want      string
		wantFound bool
	}{
		{"error enum", map[string]any{"error": "denied"}, "error", "denied", true},
		{"error free text", map[string]any{"error": "rate limited"}, "error", allowlistOmitted, true},
		{"error over cap", map[string]any{"error": strings.Repeat("a", 65)}, "error", allowlistOmitted, true},
		{"error at cap", map[string]any{"error": strings.Repeat("a", 64)}, "error", strings.Repeat("a", 64), true},
		{"error numeric", map[string]any{"error": float64(123)}, "error", allowlistOmitted, true},
		{"error object", map[string]any{"error": map[string]any{"x": 1}}, "error", allowlistOmitted, true},
		{"status enum", map[string]any{"status": "unavailable"}, "status", "unavailable", true},
		{"status free text", map[string]any{"status": "vm is down"}, "status", allowlistOmitted, true},
		{"reason enum", map[string]any{"reason": "unknown"}, "reason", "unknown", true},
		{"unknown key detail", map[string]any{"detail": "denied"}, "detail", "", false},
		{"unknown key message", map[string]any{"message": "denied"}, "message", "", false},
		{"unknown key code", map[string]any{"code": "denied"}, "code", "", false},
		{"absent key", map[string]any{}, "error", "", false},
		{"nil map", nil, "error", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := extractAllowlistField(tc.decoded, tc.key)
			if found != tc.wantFound || got != tc.want {
				t.Errorf("extractAllowlistField(%v, %q) = (%q, %v), want (%q, %v)", tc.decoded, tc.key, got, found, tc.want, tc.wantFound)
			}
		})
	}
}

func TestSummarizeContentType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"plain", "application/json", "application/json"},
		{"parameters stripped", "text/plain; charset=utf-8", "text/plain"},
		{"empty means absent", "", ""},
		{"whitespace trimmed", "  application/json  ", "application/json"},
		{"over cap", strings.Repeat("a", 65) + "/json", allowlistOmitted},
		{"crlf injection", "text/plain\r\nX-Injected: evil", allowlistOmitted},
		{"space in type", "not a type", allowlistOmitted},
		{"no slash", "textplain", allowlistOmitted},
		{"empty subtype", "text/", allowlistOmitted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarizeContentType(tc.raw); got != tc.want {
				t.Errorf("summarizeContentType(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestSummarizeBody(t *testing.T) {
	t.Parallel()
	data := []byte(`{"ok":false,"error":"denied"}`)
	decoded := map[string]any{"ok": false, "error": "denied"}
	s := summarizeBody("api error", data, "application/json; charset=utf-8", decoded, "error")
	if s.length != len(data) {
		t.Errorf("length = %d, want %d", s.length, len(data))
	}
	if s.contentType != "application/json" {
		t.Errorf("contentType = %q, want application/json", s.contentType)
	}
	if s.errorCode != "denied" {
		t.Errorf("errorCode = %q, want denied", s.errorCode)
	}
	for _, want := range []string{"api error", fmt.Sprintf("body_length=%d", len(data)), "content_type=application/json", "error=denied"} {
		if !strings.Contains(s.text, want) {
			t.Errorf("text = %q, want %q", s.text, want)
		}
	}
	// Over-cap extracted value: placeholder, never a
	// truncated prefix of the value.
	long := strings.Repeat("b", 100)
	s2 := summarizeBody("api error", []byte(long), "", map[string]any{"error": long}, "error")
	if strings.Contains(s2.text, long[:64]) || strings.Contains(s2.text, long) {
		t.Errorf("text = %q emits an over-cap value", s2.text)
	}
	if !strings.Contains(s2.text, "error="+allowlistOmitted) {
		t.Errorf("text = %q, want the over-cap placeholder", s2.text)
	}
	// No decoded map, no content-type: status + length only.
	s3 := summarizeBody("gateway error", []byte("plain body"), "", nil)
	if s3.text == "" || strings.Contains(s3.text, "plain body") {
		t.Errorf("text = %q, want a summary without body bytes", s3.text)
	}
	if strings.Contains(s3.text, "content_type=") {
		t.Errorf("text = %q, want no content-type when none was sent", s3.text)
	}
	if s3.errorCode != "" || s3.contentType != "" {
		t.Errorf("summary = %+v, want empty contentType/errorCode", s3)
	}
}
