// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Cap-before-redact: a plugin returning megabytes of text must
// never make SafeString scan megabytes, and a secret value
// straddling the cap must still be redacted, not leaked in
// part. The cap stays 4096 with an explicit marker.
func TestSafePluginTextCapBeforeRedact(t *testing.T) {
	secret := "SECRET-VALUE-xyz-1234567890"
	// Boundary-straddling secret pairs: the value is cut by
	// the cap in double quotes, single quotes, after a
	// backslash, and in %q-escaped form.
	pad := func(n int) string { return strings.Repeat("p", n) }
	cases := []string{
		`{"api_key":"` + secret + `"}`,
		`{'api_key':'` + secret + `'}`,
		`{"api_key":"ab\` + secret + `"}`,
		`\"api_key\": \"` + secret + `\"`,
	}
	for i, body := range cases {
		// Pad BEFORE the pair so the pair itself straddles
		// the 4096 cap: cut lands inside the secret value.
		s := pad(maxPluginTextLen-8) + body
		got := safePluginText(s)
		if strings.Contains(got, secret) || strings.Contains(got, "SECRET-VALUE") {
			t.Fatalf("case %d leaked straddling secret: %q", i, got)
		}
		if len(got) > maxPluginTextLen+len("…") {
			t.Fatalf("case %d len = %d, want <= %d", i, len(got), maxPluginTextLen+len("…"))
		}
		if !strings.HasSuffix(got, "…") {
			t.Fatalf("case %d missing cap marker: %q", i, got)
		}
	}
	// Small inputs are unchanged (redaction still applies).
	if got := safePluginText(`{"api_key":"abc123"}`); strings.Contains(got, "abc123") {
		t.Fatalf("small input leaked: %q", got)
	}
	if got := safePluginText("plain ok"); got != "plain ok" {
		t.Fatalf("small input changed: %q", got)
	}
	// Rune-safe: a multi-byte rune straddling the cap is not
	// split, and the result is valid UTF-8.
	s := strings.Repeat("é", 3000) // 6000 bytes
	got := safePluginText(s)
	if !utf8.ValidString(got) {
		t.Fatalf("split rune: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("multi-byte input missing marker: len=%d", len(got))
	}
}

func TestSafePluginTextLargeInputBounded(t *testing.T) {
	// 5 MB and 50 MB inputs through the capped path must
	// finish in seconds with <=4096+marker output. (Uncapped
	// SafeString on 5 MB was measured at minutes, killed.)
	secret := strings.Repeat("s", 100)
	for _, size := range []int{5 << 20, 50 << 20} {
		s := `{"api_key":"` + secret + `","pad":"` + strings.Repeat("x", size) + `"}`
		start := time.Now()
		got := safePluginText(s)
		elapsed := time.Since(start)
		t.Logf("size=%d elapsed=%s outlen=%d", size, elapsed, len(got))
		if elapsed > 5*time.Second {
			t.Fatalf("size %d took %s, want < 5s", size, elapsed)
		}
		if len(got) > maxPluginTextLen+len("…") {
			t.Fatalf("size %d outlen = %d, want <= %d", size, len(got), maxPluginTextLen+len("…"))
		}
		if strings.Contains(got, secret) {
			t.Fatalf("size %d leaked secret", size)
		}
	}
}

func TestCapPluginTextRuneSafe(t *testing.T) {
	s := strings.Repeat("é", 3000)
	got := capPluginText(s)
	if !utf8.ValidString(got) {
		t.Fatalf("cap split rune: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("cap missing marker: len=%d", len(got))
	}
	if got := capPluginText("short"); got != "short" {
		t.Fatalf("cap changed short input: %q", got)
	}
}
