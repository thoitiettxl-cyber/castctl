// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"bytes"
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

func TestStripControlCharsDropsC1Controls(t *testing.T) {
	// C1 controls (U+0080-U+009F) are terminal controls
	// when decoded from UTF-8 on some consoles (e.g. the
	// Linux console treats U+009B as CSI), so they must
	// be dropped like the C0 controls: a bare C1, a C1 NEL
	// line break, and a C1 CSI sequence must not survive.
	in := "a\u0080b\u0085c\u009b31md\u009ce"
	got := StripControlChars(in)
	for _, r := range got {
		if r >= 0x80 && r <= 0x9f {
			t.Fatalf("StripControlChars kept C1 control U+%04X: %q", r, got)
		}
	}
	if strings.ContainsAny(got, "\n\r\x1b") || strings.Contains(got, "[31m") {
		t.Fatalf("StripControlChars kept controls/remnant: %q", got)
	}
	if got != "abcde" {
		t.Fatalf("StripControlChars(%q) = %q, want %q", in, got, "abcde")
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

// TestStripControlCharsExactC1ByteSequences pins the
// single sanitizer on the exact C1 byte sequences: c2 9b
// 5b 33 31 6d (U+009B CSI + "[31m") and c2 85 (U+0085
// NEL). Neither sequence, nor any raw C1 rune, may survive;
// invalid UTF-8 bytes are replaced (U+FFFD), never passed
// through raw.
func TestStripControlCharsExactC1ByteSequences(t *testing.T) {
	csiSeq := []byte{0xc2, 0x9b, 0x5b, 0x33, 0x31, 0x6d}
	nelSeq := []byte{0xc2, 0x85}
	in := "raw boom " + string(csiSeq) + "RED" + string(nelSeq) + "TAIL"
	got := StripControlChars(in)
	if bytes.Contains([]byte(got), csiSeq) || bytes.Contains([]byte(got), nelSeq) {
		t.Fatalf("sanitizer kept C1 byte sequences: %q", got)
	}
	for _, r := range got {
		if r >= 0x80 && r <= 0x9f {
			t.Fatalf("sanitizer kept C1 control U+%04X: %q", r, got)
		}
	}
	if strings.Contains(got, "[31m") {
		t.Fatalf("sanitizer kept CSI remnant: %q", got)
	}
	// CSI grammar: '[' (0x5b) is the final byte of the
	// U+009B CSI sequence, so it is consumed and the
	// remaining "31m" is inert plain text, not a live
	// sequence: no C1 byte and no "[31m" survive.
	if got != "raw boom 31mREDTAIL" {
		t.Fatalf("StripControlChars(%q) = %q, want %q", in, got, "raw boom 31mREDTAIL")
	}
	if got := StripControlChars("a\u0085b"); got != "ab" {
		t.Fatalf("bare NEL: got %q, want %q", got, "ab")
	}
	// Raw (invalid UTF-8) 0x9b / 0x85 bytes must be
	// replaced, never survive as raw bytes.
	raw := string([]byte{'x', 0x9b, 'y', 0x85, 'z'})
	got = StripControlChars(raw)
	if strings.Contains(got, "\x9b") || strings.Contains(got, "\x85") {
		t.Fatalf("sanitizer kept raw C1 bytes: %q", got)
	}
	if got != "x\ufffdy\ufffdz" {
		t.Fatalf("invalid UTF-8: got %q, want %q", got, "x\ufffdy\ufffdz")
	}
}
