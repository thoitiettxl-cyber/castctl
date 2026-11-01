// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// C1 sanitizer tests (C1 item): checkField and
// shortPluginCheckError must use the single pluginhost
// sanitizer, so the exact C1 byte sequences c2 9b 5b 33
// 31 6d (U+009B CSI + "[31m") and c2 85 (U+0085 NEL)
// survive on NO output path: the register metadata line
// (stdout, via checkField) or the provider.call FAIL line
// (stderr, via shortPluginCheckError). This file has no
// build tag: the helpers run on every build, including
// CGO_ENABLED=0.
func assertCheckOutputClean(t *testing.T, got string) {
	t.Helper()
	csiSeq := []byte{0xc2, 0x9b, 0x5b, 0x33, 0x31, 0x6d}
	nelSeq := []byte{0xc2, 0x85}
	if bytes.Contains([]byte(got), csiSeq) || bytes.Contains([]byte(got), nelSeq) {
		t.Fatalf("check output kept C1 byte sequences: %q", got)
	}
	for _, r := range got {
		if r >= 0x80 && r <= 0x9f {
			t.Fatalf("check output kept C1 control U+%04X: %q", r, got)
		}
	}
	if strings.Contains(got, "[31m") {
		t.Fatalf("check output kept CSI remnant: %q", got)
	}
}

func TestCheckFieldStripsExactC1ByteSequences(t *testing.T) {
	csi := "\u009b[31m"
	nel := "\u0085"
	if got := checkField("evil" + csi + "RED"); got != "evil31mRED" {
		assertCheckOutputClean(t, got)
		t.Fatalf("checkField name = %q, want %q", got, "evil31mRED")
	}
	assertCheckOutputClean(t, checkField("evil"+csi+"RED"))
	if got := checkField("0.1.0" + nel + "x"); got != "0.1.0x" {
		assertCheckOutputClean(t, got)
		t.Fatalf("checkField version = %q, want %q", got, "0.1.0x")
	}
	assertCheckOutputClean(t, checkField("0.1.0"+nel+"x"))
	if got := checkField("a\nb\x1b[31mc"); strings.ContainsAny(got, "\n\r\x1b") {
		t.Fatalf("checkField kept C0/ESC controls: %q", got)
	}
}

func TestShortPluginCheckErrorStripsExactC1ByteSequences(t *testing.T) {
	err := errors.New("plugin call provider.call returned 1: raw boom \u009b[31mRED\u0085TAIL")
	got := shortPluginCheckError(err)
	assertCheckOutputClean(t, got)
	if !strings.Contains(got, "raw boom") || !strings.Contains(got, "REDTAIL") {
		t.Fatalf("shortPluginCheckError lost content: %q", got)
	}
	// A fused-call error carries the fuse reason through
	// the same hop.
	fused := errors.New("plugin \"echo\" is fused: plugin.provider.call panic: string\u009b[31mRED")
	assertCheckOutputClean(t, shortPluginCheckError(fused))
}
