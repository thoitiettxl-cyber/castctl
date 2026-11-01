// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && (linux || darwin || freebsd)

package pluginhost

import (
	"encoding/json"
	"strings"
	"testing"
	"unsafe"
)

func TestDispatchHostCallLevelSanitised(t *testing.T) {
	var got []string
	h := New(Options{Log: func(level, message string) { got = append(got, level+":"+message) }})
	for _, tc := range []struct {
		level, want string
	}{
		{"info\nEVIL: forged", "info"},
		{"warn\x1b[31m", "info"},
		{"", "info"},
		{"ERROR", "error"},
		{"warning", "warn"},
		{"bogus-level", "info"},
		{" debug ", "debug"},
	} {
		got = nil
		req, _ := json.Marshal(map[string]string{"level": tc.level, "message": "m"})
		h.dispatchHostCall("host.log", req)
		if len(got) != 1 || !strings.HasPrefix(got[0], tc.want+":") {
			t.Fatalf("level %q -> %v, want %q", tc.level, got, tc.want)
		}
	}
	// Message control chars (ESC) are stripped; newline/tab kept.
	got = nil
	req, _ := json.Marshal(map[string]string{"level": "info", "message": "a\x1b[31mb\x00c\nd"})
	h.dispatchHostCall("host.log", req)
	if len(got) != 1 || strings.Contains(got[0], "\x1b") || strings.Contains(got[0], "\x00") {
		t.Fatalf("message not sanitised: %q", got)
	}
	if !strings.Contains(got[0], "\n") {
		t.Fatalf("newline must be kept: %q", got)
	}
}

func TestBoundedCStringLen(t *testing.T) {
	// Unterminated within the bound: refused.
	buf := make([]byte, maxHostMethodLen+64)
	for i := range buf {
		buf[i] = 'x'
	}
	if _, ok := boundedCStringLen(unsafe.Pointer(&buf[0]), maxHostMethodLen); ok {
		t.Fatal("unterminated buffer: want refusal")
	}
	// Terminated early: offset found.
	buf2 := []byte{'a', 'b', 0, 'x', 'x'}
	if n, ok := boundedCStringLen(unsafe.Pointer(&buf2[0]), maxHostMethodLen); !ok || n != 2 {
		t.Fatalf("terminated buffer = (%d,%v), want (2,true)", n, ok)
	}
	// NUL exactly at the bound edge is outside the bound.
	buf3 := make([]byte, maxHostMethodLen+1)
	for i := range buf3 {
		buf3[i] = 'x'
	}
	buf3[maxHostMethodLen] = 0
	if _, ok := boundedCStringLen(unsafe.Pointer(&buf3[0]), maxHostMethodLen); ok {
		t.Fatal("NUL at the bound edge: want refusal")
	}
	if _, ok := boundedCStringLen(nil, maxHostMethodLen); !ok {
		t.Fatal("nil pointer: want empty success")
	}
}
