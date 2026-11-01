// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && (linux || darwin || freebsd) && !android

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
	// Message control chars (ESC, NUL, newline) are stripped
	// or spaced: one host.log call must never forge a second
	// log line.
	got = nil
	req2, _ := json.Marshal(map[string]string{"level": "info", "message": "a\x1b[31mb\x00c\nd"})
	h.dispatchHostCall("host.log", req2)
	if len(got) != 1 || strings.Contains(got[0], "\x1b") || strings.Contains(got[0], "\x00") || strings.Contains(got[0], "\n") {
		t.Fatalf("message not sanitised: %q", got)
	}
}

// A forged line inside a host.log message must not survive
// as a bare line: the whole message stays on the host's one
// prefixed log line.
func TestDispatchHostCallMessageNoForgedLine(t *testing.T) {
	var got []string
	h := New(Options{Log: func(level, message string) { got = append(got, level+":"+message) }})
	req, _ := json.Marshal(map[string]string{"level": "info", "message": "MSG-LINE-1\nFORGED-LINE-9999\r\nFORGED-2\tescaped"})
	h.dispatchHostCall("host.log", req)
	if len(got) != 1 {
		t.Fatalf("got %d log lines, want 1", len(got))
	}
	if strings.Contains(got[0], "\n") || strings.Contains(got[0], "\r") {
		t.Fatalf("forged newline survived: %q", got[0])
	}
	if !strings.Contains(got[0], "FORGED-LINE-9999") {
		t.Fatalf("message content lost: %q", got[0])
	}
	// Secret-keyed shapes in the message are redacted like
	// every other plugin-text surface.
	got = nil
	req, _ = json.Marshal(map[string]string{"level": "info", "message": `{"api_key":"abc123"}`})
	h.dispatchHostCall("host.log", req)
	if len(got) != 1 || strings.Contains(got[0], "abc123") {
		t.Fatalf("host.log message leaked: %q", got)
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
	// NUL one past the edge is outside the bound too.
	buf4 := make([]byte, maxHostMethodLen+2)
	for i := range buf4 {
		buf4[i] = 'x'
	}
	buf4[maxHostMethodLen+1] = 0
	if _, ok := boundedCStringLen(unsafe.Pointer(&buf4[0]), maxHostMethodLen); ok {
		t.Fatal("NUL past the bound edge: want refusal")
	}
	// NUL at the last in-bound offset is found.
	buf5 := make([]byte, maxHostMethodLen+1)
	for i := range buf5 {
		buf5[i] = 'x'
	}
	buf5[maxHostMethodLen-1] = 0
	if n, ok := boundedCStringLen(unsafe.Pointer(&buf5[0]), maxHostMethodLen); !ok || n != maxHostMethodLen-1 {
		t.Fatalf("NUL at last in-bound offset = (%d,%v), want (%d,true)", n, ok, maxHostMethodLen-1)
	}
	if _, ok := boundedCStringLen(nil, maxHostMethodLen); !ok {
		t.Fatal("nil pointer: want empty success")
	}
}
