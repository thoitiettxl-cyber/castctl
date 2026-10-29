// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

func TestQuotePython(t *testing.T) {
	cases := []struct{ in, safe, want string }{
		{"abc-._~", "", "abc-._~"},
		{"a/b c", "", "a%2Fb%20c"},
		{"a/b c", "/", "a/b%20c"},
		{"café", "", "caf%C3%A9"},
		{"a?b&c=d", "", "a%3Fb%26c%3Dd"},
		{"+", "", "%2B"},
		{"", "", ""},
		{"vm_123-abc", "", "vm_123-abc"},
	}
	for _, tc := range cases {
		if got := quotePython(tc.in, tc.safe); got != tc.want {
			t.Errorf("quotePython(%q, %q) = %q, want %q", tc.in, tc.safe, got, tc.want)
		}
	}
}

func TestMediaPath(t *testing.T) {
	cases := []struct {
		name    string
		ref     any
		want    string
		wantErr bool
	}{
		{"sandbox path", "sandbox://workspace/photo.png", "/media/raw/workspace/photo.png", false},
		{"sandbox with space", "sandbox://workspace/my photo.png", "/media/raw/workspace/my%20photo.png", false},
		{"bare path", "/workspace/a.txt", "/media/raw/workspace/a.txt", false},
		{"media raw path", "/media/raw/workspace/a.txt", "/media/raw/workspace/a.txt", false},
		{"media raw no slash", "media/raw/workspace/a.txt", "/media/raw/workspace/a.txt", false},
		{"https url", "https://vm123.metaaivm.com/media/raw/workspace/a%20b.png", "/media/raw/workspace/a%20b.png", false},
		{"https url query dropped", "https://h/media/raw/x.png?token=abc", "/media/raw/x.png", false},
		{"dict variants original", map[string]any{"variants": map[string]any{"original": "sandbox://workspace/orig.png"}, "path": "sandbox://workspace/other.png"}, "/media/raw/workspace/orig.png", false},
		{"dict path", map[string]any{"path": "sandbox://workspace/p.png"}, "/media/raw/workspace/p.png", false},
		{"dict url", map[string]any{"url": "https://h/media/raw/u.png"}, "/media/raw/u.png", false},
		{"dict empty", map[string]any{}, "", true},
		{"dict no path", map[string]any{"variants": map[string]any{}}, "", true},
		{"dotdot", "sandbox://workspace/../secret", "", true},
		{"dotdot bare", "../secret", "", true},
		{"dotdot segment", "a/../../b", "", true},
		{"empty", "", "", true},
		{"just media raw", "media/raw/", "", true},
		{"quoted dotdot", "sandbox://workspace/%2e%2e/secret", "", true},
		{"plus kept", "sandbox://workspace/a+b.png", "/media/raw/workspace/a%2Bb.png", false},
		{"unicode", "sandbox://workspace/café.png", "/media/raw/workspace/caf%C3%A9.png", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MediaPath(tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("MediaPath(%v) = %q, want error", tc.ref, got)
				}
				var ve *ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("MediaPath error type = %T, want *ValidationError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("MediaPath(%v) error: %v", tc.ref, err)
			}
			if got != tc.want {
				t.Errorf("MediaPath(%v) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}

func TestDecodeJSONValueNumbers(t *testing.T) {
	v, err := decodeJSONValue([]byte(`{"n": 123, "big": 9007199254740993, "f": 1.5, "s": "x", "arr": [1, 2]}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m := v.(map[string]any)
	if _, ok := m["n"].(json.Number); !ok {
		t.Errorf("n type = %T, want json.Number", m["n"])
	}
	if m["n"].(json.Number).String() != "123" {
		t.Errorf("n = %v", m["n"])
	}
	if m["big"].(json.Number).String() != "9007199254740993" {
		t.Errorf("big lost precision: %v", m["big"])
	}
	if m["f"].(json.Number).String() != "1.5" {
		t.Errorf("f = %v", m["f"])
	}
	if _, ok := m["arr"].([]any)[0].(json.Number); !ok {
		t.Errorf("arr[0] type = %T", m["arr"].([]any)[0])
	}
	for _, bad := range []string{``, `not json`, `{"a":}`, `{} extra`, `[1,2] [3]`} {
		if _, err := decodeJSONValue([]byte(bad)); err == nil {
			t.Errorf("decodeJSONValue(%q) = nil error", bad)
		}
	}
}

func TestEncodeBody(t *testing.T) {
	if b, _ := encodeBody(nil); b != nil {
		t.Errorf("nil body = %q", b)
	}
	if b, _ := encodeBody([]byte("raw")); string(b) != "raw" {
		t.Errorf("[]byte body = %q", b)
	}
	if b, _ := encodeBody("verbatim"); string(b) != "verbatim" {
		t.Errorf("string body = %q (conn contract: verbatim)", b)
	}
	b, err := encodeBody(map[string]any{"a": int64(1)})
	if err != nil || string(b) != `{"a":1}` {
		t.Errorf("map body = %q err=%v", b, err)
	}
	if _, err := encodeBody(func() {}); err == nil {
		t.Error("unmarshalable body: nil error")
	}
}

func TestBodyToQuery(t *testing.T) {
	q, err := bodyToQuery(map[string]any{"a": "x", "b": nil, "c": true, "d": int64(3), "e": json.Number("42")})
	if err != nil {
		t.Fatalf("bodyToQuery: %v", err)
	}
	want := map[string]string{"a": "x", "c": "True", "d": "3", "e": "42"}
	if !reflect.DeepEqual(q, want) {
		t.Errorf("query = %v, want %v", q, want)
	}
	if _, err := bodyToQuery("not a map"); err == nil {
		t.Error("non-map GET body: nil error")
	}
}

func TestBuildPath(t *testing.T) {
	got := buildPath("/api/chat/{thread_id}/seen", map[string]string{"thread_id": "a/b c"}, map[string]string{"x": "1 2"})
	if got != "/api/chat/a%2Fb%20c/seen?x=1+2" {
		t.Errorf("buildPath = %q", got)
	}
	got = buildPath("/p?q=1", nil, map[string]string{"r": "2"})
	if got != "/p?q=1&r=2" {
		t.Errorf("buildPath existing query = %q", got)
	}
	got = buildPath("/api/{id}/{id}", map[string]string{"id": "z"}, nil)
	if got != "/api/z/z" {
		t.Errorf("buildPath repeated param = %q", got)
	}
	if got := buildPath("/p", nil, nil); got != "/p" {
		t.Errorf("buildPath no params = %q", got)
	}
}

func TestParseCookies(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{"json cookies dict", `{"cookies": {"hatch_sess": "FAKE", "datr": "FAKE2"}}`, "hatch_sess=FAKE; datr=FAKE2", false},
		{"json flat", `{"hatch_sess": "FAKE"}`, "hatch_sess=FAKE", false},
		{"one line", "hatch_sess=FAKE; datr=FAKE2", "hatch_sess=FAKE; datr=FAKE2", false},
		{"multi line pick", "hatch_sess=FAKE; datr=X\n# comment\nother=1; x=2", "hatch_sess=FAKE; datr=X", false},
		{"netscape", "# Netscape\n.example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tFAKE\n.example.com\tTRUE\t/\tFALSE\t0\tdatr\tFAKE2\n", "hatch_sess=FAKE; datr=FAKE2", false},
		{"unparseable", "garbage without equals", "", true},
		{"empty", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseCookies(tc.raw, "cookies.txt")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseCookies = %q, want error", got)
				}
				var ae *conn.AuthError
				if !errors.As(err, &ae) {
					t.Fatalf("error type = %T, want *conn.AuthError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCookies: %v", err)
			}
			if got != tc.want {
				t.Errorf("ParseCookies = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoadCookiesMissingFile(t *testing.T) {
	_, err := LoadCookies(filepath.Join(t.TempDir(), "nope.txt"))
	if err == nil {
		t.Fatal("missing file: nil error")
	}
	var ae *conn.AuthError
	if errors.As(err, &ae) {
		t.Fatalf("missing file returned AuthError: %v", err)
	}
	if !os.IsNotExist(errors.Unwrap(err)) && !strings.Contains(err.Error(), "no such file") {
		t.Logf("missing file error (no IsNotExist): %v", err)
	}
}
