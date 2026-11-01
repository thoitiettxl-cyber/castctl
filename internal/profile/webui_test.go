// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func parseWebUITestConfig(t *testing.T, doc string) *SingleConfig {
	t.Helper()
	cfg, err := ParseSingleConfig([]byte(doc), t.TempDir())
	if err != nil {
		t.Fatalf("ParseSingleConfig: %v", err)
	}
	return cfg
}

func TestWebUIBlockAbsent(t *testing.T) {
	cfg := parseWebUITestConfig(t, `{"profiles":{}}`)
	if cfg.WebUI != nil {
		t.Fatalf("WebUI = %+v, want nil (absent block)", cfg.WebUI)
	}
	resolved, err := ResolveWebUI(cfg)
	if err != nil || resolved != nil {
		t.Fatalf("ResolveWebUI = %v, %v; want nil, nil", resolved, err)
	}
	if got := EffectiveListen(nil); got != DefaultWebUIListen {
		t.Fatalf("EffectiveListen(nil) = %q, want %q", got, DefaultWebUIListen)
	}
}

func TestWebUIBlockPresent(t *testing.T) {
	cfg := parseWebUITestConfig(t, `{"profiles":{},"webui":{"listen":"127.0.0.1:8317","token":"MARKER-WEBUI-TOKEN"}}`)
	if cfg.WebUI == nil {
		t.Fatal("WebUI is nil, want parsed block")
	}
	if cfg.WebUI.Listen != "127.0.0.1:8317" {
		t.Fatalf("Listen = %q", cfg.WebUI.Listen)
	}
	if cfg.WebUI.Token != "MARKER-WEBUI-TOKEN" {
		t.Fatal("Token was not preserved verbatim")
	}
	if got := EffectiveListen(cfg.WebUI); got != "127.0.0.1:8317" {
		t.Fatalf("EffectiveListen = %q", got)
	}
	// Default listen when the key is absent from a present block.
	cfg2 := parseWebUITestConfig(t, `{"profiles":{},"webui":{"token":"MARKER-WEBUI-TOKEN"}}`)
	if got := EffectiveListen(cfg2.WebUI); got != DefaultWebUIListen {
		t.Fatalf("EffectiveListen = %q, want %q", got, DefaultWebUIListen)
	}
}

func TestWebUIListenValidation(t *testing.T) {
	cases := []struct {
		listen string
		valid  bool
	}{
		{"127.0.0.1:8317", true},
		{"127.0.0.2:1", true},
		{"127.255.255.255:65535", true},
		{"localhost:8317", true},
		{"LOCALHOST:8317", true},
		{"[::1]:8317", true},
		{"0.0.0.0:8317", false},
		{"[::]:8317", false},
		{"192.168.1.1:8317", false},
		{"example.com:8317", false},
		{"127.0.0.1", false},             // missing port
		{"127.0.0.1:0", false},           // port 0
		{"127.0.0.1:65536", false},       // port out of range
		{"127.0.0.1:abc", false},         // non-numeric port
		{"http://127.0.0.1:8317", false}, // URL, not host:port
		{"user@127.0.0.1:8317", false},   // userinfo
		{"127.0.0.1:8317/path", false},   // path
		{"127.0.0.1:8317?x=1", false},    // query
		{"", false},
		{"   ", false},
	}
	for _, tc := range cases {
		doc := `{"profiles":{},"webui":{"listen":` + quoteWebUIJSON(tc.listen) + `}}`
		_, err := ParseSingleConfig([]byte(doc), t.TempDir())
		if tc.valid && err != nil {
			t.Errorf("listen %q: unexpected error: %v", tc.listen, err)
		}
		if !tc.valid {
			if err == nil {
				t.Errorf("listen %q: accepted, want rejection", tc.listen)
			} else if strings.Contains(err.Error(), tc.listen) && tc.listen != "" {
				t.Errorf("listen %q: error echoes the value: %v", tc.listen, err)
			}
		}
	}
}

func quoteWebUIJSON(s string) string {
	// Minimal JSON string quoting for the table above (no control
	// characters in the test values).
	out := `"`
	for _, r := range s {
		switch r {
		case '"':
			out += `\"`
		case '\\':
			out += `\\`
		default:
			out += string(r)
		}
	}
	return out + `"`
}

func TestWebUIBlockRejects(t *testing.T) {
	cases := []string{
		`{"profiles":{},"webui":[]}`,
		`{"profiles":{},"webui":{"listen":8317}}`,
		`{"profiles":{},"webui":{"token":""}}`,
		`{"profiles":{},"webui":{"token":123}}`,
		`{"profiles":{},"webui":{"listen":""}}`,
		`{"profiles":{},"webui":{"unknown":true}}`,
		`{"profiles":{},"webui":{"listen":"0.0.0.0:8317"}}`,
	}
	for _, doc := range cases {
		if _, err := ParseSingleConfig([]byte(doc), t.TempDir()); err == nil {
			t.Errorf("doc %s: accepted, want rejection", doc)
		}
	}
	// The token value must never be echoed in an error.
	_, err := ParseSingleConfig([]byte(`{"profiles":{},"webui":{"token":""}}`), t.TempDir())
	if err == nil || strings.Contains(err.Error(), "MARKER") {
		t.Fatalf("empty-token error = %v", err)
	}
}

func TestWebUIBlockRoundTrip(t *testing.T) {
	// A hand-built config (no raw capture) renders the block and
	// re-parses identically, token verbatim.
	cfg := &SingleConfig{
		Profiles: map[string]*Profile{},
		WebUI:    &WebUIConfig{Listen: "127.0.0.1:9000", Token: "MARKER-WEBUI-TOKEN"},
	}
	encoded, err := encodeSingleConfig(cfg)
	if err != nil {
		t.Fatalf("encodeSingleConfig: %v", err)
	}
	back, err := ParseSingleConfig(encoded, t.TempDir())
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if back.WebUI == nil || back.WebUI.Listen != "127.0.0.1:9000" || back.WebUI.Token != "MARKER-WEBUI-TOKEN" {
		t.Fatalf("round-trip WebUI = %+v", back.WebUI)
	}
	// Raw preservation: a parsed block re-renders verbatim.
	cfg2 := parseWebUITestConfig(t, "{\n  \"profiles\": {},\n  \"webui\": {\"token\": \"MARKER-WEBUI-TOKEN\", \"listen\": \"127.0.0.1:8317\"}\n}")
	encoded2, err := encodeSingleConfig(cfg2)
	if err != nil {
		t.Fatalf("encodeSingleConfig: %v", err)
	}
	if !strings.Contains(string(encoded2), `"token": "MARKER-WEBUI-TOKEN"`) {
		t.Fatalf("raw webui block not preserved verbatim:\n%s", encoded2)
	}
}

func TestWebUIUIDirParse(t *testing.T) {
	base := t.TempDir() // the config directory for these parses
	outside := t.TempDir()
	cases := []struct {
		name  string
		value string
		valid bool
	}{
		{"absolute outside", filepath.Join(outside, "ui"), true},
		{"relative outside", "../ui", true},
		{"sibling of config dir", filepath.Join(filepath.Dir(base), "other"), true},
		{"relative inside", "ui", false},
		{"dot", ".", false},
		{"dotdot", "..", false},
		{"absolute equal", base, false},
		{"absolute inside", filepath.Join(base, "MARKER-UIDIR"), false},
		{"absolute ancestor", filepath.Dir(base), false},
		{"empty", "", false},
		{"whitespace", "   ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := `{"profiles":{},"webui":{"ui_dir":` + quoteWebUIJSON(tc.value) + `}}`
			cfg, err := ParseSingleConfig([]byte(doc), base)
			if tc.valid {
				if err != nil {
					t.Fatalf("ui_dir %q: unexpected error: %v", tc.value, err)
				}
				if cfg.WebUI == nil || cfg.WebUI.UIDir != strings.TrimSpace(tc.value) {
					t.Fatalf("UIDir = %+v, want %q", cfg.WebUI, strings.TrimSpace(tc.value))
				}
				return
			}
			if err == nil {
				t.Fatalf("ui_dir %q: accepted, want rejection", tc.value)
			}
			if strings.Contains(err.Error(), "MARKER-UIDIR") {
				t.Fatalf("ui_dir error echoes the value: %v", err)
			}
		})
	}
	// Non-string ui_dir is rejected.
	if _, err := ParseSingleConfig([]byte(`{"profiles":{},"webui":{"ui_dir":123}}`), base); err == nil {
		t.Error("non-string ui_dir accepted, want rejection")
	}
	// A ui_dir value with surrounding whitespace is trimmed and
	// still checked after trimming.
	doc := `{"profiles":{},"webui":{"ui_dir":"  ` + filepath.Join(base, "ui") + `  "}}`
	if _, err := ParseSingleConfig([]byte(doc), base); err == nil {
		t.Error("whitespace-padded inside ui_dir accepted, want rejection")
	}
}

func TestWebUIUIDirRoundTrip(t *testing.T) {
	// A hand-built config renders ui_dir and re-parses
	// identically (the re-parse base is outside the ui_dir).
	cfg := &SingleConfig{
		Profiles: map[string]*Profile{},
		WebUI:    &WebUIConfig{Listen: "127.0.0.1:9000", Token: "MARKER-WEBUI-TOKEN", UIDir: "/srv/MARKER-UIDIR"},
	}
	encoded, err := encodeSingleConfig(cfg)
	if err != nil {
		t.Fatalf("encodeSingleConfig: %v", err)
	}
	back, err := ParseSingleConfig(encoded, t.TempDir())
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if back.WebUI == nil || back.WebUI.UIDir != "/srv/MARKER-UIDIR" {
		t.Fatalf("round-trip UIDir = %+v", back.WebUI)
	}
	// Raw preservation: a parsed block with ui_dir re-renders
	// verbatim.
	cfg2 := parseWebUITestConfig(t, "{\n  \"profiles\": {},\n  \"webui\": {\"token\": \"MARKER-WEBUI-TOKEN\", \"ui_dir\": \"/srv/MARKER-UIDIR\"}\n}")
	encoded2, err := encodeSingleConfig(cfg2)
	if err != nil {
		t.Fatalf("encodeSingleConfig: %v", err)
	}
	if !strings.Contains(string(encoded2), `"ui_dir": "/srv/MARKER-UIDIR"`) {
		t.Fatalf("raw webui block lost ui_dir:\n%s", encoded2)
	}
}

func TestDirOverlaps(t *testing.T) {
	cases := []struct {
		dir, candidate string
		overlap        bool
	}{
		{"/a/b", "/a/b", true},       // equal
		{"/a/b", "/a/b/c", true},     // inside
		{"/a/b", "/a", true},         // ancestor
		{"/a/b", "/", true},          // ancestor (root)
		{"/a/b", "/a/c", false},      // sibling subtree
		{"/a/b", "/a/bc", false},     // prefix lookalike, not inside
		{"/a/b", "/c/d", false},      // unrelated
		{"/a/b/", "/a/b/c/", true},   // trailing slashes cleaned
		{"/a/b", "/a/b/../c", false}, // .. resolves out (lexical)
	}
	for _, tc := range cases {
		if got := DirOverlaps(tc.dir, tc.candidate); got != tc.overlap {
			t.Errorf("DirOverlaps(%q, %q) = %v, want %v", tc.dir, tc.candidate, got, tc.overlap)
		}
	}
}

// TestDirOverlapsRelativeBaseDir covers the live defect found
// on the box (PR #25): with a relative --config path, the
// config directory is relative ("." or "wt/b"), and comparing
// it lexically with an absolute ui_dir must still decide
// overlap correctly. A relative dir and an absolute candidate
// must be absolutized against the working directory before
// the Rel comparison: filepath.Rel errors across the
// relative/absolute boundary, and DirOverlaps fails closed
// on that error, so every absolute ui_dir was refused.
func TestDirOverlapsRelativeBaseDir(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The unrelated tree must live OUTSIDE root: a path under
	// root would be inside the "." config directory.
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	cases := []struct {
		dir, candidate string
		overlap        bool
	}{
		{".", elsewhere, false},                         // unrelated absolute ui_dir
		{"sub", elsewhere, false},                       // unrelated absolute ui_dir, subdir base
		{".", root, true},                               // equal, via "."
		{"sub", filepath.Join(root, "sub"), true},       // equal, via subdir spelling
		{".", ".", true},                                // equal, relative spelling
		{".", "..", true},                               // ancestor, relative spelling
		{"sub", "sub/ui", true},                         // inside, relative spelling
		{".", "ui", true},                               // inside, relative spelling
		{"sub", root, true},                             // ancestor of the subdir
		{".", filepath.Join(root, "sub"), true},         // inside, absolute spelling
		{"sub", filepath.Join(root, "sub", "ui"), true}, // inside, absolute spelling
	}
	for _, tc := range cases {
		if got := DirOverlaps(tc.dir, tc.candidate); got != tc.overlap {
			t.Errorf("DirOverlaps(%q, %q) = %v, want %v", tc.dir, tc.candidate, got, tc.overlap)
		}
	}
}

// TestWebUIUIDirParseRelativeBaseDir is the parse-time half of
// the relative --config defect: ParseSingleConfig receives the
// config directory as given (relative for a relative --config
// path), and an unrelated absolute ui_dir must parse while
// every overlapping spelling — relative or absolute — is
// still refused.
func TestWebUIUIDirParseRelativeBaseDir(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.Mkdir(filepath.Join(root, "cfg"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The unrelated tree must live OUTSIDE root: a path under
	// root would be inside the "." config directory.
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	cfgAbs := filepath.Join(root, "cfg")
	doc := func(uiDir string) []byte {
		return []byte(`{"profiles":{},"webui":{"token":"MARKER-WEBUI-TOKEN","ui_dir":` + strconv.Quote(uiDir) + `}}`)
	}
	cases := []struct {
		name    string
		baseDir string
		uiDir   string
		valid   bool
	}{
		{"dot base unrelated absolute", ".", elsewhere, true},
		{"subdir base unrelated absolute", "cfg", elsewhere, true},
		{"absolute base unrelated absolute", cfgAbs, elsewhere, true},
		{"dot base relative inside", ".", "ui", false},
		{"dot base subdir inside", ".", "cfg/ui", false},
		{"dot base equal absolute", ".", root, false},
		{"dot base dot", ".", ".", false},
		{"dot base dotdot", ".", "..", false},
		{"subdir base equal absolute", "cfg", cfgAbs, false},
		{"subdir base dot", "cfg", ".", false},
		{"subdir base relative inside", "cfg", "ui", false},
		{"subdir base ancestor absolute", "cfg", root, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseSingleConfig(doc(tc.uiDir), tc.baseDir)
			if tc.valid {
				if err != nil {
					t.Fatalf("baseDir %q ui_dir %q: unexpected error: %v", tc.baseDir, tc.uiDir, err)
				}
				if cfg.WebUI == nil || cfg.WebUI.UIDir != tc.uiDir {
					t.Fatalf("UIDir = %+v, want %q", cfg.WebUI, tc.uiDir)
				}
				return
			}
			if err == nil {
				t.Fatalf("baseDir %q ui_dir %q: accepted, want rejection", tc.baseDir, tc.uiDir)
			}
		})
	}
}
