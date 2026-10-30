// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package fsclient

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Port of test_fs.py FSTest.test_replace.
func TestApplyReplace(t *testing.T) {
	if got, err := ApplyReplace("a b a", "a", "c", -1); err != nil || got != "c b c" {
		t.Errorf("ApplyReplace(all) = %q, %v, want c b c", got, err)
	}
	if got, err := ApplyReplace("a b a", "a", "c", 1); err != nil || got != "c b a" {
		t.Errorf("ApplyReplace(count=1) = %q, %v, want c b a", got, err)
	}
	if got, err := ApplyReplace("a b a", "a", "c", 0); err != nil || got != "a b a" {
		t.Errorf("ApplyReplace(count=0) = %q, %v, want unchanged", got, err)
	}
	if _, err := ApplyReplace("abc", "z", "y", -1); err == nil {
		t.Error("ApplyReplace missing: got nil error")
	} else if err.Error() != "--replace: text not found: 'z'" {
		t.Errorf("ApplyReplace missing error = %q, want Python-repr message", err)
	}
	// count=0 still errors when old is absent: Python checks
	// membership before replacing.
	if _, err := ApplyReplace("abc", "z", "y", 0); err == nil {
		t.Error("ApplyReplace missing count=0: got nil error")
	}
	if got, err := ApplyReplace("aaa", "a", "b", 2); err != nil || got != "bba" {
		t.Errorf("ApplyReplace(count=2) = %q, %v, want bba", got, err)
	}
}

func TestSplitEditorCommand(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"plain", "vi", []string{"vi"}},
		{"with args", "code --wait", []string{"code", "--wait"}},
		{"multiple args", "code --wait --new-window", []string{"code", "--wait", "--new-window"}},
		{"single quotes", "'my editor' --flag", []string{"my editor", "--flag"}},
		{"double quotes", `"my editor" --flag`, []string{"my editor", "--flag"}},
		{"escaped space", `my\ editor --flag`, []string{"my editor", "--flag"}},
		{"empty quoted word", `"" x`, []string{"", "x"}},
		{"single quote keeps backslash", `'a\b'`, []string{`a\b`}},
		{"double quote escape", `"a\"b"`, []string{`a"b`}},
		{"double quote backslash before other", `"a\nb"`, []string{`a\nb`}},
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"tabs and newlines", "a\tb\nc", []string{"a", "b", "c"}},
		{"quoted empty in middle", `a "" b`, []string{"a", "", "b"}},
		{"equals and dashes", "editor --opt=value", []string{"editor", "--opt=value"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SplitEditorCommand(tc.in)
			if err != nil {
				t.Fatalf("SplitEditorCommand(%q) error = %v", tc.in, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("SplitEditorCommand(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	for _, in := range []string{`'unbalanced`, `"unbalanced`, `a 'b`, `a\`} {
		if _, err := SplitEditorCommand(in); err == nil {
			t.Errorf("SplitEditorCommand(%q): got nil error, want unbalanced-quote/escape error", in)
		}
	}
}

// editorScript writes an executable shell script that appends
// "EDITED" to its last argument and records that argument's path
// in sidecar. The editor under test runs it directly (no shell),
// so the script's shebang is what executes it.
func editorScript(t *testing.T, dir, sidecar string) string {
	t.Helper()
	script := filepath.Join(dir, "fake-editor.sh")
	content := "#!/bin/sh\nfor last; do :; done\nprintf 'EDITED' >> \"$last\"\nprintf '%s' \"$last\" > " + sidecar + "\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

func TestEditInEditor(t *testing.T) {
	// t.Setenv forbids t.Parallel here; editor tests run serially.
	dir := t.TempDir()
	sidecar := filepath.Join(dir, "lastarg.txt")
	script := editorScript(t, dir, sidecar)
	ctx := context.Background()

	t.Run("editor true leaves data unchanged", func(t *testing.T) {
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", "true")
		got, err := EditInEditor(ctx, []byte("hello"), "")
		if err != nil || string(got) != "hello" {
			t.Errorf("EditInEditor(EDITOR=true) = %q, %v, want hello", got, err)
		}
	})

	t.Run("editor false leaves data unchanged", func(t *testing.T) {
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", "false")
		got, err := EditInEditor(ctx, []byte("hello"), "")
		if err != nil || string(got) != "hello" {
			t.Errorf("EditInEditor(EDITOR=false) = %q, %v, want hello", got, err)
		}
	})

	t.Run("editor with args edits last argument", func(t *testing.T) {
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", script+" --wait --extra")
		got, err := EditInEditor(ctx, []byte("hello"), ".md")
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "helloEDITED" {
			t.Errorf("EditInEditor(editor with args) = %q, want helloEDITED", got)
		}
		recorded, err := os.ReadFile(sidecar)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(string(recorded), ".md") {
			t.Errorf("edited file = %q, want .md suffix", recorded)
		}
		// The temporary file is removed afterwards.
		if _, err := os.Stat(string(recorded)); !os.IsNotExist(err) {
			t.Errorf("temp file still exists: %q (stat err %v)", recorded, err)
		}
	})

	t.Run("VISUAL beats EDITOR", func(t *testing.T) {
		t.Setenv("VISUAL", "true")
		t.Setenv("EDITOR", script)
		got, err := EditInEditor(ctx, []byte("hello"), "")
		if err != nil || string(got) != "hello" {
			t.Errorf("EditInEditor(VISUAL=true) = %q, %v, want hello", got, err)
		}
	})

	t.Run("quoted editor path with spaces", func(t *testing.T) {
		spaced := filepath.Join(dir, "my editor.sh")
		content, err := os.ReadFile(script)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(spaced, content, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", "'"+spaced+"'")
		got, err := EditInEditor(ctx, []byte("hi"), "")
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "hiEDITED" {
			t.Errorf("EditInEditor(quoted path) = %q, want hiEDITED", got)
		}
	})

	t.Run("unbalanced quote errors", func(t *testing.T) {
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", "'unbalanced")
		if _, err := EditInEditor(ctx, []byte("hi"), ""); err == nil {
			t.Error("EditInEditor(unbalanced quote): got nil error")
		}
	})

	t.Run("missing editor binary is ignored like a shell 127", func(t *testing.T) {
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", "/nonexistent/editor-xyz")
		got, err := EditInEditor(ctx, []byte("hello"), "")
		if err != nil || string(got) != "hello" {
			t.Errorf("EditInEditor(missing binary) = %q, %v, want hello", got, err)
		}
	})
}

func TestFmtSize(t *testing.T) {
	cases := []struct {
		name string
		in   *int64
		want string
	}{
		{"nil", nil, "-"},
		{"zero", int64Ptr(0), "0B"},
		{"bytes", int64Ptr(1023), "1023B"},
		{"one K", int64Ptr(1024), "1.0K"},
		{"one and half K", int64Ptr(1536), "1.5K"},
		{"just under M", int64Ptr(1048575), "1024.0K"},
		{"one M", int64Ptr(1048576), "1.0M"},
		{"gigabytes", int64Ptr(5 * 1024 * 1024 * 1024), "5.0G"},
		{"large G", int64Ptr(1500 * 1024 * 1024 * 1024), "1500.0G"},
		{"negative", int64Ptr(-5), "-5B"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FmtSize(tc.in); got != tc.want {
				t.Errorf("FmtSize(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func int64Ptr(n int64) *int64 { return &n }
