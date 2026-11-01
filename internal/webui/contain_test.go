// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRejectNewUIDirRelativeConfigDir is the API-save half of
// the relative --config defect: rejectNewUIDir receives the
// config directory as given (relative for a relative --config
// path). An unrelated absolute ui_dir must be accepted; every
// overlapping spelling must still be refused. The cookiesFiles
// argument carries RAW config values (relative to the config
// directory), as profileCookiesFiles returns them.
func TestRejectNewUIDirRelativeConfigDir(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.MkdirAll(filepath.Join(root, "sub", "ui2"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The unrelated tree must live OUTSIDE root: a path under
	// root would be inside the "." config directory.
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	subAbs := filepath.Join(root, "sub")
	cases := []struct {
		name      string
		configDir string
		value     string
		cookies   map[string]string
		reject    bool
	}{
		{"dot base unrelated absolute", ".", elsewhere, nil, false},
		{"subdir base unrelated absolute", "sub", elsewhere, nil, false},
		{"absolute base unrelated absolute", subAbs, elsewhere, nil, false},
		{"dot base relative inside", ".", "ui", nil, true},
		{"dot base subdir inside", ".", "sub/ui", nil, true},
		{"dot base equal absolute", ".", root, nil, true},
		{"dot base dot", ".", ".", nil, true},
		{"dot base dotdot", ".", "..", nil, true},
		{"subdir base equal absolute", "sub", subAbs, nil, true},
		{"subdir base dot", "sub", ".", nil, true},
		{"subdir base relative inside", "sub", "ui2", nil, true},
		{"subdir base ancestor absolute", "sub", root, nil, true},
		// Cookies file inside the new root, spelled relative
		// to the config directory: "../ext/cookies.json"
		// from "sub" lands inside the root at /ext.
		{"cookies inside root", "sub", filepath.Join(root, "ext"), map[string]string{"default": "../ext/cookies.json"}, true},
		{"cookies outside root", "sub", elsewhere, map[string]string{"default": "../sub/ui2/cookies.json"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rejectNewUIDir(tc.configDir, tc.value, tc.cookies)
			if tc.reject && err == nil {
				t.Fatalf("configDir %q ui_dir %q: accepted, want rejection", tc.configDir, tc.value)
			}
			if !tc.reject && err != nil {
				t.Fatalf("configDir %q ui_dir %q: unexpected error: %v", tc.configDir, tc.value, err)
			}
		})
	}
}

// TestCheckUIDirRelativeConfigDir is the startup-check half of
// the relative --config defect: checkUIDir receives the config
// directory as given. An unrelated absolute ui root must be
// accepted; a root overlapping the config directory, or
// containing a cookies file, must still be refused. The
// cookiesFiles argument carries values already joined with
// the config directory (as resolveCookiesFile produces), so
// they are relative to the working directory when the config
// directory is relative.
func TestCheckUIDirRelativeConfigDir(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	// The unrelated tree must live OUTSIDE root: a path under
	// root would be inside the "." config directory.
	ext := filepath.Join(t.TempDir(), "ext")
	if err := os.MkdirAll(ext, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ext, "index.html"), []byte("<html>MARKER-CHECK-UI</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(filepath.Join(sub, "ui2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "ui2", "index.html"), []byte("<html>x</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "ui2", "cookies.json"), []byte(`{"cookies":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// An index.html directly under sub/ so the "root is the
	// config subdir" case is refused for overlap, not for a
	// missing index file.
	if err := os.WriteFile(filepath.Join(sub, "index.html"), []byte("<html>sub</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<html>root</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	ui2Abs := filepath.Join(sub, "ui2")
	cases := []struct {
		name      string
		configDir string
		uiDir     string
		cookies   []string
		reject    bool
	}{
		{"dot base unrelated absolute", ".", ext, nil, false},
		{"subdir base unrelated absolute", "sub", ext, nil, false},
		{"dot base root is config dir", ".", root, nil, true},
		{"subdir base root is config dir", "sub", root, nil, true},
		{"subdir base root is config subdir", "sub", sub, nil, true},
		// Joined cookies value "sub/ui2/cookies.json" is
		// inside the root at sub/ui2: must be refused.
		{"cookies inside root", "sub", ui2Abs, []string{"sub/ui2/cookies.json"}, true},
		// Same joined value is outside the unrelated root.
		{"cookies outside root", "sub", ext, []string{"sub/ui2/cookies.json"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkUIDir(tc.configDir, tc.uiDir, tc.cookies)
			if tc.reject && err == nil {
				t.Fatalf("configDir %q ui_dir %q cookies %v: accepted, want rejection", tc.configDir, tc.uiDir, tc.cookies)
			}
			if !tc.reject && err != nil {
				t.Fatalf("configDir %q ui_dir %q cookies %v: unexpected error: %v", tc.configDir, tc.uiDir, tc.cookies, err)
			}
		})
	}
}
