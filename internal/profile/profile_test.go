// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lookupEnv(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func writeFile(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
}

func TestValidateProfileName(t *testing.T) {
	t.Parallel()
	valid := []string{"work", "a", "A-b_9", strings.Repeat("x", 64), "default", "no.0", "a.b.c"}
	for _, name := range valid {
		if got, err := ValidateProfileName(name); err != nil || got != name {
			t.Errorf("ValidateProfileName(%q) = %q, %v; want %q, nil", name, got, err, name)
		}
	}
	invalid := []string{"", ".", "..", "../x", "a/b", "/abs", "a b", "work.", ".hidden", "...",
		strings.Repeat("x", 65), "é", `a\b`, "~", "a\nb"}
	for _, name := range invalid {
		if _, err := ValidateProfileName(name); err == nil {
			t.Errorf("ValidateProfileName(%q) = nil error; want error", name)
		} else if !errors.Is(err, ErrInvalidProfile) {
			t.Errorf("ValidateProfileName(%q) error %v; want errors.Is ErrInvalidProfile", name, err)
		} else if ExitCode(err) != 2 {
			t.Errorf("ValidateProfileName(%q) ExitCode = %d; want 2", name, ExitCode(err))
		}
	}
	// Non-string input is not expressible in Go; empty is the analogue of None.
	if _, err := ValidateProfileName(""); err == nil {
		t.Error("ValidateProfileName(\"\") = nil error; want error")
	}
}

func TestResolveProfileName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		flag    *string
		env     map[string]string
		want    string
		wantErr bool
	}{
		{name: "no flag no env", env: map[string]string{}, want: "default"},
		{name: "env set", env: map[string]string{ProfileEnv: "work"}, want: "work"},
		{name: "env whitespace ignored", env: map[string]string{ProfileEnv: "  "}, want: "default"},
		{name: "env trimmed", env: map[string]string{ProfileEnv: "  work  "}, want: "work"},
		{name: "flag beats env", flag: strptr("fromflag"), env: map[string]string{ProfileEnv: "fromenv"}, want: "fromflag"},
		{name: "flag empty errors", flag: strptr(""), env: map[string]string{}, wantErr: true},
		{name: "flag invalid errors", flag: strptr("../evil"), env: map[string]string{}, wantErr: true},
		{name: "env invalid errors", env: map[string]string{ProfileEnv: "../../etc"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ResolveProfileName(tc.flag, lookupEnv(tc.env))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ResolveProfileName = %q, nil; want error", got)
				}
				if ExitCode(err) != 2 {
					t.Errorf("ExitCode = %d; want 2", ExitCode(err))
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveProfileName = %q, %v; want %q, nil", got, err, tc.want)
			}
			if got != tc.want {
				t.Errorf("ResolveProfileName = %q; want %q", got, tc.want)
			}
		})
	}
}

func strptr(s string) *string { return &s }

func TestProfilePaths(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	p, err := ProfilePaths(base, "default")
	if err != nil {
		t.Fatal(err)
	}
	if p.Dir != base || p.Config != filepath.Join(base, "config.json") ||
		p.Cookies != filepath.Join(base, "cookies.txt") || p.Chat != filepath.Join(base, "chat.json") {
		t.Errorf("default paths = %+v; want dir=%q", p, base)
	}
	p, err = ProfilePaths(base, "work")
	if err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(base, "profiles", "work")
	if p.Dir != d || p.Config != filepath.Join(d, "config.json") ||
		p.Cookies != filepath.Join(d, "cookies.txt") || p.Chat != filepath.Join(d, "chat.json") {
		t.Errorf("work paths = %+v; want dir=%q", p, d)
	}
	if _, err := ProfilePaths(base, "../evil"); err == nil {
		t.Error("ProfilePaths(invalid) = nil error; want error")
	}
}

func TestEnsureProfileDir(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)

	p, err := EnsureProfileDir(base, "work")
	if err != nil {
		t.Fatal(err)
	}
	if mode := fileMode(t, p.Dir); mode != 0o700 {
		t.Errorf("named dir mode = %o; want 700", mode)
	}
	if mode := fileMode(t, filepath.Join(base, "profiles")); mode != 0o700 {
		t.Errorf("profiles dir mode = %o; want 700", mode)
	}
	// Idempotent, and re-tightens a loosened dir (Python chmods unconditionally).
	if err := os.Chmod(p.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureProfileDir(base, "work"); err != nil {
		t.Fatal(err)
	}
	if mode := fileMode(t, p.Dir); mode != 0o700 {
		t.Errorf("after re-ensure dir mode = %o; want 700", mode)
	}

	// Default dir: created, no 0700 requirement.
	if _, err := EnsureProfileDir(base, "default"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(base); err != nil {
		t.Errorf("default dir missing: %v", err)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestDiscoverProfileNames(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	if err := os.MkdirAll(filepath.Join(base, "profiles", "work"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "profiles", "alt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "profiles", "bad name"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(base, "profiles", "stray-file"), "x", 0o644)

	names, err := DiscoverProfileNames(base)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"default", "alt", "work"}
	if len(names) != len(want) {
		t.Fatalf("DiscoverProfileNames = %v; want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("DiscoverProfileNames = %v; want %v", names, want)
		}
	}

	// Missing base dir: just default, no error.
	names, err = DiscoverProfileNames(filepath.Join(home, "nope"))
	if err != nil || len(names) != 1 || names[0] != "default" {
		t.Errorf("DiscoverProfileNames(missing) = %v, %v; want [default], nil", names, err)
	}
}

// TestDiscoverProfileNamesFollowsSymlinkedDir (loop 4): a symlinked
// profiles/<name> directory is a profile directory, not a file to
// skip: DirEntry.IsDir is false for symlink-to-dir, so discovery
// must follow the link. An unresolvable symlink holds no config and
// is skipped by discovery (migrate itself fails loudly on it; see
// TestMigrateFromSymlinkedProfileDir).
func TestDiscoverProfileNamesFollowsSymlinkedDir(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	realWork := filepath.Join(home, "elsewhere", "work")
	writeFile(t, filepath.Join(realWork, "config.json"), `{"node_id":"WORK-NODE"}`, 0o600)
	if err := os.MkdirAll(filepath.Join(base, "profiles"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realWork, filepath.Join(base, "profiles", "work")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "no-such-dir"), filepath.Join(base, "profiles", "stale")); err != nil {
		t.Fatal(err)
	}
	names, err := DiscoverProfileNames(base)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"default", "work"}
	if len(names) != len(want) {
		t.Fatalf("DiscoverProfileNames = %v; want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("DiscoverProfileNames = %v; want %v", names, want)
		}
	}
}
