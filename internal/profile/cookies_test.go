// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cookiesFileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestWriteCookiesFileFreshDefault(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "cookies.txt")
	data := []byte("hatch_sess=FAKE; datr=FAKE\n")
	backup, err := WriteCookiesFile(base, "default", dest, data)
	if err != nil {
		t.Fatal(err)
	}
	if backup {
		t.Errorf("backup=true, want false on first write")
	}
	if got := mustReadFile(t, dest); string(got) != string(data) {
		t.Errorf("cookies bytes=%q, want %q", got, data)
	}
	if mode := cookiesFileMode(t, dest); mode != 0o600 {
		t.Errorf("cookies mode=%o, want 0600", mode)
	}
	if _, err := os.Stat(dest + ".bak"); !os.IsNotExist(err) {
		t.Errorf(".bak exists after first write (err=%v)", err)
	}
}

func TestWriteCookiesFileNamedCreatesDirs(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "profiles", "work", "cookies.txt")
	backup, err := WriteCookiesFile(base, "work", dest, []byte("hatch_sess=FAKE\n"))
	if err != nil {
		t.Fatal(err)
	}
	if backup {
		t.Errorf("backup=true, want false on first write")
	}
	if mode := cookiesFileMode(t, filepath.Join(base, "profiles")); mode != 0o700 {
		t.Errorf("profiles/ mode=%o, want 0700", mode)
	}
	if mode := cookiesFileMode(t, filepath.Join(base, "profiles", "work")); mode != 0o700 {
		t.Errorf("profiles/work/ mode=%o, want 0700", mode)
	}
	if mode := cookiesFileMode(t, dest); mode != 0o600 {
		t.Errorf("cookies mode=%o, want 0600", mode)
	}
}

func TestWriteCookiesFileBackupContentsAndModes(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "cookies.txt")
	old := []byte("hatch_sess=OLD; datr=OLD\n")
	if err := os.WriteFile(dest, old, 0o644); err != nil {
		t.Fatal(err)
	}
	stale := []byte("stale backup\n")
	if err := os.WriteFile(dest+".bak", stale, 0o644); err != nil {
		t.Fatal(err)
	}
	neu := []byte("hatch_sess=NEW; datr=NEW\n")
	backup, err := WriteCookiesFile(base, "default", dest, neu)
	if err != nil {
		t.Fatal(err)
	}
	if !backup {
		t.Errorf("backup=false, want true when a previous file existed")
	}
	if got := mustReadFile(t, dest+".bak"); string(got) != string(old) {
		t.Errorf(".bak bytes=%q, want previous file bytes %q", got, old)
	}
	if mode := cookiesFileMode(t, dest+".bak"); mode != 0o600 {
		t.Errorf(".bak mode=%o, want 0600", mode)
	}
	if got := mustReadFile(t, dest); string(got) != string(neu) {
		t.Errorf("cookies bytes=%q, want %q", got, neu)
	}
	if mode := cookiesFileMode(t, dest); mode != 0o600 {
		t.Errorf("cookies mode=%o, want 0600", mode)
	}
}

func TestWriteCookiesFileSecondWriteReplacesBak(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "cookies.txt")
	a := []byte("hatch_sess=A\n")
	b := []byte("hatch_sess=B\n")
	if _, err := WriteCookiesFile(base, "default", dest, a); err != nil {
		t.Fatal(err)
	}
	backup, err := WriteCookiesFile(base, "default", dest, b)
	if err != nil {
		t.Fatal(err)
	}
	if !backup {
		t.Errorf("backup=false on second write, want true")
	}
	if got := mustReadFile(t, dest+".bak"); string(got) != string(a) {
		t.Errorf(".bak bytes=%q, want %q", got, a)
	}
	if got := mustReadFile(t, dest); string(got) != string(b) {
		t.Errorf("cookies bytes=%q, want %q", got, b)
	}
}

func TestWriteCookiesFileCustomInsidePath(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "custom", "sub", "cookies.txt")
	if _, err := WriteCookiesFile(base, "default", dest, []byte("hatch_sess=FAKE\n")); err != nil {
		t.Fatal(err)
	}
	if mode := cookiesFileMode(t, filepath.Join(base, "custom", "sub")); mode != 0o700 {
		t.Errorf("custom parent mode=%o, want 0700", mode)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatal(err)
	}
}

func TestWriteCookiesFileOutsideExistingParent(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	dest := filepath.Join(outside, "cookies.txt")
	if _, err := WriteCookiesFile(base, "default", dest, []byte("hatch_sess=FAKE\n")); err != nil {
		t.Fatal(err)
	}
	if got := mustReadFile(t, dest); string(got) != "hatch_sess=FAKE\n" {
		t.Errorf("cookies bytes=%q", got)
	}
}

func TestWriteCookiesFileOutsideMissingParent(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "no-such-dir", "cookies.txt")
	// Move the destination outside CONFIG_DIR with a missing parent:
	// use a sibling temp dir whose parent path does not exist.
	outside := filepath.Join(t.TempDir(), "missing", "cookies.txt")
	if _, err := WriteCookiesFile(base, "default", outside, []byte("hatch_sess=FAKE\n")); err == nil {
		t.Fatalf("missing outside parent: got no error")
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Errorf("file created despite missing parent (err=%v)", err)
	}
	_ = dest
}

func TestWriteCookiesFileRejectsRelativePath(t *testing.T) {
	base := t.TempDir()
	if _, err := WriteCookiesFile(base, "default", "cookies.txt", []byte("hatch_sess=FAKE\n")); err == nil {
		t.Fatalf("relative path: got no error")
	}
}

func TestWriteCookiesFileRejectsDirectoryDest(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "cookies.txt")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteCookiesFile(base, "default", dest, []byte("hatch_sess=FAKE\n")); err == nil {
		t.Fatalf("directory destination: got no error")
	}
	if _, err := os.Stat(dest + ".bak"); !os.IsNotExist(err) {
		t.Errorf(".bak created for directory destination (err=%v)", err)
	}
}

func TestWriteCookiesFileBakRenameFailureLeavesDest(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "cookies.txt")
	old := []byte("hatch_sess=OLD\n")
	if err := os.WriteFile(dest, old, 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory at the .bak path makes the backup rename fail.
	if err := os.MkdirAll(dest+".bak", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteCookiesFile(base, "default", dest, []byte("hatch_sess=NEW\n")); err == nil {
		t.Fatalf(".bak rename failure: got no error")
	}
	if got := mustReadFile(t, dest); string(got) != string(old) {
		t.Errorf("cookies bytes=%q after failed write, want untouched %q", got, old)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
