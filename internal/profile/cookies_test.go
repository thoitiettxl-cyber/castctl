// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func cookiesFileIno(t *testing.T, path string) uint64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("stat did not return *syscall.Stat_t; the inode assertion is unavailable")
	}
	return sys.Ino
}

// TestWriteCookiesFileBakIsCopyBeforeRename (K-LIVE-2): the
// backup must be produced by copying the previous file to
// .bak BEFORE the new file is renamed over the target, so the
// target is never absent mid-write. A rename-based backup
// reuses the previous file's inode for .bak; a copy does not.
// That inode difference is the deterministic observable for
// the ordering: RED on e4ef8c5 (rename), GREEN on the copy.
func TestWriteCookiesFileBakIsCopyBeforeRename(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "cookies.txt")
	old := []byte("hatch_sess=OLD\n")
	if err := os.WriteFile(dest, old, 0o644); err != nil {
		t.Fatal(err)
	}
	oldIno := cookiesFileIno(t, dest)
	neu := []byte("hatch_sess=NEW\n")
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
	if ino := cookiesFileIno(t, dest+".bak"); ino == oldIno {
		t.Errorf(".bak inode=%d equals the old file's inode: the backup was a rename, so the target was absent mid-write", ino)
	}
	if got := mustReadFile(t, dest); string(got) != string(neu) {
		t.Errorf("cookies bytes=%q, want %q", got, neu)
	}
	if mode := cookiesFileMode(t, dest); mode != 0o600 {
		t.Errorf("cookies mode=%o, want 0600", mode)
	}
}

// TestWriteCookiesFileBakPreservesSymlink (K-LIVE-2 guard): when
// the previous cookies file is a symlink, .bak remains a
// symlink to the same target, the target's content and mode
// are untouched, and the new cookies file is a regular 0600
// file. This pins the documented symlink rule under the
// copy-based backup; it passes on the old rename code too.
func TestWriteCookiesFileBakPreservesSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target.txt")
	old := []byte("hatch_sess=OLD\n")
	if err := os.WriteFile(target, old, 0o644); err != nil {
		t.Fatal(err)
	}
	// Record the target's mode as created (subject to umask):
	// the write must leave it untouched, whatever it is.
	targetMode := cookiesFileMode(t, target)
	dest := filepath.Join(base, "cookies.txt")
	if err := os.Symlink(target, dest); err != nil {
		t.Fatal(err)
	}
	neu := []byte("hatch_sess=NEW\n")
	backup, err := WriteCookiesFile(base, "default", dest, neu)
	if err != nil {
		t.Fatal(err)
	}
	if !backup {
		t.Errorf("backup=false, want true when a previous (symlink) file existed")
	}
	lst, err := os.Lstat(dest + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if lst.Mode()&os.ModeSymlink == 0 {
		t.Fatalf(".bak is not a symlink (mode=%v)", lst.Mode())
	}
	linkTarget, err := os.Readlink(dest + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if linkTarget != target {
		t.Errorf(".bak points at %q, want %q", linkTarget, target)
	}
	if got := mustReadFile(t, target); string(got) != string(old) {
		t.Errorf("symlink target bytes=%q, want untouched %q", got, old)
	}
	if mode := cookiesFileMode(t, target); mode != targetMode {
		t.Errorf("symlink target mode=%o, want untouched %o", mode, targetMode)
	}
	lst, err = os.Lstat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("cookies file is still a symlink; want a regular file")
	}
	if got := mustReadFile(t, dest); string(got) != string(neu) {
		t.Errorf("cookies bytes=%q, want %q", got, neu)
	}
	if mode := cookiesFileMode(t, dest); mode != 0o600 {
		t.Errorf("cookies mode=%o, want 0600", mode)
	}
}

// TestWriteCookiesFileBakIsDirectory (N4, loop 2): a directory at
// the .bak path refuses the write with the destination untouched
// and the directory still in place. Pins the guard under the
// temp-file backup implementation; it passed on the old code
// too (guard pre-dates loop 2).
func TestWriteCookiesFileBakIsDirectory(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "cookies.txt")
	old := []byte("hatch_sess=OLD\n")
	if err := os.WriteFile(dest, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dest+".bak", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteCookiesFile(base, "default", dest, []byte("hatch_sess=NEW\n")); err == nil {
		t.Fatalf(".bak is a directory: got no error")
	}
	if got := mustReadFile(t, dest); string(got) != string(old) {
		t.Errorf("cookies bytes=%q after failed write, want untouched %q", got, old)
	}
	if st, err := os.Stat(dest + ".bak"); err != nil || !st.IsDir() {
		t.Errorf(".bak directory missing or changed (stat err=%v, isDir=%v)", err, st != nil && st.IsDir())
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") || strings.HasPrefix(e.Name(), ".cookies-bak-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// TestWriteCookiesFileBakPreservedOnCopyFailure (N4, loop 2):
// when the backup copy cannot be made (unwritable directory),
// the stale .bak survives and the destination is untouched —
// the old .bak is never deleted before the new copy succeeds.
// Skipped as root: permission bits do not fail writes for uid 0.
func TestWriteCookiesFileBakPreservedOnCopyFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("read-only directory does not fail writes as root")
	}
	base := t.TempDir()
	dest := filepath.Join(base, "cookies.txt")
	old := []byte("hatch_sess=OLD\n")
	staleBak := []byte("hatch_sess=STALE-BAK\n")
	if err := os.WriteFile(dest, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest+".bak", staleBak, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o700) })
	if _, err := WriteCookiesFile(base, "default", dest, []byte("hatch_sess=NEW\n")); err == nil {
		t.Fatalf("unwritable directory: got no error")
	}
	if got := mustReadFile(t, dest); string(got) != string(old) {
		t.Errorf("cookies bytes=%q after failed write, want untouched %q", got, old)
	}
	if got := mustReadFile(t, dest+".bak"); string(got) != string(staleBak) {
		t.Errorf(".bak bytes=%q after failed write, want preserved %q", got, staleBak)
	}
}

// TestWriteCookiesFileStaleBakSymlinkReplaced (N4, loop 2): a
// stale .bak symlink is replaced by a regular 0600 file holding
// the previous bytes; the symlink's victim is never written
// through. Pins the rename-over behaviour of the temp-file
// backup; it passed on the old remove-then-write code too.
func TestWriteCookiesFileStaleBakSymlinkReplaced(t *testing.T) {
	base := t.TempDir()
	victim := filepath.Join(base, "victim.txt")
	victimBytes := []byte("victim\n")
	if err := os.WriteFile(victim, victimBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(base, "cookies.txt")
	old := []byte("hatch_sess=OLD\n")
	if err := os.WriteFile(dest, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, dest+".bak"); err != nil {
		t.Fatal(err)
	}
	neu := []byte("hatch_sess=NEW\n")
	backup, err := WriteCookiesFile(base, "default", dest, neu)
	if err != nil {
		t.Fatal(err)
	}
	if !backup {
		t.Errorf("backup=false, want true when a previous file existed")
	}
	lst, err := os.Lstat(dest + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		t.Fatalf(".bak is still a symlink; want a regular file")
	}
	if got := mustReadFile(t, dest+".bak"); string(got) != string(old) {
		t.Errorf(".bak bytes=%q, want previous file bytes %q", got, old)
	}
	if mode := cookiesFileMode(t, dest+".bak"); mode != 0o600 {
		t.Errorf(".bak mode=%o, want 0600", mode)
	}
	if got := mustReadFile(t, victim); string(got) != string(victimBytes) {
		t.Errorf("victim bytes=%q, want untouched %q", got, victimBytes)
	}
	if got := mustReadFile(t, dest); string(got) != string(neu) {
		t.Errorf("cookies bytes=%q, want %q", got, neu)
	}
}
