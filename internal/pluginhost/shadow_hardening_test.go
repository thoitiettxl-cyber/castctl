// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestShadowCopyHardlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hardlink (Nlink) check is unix-only; Windows refuses symlinks + non-regular files only")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "echo.so")
	if err := os.WriteFile(src, []byte("fake-plugin-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "hardlink.so")
	if err := os.Link(src, link); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if _, err := ShadowCopy(File{ID: "echo", Path: link}); err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("hardlink source err = %v, want hard-link refusal", err)
	}
}

func TestShadowCopySymlinkedComponentRefused(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	via := filepath.Join(realDir, "via.so")
	if err := os.WriteFile(via, []byte("fake-plugin-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "aliasdir")
	if err := os.Symlink(realDir, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := ShadowCopy(File{ID: "echo", Path: filepath.Join(alias, "via.so")}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked-component source err = %v, want symlink refusal", err)
	}
}

func TestShadowCopyTraversalIDRefused(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "echo.so")
	if err := os.WriteFile(src, []byte("fake-plugin-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"../../evil", "a/b", "", "echo\nx", strings.Repeat("e", 129)} {
		if _, err := ShadowCopy(File{ID: id, Path: src}); err == nil {
			t.Fatalf("ShadowCopy id %q = nil, want invalid-id refusal", id)
		}
	}
}

func TestShadowDirHardeningAndCleanup(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "echo.so")
	if err := os.WriteFile(src, []byte("fake-plugin-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	shadow, err := ShadowCopy(File{ID: "echo", Path: src})
	if err != nil {
		t.Fatal(err)
	}
	ownDir, err := shadowDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(shadow, ownDir) {
		t.Fatalf("shadow = %q, want under %q", shadow, ownDir)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(ownDir); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("shadow dir perms = %v, want 0700", info.Mode())
		}
	}
	CleanupShadowDir()
	if _, err := os.Stat(ownDir); !os.IsNotExist(err) {
		t.Fatalf("shadow dir still exists after CleanupShadowDir: %v", err)
	}
	// A later load recreates the directory.
	if _, err := ShadowCopy(File{ID: "echo", Path: src}); err != nil {
		t.Fatal(err)
	}
	CleanupShadowDir()
}

func TestSweepStaleShadowDirs(t *testing.T) {
	root := shadowRoot()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	// A pid dir for a certainly-dead pid (a huge pid that
	// cannot be live on this VM) is swept; a non-matching
	// name and a live pid's dir are kept.
	dead := filepath.Join(root, "pid-4242424242")
	if err := os.MkdirAll(dead, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dead, "castctl-plugin-echo-dead.so"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "not-a-pid-dir")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	sweepStaleShadowDirs()
	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Fatalf("dead pid dir not swept: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("non-pid dir swept: %v", err)
	}
	_ = os.RemoveAll(other)
}
