// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteCookiesFile replaces the cookies file at cookiesPath with data,
// preserving the previous file (if any) as cookiesPath + ".bak".
// It is the only cookies-file writer in the tree (auth import); no
// config file is read or written here, and no config entry is created.
//
// cookiesPath must be the already-resolved absolute path
// (Profile.CookiesFile); it is never recomputed here. The parent
// directory is created only when the path is inside baseDir
// (CONFIG_DIR): the profile's default path goes through
// EnsureProfileDir (0700 for named profiles and for the default
// directory), any other inside path gets its parent created at 0700.
// A path outside baseDir is written only when its parent already
// exists; a missing outside parent is an error (fail closed: never
// create directories at an arbitrary user-configured path).
//
// The write order is: durable temp file first, then copy the
// existing destination to .bak, then rename the temp file over
// the destination. The copy-before-rename order means the
// destination is never absent: at every moment it holds either
// the previous bytes or the new bytes, never nothing. A failure
// before the final rename leaves the previous file untouched
// (the .bak copy is a spare copy, not the file itself). Both
// the cookies file and .bak end at mode 0600, except when the
// previous file was a symlink to an existing file: then .bak
// remains that symlink (no copy is made and no chmod is done,
// so the symlink's target keeps its mode and content
// untouched) and only the new cookies file ends at 0600. The
// cookies file gets its mode via the temp file; .bak is
// written to a temp file at 0600, fsynced, and renamed over
// any stale .bak, so a stale .bak's mode never survives and
// the previous .bak is preserved until the new copy is
// durable. No previous file means no .bak and backup=false.
// Concurrent imports are last-writer-wins: each write is atomic
// (rename), there is no torn file, and no lock is taken — the
// flock+sha256 guard protects config.json only and does not apply
// here. data is written exactly as given; callers own normalisation.
func WriteCookiesFile(baseDir, profileName, cookiesPath string, data []byte) (bool, error) {
	if !filepath.IsAbs(cookiesPath) {
		return false, fmt.Errorf("cookies path %q is not absolute", cookiesPath)
	}
	cookiesPath = filepath.Clean(cookiesPath)
	paths, err := ProfilePaths(baseDir, profileName)
	if err != nil {
		return false, err
	}
	switch {
	case cookiesPath == paths.Cookies:
		if _, err := EnsureProfileDir(baseDir, profileName); err != nil {
			return false, err
		}
	case isInsideDir(cookiesPath, baseDir):
		if err := os.MkdirAll(filepath.Dir(cookiesPath), 0o700); err != nil {
			return false, err
		}
	default:
		parent := filepath.Dir(cookiesPath)
		st, err := os.Stat(parent)
		if err != nil {
			return false, fmt.Errorf("cookies parent directory %q: %w", parent, err)
		}
		if !st.IsDir() {
			return false, fmt.Errorf("cookies parent %q is not a directory", parent)
		}
	}

	dir := filepath.Dir(cookiesPath)
	tmpName, err := writeTempFile(dir, data, 0o600)
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmpName) }()

	backup := false
	if st, err := os.Stat(cookiesPath); err == nil {
		if st.IsDir() {
			return false, fmt.Errorf("cookies path %q is a directory", cookiesPath)
		}
		bak := cookiesPath + ".bak"
		if err := backupCookiesFile(cookiesPath, bak); err != nil {
			return false, err
		}
		backup = true
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := os.Rename(tmpName, cookiesPath); err != nil {
		return false, err
	}
	return backup, nil
}

// backupCookiesFile copies the previous cookies file to bak
// BEFORE the new file is renamed over the destination, so the
// destination is never absent mid-write (K-LIVE-2). The copy is
// written to a temp file in the same directory, fsynced, and
// renamed over .bak: the previous .bak survives until the new
// copy is durable, and a failed copy leaves both the previous
// .bak and the destination untouched. The directory entry is
// synced best-effort after the rename (errors ignored: opening
// a directory for sync is not portable everywhere); the file
// sync itself is required and its error propagates. A
// directory at the .bak path is an error, never removed, so a
// failed backup leaves the destination untouched. When the
// previous file is a symlink, .bak is created as a symlink to
// the same target (via a temp link name + rename, so a stale
// .bak symlink is replaced atomically) and the target is never
// read or chmodded.
func backupCookiesFile(cookiesPath, bak string) error {
	if st, err := os.Stat(bak); err == nil && st.IsDir() {
		return fmt.Errorf("backup path %q is a directory", bak)
	}
	lst, err := os.Lstat(cookiesPath)
	if err != nil {
		return err
	}
	dir := filepath.Dir(bak)
	if lst.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(cookiesPath)
		if err != nil {
			return err
		}
		// Link at a temp name, then rename over .bak: the
		// stale .bak (if any) is replaced atomically and
		// survives a failed link creation.
		tmp, err := os.CreateTemp(dir, ".cookies-bak-*.tmp")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		if err := os.Symlink(target, tmpName); err != nil {
			_ = os.Remove(tmpName)
			return err
		}
		if err := os.Rename(tmpName, bak); err != nil {
			_ = os.Remove(tmpName)
			return err
		}
		syncDir(dir)
		return nil
	}
	data, err := os.ReadFile(cookiesPath)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".cookies-bak-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, bak); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	syncDir(dir)
	return nil
}

// syncDir fsyncs a directory entry best-effort: a crash after
// the rename must not lose the new .bak name on filesystems
// that journal directory entries separately. Errors are
// ignored (opening a directory for sync is not portable on
// every target); the backup copy's own Sync above is the
// required durability step.
func syncDir(dir string) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = f.Sync()
	_ = f.Close()
}
