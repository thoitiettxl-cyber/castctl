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
// EnsureProfileDir (0700 for named profiles, 0755 for the default
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
// cookies file gets its mode via the temp file; .bak is a
// fresh file created at 0600 (plus an explicit chmod), so a
// stale .bak's mode never survives. No previous file means
// no .bak and backup=false.
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
// destination is never absent mid-write (K-LIVE-2). A stale
// .bak is replaced, never reused: the copy is a fresh file at
// mode 0600. A directory at the .bak path is an error, never
// removed, so a failed backup leaves the destination
// untouched. When the previous file is a symlink, .bak is
// created as a symlink to the same target and the target is
// never read or chmodded.
func backupCookiesFile(cookiesPath, bak string) error {
	if st, err := os.Stat(bak); err == nil && st.IsDir() {
		return fmt.Errorf("backup path %q is a directory", bak)
	}
	lst, err := os.Lstat(cookiesPath)
	if err != nil {
		return err
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(cookiesPath)
		if err != nil {
			return err
		}
		if err := os.Symlink(target, bak); err != nil {
			if !os.IsExist(err) {
				return err
			}
			if err := os.Remove(bak); err != nil {
				return err
			}
			return os.Symlink(target, bak)
		}
		return nil
	}
	data, err := os.ReadFile(cookiesPath)
	if err != nil {
		return err
	}
	// Replace any stale .bak (regular file or symlink): the
	// copy must be a fresh file, never a write through a
	// stale symlink into its target. A directory was refused
	// above, so Remove here cannot delete one.
	_ = os.Remove(bak)
	if err := os.WriteFile(bak, data, 0o600); err != nil {
		return err
	}
	// Fresh files already carry 0600; the explicit chmod is
	// defence in depth for a stale file the Remove missed.
	if lst, lerr := os.Lstat(bak); lerr == nil && lst.Mode()&os.ModeSymlink == 0 {
		if err := os.Chmod(bak, 0o600); err != nil {
			return err
		}
	}
	return nil
}
