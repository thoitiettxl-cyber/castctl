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
// The write order is: durable temp file first, then rename the
// existing destination to .bak, then rename the temp file into
// place. A failure before the final rename leaves the previous
// file untouched (or, if the backup rename already happened, in
// .bak). Both the cookies file and .bak end at mode 0600: the
// cookies file via the temp file's mode, .bak via an explicit
// chmod after the rename (a rename alone would keep the previous
// file's mode). No previous file means no .bak and backup=false.
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
		if err := os.Rename(cookiesPath, bak); err != nil {
			return false, err
		}
		// Chmod the backup explicitly: the rename keeps the old
		// mode, and the backup must be 0600 like the cookies
		// file. Skip it for a symlink backup: chmod would follow
		// the link and change the target's mode.
		if lst, lerr := os.Lstat(bak); lerr == nil && lst.Mode()&os.ModeSymlink == 0 {
			if err := os.Chmod(bak, 0o600); err != nil {
				return false, err
			}
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
