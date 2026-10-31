// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Cookie-file lock: serialised read-modify-write for cookies files.
//
// WriteCookiesFile (cookies.go) is atomic per write but takes no
// lock: concurrent writers are last-writer-wins. The session
// keeper, screencast login, and `auth import` all read, merge, and
// rewrite the same cookies file, so a read-modify-write without a
// lock can silently drop another writer's cookies. This file adds
// the lock those writers must hold for the whole read-modify-write
// window — never across a tick sleep, never across network I/O.
//
// The lock file is cookiesPath + ".lock", created mode 0600, never
// deleted (deleting it would let a later opener lock a different
// inode while an earlier holder still holds the old one — the
// same rule as config.json.lock in guard.go). The lock is an
// in-process mutex per lock path plus an inter-process flock on
// the lock file. On non-unix targets lock acquisition fails
// closed, exactly like the config guard: a guarded write never
// silently runs unlocked.

// ErrCookiesLockTimeout reports that the cookies-file lock could
// not be acquired within the caller's deadline. The tick/write
// must be skipped, never forced.
var ErrCookiesLockTimeout = errors.New("cookies lock timeout")

// ensureCookiesParent applies the same parent-directory rules as
// WriteCookiesFile: the default path goes through EnsureProfileDir,
// any other inside-baseDir path gets its parent created at 0700,
// and a path outside baseDir requires an existing parent (fail
// closed: never create directories at an arbitrary
// user-configured path).
func ensureCookiesParent(baseDir, profileName, cookiesPath string) error {
	paths, err := ProfilePaths(baseDir, profileName)
	if err != nil {
		return err
	}
	switch {
	case cookiesPath == paths.Cookies:
		_, err := EnsureProfileDir(baseDir, profileName)
		return err
	case isInsideDir(cookiesPath, baseDir):
		return os.MkdirAll(filepath.Dir(cookiesPath), 0o700)
	default:
		parent := filepath.Dir(cookiesPath)
		st, err := os.Stat(parent)
		if err != nil {
			return fmt.Errorf("cookies parent directory %q: %w", parent, err)
		}
		if !st.IsDir() {
			return fmt.Errorf("cookies parent %q is not a directory", parent)
		}
		return nil
	}
}

// LockCookiesFile acquires the cookies-file lock for cookiesPath
// (already-resolved absolute path) and returns a release function
// the caller must call exactly once. Acquisition tries the
// non-blocking flock until timeout elapses, then returns
// ErrCookiesLockTimeout. A non-positive timeout means "try once".
// The lock is held only for a short read-modify-write window: the
// caller must never sleep, wait on the network, or run a tick
// while holding it.
func LockCookiesFile(baseDir, profileName, cookiesPath string, timeout time.Duration) (release func(), err error) {
	if !filepath.IsAbs(cookiesPath) {
		return nil, fmt.Errorf("cookies path %q is not absolute", cookiesPath)
	}
	cookiesPath = filepath.Clean(cookiesPath)
	if err := ensureCookiesParent(baseDir, profileName, cookiesPath); err != nil {
		return nil, err
	}
	lockPath := cookiesPath + ".lock"
	// No in-process mutex is taken: the flock loop below
	// serialises within a process too, because every
	// acquisition opens the lock file separately (flock locks
	// are per open file description), and the loop honours
	// the caller's deadline. A mutex would need its own
	// timeout to do the same.
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		locked, err := flockTryExclusive(f)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if locked {
			return func() {
				_ = f.Close()
			}, nil
		}
		if timeout <= 0 || time.Now().After(deadline) {
			_ = f.Close()
			return nil, ErrCookiesLockTimeout
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// WriteCookiesFileLocked is WriteCookiesFile under the
// cookies-file lock: it serialises read-modify-write writers
// (keeper, login, auth import) that would otherwise race as
// last-writer-wins. The lock is held only for the write itself.
func WriteCookiesFileLocked(baseDir, profileName, cookiesPath string, data []byte, timeout time.Duration) (bool, error) {
	release, err := LockCookiesFile(baseDir, profileName, cookiesPath, timeout)
	if err != nil {
		return false, err
	}
	defer release()
	return WriteCookiesFile(baseDir, profileName, cookiesPath, data)
}

// LockShortFile acquires a short-lived exclusive flock on an
// arbitrary file (created mode 0600 when missing) and returns a
// release function the caller must call exactly once. The lock
// is retried non-blocking until timeout, then
// ErrCookiesLockTimeout is returned. The caller must hold it
// only for a short check-and-update window: never across a
// sleep, a tick, or network I/O. On non-unix targets
// acquisition fails closed. It is the keeper single-flight
// owner file's lock; it takes no lock-file suffix and never
// deletes the file.
func LockShortFile(path string, timeout time.Duration) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		locked, err := flockTryExclusive(f)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if locked {
			return func() { _ = f.Close() }, nil
		}
		if timeout <= 0 || time.Now().After(deadline) {
			_ = f.Close()
			return nil, ErrCookiesLockTimeout
		}
		time.Sleep(25 * time.Millisecond)
	}
}
