// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build unix

package update

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// acquireUpdateLock takes a non-blocking advisory flock on
// <dir>/.castctl-update.lock, held until the returned release func
// runs (closing the file releases the lock, including on SIGKILL).
// It returns held=true when another update holds the lock: the
// caller fails fast instead of waiting. The lock file is never
// deleted. A lock path that is a symlink, or whose identity changes
// between Lstat and open, refuses (G-75).
func acquireUpdateLock(dir string) (release func(), held bool, err error) {
	path := filepath.Join(dir, lockFileName)
	if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, false, errors.New("update lock file is a symlink")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	// Identity re-check: the opened file must be the path's file.
	after, lerr := os.Lstat(path)
	if lerr != nil {
		_ = f.Close()
		return nil, false, lerr
	}
	opened, serr := f.Stat()
	if serr != nil || !os.SameFile(after, opened) {
		_ = f.Close()
		return nil, false, errors.New("update lock file changed during open")
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = f.Close() }, false, nil
		}
		if err == syscall.EINTR {
			continue
		}
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, true, nil
		}
		return nil, false, err
	}
}
