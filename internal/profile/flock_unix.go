// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build unix

package profile

import (
	"os"
	"syscall"
)

// flockExclusive takes a blocking exclusive flock on f, retrying on
// EINTR. Closing f releases the lock. No cgo.
func flockExclusive(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err == nil {
			return nil
		}
		if err == syscall.EINTR {
			continue
		}
		return err
	}
}
