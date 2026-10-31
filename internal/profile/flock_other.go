// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build !unix

package profile

import (
	"errors"
	"os"
)

// flockExclusive is unsupported off unix: guarded writes fail closed
// rather than running unlocked (see guard.go).
func flockExclusive(f *os.File) error {
	return errors.New("flock is not supported on this platform")
}

// flockTryExclusive is unsupported off unix: guarded writes fail
// closed rather than running unlocked.
func flockTryExclusive(f *os.File) (bool, error) {
	return false, errors.New("flock is not supported on this platform")
}
