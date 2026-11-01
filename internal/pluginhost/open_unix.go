// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build linux || darwin || freebsd

package pluginhost

import (
	"os"
	"syscall"
)

// openPluginSource opens a plugin artifact refusing symlinks at
// open time (O_NOFOLLOW), as defence in depth over the Lstat
// check in shadowCopyToDir.
func openPluginSource(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
