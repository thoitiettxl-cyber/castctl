// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build !windows && !linux && !darwin && !freebsd

package pluginhost

import "os"

// openPluginSource opens a plugin artifact. No O_NOFOLLOW
// equivalent exists on this platform; the Lstat symlink refusal
// in shadowCopyToDir is the check here.
func openPluginSource(path string) (*os.File, error) {
	return os.Open(path)
}
