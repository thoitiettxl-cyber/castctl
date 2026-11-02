// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build windows

package pluginhost

import "os"

// openPluginSource opens a plugin artifact. Windows has no
// O_NOFOLLOW; the Lstat symlink refusal in shadowCopyToDir is
// the check on this platform.
func openPluginSource(path string) (*os.File, error) {
	return os.Open(path)
}
