// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build !linux && !darwin && !freebsd

package pluginhost

import "os"

// checkHardlink is a no-op on platforms without a Stat_t
// Nlink equivalent (Windows): the shadow copy refuses
// symlinks and non-regular files only. See docs/plugins.md.
func checkHardlink(info os.FileInfo) error { return nil }

// checkShadowDirOwnership is a no-op on platforms without
// a uid ownership check; directory hardening is
// best-effort there.
func checkShadowDirOwnership(info os.FileInfo) error { return nil }

// pidAlive is unknown on this platform, so the stale shadow
// sweep conservatively keeps every pid directory: only the
// process's own directory is removed on Host.Close.
func pidAlive(pid int) bool { return true }
