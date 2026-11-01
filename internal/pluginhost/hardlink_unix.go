// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build linux || darwin || freebsd

package pluginhost

import (
	"fmt"
	"os"
	"syscall"
)

// checkHardlink refuses a plugin file with more than one
// hard link (Nlink > 1): a hardlinked artifact shares its
// inode with another path, so replacing or removing the
// other path changes the bytes a load would map. The check
// is unix-only; Windows/macOS behaviour is documented in
// docs/plugins.md (Windows has no Nlink equivalent and
// refuses symlinks + non-regular files only; darwin uses
// this file).
func checkHardlink(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if stat.Nlink > 1 {
		return fmt.Errorf("plugin file must not be a hard link (nlink=%d)", stat.Nlink)
	}
	return nil
}

// checkShadowDirOwnership refuses a pre-existing shadow
// directory owned by another uid: a directory another user
// planted must not become the load directory. Best-effort
// hardening (Chmod) lives in shadowDir; ownership is a
// hard refusal on unix.
func checkShadowDirOwnership(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("shadow directory is owned by another user")
	}
	return nil
}

// pidAlive reports whether pid names a live process:
// Kill(pid, 0) succeeds or is refused for permission
// (alive, other uid); ESRCH means no such process.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
