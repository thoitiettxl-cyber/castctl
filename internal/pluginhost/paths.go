// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// refuseSymlinkedComponents refuses a path whose final
// component or any path component is a symlink. Lstat /
// O_NOFOLLOW checks on the final component alone do not
// catch a symlinked directory component (aliasdir/via.so),
// so every component of the absolute path is Lstat-checked.
// Plugin roots must therefore be real directories: a path
// traversing a symlinked directory (including a symlinked
// $TMPDIR on macOS) is refused; pass a resolved path
// instead. The shadow directory itself is exempt: it lives
// under os.TempDir() and is created by castctl, not named
// by an operator path.
func refuseSymlinkedComponents(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	abs = filepath.Clean(abs)
	vol := filepath.VolumeName(abs)
	rest := strings.TrimPrefix(abs, vol)
	rest = strings.TrimPrefix(rest, string(filepath.Separator))
	cur := vol
	if cur == "" {
		cur = string(filepath.Separator)
	} else {
		cur += string(filepath.Separator)
	}
	for _, comp := range strings.Split(rest, string(filepath.Separator)) {
		if comp == "" || comp == "." {
			continue
		}
		cur = filepath.Join(cur, comp)
		info, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("plugin path %q traverses a symlink at %q", path, cur)
		}
	}
	return nil
}
