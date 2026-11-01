// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build !cgo || !linux

package pluginhost

import "fmt"

// testBinaryHasGLIBCReqs is false here: darwin/windows and
// no-cgo binaries do not carry ELF GLIBC_ requirements.
const testBinaryHasGLIBCReqs = false

// runningLibcVersion is unknown on builds without cgo/glibc:
// gnu_get_libc_version is a glibc extension and is unavailable
// on darwin, windows, and no-cgo builds. Callers treat this as
// a fail-closed refusal for any plugin WITH version
// requirements (see CheckPluginCompat); it is never reported
// as a successful check.
func runningLibcVersion() (glibcVersion, error) {
	return glibcVersion{}, fmt.Errorf("running libc version is unknown on this build")
}
