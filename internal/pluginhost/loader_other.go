// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && !linux && !darwin && !freebsd && !windows && !android

package pluginhost

import "fmt"

// Default-loader coverage for cgo builds on GOOSes outside
// the claimed targets (linux/darwin/freebsd/windows):
// dynamic loading is refused with a clear error instead of
// failing to compile for a missing defaultLoader (the stub
// covers no-cgo and android builds; the unix loader covers
// cgo linux/darwin/freebsd; the windows loader covers
// windows). No load has ever run on such a target.
type otherLoader struct{}

func defaultLoader() Loader { return otherLoader{} }

// supportValue mirrors the stub loader: dynamic loading is
// refused on this platform, so SupportValue reports "0".
// (Without this definition the package does not compile for
// cgo builds on GOOSes outside the claimed set.)
const supportValue = "0"

func (otherLoader) Open(file File, host *Host) (Client, error) {
	return nil, fmt.Errorf("dynamic library plugin loading is not supported on this platform: %s", file.Path)
}
