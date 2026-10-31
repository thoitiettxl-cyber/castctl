// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build !unix

package update

import "errors"

// acquireUpdateLock fails closed off unix, mirroring the profile
// guard: an update must never run unlocked (P10). Non-Linux
// platforms have no release assets and refuse earlier anyway.
func acquireUpdateLock(dir string) (release func(), held bool, err error) {
	return nil, false, errors.New("flock is not supported on this platform")
}
