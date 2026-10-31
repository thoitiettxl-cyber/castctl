// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package update implements the `castctl update` self-update command:
// fetch the latest stable GitHub Release, verify the matching archive
// against the release checksums file, and atomically replace the
// running binary. It uses only the standard library, makes no config
// writes, and fails closed on every ambiguity.
package update
