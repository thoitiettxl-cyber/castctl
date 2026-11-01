// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// No-symbol fixture: a c-shared library that exports no
// castctl_plugin_init, so the loader must fail on the missing
// symbol with a clear error.
package main

func main() {}
