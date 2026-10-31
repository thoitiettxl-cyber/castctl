// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Command fakeflood prints 1 MiB on --version. Test-only fixture.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Print(strings.Repeat("x", 1<<20))
		return
	}
	fmt.Fprintln(os.Stderr, "fakeflood: only --version is supported")
	os.Exit(2)
}
