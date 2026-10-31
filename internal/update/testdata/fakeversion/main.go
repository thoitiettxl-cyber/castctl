// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Command fakeversion is a test-only stand-in for a downloaded castctl
// binary. It prints "castctl <version>" for --version, where <version>
// comes from CASTCTL_FAKE_VERSION (default 0.6.4). CASTCTL_FAKE_MODE
// selects hostile behaviours: hang, flood, mismatch, hostile, exit1,
// segv. Never used outside tests; never shipped.
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		switch os.Getenv("CASTCTL_FAKE_MODE") {
		case "hang":
			time.Sleep(5 * time.Minute)
		case "flood":
			fmt.Print(strings.Repeat("x", 1<<20))
			return
		case "mismatch":
			fmt.Println("castctl 9.9.9 (deadbeef 2026-01-01T00:00:00Z)")
			return
		case "hostile":
			fmt.Println("castctl 0.6.4\ninjected log line\x1b[31m")
			return
		case "exit1":
			os.Exit(1)
		case "segv":
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGSEGV)
			time.Sleep(time.Second)
			return
		}
		fmt.Printf("castctl %s (deadbeef 2026-01-01T00:00:00Z)\n", fakeVersion())
		return
	}
	fmt.Fprintln(os.Stderr, "fakeversion: only --version is supported")
	os.Exit(2)
}

func fakeVersion() string {
	if v := os.Getenv("CASTCTL_FAKE_VERSION"); v != "" {
		return v
	}
	return "0.6.4"
}
