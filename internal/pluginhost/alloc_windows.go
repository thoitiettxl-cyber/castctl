// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build windows

package pluginhost

import (
	"fmt"
	"syscall"
)

// windowsAlloc/windowFree allocate and release the response
// buffers the host hands to Windows plugins through the
// host-call callback. GlobalAlloc memory is freed by address
// in windowsHostFree, so the plugin side needs no allocator
// knowledge beyond calling the host free function.
var (
	kernel32DLL      = syscall.NewLazyDLL("kernel32.dll")
	procGlobalAlloc  = kernel32DLL.NewProc("GlobalAlloc")
	procGlobalFree   = kernel32DLL.NewProc("GlobalFree")
	globalAllocFlags = uintptr(0x0040) // GMEM_FIXED | GMEM_ZEROINIT
)

func windowsAlloc(n int) (uintptr, error) {
	if n <= 0 {
		return 0, fmt.Errorf("windowsAlloc: non-positive size")
	}
	r, _, err := procGlobalAlloc.Call(globalAllocFlags, uintptr(n))
	if r == 0 {
		return 0, fmt.Errorf("GlobalAlloc failed: %v", err)
	}
	return r, nil
}

func windowsFree(ptr uintptr) {
	if ptr == 0 {
		return
	}
	_, _, _ = procGlobalFree.Call(ptr)
}
