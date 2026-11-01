// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && (linux || darwin || freebsd)

package pluginhost

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} castctl_buffer;
*/
import "C"

import (
	"math"
	"unsafe"
)

// boundedCStringLen scans at most max bytes at ptr for a NUL
// and returns its offset. It reports false when no NUL
// appears within the bound, so the host never reads an
// unterminated method pointer unbounded (a plugin C bug —
// a forgotten NUL — must not segfault the host through its
// own callback API). Implemented in Go so the bound itself
// is unit-testable without cgo in the test file.
func boundedCStringLen(ptr unsafe.Pointer, max int) (int, bool) {
	if ptr == nil {
		return 0, true
	}
	for i := 0; i < max; i++ {
		if *(*byte)(unsafe.Add(ptr, i)) == 0 {
			return i, true
		}
	}
	return 0, false
}

//export castctlHostCall
func castctlHostCall(hostCtx unsafe.Pointer, method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.castctl_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if hostCtx == nil || method == nil {
		return 1
	}
	methodLen, ok := boundedCStringLen(unsafe.Pointer(method), maxHostMethodLen)
	if !ok {
		return 1
	}
	id := uint64(*(*C.uintptr_t)(hostCtx))
	entry, ok := lookupHostCallback(id)
	if !ok || entry.host == nil {
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		// The ABI carries the request length, but GoBytes
		// takes a C.int: refuse lengths that would
		// truncate instead of silently reading wrong
		// bytes.
		if uint64(requestLen) > math.MaxInt32 {
			return 1
		}
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	methodStr := C.GoStringN(method, C.int(methodLen))
	resp := entry.host.dispatchHostCall(methodStr, requestBytes)
	if len(resp) == 0 || response == nil {
		return 0
	}
	ptr := C.CBytes(resp)
	if ptr == nil {
		return 1
	}
	response.ptr = ptr
	response.len = C.size_t(len(resp))
	return 0
}

//export castctlHostFree
func castctlHostFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}
