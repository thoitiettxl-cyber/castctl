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
	"unsafe"
)

//export castctlHostCall
func castctlHostCall(hostCtx unsafe.Pointer, method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.castctl_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if hostCtx == nil || method == nil {
		return 1
	}
	id := uint64(*(*C.uintptr_t)(hostCtx))
	entry, ok := lookupHostCallback(id)
	if !ok || entry.host == nil {
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	resp := entry.host.dispatchHostCall(C.GoString(method), requestBytes)
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
