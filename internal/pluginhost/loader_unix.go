// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && (linux || darwin || freebsd)

package pluginhost

/*
#cgo linux LDFLAGS: -ldl
#cgo freebsd LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} castctl_buffer;

typedef int (*castctl_host_call_fn)(void*, const char*, const uint8_t*, size_t, castctl_buffer*);
typedef void (*castctl_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	castctl_host_call_fn call;
	castctl_host_free_fn free_buffer;
} castctl_host_api;

typedef int (*castctl_plugin_call_fn)(const char*, const uint8_t*, size_t, castctl_buffer*);
typedef void (*castctl_plugin_free_fn)(void*, size_t);
typedef void (*castctl_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	castctl_plugin_call_fn call;
	castctl_plugin_free_fn free_buffer;
	castctl_plugin_shutdown_fn shutdown;
} castctl_plugin_api;

typedef int (*castctl_plugin_init_fn)(const castctl_host_api*, castctl_plugin_api*);

extern int castctlHostCall(void*, const char*, const uint8_t*, size_t, castctl_buffer*);
extern void castctlHostFree(void*, size_t);

static void* castctl_dlopen(const char* path) {
	return dlopen(path, RTLD_NOW | RTLD_LOCAL);
}

static void* castctl_dlsym(void* handle, const char* name) {
	return dlsym(handle, name);
}

static const char* castctl_dlerror(void) {
	return dlerror();
}

static int castctl_call_init(void* fn, const castctl_host_api* host, castctl_plugin_api* plugin) {
	return ((castctl_plugin_init_fn)fn)(host, plugin);
}

static int castctl_call_plugin(castctl_plugin_call_fn fn, const char* method, const uint8_t* request, size_t request_len, castctl_buffer* response) {
	return fn(method, request, request_len, response);
}

static void castctl_free_plugin_buffer(castctl_plugin_free_fn fn, void* ptr, size_t len) {
	fn(ptr, len);
}

static void castctl_shutdown_plugin(castctl_plugin_shutdown_fn fn) {
	fn();
}

static void castctl_set_host_api(castctl_host_api* api, uint32_t abi_version, void* host_ctx) {
	api->abi_version = abi_version;
	api->host_ctx = host_ctx;
	api->call = castctlHostCall;
	api->free_buffer = castctlHostFree;
}

*/
import "C"

import (
	"context"
	"fmt"
	"os"
	"unsafe"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
)

// Unix dynamic-library loader, mirroring CLIProxyAPI
// internal/pluginhost/loader_unix.go at pin 250d5981 (C
// preamble :8-77, dlopen RTLD_NOW|RTLD_LOCAL :43-45, entry
// symbol lookup :130, ABI exact check :166-168, never-unload
// close :229-237), renamed into the castctl namespace
// (castctl_plugin_init, castctl_buffer, castctl_host_api /
// castctl_plugin_api). Differences from upstream: the glibc
// compat gate runs on the shadow path before dlopen (see
// CheckPluginCompat), and the host callback registry carries
// only host.log (see dispatchHostCall).
//
// Android: there is deliberately NO GOOS=android loader file.
// The KernelSU module runs the GOOS=linux/arm64 glibc build
// under the bundled glibc loader (Gate 0 PROVEN), so this
// unix loader is the Android path. GOOS=android builds fall
// back to the stub loader, which refuses loads clearly.

const supportValue = "1"

type dynamicLibraryLoader struct{}

type dynamicLibraryClient struct {
	handle  unsafe.Pointer
	hostAPI *C.castctl_host_api
	hostCtx unsafe.Pointer
	api     C.castctl_plugin_api
	host    *Host
	tag     string
}

func defaultLoader() Loader { return dynamicLibraryLoader{} }

func (dynamicLibraryLoader) Open(file File, host *Host) (Client, error) {
	loadPath, errShadow := ShadowCopy(file)
	if errShadow != nil {
		return nil, errShadow
	}
	// Compat gate on the exact bytes about to be loaded, as
	// defence in depth over the host-level check (same bytes,
	// same result; the loader never dlopens a refused file
	// even when called directly).
	if err := CheckPluginCompat(loadPath); err != nil {
		_ = removeShadowFile(loadPath)
		return nil, err
	}
	cPath := C.CString(loadPath)
	defer C.free(unsafe.Pointer(cPath))

	handle := C.castctl_dlopen(cPath)
	if handle == nil {
		_ = removeShadowFile(loadPath)
		return nil, fmt.Errorf("dlopen %s: %s", file.Path, dlerrorString())
	}
	// From here on the image must never be unloaded: dlopen
	// may already have started the plugin runtime, and a Go
	// c-shared runtime cannot be removed from the host
	// process safely. Failure paths below only detach the
	// client logically and deliberately leak the mapped
	// image together with any host callback state the
	// runtime may reference.

	cSymbol := C.CString(pluginabi.EntrySymbol)
	initSymbol := C.castctl_dlsym(handle, cSymbol)
	C.free(unsafe.Pointer(cSymbol))
	if initSymbol == nil {
		return nil, fmt.Errorf("missing %s: %s", pluginabi.EntrySymbol, dlerrorString())
	}

	hostAPI := (*C.castctl_host_api)(C.malloc(C.size_t(unsafe.Sizeof(C.castctl_host_api{}))))
	if hostAPI == nil {
		return nil, fmt.Errorf("allocate host api")
	}
	hostCtx := C.malloc(C.size_t(unsafe.Sizeof(C.uintptr_t(0))))
	if hostCtx == nil {
		return nil, fmt.Errorf("allocate host context")
	}
	id := registerHostCallback(host, file.ID)
	*(*C.uintptr_t)(hostCtx) = C.uintptr_t(id)
	C.castctl_set_host_api(hostAPI, C.uint32_t(pluginabi.ABIVersion), hostCtx)

	client := &dynamicLibraryClient{
		handle:  handle,
		hostAPI: hostAPI,
		hostCtx: hostCtx,
		host:    host,
		tag:     file.ID,
	}
	rc := C.castctl_call_init(initSymbol, hostAPI, &client.api)
	if rc != 0 {
		client.closeAfterOpenFailure()
		return nil, fmt.Errorf("%s returned %d", pluginabi.EntrySymbol, int(rc))
	}
	if uint32(client.api.abi_version) != pluginabi.ABIVersion {
		client.closeAfterOpenFailure()
		return nil, fmt.Errorf("plugin ABI version %d is not supported", uint32(client.api.abi_version))
	}
	if client.api.call == nil || client.api.free_buffer == nil {
		client.closeAfterOpenFailure()
		return nil, fmt.Errorf("plugin function table is incomplete")
	}
	return client, nil
}

func (c *dynamicLibraryClient) Call(ctx context.Context, method string, request []byte) ([]byte, error) {
	if c == nil || c.api.call == nil {
		return nil, fmt.Errorf("plugin client is closed")
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var cRequest unsafe.Pointer
	if len(request) > 0 {
		cRequest = C.CBytes(request)
		defer C.free(cRequest)
	}
	var response C.castctl_buffer
	rc := C.castctl_call_plugin(c.api.call, cMethod, (*C.uint8_t)(cRequest), C.size_t(len(request)), &response)
	var out []byte
	if response.ptr != nil && response.len > 0 {
		out = C.GoBytes(response.ptr, C.int(response.len))
	}
	if response.ptr != nil {
		C.castctl_free_plugin_buffer(c.api.free_buffer, response.ptr, response.len)
	}
	if rc != 0 {
		if isErrorEnvelope(out) {
			return out, nil
		}
		return nil, fmt.Errorf("plugin call %s returned %d: %s", method, int(rc), string(out))
	}
	return out, nil
}

// Shutdown detaches the client logically without unloading
// the plugin image (see close).
func (c *dynamicLibraryClient) Shutdown() { c.close() }

func (c *dynamicLibraryClient) closeAfterOpenFailure() { c.close() }

// close detaches the client logically without unloading the
// plugin image. Go plugin libraries are not safe to
// hot-unload: the plugin runtime, its threads, and its signal
// handlers stay resident after dlclose, so a later load in
// the same process forwards signals into unmapped memory and
// spins. This also applies when initialization failed,
// because dlopen may already have started the runtime. The
// plugin was loaded from a shadow copy, so keeping the image
// mapped does not block deleting or replacing the source
// artifact.
func (c *dynamicLibraryClient) close() {
	if c == nil {
		return
	}
	if c.api.shutdown != nil {
		C.castctl_shutdown_plugin(c.api.shutdown)
		c.api.shutdown = nil
	}
	c.api.call = nil
	c.api.free_buffer = nil
	if c.hostCtx != nil {
		// Drop the callback registration so repeated reloads
		// do not pin the host forever. The C host context
		// and host API block themselves are deliberately
		// leaked: the resident plugin runtime may still
		// pass the context back into castctlHostCall, which
		// reads the callback id from it before failing the
		// lookup.
		id := uint64(*(*C.uintptr_t)(c.hostCtx))
		unregisterHostCallback(id)
		c.hostCtx = nil
	}
	c.host = nil
}

func dlerrorString() string {
	errText := C.castctl_dlerror()
	if errText == nil {
		return ""
	}
	return C.GoString(errText)
}

func removeShadowFile(path string) error {
	return os.Remove(path)
}
