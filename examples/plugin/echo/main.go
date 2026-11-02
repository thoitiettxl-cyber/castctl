// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Command echo is the minimal castctl plugin example: a Go
// c-shared library implementing the castctl C ABI
// (castctl_plugin_init + JSON envelope, schema 1) with the
// Provider capability only. It answers provider.call with
// {"payload": "echo:<input>"} and keeps no state. It imports
// only the pluginabi contract package and the standard
// library — never pluginhost, never any Muse wire types.
//
// Build (host arch):
//
//	go build -buildmode=c-shared -o echo.so .
//
// Build for the phone (linux/arm64, glibc 2.17) to run
// inside Droidspaces:
// see docs/plugins.md "Cross-compiling the echo example".
// The resulting echo-v0.1.0.so is verified with
// `castctl plugin check` (see docs/plugins.md).
package main

/*
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

extern int castctlPluginCall(char*, uint8_t*, size_t, castctl_buffer*);
extern void castctlPluginFree(void*, size_t);
extern void castctlPluginShutdown(void);
*/
import "C"

import (
	"encoding/json"
	"unsafe"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
)

func main() {}

//export castctl_plugin_init
func castctl_plugin_init(host *C.castctl_host_api, plugin *C.castctl_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.castctl_plugin_call_fn(C.castctlPluginCall)
	plugin.free_buffer = C.castctl_plugin_free_fn(C.castctlPluginFree)
	plugin.shutdown = C.castctl_plugin_shutdown_fn(C.castctlPluginShutdown)
	return 0
}

//export castctlPluginCall
func castctlPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.castctl_buffer) C.int {
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	out, _ := handle(C.GoString(method), requestBytes)
	if len(out) > 0 {
		ptr := C.CBytes(out)
		response.ptr = ptr
		response.len = C.size_t(len(out))
	}
	return 0
}

//export castctlPluginFree
func castctlPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export castctlPluginShutdown
func castctlPluginShutdown() {}

func handle(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return registration(), nil
	case pluginabi.MethodPluginQuiesce:
		return okEnvelope(map[string]any{}), nil
	case pluginabi.MethodProviderCall:
		var req struct {
			Input string `json:"input"`
		}
		_ = json.Unmarshal(request, &req)
		return okEnvelope(map[string]string{"payload": "echo:" + req.Input}), nil
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func registration() []byte {
	// No CookieHosts declaration: the echo plugin needs no
	// session cookie, so core injects none for it
	// (fail-closed cookie scoping — see docs/plugins.md).
	raw, _ := json.Marshal(pluginabi.Registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginabi.Metadata{
			Name:    "echo",
			Version: "0.1.0",
			Author:  "castctl",
		},
		Capabilities: pluginabi.Capabilities{Provider: true},
	})
	env, _ := json.Marshal(pluginabi.Envelope{OK: true, Result: raw})
	return env
}

func okEnvelope(result any) []byte {
	raw, _ := json.Marshal(result)
	env, _ := json.Marshal(pluginabi.Envelope{OK: true, Result: raw})
	return env
}

func errorEnvelope(code, message string) []byte {
	env, _ := json.Marshal(pluginabi.NewErrorEnvelope(code, message))
	return env
}
