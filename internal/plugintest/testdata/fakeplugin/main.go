// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Fake c-shared plugin fixture for real-loader contract tests.
// It is built fresh by plugintest.BuildFakePlugin (never
// committed as a binary) and implements the castctl C ABI:
// castctl_plugin_init + JSON envelope, mirroring CLIProxyAPI's
// examples/plugin/simple/go/main.go at pin 250d5981 (renamed
// namespace, castctl schema 1). Behaviour is driven by -X
// variables (testSchema, testName, testVersion, testAuthor,
// testCaps, testFailRegister) so one source covers the good,
// bad-metadata, schema-mismatch, and no-capability fixtures.
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

static int castctl_call_host(const castctl_host_api* host, const char* method, const uint8_t* req, size_t len, castctl_buffer* resp) {
	return host->call(host->host_ctx, method, req, len, resp);
}

static void castctl_free_host_buffer(const castctl_host_api* host, void* ptr, size_t len) {
	host->free_buffer(ptr, len);
}

extern int castctlPluginCall(char*, uint8_t*, size_t, castctl_buffer*);
extern void castctlPluginFree(void*, size_t);
extern void castctlPluginShutdown(void);
*/
import "C"

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
)

var (
	testSchema       = "1"
	testABI          = ""
	testName         = "fake"
	testVersion      = "0.1.0"
	testAuthor       = "plugintest"
	testCaps         = "provider"
	testFailRegister = ""
	testCookieHosts  = ""
	testRawRC        = ""
)

var savedHost *C.castctl_host_api

func main() {}

//export castctl_plugin_init
func castctl_plugin_init(host *C.castctl_host_api, plugin *C.castctl_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	savedHost = host
	abi := pluginabi.ABIVersion
	if testABI != "" {
		if n, err := strconv.Atoi(testABI); err == nil {
			abi = uint32(n)
		}
	}
	plugin.abi_version = C.uint32_t(abi)
	plugin.call = C.castctl_plugin_call_fn(C.castctlPluginCall)
	plugin.free_buffer = C.castctl_plugin_free_fn(C.castctlPluginFree)
	plugin.shutdown = C.castctl_plugin_shutdown_fn(C.castctlPluginShutdown)
	return 0
}

//export castctlPluginCall
func castctlPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.castctl_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	// RawRC (C1 rc!=0 gap): provider.call returns rc != 0
	// with raw, non-envelope bytes carrying the exact C1
	// sequences (U+009B CSI + "[31m", U+0085 NEL) plus a
	// newline, an ESC CSI sequence, DEL, and a C0
	// control, so the loader's rc != 0 error construction
	// must sanitise them all to one line. Register and
	// quiesce keep their normal behaviour.
	if testRawRC == "1" && C.GoString(method) == pluginabi.MethodProviderCall {
		writeResponse(response, []byte("raw boom \u009b[31mRED\u0085TAIL\nFORGED\x1b[31m\x7f\x01END"))
		return 1
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
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

func writeResponse(response *C.castctl_buffer, raw []byte) {
	if response == nil {
		return
	}
	if len(raw) == 0 {
		return
	}
	ptr := C.malloc(C.size_t(len(raw)))
	if ptr == nil {
		return
	}
	copy((*[1 << 30]byte)(ptr)[:len(raw)], raw)
	response.ptr = ptr
	response.len = C.size_t(len(raw))
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

func registration() []byte {
	schema, _ := strconv.Atoi(testSchema)
	caps := pluginabi.Capabilities{}
	var commands []pluginabi.Command
	switch testCaps {
	case "provider":
		caps.Provider = true
	case "command":
		caps.CommandProvider = true
		commands = []pluginabi.Command{{Name: "fake-cmd", Usage: "fake command"}}
	case "both":
		caps.Provider = true
		caps.CommandProvider = true
		commands = []pluginabi.Command{{Name: "fake-cmd", Usage: "fake command"}}
	case "none":
	}
	reg := pluginabi.Registration{
		SchemaVersion: uint32(schema),
		Metadata: pluginabi.Metadata{
			Name:             testName,
			Version:          testVersion,
			Author:           testAuthor,
			GitHubRepository: "https://github.com/thoitiettxl-cyber/castctl",
		},
		Capabilities: caps,
		Commands:     commands,
	}
	if testCookieHosts != "" {
		reg.CookieHosts = strings.Split(testCookieHosts, ",")
	}
	return okEnvelope(reg)
}

func callHost(method string, request []byte) ([]byte, error) {
	if savedHost == nil {
		return nil, errNoHost
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var cReq unsafe.Pointer
	if len(request) > 0 {
		cReq = C.CBytes(request)
		defer C.free(cReq)
	}
	var resp C.castctl_buffer
	rc := C.castctl_call_host(savedHost, cMethod, (*C.uint8_t)(cReq), C.size_t(len(request)), &resp)
	var out []byte
	if resp.ptr != nil && resp.len > 0 {
		out = C.GoBytes(resp.ptr, C.int(resp.len))
	}
	if resp.ptr != nil {
		C.castctl_free_host_buffer(savedHost, resp.ptr, resp.len)
	}
	if rc != 0 {
		return out, errHostCall
	}
	return out, nil
}

type hostErr string

func (e hostErr) Error() string { return string(e) }

const (
	errNoHost   = hostErr("no host api")
	errHostCall = hostErr("host call failed")
)

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if testFailRegister == "1" {
			return errorEnvelope("register_failed", "fixture register failure"), nil
		}
		return registration(), nil
	case pluginabi.MethodPluginQuiesce:
		return okEnvelope(map[string]any{}), nil
	case pluginabi.MethodProviderCall:
		var req struct {
			Input string `json:"input"`
		}
		_ = json.Unmarshal(request, &req)
		return okEnvelope(map[string]string{"payload": "echo:" + req.Input}), nil
	case "fake.sleep":
		// Test-only slow call for the Call/Close race
		// test: sleeps {"ms":N} milliseconds, default 400.
		var req struct {
			Ms int `json:"ms"`
		}
		_ = json.Unmarshal(request, &req)
		if req.Ms <= 0 {
			req.Ms = 400
		}
		time.Sleep(time.Duration(req.Ms) * time.Millisecond)
		return okEnvelope(map[string]bool{"slept": true}), nil
	case "fake.log":
		resp, err := callHost(pluginabi.MethodHostLog, []byte(`{"level":"info","message":"hello from fake"}`))
		if err != nil {
			return errorEnvelope("host_log_failed", err.Error()), nil
		}
		var env pluginabi.Envelope
		if err := json.Unmarshal(resp, &env); err != nil || !env.OK {
			return errorEnvelope("host_log_failed", "host.log was not ok"), nil
		}
		return okEnvelope(map[string]bool{"logged": true}), nil
	case "fake.auth":
		resp, err := callHost("host.auth.get", []byte(`{}`))
		if err != nil {
			return errorEnvelope("host_auth_rejected", "host.auth.get call failed"), nil
		}
		var env pluginabi.Envelope
		if err := json.Unmarshal(resp, &env); err != nil || env.OK {
			return errorEnvelope("host_auth_rejected", "host.auth.get was not rejected"), nil
		}
		return errorEnvelope("host_auth_rejected", env.Error.Message), nil
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}
