// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build windows

package pluginhost

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
)

// Windows dynamic-library loader, mirroring CLIProxyAPI
// internal/pluginhost/loader_windows.go at pin 250d5981 in
// shape (host/plugin API tables, entry symbol lookup, ABI
// exact check, close detaches without unloading — no
// FreeLibrary on the close path, loader_windows.go:204
// comment), implemented with the standard syscall package
// (LazyDLL + NewCallback) instead of golang.org/x/sys so no
// new dependency is added. The Windows load itself is
// [NEEDS-MEASUREMENT]: it compiles here but has not run on a
// Windows host; see docs/plugins.md. The glibc compat gate
// does not apply to PE files (CheckPluginCompat returns nil
// for non-ELF files).

const supportValue = "1"

// windowsHostAPI mirrors the C castctl_host_api table layout
// on 64-bit Windows: uint32 + padding + three pointers.
type windowsHostAPI struct {
	abiVersion uint32
	_          uint32
	hostCtx    uintptr
	call       uintptr
	freeBuffer uintptr
}

// windowsPluginAPI mirrors the C castctl_plugin_api table
// layout: uint32 + padding + three pointers.
type windowsPluginAPI struct {
	abiVersion uint32
	_          uint32
	call       uintptr
	freeBuffer uintptr
	shutdown   uintptr
}

type windowsBuffer struct {
	ptr uintptr
	len uintptr
}

type windowsClient struct {
	dll        *syscall.LazyDLL
	api        windowsPluginAPI
	hostAPI    *windowsHostAPI
	hostCtxPtr *uintptr
	callbackID uint64
	hostCallCb uintptr
	hostFreeCb uintptr
	// keepAlive holds the Go callback funcs so the runtime
	// does not collect them while the plugin may call back.
	keepAlive []any
	closed    bool
}

func defaultLoader() Loader { return windowsLoader{} }

type windowsLoader struct{}

func (windowsLoader) Open(file File, host *Host) (Client, error) {
	loadPath, errShadow := ShadowCopy(file)
	if errShadow != nil {
		return nil, errShadow
	}
	dll := syscall.NewLazyDLL(loadPath)
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("load library %s: %w", file.Path, err)
	}
	// From here on the module must never be unloaded: the
	// same never-unload rule as the unix loader. Failure
	// paths detach logically only.
	initProc := dll.NewProc(pluginabi.EntrySymbol)
	if err := initProc.Find(); err != nil {
		return nil, fmt.Errorf("missing %s: %w", pluginabi.EntrySymbol, err)
	}
	callbackID := registerHostCallback(host, file.ID)
	hostCtxPtr := new(uintptr)
	*hostCtxPtr = uintptr(callbackID)
	hostCallCb := syscall.NewCallback(windowsHostCall)
	hostFreeCb := syscall.NewCallback(windowsHostFree)
	hostAPI := &windowsHostAPI{
		abiVersion: pluginabi.ABIVersion,
		hostCtx:    uintptr(unsafe.Pointer(hostCtxPtr)),
		call:       hostCallCb,
		freeBuffer: hostFreeCb,
	}
	var api windowsPluginAPI
	r1, _, _ := initProc.Call(uintptr(unsafe.Pointer(hostAPI)), uintptr(unsafe.Pointer(&api)))
	if r1 != 0 {
		unregisterHostCallback(callbackID)
		return nil, fmt.Errorf("%s returned %d", pluginabi.EntrySymbol, int(r1))
	}
	if api.abiVersion != pluginabi.ABIVersion {
		unregisterHostCallback(callbackID)
		return nil, fmt.Errorf("plugin ABI version %d is not supported", api.abiVersion)
	}
	if api.call == 0 || api.freeBuffer == 0 {
		unregisterHostCallback(callbackID)
		return nil, fmt.Errorf("plugin function table is incomplete")
	}
	return &windowsClient{
		dll:        dll,
		api:        api,
		hostAPI:    hostAPI,
		hostCtxPtr: hostCtxPtr,
		callbackID: callbackID,
		hostCallCb: hostCallCb,
		hostFreeCb: hostFreeCb,
		keepAlive:  []any{windowsHostCall, windowsHostFree},
	}, nil
}

// windowsHostCall is the reverse callback entry point for
// Windows plugins. Signature: (hostCtx, method, request,
// requestLen, response) -> int.
func windowsHostCall(hostCtx, methodPtr, reqPtr, reqLen, respPtr uintptr) uintptr {
	if respPtr != 0 {
		*(*windowsBuffer)(unsafe.Pointer(respPtr)) = windowsBuffer{}
	}
	if hostCtx == 0 || methodPtr == 0 {
		return 1
	}
	id := uint64(*(*uintptr)(unsafe.Pointer(hostCtx)))
	entry, ok := lookupHostCallback(id)
	if !ok || entry.host == nil {
		return 1
	}
	method := windowsCString(methodPtr)
	var request []byte
	if reqPtr != 0 && reqLen > 0 {
		request = make([]byte, reqLen)
		copy(request, unsafe.Slice((*byte)(unsafe.Pointer(reqPtr)), reqLen))
	}
	resp := entry.host.dispatchHostCall(method, request)
	if len(resp) == 0 || respPtr == 0 {
		return 0
	}
	// The buffer must outlive the plugin's read: the plugin
	// frees it through windowsHostFree, which releases the
	// GlobalAlloc allocation by address.
	alloc, err := windowsAlloc(len(resp))
	if err != nil {
		return 1
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(alloc)), len(resp)), resp)
	*(*windowsBuffer)(unsafe.Pointer(respPtr)) = windowsBuffer{ptr: alloc, len: uintptr(len(resp))}
	return 0
}

func windowsCString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var b []byte
	for p := ptr; ; p++ {
		c := *(*byte)(unsafe.Pointer(p))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

// windowsHostFree releases a buffer allocated by
// windowsHostCall. Signature: (ptr, len) -> void.
func windowsHostFree(ptr, length uintptr) uintptr {
	if ptr != 0 {
		windowsFree(ptr)
	}
	return 0
}

func (c *windowsClient) Call(ctx context.Context, method string, request []byte) ([]byte, error) {
	if c == nil || c.closed || c.api.call == 0 {
		return nil, fmt.Errorf("plugin client is closed")
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
	methodPtr, err := syscall.BytePtrFromString(method)
	if err != nil {
		return nil, err
	}
	var reqPtr uintptr
	if len(request) > 0 {
		reqPtr = uintptr(unsafe.Pointer(&request[0]))
	}
	var resp windowsBuffer
	r1, _, _ := syscall.Syscall6(
		c.api.call, 4,
		uintptr(unsafe.Pointer(methodPtr)), reqPtr, uintptr(len(request)),
		uintptr(unsafe.Pointer(&resp)), 0, 0,
	)
	var out []byte
	if resp.ptr != 0 && resp.len > 0 {
		out = make([]byte, resp.len)
		copy(out, unsafe.Slice((*byte)(unsafe.Pointer(resp.ptr)), resp.len))
	}
	if resp.ptr != 0 && c.api.freeBuffer != 0 {
		_, _, _ = syscall.Syscall(c.api.freeBuffer, 2, resp.ptr, resp.len, 0)
	}
	if r1 != 0 {
		if isErrorEnvelope(out) {
			return out, nil
		}
		return nil, fmt.Errorf("plugin call %s returned %d: %s", method, int(r1), string(out))
	}
	return out, nil
}

// Shutdown detaches logically without unloading the module.
func (c *windowsClient) Shutdown() { c.close() }

func (c *windowsClient) close() {
	if c == nil || c.closed {
		return
	}
	c.closed = true
	if c.api.shutdown != 0 {
		_, _, _ = syscall.Syscall(c.api.shutdown, 0, 0, 0, 0)
	}
	c.api.call = 0
	c.api.freeBuffer = 0
	c.api.shutdown = 0
	unregisterHostCallback(c.callbackID)
	// Deliberately no FreeLibrary: see the never-unload rule
	// in the package doc and loader_unix.go close().
	c.dll = nil
}
