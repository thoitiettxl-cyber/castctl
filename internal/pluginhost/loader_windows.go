// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build windows

package pluginhost

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"sync"
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
// is called uniformly (CheckPluginCompat returns nil for
// non-ELF files, and refuses ELF files with requirements
// present when the running libc is unknown); the call and
// its fail-closed semantics are code-reviewed, not run.

const supportValue = "1"

// windowsHostAPI mirrors the C castctl_host_api table layout
// on 64-bit Windows ONLY: uint32 + padding + three pointers.
// The layout is wrong on 32-bit Windows; no 32-bit target is
// claimed, and 32-bit builds are unsupported.
type windowsHostAPI struct {
	abiVersion uint32
	_          uint32
	hostCtx    uintptr
	call       uintptr
	freeBuffer uintptr
}

// windowsPluginAPI mirrors the C castctl_plugin_api table
// layout on 64-bit Windows ONLY: uint32 + padding + three
// pointers (see windowsHostAPI).
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
	// mu/closed/calls mirror the unix client: Call
	// snapshots the function table under mu and
	// refcounts itself; close marks closed, waits for
	// in-flight calls, then invokes shutdown outside
	// the lock.
	mu     sync.Mutex
	closed bool
	calls  sync.WaitGroup
}

func defaultLoader() Loader { return windowsLoader{} }

type windowsLoader struct{}

func (windowsLoader) Open(file File, host *Host) (Client, error) {
	loadPath, errShadow := ShadowCopy(file)
	if errShadow != nil {
		return nil, errShadow
	}
	// Verify the shadow bytes against the manifest when
	// one is configured (see loader_unix.go).
	if file.ManifestPath != "" {
		if err := VerifyShadowFileChecksum(loadPath, file.ManifestPath, filepath.Base(file.Path)); err != nil {
			_ = removeShadowFile(loadPath)
			return nil, err
		}
	}
	// Compat gate on the exact bytes about to be loaded,
	// as on unix: the loader never loads a refused file
	// even when called directly. For PE files the gate
	// is a no-op; for ELF files it refuses fail-closed.
	if err := CheckPluginCompat(loadPath); err != nil {
		_ = removeShadowFile(loadPath)
		return nil, err
	}
	dll := syscall.NewLazyDLL(loadPath)
	if err := dll.Load(); err != nil {
		_ = removeShadowFile(loadPath)
		return nil, fmt.Errorf("load library %s: %w", file.Path, err)
	}
	// From here on the module must never be unloaded: the
	// same never-unload rule as the unix loader. Failure
	// paths detach logically only.
	initProc := dll.NewProc(pluginabi.EntrySymbol)
	if err := initProc.Find(); err != nil {
		_ = removeShadowFile(loadPath)
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
		_ = removeShadowFile(loadPath)
		return nil, fmt.Errorf("%s returned %d", pluginabi.EntrySymbol, int(r1))
	}
	if api.abiVersion != pluginabi.ABIVersion {
		unregisterHostCallback(callbackID)
		_ = removeShadowFile(loadPath)
		return nil, fmt.Errorf("plugin ABI version %d is not supported", api.abiVersion)
	}
	if api.call == 0 || api.freeBuffer == 0 {
		unregisterHostCallback(callbackID)
		_ = removeShadowFile(loadPath)
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
	method, ok := windowsCStringBounded(methodPtr, maxHostMethodLen)
	if !ok {
		return 1
	}
	var request []byte
	if reqPtr != 0 && reqLen > 0 {
		if reqLen > 1<<31-1 {
			return 1
		}
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

// windowsCStringBounded reads a NUL-terminated string at
// ptr, refusing when no NUL appears within max bytes — the
// Windows counterpart of the bounded method read on unix.
// An unterminated method pointer must never be read
// unbounded into a host crash. Code-reviewed only: the
// Windows loader has not run on a Windows host.
func windowsCStringBounded(ptr uintptr, max int) (string, bool) {
	if ptr == 0 {
		return "", true
	}
	var b []byte
	for i := 0; i < max; i++ {
		c := *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
		if c == 0 {
			return string(b), true
		}
		b = append(b, c)
	}
	return "", false
}

func windowsCString(ptr uintptr) string {
	s, _ := windowsCStringBounded(ptr, maxHostMethodLen)
	return s
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
	if c == nil {
		return nil, fmt.Errorf("plugin client is closed")
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("plugin client is closed")
	}
	c.calls.Add(1)
	callFn := c.api.call
	freeFn := c.api.freeBuffer
	c.mu.Unlock()
	defer c.calls.Done()
	if callFn == 0 {
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
	// Copy the request: the plugin must never retain a
	// pointer into the caller's slice.
	reqCopy := append([]byte(nil), request...)
	var reqPtr uintptr
	if len(reqCopy) > 0 {
		reqPtr = uintptr(unsafe.Pointer(&reqCopy[0]))
	}
	var resp windowsBuffer
	r1, _, _ := syscall.Syscall6(
		callFn, 4,
		uintptr(unsafe.Pointer(methodPtr)), reqPtr, uintptr(len(reqCopy)),
		uintptr(unsafe.Pointer(&resp)), 0, 0,
	)
	var out []byte
	if resp.ptr != 0 && resp.len > 0 {
		// Bound the plugin-reported length before
		// copying, as on unix: an oversize length is an
		// error, never a truncated or over-read copy.
		if resp.len > math.MaxInt32 {
			if freeFn != 0 {
				_, _, _ = syscall.Syscall(freeFn, 2, resp.ptr, resp.len, 0)
			}
			return nil, fmt.Errorf("plugin call %s returned an oversize response", method)
		}
		out = make([]byte, resp.len)
		copy(out, unsafe.Slice((*byte)(unsafe.Pointer(resp.ptr)), resp.len))
	}
	if resp.ptr != 0 && freeFn != 0 {
		_, _, _ = syscall.Syscall(freeFn, 2, resp.ptr, resp.len, 0)
	}
	if r1 != 0 {
		if isErrorEnvelope(out) {
			return out, nil
		}
		return nil, fmt.Errorf("plugin call %s returned %d: %s", method, int(r1), safePluginText(string(out)))
	}
	return out, nil
}

// Shutdown detaches logically without unloading the module.
func (c *windowsClient) Shutdown() { c.close() }

func (c *windowsClient) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	shutdownFn := c.api.shutdown
	callbackID := c.callbackID
	c.api.call = 0
	c.api.freeBuffer = 0
	c.api.shutdown = 0
	c.dll = nil
	c.mu.Unlock()
	c.calls.Wait()
	if shutdownFn != 0 {
		_, _, _ = syscall.Syscall(shutdownFn, 0, 0, 0, 0)
	}
	unregisterHostCallback(callbackID)
	// Deliberately no FreeLibrary: see the never-unload rule
	// in the package doc and loader_unix.go close().
}
