// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && (linux || darwin || freebsd) && !android

package pluginhost

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>

typedef struct {
	void* ptr;
	size_t len;
} castctl_buffer;

// Guarded bounded string scan.
//
// A plugin passes the host.log method name as a bare C
// pointer with no length; the bound alone does not protect
// a read that crosses into an unmapped page (a forgotten
// NUL 10 bytes before a guard page still faults). The scan
// therefore runs under a SIGSEGV/SIGBUS handler that
// longjmps back only when the fault address is inside the
// scanned range [ptr, ptr+max); any other fault chains to
// the previously installed handler (the Go runtime's), so
// genuine host faults keep their normal behaviour.
//
// The handler is installed ONCE, from Go init(), and stays
// installed for the process lifetime: installing and
// restoring it around every scan leaves a window (after
// sigaction, before the saved handler is recorded) in
// which a fault on any thread finds no valid saved handler
// and dies via SIG_DFL instead of reaching the Go runtime
// — measured: a fault hammer killed the process in ~10 ms
// with per-scan install/restore, because the sigaction
// syscalls dominate each short scan. With a single
// install, done before any goroutine can fault
// concurrently, there is no install/restore window at
// all. The jmp buffer, probe pointer/length, and active
// flag stay per-thread (__thread); the SAVED previous
// handlers are process-wide globals, written once at
// install, so a fault on any thread chains to the real
// previous handler. The Go side still serialises scans
// with a mutex, so at most one guarded scan is in flight.
//
// Proven by committed tests on linux/amd64
// (callbacks_guard_test.go): page-tail reads return
// "no NUL", in-range NULs are found, and a genuine Go
// nil-deref panic on a thread that never scanned — while
// other threads hold the guard in guarded scans — is
// still recovered by the runtime, with the process
// staying alive. The handler MUST use SA_ONSTACK: without
// it the Go runtime aborts the process ("non-Go code set
// up signal handler without SA_ONSTACK flag", measured).
// If the one-time install fails, scans fail closed.
//
// Limits, stated plainly: the guard covers the method-name
// read only. Faults inside native plugin code reached
// through any other path (its own threads, its own
// callbacks) are outside this guard, like every other
// in-process native fault (see docs/plugins.md). The guard
// is compiled on linux/darwin/freebsd but measured only on
// linux; darwin/freebsd behaviour is unproven. Windows uses
// a plain bounded scan (loader_windows.go) with the same
// page-fault class unproven there. The guard assumes no
// other code replaces the SIGSEGV/SIGBUS handlers after
// install; a native plugin that does so disables the
// guard (trusted-model limit).

static __thread sigjmp_buf castctl_probe_jmp;
static __thread volatile const unsigned char *castctl_probe_ptr;
static __thread volatile size_t castctl_probe_len;
static __thread volatile int castctl_probe_active;
// Process-wide, written once by castctl_probe_install:
// sigaction is process-wide, so the saved previous
// handlers must be visible on every thread.
static struct sigaction castctl_probe_old_segv;
static struct sigaction castctl_probe_old_bus;
static volatile int castctl_probe_old_valid;

static void castctl_probe_chain(int sig, siginfo_t *info, void *uc) {
	struct sigaction *old = (sig == SIGBUS) ? &castctl_probe_old_bus : &castctl_probe_old_segv;
	if (!castctl_probe_old_valid || old->sa_handler == SIG_DFL) {
		signal(sig, SIG_DFL);
		raise(sig);
		_exit(128 + sig);
	}
	if (old->sa_handler == SIG_IGN) {
		return;
	}
	if (old->sa_flags & SA_SIGINFO) {
		old->sa_sigaction(sig, info, uc);
	} else {
		old->sa_handler(sig);
	}
}

static void castctl_probe_handler(int sig, siginfo_t *info, void *uc) {
	if ((sig == SIGSEGV || sig == SIGBUS) && castctl_probe_active) {
		const unsigned char *fault = (const unsigned char *)info->si_addr;
		if (fault >= castctl_probe_ptr && fault < castctl_probe_ptr + castctl_probe_len) {
			siglongjmp(castctl_probe_jmp, 1);
		}
	}
	castctl_probe_chain(sig, info, uc);
}

// Returns 1 and sets *out when a NUL is found within max,
// 0 when no NUL is found (including a fault inside the
// range), and -1 when the one-time handler install failed
// (caller fails closed). No sigaction happens here: the
// handler was installed once by castctl_probe_install.
static int castctl_guarded_cstring_len(const unsigned char *ptr, size_t max, size_t *out) {
	size_t i;
	size_t found = (size_t)-1;

	if (castctl_probe_active) {
		// Nested scan on this thread (cannot happen via
		// castctlHostCall: the Go mutex serialises scans
		// and dispatch never re-enters). Scan plainly;
		// a fault longjmps to the outer guard, which
		// fails closed for the outer call.
		for (i = 0; i < max; i++) {
			if (ptr[i] == 0) {
				*out = i;
				return 1;
			}
		}
		return 0;
	}
	if (!castctl_probe_old_valid) {
		return -1;
	}
	castctl_probe_ptr = ptr;
	castctl_probe_len = max;
	castctl_probe_active = 1;
	if (sigsetjmp(castctl_probe_jmp, 1) == 0) {
		for (i = 0; i < max; i++) {
			if (ptr[i] == 0) {
				found = i;
				break;
			}
		}
	}
	castctl_probe_active = 0;
	if (found == (size_t)-1) {
		return 0;
	}
	*out = found;
	return 1;
}

// Installs the probe handler once and records the
// previous handlers. Returns 1 on success, 0 when the
// SIGSEGV handler cannot be installed (the guard is then
// unusable and scans fail closed). A SIGBUS install
// failure degrades silently: SIGBUS faults then go
// straight to the previous handler unguarded. Called
// once from Go init(), before any concurrent fault can
// occur, so there is no install window for a fault to
// land in.
static int castctl_probe_install(void) {
	struct sigaction sa, oldsegv, oldbus;
	int have_bus;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = castctl_probe_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
	if (sigaction(SIGSEGV, &sa, &oldsegv) != 0) {
		return 0;
	}
	castctl_probe_old_segv = oldsegv;
	castctl_probe_old_valid = 1;
	have_bus = (sigaction(SIGBUS, &sa, &oldbus) == 0);
	if (!have_bus) {
		memset(&oldbus, 0, sizeof(oldbus));
		oldbus.sa_handler = SIG_DFL;
	}
	castctl_probe_old_bus = oldbus;
	return 1;
}
*/
import "C"

import (
	"math"
	"sync"
	"unsafe"
)

// boundedCStringMu serialises boundedCStringLen so at
// most one guarded scan is in flight at a time.
var boundedCStringMu sync.Mutex

// guardInstalled is set once by init from the C
// one-time handler install. A failed install fails
// every scan closed (boundedCStringLen returns false)
// instead of reading an unguarded pointer.
var guardInstalled bool

func init() {
	guardInstalled = C.castctl_probe_install() != 0
}

// boundedCStringLen scans at most max bytes at ptr for a NUL
// and returns its offset. It reports false when no NUL
// appears within the bound, so the host never reads an
// unterminated method pointer unbounded (a plugin C bug —
// a forgotten NUL — must not segfault the host through its
// own callback API). The scan runs under the signal
// guard installed once at init (see the C preamble): a
// fault inside the scanned range reports "no NUL"
// instead of crashing the host; faults outside the range
// chain to the previous handler. A failed handler
// install fails closed (false).
func boundedCStringLen(ptr unsafe.Pointer, max int) (int, bool) {
	if ptr == nil {
		return 0, true
	}
	if max <= 0 {
		return 0, false
	}
	boundedCStringMu.Lock()
	defer boundedCStringMu.Unlock()
	if !guardInstalled {
		return 0, false
	}
	var out C.size_t
	rc := C.castctl_guarded_cstring_len((*C.uchar)(ptr), C.size_t(max), &out)
	if rc <= 0 {
		return 0, false
	}
	return int(out), true
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
