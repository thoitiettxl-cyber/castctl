// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && linux

package pluginhost

/*
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

// castctl_libc_version returns a malloc'd copy of the running
// libc version string, or NULL when it cannot be known. The
// version is read through dlopen/dlsym on purpose: including
// <gnu/libc-version.h> would make a cgo/linux MUSL build fail
// to COMPILE (musl has no such header), while this form
// compiles everywhere and fails CLOSED at runtime on musl
// (no gnu_get_libc_version symbol), where CheckPluginCompat
// refuses ELF files with requirements present. The dlopen
// handle is deliberately leaked: the version string is read
// once per process lifetime in practice, and closing the
// libc handle is never safe.
static char* castctl_libc_version(void) {
	void* handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
	if (handle == NULL) {
		return NULL;
	}
	typedef const char* (*version_fn)(void);
	version_fn fn = (version_fn)dlsym(handle, "gnu_get_libc_version");
	if (fn == NULL) {
		return NULL;
	}
	const char* v = fn();
	if (v == NULL) {
		return NULL;
	}
	size_t len = strlen(v);
	char* out = (char*)malloc(len + 1);
	if (out == NULL) {
		return NULL;
	}
	memcpy(out, v, len + 1);
	return out;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// testBinaryHasGLIBCReqs reports whether the test binary
// itself is expected to carry GLIBC_ requirements (a
// dynamically linked glibc binary). A static no-cgo binary
// has none, and the real-binary compat test must skip there.
const testBinaryHasGLIBCReqs = true

// runningLibcVersion reports the running glibc version via
// gnu_get_libc_version, resolved at runtime through
// dlopen/dlsym (see the C helper). It exists only on
// cgo/linux builds. On musl (no such symbol) it errors,
// and the compat gate refuses fail-closed.
func runningLibcVersion() (glibcVersion, error) {
	cstr := C.castctl_libc_version()
	if cstr == nil {
		return glibcVersion{}, fmt.Errorf("gnu_get_libc_version is unavailable (non-glibc libc?)")
	}
	defer C.free(unsafe.Pointer(cstr))
	s := C.GoString(cstr)
	v, err := parseGlibcVersion(s)
	if err != nil {
		return glibcVersion{}, fmt.Errorf("running libc version %q: %w", s, err)
	}
	return v, nil
}
