// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && linux

package pluginhost

/*
#include <gnu/libc-version.h>
#include <stdlib.h>
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
// gnu_get_libc_version. It exists only on cgo/linux builds: the
// symbol is a glibc extension, absent on musl, darwin, and
// windows.
func runningLibcVersion() (glibcVersion, error) {
	cstr := C.gnu_get_libc_version()
	if cstr == nil {
		return glibcVersion{}, fmt.Errorf("gnu_get_libc_version returned nil")
	}
	s := C.GoString((*C.char)(unsafe.Pointer(cstr)))
	v, err := parseGlibcVersion(s)
	if err != nil {
		return glibcVersion{}, fmt.Errorf("running libc version %q: %w", s, err)
	}
	return v, nil
}
