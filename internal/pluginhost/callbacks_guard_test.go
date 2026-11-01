// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && linux && !android

package pluginhost

import (
	"syscall"
	"testing"
	"unsafe"
)

// The length bound alone does not protect a method pointer
// whose bytes run into an unmapped page: the scan must
// survive the fault and report "no NUL". This test maps
// two pages, guards the second PROT_NONE, and reads from
// 10 bytes before the guard.
func TestBoundedCStringLenPageBoundary(t *testing.T) {
	page := syscall.Getpagesize()
	b, err := syscall.Mmap(-1, 0, page*2, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Munmap(b)
	for i := range b[:page] {
		b[i] = 'x'
	}
	if err := syscall.Mprotect(b[page:], syscall.PROT_NONE); err != nil {
		t.Fatal(err)
	}
	ptr := unsafe.Pointer(&b[page-10])
	if _, ok := boundedCStringLen(ptr, 256); ok {
		t.Fatal("page-tail read: want refusal, got a length")
	}
	b[page-10+5] = 0
	if n, ok := boundedCStringLen(ptr, 256); !ok || n != 5 {
		t.Fatalf("page-tail NUL at 5 = (%d,%v), want (5,true)", n, ok)
	}
	// The process must still be alive and able to panic and
	// recover normally after a guarded fault.
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("want panic recovered after guarded fault")
			}
		}()
		var p *int
		_ = *p
	}()
	if _, ok := boundedCStringLen(ptr, 256); !ok {
		t.Fatal("scan after panic recovery: want success")
	}
}
