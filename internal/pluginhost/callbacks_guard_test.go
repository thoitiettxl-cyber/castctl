// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && linux && !android

package pluginhost

import (
	"sync"
	"syscall"
	"testing"
	"time"
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

// TestBoundedCStringLenCrossThreadFault is the regression
// test for the cross-thread chaining defect (B-R2): saved
// signal handlers are process-wide state (sigaction is
// process-wide), so a genuine fault on a thread that never
// installed the guard must still chain to the Go runtime
// handler and be recoverable — not die via SIG_DFL. Shape
// mirrors the red-team repro: N goroutines hammering
// boundedCStringLen on an unterminated buffer while the
// test goroutine nil-dereferences in a loop with recover,
// for ~2s. Pre-fix this died 8/8 runs with
// "signal: segmentation fault"; post-fix the process must
// survive every run. The test passes trivially if no fault
// happens to land inside a scan window, but the hammer
// keeps the guard installed near-continuously (scans are
// serialised back-to-back under the mutex), so a fault
// landing outside a window is unlikely over 2s — and a
// pre-fix build dies on the first such fault.
func TestBoundedCStringLenCrossThreadFault(t *testing.T) {
	buf := make([]byte, maxHostMethodLen)
	for i := range buf {
		buf[i] = 'x'
	}
	ptr := unsafe.Pointer(&buf[0])
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = boundedCStringLen(ptr, maxHostMethodLen)
			}
		}()
	}
	recovered := 0
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		func() {
			defer func() {
				if recover() != nil {
					recovered++
				}
			}()
			var p *int
			_ = *p
		}()
	}
	close(stop)
	wg.Wait()
	if recovered == 0 {
		t.Fatal("no nil-deref panic was recovered during the hammer; the cross-thread case was not exercised")
	}
	t.Logf("recovered %d nil-deref panics during concurrent guarded scans", recovered)
}
