// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func busyErr(path string) error {
	return &os.PathError{Op: "open", Path: path, Err: syscall.ETXTBSY}
}

func TestOpenForSyncRetriesBusyThenSucceeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "candidate")
	if err := os.WriteFile(path, []byte("candidate-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := reopenOpen
	attempts := 0
	reopenOpen = func(p string) (*os.File, error) {
		attempts++
		if attempts <= 3 {
			return nil, busyErr(p)
		}
		return os.OpenFile(p, os.O_RDWR, 0)
	}
	t.Cleanup(func() { reopenOpen = prev })

	f, err := openForSync(path)
	if err != nil {
		t.Fatalf("openForSync: %v", err)
	}
	_ = f.Close()
	if attempts != 4 {
		t.Errorf("attempts = %d, want 4", attempts)
	}
}

func TestOpenForSyncNonBusyErrorReturnsImmediately(t *testing.T) {
	prev := reopenOpen
	attempts := 0
	reopenOpen = func(p string) (*os.File, error) {
		attempts++
		return nil, &os.PathError{Op: "open", Path: p, Err: syscall.EACCES}
	}
	t.Cleanup(func() { reopenOpen = prev })

	_, err := openForSync("candidate")
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("err = %v, want EACCES", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (no retry on non-ETXTBSY)", attempts)
	}
}

func TestOpenForSyncExhaustionReturnsBusy(t *testing.T) {
	prev := reopenOpen
	attempts := 0
	reopenOpen = func(p string) (*os.File, error) {
		attempts++
		return nil, busyErr(p)
	}
	t.Cleanup(func() { reopenOpen = prev })

	_, err := openForSync("candidate")
	if !errors.Is(err, syscall.ETXTBSY) {
		t.Fatalf("err = %v, want ETXTBSY", err)
	}
	if attempts <= 1 {
		t.Errorf("attempts = %d, want > 1 (must retry before giving up)", attempts)
	}
}

func TestOpenForSyncAfterRealExec(t *testing.T) {
	// The install path execs the candidate binary and immediately
	// re-opens it O_RDWR for the pre-rename fsync. On cue (Linux,
	// ext4) the re-open failed with ETXTBSY in ~3% of
	// exec-then-open pairs (285-324/10000, all recovered within
	// 24-82ms), which flaked the full install. 200 iterations
	// expect ~6 busy windows pre-fix; the retry must absorb
	// every one. On hosts without the window the test passes
	// trivially.
	path := filepath.Join(t.TempDir(), "fakeversion")
	if err := os.WriteFile(path, fakeBinary(t), 0o755); err != nil {
		t.Fatal(err)
	}
	want := mustParse(t, "0.6.4")
	for i := 0; i < 200; i++ {
		if err := runExecCheck(context.Background(), path, want); err != nil {
			t.Fatalf("iteration %d: exec check: %v", i, err)
		}
		f, err := openForSync(path)
		if err != nil {
			t.Fatalf("iteration %d: openForSync: %v", i, err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			t.Fatalf("iteration %d: sync: %v", i, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("iteration %d: close: %v", i, err)
		}
	}
}
