// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAcquireSingleFlightRejectsBadTag (loop-2 red-team F4,
// defence in depth): a hand-built entry with an escaping tag
// is refused before any owner file is computed.
func TestAcquireSingleFlightRejectsBadTag(t *testing.T) {
	dir := t.TempDir()
	for _, tag := range []string{"a/../../x", "a\nb", "..", " k1"} {
		if _, err := AcquireSingleFlight(dir, tag, RealClock); err == nil {
			t.Fatalf("AcquireSingleFlight(%q) succeeded; want error", tag)
		}
	}
	// The constant login tag still acquires.
	release, err := AcquireSingleFlight(dir, "login", RealClock)
	if err != nil {
		t.Fatalf("AcquireSingleFlight(login): %v", err)
	}
	release()
}

// TestSingleFlightReleasePreservesForeignOwner (loop-2
// red-team N7/N3): a stale runner whose release runs after a
// takeover must not delete the new owner's file.
func TestSingleFlightReleasePreservesForeignOwner(t *testing.T) {
	dir := t.TempDir()
	release, err := AcquireSingleFlight(dir, "k1", RealClock)
	if err != nil {
		t.Fatal(err)
	}
	path, err := ownerPath(dir, "k1")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a takeover: a new owner with a fresh heartbeat.
	foreign, _ := json.Marshal(ownerFile{PID: os.Getpid() + 100000, Heartbeat: time.Now().Unix()})
	if err := os.WriteFile(path, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	release()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("owner file deleted by stale release: %v", err)
	}
	if string(raw) != string(foreign) {
		t.Fatalf("owner file = %q; want the foreign owner untouched", raw)
	}
}

// TestRefreshOwnerOwnership (loop-2 red-team N7/N3): the
// heartbeat refresh rewrites only its own owner file.
func TestRefreshOwnerOwnership(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keeper-k1.owner")
	own := os.Getpid()
	now := &fakeClock{now: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
	// Own file: refresh updates the heartbeat.
	initial, _ := json.Marshal(ownerFile{PID: own, Heartbeat: 1000})
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	if !refreshOwner(path, own, now) {
		t.Fatal("refreshOwner(own) returned false")
	}
	raw, _ := os.ReadFile(path)
	var owner ownerFile
	if err := json.Unmarshal(raw, &owner); err != nil || owner.Heartbeat != now.Now().Unix() {
		t.Fatalf("owner after refresh = %q; want heartbeat %d", raw, now.Now().Unix())
	}
	// Foreign file: refresh refuses and leaves it untouched.
	foreign, _ := json.Marshal(ownerFile{PID: own + 100000, Heartbeat: 1000})
	if err := os.WriteFile(path, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if refreshOwner(path, own, now) {
		t.Fatal("refreshOwner(foreign) returned true")
	}
	raw, _ = os.ReadFile(path)
	if string(raw) != string(foreign) {
		t.Fatalf("foreign owner file rewritten: %q", raw)
	}
}

// TestOwnerPathContainment: ownerPath refuses tags that
// would escape the profile directory even if validation
// were bypassed.
func TestOwnerPathContainment(t *testing.T) {
	dir := t.TempDir()
	if _, err := ownerPath(dir, "a/../../x"); err == nil {
		t.Fatal("ownerPath accepted an escaping tag")
	}
	p, err := ownerPath(dir, "k1")
	if err != nil || filepath.Dir(p) != dir {
		t.Fatalf("ownerPath(k1) = %q, %v", p, err)
	}
}
