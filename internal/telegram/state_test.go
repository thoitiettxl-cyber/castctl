// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestStatePath(t *testing.T) {
	if got := StatePath("/cfg/profiles/muse01"); got != filepath.Join("/cfg/profiles/muse01", "telegram-state.json") {
		t.Fatalf("StatePath = %q", got)
	}
}

func TestStateStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, corrupt, err := LoadStateStore(dir)
	if err != nil {
		t.Fatalf("LoadStateStore (missing) = %v", err)
	}
	if corrupt {
		t.Error("missing file must not report corrupt")
	}
	if got := store.Offset(); got != 0 {
		t.Errorf("Offset = %d; want 0", got)
	}
	if _, ok := store.Chat(500); ok {
		t.Error("unseen chat must report absent")
	}
	aa, ao, w := store.Toggles()
	if aa != nil || ao != nil || w != nil {
		t.Errorf("fresh toggles = %v/%v/%v; want all nil (block values apply)", aa, ao, w)
	}

	if err := store.SetChat(500, ChatEntry{SessionID: "sess-1", Title: "side chat"}); err != nil {
		t.Fatalf("SetChat = %v", err)
	}
	if err := store.SetWatermark("sess-1", 42); err != nil {
		t.Fatalf("SetWatermark = %v", err)
	}
	if err := store.NoteOffset(7); err != nil {
		t.Fatalf("NoteOffset = %v", err)
	}
	if err := store.SetToggles(true, false); err != nil {
		t.Fatalf("SetToggles = %v", err)
	}
	if err := store.SetWatch(true); err != nil {
		t.Fatalf("SetWatch = %v", err)
	}

	path := StatePath(dir)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat state file = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("state file mode = %o; want 0600", info.Mode().Perm())
	}

	reloaded, corrupt, err := LoadStateStore(dir)
	if err != nil {
		t.Fatalf("LoadStateStore (present) = %v", err)
	}
	if corrupt {
		t.Error("valid file must not report corrupt")
	}
	entry, ok := reloaded.Chat(500)
	if !ok || entry.SessionID != "sess-1" || entry.Title != "side chat" {
		t.Errorf("Chat(500) = %+v, %v; want sess-1/side chat", entry, ok)
	}
	if got := reloaded.Watermark("sess-1"); got != 42 {
		t.Errorf("Watermark = %d; want 42", got)
	}
	if got := reloaded.Offset(); got != 7 {
		t.Errorf("Offset = %d; want 7", got)
	}
	aa, ao, w = reloaded.Toggles()
	if aa == nil || *aa != true || ao == nil || *ao != false || w == nil || *w != true {
		t.Errorf("toggles = %v/%v/%v; want true/false/true", boolPtrString(aa), boolPtrString(ao), boolPtrString(w))
	}
}

func boolPtrString(p *bool) string {
	if p == nil {
		return "<nil>"
	}
	if *p {
		return "true"
	}
	return "false"
}

func TestStateStoreCorruptAndVersion(t *testing.T) {
	dir := t.TempDir()
	path := StatePath(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, corrupt, err := LoadStateStore(dir)
	if err != nil {
		t.Fatalf("LoadStateStore (garbage) = %v", err)
	}
	if !corrupt {
		t.Error("garbage file must report corrupt")
	}
	if got := store.Offset(); got != 0 {
		t.Errorf("corrupt load Offset = %d; want fresh 0", got)
	}
	// Saving over corruption must produce a valid file.
	if err := store.NoteOffset(3); err != nil {
		t.Fatalf("NoteOffset after corrupt load = %v", err)
	}
	if _, corrupt, err := LoadStateStore(dir); err != nil || corrupt {
		t.Errorf("reload after repair: err=%v corrupt=%v; want clean", err, corrupt)
	}

	// Unknown schema version refuses to start: silently
	// discarding stored mappings/watermarks would lose the
	// poll offset and session state. The error names the
	// version and the counts that would be discarded, and
	// the failed load must not mutate the file (a restart
	// after the refusal still sees version 99, not a fresh
	// file written over it).
	versioned := []byte(`{"version":99,"offset":9,"chats":{"500":{"title":"main"}},"watermarks":{"main":11},"auto_approve":true}`)
	if err := os.WriteFile(path, versioned, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadStateStore(dir); err == nil {
		t.Error("unknown version must refuse to start")
	} else if !strings.Contains(err.Error(), "version 99") || !strings.Contains(err.Error(), "1 chat mapping") || !strings.Contains(err.Error(), "1 watermark") || !strings.Contains(err.Error(), "offset 9") {
		t.Errorf("unknown-version error = %v; want version + discarded counts", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, versioned) {
		t.Error("failed unknown-version load mutated the state file; want it untouched")
	}

	// A mistyped version refuses too, instead of falling
	// through to the corrupt path (which would load fresh
	// and discard the state): a string "2" or a float 2.0
	// is a shape error, not corruption, and the file must
	// survive the refusal byte-for-byte. (A leading-zero
	// literal such as 007 never reaches the shape check: it
	// is invalid JSON, so the probe decode fails first and
	// the file takes the warned corrupt path — the
	// pre-existing accepted residual for malformed files.
	// See the micro-loop report for why no lenient pre-scan
	// was added for it.)
	for _, shaped := range []string{
		`{"version":"2","offset":9,"chats":{"500":{"title":"main"}}}`,
		`{"version":2.0,"offset":9,"chats":{"500":{"title":"main"}}}`,
		`{"version":2e0,"offset":9,"chats":{"500":{"title":"main"}}}`,
		`{"version":true,"offset":9,"chats":{"500":{"title":"main"}}}`,
		`{"version":null,"offset":9,"chats":{"500":{"title":"main"}}}`,
	} {
		shapedBytes := []byte(shaped)
		if err := os.WriteFile(path, shapedBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadStateStore(dir); err == nil {
			t.Errorf("mistyped version %s must refuse to start", shaped)
		} else if !strings.Contains(err.Error(), "non-integer shape") {
			t.Errorf("mistyped-version error = %v; want the shape refusal", err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, shapedBytes) {
			t.Errorf("failed mistyped-version load mutated the state file for %s; want it untouched", shaped)
		}
	}

	// An out-of-range integer literal refuses too, instead of
	// overflowing the body decode into the corrupt path: the
	// digit string is a valid shape but no int can hold it,
	// so the file must survive the refusal byte-for-byte.
	for _, huge := range []string{
		`{"version":99999999999999999999999,"offset":9,"chats":{"500":{"title":"main"}}}`,
		`{"version":-99999999999999999999999,"offset":9,"chats":{"500":{"title":"main"}}}`,
	} {
		hugeBytes := []byte(huge)
		if err := os.WriteFile(path, hugeBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadStateStore(dir); err == nil {
			t.Errorf("out-of-range version %s must refuse to start", huge)
		} else if !strings.Contains(err.Error(), "out of range") {
			t.Errorf("out-of-range-version error = %v; want the range refusal", err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, hugeBytes) {
			t.Errorf("failed out-of-range-version load mutated the state file for %s; want it untouched", huge)
		}
	}

	// A missing version refuses as 0, as before, without
	// mutating the file.
	missingBytes := []byte(`{"offset":9,"chats":{"500":{"title":"main"}}}`)
	if err := os.WriteFile(path, missingBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadStateStore(dir); err == nil {
		t.Error("missing version must refuse to start")
	} else if !strings.Contains(err.Error(), "version 0 is not supported") {
		t.Errorf("missing-version error = %v; want the version 0 refusal", err)
	}
	after, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, missingBytes) {
		t.Error("failed missing-version load mutated the state file; want it untouched")
	}

	// A giant mistyped version must not turn the refusal
	// into a giant log line: the echoed shape is bounded.
	giant := `{"version":"` + strings.Repeat("x", 200) + `","offset":9}`
	giantBytes := []byte(giant)
	if err := os.WriteFile(path, giantBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadStateStore(dir); err == nil {
		t.Error("giant mistyped version must refuse to start")
	} else if len(err.Error()) > 200 || !strings.Contains(err.Error(), "...") {
		t.Errorf("giant-version error length = %d; want a bounded echo", len(err.Error()))
	}
	after, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, giantBytes) {
		t.Error("failed giant-version load mutated the state file; want it untouched")
	}

	// An empty file loads fresh without a corrupt report: a
	// zero-length state file carries no claim at all.
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, corrupt, err := LoadStateStore(dir); err != nil || corrupt {
		t.Errorf("empty file: err=%v corrupt=%v; want fresh, clean", err, corrupt)
	}
}

func TestStateStoreWatermarkMonotonic(t *testing.T) {
	dir := t.TempDir()
	store, _, err := LoadStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetWatermark(WatermarkKey(""), 10); err != nil {
		t.Fatal(err)
	}
	if err := store.SetWatermark(WatermarkKey(""), 5); err != nil {
		t.Fatal(err)
	}
	if got := store.Watermark(WatermarkKey("")); got != 10 {
		t.Errorf("Watermark(main) = %d; want 10 (never moves backward)", got)
	}
	if WatermarkKey("") != "main" || WatermarkKey("sess-9") != "sess-9" {
		t.Errorf("WatermarkKey: main=%q sess=%q", WatermarkKey(""), WatermarkKey("sess-9"))
	}
}

func TestStateStoreToggleNilVsSet(t *testing.T) {
	dir := t.TempDir()
	store, _, err := LoadStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit false must survive a reload as set-false, distinct
	// from never-toggled (nil): the state file wins over the block
	// only after the first runtime toggle.
	if err := store.SetToggles(false, false); err != nil {
		t.Fatal(err)
	}
	reloaded, _, err := LoadStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	aa, ao, _ := reloaded.Toggles()
	if aa == nil || *aa {
		t.Errorf("reloaded auto_approve = %v; want set-false", boolPtrString(aa))
	}
	if ao == nil || *ao {
		t.Errorf("reloaded auto_allow_once = %v; want set-false", boolPtrString(ao))
	}
}

func TestStateStoreConcurrent(t *testing.T) {
	dir := t.TempDir()
	store, _, err := LoadStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := int64(0); i < 20; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			_ = store.NoteOffset(i)
			_ = store.SetChat(i, ChatEntry{SessionID: "s", Title: "t"})
			_ = store.Watermark("s")
		}(i)
	}
	wg.Wait()
	if got := store.Offset(); got != 19 {
		t.Errorf("Offset = %d; want 19 (max noted)", got)
	}
	if _, ok := store.Chat(19); !ok {
		t.Error("Chat(19) absent after concurrent writes")
	}
}
