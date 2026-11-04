// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// PR-B 6-file/turn cap tests: deliverFinal through the media
// path, with fabricated history. Both note carriers are proven:
// the trailing tail (media-last turn) and the last text segment
// (text-last turn).

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/wait"
)

const capNote = "📎 2 more file(s): see /files"

// capMediaEvent builds one assistant history event carrying a
// single file resource at the given seq.
func capMediaEvent(seq int64, path string) map[string]any {
	return map[string]any{
		"event_name": "message.assistant", "seq": seq,
		"payload": map[string]any{
			"display_text": "here", "status": "completed",
			"data": map[string]any{"files": []any{map[string]any{
				"path": path, "mime": "text/plain", "byte_len": int64(10),
			}}},
		},
	}
}

// capTurn runs deliverFinal with n media events (seq 11..10+n)
// and the given replies, and returns the fake for assertions.
func capTurn(t *testing.T, gw *telegramTurnFakeGateway, n int, replies []wait.Reply) *cmdFakeTelegram {
	t.Helper()
	downloads := map[string][]byte{}
	for i := 1; i <= n; i++ {
		path := fmt.Sprintf("sandbox://workspace/f%d.txt", i)
		gw.addEvent(capMediaEvent(int64(10+i), path))
		downloads[path] = []byte("x")
	}
	gw.downloads = downloads
	runner, fake := turnRunnerNamed(t, gw)
	res := &wait.Result{Outcome: "needs_input", Replies: replies}
	if err := runner.deliverFinal(context.Background(), 500, 100, "", "main chat", 10, res, false); err != nil {
		t.Fatalf("deliverFinal = %v; want nil", err)
	}
	return fake
}

func capDocNames(t *testing.T, fake *cmdFakeTelegram) []string {
	t.Helper()
	var names []string
	for _, d := range fake.documentsSeen() {
		names = append(names, d.Filename)
	}
	return names
}

func countOccurrences(texts []string, substr string) int {
	n := 0
	for _, s := range texts {
		n += strings.Count(s, substr)
	}
	return n
}

func TestTurnMediaCapEightSendsSixWithTailNote(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	// All 8 files ride ONE event at seq 11 (the reply's seq):
	// the collect window is (userSeq, deliveredTopSeq], and
	// deliveredTopSeq is the greatest reply seq, so media on
	// later seqs than every reply would fall outside the
	// window. The single reply sorts before the media, the
	// turn ends in media after the cap, and the notes ride
	// the trailing tail.
	downloads := map[string][]byte{}
	var files []any
	for i := 1; i <= 8; i++ {
		path := fmt.Sprintf("sandbox://workspace/f%d.txt", i)
		files = append(files, map[string]any{"path": path, "mime": "text/plain", "byte_len": int64(10)})
		downloads[path] = []byte("x")
	}
	gw.addEvent(map[string]any{
		"event_name": "message.assistant", "seq": int64(11),
		"payload": map[string]any{
			"display_text": "here", "status": "completed",
			"data": map[string]any{"files": files},
		},
	})
	gw.downloads = downloads
	runner, fake := turnRunnerNamed(t, gw)
	res := &wait.Result{Outcome: "needs_input", Replies: []wait.Reply{{Seq: 11, Text: "pick?"}}}
	if err := runner.deliverFinal(context.Background(), 500, 100, "", "main chat", 10, res, false); err != nil {
		t.Fatalf("deliverFinal = %v; want nil", err)
	}
	names := capDocNames(t, fake)
	want := []string{"f1.txt", "f2.txt", "f3.txt", "f4.txt", "f5.txt", "f6.txt"}
	if len(names) != len(want) {
		t.Fatalf("document sends = %v; want the first 6 by seq: %v", names, want)
	}
	for i, name := range names {
		if name != want[i] {
			t.Errorf("document[%d] = %q; want %q", i, name, want[i])
		}
	}
	if n := len(fake.mediaSendsSeen()); n != 0 {
		t.Errorf("photo/video/audio sends = %d; want 0 (.txt goes to sendDocument)", n)
	}
	sends := fake.sendsSeen()
	edits := fake.editTexts()
	if total := countOccurrences(append(append([]string{}, sends...), edits...), capNote); total != 1 {
		t.Fatalf("cap note occurrences = %d; want exactly 1 (sends=%q edits=%q)", total, sends, edits)
	}
	// The bubble edit carries the reply text; the single send
	// is the tail, carrying the other note BEFORE the cap note.
	if len(edits) != 1 || edits[0] != "pick?" {
		t.Fatalf("edits = %q; want one bubble edit of the reply text", edits)
	}
	if len(sends) != 1 {
		t.Fatalf("sends = %q; want exactly the tail send", sends)
	}
	asking := strings.Index(sends[0], "❓ Muse is asking…")
	cap := strings.Index(sends[0], capNote)
	if asking < 0 || cap < 0 || asking > cap {
		t.Errorf("tail send = %q; want the asking note before the cap note", sends[0])
	}
}

func TestTurnMediaCapEightSendsSixWithTextNote(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	// A later text reply (seq 19) makes the last segment text,
	// so the notes ride the last text segment instead of a tail.
	fake := capTurn(t, gw, 8, []wait.Reply{{Seq: 11, Text: "pick?"}, {Seq: 19, Text: "done"}})
	names := capDocNames(t, fake)
	if len(names) != 6 {
		t.Fatalf("document sends = %v; want 6", names)
	}
	sends := fake.sendsSeen()
	edits := fake.editTexts()
	if total := countOccurrences(append(append([]string{}, sends...), edits...), capNote); total != 1 {
		t.Fatalf("cap note occurrences = %d; want exactly 1 (sends=%q edits=%q)", total, sends, edits)
	}
	// The last text segment's send must carry the asking note
	// before the cap note, and there must be no tail-only send
	// carrying the note a second time.
	found := ""
	for _, s := range append(append([]string{}, sends...), edits...) {
		if strings.Contains(s, capNote) {
			found = s
		}
	}
	asking := strings.Index(found, "❓ Muse is asking…")
	cap := strings.Index(found, capNote)
	if asking < 0 || cap < 0 || asking > cap {
		t.Errorf("note carrier = %q; want the asking note before the cap note", found)
	}
}

func TestTurnMediaCapSixSendsSixWithNoNote(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	fake := capTurn(t, gw, 6, []wait.Reply{{Seq: 16, Text: "pick?"}})
	names := capDocNames(t, fake)
	if len(names) != 6 {
		t.Fatalf("document sends = %v; want 6", names)
	}
	sends := fake.sendsSeen()
	edits := fake.editTexts()
	if total := countOccurrences(append(append([]string{}, sends...), edits...), "more file(s)"); total != 0 {
		t.Fatalf("cap-note occurrences = %d; want 0 at exactly 6 files (sends=%q edits=%q)", total, sends, edits)
	}
}
