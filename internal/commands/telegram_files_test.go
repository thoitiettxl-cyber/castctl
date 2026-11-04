// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// PR-B /files + dl tests: the recent-files list command and its
// download buttons, through the full `telegram run` harness and
// through a directly wired Bot. Fake Telegram server + scripted
// fake gateway only.

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/shared"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
)

// filesHistoryEvent builds one assistant history event carrying a
// single file resource, in the shape EventResources reads.
func filesHistoryEvent(seq int64, path, mime string, byteLen *int64) map[string]any {
	res := map[string]any{"path": path}
	if mime != "" {
		res["mime"] = mime
	}
	if byteLen != nil {
		res["byte_len"] = *byteLen
	}
	return map[string]any{
		"event_name": "message.assistant", "seq": seq,
		"payload": map[string]any{
			"display_text": "here", "status": "completed",
			"data": map[string]any{"files": []any{res}},
		},
	}
}

func int64ptr(v int64) *int64 { return &v }

// filesMarkupButtons parses one send/edit reply_markup JSON into its
// buttons' text + callback_data, in row order.
func filesMarkupButtons(t *testing.T, markupJSON string) [][2]string {
	t.Helper()
	var kb struct {
		InlineKeyboard [][]struct {
			Text         string `json:"text"`
			CallbackData string `json:"callback_data"`
		} `json:"inline_keyboard"`
	}
	if err := json.Unmarshal([]byte(markupJSON), &kb); err != nil {
		t.Fatalf("markup %q is not a keyboard: %v", markupJSON, err)
	}
	var out [][2]string
	for _, row := range kb.InlineKeyboard {
		for _, b := range row {
			out = append(out, [2]string{b.Text, b.CallbackData})
		}
	}
	return out
}

func filesSendMarkup(t *testing.T, h *telegramBotHarness) string {
	t.Helper()
	h.fake.mu.Lock()
	defer h.fake.mu.Unlock()
	if len(h.fake.sendMarkupJSON) != 1 {
		t.Fatalf("sendMarkupJSON = %d entries; want 1 (the /files list)", len(h.fake.sendMarkupJSON))
	}
	return h.fake.sendMarkupJSON[0]
}

func TestFilesListsNewestFirstDedupedCapped(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	// Wire order (oldest first): f01..f13, a newer duplicate of
	// f05, then f14, f15. Reversed + deduped by path (newest
	// wins) + capped at 12: f15, f14, f05, f13..f04.
	for i := 1; i <= 13; i++ {
		gw.addEvent(filesHistoryEvent(int64(10+i), "sandbox://workspace/f"+strconv.Itoa(i)+".txt", "text/plain", int64ptr(10)))
	}
	gw.addEvent(filesHistoryEvent(24, "sandbox://workspace/f5.txt", "text/plain", int64ptr(10)))
	gw.addEvent(filesHistoryEvent(25, "sandbox://workspace/f14.txt", "text/plain", int64ptr(10)))
	gw.addEvent(filesHistoryEvent(26, "sandbox://workspace/f15.txt", "text/plain", int64ptr(10)))
	h, cancel, codeCh := runTelegramBot(t, gw, []string{telegramUpdate(1, 111, "/files")})
	defer cancel()
	waitFor(t, "files list send", func() bool { return len(sendsOf(h)) >= 1 })
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	sends := sendsOf(h)
	if len(sends) != 1 || sends[0] != "Recent files (newest first). Tap one to get it:" {
		t.Fatalf("sends = %q; want exactly the list text", sends)
	}
	buttons := filesMarkupButtons(t, filesSendMarkup(t, h))
	wantLabels := []string{
		"📥 f15.txt", "📥 f14.txt", "📥 f5.txt", "📥 f13.txt",
		"📥 f12.txt", "📥 f11.txt", "📥 f10.txt", "📥 f9.txt",
		"📥 f8.txt", "📥 f7.txt", "📥 f6.txt", "📥 f4.txt",
	}
	if len(buttons) != len(wantLabels) {
		t.Fatalf("buttons = %d; want %d: %v", len(buttons), len(wantLabels), buttons)
	}
	for i, b := range buttons {
		if b[0] != wantLabels[i] {
			t.Errorf("button[%d] label = %q; want %q", i, b[0], wantLabels[i])
		}
		if len(b[1]) > 64 || !strings.HasPrefix(b[1], "c:") {
			t.Errorf("button[%d] callback_data = %q; want a short c: token (<= 64 bytes)", i, b[1])
		}
	}
	// The history window: /files must ask for the last 40 events.
	gw.mu.Lock()
	limits := append([]int(nil), gw.historyLimits...)
	gw.mu.Unlock()
	found40 := false
	for _, l := range limits {
		if l == 40 {
			found40 = true
		}
	}
	if !found40 {
		t.Errorf("history limits requested = %v; want a read of 40", limits)
	}
}

func TestFilesLabelTruncatesLongBasename(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	long := strings.Repeat("a", 60) + ".txt"
	gw.addEvent(filesHistoryEvent(11, "sandbox://workspace/"+long, "text/plain", int64ptr(10)))
	h, cancel, codeCh := runTelegramBot(t, gw, []string{telegramUpdate(1, 111, "/files")})
	defer cancel()
	waitFor(t, "files list send", func() bool { return len(sendsOf(h)) >= 1 })
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	buttons := filesMarkupButtons(t, filesSendMarkup(t, h))
	if len(buttons) != 1 {
		t.Fatalf("buttons = %v; want 1", buttons)
	}
	want := "📥 " + strings.Repeat("a", 50)
	if buttons[0][0] != want {
		t.Errorf("button label = %q (%d runes); want %q (50-char basename cap)", buttons[0][0], len([]rune(buttons[0][0])), want)
	}
}

func TestFilesEmptyAnswersNoFiles(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBot(t, gw, []string{telegramUpdate(1, 111, "/files")})
	defer cancel()
	waitFor(t, "no-files send", func() bool { return len(sendsOf(h)) >= 1 })
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	sends := sendsOf(h)
	if len(sends) != 1 || sends[0] != "No files in recent messages here." {
		t.Fatalf("sends = %q; want exactly the no-files sentence", sends)
	}
	h.fake.mu.Lock()
	markup := ""
	if len(h.fake.sendMarkupJSON) > 0 {
		markup = h.fake.sendMarkupJSON[0]
	}
	h.fake.mu.Unlock()
	if markup != "" && markup != "null" {
		t.Errorf("no-files send markup = %q; want none", markup)
	}
}

// tapFilesButton drives /files through the wired bot, taps the
// first button, and returns the harness after shutdown.
func tapFilesButton(t *testing.T, gw *telegramTurnFakeGateway) *wiredBot {
	t.Helper()
	wb := startWiredBot(t, gw)
	wb.fake.setBatches([]string{telegramUpdate(1, 111, "/files")})
	waitFor(t, "files list send", func() bool { return len(wb.fake.sendsSeen()) >= 1 })
	wb.fake.mu.Lock()
	markup := ""
	if len(wb.fake.sendMarkupJSON) > 0 {
		markup = wb.fake.sendMarkupJSON[0]
	}
	wb.fake.mu.Unlock()
	buttons := filesMarkupButtons(t, markup)
	if len(buttons) == 0 {
		t.Fatal("no buttons on the /files list")
	}
	wb.fake.setBatches([]string{callbackUpdate(2, buttons[0][1], 100)})
	return wb
}

func TestDownloadButtonSendsFile(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.addEvent(filesHistoryEvent(11, "sandbox://workspace/report.txt?v=2", "text/plain", int64ptr(10)))
	gw.downloads = map[string][]byte{"sandbox://workspace/report.txt?v=2": []byte("hello")}
	wb := tapFilesButton(t, gw)
	defer wb.cancel()
	waitFor(t, "document send", func() bool { return len(wb.fake.documentsSeen()) >= 1 })
	wb.cancel()
	<-wb.done
	docs := wb.fake.documentsSeen()
	if len(docs) != 1 {
		t.Fatalf("documents = %+v; want 1 sendDocument", docs)
	}
	if docs[0].Filename != "report.txt" || docs[0].Caption != "" || docs[0].HasMarkup {
		t.Errorf("document = %+v; want filename report.txt, empty caption, no markup", docs[0])
	}
	gw.mu.Lock()
	calls := append([]string(nil), gw.downloadCalls...)
	gw.mu.Unlock()
	if len(calls) != 1 || calls[0] != "sandbox://workspace/report.txt?v=2" {
		t.Errorf("downloadCalls = %q; want exactly the full resource path", calls)
	}
}

func TestDownloadButtonNewestRowWins(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	// Older row says 60 MB, newer row says 10 bytes: the tap
	// must download (newest wins), not refuse.
	gw.addEvent(filesHistoryEvent(11, "sandbox://workspace/dup.txt", "text/plain", int64ptr(60<<20)))
	gw.addEvent(filesHistoryEvent(12, "sandbox://workspace/dup.txt", "text/plain", int64ptr(10)))
	gw.downloads = map[string][]byte{"sandbox://workspace/dup.txt": []byte("hello")}
	wb := tapFilesButton(t, gw)
	defer wb.cancel()
	waitFor(t, "document send", func() bool { return len(wb.fake.documentsSeen()) >= 1 })
	wb.cancel()
	<-wb.done
	if n := len(wb.fake.documentsSeen()); n != 1 {
		t.Fatalf("documents = %d; want 1 (newest row wins over the stale 60 MB row)", n)
	}
	if sends := wb.fake.sendsSeen(); len(sends) != 1 {
		t.Fatalf("sends = %q; want only the /files list (no refusal)", sends)
	}
}

func TestDownloadButtonOversizeRefusesWithoutDownload(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	res := shared.Resource{Path: "sandbox://workspace/big.bin", ByteLen: int64ptr(50 << 20)}
	data := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "dl", Resource: res})
	wb.fake.setBatches([]string{callbackUpdate(9, data, 50)})
	waitFor(t, "refusal send", func() bool {
		for _, s := range wb.fake.sendsSeen() {
			if strings.Contains(s, "Too big for Telegram") {
				return true
			}
		}
		return false
	})
	wb.cancel()
	<-wb.done
	sends := wb.fake.sendsSeen()
	if len(sends) != 1 || sends[0] != "Too big for Telegram (49 MB); use castctl download." {
		t.Fatalf("sends = %q; want exactly the refusal sentence", sends)
	}
	gw.mu.Lock()
	calls := len(gw.downloadCalls)
	gw.mu.Unlock()
	if calls != 0 {
		t.Errorf("downloadCalls = %d; want 0 (size known before download)", calls)
	}
	if n := len(wb.fake.documentsSeen()) + len(wb.fake.mediaSendsSeen()); n != 0 {
		t.Errorf("file sends = %d; want 0", n)
	}
}

func TestDownloadButtonUnknownByteLenGatesAfterDownload(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.downloads = map[string][]byte{"sandbox://workspace/huge.bin": make([]byte, (49<<20)+1)}
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	res := shared.Resource{Path: "sandbox://workspace/huge.bin"}
	data := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "dl", Resource: res})
	wb.fake.setBatches([]string{callbackUpdate(9, data, 50)})
	waitFor(t, "refusal send", func() bool {
		for _, s := range wb.fake.sendsSeen() {
			if strings.Contains(s, "Too big for Telegram") {
				return true
			}
		}
		return false
	})
	wb.cancel()
	<-wb.done
	sends := wb.fake.sendsSeen()
	if len(sends) != 1 || sends[0] != "Too big for Telegram (49 MB); use castctl download." {
		t.Fatalf("sends = %q; want exactly the refusal sentence", sends)
	}
	gw.mu.Lock()
	calls := len(gw.downloadCalls)
	gw.mu.Unlock()
	if calls != 1 {
		t.Errorf("downloadCalls = %d; want 1 (unknown size: download, then gate)", calls)
	}
	if n := len(wb.fake.documentsSeen()) + len(wb.fake.mediaSendsSeen()); n != 0 {
		t.Errorf("file sends = %d; want 0", n)
	}
}

func TestDownloadButtonFilenameFallsBackToFile(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.downloads = map[string][]byte{"": []byte("hello")}
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	data := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "dl", Resource: shared.Resource{}})
	wb.fake.setBatches([]string{callbackUpdate(9, data, 50)})
	waitFor(t, "document send", func() bool { return len(wb.fake.documentsSeen()) >= 1 })
	wb.cancel()
	<-wb.done
	docs := wb.fake.documentsSeen()
	if len(docs) != 1 || docs[0].Filename != "file" {
		t.Fatalf("documents = %+v; want one sendDocument named \"file\"", docs)
	}
}

func TestDownloadButtonExpiredAnswersExpired(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	wb.fake.setBatches([]string{callbackUpdate(9, "c:xxxxxxxx", 50)})
	waitFor(t, "expired answer", func() bool { return len(wb.fake.answersSeen()) >= 1 })
	wb.cancel()
	<-wb.done
	answers := wb.fake.answersSeen()
	if len(answers) != 1 || answers[0] != "This button expired; run the command again." {
		t.Fatalf("answers = %q; want exactly the expired text", answers)
	}
	if sends := wb.fake.sendsSeen(); len(sends) != 0 {
		t.Fatalf("sends = %q; want none for an expired button", sends)
	}
	gw.mu.Lock()
	calls := len(gw.downloadCalls)
	gw.mu.Unlock()
	if calls != 0 {
		t.Errorf("downloadCalls = %d; want 0", calls)
	}
}
