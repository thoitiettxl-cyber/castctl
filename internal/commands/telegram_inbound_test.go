// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

// Inbound user media (PR-C): a photo/file a user sends to the bot
// is downloaded through getFile plus the file URL, written to
// System Files at telegram-inbox/<timestamp>-<name>, announced
// with a silent Saved line, and told to Muse in a turn
// (upstream media_of / upload_and_send, tgbot.py:1762-1799 at
// v0.6.1, commit b4dd8f5).

// inboundMediaBatch builds one getUpdates batch whose message
// carries the given media payload under key, plus an optional
// caption and optional text.
func inboundMediaBatch(updateID, msgID int, caption, text, key string, payload any) string {
	msg := map[string]any{
		"message_id": msgID,
		"date":       1700000000,
		"chat":       map[string]any{"id": 500, "type": "private"},
		"from":       map[string]any{"id": 111, "is_bot": false, "first_name": "Tester"},
	}
	if caption != "" {
		msg["caption"] = caption
	}
	if text != "" {
		msg["text"] = text
	}
	if key != "" {
		msg[key] = payload
	}
	b, _ := json.Marshal(map[string]any{"update_id": updateID, "message": msg})
	return `{"ok":true,"result":[` + string(b) + `]}`
}

func photoPayload(fileID string, size int) []any {
	return []any{
		map[string]any{"file_id": "small-" + fileID, "file_size": 100},
		map[string]any{"file_id": fileID, "file_size": size},
	}
}

// turnInputTexts returns the display_text of every message.user
// event the fake gateway recorded for a media turn (the texts
// turns were started with, in order). The gateway seeds one
// "earlier" user event; only inputs carrying the saved-note
// are media turns, so the seed is excluded.
func turnInputTexts(gw *telegramTurnFakeGateway) []string {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	var out []string
	for _, ev := range gw.events {
		if ev["event_name"] != "message.user" {
			continue
		}
		if payload, ok := ev["payload"].(map[string]any); ok {
			if text, ok := payload["display_text"].(string); ok && strings.Contains(text, "[Telegram attachment saved") {
				out = append(out, text)
			}
		}
	}
	return out
}

// waitForMediaTurn waits until a media turn input is recorded.
func waitForMediaTurn(t *testing.T, gw *telegramTurnFakeGateway) {
	t.Helper()
	waitFor(t, "media turn input", func() bool { return len(turnInputTexts(gw)) >= 1 })
}

// fsWrittenPaths returns the paths the fake gateway received
// fs.write calls for.
func fsWrittenPaths(gw *telegramTurnFakeGateway) []string {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	var out []string
	for p := range gw.fsWritten {
		out = append(out, p)
	}
	return out
}

var inboxPathRe = regexp.MustCompile(`^telegram-inbox/\d{8}-\d{6}-photo-7\.jpg$`)

func TestInboundPhotoSavedAndToldToMuse(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "noted"}}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{})
	defer cancel()
	h.fake.mu.Lock()
	h.fake.getFileSizeSet = true
	h.fake.getFileSize = 5
	h.fake.getFilePath = "photos/file_1.jpg"
	h.fake.fileBytes = []byte("JPEG!")
	h.fake.mu.Unlock()
	h.fake.setBatches([]string{inboundMediaBatch(1, 7, "look at this", "", "photo", photoPayload("big", 5))})
	waitFor(t, "Saved line", func() bool {
		for _, s := range h.fake.sendsSeen() {
			if strings.HasPrefix(s, "📥 Saved to <code>telegram-inbox/") {
				return true
			}
		}
		return false
	})
	waitFor(t, "turn reply edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "noted") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	paths := fsWrittenPaths(gw)
	if len(paths) != 1 {
		t.Fatalf("fs.write paths = %q; want 1", paths)
	}
	if !inboxPathRe.MatchString(paths[0]) {
		t.Errorf("fs.write path = %q; want telegram-inbox/<YYYYmmdd-HHMMSS>-photo-7.jpg", paths[0])
	}
	gw.mu.Lock()
	written := gw.fsWritten[paths[0]]
	gw.mu.Unlock()
	if string(written) != "JPEG!" {
		t.Errorf("fs.write bytes = %q; want %q", written, "JPEG!")
	}
	sends := h.fake.sendsSeen()
	wantSaved := "📥 Saved to <code>" + paths[0] + "</code>"
	found := false
	for _, s := range sends {
		if s == wantSaved {
			found = true
		}
	}
	if !found {
		t.Errorf("sends = %q; want the exact Saved line %q", sends, wantSaved)
	}
	inputs := turnInputTexts(gw)
	wantNote := "[Telegram attachment saved in your System Files at " + paths[0] + " (5 bytes, image/jpeg)]"
	wantTurn := "look at this\n\n" + wantNote
	found = false
	for _, in := range inputs {
		if in == wantTurn {
			found = true
		}
	}
	if !found {
		t.Errorf("turn inputs = %q; want exactly %q", inputs, wantTurn)
	}
}

func TestInboundDocumentWithoutCaption(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "noted"}}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{})
	defer cancel()
	h.fake.mu.Lock()
	h.fake.getFileSizeSet = true
	h.fake.getFileSize = 3
	h.fake.getFilePath = "documents/file_2"
	h.fake.fileBytes = []byte("abc")
	h.fake.mu.Unlock()
	h.fake.setBatches([]string{inboundMediaBatch(1, 11, "", "", "document", map[string]any{
		"file_id": "doc1", "file_name": "notes.txt", "mime_type": "text/plain", "file_size": 3,
	})})
	waitFor(t, "Saved line", func() bool {
		for _, s := range h.fake.sendsSeen() {
			if strings.HasPrefix(s, "📥 Saved to <code>telegram-inbox/") {
				return true
			}
		}
		return false
	})
	waitForMediaTurn(t, gw)
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	paths := fsWrittenPaths(gw)
	if len(paths) != 1 {
		t.Fatalf("fs.write paths = %q; want 1", paths)
	}
	if !regexp.MustCompile(`^telegram-inbox/\d{8}-\d{6}-notes\.txt$`).MatchString(paths[0]) {
		t.Errorf("fs.write path = %q; want telegram-inbox/<ts>-notes.txt", paths[0])
	}
	inputs := turnInputTexts(gw)
	want := "I sent you a file from Telegram. [Telegram attachment saved in your System Files at " + paths[0] + " (3 bytes, text/plain)]"
	found := false
	for _, in := range inputs {
		if in == want {
			found = true
		}
	}
	if !found {
		t.Errorf("turn inputs = %q; want exactly %q", inputs, want)
	}
}

func TestInboundTextPlusPhotoIsMediaOnly(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "noted"}}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{})
	defer cancel()
	h.fake.mu.Lock()
	h.fake.getFileSizeSet = true
	h.fake.getFileSize = 5
	h.fake.getFilePath = "photos/file_1.jpg"
	h.fake.fileBytes = []byte("JPEG!")
	h.fake.mu.Unlock()
	// A message carrying BOTH text and a photo: upstream treats
	// it as media only — the text field is dropped, only the
	// caption enters the turn.
	h.fake.setBatches([]string{inboundMediaBatch(1, 7, "the caption", "dropped text", "photo", photoPayload("big", 5))})
	waitForMediaTurn(t, gw)
	waitFor(t, "Saved line", func() bool {
		for _, s := range h.fake.sendsSeen() {
			if strings.HasPrefix(s, "📥 Saved to <code>telegram-inbox/") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	inputs := turnInputTexts(gw)
	for _, in := range inputs {
		if strings.Contains(in, "dropped text") {
			t.Errorf("turn input carries the dropped text field: %q", in)
		}
	}
	found := false
	for _, in := range inputs {
		if strings.HasPrefix(in, "the caption\n\n[Telegram attachment saved") {
			found = true
		}
	}
	if !found {
		t.Errorf("turn inputs = %q; want one starting with the caption + note", inputs)
	}
}

func TestInboundSlashCaptionIsNotACommand(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "noted"}}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{})
	defer cancel()
	h.fake.mu.Lock()
	h.fake.getFileSizeSet = true
	h.fake.getFileSize = 5
	h.fake.getFilePath = "photos/file_1.jpg"
	h.fake.fileBytes = []byte("JPEG!")
	h.fake.mu.Unlock()
	h.fake.setBatches([]string{inboundMediaBatch(1, 7, "/help", "", "photo", photoPayload("big", 5))})
	waitForMediaTurn(t, gw)
	waitFor(t, "Saved line", func() bool {
		for _, s := range h.fake.sendsSeen() {
			if strings.HasPrefix(s, "📥 Saved to <code>telegram-inbox/") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	for _, s := range h.fake.sendsSeen() {
		if s == telegramBotHelpText {
			t.Error("a /help caption triggered the help command; want the media path")
		}
	}
	inputs := turnInputTexts(gw)
	found := false
	for _, in := range inputs {
		if strings.HasPrefix(in, "/help\n\n[Telegram attachment saved") {
			found = true
		}
	}
	if !found {
		t.Errorf("turn inputs = %q; want the /help caption in the turn text", inputs)
	}
}

func TestInboundOversizeDeclaredRefusesWithoutDownloadOrWrite(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBot(t, gw, []string{})
	defer cancel()
	h.fake.mu.Lock()
	h.fake.getFileSizeSet = true
	h.fake.getFileSize = 21 << 20
	h.fake.getFilePath = "documents/big.bin"
	h.fake.fileBytes = []byte("must-not-be-fetched")
	h.fake.mu.Unlock()
	h.fake.setBatches([]string{inboundMediaBatch(1, 11, "", "", "document", map[string]any{
		"file_id": "doc1", "file_name": "big.bin", "file_size": 21 << 20,
	})})
	waitFor(t, "refusal send", func() bool {
		for _, s := range h.fake.sendsSeen() {
			if s == "⚠️ That file is too big for Telegram to fetch (20 MB limit)." {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	if got := len(fsWrittenPaths(gw)); got != 0 {
		t.Errorf("fs.write paths = %d; want 0", got)
	}
	h.fake.mu.Lock()
	fileHits := len(h.fake.filePaths)
	h.fake.mu.Unlock()
	if fileHits != 0 {
		t.Errorf("file endpoint hit %d times; want 0", fileHits)
	}
	if got := len(turnInputTexts(gw)); got != 0 {
		t.Errorf("turn inputs = %d; want 0 (no turn on refusal)", got)
	}
}

func TestInboundUnknownSizeOversizeRefusesAfterDownload(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBot(t, gw, []string{})
	defer cancel()
	h.fake.mu.Lock()
	// getFile omits file_size: the post-download length gate
	// must refuse.
	h.fake.getFilePath = "documents/big.bin"
	h.fake.fileBytes = make([]byte, (20<<20)+1)
	h.fake.mu.Unlock()
	h.fake.setBatches([]string{inboundMediaBatch(1, 11, "", "", "document", map[string]any{
		"file_id": "doc1", "file_name": "big.bin",
	})})
	waitFor(t, "refusal send", func() bool {
		for _, s := range h.fake.sendsSeen() {
			if s == "⚠️ That file is too big for Telegram to fetch (20 MB limit)." {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	if got := len(fsWrittenPaths(gw)); got != 0 {
		t.Errorf("fs.write paths = %d; want 0", got)
	}
}

func TestInboundGatewayAuthErrorSendsLoginSentence(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsWriteErr = conn.NewAuthError("gateway: auth failed")
	gw.subScripts = []turnSubScript{{replyText: "noted"}}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{})
	defer cancel()
	h.fake.mu.Lock()
	h.fake.getFileSizeSet = true
	h.fake.getFileSize = 5
	h.fake.getFilePath = "photos/file_1.jpg"
	h.fake.fileBytes = []byte("JPEG!")
	h.fake.mu.Unlock()
	h.fake.setBatches([]string{inboundMediaBatch(1, 7, "", "", "photo", photoPayload("big", 5))})
	waitFor(t, "login-expired send", func() bool {
		for _, s := range h.fake.sendsSeen() {
			if s == "🔑 muse.ai login expired. Use /login." {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	for _, s := range h.fake.sendsSeen() {
		if strings.Contains(s, "Saved to") {
			t.Errorf("Saved line sent despite the failed write: %q", s)
		}
		if strings.Contains(s, "Re-export cookies") {
			t.Errorf("generic dispatch login sentence sent; want upstream's /login sentence: %q", s)
		}
	}
	if got := len(turnInputTexts(gw)); got != 0 {
		t.Errorf("turn inputs = %d; want 0 (no turn on failed write)", got)
	}
}

func TestInboundGatewayErrorSendsClassSummaryOnly(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsWriteErr = fmt.Errorf("gateway exploded: MARKER-RAW-TEXT")
	h, cancel, codeCh := runTelegramBot(t, gw, []string{})
	defer cancel()
	h.fake.mu.Lock()
	h.fake.getFileSizeSet = true
	h.fake.getFileSize = 5
	h.fake.getFilePath = "photos/file_1.jpg"
	h.fake.fileBytes = []byte("JPEG!")
	h.fake.mu.Unlock()
	h.fake.setBatches([]string{inboundMediaBatch(1, 7, "", "", "photo", photoPayload("big", 5))})
	waitFor(t, "failure send", func() bool {
		for _, s := range h.fake.sendsSeen() {
			if strings.HasPrefix(s, "⚠️ Upload to System Files failed:") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	for _, s := range h.fake.sendsSeen() {
		if strings.Contains(s, "MARKER-RAW-TEXT") {
			t.Errorf("failure send leaks raw error text: %q", s)
		}
		if strings.Contains(s, telegramTestToken) {
			t.Errorf("failure send leaks the token: %q", s)
		}
	}
	if got := len(turnInputTexts(gw)); got != 0 {
		t.Errorf("turn inputs = %d; want 0 (no turn on failed write)", got)
	}
}

func TestInboundNoTokenInSendsOrMethods(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "noted"}}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{})
	defer cancel()
	h.fake.mu.Lock()
	h.fake.getFileSizeSet = true
	h.fake.getFileSize = 5
	h.fake.getFilePath = "photos/file_1.jpg"
	h.fake.fileBytes = []byte("JPEG!")
	h.fake.mu.Unlock()
	h.fake.setBatches([]string{inboundMediaBatch(1, 7, "hi", "", "photo", photoPayload("big", 5))})
	waitFor(t, "Saved line", func() bool {
		for _, s := range h.fake.sendsSeen() {
			if strings.HasPrefix(s, "📥 Saved to <code>telegram-inbox/") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	for _, s := range h.fake.sendsSeen() {
		if strings.Contains(s, telegramTestToken) {
			t.Errorf("send leaks the token: %q", s)
		}
	}
	for _, m := range h.fake.methodsSeen() {
		if strings.Contains(m, telegramTestToken) {
			t.Errorf("recorded method leaks the token: %q", m)
		}
	}
}

// TestInboundDownloadFailureSendsCouldNotFetch pins the
// download-failure own-reply (red-team B1/M15): when the
// file endpoint answers 500, the chat gets the exact
// "Could not fetch" sentence, and nothing is written and no
// turn starts.
func TestInboundDownloadFailureSendsCouldNotFetch(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBot(t, gw, []string{})
	defer cancel()
	h.fake.mu.Lock()
	h.fake.getFileSizeSet = true
	h.fake.getFileSize = 5
	h.fake.getFilePath = "photos/file_1.jpg"
	h.fake.fileStatus = 500
	h.fake.fileBytes = []byte("MARKER-RAW-BODY")
	h.fake.mu.Unlock()
	h.fake.setBatches([]string{inboundMediaBatch(1, 7, "", "", "photo", photoPayload("big", 5))})
	waitFor(t, "could-not-fetch send", func() bool {
		for _, s := range h.fake.sendsSeen() {
			if strings.HasPrefix(s, "⚠️ Could not fetch that file from Telegram: ") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	h.fake.mu.Lock()
	fileHits := len(h.fake.filePaths)
	h.fake.mu.Unlock()
	if fileHits == 0 {
		t.Error("file endpoint never hit; want the download attempted")
	}
	for _, s := range h.fake.sendsSeen() {
		if strings.Contains(s, "Saved to") {
			t.Errorf("Saved line sent despite the failed download: %q", s)
		}
		if strings.Contains(s, "MARKER-RAW-BODY") {
			t.Errorf("failure send leaks the raw error body: %q", s)
		}
		if strings.Contains(s, telegramTestToken) {
			t.Errorf("failure send leaks the token: %q", s)
		}
	}
	if got := len(fsWrittenPaths(gw)); got != 0 {
		t.Errorf("fs.write paths = %d; want 0", got)
	}
	if got := len(turnInputTexts(gw)); got != 0 {
		t.Errorf("turn inputs = %d; want 0 (no turn on failed download)", got)
	}
}

// TestInboundFirstWriteChunkCarriesNoOverwriteAndCreateParent
// pins the overwrite=false collision guard (red-team B2/M16):
// the first fs.write chunk the fake gateway records carries
// Overwrite=false and CreateParent=true.
func TestInboundFirstWriteChunkCarriesNoOverwriteAndCreateParent(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "noted"}}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{})
	defer cancel()
	h.fake.mu.Lock()
	h.fake.getFileSizeSet = true
	h.fake.getFileSize = 5
	h.fake.getFilePath = "photos/file_1.jpg"
	h.fake.fileBytes = []byte("JPEG!")
	h.fake.mu.Unlock()
	h.fake.setBatches([]string{inboundMediaBatch(1, 7, "", "", "photo", photoPayload("big", 5))})
	waitFor(t, "Saved line", func() bool {
		for _, s := range h.fake.sendsSeen() {
			if strings.HasPrefix(s, "📥 Saved to <code>telegram-inbox/") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	gw.mu.Lock()
	calls := append([]fsWriteCall(nil), gw.fsWriteCalls...)
	gw.mu.Unlock()
	if len(calls) == 0 {
		t.Fatal("no fs.write calls recorded; want at least 1")
	}
	if calls[0].Overwrite {
		t.Errorf("first fs.write chunk has Overwrite=true; want false")
	}
	if !calls[0].CreateParent {
		t.Errorf("first fs.write chunk has CreateParent=false; want true")
	}
}

// TestInboundVideoNoteNoteOmitsMimeClause pins the empty-mime
// note (red-team B4/M7): a video_note carries no MIME type,
// so its saved note reads "(N bytes)" with no dangling ", "
// clause.
func TestInboundVideoNoteNoteOmitsMimeClause(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "noted"}}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{})
	defer cancel()
	h.fake.mu.Lock()
	h.fake.getFileSizeSet = true
	h.fake.getFileSize = 4
	h.fake.getFilePath = "notes/file_3.mp4"
	h.fake.fileBytes = []byte("VN!!")
	h.fake.mu.Unlock()
	h.fake.setBatches([]string{inboundMediaBatch(1, 7, "", "", "video_note", map[string]any{
		"file_id": "vn1", "file_size": 4,
	})})
	waitForMediaTurn(t, gw)
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	paths := fsWrittenPaths(gw)
	if len(paths) != 1 {
		t.Fatalf("fs.write paths = %q; want 1", paths)
	}
	if !regexp.MustCompile(`^telegram-inbox/\d{8}-\d{6}-video_note-7\.mp4$`).MatchString(paths[0]) {
		t.Errorf("fs.write path = %q; want telegram-inbox/<ts>-video_note-7.mp4", paths[0])
	}
	inputs := turnInputTexts(gw)
	want := "I sent you a file from Telegram. [Telegram attachment saved in your System Files at " + paths[0] + " (4 bytes)]"
	found := false
	for _, in := range inputs {
		if in == want {
			found = true
		}
	}
	if !found {
		t.Errorf("turn inputs = %q; want exactly %q", inputs, want)
	}
}

// TestInboundNoteUsesDownloadedLength pins the note's byte
// count source (red-team B3/M18): the note carries the
// DOWNLOADED length, not the size declared by getFile or
// the update, in both the overstated-size and the
// exactly-at-cap cases.
func TestInboundNoteUsesDownloadedLength(t *testing.T) {
	t.Parallel()
	runCase := func(t *testing.T, name string, declared int64, body []byte, wantBytes int) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			gw := newTelegramTurnFakeGateway()
			gw.subScripts = []turnSubScript{{replyText: "noted"}}
			h, cancel, codeCh := runTelegramBot(t, gw, []string{})
			defer cancel()
			h.fake.mu.Lock()
			h.fake.getFileSizeSet = true
			h.fake.getFileSize = declared
			h.fake.getFilePath = "photos/file_1.jpg"
			h.fake.fileBytes = body
			h.fake.mu.Unlock()
			h.fake.setBatches([]string{inboundMediaBatch(1, 7, "", "", "photo", photoPayload("big", int(declared)))})
			waitForMediaTurn(t, gw)
			cancel()
			if code := <-codeCh; code != 130 {
				t.Errorf("run code = %d; want 130", code)
			}
			paths := fsWrittenPaths(gw)
			if len(paths) != 1 {
				t.Fatalf("fs.write paths = %q; want 1", paths)
			}
			inputs := turnInputTexts(gw)
			want := fmt.Sprintf("I sent you a file from Telegram. [Telegram attachment saved in your System Files at %s (%d bytes, image/jpeg)]", paths[0], wantBytes)
			found := false
			for _, in := range inputs {
				if in == want {
					found = true
				}
			}
			if !found {
				t.Errorf("turn inputs = %q; want exactly %q", inputs, want)
			}
		})
	}
	runCase(t, "declared larger than body", 999, []byte("JPEG!"), 5)
	runCase(t, "declared exactly at cap with tiny body", 20<<20, []byte("tiny"), 4)
}
