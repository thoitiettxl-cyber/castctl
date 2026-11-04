// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-telegram/bot"
)

func TestFileKindFor(t *testing.T) {
	t.Parallel()
	const (
		photoLimit = int64(10 << 20)
	)
	tests := []struct {
		name string
		file string
		mime string
		size int64
		want FileKind
	}{
		{"jpeg mime under limit", "pic.bin", "image/jpeg", 100, FileKindPhoto},
		{"png mime at limit", "pic.bin", "image/png", photoLimit, FileKindPhoto},
		{"webp mime", "pic.bin", "image/webp", 100, FileKindPhoto},
		{"png extension no mime", "pic.png", "", 100, FileKindPhoto},
		{"jpg extension no mime", "pic.jpg", "", 100, FileKindPhoto},
		{"jpeg extension no mime", "pic.jpeg", "", 100, FileKindPhoto},
		{"webp extension no mime", "pic.webp", "", 100, FileKindPhoto},
		{"uppercase mime", "pic.bin", "IMAGE/JPEG", 100, FileKindPhoto},
		{"uppercase extension", "PIC.PNG", "", 100, FileKindPhoto},
		{"unknown size photo eligible", "pic.jpg", "", -1, FileKindPhoto},
		{"empty file photo", "pic.jpg", "", 0, FileKindPhoto},
		{"photo over limit becomes document", "pic.jpg", "", photoLimit + 1, FileKindDocument},
		{"photo mime over limit becomes document", "pic.bin", "image/jpeg", photoLimit + 1, FileKindDocument},
		{"gif mime with png name is document", "pic.png", "image/gif", 100, FileKindDocument},
		{"video mime", "clip.bin", "video/mp4", 100, FileKindVideo},
		{"video mime over photo limit stays video", "clip.bin", "video/mp4", photoLimit + 1, FileKindVideo},
		{"video extension no mime", "clip.mov", "", 100, FileKindVideo},
		{"m4v extension no mime", "clip.m4v", "", 100, FileKindVideo},
		{"video mime beats png extension", "clip.png", "video/mp4", 100, FileKindVideo},
		{"audio mime", "song.bin", "audio/mpeg", 100, FileKindAudio},
		{"audio mime over photo limit stays audio", "song.bin", "audio/mpeg", photoLimit + 1, FileKindAudio},
		{"audio extension no mime", "song.flac", "", 100, FileKindAudio},
		{"ogg extension no mime", "song.ogg", "", 100, FileKindAudio},
		{"oga extension no mime", "song.oga", "", 100, FileKindAudio},
		{"wav extension no mime", "song.wav", "", 100, FileKindAudio},
		{"m4a extension no mime", "song.m4a", "", 100, FileKindAudio},
		{"unknown extension", "data.bin", "", 100, FileKindDocument},
		{"unknown mime", "data.bin", "application/octet-stream", 100, FileKindDocument},
		{"no extension no mime", "README", "", 100, FileKindDocument},
		{"double extension uses last", "archive.tar.gz", "", 100, FileKindDocument},
		{"leading dot file has no extension", ".hidden", "", 100, FileKindDocument},
		{"all dots before last dot is no extension", "..png", "", 100, FileKindDocument},
		{"three leading dots is no extension", "...png", "", 100, FileKindDocument},
		{"dots then name before last dot has extension", "..a.png", "", 100, FileKindPhoto},
		{"all dots before last dot jpg is no extension", "..jpg", "", 100, FileKindDocument},
		{"trailing dot", "file.", "", 100, FileKindDocument},
		{"path prefix ignored for extension", "dir/sub/pic.jpg", "", 100, FileKindPhoto},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := FileKindFor(tt.file, tt.mime, tt.size); got != tt.want {
				t.Errorf("FileKindFor(%q, %q, %d) = %q; want %q", tt.file, tt.mime, tt.size, got, tt.want)
			}
		})
	}
}

func TestDocName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		stem string
		text string
		want string
	}{
		{"plain text", "muse-reply", "hello world", "muse-reply.txt"},
		{"fenced code is markdown", "muse-reply", "see:\n```go\nx\n```", "muse-reply.md"},
		{"heading is markdown", "muse-reply", "# Title\nbody", "muse-reply.md"},
		{"heading without space is not", "muse-reply", "#Title\nbody", "muse-reply.txt"},
		{"bold is markdown", "muse-reply", "a **bold** word", "muse-reply.md"},
		{"sanitize spaces and slashes", "my reply/2", "plain", "my-reply-2.txt"},
		{"sanitize collapses runs", "a  b!!c", "plain", "a-b-c.txt"},
		{"strip leading and trailing dashes", "---hi---", "plain", "hi.txt"},
		{"strip after sanitize", "!!!hi!!!", "plain", "hi.txt"},
		{"dots and underscores kept", "a.b_c-d", "plain", "a.b_c-d.txt"},
		{"cap at 40 runes", strings.Repeat("x", 50), "plain", strings.Repeat("x", 40) + ".txt"},
		{"cap after strip", "!!!" + strings.Repeat("y", 45), "plain", strings.Repeat("y", 40) + ".txt"},
		{"multibyte stem sanitizes away entirely", strings.Repeat("é", 50), "plain", ".txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := DocName(tt.stem, tt.text); got != tt.want {
				t.Errorf("DocName(%q, %q) = %q; want %q", tt.stem, tt.text, got, tt.want)
			}
		})
	}
}

func TestSendFilePhoto(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	data := []byte("fake-jpeg-bytes")
	id, err := tb.bot.SendFile(context.Background(), 500, "pic.jpg", data, "image/jpeg", "a caption", SendOptions{})
	if err != nil {
		t.Fatalf("SendFile = %v; want nil", err)
	}
	if id != 100 {
		t.Errorf("SendFile id = %d; want 100 (first fake message)", id)
	}
	if got := srv.count("getMe"); got != 1 {
		t.Errorf("getMe calls = %d; want 1 (upload instance must skip getMe)", got)
	}
	if got := srv.count("sendPhoto"); got != 1 {
		t.Fatalf("sendPhoto calls = %d; want 1", got)
	}
	if got := srv.count("sendDocument"); got != 0 {
		t.Errorf("sendDocument calls = %d; want 0", got)
	}
	call := srv.callsOf("sendPhoto")[0]
	if call.Form["caption"] != "a caption" {
		t.Errorf("caption = %q; want %q", call.Form["caption"], "a caption")
	}
	if call.Form["chat_id"] != "500" {
		t.Errorf("chat_id = %q; want %q", call.Form["chat_id"], "500")
	}
	part, ok := call.Files["photo"]
	if !ok {
		t.Fatal("sendPhoto recorded no photo file part")
	}
	if part.Filename != "pic.jpg" {
		t.Errorf("photo filename = %q; want %q", part.Filename, "pic.jpg")
	}
	if part.Size != int64(len(data)) {
		t.Errorf("photo size = %d; want %d", part.Size, len(data))
	}
}

func TestSendFileKinds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		file   string
		mime   string
		method string
		field  string
	}{
		{"video by extension", "clip.mp4", "", "sendVideo", "video"},
		{"video by mime", "clip.bin", "video/mp4", "sendVideo", "video"},
		{"audio by extension", "song.mp3", "", "sendAudio", "audio"},
		{"audio by mime", "song.bin", "audio/mpeg", "sendAudio", "audio"},
		{"document unknown", "data.bin", "", "sendDocument", "document"},
		{"document over photo limit", "pic.jpg", "", "sendDocument", "document"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := newFakeTelegramServer(t)
			tb := newTestBot(t, srv, nil)
			data := []byte("x")
			if tt.name == "document over photo limit" {
				data = make([]byte, PhotoLimit+1)
			}
			id, err := tb.bot.SendFile(context.Background(), 500, tt.file, data, tt.mime, "", SendOptions{})
			if err != nil {
				t.Fatalf("SendFile = %v; want nil", err)
			}
			if id != 100 {
				t.Errorf("SendFile id = %d; want 100", id)
			}
			if got := srv.count(tt.method); got != 1 {
				t.Fatalf("%s calls = %d; want 1", tt.method, got)
			}
			call := srv.callsOf(tt.method)[0]
			part, ok := call.Files[tt.field]
			if !ok {
				t.Fatalf("%s recorded no %q file part", tt.method, tt.field)
			}
			if part.Filename != tt.file {
				t.Errorf("filename = %q; want %q", part.Filename, tt.file)
			}
		})
	}
}

func TestSendFileCaptionTruncatedTo1024Runes(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	caption := strings.Repeat("é", 1100)
	if _, err := tb.bot.SendFile(context.Background(), 500, "notes.txt", []byte("body"), "", caption, SendOptions{}); err != nil {
		t.Fatalf("SendFile = %v; want nil", err)
	}
	calls := srv.callsOf("sendDocument")
	if len(calls) != 1 {
		t.Fatalf("sendDocument calls = %d; want 1", len(calls))
	}
	got := calls[0].Form["caption"]
	if len([]rune(got)) != CaptionLimit {
		t.Fatalf("caption runes = %d; want %d", len([]rune(got)), CaptionLimit)
	}
	if got != strings.Repeat("é", CaptionLimit) {
		t.Error("caption is not exactly the first 1024 runes of the input")
	}
}

func TestSendFileFallbackOnBadRequest(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	srv.sendPhotoFailures = []scriptedFailure{{Code: 400, Desc: "Bad Request: wrong file type"}}
	tb := newTestBot(t, srv, nil)
	id, err := tb.bot.SendFile(context.Background(), 500, "pic.jpg", []byte("data"), "image/jpeg", "cap", SendOptions{})
	if err != nil {
		t.Fatalf("SendFile = %v; want nil (fallback to sendDocument)", err)
	}
	if id != 100 {
		t.Errorf("SendFile id = %d; want 100", id)
	}
	if got := srv.count("sendPhoto"); got != 1 {
		t.Errorf("sendPhoto calls = %d; want 1", got)
	}
	if got := srv.count("sendDocument"); got != 1 {
		t.Errorf("sendDocument calls = %d; want 1 (fallback)", got)
	}
	call := srv.callsOf("sendDocument")[0]
	if call.Files["document"].Filename != "pic.jpg" {
		t.Errorf("fallback filename = %q; want %q", call.Files["document"].Filename, "pic.jpg")
	}
	if call.Files["document"].Size != 4 {
		t.Errorf("fallback file part size = %d; want 4 (a fresh reader over the full input)", call.Files["document"].Size)
	}
	if call.Form["caption"] != "cap" {
		t.Errorf("fallback caption = %q; want %q", call.Form["caption"], "cap")
	}
}

func TestSendFileNoFallbackForDocumentKind(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	srv.sendDocumentFailures = []scriptedFailure{{Code: 400, Desc: "Bad Request: wrong file type"}}
	tb := newTestBot(t, srv, nil)
	_, err := tb.bot.SendFile(context.Background(), 500, "data.bin", []byte("data"), "", "", SendOptions{})
	if err == nil {
		t.Fatal("SendFile = nil; want an error")
	}
	if !errors.Is(err, bot.ErrorBadRequest) {
		t.Errorf("SendFile error = %v; want errors.Is ErrorBadRequest", err)
	}
	if got := srv.count("sendDocument"); got != 1 {
		t.Errorf("sendDocument calls = %d; want 1 (no fallback for document kind)", got)
	}
}

func TestSendFileNoFallbackForNonBadRequest(t *testing.T) {
	t.Parallel()
	t.Run("forbidden", func(t *testing.T) {
		t.Parallel()
		srv := newFakeTelegramServer(t)
		srv.sendPhotoFailures = []scriptedFailure{{Code: 403, Desc: "Forbidden: bot was blocked by the user"}}
		tb := newTestBot(t, srv, nil)
		_, err := tb.bot.SendFile(context.Background(), 500, "pic.jpg", []byte("data"), "image/jpeg", "", SendOptions{})
		if err == nil {
			t.Fatal("SendFile = nil; want an error")
		}
		if !errors.Is(err, bot.ErrorForbidden) {
			t.Errorf("SendFile error = %v; want errors.Is ErrorForbidden", err)
		}
		if got := srv.count("sendPhoto"); got != 1 {
			t.Errorf("sendPhoto calls = %d; want 1", got)
		}
		if got := srv.count("sendDocument"); got != 0 {
			t.Errorf("sendDocument calls = %d; want 0 (no fallback for non-400)", got)
		}
	})
	t.Run("rate limited exhausts retries without fallback", func(t *testing.T) {
		t.Parallel()
		srv := newFakeTelegramServer(t)
		srv.sendPhotoFailures = []scriptedFailure{
			{Code: 429, Desc: "Too Many Requests", RetryAfter: 1},
			{Code: 429, Desc: "Too Many Requests", RetryAfter: 1},
			{Code: 429, Desc: "Too Many Requests", RetryAfter: 1},
		}
		tb := newTestBot(t, srv, nil)
		_, err := tb.bot.SendFile(context.Background(), 500, "pic.jpg", []byte("data"), "image/jpeg", "", SendOptions{})
		if err == nil {
			t.Fatal("SendFile = nil; want an error")
		}
		var tmr *bot.TooManyRequestsError
		if !errors.As(err, &tmr) || tmr.RetryAfter != 1 {
			t.Errorf("SendFile error = %v; want TooManyRequestsError with RetryAfter 1", err)
		}
		if got := srv.count("sendPhoto"); got != 3 {
			t.Errorf("sendPhoto calls = %d; want 3 (initial + 2 retries)", got)
		}
		for _, call := range srv.callsOf("sendPhoto") {
			if call.Files["photo"].Size != 4 {
				t.Errorf("retried file part size = %d; want 4 (a fresh reader over the full input)", call.Files["photo"].Size)
			}
		}
		if got := len(tb.recordedSleeps()); got != 2 {
			t.Errorf("sleeps = %d; want 2", got)
		}
		if got := srv.count("sendDocument"); got != 0 {
			t.Errorf("sendDocument calls = %d; want 0 (no fallback after 429)", got)
		}
	})
}

func TestSendFileErrorIsScrubbed(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	srv.sendDocumentFailures = []scriptedFailure{{Code: 400, Desc: "Bad Request: " + fakeToken}}
	tb := newTestBot(t, srv, nil)
	_, err := tb.bot.SendFile(context.Background(), 500, "data.bin", []byte("data"), "", "", SendOptions{})
	if err == nil {
		t.Fatal("SendFile = nil; want an error")
	}
	if !errors.Is(err, bot.ErrorBadRequest) {
		t.Errorf("SendFile error = %v; want errors.Is ErrorBadRequest", err)
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Errorf("SendFile error carries the token: %q", err.Error())
	}
}

func TestSendFileReplyAndSilent(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	if _, err := tb.bot.SendFile(context.Background(), 500, "data.bin", []byte("data"), "", "", SendOptions{ReplyTo: 42, Silent: true}); err != nil {
		t.Fatalf("SendFile = %v; want nil", err)
	}
	calls := srv.callsOf("sendDocument")
	if len(calls) != 1 {
		t.Fatalf("sendDocument calls = %d; want 1", len(calls))
	}
	form := calls[0].Form
	if form["disable_notification"] != "true" {
		t.Errorf("disable_notification = %q; want %q", form["disable_notification"], "true")
	}
	var replyParams struct {
		MessageID int `json:"message_id"`
	}
	if err := json.Unmarshal([]byte(form["reply_parameters"]), &replyParams); err != nil {
		t.Fatalf("reply_parameters %q is not JSON: %v", form["reply_parameters"], err)
	}
	if replyParams.MessageID != 42 {
		t.Errorf("reply_parameters message_id = %d; want 42", replyParams.MessageID)
	}
}
