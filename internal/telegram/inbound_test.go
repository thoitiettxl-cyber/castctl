// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-telegram/bot/models"
)

// MediaOf ports upstream media_of (src/muse_cli/tgbot.py:1762-1775
// at v0.6.1, commit b4dd8f5): photo takes the last size, other
// kinds are tried in the order document, video, audio, voice,
// video_note, animation. Expected values below are literals from
// the upstream source, not recomputed from the port.

func TestMediaOf(t *testing.T) {
	t.Parallel()
	photo := func(id string, size int) models.PhotoSize {
		return models.PhotoSize{FileID: id, FileSize: size}
	}
	cases := []struct {
		name string
		msg  *models.Message
		want *Media
	}{
		{
			name: "photo takes last element",
			msg: &models.Message{ID: 7, Photo: []models.PhotoSize{
				photo("small", 100), photo("big", 9000),
			}},
			want: &Media{FileID: "big", Name: "photo-7.jpg", MIME: "image/jpeg", Size: 9000},
		},
		{
			name: "document with file_name",
			msg: &models.Message{ID: 9, Document: &models.Document{
				FileID: "doc1", FileName: "report.pdf", MimeType: "application/pdf", FileSize: 1234,
			}},
			want: &Media{FileID: "doc1", Name: "report.pdf", MIME: "application/pdf", Size: 1234},
		},
		{
			name: "document without name takes no extension",
			msg: &models.Message{ID: 9, Document: &models.Document{
				FileID: "doc1", FileSize: 1234,
			}},
			want: &Media{FileID: "doc1", Name: "document-9", Size: 1234},
		},
		{
			name: "video without name",
			msg: &models.Message{ID: 3, Video: &models.Video{
				FileID: "vid1", MimeType: "video/mp4", FileSize: 55,
			}},
			want: &Media{FileID: "vid1", Name: "video-3.mp4", MIME: "video/mp4", Size: 55},
		},
		{
			name: "audio without name",
			msg: &models.Message{ID: 4, Audio: &models.Audio{
				FileID: "aud1", MimeType: "audio/mpeg", FileSize: 66,
			}},
			want: &Media{FileID: "aud1", Name: "audio-4.mp3", MIME: "audio/mpeg", Size: 66},
		},
		{
			name: "voice without name",
			msg: &models.Message{ID: 5, Voice: &models.Voice{
				FileID: "voi1", MimeType: "audio/ogg", FileSize: 77,
			}},
			want: &Media{FileID: "voi1", Name: "voice-5.ogg", MIME: "audio/ogg", Size: 77},
		},
		{
			name: "video note without name",
			msg: &models.Message{ID: 6, VideoNote: &models.VideoNote{
				FileID: "vn1", FileSize: 88,
			}},
			want: &Media{FileID: "vn1", Name: "video_note-6.mp4", Size: 88},
		},
		{
			name: "animation without name",
			msg: &models.Message{ID: 8, Animation: &models.Animation{
				FileID: "ani1", FileName: "", MimeType: "video/mp4", FileSize: 99,
			}},
			want: &Media{FileID: "ani1", Name: "animation-8.mp4", MIME: "video/mp4", Size: 99},
		},
		{
			name: "photo wins over document",
			msg: &models.Message{ID: 7,
				Photo:    []models.PhotoSize{photo("p1", 10)},
				Document: &models.Document{FileID: "doc1", FileName: "x.txt"},
			},
			want: &Media{FileID: "p1", Name: "photo-7.jpg", MIME: "image/jpeg", Size: 10},
		},
		{
			name: "document wins over video",
			msg: &models.Message{ID: 9,
				Document: &models.Document{FileID: "doc1", FileName: "x.txt"},
				Video:    &models.Video{FileID: "vid1"},
			},
			want: &Media{FileID: "doc1", Name: "x.txt"},
		},
		{
			name: "empty photo list falls through",
			msg:  &models.Message{ID: 1, Photo: []models.PhotoSize{}},
			want: nil,
		},
		{
			name: "no media",
			msg:  &models.Message{ID: 1, Text: "hello"},
			want: nil,
		},
		{
			name: "sticker is not media",
			msg: &models.Message{ID: 1, Sticker: &models.Sticker{
				FileID: "stk1", FileSize: 10,
			}},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MediaOf(tc.msg)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("MediaOf = %+v; want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("MediaOf = nil; want %+v", tc.want)
			}
			if *got != *tc.want {
				t.Errorf("MediaOf = %+v; want %+v", *got, *tc.want)
			}
		})
	}
	if MediaOf(nil) != nil {
		t.Error("MediaOf(nil) = non-nil; want nil")
	}
}

func TestInboxName(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 4, 7, 5, 9, 0, time.UTC)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "report.pdf", "20261104-070509-report.pdf"},
		{"spaces collapse to one underscore", "my notes.txt", "20261104-070509-my_notes.txt"},
		{"runs of bad chars collapse", "a!!!b???c", "20261104-070509-a_b_c"},
		{"leading dots and underscores stripped", "..__secret.txt", "20261104-070509-secret.txt"},
		{"trailing dots stripped", "name...", "20261104-070509-name"},
		{"empty after strip becomes file", "...", "20261104-070509-file"},
		{"empty name becomes file", "", "20261104-070509-file"},
		{"slashes become underscores", "a/b\\c.txt", "20261104-070509-a_b_c.txt"},
		{"keeps dash dot underscore", "my-file_v2.0.txt", "20261104-070509-my-file_v2.0.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := InboxName(tc.in, at); got != tc.want {
				t.Errorf("InboxName(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

// DownloadMedia fetches a user-sent file through getFile plus the
// file URL, capped at 20 MiB (upstream tgapi.download,
// tgapi.py:140-144, DOWNLOAD_LIMIT tgapi.py:20). The fake
// server scripts getFile and the /file/ endpoint.

func TestDownloadMediaSuccess(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	srv.getFileSizeSet = true
	srv.getFileSize = 5
	srv.getFilePath = "photos/file_1.jpg"
	srv.fileBytes = []byte("jpeg-bytes")
	tb := newTestBot(t, srv, nil)
	data, err := tb.bot.DownloadMedia(context.Background(), &Media{FileID: "fid1", Name: "photo-7.jpg", MIME: "image/jpeg", Size: 5})
	if err != nil {
		t.Fatalf("DownloadMedia = %v; want nil", err)
	}
	if string(data) != "jpeg-bytes" {
		t.Errorf("DownloadMedia bytes = %q; want %q", data, "jpeg-bytes")
	}
	if got := srv.count("getFile"); got != 1 {
		t.Errorf("getFile calls = %d; want 1", got)
	}
	srv.mu.Lock()
	paths := append([]string(nil), srv.filePaths...)
	srv.mu.Unlock()
	if len(paths) != 1 || paths[0] != "photos/file_1.jpg" {
		t.Errorf("file endpoint paths = %q; want [photos/file_1.jpg]", paths)
	}
}

func TestDownloadMediaOversizeDeclaredRefusesWithoutDownload(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	srv.getFileSizeSet = true
	srv.getFileSize = DownloadLimit + 1
	srv.getFilePath = "documents/big.bin"
	srv.fileBytes = []byte("must-not-be-fetched")
	tb := newTestBot(t, srv, nil)
	data, err := tb.bot.DownloadMedia(context.Background(), &Media{FileID: "fid1", Name: "big.bin"})
	if !errors.Is(err, ErrDownloadTooLarge) {
		t.Fatalf("DownloadMedia err = %v; want errors.Is ErrDownloadTooLarge", err)
	}
	if data != nil {
		t.Errorf("DownloadMedia data = %d bytes; want nil", len(data))
	}
	srv.mu.Lock()
	n := len(srv.filePaths)
	srv.mu.Unlock()
	if n != 0 {
		t.Errorf("file endpoint hit %d times; want 0 (declared-size gate refuses first)", n)
	}
}

func TestDownloadMediaUnknownSizeOversizeRefusesAfterDownload(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	// getFile omits file_size: the size is unknown, so the
	// post-download length gate must refuse.
	srv.getFilePath = "documents/big.bin"
	srv.fileBytes = make([]byte, DownloadLimit+1)
	tb := newTestBot(t, srv, nil)
	data, err := tb.bot.DownloadMedia(context.Background(), &Media{FileID: "fid1", Name: "big.bin"})
	if !errors.Is(err, ErrDownloadTooLarge) {
		t.Fatalf("DownloadMedia err = %v; want errors.Is ErrDownloadTooLarge", err)
	}
	if data != nil {
		t.Errorf("DownloadMedia data = %d bytes; want nil", len(data))
	}
}

func TestDownloadMediaExactLimitSucceeds(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	srv.getFileSizeSet = true
	srv.getFileSize = DownloadLimit
	srv.getFilePath = "documents/exact.bin"
	srv.fileBytes = make([]byte, DownloadLimit)
	tb := newTestBot(t, srv, nil)
	data, err := tb.bot.DownloadMedia(context.Background(), &Media{FileID: "fid1", Name: "exact.bin"})
	if err != nil {
		t.Fatalf("DownloadMedia = %v; want nil", err)
	}
	if int64(len(data)) != DownloadLimit {
		t.Errorf("DownloadMedia bytes = %d; want %d", len(data), DownloadLimit)
	}
}

func TestDownloadMediaEmptyFilePathFails(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	srv.getFileSizeSet = true
	srv.getFileSize = 5
	srv.getFilePath = "" // getFile reports no file_path
	tb := newTestBot(t, srv, nil)
	if _, err := tb.bot.DownloadMedia(context.Background(), &Media{FileID: "fid1"}); err == nil {
		t.Fatal("DownloadMedia = nil; want a fetch failure")
	}
	srv.mu.Lock()
	n := len(srv.filePaths)
	srv.mu.Unlock()
	if n != 0 {
		t.Errorf("file endpoint hit %d times; want 0", n)
	}
}

func TestDownloadMediaGetFileFailure(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	srv.getFileFail = &scriptedFailure{Code: 400, Desc: "Bad Request: file not found"}
	tb := newTestBot(t, srv, nil)
	_, err := tb.bot.DownloadMedia(context.Background(), &Media{FileID: "fid1"})
	if err == nil {
		t.Fatal("DownloadMedia = nil; want an error")
	}
	if errors.Is(err, ErrDownloadTooLarge) {
		t.Errorf("DownloadMedia err = %v; must not be ErrDownloadTooLarge", err)
	}
}

func TestDownloadMediaNon200HidesBodyAndToken(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	srv.getFileSizeSet = true
	srv.getFileSize = 5
	srv.getFilePath = "documents/x.bin"
	srv.fileStatus = 500
	srv.fileBytes = []byte("hostile body carrying " + fakeToken)
	tb := newTestBot(t, srv, nil)
	_, err := tb.bot.DownloadMedia(context.Background(), &Media{FileID: "fid1"})
	if err == nil {
		t.Fatal("DownloadMedia = nil; want an error")
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Errorf("DownloadMedia error carries the token: %q", err.Error())
	}
	if strings.Contains(err.Error(), "hostile body") {
		t.Errorf("DownloadMedia error echoes the body: %q", err.Error())
	}
}

func TestDownloadMediaTokenAbsentFromLogsAndCalls(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	srv.getFileSizeSet = true
	srv.getFileSize = 5
	srv.getFilePath = "photos/file_1.jpg"
	srv.fileBytes = []byte("jpeg-bytes")
	tb := newTestBot(t, srv, nil)
	if _, err := tb.bot.DownloadMedia(context.Background(), &Media{FileID: "fid1"}); err != nil {
		t.Fatalf("DownloadMedia = %v; want nil", err)
	}
	if strings.Contains(tb.logBuf.String(), fakeToken) {
		t.Errorf("bot logs carry the token: %q", tb.logBuf.String())
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, c := range srv.calls {
		for k, v := range c.Form {
			if strings.Contains(v, fakeToken) {
				t.Errorf("recorded %s field %s carries the token", c.Method, k)
			}
		}
		for k, f := range c.Files {
			if strings.Contains(f.Filename, fakeToken) {
				t.Errorf("recorded %s file %s carries the token", c.Method, k)
			}
		}
	}
}

func TestOnMessageForwardsMediaWithCaption(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startBot(t, tb.bot, ctx)
	srv.enqueueUpdates(mediaUpdate(1, 500, 111, 7, "look at this", "", "photo", []any{
		map[string]any{"file_id": "small", "file_size": 100},
		map[string]any{"file_id": "big", "file_size": 9000},
	}))
	waitFor(t, "media message delivered", func() bool { return len(tb.handler.recorded()) >= 1 })
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	calls := tb.handler.recorded()
	if len(calls) != 1 {
		t.Fatalf("handler calls = %d; want 1", len(calls))
	}
	mc := calls[0]
	if mc.Media == nil {
		t.Fatal("MessageContext.Media = nil; want the photo media")
	}
	want := Media{FileID: "big", Name: "photo-7.jpg", MIME: "image/jpeg", Size: 9000}
	if *mc.Media != want {
		t.Errorf("Media = %+v; want %+v", *mc.Media, want)
	}
	if mc.Caption != "look at this" {
		t.Errorf("Caption = %q; want %q", mc.Caption, "look at this")
	}
	if mc.Text != "" {
		t.Errorf("Text = %q; want empty (caption carries the user text)", mc.Text)
	}
}

func TestOnMessageDropsTextlessMedialessUpdate(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startBot(t, tb.bot, ctx)
	// A message with neither text nor media: the handler must
	// never see it. Wait until the poll loop has served at
	// least two getUpdates rounds (the batch is consumed),
	// then give the dispatcher a bounded drain window.
	srv.enqueueUpdates(mediaUpdate(1, 500, 111, 7, "", "", "", nil))
	waitFor(t, "poll rounds served", func() bool { return srv.count("getUpdates") >= 2 })
	time.Sleep(200 * time.Millisecond)
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	if got := len(tb.handler.recorded()); got != 0 {
		t.Errorf("handler calls = %d; want 0", got)
	}
}
