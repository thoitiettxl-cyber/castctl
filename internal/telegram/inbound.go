// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// Inbound user media, mirrored from Python 0.6.1
// (src/muse_cli/tgbot.py, media_of / upload_and_send;
// src/muse_cli/tgapi.py, download). A photo or file a user
// sends to the bot is downloaded through getFile plus the
// file URL and written to System Files under telegram-inbox/;
// the chat gets a silent Saved line and Muse gets a turn.
// Deliberate deviations are marked [DEVIATION].

// DownloadLimit is the largest file the bot fetches from a
// user: DOWNLOAD_LIMIT = 20 MiB (src/muse_cli/tgapi.py:20,
// "bots may fetch up to 20 MB"). The gate runs on getFile's
// reported size before downloading, and again on the
// downloaded length (the second gate is a castctl addition:
// upstream gates on getFile's size only).
const DownloadLimit = 20 << 20

// ErrDownloadTooLarge reports a file over DownloadLimit, from
// either size gate. Callers map it to the fixed refusal
// sentence; it carries no size, path, or URL.
var ErrDownloadTooLarge = errors.New("telegram: file exceeds the 20 MiB fetch limit")

// Media is one user-sent file carried by a message: the
// file_id to fetch, the display name, the MIME type (empty
// when the server did not report one), and the declared size
// in bytes (0 means unknown: the value types cannot express
// "absent" distinctly from a declared 0).
type Media struct {
	FileID string
	Name   string
	MIME   string
	Size   int64
}

// MediaOf ports media_of (src/muse_cli/tgbot.py:1762-1775):
// a photo takes the LAST size in the array (name
// photo-<message_id>.jpg, mime image/jpeg); other kinds are
// tried in the order document, video, audio, voice,
// video_note, animation, named file_name or
// <kind>-<message_id><ext> (voice .ogg, video and video_note
// .mp4, audio .mp3, animation .mp4; document takes no
// extension). A nil message, a message with no media, and a
// sticker all yield nil (upstream returns nil for stickers:
// they are not in media_of's order).
func MediaOf(msg *models.Message) *Media {
	if msg == nil {
		return nil
	}
	if len(msg.Photo) > 0 {
		last := msg.Photo[len(msg.Photo)-1]
		return &Media{
			FileID: last.FileID,
			Name:   fmt.Sprintf("photo-%d.jpg", msg.ID),
			MIME:   "image/jpeg",
			Size:   int64(last.FileSize),
		}
	}
	type kind struct {
		key  string
		file func() (fileID, fileName, mime string, size int64, ok bool)
	}
	kinds := []kind{
		{"document", func() (string, string, string, int64, bool) {
			if msg.Document == nil {
				return "", "", "", 0, false
			}
			return msg.Document.FileID, msg.Document.FileName, msg.Document.MimeType, msg.Document.FileSize, true
		}},
		{"video", func() (string, string, string, int64, bool) {
			if msg.Video == nil {
				return "", "", "", 0, false
			}
			return msg.Video.FileID, msg.Video.FileName, msg.Video.MimeType, msg.Video.FileSize, true
		}},
		{"audio", func() (string, string, string, int64, bool) {
			if msg.Audio == nil {
				return "", "", "", 0, false
			}
			return msg.Audio.FileID, msg.Audio.FileName, msg.Audio.MimeType, msg.Audio.FileSize, true
		}},
		{"voice", func() (string, string, string, int64, bool) {
			if msg.Voice == nil {
				return "", "", "", 0, false
			}
			return msg.Voice.FileID, "", msg.Voice.MimeType, msg.Voice.FileSize, true
		}},
		{"video_note", func() (string, string, string, int64, bool) {
			if msg.VideoNote == nil {
				return "", "", "", 0, false
			}
			return msg.VideoNote.FileID, "", "", int64(msg.VideoNote.FileSize), true
		}},
		{"animation", func() (string, string, string, int64, bool) {
			if msg.Animation == nil {
				return "", "", "", 0, false
			}
			return msg.Animation.FileID, msg.Animation.FileName, msg.Animation.MimeType, msg.Animation.FileSize, true
		}},
	}
	exts := map[string]string{
		"voice": ".ogg", "video": ".mp4", "video_note": ".mp4",
		"audio": ".mp3", "animation": ".mp4",
	}
	for _, k := range kinds {
		fileID, fileName, mime, size, ok := k.file()
		if !ok {
			continue
		}
		name := fileName
		if name == "" {
			name = fmt.Sprintf("%s-%d%s", k.key, msg.ID, exts[k.key])
		}
		return &Media{FileID: fileID, Name: name, MIME: mime, Size: size}
	}
	return nil
}

var inboxSanitize = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// InboxName builds the telegram-inbox file name for a
// user-sent file (src/muse_cli/tgbot.py:1782-1783): runs of
// characters outside [A-Za-z0-9._-] collapse to one
// underscore, leading/trailing "." and "_" are stripped, an
// empty result becomes "file", and the name is prefixed with
// the local timestamp <YYYYmmdd-HHMMSS>-. at is the upload
// time, in local time.
func InboxName(name string, at time.Time) string {
	safe := inboxSanitize.ReplaceAllString(name, "_")
	safe = strings.Trim(safe, "._")
	if safe == "" {
		safe = "file"
	}
	return at.Format("20060102-150405") + "-" + safe
}

// DownloadMedia fetches the bytes of a user-sent file: getFile
// through the poll instance, then a GET of the file URL
// through the stored 120s upload client (the same validated
// transport as the upload instance; never http.DefaultClient,
// never a re-derived client). Gate 1 refuses when getFile's
// reported size exceeds DownloadLimit, before any download
// (upstream tgapi.py:143-144). An empty file_path is a fetch
// failure. Gate 2 [DEVIATION: upstream has no post-download
// gate] reads through a LimitReader at cap+1 and refuses when
// more than DownloadLimit bytes arrive, so an unknown or
// understated size cannot fill memory unbounded. The
// download URL contains the token: it is never logged, never
// interpolated into an error, and never stored; every error
// leaving here is a scrubbed copy (see scrubErr), so no
// token-bearing URL or server body can reach a log line or a
// chat message. A non-200 file response is a scrubbed fetch
// failure carrying only the status code.
func (b *Bot) DownloadMedia(ctx context.Context, m *Media) ([]byte, error) {
	if m == nil || m.FileID == "" {
		return nil, errors.New("telegram: no file to download")
	}
	file, err := b.api.GetFile(ctx, &bot.GetFileParams{FileID: m.FileID})
	if err != nil {
		return nil, b.scrubErr(err)
	}
	if file == nil {
		return nil, errors.New("telegram: getFile returned no file")
	}
	if file.FileSize > DownloadLimit {
		return nil, ErrDownloadTooLarge
	}
	if file.FilePath == "" {
		return nil, errors.New("telegram: getFile returned no file path")
	}
	client := b.downloadClient
	if client == nil {
		return nil, errors.New("telegram: no download client (bot was not built by New)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.uploadAPI.FileDownloadLink(file), nil)
	if err != nil {
		return nil, b.scrubErr(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, b.scrubErr(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("telegram: file download failed: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, DownloadLimit+1))
	if err != nil {
		return nil, b.scrubErr(err)
	}
	if int64(len(data)) > DownloadLimit {
		return nil, ErrDownloadTooLarge
	}
	return data, nil
}

// SummarizeError renders err for a chat message as a
// class/length summary only, never verbatim error text (the
// exported counterpart of summarizeError, for handlers that
// send their own failure replies, e.g. the inbound-media
// path). The output carries a fixed-vocabulary class label
// and a message length, and no fragment of the error text.
func (b *Bot) SummarizeError(err error) string {
	return b.summarizeError(err)
}
