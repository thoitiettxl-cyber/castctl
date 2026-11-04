// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// File sending, mirrored from Python 0.6.1 (src/muse_cli/tgapi.py,
// send_file / file_kind / doc_name; src/muse_cli/tgbot.py,
// send_doc). Every function below cites its Python source in its
// doc comment; deliberate deviations are marked [DEVIATION].
//
// RAM limitation, stated honestly: DownloadFile returns []byte
// and the library materialises the whole multipart body up
// front (rawRequest), so a file is held in memory twice over
// during an upload. There is no streaming path: callers refuse
// files over UploadLimit before downloading, and SendFile
// itself enforces no size limit (see below).

// UploadLimit is the largest file the bot sends: UPLOAD_LIMIT =
// 49 MiB (src/muse_cli/tgapi.py:19). Callers enforce it; SendFile
// does not (upstream send_file/send_doc enforce it in callers
// only, tgbot.py:810, 831, 2078, 2135).
const UploadLimit = 49 << 20

// PhotoLimit is the largest file sendPhoto accepts: PHOTO_LIMIT
// = 10 MiB (src/muse_cli/tgapi.py:21). A larger photo is sent
// as a document instead (file_kind).
const PhotoLimit = 10 << 20

// uploadClientTimeout bounds the upload HTTP client: Python
// posts files with a 120s timeout (src/muse_cli/tgapi.py:139,
// _post(method, 120, ...)). The poll client keeps ClientTimeout
// (40s); only the upload instance uses this value.
const uploadClientTimeout = 120 * time.Second

// FileKind is how Telegram should receive a file: the send*
// method that carries it.
type FileKind string

const (
	// FileKindDocument is sendDocument.
	FileKindDocument FileKind = "document"
	// FileKindPhoto is sendPhoto.
	FileKindPhoto FileKind = "photo"
	// FileKindVideo is sendVideo.
	FileKindVideo FileKind = "video"
	// FileKindAudio is sendAudio.
	FileKindAudio FileKind = "audio"
)

// FileKindFor reports how Telegram should receive a file named
// name with the given mime and size, ported from file_kind
// (src/muse_cli/tgapi.py:271-281): a photo when the mime is
// jpeg/png/webp (or, with no mime, the extension is
// jpg/jpeg/png/webp) and the size is unknown or at most
// PhotoLimit; a video when the mime starts with "video/" (or,
// with no mime, the extension is mp4/mov/m4v); audio when the
// mime starts with "audio/" (or, with no mime, the extension
// is mp3/m4a/ogg/oga/wav/flac); a document otherwise. A present
// mime disables the extension fallback for that kind, and only
// the photo branch has a size cap. Size < 0 means unknown
// (Python's size=None); size == 0 is a real empty file.
func FileKindFor(name, mime string, size int64) FileKind {
	ext := fileExtension(strings.ToLower(name))
	m := strings.ToLower(mime)
	if m == "image/jpeg" || m == "image/png" || m == "image/webp" ||
		(m == "" && (ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".webp")) {
		if size < 0 || size <= PhotoLimit {
			return FileKindPhoto
		}
		return FileKindDocument
	}
	if strings.HasPrefix(m, "video/") ||
		(m == "" && (ext == ".mp4" || ext == ".mov" || ext == ".m4v")) {
		return FileKindVideo
	}
	if strings.HasPrefix(m, "audio/") ||
		(m == "" && (ext == ".mp3" || ext == ".m4a" || ext == ".ogg" || ext == ".oga" || ext == ".wav" || ext == ".flac")) {
		return FileKindAudio
	}
	return FileKindDocument
}

// fileExtension returns the extension of name (the last dot of
// the final path element, including the dot), lowercased by the
// caller: Python's os.path.splitext semantics. A leading-dot
// name has no extension; a trailing dot yields ".".
func fileExtension(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	i := strings.LastIndexByte(name, '.')
	if i <= 0 {
		return ""
	}
	if strings.TrimLeft(name[:i], ".") == "" {
		return ""
	}
	return name[i:]
}

var docNameSanitizeRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
var docNameMarkdownRe = regexp.MustCompile(`(?m)^#{1,6} |\*\*`)

// DocName builds the attached-reply file name from stem and
// text, ported from doc_name (src/muse_cli/tgapi.py:266-269):
// ".md" when the text contains a fence or a heading/bold
// marker, else ".txt"; the stem is sanitised (runs of other
// characters become "-"), stripped of leading/trailing "-",
// and capped at 40 runes, in that order, before the extension
// is appended.
func DocName(stem, text string) string {
	ext := ".txt"
	if strings.Contains(text, "```") || docNameMarkdownRe.MatchString(text) {
		ext = ".md"
	}
	name := docNameSanitizeRe.ReplaceAllString(stem, "-")
	name = strings.Trim(name, "-")
	if r := []rune(name); len(r) > 40 {
		name = string(r[:40])
	}
	return name + ext
}

// SendFile sends data as a file to chatID, choosing the send*
// method by FileKindFor(name, mime, len(data)), ported from
// send_file (src/muse_cli/tgapi.py:132-139) and send_doc
// (src/muse_cli/tgbot.py:760-770). The caption is truncated to
// CaptionLimit runes and sent plain (no parse_mode: upstream
// file captions carry none); opts.Markup is attached, opts.Silent
// sets disable_notification, and opts.ReplyTo sets
// reply_parameters when non-zero.
//
// [DEVIATION] opts.Mode is ignored: it has no upstream file
// equivalent, and running MDToHTML on a caption would change
// what Telegram shows. [DEVIATION] The mime only feeds kind
// selection: no send* params struct has a MIME field, and the
// library always writes the stdlib multipart default
// Content-Type for the part (Python sets it from the filename,
// tgapi.py:161-172) — unavoidable in this port, not an
// omission. [DEVIATION] The call goes through retryCall (429
// retries): upstream send_file does not retry, it posts once
// with the 120s timeout; the Go port retries like every other
// send path. [DEVIATION] The sendDocument fallback triggers
// ONLY on errors.Is(err, bot.ErrorBadRequest) when the kind is
// not document, exactly once: upstream retries on ANY
// TelegramError, which would also fall back after transport
// failures and exhausted 429 retries, and would depend on the
// never-observed "wrong file type" description wording. A
// document-kind failure is never retried as a document, and a
// failed fallback returns the fallback error.
//
// SendFile enforces no size limit: callers refuse oversize
// files before downloading (UploadLimit). It returns the sent
// message id, or a scrubbed error on every failure path.
func (b *Bot) SendFile(ctx context.Context, chatID int64, name string, data []byte, mime, caption string, opts SendOptions) (int, error) {
	kind := FileKindFor(name, mime, int64(len(data)))
	caption = truncateToRunes(caption, CaptionLimit)
	msg, err := b.sendFileKind(ctx, chatID, name, data, kind, caption, opts)
	if err == nil {
		return messageIDOf(msg), nil
	}
	if kind != FileKindDocument && errors.Is(err, bot.ErrorBadRequest) {
		msg, err = b.sendFileKind(ctx, chatID, name, data, FileKindDocument, caption, opts)
		if err == nil {
			return messageIDOf(msg), nil
		}
		return 0, b.scrubErr(err)
	}
	return 0, b.scrubErr(err)
}

// sendFileKind sends one file with one send* method through
// retryCall, returning the RAW error (the caller scrubs). A
// fresh InputFileUpload is built inside every retryCall
// attempt: the library consumes the reader when it builds the
// multipart body, so reusing one upload value across attempts
// would upload an empty part on the second attempt.
func (b *Bot) sendFileKind(ctx context.Context, chatID int64, name string, data []byte, kind FileKind, caption string, opts SendOptions) (*models.Message, error) {
	var call func(file *models.InputFileUpload) (*models.Message, error)
	var method string
	replyParams := func() *models.ReplyParameters {
		if opts.ReplyTo == 0 {
			return nil
		}
		return &models.ReplyParameters{MessageID: opts.ReplyTo}
	}
	switch kind {
	case FileKindPhoto:
		method = "sendPhoto"
		call = func(file *models.InputFileUpload) (*models.Message, error) {
			return b.uploadAPI.SendPhoto(ctx, &bot.SendPhotoParams{
				ChatID:              chatID,
				Photo:               file,
				Caption:             caption,
				ReplyParameters:     replyParams(),
				ReplyMarkup:         opts.Markup,
				DisableNotification: opts.Silent,
			})
		}
	case FileKindVideo:
		method = "sendVideo"
		call = func(file *models.InputFileUpload) (*models.Message, error) {
			return b.uploadAPI.SendVideo(ctx, &bot.SendVideoParams{
				ChatID:              chatID,
				Video:               file,
				Caption:             caption,
				ReplyParameters:     replyParams(),
				ReplyMarkup:         opts.Markup,
				DisableNotification: opts.Silent,
			})
		}
	case FileKindAudio:
		method = "sendAudio"
		call = func(file *models.InputFileUpload) (*models.Message, error) {
			return b.uploadAPI.SendAudio(ctx, &bot.SendAudioParams{
				ChatID:              chatID,
				Audio:               file,
				Caption:             caption,
				ReplyParameters:     replyParams(),
				ReplyMarkup:         opts.Markup,
				DisableNotification: opts.Silent,
			})
		}
	default:
		method = "sendDocument"
		call = func(file *models.InputFileUpload) (*models.Message, error) {
			return b.uploadAPI.SendDocument(ctx, &bot.SendDocumentParams{
				ChatID:              chatID,
				Document:            file,
				Caption:             caption,
				ReplyParameters:     replyParams(),
				ReplyMarkup:         opts.Markup,
				DisableNotification: opts.Silent,
			})
		}
	}
	var msg *models.Message
	err := b.retryCall(ctx, func() error {
		var err error
		msg, err = call(&models.InputFileUpload{Filename: name, Data: bytes.NewReader(data)})
		return err
	})
	if err != nil {
		return nil, err
	}
	if msg == nil {
		return nil, fmt.Errorf("telegram: %s returned no message", method)
	}
	return msg, nil
}
