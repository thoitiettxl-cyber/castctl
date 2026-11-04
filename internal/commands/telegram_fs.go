// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-telegram/bot/models"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/fsclient"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
)

// The /fs command: browse System Files from the gateway (Python
// cmd_fs, tgbot.py:2085-2152, plus cb_fs_rm at :2154-2156).
// Behaviour mirrors Python 0.6.1; every deliberate deviation is
// noted at the handler and in the PR body. The handler returns
// gateway errors upward: dispatch maps AuthError to the
// login-expired sentence and anything else to the generic
// gateway line, so no handler here sends its own auth/generic
// reply — except fsRm, which (like ideaExec) sends its own
// login-expired reply for an AuthError and returns (true, nil),
// because a callback error otherwise surfaces only as
// onCallback's summarised warning.
//
// This is a WRITE/DELETE surface: /fs mkdir and /fs mv write,
// /fs rm deletes (only after the confirm button). The PR body
// states that plainly.
//
// [DEVIATION] traversal: upstream fs.norm's ".." raise is dead
// code — normpath on a rooted path never yields a ".."
// component, so "../etc" silently collapses to "etc". This
// port rejects any pre-collapse ".." component with a fixed
// input error instead, to catch typos without losing
// functionality (upstream containment holds either way, by
// construction). /fs find arguments are never path-checked,
// as upstream: search() never norms.

// fsUsage is Python's usage line verbatim (tgbot.py:2087-2088),
// including the literal &lt;/&gt; entities: it is sent as HTML.
const fsUsage = "Usage: /fs ls [path] · tree [path] [depth] · cat|get|stat &lt;path&gt; · find &lt;name&gt; · mkdir &lt;path&gt; · mv &lt;src&gt; &lt;dst&gt; [-f] · rm [-r] &lt;path&gt;"

// fsTraversalRejected is the fixed input-class sentence for a
// ".." component in a path argument. It never echoes the input.
const fsTraversalRejected = "⚠️ path traversal not allowed"

// errFSTraversal is the sentinel fsNorm returns for a ".."
// component; the handler maps it to fsTraversalRejected.
var errFSTraversal = errors.New("path traversal not allowed")

// fsCatCap is the read cap for /fs cat (Python read_file's
// max_bytes=5MiB).
const fsCatCap = 5 << 20

// fsHasTraversal reports whether raw carries a ".." path
// component, checked BEFORE normpath collapses it. The
// preprocessing mirrors fsclient.Norm's: trim, backslashes to
// slashes, one leading sandbox:// stripped. Names like
// "..hidden" or "..." are not components and pass.
func fsHasTraversal(raw string) bool {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, "\\", "/")
	s = strings.TrimPrefix(s, "sandbox://")
	for _, part := range strings.Split(s, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// fsNorm rejects a traversal component, then normalizes with
// the exported fsclient.Norm. find never calls this: its
// argument is a name fragment, not a path.
func fsNorm(raw string) (string, error) {
	if fsHasTraversal(raw) {
		return "", errFSTraversal
	}
	return fsclient.Norm(raw)
}

// fsNormOrInputError normalizes raw for the handler: a
// traversal rejection is an input error the handler sends
// itself; a Norm error (unreachable in practice) propagates
// upward to dispatch's generic line.
func (h *telegramCmdHandler) fsNormOrInputError(ctx context.Context, chatID int64, raw string) (string, bool, error) {
	norm, err := fsNorm(raw)
	if errors.Is(err, errFSTraversal) {
		_, sendErr := h.bot.Send(ctx, chatID, fsTraversalRejected, telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return "", false, sendErr
	}
	if err != nil {
		return "", false, err
	}
	return norm, true, nil
}

// fsUsageReply sends the usage sentence and reports success:
// usage/parse/traversal failures are input errors, never
// gateway errors, so dispatch must not see them.
func (h *telegramCmdHandler) fsUsageReply(ctx context.Context, chatID int64) error {
	_, err := h.bot.Send(ctx, chatID, fsUsage, telegram.SendOptions{})
	return err
}

// replyLong ports reply_long (tgbot.py:928-936): text longer
// than telegram.ChunkSize (3800, counted in runes) arrives as
// ONE document named stem (".txt" appended when the stem has
// no dot) captioned "{name} ({n} chars)" with n the rune
// count; shorter text with pre arrives as one <pre> send;
// shorter text without pre arrives as a plain send. The name
// is NOT routed through DocName: upstream yields ".txt"
// stems, and DocName may yield ".md".
func (h *telegramCmdHandler) replyLong(ctx context.Context, chatID int64, text, stem string, pre bool) error {
	name := stem
	if !strings.Contains(name, ".") {
		name += ".txt"
	}
	if n := len([]rune(text)); n > telegram.ChunkSize {
		_, err := h.bot.SendFile(ctx, chatID, name, []byte(text), "", fmt.Sprintf("%s (%d chars)", name, n), telegram.SendOptions{})
		return err
	}
	if pre {
		_, err := h.bot.Send(ctx, chatID, "<pre>"+telegram.EscapeText(text)+"</pre>", telegram.SendOptions{})
		return err
	}
	_, err := h.bot.Send(ctx, chatID, text, telegram.SendOptions{Mode: telegram.HTMLModePlain})
	return err
}

// fs serves /fs (Python cmd_fs). The arg is dispatch's stripped
// remainder, split with the exported POSIX splitter; the op is
// lowercased, paths are not. Flags are every token starting
// with "-", from anywhere in the rest; positionals keep their
// order. Input errors (parse, usage, traversal) are sent by
// the handler and return nil; gateway errors return upward.
func (h *telegramCmdHandler) fs(ctx context.Context, chatID int64, arg string) error {
	parts, err := fsclient.SplitEditorCommand(arg)
	if err != nil {
		_, sendErr := h.bot.Send(ctx, chatID, "⚠️ "+err.Error(), telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return sendErr
	}
	if len(parts) == 0 {
		return h.fsUsageReply(ctx, chatID)
	}
	op := strings.ToLower(parts[0])
	rest := parts[1:]
	flags := map[string]bool{}
	var positionals []string
	for _, tok := range rest {
		if strings.HasPrefix(tok, "-") {
			flags[tok] = true
		} else {
			positionals = append(positionals, tok)
		}
	}
	path := ""
	if len(positionals) > 0 {
		path = positionals[0]
	}

	// find takes a name fragment: no norm, no traversal check.
	if op == "find" {
		if path == "" {
			return h.fsUsageReply(ctx, chatID)
		}
		return h.fsWithGateway(ctx, func(f *fsclient.FS) error {
			ents, err := f.Search(ctx, path, 50)
			if err != nil {
				return err
			}
			var lines []string
			for _, e := range ents {
				lines = append(lines, fsSearchLine(e))
			}
			text := strings.Join(lines, "\n")
			if text == "" {
				text = "nothing found"
			}
			return h.replyLong(ctx, chatID, text, "find.txt", true)
		})
	}

	switch op {
	case "ls", "tree", "stat", "cat", "get", "mkdir", "mv", "rm":
	default:
		return h.fsUsageReply(ctx, chatID)
	}

	// Arity, checked before any gateway call: ls/tree take an
	// optional path; stat/cat/get/mkdir/rm need exactly one
	// positional; mv needs exactly two.
	switch op {
	case "stat", "cat", "get", "mkdir", "rm":
		if len(positionals) != 1 {
			return h.fsUsageReply(ctx, chatID)
		}
	case "mv":
		if len(positionals) != 2 {
			return h.fsUsageReply(ctx, chatID)
		}
	}

	// Traversal + normalization, before the gateway call. mv
	// checks both paths.
	norm, ok, err := h.fsNormOrInputError(ctx, chatID, path)
	if err != nil || !ok {
		return err
	}
	normDst := ""
	if op == "mv" {
		normDst, ok, err = h.fsNormOrInputError(ctx, chatID, positionals[1])
		if err != nil || !ok {
			return err
		}
	}

	switch op {
	case "ls":
		showAll := flags["-a"]
		return h.fsWithGateway(ctx, func(f *fsclient.FS) error {
			ents, err := f.ListDir(ctx, norm)
			if err != nil {
				return err
			}
			var lines []string
			for _, e := range ents {
				if !showAll && strings.HasPrefix(e.Name, ".") {
					continue
				}
				if e.Type == "directory" {
					lines = append(lines, "📁 "+e.Name)
				} else {
					lines = append(lines, "📄 "+e.Name+"  "+fsclient.FmtSize(e.Size))
				}
			}
			text := "/" + norm + "\n" + strings.Join(lines, "\n")
			if len(lines) == 0 {
				text = "/" + norm + "\n(empty)"
			}
			return h.replyLong(ctx, chatID, text, "ls.txt", true)
		})
	case "tree":
		depth := 2
		if len(positionals) > 1 && isAllDigits(positionals[1]) {
			if v, err := parseTreeDepth(positionals[1]); err == nil {
				depth = v
			}
		}
		if depth < 0 {
			depth = 0
		}
		return h.fsWithGateway(ctx, func(f *fsclient.FS) error {
			rows, err := f.Walk(ctx, norm, depth)
			if err != nil {
				return err
			}
			var lines []string
			for _, row := range rows {
				if fsHasDotComponent(row.Rel) {
					continue
				}
				line := strings.Repeat("  ", row.Level+1) + row.Entry.Name
				if row.Entry.Type == "directory" {
					line += "/"
				}
				lines = append(lines, line)
			}
			return h.replyLong(ctx, chatID, "/"+norm+"\n"+strings.Join(lines, "\n"), "tree.txt", true)
		})
	case "stat":
		return h.fsWithGateway(ctx, func(f *fsclient.FS) error {
			st, err := f.Stat(ctx, norm)
			if err != nil {
				return err
			}
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", " ")
			if err := enc.Encode(st); err != nil {
				return err
			}
			return h.replyLong(ctx, chatID, strings.TrimRight(buf.String(), "\n"), "output", true)
		})
	case "cat":
		return h.fsWithGateway(ctx, func(f *fsclient.FS) error {
			cap := int64(fsCatCap)
			data, err := f.ReadFile(ctx, norm, &cap)
			if err != nil {
				return err
			}
			name := fsBaseName(norm)
			if bytes.IndexByte(firstBytes(data, 8192), 0) >= 0 {
				_, err := h.bot.SendFile(ctx, chatID, name, data, "", "/"+norm+" (binary)", telegram.SendOptions{})
				return err
			}
			text := strings.ToValidUTF8(string(data), "�")
			if len([]rune(text)) > telegram.ChunkSize {
				_, err := h.bot.SendFile(ctx, chatID, name, data, "", "/"+norm, telegram.SendOptions{})
				return err
			}
			body := telegram.EscapeText(text)
			if body == "" {
				body = "(empty)"
			}
			_, err = h.bot.Send(ctx, chatID, "<b>/"+telegram.EscapeText(norm)+"</b>\n<pre>"+body+"</pre>", telegram.SendOptions{})
			return err
		})
	case "get":
		return h.fsWithGateway(ctx, func(f *fsclient.FS) error {
			st, err := f.Stat(ctx, norm)
			if err != nil {
				return err
			}
			if kind, _ := st["kind"].(string); kind == "dir" || kind == "directory" {
				_, err := h.bot.Send(ctx, chatID, "That is a folder; /fs ls it and get the files one by one.", telegram.SendOptions{Mode: telegram.HTMLModePlain})
				return err
			}
			data, err := f.ReadFile(ctx, norm, nil)
			if err != nil {
				return err
			}
			if len(data) > telegram.UploadLimit {
				_, err := h.bot.Send(ctx, chatID, "Too big for Telegram (50 MB).", telegram.SendOptions{Mode: telegram.HTMLModePlain})
				return err
			}
			_, err = h.bot.SendFile(ctx, chatID, fsBaseName(norm), data, "", "/"+norm, telegram.SendOptions{})
			return err
		})
	case "mkdir":
		return h.fsWithGateway(ctx, func(f *fsclient.FS) error {
			if _, err := f.Mkdir(ctx, norm, true); err != nil {
				return err
			}
			_, err := h.bot.Send(ctx, chatID, "📁 Created <code>/"+telegram.EscapeText(norm)+"</code>", telegram.SendOptions{})
			return err
		})
	case "mv":
		overwrite := flags["-f"]
		return h.fsWithGateway(ctx, func(f *fsclient.FS) error {
			if _, err := f.Move(ctx, norm, normDst, overwrite, true); err != nil {
				return err
			}
			_, err := h.bot.Send(ctx, chatID, "Moved <code>/"+telegram.EscapeText(norm)+"</code> → <code>/"+telegram.EscapeText(normDst)+"</code>", telegram.SendOptions{})
			return err
		})
	case "rm":
		recursive := flags["-r"] || flags["-rf"] || flags["-R"] || flags["-fr"]
		what := ""
		if recursive {
			what = " and everything in it"
		}
		markup := models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{{
			{Text: "🗑 Yes, delete", CallbackData: h.bot.Registry().Register(telegram.CallbackEntry{Action: "fs_rm", FSPath: norm, FSRecursive: recursive})},
			{Text: "Cancel", CallbackData: h.bot.Registry().Register(telegram.CallbackEntry{Action: "noop"})},
		}}}
		_, err := h.bot.Send(ctx, chatID, "Delete <code>/"+telegram.EscapeText(norm)+"</code>"+what+"?", telegram.SendOptions{Markup: markup})
		return err
	}
	return h.fsUsageReply(ctx, chatID)
}

// fsWithGateway runs fn with an FS over the profile's gateway,
// mirroring the CLI runFS shape (fs.go:188-195).
func (h *telegramCmdHandler) fsWithGateway(ctx context.Context, fn func(*fsclient.FS) error) error {
	return h.rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
		return fn(fsclient.New(gw))
	})
}

// fsRm serves one Yes-delete tap (Python cb_fs_rm,
// tgbot.py:2154-2156): delete the registry-carried path, then
// edit the prompt message. The registry entry is never
// consumed, so a re-tap re-deletes. An AuthError gets the own
// login-expired reply (ideaExec precedent) and (true, nil);
// any other error returns to onCallback's summarised warning.
// The Edit passes nil markup: the Bot API call omits
// reply_markup (models field is omitempty), so the Yes/Cancel
// buttons STAY attached to the edited message, as upstream
// (where tgapi.call drops None params). Only ClearMarkup
// removes a keyboard.
func (h *telegramCmdHandler) fsRm(ctx context.Context, chatID int64, messageID int, entry telegram.CallbackEntry) (bool, error) {
	err := h.fsWithGateway(ctx, func(f *fsclient.FS) error {
		_, err := f.Delete(ctx, entry.FSPath, entry.FSRecursive)
		return err
	})
	if err != nil {
		var authErr *conn.AuthError
		if errors.As(err, &authErr) {
			h.logger.Warn("telegram fs delete failed (auth)", "err", logging.SummarizeErr(err))
			_, sendErr := h.bot.Send(ctx, chatID, "🔑 muse.ai login expired. Use /login.", telegram.SendOptions{Mode: telegram.HTMLModePlain})
			return true, sendErr
		}
		return true, err
	}
	if messageID != 0 {
		return true, h.bot.Edit(ctx, chatID, messageID, "🗑 Deleted /"+entry.FSPath, nil, telegram.HTMLModePlain)
	}
	return true, nil
}

// parseTreeDepth converts an ASCII-digits-only depth token.
// Overflow resolves to the default, like a non-digit token.
func parseTreeDepth(s string) (int, error) {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
		if n > 1<<30 {
			return 0, errors.New("tree depth overflows")
		}
	}
	return n, nil
}

// fsHasDotComponent reports whether any component of the
// slash-separated relpath starts with ".". The relpath
// includes the requested root, so a dot component in the root
// itself hides every row, as upstream.
func fsHasDotComponent(rel string) bool {
	for _, part := range strings.Split(rel, "/") {
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

// fsBaseName is posixpath.basename(norm): "" becomes "file".
func fsBaseName(norm string) string {
	if i := strings.LastIndex(norm, "/"); i >= 0 {
		norm = norm[i+1:]
	}
	if norm == "" {
		return "file"
	}
	return norm
}

// fsSearchLine renders one search hit: the "path" field, else
// the "name", else the JSON dump of the entry (Python
// e.get("path") or e.get("name") or json.dumps(e)).
func fsSearchLine(e fsclient.Entry) string {
	if p, ok := e.Extra["path"].(string); ok && p != "" {
		return p
	}
	if e.Name != "" {
		return e.Name
	}
	b, err := json.Marshal(e)
	if err != nil {
		return e.Name
	}
	return string(b)
}

// firstBytes returns at most the first n bytes of data.
func firstBytes(data []byte, n int) []byte {
	if len(data) > n {
		return data[:n]
	}
	return data
}
