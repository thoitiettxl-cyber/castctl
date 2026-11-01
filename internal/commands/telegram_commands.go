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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-telegram/bot/models"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/deliver"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/shared"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
	"github.com/thoitiettxl-cyber/castctl/internal/wait"
)

// The step-5 command surface: dispatch, the core conversation
// commands, and the callback-button actions. Behaviour mirrors
// Python 0.6.1's tgbot.py command handlers (surveyed,
// reimplemented); every deliberate deviation is noted at the
// handler and in the PR body.
//
// Command errors use fixed templates: a handler that already
// replied returns nil; any other error reaches the dispatch
// wrapper, which logs it summarised and sends one fixed line
// (login-expired for auth errors, a generic gateway line
// otherwise). No error text, and therefore no server body,
// ever reaches a chat message.

// telegramBotHelpText is Python's HELP verbatim
// (src/muse_cli/tgbot.py:98-117). It advertises commands PR-B
// has not wired yet; tapping one gets the deferred reply from
// dispatch, which says so plainly.
const telegramBotHelpText = `<b>Muse on Telegram</b>
Type anything to talk to Muse in the current conversation. Send a photo or file to put it in Muse's System Files (<code>telegram-inbox/</code>) and tell Muse about it.

<b>Conversation</b>
/chats open another chat · /main · /new [title]
/history [N] · /unread · /stop
/rename &lt;title&gt; · /pin · /unpin · /archive · /unarchive · /delete

<b>Muse</b>
/status · /approvals · /autoapprove on|off · /watch on|off
/files · /feed · /goals · /goal &lt;id&gt; · /ideas · /usage · /wake

<b>System Files</b>
/fs ls [path] · /fs tree [path] [depth] · /fs cat &lt;path&gt; · /fs get &lt;path&gt;
/fs find &lt;name&gt; · /fs stat &lt;path&gt; · /fs mkdir &lt;path&gt; · /fs mv &lt;src&gt; &lt;dst&gt; · /fs rm [-r] &lt;path&gt;

<b>Admin</b>
/profile · /login (new cookies) · /update · /raw &lt;method&gt; [json]`

// Commands wired in a later step (PR-B) reply with the
// deferred line instead of running; /login and /raw have no
// owner gate in this build and are not available at all.
var telegramDeferredCommands = map[string]bool{
	"files": true, "fs": true, "feed": true, "goals": true,
	"goal": true, "ideas": true, "usage": true, "wake": true,
	"profile": true, "update": true,
}

var commandNameRe = regexp.MustCompile(`^[a-z_]+$`)

// dispatch routes one message: "/name args" to the command
// table (Python on_message/run_command, tgbot.py:1013-1040),
// anything else with non-blank text to a turn. The name is the
// head before the first space, lowercased, with any @botname
// suffix stripped; the arg is the stripped remainder.
func (h *telegramCmdHandler) dispatch(ctx context.Context, mc telegram.MessageContext) error {
	text := mc.Text
	if !strings.HasPrefix(text, "/") {
		if strings.TrimSpace(text) == "" {
			return nil
		}
		h.runner.startTurn(ctx, mc.ChatID, text)
		return nil
	}
	head, rest, _ := strings.Cut(text, " ")
	name := strings.ToLower(strings.SplitN(head[1:], "@", 2)[0])
	arg := strings.TrimSpace(rest)
	err := h.runCommand(ctx, mc.ChatID, name, arg)
	if err == nil {
		return nil
	}
	var authErr *conn.AuthError
	if errors.As(err, &authErr) {
		h.logger.Warn("telegram command failed (auth)", "command", name, "err", logging.SummarizeErr(err))
		_, sendErr := h.bot.Send(ctx, mc.ChatID, "🔑 muse.ai login expired. Re-export cookies with `castctl auth export` and restart the bot.", telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return sendErr
	}
	h.logger.Warn("telegram command failed", "command", name, "err", logging.SummarizeErr(err))
	_, sendErr := h.bot.Send(ctx, mc.ChatID, "⚠️ Could not run /"+name+" (gateway error).", telegram.SendOptions{Mode: telegram.HTMLModePlain})
	return sendErr
}

func (h *telegramCmdHandler) runCommand(ctx context.Context, chatID int64, name, arg string) error {
	if !commandNameRe.MatchString(name) || name == "" {
		_, err := h.bot.Send(ctx, chatID, "Unknown command /"+telegram.EscapeText(name)+". /help lists them.", telegram.SendOptions{})
		return err
	}
	switch name {
	case "start":
		return h.start(ctx, chatID)
	case "help":
		return h.help(ctx, chatID)
	case "stop":
		return h.stop(ctx, chatID)
	case "status":
		return h.status(ctx, chatID)
	case "chats":
		return h.showChats(ctx, chatID, 0, 0)
	case "main":
		return h.main(ctx, chatID)
	case "new":
		return h.newChat(ctx, chatID, arg)
	case "history":
		return h.history(ctx, chatID, arg)
	case "unread":
		return h.unread(ctx, chatID)
	case "rename":
		return h.rename(ctx, chatID, arg)
	case "pin":
		return h.sessionOpCmd(ctx, chatID, deliver.SessionOpPin, "📌 Pinned.")
	case "unpin":
		return h.sessionOpCmd(ctx, chatID, deliver.SessionOpUnpin, "Unpinned.")
	case "archive":
		return h.archive(ctx, chatID)
	case "unarchive":
		return h.sessionOpCmd(ctx, chatID, deliver.SessionOpUnarchive, "📤 Unarchived.")
	case "delete":
		return h.deletePrompt(ctx, chatID)
	case "approvals":
		return h.approvals(ctx, chatID)
	case "autoapprove":
		return h.autoApprove(ctx, chatID, arg)
	case "watch":
		return h.watch(ctx, chatID, arg)
	case "login", "raw":
		_, err := h.bot.Send(ctx, chatID, "⚠️ /"+name+" is not available in this build.", telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return err
	default:
		if telegramDeferredCommands[name] {
			_, err := h.bot.Send(ctx, chatID, "⚠️ /"+name+" is not wired in this build yet (step 5b).", telegram.SendOptions{Mode: telegram.HTMLModePlain})
			return err
		}
		_, err := h.bot.Send(ctx, chatID, "Unknown command /"+name+". /help lists them.", telegram.SendOptions{})
		return err
	}
}

func (h *telegramCmdHandler) start(ctx context.Context, chatID int64) error {
	_, err := h.bot.Send(ctx, chatID, "👋 Connected to Muse (profile <code>"+telegram.EscapeText(h.prof.Name)+"</code>). Type a message to talk to Muse; /help lists commands.", telegram.SendOptions{})
	return err
}

func (h *telegramCmdHandler) help(ctx context.Context, chatID int64) error {
	_, err := h.bot.Send(ctx, chatID, telegramBotHelpText, telegram.SendOptions{})
	return err
}

// stop cancels the chat's active turn and asks the server to
// cancel it (Python cmd_stop, tgbot.py:1809-1834). The queued
// count is NOT reported in PR-A: the dispatcher has no
// per-chat drop API, and queued updates are not dropped (see
// the PR body). A turn that already ended still gets the
// server-side cancel, exactly as in Python.
func (h *telegramCmdHandler) stop(ctx context.Context, chatID int64) error {
	cancelled, err := h.runner.stopTurn(ctx, chatID)
	if err != nil {
		return err
	}
	text := "⏹ Stop sent; Muse reported nothing running."
	if cancelled {
		text = "⏹ Stopped Muse's turn."
	}
	_, err = h.bot.Send(ctx, chatID, text, telegram.SendOptions{Mode: telegram.HTMLModePlain})
	return err
}

// status renders the /status report (Python cmd_status,
// tgbot.py:1836-1864) from sessions.list + chat.unread_count +
// identity, the task-state probe, and the live turn (this chat
// only). The last line names castctl, not muse-cli: the binary
// reporting is castctl. The server line degrades to
// "unknown (<summary>)" on probe failure instead of failing
// the whole report, as in Python; the summary is the
// class/length form, never error text.
func (h *telegramCmdHandler) status(ctx context.Context, chatID int64) error {
	vmID, err := statusVMID(ctx, h.rt)
	if err != nil {
		return err
	}
	sessions, err := callMap(ctx, h.rt, "sessions.list", conn.RequestOptions{})
	if err != nil {
		return err
	}
	unread, err := callJSON(ctx, h.rt, "chat.unread_count", conn.RequestOptions{})
	if err != nil {
		return err
	}
	identity, err := callJSON(ctx, h.rt, "identity", conn.RequestOptions{})
	if err != nil {
		return err
	}
	summary := shared.SummarizeStatus(vmID, sessions, unread, identity)
	ident, _ := identity.(map[string]any)
	name := firstNonEmptyString(ident["name"], ident["display_name"], ident["assistant_name"])
	mapping, _ := h.store.Chat(chatID)
	scope := mapping.SessionID
	title := mapping.Title
	if title == "" {
		title = "main chat"
	}
	here := telegram.EscapeText(title)
	if scope != "" {
		here += " (<code>" + telegram.EscapeText(scope) + "</code>)"
	}
	now := "idle (no turn from this chat)"
	if preview, ok := h.runner.liveTurn(chatID); ok {
		now = telegram.EscapeText(preview.statusLine()) + " · " + formatElapsedSecs(time.Since(preview.startedAt()))
	}
	server, err := telegramTaskState(ctx, h.rt, scope)
	if err != nil {
		server = "unknown (" + logging.SummarizeErr(err) + ")"
	}
	approveOn, allowOnce := h.toggles()
	_, _, watchOn := h.store.Toggles()
	watch := false
	if watchOn != nil {
		watch = *watchOn
	}
	lines := []string{
		"<b>Muse</b>" + condSuffix(name != "", " · "+telegram.EscapeText(name)),
		"VM: <code>" + telegram.EscapeText(summary.VMID) + "</code> · chats: " + strconv.Itoa(summary.Sessions),
		"Unread: <code>" + telegram.EscapeText(marshalTruncated(summary.Unread, 200)) + "</code>",
		"Here: " + here,
		"Now: " + now,
		"Muse task here (server): <code>" + telegram.EscapeText(server) + "</code>",
		"Profile: <code>" + telegram.EscapeText(h.prof.Name) + "</code> · auto-approve: " + condSuffix(approveOn, "on (always)", "off") + " · allow-once fallback: " + onOff(allowOnce) + " · watch: " + onOff(watch),
		"castctl " + telegram.EscapeText(Version),
	}
	if tagline := firstNonEmptyString(ident["tagline"], ident["vibe"]); tagline != "" {
		lines = append(lines[:1], append([]string{"<i>" + telegram.EscapeText(truncateRunes(tagline, 300)) + "</i>"}, lines[1:]...)...)
	}
	_, err = h.bot.Send(ctx, chatID, strings.Join(lines, "\n"), telegram.SendOptions{})
	return err
}

func condSuffix(cond bool, s string, rest ...string) string {
	if cond {
		return s
	}
	if len(rest) > 0 {
		return rest[0]
	}
	return ""
}

func firstNonEmptyString(vs ...any) string {
	for _, v := range vs {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func marshalTruncated(v any, n int) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return truncateRunes(string(b), n)
}

// telegramTaskState returns the first scoped task.status the
// server replays on chat.subscribe (Python cli.task_state,
// timeout 6s), or "unknown" when none arrives. The probe is
// bounded and fake-testable through the same fake gateway the
// turn tests use.
func telegramTaskState(ctx context.Context, rt *Runtime, thread string) (string, error) {
	var status string
	found := false
	err := rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
		body := map[string]any{"capabilities": []any{"chat_cancel", "delta_stream"}}
		if thread != "" {
			body["session_id"] = thread
		}
		probeCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		_, err := gw.SubscribeRaw(probeCtx, "chat.subscribe", conn.SubscribeOptions{
			Body:           body,
			MaxRecords:     50,
			IdleTimeout:    6 * time.Second,
			OverallTimeout: 6 * time.Second,
			OnRecord: func(record []byte) bool {
				dec := json.NewDecoder(bytes.NewReader(record))
				dec.UseNumber()
				var v any
				if err := dec.Decode(&v); err != nil {
					return false
				}
				ev, ok := v.(map[string]any)
				if !ok {
					return false
				}
				if info := wait.TaskStatusInfo(ev, thread); info != nil && info.HasStatus {
					status = info.Status
					found = true
					return true
				}
				return false
			},
		})
		return err
	})
	if err != nil {
		return "", err
	}
	if !found {
		return "unknown", nil
	}
	return status, nil
}

// chatSessionRow is one sessions.list row in the shape
// _sessions consumes (cli.session_rows, cli.py:734-746).
type chatSessionRow struct {
	sessionID string
	title     string
	isThread  bool
	pinned    bool
	archived  bool
	updatedMS int64
}

func listChatSessions(ctx context.Context, rt *Runtime) ([]chatSessionRow, error) {
	res, err := callMap(ctx, rt, "sessions.list", conn.RequestOptions{})
	if err != nil {
		return nil, err
	}
	list, _ := res["sessions"].([]any)
	var rows []chatSessionRow
	for _, raw := range list {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		rows = append(rows, chatSessionRow{
			sessionID: firstNonEmptyString(m["session_id"]),
			title:     firstNonEmptyString(m["title"]),
			isThread:  boolField(m["is_thread"]),
			pinned:    boolField(m["pinned"]),
			archived:  boolField(m["archived"]),
			updatedMS: intField(m["updated_at_ms"]),
		})
	}
	// Threads only, archived excluded, newest first, then a
	// stable pinned-first reorder (Python _sessions,
	// tgbot.py:1879-1884: sort by updated desc, then sort by
	// not-pinned — stable, so updated order survives within
	// each group).
	var threads []chatSessionRow
	for _, r := range rows {
		if r.isThread && !r.archived {
			threads = append(threads, r)
		}
	}
	sort.SliceStable(threads, func(i, j int) bool { return threads[i].updatedMS > threads[j].updatedMS })
	sort.SliceStable(threads, func(i, j int) bool { return threads[i].pinned && !threads[j].pinned })
	return threads, nil
}

func boolField(v any) bool {
	b, _ := v.(bool)
	return b
}

func intField(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case json.Number:
		n, _ := t.Int64()
		return n
	case float64:
		return int64(t)
	default:
		return 0
	}
}

const chatsPageSize = 8

// showChats renders the chat picker (Python show_chats,
// tgbot.py:1886-1906): the main-chat row first, up to 8 rows,
// a nav row when paging is possible, and the page line. A
// non-zero messageID edits that message instead of sending.
// The nav row is omitted when empty (Python appends an empty
// row; an empty keyboard row carries no buttons and Telegram
// rejects it — display-identical either way).
func (h *telegramCmdHandler) showChats(ctx context.Context, chatID int64, messageID int, page int) error {
	rows, err := listChatSessions(ctx, h.rt)
	if err != nil {
		return err
	}
	mapping, _ := h.store.Chat(chatID)
	cur := mapping.SessionID
	pages := max(1, (len(rows)+chatsPageSize-1)/chatsPageSize)
	page = max(0, min(page, pages-1))
	mainLabel := "💬 main chat"
	if cur == "" {
		mainLabel += " ✓"
	}
	btns := [][]models.InlineKeyboardButton{{
		{Text: mainLabel, CallbackData: h.bot.Registry().Register(telegram.CallbackEntry{Action: "open", Title: "main chat"})},
	}}
	for _, r := range rows[page*chatsPageSize : min((page+1)*chatsPageSize, len(rows))] {
		label := ""
		if r.pinned {
			label += "📌 "
		}
		label += firstNonEmptyString(r.title, "untitled")
		if r.sessionID == cur && cur != "" {
			label += " ✓"
		}
		btns = append(btns, []models.InlineKeyboardButton{{
			Text:         telegram.ButtonText(label),
			CallbackData: h.bot.Registry().Register(telegram.CallbackEntry{Action: "open", SessionID: r.sessionID, Title: firstNonEmptyString(r.title, "untitled")}),
		}})
	}
	var nav []models.InlineKeyboardButton
	if page > 0 {
		nav = append(nav, models.InlineKeyboardButton{Text: "◀ Prev", CallbackData: h.bot.Registry().Register(telegram.CallbackEntry{Action: "chats_page", Page: page - 1})})
	}
	if page < pages-1 {
		nav = append(nav, models.InlineKeyboardButton{Text: "Next ▶", CallbackData: h.bot.Registry().Register(telegram.CallbackEntry{Action: "chats_page", Page: page + 1})})
	}
	if len(nav) > 0 {
		btns = append(btns, nav)
	}
	text := fmt.Sprintf("Your chats (%d side chats, page %d/%d). Tap one to open it.", len(rows), page+1, pages)
	markup := models.InlineKeyboardMarkup{InlineKeyboard: btns}
	if messageID != 0 {
		return h.bot.Edit(ctx, chatID, messageID, text, markup, telegram.HTMLModePlain)
	}
	_, err = h.bot.Send(ctx, chatID, text, telegram.SendOptions{Markup: markup, Mode: telegram.HTMLModePlain})
	return err
}

func (h *telegramCmdHandler) main(ctx context.Context, chatID int64) error {
	if err := h.store.SetChat(chatID, telegram.ChatEntry{SessionID: "", Title: "main chat"}); err != nil {
		return err
	}
	_, err := h.bot.Send(ctx, chatID, "💬 Now in: <b>main chat</b>", telegram.SendOptions{})
	return err
}

// newChat starts a fresh side chat (Python cmd_new,
// tgbot.py:1870-1877): session.start, the id from session_id /
// id / session.session_id in that order, no id = the warning
// with the first 300 chars of the result JSON, no switch.
func (h *telegramCmdHandler) newChat(ctx context.Context, chatID int64, arg string) error {
	var sid string
	var result any
	err := h.rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
		res, err := deliver.SessionStart(ctx, gw, arg)
		if err != nil {
			return err
		}
		result = res
		m, _ := res.(map[string]any)
		sid = firstNonEmptyString(m["session_id"], m["id"])
		if sid == "" {
			if s, ok := m["session"].(map[string]any); ok {
				sid = firstNonEmptyString(s["session_id"])
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if sid == "" {
		b, _ := json.Marshal(result)
		s := truncateRunes(string(b), 300)
		_, err := h.bot.Send(ctx, chatID, "⚠️ Muse returned no session id: <code>"+telegram.EscapeText(s)+"</code>", telegram.SendOptions{})
		return err
	}
	title := arg
	if title == "" {
		title = "new chat"
	}
	if err := h.store.SetChat(chatID, telegram.ChatEntry{SessionID: sid, Title: title}); err != nil {
		return err
	}
	_, err = h.bot.Send(ctx, chatID, "🆕 Now in a new side chat: <b>"+telegram.EscapeText(title)+"</b>", telegram.SendOptions{})
	return err
}

// history shows the last N messages of the current chat
// (Python cmd_history, tgbot.py:1920-1933). N parses from an
// all-digits arg, else 10, clamped to [1, 50]; N*3 history
// events are read and only user/assistant messages with text
// are kept. Long output splits into messages in PR-A (Python
// sends a file; file sending is PR-B media work). The text
// goes out plain: history bodies are untrusted peer text and
// must never be parsed as HTML.
func (h *telegramCmdHandler) history(ctx context.Context, chatID int64, arg string) error {
	n := 10
	if trimmed := strings.TrimSpace(arg); isAllDigits(trimmed) {
		if v, err := strconv.Atoi(trimmed); err == nil {
			n = v
		}
	}
	n = max(1, min(n, 50))
	mapping, _ := h.store.Chat(chatID)
	scope := mapping.SessionID
	title := mapping.Title
	if title == "" {
		title = "main chat"
	}
	events, _, err := (&historyAdapter{muse: h.rt.Muse, thread: scope}).ReadHistory(ctx, n*3)
	if err != nil {
		return err
	}
	var msgs []string
	for _, raw := range events {
		ev, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		// Python cmd_history filters on event_name only
		// (tgbot.py:1926) and reads text via ev_text
		// (display_text, content, then event-level
		// display_text).
		name, _ := ev["event_name"].(string)
		if name != "message.user" && name != "message.assistant" {
			continue
		}
		payload, _ := ev["payload"].(map[string]any)
		text := shared.CleanText(firstNonEmptyString(payload["display_text"], payload["content"], ev["display_text"]))
		if text == "" {
			continue
		}
		who := "🧑 You"
		if name == "message.assistant" {
			who = "🤖 Muse"
		}
		msgs = append(msgs, who+": "+text)
	}
	if len(msgs) > n {
		msgs = msgs[len(msgs)-n:]
	}
	if len(msgs) == 0 {
		_, err := h.bot.Send(ctx, chatID, "No messages here yet.", telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return err
	}
	text := "📜 " + title + "\n\n" + strings.Join(msgs, "\n\n")
	for _, piece := range telegram.SplitText(text) {
		if _, err := h.bot.Send(ctx, chatID, piece, telegram.SendOptions{Mode: telegram.HTMLModePlain}); err != nil {
			return err
		}
	}
	return nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// unread prints the raw chat.unread_count result as JSON
// inside <pre>, truncated to 3500 chars (Python cmd_unread,
// tgbot.py:1935-1937). The raw body is never logged.
func (h *telegramCmdHandler) unread(ctx context.Context, chatID int64) error {
	d, err := callJSON(ctx, h.rt, "chat.unread_count", conn.RequestOptions{})
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(d); err != nil {
		return err
	}
	s := strings.TrimRight(buf.String(), "\n")
	s = truncateRunes(s, 3500)
	_, err = h.bot.Send(ctx, chatID, "<pre>"+telegram.EscapeText(s)+"</pre>", telegram.SendOptions{})
	return err
}

// currentThread returns the chat's side-chat mapping, or sends
// the side-chat-only reply and reports false (Python
// _current_thread, tgbot.py:1939-1944).
func (h *telegramCmdHandler) currentThread(ctx context.Context, chatID int64) (telegram.ChatEntry, bool, error) {
	mapping, _ := h.store.Chat(chatID)
	if mapping.SessionID == "" {
		_, err := h.bot.Send(ctx, chatID, "That works on side chats. Open one with /chats or make one with /new.", telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return mapping, false, err
	}
	return mapping, true, nil
}

func (h *telegramCmdHandler) sessionOp(ctx context.Context, kind deliver.SessionOpKind, sessionID, title string) error {
	return h.rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
		_, err := deliver.SessionOp(ctx, gw, kind, sessionID, title)
		return err
	})
}

func (h *telegramCmdHandler) rename(ctx context.Context, chatID int64, arg string) error {
	if strings.TrimSpace(arg) == "" {
		_, err := h.bot.Send(ctx, chatID, "Usage: /rename &lt;new title&gt;", telegram.SendOptions{})
		return err
	}
	mapping, ok, err := h.currentThread(ctx, chatID)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if err := h.sessionOp(ctx, deliver.SessionOpRename, mapping.SessionID, arg); err != nil {
		return err
	}
	if err := h.store.SetChat(chatID, telegram.ChatEntry{SessionID: mapping.SessionID, Title: arg}); err != nil {
		return err
	}
	_, err = h.bot.Send(ctx, chatID, "✏️ Renamed to <b>"+telegram.EscapeText(arg)+"</b>", telegram.SendOptions{})
	return err
}

func (h *telegramCmdHandler) sessionOpCmd(ctx context.Context, chatID int64, kind deliver.SessionOpKind, reply string) error {
	mapping, ok, err := h.currentThread(ctx, chatID)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if err := h.sessionOp(ctx, kind, mapping.SessionID, ""); err != nil {
		return err
	}
	_, err = h.bot.Send(ctx, chatID, reply, telegram.SendOptions{Mode: telegram.HTMLModePlain})
	return err
}

func (h *telegramCmdHandler) archive(ctx context.Context, chatID int64) error {
	mapping, ok, err := h.currentThread(ctx, chatID)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if err := h.sessionOp(ctx, deliver.SessionOpArchive, mapping.SessionID, ""); err != nil {
		return err
	}
	if err := h.store.SetChat(chatID, telegram.ChatEntry{SessionID: "", Title: "main chat"}); err != nil {
		return err
	}
	_, err = h.bot.Send(ctx, chatID, "🗄 Archived. Back in the main chat.", telegram.SendOptions{Mode: telegram.HTMLModePlain})
	return err
}

// deletePrompt asks for confirmation first (Python cmd_delete,
// tgbot.py:1978-1984): the confirm button carries the session
// id, Cancel carries noop. Any allowed user may confirm: there
// is no owner gate in this build. That asymmetry is Python
// parity, Boss-approved 2026-11-01 on condition it is
// documented (docs/config.md); it is not hardened here.
func (h *telegramCmdHandler) deletePrompt(ctx context.Context, chatID int64) error {
	mapping, ok, err := h.currentThread(ctx, chatID)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	markup := models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{{
		{Text: "🗑 Yes, delete", CallbackData: h.bot.Registry().Register(telegram.CallbackEntry{Action: "delete", SessionID: mapping.SessionID})},
		{Text: "Cancel", CallbackData: h.bot.Registry().Register(telegram.CallbackEntry{Action: "noop"})},
	}}}
	_, err = h.bot.Send(ctx, chatID, "Delete side chat <b>"+telegram.EscapeText(mapping.Title)+"</b> for good?", telegram.SendOptions{Markup: markup})
	return err
}

// watch toggles the global watch flag in the state file only
// (Python cmd_watch, tgbot.py:2054-2061). Forwarding and
// monitors are PR-B: the reply states only that the flag is
// stored and that forwarding lands in step 5b — it must not
// promise delivery this build lacks. An invalid arg reports
// the current state.
func (h *telegramCmdHandler) watch(ctx context.Context, chatID int64, arg string) error {
	a := strings.ToLower(strings.TrimSpace(arg))
	if a == "on" || a == "off" {
		if err := h.store.SetWatch(a == "on"); err != nil {
			h.logger.Warn("telegram watch toggle save failed", "err", logging.SummarizeErr(err))
		}
	}
	_, _, watchOn := h.store.Toggles()
	on := watchOn != nil && *watchOn
	text := "👀 Watch is <b>off</b>."
	if on {
		text = "👀 Watch is <b>on</b>: the flag is stored; live event forwarding lands in step 5b."
	}
	_, err := h.bot.Send(ctx, chatID, text, telegram.SendOptions{})
	return err
}

// handleCallback serves the step-5 button actions through the
// bot's CallbackFunc hook: answer, open, chats_page, delete,
// noop. It returns handled=false for anything else, so the
// core falls back to its unknown-action log. Question answers
// go out as plain-text turns, exactly as in Python (no
// widget-answer gateway call exists): the keyboard is cleared,
// the value is sent silently, and the value starts a turn.
func (h *telegramCmdHandler) handleCallback(ctx context.Context, chatID int64, messageID int, entry telegram.CallbackEntry) (bool, error) {
	switch entry.Action {
	case "answer":
		if messageID != 0 {
			_ = h.bot.ClearMarkup(ctx, chatID, messageID)
		}
		if _, err := h.bot.Send(ctx, chatID, "➡️ "+entry.Answer, telegram.SendOptions{Silent: true, Mode: telegram.HTMLModePlain}); err != nil {
			return true, err
		}
		h.runner.startTurn(ctx, chatID, entry.Answer)
		return true, nil
	case "open":
		if err := h.store.SetChat(chatID, telegram.ChatEntry{SessionID: entry.SessionID, Title: entry.Title}); err != nil {
			return true, err
		}
		if _, err := h.bot.Send(ctx, chatID, "💬 Now in: <b>"+telegram.EscapeText(entry.Title)+"</b>", telegram.SendOptions{}); err != nil {
			return true, err
		}
		return true, h.history(ctx, chatID, "3")
	case "chats_page":
		return true, h.showChats(ctx, chatID, messageID, entry.Page)
	case "delete":
		if err := h.sessionOp(ctx, deliver.SessionOpDelete, entry.SessionID, ""); err != nil {
			return true, err
		}
		if mapping, ok := h.store.Chat(chatID); ok && mapping.SessionID == entry.SessionID {
			_ = h.store.SetChat(chatID, telegram.ChatEntry{SessionID: "", Title: "main chat"})
		}
		if messageID != 0 {
			return true, h.bot.Edit(ctx, chatID, messageID, "🗑 Deleted. Back in the main chat.", nil, telegram.HTMLModePlain)
		}
		return true, nil
	case "noop":
		if messageID != 0 {
			return true, h.bot.Edit(ctx, chatID, messageID, "Cancelled.", nil, telegram.HTMLModePlain)
		}
		return true, nil
	default:
		return false, nil
	}
}
