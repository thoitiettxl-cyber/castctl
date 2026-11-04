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
	"strconv"
	"strings"
	"time"

	"github.com/go-telegram/bot/models"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/deliver"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/shared"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
)

// The read commands: /feed, /goals, /goal, /ideas (+ the
// idea_exec button), /usage, /wake. Behaviour mirrors Python
// 0.6.1's tgbot.py command handlers (cmd_feed, cmd_goals,
// cmd_goal, cmd_ideas, cb_idea_exec, cmd_usage, cmd_wake);
// every deliberate deviation is noted at the handler and in
// the PR body. Handlers return errors upward: dispatch maps
// AuthError to the login-expired sentence and anything else
// to the generic gateway line, so no handler sends its own
// auth/generic reply — except ideaExec, which (like
// inboundMedia) sends its own login-expired reply for an
// AuthError and returns (true, nil), because a callback error
// otherwise surfaces only as onCallback's summarised warning.

// parseFeedLimit parses the /feed arg: trim, ASCII digits
// only, convert, else 10; 0 or negative resolves to 10 (a
// deliberate override of upstream, which passes 0 through
// and lists everything — see the PR body). The sanitised
// value is passed to both the feed.list query and FeedRows:
// FeedRows with limit 0 means uncapped, so 0 must never
// reach it.
func parseFeedLimit(arg string) int {
	if trimmed := strings.TrimSpace(arg); isAllDigits(trimmed) {
		if v, err := strconv.Atoi(trimmed); err == nil && v > 0 {
			return v
		}
	}
	return 10
}

// feed lists feed units (Python cmd_feed, tgbot.py:2158-2164):
// the sanitised limit goes to the feed.list query and to
// FeedRows, in document order.
func (h *telegramCmdHandler) feed(ctx context.Context, chatID int64, arg string) error {
	n := parseFeedLimit(arg)
	d, err := callMap(ctx, h.rt, "feed.list", conn.RequestOptions{Query: map[string]string{"limit": strconv.Itoa(n)}})
	if err != nil {
		return err
	}
	rows := shared.FeedRows(d, n)
	if len(rows) == 0 {
		_, err := h.bot.Send(ctx, chatID, "Your feed is empty.", telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return err
	}
	var b strings.Builder
	b.WriteString("📰 <b>Feed</b>\n")
	for i, r := range rows {
		if i > 0 {
			b.WriteString("\n")
		}
		title := derefStr(r.Title)
		if title == "" {
			title = "(untitled)"
		}
		fmt.Fprintf(&b, "• %s <i>%s</i>", telegram.EscapeText(title), telegram.EscapeText(derefStr(r.Date)))
	}
	_, err = h.bot.Send(ctx, chatID, b.String(), telegram.SendOptions{})
	return err
}

// goals lists goals (Python cmd_goals, tgbot.py:2166-2172).
func (h *telegramCmdHandler) goals(ctx context.Context, chatID int64) error {
	d, err := callMap(ctx, h.rt, "goals.list", conn.RequestOptions{})
	if err != nil {
		return err
	}
	rows := shared.GoalRows(d)
	if len(rows) == 0 {
		_, err := h.bot.Send(ctx, chatID, "No goals.", telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return err
	}
	var b strings.Builder
	b.WriteString("🎯 <b>Goals</b>\n")
	for i, r := range rows {
		if i > 0 {
			b.WriteString("\n")
		}
		title := derefStr(r.Title)
		if title == "" {
			title = "(untitled)"
		}
		status := derefStr(r.Status)
		if status == "" {
			status = "?"
		}
		fmt.Fprintf(&b, "• %s [%s] <code>%s</code>", telegram.EscapeText(title), telegram.EscapeText(status), telegram.EscapeText(derefStr(r.ID)))
	}
	b.WriteString("\n\n/goal &lt;id&gt; for details")
	_, err = h.bot.Send(ctx, chatID, b.String(), telegram.SendOptions{})
	return err
}

// goal shows one goal (Python cmd_goal, tgbot.py:2174-2188):
// the head line plus subtitle/description, then the JSON body
// (indent 1, no HTML escaping in the dump) inside <pre> — or,
// when the body alone exceeds 3000 runes, the head send
// followed by a goal.json document. The goal dict is the
// response's "goal" member when present and a dict, else the
// response itself when it is a dict, else empty (head "") —
// exactly upstream's isinstance shape. [DEVIATION] a
// whitespace-only arg answers the usage sentence: upstream
// calls goals.get with id="" (its empty check runs before
// stripping).
func (h *telegramCmdHandler) goal(ctx context.Context, chatID int64, arg string) error {
	id := strings.TrimSpace(arg)
	if id == "" {
		_, err := h.bot.Send(ctx, chatID, "Usage: /goal &lt;id&gt; (ids from /goals)", telegram.SendOptions{})
		return err
	}
	v, err := callJSON(ctx, h.rt, "goals.get", conn.RequestOptions{PathParams: map[string]string{"id": id}})
	if err != nil {
		return err
	}
	var g map[string]any
	if d, ok := v.(map[string]any); ok {
		if gv, present := d["goal"]; !present {
			g = d
		} else if inner, ok := gv.(map[string]any); ok {
			g = inner
		}
	}
	head := ""
	if g != nil {
		head = "🎯 <b>" + telegram.EscapeText(derefStr(strPtrField(g, "title"))) + "</b> [" + telegram.EscapeText(derefStr(strPtrField(g, "status"))) + "]\n"
		if sub := firstNonEmptyString(g["subtitle"], g["description"]); sub != "" {
			head += telegram.EscapeText(sub) + "\n"
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	body := strings.TrimRight(buf.String(), "\n")
	if len([]rune(body)) > 3000 {
		sendText := head
		if sendText == "" {
			sendText = "Goal:"
		}
		if _, err := h.bot.Send(ctx, chatID, sendText, telegram.SendOptions{}); err != nil {
			return err
		}
		_, err = h.bot.SendFile(ctx, chatID, "goal.json", []byte(body), "", "", telegram.SendOptions{})
		return err
	}
	_, err = h.bot.Send(ctx, chatID, head+"<pre>"+telegram.EscapeText(body)+"</pre>", telegram.SendOptions{})
	return err
}

// strPtrField returns a *string for a string-valued map field,
// or nil. It lets the goal head reuse derefStr's nil handling
// without a type assertion at each field.
func strPtrField(m map[string]any, key string) *string {
	if s, ok := m[key].(string); ok {
		return &s
	}
	return nil
}

// ideas lists idea cards (Python cmd_ideas, tgbot.py:2190-2198):
// the first 15 cards in response order, one silent send each
// with a single Execute button. The button's callback carries
// the card id (typed IdeaID field) and the RAW card title
// (no "(untitled)" fallback) server-side in the registry;
// callback data stays the short "c:" token.
func (h *telegramCmdHandler) ideas(ctx context.Context, chatID int64) error {
	d, err := callMap(ctx, h.rt, "api.idea-cards.list", conn.RequestOptions{})
	if err != nil {
		return err
	}
	rows := shared.IdeaRows(d)
	if len(rows) == 0 {
		_, err := h.bot.Send(ctx, chatID, "No idea cards right now.", telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return err
	}
	if len(rows) > 15 {
		rows = rows[:15]
	}
	for _, r := range rows {
		rawTitle := derefStr(r.Title)
		displayTitle := rawTitle
		if displayTitle == "" {
			displayTitle = "(untitled)"
		}
		text := "💡 <b>" + telegram.EscapeText(displayTitle) + "</b>"
		if section := derefStr(r.Section); section != "" {
			text += "\n<i>" + telegram.EscapeText(section) + "</i>"
		}
		markup := models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{{
			{Text: telegram.ButtonText("▶️ Execute"), CallbackData: h.bot.Registry().Register(telegram.CallbackEntry{Action: "idea_exec", IdeaID: derefStr(r.ID), Title: rawTitle})},
		}}}
		if _, err := h.bot.Send(ctx, chatID, text, telegram.SendOptions{Markup: markup, Silent: true}); err != nil {
			return err
		}
	}
	return nil
}

// ideaExec serves one Execute-button tap (Python cb_idea_exec,
// tgbot.py:2200-2205): execute the card via
// api.idea-cards.execute with the chat's CURRENT session id
// (omitted when empty, mirroring cmdIdeaExec's conditional),
// then the fixed working reply. The registry entry is never
// consumed, so a re-tap re-executes. An AuthError gets the
// own login-expired reply (inboundMedia precedent) and
// (true, nil); any other error returns to onCallback's
// summarised warning.
func (h *telegramCmdHandler) ideaExec(ctx context.Context, chatID int64, entry telegram.CallbackEntry) (bool, error) {
	mapping, _ := h.store.Chat(chatID)
	body := map[string]any{"ideaCardId": entry.IdeaID, "mode": "full"}
	if mapping.SessionID != "" {
		body["session_id"] = mapping.SessionID
	}
	_, err := callJSON(ctx, h.rt, "api.idea-cards.execute", conn.RequestOptions{
		PathParams: map[string]string{"ideaCardId": entry.IdeaID},
		Body:       body,
	})
	if err != nil {
		var authErr *conn.AuthError
		if errors.As(err, &authErr) {
			h.logger.Warn("telegram idea execute failed (auth)", "err", logging.SummarizeErr(err))
			_, sendErr := h.bot.Send(ctx, chatID, "🔑 muse.ai login expired. Use /login.", telegram.SendOptions{Mode: telegram.HTMLModePlain})
			return true, sendErr
		}
		return true, err
	}
	title := entry.Title
	if title == "" {
		title = entry.IdeaID
	}
	_, err = h.bot.Send(ctx, chatID, "▶️ Muse is working on: <b>"+telegram.EscapeText(title)+"</b>. Replies arrive here when they land.", telegram.SendOptions{})
	return true, err
}

// usage shows plan usage (Python cmd_usage, tgbot.py:2207-2213):
// FetchSubscription + SummarizeUsage + UsageLines exactly as
// the CLI `castctl usage` renders them, prefixed with 📊 and
// escaped as one joined string. [DEVIATION] no owner-notify
// on auth failure: the AuthError propagates to dispatch,
// which sends the single login-expired sentence (the
// established pattern; there is no owner-notify path in this
// build).
func (h *telegramCmdHandler) usage(ctx context.Context, chatID int64) error {
	cookies, err := h.rt.Cookies()
	if err != nil {
		return err
	}
	sub, _, err := gateway.FetchSubscription(ctx, h.rt.HTTPClient(), cookies, gateway.SubscriptionOptions{
		ActionID:         h.rt.Profile.SubscriptionActionID,
		IncludeAgreement: false,
		Store:            nil,
	})
	if err != nil {
		return err
	}
	u := shared.SummarizeUsage(sub, time.Local)
	text := "📊 " + telegram.EscapeText(strings.Join(shared.UsageLines(u, time.Local), "\n"))
	_, err = h.bot.Send(ctx, chatID, text, telegram.SendOptions{})
	return err
}

// wake asks muse.ai to wake the VM (Python cmd_wake,
// tgbot.py:2215-2218): deliver.Wake with the exact dep
// construction `castctl wake` uses, bounded by a handler-side
// 30s timeout (deliver.Wake bounds only the wake POST).
// [DEVIATION] the body JSON is compact (Go's encoder, no
// spaces after separators); upstream's json.dumps uses
// ", "/" : " separators.
func (h *telegramCmdHandler) wake(ctx context.Context, chatID int64) error {
	cookies, err := h.rt.Cookies()
	if err != nil {
		return err
	}
	wakeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result, err := deliver.Wake(wakeCtx, deliver.WakeDeps{
		Client:  h.rt.HTTPClient(),
		Cookies: cookies,
		VMID:    h.rt.Profile.VMID,
		WakeVM:  gateway.WakeVM,
	})
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result.Body); err != nil {
		return err
	}
	dumped := strings.TrimRight(buf.String(), "\n")
	text := fmt.Sprintf("⏰ Wake requested: HTTP %d<pre>%s</pre>", result.Status, telegram.EscapeText(truncateRunes(dumped, 800)))
	_, err = h.bot.Send(ctx, chatID, text, telegram.SendOptions{})
	return err
}
