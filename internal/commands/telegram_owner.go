// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
	"github.com/thoitiettxl-cyber/castctl/internal/update"
)

// The owner commands: /profile, /update, /login, /raw (Python
// cmd_profile/cmd_login/take_cookies/cmd_update/cmd_raw,
// tgbot.py:2220-2330), all behind the owner gate in
// runCommand (tgbot.py:1033-1034). Behaviour mirrors Python
// 0.6.1; every deliberate deviation is noted at the handler
// and in the PR body. Like /fs, the handlers send their own
// input-class replies and return nil; gateway errors return
// upward to dispatch's mapping — except the login write
// path, which (like ideaExec/fsRm) sends its own failure
// sentences and returns nil, because a cookie write must
// never surface a path-bearing error string.
//
// [DEVIATION] /profile is display-only: upstream lists all
// profiles with switch buttons and switches on tap; this
// bot serves the linked profile and cannot switch from
// chat.
// [DEVIATION] /update is check-only: upstream upgrades in
// place and re-execs the process; this bot runs DryRun and
// reports the manual command, never replacing its binary
// or re-execing mid-turn.
// [DEVIATION] the awaiting state admits only the uid that
// ran /login in that chat (upstream admits any sender in
// the chat), and an oversize document is refused with a
// fixed sentence after deleting the message (upstream
// drops it silently). A cookie-bearing message must not
// linger in chat either way.
// The login instruction names no absolute cookies path
// (upstream interpolates the real path); the take_cookies
// failure sentence keeps upstream's [:300] bound (NOT
// [:600]). No cookie bytes reach any log line or reply:
// the write path maps every error to a fixed sentence, and
// dispatch's summarised logging never sees cookie text.

// ownerOnlySentence is upstream's fixed owner-gate refusal
// (tgbot.py:1033-1034), identical whether no owner is
// configured or the sender is not the owner. It echoes
// nothing: a user id is not a secret, but the two cases
// must stay indistinguishable, as upstream.
const ownerOnlySentence = "Only the owner can use that command."

// isOwnerCommand reports whether name is one of the four
// owner-gated commands.
func isOwnerCommand(name string) bool {
	switch name {
	case "profile", "update", "login", "raw":
		return true
	}
	return false
}

// isOwner reports whether uid is the configured owner. With
// no owner configured every uid is refused.
func (h *telegramCmdHandler) isOwner(uid int64) bool {
	return h.hasOwner && uid == h.ownerID
}

// ownerProfile reports the serving profile (Python
// cmd_profile, tgbot.py:2220-2226, display part only): the
// linked profile's name, the configured VM id when present,
// and cookies presence from an os.Stat only — no path, no
// contents, no gateway call. [DEVIATION] no switch: see the
// file header.
func (h *telegramCmdHandler) ownerProfile(ctx context.Context, chatID int64) error {
	cookies := "missing"
	if st, err := os.Stat(h.prof.CookiesFile); err == nil && !st.IsDir() && st.Size() > 0 {
		cookies = "present"
	}
	text := "Serving profile: <b>" + telegram.EscapeText(h.prof.Name) + "</b>"
	if h.prof.VMID != "" {
		text += " (VM <code>" + telegram.EscapeText(h.prof.VMID) + "</code>)"
	}
	text += ".\nCookies: " + cookies + ".\nProfile switching is not available from chat; edit the telegram block's profile and restart the bot."
	_, err := h.bot.Send(ctx, chatID, text, telegram.SendOptions{})
	return err
}

// ownerUpdate runs the release check in dry-run mode and
// reports it (Python cmd_update, tgbot.py:2281-2309, check
// part only): the DryRun lines, the manual command, and the
// no-restart notice. [DEVIATION] check-only: see the file
// header. Any failure gets one fixed sentence and nil: the
// bot keeps running the current version either way.
func (h *telegramCmdHandler) ownerUpdate(ctx context.Context, chatID int64) error {
	updateCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	var buf bytes.Buffer
	opts := update.Options{
		CurrentVersion: h.version,
		Commit:         h.commit,
		BuildDate:      h.buildDate,
		DryRun:         true,
		Stdout:         &buf,
	}
	if h.env != nil && h.env.UpdateDeps != nil {
		opts.Deps = *h.env.UpdateDeps
	}
	if _, err := update.Run(updateCtx, opts); err != nil {
		h.logger.Warn("telegram update check failed", "err", logging.SummarizeErr(err))
		_, sendErr := h.bot.Send(ctx, chatID, "⚠️ Could not check for updates; the bot is still running the current version. Run <code>castctl update</code> to update manually.", telegram.SendOptions{})
		return sendErr
	}
	var lines []string
	if text := strings.TrimRight(buf.String(), "\n"); text != "" {
		lines = append(lines, "<pre>"+telegram.EscapeText(text)+"</pre>")
	}
	lines = append(lines, "Check only: nothing was changed and the bot was not restarted. To update, run <code>castctl update</code>.")
	_, err := h.bot.Send(ctx, chatID, strings.Join(lines, "\n"), telegram.SendOptions{})
	return err
}

// rawUsage is Python's usage line verbatim
// (tgbot.py:2312-2314), including the literal &lt;/&gt;
// entities: it is sent as HTML.
const rawUsage = "Usage: /raw &lt;method&gt; [json body]; path params go in <code>{\"_params\": {...}}</code>"

// ownerRaw runs one raw gateway call (Python cmd_raw,
// tgbot.py:2311-2330): usage on an empty method, the route
// check BEFORE any gateway is opened, JSON parse, the
// _params pop, the call, and the replyLong render. Gateway
// errors return upward to dispatch's mapping.
func (h *telegramCmdHandler) ownerRaw(ctx context.Context, chatID int64, arg string) error {
	method, rest, _ := strings.Cut(arg, " ")
	method = strings.TrimSpace(method)
	rest = strings.TrimSpace(rest)
	if method == "" {
		_, err := h.bot.Send(ctx, chatID, rawUsage, telegram.SendOptions{})
		return err
	}
	table, err := gateway.DefaultRoutes()
	if err != nil {
		return err
	}
	if _, ok := table.LookupRoute(method); !ok {
		_, err := h.bot.Send(ctx, chatID, "Unknown method <code>"+telegram.EscapeText(method)+"</code> ("+strconv.Itoa(table.Total())+" known).", telegram.SendOptions{})
		return err
	}
	var body any
	if rest != "" {
		v, err := decodeJSONNumber([]byte(rest))
		if err != nil {
			// The bare decoder error only: the body is
			// never echoed (it may carry secrets).
			_, sendErr := h.bot.Send(ctx, chatID, "⚠️ invalid JSON: "+err.Error(), telegram.SendOptions{Mode: telegram.HTMLModePlain})
			return sendErr
		}
		body = v
	}
	var pathParams map[string]string
	if m, ok := body.(map[string]any); ok {
		if raw, ok := m["_params"]; ok {
			if params, ok := raw.(map[string]any); ok {
				pathParams = make(map[string]string, len(params))
				for k, v := range params {
					s, ok := v.(string)
					if !ok {
						_, sendErr := h.bot.Send(ctx, chatID, "⚠️ _params values must be strings", telegram.SendOptions{Mode: telegram.HTMLModePlain})
						return sendErr
					}
					pathParams[k] = s
				}
				delete(m, "_params")
			}
		}
	}
	var data []byte
	err = h.rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
		var err error
		data, err = gw.Request(ctx, method, conn.RequestOptions{
			Body:       body,
			PathParams: pathParams,
			Timeout:    30 * time.Second,
		})
		return err
	})
	if err != nil {
		return err
	}
	return h.replyLong(ctx, chatID, renderRawResult(data), method+".json", true)
}

// renderRawResult renders one gw.Request reply the way cmdRaw
// does: empty becomes {}, valid JSON is re-encoded indented,
// anything else stays raw text.
func renderRawResult(data []byte) string {
	if len(data) == 0 {
		return "{}"
	}
	v, err := decodeJSONNumber(data)
	if err != nil {
		return string(data)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return string(data)
	}
	return strings.TrimRight(buf.String(), "\n")
}

// loginCookiesLimit is the take_cookies document cap
// (Python tgapi.download limit=1MiB, tgbot.py:2253).
const loginCookiesLimit = 1 << 20

// loginTooBigSentence is the fixed refusal for an oversize
// cookies document. It carries no size: the declared size
// can lie, and the sentence must not echo either figure.
const loginTooBigSentence = "⚠️ That cookies file is too big (1 MiB limit)."

// loginNoHatchSessSentence is upstream's exact sentence
// (tgbot.py:2263) for a message without hatch_sess.
const loginNoHatchSessSentence = "⚠️ No hatch_sess cookie in that, so nothing changed. /login to retry."

// loginCookiesLockTimeout bounds the cookies-file lock hold
// for the login write (the keeper's own default is 5s; the
// login write is user-initiated and may wait a little
// longer, but never unbounded: a timeout is a generic
// failure, never a forced write).
const loginCookiesLockTimeout = 10 * time.Second

// ownerLogin arms the per-chat cookie-awaiting state
// (Python cmd_login, tgbot.py:2244-2249) and sends the
// instruction. The instruction names the profile's
// cookies.txt with no absolute path (B1 precedent), keeps
// the delete notice and the .bak sentence, and states the
// state is in-memory (lost on restart).
func (h *telegramCmdHandler) ownerLogin(ctx context.Context, mc telegram.MessageContext) error {
	h.armAwaitingCookies(mc.ChatID, mc.UserID)
	_, err := h.bot.Send(ctx, mc.ChatID, "🔑 Send the muse.ai cookies now: the <code>cookies.txt</code> file from <code>castctl auth export</code>, or one line like <code>hatch_sess=…; other=…</code>. I delete your message after reading it. They replace the profile's <code>cookies.txt</code> (the old one is kept as <code>.bak</code>). This waiting state is kept in memory only and is lost if the bot restarts.", telegram.SendOptions{})
	return err
}

// armAwaitingCookies records that chatID's next cookie answer
// may come only from uid.
func (h *telegramCmdHandler) armAwaitingCookies(chatID, uid int64) {
	h.awaitingMu.Lock()
	defer h.awaitingMu.Unlock()
	if h.awaitingCookies == nil {
		h.awaitingCookies = make(map[int64]awaitingLogin)
	}
	h.awaitingCookies[chatID] = awaitingLogin{uid: uid}
}

// popAwaitingCookies removes and reports chatID's awaiting
// entry, but only when uid is the user that armed it.
// Anything else leaves the state untouched.
func (h *telegramCmdHandler) popAwaitingCookies(chatID, uid int64) bool {
	h.awaitingMu.Lock()
	defer h.awaitingMu.Unlock()
	if h.awaitingCookies == nil {
		return false
	}
	want, ok := h.awaitingCookies[chatID]
	if !ok || want.uid != uid {
		return false
	}
	delete(h.awaitingCookies, chatID)
	return true
}

// takeAwaitingCookies consumes mc as the awaited cookie
// answer (Python on_message's awaiting branch,
// tgbot.py:1016-1019, plus take_cookies, :2251-2279). It
// reports whether the message was consumed; a consumed
// message that fails (download, write) returns the error
// for dispatch's mapping. Only a document or non-blank
// text from the arming user consumes the state: commands
// are handled before this runs, and photos fall through
// to the inbox untouched.
func (h *telegramCmdHandler) takeAwaitingCookies(ctx context.Context, mc telegram.MessageContext) (bool, error) {
	if !mc.IsDocument && (mc.Media != nil || strings.TrimSpace(mc.Text) == "") {
		return false, nil
	}
	if !h.popAwaitingCookies(mc.ChatID, mc.UserID) {
		return false, nil
	}
	chatID := mc.ChatID
	var text string
	if mc.IsDocument && mc.Media != nil {
		// Declared-size gate BEFORE downloading (upstream's
		// download raises on the reported size); the body
		// gate below covers a lying declaration.
		if mc.Media.Size > loginCookiesLimit {
			_ = h.bot.Delete(ctx, chatID, mc.MessageID)
			_, err := h.bot.Send(ctx, chatID, loginTooBigSentence, telegram.SendOptions{Mode: telegram.HTMLModePlain})
			return true, err
		}
		data, err := h.bot.DownloadMedia(ctx, mc.Media)
		if err != nil {
			// The message may hold cookies: delete it
			// even though the fetch failed, then surface
			// the failure through dispatch's generic
			// line (the error is scrubbed; it carries no
			// cookie bytes).
			_ = h.bot.Delete(ctx, chatID, mc.MessageID)
			return true, err
		}
		if int64(len(data)) > loginCookiesLimit {
			_ = h.bot.Delete(ctx, chatID, mc.MessageID)
			_, err := h.bot.Send(ctx, chatID, loginTooBigSentence, telegram.SendOptions{Mode: telegram.HTMLModePlain})
			return true, err
		}
		text = string(data)
	} else {
		text = mc.Text
	}
	// Delete the user's message BEFORE validating: the copy
	// in chat must not linger, on every path below. The
	// delete error is swallowed, as upstream.
	_ = h.bot.Delete(ctx, chatID, mc.MessageID)
	if !strings.Contains(text, "hatch_sess") {
		_, err := h.bot.Send(ctx, chatID, loginNoHatchSessSentence, telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return true, err
	}
	if err := h.saveLoginCookies(text); err != nil {
		// Never surface the write error: WriteCookiesFile
		// errors embed the cookies path.
		h.logger.Warn("telegram login cookies save failed", "err", logging.SummarizeErr(err))
		_, sendErr := h.bot.Send(ctx, chatID, "⚠️ Could not save the cookies; nothing changed. /login to retry.", telegram.SendOptions{Mode: telegram.HTMLModePlain})
		return true, sendErr
	}
	h.resetMuse()
	vmID, err := statusVMID(ctx, h.rt)
	if err != nil {
		// Upstream's failure sentence keeps [:300] (NOT
		// [:600]): the summary is class/length already,
		// truncated to 300 runes for parity.
		summary := truncateRunes(logging.SummarizeErr(err), 300)
		_, sendErr := h.bot.Send(ctx, chatID, "⚠️ Saved, but Muse still refuses: "+telegram.EscapeText(summary), telegram.SendOptions{})
		return true, sendErr
	}
	_, err = h.bot.Send(ctx, chatID, "✅ Cookies saved and working (VM <code>"+telegram.EscapeText(vmID)+"</code>).", telegram.SendOptions{})
	return true, err
}

// saveLoginCookies writes text (stripped, one trailing
// newline, upstream's shape) to the profile's cookies file
// under the cookies-file lock, mode 0600, previous file
// kept as .bak. It never logs or returns cookie bytes.
func (h *telegramCmdHandler) saveLoginCookies(text string) error {
	if h.rt == nil || h.rt.Location == nil {
		return errors.New("telegram login: no config location")
	}
	_, err := profile.WriteCookiesFileLocked(h.rt.Location.ConfigDir, h.prof.Name, h.prof.CookiesFile, []byte(strings.TrimSpace(text)+"\n"), loginCookiesLockTimeout)
	return err
}

// resetMuse drops the shared gateway connection so the next
// Connect re-reads the fresh cookies file. A nil Muse (only
// in directly built test handlers) skips the reset: the
// production path always sets Muse before polling.
func (h *telegramCmdHandler) resetMuse() {
	if h.rt != nil && h.rt.Muse != nil {
		h.rt.Muse.Reset()
	}
}
