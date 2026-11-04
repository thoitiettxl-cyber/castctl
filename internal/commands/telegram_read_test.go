// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// PR-D read-command tests: /feed, /goals, /goal, /ideas (+ the
// idea_exec button), /usage, /wake through the full `telegram
// run` harness (fake Telegram server + scripted fake gateway),
// plus button-tap tests through a directly wired Bot. No live
// network, no token, no cookies beyond the seeded fake file.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
)

const readLoginExpired = "🔑 muse.ai login expired. Re-export cookies with `castctl auth export` and restart the bot."
const readGatewayErrorFeed = "⚠️ Could not run /feed (gateway error)."

// seedProfileCookies writes the fake cookies file at the path
// rt.Cookies() resolves for the harness's muse01 profile
// (<home>/profiles/muse01/cookies.txt), so /usage and /wake
// reach the scripted muse.ai branches instead of failing on a
// missing cookies file. Call before staging the command batch.
func seedProfileCookies(t *testing.T, h *telegramBotHarness) {
	t.Helper()
	dir := filepath.Join(h.homeDir, "profiles", "muse01")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cookies.txt"), []byte(fakeCookie), 0o600); err != nil {
		t.Fatal(err)
	}
}

// runReadBot starts the harness with no staged updates; the
// caller seeds cookies if needed, then stages batches with
// setBatches.
func runReadBot(t *testing.T, gw *telegramTurnFakeGateway) (*telegramBotHarness, func()) {
	t.Helper()
	h, cancel, _ := runTelegramBot(t, gw, []string{})
	return h, cancel
}

// waitForSends waits until the fake has recorded at least n
// sends, and returns them.
func waitForSends(t *testing.T, h *telegramBotHarness, n int) []string {
	t.Helper()
	waitFor(t, fmt.Sprintf("%d sends", n), func() bool { return len(h.fake.sendsSeen()) >= n })
	return h.fake.sendsSeen()
}

// sendOnly stages one command and requires exactly one reply
// carrying want (substring wait), then returns all sends.
func sendOnly(t *testing.T, h *telegramBotHarness, text string) []string {
	t.Helper()
	h.fake.setBatches([]string{telegramUpdate(1, 111, text)})
	return waitForSends(t, h, 1)
}

func feedFixture(n int) map[string]any {
	units := make([]any, 0, n)
	for i := 1; i <= n; i++ {
		units = append(units, map[string]any{"unit_id": fmt.Sprintf("u%02d", i), "title": fmt.Sprintf("Unit %02d", i)})
	}
	return map[string]any{"days": []any{
		map[string]any{"local_date": "2026-11-01", "editions": []any{
			map[string]any{"kind": "daily", "units": units},
		}},
	}}
}

func TestReadFeedData(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.feedScript = map[string]any{"days": []any{
		map[string]any{"local_date": "2026-11-01", "editions": []any{
			map[string]any{"kind": "daily", "units": []any{
				map[string]any{"unit_id": "u1", "title": "Cats <dogs> & birds"},
				map[string]any{"unit_id": "u2"},
			}},
		}},
		map[string]any{"editions": []any{
			map[string]any{"kind": "weekly", "units": []any{
				map[string]any{"unit_id": "u3", "title": "Third"},
			}},
		}},
	}}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/feed")
	if len(sends) != 1 {
		t.Fatalf("sends = %q; want exactly 1", sends)
	}
	want := "📰 <b>Feed</b>\n" +
		"• Cats &lt;dogs&gt; &amp; birds <i>2026-11-01</i>\n" +
		"• (untitled) <i>2026-11-01</i>\n" +
		"• Third <i></i>"
	if sends[0] != want {
		t.Errorf("send = %q; want %q", sends[0], want)
	}
	queries := gw.feedQueriesSeen()
	if len(queries) != 1 || queries[0]["limit"] != "10" {
		t.Errorf("feed queries = %v; want one query with limit 10", queries)
	}
}

func TestReadFeedEmpty(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.feedScript = map[string]any{}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/feed")
	if len(sends) != 1 || sends[0] != "Your feed is empty." {
		t.Errorf("sends = %q; want exactly [Your feed is empty.]", sends)
	}
}

func TestReadFeedArgLimits(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		text  string
		limit string
	}{
		{"explicit 5", "/feed 5", "5"},
		{"bare defaults to 10", "/feed", "10"},
		{"non-numeric defaults to 10", "/feed abc", "10"},
		{"zero defaults to 10", "/feed 0", "10"},
		{"negative defaults to 10", "/feed -5", "10"},
		{"spaces trimmed", "/feed  7 ", "7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gw := newTelegramTurnFakeGateway()
			gw.feedScript = feedFixture(12)
			h, cancel := runReadBot(t, gw)
			defer cancel()
			sends := sendOnly(t, h, tc.text)
			if len(sends) != 1 {
				t.Fatalf("sends = %d; want exactly 1: %q", len(sends), sends)
			}
			wantBullets, _ := strconv.Atoi(tc.limit)
			if got := strings.Count(sends[0], "\n• "); got != wantBullets {
				t.Errorf("reply has %d bullets; want %d: %q", got, wantBullets, sends[0])
			}
			queries := gw.feedQueriesSeen()
			if len(queries) != 1 || queries[0]["limit"] != tc.limit {
				t.Errorf("feed queries = %v; want one query with limit %q", queries, tc.limit)
			}
		})
	}
}

func TestReadFeedGatewayError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.feedErr = errors.New("marker-feed-boom")
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/feed")
	if len(sends) != 1 || sends[0] != readGatewayErrorFeed {
		t.Errorf("sends = %q; want exactly [%q]", sends, readGatewayErrorFeed)
	}
	if strings.Contains(sends[0], "marker-feed-boom") {
		t.Errorf("send leaks raw error text: %q", sends[0])
	}
}

func TestReadFeedAuthError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.feedErr = conn.NewAuthError("expired")
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/feed")
	if len(sends) != 1 || sends[0] != readLoginExpired {
		t.Errorf("sends = %q; want exactly [%q]", sends, readLoginExpired)
	}
}
func TestReadGoalsData(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.goalsScript = map[string]any{"goals": []any{
		map[string]any{"id": "g1", "title": "Ship <v1> & rest", "status": "active"},
		map[string]any{"goal_id": "g2", "title": "Second"},
		map[string]any{"id": "", "goal_id": "g3", "title": "Third", "status": "done"},
	}}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goals")
	if len(sends) != 1 {
		t.Fatalf("sends = %q; want exactly 1", sends)
	}
	want := "🎯 <b>Goals</b>\n" +
		"• Ship &lt;v1&gt; &amp; rest [active] <code>g1</code>\n" +
		"• Second [?] <code>g2</code>\n" +
		"• Third [done] <code>g3</code>\n" +
		"\n/goal &lt;id&gt; for details"
	if sends[0] != want {
		t.Errorf("send = %q; want %q", sends[0], want)
	}
}

func TestReadGoalsEmpty(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.goalsScript = map[string]any{}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goals")
	if len(sends) != 1 || sends[0] != "No goals." {
		t.Errorf("sends = %q; want exactly [No goals.]", sends)
	}
}

func TestReadGoalsGatewayError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.goalsErr = errors.New("marker-goals-boom")
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goals")
	want := "⚠️ Could not run /goals (gateway error)."
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
}

func TestReadGoalsAuthError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.goalsErr = conn.NewAuthError("expired")
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goals")
	if len(sends) != 1 || sends[0] != readLoginExpired {
		t.Errorf("sends = %q; want exactly [%q]", sends, readLoginExpired)
	}
}

func TestReadGoalUsage(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goal")
	want := "Usage: /goal &lt;id&gt; (ids from /goals)"
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
	if ids := gw.goalIDsSeen(); len(ids) != 0 {
		t.Errorf("goals.get ids = %v; want no call for an empty arg", ids)
	}
}

func TestReadGoalUsageWhitespace(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goal   ")
	want := "Usage: /goal &lt;id&gt; (ids from /goals)"
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
	if ids := gw.goalIDsSeen(); len(ids) != 0 {
		t.Errorf("goals.get ids = %v; want no call for a whitespace-only arg", ids)
	}
}

func TestReadGoalSmall(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.goalScript = map[string]any{
		"goal": map[string]any{"status": "active", "subtitle": "Sub & <desc>", "title": "Ship <it> & more"},
		"id":   "g1",
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goal g1")
	if len(sends) != 1 {
		t.Fatalf("sends = %q; want exactly 1", sends)
	}
	head := "🎯 <b>Ship &lt;it&gt; &amp; more</b> [active]\nSub &amp; &lt;desc&gt;\n"
	body := "{\n \"goal\": {\n  \"status\": \"active\",\n  \"subtitle\": \"Sub &amp; &lt;desc&gt;\",\n  \"title\": \"Ship &lt;it&gt; &amp; more\"\n },\n \"id\": \"g1\"\n}"
	want := head + "<pre>" + body + "</pre>"
	if sends[0] != want {
		t.Errorf("send = %q; want %q", sends[0], want)
	}
	if ids := gw.goalIDsSeen(); len(ids) != 1 || ids[0] != "g1" {
		t.Errorf("goals.get ids = %v; want [g1]", ids)
	}
	if docs := h.fake.documentsSeen(); len(docs) != 0 {
		t.Errorf("documents = %+v; want none for a small body", docs)
	}
}

func TestReadGoalDocument(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.goalScript = map[string]any{
		"goal": map[string]any{"status": "active", "title": "Big"},
		"pad":  strings.Repeat("x", 3100),
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goal g1")
	head := "🎯 <b>Big</b> [active]\n"
	if len(sends) != 1 || sends[0] != head {
		t.Errorf("sends = %q; want exactly the head send [%q]", sends, head)
	}
	// The document follows the head send asynchronously from
	// the test's viewpoint: wait for it before asserting.
	waitFor(t, "goal.json document", func() bool { return len(h.fake.documentsSeen()) >= 1 })
	docs := h.fake.documentsSeen()
	if len(docs) != 1 {
		t.Fatalf("documents = %+v; want exactly 1", docs)
	}
	if docs[0].Filename != "goal.json" || docs[0].Caption != "" || docs[0].HasMarkup {
		t.Errorf("document = %+v; want filename goal.json, empty caption, no markup", docs[0])
	}
	if docs[0].Size <= 3000 {
		t.Errorf("document size = %d; want over 3000", docs[0].Size)
	}
}

// TestReadGoalBoundary3000 pins the threshold: a body of exactly
// 3000 runes takes the <pre> branch, not the document branch.
// The dump shape is fixed by construction (see the arithmetic in
// the test): 68 fixed runes + the pad.
func TestReadGoalBoundary3000(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.goalScript = map[string]any{
		"goal": map[string]any{"status": "active", "title": "Big"},
		"pad":  strings.Repeat("x", 2932),
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goal g1")
	if len(sends) != 1 {
		t.Fatalf("sends = %q; want exactly 1", sends)
	}
	if docs := h.fake.documentsSeen(); len(docs) != 0 {
		t.Errorf("documents = %+v; want none at exactly 3000 runes", docs)
	}
	if !strings.Contains(sends[0], "<pre>") {
		t.Errorf("send = %q; want the <pre> branch", sends[0])
	}
	// Prove the body really is 3000 runes: strip the head and
	// the <pre> tags from the observed send and unescape.
	head := "🎯 <b>Big</b> [active]\n"
	rest := strings.TrimPrefix(sends[0], head)
	rest = strings.TrimPrefix(rest, "<pre>")
	rest = strings.TrimSuffix(rest, "</pre>")
	rest = strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">").Replace(rest)
	if n := len([]rune(rest)); n != 3000 {
		t.Errorf("body is %d runes; want exactly 3000", n)
	}
}

func TestReadGoalNonDict(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.goalResult = "just a string"
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goal g1")
	want := `<pre>"just a string"</pre>`
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
}

func TestReadGoalNonDictLarge(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.goalResult = strings.Repeat("y", 3100)
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goal g1")
	if len(sends) != 1 || sends[0] != "Goal:" {
		t.Errorf("sends = %q; want exactly the [Goal:] head send", sends)
	}
	waitFor(t, "goal.json document", func() bool { return len(h.fake.documentsSeen()) >= 1 })
	docs := h.fake.documentsSeen()
	if len(docs) != 1 || docs[0].Filename != "goal.json" {
		t.Errorf("documents = %+v; want exactly 1 goal.json", docs)
	}
}

func TestReadGoalGatewayError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.goalErr = errors.New("marker-goal-boom")
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goal g1")
	want := "⚠️ Could not run /goal (gateway error)."
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
}

func TestReadGoalAuthError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.goalErr = conn.NewAuthError("expired")
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goal g1")
	if len(sends) != 1 || sends[0] != readLoginExpired {
		t.Errorf("sends = %q; want exactly [%q]", sends, readLoginExpired)
	}
}

func ideasFixture() map[string]any {
	return map[string]any{"sections": []any{
		map[string]any{"title": "Work", "cards": []any{
			map[string]any{"id": "c1", "title": "Build <thing> & stuff"},
			map[string]any{"id": "c2"},
		}},
		map[string]any{"ideas": []any{
			map[string]any{"ideaCardId": "c3", "title": "Third"},
		}},
	}}
}

func TestReadIdeasData(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.ideasScript = ideasFixture()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	h.fake.setBatches([]string{telegramUpdate(1, 111, "/ideas")})
	sends := waitForSends(t, h, 3)
	if len(sends) != 3 {
		t.Fatalf("sends = %q; want exactly 3", sends)
	}
	want := []string{
		"💡 <b>Build &lt;thing&gt; &amp; stuff</b>\n<i>Work</i>",
		"💡 <b>(untitled)</b>\n<i>Work</i>",
		"💡 <b>Third</b>",
	}
	for i, w := range want {
		if sends[i] != w {
			t.Errorf("send[%d] = %q; want %q", i, sends[i], w)
		}
	}
	silent := h.fake.sendsSilent()
	if len(silent) != 3 {
		t.Fatalf("silent flags = %v; want 3", silent)
	}
	for i, s := range silent {
		if !s {
			t.Errorf("send[%d] is not silent", i)
		}
	}
	markups := h.fake.sendMarkupJSON
	if len(markups) != 3 {
		t.Fatalf("markup JSONs = %d; want 3", len(markups))
	}
	for i, mj := range markups {
		btns := filesMarkupButtons(t, mj)
		if len(btns) != 1 {
			t.Errorf("send[%d] has %d buttons; want exactly 1", i, len(btns))
			continue
		}
		if btns[0][0] != "▶️ Execute" {
			t.Errorf("send[%d] button text = %q; want ▶️ Execute", i, btns[0][0])
		}
		if len(btns[0][1]) > 64 {
			t.Errorf("send[%d] callback_data is %d bytes; want <= 64", i, len(btns[0][1]))
		}
	}
}

func TestReadIdeasCap15(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	cards := make([]any, 0, 16)
	for i := 0; i < 16; i++ {
		cards = append(cards, map[string]any{"id": fmt.Sprintf("k%02d", i), "title": fmt.Sprintf("Card %02d", i)})
	}
	gw.ideasScript = map[string]any{"sections": []any{
		map[string]any{"title": "Many", "cards": cards},
	}}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	h.fake.setBatches([]string{telegramUpdate(1, 111, "/ideas")})
	sends := waitForSends(t, h, 15)
	if len(sends) != 15 {
		t.Fatalf("sends = %d; want exactly 15", len(sends))
	}
	if strings.Contains(sends[14], "Card 15") {
		t.Errorf("16th card leaked into the sends: %q", sends[14])
	}
	for i, s := range sends {
		if !strings.Contains(s, fmt.Sprintf("Card %02d", i)) {
			t.Errorf("send[%d] = %q; want Card %02d", i, s, i)
		}
	}
}

func TestReadIdeasEmpty(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.ideasScript = map[string]any{}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/ideas")
	if len(sends) != 1 || sends[0] != "No idea cards right now." {
		t.Errorf("sends = %q; want exactly [No idea cards right now.]", sends)
	}
}

func TestReadIdeasGatewayError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.ideasErr = errors.New("marker-ideas-boom")
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/ideas")
	want := "⚠️ Could not run /ideas (gateway error)."
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
}

func TestReadIdeasAuthError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.ideasErr = conn.NewAuthError("expired")
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/ideas")
	if len(sends) != 1 || sends[0] != readLoginExpired {
		t.Errorf("sends = %q; want exactly [%q]", sends, readLoginExpired)
	}
}

// tapIdeaButton renders /ideas through a directly wired Bot and
// taps the button at index idx, returning the harness.
// sessionID, when non-empty, is the chat's current session,
// mapped before the tap is staged.
func tapIdeaButton(t *testing.T, gw *telegramTurnFakeGateway, idx int, sessionID string) *wiredBot {
	t.Helper()
	wb := startWiredBot(t, gw)
	if sessionID != "" {
		if err := wb.store.SetChat(500, telegram.ChatEntry{SessionID: sessionID, Title: "t"}); err != nil {
			t.Fatal(err)
		}
	}
	wb.fake.setBatches([]string{telegramUpdate(1, 111, "/ideas")})
	waitFor(t, "ideas sends", func() bool { return len(wb.fake.sendsSeen()) >= 3 })
	wb.fake.mu.Lock()
	markup := ""
	if idx < len(wb.fake.sendMarkupJSON) {
		markup = wb.fake.sendMarkupJSON[idx]
	}
	wb.fake.mu.Unlock()
	buttons := filesMarkupButtons(t, markup)
	if len(buttons) == 0 {
		t.Fatal("no buttons on the ideas send")
	}
	wb.fake.setBatches([]string{callbackUpdate(2, buttons[0][1], 100)})
	return wb
}

func TestIdeaExecTap(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.ideasScript = ideasFixture()
	wb := tapIdeaButton(t, gw, 0, "sess-9")
	defer wb.cancel()
	// The chat's current session is sess-9: the execute call
	// must carry it, plus the card id in both places.
	waitFor(t, "idea execute call", func() bool { return len(gw.executeCallsSeen()) >= 1 })
	want := "▶️ Muse is working on: <b>Build &lt;thing&gt; &amp; stuff</b>. Replies arrive here when they land."
	// Wait for the working reply BEFORE cancelling: the reply
	// Send runs after callJSON on the cancellable Start ctx,
	// so cancelling on the execute call alone races it (the
	// TestIdeaExecTapAuthError pattern — wait for the reply).
	waitFor(t, "working reply", func() bool {
		for _, s := range wb.fake.sendsSeen() {
			if s == want {
				return true
			}
		}
		return false
	})
	wb.cancel()
	<-wb.done
	calls := gw.executeCallsSeen()
	if len(calls) != 1 {
		t.Fatalf("execute calls = %+v; want exactly 1", calls)
	}
	if calls[0].PathParams["ideaCardId"] != "c1" {
		t.Errorf("PathParams = %v; want ideaCardId c1", calls[0].PathParams)
	}
	if calls[0].Body["ideaCardId"] != "c1" || calls[0].Body["mode"] != "full" || calls[0].Body["session_id"] != "sess-9" {
		t.Errorf("Body = %v; want ideaCardId c1, mode full, session_id sess-9", calls[0].Body)
	}
	sends := wb.fake.sendsSeen()
	found := false
	for _, s := range sends {
		if s == want {
			found = true
		}
	}
	if !found {
		t.Errorf("sends = %q; want the working reply %q", sends, want)
	}
}

func TestIdeaExecTapNoSession(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.ideasScript = ideasFixture()
	wb := tapIdeaButton(t, gw, 0, "")
	defer wb.cancel()
	waitFor(t, "idea execute call", func() bool { return len(gw.executeCallsSeen()) >= 1 })
	wb.cancel()
	<-wb.done
	calls := gw.executeCallsSeen()
	if len(calls) != 1 {
		t.Fatalf("execute calls = %+v; want exactly 1", calls)
	}
	if _, ok := calls[0].Body["session_id"]; ok {
		t.Errorf("Body = %v; want no session_id key for the main chat", calls[0].Body)
	}
}

func TestIdeaExecTapUntitledFallsBackToID(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.ideasScript = ideasFixture()
	wb := tapIdeaButton(t, gw, 1, "")
	defer wb.cancel()
	waitFor(t, "idea execute call", func() bool { return len(gw.executeCallsSeen()) >= 1 })
	want := "▶️ Muse is working on: <b>c2</b>. Replies arrive here when they land."
	// Wait for the working reply before cancelling, as in
	// TestIdeaExecTap: cancelling on the execute call alone
	// races the reply Send on the cancellable Start ctx.
	waitFor(t, "working reply", func() bool {
		for _, s := range wb.fake.sendsSeen() {
			if s == want {
				return true
			}
		}
		return false
	})
	wb.cancel()
	<-wb.done
	calls := gw.executeCallsSeen()
	if len(calls) != 1 || calls[0].PathParams["ideaCardId"] != "c2" {
		t.Fatalf("execute calls = %+v; want exactly 1 for card c2", calls)
	}
	sends := wb.fake.sendsSeen()
	found := false
	for _, s := range sends {
		if s == want {
			found = true
		}
	}
	if !found {
		t.Errorf("sends = %q; want the working reply %q", sends, want)
	}
}

func TestIdeaExecRetapReexecutes(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.ideasScript = ideasFixture()
	wb := tapIdeaButton(t, gw, 0, "")
	defer wb.cancel()
	waitFor(t, "first execute call", func() bool { return len(gw.executeCallsSeen()) >= 1 })
	// Re-tap the same button: the entry is never consumed, so
	// the execute runs again.
	wb.fake.mu.Lock()
	markup := wb.fake.sendMarkupJSON[0]
	wb.fake.mu.Unlock()
	buttons := filesMarkupButtons(t, markup)
	wb.fake.setBatches([]string{callbackUpdate(3, buttons[0][1], 100)})
	waitFor(t, "second execute call", func() bool { return len(gw.executeCallsSeen()) >= 2 })
	wb.cancel()
	<-wb.done
	if n := len(gw.executeCallsSeen()); n != 2 {
		t.Errorf("execute calls = %d; want 2 (re-tap re-executes)", n)
	}
}

func TestIdeaExecTapAuthError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.ideasScript = ideasFixture()
	gw.executeErr = conn.NewAuthError("expired")
	wb := tapIdeaButton(t, gw, 0, "")
	defer wb.cancel()
	waitFor(t, "login-expired reply", func() bool {
		for _, s := range wb.fake.sendsSeen() {
			if s == "🔑 muse.ai login expired. Use /login." {
				return true
			}
		}
		return false
	})
	wb.cancel()
	<-wb.done
}

func TestIdeaExecTapGenericError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.ideasScript = ideasFixture()
	gw.executeErr = errors.New("marker-exec-boom")
	wb := tapIdeaButton(t, gw, 0, "")
	defer wb.cancel()
	waitFor(t, "warning send", func() bool {
		for _, s := range wb.fake.sendsSeen() {
			if strings.HasPrefix(s, "⚠️ ") {
				return true
			}
		}
		return false
	})
	wb.cancel()
	<-wb.done
	for _, s := range wb.fake.sendsSeen() {
		if strings.Contains(s, "marker-exec-boom") {
			t.Errorf("send leaks raw error text: %q", s)
		}
	}
}

func TestReadUsageData(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	seedProfileCookies(t, h)
	sends := sendOnly(t, h, "/usage")
	want := "📊 Pro: ok\nAdditional tokens: none"
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
}

func TestReadUsageEscape(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	seedProfileCookies(t, h)
	h.fake.mu.Lock()
	h.fake.settingsRSC = "0:{\"a\":\"$@1\"}\n1:{\"success\":true,\"subscription\":{\"tier\":{\"name\":\"A<B> & \\\"C\\\"\"},\"usage\":{\"state\":\"ok\"}}}\n"
	h.fake.mu.Unlock()
	sends := sendOnly(t, h, "/usage")
	want := "📊 A&lt;B&gt; &amp; \"C\": ok\nAdditional tokens: none"
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
}

func TestReadUsageGatewayError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	seedProfileCookies(t, h)
	h.fake.mu.Lock()
	h.fake.settingsStatus = http.StatusInternalServerError
	h.fake.mu.Unlock()
	sends := sendOnly(t, h, "/usage")
	want := "⚠️ Could not run /usage (gateway error)."
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
}

func TestReadUsageAuthError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	seedProfileCookies(t, h)
	h.fake.mu.Lock()
	h.fake.settingsStatus = http.StatusUnauthorized
	h.fake.mu.Unlock()
	sends := sendOnly(t, h, "/usage")
	if len(sends) != 1 || sends[0] != readLoginExpired {
		t.Errorf("sends = %q; want exactly [%q]", sends, readLoginExpired)
	}
}

func TestReadWakeData(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	seedProfileCookies(t, h)
	sends := sendOnly(t, h, "/wake")
	want := "⏰ Wake requested: HTTP 200<pre>{\"woke\":true}</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
	bodies := h.fake.wakeBodiesSeen()
	if len(bodies) != 1 {
		t.Fatalf("wake bodies = %v; want exactly 1", bodies)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(bodies[0]), &decoded); err != nil {
		t.Fatalf("wake body %q is not JSON: %v", bodies[0], err)
	}
	if decoded["vm_id"] != "vm-test" || decoded["retry_count"] != float64(0) {
		t.Errorf("wake body = %v; want vm_id vm-test, retry_count 0", decoded)
	}
}

func TestReadWakeEscape(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	seedProfileCookies(t, h)
	h.fake.mu.Lock()
	h.fake.wakeBody = `{"note":"a<b>&c"}`
	h.fake.mu.Unlock()
	sends := sendOnly(t, h, "/wake")
	want := "⏰ Wake requested: HTTP 200<pre>{\"note\":\"a&lt;b&gt;&amp;c\"}</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
}

func TestReadWakeEmptyBody(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	seedProfileCookies(t, h)
	h.fake.mu.Lock()
	h.fake.wakeNoBody = true
	h.fake.mu.Unlock()
	sends := sendOnly(t, h, "/wake")
	want := "⏰ Wake requested: HTTP 200<pre>null</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
}

func TestReadWakeStatus500(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	seedProfileCookies(t, h)
	h.fake.mu.Lock()
	h.fake.wakeStatus = http.StatusInternalServerError
	h.fake.wakeBody = `{"err":"x"}`
	h.fake.mu.Unlock()
	sends := sendOnly(t, h, "/wake")
	want := "⏰ Wake requested: HTTP 500<pre>{\"err\":\"x\"}</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
}

func TestReadWakeAuthError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	seedProfileCookies(t, h)
	h.fake.mu.Lock()
	h.fake.authCheckStatus = http.StatusUnauthorized
	h.fake.mu.Unlock()
	sends := sendOnly(t, h, "/wake")
	if len(sends) != 1 || sends[0] != readLoginExpired {
		t.Errorf("sends = %q; want exactly [%q]", sends, readLoginExpired)
	}
}

func TestReadWakeGenericError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	seedProfileCookies(t, h)
	h.fake.mu.Lock()
	h.fake.wakeDrop = true
	h.fake.mu.Unlock()
	sends := sendOnly(t, h, "/wake")
	want := "⚠️ Could not run /wake (gateway error)."
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
}

func TestReadWakeNoCookies(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	// No cookies seeded: rt.Cookies() fails with the typed
	// cookies_missing error, which is NOT a *conn.AuthError,
	// so dispatch answers the generic line (established
	// contract: only *conn.AuthError maps to login-expired).
	// The reply must not leak the cookies path.
	sends := sendOnly(t, h, "/wake")
	want := "⚠️ Could not run /wake (gateway error)."
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
	if strings.Contains(sends[0], "cookies.txt") {
		t.Errorf("send leaks the cookies path: %q", sends[0])
	}
}

// --- Fix loop 1 (Round-1 review findings) ---

// TestReadGoalBoundary3000Multibyte pins the 3000 gate in
// RUNES, not bytes: a body of exactly 3000 runes built from
// multi-byte chars (5932 bytes) takes the <pre> branch, and
// 3001 runes takes the document branch. A byte-count mutant
// (len(body)) sends a document for the 3000-rune body.
func TestReadGoalBoundary3000Multibyte(t *testing.T) {
	t.Parallel()
	// The dump shape is fixed by construction, as in
	// TestReadGoalBoundary3000: 68 fixed runes + the pad.
	// The pad is U+00E9 (1 rune, 2 bytes in UTF-8, emitted
	// raw: the dump encoder has SetEscapeHTML(false)).
	for _, tc := range []struct {
		name    string
		pad     int
		wantDoc bool
	}{
		{name: "exactly_3000_runes", pad: 2932, wantDoc: false},
		{name: "3001_runes", pad: 2933, wantDoc: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gw := newTelegramTurnFakeGateway()
			gw.goalScript = map[string]any{
				"goal": map[string]any{"status": "active", "title": "Big"},
				"pad":  strings.Repeat("é", tc.pad),
			}
			h, cancel := runReadBot(t, gw)
			defer cancel()
			sends := sendOnly(t, h, "/goal g1")
			if tc.wantDoc {
				head := "🎯 <b>Big</b> [active]\n"
				if len(sends) != 1 || sends[0] != head {
					t.Errorf("sends = %q; want exactly the head send [%q]", sends, head)
				}
				waitFor(t, "goal.json document", func() bool { return len(h.fake.documentsSeen()) >= 1 })
				if docs := h.fake.documentsSeen(); len(docs) != 1 || docs[0].Filename != "goal.json" {
					t.Errorf("documents = %+v; want exactly 1 goal.json", docs)
				}
				return
			}
			if len(sends) != 1 {
				t.Fatalf("sends = %q; want exactly 1", sends)
			}
			if docs := h.fake.documentsSeen(); len(docs) != 0 {
				t.Errorf("documents = %+v; want none at exactly 3000 runes", docs)
			}
			if !strings.Contains(sends[0], "<pre>") {
				t.Errorf("send = %q; want the <pre> branch", sends[0])
			}
			// Prove the body really is 3000 runes AND more
			// than 3000 bytes: strip the head and the <pre>
			// tags and unescape, as in
			// TestReadGoalBoundary3000.
			head := "🎯 <b>Big</b> [active]\n"
			rest := strings.TrimPrefix(sends[0], head)
			rest = strings.TrimPrefix(rest, "<pre>")
			rest = strings.TrimSuffix(rest, "</pre>")
			rest = strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">").Replace(rest)
			if n := len([]rune(rest)); n != 3000 {
				t.Errorf("body is %d runes; want exactly 3000", n)
			}
			if n := len(rest); n <= 3000 {
				t.Errorf("body is %d bytes; want over 3000 (multi-byte pad)", n)
			}
		})
	}
}

// TestIdeaExecTapUsesCurrentSession pins the tap-time session
// read: render /ideas with sess-A mapped, switch the store to
// sess-B, then tap — the execute must carry sess-B. A mutant
// capturing the session into the registry entry at render
// time executes with the stale sess-A.
func TestIdeaExecTapUsesCurrentSession(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.ideasScript = ideasFixture()
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	if err := wb.store.SetChat(500, telegram.ChatEntry{SessionID: "sess-A", Title: "t"}); err != nil {
		t.Fatal(err)
	}
	wb.fake.setBatches([]string{telegramUpdate(1, 111, "/ideas")})
	waitFor(t, "ideas sends", func() bool { return len(wb.fake.sendsSeen()) >= 3 })
	// Switch sessions AFTER the render, BEFORE the tap.
	if err := wb.store.SetChat(500, telegram.ChatEntry{SessionID: "sess-B", Title: "t"}); err != nil {
		t.Fatal(err)
	}
	wb.fake.mu.Lock()
	markup := wb.fake.sendMarkupJSON[0]
	wb.fake.mu.Unlock()
	buttons := filesMarkupButtons(t, markup)
	if len(buttons) == 0 {
		t.Fatal("no buttons on the ideas send")
	}
	wb.fake.setBatches([]string{callbackUpdate(2, buttons[0][1], 100)})
	waitFor(t, "idea execute call", func() bool { return len(gw.executeCallsSeen()) >= 1 })
	want := "▶️ Muse is working on: <b>Build &lt;thing&gt; &amp; stuff</b>. Replies arrive here when they land."
	waitFor(t, "working reply", func() bool {
		for _, s := range wb.fake.sendsSeen() {
			if s == want {
				return true
			}
		}
		return false
	})
	wb.cancel()
	<-wb.done
	calls := gw.executeCallsSeen()
	if len(calls) != 1 {
		t.Fatalf("execute calls = %+v; want exactly 1", calls)
	}
	if calls[0].Body["session_id"] != "sess-B" {
		t.Errorf("Body = %v; want session_id sess-B (the session at tap time)", calls[0].Body)
	}
}

// TestReadWakeLongEscapeOrder pins the /wake slice-then-escape
// order AND the 800-rune bound: a 911-rune dumped body rich in
// `<` must yield the first 800 runes escaped (791 `&lt;`
// entities). Escape-before-slice truncates mid-entity (197
// entities + a dangling `&lt`), and no-truncation yields all
// 900 — both mutants fail this exact expectation.
func TestReadWakeLongEscapeOrder(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	seedProfileCookies(t, h)
	h.fake.mu.Lock()
	h.fake.wakeBody = `{"note":"` + strings.Repeat("<", 900) + `"}`
	h.fake.mu.Unlock()
	sends := sendOnly(t, h, "/wake")
	// Dumped body: `{"note":"` (9 runes) + 900 `<` + `"}` =
	// 911 runes; sliced to 800 runes, then escaped: the 9
	// literal runes + 791 `&lt;` entities, closing quote cut.
	want := "⏰ Wake requested: HTTP 200<pre>{\"note\":\"" + strings.Repeat("&lt;", 791) + "</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("sends = %q; want exactly [%q]", sends, want)
	}
	if n := strings.Count(sends[0], "&lt;"); n != 791 {
		t.Errorf("send has %d &lt; entities; want 791", n)
	}
}

// TestReadGoalsHostileStatus pins escaping of the status
// field: a status carrying markup must render escaped, like
// the title and id already pinned by TestReadGoalsData.
func TestReadGoalsHostileStatus(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.goalsScript = map[string]any{"goals": []any{
		map[string]any{"id": "g1", "title": "T", "status": "a<b>&c"},
	}}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendOnly(t, h, "/goals")
	want := "🎯 <b>Goals</b>\n• T [a&lt;b&gt;&amp;c] <code>g1</code>\n\n/goal &lt;id&gt; for details"
	if len(sends) != 1 || sends[0] != want {
		t.Errorf("send = %q; want %q", sends[0], want)
	}
}

// runReadBotWithLog starts the harness like runTelegramBot but
// with the bot logger writing into logBuf, so a test can
// assert on dispatch log lines. The shared harness builds Env
// without a Logger (rt.Logger("telegram") applies);
// replicating its setup here is the least invasive capture
// seam — no production change, no global slog.Default swap.
func runReadBotWithLog(t *testing.T, gw *telegramTurnFakeGateway, logBuf *bytes.Buffer) (*telegramBotHarness, func()) {
	t.Helper()
	fake := &cmdFakeTelegram{batches: []string{}}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	t.Cleanup(srv.Close)
	fakeAddr := srv.Listener.Addr().String()
	dialFake := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, fakeAddr)
	}
	fakeClient := &http.Client{Transport: &http.Transport{
		Proxy:       nil,
		DialContext: dialFake,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialFake(ctx, network, addr)
		},
	}}
	home, configFile := testHome(t, telegramTestConfig())
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	env := &Env{Stdout: &strings.Builder{}, Stderr: &strings.Builder{}, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile}), Logger: logger}
	muse := conn.New(func(context.Context, conn.Config) (conn.Gateway, error) { return gw, nil })
	env.BuildRuntime = func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, env *Env) (*Runtime, error) {
		prof.VMID = "vm-test"
		return &Runtime{Profile: prof, Muse: muse, httpClientOverride: fakeClient}, nil
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	codeCh := make(chan int, 1)
	done := make(chan struct{})
	go func() {
		codeCh <- Run(ctx, []string{"telegram", "run"}, env)
		close(done)
	}()
	_ = codeCh
	h := &telegramBotHarness{fake: fake, gw: gw, homeDir: home}
	cancel := func() {
		cancelFn()
		<-done
		drainTurns(fake)
	}
	return h, cancel
}

// TestDispatchLogHasNoCookiesPath (B1) feeds the missing/empty
// cookie-file error through the REAL dispatch path and asserts
// the captured dispatch log carries the auth class but no
// absolute cookies path. The send stays the exact generic
// sentence. Both dispatch-routed rt.Cookies() callers (/wake,
// /usage) and both failure variants (missing file, empty
// file) are covered: the fix is in typedAuthError's
// LogSummary, shared by all of them.
func TestDispatchLogHasNoCookiesPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		command string
		empty   bool // empty cookies file vs missing file
	}{
		{name: "wake/missing", command: "/wake"},
		{name: "wake/empty", command: "/wake", empty: true},
		{name: "usage/missing", command: "/usage"},
		{name: "usage/empty", command: "/usage", empty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gw := newTelegramTurnFakeGateway()
			var logBuf bytes.Buffer
			h, cancel := runReadBotWithLog(t, gw, &logBuf)
			defer cancel()
			if tc.empty {
				dir := filepath.Join(h.homeDir, "profiles", "muse01")
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "cookies.txt"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			sends := sendOnly(t, h, tc.command)
			want := "⚠️ Could not run " + tc.command + " (gateway error)."
			if len(sends) != 1 || sends[0] != want {
				t.Errorf("sends = %q; want exactly [%q]", sends, want)
			}
			// The dispatch Warn line is logged before the
			// send, so it is in the buffer by now.
			absPath := filepath.Join(h.homeDir, "profiles", "muse01", "cookies.txt")
			found := false
			for _, line := range strings.Split(logBuf.String(), "\n") {
				if !strings.Contains(line, "telegram command failed") {
					continue
				}
				found = true
				if strings.Contains(line, h.homeDir) || strings.Contains(line, absPath) || strings.Contains(line, "cookies.txt") {
					t.Errorf("dispatch log line carries the cookies path: %q", line)
				}
				if !strings.Contains(line, "cookies_missing") {
					t.Errorf("dispatch log line = %q; want the cookies_missing class", line)
				}
			}
			if !found {
				t.Errorf("no dispatch failure log line in logs = %q", logBuf.String())
			}
		})
	}
}

// TestCookiesMissingSummaryHasNoPath pins the B1 fix at the
// producer: requireCookiesFile's missing/empty/stat errors
// render (via SummarizeErr, the dispatch/CLI rendering) as
// the class-prefixed, path-free message. The messages embed
// no absolute path — there is no LogSummary method on
// typedAuthError (a wrapper-level summary would shadow the
// inner SafeString rendering pinned by
// TestClassifyErrorTwelveShapes).
func TestCookiesMissingSummaryHasNoPath(t *testing.T) {
	t.Parallel()
	absDir := filepath.Join(t.TempDir(), "profiles", "muse01")
	absPath := filepath.Join(absDir, "cookies.txt")
	prof := &profile.Profile{CookiesFile: absPath}
	// Missing file.
	err := requireCookiesFile(prof)
	if err == nil {
		t.Fatal("requireCookiesFile(nil file) = nil; want cookies_missing")
	}
	for _, text := range []string{logging.SummarizeErr(err), err.Error()} {
		if strings.Contains(text, absDir) || strings.Contains(text, absPath) {
			t.Errorf("missing-file rendering %q carries the absolute path", text)
		}
		if !strings.Contains(text, "cookies_missing") {
			t.Errorf("missing-file rendering %q lacks the cookies_missing class", text)
		}
	}
	// Empty file.
	if err := os.MkdirAll(absDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err = requireCookiesFile(prof)
	if err == nil {
		t.Fatal("requireCookiesFile(empty file) = nil; want cookies_missing")
	}
	if got := logging.SummarizeErr(err); strings.Contains(got, absPath) || !strings.Contains(got, "cookies_missing") {
		t.Errorf("empty-file summary = %q; want class only, no path", got)
	}
}
