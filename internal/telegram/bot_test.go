// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

// Bot behaviour tests against the fake Telegram server: polling,
// allowlist, dedupe, per-chat order, recover, send/edit surface,
// 429 retry, callbacks, and token secrecy. Expected values are
// literals from the Python survey; server observations (method,
// form fields, offsets) are the assertions.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBotConstructionCallsGetMeOnce(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	_ = tb
	if got := srv.count("getMe"); got != 1 {
		t.Fatalf("getMe calls = %d; want 1 at construction (no SkipGetMe)", got)
	}
	if got := srv.count("getUpdates"); got != 0 {
		t.Fatalf("getUpdates calls = %d before Start; want 0", got)
	}
}

func TestBotConstructionValidation(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	// Bad token shape: error, no request at all.
	if _, err := New(Settings{Token: "not-a-token", AllowedUserIDs: []int64{1}, HTTPClient: fakeHTTPClient(), ServerURL: srv.url()}); err == nil {
		t.Error("New(bad token) = nil; want error")
	}
	if got := srv.count("getMe"); got != 0 {
		t.Errorf("getMe calls after failed New = %d; want 0 (no token use on validation failure)", got)
	}
	// Empty allowlist: fail-closed, no request.
	if _, err := New(Settings{Token: fakeToken, HTTPClient: fakeHTTPClient(), ServerURL: srv.url()}); err == nil {
		t.Error("New(empty allowlist) = nil; want error")
	}
	// Nil client: fail-closed.
	if _, err := New(Settings{Token: fakeToken, AllowedUserIDs: []int64{1}, ServerURL: srv.url()}); err == nil {
		t.Error("New(nil client) = nil; want error")
	}
	// A client whose transport may consult env proxies is refused:
	// nil Transport (stdlib default) and ProxyFromEnvironment both.
	if _, err := New(Settings{Token: fakeToken, AllowedUserIDs: []int64{1}, HTTPClient: &http.Client{}, ServerURL: srv.url()}); err == nil {
		t.Error("New(bare client, nil Transport) = nil; want error (env-proxy inheritance)")
	}
	if _, err := New(Settings{Token: fakeToken, AllowedUserIDs: []int64{1}, HTTPClient: &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}, ServerURL: srv.url()}); err == nil {
		t.Error("New(env-proxy transport) = nil; want error")
	}
	if got := srv.count("getMe"); got != 0 {
		t.Errorf("getMe calls after rejected constructions = %d; want 0", got)
	}
}

func TestBotStartPollsAndHandlesMessage(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	srv.enqueueUpdates(messageUpdate(10, 500, 111, "hello"))
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "message handled", func() bool { return len(tb.handler.recorded()) == 1 })
	// Offset advances: first poll offset=1, next poll offset=11
	// (last update_id 10 + 1), as the library computes it.
	waitFor(t, "second poll with offset 11", func() bool {
		for _, c := range srv.callsOf("getUpdates") {
			if c.Form["offset"] == "11" {
				return true
			}
		}
		return false
	})
	if err := stopBot(t, cancel, done); !errors.Is(err, context.Canceled) {
		t.Errorf("Start after cancel = %v; want context.Canceled", err)
	}
	calls := tb.handler.recorded()
	if calls[0].ChatID != 500 || calls[0].UserID != 111 || calls[0].Text != "hello" {
		t.Errorf("handler call = %+v; want chat 500 user 111 text hello", calls[0])
	}
	// No second GetMe: startup calls it once, polling never does.
	if got := srv.count("getMe"); got != 1 {
		t.Errorf("getMe calls = %d; want 1", got)
	}
	// allowed_updates restricted to message + callback_query.
	for _, c := range srv.callsOf("getUpdates") {
		if !strings.Contains(c.Form["allowed_updates"], "message") || !strings.Contains(c.Form["allowed_updates"], "callback_query") {
			t.Errorf("getUpdates allowed_updates = %q; want message + callback_query", c.Form["allowed_updates"])
		}
	}
}

func TestBotAllowlistSilentDrop(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	srv.enqueueUpdates(
		messageUpdate(20, 500, 999, "stranger"),
		messageUpdateNoSender(21, 500, "no sender"),
		messageUpdate(22, 500, 111, "friend"),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "allowed message handled", func() bool { return len(tb.handler.recorded()) == 1 })
	// Give the loop a beat to (not) handle the dropped updates.
	time.Sleep(100 * time.Millisecond)
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	if got := tb.handler.recorded(); len(got) != 1 || got[0].Text != "friend" {
		t.Errorf("handler calls = %+v; want only the allowlisted message", got)
	}
	if got := srv.count("sendMessage"); got != 0 {
		t.Errorf("sendMessage calls = %d for dropped updates; want 0 (silent drop, no reply)", got)
	}
}

func TestBotDedupe(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	dup := messageUpdate(30, 500, 111, "once")
	srv.enqueueUpdates(dup)
	srv.enqueueUpdates(dup) // redelivery: same update_id again
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "update handled", func() bool { return len(tb.handler.recorded()) == 1 })
	time.Sleep(150 * time.Millisecond)
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	if got := len(tb.handler.recorded()); got != 1 {
		t.Errorf("handler calls = %d for a twice-delivered update; want 1 (update_id dedupe)", got)
	}
}

func TestBotPerChatOrder(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	// Slow handler: cross-chat work must still preserve
	// per-chat order.
	tb.handler.delay = 30 * time.Millisecond
	srv.enqueueUpdates(
		messageUpdate(40, 500, 111, "a1"),
		messageUpdate(41, 600, 111, "b1"),
		messageUpdate(42, 500, 111, "a2"),
		messageUpdate(43, 600, 111, "b2"),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "all messages handled", func() bool { return len(tb.handler.recorded()) == 4 })
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	calls := tb.handler.recorded()
	pos := map[string]int{}
	for i, c := range calls {
		pos[c.Text] = i
	}
	if pos["a1"] > pos["a2"] || pos["b1"] > pos["b2"] {
		t.Errorf("per-chat order broken: %v", calls)
	}
}

func TestBotRecoverPerUpdate(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	// The panic value carries the fixture token: no log line may
	// ever contain it.
	tb.handler.panicErr = errors.New("boom " + fakeToken)
	tb.handler.panicOnce = true
	srv.enqueueUpdates(
		messageUpdate(50, 500, 111, "first"),
		messageUpdate(51, 500, 111, "second"),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "second message handled after panic", func() bool { return len(tb.handler.recorded()) == 2 })
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	if got := len(tb.handler.recorded()); got != 2 {
		t.Fatalf("handler calls = %d; want 2 (panic in one update must not kill the loop)", got)
	}
	if strings.Contains(tb.logBuf.String(), fakeToken) {
		t.Errorf("log output contains the fixture token after a token-bearing panic:\n%s", tb.logBuf.String())
	}
}

func TestBotSendSplitAndMarkup(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	// Build a two-piece text: paragraph break at 2000.
	text := strings.Repeat("a", 2000) + "\n\n" + strings.Repeat("b", 2000)
	reg := NewCallbackRegistry()
	mk := ApprovalMarkup(Approval{ID: "a"}, ResumeTriple{}, reg)
	lastID, err := tb.bot.Send(context.Background(), 500, text, SendOptions{Markup: mk, ReplyTo: 77, Silent: true})
	if err != nil {
		t.Fatal(err)
	}
	calls := srv.callsOf("sendMessage")
	if len(calls) != 2 {
		t.Fatalf("sendMessage calls = %d; want 2 pieces", len(calls))
	}
	if lastID != 101 {
		t.Errorf("last message id = %d; want 101 (fake ids start at 100)", lastID)
	}
	if calls[0].Form["text"] != strings.Repeat("a", 2000) || calls[1].Form["text"] != strings.Repeat("b", 2000) {
		t.Errorf("pieces = %q / %q", calls[0].Form["text"][:10], calls[1].Form["text"][:10])
	}
	if _, ok := calls[0].Form["reply_markup"]; ok {
		t.Error("first piece carries reply_markup; want markup only on the last piece")
	}
	if _, ok := calls[1].Form["reply_markup"]; !ok {
		t.Error("last piece lacks reply_markup")
	}
	for i, c := range calls {
		// The library encodes ReplyParameters as JSON in the
		// reply_parameters field; assert the id appears.
		if !strings.Contains(c.Form["reply_parameters"], "77") {
			t.Errorf("piece %d reply_parameters = %q; want message 77", i, c.Form["reply_parameters"])
		}
		if c.Form["disable_notification"] != "true" {
			t.Errorf("piece %d disable_notification = %q; want true (silent)", i, c.Form["disable_notification"])
		}
		if !strings.Contains(c.Form["link_preview_options"], "true") {
			t.Errorf("piece %d link_preview_options = %q; want previews disabled", i, c.Form["link_preview_options"])
		}
	}
}

func TestBotSendHTMLFallback(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	srv.sendFailures = []scriptedFailure{{Code: 400, Desc: "Bad Request: can't parse entities: unsupported start tag"}}
	_, err := tb.bot.Send(context.Background(), 500, "<b>bold", SendOptions{})
	if err != nil {
		t.Fatalf("Send with parse error = %v; want plain-text fallback success", err)
	}
	calls := srv.callsOf("sendMessage")
	if len(calls) != 2 {
		t.Fatalf("sendMessage calls = %d; want 2 (HTML attempt + plain fallback)", len(calls))
	}
	if calls[0].Form["parse_mode"] != "HTML" {
		t.Errorf("first attempt parse_mode = %q; want HTML", calls[0].Form["parse_mode"])
	}
	if calls[1].Form["parse_mode"] != "" {
		t.Errorf("fallback parse_mode = %q; want absent (plain text)", calls[1].Form["parse_mode"])
	}
	// A non-parse 400 propagates with no fallback.
	srv.sendFailures = []scriptedFailure{{Code: 400, Desc: "Bad Request: chat not found"}}
	if _, err := tb.bot.Send(context.Background(), 500, "hi", SendOptions{}); err == nil {
		t.Error("Send(chat not found) = nil; want error, no fallback")
	}
	if got := srv.count("sendMessage"); got != 3 {
		t.Errorf("sendMessage calls = %d; want 3 (no fallback attempt for non-parse errors)", got)
	}
	// An HTML body over 4096 chars skips the HTML attempt
	// entirely. Send splits first (3800), so the >4096 branch
	// is reachable through Edit, which never splits.
	srv.sendFailures = nil
	longHTML := "<b>" + strings.Repeat("x", 5000) + "</b>"
	if err := tb.bot.Edit(context.Background(), 500, 7, longHTML, nil, HTMLModeHTML); err != nil {
		t.Fatal(err)
	}
	edits := srv.callsOf("editMessageText")
	last := edits[len(edits)-1]
	if last.Form["parse_mode"] != "" {
		t.Errorf("oversize edit parse_mode = %q; want plain path only", last.Form["parse_mode"])
	}
	if strings.Contains(last.Form["text"], "<b>") || len([]rune(last.Form["text"])) != TextLimit {
		t.Errorf("oversize plain text len=%d contains tags=%v; want 4096 tag-stripped runes", len([]rune(last.Form["text"])), strings.Contains(last.Form["text"], "<b>"))
	}
}

func TestBotSendMarkdown(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	_, err := tb.bot.SendMD(context.Background(), 500, "**bold** and `code`", SendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	calls := srv.callsOf("sendMessage")
	if len(calls) != 1 {
		t.Fatalf("sendMessage calls = %d; want 1", len(calls))
	}
	if calls[0].Form["parse_mode"] != "HTML" || calls[0].Form["text"] != "<b>bold</b> and <code>code</code>" {
		t.Errorf("markdown send = parse_mode %q text %q", calls[0].Form["parse_mode"], calls[0].Form["text"])
	}
}

func TestBotEdit(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	ctx := context.Background()
	if err := tb.bot.Edit(ctx, 500, 100, "new *text*", nil, HTMLModeMarkdown); err != nil {
		t.Fatal(err)
	}
	calls := srv.callsOf("editMessageText")
	if len(calls) != 1 || calls[0].Form["message_id"] != "100" || calls[0].Form["text"] != "new *text*" {
		t.Errorf("editMessageText calls = %+v", calls)
	}
	// "message is not modified" is swallowed.
	srv.editFailures = []scriptedFailure{{Code: 400, Desc: "Bad Request: message is not modified"}}
	if err := tb.bot.Edit(ctx, 500, 100, "same", nil, HTMLModePlain); err != nil {
		t.Errorf("Edit(not modified) = %v; want nil", err)
	}
	// Other edit errors propagate.
	srv.editFailures = []scriptedFailure{{Code: 400, Desc: "Bad Request: message to edit not found"}}
	if err := tb.bot.Edit(ctx, 500, 100, "x", nil, HTMLModePlain); err == nil {
		t.Error("Edit(not found) = nil; want error")
	}
	// EditPlain swallows every error.
	srv.editFailures = []scriptedFailure{{Code: 500, Desc: "Internal Server Error"}}
	if err := tb.bot.EditPlain(ctx, 500, 100, "stream"); err != nil {
		t.Errorf("EditPlain = %v; want nil (stream edits never fail a turn)", err)
	}
	// Edit returning JSON true (nil *Message) is success.
	srv.editFailures = nil
	srv.editTextTrue = true
	if err := tb.bot.Edit(ctx, 500, 100, "x", nil, HTMLModePlain); err != nil {
		t.Errorf("Edit(result:true) = %v; want nil", err)
	}
}

func TestBotSend429Retry(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	ctx := context.Background()
	// One 429 with retry_after=1: retry once after 1.5s (recorded
	// sleep, no real wait), then success.
	srv.sendFailures = []scriptedFailure{{Code: 429, Desc: "Too Many Requests", RetryAfter: 1}}
	if _, err := tb.bot.Send(ctx, 500, "hi", SendOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := srv.count("sendMessage"); got != 2 {
		t.Errorf("sendMessage calls = %d; want 2 (one retry)", got)
	}
	sleeps := tb.recordedSleeps()
	if len(sleeps) != 1 || sleeps[0] != 1500*time.Millisecond {
		t.Errorf("sleeps = %v; want [1.5s] (retry_after + 0.5s)", sleeps)
	}
	// retry_after > 60: no retry.
	srv.sendFailures = []scriptedFailure{{Code: 429, Desc: "Too Many Requests", RetryAfter: 61}}
	if _, err := tb.bot.Send(ctx, 500, "hi", SendOptions{}); err == nil {
		t.Error("Send(429 retry_after 61) = nil; want error")
	}
	// Three consecutive 429s: 3 attempts total (2 retries), then error.
	srv.sendFailures = []scriptedFailure{
		{Code: 429, Desc: "Too Many Requests", RetryAfter: 1},
		{Code: 429, Desc: "Too Many Requests", RetryAfter: 1},
		{Code: 429, Desc: "Too Many Requests", RetryAfter: 1},
	}
	if _, err := tb.bot.Send(ctx, 500, "hi", SendOptions{}); err == nil {
		t.Error("Send(persistent 429) = nil; want error after retries exhausted")
	}
}

func TestBotCallbackDecide(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	after := int64(42)
	mk := tb.bot.ApprovalMarkup(Approval{ID: "appr-1", Options: []string{"allow_once", "deny"}}, ResumeTriple{SessionID: "s1", Title: "t", AfterSeq: &after})
	data := mk.InlineKeyboard[0][0].CallbackData // Allow once button
	srv.enqueueUpdates(callbackUpdate(60, 111, 500, 100, data, "cq-1"))
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "decide handled", func() bool { return len(tb.decider.recorded()) == 1 })
	waitFor(t, "resume called", func() bool { return len(tb.recordedResumes()) == 1 })
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	// Answer first, no text for a known button.
	answers := srv.callsOf("answerCallbackQuery")
	if len(answers) != 1 || answers[0].Form["callback_query_id"] != "cq-1" || answers[0].Form["text"] != "" {
		t.Errorf("answerCallbackQuery calls = %+v; want one silent answer", answers)
	}
	calls := tb.decider.recorded()
	if calls[0] != (decideCall{ID: "appr-1", Decision: "allow_once"}) {
		t.Errorf("decider calls = %+v", calls)
	}
	// Confirmation message with the label + approval id.
	sends := srv.callsOf("sendMessage")
	found := false
	for _, c := range sends {
		if strings.Contains(c.Form["text"], "✅ Allowed once") && strings.Contains(c.Form["text"], "appr-1") {
			found = true
		}
	}
	if !found {
		t.Errorf("confirmation send not found in %+v", sends)
	}
	// Buttons cleared with an empty markup edit.
	if got := srv.count("editMessageReplyMarkup"); got != 1 {
		t.Errorf("editMessageReplyMarkup calls = %d; want 1 (clear buttons)", got)
	}
	resumes := tb.recordedResumes()
	if resumes[0].SessionID != "s1" || resumes[0].Title != "t" || resumes[0].AfterSeq != 42 {
		t.Errorf("resume = %+v", resumes[0])
	}
}

func TestBotCallbackExpiredAndStranger(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	srv.enqueueUpdates(
		callbackUpdate(70, 111, 500, 100, "c:nosuchtoken", "cq-exp"),
		callbackUpdate(71, 999, 500, 100, "c:alsono", "cq-stranger"),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "expired answer sent", func() bool { return srv.count("answerCallbackQuery") == 1 })
	time.Sleep(100 * time.Millisecond)
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	answers := srv.callsOf("answerCallbackQuery")
	if len(answers) != 1 {
		t.Fatalf("answerCallbackQuery calls = %d; want 1 (expired only; stranger gets nothing)", len(answers))
	}
	if answers[0].Form["text"] != "This button expired; run the command again." {
		t.Errorf("expired answer text = %q", answers[0].Form["text"])
	}
	if got := len(tb.decider.recorded()); got != 0 {
		t.Errorf("decider calls = %d; want 0", got)
	}
	if got := srv.count("sendMessage"); got != 0 {
		t.Errorf("sendMessage calls = %d; want 0", got)
	}
}

func TestBotCallbackDecideActiveTurnBlocksResume(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	after := int64(7)
	mk := tb.bot.ApprovalMarkup(Approval{ID: "appr-9"}, ResumeTriple{SessionID: "s", Title: "t", AfterSeq: &after})
	data := mk.InlineKeyboard[0][0].CallbackData
	tb.bot.BeginTurn(500)
	srv.enqueueUpdates(callbackUpdate(80, 111, 500, 100, data, "cq-1"))
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "decide handled", func() bool { return len(tb.decider.recorded()) == 1 })
	time.Sleep(100 * time.Millisecond)
	if got := len(tb.recordedResumes()); got != 0 {
		t.Errorf("resumes = %d with an active turn; want 0", got)
	}
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
}

func TestBotApproveAll(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, func(s *Settings) {
		s.Pending = func(context.Context) ([]Approval, error) {
			return []Approval{
				{ID: "appr-f", Title: "Forever one", Options: []string{"allow_always"}},
				{ID: "appr-o", Title: "Once one", Options: []string{"allow_once"}},
			}, nil
		}
	})
	mk := tb.bot.ApproveAllMarkup()
	data := mk.InlineKeyboard[0][0].CallbackData
	srv.enqueueUpdates(callbackUpdate(90, 111, 500, 100, data, "cq-1"))
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "approve-all handled", func() bool { return len(tb.decider.recorded()) == 1 })
	// The confirmation send follows the decide; wait for it
	// before stopping, or cancellation can abort it mid-flight.
	waitFor(t, "approve-all confirmation sent", func() bool { return srv.count("sendMessage") >= 1 })
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	calls := tb.decider.recorded()
	if calls[0] != (decideCall{ID: "appr-f", Decision: "allow_always"}) {
		t.Errorf("decider calls = %+v; want only the forever-offering approval", calls)
	}
	sends := srv.callsOf("sendMessage")
	found := false
	for _, c := range sends {
		if strings.Contains(c.Form["text"], "Forever one") {
			found = true
		}
	}
	if !found {
		t.Errorf("approve-all confirmation not found in %+v", sends)
	}
	if got := srv.count("editMessageReplyMarkup"); got != 0 {
		t.Errorf("editMessageReplyMarkup calls = %d; approve-all clears no markup", got)
	}
}

func TestBotEnvProxyIgnoredAndOtherServerUntouched(t *testing.T) {
	// NOT t.Parallel: t.Setenv forbids parallel tests.
	// Counting proxy: every request through it is recorded.
	var proxyHits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)

	other := newFakeTelegramServer(t)
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	_ = other
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "polling happened", func() bool { return srv.count("getUpdates") >= 1 })
	if _, err := tb.bot.Send(ctx, 500, "hi", SendOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	if got := proxyHits.Load(); got != 0 {
		t.Errorf("env proxy saw %d requests; want 0 (Proxy: nil transport)", got)
	}
	if got := other.count("getMe"); got != 0 {
		t.Errorf("other server saw %d getMe calls; bot must use only its injected client", got)
	}
	// No request ever went to a /file/ URL (no downloads in item 4).
	for _, c := range srv.callsOf("bad-path") {
		_ = c
	}
	if got := srv.count("bad-path"); got != 0 {
		t.Errorf("bad-path calls = %d; every call must be /bot<token>/<method>", got)
	}
}

func TestBotTokenAbsenceHostileServer(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	// Hostile getUpdates body: invalid JSON embedding the token.
	srv.getUpdatesGarbage = true
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	// Let the hostile poll cycle through the errors handler.
	time.Sleep(300 * time.Millisecond)
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	if strings.Contains(tb.logBuf.String(), fakeToken) {
		t.Errorf("log output contains the fixture token after a hostile server body:\n%s", tb.logBuf.String())
	}
	// The token must also be absent from every error the bot
	// returns to a caller on the hostile path.
	srv.sendFailures = []scriptedFailure{{Code: 400, Desc: "Bad Request: token " + fakeToken + " rejected"}}
	if _, err := tb.bot.Send(context.Background(), 500, "hi", SendOptions{}); err != nil {
		if strings.Contains(err.Error(), fakeToken) {
			t.Errorf("Send error contains the token: %v", err)
		}
	} else {
		t.Error("Send(hostile description) = nil; want error")
	}
}
