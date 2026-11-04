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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/go-telegram/bot"
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

func TestBotSecondStartErrors(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startBot(t, tb.bot, ctx)
	// Wait until the first Start is actually polling: the
	// started flag is set by whichever Start wins the race,
	// and calling the second Start before the first runs
	// would let the second one become the poller.
	waitFor(t, "first Start polling", func() bool { return srv.count("getUpdates") >= 1 })
	// A second Start on the same bot must fail closed
	// instead of double-polling (one poller per token).
	if err := tb.bot.Start(ctx); err == nil || !strings.Contains(err.Error(), "already started") {
		t.Errorf("second Start = %v; want the already-started error", err)
	}
	if err := stopBot(t, cancel, done); !errors.Is(err, context.Canceled) {
		t.Errorf("first Start after cancel = %v; want context.Canceled", err)
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
		t.Errorf("log output contains the fixture token after a token-bearing panic (log buffer not printed: it may carry secrets)")
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
	// Pin the attempt count: 2 + 1 + 3 = 6 sendMessage calls,
	// and 1 + 0 + 2 = 3 recorded sleeps.
	if got := srv.count("sendMessage"); got != 6 {
		t.Errorf("sendMessage calls = %d; want 6 (2 + 1 + 3 attempts)", got)
	}
	if sleeps := tb.recordedSleeps(); len(sleeps) != 3 {
		t.Errorf("sleeps = %v; want 3 (1 + 0 + 2 retries)", sleeps)
	}
}

func TestBotSend429RetrySleepRespectsCancel(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	// Default timer-based sleep (no recorder): the retry pause
	// is real, so cancellation mid-pause must cut it short
	// instead of waiting out the full retry_after.
	tb := newTestBot(t, srv, func(s *Settings) { s.Sleep = nil })
	srv.sendFailures = []scriptedFailure{{Code: 429, Desc: "Too Many Requests", RetryAfter: 60}}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := tb.bot.Send(ctx, 500, "hi", SendOptions{})
		errCh <- err
	}()
	// Wait until the 429 was served and the retry pause began.
	deadline := time.Now().Add(5 * time.Second)
	for srv.count("sendMessage") < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.count("sendMessage") < 1 {
		t.Fatal("no sendMessage attempt served; cannot prove the retry pause began")
	}
	start := time.Now()
	cancel()
	select {
	case err := <-errCh:
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("Send returned after %v; want < 5s (must not wait out the 60s retry_after)", elapsed)
		}
		if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), context.Canceled.Error()) {
			t.Errorf("Send error = %v; want a cancellation error (scrubErr returns the cancellation as text, not the chain)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Send did not return within 10s of cancel; retry pause ignored ctx cancellation")
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

func TestDecideOncePerIDLocking(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	enteredA := make(chan struct{})
	releaseA := make(chan struct{})
	var mu sync.Mutex
	var order []string
	tb.bot.decider = DeciderFunc(func(_ context.Context, id, _ string) error {
		if id == "A" {
			close(enteredA)
			<-releaseA
		}
		// Recorded at completion: B must complete while A is
		// still blocked, so the completion order is [B A].
		mu.Lock()
		order = append(order, id)
		mu.Unlock()
		return nil
	})
	ctx := context.Background()
	aDone := make(chan bool, 1)
	go func() {
		ok, err := tb.bot.decideOnce(ctx, "A", "allow_once")
		if err != nil {
			t.Errorf("decideOnce(A) error = %v", err)
		}
		aDone <- ok
	}()
	select {
	case <-enteredA:
	case <-time.After(5 * time.Second):
		t.Fatal("decideOnce(A) never entered the decider")
	}
	// B must decide WITHOUT waiting for A's release: no
	// head-of-line blocking across approval ids.
	bDone := make(chan bool, 1)
	go func() {
		ok, err := tb.bot.decideOnce(ctx, "B", "deny")
		if err != nil {
			t.Errorf("decideOnce(B) error = %v", err)
		}
		bDone <- ok
	}()
	select {
	case ok := <-bDone:
		if !ok {
			t.Error("decideOnce(B) = false; want true (first decision for B)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("decideOnce(B) blocked behind decideOnce(A)")
	}
	close(releaseA)
	select {
	case ok := <-aDone:
		if !ok {
			t.Error("decideOnce(A) = false; want true (first decision for A)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("decideOnce(A) did not return after release")
	}
	mu.Lock()
	got := append([]string{}, order...)
	mu.Unlock()
	if len(got) != 2 || got[0] != "B" || got[1] != "A" {
		t.Errorf("decider order = %v; want [B A] (B completed while A was blocked)", got)
	}
	// A second call for A is a no-op: no second RPC.
	if ok, err := tb.bot.decideOnce(ctx, "A", "allow_once"); err != nil || ok {
		t.Errorf("decideOnce(A) again = (%v, %v); want (false, nil)", ok, err)
	}
	// Concurrent same-id calls single-flight: exactly one RPC.
	var wg sync.WaitGroup
	results := make([]bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, err := tb.bot.decideOnce(ctx, "C", "allow_once")
			if err != nil {
				t.Errorf("decideOnce(C) error = %v", err)
			}
			results[i] = ok
		}(i)
	}
	wg.Wait()
	if results[0] == results[1] {
		t.Errorf("concurrent decideOnce(C) results = %v; want exactly one true", results)
	}
	mu.Lock()
	calls := 0
	for _, id := range order {
		if id == "C" {
			calls++
		}
	}
	mu.Unlock()
	if calls != 1 {
		t.Errorf("decider calls for C = %d; want 1", calls)
	}
}

func TestDecideOncePanickingDeciderDoesNotStrandID(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	var calls atomic.Int32
	tb.bot.decider = DeciderFunc(func(_ context.Context, id, _ string) error {
		if calls.Add(1) == 1 {
			panic("test panic in decider")
		}
		return nil
	})
	ctx := context.Background()
	// The panic propagates out of decideOnce (the dispatcher
	// per-update recover bounds it in production); the marker
	// cleanup must still run, so the next tap for the same id
	// proceeds instead of waiting until shutdown.
	func() {
		defer func() { _ = recover() }()
		_, _ = tb.bot.decideOnce(ctx, "A", "allow_once")
	}()
	ok, err := tb.bot.decideOnce(ctx, "A", "allow_once")
	if err != nil || !ok {
		t.Errorf("decideOnce(A) after panic = (%v, %v); want (true, nil)", ok, err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("decider calls = %d; want 2 (panic + retry)", got)
	}
}

func TestBotCallbackDecideDistinctEntriesOneRPC(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	after := int64(42)
	mk1 := tb.bot.ApprovalMarkup(Approval{ID: "appr-1", Options: []string{"allow_once", "deny"}}, ResumeTriple{SessionID: "s1", Title: "t", AfterSeq: &after})
	data1 := mk1.InlineKeyboard[0][0].CallbackData
	mk2 := tb.bot.ApprovalMarkup(Approval{ID: "appr-1", Options: []string{"allow_once", "deny"}}, ResumeTriple{SessionID: "s1", Title: "t", AfterSeq: &after})
	data2 := mk2.InlineKeyboard[0][0].CallbackData
	if data1 == data2 {
		t.Fatalf("distinct markups produced identical callback data %q", data1)
	}
	srv.enqueueUpdates(
		callbackUpdate(60, 111, 500, 100, data1, "cq-1"),
		callbackUpdate(61, 111, 500, 100, data2, "cq-2"),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "decide handled", func() bool { return len(tb.decider.recorded()) == 1 })
	waitFor(t, "both callbacks answered", func() bool { return srv.count("answerCallbackQuery") == 2 })
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	if got := len(tb.decider.recorded()); got != 1 {
		t.Errorf("decider calls = %d; want 1 (distinct entries, same approval id)", got)
	}
	// The deduped tap clears its buttons and is answered, but
	// schedules no second resume: one resume per approval
	// (the first tap's) is the decideOnce invariant.
	if got := len(tb.recordedResumes()); got != 1 {
		t.Errorf("resumes = %d; want 1", got)
	}
}

func TestRecordDecidedSuppressesLaterDecide(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	// An auto-path decision recorded via RecordDecided
	// suppresses a later manual tap for the same id: no
	// second RPC.
	tb.bot.RecordDecided("appr-9", "allow_always")
	if ok, err := tb.bot.decideOnce(context.Background(), "appr-9", "allow_always"); err != nil || ok {
		t.Errorf("decideOnce(recorded id) = (%v, %v); want (false, nil)", ok, err)
	}
	if got := len(tb.decider.recorded()); got != 0 {
		t.Errorf("decider calls = %d; want 0", got)
	}
	// A different id is unaffected.
	if ok, err := tb.bot.decideOnce(context.Background(), "appr-10", "deny"); err != nil || !ok {
		t.Errorf("decideOnce(other id) = (%v, %v); want (true, nil)", ok, err)
	}
	if got := len(tb.decider.recorded()); got != 1 {
		t.Errorf("decider calls = %d; want 1", got)
	}
}

func TestDecidedCapEvictsOldest(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	for i := 0; i < decidedCap+1; i++ {
		tb.bot.RecordDecided(fmt.Sprintf("id-%d", i), "allow_once")
	}
	// The oldest id was evicted: deciding it again re-issues.
	if ok, err := tb.bot.decideOnce(context.Background(), "id-0", "allow_once"); err != nil || !ok {
		t.Errorf("decideOnce(evicted id-0) = (%v, %v); want (true, nil)", ok, err)
	}
	// The newest id is still recorded: no second RPC.
	if ok, err := tb.bot.decideOnce(context.Background(), fmt.Sprintf("id-%d", decidedCap), "allow_once"); err != nil || ok {
		t.Errorf("decideOnce(newest) = (%v, %v); want (false, nil)", ok, err)
	}
	if got := len(tb.decider.recorded()); got != 1 {
		t.Errorf("decider calls = %d; want 1 (only the evicted id)", got)
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

func TestBotCallbackDecideSchedulesResumeWhileTurnActive(t *testing.T) {
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
	// The Bot layer always schedules the resume when a triple
	// is present, even with a turn active: it cannot tell a
	// running turn from one in teardown (final edit shown,
	// watermark save in progress), and dropping the schedule
	// here would strand the decision. The guard lives in the
	// runner's startResume (active-slot wait + HasActiveTurn
	// + stale-seq re-validation), covered in the commands
	// package; here the schedule itself is asserted.
	waitFor(t, "resume scheduled", func() bool { return len(tb.recordedResumes()) == 1 })
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	resumes := tb.recordedResumes()
	if resumes[0].ChatID != 500 || resumes[0].SessionID != "s" || resumes[0].Title != "t" || resumes[0].AfterSeq != 7 {
		t.Errorf("resume = %+v", resumes[0])
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
	// Limitation: this test is weak in isolation — ProxyFromEnvironment
	// bypasses loopback destinations anyway, so a proxy-consulting
	// transport could still pass it for a loopback fake. Env-proxy
	// rejection is really proven by TestBotConstructionValidation
	// (BoundClient rejects env-proxy transports at construction);
	// this test proves only that no request reaches the proxy or
	// the other server on the polling path.
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
		t.Errorf("log output contains the fixture token after a hostile server body (log buffer not printed: it may carry secrets)")
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

// walkErrChain visits err and every error reachable through
// Unwrap() error and Unwrap() []error, so a test can prove no
// layer of a returned error carries the token.
func walkErrChain(err error, visit func(error)) {
	seen := map[error]bool{}
	var walk func(error)
	walk = func(e error) {
		if e == nil || seen[e] {
			return
		}
		seen[e] = true
		visit(e)
		if u, ok := e.(interface{ Unwrap() error }); ok {
			walk(u.Unwrap())
		}
		if u, ok := e.(interface{ Unwrap() []error }); ok {
			for _, sub := range u.Unwrap() {
				walk(sub)
			}
		}
	}
	walk(err)
}

func TestBotCallbackInaccessibleMessage(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	after := int64(42)
	mk := tb.bot.ApprovalMarkup(Approval{ID: "appr-inacc", Options: []string{"allow_once", "deny"}}, ResumeTriple{SessionID: "s1", Title: "t", AfterSeq: &after})
	data := mk.InlineKeyboard[0][0].CallbackData
	// Chat 600 is the inaccessible message's chat; 111 is only
	// the sender. Routing must use 600, never the sender id.
	srv.enqueueUpdates(callbackUpdateInaccessible(100, 111, 600, 100, data, "cq-inacc"))
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "decide handled", func() bool { return len(tb.decider.recorded()) == 1 })
	waitFor(t, "markup cleared", func() bool { return srv.count("editMessageReplyMarkup") == 1 })
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	sends := srv.callsOf("sendMessage")
	found := false
	for _, c := range sends {
		if c.Form["chat_id"] == "600" {
			found = true
		}
	}
	if !found {
		t.Errorf("confirmation sends = %+v; want one to chat 600 (the message chat, not the sender)", sends)
	}
	edits := srv.callsOf("editMessageReplyMarkup")
	if len(edits) != 1 || edits[0].Form["chat_id"] != "600" || edits[0].Form["message_id"] != "100" {
		t.Errorf("markup-clear calls = %+v; want one chat 600 message 100", edits)
	}
}

func TestBotCombinedUpdateCallbackSenderGates(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	mk := tb.bot.ApprovalMarkup(Approval{ID: "appr-comb", Options: []string{"allow_once", "deny"}}, ResumeTriple{})
	data := mk.InlineKeyboard[0][0].CallbackData
	// Real servers never emit combined updates; only a
	// hostile/compromised API response can. The gate must
	// derive the sender from the dispatched kind (callback).
	// The two updates go in separate batches so the
	// stranger-callback outcome is observable before the
	// allowlisted one is delivered.
	srv.enqueueUpdates(combinedUpdate(110, 111, 500, 999, 600, 100, data, "cq-stranger"))
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	// The stranger-callback update must decide nothing.
	time.Sleep(200 * time.Millisecond)
	if got := len(tb.decider.recorded()); got != 0 {
		t.Errorf("decider calls after stranger callback = %d; want 0", got)
	}
	if got := srv.count("answerCallbackQuery"); got != 0 {
		t.Errorf("answerCallbackQuery calls after stranger callback = %d; want 0", got)
	}
	srv.enqueueUpdates(combinedUpdate(111, 999, 500, 111, 600, 100, data, "cq-friend"))
	waitFor(t, "allowlisted callback decided", func() bool { return len(tb.decider.recorded()) == 1 })
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	if got := len(tb.handler.recorded()); got != 0 {
		t.Errorf("handler calls = %d for combined updates; want 0 (callback dispatch, no message handling)", got)
	}
	if got := srv.count("answerCallbackQuery"); got != 1 {
		t.Errorf("answerCallbackQuery calls = %d; want 1 (the allowlisted callback only)", got)
	}
}

func TestBotScrubbedErrorTokenFreeAtObjectLevel(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	assertTokenFree := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("scrubbed error is nil; want a scrubbed error")
		}
		if strings.Contains(err.Error(), fakeToken) {
			t.Error("scrubbed Error() contains the token")
		}
		if strings.Contains(fmt.Sprintf("%+v", err), fakeToken) {
			t.Error("scrubbed verbose formatting contains the token (never unwrap-and-print)")
		}
		if strings.Contains(fmt.Sprintf("%#v", err), fakeToken) {
			t.Error("scrubbed Go-syntax formatting contains the token")
		}
		walkErrChain(err, func(e error) {
			if strings.Contains(e.Error(), fakeToken) {
				t.Errorf("error chain layer %T contains the token", e)
			}
		})
	}
	// 429 path: the typed copy must carry the scrubbed message
	// and RetryAfter, and errors.As must still find it.
	tmr := &bot.TooManyRequestsError{Message: "too many requests, " + fakeToken, RetryAfter: 5}
	scrubbed := tb.bot.scrubErr(tmr)
	assertTokenFree(t, scrubbed)
	var gotTMR *bot.TooManyRequestsError
	if !errors.As(scrubbed, &gotTMR) {
		t.Fatal("errors.As(scrubbed 429) does not find TooManyRequestsError")
	}
	if gotTMR.RetryAfter != 5 || strings.Contains(gotTMR.Message, fakeToken) {
		t.Errorf("scrubbed TooManyRequestsError = %+v; want RetryAfter 5 and a token-free Message", gotTMR)
	}
	// 400 path: errors.Is for the BadRequest sentinel and the
	// parse-error classification must survive scrubbing (the
	// step-5 needs: isParseError / retryCall).
	bad := fmt.Errorf("%w, %s", bot.ErrorBadRequest, "Bad Request: can't parse entities: "+fakeToken)
	scrubbedBad := tb.bot.scrubErr(bad)
	assertTokenFree(t, scrubbedBad)
	if !errors.Is(scrubbedBad, bot.ErrorBadRequest) {
		t.Error("errors.Is(scrubbed 400, ErrorBadRequest) = false; want true")
	}
	if !isParseError(scrubbedBad) {
		t.Error("isParseError(scrubbed 400 parse error) = false; want true")
	}
	// Migrate path: typed fields scrubbed, id preserved.
	mig := &bot.MigrateError{Message: "migrate: " + fakeToken, MigrateToChatID: 42}
	scrubbedMig := tb.bot.scrubErr(mig)
	assertTokenFree(t, scrubbedMig)
	var gotMig *bot.MigrateError
	if !errors.As(scrubbedMig, &gotMig) || gotMig.MigrateToChatID != 42 {
		t.Errorf("scrubbed MigrateError = %v; want As-found with MigrateToChatID 42", scrubbedMig)
	}
	// A token-bearing Send error must be token-free at the
	// object level too (not only in Error()).
	srv.sendFailures = []scriptedFailure{{Code: 400, Desc: "Bad Request: token " + fakeToken + " rejected"}}
	if _, err := tb.bot.Send(context.Background(), 500, "hi", SendOptions{}); err != nil {
		assertTokenFree(t, err)
	} else {
		t.Error("Send(hostile description) = nil; want error")
	}
}

func TestBotHostileBodyNotLogged(t *testing.T) {
	t.Parallel()
	const marker = "HOSTILE-BODY-MARKER-7f3a91"
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	srv.garbageBody = `{"ok":true,"result":[` + marker + ` ` + fakeToken + ` ` + strings.Repeat("x", 900) + `]}`
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	time.Sleep(300 * time.Millisecond)
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	logged := tb.logBuf.String()
	if strings.Contains(logged, marker) {
		t.Error("log output contains the hostile body marker (raw body bytes reached the log)")
	}
	if strings.Contains(logged, fakeToken) {
		t.Error("log output contains the fixture token after a hostile body")
	}
	if len(logged) > 400 {
		t.Errorf("log output is %d bytes after one hostile poll; want length-bounded (status/class/length summary)", len(logged))
	}
	if !strings.Contains(logged, "message_length=") {
		t.Error("log output lacks a status/class/length summary naming message_length (log buffer not printed: it may carry secrets)")
	}
}

func TestBotHostileDescriptionNotLogged(t *testing.T) {
	t.Parallel()
	const marker = "R6A-DESC-MARKER-"
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	// Valid-JSON 400 envelope whose description is a large
	// marker body plus the fixture token: the library embeds
	// the description verbatim in its error, so the poll log
	// must carry only a class/length summary.
	desc := strings.Repeat(marker, 1500) + " " + fakeToken
	srv.garbageBody = `{"ok":false,"error_code":400,"description":` + jsonString(desc) + `}`
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	time.Sleep(300 * time.Millisecond)
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	logged := tb.logBuf.String()
	if strings.Contains(logged, marker) {
		t.Error("log output contains the hostile description marker (server text reached the log)")
	}
	if strings.Contains(logged, fakeToken) {
		t.Error("log output contains the fixture token after a hostile description")
	}
	if len(logged) > 400 {
		t.Errorf("log output is %d bytes after one hostile poll; want length-bounded (class/length summary)", len(logged))
	}
	if !strings.Contains(logged, "message_length=") {
		t.Error("log output lacks a class/length summary naming message_length (log buffer not printed: it may carry secrets)")
	}
}

func TestBotHostileDecodeUpdateNotLogged(t *testing.T) {
	t.Parallel()
	const marker = "R6B-UPDATE-MARKER-"
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	// Undecodable update: the library logs the raw update JSON
	// verbatim through the errors handler.
	raw := `{"update_id":42,"message":"` + strings.Repeat(marker, 130) + `"}`
	srv.enqueueUpdates(raw)
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	time.Sleep(300 * time.Millisecond)
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	if got := len(tb.handler.recorded()); got != 0 {
		t.Errorf("handler calls = %d; want 0 (undecodable update must not be handled)", got)
	}
	logged := tb.logBuf.String()
	if strings.Contains(logged, marker) {
		t.Error("log output contains the hostile raw-update marker (server text reached the log)")
	}
	if strings.Contains(logged, fakeToken) {
		t.Error("log output contains the fixture token after a hostile update")
	}
	if len(logged) > 400 {
		t.Errorf("log output is %d bytes after one hostile batch; want length-bounded (class/length summary)", len(logged))
	}
	if !strings.Contains(logged, "message_length=") {
		t.Error("log output lacks a class/length summary naming message_length (log buffer not printed: it may carry secrets)")
	}
}

func TestSummarizeNeverEmitsServerText(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	cases := []struct {
		name string
		in   string
		want string // fragment that must be absent
	}{
		{"short description", "bad request, R6D-SHORT-MARKER " + fakeToken, "R6D-SHORT-MARKER"},
		{"short decode update", `error decode update 42, skipped, {"update_id":42,"message":"R6D-DECODE-MARKER"}: cannot unmarshal`, "R6D-DECODE-MARKER"},
		{"long description", "bad request, " + strings.Repeat("R6D-LONG-MARKER-", 1500), "R6D-LONG-MARKER-"},
		{"long decode update", "error decode update 42, skipped, " + strings.Repeat("R6D-LONG-UPDATE-", 1500), "R6D-LONG-UPDATE-"},
		{"long arbitrary", strings.Repeat("R6D-GENERIC-", 5000), "R6D-GENERIC-"},
	}
	for _, tc := range cases {
		got := tb.bot.summarize(tc.in)
		if strings.Contains(got, tc.want) {
			t.Errorf("%s: summarize kept a server fragment in %q", tc.name, got[:min(len(got), 120)])
		}
		if strings.Contains(got, fakeToken) {
			t.Errorf("%s: summarize kept the fixture token", tc.name)
		}
		if len(got) > 400 {
			t.Errorf("%s: summarize output is %d bytes; want length-bounded", tc.name, len(got))
		}
		if !strings.Contains(got, "message_length=") {
			t.Errorf("%s: summarize output %q lacks message_length=", tc.name, got)
		}
	}
}

func TestSummarizeHostileBodyBoundedWork(t *testing.T) {
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	// 5MB of hostile text: the old SafeString pass over the
	// whole input took tens of seconds; the bounded path must
	// finish in seconds and emit only a short summary.
	in := strings.Repeat("R6D-CPU-MARKER-", 350000)
	start := time.Now()
	got := tb.bot.summarize(in)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("summarize(5MB) took %v; want bounded work (<10s)", elapsed)
	}
	if strings.Contains(got, "R6D-CPU-MARKER-") {
		t.Error("summarize kept a server fragment from a 5MB input")
	}
	if len(got) > 400 {
		t.Errorf("summarize(5MB) output is %d bytes; want length-bounded", len(got))
	}
	if !strings.Contains(got, "message_length=") {
		t.Errorf("summarize(5MB) output of %d bytes lacks message_length=", len(got))
	}
}

// expectedSummary builds the exact summary summarizeError must
// emit for label and err, pinning the shared format: the decode
// classes keep the historical "telegram poll error:" prefix,
// every other class uses "telegram error:". A nil error has
// message_length=0.
func expectedSummary(label string, err error) string {
	length := 0
	if err != nil {
		length = utf8.RuneCountInString(err.Error())
	}
	if label == "response decode failure" || label == "update decode failure" {
		return fmt.Sprintf("telegram poll error: %s message_length=%d", label, length)
	}
	return fmt.Sprintf("telegram error: %s message_length=%d", label, length)
}

// mustJSONDecodeError returns a genuine encoding/json decode
// error, the leaf the library wraps in its decode formats
// (raw_request.go, get_updates.go).
func mustJSONDecodeError(t *testing.T) error {
	t.Helper()
	var dst struct {
		UpdateID int64 `json:"update_id"`
	}
	err := json.Unmarshal([]byte(`{"update_id":`), &dst)
	if err == nil {
		t.Fatal("json.Unmarshal(truncated object) = nil; want a decode error")
	}
	return err
}

func TestSummarizeErrorClasses(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	decodeErr := mustJSONDecodeError(t)
	responseDecode := func() error {
		return fmt.Errorf("error decode response body for method %s, %s, %w", "getUpdates", `{"ok":true,"result":[]}`, decodeErr)
	}
	timeoutURL := func() error {
		return &url.Error{
			Op:  "Post",
			URL: "https://api.telegram.org/bot" + fakeToken + "/getUpdates",
			Err: &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded},
		}
	}
	dnsURL := func() error {
		return &url.Error{
			Op:  "Post",
			URL: "https://api.telegram.org/",
			Err: &net.DNSError{Err: "no such host", Name: "api.telegram.org", IsNotFound: true},
		}
	}
	refusedURL := func() error {
		return &url.Error{
			Op:  "dial",
			URL: "",
			Err: &net.OpError{
				Op:   "dial",
				Net:  "tcp",
				Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
				Err:  &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED},
			},
		}
	}
	cases := []struct {
		name string
		want string
		err  func(b *Bot) error
	}{
		{"too many requests typed", "too many requests", func(*Bot) error {
			return &bot.TooManyRequestsError{Message: "too many requests, retry after 5", RetryAfter: 5}
		}},
		{"too many requests sentinel wrap", "too many requests", func(*Bot) error {
			return fmt.Errorf("%w, retry after 5", bot.ErrorTooManyRequests)
		}},
		{"too many requests scrubbed", "too many requests", func(b *Bot) error {
			return b.scrubErr(&bot.TooManyRequestsError{Message: "too many requests, " + fakeToken, RetryAfter: 5})
		}},
		{"bad request sentinel", "bad request", func(*Bot) error {
			return fmt.Errorf("%w, can't parse entities", bot.ErrorBadRequest)
		}},
		{"bad request scrubbed", "bad request", func(b *Bot) error {
			return b.scrubErr(fmt.Errorf("%w, Bad Request: %s", bot.ErrorBadRequest, fakeToken))
		}},
		{"bad request migrate error", "bad request", func(*Bot) error {
			return &bot.MigrateError{Message: "bad request: group migrated", MigrateToChatID: -100123}
		}},
		{"forbidden sentinel", "forbidden", func(*Bot) error {
			return fmt.Errorf("%w, bot was blocked by the user", bot.ErrorForbidden)
		}},
		{"unauthorized sentinel", "unauthorized", func(*Bot) error {
			return fmt.Errorf("%w, Unauthorized", bot.ErrorUnauthorized)
		}},
		{"not found sentinel", "not found", func(*Bot) error {
			return fmt.Errorf("%w, chat not found", bot.ErrorNotFound)
		}},
		{"conflict sentinel", "conflict", func(*Bot) error {
			return fmt.Errorf("%w, terminated by other getUpdates request", bot.ErrorConflict)
		}},
		{"response decode body", "response decode failure", func(*Bot) error { return responseDecode() }},
		{"response decode body wrapped by poll loop", "response decode failure", func(*Bot) error {
			return fmt.Errorf("error get updates, %w", responseDecode())
		}},
		{"response decode body scrubbed", "response decode failure", func(b *Bot) error {
			return b.scrubErr(responseDecode())
		}},
		{"response decode result", "response decode failure", func(*Bot) error {
			return fmt.Errorf("error decode response result for method %s, %w", "sendMessage", decodeErr)
		}},
		{"response read body beats eof", "response decode failure", func(*Bot) error {
			return fmt.Errorf("error read response body for method %s, %w", "getUpdates", io.ErrUnexpectedEOF)
		}},
		{"update decode", "update decode failure", func(*Bot) error {
			return fmt.Errorf("error decode update, %s, %w", `{"update_id":42}`, decodeErr)
		}},
		{"update decode skipped", "update decode failure", func(*Bot) error {
			return fmt.Errorf("error decode update %d, skipped, %s, %w", 42, `{"update_id":42}`, decodeErr)
		}},
		{"timeout op error", "timeout", func(*Bot) error { return timeoutURL() }},
		{"timeout wrapped do request", "timeout", func(*Bot) error {
			return fmt.Errorf("error do request for method %s, %w", "getUpdates", timeoutURL())
		}},
		{"timeout scrubbed fallback", "timeout", func(b *Bot) error {
			return b.scrubErr(fmt.Errorf("error do request for method %s, %w", "sendMessage", timeoutURL()))
		}},
		{"dns error", "dns", func(*Bot) error { return dnsURL() }},
		{"dns wrapped do request", "dns", func(*Bot) error {
			return fmt.Errorf("error do request for method %s, %w", "getMe", dnsURL())
		}},
		{"dns scrubbed fallback", "dns", func(b *Bot) error {
			return b.scrubErr(fmt.Errorf("error do request for method %s, %w", "getMe", dnsURL()))
		}},
		{"tls record header", "tls", func(*Bot) error {
			return &url.Error{
				Op:  "Post",
				URL: "https://api.telegram.org/",
				Err: tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
			}
		}},
		{"tls bad certificate text", "tls", func(*Bot) error {
			return &url.Error{Op: "Post", URL: "https://api.telegram.org/", Err: errors.New("tls: bad certificate")}
		}},
		{"connection refused errno", "connection refused", func(*Bot) error {
			return fmt.Errorf("dial tcp: %w", syscall.ECONNREFUSED)
		}},
		{"connection refused url wrapped", "connection refused", func(*Bot) error { return refusedURL() }},
		{"connection refused scrubbed fallback", "connection refused", func(b *Bot) error {
			return b.scrubErr(fmt.Errorf("error do request for method %s, %w", "sendMessage", refusedURL()))
		}},
		{"connection reset errno", "connection reset", func(*Bot) error {
			return fmt.Errorf("read tcp: %w", syscall.ECONNRESET)
		}},
		{"unreachable host", "unreachable", func(*Bot) error {
			return fmt.Errorf("dial: %w", syscall.EHOSTUNREACH)
		}},
		{"unreachable network", "unreachable", func(*Bot) error {
			return fmt.Errorf("dial: %w", syscall.ENETUNREACH)
		}},
		{"eof", "eof", func(*Bot) error {
			return fmt.Errorf("reading response: %w", io.EOF)
		}},
		{"unexpected eof", "eof", func(*Bot) error { return io.ErrUnexpectedEOF }},
		{"context canceled", "context canceled", func(*Bot) error { return context.Canceled }},
		{"context canceled wrapped", "context canceled", func(*Bot) error {
			return fmt.Errorf("poll: %w", context.Canceled)
		}},
		{"context canceled in url error", "context canceled", func(*Bot) error {
			return &url.Error{Op: "Post", URL: "https://api.telegram.org/", Err: context.Canceled}
		}},
		{"context deadline exceeded", "context deadline exceeded", func(*Bot) error {
			return context.DeadlineExceeded
		}},
		{"context deadline exceeded from expired ctx", "context deadline exceeded", func(*Bot) error {
			ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
			defer cancel()
			time.Sleep(time.Millisecond)
			return ctx.Err()
		}},
		{"http 5xx", "http 5xx", func(*Bot) error {
			return fmt.Errorf("error response from telegram for method %s, %d %s", "getUpdates", 500, "Internal Server Error")
		}},
		{"http 5xx wrapped by poll loop", "http 5xx", func(*Bot) error {
			return fmt.Errorf("error get updates, %w", fmt.Errorf("error response from telegram for method %s, %d %s", "getUpdates", 503, "Service Unavailable"))
		}},
		{"http 4xx", "http 4xx", func(*Bot) error {
			return fmt.Errorf("error response from telegram for method %s, %d %s", "sendMessage", 422, "Unprocessable Entity")
		}},
		{"unclassified plain", "unclassified", func(*Bot) error {
			return errors.New("something completely unexpected")
		}},
		{"unclassified nil", "unclassified", func(*Bot) error { return nil }},
		{"unclassified scrubbed unknown", "unclassified", func(b *Bot) error {
			return b.scrubErr(errors.New("weird failure"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.err(tb.bot)
			got := tb.bot.summarizeError(err)
			if want := expectedSummary(tc.want, err); got != want {
				t.Errorf("summarizeError = %q; want %q (label %q)", got, want, tc.want)
			}
			if strings.Contains(got, "method=") {
				t.Errorf("summarizeError emitted a method= field in %q", got)
			}
			if err != nil && strings.Contains(got, fakeToken) {
				t.Errorf("summarizeError kept the fixture token in %q", got)
			}
			if len(got) > 400 {
				t.Errorf("summarizeError output is %d bytes; want length-bounded", len(got))
			}
		})
	}
}

// TestSummarizeErrorHostileDescriptionNotDecode is the
// negative case for typed classification: a 400-rune server
// description that merely contains the decode phrase must
// neither select a decode class nor leak any fragment. The
// first error carries the decode phrase after a sentinel, so
// the sentinel wins; the second carries it with no chain at
// all, so only an anchored chain marker could select decode
// — and there is none. (The string-only summarize keeps the
// legacy substring behaviour for panic values; that split is
// pinned by TestSummarizeLoop4NoMethodField.)
func TestSummarizeErrorHostileDescriptionNotDecode(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	phrase := "decode response body"
	desc := strings.Repeat("D", 100) + " " + phrase + " " + fakeToken + " " +
		strings.Repeat("E", 400-100-1-len(phrase)-1-len(fakeToken)-1)
	if n := utf8.RuneCountInString(desc); n != 400 {
		t.Fatalf("description is %d runes; want exactly 400", n)
	}
	err := fmt.Errorf("%w, %s", bot.ErrorBadRequest, desc)
	got := tb.bot.summarizeError(err)
	if want := expectedSummary("bad request", err); got != want {
		t.Errorf("summarizeError(hostile 400) = %q; want %q", got, want)
	}
	if strings.Contains(got, phrase) {
		t.Errorf("summarizeError leaked the decode phrase in %q", got)
	}
	if strings.Contains(got, fakeToken) {
		t.Errorf("summarizeError kept the fixture token in %q", got)
	}
	plain := errors.New(strings.Repeat("z", 100) + " decode response body for method getUpdates, {\"ok\":true}" + strings.Repeat("z", 200))
	gotPlain := tb.bot.summarizeError(plain)
	if want := expectedSummary("unclassified", plain); gotPlain != want {
		t.Errorf("summarizeError(unanchored decode phrase) = %q; want %q", gotPlain, want)
	}
	if strings.Contains(gotPlain, phrase) {
		t.Errorf("summarizeError leaked the decode phrase in %q", gotPlain)
	}
}

// TestSummarizeErrorHugeInputBounded mirrors
// TestSummarizeHostileBodyBoundedWork for the typed path: a
// multi-megabyte error must finish in seconds, emit only a
// short summary, and never select a class from text past the
// bounded prefix.
func TestSummarizeErrorHugeInputBounded(t *testing.T) {
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	inputs := []struct {
		name string
		err  error
		want string // fragment that must be absent
	}{
		{"plain 5MB", errors.New(strings.Repeat("R6D-CPU-MARKER-", 350000)), "R6D-CPU-MARKER-"},
		{"late decode phrase", errors.New(strings.Repeat("q", 100000) + " decode response body " + strings.Repeat("q", 5000000-100000-22)), "decode response body"},
	}
	for _, tc := range inputs {
		start := time.Now()
		got := tb.bot.summarizeError(tc.err)
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Errorf("summarizeError(%s) took %v; want bounded work (<10s)", tc.name, elapsed)
		}
		if want := expectedSummary("unclassified", tc.err); got != want {
			t.Errorf("summarizeError(%s) = %q; want %q", tc.name, got, want)
		}
		if strings.Contains(got, tc.want) {
			t.Errorf("summarizeError(%s) kept an input fragment in %q", tc.name, got)
		}
		if len(got) > 400 {
			t.Errorf("summarizeError(%s) output is %d bytes; want length-bounded", tc.name, len(got))
		}
	}
}

// TestSummarizeUnclassifiedFallback pins the end of the ""
// branch: the string path never emits a labelless summary
// either.
func TestSummarizeUnclassifiedFallback(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	for _, in := range []string{"totally unknown shape", ""} {
		got := tb.bot.summarize(in)
		want := "telegram error: unclassified message_length=" + fmt.Sprint(utf8.RuneCountInString(in))
		if got != want {
			t.Errorf("summarize(%q) = %q; want %q", in, got, want)
		}
		if strings.Contains(got, "telegram error: message_length=") {
			t.Errorf("summarize(%q) emitted the old labelless shape %q", in, got)
		}
	}
}

func TestBotEditPlainHostileDescriptionNotLogged(t *testing.T) {
	t.Parallel()
	const marker = "R6E-EDIT-MARKER"
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	// A non-poll log exit (EditPlain / stream-edit): a short
	// description-carrying 400 and a long one must both stay
	// out of the log.
	srv.editFailures = []scriptedFailure{
		{Code: 400, Desc: marker + " " + fakeToken},
		{Code: 400, Desc: strings.Repeat(marker+"-", 1500)},
	}
	if err := tb.bot.EditPlain(context.Background(), 500, 100, "hello"); err != nil {
		t.Fatalf("EditPlain(short hostile description) = %v; want nil (swallowed)", err)
	}
	if err := tb.bot.EditPlain(context.Background(), 500, 100, "hello"); err != nil {
		t.Fatalf("EditPlain(long hostile description) = %v; want nil (swallowed)", err)
	}
	logged := tb.logBuf.String()
	if strings.Contains(logged, marker) {
		t.Error("log output contains the hostile description marker on the EditPlain exit")
	}
	if strings.Contains(logged, fakeToken) {
		t.Error("log output contains the fixture token on the EditPlain exit")
	}
	if len(logged) > 400 {
		t.Errorf("log output is %d bytes on the EditPlain exit; want length-bounded", len(logged))
	}
	if !strings.Contains(logged, "message_length=") {
		t.Error("log output lacks a class/length summary naming message_length (log buffer not printed: it may carry secrets)")
	}
}

func TestBotHandlerErrorHostileDescriptionNotLogged(t *testing.T) {
	t.Parallel()
	const marker = "R6E-HANDLER-MARKER"
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	// A non-poll log exit (message handler error): the handler
	// returns a description-carrying error.
	tb.handler.returnErr = errors.New("bad request, " + marker + " " + fakeToken)
	srv.enqueueUpdates(messageUpdate(60, 500, 111, "hi"))
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "handler called", func() bool { return len(tb.handler.recorded()) == 1 })
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	logged := tb.logBuf.String()
	if strings.Contains(logged, marker) {
		t.Error("log output contains the hostile description marker on the handler-error exit")
	}
	if strings.Contains(logged, fakeToken) {
		t.Error("log output contains the fixture token on the handler-error exit")
	}
	if len(logged) > 400 {
		t.Errorf("log output is %d bytes on the handler-error exit; want length-bounded", len(logged))
	}
	if !strings.Contains(logged, "message_length=") {
		t.Error("log output lacks a class/length summary naming message_length (log buffer not printed: it may carry secrets)")
	}
}

func TestBotRedirectRefused(t *testing.T) {
	t.Parallel()
	var secondHits atomic.Int64
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true,"result":{"message_id":1,"chat":{"id":500,"type":"private"},"date":0,"text":"evil"}}`)
	}))
	defer second.Close()
	srv := newFakeTelegramServer(t)
	srv.sendRedirect = true
	srv.redirectTarget = second.URL
	tb := newTestBot(t, srv, nil)
	if _, err := tb.bot.Send(context.Background(), 500, "hi", SendOptions{}); err == nil {
		t.Error("Send(302 redirect) = nil; want an error (redirects refused)")
	}
	if got := secondHits.Load(); got != 0 {
		t.Errorf("second server saw %d requests; want 0 (no redirect followed)", got)
	}
	if got := srv.count("sendMessage"); got != 1 {
		t.Errorf("sendMessage calls = %d; want 1 (the redirect itself, never followed)", got)
	}
}

// delegatingTransport wraps another RoundTripper and delegates
// every request: BoundClient must reject it outright.
type delegatingTransport struct{ base http.RoundTripper }

func (d *delegatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return d.base.RoundTrip(req)
}

func TestBotBoundClientRejectsDelegatingAndDirectDial(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	// Delegating wrapper around a direct transport.
	if _, err := New(Settings{Token: fakeToken, AllowedUserIDs: []int64{111}, HTTPClient: &http.Client{Transport: &delegatingTransport{base: &http.Transport{Proxy: nil}}}, ServerURL: srv.url()}); err == nil {
		t.Error("New(delegating RoundTripper) = nil; want rejection")
	}
	// Direct-dial *http.Transport: nil Proxy but no custom dial
	// path (nil DialContext and DialTLSContext) — the stdlib
	// default dial shape, indistinguishable from a direct
	// connection that bypasses the profile outbound.
	if _, err := New(Settings{Token: fakeToken, AllowedUserIDs: []int64{111}, HTTPClient: &http.Client{Transport: &http.Transport{Proxy: nil}}, ServerURL: srv.url()}); err == nil {
		t.Error("New(direct-dial transport) = nil; want rejection")
	}
	if got := srv.count("getMe"); got != 0 {
		t.Errorf("getMe calls after rejected constructions = %d; want 0", got)
	}
}

func TestBotStartReturnsOnCancelWithBlockedHandler(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	entered := make(chan struct{})
	var once sync.Once
	gate := make(chan struct{})
	tb := newTestBot(t, srv, func(s *Settings) {
		s.MessageHandler = func(_ context.Context, _ MessageContext) error {
			once.Do(func() { close(entered) })
			<-gate
			return nil
		}
	})
	tb.bot.dispatch.shutdownTimeout = 150 * time.Millisecond
	srv.enqueueUpdates(messageUpdate(200, 500, 111, "blocked"))
	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	done := startBot(t, tb.bot, ctx)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked handler never entered")
	}
	cancel()
	select {
	case err := <-done:
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("Start returned after %v; want within the shutdown deadline", elapsed)
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Start = %v; want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after cancel with a blocked handler")
	}
	close(gate)
	time.Sleep(100 * time.Millisecond)
}

// Loop-4 (D1) regression probes: no server-chosen fragment may ride
// a summary through a method= field. Fresh markers (L4D1), never
// reused from loop 3. Every probe must show NO "method=" field at
// all. These tests were written before the fix and FAIL on 2cb0249,
// where summarize emitted method=<identifier fragment>.

func TestSummarizeLoop4NoMethodField(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	cases := []struct {
		name string
		in   string
		want string // injected fragment that must be absent
	}{
		{"identifier", "failed to decode response body for method L4D1IDENT, retry", "L4D1IDENT"},
		{"capped", "failed to decode response body for method " + "L4D1CAP" + strings.Repeat("X", 44) + ", retry", "L4D1CAP"},
		{"token digits", "failed to decode response body for method 123456, retry", "123456"},
		{"misclassifying phrase", "bad request, decode response body for method L4D1MISCLASS, bad", "L4D1MISCLASS"},
	}
	for _, tc := range cases {
		got := tb.bot.summarize(tc.in)
		if strings.Contains(got, "method=") {
			t.Errorf("%s: summarize emitted a method= field in %q", tc.name, got)
		}
		if strings.Contains(got, tc.want) {
			t.Errorf("%s: summarize kept the injected fragment in %q", tc.name, got)
		}
		if strings.Contains(got, fakeToken) {
			t.Errorf("%s: summarize kept the fixture token", tc.name)
		}
		if !strings.HasPrefix(got, "telegram poll error: response decode failure message_length=") {
			t.Errorf("%s: summarize = %q; want the response-decode class with no method field", tc.name, got)
		}
		if len(got) > 400 {
			t.Errorf("%s: summarize output is %d bytes; want length-bounded", tc.name, len(got))
		}
	}
}

func TestBotGetUpdatesMethodInjectionNotLogged(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	// Hostile 400 description carrying a decode-body phrase and a
	// method fragment: the poll log must carry no method= field.
	desc := "bad request, decode response body for method L4D1POLL, " + fakeToken
	srv.garbageBody = `{"ok":false,"error_code":400,"description":` + jsonString(desc) + `}`
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	time.Sleep(300 * time.Millisecond)
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	logged := tb.logBuf.String()
	if strings.Contains(logged, "method=") {
		t.Errorf("log output contains a method= field (length %d; buffer not printed: it may carry secrets)", len(logged))
	}
	if strings.Contains(logged, "L4D1POLL") {
		t.Error("log output contains the injected method fragment L4D1POLL")
	}
	if strings.Contains(logged, fakeToken) {
		t.Error("log output contains the fixture token after a hostile description")
	}
	if len(logged) > 400 {
		t.Errorf("log output is %d bytes after one hostile poll; want length-bounded", len(logged))
	}
	if !strings.Contains(logged, "message_length=") {
		t.Error("log output lacks a class/length summary naming message_length")
	}
}

func TestBotHandlerErrorMethodInjectionNotLogged(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	tb.handler.returnErr = errors.New("decode response body for method L4D1HANDLER, L4D1HANDLER-MARKER")
	srv.enqueueUpdates(messageUpdate(61, 500, 111, "hi"))
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "handler called", func() bool { return len(tb.handler.recorded()) == 1 })
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	logged := tb.logBuf.String()
	if strings.Contains(logged, "method=") {
		t.Errorf("log output contains a method= field on the handler-error exit (length %d; buffer not printed)", len(logged))
	}
	if strings.Contains(logged, "L4D1HANDLER") {
		t.Error("log output contains the injected method fragment on the handler-error exit")
	}
	if len(logged) > 400 {
		t.Errorf("log output is %d bytes on the handler-error exit; want length-bounded", len(logged))
	}
	if !strings.Contains(logged, "message_length=") {
		t.Error("log output lacks a class/length summary naming message_length")
	}
}

func TestBotPanicMethodInjectionNotLogged(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	tb.handler.panicErr = errors.New("decode response body for method L4D1PANIC, L4D1PANIC-MARKER")
	tb.handler.panicOnce = true
	srv.enqueueUpdates(
		messageUpdate(62, 500, 111, "first"),
		messageUpdate(63, 500, 111, "second"),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "second message handled after panic", func() bool { return len(tb.handler.recorded()) == 2 })
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	logged := tb.logBuf.String()
	if strings.Contains(logged, "method=") {
		t.Errorf("log output contains a method= field on the panic exit (length %d; buffer not printed)", len(logged))
	}
	if strings.Contains(logged, "L4D1PANIC") {
		t.Error("log output contains the injected method fragment on the panic exit")
	}
	if strings.Contains(logged, fakeToken) {
		t.Error("log output contains the fixture token after a token-bearing panic")
	}
	if !strings.Contains(logged, "message_length=") {
		t.Error("log output lacks a class/length summary naming message_length")
	}
}

func TestBotCallbackWarningNoMethodField(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	// The decider error carries a method-injection phrase; the
	// warning sent to chat is built from summarize and must
	// carry no method= field either.
	tb.decider.err = errors.New("decode response body for method L4D1CALLBACK, L4D1CALLBACK-MARKER")
	after := int64(42)
	mk := tb.bot.ApprovalMarkup(Approval{ID: "appr-1", Options: []string{"allow_once", "deny"}}, ResumeTriple{SessionID: "s1", Title: "t", AfterSeq: &after})
	data := mk.InlineKeyboard[0][0].CallbackData
	srv.enqueueUpdates(callbackUpdate(64, 111, 500, 100, data, "cq-1"))
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	waitFor(t, "decide handled", func() bool { return len(tb.decider.recorded()) == 1 })
	waitFor(t, "warning sent", func() bool { return len(srv.callsOf("sendMessage")) >= 1 })
	if err := stopBot(t, cancel, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	for _, c := range srv.callsOf("sendMessage") {
		if strings.Contains(c.Form["text"], "method=") {
			t.Errorf("chat warning carries a method= field in %q", c.Form["text"][:min(len(c.Form["text"]), 120)])
		}
		if strings.Contains(c.Form["text"], "L4D1CALLBACK") {
			t.Error("chat warning carries the injected method fragment")
		}
	}
	if strings.Contains(tb.logBuf.String(), "method=") {
		t.Error("log output contains a method= field on the callback-error exit")
	}
}

func TestBotStartLogsShutdownPhases(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := startBot(t, tb.bot, ctx)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Start = %v; want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after cancel")
	}
	buf := tb.logBuf.String()
	loop := strings.Index(buf, "telegram poll loop stopped")
	drained := strings.Index(buf, "telegram dispatcher drained")
	if loop < 0 || drained < 0 || drained < loop {
		t.Errorf("shutdown phases not logged in order in %q", buf)
	}
}
