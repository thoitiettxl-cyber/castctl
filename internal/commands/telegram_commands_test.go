// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// A4 command tests: dispatch, the core conversation commands,
// and the callback-button actions, through `telegram run` and
// through a directly wired Bot. Fake Telegram server + scripted
// fake gateway only; assertions are on observable sends, edits,
// button markup, and gateway calls.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
)

func sendsOf(h *telegramBotHarness) []string {
	h.fake.mu.Lock()
	defer h.fake.mu.Unlock()
	return append([]string(nil), h.fake.sends...)
}

func waitForSend(t *testing.T, h *telegramBotHarness, substr string) string {
	t.Helper()
	var found string
	waitFor(t, "send containing "+substr, func() bool {
		for _, s := range sendsOf(h) {
			if strings.Contains(s, substr) {
				found = s
				return true
			}
		}
		return false
	})
	return found
}

func sessionRow(id, title string, thread, pinned, archived bool, updated int64) map[string]any {
	return map[string]any{
		"session_id": id, "title": title, "is_thread": thread,
		"pinned": pinned, "archived": archived, "updated_at_ms": updated,
	}
}

func markupButtons(t *testing.T, markupJSON string) [][]string {
	t.Helper()
	var kb struct {
		InlineKeyboard [][]struct {
			Text string `json:"text"`
		} `json:"inline_keyboard"`
	}
	if err := json.Unmarshal([]byte(markupJSON), &kb); err != nil {
		t.Fatalf("markup %q is not a keyboard: %v", markupJSON, err)
	}
	var rows [][]string
	for _, row := range kb.InlineKeyboard {
		var texts []string
		for _, b := range row {
			texts = append(texts, b.Text)
		}
		rows = append(rows, texts)
	}
	return rows
}

func TestTelegramDispatchHelpStartUnknownDeferred(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBot(t, gw, []string{
		telegramUpdate(1, 111, "/help"),
		telegramUpdate(2, 111, "/start"),
		telegramUpdate(3, 111, "/bogus"),
		telegramUpdate(4, 111, "/foo-bar"),
		telegramUpdate(5, 111, "/files"),
		telegramUpdate(6, 111, "/login"),
		telegramUpdate(7, 111, "/raw something"),
		telegramUpdate(8, 111, "/HELP"),
	})
	defer cancel()
	waitFor(t, "8 command replies", func() bool { return len(sendsOf(h)) >= 8 })
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	sends := sendsOf(h)
	if len(sends) != 8 {
		t.Fatalf("sends = %d, want 8: %q", len(sends), sends)
	}
	if sends[0] != telegramBotHelpText {
		t.Errorf("help send differs from the verbatim HELP text:\n%q", sends[0])
	}
	if !strings.Contains(sends[1], "👋 Connected to Muse (profile <code>muse01</code>)") {
		t.Errorf("start send = %q", sends[1])
	}
	if sends[2] != "Unknown command /bogus. /help lists them." {
		t.Errorf("unknown send = %q", sends[2])
	}
	if sends[3] != "Unknown command /foo-bar. /help lists them." {
		t.Errorf("dashed-name send = %q", sends[3])
	}
	if sends[4] != "⚠️ /files is not wired in this build yet (step 5b)." {
		t.Errorf("deferred send = %q", sends[4])
	}
	if sends[5] != "⚠️ /login is not available in this build." {
		t.Errorf("login send = %q", sends[5])
	}
	if sends[6] != "⚠️ /raw is not available in this build." {
		t.Errorf("raw send = %q", sends[6])
	}
	if sends[7] != telegramBotHelpText {
		t.Errorf("/HELP (uppercase) did not reach help")
	}
}

func TestTelegramStatusReport(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.sessionsScript = []any{
		sessionRow("s1", "Chat 1", true, false, false, 300),
		sessionRow("s2", "Chat 2", true, true, false, 100),
		sessionRow("s3", "Archived", true, false, true, 400),
		sessionRow("s4", "Not a thread", false, false, false, 500),
	}
	gw.unreadScript = map[string]any{"total": 2}
	gw.identityScript = map[string]any{"name": "Muse", "tagline": "Helpful assistant"}
	gw.subScripts = []turnSubScript{{probeStatus: "running"}}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{telegramUpdate(1, 111, "/status@FakeBot")})
	defer cancel()
	report := waitForSend(t, h, "<b>Muse</b>")
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	want := "<b>Muse</b> · Muse\n" +
		"<i>Helpful assistant</i>\n" +
		"VM: <code>vm-test</code> · chats: 4\n" +
		"Unread: <code>{\"total\":2}</code>\n" +
		"Here: main chat\n" +
		"Now: idle (no turn from this chat)\n" +
		"Muse task here (server): <code>running</code>\n" +
		"Profile: <code>muse01</code> · auto-approve: on (always) · allow-once fallback: off · watch: off\n" +
		"castctl " + Version
	if report != want {
		t.Errorf("status report =\n%q\nwant\n%q", report, want)
	}
}

func TestTelegramStatusLiveTurnLine(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.blockSub = make(chan struct{})
	gw.subScripts = []turnSubScript{
		{replyText: "Slow reply", deltas: []string{"Slow"}},
		{probeStatus: "running"},
	}
	gw.sessionsScript = []any{}
	gw.unreadScript = map[string]any{}
	gw.identityScript = map[string]any{}
	h, cancel, codeCh := runTelegramBotGated(t, gw, []string{
		telegramUpdate(1, 111, "first"),
		telegramUpdate(2, 111, "/status"),
	}, []func(*cmdFakeTelegram) bool{
		nil,
		func(*cmdFakeTelegram) bool {
			_, _, subscribes, _ := gw.counts()
			return subscribes >= 1
		},
	})
	defer cancel()
	report := waitForSend(t, h, "Now: ⏳")
	close(gw.blockSub)
	waitFor(t, "turn completion", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Slow reply") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	if !strings.Contains(report, "Now: ⏳ Muse is working… · ") {
		t.Errorf("status report Now line = %q", report)
	}
}

func TestTelegramChatsPicker(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.sessionsScript = []any{
		sessionRow("s1", "Alpha", true, false, false, 300),
		sessionRow("s2", "Beta", true, true, false, 100),
		sessionRow("s3", "Gamma", true, false, false, 200),
		sessionRow("s4", "Archived", true, false, true, 400),
		sessionRow("s5", "Not a thread", false, false, false, 500),
	}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{telegramUpdate(1, 111, "/chats")})
	defer cancel()
	waitForSend(t, h, "Your chats")
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	sends := sendsOf(h)
	if len(sends) != 1 || sends[0] != "Your chats (3 side chats, page 1/1). Tap one to open it." {
		t.Fatalf("picker sends = %q", sends)
	}
	h.fake.mu.Lock()
	markupJSON := ""
	if len(h.fake.sendMarkupJSON) > 0 {
		markupJSON = h.fake.sendMarkupJSON[0]
	}
	h.fake.mu.Unlock()
	rows := markupButtons(t, markupJSON)
	// Main row, then pinned-first (Beta), then updated-desc
	// (Alpha 300, Gamma 200). No nav row on a single page.
	want := [][]string{
		{"💬 main chat ✓"},
		{"📌 Beta"},
		{"Alpha"},
		{"Gamma"},
	}
	if len(rows) != len(want) {
		t.Fatalf("picker rows = %v, want %v", rows, want)
	}
	for i := range want {
		if len(rows[i]) != 1 || rows[i][0] != want[i][0] {
			t.Errorf("picker row %d = %v, want %v", i, rows[i], want[i])
		}
	}
}

func TestTelegramMainNewHistoryUnread(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.sessionStartScript = map[string]any{"session_id": "sess-1"}
	gw.unreadScript = map[string]any{"total": 2}
	gw.addEvent(map[string]any{"event_name": "message.user", "seq": int64(20), "payload": map[string]any{"display_text": "q1"}})
	gw.addEvent(map[string]any{"event_name": "message.assistant", "seq": int64(21), "payload": map[string]any{"display_text": "a1"}})
	gw.addEvent(map[string]any{"event_name": "message.user", "seq": int64(22), "payload": map[string]any{"display_text": "q2"}})
	h, cancel, codeCh := runTelegramBot(t, gw, []string{
		telegramUpdate(1, 111, "/new My Title"),
		telegramUpdate(2, 111, "/history 2"),
		telegramUpdate(3, 111, "/history abc"),
		telegramUpdate(4, 111, "/unread"),
		telegramUpdate(5, 111, "/main"),
	})
	defer cancel()
	waitFor(t, "5 command replies", func() bool { return len(sendsOf(h)) >= 5 })
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	sends := sendsOf(h)
	if len(sends) != 5 {
		t.Fatalf("sends = %q", sends)
	}
	if sends[0] != "🆕 Now in a new side chat: <b>My Title</b>" {
		t.Errorf("new send = %q", sends[0])
	}
	if !strings.Contains(sends[1], "🤖 Muse: a1") || !strings.Contains(sends[1], "🧑 You: q2") || strings.Contains(sends[1], "q1") {
		t.Errorf("history 2 send = %q; want only the last 2 messages", sends[1])
	}
	if !strings.Contains(sends[2], "🧑 You: q1") || !strings.Contains(sends[2], "earlier") {
		t.Errorf("history abc send = %q; want all messages", sends[2])
	}
	if !strings.Contains(sends[3], "<pre>") || !strings.Contains(sends[3], `"total": 2`) {
		t.Errorf("unread send = %q", sends[3])
	}
	if sends[4] != "💬 Now in: <b>main chat</b>" {
		t.Errorf("main send = %q", sends[4])
	}
	if mapping, ok := h.stateStore(t).Chat(500); !ok || mapping.SessionID != "" || mapping.Title != "main chat" {
		t.Errorf("chat mapping = %+v, want main chat after /main", mapping)
	}
}

func TestTelegramNewNoSessionID(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.sessionStartScript = map[string]any{}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{telegramUpdate(1, 111, "/new")})
	defer cancel()
	send := waitForSend(t, h, "no session id")
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	if !strings.HasPrefix(send, "⚠️ Muse returned no session id: <code>{}</code>") {
		t.Errorf("no-id send = %q", send)
	}
}

func TestTelegramSessionOps(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.sessionStartScript = map[string]any{"session_id": "sess-1"}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{
		telegramUpdate(1, 111, "/rename Early"),
		telegramUpdate(2, 111, "/new T"),
		telegramUpdate(3, 111, "/rename"),
		telegramUpdate(4, 111, "/rename Renamed"),
		telegramUpdate(5, 111, "/pin"),
		telegramUpdate(6, 111, "/archive"),
		telegramUpdate(7, 111, "/pin"),
	})
	defer cancel()
	waitFor(t, "7 command replies", func() bool { return len(sendsOf(h)) >= 7 })
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	sends := sendsOf(h)
	if len(sends) != 7 {
		t.Fatalf("sends = %q", sends)
	}
	if sends[0] != "That works on side chats. Open one with /chats or make one with /new." {
		t.Errorf("rename-on-main send = %q", sends[0])
	}
	if sends[1] != "🆕 Now in a new side chat: <b>T</b>" {
		t.Errorf("new send = %q", sends[1])
	}
	if sends[2] != "Usage: /rename &lt;new title&gt;" {
		t.Errorf("bare rename send = %q", sends[2])
	}
	if sends[3] != "✏️ Renamed to <b>Renamed</b>" {
		t.Errorf("rename send = %q", sends[3])
	}
	if sends[4] != "📌 Pinned." {
		t.Errorf("pin send = %q", sends[4])
	}
	if sends[5] != "🗄 Archived. Back in the main chat." {
		t.Errorf("archive send = %q", sends[5])
	}
	if sends[6] != "That works on side chats. Open one with /chats or make one with /new." {
		t.Errorf("pin-after-archive send = %q", sends[6])
	}
	ops := gw.sessionOps()
	if len(ops) != 3 {
		t.Fatalf("session ops = %v, want rename+pin+archive", ops)
	}
	if ops[0]["method"] != "session.rename" || ops[0]["session_id"] != "sess-1" || ops[0]["title"] != "Renamed" {
		t.Errorf("rename op = %v", ops[0])
	}
	if ops[1]["method"] != "session.pin" || ops[2]["method"] != "session.archive" {
		t.Errorf("ops = %v", ops)
	}
	if mapping, ok := h.stateStore(t).Chat(500); !ok || mapping.SessionID != "" {
		t.Errorf("chat mapping after archive = %+v, want main chat", mapping)
	}
}

func TestTelegramWatchCommand(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBot(t, gw, []string{
		telegramUpdate(1, 111, "/watch on"),
		telegramUpdate(2, 111, "/watch"),
		telegramUpdate(3, 111, "/watch bogus"),
		telegramUpdate(4, 111, "/watch off"),
	})
	defer cancel()
	waitFor(t, "4 command replies", func() bool { return len(sendsOf(h)) >= 4 })
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	sends := sendsOf(h)
	if len(sends) != 4 {
		t.Fatalf("sends = %q", sends)
	}
	if sends[0] != "👀 Watch is <b>on</b>: the flag is stored; live event forwarding lands in step 5b." {
		t.Errorf("watch-on send = %q", sends[0])
	}
	if sends[1] != sends[0] || sends[2] != sends[0] {
		t.Errorf("watch report sends = %q / %q; want the on-report twice (bogus changes nothing)", sends[1], sends[2])
	}
	if sends[3] != "👀 Watch is <b>off</b>." {
		t.Errorf("watch-off send = %q", sends[3])
	}
	_, _, watchOn := h.stateStore(t).Toggles()
	if watchOn == nil || *watchOn {
		t.Errorf("persisted watch = %v, want false", watchOn)
	}
}

func TestTelegramStopDispatch(t *testing.T) {
	t.Parallel()
	// No active turn: the server-side cancel still runs, and
	// the reply reports what the server said.
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBot(t, gw, []string{telegramUpdate(1, 111, "/stop")})
	defer cancel()
	send := waitForSend(t, h, "⏹")
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	if send != "⏹ Stopped Muse's turn." {
		t.Errorf("stop send = %q", send)
	}
	if _, _, _, cancels := gw.counts(); cancels != 1 {
		t.Errorf("cancelCalls = %d, want 1", cancels)
	}
}

func TestTelegramStopDispatchCancelsRunningTurn(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.blockSub = make(chan struct{})
	gw.subScripts = []turnSubScript{{replyText: "Slow reply", deltas: []string{"Slow"}}}
	h, cancel, codeCh := runTelegramBotGated(t, gw, []string{
		telegramUpdate(1, 111, "first"),
		telegramUpdate(2, 111, "/stop"),
	}, []func(*cmdFakeTelegram) bool{
		nil,
		func(*cmdFakeTelegram) bool {
			_, _, subscribes, _ := gw.counts()
			return subscribes >= 1
		},
	})
	defer cancel()
	send := waitForSend(t, h, "⏹ Stopped Muse's turn.")
	// The turn itself ends with the Stopped bubble edit.
	waitFor(t, "stopped bubble edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "⏹ Stopped.") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	if send != "⏹ Stopped Muse's turn." {
		t.Errorf("stop send = %q", send)
	}
	if _, _, _, cancels := gw.counts(); cancels != 1 {
		t.Errorf("cancelCalls = %d, want 1", cancels)
	}
}

// wiredBot is a Bot with the full A3/A4 wiring, started
// against the fake server, for callback-action tests.
type wiredBot struct {
	bot     *telegram.Bot
	handler *telegramCmdHandler
	fake    *cmdFakeTelegram
	gw      *telegramTurnFakeGateway
	store   *telegram.StateStore
	cancel  context.CancelFunc
	done    chan struct{}
}

func startWiredBot(t *testing.T, gw *telegramTurnFakeGateway) *wiredBot {
	t.Helper()
	// Non-nil empty batches: the fake serves nothing until the
	// test stages batches with setBatches (nil would serve the
	// default "hello" update once).
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
	storeDir := t.TempDir()
	store, _, err := telegram.LoadStateStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	muse := conn.New(func(context.Context, conn.Config) (conn.Gateway, error) { return gw, nil })
	rt := &Runtime{Muse: muse, Profile: &profile.Profile{Name: "muse01", NodeID: "node-1", VMID: "vm-test"}}
	toggles := func() (bool, bool) {
		aa, ao, _ := store.Toggles()
		approve, allowOnce := false, false
		if aa != nil {
			approve = *aa
		}
		if ao != nil {
			allowOnce = *ao
		}
		return approve, allowOnce
	}
	var bot *telegram.Bot
	var runner *telegramTurnRunner
	var handler *telegramCmdHandler
	bot, err = telegram.New(telegram.Settings{
		Token:          telegramTestToken,
		AllowedUserIDs: []int64{111},
		HTTPClient:     fakeClient,
		Logger:         slog.Default(),
		Decider:        gatewayDecider{muse: muse},
		Pending: func(ctx context.Context) ([]telegram.Approval, error) {
			return telegramPendingApprovals(ctx, rt)
		},
		Resume: func(ctx context.Context, info telegram.ResumeInfo) error {
			return runner.runResume(ctx, info)
		},
		MessageHandler: func(ctx context.Context, mc telegram.MessageContext) error {
			return handler.dispatch(ctx, mc)
		},
		CallbackFunc: func(ctx context.Context, chatID int64, messageID int, entry telegram.CallbackEntry) (bool, error) {
			return handler.handleCallback(ctx, chatID, messageID, entry)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	runner = newTelegramTurnRunner(telegramTurnDeps{
		env:     &Env{},
		bot:     bot,
		rt:      rt,
		prof:    rt.Profile,
		store:   store,
		logger:  slog.Default(),
		toggles: toggles,
	})
	handler = &telegramCmdHandler{
		env:     &Env{},
		bot:     bot,
		rt:      rt,
		prof:    rt.Profile,
		store:   store,
		runner:  runner,
		toggles: toggles,
		logger:  slog.Default(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = bot.Start(ctx); close(done) }()
	return &wiredBot{bot: bot, handler: handler, fake: fake, gw: gw, store: store, cancel: cancel, done: done}
}

func callbackUpdate(updateID int64, data string, messageID int) string {
	dataJSON, _ := json.Marshal(data)
	return `{"ok":true,"result":[{"update_id":` + strconv.FormatInt(updateID, 10) + `,"callback_query":{"id":"q1","from":{"id":111,"is_bot":false,"first_name":"Tester"},"message":{"message_id":` + strconv.Itoa(messageID) + `,"chat":{"id":500,"type":"private"},"text":"picker"},"data":` + string(dataJSON) + `}}]}`
}

func TestCallbackAnswerStartsTurn(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "Yes, going ahead", deltas: []string{"Yes"}}}
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	data := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "answer", Answer: "Yes please"})
	wb.fake.setBatches([]string{callbackUpdate(9, data, 50)})
	waitFor(t, "answer turn final edit", func() bool {
		for _, e := range wb.fake.editTexts() {
			if strings.Contains(e, "Yes, going ahead") {
				return true
			}
		}
		return false
	})
	wb.cancel()
	<-wb.done
	wb.fake.mu.Lock()
	sends := append([]string(nil), wb.fake.sends...)
	wb.fake.mu.Unlock()
	found := false
	for _, s := range sends {
		if s == "➡️ Yes please" {
			found = true
		}
	}
	if !found {
		t.Errorf("sends = %q; want the silent answer echo", sends)
	}
	if _, streams, _, _ := gw.counts(); streams != 1 {
		t.Errorf("openStreams = %d, want 1 (the answer started a turn)", streams)
	}
}

func TestCallbackOpenAndChatsPage(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.sessionsScript = []any{
		sessionRow("s1", "One", true, false, false, 900),
		sessionRow("s2", "Two", true, false, false, 800),
		sessionRow("s3", "Three", true, false, false, 700),
		sessionRow("s4", "Four", true, false, false, 600),
		sessionRow("s5", "Five", true, false, false, 500),
		sessionRow("s6", "Six", true, false, false, 400),
		sessionRow("s7", "Seven", true, false, false, 300),
		sessionRow("s8", "Eight", true, false, false, 200),
		sessionRow("s9", "Nine", true, false, false, 100),
		sessionRow("s10", "Ten", true, false, false, 50),
	}
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	// Page 1 first, via the /chats command.
	wb.fake.setBatches([]string{telegramUpdate(1, 111, "/chats")})
	waitFor(t, "picker send", func() bool {
		wb.fake.mu.Lock()
		defer wb.fake.mu.Unlock()
		return len(wb.fake.sends) >= 1
	})
	// The picker send returns message_id 100 in the fake; page
	// forward edits it.
	pageData := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "chats_page", Page: 1})
	wb.fake.setBatches([]string{callbackUpdate(2, pageData, 100)})
	waitFor(t, "page 2 edit", func() bool {
		for _, e := range wb.fake.editTexts() {
			if strings.Contains(e, "page 2/2") {
				return true
			}
		}
		return false
	})
	// Open "Ten" from page 2.
	openData := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "open", SessionID: "s10", Title: "Ten"})
	wb.fake.setBatches([]string{callbackUpdate(3, openData, 100)})
	waitFor(t, "open reply", func() bool {
		wb.fake.mu.Lock()
		defer wb.fake.mu.Unlock()
		for _, s := range wb.fake.sends {
			if strings.Contains(s, "Now in: <b>Ten</b>") {
				return true
			}
		}
		return false
	})
	wb.cancel()
	<-wb.done
	mapping, ok := wb.store.Chat(500)
	if !ok || mapping.SessionID != "s10" || mapping.Title != "Ten" {
		t.Errorf("chat mapping = %+v, want s10/Ten", mapping)
	}
	wb.fake.mu.Lock()
	editJSON := ""
	if len(wb.fake.editMarkupJSON) > 0 {
		editJSON = wb.fake.editMarkupJSON[0]
	}
	wb.fake.mu.Unlock()
	rows := markupButtons(t, editJSON)
	lastRow := rows[len(rows)-1]
	if len(lastRow) != 1 || lastRow[0] != "◀ Prev" {
		t.Errorf("page-2 nav row = %v, want only Prev", lastRow)
	}
}

func TestCallbackDeleteAndNoop(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	if err := wb.store.SetChat(500, telegram.ChatEntry{SessionID: "sess-9", Title: "Chat 9"}); err != nil {
		t.Fatal(err)
	}
	delData := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "delete", SessionID: "sess-9"})
	noopData := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "noop"})
	wb.fake.setBatches([]string{
		callbackUpdate(9, delData, 50),
		callbackUpdate(10, noopData, 51),
	})
	waitFor(t, "delete + cancel edits", func() bool {
		edits := wb.fake.editTexts()
		if len(edits) < 2 {
			return false
		}
		return strings.Contains(edits[0], "🗑 Deleted") && strings.Contains(edits[1], "Cancelled.")
	})
	wb.cancel()
	<-wb.done
	ops := gw.sessionOps()
	if len(ops) != 1 || ops[0]["method"] != "session.delete" || ops[0]["session_id"] != "sess-9" {
		t.Fatalf("session ops = %v, want one delete of sess-9", ops)
	}
	if mapping, ok := wb.store.Chat(500); !ok || mapping.SessionID != "" {
		t.Errorf("chat mapping after delete = %+v, want main chat", mapping)
	}
}

func TestCallbackDecideResumesTurn(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "Continued", deltas: []string{"Con"}}}
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	// AfterSeq is the last record seq seen when the approval
	// arrived: the fake's user message has seq 9, so the
	// boundary is 9 — an older value makes the runner treat
	// that user message as superseding the resume's reply.
	afterSeq := int64(9)
	data := wb.bot.Registry().Register(telegram.CallbackEntry{
		Action: "decide", ApprovalID: "A1", Decision: "allow_always",
		SessionID: "", Title: "main chat", AfterSeq: &afterSeq,
	})
	wb.fake.setBatches([]string{callbackUpdate(9, data, 50)})
	waitFor(t, "resume final edit", func() bool {
		for _, e := range wb.fake.editTexts() {
			if strings.Contains(e, "Continued") {
				return true
			}
		}
		return false
	})
	wb.cancel()
	<-wb.done
	calls := gw.decideHistory()
	if len(calls) != 1 || calls[0] != (decideRecord{approvalID: "A1", decision: "allow_always"}) {
		t.Fatalf("decide calls = %+v", calls)
	}
	wb.fake.mu.Lock()
	sends := append([]string(nil), wb.fake.sends...)
	wb.fake.mu.Unlock()
	foundConfirm, foundBubble := false, false
	for _, s := range sends {
		if strings.Contains(s, "✅ Always allowed") {
			foundConfirm = true
		}
		if strings.Contains(s, "Muse is continuing") {
			foundBubble = true
		}
	}
	if !foundConfirm || !foundBubble {
		t.Errorf("sends = %q; want the decide confirm + the resume bubble", sends)
	}
}

func TestRuntimeLoggerRoutesThroughFactory(t *testing.T) {
	t.Parallel()
	// No factory: the slog.Default() fallback, as before.
	if got := (&Runtime{}).Logger("telegram"); got == nil {
		t.Error("nil-runtime Logger is nil")
	}
	// With a factory: a distinct logger, not the default.
	handle, err := logging.NewFactory(context.Background(), logging.Settings{Disabled: true}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	rt := &Runtime{}
	rt.logHandle = handle
	if got := rt.Logger("telegram"); got == nil || got == slog.Default() {
		t.Error("factory Logger fell back to slog.Default()")
	}
}
