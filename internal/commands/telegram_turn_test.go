// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// Turn-runner tests: the full `telegram run` path against a fake
// Telegram server and a scripted in-memory Muse gateway. No live
// network, no token, no cookies. Assertions are on observable
// Telegram + gateway calls (sends, edits, history reads, stream
// opens), never on runner internals.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
	"github.com/thoitiettxl-cyber/castctl/internal/wait"
)

// telegramTurnFakeGateway is an in-memory Muse gateway with an
// append-only event log. chat.history reads slice the log by
// limit (limit 1 = latest event only, the deliverSend baseline;
// any larger limit = the whole log). OpenStream records the
// sent text as a user event (unless noAck). SubscribeRaw
// appends the scripted assistant reply to the log, then feeds
// the scripted delta records plus a terminal task.status, so
// the waiter's settle history read sees the reply. It embeds
// conn.Gateway so only the methods the turn path uses need
// bodies; Ping/Alive/Dead/LastRecv/LastUsed/Close are
// implemented because the process-lifetime heartbeat probes
// the shared gateway.
type telegramTurnFakeGateway struct {
	conn.Gateway
	mu              sync.Mutex
	events          []map[string]any
	nextSeq         int64
	historyCalls    int
	openStreams     int
	subscribeCalls  int
	cancelCalls     int
	decideCalls     []decideRecord
	decideErr       error
	approvalsScript []any
	// approvalsFallback makes egress.approvals answer under
	// the "pending" key instead of "pending_approvals".
	approvalsFallback bool
	approvalsErr      error
	subScripts        []turnSubScript
	blockSub          chan struct{}
	noAck             bool
}

// decideRecord is one egress.approval.decide call.
type decideRecord struct {
	approvalID string
	decision   string
}

// turnSubScript is one SubscribeRaw call's feed: the assistant
// reply appended to the history log, the delta texts fed live,
// the raw approval records fed live, and the terminal
// task.status.
type turnSubScript struct {
	replyText       string
	deltas          []string
	approvalRecords []string
}

func newTelegramTurnFakeGateway() *telegramTurnFakeGateway {
	return &telegramTurnFakeGateway{
		events: []map[string]any{{
			"event_name": "message.user", "seq": int64(9),
			"payload": map[string]any{"display_text": "earlier"},
		}},
		nextSeq: 10,
	}
}

func (f *telegramTurnFakeGateway) CallJSON(ctx context.Context, method string, opts conn.RequestOptions) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch method {
	case "chat.history":
		f.historyCalls++
		limit := 0
		if body, ok := opts.Body.(map[string]any); ok {
			limit, _ = body["limit"].(int)
		}
		events := f.events
		if limit == 1 && len(events) > 0 {
			events = events[len(events)-1:]
		}
		out := make([]any, len(events))
		for i, ev := range events {
			out[i] = ev
		}
		return map[string]any{"chat_events": out}, nil
	case "chat.cancel":
		f.cancelCalls++
		return map[string]any{"cancelled": true}, nil
	case "egress.approval.decide":
		if f.decideErr != nil {
			return nil, f.decideErr
		}
		id := ""
		if opts.PathParams != nil {
			id = opts.PathParams["approval_id"]
		}
		decision := ""
		if body, ok := opts.Body.(map[string]any); ok {
			decision, _ = body["decision"].(string)
		}
		f.decideCalls = append(f.decideCalls, decideRecord{approvalID: id, decision: decision})
		return map[string]any{"ok": true}, nil
	case "egress.approvals":
		if f.approvalsErr != nil {
			return nil, f.approvalsErr
		}
		if f.approvalsFallback {
			return map[string]any{"pending": f.approvalsScript}, nil
		}
		return map[string]any{"pending_approvals": f.approvalsScript}, nil
	default:
		return nil, fmt.Errorf("unexpected method %s", method)
	}
}

func (f *telegramTurnFakeGateway) OpenStream(ctx context.Context, method string, opts conn.OpenStreamOptions) (int64, error) {
	if method != "chat.stream" {
		return 0, fmt.Errorf("unexpected stream method %s", method)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openStreams++
	if !f.noAck {
		text := ""
		if body, ok := opts.Body.(map[string]any); ok {
			if items, ok := body["items"].([]any); ok && len(items) > 0 {
				if item, ok := items[0].(map[string]any); ok {
					text, _ = item["text"].(string)
				}
			}
		}
		seq := f.nextSeq
		f.nextSeq++
		f.events = append(f.events, map[string]any{
			"event_name": "message.user", "seq": seq,
			"payload": map[string]any{"display_text": text},
		})
	}
	return 7, nil
}

func (f *telegramTurnFakeGateway) SubscribeRaw(ctx context.Context, method string, opts conn.SubscribeOptions) ([][]byte, error) {
	if method != "chat.subscribe" {
		return nil, fmt.Errorf("unexpected subscribe method %s", method)
	}
	f.mu.Lock()
	f.subscribeCalls++
	callIdx := f.subscribeCalls - 1
	block := f.blockSub
	f.mu.Unlock()
	if block != nil && callIdx == 0 {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	var script turnSubScript
	if callIdx < len(f.subScripts) {
		script = f.subScripts[callIdx]
	}
	// Append the reply to the history log BEFORE feeding, so
	// the settle history read sees it.
	var replySeq int64
	if script.replyText != "" {
		replySeq = f.nextSeq
		f.nextSeq++
		f.events = append(f.events, map[string]any{
			"event_name": "message.assistant", "seq": replySeq,
			"payload": map[string]any{"display_text": script.replyText, "status": "completed"},
		})
	}
	onRecord := opts.OnRecord
	f.mu.Unlock()
	feed := func(rec string) bool {
		if onRecord == nil {
			return false
		}
		return onRecord([]byte(rec))
	}
	for _, delta := range script.deltas {
		rec, _ := json.Marshal(map[string]any{
			"event_name": "delta.text_append", "seq": replySeq,
			"payload": map[string]any{"text": delta, "message_id": "m1"},
		})
		if feed(string(rec)) {
			return nil, nil
		}
	}
	for _, rec := range script.approvalRecords {
		if feed(rec) {
			return nil, nil
		}
	}
	if script.replyText != "" {
		rec, _ := json.Marshal(map[string]any{
			"event": "task.status", "seq": replySeq + 1,
			"payload": map[string]any{"status": "completed", "root_agent_id": "R", "agent_id": "R"},
		})
		feed(string(rec))
	}
	return nil, nil
}

func (f *telegramTurnFakeGateway) Ping(context.Context, time.Duration) (any, error) {
	return map[string]any{"ok": true}, nil
}

func (f *telegramTurnFakeGateway) Alive() bool { return true }

func (f *telegramTurnFakeGateway) Dead() error { return nil }

func (f *telegramTurnFakeGateway) LastRecv() time.Time { return time.Now() }

func (f *telegramTurnFakeGateway) LastUsed() time.Time { return time.Now() }

func (f *telegramTurnFakeGateway) Close() error { return nil }

func (f *telegramTurnFakeGateway) counts() (history, streams, subscribes, cancels int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.historyCalls, f.openStreams, f.subscribeCalls, f.cancelCalls
}

func (f *telegramTurnFakeGateway) decideHistory() []decideRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]decideRecord(nil), f.decideCalls...)
}

// telegramBotHarness runs `telegram run` against a fake
// Telegram server and a scripted fake gateway. The caller waits
// on fake observations, then cancels; run returns the exit code.
type telegramBotHarness struct {
	fake    *cmdFakeTelegram
	gw      *telegramTurnFakeGateway
	homeDir string
}

func runTelegramBot(t *testing.T, gw *telegramTurnFakeGateway, batches []string) (*telegramBotHarness, context.CancelFunc, chan int) {
	return runTelegramBotGated(t, gw, batches, nil)
}

func runTelegramBotGated(t *testing.T, gw *telegramTurnFakeGateway, batches []string, gates []func(*cmdFakeTelegram) bool) (*telegramBotHarness, context.CancelFunc, chan int) {
	t.Helper()
	fake := &cmdFakeTelegram{batches: batches, gates: gates}
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
	env := &Env{Stdout: &strings.Builder{}, Stderr: &strings.Builder{}, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	muse := conn.New(func(context.Context, conn.Config) (conn.Gateway, error) { return gw, nil })
	env.BuildRuntime = func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, env *Env) (*Runtime, error) {
		return &Runtime{Profile: prof, Muse: muse, httpClientOverride: fakeClient}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	codeCh := make(chan int, 1)
	go func() { codeCh <- Run(ctx, []string{"telegram", "run"}, env) }()
	h := &telegramBotHarness{fake: fake, gw: gw, homeDir: home}
	return h, cancel, codeCh
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// stateStore loads the state file the bot wrote under the test
// home, asserting its 0600 mode. It fails when no state file
// exists.
func (h *telegramBotHarness) stateStore(t *testing.T) *telegram.StateStore {
	t.Helper()
	path := h.stateFilePath(t)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("state file mode = %o, want 0600", info.Mode().Perm())
	}
	store, corrupt, err := telegram.LoadStateStore(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if corrupt {
		t.Error("state file loads as corrupt")
	}
	return store
}

func (h *telegramBotHarness) stateFilePath(t *testing.T) string {
	t.Helper()
	var path string
	_ = filepath.Walk(h.homeDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Name() == "telegram-state.json" {
			path = p
		}
		return nil
	})
	if path == "" {
		t.Fatal("no telegram-state.json under the test home")
	}
	return path
}

func (h *telegramBotHarness) hasStateFile() bool {
	found := false
	_ = filepath.Walk(h.homeDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Name() == "telegram-state.json" {
			found = true
		}
		return nil
	})
	return found
}

func telegramUpdate(updateID int64, userID int64, text string) string {
	textJSON, _ := json.Marshal(text)
	return fmt.Sprintf(`{"ok":true,"result":[{"update_id":%d,"message":{"message_id":1,"date":1700000000,"chat":{"id":500,"type":"private"},"from":{"id":%d,"is_bot":false,"first_name":"Tester"},"text":%s}}]}`, updateID, userID, textJSON)
}

func TestTelegramRunTurnDeliversStreamedEditedReply(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{{replyText: "Hello back", deltas: []string{"Hel", "Hello"}}}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{telegramUpdate(1, 111, "hello")})
	defer cancel()
	waitFor(t, "final edit with the reply", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Hello back") {
				return true
			}
		}
		return false
	})
	// The streaming edits carried the partial text before the
	// final edit landed: the first delta feeds synchronously
	// into an immediate edit, before the terminal record.
	sawPartial := false
	for _, e := range h.fake.editTexts() {
		if strings.Contains(e, "Hel") && !strings.Contains(e, "Hello back") {
			sawPartial = true
		}
	}
	if !sawPartial {
		t.Errorf("edits = %q; want a streaming edit with partial text before the final reply", h.fake.editTexts())
	}
	cancel()
	code := <-codeCh
	if code != 130 {
		t.Errorf("run code = %d; want 130 (interrupted)", code)
	}
	h.fake.mu.Lock()
	sends := append([]string(nil), h.fake.sends...)
	h.fake.mu.Unlock()
	if len(sends) < 1 || !strings.Contains(sends[0], "Sending to Muse") {
		t.Errorf("sends = %q; want the streaming bubble first", sends)
	}
	for _, s := range sends {
		if strings.Contains(s, "does not run Muse turns yet") {
			t.Errorf("placeholder notice still sent: %q", s)
		}
	}
	history, streams, subscribes, _ := gw.counts()
	if streams != 1 {
		t.Errorf("openStreams = %d, want 1 (one send)", streams)
	}
	if subscribes < 1 {
		t.Errorf("subscribeCalls = %d, want >= 1", subscribes)
	}
	if history < 3 {
		t.Errorf("historyCalls = %d, want >= 3 (baseline + confirm + ack poll)", history)
	}
	if got := h.stateStore(t).Offset(); got != 1 {
		t.Errorf("persisted offset = %d, want 1", got)
	}
}

func TestTelegramRunNonAllowedUserGetsNoReply(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel, codeCh := runTelegramBot(t, gw, []string{telegramUpdate(1, 999, "hello")})
	defer cancel()
	// The gate drops the update before the dispatcher: wait
	// until the batch was served and a second (empty) poll
	// returned, so the drop certainly happened, then settle.
	waitFor(t, "second getUpdates poll", func() bool {
		h.fake.mu.Lock()
		defer h.fake.mu.Unlock()
		n := 0
		for _, m := range h.fake.methods {
			if m == "getUpdates" {
				n++
			}
		}
		return n >= 2
	})
	time.Sleep(200 * time.Millisecond)
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	h.fake.mu.Lock()
	sends := append([]string(nil), h.fake.sends...)
	edits := append([]string(nil), h.fake.edits...)
	h.fake.mu.Unlock()
	if len(sends) != 0 || len(edits) != 0 {
		t.Errorf("sends = %q edits = %q; want no reply content for a non-allowed user", sends, edits)
	}
	history, streams, subscribes, _ := gw.counts()
	if history != 0 || streams != 0 || subscribes != 0 {
		t.Errorf("gateway calls history=%d streams=%d subscribes=%d; want 0/0/0 (no Muse call)", history, streams, subscribes)
	}
	if h.hasStateFile() {
		t.Error("state file was written for a dropped update; the gate promises no state change")
	}
}

func TestTelegramRunFreshReplyPerTurn(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{
		{replyText: "First reply", deltas: []string{"First"}},
		{replyText: "Second reply", deltas: []string{"Second"}},
	}
	h, cancel, codeCh := runTelegramBotGated(t, gw, []string{
		telegramUpdate(1, 111, "hello"),
		telegramUpdate(2, 111, "hello again"),
	}, []func(*cmdFakeTelegram) bool{
		nil,
		// The second update is served only after the first
		// turn's final edit landed: without the gate it
		// would arrive mid-turn and correctly get the busy
		// reply instead of a second turn.
		func(f *cmdFakeTelegram) bool {
			for _, e := range f.editTexts() {
				if strings.Contains(e, "First reply") {
					return true
				}
			}
			return false
		},
	})
	defer cancel()
	waitFor(t, "second turn's final edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Second reply") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	edits := h.fake.editTexts()
	var finals []string
	for _, e := range edits {
		if strings.Contains(e, "reply") {
			finals = append(finals, e)
		}
	}
	if len(finals) < 2 {
		t.Fatalf("edits = %q; want two final edits, one per turn", edits)
	}
	if !strings.Contains(finals[0], "First reply") || !strings.Contains(finals[1], "Second reply") {
		t.Errorf("final edits = %q; want First reply then Second reply (no reply reuse)", finals)
	}
	history, streams, _, _ := gw.counts()
	if streams != 2 {
		t.Errorf("openStreams = %d, want 2 (one send per turn)", streams)
	}
	if history < 6 {
		t.Errorf("historyCalls = %d, want >= 6 (two baselines + confirms + polls)", history)
	}
	if got := h.stateStore(t).Offset(); got != 2 {
		t.Errorf("persisted offset = %d, want 2", got)
	}
}

func TestTelegramRunBusyWhileTurnActive(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.blockSub = make(chan struct{})
	gw.subScripts = []turnSubScript{{replyText: "Slow reply", deltas: []string{"Slow"}}}
	h, cancel, codeCh := runTelegramBot(t, gw, []string{
		telegramUpdate(1, 111, "first"),
		telegramUpdate(2, 111, "second"),
	})
	defer cancel()
	// The second message arrives while the first turn is
	// blocked in its subscription: it must get the busy reply,
	// not queue a second turn.
	waitFor(t, "busy reply", func() bool {
		h.fake.mu.Lock()
		defer h.fake.mu.Unlock()
		for _, s := range h.fake.sends {
			if strings.Contains(s, "already working") {
				return true
			}
		}
		return false
	})
	close(gw.blockSub)
	waitFor(t, "first turn's final edit", func() bool {
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
	_, streams, _, _ := gw.counts()
	if streams != 1 {
		t.Errorf("openStreams = %d, want 1 (the busy message sent nothing)", streams)
	}
}

// directTurnRunner drives a turn runner without `telegram run`,
// for the paths the CLI default timeouts make untestable
// end-to-end (short ack timeout, stop mid-subscription).
func directTurnRunner(t *testing.T, gw *telegramTurnFakeGateway, ackTimeout time.Duration) (*telegramTurnRunner, *cmdFakeTelegram) {
	t.Helper()
	fake := &cmdFakeTelegram{}
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
	bot, err := telegram.New(telegram.Settings{
		Token:          telegramTestToken,
		AllowedUserIDs: []int64{111},
		HTTPClient:     fakeClient,
		Logger:         slog.Default(),
	})
	if err != nil {
		t.Fatal(err)
	}
	store, _, err := telegram.LoadStateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	muse := conn.New(func(context.Context, conn.Config) (conn.Gateway, error) { return gw, nil })
	runner := newTelegramTurnRunner(telegramTurnDeps{
		env:        &Env{},
		bot:        bot,
		rt:         &Runtime{Muse: muse},
		prof:       &profile.Profile{NodeID: "node-1"},
		store:      store,
		logger:     slog.Default(),
		toggles:    func() (bool, bool) { return false, false },
		ackTimeout: ackTimeout,
	})
	return runner, fake
}

func TestTelegramTurnNoAckEditsWarning(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.noAck = true
	runner, fake := directTurnRunner(t, gw, 300*time.Millisecond)
	if err := runner.runTextTurn(context.Background(), 500, "hello"); err != nil {
		t.Fatalf("runTextTurn = %v", err)
	}
	edits := fake.editTexts()
	found := false
	for _, e := range edits {
		if strings.Contains(e, "did not confirm delivery") {
			found = true
		}
	}
	if !found {
		t.Errorf("edits = %q; want the no-ack warning", edits)
	}
	if _, streams, subscribes, _ := gw.counts(); streams != 1 || subscribes != 0 {
		t.Errorf("streams = %d subscribes = %d; want 1/0 (sent, never waited)", streams, subscribes)
	}
}

func TestTelegramStopTurnCancelsActiveTurn(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.blockSub = make(chan struct{})
	gw.subScripts = []turnSubScript{{replyText: "Slow reply", deltas: []string{"Slow"}}}
	runner, fake := directTurnRunner(t, gw, 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- runner.runTextTurn(context.Background(), 500, "first") }()
	waitFor(t, "turn inside its subscription", func() bool {
		_, _, subscribes, _ := gw.counts()
		return subscribes >= 1
	})
	cancelled, err := runner.stopTurn(context.Background(), 500)
	if err != nil {
		t.Fatalf("stopTurn = %v", err)
	}
	if !cancelled {
		t.Error("stopTurn cancelled = false, want true (chat.cancel said so)")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("turn returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("turn did not end after stop")
	}
	_, _, _, cancels := gw.counts()
	if cancels != 1 {
		t.Errorf("cancelCalls = %d, want 1", cancels)
	}
	stopped := false
	for _, e := range fake.editTexts() {
		if strings.Contains(e, "⏹ Stopped.") {
			stopped = true
		}
	}
	if !stopped {
		t.Errorf("edits = %q; want the bubble edited to Stopped", fake.editTexts())
	}
}

// questionOptions / listOptions / outcomeNotes unit tests.

func TestQuestionOptionsWidget(t *testing.T) {
	t.Parallel()
	reply := wait.Reply{Widgets: []wait.Widget{{
		Options: []any{"Alpha", "Beta"},
	}}}
	opts := questionOptions(reply)
	if len(opts) != 2 || opts[0].value != "Alpha" || opts[1].value != "Beta" {
		t.Fatalf("widget string options = %+v", opts)
	}
	reply = wait.Reply{Widgets: []wait.Widget{{
		Options: []any{map[string]any{"label": "Pick me", "value": "pick"}, "Plain"},
	}}}
	opts = questionOptions(reply)
	if len(opts) != 2 || opts[0].label != "Pick me" || opts[0].value != "pick" || opts[1].value != "Plain" {
		t.Fatalf("widget dict options = %+v", opts)
	}
	// More than 10 widget options truncate to 10.
	var many []any
	for i := 0; i < 12; i++ {
		many = append(many, fmt.Sprintf("opt%d", i))
	}
	opts = questionOptions(wait.Reply{Widgets: []wait.Widget{{Options: many}}})
	if len(opts) != 10 {
		t.Fatalf("widget options = %d, want 10", len(opts))
	}
}

func TestQuestionOptionsListAndGeneric(t *testing.T) {
	t.Parallel()
	text := "Pick one:\n1. Apple\n2. Banana\n3. Cherry\nWhich do you want?"
	opts := questionOptions(wait.Reply{Text: text})
	if len(opts) != 3 || opts[0].value != "Apple" || opts[2].value != "Cherry" {
		t.Fatalf("list options = %+v", opts)
	}
	text = "Pick one:\n- Red\n• Blue\n* Green"
	opts = questionOptions(wait.Reply{Text: text})
	if len(opts) != 3 || opts[1].value != "Blue" {
		t.Fatalf("bullet options = %+v", opts)
	}
	// A single item is not a list: generic fallback.
	opts = questionOptions(wait.Reply{Text: "Just one thing:\n1. Only"})
	if len(opts) != 3 || opts[0].value != "Yes" {
		t.Fatalf("generic options = %+v", opts)
	}
	// No list at all: generic fallback.
	opts = questionOptions(wait.Reply{Text: "What should I do?"})
	if len(opts) != 3 || opts[2].value != "Go ahead" {
		t.Fatalf("generic options = %+v", opts)
	}
}

func TestParseListItem(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{"1. Apple", "Apple", true},
		{"(2) Banana", "Banana", true},
		{"(a) Cherry", "Cherry", true},
		{"- Red", "Red", true},
		{"• Blue", "Blue", true},
		{"* Green", "Green", true},
		{"Hello world", "", false},
		{"-", "", false},
		{"1. ", "", false},
		{"1.5 things", "5 things", true},
	}
	for _, tc := range cases {
		got, ok := parseListItem(tc.line)
		if ok != tc.ok || got != tc.want {
			t.Errorf("parseListItem(%q) = (%q,%v), want (%q,%v)", tc.line, got, ok, tc.want, tc.ok)
		}
	}
	// Over 80 runes is not an item.
	long := "1. " + strings.Repeat("x", 81)
	if _, ok := parseListItem(long); ok {
		t.Error("81-rune item parsed, want rejection")
	}
}

func TestOutcomeNotes(t *testing.T) {
	t.Parallel()
	res := &wait.Result{Outcome: "needs_input"}
	if got := outcomeNotes(res, false); got != "❓ Muse is asking…" {
		t.Errorf("needs_input notes = %q", got)
	}
	res = &wait.Result{Outcome: "failed", Status: "interrupted"}
	if got := outcomeNotes(res, false); got != "⚠️ Muse's turn ended: interrupted" {
		t.Errorf("failed notes = %q", got)
	}
	if got := outcomeNotes(res, true); got != "⏹ Stopped." {
		t.Errorf("stopped notes = %q", got)
	}
	res = &wait.Result{Outcome: "timeout"}
	if got := outcomeNotes(res, false); got != "⌛ Still running after 6h…" {
		t.Errorf("timeout notes = %q", got)
	}
	res = &wait.Result{Outcome: "done"}
	if got := outcomeNotes(res, false); got != "" {
		t.Errorf("done notes = %q, want empty", got)
	}
}

func TestDeliveredTopSeq(t *testing.T) {
	t.Parallel()
	res := &wait.Result{Replies: []wait.Reply{{Seq: 5}, {Seq: 12}, {Seq: 3}}}
	if got := deliveredTopSeq(10, res); got != 12 {
		t.Errorf("top = %d, want 12", got)
	}
	if got := deliveredTopSeq(20, res); got != 20 {
		t.Errorf("top = %d, want 20 (user seq wins)", got)
	}
}
