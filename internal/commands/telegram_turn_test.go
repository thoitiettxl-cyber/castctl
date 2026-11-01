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
	"runtime/debug"
	"runtime/pprof"
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
	// Command-path scripts.
	sessionsScript      []any
	unreadScript        any
	identityScript      any
	sessionStartScript  map[string]any
	sessionStartErr     error
	sessionOpCalls      []map[string]any
	subScripts          []turnSubScript
	blockSub            chan struct{}
	blockCallIdx        int // subscribe call index to block; 0 (first) by default
	exhaustedSubscribes int
	exhaustedStack      []byte // stack of the first exhausted SubscribeRaw call
	noAck               bool
}

// decideRecord is one egress.approval.decide call.
type decideRecord struct {
	approvalID string
	decision   string
}

// turnSubScript is one SubscribeRaw call's feed: the assistant
// reply appended to the history log, the delta texts fed live,
// the raw approval records fed live, the terminal task.status,
// and (for the /status probe) a standalone task.status record.
type turnSubScript struct {
	replyText       string
	deltas          []string
	approvalRecords []string
	probeStatus     string
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
	case "sessions.list":
		return map[string]any{"sessions": f.sessionsScript}, nil
	case "chat.unread_count":
		if f.unreadScript != nil {
			return f.unreadScript, nil
		}
		return map[string]any{}, nil
	case "identity":
		if f.identityScript != nil {
			return f.identityScript, nil
		}
		return map[string]any{}, nil
	case "session.start":
		if f.sessionStartErr != nil {
			return nil, f.sessionStartErr
		}
		if f.sessionStartScript != nil {
			return f.sessionStartScript, nil
		}
		return map[string]any{}, nil
	case "session.rename", "session.pin", "session.unpin", "session.archive", "session.unarchive", "session.delete":
		b, _ := json.Marshal(opts.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		body["method"] = method
		f.sessionOpCalls = append(f.sessionOpCalls, body)
		return map[string]any{"ok": true}, nil
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
	blockIdx := f.blockCallIdx
	f.mu.Unlock()
	if block != nil && callIdx == blockIdx {
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
	} else {
		// Exhaustion is a test-authoring error, not a script:
		// count it so a hang here is diagnosable instead of a
		// silent resubscribe loop (see TestTelegramRunFreshReplyPerTurn).
		f.exhaustedSubscribes++
		if f.exhaustedStack == nil {
			f.exhaustedStack = debug.Stack()
		}
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
	if script.probeStatus != "" {
		rec, _ := json.Marshal(map[string]any{
			"event": "task.status", "seq": replySeq + 1,
			"payload": map[string]any{"status": script.probeStatus, "root_agent_id": "R", "agent_id": "R"},
		})
		feed(string(rec))
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

// exhausted returns how many SubscribeRaw calls found no script
// left: a positive count on a hung test means the fake ran out
// of scripts, not that the turn logic stalled.
func (f *telegramTurnFakeGateway) exhausted() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exhaustedSubscribes
}

// exhaustedStackTrace returns the stack captured at the first
// exhausted SubscribeRaw call, or "" when no call exhausted.
func (f *telegramTurnFakeGateway) exhaustedStackTrace() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.exhaustedStack)
}

func (f *telegramTurnFakeGateway) decideHistory() []decideRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]decideRecord(nil), f.decideCalls...)
}

// addEvent appends a history event to the log (test setup).
func (f *telegramTurnFakeGateway) addEvent(ev map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
}

// resetHistory restores the fake's event log to its initial
// state (one baseline event, next seq 10), so a later turn
// observes the same user seq as an earlier turn: the
// session-keyed resume-guard repro needs equal AfterSeq
// values across two sessions in one chat (AfterSeq is
// per-session, and the fake's log is global).
func (f *telegramTurnFakeGateway) resetHistory() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = []map[string]any{{
		"event_name": "message.user", "seq": int64(9),
		"payload": map[string]any{"display_text": "earlier"},
	}}
	f.nextSeq = 10
}

// eventsSnapshot returns a copy of the history log.
func (f *telegramTurnFakeGateway) eventsSnapshot() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.events...)
}

func (f *telegramTurnFakeGateway) sessionOps() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.sessionOpCalls...)
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
	return runTelegramBotWithConfig(t, gw, batches, telegramTestConfig(), gates)
}

// runTelegramBotWithConfig is runTelegramBotGated with an
// explicit config JSON: tests that need toggles other than the
// shared config's (auto_approve on) use it.
func runTelegramBotWithConfig(t *testing.T, gw *telegramTurnFakeGateway, batches []string, configJSON string, gates []func(*cmdFakeTelegram) bool) (*telegramBotHarness, context.CancelFunc, chan int) {
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
	home, configFile := testHome(t, configJSON)
	env := &Env{Stdout: &strings.Builder{}, Stderr: &strings.Builder{}, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	muse := conn.New(func(context.Context, conn.Config) (conn.Gateway, error) { return gw, nil })
	env.BuildRuntime = func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, env *Env) (*Runtime, error) {
		// The status report needs a VM id without the
		// FetchSessionInfo fallback (no cookies in tests).
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
	h := &telegramBotHarness{fake: fake, gw: gw, homeDir: home}
	// The returned cancel waits for Run to return (via done,
	// without consuming codeCh, which stays the caller's to
	// read) and then drains in-flight turn goroutines: turns
	// run async (so /stop can run mid-turn), and their
	// deferred watermark save writes into the temp home —
	// without the drain, the save can race t.TempDir cleanup
	// ("directory not empty") or land after the directory
	// is gone. The drain waits for the fake's send/edit
	// counts to stay quiet, which is the turn goroutine's
	// last observable act before the save. Production
	// shutdown does not join turns (documented); this is a
	// test-harness-only join. Safe to call twice: done is
	// closed once, and a second drain finds quiet counts.
	cancel := func() {
		cancelFn()
		<-done
		drainTurns(fake)
	}
	return h, cancel, codeCh
}

// drainTurns waits until the fake has seen no new send/edit
// for 300ms (three quiet 100ms polls), capped at 5s. A turn
// goroutine's final edit precedes its watermark save in the
// same goroutine, so a quiet window means no turn is still
// writing into the temp home.
func drainTurns(fake *cmdFakeTelegram) {
	deadline := time.Now().Add(5 * time.Second)
	lastSends, lastEdits := -1, -1
	quiet := 0
	for time.Now().Before(deadline) {
		fake.mu.Lock()
		sends, edits := len(fake.sends), len(fake.edits)
		fake.mu.Unlock()
		if sends == lastSends && edits == lastEdits {
			quiet++
			if quiet >= 3 {
				return
			}
		} else {
			quiet = 0
			lastSends, lastEdits = sends, edits
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// readState returns the persisted offset and main-chat
// watermark, or ok=false when no state file exists yet or it
// does not load cleanly (a concurrent save mid-read).
func (h *telegramBotHarness) readState() (offset, watermark int64, ok bool) {
	if !h.hasStateFile() {
		return 0, 0, false
	}
	var path string
	_ = filepath.Walk(h.homeDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Name() == "telegram-state.json" {
			path = p
		}
		return nil
	})
	if path == "" {
		return 0, 0, false
	}
	store, corrupt, err := telegram.LoadStateStore(filepath.Dir(path))
	if err != nil || corrupt {
		return 0, 0, false
	}
	return store.Offset(), store.Watermark(telegram.WatermarkKey("")), true
}

// turnDiagnostics snapshots the fake counters, the bot's
// sends, and the persisted state for a hung-turn failure, so
// the next flake is diagnosable from the failure output
// instead of from rerun counts: exhausted>0 implicates fake
// script exhaustion; a busy reply with no second subscribe
// implicates the teardown window; a goroutine dump shows
// where the Runner and dispatcher workers are stuck.
func turnDiagnostics(h *telegramBotHarness, gw *telegramTurnFakeGateway) string {
	hist, streams, subs, cancels := gw.counts()
	offset, watermark, stateOK := h.readState()
	h.fake.mu.Lock()
	sends := append([]string(nil), h.fake.sends...)
	edits := append([]string(nil), h.fake.edits...)
	h.fake.mu.Unlock()
	busy := false
	for _, s := range sends {
		if strings.Contains(s, "already working") {
			busy = true
		}
	}
	var stacks strings.Builder
	_ = pprof.Lookup("goroutine").WriteTo(&stacks, 1)
	dump := stacks.String()
	if len(dump) > 8000 {
		dump = dump[:8000] + "\n...[truncated]"
	}
	return fmt.Sprintf("history=%d streams=%d subscribes=%d cancels=%d exhausted=%d exhaustedStack=%q stateOK=%v offset=%d watermark=%d busyReply=%v sends=%q edits=%q\n-- goroutines --\n%s",
		hist, streams, subs, cancels, gw.exhausted(), gw.exhaustedStackTrace(), stateOK, offset, watermark, busy, sends, edits, dump)
}

// waitForTurnEnd stages on turn completion: the watermark
// advanced past prev in the state file (the save is the turn
// goroutine's last act before it clears the active slot),
// followed by a short quiet window for the slot clear.
// Staging on edit visibility instead races the teardown
// window: the final edit lands before the watermark save and
// the active-slot clear, so a second update staged on the
// edit can get the busy reply and never run a turn.
func waitForTurnEnd(t *testing.T, h *telegramBotHarness, prev int64) {
	t.Helper()
	waitForTimeout(t, "turn-end watermark", 10*time.Second, func() bool {
		_, wm, ok := h.readState()
		return ok && wm > prev
	})
	time.Sleep(150 * time.Millisecond)
}

// TestTelegramResumeAsyncStopRunsMidFollow is the R2
// acceptance test for the async resume: the resume-follow
// runs in its own goroutine under the active-turn guard, so a
// /stop sent while the follow is blocked in its wait is
// processed promptly (the dispatcher worker is free), and a
// concurrent plain message gets the busy reply (the guard
// holds) instead of starting a second turn.
func TestTelegramResumeAsyncStopRunsMidFollow(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	approvalJSON, err := json.Marshal(approvalFixture("A1", "Run tests", "allow_always", "allow_once"))
	if err != nil {
		t.Fatal(err)
	}
	gw.subScripts = []turnSubScript{
		{
			replyText:       "Waiting",
			deltas:          []string{"Wa"},
			approvalRecords: []string{fmt.Sprintf(`{"event":"approvals.snapshot","payload":{"pending_approvals":[%s]}}`, approvalJSON)},
		},
		{replyText: "Continued", deltas: []string{"Co"}},
	}
	// Block the resume follow's subscribe (call index 1);
	// turn 1's subscribe (index 0) runs free. The config
	// leaves auto_approve off (unlike the shared test
	// config): the approval must surface as buttons, not
	// be auto-decided, or there is no tap to resume from.
	gw.blockSub = make(chan struct{})
	gw.blockCallIdx = 1
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{telegramUpdate(1, 111, "run tests")}, telegramTestConfigNoAuto(), nil)
	defer cancel()

	// Stage the tap only after turn 1 ended: the buttons are
	// attached to the final edit, which lands before the
	// watermark save and active-slot clear.
	waitFor(t, "approval note edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Approval: Run tests") {
				return true
			}
		}
		return false
	})
	waitForTurnEnd(t, h, 0)
	// Callback data is an opaque "c:<token>": match the
	// decide button by its label, not by the data.
	data := ""
	waitFor(t, "decide button on the final edit", func() bool {
		h.fake.mu.Lock()
		markups := append([]string(nil), h.fake.editMarkupJSON...)
		h.fake.mu.Unlock()
		for _, m := range markups {
			var markup struct {
				InlineKeyboard [][]struct {
					Text         string `json:"text"`
					CallbackData string `json:"callback_data"`
				} `json:"inline_keyboard"`
			}
			if json.Unmarshal([]byte(m), &markup) != nil {
				continue
			}
			for _, row := range markup.InlineKeyboard {
				for _, btn := range row {
					if btn.Text == "✅ Always allow" {
						data = btn.CallbackData
						return true
					}
				}
			}
		}
		return false
	})
	h.fake.setBatches([]string{callbackUpdate(2, data, 1)})
	// The decide confirm + resume bubble prove cbDecide ran
	// and the follow started; the follow then blocks in its
	// subscribe, holding the active guard.
	waitFor(t, "decide confirm + resume bubble", func() bool {
		foundConfirm, foundBubble := false, false
		h.fake.mu.Lock()
		sends := append([]string(nil), h.fake.sends...)
		h.fake.mu.Unlock()
		for _, s := range sends {
			if strings.Contains(s, "Always allowed") {
				foundConfirm = true
			}
			if strings.Contains(s, "Muse is continuing") {
				foundBubble = true
			}
		}
		return foundConfirm && foundBubble
	})
	// A concurrent plain message must get the busy reply:
	// the resume follow holds the one-turn-per-chat guard.
	h.fake.setBatches([]string{telegramUpdate(3, 111, "second message")})
	waitFor(t, "busy reply for the concurrent message", func() bool {
		h.fake.mu.Lock()
		sends := append([]string(nil), h.fake.sends...)
		h.fake.mu.Unlock()
		for _, s := range sends {
			if strings.Contains(s, "already working") {
				return true
			}
		}
		return false
	})
	// /stop sent while the follow is blocked must be
	// processed promptly: the worker is not behind the
	// follow. 2s is far below the follow's 6h-class wait.
	stopSent := time.Now()
	h.fake.setBatches([]string{telegramUpdate(4, 111, "/stop")})
	waitForTimeout(t, "stop reply while resume blocked", 2*time.Second, func() bool {
		h.fake.mu.Lock()
		sends := append([]string(nil), h.fake.sends...)
		h.fake.mu.Unlock()
		for _, s := range sends {
			if strings.Contains(s, "Stopped Muse") {
				return true
			}
		}
		return false
	})
	if elapsed := time.Since(stopSent); elapsed > 2*time.Second {
		t.Errorf("/stop took %v while the resume follow was blocked; want prompt processing", elapsed)
	}
	// Release the follow: its context was cancelled by the
	// stop, so it ends stopped, not continued.
	close(gw.blockSub)
	waitFor(t, "stopped final edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Stopped.") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("bot exit code = %d, want 130 (interrupted)", code)
	}
	if calls := gw.decideHistory(); len(calls) != 1 {
		t.Fatalf("decide calls = %+v, want exactly 1", calls)
	}
	if _, _, subs, _ := gw.counts(); subs < 2 {
		t.Errorf("subscribe calls = %d, want at least 2 (turn + resume follow)", subs)
	}
}

// TestTelegramResumeDroppedWhileTurnActive covers the
// startResume guard's drop path: a decide tap that arrives
// while another turn holds the chat's active slot schedules
// a follow that must NOT run — the decide still confirms
// (one RPC), but no resume bubble appears, no follow
// subscribes, and the running turn completes normally.
func TestTelegramResumeDroppedWhileTurnActive(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	approvalJSON, err := json.Marshal(approvalFixture("A1", "Run tests", "allow_always", "allow_once"))
	if err != nil {
		t.Fatal(err)
	}
	gw.subScripts = []turnSubScript{
		{
			replyText:       "Waiting",
			deltas:          []string{"Wa"},
			approvalRecords: []string{fmt.Sprintf(`{"event":"approvals.snapshot","payload":{"pending_approvals":[%s]}}`, approvalJSON)},
		},
		{replyText: "Second task reply", deltas: []string{"Se"}},
	}
	// Block the second turn's subscribe (call index 1).
	gw.blockSub = make(chan struct{})
	gw.blockCallIdx = 1
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{telegramUpdate(1, 111, "run tests")}, telegramTestConfigNoAuto(), nil)
	defer cancel()
	waitFor(t, "approval note edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Approval: Run tests") {
				return true
			}
		}
		return false
	})
	waitForTurnEnd(t, h, 0)
	data := ""
	waitFor(t, "decide button on the final edit", func() bool {
		h.fake.mu.Lock()
		markups := append([]string(nil), h.fake.editMarkupJSON...)
		h.fake.mu.Unlock()
		for _, m := range markups {
			var markup struct {
				InlineKeyboard [][]struct {
					Text         string `json:"text"`
					CallbackData string `json:"callback_data"`
				} `json:"inline_keyboard"`
			}
			if json.Unmarshal([]byte(m), &markup) != nil {
				continue
			}
			for _, row := range markup.InlineKeyboard {
				for _, btn := range row {
					if btn.Text == "✅ Always allow" {
						data = btn.CallbackData
						return true
					}
				}
			}
		}
		return false
	})
	// Start turn 2 and wait until its subscribe blocks.
	h.fake.setBatches([]string{telegramUpdate(2, 111, "second task")})
	waitFor(t, "second turn subscribe started", func() bool {
		_, _, subs, _ := gw.counts()
		return subs >= 2
	})
	// Tap the old approval button while turn 2 runs.
	h.fake.setBatches([]string{callbackUpdate(3, data, 1)})
	waitFor(t, "decide confirm while turn active", func() bool {
		h.fake.mu.Lock()
		sends := append([]string(nil), h.fake.sends...)
		h.fake.mu.Unlock()
		for _, s := range sends {
			if strings.Contains(s, "Always allowed") {
				return true
			}
		}
		return false
	})
	// The scheduled follow waits out the slot-wait bound
	// (5s) and drops: no resume bubble may appear in that
	// window, and no follow may subscribe.
	time.Sleep(6 * time.Second)
	h.fake.mu.Lock()
	sends := append([]string(nil), h.fake.sends...)
	h.fake.mu.Unlock()
	for _, s := range sends {
		if strings.Contains(s, "Muse is continuing") {
			t.Errorf("resume bubble sent while a turn was active: %q; want the follow dropped", s)
		}
	}
	if _, _, subs, _ := gw.counts(); subs != 2 {
		t.Errorf("subscribe calls = %d, want exactly 2 (no resume follow)", subs)
	}
	// Release turn 2: it completes normally, with no follow.
	close(gw.blockSub)
	waitFor(t, "second turn final edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Second task reply") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("bot exit code = %d, want 130 (interrupted)", code)
	}
	if calls := gw.decideHistory(); len(calls) != 1 {
		t.Fatalf("decide calls = %+v, want exactly 1", calls)
	}
}

// decideButtonData polls the fake's edit markups for the
// callback data of the newest "✅ Always allow" button whose
// token differs from exclude: the newest match wins, so a
// second turn's buttons are found even when an earlier
// turn's buttons are still recorded (a stale token would
// answer expired and decide nothing).
func decideButtonData(t *testing.T, h *telegramBotHarness, exclude string) string {
	t.Helper()
	data := ""
	waitFor(t, "decide button on the final edit", func() bool {
		h.fake.mu.Lock()
		markups := append([]string(nil), h.fake.editMarkupJSON...)
		h.fake.mu.Unlock()
		for i := len(markups) - 1; i >= 0; i-- {
			var markup struct {
				InlineKeyboard [][]struct {
					Text         string `json:"text"`
					CallbackData string `json:"callback_data"`
				} `json:"inline_keyboard"`
			}
			if json.Unmarshal([]byte(markups[i]), &markup) != nil {
				continue
			}
			for _, row := range markup.InlineKeyboard {
				for _, btn := range row {
					if btn.Text == "✅ Always allow" {
						if btn.CallbackData == exclude {
							return false
						}
						data = btn.CallbackData
						return true
					}
				}
			}
		}
		return false
	})
	return data
}

// TestTelegramResumeGuardKeyedBySession is the R-M1 repro:
// the same Telegram chat runs a main-session turn and a side
// session turn whose AfterSeq values are equal (the fake
// history is reset between them, mirroring per-session seq
// spaces). Both end needs_approval and both Allow taps must
// run their follows: the stale-resume guard is keyed by
// (chat, session), not by chat alone.
func TestTelegramResumeGuardKeyedBySession(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	approval1, err := json.Marshal(approvalFixture("A1", "Run tests", "allow_always", "allow_once"))
	if err != nil {
		t.Fatal(err)
	}
	approval2, err := json.Marshal(approvalFixture("A2", "Side approval", "allow_always", "allow_once"))
	if err != nil {
		t.Fatal(err)
	}
	gw.sessionStartScript = map[string]any{"session_id": "sess-1"}
	gw.subScripts = []turnSubScript{
		{
			replyText:       "Waiting",
			deltas:          []string{"Wa"},
			approvalRecords: []string{fmt.Sprintf(`{"event":"approvals.snapshot","payload":{"pending_approvals":[%s]}}`, approval1)},
		},
		{replyText: "Continued", deltas: []string{"Co"}},
		{
			replyText:       "Side waiting",
			deltas:          []string{"Si"},
			approvalRecords: []string{fmt.Sprintf(`{"event":"approvals.snapshot","payload":{"pending_approvals":[%s]}}`, approval2)},
		},
		{replyText: "Side continued", deltas: []string{"Sc"}},
	}
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{telegramUpdate(1, 111, "run tests")}, telegramTestConfigNoAuto(), nil)
	defer cancel()

	waitFor(t, "approval note edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Approval: Run tests") {
				return true
			}
		}
		return false
	})
	waitForTurnEnd(t, h, 0)
	data1 := decideButtonData(t, h, "")
	h.fake.setBatches([]string{callbackUpdate(2, data1, 1)})
	waitFor(t, "first resume bubble", func() bool {
		for _, s := range sendsOf(h) {
			if strings.Contains(s, "Muse is continuing") {
				return true
			}
		}
		return false
	})
	waitFor(t, "first follow final edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Continued") {
				return true
			}
		}
		return false
	})
	// Reset the fake history so the side session's turn
	// observes the same user seq as the main turn.
	gw.resetHistory()
	h.fake.setBatches([]string{telegramUpdate(3, 111, "/new Side")})
	waitFor(t, "new side chat reply", func() bool {
		for _, s := range sendsOf(h) {
			if strings.Contains(s, "Now in a new side chat") {
				return true
			}
		}
		return false
	})
	h.fake.setBatches([]string{telegramUpdate(4, 111, "side task")})
	waitFor(t, "side approval note edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Approval: Side approval") {
				return true
			}
		}
		return false
	})
	// Stage the second tap on edit visibility: if it lands
	// in the side turn's teardown window, startResume's
	// slot-wait absorbs it (up to 5s).
	data2 := decideButtonData(t, h, data1)
	h.fake.setBatches([]string{callbackUpdate(5, data2, 1)})
	waitFor(t, "two resume bubbles", func() bool {
		n := 0
		for _, s := range sendsOf(h) {
			if strings.Contains(s, "Muse is continuing") {
				n++
			}
		}
		return n >= 2
	})
	waitFor(t, "second follow subscribed", func() bool {
		_, _, subs, _ := gw.counts()
		return subs >= 4
	})
	waitFor(t, "second follow final edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Side continued") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("bot exit code = %d, want 130 (interrupted)", code)
	}
	calls := gw.decideHistory()
	if len(calls) != 2 {
		t.Fatalf("decide calls = %+v, want exactly 2 (A1 + A2)", calls)
	}
	if _, _, subs, _ := gw.counts(); subs != 4 {
		t.Errorf("subscribe calls = %d, want exactly 4 (2 turns + 2 follows)", subs)
	}
}

// lockedWriter is a goroutine-safe strings.Builder for
// capturing slog output from the bot's concurrent workers.
type lockedWriter struct {
	mu sync.Mutex
	sb strings.Builder
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sb.Write(p)
}

func (w *lockedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sb.String()
}

// TestTelegramResumeDropLogsAndNotifies is the R-M3 repro: a
// decide tap that arrives while another turn holds the chat's
// active slot schedules a follow that drops after the 5s
// slot-wait bound. The drop must be observable: a warn log
// naming chat, session, AfterSeq, and reason, plus a
// user-visible notice in the chat. No t.Parallel: the test
// replaces the process default logger to capture the drop
// line, and must not run alongside other tests' log output.
func TestTelegramResumeDropLogsAndNotifies(t *testing.T) {
	var logs lockedWriter
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	gw := newTelegramTurnFakeGateway()
	approvalJSON, err := json.Marshal(approvalFixture("A1", "Run tests", "allow_always", "allow_once"))
	if err != nil {
		t.Fatal(err)
	}
	gw.subScripts = []turnSubScript{
		{
			replyText:       "Waiting",
			deltas:          []string{"Wa"},
			approvalRecords: []string{fmt.Sprintf(`{"event":"approvals.snapshot","payload":{"pending_approvals":[%s]}}`, approvalJSON)},
		},
		{replyText: "Second task reply", deltas: []string{"Se"}},
	}
	// Block the second turn's subscribe (call index 1).
	gw.blockSub = make(chan struct{})
	gw.blockCallIdx = 1
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{telegramUpdate(1, 111, "run tests")}, telegramTestConfigNoAuto(), nil)
	defer cancel()
	waitFor(t, "approval note edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Approval: Run tests") {
				return true
			}
		}
		return false
	})
	waitForTurnEnd(t, h, 0)
	data := decideButtonData(t, h, "")
	// Start turn 2 and wait until its subscribe blocks.
	h.fake.setBatches([]string{telegramUpdate(2, 111, "second task")})
	waitFor(t, "second turn subscribe started", func() bool {
		_, _, subs, _ := gw.counts()
		return subs >= 2
	})
	// Tap the old approval button while turn 2 runs.
	h.fake.setBatches([]string{callbackUpdate(3, data, 1)})
	waitFor(t, "decide confirm while turn active", func() bool {
		for _, s := range sendsOf(h) {
			if strings.Contains(s, "Always allowed") {
				return true
			}
		}
		return false
	})
	// The scheduled follow waits out the slot-wait bound
	// (5s) and drops: no resume bubble, but a drop notice.
	time.Sleep(6 * time.Second)
	sends := sendsOf(h)
	for _, s := range sends {
		if strings.Contains(s, "Muse is continuing") {
			t.Errorf("resume bubble sent while a turn was active: %q; want the follow dropped", s)
		}
	}
	foundNotice := false
	for _, s := range sends {
		if strings.Contains(s, "Follow dropped") && strings.Contains(s, "Send a message to continue") {
			foundNotice = true
		}
	}
	if !foundNotice {
		t.Errorf("drop notice not found in sends = %q", sends)
	}
	if _, _, subs, _ := gw.counts(); subs != 2 {
		t.Errorf("subscribe calls = %d, want exactly 2 (no resume follow)", subs)
	}
	logged := logs.String()
	for _, want := range []string{"telegram resume dropped", "chat_id=500", "after_seq=10", "reason=slot-wait-expired", "session_id="} {
		if !strings.Contains(logged, want) {
			t.Errorf("drop log does not contain %q:\n%s", want, logged)
		}
	}
	// Release turn 2: it completes normally, with no follow.
	close(gw.blockSub)
	waitFor(t, "second turn final edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Second task reply") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("bot exit code = %d, want 130 (interrupted)", code)
	}
	if calls := gw.decideHistory(); len(calls) != 1 {
		t.Fatalf("decide calls = %+v, want exactly 1", calls)
	}
}

// TestTelegramResumeSlotWaitSuccess covers the slot-wait
// success path: a decide tap staged on the approval buttons'
// first visibility — i.e. inside the deciding turn's teardown
// window, while it may still hold the chat's active slot —
// must run its follow, not drop it. The tap may land just
// before or just after the slot clears (the teardown save is
// not synchronised with the tap); both cases must run the
// follow, which is exactly what the slot-wait exists for.
// The wait-then-drop path is covered by
// TestTelegramResumeDroppedWhileTurnActive; this test covers
// the wait-then-run path. An intervening second turn between
// the tap and the follow is NOT staged here: the wait core's
// finish reconcile treats a newer user message as a
// follow-up boundary and drops the follow's reply (observed
// in this harness, stale text delivered — see the fix-loop-2
// report; out of this loop's scope).
func TestTelegramResumeSlotWaitSuccess(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	approvalJSON, err := json.Marshal(approvalFixture("A1", "Run tests", "allow_always", "allow_once"))
	if err != nil {
		t.Fatal(err)
	}
	gw.subScripts = []turnSubScript{
		{
			replyText:       "Waiting",
			deltas:          []string{"Wa"},
			approvalRecords: []string{fmt.Sprintf(`{"event":"approvals.snapshot","payload":{"pending_approvals":[%s]}}`, approvalJSON)},
		},
		{replyText: "Continued", deltas: []string{"Co"}},
	}
	h, cancel, codeCh := runTelegramBotWithConfig(t, gw, []string{telegramUpdate(1, 111, "run tests")}, telegramTestConfigNoAuto(), nil)
	defer cancel()
	// Stage the tap on the buttons' first visibility, NOT on
	// turn-end: the deciding turn is still in teardown
	// (watermark save + slot clear pending) when the tap
	// lands, so startResume must wait the slot out.
	data := decideButtonData(t, h, "")
	h.fake.setBatches([]string{callbackUpdate(2, data, 1)})
	waitFor(t, "decide confirm", func() bool {
		for _, s := range sendsOf(h) {
			if strings.Contains(s, "Always allowed") {
				return true
			}
		}
		return false
	})
	waitFor(t, "resume bubble after tap in teardown window", func() bool {
		for _, s := range sendsOf(h) {
			if strings.Contains(s, "Muse is continuing") {
				return true
			}
		}
		return false
	})
	waitFor(t, "follow final edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Continued") {
				return true
			}
		}
		return false
	})
	for _, s := range sendsOf(h) {
		if strings.Contains(s, "Follow dropped") {
			t.Errorf("drop notice sent on the slot-wait success path: %q", s)
		}
	}
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("bot exit code = %d, want 130 (interrupted)", code)
	}
	if calls := gw.decideHistory(); len(calls) != 1 {
		t.Fatalf("decide calls = %+v, want exactly 1", calls)
	}
	if _, _, subs, _ := gw.counts(); subs != 2 {
		t.Errorf("subscribe calls = %d, want exactly 2 (turn + follow)", subs)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	waitForTimeout(t, what, 10*time.Second, cond)
}

func waitForTimeout(t *testing.T, what string, budget time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
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
	h, cancel, codeCh := runTelegramBot(t, gw, []string{
		telegramUpdate(1, 111, "hello"),
	})
	defer cancel()
	// Two stages, so a timeout names the slow half: the first
	// turn must land its final edit AND end (watermark saved,
	// active slot cleared) before the second update is staged
	// (setBatches, not a poll gate). Staging on the edit alone
	// is the proven flake mechanism (fix loop 1, GOMAXPROCS=2
	// -count=30 probe, 1 failure in the first 11 iterations
	// with diagnostics:
	// subscribes=1, streams=1, exhausted=0, busyReply=true,
	// watermark saved, no Runner goroutine stuck): the final
	// edit lands before the watermark save and the
	// active-slot clear, so an update staged on the edit can
	// arrive while r.active is still set, get the busy reply,
	// and never run a turn — a 120s stage-2 timeout with
	// nothing stuck anywhere. The busy reply in that window
	// is the intended at-most-one-turn guard, not a bug to
	// weaken here; the test must stage on turn-end.
	waitFor(t, "first turn's final edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "First reply") {
				return true
			}
		}
		return false
	})
	waitForTurnEnd(t, h, 0)
	h.fake.setBatches([]string{telegramUpdate(2, 111, "hello again")})
	// Stage 2 keeps the 120s budget and fails with full
	// diagnostics (counts, busy-reply presence, goroutine
	// dump) instead of a bare timeout: the mechanism, not
	// the rerun count, is the evidence.
	{
		deadline := time.Now().Add(120 * time.Second)
		for {
			found := false
			for _, e := range h.fake.editTexts() {
				if strings.Contains(e, "Second reply") {
					found = true
					break
				}
			}
			if found {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for second turn's final edit\n%s", turnDiagnostics(h, gw))
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	// Update 2 must have run a turn, not taken the busy
	// reply: any busy reply here means the staging raced the
	// teardown window again. And no subscribe may have
	// exhausted the fake's scripts: exhaustion would mean
	// the second turn ran on an empty script, not the
	// scripted reply.
	h.fake.mu.Lock()
	sends := append([]string(nil), h.fake.sends...)
	h.fake.mu.Unlock()
	for _, s := range sends {
		if strings.Contains(s, "already working") {
			t.Errorf("busy reply sent for update 2: %q; want a second turn", s)
		}
	}
	if got := gw.exhausted(); got != 0 {
		t.Errorf("exhausted subscribes = %d; want 0", got)
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

// TestBubbleEditorSignalNeverBlocksOnSlowEdit is the R7
// acceptance test for the edit move off the Runner goroutine:
// a slow (2s) streaming edit must not stall the signal path.
// Signals return immediately while the edit is in flight (the
// old maybeEdit-on-OnEvent path would block the first signal
// for the full 2s); the loop goroutine still performs the
// edit, exactly once, and finish() joins it.
func TestBubbleEditorSignalNeverBlocksOnSlowEdit(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	starts, ends := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/getMe") {
			fmt.Fprint(w, `{"ok":true,"result":{"id":1,"is_bot":true,"first_name":"Test","username":"testbot"}}`)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/editMessageText") {
			fmt.Fprint(w, `{"ok":true,"result":true}`)
			return
		}
		mu.Lock()
		starts++
		first := starts == 1
		mu.Unlock()
		if first {
			time.Sleep(2 * time.Second)
		}
		mu.Lock()
		ends++
		mu.Unlock()
		fmt.Fprint(w, `{"ok":true,"result":{"message_id":1,"chat":{"id":500,"type":"private"},"date":0,"text":"ok"}}`)
	}))
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: &http.Transport{DialContext: (&net.Dialer{}).DialContext}}
	bot, err := telegram.New(telegram.Settings{
		Token:          telegramTestToken,
		AllowedUserIDs: []int64{111},
		HTTPClient:     client,
		Logger:         slog.Default(),
		ServerURL:      srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	preview := newStreamPreview(time.Now())
	preview.feed(wait.Event{"event_name": "delta.text_append", "payload": map[string]any{"text": "Hello slow", "message_id": "m1"}})
	editor := newBubbleEditor(bot, context.Background(), 500, 1, preview)
	go editor.loop()
	start := time.Now()
	for i := 0; i < 50; i++ {
		editor.signal()
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("50 signals took %v with a slow edit in flight; want < 1s (non-blocking signal path)", elapsed)
	}
	done := make(chan struct{})
	go func() { editor.finish(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("finish() did not return after the slow edit")
	}
	mu.Lock()
	defer mu.Unlock()
	if starts != 1 || ends != 1 {
		t.Errorf("streaming edits started=%d ended=%d; want exactly 1 (loop edit, no drain duplicate)", starts, ends)
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
	// All widgets are scanned: an empty first widget does not
	// hide the second widget's options.
	reply = wait.Reply{Widgets: []wait.Widget{
		{Options: []any{}},
		{Options: []any{"Second"}},
	}}
	opts = questionOptions(reply)
	if len(opts) != 1 || opts[0].value != "Second" {
		t.Fatalf("second-widget options = %+v, want [Second]", opts)
	}
	// Scalar options stringify; dict key orders fall through
	// empty fields (label→text→title→value,
	// value→label→text→title).
	reply = wait.Reply{Widgets: []wait.Widget{{Options: []any{
		float64(42),
		true,
		map[string]any{"label": "", "text": "T", "value": "v"},
		map[string]any{"value": "only"},
	}}}}
	opts = questionOptions(reply)
	if len(opts) != 4 || opts[0].value != "42" || opts[1].value != "true" ||
		opts[2].label != "T" || opts[2].value != "v" ||
		opts[3].label != "only" || opts[3].value != "only" {
		t.Fatalf("scalar/dict options = %+v", opts)
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
	// Reset rule: a non-option line after options clears the
	// block, unless it ends with "?".
	opts = questionOptions(wait.Reply{Text: "1. A\n2. B\nNot a list\n3. C\n4. D"})
	if len(opts) != 2 || opts[0].value != "C" || opts[1].value != "D" {
		t.Fatalf("reset options = %+v, want [C D]", opts)
	}
	opts = questionOptions(wait.Reply{Text: "1. A\n2. B\nWhich?\n3. C"})
	if len(opts) != 3 || opts[2].value != "C" {
		t.Fatalf("question-tolerated options = %+v, want [A B C]", opts)
	}
	// More than 8 items is not a list: generic fallback, not
	// the first 8.
	var nine strings.Builder
	for i := 1; i <= 9; i++ {
		fmt.Fprintf(&nine, "%d. Item%d\n", i, i)
	}
	opts = questionOptions(wait.Reply{Text: nine.String()})
	if len(opts) != 3 || opts[0].value != "Yes" {
		t.Fatalf("nine-item options = %+v, want generic fallback", opts)
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
		{"1.5 things", "", false},
		{"10. Ten", "Ten", true},
		{"123. Too many digits", "", false},
		{"I. Beyond H", "", false},
		{"H. Last letter", "Last letter", true},
		{"(H) Paren letter", "Paren letter", true},
		{"-nospace", "", false},
		{"1.Nospace", "", false},
		{"•nospace", "", false},
		{"1. *a* _b_ `c`", "a b c", true},
		{"  2.  Spaced  ", "Spaced", true},
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
