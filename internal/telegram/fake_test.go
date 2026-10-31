// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

// Fake Telegram server + bot test harness. The fake speaks the Bot
// API over loopback only (httptest), records every method call's
// form fields (never the token-bearing URL), and serves scripted
// results. Fixture token only; no live network, no real bot.

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
	"strings"
	"sync"
	"testing"
	"time"
)

const fakeToken = "123456:FAKE-TOKEN-0123456789ABCD"

// recordedCall is one API call the fake server saw. Form holds the
// first value per multipart field. The request path (which carries
// the token) is never stored.
type recordedCall struct {
	Method string
	Form   map[string]string
}

type scriptedFailure struct {
	Code       int
	Desc       string
	RetryAfter int
}

type fakeTelegramServer struct {
	t      *testing.T
	server *httptest.Server

	mu       sync.Mutex
	calls    []recordedCall
	batches  [][]byte
	nextMsg  int
	getMeErr bool
	// getUpdatesGarbage, when true, makes the next getUpdates
	// return invalid JSON embedding the fixture token (a hostile
	// server body): the bot's error path must scrub it.
	getUpdatesGarbage bool
	// garbageBody, when non-empty, is the exact hostile
	// getUpdates body returned once (invalid JSON carrying a
	// marker distinct from the token, so body-byte leakage is
	// detectable even when the token is scrubbed).
	garbageBody string
	// sendRedirect, when true, makes sendMessage answer 302 to
	// redirectTarget instead of 200: the bot must refuse the
	// redirect and never request the second server.
	sendRedirect   bool
	redirectTarget string
	sendFailures   []scriptedFailure
	editFailures   []scriptedFailure
	editTextTrue   bool
}

func newFakeTelegramServer(t *testing.T) *fakeTelegramServer {
	t.Helper()
	f := &fakeTelegramServer{t: t, nextMsg: 100}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeTelegramServer) url() string { return f.server.URL }

func (f *fakeTelegramServer) handle(w http.ResponseWriter, r *http.Request) {
	method := ""
	rest := strings.TrimPrefix(r.URL.Path, "/bot"+fakeToken+"/")
	if rest == r.URL.Path {
		// Path does not carry the expected token prefix; record
		// it as a bad path without storing the path itself.
		method = "bad-path"
	} else {
		method = strings.Trim(rest, "/")
	}
	form := map[string]string{}
	if err := r.ParseMultipartForm(1 << 20); err == nil && r.MultipartForm != nil {
		for k, v := range r.MultipartForm.Value {
			if len(v) > 0 {
				form[k] = v[0]
			}
		}
	} else if err := r.ParseForm(); err == nil {
		for k, v := range r.Form {
			if len(v) > 0 {
				form[k] = v[0]
			}
		}
	}
	f.mu.Lock()
	f.calls = append(f.calls, recordedCall{Method: method, Form: form})
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	switch method {
	case "getMe":
		if f.getMeErr {
			writeFakeError(w, 401, "Unauthorized")
			return
		}
		fmt.Fprint(w, `{"ok":true,"result":{"id":1,"is_bot":true,"first_name":"Fake","username":"fakebot"}}`)
	case "getUpdates":
		if f.garbageBody != "" {
			f.mu.Lock()
			body := f.garbageBody
			f.garbageBody = ""
			f.mu.Unlock()
			fmt.Fprint(w, body)
			return
		}
		if f.getUpdatesGarbage {
			f.mu.Lock()
			f.getUpdatesGarbage = false
			f.mu.Unlock()
			// Invalid JSON embedding the token: must be scrubbed
			// from every log line the bot emits about it.
			fmt.Fprintf(w, `{"ok":true,"result":[%s]}`, fakeToken)
			return
		}
		f.mu.Lock()
		var batch []byte
		if len(f.batches) > 0 {
			batch = f.batches[0]
			f.batches = f.batches[1:]
		}
		f.mu.Unlock()
		if batch == nil {
			batch = []byte("[]")
		}
		// Small delay so the poll loop does not spin hot.
		time.Sleep(5 * time.Millisecond)
		fmt.Fprintf(w, `{"ok":true,"result":%s}`, batch)
	case "sendMessage":
		f.mu.Lock()
		redirect := f.sendRedirect
		target := f.redirectTarget
		f.mu.Unlock()
		if redirect {
			w.Header().Set("Location", target+"/bot"+fakeToken+"/sendMessage")
			w.WriteHeader(http.StatusFound)
			return
		}
		f.mu.Lock()
		var fail *scriptedFailure
		if len(f.sendFailures) > 0 {
			c := f.sendFailures[0]
			f.sendFailures = f.sendFailures[1:]
			fail = &c
		}
		f.mu.Unlock()
		if fail != nil {
			writeFakeErrorParams(w, fail.Code, fail.Desc, fail.RetryAfter)
			return
		}
		f.mu.Lock()
		id := f.nextMsg
		f.nextMsg++
		f.mu.Unlock()
		fmt.Fprintf(w, `{"ok":true,"result":{"message_id":%d,"chat":{"id":%s,"type":"private"},"date":0,"text":%s}}`,
			id, form["chat_id"], jsonString(form["text"]))
	case "editMessageText":
		f.mu.Lock()
		var fail *scriptedFailure
		if len(f.editFailures) > 0 {
			c := f.editFailures[0]
			f.editFailures = f.editFailures[1:]
			fail = &c
		}
		editTrue := f.editTextTrue
		f.mu.Unlock()
		if fail != nil {
			writeFakeError(w, fail.Code, fail.Desc)
			return
		}
		if editTrue {
			fmt.Fprint(w, `{"ok":true,"result":true}`)
			return
		}
		fmt.Fprintf(w, `{"ok":true,"result":{"message_id":%s,"chat":{"id":%s,"type":"private"},"date":0,"text":%s}}`,
			form["message_id"], form["chat_id"], jsonString(form["text"]))
	case "editMessageReplyMarkup", "answerCallbackQuery", "deleteMessage":
		fmt.Fprint(w, `{"ok":true,"result":true}`)
	default:
		writeFakeError(w, 404, "Not Found")
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func writeFakeError(w http.ResponseWriter, code int, desc string) {
	writeFakeErrorParams(w, code, desc, 0)
}

func writeFakeErrorParams(w http.ResponseWriter, code int, desc string, retryAfter int) {
	params := ""
	if retryAfter > 0 {
		params = fmt.Sprintf(`,"parameters":{"retry_after":%d}`, retryAfter)
	}
	fmt.Fprintf(w, `{"ok":false,"error_code":%d,"description":%s%s}`, code, jsonString(desc), params)
}

// enqueueUpdates appends one getUpdates batch (an array of update
// JSON objects, already marshalled) to the delivery queue.
func (f *fakeTelegramServer) enqueueUpdates(updates ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = append(f.batches, []byte("["+strings.Join(updates, ",")+"]"))
}

func (f *fakeTelegramServer) callsOf(method string) []recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recordedCall
	for _, c := range f.calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeTelegramServer) count(method string) int { return len(f.callsOf(method)) }

// waitFor polls cond until it is true or the deadline passes.
func waitFor(t *testing.T, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

func messageUpdate(id int64, chatID, userID int64, text string) string {
	b, _ := json.Marshal(map[string]any{
		"update_id": id,
		"message": map[string]any{
			"message_id": 1,
			"date":       0,
			"chat":       map[string]any{"id": chatID, "type": "private"},
			"from":       map[string]any{"id": userID, "is_bot": false, "first_name": "Tester"},
			"text":       text,
		},
	})
	return string(b)
}

func messageUpdateNoSender(id int64, chatID int64, text string) string {
	b, _ := json.Marshal(map[string]any{
		"update_id": id,
		"message": map[string]any{
			"message_id": 1,
			"date":       0,
			"chat":       map[string]any{"id": chatID, "type": "private"},
			"text":       text,
		},
	})
	return string(b)
}

func callbackUpdate(id int64, userID, chatID int64, msgID int, data, cqID string) string {
	b, _ := json.Marshal(map[string]any{
		"update_id": id,
		"callback_query": map[string]any{
			"id":   cqID,
			"from": map[string]any{"id": userID, "is_bot": false, "first_name": "Tester"},
			"message": map[string]any{
				"message_id": msgID,
				// Non-zero date: the library treats a date:0
				// message as an inaccessible message.
				"date": 1700000000,
				"chat": map[string]any{"id": chatID, "type": "private"},
				"text": "approval?",
			},
			"data": data,
		},
	})
	return string(b)
}

func fakeHTTPClient() *http.Client {
	// Test-only transport shape satisfying BoundClient: a
	// *http.Transport with an explicit dial path (the loopback
	// fake server is plain HTTP, so DialTLSContext is never
	// invoked; it exists only so the transport is not the
	// stdlib default direct-dial shape).
	dialer := &net.Dialer{}
	return &http.Client{Transport: &http.Transport{
		Proxy:       nil,
		DialContext: dialer.DialContext,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}}
}

// callbackUpdateInaccessible builds a callback_query whose
// message has date 0: the library parses it as a
// MaybeInaccessibleMessage (InaccessibleMessage), not a Message.
func callbackUpdateInaccessible(id int64, userID, chatID int64, msgID int, data, cqID string) string {
	b, _ := json.Marshal(map[string]any{
		"update_id": id,
		"callback_query": map[string]any{
			"id":   cqID,
			"from": map[string]any{"id": userID, "is_bot": false, "first_name": "Tester"},
			"message": map[string]any{
				"message_id": msgID,
				"date":       0,
				"chat":       map[string]any{"id": chatID, "type": "private"},
			},
			"data": data,
		},
	})
	return string(b)
}

// combinedUpdate builds one update carrying BOTH a message and
// a callback_query, with independent senders (a shape real
// servers never emit; only a hostile/compromised response can
// produce it). The gate must follow the dispatched kind.
func combinedUpdate(id int64, msgUserID, msgChatID, cqUserID, cqChatID int64, msgID int, data, cqID string) string {
	b, _ := json.Marshal(map[string]any{
		"update_id": id,
		"message": map[string]any{
			"message_id": 1,
			"date":       1700000000,
			"chat":       map[string]any{"id": msgChatID, "type": "private"},
			"from":       map[string]any{"id": msgUserID, "is_bot": false, "first_name": "Tester"},
			"text":       "combined",
		},
		"callback_query": map[string]any{
			"id":   cqID,
			"from": map[string]any{"id": cqUserID, "is_bot": false, "first_name": "Tester"},
			"message": map[string]any{
				"message_id": msgID,
				"date":       1700000000,
				"chat":       map[string]any{"id": cqChatID, "type": "private"},
				"text":       "approval?",
			},
			"data": data,
		},
	})
	return string(b)
}

type recordingDecider struct {
	mu    sync.Mutex
	calls []decideCall
	err   error
	// block, when non-nil, holds Decide until closed (takeover test).
	block chan struct{}
}

type decideCall struct {
	ID       string
	Decision string
}

func (d *recordingDecider) Decide(_ context.Context, id, decision string) error {
	d.mu.Lock()
	if d.block != nil {
		ch := d.block
		d.mu.Unlock()
		<-ch
		d.mu.Lock()
	}
	d.calls = append(d.calls, decideCall{ID: id, Decision: decision})
	err := d.err
	d.mu.Unlock()
	return err
}

func (d *recordingDecider) recorded() []decideCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]decideCall{}, d.calls...)
}

type recordingHandler struct {
	mu        sync.Mutex
	calls     []MessageContext
	panicErr  error
	panicOnce bool
	panicked  bool
	delay     time.Duration
	returnErr error
}

func (h *recordingHandler) handle(_ context.Context, mc MessageContext) error {
	if h.delay > 0 {
		time.Sleep(h.delay)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, mc)
	if h.panicErr != nil && (!h.panicOnce || !h.panicked) {
		h.panicked = true
		panic(h.panicErr)
	}
	return h.returnErr
}

func (h *recordingHandler) recorded() []MessageContext {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]MessageContext{}, h.calls...)
}

type testBot struct {
	bot     *Bot
	logBuf  *bytes.Buffer
	decider *recordingDecider
	handler *recordingHandler
	resumes []ResumeInfo
	resMu   sync.Mutex
	sleeps  []time.Duration
	sleepMu sync.Mutex
}

func newTestBot(t *testing.T, srv *fakeTelegramServer, mutate func(*Settings)) *testBot {
	t.Helper()
	tb := &testBot{
		logBuf:  &bytes.Buffer{},
		decider: &recordingDecider{},
		handler: &recordingHandler{},
	}
	logger := slog.New(slog.NewTextHandler(tb.logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s := Settings{
		Token:          fakeToken,
		AllowedUserIDs: []int64{111},
		ServerURL:      srv.url(),
		HTTPClient:     fakeHTTPClient(),
		Logger:         logger,
		Decider:        tb.decider,
		MessageHandler: tb.handler.handle,
		ClaimWait:      100 * time.Millisecond,
		Sleep: func(d time.Duration) {
			tb.sleepMu.Lock()
			tb.sleeps = append(tb.sleeps, d)
			tb.sleepMu.Unlock()
		},
		Resume: func(_ context.Context, info ResumeInfo) error {
			tb.resMu.Lock()
			tb.resumes = append(tb.resumes, info)
			tb.resMu.Unlock()
			return nil
		},
	}
	if mutate != nil {
		mutate(&s)
	}
	b, err := New(s)
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	tb.bot = b
	return tb
}

func (tb *testBot) recordedResumes() []ResumeInfo {
	tb.resMu.Lock()
	defer tb.resMu.Unlock()
	return append([]ResumeInfo{}, tb.resumes...)
}

func (tb *testBot) recordedSleeps() []time.Duration {
	tb.sleepMu.Lock()
	defer tb.sleepMu.Unlock()
	return append([]time.Duration{}, tb.sleeps...)
}

// startBot runs Start in a goroutine; the caller cancels ctx and
// waits on done.
func startBot(t *testing.T, b *Bot, ctx context.Context) chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- b.Start(ctx) }()
	return done
}

func stopBot(t *testing.T, cancel context.CancelFunc, done chan error) error {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after cancel")
		return nil
	}
}

var errTestDecider = errors.New("test decider failure")
