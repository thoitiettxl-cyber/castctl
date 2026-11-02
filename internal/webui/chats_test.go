// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeChats is a controllable ChatDeps: the send seam blocks on
// release until the test releases it, so the 409 and polling
// behaviour is deterministic.
type fakeChats struct {
	mu          sync.Mutex
	listCalls   []string
	historySeen []historyCall
	sendCalls   int
	release     chan struct{}
	released    bool
	sendErr     error
	startID     string
}

type historyCall struct {
	profile, session string
	limit            int
}

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

func newFakeChats() *fakeChats {
	return &fakeChats{release: make(chan struct{}), startID: "sess-new"}
}

func (f *fakeChats) deps() *ChatDeps {
	return &ChatDeps{
		ListSessions: func(ctx context.Context, profileName string, includeArchived bool) ([]ChatSession, error) {
			f.mu.Lock()
			f.listCalls = append(f.listCalls, profileName)
			f.mu.Unlock()
			rows := []ChatSession{
				{SessionID: strPtr("a"), Title: strPtr("Main"), Thread: boolPtr(false), Pinned: boolPtr(false), Archived: boolPtr(false), Updated: "2026-11-01 00:00"},
			}
			if includeArchived {
				rows = append(rows, ChatSession{SessionID: strPtr("b"), Title: strPtr("Old"), Thread: boolPtr(true), Pinned: boolPtr(true), Archived: boolPtr(true), Updated: "2026-10-01 00:00"})
			}
			return rows, nil
		},
		GetHistory: func(ctx context.Context, profileName, sessionID string, limit int) ([]ChatEvent, error) {
			f.mu.Lock()
			f.historySeen = append(f.historySeen, historyCall{profileName, sessionID, limit})
			f.mu.Unlock()
			return []ChatEvent{
				{Seq: int64Ptr(1), Role: strPtr("user"), MessageID: strPtr("m1"), Text: "hello"},
				{Seq: int64Ptr(2), Role: strPtr("agent"), MessageID: strPtr("m2"), Text: "hi"},
			}, nil
		},
		StartSession: func(ctx context.Context, profileName, title string) (string, error) {
			return f.startID, nil
		},
		SessionOp: func(ctx context.Context, profileName, sessionID, op, title string) error {
			return nil
		},
		SendChat: func(ctx context.Context, profileName, sessionID, text string) (*ChatSendResult, error) {
			f.mu.Lock()
			f.sendCalls++
			f.mu.Unlock()
			<-f.release
			if f.sendErr != nil {
				return nil, f.sendErr
			}
			return &ChatSendResult{
				Outcome:  "done",
				AfterSeq: 7,
				Replies:  []ChatReply{{Seq: 7, Text: "reply text", MessageID: strPtr("m7")}},
			}, nil
		},
	}
}

func int64Ptr(n int64) *int64 { return &n }

func (f *fakeChats) releaseSend() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.released {
		f.released = true
		close(f.release)
	}
}

func TestChatsListAndHistory(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.Chats = newFakeChats().deps() })
	rec := ts.do(t, "GET", "/api/v1/chats/muse01", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"session_id":"b"`) {
		t.Fatalf("archived session leaked without include_archived: %s", rec.Body.String())
	}
	rec = ts.do(t, "GET", "/api/v1/chats/muse01?include_archived=1", "", true)
	if !strings.Contains(rec.Body.String(), `"session_id":"b"`) {
		t.Fatalf("archived session missing with include_archived: %s", rec.Body.String())
	}
	// History: the "main" segment maps to the empty session id,
	// and limit validation rejects out-of-range values.
	f := newFakeChats()
	ts2 := newTestServer(t, fixtureConfig, func(d *Deps) { d.Chats = f.deps() })
	rec = ts2.do(t, "GET", "/api/v1/chats/muse01/main?limit=10", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("history: got %d: %s", rec.Code, rec.Body.String())
	}
	f.mu.Lock()
	seen := f.historySeen
	f.mu.Unlock()
	if len(seen) != 1 || seen[0].session != "" || seen[0].limit != 10 {
		t.Fatalf("history call = %+v, want one call with empty session and limit 10", seen)
	}
	if !strings.Contains(rec.Body.String(), `"text":"hello"`) {
		t.Fatalf("history body lacks events: %s", rec.Body.String())
	}
	for _, bad := range []string{"0", "201", "abc"} {
		rec = ts2.do(t, "GET", "/api/v1/chats/muse01/main?limit="+bad, "", true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("limit=%s: got %d, want 400", bad, rec.Code)
		}
	}
	// Unknown profile 404s before any seam call.
	rec = ts2.do(t, "GET", "/api/v1/chats/nope", "", true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown profile list: got %d, want 404", rec.Code)
	}
}

func TestChatsUnavailableWithoutSeam(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	rec := ts.do(t, "GET", "/api/v1/chats/muse01", "", true)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("no seam: got %d, want 501", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unavailable") {
		t.Fatalf("no seam body: %s", rec.Body.String())
	}
}

func TestChatsStartAndOps(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.Chats = newFakeChats().deps() })
	rec := ts.do(t, "POST", "/api/v1/chats/muse01", `{"title":"Hello"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("start: got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"session_id":"sess-new"`) {
		t.Fatalf("start body: %s", rec.Body.String())
	}
	// Ops: unknown op and rename-without-title are 400; a
	// delete succeeds.
	rec = ts.do(t, "POST", "/api/v1/chats/muse01/sess-1/op", `{"op":"explode"}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad op: got %d, want 400", rec.Code)
	}
	rec = ts.do(t, "POST", "/api/v1/chats/muse01/sess-1/op", `{"op":"rename"}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("rename without title: got %d, want 400", rec.Code)
	}
	rec = ts.do(t, "POST", "/api/v1/chats/muse01/sess-1/op", `{"op":"rename","title":"New"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename: got %d: %s", rec.Code, rec.Body.String())
	}
	rec = ts.do(t, "POST", "/api/v1/chats/muse01/sess-1/op", `{"op":"delete"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: got %d: %s", rec.Code, rec.Body.String())
	}
	// Unknown field in the body is rejected (strict decode).
	rec = ts.do(t, "POST", "/api/v1/chats/muse01/sess-1/op", `{"op":"pin","bogus":1}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: got %d, want 400", rec.Code)
	}
}

func TestChatsSendJobLifecycle(t *testing.T) {
	f := newFakeChats()
	ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.Chats = f.deps() })
	// Empty text is a validation error, never a job.
	rec := ts.do(t, "POST", "/api/v1/chats/muse01/main/send", `{"text":"  "}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty text: got %d, want 400", rec.Code)
	}
	// Create: 202 with a running job.
	rec = ts.do(t, "POST", "/api/v1/chats/muse01/main/send", `{"text":"hello"}`, true)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send: got %d: %s", rec.Code, rec.Body.String())
	}
	env := decodeEnvelope(t, rec)
	data, _ := env["data"].(map[string]any)
	jobID, _ := data["id"].(string)
	if jobID == "" || data["status"] != "running" {
		t.Fatalf("job view = %v, want id + running", data)
	}
	// A second send on the same profile while one is in flight
	// is a fixed 409.
	rec = ts.do(t, "POST", "/api/v1/chats/muse01/main/send", `{"text":"again"}`, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second send: got %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "send_in_flight") {
		t.Fatalf("409 body: %s", rec.Body.String())
	}
	// Polling shows running until release, then done with the
	// result — and no error field.
	rec = ts.do(t, "GET", "/api/v1/chats/jobs/"+jobID, "", true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"running"`) {
		t.Fatalf("poll running: %d %s", rec.Code, rec.Body.String())
	}
	f.releaseSend()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec = ts.do(t, "GET", "/api/v1/chats/jobs/"+jobID, "", true)
		if strings.Contains(rec.Body.String(), `"status":"done"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job never finished: %s", rec.Body.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(rec.Body.String(), `"outcome":"done"`) || !strings.Contains(rec.Body.String(), `"text":"reply text"`) {
		t.Fatalf("poll done body: %s", rec.Body.String())
	}
	// A different profile is not blocked by this profile's job
	// history (no job is running now in any case): a fresh
	// send on muse01 works again after completion.
	f2 := newFakeChats()
	ts2 := newTestServer(t, fixtureConfig, func(d *Deps) { d.Chats = f2.deps() })
	rec = ts2.do(t, "POST", "/api/v1/chats/muse01/main/send", `{"text":"x"}`, true)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send after completion: got %d, want 202", rec.Code)
	}
	f2.releaseSend()
	// Unknown job 404s.
	rec = ts.do(t, "GET", "/api/v1/chats/jobs/does-not-exist", "", true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown job: got %d, want 404", rec.Code)
	}
}

func TestChatsSendFailureIsFixedMessage(t *testing.T) {
	f := newFakeChats()
	f.sendErr = errors.New("gateway: boom with SECRET-PAYLOAD-MARKER")
	ts := newTestServer(t, fixtureConfig, func(d *Deps) { d.Chats = f.deps() })
	rec := ts.do(t, "POST", "/api/v1/chats/muse01/main/send", `{"text":"hello"}`, true)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send: got %d", rec.Code)
	}
	jobID, _ := decodeEnvelope(t, rec)["data"].(map[string]any)["id"].(string)
	f.releaseSend()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec = ts.do(t, "GET", "/api/v1/chats/jobs/"+jobID, "", true)
		if strings.Contains(rec.Body.String(), `"status":"failed"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job never failed: %s", rec.Body.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(rec.Body.String(), "SECRET-PAYLOAD-MARKER") || strings.Contains(rec.Body.String(), "boom") {
		t.Fatalf("failed job leaks seam error text: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"error":"upstream error"`) {
		t.Fatalf("failed job body: %s", rec.Body.String())
	}
}

func TestChatJobStoreTTLAndCap(t *testing.T) {
	now := time.Now()
	store := newChatJobStore()
	store.now = func() time.Time { return now }
	job, err := store.create("muse01", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	store.finish(job.ID, &ChatSendResult{Outcome: "done"}, "")
	// Inside the TTL the job is still pollable.
	if got := store.get(job.ID); got == nil {
		t.Fatal("job pruned inside TTL")
	}
	// Past the TTL it reads as not found.
	now = now.Add(chatJobTTL + time.Second)
	if got := store.get(job.ID); got != nil {
		t.Fatal("job survived past TTL")
	}
	// The cap evicts the oldest finished jobs, never a running one.
	store2 := newChatJobStore()
	now2 := time.Now()
	store2.now = func() time.Time { return now2 }
	var first string
	for i := 0; i < chatJobMax+5; i++ {
		j, err := store2.create("muse01", "")
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		if i == 0 {
			first = j.ID
		}
		store2.finish(j.ID, &ChatSendResult{Outcome: "done"}, "")
	}
	if got := store2.get(first); got != nil {
		t.Fatal("oldest finished job survived past the cap")
	}
	running, err := store2.create("muse01", "")
	if err != nil {
		t.Fatalf("create running: %v", err)
	}
	for i := 0; i < chatJobMax+5; i++ {
		j, err := store2.create("other", "")
		if err != nil {
			t.Fatalf("create other %d: %v", i, err)
		}
		store2.finish(j.ID, &ChatSendResult{Outcome: "done"}, "")
	}
	if got := store2.get(running.ID); got == nil || got.Status != chatJobRunning {
		t.Fatal("running job was evicted by the cap")
	}
}

func TestPluginsUnavailable(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	rec := ts.do(t, "GET", "/api/v1/plugins", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("plugins: got %d, want 200 with available:false", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"available":false`) {
		t.Fatalf("plugins body lacks available:false: %s", body)
	}
	if !strings.Contains(body, `"plugins":[]`) {
		t.Fatalf("plugins body lacks empty list: %s", body)
	}
	if !strings.Contains(body, `"reason":`) {
		t.Fatalf("plugins body lacks a reason: %s", body)
	}
	// Unauthenticated stays 401: the unavailable advertisement
	// is not a public endpoint.
	rec = ts.do(t, "GET", "/api/v1/plugins", "", false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("plugins unauthenticated: got %d, want 401", rec.Code)
	}
}
