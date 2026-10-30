// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"net/http"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/gateway/gatewaytest"
	pb "github.com/thoitiettxl-cyber/castctl/internal/proto"
)

func TestStatusCommand(t *testing.T) {
	s := newFakeStack(t, routeHandler(map[string]string{
		"/api/session/list":  `{"sessions":[{"session_id":"s1","title":"T","updated_at_ms":1761800000000},{"session_id":"s2","title":"U","updated_at_ms":1761800001000}]}`,
		"/chat/unread-count": `{"unread":3}`,
		"/identity":          `{"name":"Boss"}`,
	}), nil)
	// The profile carries no vm_id, so status resolves it via
	// FetchSessionInfo (CannedAuth VMID). The connector already
	// fetched it once during connect; the gateway exposes no vm_id
	// accessor, so this second call is the documented cost of the
	// fallback (see the final report).
	if code := s.run("status"); code != 0 {
		t.Fatalf("status: code=%d err=%q", code, s.errb.String())
	}
	var summary struct {
		VMID     string `json:"vm_id"`
		Sessions int    `json:"sessions"`
		Unread   any    `json:"unread"`
		Identity any    `json:"identity"`
	}
	mustJSON(t, s.out.Bytes(), &summary)
	if summary.VMID != "vm-test" || summary.Sessions != 2 {
		t.Errorf("summary=%+v", summary)
	}
	if s.auth.SessionCalls.Load() != 2 {
		t.Errorf("session calls=%d, want 2 (connector + vm_id fallback)", s.auth.SessionCalls.Load())
	}
}

func TestStatusWithProfileVMIDSkipsSessionInfo(t *testing.T) {
	_, configFile := testHome(t, `{"profiles":{"default":{"vm_id":"vm-configured"}}}`)
	s := newFakeStack(t, routeHandler(map[string]string{
		"/api/session/list":  `{"sessions":[]}`,
		"/chat/unread-count": `0`,
		"/api/identity":      `{}`,
	}), nil)
	s.env.Getenv = mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})
	if code := s.run("status"); code != 0 {
		t.Fatalf("status: code=%d err=%q", code, s.errb.String())
	}
	if !strings.Contains(s.out.String(), `"vm_id": "vm-configured"`) {
		t.Errorf("out=%q", s.out.String())
	}
	if s.auth.SessionCalls.Load() != 0 {
		t.Errorf("session calls=%d, want 0 (vm_id from profile)", s.auth.SessionCalls.Load())
	}
}

func TestThreadsCommand(t *testing.T) {
	s := newFakeStack(t, routeHandler(map[string]string{
		"/api/session/list": `{"sessions":[
		  {"session_id":"a","title":"Main","is_thread":false,"pinned":false,"archived":false,"updated_at_ms":1761800000000},
		  {"session_id":"b","title":"Old","is_thread":true,"pinned":true,"archived":true,"updated_at_ms":0}]}`,
	}), nil)
	if code := s.run("threads"); code != 0 {
		t.Fatalf("threads: code=%d err=%q", code, s.errb.String())
	}
	if strings.Contains(s.out.String(), `"session_id": "b"`) {
		t.Errorf("archived session leaked without --all: %q", s.out.String())
	}
	if code := s.run("threads", "--all"); code != 0 {
		t.Fatalf("threads --all: code=%d", code)
	}
	if !strings.Contains(s.out.String(), `"session_id": "b"`) {
		t.Errorf("--all must include archived: %q", s.out.String())
	}
}

func TestHistoryAndFiles(t *testing.T) {
	history := `{"chat_events":[
	  {"seq":1,"event_name":"user","payload":{"role":"user","display_text":"hello","message_id":"m1"}},
	  {"seq":2,"event_name":"agent","payload":{"role":"agent","content":"hi","message_id":"m2","data":{"images":[{"path":"sandbox://workspace/pic.png","mime":"image/png","byte_len":4}]}}},
	  {"seq":3,"event_name":"agent","payload":{"role":"agent"}}]}`
	s := newFakeStack(t, routeHandler(map[string]string{
		"/chat/history": history,
	}), nil)
	if code := s.run("history"); code != 0 {
		t.Fatalf("history: code=%d err=%q", code, s.errb.String())
	}
	// Only events with display_text/content survive, in order.
	if strings.Contains(s.out.String(), `"seq": 3`) {
		t.Errorf("textless event leaked: %q", s.out.String())
	}
	if !strings.Contains(s.out.String(), `"text": "hello"`) || !strings.Contains(s.out.String(), `"text": "hi"`) {
		t.Errorf("history rows: %q", s.out.String())
	}
	// The limit travels in the query string (GET bodies become
	// query params on the wire).
	reqs := s.server.Requests()
	if len(reqs) != 1 || !strings.Contains(reqs[0].Path, "limit=10") {
		t.Errorf("history request path=%q, want limit=10 in the query", reqs[0].Path)
	}
	if code := s.run("history", "--raw"); code != 0 {
		t.Fatalf("history --raw: code=%d", code)
	}
	if !strings.Contains(s.out.String(), `"chat_events"`) {
		t.Errorf("--raw must print the whole object: %q", s.out.String())
	}
	if code := s.run("files"); code != 0 {
		t.Fatalf("files: code=%d err=%q", code, s.errb.String())
	}
	if !strings.Contains(s.out.String(), "pic.png") {
		t.Errorf("files rows: %q", s.out.String())
	}
}

func TestDownloadCommand(t *testing.T) {
	history := `{"chat_events":[
	  {"seq":7,"event_name":"agent","payload":{"role":"agent","content":"x","message_id":"m7","data":{"images":[{"path":"sandbox://workspace/pic.png","mime":"image/png","byte_len":4}]}}}]}`
	// media.raw download: the gateway serves it via the media route;
	// routeHandler answers every path with the same frame, so use a
	// handler that distinguishes the media download path.
	s := newFakeStack(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		var body string
		path, _, _ := strings.Cut(req.GetPath(), "?")
		switch path {
		case "/chat/history":
			body = `{"ok":true,"result":` + history + `}`
		default:
			// media.raw: raw bytes split across a response frame
			// and a final chunk, like the gateway e2e test.
			return gatewaytest.Response{Frames: []*pb.ServiceFrame{
				gatewaytest.ResponseFrame(0, 200, []byte("PN"), false),
				gatewaytest.ChunkFrame(0, []byte("G!"), true),
			}}
		}
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte(body), true),
		}}
	}), nil)
	outDir := t.TempDir()
	if code := s.run("download", "7", "-o", outDir); code != 0 {
		t.Fatalf("download by seq: code=%d err=%q out=%q", code, s.errb.String(), s.out.String())
	}
	if !strings.Contains(s.out.String(), "pic.png") {
		t.Errorf("download rows: %q", s.out.String())
	}
	if code := s.run("download", "nope", "-o", outDir); code != 1 {
		t.Fatalf("download missing: code=%d, want 1 (err=%q)", code, s.errb.String())
	}
}

func TestWatchRows(t *testing.T) {
	// Direct unit tests for the row shaping (streaming itself is
	// covered by the gateway-level SubscribeRaw tests; here the
	// fake server ends the stream after the frames).
	s := newFakeStack(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte("{\"event\":\"agent.status\",\"seq\":1,\"payload\":{\"status\":\"thinking\"}}\n{\"event\":\"agent.message\",\"seq\":2,\"payload\":{\"display_text\":\"hello world\"}}\nnot-json\n"), false),
			gatewaytest.ChunkFrame(0, []byte("{\"event\":\"agent.message\",\"seq\":3,\"payload\":{\"content\":\"done\"}}"), true),
		}}
	}), nil)
	if code := s.run("watch", "--n", "10"); code != 0 {
		t.Fatalf("watch: code=%d err=%q", code, s.errb.String())
	}
	lines := strings.Split(strings.TrimSpace(s.out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("watch lines=%d: %q", len(lines), s.out.String())
	}
	if !strings.Contains(lines[0], `"display_text":"hello world"`) {
		t.Errorf("line 0: %q", lines[0])
	}
	if strings.Contains(s.out.String(), "agent.status") {
		t.Errorf("agent.status must be dropped without --all: %q", s.out.String())
	}
	if code := s.run("watch", "--all", "--n", "10"); code != 0 {
		t.Fatalf("watch --all: code=%d", code)
	}
	if !strings.Contains(s.out.String(), "agent.status") {
		t.Errorf("--all must keep agent.status: %q", s.out.String())
	}
}

func TestPrintWatchRowUnit(t *testing.T) {
	var buf strings.Builder
	printWatchRow(&buf, []byte(`{"event":"x","seq":9,"payload":{"display_text":"`+strings.Repeat("a", 400)+`"}}`), false)
	if !strings.Contains(buf.String(), strings.Repeat("a", 300)) || strings.Contains(buf.String(), strings.Repeat("a", 301)) {
		t.Errorf("text must truncate to 300 runes: len=%d", len(buf.String()))
	}
	buf.Reset()
	printWatchRow(&buf, []byte(`not json`), false)
	if buf.Len() != 0 {
		t.Errorf("bad JSON must be dropped, got %q", buf.String())
	}
	buf.Reset()
	printWatchRow(&buf, []byte(`{"seq":5}`), false)
	if !strings.Contains(buf.String(), `"event":null`) {
		t.Errorf("missing event must be null: %q", buf.String())
	}
}

func TestFeedGoalsIdeas(t *testing.T) {
	s := newFakeStack(t, routeHandler(map[string]string{
		"/api/feed":                   `{"days":[{"local_date":"2026-10-29","editions":[{"kind":"morning","units":[{"unit_id":"u1","title":"News"}]}]}]}`,
		"/api/feed/status":            `{"pending":1}`,
		"/api/feed/units/u1/reaction": `{"ok":true}`,
		"/api/feed/prompt":            `{"prompt":"What matters today?"}`,
		"/goals":                      `{"goals":[{"id":"g1","title":"Ship it","status":"active","subtitle":"soon"}]}`,
		"/goals/g1":                   `{"id":"g1","title":"Ship it"}`,
		"/api/idea-cards":             `{"cards":[{"id":"i1","title":"Idea"}]}`,
		"/api/idea-cards/i1":          `{"id":"i1"}`,
		"/api/idea-cards/i1/execute":  `{"started":true}`,
		"/chat/unread-count":          `{"unread":2}`,
		"/api/chat/t1/seen":           `{"seen":true}`,
	}), nil)
	cases := [][]string{
		{"feed"}, {"feed", "--raw"}, {"feed-status"}, {"feed-react", "u1"},
		{"feed-react", "u1", "fire"}, {"feed-prompt"}, {"goals"}, {"goal", "g1"},
		{"ideas"}, {"idea", "i1"}, {"idea-exec", "i1"}, {"unread"}, {"seen", "t1"},
	}
	for _, args := range cases {
		if code := s.run(args...); code != 0 {
			t.Errorf("%v: code=%d err=%q", args, code, s.errb.String())
		}
	}
	if code := s.run("feed"); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(s.out.String(), `"id": "u1"`) || !strings.Contains(s.out.String(), `"edition": "morning"`) {
		t.Errorf("feed rows: %q", s.out.String())
	}
	if code := s.run("feed", "--limit", "1"); code != 0 {
		t.Fatal(code)
	}
	reqs := s.server.Requests()
	last := reqs[len(reqs)-1]
	if !strings.Contains(last.Path, "limit=1") {
		t.Errorf("feed limit request path=%q, want limit=1 in the query", last.Path)
	}
}

func TestUsageInviteRedeem(t *testing.T) {
	subJSON := `{"success":true,"subscription":{"tier":{"name":"Pro"},"usage":{"state":"ok"},"topupTotal":100,"topupBalance":40,"topupRowLabel":"Additional tokens","topupRowValueLabel":"60% used (3B tokens left)"}}`
	rsc := "0:{\"a\":\"$@1\"}\n1:" + subJSON + "\n"
	extra := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/settings":
			w.Header().Set("Content-Type", "text/x-component; charset=utf-8")
			_, _ = w.Write([]byte(rsc))
		case "/api/hatch/invite":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`{"invite_state":"active","code":"ABCDEF","invite_link":"https://muse.ai/i/ABCDEF","max_uses":5,"use_count":2,"reward":{"title":"Pro","body":"1 month"},"subtitle":"Join!"}`))
				return
			}
			_, _ = w.Write([]byte(`{"code":"ABCDEF"}`))
		case "/api/hatch/invite-code/redeem":
			_, _ = w.Write([]byte(`{"success":true,"redemptionStatus":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	})
	s := newFakeStack(t, nil, extra)
	if code := s.run("usage"); code != 0 {
		t.Fatalf("usage: code=%d err=%q", code, s.errb.String())
	}
	if !strings.Contains(s.out.String(), "Pro") {
		t.Errorf("usage lines: %q", s.out.String())
	}
	if code := s.run("usage", "--json"); code != 0 {
		t.Fatalf("usage --json: code=%d", code)
	}
	if !strings.Contains(s.out.String(), `"remaining_tokens": 3000000000`) {
		t.Errorf("usage summary: %q", s.out.String())
	}
	if code := s.run("invite"); code != 0 {
		t.Fatalf("invite: code=%d err=%q", code, s.errb.String())
	}
	if !strings.Contains(s.out.String(), "Invite code: ABCDEF") || !strings.Contains(s.out.String(), "Uses left: 3 of 5") {
		t.Errorf("invite text: %q", s.out.String())
	}
	if code := s.run("redeem", "abcdef"); code != 0 {
		t.Fatalf("redeem: code=%d err=%q", code, s.errb.String())
	}
	if !strings.Contains(s.out.String(), "Redeemed: ok") {
		t.Errorf("redeem text: %q", s.out.String())
	}
	if code := s.run("redeem", "bad!"); code != 2 {
		t.Fatalf("redeem bad code: code=%d, want 2", code)
	}
}

func TestRawCommand(t *testing.T) {
	s := newFakeStack(t, routeHandler(map[string]string{
		"/api/session/list": `{"sessions":[]}`,
	}), nil)
	if code := s.run("raw", "sessions.list"); code != 0 {
		t.Fatalf("raw: code=%d err=%q", code, s.errb.String())
	}
	if !strings.Contains(s.out.String(), `"sessions": []`) {
		t.Errorf("raw out: %q", s.out.String())
	}
	if code := s.run("raw", "no.such.method"); code != 2 {
		t.Fatalf("raw unknown: code=%d, want 2", code)
	}
	if !strings.Contains(s.errb.String(), "unknown method") || !strings.Contains(s.errb.String(), "known methods") {
		t.Errorf("raw unknown message: %q", s.errb.String())
	}
	if code := s.run("raw", "sessions.list", "--body", "{bad"); code != 2 {
		t.Fatalf("raw bad body: code=%d, want 2", code)
	}
	// Non-JSON reply prints as text.
	s2 := newFakeStack(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte("plain text reply"), true),
		}}
	}), nil)
	if code := s2.run("raw", "sessions.list"); code != 0 {
		t.Fatalf("raw text: code=%d", code)
	}
	if strings.TrimSpace(s2.out.String()) != "plain text reply" {
		t.Errorf("raw text out: %q", s2.out.String())
	}
}
