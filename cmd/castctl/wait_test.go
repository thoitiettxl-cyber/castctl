// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/commands"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway/gatewaytest"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	pb "github.com/thoitiettxl-cyber/castctl/internal/proto"
)

// scriptedHandler answers gateway methods from per-test scripts. It
// dispatches on the request path prefix (query strings stripped) and
// records every decide/stream call for assertions.
type scriptedHandler struct {
	mu sync.Mutex

	history   []string // chat.history bodies, in call order; the last repeats
	subscribe [][]byte // chat.subscribe record batches, in call order; the last repeats
	approvals string   // egress.approvals body
	recent    string   // egress.approvals body for --recent
	sessions  string   // sessions.list body
	start     string   // session.start body
	decide    string   // egress.approval.decide body

	historyCalls   int
	subscribeCalls int
	decideCalls    int
	decidePaths    []string
	decideBodies   []string
	streamBodies   []string
	streamCount    int
}

func (h *scriptedHandler) Handle(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
	path := req.GetPath()
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	jsonResp := func(body string) gatewaytest.Response {
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte(body), true),
		}}
	}
	switch {
	case strings.HasPrefix(path, "/chat/history"):
		h.historyCalls++
		body := ""
		if len(h.history) > 0 {
			body = h.history[min(h.historyCalls-1, len(h.history)-1)]
		}
		return jsonResp(body)
	case strings.HasPrefix(path, "/chat/subscribe"):
		h.subscribeCalls++
		var batch []byte
		if len(h.subscribe) > 0 {
			batch = h.subscribe[min(h.subscribeCalls-1, len(h.subscribe)-1)]
		}
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, batch, true),
		}}
	case strings.HasPrefix(path, "/chat/stream"):
		h.streamCount++
		h.streamBodies = append(h.streamBodies, string(req.GetBody()))
		return gatewaytest.Response{}
	case strings.HasPrefix(path, "/approvals"):
		if strings.HasSuffix(path, "/decide") {
			h.decideCalls++
			h.decidePaths = append(h.decidePaths, path)
			h.decideBodies = append(h.decideBodies, string(req.GetBody()))
			return jsonResp(h.decide)
		}
		if h.recent != "" {
			return jsonResp(h.recent)
		}
		return jsonResp(h.approvals)
	case strings.HasPrefix(path, "/api/session/list"):
		return jsonResp(h.sessions)
	case strings.HasPrefix(path, "/session/start"):
		return jsonResp(h.start)
	default:
		return jsonResp(`{"error":"unhandled path in test handler"}`)
	}
}

// fakeHome writes a single-file config plus a fake cookies file under
// a hermetic HOME and returns the home dir.
func fakeHome(t *testing.T, cfgJSON string) string {
	t.Helper()
	home := t.TempDir()
	base := filepath.Join(home, ".config", "castctl")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "config.json"), []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	// The "default" profile's files live at the config dir root,
	// not under profiles/default/ (ProfilePaths).
	if err := os.WriteFile(filepath.Join(base, "cookies.txt"), []byte("hatch_sess=FAKE; datr=FAKE"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

const defaultSingleConfig = `{"default_profile":"default","profiles":{"default":{}}}`

// runWired runs the real dispatch against a fake gateway and returns
// the exit code, stdout, stderr and the handler for assertions.
func runWired(t *testing.T, home string, handler *scriptedHandler, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("CASTCTL_CONFIG", "")
	t.Setenv("CASTCTL_PROFILE", "")
	server, err := gatewaytest.NewServer(handler)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer func() { _ = server.Close() }()
	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT-FAKE", HatchToken: "HT-FAKE"}
	dialer := gatewaytest.NewFakeDialer(server, auth)
	var out, errb bytes.Buffer
	env := &commands.Env{
		Stdout: &out,
		Stderr: &errb,
		Stdin:  strings.NewReader(""),
		NewConnector: func(d gateway.OutboundDialer, opts ...gateway.ConnectorOption) conn.Connector {
			_ = d
			_ = opts
			return gateway.NewConnector(dialer, gateway.WithWebSocketSecure(false))
		},
	}
	code := commands.Run(context.Background(), args, env)
	return code, out.String(), errb.String()
}

func historyBody(events ...string) string {
	return `{"chat_events":[` + strings.Join(events, ",") + `],"has_more":false}`
}

func userEv(seq int, text string) string {
	return `{"seq":` + itoa(seq) + `,"event_name":"message.user","payload":{"display_text":` + quote(text) + `,"role":"user","message_id":"u1"}}`
}

func asstEv(seq int, text string) string {
	return `{"seq":` + itoa(seq) + `,"event_name":"message.assistant","payload":{"status":"completed","display_text":` + quote(text) + `,"role":"assistant","message_id":"m1"}}`
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func recordJSON(s string) []byte { return []byte(s + "\n") }

func taskRecord(status string) []byte {
	return recordJSON(`{"event":"task.status","payload":{"status":` + quote(status) + `,"root_agent_id":"R","agent_id":"R"}}`)
}

func approvalRecord(approvalJSON string) []byte {
	return recordJSON(`{"event":"approvals.snapshot","payload":{"pending_approvals":[` + approvalJSON + `]}}`)
}

const approvalA = `{"approval_id":"A","display":{"summary_title":"Allow site","permission_question":{"text":"Allow {assistant} to visit example.com?","kind":"browse","scope":"example.com"},"short_explanation":"needed"},"payload":{"type":"browse"},"request_expires_at_ms":4102444800000,"decision_options":[{"kind":"allow_always"},{"kind":"allow_once"}]}`

func TestWaitDoneJSON(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history: []string{
			historyBody(userEv(100, "hi")),
			historyBody(userEv(100, "hi"), asstEv(150, "via gateway")),
		},
		subscribe: [][]byte{append(taskRecord("running"), taskRecord("completed")...)},
	}
	code, out, errb := runWired(t, home, h, "wait", "--json", "--timeout", "10")
	if code != 0 {
		t.Fatalf("wait: code=%d out=%q err=%q", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v (out=%q)", err, out)
	}
	if res["outcome"] != "done" || res["status"] != "completed" {
		t.Errorf("outcome/status = %v/%v, want done/completed", res["outcome"], res["status"])
	}
	if res["after_seq"] != float64(100) || res["final_text"] != "via gateway" {
		t.Errorf("after_seq/final_text = %v/%v", res["after_seq"], res["final_text"])
	}
	replies, _ := res["replies"].([]any)
	if len(replies) != 1 {
		t.Fatalf("replies = %v, want 1", res["replies"])
	}
	r0, _ := replies[0].(map[string]any)
	if r0["seq"] != float64(150) || r0["text"] != "via gateway" || r0["message_id"] != "m1" {
		t.Errorf("reply = %v", r0)
	}
	if _, ok := res["final_read_failed"]; ok {
		t.Errorf("final_read_failed must be absent: %q", out)
	}
	// Key order pins the Python result-dict order.
	keys := []string{`"outcome"`, `"status"`, `"after_seq"`, `"final_text"`, `"replies"`}
	last := -1
	for _, k := range keys {
		i := strings.Index(out, k)
		if i < 0 || i < last {
			t.Errorf("key order: %s at %d after %d in %q", k, i, last, out)
		}
		last = i
	}
	if strings.Contains(out, "hatch_sess") || strings.Contains(out, "FAKE") {
		t.Errorf("output leaks cookie material: %q", out)
	}
}

func TestWaitTextMode(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history: []string{
			historyBody(userEv(100, "hi")),
			historyBody(userEv(100, "hi"), asstEv(150, "hello back")),
		},
		subscribe: [][]byte{append(taskRecord("running"), taskRecord("completed")...)},
	}
	code, out, errb := runWired(t, home, h, "wait", "--timeout", "10")
	if code != 0 {
		t.Fatalf("wait: code=%d out=%q err=%q", code, out, errb)
	}
	if !strings.Contains(out, "[150] hello back") {
		t.Errorf("text output = %q, want [150] line", out)
	}
	if !strings.Contains(errb, "-- done (status=completed)") {
		t.Errorf("stderr = %q, want summary line", errb)
	}
}

func TestWaitTimeout124(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history:   []string{historyBody(userEv(100, "hi"))},
		subscribe: [][]byte{taskRecord("running")},
	}
	code, out, _ := runWired(t, home, h, "wait", "--json", "--timeout", "2")
	if code != 124 {
		t.Fatalf("wait timeout: code=%d, want 124 (out=%q)", code, out)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res["outcome"] != "timeout" {
		t.Errorf("outcome = %v, want timeout", res["outcome"])
	}
}

func TestWaitNeedsApprovalExit4(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history:   []string{historyBody(userEv(100, "hi"))},
		subscribe: [][]byte{append(taskRecord("running"), approvalRecord(approvalA)...)},
	}
	code, out, _ := runWired(t, home, h, "wait", "--json", "--timeout", "10")
	if code != 4 {
		t.Fatalf("wait approval: code=%d, want 4 (out=%q)", code, out)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res["outcome"] != "needs_approval" {
		t.Errorf("outcome = %v, want needs_approval", res["outcome"])
	}
	appr, _ := res["approvals"].([]any)
	if len(appr) != 1 {
		t.Fatalf("approvals = %v, want 1", res["approvals"])
	}
	a0, _ := appr[0].(map[string]any)
	if a0["approval_id"] != "A" || a0["title"] != "Allow site" || a0["question"] != "Allow Muse to visit example.com?" {
		t.Errorf("approval = %v", a0)
	}
	if a0["kind"] != "browse" || a0["scope"] != "example.com" || a0["why"] != "needed" {
		t.Errorf("approval kind/scope/why = %v", a0)
	}
	if a0["expires_at_ms"] != float64(4102444800000) {
		t.Errorf("expires_at_ms = %v", a0["expires_at_ms"])
	}
	opts, _ := a0["options"].([]any)
	if len(opts) != 2 || opts[0] != "allow_always" || opts[1] != "allow_once" {
		t.Errorf("options = %v", a0["options"])
	}
}

func TestWaitAutoApproveDecidesOnce(t *testing.T) {
	home := fakeHome(t, `{"default_profile":"default","profiles":{"default":{"auto_approve":"always"}}}`)
	h := &scriptedHandler{
		history: []string{
			historyBody(userEv(100, "hi")),
			historyBody(userEv(100, "hi"), asstEv(150, "done after approval")),
		},
		subscribe: [][]byte{
			append(taskRecord("running"), approvalRecord(approvalA)...),
			append(taskRecord("running"), approvalRecord(approvalA)...),
			taskRecord("completed"),
		},
		decide: `{"decided":true}`,
	}
	code, out, errb := runWired(t, home, h, "wait", "--json", "--timeout", "15")
	if code != 0 {
		t.Fatalf("wait auto-approve: code=%d out=%q err=%q", code, out, errb)
	}
	if h.decideCalls != 1 {
		t.Fatalf("decide calls = %d, want 1 (claim: second offer must not re-decide)", h.decideCalls)
	}
	if len(h.decideBodies) != 1 || !strings.Contains(h.decideBodies[0], `"allow_always"`) {
		t.Fatalf("decide body = %v, want one allow_always", h.decideBodies)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	approved, _ := res["auto_approved"].([]any)
	if len(approved) != 1 {
		t.Fatalf("auto_approved = %v, want 1", res["auto_approved"])
	}
	if !strings.Contains(errb, "auto-approved A (allow_always)") {
		t.Errorf("stderr = %q, want auto-approved line", errb)
	}
}

func TestWaitFlagOverridesConfigAutoApprove(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history: []string{
			historyBody(userEv(100, "hi")),
			historyBody(userEv(100, "hi"), asstEv(150, "ok")),
		},
		subscribe: [][]byte{
			append(taskRecord("running"), approvalRecord(approvalA)...),
			taskRecord("completed"),
		},
		decide: `{"decided":true}`,
	}
	code, _, errb := runWired(t, home, h, "wait", "--json", "--timeout", "15", "--auto-approve")
	if code != 0 {
		t.Fatalf("wait --auto-approve: code=%d err=%q", code, errb)
	}
	if h.decideCalls != 1 {
		t.Fatalf("decide calls = %d, want 1", h.decideCalls)
	}
}

func TestWaitConflictingAutoFlagsExit2(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{}
	if code, _, _ := runWired(t, home, h, "wait", "--auto-approve", "--no-auto-approve"); code != 2 {
		t.Fatalf("conflicting flags: code=%d, want 2", code)
	}
	if code, _, _ := runWired(t, home, h, "wait", "--auto-allow-once", "--no-auto-allow-once"); code != 2 {
		t.Fatalf("conflicting once flags: code=%d, want 2", code)
	}
}

func TestSendDeliversAndWaits(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history: []string{
			historyBody(userEv(100, "old")),
			historyBody(userEv(100, "old")),
			historyBody(userEv(100, "old"), userEv(110, "hello")),
			historyBody(userEv(100, "old"), userEv(110, "hello")),
			historyBody(userEv(100, "old"), userEv(110, "hello"), asstEv(150, "reply text")),
		},
		subscribe: [][]byte{append(taskRecord("running"), taskRecord("completed")...)},
	}
	code, out, errb := runWired(t, home, h, "send", "hello", "--wait", "10", "--ack-timeout", "5")
	if code != 0 {
		t.Fatalf("send: code=%d out=%q err=%q", code, out, errb)
	}
	if h.streamCount != 1 {
		t.Fatalf("chat.stream calls = %d, want 1 (never re-sent)", h.streamCount)
	}
	var streamBody map[string]any
	if err := json.Unmarshal([]byte(h.streamBodies[0]), &streamBody); err != nil {
		t.Fatalf("stream body: %v", err)
	}
	items, _ := streamBody["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("stream items = %v", streamBody["items"])
	}
	item, _ := items[0].(map[string]any)
	if item["type"] != "text" || item["text"] != "hello" {
		t.Errorf("stream item = %v", item)
	}
	if _, ok := streamBody["capabilities"]; !ok {
		t.Errorf("stream body lacks capabilities: %v", streamBody)
	}
	if _, ok := streamBody["session_id"]; ok {
		t.Errorf("stream body must not carry session_id without --thread: %v", streamBody)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v (out=%q)", err, out)
	}
	if res["sent"] != true || res["delivered"] != true || res["user_seq"] != float64(110) {
		t.Errorf("send result head = sent=%v delivered=%v user_seq=%v", res["sent"], res["delivered"], res["user_seq"])
	}
	if _, ok := res["stream"]; !ok {
		t.Errorf("send result lacks stream: %q", out)
	}
	if res["outcome"] != "done" || res["final_text"] != "reply text" {
		t.Errorf("send wait outcome/final_text = %v/%v", res["outcome"], res["final_text"])
	}
	reply, _ := res["reply"].(map[string]any)
	if reply["seq"] != float64(150) || reply["role"] != "message.assistant" || reply["text"] != "reply text" {
		t.Errorf("reply = %v", reply)
	}
	if _, ok := res["note"]; ok {
		t.Errorf("done send must not carry a note: %q", out)
	}
}

func TestSendNoWait(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history: []string{
			historyBody(userEv(100, "old")),
			historyBody(userEv(100, "old"), userEv(110, "hello")),
		},
	}
	code, out, errb := runWired(t, home, h, "send", "hello", "--wait", "0", "--ack-timeout", "5")
	if code != 0 {
		t.Fatalf("send --wait 0: code=%d out=%q err=%q", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res["sent"] != true || res["delivered"] != true || res["user_seq"] != float64(110) {
		t.Errorf("result = %v", res)
	}
	if _, ok := res["outcome"]; ok {
		t.Errorf("no-wait send must not carry wait fields: %q", out)
	}
}

func TestSendNoAckExit5(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history: []string{historyBody(userEv(100, "old"))},
	}
	code, out, errb := runWired(t, home, h, "send", "hello", "--wait", "10", "--ack-timeout", "1")
	if code != 5 {
		t.Fatalf("send no-ack: code=%d, want 5 (out=%q err=%q)", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res["sent"] != true || res["delivered"] != false || res["user_seq"] != nil {
		t.Errorf("result = %v, want sent/delivered=false/user_seq null", res)
	}
	if !strings.Contains(res["note"].(string), "no delivery ack within 1s") {
		t.Errorf("note = %v", res["note"])
	}
	if h.streamCount != 1 {
		t.Fatalf("stream calls = %d, want 1", h.streamCount)
	}
}

func TestSendThreadScope(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history: []string{
			historyBody(userEv(100, "old")),
			historyBody(userEv(100, "old"), userEv(110, "hello")),
		},
	}
	code, _, errb := runWired(t, home, h, "send", "hello", "--wait", "0", "--thread", "s-thread", "--ack-timeout", "5")
	if code != 0 {
		t.Fatalf("send --thread: code=%d err=%q", code, errb)
	}
	var streamBody map[string]any
	if err := json.Unmarshal([]byte(h.streamBodies[0]), &streamBody); err != nil {
		t.Fatalf("stream body: %v", err)
	}
	if streamBody["session_id"] != "s-thread" {
		t.Errorf("stream session_id = %v, want s-thread", streamBody["session_id"])
	}
}

func TestSendNodeIDOrigins(t *testing.T) {
	t.Run("generate and persist", func(t *testing.T) {
		home := fakeHome(t, defaultSingleConfig)
		h := &scriptedHandler{
			history: []string{
				historyBody(userEv(100, "old")),
				historyBody(userEv(100, "old"), userEv(110, "hello")),
			},
		}
		code, _, errb := runWired(t, home, h, "send", "hello", "--wait", "0", "--ack-timeout", "5")
		if code != 0 {
			t.Fatalf("send: code=%d err=%q", code, errb)
		}
		var streamBody map[string]any
		if err := json.Unmarshal([]byte(h.streamBodies[0]), &streamBody); err != nil {
			t.Fatalf("stream body: %v", err)
		}
		nodeID, _ := streamBody["node_id"].(string)
		if len(nodeID) != 16 {
			t.Fatalf("generated node_id = %q, want 16 hex chars", nodeID)
		}
		for _, c := range nodeID {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				t.Fatalf("generated node_id = %q, want lowercase hex", nodeID)
			}
		}
		raw, err := os.ReadFile(filepath.Join(home, ".config", "castctl", "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		profs, _ := cfg["profiles"].(map[string]any)
		def, _ := profs["default"].(map[string]any)
		if def["node_id"] != nodeID {
			t.Errorf("persisted node_id = %v, want %s (file=%s)", def["node_id"], nodeID, raw)
		}
		// Second send reuses the persisted value verbatim.
		h2 := &scriptedHandler{
			history: []string{
				historyBody(userEv(100, "old")),
				historyBody(userEv(100, "old"), userEv(110, "hello")),
			},
		}
		if code, _, errb := runWired(t, home, h2, "send", "hello", "--wait", "0", "--ack-timeout", "5"); code != 0 {
			t.Fatalf("second send: code=%d err=%q", code, errb)
		}
		var streamBody2 map[string]any
		_ = json.Unmarshal([]byte(h2.streamBodies[0]), &streamBody2)
		if streamBody2["node_id"] != nodeID {
			t.Errorf("second send node_id = %v, want persisted %s", streamBody2["node_id"], nodeID)
		}
	})
	t.Run("env wins and is not persisted", func(t *testing.T) {
		home := fakeHome(t, defaultSingleConfig)
		t.Setenv("MUSE_NODE_ID", "env-node-123")
		h := &scriptedHandler{
			history: []string{
				historyBody(userEv(100, "old")),
				historyBody(userEv(100, "old"), userEv(110, "hello")),
			},
		}
		code, _, errb := runWired(t, home, h, "send", "hello", "--wait", "0", "--ack-timeout", "5")
		if code != 0 {
			t.Fatalf("send: code=%d err=%q", code, errb)
		}
		var streamBody map[string]any
		_ = json.Unmarshal([]byte(h.streamBodies[0]), &streamBody)
		if streamBody["node_id"] != "env-node-123" {
			t.Errorf("node_id = %v, want env-node-123", streamBody["node_id"])
		}
		raw, _ := os.ReadFile(filepath.Join(home, ".config", "castctl", "config.json"))
		if strings.Contains(string(raw), "node_id") {
			t.Errorf("env node_id must not be persisted: %s", raw)
		}
	})
	t.Run("file wins verbatim", func(t *testing.T) {
		home := fakeHome(t, `{"default_profile":"default","profiles":{"default":{"node_id":"file-node-9"}}}`)
		h := &scriptedHandler{
			history: []string{
				historyBody(userEv(100, "old")),
				historyBody(userEv(100, "old"), userEv(110, "hello")),
			},
		}
		before, _ := os.ReadFile(filepath.Join(home, ".config", "castctl", "config.json"))
		code, _, errb := runWired(t, home, h, "send", "hello", "--wait", "0", "--ack-timeout", "5")
		if code != 0 {
			t.Fatalf("send: code=%d err=%q", code, errb)
		}
		var streamBody map[string]any
		_ = json.Unmarshal([]byte(h.streamBodies[0]), &streamBody)
		if streamBody["node_id"] != "file-node-9" {
			t.Errorf("node_id = %v, want file-node-9", streamBody["node_id"])
		}
		after, _ := os.ReadFile(filepath.Join(home, ".config", "castctl", "config.json"))
		if string(before) != string(after) {
			t.Errorf("config file must not be rewritten when node_id is present:\nbefore %s\nafter %s", before, after)
		}
	})
	t.Run("env value used verbatim", func(t *testing.T) {
		home := fakeHome(t, defaultSingleConfig)
		t.Setenv("MUSE_NODE_ID", "has space")
		h := &scriptedHandler{
			history: []string{
				historyBody(userEv(100, "old")),
				historyBody(userEv(100, "old"), userEv(110, "hello")),
			},
		}
		code, _, errb := runWired(t, home, h, "send", "hello", "--wait", "0", "--ack-timeout", "5")
		if code != 0 {
			t.Fatalf("send: code=%d err=%q", code, errb)
		}
		var streamBody map[string]any
		_ = json.Unmarshal([]byte(h.streamBodies[0]), &streamBody)
		// Neither Python nor the profile loader validates node_id:
		// the env value is sent verbatim.
		if streamBody["node_id"] != "has space" {
			t.Errorf("node_id = %v, want verbatim env value", streamBody["node_id"])
		}
	})
}

func TestApprovalsList(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{approvals: `{"pending":[` + approvalA + `]}`}
	// approvals always prints JSON; there is no --json flag.
	code, out, errb := runWired(t, home, h, "approvals")
	if code != 0 {
		t.Fatalf("approvals: code=%d out=%q err=%q", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pending, _ := res["pending"].([]any)
	if len(pending) != 1 {
		t.Fatalf("pending = %v", res["pending"])
	}
	a0, _ := pending[0].(map[string]any)
	if a0["approval_id"] != "A" || a0["title"] != "Allow site" || a0["question"] != "Allow Muse to visit example.com?" {
		t.Errorf("approval = %v", a0)
	}
	if a0["expires_at_ms"] != float64(4102444800000) {
		t.Errorf("expires_at_ms = %v", a0["expires_at_ms"])
	}
}

func TestApprovalsRecentAndRaw(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{recent: `{"recent":[{"approval_id":"R1","display":{"summary_title":"T","permission_question":{"text":"Q?","kind":"browse","scope":"example.com"}},"decision":"allow_once"}]}`}
	code, out, errb := runWired(t, home, h, "approvals", "--recent")
	if code != 0 {
		t.Fatalf("approvals --recent: code=%d out=%q err=%q", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	recent, _ := res["recent"].([]any)
	if len(recent) != 1 {
		t.Fatalf("recent = %v", res["recent"])
	}
	r0, _ := recent[0].(map[string]any)
	if r0["approval_id"] != "R1" || r0["decision"] != "allow_once" || r0["title"] != "T" {
		t.Errorf("recent row = %v", r0)
	}

	rawBody := `{"pending_approvals":[{"approval_id":"A"}],"extra":1}`
	h2 := &scriptedHandler{approvals: rawBody}
	code, out, errb = runWired(t, home, h2, "approvals", "--raw")
	if code != 0 {
		t.Fatalf("approvals --raw: code=%d err=%q", code, errb)
	}
	// --raw re-serializes the parsed result (like Python's out()),
	// so the comparison is on parsed JSON, not raw bytes.
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal --raw: %v (out=%q)", err, out)
	}
	if got["extra"] != float64(1) {
		t.Errorf("--raw result = %v, want the server result", got)
	}
	pend, _ := got["pending_approvals"].([]any)
	if len(pend) != 1 {
		t.Errorf("--raw pending_approvals = %v", got["pending_approvals"])
	}
}

func TestApproveAndDeny(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{decide: `{"ok":true}`}
	code, out, errb := runWired(t, home, h, "approve", "A1")
	if code != 0 {
		t.Fatalf("approve: code=%d out=%q err=%q", code, out, errb)
	}
	// approve prints the decide result through the JSON writer
	// (indent 2), like Python's out(): compare parsed, not bytes.
	var decided map[string]any
	if err := json.Unmarshal([]byte(out), &decided); err != nil {
		t.Fatalf("approve output JSON: %v (%q)", err, out)
	}
	if decided["ok"] != true {
		t.Errorf("approve output = %q", out)
	}
	if len(h.decidePaths) != 1 || h.decidePaths[0] != "/approvals/A1/decide" {
		t.Fatalf("decide path = %v", h.decidePaths)
	}
	if !strings.Contains(h.decideBodies[0], `"decision":"allow_once"`) {
		t.Fatalf("decide body = %v, want allow_once", h.decideBodies)
	}

	h2 := &scriptedHandler{decide: `{"ok":true}`}
	if code, _, errb := runWired(t, home, h2, "deny", "A1", "--always"); code != 0 {
		t.Fatalf("deny --always: code=%d err=%q", code, errb)
	}
	if !strings.Contains(h2.decideBodies[0], `"decision":"deny_always"`) {
		t.Fatalf("deny body = %v, want deny_always", h2.decideBodies)
	}

	h3 := &scriptedHandler{decide: `{"ok":true}`}
	if code, _, errb := runWired(t, home, h3, "approve", "A1", "--today"); code != 0 {
		t.Fatalf("approve --today: code=%d err=%q", code, errb)
	}
	if !strings.Contains(h3.decideBodies[0], `"decision":"allow_today"`) {
		t.Fatalf("approve --today body = %v", h3.decideBodies)
	}
}

func TestDecideUsageErrors(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{}
	for _, args := range [][]string{
		{"approve"},
		{"approve", "A1", "--all"},
		{"approve", "A1", "--once", "--always"},
		{"deny"},
	} {
		if code, _, errb := runWired(t, home, h, args...); code != 2 {
			t.Fatalf("%v: code=%d, want 2 (err=%q)", args, code, errb)
		}
	}
	if h.decideCalls != 0 {
		t.Fatalf("usage errors must not decide: %d calls", h.decideCalls)
	}
}

func TestApproveAllSkipsNoForever(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	onceOnly := `{"approval_id":"B","display":{"summary_title":"Once only"},"decision_options":[{"kind":"allow_once"}]}`
	// approve --all --always: the FOREVER decision skips approvals with
	// no forever option; the default allow_once decision decides all.
	h := &scriptedHandler{
		approvals: `{"pending":[` + approvalA + `,` + onceOnly + `]}`,
		decide:    `{"ok":true}`,
	}
	code, out, errb := runWired(t, home, h, "approve", "--all", "--always")
	if code != 0 {
		t.Fatalf("approve --all --always: code=%d out=%q err=%q", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	approved, _ := res["approved"].([]any)
	if len(approved) != 1 {
		t.Fatalf("approved = %v, want 1", res["approved"])
	}
	a0, _ := approved[0].(map[string]any)
	if a0["approval_id"] != "A" || a0["decision"] != "allow_always" {
		t.Errorf("approved row = %v", a0)
	}
	if h.decideCalls != 1 {
		t.Fatalf("decide calls = %d, want 1 (B skipped)", h.decideCalls)
	}
	if !strings.Contains(errb, "skipped B") {
		t.Errorf("stderr = %q, want skipped B line", errb)
	}
	if !strings.Contains(errb, "approved A (allow_always)") {
		t.Errorf("stderr = %q, want approved A line", errb)
	}

	h2 := &scriptedHandler{
		approvals: `{"pending":[` + approvalA + `,` + onceOnly + `]}`,
		decide:    `{"ok":true}`,
	}
	if code, _, errb := runWired(t, home, h2, "approve", "--all"); code != 0 {
		t.Fatalf("approve --all: code=%d err=%q", code, errb)
	}
	if h2.decideCalls != 2 {
		t.Fatalf("approve --all decide calls = %d, want 2 (allow_once decides all)", h2.decideCalls)
	}
	for _, b := range h2.decideBodies {
		if !strings.Contains(b, `"decision":"allow_once"`) {
			t.Fatalf("decide body = %q, want allow_once", b)
		}
	}

	// approvals --approve-all is the same FOREVER + skip rule.
	h3 := &scriptedHandler{
		approvals: `{"pending":[` + approvalA + `,` + onceOnly + `]}`,
		decide:    `{"ok":true}`,
	}
	if code, _, errb := runWired(t, home, h3, "approvals", "--approve-all"); code != 0 {
		t.Fatalf("approvals --approve-all: code=%d err=%q", code, errb)
	}
	if h3.decideCalls != 1 {
		t.Fatalf("approvals --approve-all decide calls = %d, want 1", h3.decideCalls)
	}
}

func TestAutoApproveStatusAndToggles(t *testing.T) {
	home := fakeHome(t, `{"default_profile":"default","profiles":{"default":{"auto_approve":"always","auto_allow_once":true}}}`)
	h := &scriptedHandler{}
	code, out, errb := runWired(t, home, h, "auto-approve")
	if code != 0 {
		t.Fatalf("auto-approve status: code=%d out=%q err=%q", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res["auto_approve"] != "always" || res["auto_allow_once"] != true {
		t.Errorf("status = %v", res)
	}
	if res["source"] != "config "+filepath.Join(home, ".config", "castctl", "config.json") || !strings.HasPrefix(res["once_source"].(string), "config ") {
		t.Errorf("sources = %v/%v, want config paths", res["source"], res["once_source"])
	}
	if res["config"] != "always" || res["once_config"] != true {
		t.Errorf("config values = %v/%v", res["config"], res["once_config"])
	}

	if code, _, errb := runWired(t, home, h, "auto-approve", "off"); code != 0 {
		t.Fatalf("auto-approve off: code=%d err=%q", code, errb)
	}
	raw, _ := os.ReadFile(filepath.Join(home, ".config", "castctl", "config.json"))
	if !strings.Contains(string(raw), `"auto_approve": "off"`) {
		t.Errorf("config after off: %s", raw)
	}
	if code, out, _ := runWired(t, home, h, "auto-approve", "status"); code != 0 {
		t.Fatalf("status after off: code=%d", code)
	} else {
		var res2 map[string]any
		_ = json.Unmarshal([]byte(out), &res2)
		if res2["auto_approve"] != "off" {
			t.Errorf("status after off = %v", res2)
		}
	}

	if code, _, errb := runWired(t, home, h, "auto-approve", "once", "off"); code != 0 {
		t.Fatalf("auto-approve once off: code=%d err=%q", code, errb)
	}
	raw, _ = os.ReadFile(filepath.Join(home, ".config", "castctl", "config.json"))
	if !strings.Contains(string(raw), `"auto_allow_once": false`) {
		t.Errorf("config after once off: %s", raw)
	}

	// Env override wins for status display without touching the file.
	t.Setenv("MUSE_AUTO_APPROVE", "off")
	_, out, _ = runWired(t, home, h, "auto-approve", "status")
	var res3 map[string]any
	_ = json.Unmarshal([]byte(out), &res3)
	if res3["auto_approve"] != "off" || res3["source"] != "env MUSE_AUTO_APPROVE" || res3["env"] != "off" {
		t.Errorf("env status = %v", res3)
	}
	// An invalid env value is a config error (exit 2), not a default.
	t.Setenv("MUSE_AUTO_APPROVE", "bogus")
	if code, _, _ := runWired(t, home, h, "auto-approve", "status"); code != 2 {
		t.Fatalf("invalid env: code=%d, want 2", code)
	}
}

func TestAutoApproveDefaultsWithoutConfig(t *testing.T) {
	home := t.TempDir()
	h := &scriptedHandler{}
	code, out, errb := runWired(t, home, h, "auto-approve", "status")
	if code != 0 {
		t.Fatalf("status without config: code=%d out=%q err=%q", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res["auto_approve"] != "off" || res["auto_allow_once"] != false {
		t.Errorf("defaults = %v", res)
	}
	if code, _, _ := runWired(t, home, h, "auto-approve", "on"); code != 2 {
		t.Fatalf("toggle without a single file: code=%d, want 2", code)
	}
}

func TestAutoApproveBadArgsExit2(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{}
	for _, args := range [][]string{
		{"auto-approve", "bogus"},
		{"auto-approve", "on", "extra"},
		{"auto-approve", "on", "off"},
		{"auto-approve", "once", "bogus"},
	} {
		if code, _, _ := runWired(t, home, h, args...); code != 2 {
			t.Fatalf("%v: code=%d, want 2", args, code)
		}
	}
}

// panicGateway panics from SubscribeRaw, proving the CLI-boundary
// recover converts a Subscriber panic into exit 2 with a redacted
// message and no stack trace. Every other method is a stub: the
// panic fires before any of them is reached.
type panicGateway struct{}

func (g *panicGateway) CallJSON(_ context.Context, _ string, _ conn.RequestOptions) (any, error) {
	return nil, errUnused
}

func (g *panicGateway) Request(_ context.Context, _ string, _ conn.RequestOptions) ([]byte, error) {
	return nil, errUnused
}

func (g *panicGateway) SubscribeRaw(_ context.Context, _ string, _ conn.SubscribeOptions) ([][]byte, error) {
	panic("subscriber boom hatch_sess=PANICSECRET")
}

func (g *panicGateway) SubscribeJSON(_ context.Context, _ string, _ conn.SubscribeOptions) ([]any, error) {
	return nil, errUnused
}

func (g *panicGateway) DownloadFile(_ context.Context, _ any, _ conn.DownloadOptions) ([]byte, error) {
	return nil, errUnused
}

func (g *panicGateway) Ping(_ context.Context, _ time.Duration) (any, error) {
	return nil, errUnused
}

func (g *panicGateway) OpenStream(_ context.Context, _ string, _ conn.OpenStreamOptions) (int64, error) {
	return 0, errUnused
}

func (g *panicGateway) CancelStream(_ context.Context, _ int64) error { return nil }

func (g *panicGateway) LookupRoute(_ string) (conn.Route, bool) { return conn.Route{}, false }

func (g *panicGateway) Alive() bool         { return true }
func (g *panicGateway) Dead() error         { return nil }
func (g *panicGateway) LastRecv() time.Time { return time.Time{} }
func (g *panicGateway) LastUsed() time.Time { return time.Time{} }
func (g *panicGateway) Close() error        { return nil }

var errUnused = errors.New("unused in panic test")

var _ conn.Gateway = (*panicGateway)(nil)

func runWithRuntime(t *testing.T, home string, rt *commands.Runtime, rtErr error, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("CASTCTL_CONFIG", "")
	t.Setenv("CASTCTL_PROFILE", "")
	var out, errb bytes.Buffer
	env := &commands.Env{
		Stdout: &out,
		Stderr: &errb,
		Stdin:  strings.NewReader(""),
		BuildRuntime: func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, e *commands.Env) (*commands.Runtime, error) {
			_ = ctx
			_ = loc
			_ = prof
			_ = e
			return rt, rtErr
		},
	}
	code := commands.Run(context.Background(), args, env)
	return code, out.String(), errb.String()
}

func TestRecoverConvertsSubscriberPanic(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	muse := conn.New(func(ctx context.Context, cfg conn.Config) (conn.Gateway, error) {
		return &panicGateway{}, nil
	})
	rt := &commands.Runtime{Muse: muse}
	code, _, errb := runWithRuntime(t, home, rt, nil, "wait", "--timeout", "5")
	if code != 2 {
		t.Fatalf("subscriber panic: code=%d, want 2 (err=%q)", code, errb)
	}
	if !strings.Contains(errb, "panic") {
		t.Errorf("stderr = %q, want a panic line", errb)
	}
	if strings.Contains(errb, "PANICSECRET") {
		t.Errorf("stderr leaks the panic's secret value: %q", errb)
	}
	if !strings.Contains(errb, "panic_length=") {
		t.Errorf("stderr = %q, want the panic summary (type + length, never the value)", errb)
	}
	if strings.Contains(errb, "goroutine") || strings.Contains(errb, ".go:") {
		t.Errorf("stderr carries a stack trace: %q", errb)
	}
}

func TestRecoverConvertsBuildPanic(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("CASTCTL_CONFIG", "")
	t.Setenv("CASTCTL_PROFILE", "")
	var out, errb bytes.Buffer
	env := &commands.Env{
		Stdout: &out,
		Stderr: &errb,
		Stdin:  strings.NewReader(""),
		BuildRuntime: func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, e *commands.Env) (*commands.Runtime, error) {
			panic("build boom hatch_sess=BUILDSECRET")
		},
	}
	code := commands.Run(context.Background(), []string{"status"}, env)
	if code != 2 {
		t.Fatalf("build panic: code=%d, want 2 (err=%q)", code, errb.String())
	}
	if strings.Contains(errb.String(), "BUILDSECRET") {
		t.Errorf("stderr leaks the panic's secret value: %q", errb.String())
	}
	if !strings.Contains(errb.String(), "panic_length=") {
		t.Errorf("stderr = %q, want the panic summary (type + length, never the value)", errb.String())
	}
	if strings.Contains(errb.String(), "goroutine") {
		t.Errorf("stderr carries a stack trace: %q", errb.String())
	}
}

// F3: Python's send parser has no --json; the flag must be
// rejected with exit 2, not silently ignored.
func TestSendJSONFlagRejected(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{}
	if code, _, errb := runWired(t, home, h, "send", "hello", "--json", "--wait", "0", "--ack-timeout", "1"); code != 2 {
		t.Fatalf("send --json: code=%d, want 2 (err=%q)", code, errb)
	}
}

// F2: Python's `or` fallback — an empty first key falls through
// to the second (r.get("pending_approvals") or r.get("pending")).
func TestPendingApprovalsEmptyFallsThrough(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{approvals: `{"pending_approvals":[],"pending":[` + approvalA + `]}`}
	code, out, errb := runWired(t, home, h, "approvals")
	if code != 0 {
		t.Fatalf("approvals: code=%d out=%q err=%q", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pending, _ := res["pending"].([]any)
	if len(pending) != 1 {
		t.Fatalf("pending = %v, want the fallback list with 1 item", res["pending"])
	}
	a0, _ := pending[0].(map[string]any)
	if a0["approval_id"] != "A" {
		t.Errorf("pending row = %v, want approval A", a0)
	}
}

func TestRecentApprovalsEmptyFallsThrough(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{recent: `{"recent_approvals":[],"recent":[{"approval_id":"R1","display":{"summary_title":"T","permission_question":{"text":"Q?","kind":"browse","scope":"example.com"}},"decision":"allow_once"}]}`}
	code, out, errb := runWired(t, home, h, "approvals", "--recent")
	if code != 0 {
		t.Fatalf("approvals --recent: code=%d out=%q err=%q", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	recent, _ := res["recent"].([]any)
	if len(recent) != 1 {
		t.Fatalf("recent = %v, want the fallback list with 1 item", res["recent"])
	}
	r0, _ := recent[0].(map[string]any)
	if r0["approval_id"] != "R1" {
		t.Errorf("recent row = %v, want R1", r0)
	}
}

// M1: a timeout with no known task status reports status null,
// like Python's w.status (None), in both wait and send results.
func TestWaitTimeoutStatusNull(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history:   []string{historyBody()},
		subscribe: [][]byte{[]byte("{\"event\":\"unknown.thing\",\"payload\":{}}\n")},
	}
	code, out, errb := runWired(t, home, h, "wait", "--json", "--timeout", "1")
	if code != 124 {
		t.Fatalf("wait timeout: code=%d, want 124 (out=%q err=%q)", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := res["status"]; !ok {
		t.Errorf("timeout result lacks the status key: %q", out)
	} else if res["status"] != nil {
		t.Errorf("timeout result status = %v, want null", res["status"])
	}
}

func TestSendWaitTimeoutStatusNull(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	h := &scriptedHandler{
		history: []string{
			historyBody(userEv(100, "old")),
			historyBody(userEv(100, "old")),
			historyBody(userEv(100, "old"), userEv(110, "hello")),
			historyBody(userEv(100, "old"), userEv(110, "hello")),
		},
		// No task.status record is ever seen, so the timeout has
		// no known status (unlike a "running" batch, which
		// correctly reports status "running").
		subscribe: [][]byte{[]byte("{\"event\":\"unknown.thing\",\"payload\":{}}\n")},
	}
	code, out, errb := runWired(t, home, h, "send", "hello", "--wait", "1", "--ack-timeout", "5")
	if code != 124 {
		t.Fatalf("send wait timeout: code=%d, want 124 (out=%q err=%q)", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := res["status"]; !ok {
		t.Errorf("send timeout result lacks the status key: %q", out)
	} else if res["status"] != nil {
		t.Errorf("send timeout result status = %v, want null", res["status"])
	}
}

// M2: approve-all rows collapse absent fields to null, like
// Python's describe_approval/.get() rows.
func TestApproveAllNullFields(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	bare := `{"approval_id":"N","decision_options":[{"kind":"allow_always"}]}`
	h := &scriptedHandler{approvals: `{"pending":[` + bare + `]}`, decide: `{"ok":true}`}
	code, out, errb := runWired(t, home, h, "approvals", "--approve-all")
	if code != 0 {
		t.Fatalf("approve-all: code=%d out=%q err=%q", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	approved, _ := res["approved"].([]any)
	if len(approved) != 1 {
		t.Fatalf("approved = %v, want 1", res["approved"])
	}
	row, _ := approved[0].(map[string]any)
	if row["approval_id"] != "N" || row["decision"] != "allow_always" {
		t.Errorf("approved row = %v", row)
	}
	for _, k := range []string{"title", "kind", "scope"} {
		if _, ok := row[k]; !ok {
			t.Errorf("approved row lacks %q: %v", k, row)
		} else if row[k] != nil {
			t.Errorf("approved row %q = %v, want null", k, row[k])
		}
	}
	if h.decideCalls != 1 {
		t.Fatalf("decide calls = %d, want 1", h.decideCalls)
	}
}

// M2: auto_approve_errors rows collapse an absent decision (and
// absent kind/scope) to null; the SKIPPED case has no decision.
func TestWaitAutoApproveErrorsNullDecision(t *testing.T) {
	home := fakeHome(t, `{"default_profile":"default","profiles":{"default":{"auto_approve":"always"}}}`)
	onceOnly := `{"approval_id":"B","display":{"summary_title":"Once only"},"decision_options":[{"kind":"allow_once"}]}`
	h := &scriptedHandler{
		history:   []string{historyBody(userEv(100, "hi"))},
		subscribe: [][]byte{append(taskRecord("running"), approvalRecord(onceOnly)...)},
	}
	code, out, errb := runWired(t, home, h, "wait", "--json", "--timeout", "10")
	if code != 4 {
		t.Fatalf("wait no-forever approval: code=%d, want 4 (out=%q err=%q)", code, out, errb)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	errs, _ := res["auto_approve_errors"].([]any)
	if len(errs) != 1 {
		t.Fatalf("auto_approve_errors = %v, want 1", res["auto_approve_errors"])
	}
	row, _ := errs[0].(map[string]any)
	if row["approval_id"] != "B" || row["title"] != "Once only" {
		t.Errorf("error row = %v", row)
	}
	for _, k := range []string{"decision", "kind", "scope"} {
		if _, ok := row[k]; !ok {
			t.Errorf("error row lacks %q: %v", k, row)
		} else if row[k] != nil {
			t.Errorf("error row %q = %v, want null", k, row[k])
		}
	}
	if h.decideCalls != 0 {
		t.Fatalf("decide calls = %d, want 0 (no forever option, fallback off)", h.decideCalls)
	}
}

// R1 constraint: a plain transport failure is still a timeout
// (124), never an auth failure (2). Only the cookies-file class
// — now typed AuthError at the connector — exits 2.
func TestWaitNetworkDownStillTimeout124(t *testing.T) {
	home := fakeHome(t, defaultSingleConfig)
	muse := conn.New(func(ctx context.Context, cfg conn.Config) (conn.Gateway, error) {
		return nil, errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	})
	rt := &commands.Runtime{Muse: muse}
	code, out, _ := runWithRuntime(t, home, rt, nil, "wait", "--json", "--timeout", "2")
	if code != 124 {
		t.Fatalf("wait network down: code=%d, want 124 (out=%q)", code, out)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res["outcome"] != "timeout" {
		t.Errorf("outcome = %v, want timeout", res["outcome"])
	}
}
