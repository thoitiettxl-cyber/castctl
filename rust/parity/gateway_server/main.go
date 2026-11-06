// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Command gateway_server is the M4a cross-language parity
// harness: one binary, three modes, no production code touched
// (this file is the ONLY new Go file in the PR; it builds on
// the existing internal/gateway/gatewaytest.Server and the Go
// gateway Connector — no Go file is modified).
//
//	serve     — start a fake gateway server (gatewaytest.Server)
//	          with canned JSON per path, print READY addr=<addr>
//	          and serve until SIGINT/SIGTERM.
//	serve-e2e — start a STATEFUL fake gateway for the M5b Rust
//	          turn E2E (rust/castctl-telegram/tests/turn_e2e.rs):
//	          scripted history that evolves per call (user ack
//	          echo, streaming deltas, assistant reply + media,
//	          one pending approval), decide/fs.write logging to
//	          stderr, media bytes for /media/raw/*.
//	serve-wait — start a STATEFUL fake gateway for the M7a Rust
//	          wait Tier A goldens: scripted chat.history windows
//	          (staged by history call count) + scripted
//	          chat.subscribe NDJSON frames (staged by subscribe
//	          call count, with delay / end-body / drop). One
//	          shared script file (JSON) is the determinism
//	          contract: the Go wait_driver and the Rust
//	          wait_driver example both dial this server.
//	serve-m7b — start a scripted fake gateway for the M7b Rust
//	          Phase A CLI wiring (rust/parity/m7b_cases/*.json):
//	          canned responses per request path from the case
//	          script, every request logged as
//	          `M7B <verb> <path> <body>` (full body, no
//	          truncation — Phase A bodies are small) to stderr.
//	          The Go m7b_driver and the Rust m7b_driver example
//	          both dial a server running the same script with
//	          the same argv; their stdout/stderr/exit plus the
//	          M7B request logs must be byte-identical.
//	client    — connect the GO gateway client to a running server
//	          (serve mode, or any gatewaytest server) and call
//	          the methods given on the command line, printing one
//	          line per method: "<method>\t<compact JSON result>".
//
// The Rust parity client (castctl-gateway example
// parity_client) prints the same lines against the same
// server; the parity gate diffs the two outputs. All
// credentials here are fake (hatch_sess=FAKE, AT-FAKE,
// HT-FAKE); nothing real is ever read.
//
// Usage:
//
//	gateway_server serve
//	gateway_server serve-e2e
//	gateway_server serve-wait <script.json>
//	gateway_server serve-m7b <script.json>
//	gateway_server client <addr> <method> [method ...]
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway/gatewaytest"
	pb "github.com/thoitiettxl-cyber/castctl/internal/proto"
)

const fakeCookie = "hatch_sess=FAKE; datr=FAKE"

// cannedResult is the "result" field the fake server returns
// for each route path (the envelope is always
// {"ok":true,"result":<here>}). The Rust fake server in
// castctl-gateway/tests/common returns the same bodies.
// Paths are the REAL routes from internal/proto/routes.json:
// connection.ping -> POST /api/ping, sessions.list -> GET
// /api/session/list, chat.history -> GET /chat/history,
// feed.list -> GET /api/feed, goals.list -> GET /goals.
func cannedResult(path string) string {
	switch path {
	case "/api/ping":
		return `{"pong":true}`
	case "/api/session/list":
		return `{"sessions":[{"id":"s1","title":"t1"}]}`
	case "/chat/history":
		return `{"messages":[{"role":"user","text":"hi"}]}`
	case "/api/feed":
		return `{"items":[{"id":"f1"}]}`
	case "/goals":
		return `{"goals":[{"id":"g1","title":"goal"}]}`
	default:
		return `{}`
	}
}

func handler() gatewaytest.Handler {
	return gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		body := `{"ok":true,"result":` + cannedResult(req.Path) + `}`
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte(body), true),
		}}
	})
}

// plainDialer is the minimal gateway.OutboundDialer for the
// client mode: plain TCP to the host:port the WS URL names
// (the fake server is loopback, no TLS), and the canned auth
// chain for the HTTPS steps.
type plainDialer struct {
	auth http.Handler
}

func (d *plainDialer) WebSocketDial(ctx context.Context, network, host string, port uint16, secure bool, _ option.OutboundTLSOptions) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
}

func (d *plainDialer) HTTPClient() *http.Client {
	return &http.Client{Transport: gatewaytest.HandlerRoundTripper(d.auth)}
}

func runServe() error {
	server, err := gatewaytest.NewServer(handler())
	if err != nil {
		return err
	}
	defer server.Close()
	fmt.Printf("READY addr=%s\n", server.Addr())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	return nil
}

// ----------------------------------------------------------------
// serve-e2e: scripted history for the M5b Rust turn E2E.
// ----------------------------------------------------------------

// e2eState is the script's append-only event log. Every
// history call returns all events logged so far; follow
// stages are appended lazily on the 2nd and 3rd history
// calls after each stream open, so the Rust turn's 1s
// follow poll sees the deltas in two separate polls
// (streaming edits are spread across ticks, not batched).
type e2eState struct {
	mu sync.Mutex
	// events is the append-only log (marshalled per call).
	events []json.RawMessage
	// nextSeq allocates history seqs, 10 apart.
	nextSeq int64
	// streams opened so far; streamTexts[k] is the k-th
	// stream's user text (echoed back as its user event).
	streams     int
	streamTexts []string
	// histSinceStream counts chat.history calls since the
	// latest stream opened.
	histSinceStream int
	// decide/fs.write/media observations, for the E2E log.
	decided   []string
	fsWrites  []string
	mediaGets []string
}

func (s *e2eState) allocSeq() int64 {
	seq := s.nextSeq
	s.nextSeq += 10
	return seq
}

func (s *e2eState) event(seq int64, name string, payload string) {
	s.events = append(s.events, json.RawMessage(fmt.Sprintf(
		`{"seq":%d,"event_name":%q,"payload":%s}`, seq, name, payload)))
}

// history returns the current log, appending the next
// follow stage when the call is a follow poll
// (limit == 200: the turn's 1s poll; ack polls use
// limit 10 and baselines 1/20, and must never advance
// the stages). Callers must hold s.mu.
func (s *e2eState) history(limit int64) string {
	if s.streams == 0 {
		return `{"chat_events":[]}`
	}
	if limit == 200 {
		s.histSinceStream++
	}
	switch s.histSinceStream {
	case 2:
		// Follow poll 1: first delta + running.
		seq := s.allocSeq()
		s.event(seq, "delta.text_append", `{"text":"Hel","message_id":"m1"}`)
		seq = s.allocSeq()
		s.event(seq, "task.status", `{"status":"running","root_agent_id":"root1","agent_id":"root1"}`)
	case 3:
		// Follow poll 2: rest of the delta, the completed
		// reply (with one media file), one pending
		// approval, then the terminal status.
		seq := s.allocSeq()
		s.event(seq, "delta.text_append", `{"text":"lo","message_id":"m1"}`)
		seq = s.allocSeq()
		s.event(seq, "message.assistant", `{"status":"completed","display_text":"Hello from Muse","message_id":"m1","data":{"images":[{"path":"sandbox://e2e.png","mime":"image/png","byte_len":4,"label":"e2e image"}]}}`)
		seq = s.allocSeq()
		s.event(seq, "approvals.pending", `{"pending_approvals":[{"approval_id":"a1","display":{"summary_title":"Run shell","permission_question":{"text":"Allow Muse to run?"},"decision_options":[{"kind":"allow_always"},{"kind":"allow_once"},{"kind":"deny"}]}}]}`)
		seq = s.allocSeq()
		s.event(seq, "task.status", `{"status":"completed","root_agent_id":"root1","agent_id":"root1"}`)
	}
	var b strings.Builder
	b.WriteString(`{"chat_events":[`)
	for i, ev := range s.events {
		if i > 0 {
			b.WriteString(",")
		}
		b.Write(ev)
	}
	b.WriteString(`]}`)
	return b.String()
}

func e2eHandler(st *e2eState) gatewaytest.Handler {
	return gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		// The Rust gateway sends GET params as a query
		// string (chat.history arrives as
		// "/chat/history?limit=10" with an empty body),
		// so split the path before exact matching and
		// read the limit from the query when the body
		// has none. (Without this, every history call
		// hit the default case and returned {}, and the
		// ack poll looped the full 30s — observed in the
		// first E2E run, 2026-11-06.)
		path, query := req.Path, ""
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path, query = path[:i], path[i+1:]
		}
		limitFromQuery := func() int64 {
			for _, kv := range strings.Split(query, "&") {
				if k, v, ok := strings.Cut(kv, "="); ok && k == "limit" {
					if n, err := strconv.ParseInt(v, 10, 64); err == nil {
						return n
					}
				}
			}
			return 0
		}
		st.mu.Lock()
		defer st.mu.Unlock()
		reply := func(body string) gatewaytest.Response {
			fmt.Fprintf(os.Stderr, "E2E %s %s %s\n", req.Verb, path, truncateLog(string(req.Body), 200))
			return gatewaytest.Response{Frames: []*pb.ServiceFrame{
				gatewaytest.ResponseFrame(0, 200, []byte(`{"ok":true,"result":`+body+`}`), true),
			}}
		}
		raw := func(body []byte) gatewaytest.Response {
			fmt.Fprintf(os.Stderr, "E2E %s %s %s\n", req.Verb, path, truncateLog(string(req.Body), 200))
			return gatewaytest.Response{Frames: []*pb.ServiceFrame{
				gatewaytest.ResponseFrame(0, 200, body, true),
			}}
		}
		switch {
		case path == "/chat/history":
			var body struct {
				Limit int64 `json:"limit"`
			}
			_ = json.Unmarshal(req.Body, &body)
			limit := body.Limit
			if limit == 0 {
				limit = limitFromQuery()
			}
			return reply(st.history(limit))
		case path == "/chat/stream":
			// Record the sent text for the ack echo.
			var body struct {
				Items []struct {
					Text string `json:"text"`
				} `json:"items"`
			}
			_ = json.Unmarshal(req.Body, &body)
			text := ""
			if len(body.Items) > 0 {
				text = body.Items[0].Text
			}
			st.streams++
			st.streamTexts = append(st.streamTexts, text)
			st.histSinceStream = 0
			seq := st.allocSeq()
			st.event(seq, "message.user", fmt.Sprintf(`{"display_text":%q,"content":%q}`, text, text))
			return reply(`{}`)
		case path == "/approvals":
			return reply(`{"pending_approvals":[{"approval_id":"a1","display":{"summary_title":"Run shell","permission_question":{"text":"Allow Muse to run?"},"decision_options":[{"kind":"allow_always"},{"kind":"allow_once"},{"kind":"deny"}]}}]}`)
		case strings.HasPrefix(path, "/approvals/") && strings.HasSuffix(path, "/decide"):
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/approvals/"), "/decide")
			st.decided = append(st.decided, id+":"+string(req.Body))
			fmt.Fprintf(os.Stderr, "E2E DECIDE %s %s\n", id, string(req.Body))
			return reply(`{}`)
		case path == "/fs/write":
			var body struct {
				Path string `json:"path"`
			}
			_ = json.Unmarshal(req.Body, &body)
			st.fsWrites = append(st.fsWrites, body.Path)
			fmt.Fprintf(os.Stderr, "E2E FS-WRITE %s\n", body.Path)
			return reply(`{}`)
		case strings.HasPrefix(path, "/media/raw/"):
			st.mediaGets = append(st.mediaGets, path)
			return raw([]byte("PNG!"))
		case path == "/chat/cancel":
			return reply(`{"cancelled":true}`)
		default:
			return reply(`{}`)
		}
	})
}

func truncateLog(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func runServeE2E() error {
	st := &e2eState{nextSeq: 10}
	server, err := gatewaytest.NewServer(e2eHandler(st))
	if err != nil {
		return err
	}
	defer server.Close()
	fmt.Printf("READY addr=%s\n", server.Addr())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	st.mu.Lock()
	fmt.Fprintf(os.Stderr, "E2E SUMMARY streams=%d decided=%v fsWrites=%v mediaGets=%v\n",
		st.streams, st.decided, st.fsWrites, st.mediaGets)
	st.mu.Unlock()
	return nil
}

// ----------------------------------------------------------------
// serve-wait: scripted history + subscribe for the M7a Rust
// wait Tier A goldens (parity-live.md §3).
// ----------------------------------------------------------------

// waitScript is the shared script file (JSON) consumed by the
// serve-wait handler. It is the determinism contract: the Go
// wait_driver and the Rust wait_driver example both dial a
// server running this script, with the same argv, and their
// outputs must be byte-identical.
//
//   - history_stages: chat.history answers, staged by history
//     call count. The applicable stage is the LAST one whose
//     from_call <= the call number (1-based); if none applies
//     the answer is empty with has_more=false. Scripted
//     histories are smaller than any Runner window (200/500/
//     1000), so the requested limit never binds and is only
//     logged.
//   - subscribes: chat.subscribe answers, staged by subscribe
//     call count. Beyond the list the LAST entry repeats, so a
//     resubscribing Runner sees a stable answer. frames are
//     NDJSON lines (one JSON object per line, no trailing
//     newline in the file; the server joins them with "\n" and
//     appends a trailing "\n"). end_body ends the stream
//     cleanly (Response EndBody=true); drop closes the whole
//     WS connection AFTER sending the frames (gatewaytest
//     CloseAfter — CloseWithoutReply would send nothing).
//     frames=[] with end_body=false and drop=false is pure
//     silence: the server sends nothing and the client's idle
//     timeout ends the batch.
type waitScript struct {
	Thread        string             `json:"thread"`
	HistoryStages []waitHistoryStage `json:"history_stages"`
	Subscribes    []waitSubscribe    `json:"subscribes"`
}

type waitHistoryStage struct {
	FromCall int               `json:"from_call"`
	Events   []json.RawMessage `json:"events"`
	HasMore  bool              `json:"has_more"`
}

type waitSubscribe struct {
	DelayMs int      `json:"delay_ms"`
	Frames  []string `json:"frames"`
	EndBody bool     `json:"end_body"`
	Drop    bool     `json:"drop"`
}

type waitState struct {
	mu             sync.Mutex
	script         *waitScript
	historyCalls   int
	subscribeCalls int
	streams        int
	mediaGets      []string
}

// waitHistoryResult is the chat.history result object the
// Runner's HistoryReader parses: chat_events + has_more
// (internal/commands/wait.go callHistoryEvents reads
// chat_events; the Runner also needs has_more).
type waitHistoryResult struct {
	Events  []json.RawMessage `json:"chat_events"`
	HasMore bool              `json:"has_more"`
}

func (s *waitState) historyStage() waitHistoryStage {
	s.mu.Lock()
	defer s.mu.Unlock()
	stage := waitHistoryStage{FromCall: 1, Events: []json.RawMessage{}, HasMore: false}
	for _, st := range s.script.HistoryStages {
		if st.FromCall <= s.historyCalls {
			stage = st
		}
	}
	return stage
}

func (s *waitState) nextSubscribe() waitSubscribe {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.script.Subscribes
	if len(list) == 0 {
		return waitSubscribe{}
	}
	// subscribeCalls is 1-based (incremented before this call);
	// index 0-based and repeat the last entry beyond the list.
	idx := s.subscribeCalls - 1
	if idx >= len(list) {
		idx = len(list) - 1
	}
	return list[idx]
}

func waitHandler(st *waitState) gatewaytest.Handler {
	return gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		// Request() turns a GET body into a query string, so
		// a chat.history call arrives as
		// "/chat/history?limit=200" — match on the path
		// without the query, or the exact-match cases below
		// never fire and the request falls through to the
		// canned default handler (which answers {} with no
		// log line, so the call is invisible in the counts).
		path := req.Path
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		if path == "/chat/stream" {
			// The stream open itself is answered by the
			// canned default handler below (its {} result
			// opens the stream); this arm only counts and
			// logs it, so a fixture that never opens a
			// stream cannot pass as a send turn.
			st.mu.Lock()
			st.streams++
			st.mu.Unlock()
			fmt.Fprintf(os.Stderr, "WAIT stream chat.stream\n")
			return handler().Handle(req, service)
		}
		if strings.HasPrefix(path, "/media/raw/") {
			// Media bytes for send --download (and any
			// future download step): fixed bytes, so the
			// byte_len check in the case fixture is
			// deterministic.
			st.mu.Lock()
			st.mediaGets = append(st.mediaGets, path)
			st.mu.Unlock()
			fmt.Fprintf(os.Stderr, "WAIT media %s\n", path)
			return gatewaytest.Response{Frames: []*pb.ServiceFrame{
				gatewaytest.ResponseFrame(0, 200, []byte("hello-bytes"), true),
			}}
		}
		switch path {
		case "/chat/history":
			st.mu.Lock()
			st.historyCalls++
			call := st.historyCalls
			st.mu.Unlock()
			stage := st.historyStage()
			var limit int
			var sessionID string
			var bodyMap map[string]any
			if err := json.Unmarshal(req.Body, &bodyMap); err == nil {
				if l, ok := bodyMap["limit"].(float64); ok {
					limit = int(l)
				}
				if sid, ok := bodyMap["session_id"].(string); ok {
					sessionID = sid
				}
			}
			// GET calls carry limit/session_id in the query
			// (the body was moved there by Request); the
			// body parse above stays first so a real body
			// still wins.
			if u, err := url.Parse(req.Path); err == nil {
				q := u.Query()
				if limit == 0 {
					if l, err := strconv.Atoi(q.Get("limit")); err == nil {
						limit = l
					}
				}
				if sessionID == "" {
					sessionID = q.Get("session_id")
				}
			}
			events := stage.Events
			if events == nil {
				events = []json.RawMessage{}
			}
			result, err := json.Marshal(waitHistoryResult{Events: events, HasMore: stage.HasMore})
			if err != nil {
				fmt.Fprintf(os.Stderr, "WAIT history call=%d marshal error: %v\n", call, err)
				return gatewaytest.Response{Frames: []*pb.ServiceFrame{
					gatewaytest.ResponseFrame(0, 500, []byte(`{"ok":false,"error":"marshal"}`), true),
				}}
			}
			fmt.Fprintf(os.Stderr, "WAIT history call=%d limit=%d session_id=%q events=%d has_more=%v\n",
				call, limit, sessionID, len(events), stage.HasMore)
			envelope := `{"ok":true,"result":` + string(result) + `}`
			return gatewaytest.Response{Frames: []*pb.ServiceFrame{
				gatewaytest.ResponseFrame(0, 200, []byte(envelope), true),
			}}
		case "/chat/subscribe":
			st.mu.Lock()
			st.subscribeCalls++
			call := st.subscribeCalls
			st.mu.Unlock()
			sub := st.nextSubscribe()
			fmt.Fprintf(os.Stderr, "WAIT subscribe #%d delay_ms=%d frames=%d end_body=%v drop=%v\n",
				call, sub.DelayMs, len(sub.Frames), sub.EndBody, sub.Drop)
			if sub.DelayMs > 0 {
				time.Sleep(time.Duration(sub.DelayMs) * time.Millisecond)
			}
			if len(sub.Frames) == 0 && !sub.EndBody && !sub.Drop {
				// Pure silence: send nothing; the client's idle
				// timeout ends the batch (E1).
				return gatewaytest.Response{}
			}
			payload := ""
			if len(sub.Frames) > 0 {
				payload = strings.Join(sub.Frames, "\n") + "\n"
			}
			return gatewaytest.Response{
				Frames: []*pb.ServiceFrame{
					gatewaytest.ResponseFrame(0, 200, []byte(payload), sub.EndBody),
				},
				CloseAfter: sub.Drop,
			}
		default:
			return handler().Handle(req, service)
		}
	})
}

func runServeWait(scriptPath string) error {
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("wait script: %w", err)
	}
	var script waitScript
	// Case files nest the script under "script"
	// (args+name+script); unmarshalling the file straight
	// into waitScript leaves HistoryStages and Subscribes
	// empty, so every subscribe serves silence and no case
	// can ever complete. A bare waitScript file is still
	// accepted. When both are present the envelope wins
	// (round-2 R2-4).
	var envelope struct {
		Script *waitScript `json:"script"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("wait script %s: %w", scriptPath, err)
	}
	if envelope.Script != nil {
		script = *envelope.Script
	} else if err := json.Unmarshal(raw, &script); err != nil {
		return fmt.Errorf("wait script %s: %w", scriptPath, err)
	}
	// An empty script (no stages AND no subscribes) is a
	// broken case file, not a silent script: both drivers
	// would time out identically and the harness would
	// PASS a case that tests nothing (round-2 R2-4).
	// Fail at load instead.
	if len(script.HistoryStages) == 0 && len(script.Subscribes) == 0 {
		return fmt.Errorf("wait script %s: empty script (no history_stages and no subscribes)", scriptPath)
	}
	// `historyStage()` picks the last stage with
	// `from_call <= historyCalls`, so stages must be
	// ordered by `from_call` — sort once at load time
	// instead of trusting file order (red-team F12).
	sort.SliceStable(script.HistoryStages, func(i, j int) bool {
		return script.HistoryStages[i].FromCall < script.HistoryStages[j].FromCall
	})
	st := &waitState{script: &script}
	server, err := gatewaytest.NewServer(waitHandler(st))
	if err != nil {
		return err
	}
	defer server.Close()
	fmt.Printf("READY addr=%s\n", server.Addr())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	st.mu.Lock()
	fmt.Fprintf(os.Stderr, "WAIT SUMMARY history_calls=%d subscribes=%d\n",
		st.historyCalls, st.subscribeCalls)
	fmt.Fprintf(os.Stderr, "WAIT SUMMARY streams=%d media=%v\n",
		st.streams, st.mediaGets)
	st.mu.Unlock()
	return nil
}

func runClient(addr string, methods []string) error {
	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT-FAKE", HatchToken: "HT-FAKE"}
	dialer := &plainDialer{auth: auth}
	// Unique temp file (0600), not a fixed name: two parity
	// runs must never share — or clobber — each other's
	// cookie file.
	cookiesTmp, err := os.CreateTemp("", "parity-cookies-*.txt")
	if err != nil {
		return err
	}
	cookiesFile := cookiesTmp.Name()
	if _, err := cookiesTmp.Write([]byte(fakeCookie)); err != nil {
		cookiesTmp.Close()
		os.Remove(cookiesFile)
		return err
	}
	if err := cookiesTmp.Close(); err != nil {
		os.Remove(cookiesFile)
		return err
	}
	defer os.Remove(cookiesFile)
	connect := gateway.NewConnector(
		dialer,
		gateway.WithWebSocketSecure(false),
		gateway.WithWSURL(func(vmID, token string) string {
			return fmt.Sprintf("ws://%s/v1/noise?vm_id=%s&auth_token=%s", addr, vmID, token)
		}),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gw, err := connect(ctx, conn.Config{CookiesFile: cookiesFile, VMID: "vm-test"})
	if err != nil {
		return fmt.Errorf("go connector: %w", err)
	}
	defer gw.Close()
	for _, method := range methods {
		out, err := gw.CallJSON(ctx, method, conn.RequestOptions{})
		if err != nil {
			return fmt.Errorf("go CallJSON %s: %w", method, err)
		}
		raw, err := json.Marshal(out)
		if err != nil {
			return fmt.Errorf("go marshal %s: %w", method, err)
		}
		fmt.Printf("%s\t%s\n", method, raw)
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gateway_server serve | serve-e2e | serve-wait <script.json> | serve-m7b <script.json> | client <addr> <method> [method ...]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe()
	case "serve-e2e":
		err = runServeE2E()
	case "serve-wait":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: gateway_server serve-wait <script.json>")
			os.Exit(2)
		}
		err = runServeWait(os.Args[2])
	case "serve-m7b":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: gateway_server serve-m7b <script.json>")
			os.Exit(2)
		}
		err = runServeM7b(os.Args[2])
	case "client":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: gateway_server client <addr> <method> [method ...]")
			os.Exit(2)
		}
		err = runClient(os.Args[2], os.Args[3:])
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gateway_server:", err)
		os.Exit(1)
	}
}

// ----------------------------------------------------------------
// serve-m7b: scripted canned responses for the M7b Rust Phase A
// CLI wiring (rust/parity/run_m7b_cases.sh).
// ----------------------------------------------------------------

// m7bEntry is one canned gateway response, keyed by request
// path in the case script. Exactly one of result / raw_b64 /
// body selects the frame body:
//
//   - result: the frame is {"ok":true,"result":<result>}.
//   - raw_b64: the frame is the base64-decoded bytes verbatim
//     (media downloads: the client reads raw bytes).
//   - body: the frame is the string verbatim (error envelopes
//     and other exact-byte bodies).
//
// status defaults to 200. An entry with none of the three set
// answers {"ok":true,"result":{}}.
type m7bEntry struct {
	Status int             `json:"status"`
	Result json.RawMessage `json:"result"`
	RawB64 string          `json:"raw_b64"`
	Body   string          `json:"body"`
}

// m7bScript is the shared script file (JSON) consumed by the
// serve-m7b handler and by the M7b fake HTTP server
// (rust/parity/m7b_http_server.py, which serves the "http"
// map). It is the determinism contract: the Go m7b_driver and
// the Rust m7b_driver example both dial a server running this
// script, with the same argv, and their outputs plus the M7B
// request logs must be byte-identical.
type m7bScript struct {
	Gateway map[string]m7bEntry `json:"gateway"`
	HTTP    map[string]m7bEntry `json:"http"`
}

type m7bState struct {
	mu       sync.Mutex
	script   *m7bScript
	requests int
}

func m7bHandler(st *m7bState) gatewaytest.Handler {
	return gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		// Full request body, no truncation: Phase A bodies
		// are small, and the log is the byte-parity evidence
		// for request construction (D-M7b-3 ordered bodies).
		fmt.Fprintf(os.Stderr, "M7B %s %s %s\n", req.Verb, req.Path, string(req.Body))
		st.mu.Lock()
		st.requests++
		// GET calls carry their body as a query string
		// (calls.go:83: bodyToQuery), so the lookup key is
		// the path without the query; the log above keeps
		// the full path+query as the byte evidence.
		lookupPath := req.Path
		if i := strings.Index(lookupPath, "?"); i >= 0 {
			lookupPath = lookupPath[:i]
		}
		entry, ok := st.script.Gateway[lookupPath]
		st.mu.Unlock()
		status := 200
		var frame []byte
		switch {
		case !ok:
			status = 404
			frame = []byte(`{"ok":false,"error":"m7b: no canned response for ` + req.Path + `"}`)
		case entry.RawB64 != "":
			raw, err := base64.StdEncoding.DecodeString(entry.RawB64)
			if err != nil {
				status = 500
				frame = []byte(`{"ok":false,"error":"m7b: bad raw_b64"}`)
				break
			}
			if entry.Status != 0 {
				status = entry.Status
			}
			frame = raw
		case entry.Body != "":
			if entry.Status != 0 {
				status = entry.Status
			}
			frame = []byte(entry.Body)
		case entry.Result != nil:
			if entry.Status != 0 {
				status = entry.Status
			}
			frame = []byte(`{"ok":true,"result":` + string(entry.Result) + `}`)
		default:
			if entry.Status != 0 {
				status = entry.Status
			}
			frame = []byte(`{"ok":true,"result":{}}`)
		}
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, int32(status), frame, true),
		}}
	})
}

func runServeM7b(scriptPath string) error {
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("m7b script: %w", err)
	}
	var script m7bScript
	if err := json.Unmarshal(raw, &script); err != nil {
		return fmt.Errorf("m7b script %s: %w", scriptPath, err)
	}
	st := &m7bState{script: &script}
	server, err := gatewaytest.NewServer(m7bHandler(st))
	if err != nil {
		return err
	}
	defer server.Close()
	fmt.Printf("READY addr=%s\n", server.Addr())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	st.mu.Lock()
	fmt.Fprintf(os.Stderr, "M7B SUMMARY requests=%d\n", st.requests)
	st.mu.Unlock()
	return nil
}
