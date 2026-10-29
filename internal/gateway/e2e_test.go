// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/gateway/gatewaytest"
	pb "github.com/thoitiettxl-cyber/muse-cli/go/internal/proto"
)

// e2eSetup starts a fake gateway + fake dialer and connects one
// Gateway through the full Connector (auth chain + WS dial +
// Noise handshake). All traffic is loopback; cookies are fake.
type e2eSetup struct {
	server  *gatewaytest.Server
	dialer  *gatewaytest.FakeDialer
	auth    *gatewaytest.CannedAuth
	gw      conn.Gateway
	cleanup func()
}

func startE2E(t *testing.T, handler gatewaytest.Handler) *e2eSetup {
	t.Helper()
	server, err := gatewaytest.NewServer(handler)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT-FAKE", HatchToken: "HT-FAKE"}
	dialer := gatewaytest.NewFakeDialer(server, auth)
	cookiesFile := filepath.Join(t.TempDir(), "cookies.txt")
	if err := os.WriteFile(cookiesFile, []byte(fakeCookie), 0o600); err != nil {
		t.Fatalf("write cookies: %v", err)
	}
	connector := NewConnector(dialer, WithWebSocketSecure(false))
	gw, err := connector(context.Background(), conn.Config{CookiesFile: cookiesFile, VMID: "vm-test"})
	if err != nil {
		server.Close()
		t.Fatalf("connector: %v", err)
	}
	s := &e2eSetup{server: server, dialer: dialer, auth: auth, gw: gw}
	s.cleanup = func() {
		_ = gw.Close()
		_ = server.Close()
	}
	return s
}

func jsonOKHandler(result string) gatewaytest.Handler {
	return gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte(`{"ok":true,"result":`+result+`}`), true),
		}}
	})
}

func TestE2EAuthChainCounts(t *testing.T) {
	s := startE2E(t, jsonOKHandler(`{}`))
	defer s.cleanup()
	// VMID was given, so no session call; auth/check + hatch/token once each.
	if got := s.auth.SessionCalls.Load(); got != 0 {
		t.Errorf("session calls = %d, want 0 (VMID supplied)", got)
	}
	if got := s.auth.AuthCheckCalls.Load(); got != 1 {
		t.Errorf("auth/check calls = %d, want 1", got)
	}
	if got := s.auth.HatchCalls.Load(); got != 1 {
		t.Errorf("hatch/token calls = %d, want 1", got)
	}
	if got := s.dialer.Dials(); got != 1 {
		t.Errorf("ws dials = %d, want 1", got)
	}
	for _, c := range s.auth.SeenCookies {
		if c != fakeCookie {
			t.Errorf("cookie header = %q, want fake cookie", c)
		}
	}
	if !s.gw.Alive() || s.gw.Dead() != nil {
		t.Error("gateway not alive after connect")
	}
}

func TestE2EAuthChainDiscoversVMID(t *testing.T) {
	server, err := gatewaytest.NewServer(jsonOKHandler(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	auth := &gatewaytest.CannedAuth{VMID: "vm-discovered", AccessToken: "AT", HatchToken: "HT"}
	dialer := gatewaytest.NewFakeDialer(server, auth)
	cookiesFile := filepath.Join(t.TempDir(), "cookies.txt")
	_ = os.WriteFile(cookiesFile, []byte(fakeCookie), 0o600)
	gw, err := NewConnector(dialer, WithWebSocketSecure(false))(context.Background(), conn.Config{CookiesFile: cookiesFile})
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	defer gw.Close()
	if got := auth.SessionCalls.Load(); got != 1 {
		t.Errorf("session calls = %d, want 1", got)
	}
}

func TestE2EAuthChainFailureIsAuthError(t *testing.T) {
	server, err := gatewaytest.NewServer(jsonOKHandler(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	auth := &gatewaytest.CannedAuth{VMID: "vm-x", AuthCheckStatus: 401}
	dialer := gatewaytest.NewFakeDialer(server, auth)
	cookiesFile := filepath.Join(t.TempDir(), "cookies.txt")
	_ = os.WriteFile(cookiesFile, []byte(fakeCookie), 0o600)
	_, err = NewConnector(dialer, WithWebSocketSecure(false))(context.Background(), conn.Config{CookiesFile: cookiesFile, VMID: "vm-x"})
	var ae *conn.AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("connector err = %T (%v), want *AuthError", err, err)
	}
	if got := dialer.Dials(); got != 0 {
		t.Errorf("ws dials = %d, want 0 (auth failed first)", got)
	}
}

func TestE2EAuthChainVMUnavailableIsGatewayError(t *testing.T) {
	server, err := gatewaytest.NewServer(jsonOKHandler(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	auth := &gatewaytest.CannedAuth{SessionNoVMID: true}
	dialer := gatewaytest.NewFakeDialer(server, auth)
	cookiesFile := filepath.Join(t.TempDir(), "cookies.txt")
	_ = os.WriteFile(cookiesFile, []byte(fakeCookie), 0o600)
	_, err = NewConnector(dialer, WithWebSocketSecure(false))(context.Background(), conn.Config{CookiesFile: cookiesFile})
	var ge *conn.GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("connector err = %T (%v), want *GatewayError", err, err)
	}
	var ae *conn.AuthError
	if errors.As(err, &ae) {
		t.Fatal("VM-unavailable error also matches AuthError")
	}
}

func TestE2ECallJSONRoundTrip(t *testing.T) {
	s := startE2E(t, jsonOKHandler(`{"n":123,"big":9007199254740993}`))
	defer s.cleanup()
	res, err := s.gw.CallJSON(context.Background(), "sessions.list", conn.RequestOptions{})
	if err != nil {
		t.Fatalf("CallJSON: %v", err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("result = %T", res)
	}
	if m["n"].(json.Number).String() != "123" {
		t.Errorf("n = %v (%T)", m["n"], m["n"])
	}
	if m["big"].(json.Number).String() != "9007199254740993" {
		t.Errorf("big lost precision: %v", m["big"])
	}
	reqs := s.server.Requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d", len(reqs))
	}
	req := reqs[0]
	if req.Verb != "GET" || req.Path != "/api/session/list" {
		t.Errorf("request = %s %s", req.Verb, req.Path)
	}
	if req.Service != pb.ServiceType_SERVICE_DAEMON {
		t.Errorf("service = %v", req.Service)
	}
	if req.Headers["x-request-id"] == "" {
		t.Error("x-request-id missing")
	}
	if _, ok := req.Headers["content-type"]; ok {
		t.Errorf("content-type present with no body: %v", req.Headers)
	}
	if req.StreamID != 1 {
		t.Errorf("first stream id = %d, want 1", req.StreamID)
	}
}

func TestE2ERequestErrors(t *testing.T) {
	t.Run("status 404", func(t *testing.T) {
		s := startE2E(t, gatewaytest.JSONHandler(404, []byte("not found here")))
		defer s.cleanup()
		_, err := s.gw.Request(context.Background(), "sessions.list", conn.RequestOptions{})
		var ge *conn.GatewayError
		if !errors.As(err, &ge) {
			t.Fatalf("err = %T (%v)", err, err)
		}
		if ge.Status != 404 || ge.Payload != "not found here" {
			t.Errorf("GatewayError = %+v", ge)
		}
	})
	t.Run("status payload truncated to 500", func(t *testing.T) {
		s := startE2E(t, gatewaytest.JSONHandler(500, []byte(strings.Repeat("e", 900))))
		defer s.cleanup()
		_, err := s.gw.Request(context.Background(), "sessions.list", conn.RequestOptions{})
		var ge *conn.GatewayError
		if !errors.As(err, &ge) || len(ge.Payload) != 500 {
			t.Fatalf("err = %T (%v)", err, err)
		}
	})
	t.Run("reset", func(t *testing.T) {
		s := startE2E(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
			return gatewaytest.Response{Frames: []*pb.ServiceFrame{gatewaytest.ResetFrame(0, pb.Reset_INTERNAL_ERROR, "boom")}}
		}))
		defer s.cleanup()
		_, err := s.gw.Request(context.Background(), "sessions.list", conn.RequestOptions{})
		var ge *conn.GatewayError
		if !errors.As(err, &ge) || ge.Status != -1 || !strings.Contains(ge.Payload, "stream reset 5: boom") {
			t.Fatalf("err = %T (%v)", err, err)
		}
	})
	t.Run("non-JSON call_json", func(t *testing.T) {
		s := startE2E(t, gatewaytest.JSONHandler(200, []byte(`not json`)))
		defer s.cleanup()
		_, err := s.gw.CallJSON(context.Background(), "sessions.list", conn.RequestOptions{})
		var ge *conn.GatewayError
		if !errors.As(err, &ge) || ge.Status != -1 {
			t.Fatalf("err = %T (%v)", err, err)
		}
	})
	t.Run("ok false", func(t *testing.T) {
		s := startE2E(t, gatewaytest.JSONHandler(200, []byte(`{"ok":false,"error":"denied"}`)))
		defer s.cleanup()
		_, err := s.gw.CallJSON(context.Background(), "sessions.list", conn.RequestOptions{})
		var ge *conn.GatewayError
		if !errors.As(err, &ge) || !strings.Contains(ge.Payload, "denied") {
			t.Fatalf("err = %T (%v)", err, err)
		}
	})
	t.Run("empty body is empty object", func(t *testing.T) {
		s := startE2E(t, gatewaytest.JSONHandler(200, []byte(``)))
		defer s.cleanup()
		res, err := s.gw.CallJSON(context.Background(), "sessions.list", conn.RequestOptions{})
		if err != nil {
			t.Fatalf("CallJSON: %v", err)
		}
		if m, ok := res.(map[string]any); !ok || len(m) != 0 {
			t.Errorf("result = %#v", res)
		}
	})
	t.Run("non-dict result returned whole", func(t *testing.T) {
		s := startE2E(t, gatewaytest.JSONHandler(200, []byte(`[1,2]`)))
		defer s.cleanup()
		res, err := s.gw.CallJSON(context.Background(), "sessions.list", conn.RequestOptions{})
		if err != nil {
			t.Fatalf("CallJSON: %v", err)
		}
		if arr, ok := res.([]any); !ok || len(arr) != 2 {
			t.Errorf("result = %#v", res)
		}
	})
	t.Run("unknown method", func(t *testing.T) {
		s := startE2E(t, jsonOKHandler(`{}`))
		defer s.cleanup()
		_, err := s.gw.Request(context.Background(), "no.such.method", conn.RequestOptions{})
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("err = %T (%v), want ValidationError", err, err)
		}
		if s.server.RequestCount() != 0 {
			t.Error("unknown method was sent on the wire")
		}
	})
}

func TestE2EPathParamsAndGETBodyToQuery(t *testing.T) {
	s := startE2E(t, jsonOKHandler(`{"ok":true}`))
	defer s.cleanup()
	ctx := context.Background()
	_, err := s.gw.CallJSON(ctx, "chat.mark_seen", conn.RequestOptions{PathParams: map[string]string{"thread_id": "a/b c"}})
	if err != nil {
		t.Fatalf("mark_seen: %v", err)
	}
	_, err = s.gw.Request(ctx, "chat.history", conn.RequestOptions{Body: map[string]any{"limit": int64(10), "cursor": "x y", "skip": nil}})
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	reqs := s.server.Requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %d", len(reqs))
	}
	if reqs[0].Path != "/api/chat/a%2Fb%20c/seen" {
		t.Errorf("path params path = %q", reqs[0].Path)
	}
	// GET body -> query: no body on the wire, query carries limit+cursor.
	if len(reqs[1].Body) != 0 {
		t.Errorf("GET body sent: %q", reqs[1].Body)
	}
	if !strings.HasPrefix(reqs[1].Path, "/chat/history?") {
		t.Errorf("GET path = %q", reqs[1].Path)
	}
	if !strings.Contains(reqs[1].Path, "limit=10") || !strings.Contains(reqs[1].Path, "cursor=x+y") || strings.Contains(reqs[1].Path, "skip=") {
		t.Errorf("GET query = %q", reqs[1].Path)
	}
}

func TestE2EServiceRouting(t *testing.T) {
	s := startE2E(t, jsonOKHandler(`{"ok":true}`))
	defer s.cleanup()
	ctx := context.Background()
	if _, err := s.gw.CallJSON(ctx, "egress.approvals", conn.RequestOptions{}); err != nil {
		t.Fatalf("approvals: %v", err)
	}
	if _, err := s.gw.CallJSON(ctx, "custom_connectors.list", conn.RequestOptions{}); err != nil {
		t.Fatalf("connectors: %v", err)
	}
	if _, err := s.gw.CallJSON(ctx, "vault.luks_status", conn.RequestOptions{}); err != nil {
		t.Fatalf("vault: %v", err)
	}
	reqs := s.server.Requests()
	if len(reqs) != 3 {
		t.Fatalf("requests = %d", len(reqs))
	}
	want := []pb.ServiceType{pb.ServiceType_SERVICE_SENTINEL, pb.ServiceType_SERVICE_AUTHD, pb.ServiceType_SERVICE_VAULT}
	for i, w := range want {
		if reqs[i].Service != w {
			t.Errorf("request %d service = %v, want %v", i, reqs[i].Service, w)
		}
	}
}

func TestE2ELargePayloadChunkedAndShuffled(t *testing.T) {
	big := make([]byte, 150000)
	for i := range big {
		big[i] = byte(i % 251)
	}
	s := startE2E(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		// Respond in two chunks, pieces shuffled: the client
		// must join by chunk_index.
		return gatewaytest.Response{
			ShufflePieces: true,
			Frames: []*pb.ServiceFrame{
				gatewaytest.ResponseFrame(0, 200, big[:80000], false),
				gatewaytest.ChunkFrame(0, big[80000:], true),
			},
		}
	}))
	defer s.cleanup()
	got, err := s.gw.Request(context.Background(), "sessions.list", conn.RequestOptions{})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if len(got) != len(big) {
		t.Fatalf("payload len = %d, want %d", len(got), len(big))
	}
	for i := range big {
		if got[i] != big[i] {
			t.Fatalf("payload mismatch at %d", i)
		}
	}
}

func TestE2ELargeRequestChunked(t *testing.T) {
	bigBody := make([]byte, 130000)
	for i := range bigBody {
		bigBody[i] = byte('a' + i%26)
	}
	s := startE2E(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		if len(req.Body) != len(bigBody) {
			return gatewaytest.Response{Frames: []*pb.ServiceFrame{gatewaytest.ResponseFrame(0, 500, []byte(fmt.Sprintf("body len %d", len(req.Body))), true)}}
		}
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{gatewaytest.ResponseFrame(0, 200, []byte(`{"ok":true}`), true)}}
	}))
	defer s.cleanup()
	_, err := s.gw.Request(context.Background(), "custom_connectors.list", conn.RequestOptions{Body: bigBody})
	if err != nil {
		t.Fatalf("large request: %v", err)
	}
}

func TestE2ESubscribeRaw(t *testing.T) {
	s := startE2E(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte("{\"seq\":1}\n{\"seq\":2}\n"), false),
			gatewaytest.ChunkFrame(0, []byte("{\"seq\":3}"), true),
		}}
	}))
	defer s.cleanup()
	var opened bool
	records, err := s.gw.SubscribeRaw(context.Background(), "chat.subscribe", conn.SubscribeOptions{
		OnOpen: func() { opened = true },
	})
	if err != nil {
		t.Fatalf("SubscribeRaw: %v", err)
	}
	if !opened {
		t.Error("OnOpen not called")
	}
	if len(records) != 3 {
		t.Fatalf("records = %d: %q", len(records), records)
	}
	for i, want := range []string{`{"seq":1}`, `{"seq":2}`, `{"seq":3}`} {
		if string(records[i]) != want {
			t.Errorf("record %d = %q, want %q", i, records[i], want)
		}
	}
}

func TestE2ESubscribeOnRecordStopsAndResets(t *testing.T) {
	s := startE2E(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		// No end_body: the stream is still open when OnRecord
		// stops it, so the client must send a reset (Python:
		// ended -> forget, otherwise -> cancel).
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte("a\nb\nc\n"), false),
		}}
	}))
	defer s.cleanup()
	var seen [][]byte
	records, err := s.gw.SubscribeRaw(context.Background(), "chat.subscribe", conn.SubscribeOptions{
		OnRecord: func(rec []byte) bool {
			seen = append(seen, rec)
			return len(seen) >= 1
		},
	})
	if err != nil {
		t.Fatalf("SubscribeRaw: %v", err)
	}
	if len(records) != 1 || string(records[0]) != "a" {
		t.Fatalf("records = %q", records)
	}
	// Give the reset a moment to reach the server.
	deadline := time.Now().Add(2 * time.Second)
	for s.server.ResetCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.server.ResetCount() == 0 {
		t.Error("no reset frame reached the server after OnRecord stop")
	}
}

func TestE2ESubscribeShouldStop(t *testing.T) {
	s := startE2E(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		return gatewaytest.Response{
			Delay:  3 * time.Second,
			Frames: []*pb.ServiceFrame{gatewaytest.ResponseFrame(0, 200, []byte("late\n"), true)},
		}
	}))
	defer s.cleanup()
	stopped := false
	start := time.Now()
	records, err := s.gw.SubscribeRaw(context.Background(), "chat.subscribe", conn.SubscribeOptions{
		IdleTimeout:    30 * time.Second,
		OverallTimeout: 30 * time.Second,
		ShouldStop: func() bool {
			if time.Since(start) > 300*time.Millisecond {
				stopped = true
				return true
			}
			return false
		},
	})
	if err != nil {
		t.Fatalf("SubscribeRaw: %v", err)
	}
	if !stopped || len(records) != 0 {
		t.Errorf("stopped=%v records=%q", stopped, records)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("ShouldStop took %v to end the subscription", elapsed)
	}
}

func TestE2ESubscribeJSONDropsBadLines(t *testing.T) {
	s := startE2E(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte("{\"a\":1}\nnot json\n{\"b\":2}\n"), true),
		}}
	}))
	defer s.cleanup()
	out, err := s.gw.SubscribeJSON(context.Background(), "chat.subscribe", conn.SubscribeOptions{})
	if err != nil {
		t.Fatalf("SubscribeJSON: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("out = %#v", out)
	}
}

func TestE2EDownloadFile(t *testing.T) {
	content := []byte("file-bytes-12345")
	s := startE2E(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		if req.Verb != "GET" || req.Path != "/media/raw/workspace/my%20photo.png" {
			return gatewaytest.Response{Frames: []*pb.ServiceFrame{gatewaytest.ResponseFrame(0, 404, []byte("wrong path "+req.Path), true)}}
		}
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, content[:8], false),
			gatewaytest.ChunkFrame(0, content[8:], true),
		}}
	}))
	defer s.cleanup()
	got, err := s.gw.DownloadFile(context.Background(), "sandbox://workspace/my photo.png", conn.DownloadOptions{})
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("download = %q, want %q", got, content)
	}
	if _, err := s.gw.DownloadFile(context.Background(), "../escape", conn.DownloadOptions{}); err == nil {
		t.Error("dotdot download: nil error")
	}
}

func TestE2EPing(t *testing.T) {
	s := startE2E(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		if string(req.Body) != `{"presence":"away"}` {
			return gatewaytest.Response{Frames: []*pb.ServiceFrame{gatewaytest.ResponseFrame(0, 500, []byte("bad ping body"), true)}}
		}
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte(`{"ok":true,"result":{"pong":true}}`), true),
		}}
	}))
	defer s.cleanup()
	res, err := s.gw.Ping(context.Background(), 10*time.Second)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if res.(map[string]any)["pong"] != true {
		t.Errorf("ping result = %#v", res)
	}
}

func TestE2ERequestTimeout(t *testing.T) {
	s := startE2E(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		return gatewaytest.Response{
			Delay:  1 * time.Second,
			Frames: []*pb.ServiceFrame{gatewaytest.ResponseFrame(0, 200, []byte(`{}`), true)},
		}
	}))
	defer s.cleanup()
	start := time.Now()
	_, err := s.gw.Request(context.Background(), "sessions.list", conn.RequestOptions{Timeout: 200 * time.Millisecond})
	if err == nil {
		t.Fatal("nil error for timed-out request")
	}
	var te *conn.TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("err = %T (%v), want TimeoutError", err, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("TimeoutError does not unwrap to DeadlineExceeded: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("timeout took %v", elapsed)
	}
	// The timed-out stream was cancelled (reset) on the server.
	// The server only reads the reset after its delayed handler
	// returns, so allow past the 1s delay.
	deadline := time.Now().Add(4 * time.Second)
	for s.server.ResetCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.server.ResetCount() == 0 {
		t.Error("no reset after request timeout")
	}
}

func TestE2EDropThenConnectionDown(t *testing.T) {
	s := startE2E(t, jsonOKHandler(`{}`))
	// Drop the connection from the server side.
	_ = s.server.Close()
	// Wait for the reader to notice.
	deadline := time.Now().Add(3 * time.Second)
	for s.gw.Alive() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.gw.Alive() {
		t.Fatal("gateway still alive after server close")
	}
	if s.gw.Dead() == nil {
		t.Fatal("Dead() nil after drop")
	}
	_, err := s.gw.Request(context.Background(), "sessions.list", conn.RequestOptions{})
	var down *conn.ConnectionDown
	if !errors.As(err, &down) {
		t.Fatalf("after drop Request err = %T (%v), want ConnectionDown", err, err)
	}
	_, err = s.gw.OpenStream(context.Background(), "sessions.list", conn.OpenStreamOptions{})
	if !errors.As(err, &down) {
		t.Fatalf("after drop OpenStream err = %T (%v), want ConnectionDown", err, err)
	}
	_ = s.gw.Close()
}

func TestE2ECloseUnblocksBlockedRequest(t *testing.T) {
	s := startE2E(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		return gatewaytest.Response{
			Delay:  2 * time.Second,
			Frames: []*pb.ServiceFrame{gatewaytest.ResponseFrame(0, 200, []byte(`{}`), true)},
		}
	}))
	defer s.server.Close()
	done := make(chan error, 1)
	go func() {
		_, err := s.gw.Request(context.Background(), "sessions.list", conn.RequestOptions{Timeout: 30 * time.Second})
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	_ = s.gw.Close()
	select {
	case err := <-done:
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("Close took %v to unblock request", elapsed)
		}
		var ce *conn.ConnectionError
		if !errors.As(err, &ce) {
			t.Fatalf("blocked request err = %T (%v), want ConnectionError", err, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked request not unblocked by Close")
	}
	// Close is idempotent.
	if err := s.gw.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestE2EOpenStreamTrackFalseDropsFrames(t *testing.T) {
	s := startE2E(t, jsonOKHandler(`{"ok":true}`))
	defer s.cleanup()
	sid, err := s.gw.OpenStream(context.Background(), "sessions.list", conn.OpenStreamOptions{Track: false})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if sid != 1 {
		t.Errorf("sid = %d", sid)
	}
	time.Sleep(300 * time.Millisecond)
	if !s.gw.Alive() {
		t.Fatal("gateway died after untracked frames")
	}
	// CancelStream on an untracked stream is a no-op success.
	if err := s.gw.CancelStream(context.Background(), sid); err != nil {
		t.Errorf("CancelStream: %v", err)
	}
}

func TestE2EConcurrentCalls(t *testing.T) {
	s := startE2E(t, jsonOKHandler(`{"ok":true,"result":1}`))
	defer s.cleanup()
	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = s.gw.CallJSON(context.Background(), "sessions.list", conn.RequestOptions{})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("call %d: %v", i, err)
		}
	}
	reqs := s.server.Requests()
	if len(reqs) != n {
		t.Fatalf("requests = %d, want %d", len(reqs), n)
	}
	seen := map[int64]bool{}
	for _, r := range reqs {
		if seen[r.StreamID] {
			t.Errorf("duplicate stream id %d", r.StreamID)
		}
		seen[r.StreamID] = true
	}
}

func TestE2ELease(t *testing.T) {
	s := startE2E(t, jsonOKHandler(`{"ok":true}`))
	defer s.server.Close()
	lease := s.gw.(conn.Leaser).Lease()
	if err := lease.Close(); err != nil {
		t.Errorf("lease Close: %v", err)
	}
	if !s.gw.Alive() {
		t.Fatal("gateway died after lease Close")
	}
	if _, err := lease.CallJSON(context.Background(), "sessions.list", conn.RequestOptions{}); err != nil {
		t.Fatalf("lease CallJSON: %v", err)
	}
	if err := s.gw.Close(); err != nil {
		t.Errorf("real Close: %v", err)
	}
	if s.gw.Alive() {
		t.Error("gateway alive after real Close")
	}
}

func TestE2EStreamIDsIncrement(t *testing.T) {
	s := startE2E(t, jsonOKHandler(`{}`))
	defer s.cleanup()
	ctx := context.Background()
	for want := int64(1); want <= 3; want++ {
		sid, err := s.gw.OpenStream(ctx, "sessions.list", conn.OpenStreamOptions{Track: true})
		if err != nil {
			t.Fatalf("OpenStream: %v", err)
		}
		if sid != want {
			t.Errorf("sid = %d, want %d", sid, want)
		}
		_ = s.gw.CancelStream(ctx, sid)
	}
}

// TestE2ECancelStreamUsesStoredService (B1): the CANCELLED reset
// must ride the service stored at open() for the stream, not the
// hardcoded daemon service — and an unknown stream id defaults to
// daemon.
func TestE2ECancelStreamUsesStoredService(t *testing.T) {
	s := startE2E(t, jsonOKHandler(`{}`))
	defer s.cleanup()
	ctx := context.Background()
	cases := []struct {
		method string
		want   pb.ServiceType
	}{
		{"egress.approvals", pb.ServiceType_SERVICE_SENTINEL},
		{"custom_connectors.list", pb.ServiceType_SERVICE_AUTHD},
		{"vault.luks_status", pb.ServiceType_SERVICE_VAULT},
	}
	for _, tc := range cases {
		sid, err := s.gw.OpenStream(ctx, tc.method, conn.OpenStreamOptions{Track: true})
		if err != nil {
			t.Fatalf("OpenStream(%s): %v", tc.method, err)
		}
		if err := s.gw.CancelStream(ctx, sid); err != nil {
			t.Fatalf("CancelStream(%s): %v", tc.method, err)
		}
	}
	// Unknown stream id: no stored service, daemon default.
	if err := s.gw.CancelStream(ctx, 9999); err != nil {
		t.Fatalf("CancelStream(unknown): %v", err)
	}
	want := []pb.ServiceType{
		pb.ServiceType_SERVICE_SENTINEL,
		pb.ServiceType_SERVICE_AUTHD,
		pb.ServiceType_SERVICE_VAULT,
		pb.ServiceType_SERVICE_DAEMON,
	}
	pollUntil(t, 5*time.Second, "server resets on stored services", func() bool {
		return len(s.server.ResetServices()) >= len(want)
	})
	got := s.server.ResetServices()
	if len(got) != len(want) {
		t.Fatalf("reset services = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("reset %d service = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestE2EHandshakeTimeout(t *testing.T) {
	// A listener that accepts TCP but never completes a WebSocket
	// upgrade must fail the dial fast (gorilla handshake error),
	// not hang: the connector must not wait out the 20s handshake
	// bound for a server that answers HTTP 404.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
				time.Sleep(100 * time.Millisecond)
			}(c)
		}
	}()
	dialer := &addrDialer{addr: ln.Addr().String()}
	cookiesFile := filepath.Join(t.TempDir(), "cookies.txt")
	_ = os.WriteFile(cookiesFile, []byte(fakeCookie), 0o600)
	start := time.Now()
	_, err = NewConnector(dialer, WithWebSocketSecure(false), WithWSURL(func(vmID, token string) string {
		return "ws://127.0.0.1/v1/noise?vm_id=" + vmID + "&auth_token=" + token
	}))(context.Background(), conn.Config{CookiesFile: cookiesFile, VMID: "vm-x"})
	if err == nil {
		t.Fatal("nil error dialing non-WS server")
	}
	var ce *conn.ConnectionError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %T (%v), want ConnectionError", err, err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("failed handshake took %v", elapsed)
	}
}

// addrDialer is a test OutboundDialer that dials one fixed address
// for WebSocket and serves canned auth over HTTP.
type addrDialer struct {
	addr string
}

func (d *addrDialer) WebSocketDial(ctx context.Context, network, host string, port uint16, secure bool, _ option.OutboundTLSOptions) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", d.addr)
}

func (d *addrDialer) HTTPClient() *http.Client {
	auth := &gatewaytest.CannedAuth{VMID: "vm-x", AccessToken: "AT", HatchToken: "HT"}
	return &http.Client{Transport: gatewaytest.HandlerRoundTripper(auth)}
}

// withTestReassembler is a test-only ConnectorOption that sets the
// frame reassembler (and its caps) for gateways built by the
// connector. Production connectors always use the defaults.
func withTestReassembler(r *reassembler) ConnectorOption {
	return func(c *connectorConfig) { c.reassembler = r }
}

// TestE2EReassemblyCapFailsStreamNotGateway: a frame over the
// reassembly cap fails the affected Request with a typed
// *ReassemblySizeError and NO partial payload, the gateway
// stays alive (Dead()==nil), the failed group's reassembly
// state is released, and a second request on the same gateway
// completes with its own state released too. Small test caps
// (64 bytes) stand in for the 64 MiB production cap so the
// behaviour is exercisable without megabytes of wire traffic;
// the cap is above one ordinary response frame (~36 bytes of
// reassembled ServiceResponse/ServiceFrame for the ping reply
// below) and below the oversized frame (~80 bytes);
// the cap values themselves are pinned in TestReassemblerFeed.
func TestE2EReassemblyCapFailsStreamNotGateway(t *testing.T) {
	var n atomic.Int64
	server, err := gatewaytest.NewServer(gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		if n.Add(1) == 1 {
			// One chunk frame whose reassembled payload
			// (65 data bytes plus framing) exceeds the
			// 64-byte test cap in a single transport piece.
			return gatewaytest.Response{Frames: []*pb.ServiceFrame{
				gatewaytest.ChunkFrame(0, []byte(strings.Repeat("x", 65)), false),
			}}
		}
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, []byte(`{"ok":true,"result":{}}`), true),
		}}
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT-FAKE", HatchToken: "HT-FAKE"}
	dialer := gatewaytest.NewFakeDialer(server, auth)
	cookiesFile := filepath.Join(t.TempDir(), "cookies.txt")
	if err := os.WriteFile(cookiesFile, []byte(fakeCookie), 0o600); err != nil {
		t.Fatalf("write cookies: %v", err)
	}
	connector := NewConnector(dialer, WithWebSocketSecure(false), withTestReassembler(newReassemblerWithLimits(64, 4)))
	gw, err := connector(context.Background(), conn.Config{CookiesFile: cookiesFile, VMID: "vm-test"})
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	defer gw.Close()
	ctx := context.Background()
	heldState := func() (groups, bytesHeld int) {
		r := concreteGateway(t, gw).partial
		groups = len(r.groups)
		for _, g := range r.groups {
			bytesHeld += g.size
		}
		return groups, bytesHeld
	}
	payload, err := gw.Request(ctx, "connection.ping", conn.RequestOptions{Body: map[string]any{"presence": "away"}, Timeout: 5 * time.Second})
	if err == nil {
		t.Fatal("oversized request: nil error, want *ReassemblySizeError")
	}
	if len(payload) != 0 {
		t.Errorf("oversized request returned %d payload bytes, want no partial delivery", len(payload))
	}
	var sizeErr *ReassemblySizeError
	if !errors.As(err, &sizeErr) {
		t.Fatalf("oversized request error = %T (%v), want *ReassemblySizeError", err, err)
	}
	var groupsErr *TooManyUnfinishedGroupsError
	if errors.As(err, &groupsErr) {
		t.Errorf("size-cap error also matches *TooManyUnfinishedGroupsError")
	}
	if !gw.Alive() || gw.Dead() != nil {
		t.Errorf("gateway alive=%v dead=%v after cap failure: want alive with nil Dead (no gateway-wide death)", gw.Alive(), gw.Dead())
	}
	// The failed stream's reassembly state is released.
	if groups, bytesHeld := heldState(); groups != 0 || bytesHeld != 0 {
		t.Errorf("held state after cap failure = (%d groups, %d bytes), want (0, 0)", groups, bytesHeld)
	}
	// The same gateway serves the next request normally.
	if _, err := gw.CallJSON(ctx, "connection.ping", conn.RequestOptions{Body: map[string]any{"presence": "away"}}); err != nil {
		t.Fatalf("request after cap failure: %v", err)
	}
	// Completion also releases its state: no leak.
	if groups, bytesHeld := heldState(); groups != 0 || bytesHeld != 0 {
		t.Errorf("held state after completion = (%d groups, %d bytes), want (0, 0)", groups, bytesHeld)
	}
}

// TestE2ESubscribeReassemblyCapDeliversNoRecords: a subscription
// whose first frame exceeds the reassembly cap fails typed with
// no record delivered — neither through the returned slice nor
// through OnRecord (no partial delivery) — and the gateway
// stays alive for the next call.
func TestE2ESubscribeReassemblyCapDeliversNoRecords(t *testing.T) {
	server, err := gatewaytest.NewServer(gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		// One chunk frame carrying a would-be record line,
		// oversized as a single reassembled frame.
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ChunkFrame(0, []byte(strings.Repeat("x", 65)+"\n"), false),
		}}
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT-FAKE", HatchToken: "HT-FAKE"}
	dialer := gatewaytest.NewFakeDialer(server, auth)
	cookiesFile := filepath.Join(t.TempDir(), "cookies.txt")
	if err := os.WriteFile(cookiesFile, []byte(fakeCookie), 0o600); err != nil {
		t.Fatalf("write cookies: %v", err)
	}
	connector := NewConnector(dialer, WithWebSocketSecure(false), withTestReassembler(newReassemblerWithLimits(64, 4)))
	gw, err := connector(context.Background(), conn.Config{CookiesFile: cookiesFile, VMID: "vm-test"})
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	defer gw.Close()
	var onRecordCalls int
	records, err := gw.SubscribeRaw(context.Background(), "chat.subscribe", conn.SubscribeOptions{
		IdleTimeout: 2 * time.Second, OverallTimeout: 5 * time.Second,
		OnRecord: func(rec []byte) bool {
			onRecordCalls++
			return false
		},
	})
	if err == nil {
		t.Fatal("oversized subscribe: nil error, want *ReassemblySizeError")
	}
	if len(records) != 0 {
		t.Errorf("oversized subscribe returned %d records, want none (no partial delivery)", len(records))
	}
	if onRecordCalls != 0 {
		t.Errorf("OnRecord called %d times, want 0 (no partial delivery)", onRecordCalls)
	}
	var sizeErr *ReassemblySizeError
	if !errors.As(err, &sizeErr) {
		t.Fatalf("oversized subscribe error = %T (%v), want *ReassemblySizeError", err, err)
	}
	if !gw.Alive() || gw.Dead() != nil {
		t.Errorf("gateway alive=%v dead=%v after cap failure: want alive with nil Dead", gw.Alive(), gw.Dead())
	}
}
