// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/thoitiettxl-cyber/castctl/internal/keeper"
)

// The screencast relay test drives a session through a real
// WebSocket with a fake starter (no browser, no CDP): the
// starter sends one frame and one phase, then waits for the
// Done input the test client sends, and reports saved. It
// proves the relay wiring — session minting, single-use token,
// frame/phase forwarding, input allowlisting, terminal report
// — not the browser itself (live gate, box-side only).

func TestScreencastRelayEndToEnd(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, func(d *Deps) {
		d.ScreencastAvailable = func(ctx context.Context, profileName string) (bool, string, error) {
			return true, "", nil
		}
		d.ScreencastStarter = func(ctx context.Context, profileName, sessionID string, transport keeper.Transport) (keeper.LoginResult, error) {
			if profileName != "muse01" {
				t.Errorf("starter profile = %q", profileName)
			}
			if err := transport.SendFrame(ctx, keeper.Frame{Data: []byte{0xff, 0xd8, 0xff}, SessionID: 7, Width: 100, Height: 50}); err != nil {
				t.Errorf("SendFrame: %v", err)
			}
			if err := transport.SendPhase(ctx, keeper.PhaseReady, ""); err != nil {
				t.Errorf("SendPhase: %v", err)
			}
			// Wait for Done (or transport death / timeout).
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				select {
				case ev := <-transport.Inputs():
					if ev.Kind == keeper.InputDone {
						return keeper.LoginResult{Outcome: keeper.LoginSaved, CookiesSaved: true, SavedNames: []string{"hatch_sess"}}, nil
					}
				case <-transport.Done():
					return keeper.LoginResult{Outcome: keeper.LoginCancelled}, nil
				case <-ctx.Done():
					return keeper.LoginResult{Outcome: keeper.LoginTimeout}, nil
				}
			}
			return keeper.LoginResult{Outcome: keeper.LoginTimeout}, nil
		}
	})
	server := httptest.NewServer(ts.handler)
	defer server.Close()

	// Mint a session (Bearer).
	req, _ := http.NewRequest("POST", server.URL+"/api/v1/screencast/muse01/start", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var startEnv map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&startEnv); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	start := startEnv["data"].(map[string]any)
	wsURL, _ := start["ws_url"].(string)
	if wsURL == "" {
		t.Fatalf("start response = %v", startEnv)
	}
	wsEndpoint := "ws" + strings.TrimPrefix(server.URL, "http") + wsURL

	// A second mint while no session is live is fine (the
	// first token is unconsumed, not live); consuming the
	// first token twice must fail.
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	conn, _, err := dialer.Dial(wsEndpoint, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Replaying the same token must 401 (single-use).
	_, resp2, err := dialer.Dial(wsEndpoint, nil)
	if err == nil {
		_ = resp2.Body.Close()
		t.Fatal("second dial with the same token succeeded, want rejection")
	}
	if resp2 != nil && resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second dial status = %d, want 401", resp2.StatusCode)
	}

	// Read frame + phase in either order: SendPhase writes
	// directly while frames go through the pump goroutine,
	// so arrival order is not guaranteed.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var frame, phase map[string]any
	for i := 0; i < 2; i++ {
		var msg map[string]any
		if err := conn.ReadJSON(&msg); err != nil {
			t.Fatalf("read message %d: %v", i, err)
		}
		switch msg["type"] {
		case "frame":
			frame = msg
		case "phase":
			phase = msg
		default:
			t.Fatalf("unexpected message: %v", msg)
		}
	}
	if frame == nil || frame["width"] != float64(100) {
		t.Fatalf("frame = %v", frame)
	}
	data, _ := frame["data"].(string)
	if data != "/9j/" { // base64 of ff d8 ff
		t.Fatalf("frame data = %q", data)
	}
	if phase == nil || phase["phase"] != "ready" {
		t.Fatalf("phase = %v", phase)
	}
	// Invalid kind: dropped, session continues.
	if err := conn.WriteJSON(map[string]any{"kind": "teleport"}); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteJSON(map[string]any{"kind": "mouse", "mouse_type": "mouseMoved", "button": "none", "x": 10, "y": 20}); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteJSON(map[string]any{"kind": "done"}); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := conn.ReadJSON(&result); err != nil {
		t.Fatalf("read result: %v", err)
	}
	if result["type"] != "result" || result["outcome"] != "saved" || result["cookies_saved"] != true {
		t.Fatalf("result = %v", result)
	}
}

func TestSessionRegistrySingleUseAndExpiry(t *testing.T) {
	r := newSessionRegistry()
	token, err := r.mint("muse01")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.consume(token); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if _, err := r.consume(token); err == nil {
		t.Fatal("second consume succeeded, want rejection")
	}
	// Busy: a live session blocks a second mint for the
	// profile until released.
	if _, err := r.mint("muse01"); err == nil {
		t.Fatal("mint while live succeeded, want screencast_busy")
	}
	r.release("muse01")
	if _, err := r.mint("muse01"); err != nil {
		t.Fatalf("mint after release: %v", err)
	}
}

func TestValidateWSInput(t *testing.T) {
	if _, ok := validateWSInput(wsInputMessage{Kind: "mouse", MouseType: "mousePressed", Button: "left", ClickCount: 1}); !ok {
		t.Fatal("valid mouse rejected")
	}
	if _, ok := validateWSInput(wsInputMessage{Kind: "mouse", MouseType: "mouseTeleport"}); ok {
		t.Fatal("invalid mouse type accepted")
	}
	if _, ok := validateWSInput(wsInputMessage{Kind: "key", KeyType: "keyDown", Key: "a"}); !ok {
		t.Fatal("valid key rejected")
	}
	if _, ok := validateWSInput(wsInputMessage{Kind: "key", KeyType: "eval", Key: "x"}); ok {
		t.Fatal("invalid key type accepted")
	}
	if _, ok := validateWSInput(wsInputMessage{Kind: "text", Text: strings.Repeat("x", 1025)}); ok {
		t.Fatal("oversize text accepted")
	}
	if _, ok := validateWSInput(wsInputMessage{Kind: "done"}); !ok {
		t.Fatal("done rejected")
	}
	if _, ok := validateWSInput(wsInputMessage{Kind: "bogus"}); ok {
		t.Fatal("bogus kind accepted")
	}
}
