// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeCDPServer is a SYNTHETIC Chromium-shaped CDP endpoint: the
// /json/version and Storage/Network.getCookies payload shapes
// follow the real Chromium wire format (cdproto structs decode
// them), but every value is invented test data and the server
// is the test's own code. Nothing here is a capture from a real
// browser; real-Chromium scoping is the P1 box-side gate.
type fakeCDPServer struct {
	t            *testing.T
	storageFails bool
	mu           sync.Mutex
	methods      []string
	messages     []cdpMessage
	server       *httptest.Server
}

type cdpMessage struct {
	ID        json.RawMessage `json:"id"`
	SessionID string          `json:"sessionId,omitempty"`
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params"`
}

func newFakeCDPServer(t *testing.T, storageFails bool) *fakeCDPServer {
	t.Helper()
	f := &fakeCDPServer{t: t, storageFails: storageFails}
	mux := http.NewServeMux()
	mux.HandleFunc("/json/version", func(w http.ResponseWriter, r *http.Request) {
		wsURL := "ws://" + r.Host + "/devtools/browser/FAKE-BROWSER-ID"
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Browser":"Chrome/140.0.0.0","Protocol-Version":"1.3","User-Agent":"Mozilla/5.0 (SYNTHETIC)","V8-Version":"14.0.0","WebKit-Version":"537.36","webSocketDebuggerUrl":` + quoteJSON(wsURL) + `}`))
	})
	mux.HandleFunc("/json/list", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"FAKE-TARGET-ID","type":"page","url":"https://muse.ai/","title":"SYNTHETIC","webSocketDebuggerUrl":"ws://` + r.Host + `/devtools/page/FAKE-TARGET-ID"}]`))
	})
	mux.HandleFunc("/devtools/browser/FAKE-BROWSER-ID", func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			var msg cdpMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			f.mu.Lock()
			f.methods = append(f.methods, msg.Method)
			f.messages = append(f.messages, msg)
			f.mu.Unlock()
			resp := map[string]any{"id": json.RawMessage(msg.ID), "result": map[string]any{}}
			if msg.SessionID != "" {
				resp["sessionId"] = msg.SessionID
			}
			switch msg.Method {
			case "Target.attachToTarget":
				resp["result"] = map[string]any{"sessionId": "FAKE-SESSION-1"}
			case "Page.getFrameTree":
				// chromedp dereferences FrameTree.Frame during
				// target init: an empty result panics it.
				resp["result"] = map[string]any{"frameTree": map[string]any{"frame": map[string]any{"id": "FAKE-FRAME-ID", "url": "https://muse.ai/", "mimeType": "text/html"}}}
			case "DOM.getDocument":
				resp["result"] = map[string]any{"root": map[string]any{"nodeId": 1, "parentId": 0, "nodeType": 9, "nodeName": "#document"}}
			case "Browser.getVersion":
				resp["result"] = map[string]any{"protocolVersion": "1.3", "product": "Chrome/140.0.0.0", "userAgent": "Mozilla/5.0 (SYNTHETIC)", "revision": "FAKE", "jsVersion": "14.0.0"}
			case "Runtime.evaluate":
				resp["result"] = map[string]any{"result": map[string]any{"type": "object"}}
			case "Storage.getCookies":
				if f.storageFails {
					resp = map[string]any{"id": json.RawMessage(msg.ID), "error": map[string]any{"code": -32601, "message": "Storage.getCookies wasn't found"}}
					if msg.SessionID != "" {
						resp["sessionId"] = msg.SessionID
					}
					break
				}
				resp["result"] = map[string]any{"cookies": syntheticCookies()}
			case "Network.getCookies":
				resp["result"] = map[string]any{"cookies": syntheticCookies()}
			}
			if err := conn.WriteJSON(resp); err != nil {
				return
			}
		}
	})
	f.server = httptest.NewServer(mux)
	return f
}

// syntheticCookies returns Chromium-shaped network.Cookie JSON
// with FAKE values. expires is a float64 epoch; the session
// cookie uses -1, matching Chromium's encoding.
func syntheticCookies() []map[string]any {
	return []map[string]any{
		{"name": "hatch_sess", "value": "FAKE-EXPORTED-SESS", "domain": ".muse.ai", "path": "/", "expires": float64(1796040000), "size": 20, "httpOnly": true, "secure": true, "session": false, "sameSite": "Lax", "priority": "Medium", "sourceScheme": "Secure", "sourcePort": 443},
		{"name": "hatch_gw", "value": "FAKE-EXPORTED-GW", "domain": ".muse.ai", "path": "/", "expires": float64(1820000000), "size": 18, "httpOnly": true, "secure": true, "session": false, "sameSite": "Lax", "priority": "Medium", "sourceScheme": "Secure", "sourcePort": 443},
		{"name": "sess", "value": "FAKE-SESSION", "domain": "muse.ai", "path": "/", "expires": float64(-1), "size": 12, "httpOnly": false, "secure": true, "session": true, "sameSite": "Lax", "priority": "Medium", "sourceScheme": "Secure", "sourcePort": 443},
	}
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (f *fakeCDPServer) methodsSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]string, len(f.methods))
	copy(cp, f.methods)
	return cp
}

// messagesSeen returns every CDP message the server received,
// in order, with params. Wire tests assert on these.
func (f *fakeCDPServer) messagesSeen() []cdpMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]cdpMessage, len(f.messages))
	copy(cp, f.messages)
	return cp
}

func TestCDPExportPrimaryPath(t *testing.T) {
	f := newFakeCDPServer(t, false)
	defer f.server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exp := NewCDPExporter(f.server.URL)
	cookies, err := exp.Export(ctx)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(cookies) != 3 {
		t.Fatalf("cookies = %+v; want 3 synthetic cookies", cookies)
	}
	if cookies[0].Name != "hatch_sess" || cookies[0].Value != "FAKE-EXPORTED-SESS" || cookies[0].Domain != ".muse.ai" || cookies[0].Expires != 1796040000 {
		t.Fatalf("cookie 0 = %+v", cookies[0])
	}
	// Session cookie: -1 expiry + session flag -> merge form
	// expiry 0 via FromExportedCookie.
	sc := FromExportedCookie(cookies[2])
	if sc.Expires != 0 || sc.Name != "sess" {
		t.Fatalf("session conversion = %+v", sc)
	}
	seen := f.methodsSeen()
	found := false
	for _, m := range seen {
		if m == "Storage.getCookies" {
			found = true
		}
		if m == "Network.getCookies" {
			t.Fatalf("fallback Network.getCookies called on the primary path: %v", seen)
		}
	}
	if !found {
		t.Fatalf("Storage.getCookies never called: %v", seen)
	}
	// The export path sends no Runtime calls at all: the
	// browser-level read is the allowlist-honouring path.
	// (The ATTACH path's bootstrap does enable Runtime; that
	// is asserted separately in screencast_wire_test.go.)
	for _, m := range seen {
		if strings.HasPrefix(m, "Runtime.") {
			t.Fatalf("export path sent %q: %v", m, seen)
		}
	}
}

func TestCDPExportFallbackPath(t *testing.T) {
	f := newFakeCDPServer(t, true)
	defer f.server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exp := NewCDPExporter(f.server.URL)
	cookies, err := exp.Export(ctx)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(cookies) != 3 {
		t.Fatalf("cookies = %+v; want 3 via fallback", cookies)
	}
	seen := f.methodsSeen()
	hasStorage, hasNetwork := false, false
	for _, m := range seen {
		if m == "Storage.getCookies" {
			hasStorage = true
		}
		if m == "Network.getCookies" {
			hasNetwork = true
		}
	}
	if !hasStorage || !hasNetwork {
		t.Fatalf("methods = %v; want Storage attempt then Network fallback", seen)
	}
}

func TestDiscoverWebSocketURLMalformed(t *testing.T) {
	cases := []struct {
		name string
		body string
		code int
	}{
		{"empty object", `{}`, 200},
		{"html", `<html><body>not json</body></html>`, 200},
		{"wrong type", `{"webSocketDebuggerUrl": 42}`, 200},
		{"missing field", `{"Browser": "Chrome/140.0.0.0"}`, 200},
		{"server error", `{"webSocketDebuggerUrl": "ws://127.0.0.1:9/x"}`, 500},
		{"remote ws url", `{"webSocketDebuggerUrl": "ws://192.0.2.1:9222/devtools/browser/x"}`, 200},
		{"non-ws scheme", `{"webSocketDebuggerUrl": "http://127.0.0.1:9222/"}`, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// No panic on any malformed payload: a typed error.
			if _, err := DiscoverWebSocketURL(ctx, srv.URL); err == nil {
				t.Fatalf("DiscoverWebSocketURL(%q) succeeded; want error", tc.body)
			}
		})
	}
	// Non-loopback browser URLs are rejected before any dial.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := DiscoverWebSocketURL(ctx, "http://192.0.2.1:9222/"); err == nil {
		t.Fatal("non-loopback browser URL accepted")
	}
	if _, err := DiscoverWebSocketURL(ctx, "ws://192.0.2.1:9222/devtools/browser/x"); err == nil {
		t.Fatal("non-loopback ws URL accepted")
	}
	// ws:// loopback passes through untouched.
	ws, err := DiscoverWebSocketURL(ctx, "ws://127.0.0.1:9226/devtools/browser/FAKE")
	if err != nil || ws != "ws://127.0.0.1:9226/devtools/browser/FAKE" {
		t.Fatalf("ws passthrough = %q, %v", ws, err)
	}
	// Unreachable loopback endpoint: error, not a hang (5s cap).
	if _, err := DiscoverWebSocketURL(ctx, "http://127.0.0.1:1/"); err == nil {
		t.Fatal("unreachable endpoint accepted")
	}
	// The discovery never logs or returns cookie values: the
	// error for a bad version payload must not contain one.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"webSocketDebuggerUrl": ""}`))
	}))
	defer srv.Close()
	_, err = DiscoverWebSocketURL(ctx, srv.URL)
	if err == nil || strings.Contains(err.Error(), "FAKE") {
		t.Fatalf("discovery error = %v", err)
	}
}
