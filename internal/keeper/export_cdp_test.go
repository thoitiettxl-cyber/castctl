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
	t                    *testing.T
	storageFails         bool
	storageEmpty         bool
	networkEmpty         bool
	targetNetworkEmpty   bool
	targetNetworkPartial bool
	networkFails         bool
	targetNetworkFails   bool
	browserNetworkFails  bool
	targetStorageFails   bool
	unscopedTabCookie    bool
	noTargets            bool
	blankTarget          bool
	mu                   sync.Mutex
	methods              []string
	messages             []cdpMessage
	server               *httptest.Server
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
		if f.noTargets {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if f.blankTarget {
			_, _ = w.Write([]byte(`[{"id":"FAKE-TARGET-ID","type":"page","url":"about:blank","title":"SYNTHETIC","webSocketDebuggerUrl":"ws://` + r.Host + `/devtools/page/FAKE-TARGET-ID"}]`))
			return
		}
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
				// Per-level error injection: storageFails
				// errors on every session; targetStorageFails
				// only on a target session (a read harvest
				// never issues, so it must not poison the
				// browser-level read). The message is
				// distinct from both Network messages so a
				// joined error's components stay
				// distinguishable. Defaults off.
				if f.storageFails || (f.targetStorageFails && msg.SessionID != "") {
					resp = map[string]any{"id": json.RawMessage(msg.ID), "error": map[string]any{"code": -32601, "message": "storage synthetic failure: Storage.getCookies unavailable"}}
					if msg.SessionID != "" {
						resp["sessionId"] = msg.SessionID
					}
					break
				}
				// Chrome-155 shape: the BROWSER-level read
				// (no session) succeeds empty while the
				// browser holds cookies. A target-session
				// read still returns the synthetic set.
				if f.storageEmpty && msg.SessionID == "" {
					resp["result"] = map[string]any{"cookies": []map[string]any{}}
					break
				}
				resp["result"] = map[string]any{"cookies": syntheticCookies()}
			case "Network.getCookies":
				// Params-aware error injection + scoping
				// shape: the handler inspects the urls list,
				// because the harvest's second target read
				// is unscoped (no urls) while the first is
				// scoped to ExportURLs. Error injection is
				// gated by session: networkFails errors on
				// every session (legacy, kept for the
				// target-error fall-through case);
				// targetNetworkFails only on a target
				// session and browserNetworkFails only on
				// the browser session, each with a message
				// distinct from the other levels so a
				// joined error's components stay
				// distinguishable. Defaults off; no
				// existing export test sets the new flags.
				var getCookiesParams struct {
					URLs []string `json:"urls"`
				}
				if len(msg.Params) > 0 {
					_ = json.Unmarshal(msg.Params, &getCookiesParams)
				}
				scoped := len(getCookiesParams.URLs) > 0
				isTarget := msg.SessionID != ""
				failMessage := ""
				switch {
				case f.networkFails && isTarget, f.targetNetworkFails && isTarget:
					failMessage = "target synthetic failure: Network.getCookies unavailable"
				case f.networkFails && !isTarget, f.browserNetworkFails && !isTarget:
					failMessage = "browser synthetic failure: Network.getCookies unavailable"
				}
				if failMessage != "" {
					resp = map[string]any{"id": json.RawMessage(msg.ID), "error": map[string]any{"code": -32601, "message": failMessage}}
					if isTarget {
						resp["sessionId"] = msg.SessionID
					}
					break
				}
				// Unscoped target read (the harvest's
				// second target read, L1b): it sees only
				// the tab's own host, so when
				// unscopedTabCookie is on it returns a
				// DIFFERENT synthetic set — a host-only
				// tab-host cookie whose value and domain
				// prove L1b served it — and empty when
				// off. The scoped flags below do not apply
				// to it. Defaults off; no export call sends
				// an unscoped target read.
				if isTarget && !scoped {
					if f.unscopedTabCookie {
						resp["result"] = map[string]any{"cookies": syntheticTabCookies()}
					} else {
						resp["result"] = map[string]any{"cookies": []map[string]any{}}
					}
					break
				}
				// Partial-target injection: the scoped
				// target-session read returns a non-empty
				// set WITHOUT hatch_sess (2 of the 3
				// synthetic cookies) while the
				// browser-level reads still return the
				// full set. Defaults off.
				if f.targetNetworkPartial && isTarget {
					resp["result"] = map[string]any{"cookies": syntheticCookies()[1:]}
					break
				}
				// A target-session read that yields nothing
				// (logged-out tab) while the browser-level
				// read still sees cookies.
				if f.networkEmpty || (f.targetNetworkEmpty && isTarget) {
					resp["result"] = map[string]any{"cookies": []map[string]any{}}
					break
				}
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

// syntheticTabCookies returns the unscoped-read synthetic set: a
// host-only hatch_sess on the tab's own host (www.muse.ai, no
// leading dot), which the scoped ExportURLs read cannot see.
// Its hatch_sess value and domain differ from syntheticCookies
// so a test can tell which read served the harvest.
func syntheticTabCookies() []map[string]any {
	return []map[string]any{
		{"name": "hatch_sess", "value": "FAKE-TABHOST-SESS", "domain": "www.muse.ai", "path": "/", "expires": float64(1796040000), "size": 18, "httpOnly": true, "secure": true, "session": false, "sameSite": "Lax", "priority": "Medium", "sourceScheme": "Secure", "sourcePort": 443},
		{"name": "hatch_gw", "value": "FAKE-TABHOST-GW", "domain": "www.muse.ai", "path": "/", "expires": float64(1820000000), "size": 16, "httpOnly": true, "secure": true, "session": false, "sameSite": "Lax", "priority": "Medium", "sourceScheme": "Secure", "sourcePort": 443},
		{"name": "sess", "value": "FAKE-TABHOST-SESSION", "domain": "www.muse.ai", "path": "/", "expires": float64(-1), "size": 19, "httpOnly": false, "secure": true, "session": true, "sameSite": "Lax", "priority": "Medium", "sourceScheme": "Secure", "sourcePort": 443},
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

// assertExportWire checks the CDP wire discipline for the
// export path: no navigation, no input, no target
// creation/activation/closure, and any Runtime.evaluate is
// exactly chromedp's constant "self" from the target-attach
// bootstrap (never castctl's own script).
func assertExportWire(t *testing.T, f *fakeCDPServer) {
	t.Helper()
	forbidden := map[string]bool{
		"Page.navigate": true, "Page.stopLoading": true,
		"Input.dispatchMouseEvent": true, "Input.dispatchKeyEvent": true,
		"Input.insertText": true, "Input.dispatchTouchEvent": true,
		"Target.createTarget": true, "Target.closeTarget": true,
		"Target.activateTarget": true,
	}
	for _, msg := range f.messagesSeen() {
		if forbidden[msg.Method] {
			t.Fatalf("export path sent forbidden %q", msg.Method)
		}
		if msg.Method == "Runtime.evaluate" {
			var params struct {
				Expression string `json:"expression"`
			}
			if err := json.Unmarshal(msg.Params, &params); err != nil {
				t.Fatalf("Runtime.evaluate params undecodable: %v", err)
			}
			if params.Expression != "self" {
				t.Fatalf("Runtime.evaluate expression = %q; want the bootstrap constant \"self\"", params.Expression)
			}
		}
	}
}

// TestCDPExportTargetLevelPrimary pins the K-LIVE-2 fix: the
// browser-level Storage read succeeds EMPTY (the Chrome 155
// headless shape) while the browser holds a live session, and
// the export still returns the full set via the target-level
// read. No browser-level Storage call may happen at all on
// this path: the target read succeeds first.
func TestCDPExportTargetLevelPrimary(t *testing.T) {
	f := newFakeCDPServer(t, false)
	f.storageEmpty = true
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
	attached, targetNetwork, browserStorage := false, false, false
	for _, msg := range f.messagesSeen() {
		switch msg.Method {
		case "Target.attachToTarget":
			attached = true
		case "Network.getCookies":
			if msg.SessionID != "" {
				targetNetwork = true
			}
		case "Storage.getCookies":
			if msg.SessionID == "" {
				browserStorage = true
			}
		}
	}
	if !attached || !targetNetwork {
		t.Fatalf("methods = %v; want target attach + target-level Network.getCookies", f.methodsSeen())
	}
	if browserStorage {
		t.Fatalf("browser-level Storage.getCookies called despite a successful target read: %v", f.methodsSeen())
	}
	assertExportWire(t, f)
}

// TestCDPExportTargetEmptyFallsThrough pins the target-level
// empty guard: a Muse tab that yields no cookies (logged-out
// tab) falls through to the browser-level Storage read, which
// still sees the session.
func TestCDPExportTargetEmptyFallsThrough(t *testing.T) {
	f := newFakeCDPServer(t, false)
	f.targetNetworkEmpty = true
	defer f.server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exp := NewCDPExporter(f.server.URL)
	cookies, err := exp.Export(ctx)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(cookies) != 3 {
		t.Fatalf("cookies = %+v; want 3 via browser-level Storage", cookies)
	}
	seen := f.methodsSeen()
	hasTargetNetwork, hasStorage := false, false
	for _, msg := range f.messagesSeen() {
		if msg.Method == "Network.getCookies" && msg.SessionID != "" {
			hasTargetNetwork = true
		}
		if msg.Method == "Storage.getCookies" && msg.SessionID == "" {
			hasStorage = true
		}
	}
	if !hasTargetNetwork || !hasStorage {
		t.Fatalf("methods = %v; want target Network attempt then browser Storage", seen)
	}
	assertExportWire(t, f)
}

// TestCDPExportBrowserFallback pins the browser-level chain
// when no Muse page is open: Storage fails, Network with
// explicit URLs returns the set. No target attach happens:
// there is no page to attach to.
func TestCDPExportBrowserFallback(t *testing.T) {
	f := newFakeCDPServer(t, true)
	f.noTargets = true
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
	hasStorage, hasNetwork, attached := false, false, false
	for _, m := range seen {
		if m == "Storage.getCookies" {
			hasStorage = true
		}
		if m == "Network.getCookies" {
			hasNetwork = true
		}
		if m == "Target.attachToTarget" {
			attached = true
		}
	}
	if !hasStorage || !hasNetwork {
		t.Fatalf("methods = %v; want Storage attempt then Network fallback", seen)
	}
	if attached {
		t.Fatalf("target attach with no Muse page open: %v", seen)
	}
	// The browser-level path sends no Runtime calls at all.
	for _, m := range seen {
		if strings.HasPrefix(m, "Runtime.") {
			t.Fatalf("browser-level path sent %q: %v", m, seen)
		}
	}
}

// TestCDPExportEmptyStorageFallsThrough pins the browser-level
// empty guard: Storage succeeds EMPTY (Chrome 155 shape) and
// the export still returns the set via Network instead of
// short-circuiting to an empty result.
func TestCDPExportEmptyStorageFallsThrough(t *testing.T) {
	f := newFakeCDPServer(t, false)
	f.noTargets = true
	f.storageEmpty = true
	defer f.server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exp := NewCDPExporter(f.server.URL)
	cookies, err := exp.Export(ctx)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(cookies) != 3 {
		t.Fatalf("cookies = %+v; want 3 via Network after empty Storage", cookies)
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

// TestCDPExportAllLevelsEmpty pins P1: when every read level
// yields empty with success, Export returns an empty result
// with a nil error and the tick's validation gate decides
// (the entry stops). An empty read is not an export error.
func TestCDPExportAllLevelsEmpty(t *testing.T) {
	f := newFakeCDPServer(t, false)
	f.noTargets = true
	f.storageEmpty = true
	f.networkEmpty = true
	defer f.server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exp := NewCDPExporter(f.server.URL)
	cookies, err := exp.Export(ctx)
	if err != nil {
		t.Fatalf("Export: %v; want nil error for an all-empty read", err)
	}
	if len(cookies) != 0 {
		t.Fatalf("cookies = %+v; want empty", cookies)
	}
}

// TestCDPExportBlankPageTarget pins the any-page fallback:
// with only an about:blank tab open and the browser-level
// Storage read succeeding empty, the export still returns
// the set via the target-level read with explicit URLs.
func TestCDPExportBlankPageTarget(t *testing.T) {
	f := newFakeCDPServer(t, false)
	f.storageEmpty = true
	f.blankTarget = true
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
	attached, targetNetwork, browserStorage := false, false, false
	for _, msg := range f.messagesSeen() {
		switch msg.Method {
		case "Target.attachToTarget":
			attached = true
		case "Network.getCookies":
			if msg.SessionID != "" {
				targetNetwork = true
			}
		case "Storage.getCookies":
			if msg.SessionID == "" {
				browserStorage = true
			}
		}
	}
	if !attached || !targetNetwork {
		t.Fatalf("methods = %v; want target attach + target-level Network.getCookies", f.methodsSeen())
	}
	if browserStorage {
		t.Fatalf("browser-level Storage.getCookies called despite a successful target read: %v", f.methodsSeen())
	}
	assertExportWire(t, f)
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
