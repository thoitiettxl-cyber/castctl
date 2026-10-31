// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// transientFakeCDP is a minimal CDP endpoint for the
// re-check-transient test: /json/version for discovery plus a
// WebSocket endpoint answering Storage.getCookies with one
// valid hatch_sess cookie. SYNTHETIC (invented values); it
// proves what the tick sends and receives, not what a real
// browser does (P1/CDP-skew gates stay box-side).
type transientFakeCDP struct {
	t      *testing.T
	server *httptest.Server
	seen   []string
	mu     sync.Mutex
}

func newTransientFakeCDP(t *testing.T) *transientFakeCDP {
	t.Helper()
	f := &transientFakeCDP{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/json/version", func(w http.ResponseWriter, r *http.Request) {
		wsURL := "ws://" + r.Host + "/devtools/browser/FAKE"
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"Browser":"Fake/1.0","Protocol-Version":"1.3","User-Agent":"Fake","V8-Version":"1","WebKit-Version":"1","webSocketDebuggerUrl":%q}`, wsURL)
	})
	mux.HandleFunc("/devtools/browser/FAKE", func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			var msg map[string]json.RawMessage
			if err := c.ReadJSON(&msg); err != nil {
				return
			}
			var method string
			_ = json.Unmarshal(msg["method"], &method)
			var id int64
			_ = json.Unmarshal(msg["id"], &id)
			f.mu.Lock()
			f.seen = append(f.seen, method)
			f.mu.Unlock()
			resp := map[string]any{"id": id}
			if method == "Storage.getCookies" {
				resp["result"] = map[string]any{"cookies": []any{
					map[string]any{
						"name": "hatch_sess", "value": "FAKE-EXPORTED", "domain": ".muse.ai",
						"path": "/", "expires": float64(time.Now().Add(30 * 24 * time.Hour).Unix()),
						"secure": true, "httpOnly": true, "session": false,
					},
				}}
			} else {
				resp["result"] = map[string]any{}
			}
			if err := c.WriteJSON(resp); err != nil {
				return
			}
		}
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *transientFakeCDP) saw(method string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.seen {
		if m == method {
			return true
		}
	}
	return false
}

// TestKeeperCheckContinuesPastRecheckTransient (micro-loop,
// red-team R2-3): a fast commands-level regression test for
// the transient-continuation path. The loop-2 PR body claimed
// no such test could exist because the path needs
// minute-scale backoff sleeps; that is false for the
// RE-CHECK transient path. k1's tick: the first cheap-chain
// check returns AuthError (session 401, which breaks the
// phase-2 loop with no sleep), the export re-check returns a
// GatewayError (session 200 with a non-object body, no
// vm_id), and the tick records the transient outcome
// immediately — the backoff ladder runs only for transient
// errors on the FIRST check, and the re-check is a single
// call. k2 stays healthy. Both entries must print their JSON
// and the exit code must be the transient's (3, GatewayError
// via classifyError). The 60s bound is decisive: the first
// ladder delay alone is 5m, so any ladder sleep fails it.
//
// Boundary, stated honestly: the FIRST-check transient
// ladder path still has no fast test — the commands factory
// hardcodes keeper.RealClock, so a fake-clock seam there is
// a follow-up, not part of this test.
func TestKeeperCheckContinuesPastRecheckTransient(t *testing.T) {
	cdp1 := newTransientFakeCDP(t)
	cdp2 := newTransientFakeCDP(t)
	// Two fake CDP servers on distinct ports: the
	// duplicate-browser guard rejects one shared URL.
	config := `{"default_profile":"default","profiles":{"default":{},"muse01":{}},` +
		`"keeper":[{"tag":"k1","profile":"default","browser":"` + cdp1.server.URL + `","interval":"1h"},` +
		`{"tag":"k2","profile":"muse01","browser":"` + cdp2.server.URL + `","interval":"1h"}]}`
	fake := &keeperFakeGateway{
		authStatus: 200,
		sessionScript: []keeperFakeSessionStep{
			{status: 401},             // k1 first check: AuthError.
			{status: 200, body: `[]`}, // k1 re-check: GatewayError.
			// k2 healthy (clamped last step for later calls).
			{status: 200, cookies: []string{"hatch_sess=FAKE-RENEWED; Max-Age=2592000; Path=/; Secure; HttpOnly"}},
		},
	}
	env, out, errb, _ := keeperTestEnv(t, config, fake)
	start := time.Now()
	code := Run(context.Background(), []string{"keeper", "check"}, env)
	elapsed := time.Since(start)
	if elapsed > 60*time.Second {
		t.Fatalf("check took %v; want fast (no backoff sleeps)", elapsed)
	}
	if code != 3 {
		t.Fatalf("check code=%d, want 3 (transient); stdout=%q stderr=%q", code, out.String(), errb.String())
	}
	if n := strings.Count(out.String(), `"tag":`); n != 2 {
		t.Fatalf("check printed %d JSON objects; want 2 (k1 transient + k2 healthy): %q", n, out.String())
	}
	if !strings.Contains(out.String(), `"tag": "k1"`) || !strings.Contains(out.String(), `"tag": "k2"`) {
		t.Fatalf("check output = %q; want both entry tags", out.String())
	}
	if !cdp1.saw("Storage.getCookies") {
		t.Fatalf("first entry's CDP server saw no Storage.getCookies: export did not run")
	}
}
