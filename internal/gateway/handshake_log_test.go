// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

// Gateway handshake-event tests: dialWebSocket must emit ONE
// debug line carrying ONLY the parsed status (a numeric status
// code, or a validated status token) — never the raw status line,
// never the URL (which carries vm_id + auth_token), never header
// values, never the full gorilla error. Shapes that carry no
// parseable status emit NOTHING.
//
// What each test observes: bytes in a buffer writer behind a
// trace-level factory, after dialWebSocket against a scripted
// loopback server (same harness as ws_handshake_test.go).
// What the red run catches: the event missing entirely, the raw
// status line / URL / reason phrase leaking into the capture, or
// an event emitted for a shape with no parseable status.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	singlog "github.com/sagernet/sing-box/log"

	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

const (
	hsLogVMID   = "LOGFIX-VMID-22d9f0"
	hsLogToken  = "LOGFIX-HT-2c6e88"
	hsLogCookie = "LOGFIX-SESS-9d2e41"
)

func hsFixtureURL(srv *scriptServer, secure bool) string {
	scheme := "ws"
	if secure {
		scheme = "wss"
	}
	return scheme + "://" + srv.addr() + "/v1/noise?vm_id=" + hsLogVMID + "&auth_token=" + hsLogToken
}

func hsCapture(t *testing.T, level string) (*bytes.Buffer, singlog.ContextLogger) {
	t.Helper()
	buf := &bytes.Buffer{}
	handle, err := logging.NewFactory(context.Background(), logging.Settings{Level: level, Output: "stderr"}, buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	return buf, handle.Logger("gateway")
}

func hsScanFixtures(t *testing.T, capture string) {
	t.Helper()
	for _, v := range []string{hsLogVMID, hsLogToken, hsLogCookie, "/v1/noise", "Bad Gateway", "Sec-WebSocket", "HTTP/1.1"} {
		if strings.Contains(capture, v) {
			t.Errorf("capture contains forbidden %q:\n%s", v, capture)
		}
	}
}

// TestHandshakeStatusToken is the pure-extractor table: the
// extractor is the ONLY place a status token is derived, and it
// must fail closed on anything that is not a numeric code or a
// short token-shaped fragment. Only a 3-DIGIT code is ever
// emitted as a token (loop 7, item R4): a token-shaped,
// non-numeric, or over-long token renders as its LENGTH only,
// never its bytes.
func TestHandshakeStatusToken(t *testing.T) {
	cases := []struct {
		name  string
		resp  *http.Response
		err   error
		token string
		kind  string
		ok    bool
	}{
		{name: "101", resp: &http.Response{StatusCode: 101}, token: "101", kind: "status_code", ok: true},
		{name: "502", resp: &http.Response{StatusCode: 502}, token: "502", kind: "status_code", ok: true},
		{name: "resp-wins-over-err", resp: &http.Response{StatusCode: 502}, err: errors.New(`malformed HTTP status code "error"`), token: "502", kind: "status_code", ok: true},
		{name: "malformed-3digit", err: errors.New(`malformed HTTP status code "502"`), token: "502", kind: "status_token", ok: true},
		{name: "malformed-error", err: errors.New(`malformed HTTP status code "error"`), token: "5", kind: "status_token_length", ok: true},
		{name: "malformed-abc", err: errors.New(`malformed HTTP status code "abc"`), token: "3", kind: "status_token_length", ok: true},
		{name: "malformed-2digit", err: errors.New(`malformed HTTP status code "42"`), token: "2", kind: "status_token_length", ok: true},
		{name: "malformed-4digit", err: errors.New(`malformed HTTP status code "1234"`), token: "4", kind: "status_token_length", ok: true},
		{name: "malformed-alnum", err: errors.New(`malformed HTTP status code "12a"`), token: "3", kind: "status_token_length", ok: true},
		{name: "malformed-too-long", err: errors.New(`malformed HTTP status code "` + strings.Repeat("x", 33) + `"`), token: "33", kind: "status_token_length", ok: true},
		{name: "wrapped-malformed", err: errors.New(`read: malformed HTTP status code "error": boom`), token: "5", kind: "status_token_length", ok: true},
		{name: "malformed-response-shape", err: errors.New(`malformed HTTP response "error"`), ok: false},
		{name: "bad-handshake", err: errors.New("websocket: bad handshake"), ok: false},
		{name: "eof", err: errors.New("unexpected EOF"), ok: false},
		{name: "token-with-space", err: errors.New(`malformed HTTP status code "a b"`), ok: false},
		{name: "token-with-slash", err: errors.New(`malformed HTTP status code "a/b"`), ok: false},
		{name: "nil-nil", ok: false},
		{name: "empty-token", err: errors.New(`malformed HTTP status code ""`), ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, kind, ok := handshakeStatusToken(tc.resp, tc.err)
			if ok != tc.ok || token != tc.token || kind != tc.kind {
				t.Errorf("handshakeStatusToken = (%q,%q,%v), want (%q,%q,%v)", token, kind, ok, tc.token, tc.kind, tc.ok)
			}
		})
	}
}

// TestDialWebSocketHandshakeEvent drives every script shape and
// pins the exact event line (or its absence) plus the fixture
// scan on the whole capture.
func TestDialWebSocketHandshakeEvent(t *testing.T) {
	cases := []struct {
		name      string
		kind      scriptKind
		wsTimeout time.Duration
		wantLine  string // "" = no event line at all
	}{
		{name: "101", kind: script101, wsTimeout: 2 * time.Second, wantLine: "event=ws_handshake status_code=101"},
		{name: "well-formed-502", kind: scriptWellFormed502, wsTimeout: 2 * time.Second, wantLine: "event=ws_handshake status_code=502"},
		{name: "plaintext-error", kind: scriptPlaintextError, wsTimeout: 2 * time.Second, wantLine: "event=ws_handshake status_token_length=5"},
		{name: "bad-code", kind: scriptBadCode, wsTimeout: 2 * time.Second, wantLine: "event=ws_handshake status_token_length=3"},
		{name: "no-space", kind: scriptNoSpace, wsTimeout: 2 * time.Second, wantLine: ""},
		{name: "immediate-close", kind: scriptImmediateClose, wsTimeout: 2 * time.Second, wantLine: ""},
		{name: "silent", kind: scriptSilent, wsTimeout: 200 * time.Millisecond, wantLine: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startScriptServer(t, false, nil, tc.kind)
			dialer := &scriptDialer{addr: srv.addr()}
			buf, logger := hsCapture(t, "trace")
			ws, _, _, err := dialWebSocket(t.Context(), dialer, hsFixtureURL(srv, false), false, tc.wsTimeout, logger)
			if ws != nil {
				_ = ws.Close()
			}
			_ = err // errors are expected on failure shapes; the event is the assertion
			srv.waitDone(t)
			got := buf.String()
			if tc.wantLine != "" {
				if !strings.Contains(got, tc.wantLine) {
					t.Errorf("capture %q, want event line %q", got, tc.wantLine)
				}
				if n := strings.Count(got, "event=ws_handshake"); n != 1 {
					t.Errorf("capture %q: %d ws_handshake lines, want exactly 1", got, n)
				}
			} else if strings.Contains(got, "event=ws_handshake") {
				t.Errorf("capture %q, want NO ws_handshake event for this shape", got)
			}
			hsScanFixtures(t, got)
		})
	}
}

// TestDialWebSocketHandshakeEventSuppressedAtWarn: the single
// level gate applies at the gateway seam too.
func TestDialWebSocketHandshakeEventSuppressedAtWarn(t *testing.T) {
	srv := startScriptServer(t, false, nil, scriptWellFormed502)
	dialer := &scriptDialer{addr: srv.addr()}
	buf, logger := hsCapture(t, "warn")
	ws, _, _, _ := dialWebSocket(t.Context(), dialer, hsFixtureURL(srv, false), false, 2*time.Second, logger)
	if ws != nil {
		_ = ws.Close()
	}
	srv.waitDone(t)
	if strings.Contains(buf.String(), "event=ws_handshake") {
		t.Errorf("warn-level capture %q, want the debug event suppressed", buf.String())
	}
}
