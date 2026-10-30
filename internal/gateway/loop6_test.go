// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

// Loop-6 RED tests: distinctive markers driven through every
// fixed rendering must FAIL on the loop-5 behaviour. Each test
// asserts the summary fields that must be present (positive
// control) as well as marker absence, and asserts a non-empty
// rendering where absence is claimed.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

const loop6Marker = "LOOP6MARKER7f3a91"

func loop6Body() string {
	return "plain body words " + loop6Marker + " more words"
}

func assertNoLoop6Marker(t *testing.T, what, got string) {
	t.Helper()
	if got == "" {
		t.Fatalf("%s is empty: positive control failed", what)
	}
	if strings.Contains(got, loop6Marker) {
		t.Errorf("%s %q carries the loop-6 marker", what, got)
	}
}

// --- (1) close-frame leak -------------------------------------------

func TestLoop6CloseFrameSummary(t *testing.T) {
	reason := "plain close words " + loop6Marker
	s := startE2E(t, jsonOKHandler(`{}`))
	defer s.cleanup()
	cgw := concreteGateway(t, s.gw)
	s.server.SendClose(websocket.CloseNormalClosure, reason)
	pollUntil(t, 5*time.Second, "gateway death after close frame", func() bool {
		return cgw.Dead() != nil || !cgw.Alive()
	})
	dead := cgw.Dead()
	if dead == nil {
		t.Fatal("Dead() is nil after a close frame: positive control failed")
	}
	assertNoLoop6Marker(t, "Dead().Error()", dead.Error())
	if !strings.Contains(dead.Error(), "close_code=1000") {
		t.Errorf("Dead().Error() = %q, want close_code=1000", dead.Error())
	}
	if !strings.Contains(dead.Error(), fmt.Sprintf("reason_length=%d", len(reason))) {
		t.Errorf("Dead().Error() = %q, want reason_length=%d", dead.Error(), len(reason))
	}
	sum := logging.SummarizeErr(dead)
	assertNoLoop6Marker(t, "SummarizeErr(Dead())", sum)
	if !strings.Contains(sum, "close_code=1000") || !strings.Contains(sum, fmt.Sprintf("reason_length=%d", len(reason))) {
		t.Errorf("SummarizeErr(Dead()) = %q, want code + reason length", sum)
	}
	// Classification is preserved: the CloseError stays
	// reachable through the summary wrapper.
	var ce *websocket.CloseError
	if !errors.As(dead, &ce) || ce.Code != websocket.CloseNormalClosure {
		t.Errorf("errors.As(Dead(), CloseError) = %v, want the 1000 close error in the chain", ce)
	}
	var connErr *conn.ConnectionError
	if !errors.As(dead, &connErr) {
		t.Errorf("Dead() type: %T (%v), want *conn.ConnectionError in the chain", dead, dead)
	}
}

func TestLoop6CloseFrameLossRendering(t *testing.T) {
	// Loss path: the server drops the TCP connection without a
	// close frame, so the reader synthesises the loss (a 1006
	// CloseError carries no text in gorilla — a 1006 frame
	// with a reason is rejected by the library itself, so no
	// marker text can arrive that way; the stored-reason path
	// below pins the latent state for real frames instead).
	s := startE2E(t, jsonOKHandler(`{}`))
	defer s.cleanup()
	cgw := concreteGateway(t, s.gw)
	_ = s.server.Close()
	pollUntil(t, 5*time.Second, "gateway death after TCP drop", func() bool {
		return cgw.Dead() != nil || !cgw.Alive()
	})
	dead := cgw.Dead()
	if dead == nil {
		t.Fatal("Dead() is nil after a TCP drop: positive control failed")
	}
	if _, ok := AsConnectionLost(dead); !ok {
		t.Fatalf("Dead() = %T (%v), want *ErrConnectionLost", dead, dead)
	}
	if dead.Error() == "" || logging.SummarizeErr(dead) == "" {
		t.Fatal("loss renderings are empty: positive control failed")
	}
	if !strings.Contains(dead.Error(), "connection lost") {
		t.Errorf("Dead().Error() = %q, want the loss class", dead.Error())
	}
	// The stored reason is the redacted prose (latent state):
	// classifyConnectionLost returns it, and
	// ErrConnectionLost.Error() must never render it.
	reason := "plain close words " + loop6Marker
	code, stored, ok := classifyConnectionLost(&conn.ConnectionError{Err: &websocket.CloseError{Code: websocket.CloseAbnormalClosure, Text: reason}})
	if !ok || code != websocket.CloseAbnormalClosure || !strings.Contains(stored, loop6Marker) {
		t.Errorf("classifyConnectionLost = (%d, %q, %v), want the documented latent stored form", code, stored, ok)
	}
	lost := &ErrConnectionLost{CloseCode: code, CloseReason: stored, CloseSeen: true, Cause: errors.New("gateway: websocket closed (close_code=1006 reason_length=" + fmt.Sprint(len(reason)) + ")")}
	assertNoLoop6Marker(t, "ErrConnectionLost.Error() with stored reason", lost.Error())
}

// --- (2) transport-error fallback: real-stack drive ------------------

// rawResponseServer serves one canned raw response per connection
// over plain TCP, read through the REAL net/http Transport
// (Proxy disabled so no sandbox proxy intervenes; the HTTP
// parsing stack under test is stdlib's).
func rawResponseServer(t *testing.T, raw string) (*http.Client, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil || line == "\r\n" || line == "\n" {
						break
					}
				}
				_, _ = io.WriteString(c, raw)
			}(c)
		}
	}()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	return client, "http://" + ln.Addr().String() + "/api/session"
}

func TestLoop6TransportMalformedHeaderDrive(t *testing.T) {
	// Drive setup: a fake server emitting a malformed header
	// line whose text IS the marker, read through doHatch with
	// the real http.Transport. Observed output (loop-5 code):
	// the error must be recorded here when this test runs red.
	raw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nBadHeaderLine " + loop6Marker + "\r\nContent-Length: 2\r\n\r\n{}"
	client, rawURL := rawResponseServer(t, raw)
	_, _, _, err := doHatch(context.Background(), client, http.MethodGet, rawURL, hatchHeaders(fakeCookie, ""), nil)
	if err == nil {
		t.Fatal("doHatch with a malformed header line: nil error, want a transport error")
	}
	assertNoLoop6Marker(t, "doHatch error", err.Error())
	sum := logging.SummarizeErr(err)
	assertNoLoop6Marker(t, "SummarizeErr(transport error)", sum)
	// Typed summary: operation, error class, net-error kind —
	// present in every rendering, no peer text.
	for _, field := range []string{"class=", "kind="} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("doHatch error = %q, want the typed-summary field %q", err.Error(), field)
		}
		if !strings.Contains(sum, field) {
			t.Errorf("SummarizeErr = %q, want the typed-summary field %q", sum, field)
		}
	}
	// The original chain stays reachable for classification.
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		t.Errorf("errors.As(err, *url.Error) = false, want the transport chain preserved")
	}
}

func TestLoop6TransportMalformedStatusLineDrive(t *testing.T) {
	raw := "GARBAGESTATUS " + loop6Marker + "\r\n\r\n"
	client, rawURL := rawResponseServer(t, raw)
	_, _, _, err := doHatch(context.Background(), client, http.MethodGet, rawURL, hatchHeaders(fakeCookie, ""), nil)
	if err == nil {
		t.Fatal("doHatch with a malformed status line: nil error, want a transport error")
	}
	assertNoLoop6Marker(t, "doHatch error", err.Error())
	assertNoLoop6Marker(t, "SummarizeErr(transport error)", logging.SummarizeErr(err))
	if !strings.Contains(err.Error(), "class=") || !strings.Contains(err.Error(), "kind=") {
		t.Errorf("doHatch error = %q, want class=/kind= typed summary", err.Error())
	}
}

func TestLoop6TransportDialRefusedSummary(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	_, _, _, err = doHatch(context.Background(), client, http.MethodGet, "http://"+addr+"/api/session", hatchHeaders(fakeCookie, ""), nil)
	if err == nil {
		t.Fatal("doHatch to a closed port: nil error, want a transport error")
	}
	if !strings.Contains(err.Error(), "class=") || !strings.Contains(err.Error(), "kind=") {
		t.Errorf("doHatch error = %q, want class=/kind= typed summary", err.Error())
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Errorf("errors.As(err, *net.OpError) = false, want the dial chain preserved")
	}
}

// --- (3) redeem ------------------------------------------------------

func TestLoop6RedeemJSONFailureGated(t *testing.T) {
	body := `{"success":false,"reason":"free text ` + loop6Marker + ` here","detail":"free text ` + loop6Marker + ` detail","extraKey":"` + loop6Marker + `","redemptionStatus":"x"}`
	_, b, err := RedeemInviteCode(context.Background(), straddleBodyClient(400, body), fakeCookie, "ABCDEF")
	if err != nil {
		t.Fatalf("RedeemInviteCode: %v", err)
	}
	m, ok := b.(map[string]any)
	if !ok {
		t.Fatalf("body = %#v, want a map", b)
	}
	assertNoLoop6Marker(t, "redeem failure body", fmt.Sprintf("%v", m))
	if m["reason"] != "[omitted]" {
		t.Errorf("reason = %#v, want [omitted] for a free-text value", m["reason"])
	}
	if m["detail"] != "[omitted]" {
		t.Errorf("detail = %#v, want [omitted] for a free-text value", m["detail"])
	}
	if _, present := m["extraKey"]; present {
		t.Errorf("body carries extraKey: only allowlisted keys may survive on the error path: %v", m)
	}
	if m["success"] != false {
		t.Errorf("success = %#v, want false", m["success"])
	}
	// Enum-shaped values survive; numeric/composite values do not.
	body2 := `{"success":false,"reason":"denied","detail":123,"extra":true}`
	_, b2, err := RedeemInviteCode(context.Background(), straddleBodyClient(200, body2), fakeCookie, "ABCDEF")
	if err != nil {
		t.Fatalf("RedeemInviteCode: %v", err)
	}
	m2 := b2.(map[string]any)
	if m2["reason"] != "denied" {
		t.Errorf("reason = %#v, want the enum value emitted", m2["reason"])
	}
	if m2["detail"] != "[omitted]" {
		t.Errorf("detail = %#v, want [omitted] for a numeric value", m2["detail"])
	}
	if _, present := m2["extra"]; present {
		t.Errorf("body carries extra: only allowlisted keys may survive: %v", m2)
	}
	// Success data is NOT gated: extra keys and values pass through.
	body3 := `{"success":true,"redemptionStatus":"redeemed","extraKey":"kept-value"}`
	_, b3, err := RedeemInviteCode(context.Background(), straddleBodyClient(200, body3), fakeCookie, "ABCDEF")
	if err != nil {
		t.Fatalf("RedeemInviteCode: %v", err)
	}
	m3 := b3.(map[string]any)
	if m3["extraKey"] != "kept-value" || m3["redemptionStatus"] != "redeemed" {
		t.Errorf("success body = %v, want data passthrough unchanged", m3)
	}
}

// --- (4) MediaPath ----------------------------------------------------

func TestLoop6MediaPathSummary(t *testing.T) {
	refs := []any{
		"sandbox://../" + loop6Marker,
		"https://example.com/%zz" + loop6Marker,
		map[string]any{"path": "a/../" + loop6Marker},
		map[string]any{"variants": map[string]any{"original": "../" + loop6Marker}},
		"",
	}
	for _, ref := range refs {
		_, err := MediaPath(ref)
		if err == nil {
			t.Fatalf("MediaPath(%v): nil error, want a ValidationError", ref)
		}
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("MediaPath(%v): err = %T, want *ValidationError", ref, err)
		}
		assertNoLoop6Marker(t, "MediaPath error", err.Error())
		if !strings.Contains(err.Error(), "bad sandbox path") {
			t.Errorf("MediaPath error = %q, want the kind label", err.Error())
		}
		if !strings.Contains(err.Error(), "ref_length=") {
			t.Errorf("MediaPath error = %q, want ref_length", err.Error())
		}
	}
	// Through Gateway.DownloadFile: the MediaPath error surfaces
	// before any network use, marker-free.
	s := startE2E(t, jsonOKHandler(`{}`))
	defer s.cleanup()
	_, err := s.gw.DownloadFile(context.Background(), "sandbox://../"+loop6Marker, conn.DownloadOptions{})
	if err == nil {
		t.Fatal("DownloadFile(marker ref): nil error")
	}
	assertNoLoop6Marker(t, "DownloadFile error", err.Error())
	if !strings.Contains(err.Error(), "ref_length=") {
		t.Errorf("DownloadFile error = %q, want ref_length", err.Error())
	}
}

// --- (6b) subscription wire length ------------------------------------

func TestLoop6SubscriptionBodyLength(t *testing.T) {
	rsc := "1:{\"success\":false,\"error\":\"denied\",\"note\":\"" + loop6Marker + "\"}\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x-component")
		_, _ = io.WriteString(w, rsc)
	}))
	defer srv.Close()
	_, _, err := FetchSubscription(context.Background(), srv.Client(), fakeCookie, SubscriptionOptions{Page: srv.URL})
	var ge *conn.GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("err = %T (%v), want *conn.GatewayError", err, err)
	}
	assertNoLoop6Marker(t, "GatewayError.Payload", ge.Payload)
	if ge.BodyLength != len(rsc) {
		t.Errorf("BodyLength = %d, want the wire RSC length %d (never the summary-text length %d)", ge.BodyLength, len(rsc), len(ge.Payload))
	}
	if !strings.Contains(ge.Error(), fmt.Sprintf("body_length=%d", len(rsc))) {
		t.Errorf("GatewayError.Error() = %q, want body_length=%d", ge.Error(), len(rsc))
	}

	// Loop 7 (T1): the same wire-length contract on the
	// non-200 / non-x-component branch. Every POST answers
	// 500 with a fixed plain-text body; the scan finds an id
	// whose call also answers 500, so the failure summary is
	// built from the 500 wire length. The Payload text, the
	// rendered error, and the wire length must all agree.
	body500 := "server exploded " + loop6Marker
	mux := http.NewServeMux()
	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<script src="/_next/static/chunks/abc.js"></script>`))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(500)
		_, _ = w.Write([]byte(body500))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`createServerReference)("abcdef1234567890abcdef",{},"fetchSubscriptionAction")`))
	})
	_, _, err = FetchSubscription(context.Background(), muxClient(mux), fakeCookie, SubscriptionOptions{Page: "https://muse.ai/settings"})
	var ge500 *conn.GatewayError
	if !errors.As(err, &ge500) {
		t.Fatalf("500 branch: err = %T (%v), want *conn.GatewayError", err, err)
	}
	assertNoLoop6Marker(t, "500 GatewayError.Payload", ge500.Payload)
	if ge500.BodyLength != len(body500) {
		t.Errorf("500 branch: BodyLength = %d, want the wire length %d (never 0, never the summary-text length %d)", ge500.BodyLength, len(body500), len(ge500.Payload))
	}
	if !strings.Contains(ge500.Payload, fmt.Sprintf("body_length=%d", len(body500))) {
		t.Errorf("500 branch: Payload = %q, want body_length=%d", ge500.Payload, len(body500))
	}
	if !strings.Contains(ge500.Error(), fmt.Sprintf("body_length=%d", len(body500))) {
		t.Errorf("500 branch: GatewayError.Error() = %q, want body_length=%d", ge500.Error(), len(body500))
	}
}

func TestLoop6VMUnavailableGuidance(t *testing.T) {
	for _, body := range []string{
		`{"status":"unavailable"}`,
		`{"vm_id":null}`,
	} {
		_, err := FetchSessionInfo(context.Background(), straddleBodyClient(200, body), fakeCookie)
		var ge *conn.GatewayError
		if !errors.As(err, &ge) {
			t.Fatalf("body %s: err = %T (%v), want *conn.GatewayError", body, err, err)
		}
		if !strings.Contains(ge.Payload, "VM unavailable") {
			t.Errorf("Payload = %q, want the VM unavailable class label", ge.Payload)
		}
		if !strings.Contains(ge.Payload, "castctl wake") || !strings.Contains(ge.Payload, "MUSE_VM_ID=") {
			t.Errorf("Payload = %q, want the constant wake guidance restored", ge.Payload)
		}
	}
}

// --- (6f) stored close/ping text: renderings only ----------------------

func TestLoop6StoredPingNeverRendered(t *testing.T) {
	// A marker ping payload is stored raw (LastPing is a
	// test-only surface; no production code reads it) and must
	// reach no error rendering: the gateway stays alive and
	// Dead stays nil, and a later close renders summary-only.
	s := startE2E(t, jsonOKHandler(`{}`))
	defer s.cleanup()
	cgw := concreteGateway(t, s.gw)
	s.server.PingAll("ping-payload " + loop6Marker)
	pollUntil(t, 5*time.Second, "server pong", func() bool { return s.server.PongCount() >= 1 })
	at, data := cgw.LastPing()
	if at.IsZero() || data != "ping-payload "+loop6Marker {
		t.Errorf("LastPing() = (%v, %q), want the stored ping payload (documented latent state)", at, data)
	}
	if dead := cgw.Dead(); dead != nil {
		t.Errorf("Dead() = %v after a ping, want nil", dead)
	}
}
