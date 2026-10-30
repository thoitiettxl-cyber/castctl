// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

// Producer-redaction tests: peer/server free text must be
// redacted where it is produced (CloseReason, server payloads),
// with the STRICTER free-text boundary — every query value of a
// URL, JSON secret values, bare key=value fragments — not
// redact.String, under which a vm_id query value survives
// (pinned by TestRedactErrorString). Fixture values actually
// enter each producer under test; captures assert absence plus
// a marker. Loop 5: server-payload producers no longer redact
// at all — they emit the allowlist summary instead (see
// TestServerPayloadRedactedAtProducer and the allowlist
// tests); only the stored CloseReason still uses
// redactFreeText, and it has no output path. The reader-panic
// producer (gateway.go) likewise emits class + length only;
// it is not driven here — a panic in the reader loop cannot
// be triggered hermetically without a corrupt frame stream —
// and is recorded as unexercised, as in the loop-2 report.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway/gatewaytest"
	pb "github.com/thoitiettxl-cyber/castctl/internal/proto"
)

const (
	producerVMID  = "LOGFIX-VMID-22d9f0"
	producerToken = "LOGFIX-HT-2c6e88"
	producerPW    = "LOGFIX-PW-31c7aa"
)

func producerFixtureURL() string {
	return "wss://gateway.example.invalid/v1/noise?vm_id=" + producerVMID + "&auth_token=" + producerToken + "&unknown_key=" + producerPW
}

func assertProducerRedacted(t *testing.T, got string) {
	t.Helper()
	if got == "" {
		t.Fatal("redacted output empty: positive control failed")
	}
	for _, v := range []string{producerVMID, producerToken, producerPW} {
		if strings.Contains(got, v) {
			t.Errorf("output contains fixture value %q: %q", v, got)
		}
	}
	if !strings.Contains(got, "[redacted]") {
		t.Errorf("output %q, want a [redacted] marker (positive control)", got)
	}
}

// TestRedactFreeTextIsStricter: the free-text boundary strips
// the vm_id value, the unknown query key's value, and a JSON
// password fragment — all of which redact.String leaves (in
// whole or part). The same input through redactErrorString
// keeps the vm_id value, pinning the contrast.
func TestRedactFreeTextIsStricter(t *testing.T) {
	t.Parallel()
	in := "peer said " + producerFixtureURL() + ` and {"password": "` + producerPW + `"}`
	got := redactFreeText(in)
	assertProducerRedacted(t, got)
	if !strings.Contains(got, "gateway.example.invalid") {
		t.Errorf("free-text redaction over-redacted the host: %q", got)
	}
	loose := redactErrorString(producerFixtureURL())
	if !strings.Contains(loose, producerVMID) {
		t.Errorf("redactErrorString(%q) = %q, want the vm_id value to survive it (contrast pin)", producerFixtureURL(), loose)
	}
}

// TestClassifyConnectionLostCloseReasonRedacted: a peer close
// frame (1006) carrying a fixture URL as its reason must come
// out of classifyConnectionLost with no fixture value in the
// recorded reason. Benign reason text survives.
func TestClassifyConnectionLostCloseReasonRedacted(t *testing.T) {
	t.Parallel()
	ce := &websocket.CloseError{Code: websocket.CloseAbnormalClosure, Text: "dropped: " + producerFixtureURL()}
	code, reason, ok := classifyConnectionLost(ce)
	if !ok || code != websocket.CloseAbnormalClosure {
		t.Fatalf("classifyConnectionLost = (%d, %q, %v), want (1006, redacted, true)", code, reason, ok)
	}
	assertProducerRedacted(t, reason)

	_, benign, ok := classifyConnectionLost(&websocket.CloseError{Code: websocket.CloseAbnormalClosure, Text: "bye"})
	if !ok || benign != "bye" {
		t.Errorf("benign close reason = %q, want it preserved byte-identical", benign)
	}
}

// TestServerPayloadRedactedAtProducer: a 500 server payload
// carrying fixture values, driven through the real E2E gateway
// (the calls.go GatewayError construction), must carry no
// fixture value in any rendering, while the allowlist fields
// (status, wire body length) are present. Loop 5 supersedes
// the old host-survival expectation: no body bytes survive
// at all, redacted or otherwise.
func TestServerPayloadRedactedAtProducer(t *testing.T) {
	payload := []byte(`see ` + producerFixtureURL() + ` and {"password": "` + producerPW + `"}`)
	s := startE2E(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 500, payload, true),
		}}
	}))
	defer s.cleanup()
	_, err := s.gw.Request(context.Background(), "connection.ping", conn.RequestOptions{Body: map[string]any{"presence": "away"}})
	if err == nil {
		t.Fatal("Request with 500: nil error")
	}
	var gwErr *conn.GatewayError
	if !errors.As(err, &gwErr) {
		t.Fatalf("error type: %T, want *conn.GatewayError", err)
	}
	for _, v := range []string{producerVMID, producerToken, producerPW, "gateway.example.invalid"} {
		if strings.Contains(gwErr.Payload, v) || strings.Contains(gwErr.Error(), v) || strings.Contains(gwErr.LogSummary(), v) {
			t.Errorf("error rendering carries fixture/host value %q: payload=%q error=%q", v, gwErr.Payload, gwErr.Error())
		}
	}
	if gwErr.Status != 500 || gwErr.BodyLength != len(payload) {
		t.Errorf("GatewayError status=%d BodyLength=%d, want 500/%d", gwErr.Status, gwErr.BodyLength, len(payload))
	}
	if !strings.Contains(gwErr.Error(), "body_length=") {
		t.Errorf("GatewayError.Error() = %q, want body_length", gwErr.Error())
	}
}

// TestFetchHatchToken403ShapesRedacted drives the same 12
// server-text shapes through the real FetchHatchToken 403
// path: a hermetic fake gateway returns 403 with the shape as
// the body, and the AuthError text must carry no full fixture
// value. Bodies stay well under FetchHatchToken's old
// 160-rune truncation so truncation can never explain an
// absence. Loop 5 supersedes the publicKey prefix rule here:
// the error carries the allowlist summary only, so no value
// bytes survive — not even the 8-char prefix. Shape names
// and forms match TestSafeStringTwelveServerShapes; shapes
// 10-12 are the derived already-stripped ones, named
// explicitly there.
func TestFetchHatchToken403ShapesRedacted(t *testing.T) {
	t.Parallel()
	const (
		colonVal  = "LOGFIX-GWCOLON-2c6e88"
		singleVal = "LOGFIX-GWSINGLE-51bc07"
		basicVal  = "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
		pctVal    = "LOGFIX-GWPCT-83af10"
		fragVal   = "LOGFIX-GWFRAG-9d2e41"
		authVal   = "LOGFIX-GWAUTH-77d4e9"
		secretVal = "LOGFIX-GWSECRET-22d9f0"
		privVal   = "LOGFIX-GWPRIV-6e19d0"
		pubVal    = "LOGFIX-GWPUB-4b77c2"
		tokenVal  = "LOGFIX-GWAT-83af10"
		bearerVal = "LOGFIX-GWBEARER-1a8f33"
	)
	shapes := []struct {
		name       string
		body       string
		forbidden  []string
		wantPrefix string
	}{
		{"camelCase-privateKey-JSON", `{"privateKey": "` + privVal + `"}`, []string{privVal}, ""},
		{"camelCase-publicKey-JSON", `{"publicKey": "` + pubVal + `"}`, []string{pubVal}, ""},
		{"colon-form", "private_key: " + colonVal, []string{colonVal}, ""},
		{"single-quote-JSON", `{'token': '` + singleVal + `'}`, []string{singleVal}, ""},
		{"authorization-basic", "Authorization: Basic " + basicVal, []string{basicVal}, ""},
		{"percent-encoded-equals-query", "https://example.invalid/cb?auth_token%3D" + pctVal, []string{pctVal}, ""},
		{"bare-fragment", "https://example.invalid/reset#" + fragVal, []string{fragVal}, ""},
		{"bare-auth-equals", "auth=" + authVal, []string{authVal}, ""},
		{"bare-secret-equals", "secret=" + secretVal, []string{secretVal}, ""},
		{"double-quote-JSON-token (derived)", `{"token": "` + tokenVal + `"}`, []string{tokenVal}, ""},
		{"bare-keyvalue-token (derived)", "token=" + tokenVal, []string{tokenVal}, ""},
		{"bearer (derived)", "Authorization: Bearer " + bearerVal, []string{bearerVal}, ""},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			body := sh.body
			handler := gatewaytest.HandlerRoundTripper(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(403)
				_, _ = w.Write([]byte(body))
			}))
			client := &http.Client{Transport: handler}
			_, err := FetchHatchToken(context.Background(), client, fakeCookie, "AT", "vm-1")
			if err == nil {
				t.Fatal("FetchHatchToken(403) = nil, want an AuthError")
			}
			var ae *conn.AuthError
			if !errors.As(err, &ae) {
				t.Fatalf("err = %T, want *conn.AuthError", err)
			}
			got := err.Error()
			if !strings.Contains(got, "403") {
				t.Errorf("error %q, want the 403 status (proves the fake body entered the path)", got)
			}
			for _, v := range sh.forbidden {
				if strings.Contains(got, v) {
					t.Errorf("FetchHatchToken error %q contains fixture value %q", got, v)
				}
			}
			if sh.wantPrefix != "" && !strings.Contains(got, sh.wantPrefix) {
				t.Errorf("FetchHatchToken error %q, want the 8-char public-key prefix %q present", got, sh.wantPrefix)
			}
		})
	}
}

// TestFetchHatchToken403QuoteCombinations (loop 4, (b)): all
// four JSON quote combinations through the real FetchHatchToken
// 403 path. The double-key/single-value form is the loop-3
// survivor and must be stripped here, not only in SafeString.
func TestFetchHatchToken403QuoteCombinations(t *testing.T) {
	t.Parallel()
	const val = "LOGFIX-GWQUOTE-83af10"
	shapes := []struct {
		name string
		body string
	}{
		{"double-double", `{"token": "` + val + `"}`},
		{"single-single", `{'token': '` + val + `'}`},
		{"double-single", `{"token": '` + val + `'}`},
		{"single-double", `{'token': "` + val + `"}`},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			handler := gatewaytest.HandlerRoundTripper(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(403)
				_, _ = w.Write([]byte(sh.body))
			}))
			client := &http.Client{Transport: handler}
			_, err := FetchHatchToken(context.Background(), client, fakeCookie, "AT", "vm-1")
			if err == nil {
				t.Fatal("FetchHatchToken(403) = nil, want an AuthError")
			}
			var ae *conn.AuthError
			if !errors.As(err, &ae) {
				t.Fatalf("err = %T, want *conn.AuthError", err)
			}
			got := err.Error()
			if !strings.Contains(got, "403") {
				t.Errorf("error %q, want the 403 status (proves the fake body entered the path)", got)
			}
			if strings.Contains(got, val) {
				t.Errorf("FetchHatchToken error %q contains fixture value %q", got, val)
			}
			if !strings.Contains(got, "body_length=") {
				t.Errorf("FetchHatchToken error %q, want the allowlist body_length (proves the body entered the path)", got)
			}
		})
	}
}

// TestFetchHatchToken403ObservationShapes (loop 4, (c)): the
// four observation shapes through the real FetchHatchToken 403
// path: unicode-escaped key, numeric JSON value, digitless
// fragment, percent-encoded key name.
func TestFetchHatchToken403ObservationShapes(t *testing.T) {
	t.Parallel()
	shapes := []struct {
		name      string
		body      string
		forbidden []string
	}{
		{"unicode-escaped-key", `{"tok\u0065n": "LOGFIX-GWUNI-22d9f0"}`, []string{"LOGFIX-GWUNI-22d9f0"}},
		{"numeric-value", `{"token": 987654321}`, []string{"987654321"}},
		{"digitless-fragment", "see #LOGFIXGWFRAG-abcdef", []string{"LOGFIXGWFRAG-abcdef"}},
		{"pct-encoded-key", "%61uth_token=LOGFIX-GWPCTKEY-51bc07", []string{"LOGFIX-GWPCTKEY-51bc07"}},
		{"pct-encoded-key-equals", "%61uth_token%3DLOGFIX-GWPCTKEY-51bc07", []string{"LOGFIX-GWPCTKEY-51bc07"}},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			handler := gatewaytest.HandlerRoundTripper(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(403)
				_, _ = w.Write([]byte(sh.body))
			}))
			client := &http.Client{Transport: handler}
			_, err := FetchHatchToken(context.Background(), client, fakeCookie, "AT", "vm-1")
			if err == nil {
				t.Fatal("FetchHatchToken(403) = nil, want an AuthError")
			}
			var ae *conn.AuthError
			if !errors.As(err, &ae) {
				t.Fatalf("err = %T, want *conn.AuthError", err)
			}
			got := err.Error()
			if !strings.Contains(got, "403") {
				t.Errorf("error %q, want the 403 status (proves the fake body entered the path)", got)
			}
			for _, v := range sh.forbidden {
				if strings.Contains(got, v) {
					t.Errorf("FetchHatchToken error %q contains fixture value %q", got, v)
				}
			}
		})
	}
}
