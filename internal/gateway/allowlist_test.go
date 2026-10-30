// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

// Loop-5 allowlist tests (RED first): no untrusted server/peer
// body byte may reach any output rendering. A distinctive
// marker body (plain words, no secret label, so no redactor
// can strip it) is driven through every body-consuming
// producer; every rendering of the resulting error —
// Error(), LogSummary(), the stored Payload, and returned
// data that reaches an error/data surface — must be free of
// the marker while carrying the allowlist fields (status,
// class, body length, content-type, parsed-by-key enum
// fields). Fixtures are literals, never recomputed from the
// code under test.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway/gatewaytest"
	pb "github.com/thoitiettxl-cyber/castctl/internal/proto"
)

const allowlistMarker = "ALLOW5MARKER9d2e41"

// markerBody is a plain-words body carrying the marker and no
// secret label.
func markerBody() string {
	return "plain body words " + allowlistMarker + " more words"
}

func assertNoMarker(t *testing.T, what, got string) {
	t.Helper()
	if got == "" {
		t.Fatalf("%s is empty: positive control failed", what)
	}
	if strings.Contains(got, allowlistMarker) {
		t.Errorf("%s %q carries the marker body bytes", what, got)
	}
}

func TestAllowlistSessionNonJSON(t *testing.T) {
	body := markerBody()
	_, err := FetchSessionInfo(context.Background(), straddleBodyClient(200, body), fakeCookie)
	var ae *conn.AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %T (%v), want *conn.AuthError", err, err)
	}
	assertNoMarker(t, "AuthError.Error()", ae.Error())
	assertNoMarker(t, "AuthError.LogSummary()", ae.LogSummary())
	if !strings.Contains(ae.Error(), fmt.Sprintf("body_length=%d", len(body))) {
		t.Errorf("AuthError.Error() = %q, want body_length=%d", ae.Error(), len(body))
	}
	if !strings.Contains(ae.Error(), "content_type=text/plain") {
		t.Errorf("AuthError.Error() = %q, want content_type=text/plain", ae.Error())
	}
}

func TestAllowlistSessionMissingVMID(t *testing.T) {
	body := `{"status":"unavailable","note":"` + allowlistMarker + `"}`
	_, err := FetchSessionInfo(context.Background(), straddleBodyClient(200, body), fakeCookie)
	var ge *conn.GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("err = %T (%v), want *conn.GatewayError", err, err)
	}
	assertNoMarker(t, "GatewayError.Error()", ge.Error())
	assertNoMarker(t, "GatewayError.Payload", ge.Payload)
	assertNoMarker(t, "GatewayError.LogSummary()", ge.LogSummary())
	if !strings.Contains(ge.Payload, "VM unavailable") {
		t.Errorf("Payload = %q, want the VM unavailable class label", ge.Payload)
	}
	if !strings.Contains(ge.Payload, "body_status=unavailable") {
		t.Errorf("Payload = %q, want the parsed body_status enum", ge.Payload)
	}
	if ge.BodyLength != len(body) {
		t.Errorf("BodyLength = %d, want wire length %d", ge.BodyLength, len(body))
	}
}

func TestAllowlistAccessTokenNon200(t *testing.T) {
	body := markerBody()
	_, err := FetchAccessToken(context.Background(), straddleBodyClient(500, body), fakeCookie)
	var ae *conn.AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %T (%v), want *conn.AuthError", err, err)
	}
	assertNoMarker(t, "AuthError.Error()", ae.Error())
	if !strings.Contains(ae.Error(), "auth/check") || !strings.Contains(ae.Error(), "500") {
		t.Errorf("AuthError.Error() = %q, want endpoint + status", ae.Error())
	}
	if !strings.Contains(ae.Error(), fmt.Sprintf("body_length=%d", len(body))) {
		t.Errorf("AuthError.Error() = %q, want body_length=%d", ae.Error(), len(body))
	}
}

func TestAllowlistHatchTokenNon200(t *testing.T) {
	body := markerBody()
	_, err := FetchHatchToken(context.Background(), straddleBodyClient(403, body), fakeCookie, "AT", "vm-1")
	var ae *conn.AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %T (%v), want *conn.AuthError", err, err)
	}
	assertNoMarker(t, "AuthError.Error()", ae.Error())
	if !strings.Contains(ae.Error(), "hatch/token") || !strings.Contains(ae.Error(), "403") {
		t.Errorf("AuthError.Error() = %q, want endpoint + status", ae.Error())
	}
}

func TestAllowlistInviteNon200(t *testing.T) {
	body := markerBody()
	_, err := FetchInvite(context.Background(), straddleBodyClient(500, body), fakeCookie)
	var ge *conn.GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("err = %T (%v), want *conn.GatewayError", err, err)
	}
	assertNoMarker(t, "GatewayError.Error()", ge.Error())
	assertNoMarker(t, "GatewayError.Payload", ge.Payload)
	if ge.Status != 500 || ge.BodyLength != len(body) {
		t.Errorf("GatewayError status=%d BodyLength=%d, want 500/%d", ge.Status, ge.BodyLength, len(body))
	}
	if !strings.Contains(ge.Error(), "body_length=") {
		t.Errorf("GatewayError.Error() = %q, want body_length", ge.Error())
	}
}

func TestAllowlistInviteNonJSON(t *testing.T) {
	body := markerBody()
	_, err := FetchInvite(context.Background(), straddleBodyClient(200, body), fakeCookie)
	var ge *conn.GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("err = %T (%v), want *conn.GatewayError", err, err)
	}
	assertNoMarker(t, "GatewayError.Error()", ge.Error())
	assertNoMarker(t, "GatewayError.Payload", ge.Payload)
	if !strings.Contains(ge.Payload, "non-JSON") {
		t.Errorf("Payload = %q, want the non-JSON class label", ge.Payload)
	}
}

func TestAllowlistRedeemNonJSON(t *testing.T) {
	body := markerBody()
	_, b, err := RedeemInviteCode(context.Background(), straddleBodyClient(400, body), fakeCookie, "ABCDEF")
	if err != nil {
		t.Fatalf("RedeemInviteCode: %v", err)
	}
	m, ok := b.(map[string]any)
	if !ok {
		t.Fatalf("body = %#v, want a map", b)
	}
	detail, _ := m["detail"].(string)
	assertNoMarker(t, "redeem detail", detail)
	if !strings.Contains(detail, fmt.Sprintf("body_length=%d", len(body))) {
		t.Errorf("detail = %q, want body_length=%d", detail, len(body))
	}
	if m["reason"] != "unknown" {
		t.Errorf("reason = %#v, want \"unknown\"", m["reason"])
	}
}

func TestAllowlistSubscriptionErrorValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x-component")
		_, _ = io.WriteString(w, "1:{\"success\":false,\"error\":\"free text "+allowlistMarker+" here\"}\n")
	}))
	defer srv.Close()
	_, _, err := FetchSubscription(context.Background(), srv.Client(), fakeCookie, SubscriptionOptions{Page: srv.URL})
	var ge *conn.GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("err = %T (%v), want *conn.GatewayError", err, err)
	}
	assertNoMarker(t, "GatewayError.Error()", ge.Error())
	assertNoMarker(t, "GatewayError.Payload", ge.Payload)
	if strings.Contains(ge.Payload, allowlistMarker) {
		t.Errorf("Payload = %q carries the free-text error value", ge.Payload)
	}
}

func TestAllowlistCallJSONOkFalseFreeText(t *testing.T) {
	s := startE2E(t, gatewaytest.JSONHandler(200, []byte(`{"ok":false,"error":"rate limited `+allowlistMarker+`"}`)))
	defer s.cleanup()
	_, err := s.gw.CallJSON(context.Background(), "sessions.list", conn.RequestOptions{})
	var ge *conn.GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("err = %T (%v), want *conn.GatewayError", err, err)
	}
	assertNoMarker(t, "GatewayError.Error()", ge.Error())
	assertNoMarker(t, "GatewayError.Payload", ge.Payload)
	// Free text (spaces) is not an error enum: the value must
	// be replaced by a placeholder, never emitted.
	if strings.Contains(ge.Payload, "rate limited") {
		t.Errorf("Payload = %q emits the free-text error value", ge.Payload)
	}
}

func TestAllowlistCallJSONOkFalseEnumEmitted(t *testing.T) {
	s := startE2E(t, gatewaytest.JSONHandler(200, []byte(`{"ok":false,"error":"denied"}`)))
	defer s.cleanup()
	_, err := s.gw.CallJSON(context.Background(), "sessions.list", conn.RequestOptions{})
	var ge *conn.GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("err = %T (%v), want *conn.GatewayError", err, err)
	}
	if !strings.Contains(ge.Payload, "error=denied") {
		t.Errorf("Payload = %q, want the parsed error enum emitted", ge.Payload)
	}
	assertNoMarker(t, "GatewayError.Error()", ge.Error())
}

func TestAllowlistRequestNon2xx(t *testing.T) {
	body := markerBody()
	s := startE2E(t, gatewaytest.JSONHandler(404, []byte(body)))
	defer s.cleanup()
	_, err := s.gw.Request(context.Background(), "sessions.list", conn.RequestOptions{})
	var ge *conn.GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("err = %T (%v), want *conn.GatewayError", err, err)
	}
	assertNoMarker(t, "GatewayError.Error()", ge.Error())
	assertNoMarker(t, "GatewayError.Payload", ge.Payload)
	if ge.BodyLength != len(body) {
		t.Errorf("BodyLength = %d, want wire length %d", ge.BodyLength, len(body))
	}
}

func TestAllowlistResetReason(t *testing.T) {
	s := startE2E(t, gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{gatewaytest.ResetFrame(0, pb.Reset_INTERNAL_ERROR, allowlistMarker)}}
	}))
	defer s.cleanup()
	_, err := s.gw.Request(context.Background(), "sessions.list", conn.RequestOptions{})
	var ge *conn.GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("err = %T (%v), want *conn.GatewayError", err, err)
	}
	assertNoMarker(t, "GatewayError.Error()", ge.Error())
	assertNoMarker(t, "GatewayError.Payload", ge.Payload)
	if !strings.Contains(ge.Payload, "reset") || !strings.Contains(ge.Payload, "5") {
		t.Errorf("Payload = %q, want the reset class + code", ge.Payload)
	}
	if !strings.Contains(ge.Payload, fmt.Sprintf("reason_length=%d", len(allowlistMarker))) {
		t.Errorf("Payload = %q, want reason_length=%d", ge.Payload, len(allowlistMarker))
	}
}

func TestAllowlistWakeNonJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, markerBody())
	}))
	defer srv.Close()
	overrideWakeURL(t, srv.URL+"/api/hatch/vm/wake")
	_, body, err := WakeVM(context.Background(), srv.Client(), fakeCookie, "AT", "vm-1")
	if err != nil {
		t.Fatalf("WakeVM: %v", err)
	}
	got, ok := body.(string)
	if !ok {
		t.Fatalf("body = %#v, want a summary string", body)
	}
	assertNoMarker(t, "WakeVM body", got)
	if !strings.Contains(got, fmt.Sprintf("body_length=%d", len(markerBody()))) {
		t.Errorf("body = %q, want body_length=%d", got, len(markerBody()))
	}
}
