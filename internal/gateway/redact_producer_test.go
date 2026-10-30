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
// a marker. The reader-panic producer (gateway.go:248) uses the
// same redactFreeText call on an arbitrary panic value; it is
// not driven here — a panic in the reader loop cannot be
// triggered hermetically without a corrupt frame stream — and
// is recorded as unexercised in the loop-2 report.

import (
	"context"
	"errors"
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
// (the calls.go:165 GatewayError construction), must carry no
// fixture value in its printed form, while the host survives.
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
	assertProducerRedacted(t, gwErr.Payload)
	if !strings.Contains(gwErr.Payload, "gateway.example.invalid") {
		t.Errorf("payload over-redacted: %q", gwErr.Payload)
	}
}
