// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

// Loop-8 RED tests (F1, Boss ruling 2026-10-30 12:21): the
// RSC path must carry an explicit known/unknown body-length
// flag. A known 0-byte body renders body_length=0 in ALL
// THREE renderings (Payload text, Error(), LogSummary());
// an unknown length renders NO body_length field anywhere.
// These tests FAIL on the loop-7 behaviour, where a 0-byte
// body rendered the summary-text length (45) in Error() /
// LogSummary() while the Payload text said body_length=0.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

// TestLoop8ZeroByteRSCKnownLength drives a 0-byte RSC body
// through FetchSubscription (both candidates and the scanned
// id answer empty): the failure summary must agree at
// exactly 0 in every rendering.
func TestLoop8ZeroByteRSCKnownLength(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<script src="/_next/static/chunks/abc.js"></script>`))
			return
		}
		w.Header().Set("Content-Type", "text/x-component")
		w.WriteHeader(200)
		// Empty body: a known 0-byte read, not "no body".
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`createServerReference)("abcdef1234567890abcdef",{},"fetchSubscriptionAction")`))
	})
	_, _, err := FetchSubscription(context.Background(), muxClient(mux), fakeCookie, SubscriptionOptions{Page: "https://muse.ai/settings"})
	var ge *conn.GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("err = %T (%v), want *conn.GatewayError", err, err)
	}
	if ge.BodyLength != 0 {
		t.Errorf("BodyLength = %d, want the known 0-byte length", ge.BodyLength)
	}
	for _, what := range []struct {
		name string
		got  string
	}{
		{"Payload", ge.Payload},
		{"Error()", ge.Error()},
		{"LogSummary()", ge.LogSummary()},
	} {
		if what.got == "" {
			t.Fatalf("%s is empty: positive control failed", what.name)
		}
		if !strings.Contains(what.got, "body_length=0") {
			t.Errorf("%s = %q, want body_length=0 (known 0-byte body)", what.name, what.got)
		}
	}
}

// TestLoop8NonEmptyRSCByteLength pins the wire-length
// contract in BYTES (not runes) across all three renderings:
// "café ☕" adds 3 bytes over its rune count.
func TestLoop8NonEmptyRSCByteLength(t *testing.T) {
	rsc := "1:{\"success\":false,\"error\":\"denied\",\"note\":\"café ☕\"}\n"
	if utf8.RuneCountInString(rsc) == len(rsc) {
		t.Fatal("fixture has no multi-byte runes: byte-vs-rune distinction untested")
	}
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
	if ge.BodyLength != len(rsc) {
		t.Errorf("BodyLength = %d, want the wire byte length %d (rune count %d)", ge.BodyLength, len(rsc), utf8.RuneCountInString(rsc))
	}
	want := fmt.Sprintf("body_length=%d", len(rsc))
	for _, what := range []struct {
		name string
		got  string
	}{
		{"Payload", ge.Payload},
		{"Error()", ge.Error()},
		{"LogSummary()", ge.LogSummary()},
	} {
		if !strings.Contains(what.got, want) {
			t.Errorf("%s = %q, want %s", what.name, what.got, want)
		}
		if strings.Contains(what.got, "café") || strings.Contains(what.got, "denied\"") {
			t.Errorf("%s = %q, carries body bytes", what.name, what.got)
		}
	}
}

// TestLoop8UnknownLengthSummaryOmitsField drives the summary
// builder with no body bytes at all (nil data): the summary
// text and every GatewayError rendering must carry NO
// body_length field — never the summary-text length.
func TestLoop8UnknownLengthSummaryOmitsField(t *testing.T) {
	sum := summarizeBody("api error", nil, "", map[string]any{"error": "denied"}, "error")
	ge := gatewayErrorFromSummary(-1, sum)
	if ge.Payload == "" {
		t.Fatal("Payload is empty: positive control failed")
	}
	for _, what := range []struct {
		name string
		got  string
	}{
		{"Payload", ge.Payload},
		{"Error()", ge.Error()},
		{"LogSummary()", ge.LogSummary()},
	} {
		if strings.Contains(what.got, "body_length") {
			t.Errorf("%s = %q, want NO body_length field for an unknown length", what.name, what.got)
		}
	}
	if !strings.Contains(ge.Payload, "error=denied") {
		t.Errorf("Payload = %q, want the allowlisted error enum", ge.Payload)
	}
}
