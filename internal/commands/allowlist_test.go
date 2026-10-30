// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// Loop-5 allowlist tests for the CLI error path: classifyError
// must never return body bytes in ANY branch (plain, typed
// JSON, AuthError JSON, gateway sub-case, wrapped forms, %q
// rendering), and the profile-test message renderer must not
// either. A plain-words marker body (no secret label) is
// carried in a GatewayError/AuthError fixture; the returned
// text must be free of it while carrying the allowlist fields
// and the same exit code as before.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
)

const cliAllowlistMarker = "ALLOW5CLI-9d2e41"

func TestClassifyErrorAllowlist(t *testing.T) {
	t.Parallel()
	gw := &conn.GatewayError{Status: 500, Payload: "plain body words " + cliAllowlistMarker}
	ae := conn.NewAuthError("hatch/token -> 403 plain body words " + cliAllowlistMarker)
	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"gateway plain", gw, 3},
		{"gateway wrapped", fmt.Errorf("outer: %w", gw), 3},
		{"gateway in ConnectionError", &conn.ConnectionError{Err: gw}, 3},
		{"gateway in typed auth", &typedAuthError{Code: 2, Type: "session_unavailable", Err: gw}, 2},
		{"gateway in cmdError typed", &cmdError{Code: 3, Type: "gateway", Err: gw}, 3},
		{"gateway in cmdError plain", &cmdError{Code: 3, Err: gw}, 3},
		{"auth", ae, 2},
		{"auth wrapped", fmt.Errorf("outer: %w", ae), 2},
		{"auth in typed auth", &typedAuthError{Code: 2, Type: "auth_failed", Err: ae}, 2},
		{"reassembly", &gateway.ReassemblySizeError{ChunkID: 7, Size: 10, Limit: 5}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, text := classifyError(tc.err)
			if code != tc.wantCode {
				t.Errorf("classifyError code = %d, want %d", code, tc.wantCode)
			}
			if text == "" {
				t.Fatalf("classifyError text empty: positive control failed")
			}
			if strings.Contains(text, cliAllowlistMarker) || strings.Contains(text, "plain body words") {
				t.Errorf("classifyError text %q carries body bytes", text)
			}
		})
	}
	// Positive controls: the allowlist fields are present.
	if _, text := classifyError(gw); !strings.Contains(text, "status=500") || !strings.Contains(text, "body_length=") {
		t.Errorf("gateway text %q, want status + body_length", text)
	}
	if _, text := classifyError(ae); !strings.Contains(text, "auth_failed") {
		t.Errorf("auth text %q, want the auth_failed class", text)
	}
}

func TestRedactMessageAllowlist(t *testing.T) {
	t.Parallel()
	gw := &conn.GatewayError{Status: 500, Payload: "plain body words " + cliAllowlistMarker}
	got := redactMessage(gw)
	if got == "" {
		t.Fatal("redactMessage empty: positive control failed")
	}
	if strings.Contains(got, cliAllowlistMarker) || strings.Contains(got, "plain body words") {
		t.Errorf("redactMessage %q carries body bytes", got)
	}
	if !strings.Contains(got, "status=500") {
		t.Errorf("redactMessage %q, want the status summary", got)
	}
}

type markerRoundTripper struct{ body string }

func (m markerRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(strings.NewReader(m.body)),
	}
	return resp, nil
}

func TestFetchEgressIPAllowlist(t *testing.T) {
	t.Parallel()
	client := &http.Client{Transport: markerRoundTripper{body: "not an ip " + cliAllowlistMarker}}
	_, err := fetchEgressIP(context.Background(), client)
	if err == nil {
		t.Fatal("fetchEgressIP succeeded on a non-IP body, want an error")
	}
	if strings.Contains(err.Error(), cliAllowlistMarker) || strings.Contains(err.Error(), "not an ip") {
		t.Errorf("fetchEgressIP error %q carries peer body bytes", err.Error())
	}
	if !strings.Contains(err.Error(), "body_length=") {
		t.Errorf("fetchEgressIP error %q, want body_length", err.Error())
	}
}
