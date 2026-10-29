// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/gateway/gatewaytest"
)

const fakeCookie = "hatch_sess=FAKE; datr=FAKE"

func authClient(auth *gatewaytest.CannedAuth) *http.Client {
	return &http.Client{Transport: gatewaytest.HandlerRoundTripper(auth)}
}

// headerCapture wraps a handler and records request headers per path.
type headerCapture struct {
	seen map[string]http.Header
	next http.Handler
}

func (h *headerCapture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.seen == nil {
		h.seen = map[string]http.Header{}
	}
	h.seen[r.URL.Path] = r.Header.Clone()
	h.next.ServeHTTP(w, r)
}

func TestFetchSessionInfo(t *testing.T) {
	ctx := context.Background()
	t.Run("ok", func(t *testing.T) {
		auth := &gatewaytest.CannedAuth{VMID: "vm-123", AccessToken: "AT", HatchToken: "HT"}
		info, err := FetchSessionInfo(ctx, authClient(auth), fakeCookie)
		if err != nil {
			t.Fatalf("FetchSessionInfo: %v", err)
		}
		if info.VMID != "vm-123" {
			t.Errorf("VMID = %q", info.VMID)
		}
	})
	t.Run("non-200 is AuthError", func(t *testing.T) {
		auth := &gatewaytest.CannedAuth{SessionStatus: 401}
		_, err := FetchSessionInfo(ctx, authClient(auth), fakeCookie)
		var ae *conn.AuthError
		if !errors.As(err, &ae) {
			t.Fatalf("err = %T (%v), want *AuthError", err, err)
		}
	})
	t.Run("missing vm_id is GatewayError not AuthError", func(t *testing.T) {
		auth := &gatewaytest.CannedAuth{SessionNoVMID: true}
		_, err := FetchSessionInfo(ctx, authClient(auth), fakeCookie)
		var ge *conn.GatewayError
		if !errors.As(err, &ge) {
			t.Fatalf("err = %T (%v), want *GatewayError", err, err)
		}
		if ge.Status != -1 {
			t.Errorf("status = %d, want -1", ge.Status)
		}
		var ae *conn.AuthError
		if errors.As(err, &ae) {
			t.Fatalf("GatewayError also matches AuthError")
		}
		if !strings.Contains(ge.Payload, "VM unavailable") {
			t.Errorf("payload = %q", ge.Payload)
		}
	})
	t.Run("headers", func(t *testing.T) {
		auth := &gatewaytest.CannedAuth{VMID: "vm-1"}
		cap := &headerCapture{next: auth}
		client := &http.Client{Transport: gatewaytest.HandlerRoundTripper(cap)}
		if _, err := FetchSessionInfo(ctx, client, fakeCookie); err != nil {
			t.Fatalf("FetchSessionInfo: %v", err)
		}
		h := cap.seen["/api/session"]
		if h.Get("User-Agent") != UserAgent {
			t.Errorf("UA = %q", h.Get("User-Agent"))
		}
		if h.Get("Referer") != "https://muse.ai/" || h.Get("Origin") != "https://muse.ai" {
			t.Errorf("Referer/Origin = %q/%q", h.Get("Referer"), h.Get("Origin"))
		}
		if h.Get("Sec-Fetch-Site") != "same-origin" || h.Get("Sec-Fetch-Mode") != "cors" || h.Get("Sec-Fetch-Dest") != "empty" {
			t.Errorf("Sec-Fetch headers = %v", h)
		}
		if h.Get("Cookie") != fakeCookie {
			t.Errorf("Cookie = %q", h.Get("Cookie"))
		}
		if h.Get("Authorization") != "" {
			t.Errorf("Authorization present on session call: %q", h.Get("Authorization"))
		}
		if h.Get("Accept") != "application/json" || h.Get("Content-Type") != "application/json" {
			t.Errorf("Accept/Content-Type = %q/%q", h.Get("Accept"), h.Get("Content-Type"))
		}
	})
}

func TestFetchAccessAndHatchTokens(t *testing.T) {
	ctx := context.Background()
	t.Run("ok and bearer header", func(t *testing.T) {
		auth := &gatewaytest.CannedAuth{VMID: "vm-9", AccessToken: "AT-1", HatchToken: "HT-1"}
		cap := &headerCapture{next: auth}
		client := &http.Client{Transport: gatewaytest.HandlerRoundTripper(cap)}
		at, err := FetchAccessToken(ctx, client, fakeCookie)
		if err != nil || at != "AT-1" {
			t.Fatalf("FetchAccessToken = %q, %v", at, err)
		}
		ht, err := FetchHatchToken(ctx, client, fakeCookie, at, "vm-9")
		if err != nil || ht != "HT-1" {
			t.Fatalf("FetchHatchToken = %q, %v", ht, err)
		}
		if got := cap.seen["/api/hatch/token"].Get("Authorization"); got != "Bearer AT-1" {
			t.Errorf("hatch/token Authorization = %q", got)
		}
	})
	t.Run("non-200 is AuthError", func(t *testing.T) {
		auth := &gatewaytest.CannedAuth{AuthCheckStatus: 403, HatchStatus: 500}
		client := authClient(auth)
		if _, err := FetchAccessToken(ctx, client, fakeCookie); err == nil {
			t.Error("auth/check 403: nil error")
		} else {
			var ae *conn.AuthError
			if !errors.As(err, &ae) {
				t.Errorf("err = %T, want AuthError", err)
			}
		}
		if _, err := FetchHatchToken(ctx, client, fakeCookie, "AT", "vm-1"); err == nil {
			t.Error("hatch/token 500: nil error")
		} else {
			var ae *conn.AuthError
			if !errors.As(err, &ae) {
				t.Errorf("err = %T, want AuthError", err)
			}
		}
	})
}

func TestDefaultWSURL(t *testing.T) {
	fn := defaultWSURL(true, GatewayHost)
	u := fn("vm-1", "tok/en?&=")
	want := "wss://hatch.metaaivm.com/v1/noise?vm_id=vm-1&auth_token=tok%2Fen%3F%26%3D"
	if u != want {
		t.Errorf("URL = %q, want %q", u, want)
	}
	if got := defaultWSURL(false, "example.test")("v", "t"); got != "ws://example.test/v1/noise?vm_id=v&auth_token=t" {
		t.Errorf("plain URL = %q", got)
	}
}
