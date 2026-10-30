// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Fake credentials only; never real secrets.
const fakeAccessToken = "FAKE-ACCESS-TOKEN"

// overrideWakeURL points wakeURL at url for the duration of t and
// restores the previous value when t ends.
func overrideWakeURL(t *testing.T, url string) {
	t.Helper()
	old := wakeURL
	wakeURL = url
	t.Cleanup(func() { wakeURL = old })
}

func TestWakeVM(t *testing.T) {
	// No t.Parallel: these subtests mutate the package-level
	// wakeURL, so they must run sequentially.
	tests := []struct {
		name     string
		status   int
		response string
		want     any
	}{
		{
			name:     "success JSON object",
			status:   http.StatusOK,
			response: `{"status":"ok","n":42}`,
			want:     map[string]any{"status": "ok", "n": json.Number("42")},
		},
		{
			name:     "success JSON array",
			status:   http.StatusOK,
			response: `[1,"two"]`,
			want:     []any{json.Number("1"), "two"},
		},
		{
			name:     "success JSON scalar",
			status:   http.StatusOK,
			response: `true`,
			want:     true,
		},
		{
			name:     "non-2xx is not an error",
			status:   http.StatusServiceUnavailable,
			response: `{"status":"unavailable"}`,
			want:     map[string]any{"status": "unavailable"},
		},
		{
			name:     "empty body is nil (JSON null)",
			status:   http.StatusOK,
			response: ``,
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.response)
			}))
			defer srv.Close()
			overrideWakeURL(t, srv.URL+"/api/hatch/vm/wake")

			status, body, err := WakeVM(context.Background(), srv.Client(), fakeCookie, fakeAccessToken, "vm-fake-1")
			if err != nil {
				t.Fatalf("WakeVM: %v", err)
			}
			if status != tt.status {
				t.Errorf("status = %d, want %d", status, tt.status)
			}
			if !reflect.DeepEqual(body, tt.want) {
				t.Errorf("body = %#v, want %#v", body, tt.want)
			}
		})
	}
}

func TestWakeVMNonJSONTruncated(t *testing.T) {
	text := strings.Repeat("abcdefghij", 40) // 400 bytes
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, text)
	}))
	defer srv.Close()
	overrideWakeURL(t, srv.URL+"/api/hatch/vm/wake")

	status, body, err := WakeVM(context.Background(), srv.Client(), fakeCookie, fakeAccessToken, "vm-fake-1")
	if err != nil {
		t.Fatalf("WakeVM: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	got, ok := body.(string)
	if !ok {
		t.Fatalf("body = %#v, want string", body)
	}
	// Loop 5: the non-JSON form is the allowlist summary
	// (body length + content-type), never the raw text.
	if strings.Contains(got, text) {
		t.Errorf("body = %q carries the raw response text", got)
	}
	if !strings.Contains(got, "body_length=400") || !strings.Contains(got, "content_type=text/plain") {
		t.Errorf("body = %q, want body_length + content_type", got)
	}
}

func TestWakeVMHeadersAndRequest(t *testing.T) {
	var gotHeader http.Header
	var gotMethod, gotPath string
	var gotBody struct {
		VMID       string `json:"vm_id"`
		RetryCount int    `json:"retry_count"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		gotMethod, gotPath = r.Method, r.URL.Path
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer srv.Close()
	overrideWakeURL(t, srv.URL+"/api/hatch/vm/wake")

	if _, _, err := WakeVM(context.Background(), srv.Client(), fakeCookie, fakeAccessToken, "vm-fake-1"); err != nil {
		t.Fatalf("WakeVM: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/hatch/vm/wake" {
		t.Errorf("path = %q, want /api/hatch/vm/wake", gotPath)
	}
	if gotBody.VMID != "vm-fake-1" || gotBody.RetryCount != 0 {
		t.Errorf("request body = %+v, want {vm-fake-1 0}", gotBody)
	}
	// Presence only for credential-carrying headers: never assert
	// secret values, even fake ones.
	if gotHeader.Get("Cookie") == "" {
		t.Error("Cookie header absent")
	}
	if gotHeader.Get("Authorization") == "" {
		t.Error("Authorization header absent")
	}
	if gotHeader.Get("User-Agent") != UserAgent {
		t.Errorf("User-Agent = %q, want %q", gotHeader.Get("User-Agent"), UserAgent)
	}
}

func TestWakeVMNilClient(t *testing.T) {
	status, body, err := WakeVM(context.Background(), nil, fakeCookie, fakeAccessToken, "vm-fake-1")
	if err == nil {
		t.Fatal("WakeVM with nil client: nil error")
	}
	if !strings.Contains(err.Error(), "nil http client") {
		t.Errorf("err = %q, want it to mention nil http client", err)
	}
	if status != 0 || body != nil {
		t.Errorf("status/body = %d/%#v, want 0/nil", status, body)
	}
}

func TestWakeVMTimeout(t *testing.T) {
	// The server sleeps longer than the caller's deadline, so the
	// call must fail on the caller's deadline — without waiting
	// out the 15s wakeTimeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer srv.Close()
	overrideWakeURL(t, srv.URL+"/api/hatch/vm/wake")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	status, body, err := WakeVM(ctx, srv.Client(), fakeCookie, fakeAccessToken, "vm-fake-1")
	if err == nil {
		t.Fatal("WakeVM with expired deadline: nil error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded in the chain", err)
	}
	if status != 0 || body != nil {
		t.Errorf("status/body = %d/%#v, want 0/nil", status, body)
	}
}
