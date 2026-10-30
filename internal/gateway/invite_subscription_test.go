// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway/gatewaytest"
)

// muxClient builds an *http.Client serving requests through mux in memory.
func muxClient(mux http.Handler) *http.Client {
	return &http.Client{Transport: gatewaytest.HandlerRoundTripper(mux)}
}

func TestFetchInvite(t *testing.T) {
	ctx := context.Background()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hatch/invite", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("FetchInvite used %s", r.Method)
		}
		gatewaytest.WriteJSON(w, 200, `{"invite_state":"ELIGIBLE","code":null,"max_uses":5}`)
	})
	d, err := FetchInvite(ctx, muxClient(mux), fakeCookie)
	if err != nil {
		t.Fatalf("FetchInvite: %v", err)
	}
	if d["invite_state"] != "ELIGIBLE" {
		t.Errorf("invite_state = %v", d["invite_state"])
	}
}

func TestFetchInviteErrors(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		status int
		body   string
		check  func(t *testing.T, err error)
	}{
		{"401 auth", 401, `{}`, func(t *testing.T, err error) {
			var ae *conn.AuthError
			if !errors.As(err, &ae) {
				t.Fatalf("err = %T, want AuthError", err)
			}
		}},
		{"403 auth", 403, `{}`, func(t *testing.T, err error) {
			var ae *conn.AuthError
			if !errors.As(err, &ae) {
				t.Fatalf("err = %T, want AuthError", err)
			}
		}},
		{"500 gateway", 500, strings.Repeat("x", 300), func(t *testing.T, err error) {
			var ge *conn.GatewayError
			if !errors.As(err, &ge) {
				t.Fatalf("err = %T, want GatewayError", err)
			}
			if ge.Status != 500 || ge.BodyLength != 300 {
				t.Errorf("status=%d BodyLength=%d, want 500/300 (wire length, not truncation)", ge.Status, ge.BodyLength)
			}
			if strings.Contains(ge.Payload, "x") {
				t.Errorf("Payload = %q carries body bytes", ge.Payload)
			}
		}},
		{"non-json", 200, `not json`, func(t *testing.T, err error) {
			var ge *conn.GatewayError
			if !errors.As(err, &ge) || ge.Status != -1 {
				t.Fatalf("err = %T (%v)", err, err)
			}
		}},
		{"non-dict", 200, `[1,2]`, func(t *testing.T, err error) {
			var ge *conn.GatewayError
			if !errors.As(err, &ge) || ge.Status != -1 {
				t.Fatalf("err = %T (%v)", err, err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/hatch/invite", func(w http.ResponseWriter, r *http.Request) {
				gatewaytest.WriteJSON(w, tc.status, tc.body)
			})
			_, err := FetchInvite(ctx, muxClient(mux), fakeCookie)
			if err == nil {
				t.Fatal("nil error")
			}
			tc.check(t, err)
		})
	}
}

func TestCreateInvite(t *testing.T) {
	ctx := context.Background()
	var method, bodyLen string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hatch/invite", func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		var buf [1]byte
		n, _ := r.Body.Read(buf[:])
		bodyLen = string(rune('0' + n))
		gatewaytest.WriteJSON(w, 200, `{"code":"ABCDEF","max_uses":5}`)
	})
	d, err := CreateInvite(ctx, muxClient(mux), fakeCookie)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if method != http.MethodPost {
		t.Errorf("method = %s", method)
	}
	if bodyLen != "0" {
		t.Errorf("POST body length = %s, want empty", bodyLen)
	}
	if d["code"] != "ABCDEF" {
		t.Errorf("code = %v", d["code"])
	}
}

func TestRedeemInviteCode(t *testing.T) {
	ctx := context.Background()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hatch/invite-code/redeem", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if req["code"] != "ABC123" || req["supportsRedemptionStatus"] != true {
			t.Errorf("body = %v", req)
		}
		gatewaytest.WriteJSON(w, 200, `{"success":true,"redemptionStatus":"redeemed"}`)
	})
	status, body, err := RedeemInviteCode(ctx, muxClient(mux), fakeCookie, "  abc123 ")
	if err != nil || status != 200 {
		t.Fatalf("Redeem = %d %v %v", status, body, err)
	}
	if body.(map[string]any)["redemptionStatus"] != "redeemed" {
		t.Errorf("body = %v", body)
	}
	for _, bad := range []string{"", "AB", "ABCDEF12345678901", "abc-def", "ABC 123"} {
		if _, _, err := RedeemInviteCode(ctx, muxClient(mux), fakeCookie, bad); err == nil {
			t.Errorf("code %q: nil error", bad)
		} else {
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Errorf("code %q: err = %T, want ValidationError", bad, err)
			}
		}
	}
}

func TestRedeemInviteCodeNonJSON(t *testing.T) {
	ctx := context.Background()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hatch/invite-code/redeem", func(w http.ResponseWriter, r *http.Request) {
		gatewaytest.WriteJSON(w, 400, `not json`)
	})
	status, body, err := RedeemInviteCode(ctx, muxClient(mux), fakeCookie, "ABCDEF")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if status != 400 {
		t.Errorf("status = %d", status)
	}
	m := body.(map[string]any)
	if m["success"] != false || m["reason"] != "unknown" {
		t.Errorf("body = %v", body)
	}
}

func TestParseRSCResult(t *testing.T) {
	cases := []struct {
		name string
		text string
		want any
	}{
		{"ref row", "0:{\"a\":\"$@1\"}\n1:{\"success\":true,\"subscription\":{\"tier\":\"pro\"}}\n", map[string]any{"success": true, "subscription": map[string]any{"tier": "pro"}}},
		{"row1 fallback", "0:{\"x\":1}\n1:{\"success\":true}\n", map[string]any{"success": true}},
		{"head only", "0:{\"success\":true}\n", map[string]any{"success": true}},
		{"bad json line skipped", "0:not json\n1:{\"a\":1}\n", map[string]any{"a": json.Number("1")}},
		{"empty", "", nil},
		{"array row", "0:[1,2]\n", []any{json.Number("1"), json.Number("2")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseRSCResult(tc.text)
			if !deepEqualJSON(got, tc.want) {
				t.Errorf("ParseRSCResult = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func deepEqualJSON(a, b any) bool {
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}

// memStore is an ActionIDStore backed by memory.
type memStore struct {
	mu sync.Mutex
	id string
}

func (s *memStore) GetActionID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id
}

func (s *memStore) SetActionID(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.id = id
	return nil
}

func rscBody(result string) string {
	return "0:{\"a\":\"$@1\"}\n1:" + result + "\n"
}

func TestFetchSubscription(t *testing.T) {
	ctx := context.Background()
	subJSON := `{"success":true,"subscription":{"tier":{"name":"Pro"},"usage":{"state":"ok"}}}`
	t.Run("configured id wins", func(t *testing.T) {
		var gotID string
		mux := http.NewServeMux()
		mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
			gotID = r.Header.Get("Next-Action")
			w.Header().Set("Content-Type", "text/x-component; charset=utf-8")
			_, _ = w.Write([]byte(rscBody(subJSON)))
		})
		sub, aid, err := FetchSubscription(ctx, muxClient(mux), fakeCookie, SubscriptionOptions{ActionID: "configuredid1234567890", Page: "https://muse.ai/settings"})
		if err != nil {
			t.Fatalf("FetchSubscription: %v", err)
		}
		if aid != "configuredid1234567890" || gotID != aid {
			t.Errorf("aid=%q gotID=%q", aid, gotID)
		}
		if sub["tier"].(map[string]any)["name"] != "Pro" {
			t.Errorf("sub = %v", sub)
		}
	})
	t.Run("stale id falls through to default then scan and caches", func(t *testing.T) {
		store := &memStore{}
		mux := http.NewServeMux()
		mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<script src="/_next/static/chunks/abc.js"></script>`))
				return
			}
			id := r.Header.Get("Next-Action")
			if id == "abcdef1234567890abcdef" {
				w.Header().Set("Content-Type", "text/x-component")
				_, _ = w.Write([]byte(rscBody(subJSON)))
				return
			}
			// Stale: 200 without x-component.
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html></html>"))
		})
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`createServerReference)("abcdef1234567890abcdef",{},"fetchSubscriptionAction")`))
		})
		// The settings page GET for the scan returns the chunk list
		// (handled above); chunk fetches hit the "/" handler.
		sub, aid, err := FetchSubscription(ctx, muxClient(mux), fakeCookie, SubscriptionOptions{Store: store, Page: "https://muse.ai/settings"})
		if err != nil {
			t.Fatalf("FetchSubscription: %v", err)
		}
		_ = sub
		if aid != "abcdef1234567890abcdef" {
			t.Errorf("aid = %q", aid)
		}
		if store.GetActionID() != aid {
			t.Errorf("cached id = %q, want %q", store.GetActionID(), aid)
		}
	})
	t.Run("401 is AuthError", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(401)
		})
		_, _, err := FetchSubscription(ctx, muxClient(mux), fakeCookie, SubscriptionOptions{ActionID: "x12345678901234567890", Page: "https://muse.ai/settings"})
		var ae *conn.AuthError
		if !errors.As(err, &ae) {
			t.Fatalf("err = %T (%v), want AuthError", err, err)
		}
	})
	t.Run("no id found is GatewayError", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<html>no chunks</html>`))
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("stale"))
		})
		_, _, err := FetchSubscription(ctx, muxClient(mux), fakeCookie, SubscriptionOptions{Page: "https://muse.ai/settings"})
		var ge *conn.GatewayError
		if !errors.As(err, &ge) {
			t.Fatalf("err = %T (%v), want GatewayError", err, err)
		}
	})
	t.Run("failed result is GatewayError", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/x-component")
			_, _ = w.Write([]byte(rscBody(`{"success":false,"error":"boom"}`)))
		})
		_, _, err := FetchSubscription(ctx, muxClient(mux), fakeCookie, SubscriptionOptions{ActionID: "id12345678901234567890", Page: "https://muse.ai/settings"})
		var ge *conn.GatewayError
		if !errors.As(err, &ge) || !strings.Contains(ge.Payload, "error=boom") {
			t.Fatalf("err = %T (%v), want GatewayError with the parsed error enum", err, err)
		}
	})
}

func TestFindActionIDMaxFiles(t *testing.T) {
	ctx := context.Background()
	// A chunk graph that keeps discovering new chunks forever:
	// FindActionID must stop at 3000 fetches and return "".
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/settings" {
			_, _ = w.Write([]byte(`/_next/static/chunks/c0.js`))
			return
		}
		var idx int
		_, _ = fmt.Sscanf(r.URL.Path, "/_next/static/chunks/c%d.js", &idx)
		_, _ = w.Write([]byte(`/_next/static/chunks/c` + itoa(idx+1) + `.js`))
	})
	id, err := FindActionID(ctx, muxClient(mux2), fakeCookie, SubscriptionActionName, "https://muse.ai/settings")
	if err != nil {
		t.Fatalf("FindActionID: %v", err)
	}
	if id != "" {
		t.Errorf("id = %q, want empty", id)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestSubscriptionTransportErrorsAreRedactedAndChained (F6): the
// subscription.go transport paths (fetchText, callAction) must
// return errors as typed summaries (loop 6, item 2): the printed
// text carries no peer/credential bytes at all (operation, class,
// kind only), while errors.Is must still find the underlying
// cause. The loop-4 redactErr rendering (a "[redacted]" marker
// in the text) is superseded by the typed summary.
func TestSubscriptionTransportErrorsAreRedactedAndChained(t *testing.T) {
	sentinel := errors.New("sentinel transport failure")
	client := &http.Client{Transport: gatewaytest.RoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("proxy dial: Bearer abcdefgh12345678: %w", sentinel)
	})}
	ctx := context.Background()

	_, err := fetchText(ctx, client, "https://muse.ai/settings", http.Header{}, time.Second)
	if err == nil {
		t.Fatal("fetchText transport error = nil")
	}
	if strings.Contains(err.Error(), "abcdefgh12345678") {
		t.Errorf("fetchText error leaks the token: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "class=") || !strings.Contains(err.Error(), "kind=") {
		t.Errorf("fetchText error = %q, want the typed-summary fields", err.Error())
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("fetchText error chain = %v, want errors.Is to find the sentinel", err)
	}

	_, _, err = callAction(ctx, client, fakeCookie, "actionid12345678901234", nil, "https://muse.ai/settings")
	if err == nil {
		t.Fatal("callAction transport error = nil")
	}
	if strings.Contains(err.Error(), "abcdefgh12345678") {
		t.Errorf("callAction error leaks the token: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "class=") || !strings.Contains(err.Error(), "kind=") {
		t.Errorf("callAction error = %q, want the typed-summary fields", err.Error())
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("callAction error chain = %v, want errors.As to find the sentinel", err)
	}
}
