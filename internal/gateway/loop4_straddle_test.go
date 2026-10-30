// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

// Loop-4 (a) truncation-straddle tests: at EVERY cut length that
// truncates server response text, a secret shape straddling the
// cut must be stripped. The order is redact-the-full-text first,
// then truncate: under the old truncate-first order the part of
// the shape before the cut survived because it was too short
// for the redaction floors (fragment <16 chars, Basic <8
// chars) or matched no pattern (double-key/single-value JSON,
// bare percent-encoded query). Each subtest builds a body whose
// cut lands inside the secret shape (mid-secret variant, with
// 'x' and space padding) or two characters into its label
// (label-boundary variant), drives it through the real producer,
// and asserts the pre-cut fragment of the secret (leakProbe)
// is absent from the output. The construction is proven inside
// the test: the truncated body (body[:cut]) must contain
// leakProbe, so a passing test cannot be explained by the
// shape never reaching the cut. All fixtures are ASCII, so
// rune cuts and byte cuts coincide. Bodies are literals here,
// never recomputed from the code under test.
//
// Not parallel: the wake site mutates the package-level wakeURL
// (restored per subtest via overrideWakeURL).

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway/gatewaytest"
)

func straddleBodyClient(status int, body string) *http.Client {
	return &http.Client{Transport: gatewaytest.HandlerRoundTripper(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))}
}

func TestTruncationStraddleRedactBeforeTruncate(t *testing.T) {
	const (
		fragVal  = "LOGFIXSTRAD-1234567890"
		basicTok = "MTIzNDU2Nzg5YWJjZGVm"
		jsonVal  = "LOGFIXSTRAD-JSON99"
		queryVal = "LOGFIXSTRAD-QRY99"
	)
	shapes := []struct {
		name      string
		shape     string
		midOffset int    // chars into shape where the cut lands (mid-secret)
		leakProbe string // pre-cut fragment that old truncate-first order left behind
		fullValue string // whole secret value, absent in every variant
	}{
		{"fragment", "#" + fragVal, 10, "#LOGFIXSTR", fragVal},
		{"basic", "Basic " + basicTok, 13, "MTIzNDU", basicTok},
		{"json-double-single", `{"token": '` + jsonVal + `'}`, 17, "LOGFIX", jsonVal},
		{"query-pct", "%61uth_token%3D" + queryVal, 23, "LOGFIX", queryVal},
	}
	type site struct {
		name  string
		cut   int
		drive func(t *testing.T, body string) string
	}
	gatewayPayload := func(t *testing.T, err error) string {
		t.Helper()
		if err == nil {
			t.Fatal("nil error, want a GatewayError carrying the body")
		}
		var ge *conn.GatewayError
		if !errors.As(err, &ge) {
			t.Fatalf("err = %T (%v), want *conn.GatewayError", err, err)
		}
		return ge.Payload
	}
	authText := func(t *testing.T, err error) string {
		t.Helper()
		if err == nil {
			t.Fatal("nil error, want an AuthError carrying the body")
		}
		var ae *conn.AuthError
		if !errors.As(err, &ae) {
			t.Fatalf("err = %T (%v), want *conn.AuthError", err, err)
		}
		return err.Error()
	}
	sites := []site{
		{"session-80", 80, func(t *testing.T, body string) string {
			_, err := FetchSessionInfo(context.Background(), straddleBodyClient(200, body), fakeCookie)
			return authText(t, err)
		}},
		{"access-120", 120, func(t *testing.T, body string) string {
			_, err := FetchAccessToken(context.Background(), straddleBodyClient(500, body), fakeCookie)
			return authText(t, err)
		}},
		{"hatch-160", 160, func(t *testing.T, body string) string {
			_, err := FetchHatchToken(context.Background(), straddleBodyClient(403, body), fakeCookie, "AT", "vm-1")
			return authText(t, err)
		}},
		{"invite-200", 200, func(t *testing.T, body string) string {
			_, err := FetchInvite(context.Background(), straddleBodyClient(500, body), fakeCookie)
			return gatewayPayload(t, err)
		}},
		{"invite-80", 80, func(t *testing.T, body string) string {
			_, err := FetchInvite(context.Background(), straddleBodyClient(200, body), fakeCookie)
			return gatewayPayload(t, err)
		}},
		{"create-200", 200, func(t *testing.T, body string) string {
			_, err := CreateInvite(context.Background(), straddleBodyClient(500, body), fakeCookie)
			return gatewayPayload(t, err)
		}},
		{"create-80", 80, func(t *testing.T, body string) string {
			_, err := CreateInvite(context.Background(), straddleBodyClient(200, body), fakeCookie)
			return gatewayPayload(t, err)
		}},
		{"redeem-200", 200, func(t *testing.T, body string) string {
			_, b, err := RedeemInviteCode(context.Background(), straddleBodyClient(400, body), fakeCookie, "ABCDEF")
			if err != nil {
				t.Fatalf("RedeemInviteCode: %v", err)
			}
			m, ok := b.(map[string]any)
			if !ok {
				t.Fatalf("body = %#v, want a detail map", b)
			}
			detail, _ := m["detail"].(string)
			if detail == "" {
				t.Fatalf("detail empty: body = %#v (path not entered?)", b)
			}
			return detail
		}},
		{"request-500", 500, func(t *testing.T, body string) string {
			s := startE2E(t, gatewaytest.JSONHandler(500, []byte(body)))
			defer s.cleanup()
			_, err := s.gw.Request(context.Background(), "sessions.list", conn.RequestOptions{})
			return gatewayPayload(t, err)
		}},
		{"calljson-200", 200, func(t *testing.T, body string) string {
			s := startE2E(t, gatewaytest.JSONHandler(200, []byte(body)))
			defer s.cleanup()
			_, err := s.gw.CallJSON(context.Background(), "sessions.list", conn.RequestOptions{})
			return gatewayPayload(t, err)
		}},
		{"wake-300", 300, func(t *testing.T, body string) string {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, body)
			}))
			defer srv.Close()
			overrideWakeURL(t, srv.URL+"/api/hatch/vm/wake")
			_, b, err := WakeVM(context.Background(), srv.Client(), fakeCookie, fakeAccessToken, "vm-fake-1")
			if err != nil {
				t.Fatalf("WakeVM: %v", err)
			}
			text, ok := b.(string)
			if !ok {
				t.Fatalf("body = %#v, want the non-JSON string fallback", b)
			}
			return text
		}},
	}
	// Padding variants: space-padded and dot-padded
	// mid-straddles (both give the shape a word boundary,
	// as a real body would — a shape glued to a preceding
	// word is one word, and no boundary-anchored pattern
	// matches inside a word), plus the label-boundary
	// variant (cut two characters into the label).
	variants := []struct {
		name      string
		pad       string
		offset    func(shapeMid int) int
		checkLeak bool
	}{
		{"pad-space-mid", " ", func(mid int) int { return mid }, true},
		{"pad-dot-mid", ".", func(mid int) int { return mid }, true},
		{"label-boundary", " ", func(int) int { return 2 }, false},
	}
	for _, st := range sites {
		t.Run(st.name, func(t *testing.T) {
			for _, sh := range shapes {
				for _, v := range variants {
					t.Run(sh.name+"/"+v.name, func(t *testing.T) {
						offset := v.offset(sh.midOffset)
						prefixLen := st.cut - offset
						if prefixLen < 0 {
							t.Fatalf("cut %d < offset %d: fixture construction error", st.cut, offset)
						}
						body := strings.Repeat(v.pad, prefixLen) + sh.shape + " END"
						// Construction proof: the truncated body
						// really does straddle the shape.
						if got := body[:st.cut]; !strings.Contains(got, sh.shape[:offset]) {
							t.Fatalf("body[:%d] = %q does not contain the shape prefix %q: straddle not constructed", st.cut, got, sh.shape[:offset])
						}
						out := st.drive(t, body)
						if out == "" {
							t.Fatal("output empty: positive control failed (path not entered?)")
						}
						if strings.Contains(out, sh.fullValue) {
							t.Errorf("output %q contains full secret value %q", out, sh.fullValue)
						}
						if v.checkLeak && strings.Contains(out, sh.leakProbe) {
							t.Errorf("output %q contains pre-cut fragment %q (truncate-first survivor)", out, sh.leakProbe)
						}
					})
				}
			}
		})
	}
}
