// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// Loop-6 tests: redeem --json/text gating on the error path
// (item 3, success data untouched), logAutoApproved title gating
// (item 5), the AuthError CLI boundary invariant (item 6d), and
// the transport-error CLI rendering from a real stdlib error
// (item 2, commands side).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/approvals"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/wait"
)

const loop6Marker = "LOOP6MARKER7f3a91"

func assertNoLoop6Marker(t *testing.T, what, got string) {
	t.Helper()
	if got == "" {
		t.Fatalf("%s is empty: positive control failed", what)
	}
	if strings.Contains(got, loop6Marker) {
		t.Errorf("%s %q carries the loop-6 marker", what, got)
	}
}

// --- (3) redeem command ------------------------------------------------

func loop6RedeemExtra(markerBody string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/hatch/invite-code/redeem" {
			_, _ = io.WriteString(w, markerBody)
			return
		}
		http.NotFound(w, r)
	})
}

func TestLoop6RedeemCommandGated(t *testing.T) {
	failure := `{"success":false,"reason":"free text ` + loop6Marker + ` here","detail":"free text ` + loop6Marker + ` detail","extraKey":"` + loop6Marker + `"}`
	s := newFakeStack(t, nil, loop6RedeemExtra(failure))
	if code := s.run("redeem", "--json", "abcdef"); code != 1 {
		t.Fatalf("redeem --json failure: code=%d, want 1 (out=%q err=%q)", code, s.out.String(), s.errb.String())
	}
	out := s.out.String()
	assertNoLoop6Marker(t, "redeem --json stdout", out)
	if strings.Contains(s.errb.String(), loop6Marker) {
		t.Errorf("redeem --json stderr %q carries the loop-6 marker", s.errb.String())
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("redeem --json stdout = %q, want JSON: %v", out, err)
	}
	for k := range got {
		switch k {
		case "status", "success", "reason", "detail":
		default:
			t.Errorf("redeem --json error output carries key %q: only allowlisted keys may survive: %v", k, got)
		}
	}
	if got["reason"] != "[omitted]" || got["detail"] != "[omitted]" {
		t.Errorf("redeem --json = %v, want reason/detail [omitted]", got)
	}
	// Text path: same gating, same exit code.
	if code := s.run("redeem", "abcdef"); code != 1 {
		t.Fatalf("redeem text failure: code=%d, want 1", code)
	}
	assertNoLoop6Marker(t, "redeem text stdout", s.out.String())
	if !strings.Contains(s.out.String(), "[omitted]") {
		t.Errorf("redeem text = %q, want [omitted] in place of the free-text fields", s.out.String())
	}
}

func TestLoop6RedeemCommandSuccessUntouched(t *testing.T) {
	success := `{"success":true,"redemptionStatus":"redeemed","extraKey":"kept-value"}`
	s := newFakeStack(t, nil, loop6RedeemExtra(success))
	if code := s.run("redeem", "--json", "abcdef"); code != 0 {
		t.Fatalf("redeem --json success: code=%d, want 0 (err=%q)", code, s.errb.String())
	}
	var got map[string]any
	if err := json.Unmarshal(s.out.Bytes(), &got); err != nil {
		t.Fatalf("redeem --json stdout = %q, want JSON: %v", s.out.String(), err)
	}
	if got["extraKey"] != "kept-value" || got["redemptionStatus"] != "redeemed" {
		t.Errorf("redeem --json success = %v, want data passthrough unchanged", got)
	}
	if code := s.run("redeem", "abcdef"); code != 0 {
		t.Fatalf("redeem text success: code=%d, want 0", code)
	}
	if !strings.Contains(s.out.String(), "Redeemed: redeemed") {
		t.Errorf("redeem text = %q, want Redeemed: redeemed", s.out.String())
	}
}

// --- (5) logAutoApproved title gating -----------------------------------
// Loop 8 SUPERSEDES the SafeString/64-rune-cap rendering: the
// title renders as title_length only. The same hostile fixture
// (labelled secret + 100-char tail) now pins the structural
// line exactly; no title byte reaches stderr.

func TestLoop6LogAutoApprovedTitle(t *testing.T) {
	secret := loop6Marker
	title := "token=" + secret + " " + strings.Repeat("abcdefghij", 10)
	res := &wait.Result{
		AutoApproved: []approvals.ApprovedRecord{
			{ApprovalID: "A1", Title: title, Kind: "shell", Scope: "test", Decision: "allow_once"},
		},
	}
	var buf bytes.Buffer
	logAutoApproved(&buf, res)
	out := buf.String()
	if out == "" {
		t.Fatal("logAutoApproved output is empty: positive control failed")
	}
	if strings.Contains(out, secret) {
		t.Errorf("logAutoApproved output = %q, carries the labelled secret value", out)
	}
	want := fmt.Sprintf("auto-approved A1 (allow_once): title_length=%d [shell [omitted]]\n", len(title))
	if out != want {
		t.Errorf("logAutoApproved output = %q, want %q", out, want)
	}
	// A plain long title renders the same structural form.
	plain := strings.Repeat("abcdefghij", 10)
	res2 := &wait.Result{AutoApproved: []approvals.ApprovedRecord{
		{ApprovalID: "A2", Title: plain, Kind: "shell", Scope: "test", Decision: "allow_once"},
	}}
	buf.Reset()
	logAutoApproved(&buf, res2)
	want2 := fmt.Sprintf("auto-approved A2 (allow_once): title_length=%d [shell [omitted]]\n", len(plain))
	if buf.String() != want2 {
		t.Errorf("logAutoApproved output = %q, want %q", buf.String(), want2)
	}
}

// --- (6d) AuthError CLI boundary invariant -------------------------------

func TestLoop6ClassifyErrorAuthBoundary(t *testing.T) {
	// Even an AuthError whose Message was built with body bytes
	// (a producer slip) must never reach stderr through
	// classifyError: the AuthError branch renders through
	// SummarizeErr (the ExportError guidance branch is the
	// only branch that does not; see classifyError).
	auth := conn.NewAuthError("plain body words " + loop6Marker)
	code, text := classifyError(auth)
	if code != 2 {
		t.Errorf("classifyError(AuthError) code = %d, want 2", code)
	}
	assertNoLoop6Marker(t, "classifyError(AuthError)", text)
	if !strings.Contains(text, "auth_failed") {
		t.Errorf("classifyError(AuthError) = %q, want the auth_failed type", text)
	}
	typed := &typedAuthError{Code: 2, Type: "session_unavailable", Err: auth}
	code, text = classifyError(typed)
	if code != 2 {
		t.Errorf("classifyError(typedAuthError) code = %d, want 2", code)
	}
	assertNoLoop6Marker(t, "classifyError(typedAuthError)", text)
}

// --- (2) transport error at the CLI boundary ------------------------------

func TestLoop6ClassifyErrorTransportDrive(t *testing.T) {
	// A real stdlib transport error through the production
	// path: FetchSessionInfo/doHatch with a real http.Transport
	// whose TLS dial is pointed at a raw TCP server emitting a
	// malformed header line carrying the marker (only the dial
	// target is faked, as the gateway FakeDialer does for
	// loopback; the HTTP parsing stack is stdlib's). The error
	// reaching classifyError is the doHatch error, as in
	// production; the CLI rendering must carry no peer text.
	raw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nBadHeaderLine " + loop6Marker + "\r\nContent-Length: 2\r\n\r\n{}"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
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
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy: nil,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, ln.Addr().String())
		},
	}
	client := &http.Client{Transport: transport}
	_, err = gateway.FetchSessionInfo(context.Background(), client, "hatch_sess=FAKE; datr=FAKE")
	if err == nil {
		t.Fatal("FetchSessionInfo with a malformed header line: nil error, want a transport error")
	}
	// The CLI rendering of a genuine transport error carries no
	// peer text.
	code, text := classifyError(err)
	if code != 1 && code != 2 {
		t.Errorf("classifyError(transport error) code = %d, want 1 or 2 (not a crash)", code)
	}
	assertNoLoop6Marker(t, "classifyError(transport error)", text)
}
