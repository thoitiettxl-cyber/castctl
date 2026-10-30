// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// Loop-7 tests (RED): fetchEgressIP transport summary (S1),
// approveAll stderr gating (S2), logAutoApproved sibling-field
// gating (R1), and the separator/newline title path (R2).

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/thoitiettxl-cyber/castctl/internal/approvals"
	"github.com/thoitiettxl-cyber/castctl/internal/wait"
)

const loop7Marker = "LOOP7MARKER3c8e12"

// loop7RawServer serves one fixed raw response to every
// connection (same harness shape as the loop-6 transport
// drive): only the dial target is faked; the HTTP parsing
// stack is stdlib's.
func loop7RawServer(t *testing.T, raw string) (client *http.Client) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
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
	return &http.Client{Transport: &http.Transport{
		Proxy: nil,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, ln.Addr().String())
		},
	}}
}

// --- (S1) fetchEgressIP transport summary -------------------------------

func TestLoop7FetchEgressIPTransportSummary(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "malformed-status-line",
			raw:  "HTTP/1.1 " + loop7Marker + "\r\n\r\n",
		},
		{
			name: "malformed-header-line",
			raw:  "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nBadHeaderLine " + loop7Marker + "\r\nContent-Length: 2\r\n\r\n{}",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := loop7RawServer(t, tc.raw)
			_, err := fetchEgressIP(context.Background(), client)
			if err == nil {
				t.Fatal("fetchEgressIP with a malformed response: nil error, want a transport error")
			}
			got := err.Error()
			if got == "" {
				t.Fatal("fetchEgressIP error is empty: positive control failed")
			}
			if strings.Contains(got, loop7Marker) {
				t.Errorf("fetchEgressIP error %q carries peer response bytes", got)
			}
			if !strings.Contains(got, "class=") || !strings.Contains(got, "kind=") {
				t.Errorf("fetchEgressIP error %q, want the typed transport summary (class/kind)", got)
			}
			// The profile-test warning/error rendering is
			// redactMessage: it must carry the summary only.
			warn := redactMessage(err)
			if warn == "" {
				t.Fatal("redactMessage empty: positive control failed")
			}
			if strings.Contains(warn, loop7Marker) {
				t.Errorf("redactMessage %q carries peer response bytes", warn)
			}
			if !strings.Contains(warn, "class=") || !strings.Contains(warn, "kind=") {
				t.Errorf("redactMessage %q, want the typed transport summary (class/kind)", warn)
			}
		})
	}
	// The malformed-header shape classifies as a response-parse
	// failure, like the gateway's transport summary.
	t.Run("malformed-header-kind", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nBadHeaderLine " + loop7Marker + "\r\nContent-Length: 2\r\n\r\n{}"
		_, err := fetchEgressIP(context.Background(), loop7RawServer(t, raw))
		if err == nil {
			t.Fatal("fetchEgressIP: nil error")
		}
		if !strings.Contains(err.Error(), "kind=response_parse") {
			t.Errorf("fetchEgressIP error %q, want kind=response_parse", err.Error())
		}
	})
}

// --- (S2) approveAll stderr lines ----------------------------------------

func TestLoop7ApproveAllStderrGated(t *testing.T) {
	tail := strings.Repeat("abcdefghij", 8) // 80-char tail
	pending := `{"pending_approvals":[
		{"approval_id":"SKIP1",
		 "display":{"summary_title":"skipped title"},
		 "permission_question":{"kind":"shell","scope":"test"},
		 "decision_options":[{"kind":"allow_once"},{"kind":"token=` + loop7Marker + `"}]},
		{"approval_id":"OK1",
		 "display":{"summary_title":"token=` + loop7Marker + ` ` + tail + `"},
		 "permission_question":{"kind":"shell","scope":"test"},
		 "decision_options":[{"kind":"allow_always"}]}
	]}`
	s := newFakeStack(t, routeHandler(map[string]string{"/approvals": pending}), nil)
	if code := s.run("approvals", "--approve-all"); code != 0 {
		t.Fatalf("approvals --approve-all: code=%d err=%q", code, s.errb.String())
	}
	stderr := s.errb.String()
	if stderr == "" {
		t.Fatal("stderr is empty: positive control failed")
	}
	if strings.Contains(stderr, loop7Marker) {
		t.Errorf("stderr %q carries the peer marker", stderr)
	}
	if strings.Contains(stderr, tail) {
		t.Errorf("stderr %q carries the full 80-char title tail", stderr)
	}
	if !strings.Contains(stderr, "[redacted]") {
		t.Errorf("stderr %q, want the SafeString redaction marker", stderr)
	}
	// The approved line's title segment is capped at 64 runes.
	for _, line := range strings.Split(strings.TrimRight(stderr, "\n"), "\n") {
		if !strings.HasPrefix(line, "approved ") {
			continue
		}
		seg := line[strings.Index(line, ": ")+2 : strings.LastIndex(line, " [")]
		if utf8.RuneCountInString(seg) > 64 {
			t.Errorf("approved title segment is %d runes, want at most 64: %q", utf8.RuneCountInString(seg), seg)
		}
	}
	// Stdout JSON is data output and is NOT gated: the raw
	// title and options survive there byte-identical.
	stdout := s.out.String()
	if !strings.Contains(stdout, loop7Marker) || !strings.Contains(stdout, tail) {
		t.Errorf("stdout %q, want the raw data output untouched", stdout)
	}
}

// --- (R1) logAutoApproved sibling fields ---------------------------------

func TestLoop7LogAutoApprovedSiblingFields(t *testing.T) {
	// Every sibling field carries a newline (line-splitting)
	// and a labelled secret; each must be gated like the
	// title: SafeString + 64-rune cap, newlines neutralised.
	longTail := strings.Repeat("z", 100) + "TAILMARK7"
	rec := approvals.ApprovedRecord{
		ApprovalID: "A1\ntoken=" + loop7Marker + longTail,
		Decision:   "allow_once\ntoken=" + loop7Marker,
		Title:      "plain title",
		Kind:       "shell\ntoken=" + loop7Marker + longTail,
		Scope:      "test\ntoken=" + loop7Marker + longTail,
	}
	skip := &approvals.ApproveError{
		ApprovalID: "B1\ntoken=" + loop7Marker + longTail,
		Kind:       "shell\ntoken=" + loop7Marker + longTail,
		Scope:      "test\ntoken=" + loop7Marker + longTail,
		Decision:   "",
		Err:        errors.New("plain decision error"),
	}
	res := &wait.Result{AutoApproved: []approvals.ApprovedRecord{rec}, AutoApproveErrors: []*approvals.ApproveError{skip}}
	var buf bytes.Buffer
	logAutoApproved(&buf, res)
	out := buf.String()
	if out == "" {
		t.Fatal("logAutoApproved output is empty: positive control failed")
	}
	if strings.Contains(out, loop7Marker) {
		t.Errorf("logAutoApproved output = %q, carries the labelled secret value", out)
	}
	if strings.Contains(out, "TAILMARK7") {
		t.Errorf("logAutoApproved output = %q, carries an over-cap field tail", out)
	}
	if strings.Count(out, "\n") != 2 {
		t.Errorf("logAutoApproved output has %d lines, want exactly 2 (no field may split a line):\n%q", strings.Count(out, "\n"), out)
	}
	if !strings.Contains(out, "[redacted]") {
		t.Errorf("logAutoApproved output = %q, want the SafeString redaction marker", out)
	}
	// The FAILED line gates its ApprovalID too.
	fail := &approvals.ApproveError{
		ApprovalID: "C1\ntoken=" + loop7Marker + longTail,
		Decision:   "allow_once",
		Err:        errors.New("plain decision error"),
	}
	res2 := &wait.Result{AutoApproveErrors: []*approvals.ApproveError{fail}}
	buf.Reset()
	logAutoApproved(&buf, res2)
	out2 := buf.String()
	if strings.Contains(out2, loop7Marker) || strings.Contains(out2, "TAILMARK7") {
		t.Errorf("FAILED line = %q, carries the ungated ApprovalID", out2)
	}
	if strings.Count(out2, "\n") != 1 {
		t.Errorf("FAILED line has %d lines, want exactly 1: %q", strings.Count(out2, "\n"), out2)
	}
}

// --- (R2) title path: separators + newlines -------------------------------

func TestLoop7SafeTitleSeparators(t *testing.T) {
	// The 6 loop-6 separator shapes: NBSP (U+00A0), EM SPACE
	// (U+2003), and vertical tab between the label and the
	// separator, in both the equals and the colon spelling.
	// A 7th/8th shape drives a literal newline inside a JSON
	// string value (scanQuoted must survive it).
	shapes := []struct {
		name string
		in   string
	}{
		{name: "nbsp-equals", in: "token\u00A0=" + loop7Marker},
		{name: "emspace-equals", in: "token\u2003=" + loop7Marker},
		{name: "vtab-equals", in: "token\v=" + loop7Marker},
		{name: "nbsp-colon", in: "token\u00A0:" + loop7Marker},
		{name: "emspace-colon", in: "token\u2003:" + loop7Marker},
		{name: "vtab-colon", in: "token\v:" + loop7Marker},
		{name: "json-newline-double", in: `{"token": "` + loop7Marker + "\nTAIL\"}"},
		{name: "json-newline-single", in: `{'token': '` + loop7Marker + "\nTAIL'}"},
	}
	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			got := safeTitle(tc.in)
			if got == "" {
				t.Fatalf("safeTitle(%q) is empty: positive control failed", tc.in)
			}
			if strings.Contains(got, loop7Marker) {
				t.Errorf("safeTitle(%q) = %q, carries the secret value", tc.in, got)
			}
			if !strings.Contains(got, "[redacted]") {
				t.Errorf("safeTitle(%q) = %q, want the [redacted] marker", tc.in, got)
			}
		})
	}
	// Positive control through the same seam: a plain title
	// survives byte-identical, and the SafeString output is
	// what gets capped (checked by the loop-6 title test).
	if got := safeTitle("plain title"); got != "plain title" {
		t.Errorf("safeTitle(plain) = %q, want it unchanged", got)
	}
}
