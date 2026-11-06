// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Command wait_driver is the Go side of the M7a wait Tier A
// parity gate (parity-live.md §3): run the Go wait.Runner
// against a scripted gateway_server (serve-wait mode) and
// print the CLI result shape + exit code, so the gate can
// diff it byte-for-byte against the Rust wait_driver example
// run with the same script and argv.
//
// It CANNOT import internal/commands (unexported
// toWaitResultJSON / executeWait / printWaitText), so it
// re-encodes wait.Result with local structs whose field
// order is copied verbatim from internal/commands/wait.go
// waitResultJSON / replyJSON / widgetJSON / approvalJSON /
// approvedJSON / approveErrorJSON, and duplicates the text
// rendering (printWaitText / printWaitTail format strings).
// That drift risk is bounded by Tier B (live CLI-vs-CLI byte
// equality on the real commands) and by the CLI's own
// wait_json_* / print_wait_text_* unit tests.
//
// The connection mirrors the real CLI: conn.Muse over the
// fake gateway connector (plain TCP dialer + canned auth),
// Connect returns a SharedConn lease (3-attempt subscribe
// retry, same as the Rust driver example), history reads go
// through muse.Call("chat.history").
//
// Usage:
//
//	wait_driver --addr 127.0.0.1:PORT [--thread ID]
//	    [--after-seq N] [--timeout SECONDS] [--json]
//
// Defaults: --timeout 600 (Runner clamps <=0 to 600),
// text mode unless --json. --after-seq is presence-tracked:
// absent means derive the boundary from history, exactly
// like the CLI's intIsSet("after-seq").
//
// All credentials here are fake (hatch_sess=FAKE, AT-FAKE,
// HT-FAKE); nothing real is ever read.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/thoitiettxl-cyber/castctl/internal/approvals"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway/gatewaytest"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/wait"
)

const fakeCookie = "hatch_sess=FAKE; datr=FAKE"

// plainDialer is the minimal gateway.OutboundDialer for the
// fake server: plain TCP to the host:port the WS URL names
// (the fake server is loopback, no TLS), and the canned auth
// chain for the HTTPS steps. Copied from
// rust/parity/gateway_server/main.go (plainDialer); that file
// is the source of truth — keep the two in sync.
type plainDialer struct {
	auth http.Handler
}

func (d *plainDialer) WebSocketDial(ctx context.Context, network, host string, port uint16, secure bool, _ option.OutboundTLSOptions) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
}

func (d *plainDialer) HTTPClient() *http.Client {
	return &http.Client{Transport: gatewaytest.HandlerRoundTripper(d.auth)}
}

// --- local JSON structs: field order copied verbatim from
// internal/commands/wait.go (waitResultJSON etc.). ---

type widgetJSON struct {
	ID      any     `json:"widget_id"`
	Kind    string  `json:"kind"`
	Text    *string `json:"text"`
	Options any     `json:"options"`
}

type replyJSON struct {
	Seq       int64        `json:"seq"`
	MessageID *string      `json:"message_id"`
	Text      string       `json:"text"`
	Widgets   []widgetJSON `json:"widgets,omitempty"`
	Media     bool         `json:"media,omitempty"`
}

type approvalJSON struct {
	ApprovalID  *string  `json:"approval_id"`
	Title       *string  `json:"title"`
	Question    *string  `json:"question"`
	Kind        *string  `json:"kind"`
	Scope       *string  `json:"scope"`
	Why         *string  `json:"why"`
	ExpiresAtMS *float64 `json:"expires_at_ms"`
	Options     []string `json:"options"`
}

type approvedJSON struct {
	ApprovalID *string `json:"approval_id"`
	Title      *string `json:"title"`
	Kind       *string `json:"kind"`
	Scope      *string `json:"scope"`
	Decision   *string `json:"decision"`
}

type approveErrorJSON struct {
	ApprovalID *string `json:"approval_id"`
	Title      *string `json:"title"`
	Kind       *string `json:"kind"`
	Scope      *string `json:"scope"`
	Decision   *string `json:"decision"`
	Error      string  `json:"error"`
}

type waitResultJSON struct {
	Outcome           string             `json:"outcome"`
	Status            *string            `json:"status"`
	AfterSeq          int64              `json:"after_seq"`
	FinalText         *string            `json:"final_text"`
	Replies           []replyJSON        `json:"replies"`
	FinalReadFailed   bool               `json:"final_read_failed,omitempty"`
	Note              string             `json:"note,omitempty"`
	Approvals         *[]approvalJSON    `json:"approvals,omitempty"`
	AutoApproved      *[]approvedJSON    `json:"auto_approved,omitempty"`
	AutoApproveErrors []approveErrorJSON `json:"auto_approve_errors,omitempty"`
	Widgets           *[]widgetJSON      `json:"widgets,omitempty"`
	NeedsInputReason  *string            `json:"needs_input_reason,omitempty"`
	Question          *string            `json:"question,omitempty"`
}

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func toWidgetJSON(w wait.Widget) widgetJSON {
	return widgetJSON{ID: w.ID, Kind: w.Kind, Text: w.Text, Options: w.Options}
}

func toReplyJSON(r wait.Reply) replyJSON {
	out := replyJSON{Seq: r.Seq, MessageID: strPtrOrNil(r.MessageID), Text: r.Text, Media: r.Media}
	if len(r.Widgets) > 0 {
		ws := make([]widgetJSON, len(r.Widgets))
		for i, w := range r.Widgets {
			ws[i] = toWidgetJSON(w)
		}
		out.Widgets = ws
	}
	return out
}

func toApprovalsJSON(list []approvals.DescribedApproval) []approvalJSON {
	out := make([]approvalJSON, 0, len(list))
	for _, a := range list {
		out = append(out, approvalJSON{
			ApprovalID: a.ApprovalID, Title: a.Title, Question: a.Question,
			Kind: a.Kind, Scope: a.Scope, Why: a.Why,
			ExpiresAtMS: a.ExpiresAtMS, Options: a.Options,
		})
	}
	return out
}

// toWaitResultJSON mirrors internal/commands/wait.go
// toWaitResultJSON with autoApproveEnabled=false (this driver
// configures no approver, so AutoApproved /
// AutoApproveErrors are always empty and omitted).
func toWaitResultJSON(res *wait.Result) waitResultJSON {
	out := waitResultJSON{
		Outcome:  res.Outcome,
		Status:   strPtrOrNil(res.Status),
		AfterSeq: res.AfterSeq,
		Replies:  make([]replyJSON, 0, len(res.Replies)),
	}
	for _, r := range res.Replies {
		out.Replies = append(out.Replies, toReplyJSON(r))
	}
	if len(res.Replies) > 0 {
		text := res.FinalText
		out.FinalText = &text
	}
	if res.FinalReadFailed {
		out.FinalReadFailed = true
	}
	if res.Note != "" {
		out.Note = res.Note
	}
	if res.Kind == wait.KindApproval {
		appr := toApprovalsJSON(res.Approvals)
		out.Approvals = &appr
	}
	if len(res.Replies) > 0 {
		if widgets := res.Replies[len(res.Replies)-1].Widgets; len(widgets) > 0 {
			ws := make([]widgetJSON, len(widgets))
			for i, w := range widgets {
				ws[i] = toWidgetJSON(w)
			}
			out.Widgets = &ws
		}
	}
	if res.Outcome == "needs_input" {
		reason := res.NeedsInputReason
		out.NeedsInputReason = &reason
		question := res.Question
		out.Question = &question
	}
	return out
}

// --- text rendering: format strings copied verbatim from
// internal/commands/wait.go printWaitText / printWaitTail. ---

func widgetIDStr(id any) string {
	if id == nil {
		return "None"
	}
	return fmt.Sprint(id)
}

func widgetOptionsStr(options any) string {
	list, ok := options.([]any)
	if !ok {
		if options == nil {
			return ""
		}
		return fmt.Sprint(options)
	}
	parts := make([]string, 0, len(list))
	for _, v := range list {
		parts = append(parts, fmt.Sprint(v))
	}
	return strings.Join(parts, " / ")
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func printWaitTail(w, errW *os.File, res *wait.Result, summary bool) {
	if res.Outcome == "needs_input" && res.Question != "" {
		fmt.Fprintf(w, "NEEDS INPUT (%s): %s\n", res.NeedsInputReason, res.Question)
	}
	for _, a := range res.Approvals {
		fmt.Fprintf(w, "NEEDS APPROVAL %s: %s - %s\n", derefStr(a.ApprovalID), derefStr(a.Title), derefStr(a.Question))
		if derefStr(a.Why) != "" {
			fmt.Fprintf(w, "  why: %s\n", derefStr(a.Why))
		}
	}
	if res.Note != "" {
		fmt.Fprintf(errW, "note: %s\n", res.Note)
	}
	if summary {
		fmt.Fprintf(errW, "-- %s (status=%s)\n", res.Outcome, res.Status)
	}
}

func printWaitText(w, errW *os.File, res *wait.Result) {
	for _, r := range res.Replies {
		fmt.Fprintf(w, "[%d] %s\n", r.Seq, r.Text)
		for _, wd := range r.Widgets {
			line := fmt.Sprintf("  ? widget %s: %s", widgetIDStr(wd.ID), derefStr(wd.Text))
			if opts := widgetOptionsStr(wd.Options); opts != "" {
				line += " [" + opts + "]"
			}
			fmt.Fprintln(w, line)
		}
	}
	printWaitTail(w, errW, res, true)
}

// writeJSONCompact writes v as compact JSON with HTML
// escaping disabled and a trailing newline — the canonical
// Tier A form both drivers print (the CLI's indented form
// is pinned separately by Tier B raw bytes + the M2
// write_json_text goldens).
func writeJSONCompact(w *os.File, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// historyReader adapts muse.Call("chat.history") to
// wait.HistoryReader: body {"limit"} + session_id, result
// object with chat_events + has_more.
type historyReader struct {
	muse   *conn.Muse
	thread string
}

func (h *historyReader) ReadHistory(ctx context.Context, limit int) ([]any, bool, error) {
	body := map[string]any{"limit": limit}
	if h.thread != "" {
		body["session_id"] = h.thread
	}
	v, err := h.muse.Call(ctx, "chat.history", conn.RequestOptions{Body: body})
	if err != nil {
		return nil, false, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false, fmt.Errorf("gateway: chat.history result is not an object: %T", v)
	}
	events, _ := m["chat_events"].([]any)
	hasMore, _ := m["has_more"].(bool)
	return events, hasMore, nil
}

func run() int {
	addr := flag.String("addr", "", "fake gateway addr 127.0.0.1:PORT (required)")
	thread := flag.String("thread", "", "thread/session id")
	afterSeq := flag.Int64("after-seq", 0, "explicit boundary seq")
	hasAfterSeq := false
	timeout := flag.Int64("timeout", 600, "wait timeout in seconds")
	jsonOut := flag.Bool("json", false, "print JSON instead of text")
	flag.Parse()
	// Presence-track --after-seq: flag.NFlag/Visit only tells
	// whether it was set on the command line.
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "after-seq" {
			hasAfterSeq = true
		}
	})
	if *addr == "" {
		fmt.Fprintln(os.Stderr, "wait_driver: --addr is required")
		return 2
	}

	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT-FAKE", HatchToken: "HT-FAKE"}
	dialer := &plainDialer{auth: auth}
	cookiesTmp, err := os.CreateTemp("", "wait-driver-cookies-*.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, "wait_driver:", err)
		return 1
	}
	cookiesFile := cookiesTmp.Name()
	if _, err := cookiesTmp.Write([]byte(fakeCookie)); err != nil {
		cookiesTmp.Close()
		os.Remove(cookiesFile)
		fmt.Fprintln(os.Stderr, "wait_driver:", err)
		return 1
	}
	if err := cookiesTmp.Close(); err != nil {
		os.Remove(cookiesFile)
		fmt.Fprintln(os.Stderr, "wait_driver:", err)
		return 1
	}
	defer os.Remove(cookiesFile)

	connect := gateway.NewConnector(
		dialer,
		gateway.WithWebSocketSecure(false),
		gateway.WithWSURL(func(vmID, token string) string {
			return fmt.Sprintf("ws://%s/v1/noise?vm_id=%s&auth_token=%s", *addr, vmID, token)
		}),
	)
	muse := conn.New(connect)
	ctx := context.Background()
	gw, err := muse.Connect(ctx, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wait_driver: connect:", err)
		return 1
	}
	defer gw.Close()

	runner, err := wait.NewRunner(wait.Config{
		Thread:      *thread,
		NodeID:      "wait-driver",
		AfterSeq:    *afterSeq,
		HasAfterSeq: hasAfterSeq,
		Timeout:     time.Duration(*timeout) * time.Second,
		Dial: func(ctx context.Context) (wait.Subscriber, error) {
			return gw, nil
		},
		History: &historyReader{muse: muse, thread: *thread},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "wait_driver: NewRunner:", err)
		return 1
	}
	res, err := runner.Run(ctx)
	if err != nil {
		// Mirror executeWait (wait.go): auth propagates as
		// exit 2, context death as 130, anything else as a
		// synthetic timeout 124 with the fixed note. The
		// fixture never triggers this path; it exists so a
		// broken fixture fails loudly instead of hanging.
		var authErr *conn.AuthError
		if errors.As(err, &authErr) {
			fmt.Fprintf(os.Stderr, "wait_driver: wait: %s\n", logging.SummarizeErr(err))
			return 2
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return 130
		}
		fmt.Fprintf(os.Stderr, "wait_driver: wait: unexpected error (%s); reporting timeout\n", logging.SummarizeErr(err))
		res = &wait.Result{
			Kind: wait.KindTimeout, Outcome: "timeout", AfterSeq: *afterSeq,
			Replies: []wait.Reply{}, Note: "wait failed internally; run `castctl wait` again",
			ExitCode: wait.ExitTimeout,
		}
	}
	if *jsonOut {
		if err := writeJSONCompact(os.Stdout, toWaitResultJSON(res)); err != nil {
			fmt.Fprintln(os.Stderr, "wait_driver:", err)
			return 1
		}
	} else {
		printWaitText(os.Stdout, os.Stderr, res)
	}
	return res.ExitCode
}

func main() {
	os.Exit(run())
}
