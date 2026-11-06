// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Command send_wait_driver is the Go side of the M7b PR-2
// send Tier A parity gate: run Go's `cmdSend` shape
// (deliverSend + wait.Runner + buildSendWaitJSON +
// sendDownloadStep) against a scripted gateway_server
// (serve-wait mode) and print the CLI result shape + exit
// code, so the gate can diff it byte-for-byte against the
// Rust send_wait_driver example run with the same script
// and argv.
//
// It CANNOT import internal/commands (unexported cmdSend /
// deliverSend / buildSendWaitJSON / sendDownloadStep), so
// it re-encodes the send result with local structs whose
// field order is copied verbatim from
// internal/commands/wait.go (sendBaseJSON / sendWaitJSON /
// sendReplyJSON / sendNoWaitJSON / waitResultJSON /
// replyJSON / widgetJSON / approvalJSON / approvedJSON /
// approveErrorJSON), duplicates deliverSend and
// sendDownloadStep (incl. the local dedupResources), and
// duplicates the text rendering (printWaitText /
// printWaitTail format strings). That drift risk is
// bounded by Tier B (live CLI-vs-CLI byte equality on the
// real command) and by the CLI's own send_json_* unit
// tests.
//
// The connection mirrors the real CLI: conn.Muse over the
// fake gateway connector (plain TCP dialer + canned auth),
// Connect returns a SharedConn lease (3-attempt subscribe
// retry, same as the Rust driver example), the baseline /
// ack-poll history reads go through the leased gateway
// (gw.CallJSON), the stream opens on it (Track=false),
// and the Runner follows the turn on the same lease.
//
// Usage:
//
//	send_wait_driver --addr 127.0.0.1:PORT [--thread ID]
//	    [--wait SECONDS] [--until-done] [--text]
//	    [--ack-timeout SECONDS] [--download DIR] TEXT
//
// Defaults: --wait 90, --ack-timeout 30. JSON is the
// default output (compact, SetEscapeHTML(false) — the
// canonical Tier A form, same as wait_driver); --text
// prints `user_seq=<N>` + the wait text instead.
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
	"io"
	"log/slog"
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
	"github.com/thoitiettxl-cyber/castctl/internal/shared"
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

// --- send shapes: field order copied verbatim from
// internal/commands/wait.go (sendBaseJSON / sendWaitJSON /
// sendReplyJSON / sendNoWaitJSON). ---

type sendBaseJSON struct {
	Sent      bool   `json:"sent"`
	Delivered bool   `json:"delivered"`
	UserSeq   *int64 `json:"user_seq"`
	Stream    int64  `json:"stream"`
}

type sendWaitJSON struct {
	sendBaseJSON
	Outcome           string             `json:"outcome"`
	Status            *string            `json:"status"`
	FinalText         *string            `json:"final_text"`
	Replies           []replyJSON        `json:"replies"`
	Approvals         *[]approvalJSON    `json:"approvals,omitempty"`
	AutoApproved      *[]approvedJSON    `json:"auto_approved,omitempty"`
	AutoApproveErrors []approveErrorJSON `json:"auto_approve_errors,omitempty"`
	Widgets           *[]widgetJSON      `json:"widgets,omitempty"`
	Question          *string            `json:"question,omitempty"`
	NeedsInputReason  *string            `json:"needs_input_reason,omitempty"`
	Reply             *sendReplyJSON     `json:"reply,omitempty"`
	Downloads         []shared.SaveRow   `json:"downloads,omitempty"`
	DownloadError     string             `json:"download_error,omitempty"`
	Note              string             `json:"note,omitempty"`
}

type sendReplyJSON struct {
	Seq       int64   `json:"seq"`
	Role      string  `json:"role"`
	MessageID *string `json:"message_id"`
	Text      string  `json:"text"`
}

type sendNoWaitJSON struct {
	sendBaseJSON
	Note string `json:"note,omitempty"`
}

// buildSendWaitJSON mirrors internal/commands/wait.go
// buildSendWaitJSON (autoApproveEnabled=false here, so
// AutoApproved / AutoApproveErrors come from the wait
// JSON as built above — always empty/omitted).
func buildSendWaitJSON(base sendBaseJSON, waitJSON waitResultJSON, res *wait.Result, waitSeconds int64, userSeq int64) sendWaitJSON {
	result := sendWaitJSON{sendBaseJSON: base}
	result.Outcome = waitJSON.Outcome
	result.Status = waitJSON.Status
	result.FinalText = waitJSON.FinalText
	result.Replies = waitJSON.Replies
	result.Approvals = waitJSON.Approvals
	result.AutoApproved = waitJSON.AutoApproved
	result.AutoApproveErrors = waitJSON.AutoApproveErrors
	result.Widgets = waitJSON.Widgets
	result.NeedsInputReason = waitJSON.NeedsInputReason
	result.Question = waitJSON.Question
	if len(res.Replies) > 0 {
		last := res.Replies[len(res.Replies)-1]
		result.Reply = &sendReplyJSON{
			Seq: last.Seq, Role: "message.assistant",
			MessageID: strPtrOrNil(last.MessageID), Text: last.Text,
		}
	}
	if res.Outcome == "timeout" {
		result.Note = fmt.Sprintf("turn not finished within %ds; run `castctl wait --after-seq %d`", waitSeconds, userSeq)
	} else {
		result.Note = waitJSON.Note
	}
	return result
}

// --- history helpers: copied from
// internal/commands/wait.go (callHistoryEvents,
// swallowableHistoryError, maxSeq, eventSeq). ---

func callHistoryEvents(ctx context.Context, gw conn.Gateway, limit int, thread string) ([]any, error) {
	body := map[string]any{"limit": limit}
	if thread != "" {
		body["session_id"] = thread
	}
	v, err := gw.CallJSON(ctx, "chat.history", conn.RequestOptions{Body: body})
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("gateway: chat.history result is not an object: %T", v)
	}
	events, _ := m["chat_events"].([]any)
	return events, nil
}

func swallowableHistoryError(err error) bool {
	var gwErr *conn.GatewayError
	if errors.As(err, &gwErr) {
		return true
	}
	var timeoutErr *conn.TimeoutError
	return errors.As(err, &timeoutErr)
}

func eventSeq(raw any) int64 {
	ev, ok := raw.(map[string]any)
	if !ok {
		return 0
	}
	switch seq := ev["seq"].(type) {
	case int64:
		return seq
	case json.Number:
		n, _ := seq.Int64()
		return n
	case float64:
		return int64(seq)
	default:
		return 0
	}
}

func maxSeq(events []any) int64 {
	var max int64
	for _, raw := range events {
		if seq := eventSeq(raw); seq > max {
			max = seq
		}
	}
	return max
}

// deliverSend mirrors internal/commands/wait.go
// deliverSend (baseline limit=1 + limit=20, OpenStream
// Track=false, ack poll limit=10 every 100ms).
func deliverSend(ctx context.Context, gw conn.Gateway, nodeID, text, thread string, ackTimeout time.Duration) (*int64, int64, error) {
	events, err := callHistoryEvents(ctx, gw, 1, thread)
	if err != nil {
		return nil, 0, err
	}
	baseline := maxSeq(events)
	confirm, err := callHistoryEvents(ctx, gw, 20, thread)
	if err != nil {
		return nil, 0, err
	}
	if m := maxSeq(confirm); m > baseline {
		baseline = m
	}
	params := map[string]any{
		"items":        []any{map[string]any{"type": "text", "text": text}},
		"node_id":      nodeID,
		"capabilities": map[string]any{},
	}
	if thread != "" {
		params["session_id"] = thread
	}
	streamID, err := gw.OpenStream(ctx, "chat.stream", conn.OpenStreamOptions{Body: params, Track: false})
	if err != nil {
		return nil, 0, err
	}
	deadline := time.Now().Add(ackTimeout)
	var userSeq *int64
	for userSeq == nil && time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		events, err := callHistoryEvents(ctx, gw, 10, thread)
		if err == nil {
			if seq, ok := wait.UserAck(events, baseline, &text); ok {
				userSeq = &seq
			}
		} else if !swallowableHistoryError(err) {
			return nil, 0, err
		}
		if userSeq == nil {
			remaining := time.Until(deadline)
			pause := 100 * time.Millisecond
			if remaining < pause {
				pause = remaining
			}
			if pause > 0 {
				timer := time.NewTimer(pause)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil, 0, ctx.Err()
				case <-timer.C:
				}
			}
		}
	}
	return userSeq, streamID, nil
}

// dedupResources mirrors internal/commands/wait.go
// dedupResources (local copy: the driver cannot import
// internal/commands).
func dedupResources(events []any) []shared.Resource {
	var res []shared.Resource
	seen := map[string]bool{}
	for _, e := range events {
		ev, ok := e.(map[string]any)
		if !ok {
			continue
		}
		for _, r := range shared.EventResources(ev) {
			if seen[r.Path] {
				continue
			}
			seen[r.Path] = true
			res = append(res, r)
		}
	}
	return res
}

// sendDownloadStep mirrors internal/commands/wait.go
// sendDownloadStep (fresh lease via WithGateway, history
// limit=30, SaveResources overwrite=false; auth/cancel
// propagate, anything else becomes download_error).
func sendDownloadStep(ctx context.Context, muse *conn.Muse, thread string, userSeq int64, dir string, result *sendWaitJSON) error {
	err := muse.WithGateway(ctx, func(gw conn.Gateway) error {
		events, err := callHistoryEvents(ctx, gw, 30, thread)
		if err != nil {
			return err
		}
		var fresh []any
		for _, raw := range events {
			if eventSeq(raw) > userSeq {
				fresh = append(fresh, raw)
			}
		}
		rows, err := shared.SaveResources(ctx, gw, dedupResources(fresh), dir, false)
		if err != nil {
			return err
		}
		result.Downloads = rows
		return nil
	})
	if err != nil {
		var authErr *conn.AuthError
		if errors.As(err, &authErr) || ctx.Err() != nil {
			return err
		}
		result.DownloadError = logging.SummarizeErr(err)
		return nil
	}
	return nil
}

// historyReader adapts muse.Call("chat.history") to
// wait.HistoryReader: body {"limit"} + session_id, result
// object with chat_events + has_more. Copied from
// wait_driver.
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
	waitSeconds := flag.Int64("wait", 90, "wait timeout in seconds")
	untilDone := flag.Bool("until-done", false, "wait up to 24h")
	textMode := flag.Bool("text", false, "print text instead of JSON")
	ackTimeout := flag.Int64("ack-timeout", 30, "delivery ack timeout in seconds")
	downloadDir := flag.String("download", "", "save the turn's resources to DIR")
	flag.Parse()
	if *addr == "" {
		fmt.Fprintln(os.Stderr, "send_wait_driver: --addr is required")
		return 2
	}
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "send_wait_driver: text is required")
		return 2
	}
	text := args[0]
	if *untilDone {
		*waitSeconds = 24 * 3600
	}
	ackTimeoutDur := time.Duration(*ackTimeout) * time.Second

	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT-FAKE", HatchToken: "HT-FAKE"}
	dialer := &plainDialer{auth: auth}
	cookiesTmp, err := os.CreateTemp("", "send-wait-driver-cookies-*.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, "send_wait_driver:", err)
		return 1
	}
	cookiesFile := cookiesTmp.Name()
	if _, err := cookiesTmp.Write([]byte(fakeCookie)); err != nil {
		cookiesTmp.Close()
		os.Remove(cookiesFile)
		fmt.Fprintln(os.Stderr, "send_wait_driver:", err)
		return 1
	}
	if err := cookiesTmp.Close(); err != nil {
		os.Remove(cookiesFile)
		fmt.Fprintln(os.Stderr, "send_wait_driver:", err)
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
	muse := conn.New(connect,
		conn.WithConfig(conn.Config{CookiesFile: cookiesFile}),
		conn.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	ctx := context.Background()
	gw, err := muse.Connect(ctx, &conn.Config{CookiesFile: cookiesFile})
	if err != nil {
		fmt.Fprintln(os.Stderr, "send_wait_driver: connect:", err)
		return 1
	}
	defer gw.Close()

	userSeq, streamID, err := deliverSend(ctx, gw, "wait-driver", text, *thread, ackTimeoutDur)
	if err != nil {
		var authErr *conn.AuthError
		if errors.As(err, &authErr) {
			fmt.Fprintf(os.Stderr, "send_wait_driver: send: %s\n", logging.SummarizeErr(err))
			return 2
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return 130
		}
		fmt.Fprintf(os.Stderr, "send_wait_driver: send: %s\n", logging.SummarizeErr(err))
		return 1
	}
	base := sendBaseJSON{Sent: true, Delivered: userSeq != nil, UserSeq: userSeq, Stream: streamID}
	if userSeq == nil {
		result := sendNoWaitJSON{sendBaseJSON: base}
		result.Note = fmt.Sprintf("no delivery ack within %ds; check `castctl history`", int(ackTimeoutDur.Seconds()))
		if err := writeJSONCompact(os.Stdout, result); err != nil {
			fmt.Fprintln(os.Stderr, "send_wait_driver:", err)
			return 1
		}
		return 5
	}
	if *waitSeconds == 0 {
		if err := writeJSONCompact(os.Stdout, sendNoWaitJSON{sendBaseJSON: base}); err != nil {
			fmt.Fprintln(os.Stderr, "send_wait_driver:", err)
			return 1
		}
		return 0
	}
	// Follow the turn on the connection that sent it
	// (multiplexed): no new connect + Noise handshake per
	// subscription or history read. The heartbeat replaces
	// it if it dies silently, like `wait`'s own.
	runner, err := wait.NewRunner(wait.Config{
		Thread:      *thread,
		NodeID:      "wait-driver",
		AfterSeq:    *userSeq,
		HasAfterSeq: true,
		Timeout:     time.Duration(*waitSeconds) * time.Second,
		Dial: func(ctx context.Context) (wait.Subscriber, error) {
			return gw, nil
		},
		History: &historyReader{muse: muse, thread: *thread},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "send_wait_driver: NewRunner:", err)
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
			fmt.Fprintf(os.Stderr, "send_wait_driver: wait: %s\n", logging.SummarizeErr(err))
			return 2
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return 130
		}
		fmt.Fprintf(os.Stderr, "send_wait_driver: wait: unexpected error (%s); reporting timeout\n", logging.SummarizeErr(err))
		res = &wait.Result{
			Kind: wait.KindTimeout, Outcome: "timeout", AfterSeq: *userSeq,
			Replies: []wait.Reply{}, Note: "wait failed internally; run `castctl wait` again",
			ExitCode: wait.ExitTimeout,
		}
	}
	waitJSON := toWaitResultJSON(res)
	result := buildSendWaitJSON(base, waitJSON, res, *waitSeconds, *userSeq)
	if *downloadDir != "" && len(res.Replies) > 0 {
		if err := sendDownloadStep(ctx, muse, *thread, *userSeq, *downloadDir, &result); err != nil {
			var authErr *conn.AuthError
			if errors.As(err, &authErr) {
				fmt.Fprintf(os.Stderr, "send_wait_driver: download: %s\n", logging.SummarizeErr(err))
				return 2
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return 130
			}
			fmt.Fprintf(os.Stderr, "send_wait_driver: download: %s\n", logging.SummarizeErr(err))
			return 1
		}
	}
	if *textMode {
		fmt.Fprintf(os.Stdout, "user_seq=%d\n", *userSeq)
		printWaitText(os.Stdout, os.Stderr, res)
	} else {
		if err := writeJSONCompact(os.Stdout, result); err != nil {
			fmt.Fprintln(os.Stderr, "send_wait_driver:", err)
			return 1
		}
	}
	return res.ExitCode
}

func main() {
	os.Exit(run())
}
