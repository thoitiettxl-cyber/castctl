// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/approvals"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/profile"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/redact"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/shared"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/wait"
)

// PR4 wiring: wait, send, approvals, approve, deny and auto-approve.
// The wait core (internal/wait) and the approver (internal/approvals)
// are wired to the CLI here, following SEAMS.md: one Runner per turn,
// the HistoryReader adapter over the profile's shared connection, the
// Dial adapter returning a lease of the same Muse (so send --wait
// follows the turn on the connection that sent it, multiplexed), and
// one AutoApprover per turn whose Decider opens a fresh lease per
// approve batch. The exit-code contract is spec: wait/send only
// 0/2/4/124, send 5 for no delivery ack; egress.approval.decide is
// never retried (the shared connection only repeats safe reads and
// pre-send failures).

func init() {
	boolFlag := func(name string) flagDef { return flagDef{name: name, kind: flagBool} }
	strFlag := func(name string) flagDef { return flagDef{name: name, kind: flagString} }
	registerCommand(&commandSpec{name: "wait", help: "wait for the current turn to end", helpText: waitHelpText, handler: cmdWait})
	registerCommand(&commandSpec{name: "send", help: "send a message and wait for the turn", helpText: sendHelpText, handler: cmdSend})
	registerCommand(&commandSpec{name: "approvals", help: "list pending approvals (network access etc.)", helpText: approvalsHelpText, handler: cmdApprovals})
	registerCommand(&commandSpec{name: "approve", help: "approve a pending request (or --all)", helpText: approveHelpText, handler: cmdApprove})
	registerCommand(&commandSpec{name: "deny", help: "deny a pending request", helpText: denyHelpText, handler: cmdDeny})
	registerCommand(&commandSpec{name: "auto-approve", help: "let wait/send approve every approval with allow_always", helpText: autoApproveHelpText, handler: cmdAutoApprove})

	registerFlags("wait", "wait [--thread ID] [--after-seq N] [--timeout SECONDS] [--json] [--require-running] [--auto-approve|--no-auto-approve] [--auto-allow-once|--no-auto-allow-once]",
		[]flagDef{strFlag("thread"), {name: "after-seq", kind: flagInt}, intFlag("timeout", 0, 600), boolFlag("json"), boolFlag("require-running"), boolFlag("auto-approve"), boolFlag("no-auto-approve"), boolFlag("auto-allow-once"), boolFlag("no-auto-allow-once")})
	registerFlags("send", "send TEXT [--thread ID] [--wait SECONDS] [--until-done] [--text] [--ack-timeout SECONDS] [--download DIR] [--auto-approve|--no-auto-approve] [--auto-allow-once|--no-auto-allow-once]",
		[]flagDef{strFlag("thread"), intFlag("wait", 0, 90), boolFlag("until-done"), boolFlag("text"), intFlag("ack-timeout", 0, 30), strFlag("download"), boolFlag("auto-approve"), boolFlag("no-auto-approve"), boolFlag("auto-allow-once"), boolFlag("no-auto-allow-once")})
	registerFlags("approvals", "approvals [--recent] [--raw] [--approve-all]",
		[]flagDef{boolFlag("recent"), boolFlag("raw"), boolFlag("approve-all")})
	registerFlags("approve", "approve [ID] [--all] [--once|--session|--today|--always]",
		[]flagDef{boolFlag("all"), boolFlag("once"), boolFlag("session"), boolFlag("today"), boolFlag("always")})
	registerFlags("deny", "deny ID [--always]",
		[]flagDef{boolFlag("always")})
	registerFlags("auto-approve", "auto-approve [on|always|off|status] [once on|off|status]", nil)
}

// autoToggles are the resolved per-call auto-approve flags: a nil
// pointer means the flag was not given (fall through to env/config).
type autoToggles struct {
	approve   *bool
	allowOnce *bool
}

// parseAutoToggles reads the --auto-approve/--no-auto-approve and
// --auto-allow-once/--no-auto-allow-once pairs. Giving both halves of
// a pair is a usage error (argparse's mutually exclusive group).
func parseAutoToggles(p *parsed) (autoToggles, error) {
	var t autoToggles
	if p.bool("auto-approve") && p.bool("no-auto-approve") {
		return t, fmt.Errorf("argument --no-auto-approve: not allowed with argument --auto-approve")
	}
	if p.bool("auto-allow-once") && p.bool("no-auto-allow-once") {
		return t, fmt.Errorf("argument --no-auto-allow-once: not allowed with argument --auto-allow-once")
	}
	if p.bool("auto-approve") {
		v := true
		t.approve = &v
	} else if p.bool("no-auto-approve") {
		v := false
		t.approve = &v
	}
	if p.bool("auto-allow-once") {
		v := true
		t.allowOnce = &v
	} else if p.bool("no-auto-allow-once") {
		v := false
		t.allowOnce = &v
	}
	return t, nil
}

// ensureNodeID resolves the stable per-profile node_id (NODE_ID.md):
// file > MUSE_NODE_ID env > generate (16 hex chars) + persist. A
// generated id is persisted only into a single-file entry for this
// profile; legacy layouts and profiles absent from the single file
// keep the generated id in memory only (never-write-on-read: the
// legacy file is never rewritten). The value is sent verbatim on
// every chat.stream; it is never validated, matching Python.
func ensureNodeID(loc *profile.ConfigLocation, prof *profile.Profile, getenv func(string) (string, bool)) error {
	if prof.NodeID != "" {
		return nil
	}
	if getenv != nil {
		if v, ok := getenv("MUSE_NODE_ID"); ok && v != "" {
			prof.NodeID = v
			return nil
		}
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	generated := hex.EncodeToString(b[:])
	state, err := profile.LoadConfigState(loc.ConfigDir)
	if err != nil {
		return err
	}
	if !state.Found {
		prof.NodeID = generated
		return nil
	}
	if _, ok := state.Config.Profiles[prof.Name]; !ok {
		prof.NodeID = generated
		return nil
	}
	nodeID := generated
	if err := profile.UpdateSingleConfig(loc.ConfigDir, func(cfg *profile.SingleConfig) error {
		p, ok := cfg.Profiles[prof.Name]
		if !ok {
			return fmt.Errorf("profile %q does not exist in the single config file", prof.Name)
		}
		if p.NodeID != "" {
			// Another writer persisted one first: adopt it.
			nodeID = p.NodeID
			return nil
		}
		p.NodeID = nodeID
		return nil
	}); err != nil {
		return err
	}
	prof.NodeID = nodeID
	return nil
}

// runWaitNetwork mirrors runNetwork for the wait path: resolve the
// config + active profile, ensure the node_id (so the runtime is
// built with the identity the send path will transmit), build the
// runtime, run fn, and close the runtime. Gateway/auth failures from
// fn are classified into the typed auth taxonomy, as in runNetwork.
func runWaitNetwork(ctx context.Context, env *Env, g *globalOpts, fn func(*Runtime, *profile.Profile) error) error {
	return runWithProfile(ctx, env, g, func(loc *profile.ConfigLocation, prof *profile.Profile) error {
		if err := ensureNodeID(loc, prof, env.lookupEnv); err != nil {
			return err
		}
		rt, err := env.buildRuntime(ctx, loc, prof)
		if err != nil {
			return err
		}
		defer func() { _ = rt.Close() }()
		if err := fn(rt, prof); err != nil {
			return classifyConnError(err)
		}
		return nil
	})
}

// historyAdapter is the HistoryReader production adapter (SEAMS.md
// §4): chat.history through the profile's shared connection, scoped
// to the thread, with the caller's ctx (and its budgets) bounding
// every read. Auth failures pass through unwrapped-typed so the
// Runner ends the wait with exit 2 instead of 124.
type historyAdapter struct {
	muse   *conn.Muse
	thread string
}

func (a *historyAdapter) ReadHistory(ctx context.Context, limit int) ([]any, bool, error) {
	body := map[string]any{"limit": limit}
	if a.thread != "" {
		body["session_id"] = a.thread
	}
	v, err := a.muse.Call(ctx, "chat.history", conn.RequestOptions{Body: body})
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

// waitDial returns the Runner's Dial: a lease of the profile's shared
// connection, opened under the 30 s connect cap (Python's
// _wait_connection connect_timeout=30). Leases share the one warm
// connection, so the wait follows the turn on the connection that
// sent it and a dropped connection is replaced by the heartbeat.
func waitDial(muse *conn.Muse) func(context.Context) (wait.Subscriber, error) {
	return func(ctx context.Context) (wait.Subscriber, error) {
		dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		gw, err := muse.Connect(dialCtx, nil)
		if err != nil {
			return nil, err
		}
		return gw, nil
	}
}

// waitApprover builds one AutoApprover for a turn. Its Decider opens
// a fresh lease per approve batch and decides with
// egress.approval.decide, which is never retried (the shared
// connection only repeats safe reads and pre-send failures). Claim
// concurrency inside one turn is the AutoApprover's decided set: an
// id is decided at most once per approver lifetime. The 15 s
// in-flight claim wait between a monitor and a turn is a
// driver/monitor concern (tgbot.py, PR5), not part of AutoApprover.
func waitApprover(muse *conn.Muse, allowOnce bool) *approvals.AutoApprover {
	connect := func(ctx context.Context) (approvals.Decider, func(), error) {
		gw, err := muse.Connect(ctx, nil)
		if err != nil {
			return nil, nil, err
		}
		decide := func(ctx context.Context, a approvals.DescribedApproval, decision string) error {
			if a.ApprovalID == nil {
				return errors.New("approvals: cannot decide an approval without an id")
			}
			_, err := gw.CallJSON(ctx, "egress.approval.decide", conn.RequestOptions{
				PathParams: map[string]string{"approval_id": *a.ApprovalID},
				Body:       map[string]any{"decision": decision},
			})
			return err
		}
		return decide, func() { _ = gw.Close() }, nil
	}
	return approvals.NewAutoApprover(connect, allowOnce)
}

// waitRunArgs are executeWait's inputs.
type waitRunArgs struct {
	thread         string
	afterSeq       *int64
	timeout        time.Duration
	requireRunning bool // accepted, no live effect: the core stores it as a dead parameter (waiter.go)
	toggles        autoToggles
}

// executeWait runs one Runner turn on the profile's connection with
// the heartbeat started (a silently dead connection is detected,
// replaced and resubscribed, exactly like Python's wait path). It
// returns the Result, whether auto-approve was enabled (for the
// auto_approved key), and an error only for auth failures,
// cancellation, or a stalled Dial/History failure the endgame could
// not absorb — any other failure is reported as a timeout (exit
// 124), mirroring _run_wait's catch-all. The caller must never read
// waiter state after this returns an error: a cancelled Run may
// leave the waiter mutated (see the R2/R4 containment notes).
func executeWait(ctx context.Context, env *Env, rt *Runtime, prof *profile.Profile, args waitRunArgs) (*wait.Result, bool, error) {
	approveResolved, err := profile.ResolveAutoApprove(prof, args.toggles.approve, env.lookupEnv)
	if err != nil {
		return nil, false, err
	}
	allowOnceResolved, err := profile.ResolveAutoAllowOnce(prof, args.toggles.allowOnce, env.lookupEnv)
	if err != nil {
		return nil, false, err
	}
	cfg := wait.Config{
		Thread:  args.thread,
		NodeID:  prof.NodeID,
		Timeout: args.timeout,
		Dial:    waitDial(rt.Muse),
		History: &historyAdapter{muse: rt.Muse, thread: args.thread},
	}
	if args.afterSeq != nil {
		cfg.AfterSeq = *args.afterSeq
		cfg.HasAfterSeq = true
	}
	if approveResolved.Enabled {
		cfg.Approver = waitApprover(rt.Muse, allowOnceResolved.Enabled).AsApprover()
	}
	runner, err := wait.NewRunner(cfg)
	if err != nil {
		return nil, false, err
	}
	rt.Muse.StartHeartbeat(0)
	defer rt.Muse.StopHeartbeat()
	res, err := runner.Run(ctx)
	if err != nil {
		var authErr *conn.AuthError
		if errors.As(err, &authErr) {
			return nil, false, err
		}
		if ctx.Err() != nil {
			return nil, false, err
		}
		fmt.Fprintf(env.stderr(), "muse-cli: wait: unexpected error (%s); reporting timeout\n", redact.String(err.Error()))
		afterSeq := int64(0)
		if args.afterSeq != nil {
			afterSeq = *args.afterSeq
		}
		return &wait.Result{
			Kind:     wait.KindTimeout,
			Outcome:  "timeout",
			AfterSeq: afterSeq,
			Replies:  []wait.Reply{},
			Note:     "wait failed internally; run `muse-cli wait` again",
			ExitCode: wait.ExitTimeout,
		}, approveResolved.Enabled, nil
	}
	logAutoApproved(env.stderr(), res)
	return res, approveResolved.Enabled, nil
}

// logAutoApproved prints the auto-approve stderr lines for a Result
// (SEAMS.md D6): one line per approved record and per error, in
// result order. The core never logs; the caller owns stderr.
func logAutoApproved(w io.Writer, res *wait.Result) {
	for _, rec := range res.AutoApproved {
		fmt.Fprintf(w, "auto-approved %s (%s): %s [%s %s]\n", rec.ApprovalID, rec.Decision, rec.Title, rec.Kind, rec.Scope)
	}
	for _, e := range res.AutoApproveErrors {
		if e == nil {
			continue
		}
		underlying := ""
		if e.Err != nil {
			underlying = e.Err.Error()
		}
		if e.Decision == "" {
			fmt.Fprintf(w, "auto-approve SKIPPED %s: %s [%s %s]\n", e.ApprovalID, underlying, e.Kind, e.Scope)
		} else {
			fmt.Fprintf(w, "auto-approve FAILED %s: %s\n", e.ApprovalID, underlying)
		}
	}
}

// --- JSON shapes (ordered structs, never maps) ---

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

type widgetJSON struct {
	ID      any     `json:"widget_id"`
	Kind    string  `json:"kind"`
	Text    *string `json:"text"`
	Options any     `json:"options"`
}

func toWidgetJSON(w wait.Widget) widgetJSON {
	return widgetJSON{ID: w.ID, Kind: w.Kind, Text: w.Text, Options: w.Options}
}

type replyJSON struct {
	Seq       int64        `json:"seq"`
	MessageID *string      `json:"message_id"`
	Text      string       `json:"text"`
	Widgets   []widgetJSON `json:"widgets,omitempty"`
	Media     bool         `json:"media,omitempty"`
}

func toReplyJSON(r wait.Reply) replyJSON {
	out := replyJSON{Seq: r.Seq, MessageID: strPtrOrNil(r.MessageID), Text: r.Text, Media: r.Media}
	if len(r.Widgets) > 0 {
		out.Widgets = make([]widgetJSON, len(r.Widgets))
		for i, w := range r.Widgets {
			out.Widgets[i] = toWidgetJSON(w)
		}
	}
	return out
}

func toRepliesJSON(replies []wait.Reply) []replyJSON {
	out := make([]replyJSON, 0, len(replies))
	for _, r := range replies {
		out = append(out, toReplyJSON(r))
	}
	return out
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

func toApprovalJSON(d approvals.DescribedApproval) approvalJSON {
	return approvalJSON{
		ApprovalID:  d.ApprovalID,
		Title:       d.Title,
		Question:    d.Question,
		Kind:        d.Kind,
		Scope:       d.Scope,
		Why:         d.Why,
		ExpiresAtMS: d.ExpiresAtMS,
		Options:     d.Options,
	}
}

func toApprovalsJSON(list []approvals.DescribedApproval) []approvalJSON {
	out := make([]approvalJSON, 0, len(list))
	for _, d := range list {
		out = append(out, toApprovalJSON(d))
	}
	return out
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

// waitResultJSON is the wait/send result dict, in Python's key
// order: outcome, status, after_seq, final_text, replies,
// final_read_failed?, note?, approvals?, auto_approved?,
// auto_approve_errors?, widgets?, needs_input_reason?, question?.
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

func toWaitResultJSON(res *wait.Result, autoApproveEnabled bool) waitResultJSON {
	out := waitResultJSON{
		Outcome:  res.Outcome,
		Status:   strPtrOrNil(res.Status),
		AfterSeq: res.AfterSeq,
		Replies:  toRepliesJSON(res.Replies),
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
	if autoApproveEnabled {
		approved := make([]approvedJSON, 0, len(res.AutoApproved))
		for _, rec := range res.AutoApproved {
			approved = append(approved, approvedJSON{
				ApprovalID: strPtrOrNil(rec.ApprovalID), Title: strPtrOrNil(rec.Title), Kind: strPtrOrNil(rec.Kind), Scope: strPtrOrNil(rec.Scope), Decision: strPtrOrNil(rec.Decision),
			})
		}
		out.AutoApproved = &approved
	}
	if len(res.AutoApproveErrors) > 0 {
		for _, e := range res.AutoApproveErrors {
			if e == nil {
				continue
			}
			errText := ""
			if e.Err != nil {
				errText = e.Err.Error()
			}
			out.AutoApproveErrors = append(out.AutoApproveErrors, approveErrorJSON{
				ApprovalID: strPtrOrNil(e.ApprovalID), Title: strPtrOrNil(e.Title), Kind: strPtrOrNil(e.Kind), Scope: strPtrOrNil(e.Scope), Decision: strPtrOrNil(e.Decision), Error: errText,
			})
		}
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

// --- text display ---

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

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

// printWaitTail prints the question / approval / summary tail shared
// by `wait` text mode and the REPL display.
func printWaitTail(w io.Writer, errW io.Writer, res *wait.Result, summary bool) {
	if res.Outcome == "needs_input" && res.Question != "" {
		fmt.Fprintf(w, "NEEDS INPUT (%s): %s\n", res.NeedsInputReason, res.Question)
	}
	for _, a := range res.Approvals {
		fmt.Fprintf(w, "NEEDS APPROVAL %s: %s - %s\n", derefStr(a.ApprovalID), derefStr(a.Title), derefStr(a.Question))
		if derefStr(a.Why) != "" {
			fmt.Fprintf(w, "  why: %s\n", derefStr(a.Why))
		}
	}
	if summary {
		fmt.Fprintf(errW, "-- %s (status=%s)\n", res.Outcome, res.Status)
	}
}

func printWaitText(w io.Writer, errW io.Writer, res *wait.Result) {
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

// --- wait ---

func cmdWait(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["wait"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "wait"); err != nil {
		return usageErr(err)
	}
	toggles, err := parseAutoToggles(p)
	if err != nil {
		return errCode(2, err)
	}
	var afterSeq *int64
	if p.intIsSet("after-seq") {
		v := p.intVal("after-seq")
		afterSeq = &v
	}
	timeout := time.Duration(p.intVal("timeout")) * time.Second
	return runWaitNetwork(ctx, env, g, func(rt *Runtime, prof *profile.Profile) error {
		res, enabled, err := executeWait(ctx, env, rt, prof, waitRunArgs{
			thread: p.str("thread"), afterSeq: afterSeq, timeout: timeout,
			requireRunning: p.bool("require-running"), toggles: toggles,
		})
		if err != nil {
			return err
		}
		if p.bool("json") {
			if err := writeJSON(env.stdout(), toWaitResultJSON(res, enabled)); err != nil {
				return err
			}
		} else {
			printWaitText(env.stdout(), env.stderr(), res)
		}
		if res.ExitCode != 0 {
			return errCode(res.ExitCode, nil)
		}
		return nil
	})
}

// --- send ---

// callHistoryEvents reads one chat.history page through gw. Only
// GatewayError/TimeoutError are swallowable by the ack poll; auth
// failures and anything else propagate.
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

func maxSeq(events []any) int64 {
	var max int64
	for _, raw := range events {
		if seq := eventSeq(raw); seq > max {
			max = seq
		}
	}
	return max
}

// eventSeq extracts a numeric seq from a history event, leniently:
// a non-numeric or absent seq reads as 0.
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

// deliverSend sends text on gw and waits for the delivery ack: our
// message.user must show up in history with a seq. It returns
// (user_seq, stream_id); user_seq is nil when no ack arrived within
// ackTimeout. The gateway stays open until the turn is over: closing
// it early can drop the chat.stream request. A sent chat.stream is
// never re-sent. The node_id is sent verbatim with an empty
// capabilities object, exactly as Python's deliver().
func deliverSend(ctx context.Context, gw conn.Gateway, prof *profile.Profile, text, thread string, ackTimeout time.Duration) (*int64, int64, error) {
	baseline := int64(0)
	if events, err := callHistoryEvents(ctx, gw, 1, thread); err == nil {
		baseline = maxSeq(events)
	} else if !swallowableHistoryError(err) {
		return nil, 0, err
	}
	params := map[string]any{
		"items":        []any{map[string]any{"type": "text", "text": text}},
		"node_id":      prof.NodeID,
		"capabilities": map[string]any{},
	}
	if thread != "" {
		params["session_id"] = thread
	}
	// Nobody reads chat.stream's own frames (the turn is followed on
	// chat.subscribe); Track=false drops them at the gateway.
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

// sendBaseJSON is the sent/delivered/user_seq/stream head shared by
// every send result.
type sendBaseJSON struct {
	Sent      bool   `json:"sent"`
	Delivered bool   `json:"delivered"`
	UserSeq   *int64 `json:"user_seq"`
	Stream    int64  `json:"stream"`
}

// sendWaitJSON is the full send result after waiting, in Python's
// key order: head, outcome, status, final_text, replies, approvals?,
// auto_approved?, auto_approve_errors?, widgets?, needs_input_reason?,
// question?, reply?, downloads?, download_error?, note?.
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

// sendNoWaitJSON is the sent-but-not-waited result: head plus an
// optional note (the no-ack case only).
type sendNoWaitJSON struct {
	sendBaseJSON
	Note string `json:"note,omitempty"`
}

func cmdSend(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["send"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, []string{"text"}, "send"); err != nil {
		return usageErr(err)
	}
	toggles, err := parseAutoToggles(p)
	if err != nil {
		return errCode(2, err)
	}
	text := p.positionals[0]
	thread := p.str("thread")
	ackTimeout := time.Duration(p.intVal("ack-timeout")) * time.Second
	return runWaitNetwork(ctx, env, g, func(rt *Runtime, prof *profile.Profile) error {
		// The sending connection stays open until we are done
		// waiting, so the chat.stream request is never torn down
		// mid-turn.
		gw, err := rt.Muse.Connect(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = gw.Close() }()
		userSeq, streamID, err := deliverSend(ctx, gw, prof, text, thread, ackTimeout)
		if err != nil {
			return err
		}
		base := sendBaseJSON{Sent: true, Delivered: userSeq != nil, UserSeq: userSeq, Stream: streamID}
		if userSeq == nil {
			result := sendNoWaitJSON{sendBaseJSON: base}
			result.Note = fmt.Sprintf("no delivery ack within %ds; check `muse-cli history`", int(ackTimeout.Seconds()))
			if err := writeJSON(env.stdout(), result); err != nil {
				return err
			}
			return errCode(5, nil)
		}
		waitSeconds := p.intVal("wait")
		if p.bool("until-done") {
			waitSeconds = 24 * 3600
		}
		if waitSeconds == 0 {
			if err := writeJSON(env.stdout(), sendNoWaitJSON{sendBaseJSON: base}); err != nil {
				return err
			}
			return nil
		}
		// Follow the turn on the connection that sent it
		// (multiplexed): no new connect + Noise handshake per
		// subscription or history read. The heartbeat replaces
		// it if it dies silently, like `wait`'s own.
		res, enabled, err := executeWait(ctx, env, rt, prof, waitRunArgs{
			thread: thread, afterSeq: userSeq, timeout: time.Duration(waitSeconds) * time.Second,
			requireRunning: true, toggles: toggles,
		})
		if err != nil {
			return err
		}
		waitJSON := toWaitResultJSON(res, enabled)
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
		if p.str("download") != "" && len(res.Replies) > 0 {
			if err := sendDownloadStep(ctx, rt, thread, *userSeq, p.str("download"), &result); err != nil {
				return err
			}
		}
		if res.Outcome == "timeout" {
			result.Note = fmt.Sprintf("turn not finished within %ds; run `muse-cli wait --after-seq %d`", waitSeconds, *userSeq)
		}
		if p.bool("text") {
			fmt.Fprintf(env.stdout(), "user_seq=%d\n", *userSeq)
			printWaitText(env.stdout(), env.stderr(), res)
		} else {
			if err := writeJSON(env.stdout(), result); err != nil {
				return err
			}
		}
		if res.ExitCode != 0 {
			return errCode(res.ExitCode, nil)
		}
		return nil
	})
}

// sendDownloadStep downloads the resources referenced by history
// events newer than userSeq into dir, on the shared connection (the
// Go equivalent of Python's fresh connect: multiplexed, no extra
// handshake). A gateway/timeout failure becomes download_error;
// auth failures and cancellation propagate.
func sendDownloadStep(ctx context.Context, rt *Runtime, thread string, userSeq int64, dir string, result *sendWaitJSON) error {
	err := rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
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
		result.DownloadError = redact.String(err.Error())
		return nil
	}
	return nil
}

// --- approvals / approve / deny ---

// pendingApprovals returns the raw egress.approvals result and the
// pending list (pending_approvals, falling back to pending).
func pendingApprovals(ctx context.Context, rt *Runtime) (any, []any, error) {
	v, err := rt.Muse.Call(ctx, "egress.approvals", conn.RequestOptions{})
	if err != nil {
		return nil, nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("gateway: egress.approvals result is not an object: %T", v)
	}
	var pend []any
	// Python `or` semantics: an empty first list falls through
	// to the fallback key (r.get("pending_approvals") or
	// r.get("pending") or []).
	if p, ok := m["pending_approvals"].([]any); ok && len(p) > 0 {
		pend = p
	} else if p, ok := m["pending"].([]any); ok {
		pend = p
	}
	return v, pend, nil
}

func describeApprovals(list []any) []approvalJSON {
	out := make([]approvalJSON, 0, len(list))
	for _, item := range list {
		out = append(out, toApprovalJSON(approvals.DescribeApproval(item)))
	}
	return out
}

// decideApproval is the one call behind approve, deny, approve --all
// and auto-approve. It is never retried by the caller.
func decideApproval(ctx context.Context, rt *Runtime, approvalID, decision string) (any, error) {
	return rt.Muse.Call(ctx, "egress.approval.decide", conn.RequestOptions{
		PathParams: map[string]string{"approval_id": approvalID},
		Body:       map[string]any{"decision": decision},
	})
}

// approveAll decides every currently pending approval with
// decision, skipping approvals with no forever option when the
// decision is allow_always. It prints one stderr line per approval,
// mirroring Python's approve_all.
func approveAll(ctx context.Context, env *Env, rt *Runtime, decision string) ([]approvedJSON, error) {
	_, pend, err := pendingApprovals(ctx, rt)
	if err != nil {
		return nil, err
	}
	done := []approvedJSON{}
	for _, item := range pend {
		d := approvals.DescribeApproval(item)
		if decision == approvals.Forever && !approvals.OffersForever(d) {
			fmt.Fprintf(env.stderr(), "skipped %s: no forever option %v\n", derefStr(d.ApprovalID), d.Options)
			continue
		}
		if _, err := decideApproval(ctx, rt, derefStr(d.ApprovalID), decision); err != nil {
			return nil, err
		}
		row := approvedJSON{
			ApprovalID: strPtrOrNil(derefStr(d.ApprovalID)), Title: strPtrOrNil(derefStr(d.Title)),
			Kind: strPtrOrNil(derefStr(d.Kind)), Scope: strPtrOrNil(derefStr(d.Scope)), Decision: strPtrOrNil(decision),
		}
		done = append(done, row)
		fmt.Fprintf(env.stderr(), "approved %s (%s): %s [%s %s]\n", derefStr(row.ApprovalID), decision, derefStr(row.Title), derefStr(row.Kind), derefStr(row.Scope))
	}
	return done, nil
}

type approvalsJSON struct {
	Pending []approvalJSON `json:"pending"`
	Recent  *[]recentJSON  `json:"recent,omitempty"`
}

type recentJSON struct {
	approvalJSON
	Decision any `json:"decision"`
}

// approvedListJSON is the {"approved": [...]} result of approve
// --all and approvals --approve-all.
type approvedListJSON struct {
	Approved []approvedJSON `json:"approved"`
}

func cmdApprovals(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["approvals"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "approvals"); err != nil {
		return usageErr(err)
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		if p.bool("approve-all") {
			done, err := approveAll(ctx, env, rt, approvals.Forever)
			if err != nil {
				return err
			}
			return writeJSON(env.stdout(), approvedListJSON{Approved: done})
		}
		raw, pend, err := pendingApprovals(ctx, rt)
		if err != nil {
			return err
		}
		if p.bool("raw") {
			return writeJSON(env.stdout(), raw)
		}
		out := approvalsJSON{Pending: describeApprovals(pend)}
		if p.bool("recent") {
			m, _ := raw.(map[string]any)
			var recent []any
			if r, ok := m["recent_approvals"].([]any); ok && len(r) > 0 {
				recent = r
			} else if r, ok := m["recent"].([]any); ok {
				recent = r
			}
			rows := []recentJSON{}
			for _, item := range recent {
				d := approvals.DescribeApproval(item)
				decision := any(nil)
				if row, ok := item.(map[string]any); ok {
					decision = row["decision"]
				}
				rows = append(rows, recentJSON{approvalJSON: toApprovalJSON(d), Decision: decision})
			}
			out.Recent = &rows
		}
		return writeJSON(env.stdout(), out)
	})
}

func approveDecision(p *parsed) (string, error) {
	var seen string
	count := 0
	decision := "allow_once"
	for _, k := range []string{"once", "session", "today", "always"} {
		if p.bool(k) {
			count++
			if count == 1 {
				seen = k
				decision = "allow_" + k
			} else {
				return "", fmt.Errorf("argument --%s: not allowed with argument --%s", k, seen)
			}
		}
	}
	return decision, nil
}

func cmdApprove(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["approve"], args, env)
	if err != nil {
		return err
	}
	if len(p.positionals) > 1 {
		return usageErr(&parserError{msg: fmt.Sprintf("unrecognized arguments: %s", strings.Join(p.positionals[1:], " "))})
	}
	decision, err := approveDecision(p)
	if err != nil {
		return errCode(2, err)
	}
	id := ""
	if len(p.positionals) == 1 {
		id = p.positionals[0]
	}
	if p.bool("all") == (id != "") {
		return errCode(2, errors.New("give an approval ID or --all (not both)"))
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		if p.bool("all") {
			done, err := approveAll(ctx, env, rt, decision)
			if err != nil {
				return err
			}
			return writeJSON(env.stdout(), approvedListJSON{Approved: done})
		}
		res, err := decideApproval(ctx, rt, id, decision)
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), res)
	})
}

func cmdDeny(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["deny"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, []string{"id"}, "deny"); err != nil {
		return usageErr(err)
	}
	decision := "deny"
	if p.bool("always") {
		decision = "deny_always"
	}
	id := p.positionals[0]
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		res, err := decideApproval(ctx, rt, id, decision)
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), res)
	})
}

// --- auto-approve ---

type autoApproveStatusJSON struct {
	AutoApprove   string  `json:"auto_approve"`
	Source        string  `json:"source"`
	Config        string  `json:"config"`
	Env           *string `json:"env"`
	AutoAllowOnce bool    `json:"auto_allow_once"`
	OnceSource    string  `json:"once_source"`
	OnceConfig    bool    `json:"once_config"`
	OnceEnv       *string `json:"once_env"`
}

func cmdAutoApprove(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["auto-approve"], args, env)
	if err != nil {
		return err
	}
	if len(p.positionals) > 2 {
		return usageErr(&parserError{msg: fmt.Sprintf("unrecognized arguments: %s", strings.Join(p.positionals[2:], " "))})
	}
	state := "status"
	onceState := ""
	if len(p.positionals) >= 1 {
		state = p.positionals[0]
	}
	if len(p.positionals) == 2 {
		onceState = p.positionals[1]
	}
	switch state {
	case "on", "always", "off", "status", "once":
	default:
		return errCode(2, fmt.Errorf("argument state: invalid choice: %q (choose from on, always, off, status, once)", state))
	}
	switch onceState {
	case "", "on", "off", "status":
	default:
		return errCode(2, fmt.Errorf("argument once_state: invalid choice: %q (choose from on, off, status)", onceState))
	}
	if onceState != "" && state != "once" {
		return errCode(2, fmt.Errorf("unexpected %q: use `auto-approve once on|off|status`", onceState))
	}
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	prof, err := resolveActive(loc, g, env)
	if err != nil {
		return err
	}
	getenv := env.lookupEnv
	switch {
	case state == "on" || state == "always":
		if _, err := profile.SetAutoApprove(loc.ConfigDir, prof.Name, "always"); err != nil {
			return err
		}
	case state == "off":
		if _, err := profile.SetAutoApprove(loc.ConfigDir, prof.Name, "off"); err != nil {
			return err
		}
	case state == "once" && (onceState == "on" || onceState == "off"):
		if _, err := profile.SetAutoAllowOnce(loc.ConfigDir, prof.Name, onceState == "on"); err != nil {
			return err
		}
	}
	// Re-read the profile so the status reflects the just-written
	// toggles (and any env override, which wins for display).
	prof, err = profile.LoadProfile(loc.ConfigDir, prof.Name, getenv)
	if err != nil {
		return err
	}
	enabled, err := profile.ResolveAutoApprove(prof, nil, getenv)
	if err != nil {
		return err
	}
	onceEnabled, err := profile.ResolveAutoAllowOnce(prof, nil, getenv)
	if err != nil {
		return err
	}
	display := "off"
	if enabled.Enabled {
		display = "always"
	}
	configVal := prof.AutoApprove
	if configVal == "" {
		configVal = "off"
	}
	status := autoApproveStatusJSON{
		AutoApprove:   display,
		Source:        enabled.Source,
		Config:        configVal,
		AutoAllowOnce: onceEnabled.Enabled,
		OnceSource:    onceEnabled.Source,
		OnceConfig:    prof.AutoAllowOnce,
	}
	if v, ok := getenv("MUSE_AUTO_APPROVE"); ok {
		status.Env = &v
	}
	if v, ok := getenv("MUSE_AUTO_ALLOW_ONCE"); ok {
		status.OnceEnv = &v
	}
	return writeJSON(env.stdout(), status)
}
