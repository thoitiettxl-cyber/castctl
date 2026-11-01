// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// Approval-wiring tests: the gateway decider adapter, the
// pending-approvals read, the /approvals + /autoapprove command
// handlers, and the auto-approve turn path — all against the
// scripted fake gateway and fake Telegram server. No live
// network.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
)

// approvalFixture is one server approval dict in the shape
// approvals.DescribeApproval reads.
func approvalFixture(id, title string, options ...string) map[string]any {
	var opts []any
	for _, o := range options {
		opts = append(opts, map[string]any{"kind": o})
	}
	return map[string]any{
		"approval_id": id,
		"display": map[string]any{
			"summary_title": title,
			"permission_question": map[string]any{
				"text":  "Allow " + title + "?",
				"kind":  "shell",
				"scope": "example.com",
			},
			"short_explanation": "test approval",
		},
		"decision_options": opts,
	}
}

func TestGatewayDeciderDecidesOnce(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	muse := conn.New(func(context.Context, conn.Config) (conn.Gateway, error) { return gw, nil })
	d := gatewayDecider{muse: muse}
	if err := d.Decide(context.Background(), "A1", "allow_always"); err != nil {
		t.Fatalf("Decide = %v", err)
	}
	calls := gw.decideHistory()
	if len(calls) != 1 || calls[0] != (decideRecord{approvalID: "A1", decision: "allow_always"}) {
		t.Fatalf("decide calls = %+v, want one A1/allow_always", calls)
	}
	// A decision failure propagates unwrapped-typed, with no
	// retry: the approval stays undecided, never approved.
	gwErr := &conn.GatewayError{Status: 502, Payload: "bad gateway"}
	gw.decideErr = gwErr
	err := d.Decide(context.Background(), "A2", "allow_once")
	var got *conn.GatewayError
	if !errors.As(err, &got) {
		t.Fatalf("Decide error = %v (%T), want *conn.GatewayError", err, err)
	}
	if len(gw.decideHistory()) != 1 {
		t.Errorf("decide calls = %d, want 1 (no retry on failure)", len(gw.decideHistory()))
	}
	// An auth failure passes through typed as well.
	gw.decideErr = &conn.AuthError{Message: "expired"}
	err = d.Decide(context.Background(), "A3", "allow_once")
	var authErr *conn.AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("Decide error = %v (%T), want *conn.AuthError", err, err)
	}
}

func TestTelegramPendingApprovals(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.approvalsScript = []any{
		approvalFixture("A1", "Run tests", "allow_always", "allow_once"),
		approvalFixture("A2", "Read file", "allow_once"),
	}
	muse := conn.New(func(context.Context, conn.Config) (conn.Gateway, error) { return gw, nil })
	rt := &Runtime{Muse: muse}
	pend, err := telegramPendingApprovals(context.Background(), rt)
	if err != nil {
		t.Fatal(err)
	}
	if len(pend) != 2 {
		t.Fatalf("pending = %d, want 2", len(pend))
	}
	if pend[0].ID != "A1" || pend[0].Title != "Run tests" || pend[0].Question != "Allow Run tests?" ||
		pend[0].Kind != "shell" || pend[0].Scope != "example.com" || pend[0].Why != "test approval" ||
		len(pend[0].Options) != 2 || pend[0].Options[0] != "allow_always" {
		t.Errorf("first approval = %+v", pend[0])
	}
	if len(pend[1].Options) != 1 || pend[1].Options[0] != "allow_once" {
		t.Errorf("second approval options = %v", pend[1].Options)
	}
	// The "pending" fallback key is honoured when
	// "pending_approvals" is absent.
	gw.approvalsFallback = true
	pend, err = telegramPendingApprovals(context.Background(), rt)
	if err != nil || len(pend) != 2 {
		t.Fatalf("fallback pending = %d, err = %v", len(pend), err)
	}
	// An empty list is empty, not an error.
	gw.approvalsScript = nil
	pend, err = telegramPendingApprovals(context.Background(), rt)
	if err != nil || len(pend) != 0 {
		t.Fatalf("empty pending = %d, err = %v", len(pend), err)
	}
}

// approvalHarness builds a command handler over a fake Bot +
// fake gateway for direct handler tests (dispatch lands in A4).
type approvalHarness struct {
	handler *telegramCmdHandler
	fake    *cmdFakeTelegram
	gw      *telegramTurnFakeGateway
	store   *telegram.StateStore
	dir     string
}

func newApprovalHarness(t *testing.T, gw *telegramTurnFakeGateway) *approvalHarness {
	t.Helper()
	fake := &cmdFakeTelegram{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	t.Cleanup(srv.Close)
	fakeAddr := srv.Listener.Addr().String()
	dialFake := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, fakeAddr)
	}
	fakeClient := &http.Client{Transport: &http.Transport{
		Proxy:       nil,
		DialContext: dialFake,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialFake(ctx, network, addr)
		},
	}}
	bot, err := telegram.New(telegram.Settings{
		Token:          telegramTestToken,
		AllowedUserIDs: []int64{111},
		HTTPClient:     fakeClient,
		Logger:         slog.Default(),
	})
	if err != nil {
		t.Fatal(err)
	}
	storeDir := t.TempDir()
	store, _, err := telegram.LoadStateStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	muse := conn.New(func(context.Context, conn.Config) (conn.Gateway, error) { return gw, nil })
	rt := &Runtime{Muse: muse}
	toggles := func() (bool, bool) {
		aa, ao, _ := store.Toggles()
		approve, allowOnce := false, false
		if aa != nil {
			approve = *aa
		}
		if ao != nil {
			allowOnce = *ao
		}
		return approve, allowOnce
	}
	runner := newTelegramTurnRunner(telegramTurnDeps{
		env:     &Env{},
		bot:     bot,
		rt:      rt,
		prof:    &profile.Profile{NodeID: "node-1"},
		store:   store,
		logger:  slog.Default(),
		toggles: toggles,
	})
	h := &telegramCmdHandler{
		env:     &Env{},
		bot:     bot,
		rt:      rt,
		prof:    &profile.Profile{NodeID: "node-1"},
		store:   store,
		runner:  runner,
		toggles: toggles,
		logger:  slog.Default(),
	}
	return &approvalHarness{handler: h, fake: fake, gw: gw, store: store, dir: storeDir}
}

func TestApprovalsCommandListsWithButtons(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.approvalsScript = []any{
		approvalFixture("A1", "Run tests", "allow_always", "allow_once"),
		approvalFixture("A2", "Read file", "allow_once"),
	}
	h := newApprovalHarness(t, gw)
	if err := h.handler.approvals(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	h.fake.mu.Lock()
	sends := append([]string(nil), h.fake.sends...)
	markups := append([]bool(nil), h.fake.sendMarkups...)
	h.fake.mu.Unlock()
	if len(sends) != 3 {
		t.Fatalf("sends = %q, want 2 approvals + approve-all", sends)
	}
	if !strings.Contains(sends[0], "Run tests") || !strings.Contains(sends[1], "Read file") {
		t.Errorf("sends = %q", sends)
	}
	if !markups[0] || !markups[1] {
		t.Errorf("sendMarkups = %v, want decide buttons on both approvals", markups)
	}
	if sends[2] != "Or decide them all:" || !markups[2] {
		t.Errorf("third send = %q markup=%v, want approve-all prompt with buttons", sends[2], markups[2])
	}
	// A single approval gets no approve-all message.
	gw.approvalsScript = gw.approvalsScript[:1]
	h.fake.mu.Lock()
	h.fake.sends = nil
	h.fake.sendMarkups = nil
	h.fake.mu.Unlock()
	if err := h.handler.approvals(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	h.fake.mu.Lock()
	n := len(h.fake.sends)
	h.fake.mu.Unlock()
	if n != 1 {
		t.Errorf("single-approval sends = %d, want 1", n)
	}
}

func TestApprovalsCommandEmptyAndFailure(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h := newApprovalHarness(t, gw)
	if err := h.handler.approvals(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	sends := append([]string(nil), h.fake.sends...)
	if len(sends) != 1 || sends[0] != "No pending approvals. Auto-approve is off." {
		t.Errorf("empty sends = %q", sends)
	}
	// Auto-approve on changes the empty report.
	if err := h.store.SetToggles(true, false); err != nil {
		t.Fatal(err)
	}
	h.fake.mu.Lock()
	h.fake.sends = nil
	h.fake.mu.Unlock()
	if err := h.handler.approvals(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	sends = append([]string(nil), h.fake.sends...)
	if len(sends) != 1 || sends[0] != "No pending approvals. Auto-approve is on (always)." {
		t.Errorf("empty-on sends = %q", sends)
	}
	// A gateway failure gets the fixed reply, never error text.
	gw.approvalsErr = errors.New("gateway exploded")
	h.fake.mu.Lock()
	h.fake.sends = nil
	h.fake.mu.Unlock()
	if err := h.handler.approvals(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	sends = append([]string(nil), h.fake.sends...)
	if len(sends) != 1 || sends[0] != "⚠️ Could not list approvals (gateway error)." {
		t.Errorf("failure sends = %q", sends)
	}
}

func TestAutoApproveCommandForms(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h := newApprovalHarness(t, gw)
	ctx := context.Background()
	lastSend := func() string {
		h.fake.mu.Lock()
		defer h.fake.mu.Unlock()
		if len(h.fake.sends) == 0 {
			return ""
		}
		return h.fake.sends[len(h.fake.sends)-1]
	}
	clearSends := func() {
		h.fake.mu.Lock()
		h.fake.sends = nil
		h.fake.mu.Unlock()
	}
	toggleState := func() (aa, ao *bool) {
		aa, ao, _ = h.store.Toggles()
		return aa, ao
	}

	// Bare = report only, no write.
	if err := h.handler.autoApprove(ctx, 500, ""); err != nil {
		t.Fatal(err)
	}
	if got := lastSend(); got != "Auto-approve is <b>off</b>: approvals come here with buttons." {
		t.Errorf("bare report = %q", got)
	}
	if aa, _ := toggleState(); aa != nil {
		t.Error("bare /autoapprove wrote state")
	}
	// "on": sets, reports, no fallback sentence while
	// allow-once is off.
	clearSends()
	if err := h.handler.autoApprove(ctx, 500, "on"); err != nil {
		t.Fatal(err)
	}
	if got := lastSend(); got != "✅ Auto-approve is <b>on</b>: every approval gets Muse's forever choice (allow_always), so Muse never blocks." {
		t.Errorf("on report = %q", got)
	}
	if aa, ao := toggleState(); aa == nil || !*aa || ao == nil || *ao {
		t.Errorf("state after on = (%v,%v), want (true,false)", aa, ao)
	}
	// "once on": sets only the fallback; the other toggle is
	// carried over untouched.
	clearSends()
	if err := h.handler.autoApprove(ctx, 500, "once on"); err != nil {
		t.Fatal(err)
	}
	want := "Auto-allow-once is <b>on</b>: approvals with no forever option are decided with allow_once when auto-approve is on. Auto-approve is <b>on</b>."
	if got := lastSend(); got != want {
		t.Errorf("once-on report = %q, want %q", got, want)
	}
	if aa, ao := toggleState(); aa == nil || !*aa || ao == nil || !*ao {
		t.Errorf("state after once-on = (%v,%v), want (true,true)", aa, ao)
	}
	// The fallback sentence now appears in the main report.
	clearSends()
	if err := h.handler.autoApprove(ctx, 500, "status"); err != nil {
		t.Fatal(err)
	}
	want = "✅ Auto-approve is <b>on</b>: every approval gets Muse's forever choice (allow_always), so Muse never blocks. Approvals with no forever option fall back to allow_once."
	if got := lastSend(); got != want {
		t.Errorf("status report = %q, want %q", got, want)
	}
	// "always" is accepted as "on"; case-insensitive.
	clearSends()
	if err := h.handler.autoApprove(ctx, 500, "OFF"); err != nil {
		t.Fatal(err)
	}
	if got := lastSend(); got != "Auto-approve is <b>off</b>: approvals come here with buttons." {
		t.Errorf("off report = %q", got)
	}
	// Invalid forms: usage, no write.
	clearSends()
	if err := h.handler.autoApprove(ctx, 500, "bogus"); err != nil {
		t.Fatal(err)
	}
	if got := lastSend(); got != "Usage: /autoapprove on|off|status" {
		t.Errorf("bogus report = %q", got)
	}
	if err := h.handler.autoApprove(ctx, 500, "on extra"); err != nil {
		t.Fatal(err)
	}
	if got := lastSend(); got != "Usage: /autoapprove on|off|status" {
		t.Errorf("on-extra report = %q", got)
	}
	if err := h.handler.autoApprove(ctx, 500, "once bogus"); err != nil {
		t.Fatal(err)
	}
	if got := lastSend(); got != "Usage: /autoapprove once on|off|status" {
		t.Errorf("once-bogus report = %q", got)
	}
	// The toggles survive a store reload (restart persistence).
	aa, ao, _ := h.store.Toggles()
	if aa == nil || *aa || ao == nil || !*ao {
		t.Fatalf("state before reload = (%v,%v), want (false,true)", boolVal(aa), boolVal(ao))
	}
	reloaded, _, err := telegram.LoadStateStore(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	raa, rao, _ := reloaded.Toggles()
	if raa == nil || *raa || rao == nil || !*rao {
		t.Errorf("reloaded toggles = (%v,%v), want (false,true)", raa, rao)
	}
}

func boolVal(p *bool) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestTurnAutoApproveDecidesWithoutButton(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	approvalJSON, err := json.Marshal(approvalFixture("A1", "Run tests", "allow_always", "allow_once"))
	if err != nil {
		t.Fatal(err)
	}
	gw.subScripts = []turnSubScript{{
		replyText:       "Done",
		deltas:          []string{"Do"},
		approvalRecords: []string{fmt.Sprintf(`{"event":"approvals.snapshot","payload":{"pending_approvals":[%s]}}`, approvalJSON)},
	}}
	// auto_approve:true in telegramTestConfig: the turn's
	// approver must decide without any button press.
	h, cancel, codeCh := runTelegramBot(t, gw, []string{telegramUpdate(1, 111, "run tests")})
	defer cancel()
	waitFor(t, "final edit", func() bool {
		for _, e := range h.fake.editTexts() {
			if strings.Contains(e, "Done") {
				return true
			}
		}
		return false
	})
	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run code = %d; want 130", code)
	}
	calls := gw.decideHistory()
	if len(calls) != 1 || calls[0] != (decideRecord{approvalID: "A1", decision: "allow_always"}) {
		t.Fatalf("decide calls = %+v, want one A1/allow_always without a button press", calls)
	}
	// The auto-approval is noted in the delivered reply.
	noted := false
	for _, e := range h.fake.editTexts() {
		if strings.Contains(e, "auto-approved (always)") && strings.Contains(e, "Run tests") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("edits = %q; want the auto-approval note", h.fake.editTexts())
	}
}

func TestTurnAutoApproveOffSurfacesApprovalButtons(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	approvalJSON, err := json.Marshal(approvalFixture("A1", "Run tests", "allow_always", "allow_once"))
	if err != nil {
		t.Fatal(err)
	}
	gw.subScripts = []turnSubScript{{
		replyText:       "Waiting",
		deltas:          []string{"Wa"},
		approvalRecords: []string{fmt.Sprintf(`{"event":"approvals.snapshot","payload":{"pending_approvals":[%s]}}`, approvalJSON)},
	}}
	// Direct runner with toggles off: the approval must NOT be
	// decided; the turn ends needs_approval with buttons.
	runner, fake := directTurnRunner(t, gw, 5*time.Second)
	if err := runner.runTextTurn(context.Background(), 500, "run tests"); err != nil {
		t.Fatal(err)
	}
	if len(gw.decideHistory()) != 0 {
		t.Fatalf("decide calls = %+v, want none with auto-approve off", gw.decideHistory())
	}
	edits := fake.editTexts()
	if len(edits) == 0 {
		t.Fatal("no edits")
	}
	last := edits[len(edits)-1]
	if !strings.Contains(last, "🔐 Approval: Run tests") {
		t.Errorf("last edit = %q; want the approval note", last)
	}
	fake.mu.Lock()
	markups := append([]bool(nil), fake.editMarkups...)
	fake.mu.Unlock()
	if len(markups) == 0 || !markups[len(markups)-1] {
		t.Errorf("editMarkups = %v; want buttons on the final edit", markups)
	}
}

func TestCallbackApproveAllThroughBot(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.approvalsScript = []any{
		approvalFixture("A1", "Run tests", "allow_always", "allow_once"),
		approvalFixture("A2", "Read file", "allow_once"),
	}
	// A real Bot with the A3 wiring, driven by a callback_query
	// update through the fake server.
	fake := &cmdFakeTelegram{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	fakeAddr := srv.Listener.Addr().String()
	dialFake := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, fakeAddr)
	}
	fakeClient := &http.Client{Transport: &http.Transport{
		Proxy:       nil,
		DialContext: dialFake,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialFake(ctx, network, addr)
		},
	}}
	muse := conn.New(func(context.Context, conn.Config) (conn.Gateway, error) { return gw, nil })
	rt := &Runtime{Muse: muse}
	bot, err := telegram.New(telegram.Settings{
		Token:          telegramTestToken,
		AllowedUserIDs: []int64{111},
		HTTPClient:     fakeClient,
		Logger:         slog.Default(),
		Decider:        gatewayDecider{muse: muse},
		Pending: func(ctx context.Context) ([]telegram.Approval, error) {
			return telegramPendingApprovals(ctx, rt)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	data := bot.Registry().Register(telegram.CallbackEntry{Action: "approve_all"})
	cbUpdate := fmt.Sprintf(`{"ok":true,"result":[{"update_id":9,"callback_query":{"id":"q1","from":{"id":111,"is_bot":false,"first_name":"Tester"},"message":{"message_id":50,"chat":{"id":500,"type":"private"},"text":"Or decide them all:"},"data":%q}}]}`, data)
	fake.batches = []string{cbUpdate}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = bot.Start(ctx); close(done) }()
	waitFor(t, "approve-all confirm", func() bool {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		for _, s := range fake.sends {
			if strings.Contains(s, "Always allowed") {
				return true
			}
		}
		return false
	})
	cancel()
	<-done
	calls := gw.decideHistory()
	if len(calls) != 1 || calls[0] != (decideRecord{approvalID: "A1", decision: "allow_always"}) {
		t.Fatalf("decide calls = %+v, want only the forever-offering A1", calls)
	}
	fake.mu.Lock()
	sends := append([]string(nil), fake.sends...)
	fake.mu.Unlock()
	found := false
	for _, s := range sends {
		if strings.Contains(s, "Always allowed") && strings.Contains(s, "Run tests") {
			found = true
		}
	}
	if !found {
		t.Errorf("sends = %q; want the approve-all confirm naming Run tests", sends)
	}
}

// TestCallbackDecideSingleFlight is the R1 acceptance test:
// two callback updates with identical callback data and
// distinct update_ids (double-tap / redelivery / two users)
// must issue exactly ONE Decide RPC; the second tap takes
// the expired path (no second confirm, no warning).
func TestCallbackDecideSingleFlight(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	muse := conn.New(func(context.Context, conn.Config) (conn.Gateway, error) { return gw, nil })
	rt := &Runtime{Muse: muse}
	fake := &cmdFakeTelegram{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	fakeAddr := srv.Listener.Addr().String()
	dialFake := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, fakeAddr)
	}
	fakeClient := &http.Client{Transport: &http.Transport{
		Proxy:       nil,
		DialContext: dialFake,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialFake(ctx, network, addr)
		},
	}}
	bot, err := telegram.New(telegram.Settings{
		Token:          telegramTestToken,
		AllowedUserIDs: []int64{111},
		HTTPClient:     fakeClient,
		Logger:         slog.Default(),
		Decider:        gatewayDecider{muse: muse},
		Pending: func(ctx context.Context) ([]telegram.Approval, error) {
			return telegramPendingApprovals(ctx, rt)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	data := bot.Registry().Register(telegram.CallbackEntry{Action: "decide", ApprovalID: "A1", Decision: "allow_always"})
	cb := func(updateID int64, queryID string) string {
		return fmt.Sprintf(`{"update_id":%d,"callback_query":{"id":%q,"from":{"id":111,"is_bot":false,"first_name":"Tester"},"message":{"message_id":50,"chat":{"id":500,"type":"private"},"text":"Approval"},"data":%q}}`, updateID, queryID, data)
	}
	fake.batches = []string{`{"ok":true,"result":[` + cb(9, "q1") + `,` + cb(10, "q2") + `]}`}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = bot.Start(ctx); close(done) }()
	waitFor(t, "decide confirm", func() bool {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		for _, s := range fake.sends {
			if strings.Contains(s, "Always allowed") {
				return true
			}
		}
		return false
	})
	// Both updates share chat 500, so one dispatcher worker
	// handles them in order; wait for the second tap's
	// callback answer (the expired answer) instead of a
	// fixed sleep, so the counts are asserted only after
	// both taps were processed.
	waitFor(t, "second tap answered", func() bool {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		n := 0
		for _, m := range fake.methods {
			if m == "answerCallbackQuery" {
				n++
			}
		}
		return n >= 2
	})
	cancel()
	<-done
	if calls := gw.decideHistory(); len(calls) != 1 || calls[0] != (decideRecord{approvalID: "A1", decision: "allow_always"}) {
		t.Fatalf("decide calls = %+v, want exactly one", calls)
	}
	fake.mu.Lock()
	sends := append([]string(nil), fake.sends...)
	fake.mu.Unlock()
	confirms, warnings := 0, 0
	for _, s := range sends {
		if strings.Contains(s, "Always allowed") {
			confirms++
		}
		if strings.Contains(s, "⚠️") {
			warnings++
		}
	}
	if confirms != 1 {
		t.Errorf("confirms = %d, sends = %q; want exactly one decide confirm", confirms, sends)
	}
	if warnings != 0 {
		t.Errorf("warnings = %d, sends = %q; want none (second tap takes the expired answer)", warnings, sends)
	}
}
