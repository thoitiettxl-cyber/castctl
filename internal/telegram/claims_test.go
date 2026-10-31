// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

// Claims and notify tests: the allow_once / claim / notified
// state machine mirrored from src/muse_cli/tgbot.py:1505-1701.
// All state is in-memory; the restart-loss case is proven by
// constructing a second Bot on the same fake server and showing
// it re-decides an id the first bot already decided.

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func foreverApproval(id string) Approval {
	return Approval{ID: id, Title: "T-" + id, Options: []string{"allow_always", "allow_once", "deny"}}
}

func onceOnlyApproval(id string) Approval {
	return Approval{ID: id, Title: "T-" + id, Options: []string{"allow_once", "deny"}}
}

func denyOnlyApproval(id string) Approval {
	return Approval{ID: id, Title: "T-" + id, Options: []string{"deny"}}
}

func TestApproveForeverConcurrentDecidesOnce(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, func(s *Settings) { s.AutoApprove = true })
	tb.decider.block = make(chan struct{})
	a := foreverApproval("appr-1")
	done1 := make(chan []string, 1)
	done2 := make(chan []string, 1)
	go func() { done1 <- tb.bot.ApproveForever(context.Background(), []Approval{a}) }()
	// The first call takes the claim and blocks inside Decide.
	time.Sleep(100 * time.Millisecond)
	// The second call awaits the claim. The first settles
	// before the 100ms claim wait expires, so the second
	// must see the decision and not decide again.
	go func() { done2 <- tb.bot.ApproveForever(context.Background(), []Approval{a}) }()
	time.Sleep(50 * time.Millisecond)
	close(tb.decider.block)
	got1 := <-done1
	got2 := <-done2
	if len(tb.decider.recorded()) != 1 {
		t.Fatalf("decider calls = %d; want 1 (concurrent callers share one claim)", len(tb.decider.recorded()))
	}
	if len(got1) != 1 || len(got2) != 1 {
		t.Errorf("done lists = %v, %v; want both [appr-1]", got1, got2)
	}
}

func TestApproveForeverFailedDecideReleasesClaim(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, func(s *Settings) { s.AutoApprove = true })
	tb.decider.err = errDecideFail
	if got := tb.bot.ApproveForever(context.Background(), []Approval{foreverApproval("appr-2")}); len(got) != 0 {
		t.Errorf("done = %v after failed decide; want empty", got)
	}
	// The claim was released: a retry with a working decider
	// decides the id.
	tb.decider.err = nil
	if got := tb.bot.ApproveForever(context.Background(), []Approval{foreverApproval("appr-2")}); len(got) != 1 {
		t.Errorf("retry done = %v; want [appr-2] (claim released)", got)
	}
	if len(tb.decider.recorded()) != 2 {
		t.Errorf("decider calls = %d; want 2 (failed + retry)", len(tb.decider.recorded()))
	}
}

func TestApproveForeverAlreadyDecidedSkipsDecider(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, func(s *Settings) { s.AutoApprove = true })
	a := foreverApproval("appr-3")
	if got := tb.bot.ApproveForever(context.Background(), []Approval{a}); len(got) != 1 {
		t.Fatalf("first done = %v", got)
	}
	if got := tb.bot.ApproveForever(context.Background(), []Approval{a}); len(got) != 1 {
		t.Errorf("second done = %v; want [appr-3] from the decided set", got)
	}
	if len(tb.decider.recorded()) != 1 {
		t.Errorf("decider calls = %d; want 1 (decided ids are not re-decided)", len(tb.decider.recorded()))
	}
}

func TestApproveForeverToggleOffSkipsOnceOnly(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	// Auto-approve on, allow-once toggle off: a once-only
	// approval is not decided (tgbot.py:163-164, 2009-2052).
	tb := newTestBot(t, srv, func(s *Settings) { s.AutoApprove = true; s.AutoAllowOnce = false })
	if got := tb.bot.ApproveForever(context.Background(), []Approval{onceOnlyApproval("appr-4")}); len(got) != 0 {
		t.Errorf("done = %v with the toggle off; want empty", got)
	}
	if len(tb.decider.recorded()) != 0 {
		t.Errorf("decider calls = %d; want 0", len(tb.decider.recorded()))
	}
	// Toggle on: the same approval is decided allow_once.
	tb.bot.AutoAllowOnce = true
	if got := tb.bot.ApproveForever(context.Background(), []Approval{onceOnlyApproval("appr-4")}); len(got) != 1 {
		t.Errorf("done = %v with the toggle on; want [appr-4]", got)
	}
	calls := tb.decider.recorded()
	if len(calls) != 1 || calls[0].Decision != DecisionOnce {
		t.Errorf("decider calls = %+v; want one allow_once", calls)
	}
}

func TestApproveForeverDenyOnlyWarnsOnce(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, func(s *Settings) { s.AutoApprove = true })
	a := denyOnlyApproval("appr-5")
	_ = tb.bot.ApproveForever(context.Background(), []Approval{a})
	_ = tb.bot.ApproveForever(context.Background(), []Approval{a})
	if len(tb.decider.recorded()) != 0 {
		t.Errorf("decider calls = %d; want 0 (no forever option)", len(tb.decider.recorded()))
	}
	// The warned-once rule: exactly one warning line.
	warns := 0
	for _, line := range strings.Split(tb.logBuf.String(), "\n") {
		if strings.Contains(line, "offers no forever option") {
			warns++
		}
	}
	if warns != 1 {
		t.Errorf("warn lines = %d; want 1 (warned_no_forever)", warns)
	}
}

func TestClaimTakeoverAfterShortWait(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, func(s *Settings) {
		s.AutoApprove = true
		s.ClaimWait = 50 * time.Millisecond
	})
	tb.decider.block = make(chan struct{})
	a := foreverApproval("appr-6")
	firstDone := make(chan []string, 1)
	go func() { firstDone <- tb.bot.ApproveForever(context.Background(), []Approval{a}) }()
	// Let the first call take the claim and block in Decide.
	time.Sleep(100 * time.Millisecond)
	secondDone := make(chan []string, 1)
	go func() { secondDone <- tb.bot.ApproveForever(context.Background(), []Approval{a}) }()
	// The second caller waits ClaimWait, takes over, and
	// blocks in Decide behind the same gate; releasing the
	// gate lets both Decide calls return, and the late first
	// caller records nothing.
	time.Sleep(200 * time.Millisecond)
	close(tb.decider.block)
	second := <-secondDone
	if len(second) != 1 || second[0] != "appr-6" {
		t.Errorf("takeover done = %v; want [appr-6]", second)
	}
	first := <-firstDone
	if len(first) != 0 {
		t.Errorf("superseded first done = %v; want empty (late owner records nothing)", first)
	}
	if len(tb.decider.recorded()) != 2 {
		t.Errorf("decider calls = %d; want 2 (blocked first + takeover)", len(tb.decider.recorded()))
	}
}

func TestNotifyPendingAutoApproveNotifiesOnce(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, func(s *Settings) { s.AutoApprove = true })
	items := []Approval{foreverApproval("appr-7"), onceOnlyApproval("appr-8")}
	// Toggle off: only the forever approval is auto-decided.
	if err := tb.bot.NotifyPending(context.Background(), 500, items); err != nil {
		t.Fatal(err)
	}
	calls := tb.decider.recorded()
	if len(calls) != 1 || calls[0].Decision != DecisionForever {
		t.Fatalf("decider calls = %+v; want one allow_always", calls)
	}
	sends := srv.callsOf("sendMessage")
	notify := 0
	buttons := 0
	for _, c := range sends {
		if strings.Contains(c.Form["text"], "✅ Auto-approved (always)") {
			notify++
		}
		if strings.Contains(c.Form["text"], "Approval") || strings.Contains(c.Form["text"], "T-appr-8") {
			buttons++
		}
	}
	if notify != 1 {
		t.Errorf("auto-approved notifies = %d; want 1", notify)
	}
	if buttons != 1 {
		t.Errorf("button sends = %d; want 1 (the once-only approval as buttons)", buttons)
	}
	// A second call notifies nothing: notified dedupe.
	before := srv.count("sendMessage")
	if err := tb.bot.NotifyPending(context.Background(), 500, items); err != nil {
		t.Fatal(err)
	}
	if got := srv.count("sendMessage"); got != before {
		t.Errorf("sendMessage calls grew %d -> %d; want no re-notify", before, got)
	}
}

func TestNotifyPendingActiveTurnSendsNothing(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, func(s *Settings) { s.AutoApprove = true })
	tb.bot.BeginTurn(500)
	items := []Approval{foreverApproval("appr-9")}
	if err := tb.bot.NotifyPending(context.Background(), 500, items); err != nil {
		t.Fatal(err)
	}
	// Decisions are recorded (ApproveForever ran) but nothing
	// is sent while a turn runs.
	if len(tb.decider.recorded()) != 1 {
		t.Fatalf("decider calls = %d; want 1 (decision still recorded)", len(tb.decider.recorded()))
	}
	if got := srv.count("sendMessage"); got != 0 {
		t.Errorf("sendMessage calls = %d during a turn; want 0", got)
	}
	tb.bot.EndTurn(500)
	// The surveyed early-return behaviour: the approval is
	// already decided, so a later call still sends nothing for
	// it — no reminder queue exists (tgbot.py:1630-1701).
	if err := tb.bot.NotifyPending(context.Background(), 500, items); err != nil {
		t.Fatal(err)
	}
	if got := srv.count("sendMessage"); got != 0 {
		t.Errorf("sendMessage calls = %d after turn end; want 0 (never notified later)", got)
	}
}

func TestNotifyPendingToggleOffSendsButtonsOnly(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, func(s *Settings) { s.AutoApprove = false })
	if err := tb.bot.NotifyPending(context.Background(), 500, []Approval{foreverApproval("appr-10")}); err != nil {
		t.Fatal(err)
	}
	if len(tb.decider.recorded()) != 0 {
		t.Errorf("decider calls = %d; want 0 (auto-approve off)", len(tb.decider.recorded()))
	}
	sends := srv.callsOf("sendMessage")
	if len(sends) != 1 {
		t.Fatalf("sendMessage calls = %d; want 1 button send", len(sends))
	}
	if sends[0].Form["reply_markup"] == "" {
		t.Errorf("button send has no reply_markup")
	}
}

func TestRestartLosesClaimState(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb1 := newTestBot(t, srv, func(s *Settings) { s.AutoApprove = true })
	if got := tb1.bot.ApproveForever(context.Background(), []Approval{foreverApproval("appr-11")}); len(got) != 1 {
		t.Fatalf("first bot done = %v", got)
	}
	// A second Bot (a restarted process) has no decided set:
	// it decides the same id again. This is the surveyed
	// restart-loss behaviour (tgbot.py:1505-1701 state is
	// in-memory; only toggles/offset persist).
	tb2 := newTestBot(t, srv, func(s *Settings) { s.AutoApprove = true })
	if got := tb2.bot.ApproveForever(context.Background(), []Approval{foreverApproval("appr-11")}); len(got) != 1 {
		t.Errorf("restarted bot done = %v; want [appr-11] (state lost on restart)", got)
	}
	if len(tb2.decider.recorded()) != 1 {
		t.Errorf("restarted decider calls = %d; want 1", len(tb2.decider.recorded()))
	}
}

func TestAutoLogCapsAt51(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, func(s *Settings) { s.AutoApprove = true })
	var items []Approval
	for i := 0; i < 60; i++ {
		items = append(items, foreverApproval("log-"+itoa(i)))
	}
	_ = tb.bot.ApproveForever(context.Background(), items)
	log := tb.bot.AutoLog()
	if len(log) != 51 {
		t.Errorf("auto log len = %d; want 51 (Python keeps at most 51)", len(log))
	}
	if log[0].ApprovalID != "log-9" {
		t.Errorf("first log entry = %q; want log-9 (oldest dropped)", log[0].ApprovalID)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

var errDecideFail = errString("decide failed")

type errString string

func (e errString) Error() string { return string(e) }

func TestApproveForeverClaimStormDocumentedResidual(t *testing.T) {
	t.Parallel()
	// DOCUMENTED RESIDUAL (loop-2 fallback for R-F5): 20
	// concurrent callers, a 150ms decider, a 20ms ClaimWait.
	// The mirrored Python claim protocol decides once per
	// caller that times out, so all 20 call Decide. This test
	// pins that residual behaviour; it is NOT the desired
	// exactly-once outcome. See the proof in claims.go and
	// the deviation in the PR draft: gateway-side idempotency
	// is required in step 5. No fix that keeps the surveyed
	// timeout-takeover semantics can yield 1 call here (the
	// owner is observably identical — blocked inside Decide
	// with no progress signal — in the storm and in the
	// takeover case), so the protocol is kept as surveyed
	// and the storm is disclosed instead of half-fixed.
	srv := newFakeTelegramServer(t)
	var calls atomic.Int32
	slow := DeciderFunc(func(_ context.Context, _, _ string) error {
		calls.Add(1)
		time.Sleep(150 * time.Millisecond)
		return nil
	})
	tb := newTestBot(t, srv, func(s *Settings) {
		s.AutoApprove = true
		s.ClaimWait = 20 * time.Millisecond
		s.Decider = slow
	})
	a := foreverApproval("appr-storm")
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = tb.bot.ApproveForever(context.Background(), []Approval{a})
		}()
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("storm callers did not return")
	}
	if got := calls.Load(); got != 20 {
		t.Errorf("decider calls in the storm = %d; want 20 (the documented residual)", got)
	}
}

// Loop-4 (D2) regression probes: the ApproveForever no-forever
// warning must carry no verbatim caller/server bytes. Fresh
// markers (L4D2), never reused from loop 3. These tests were
// written before the fix and FAIL on 2cb0249, where the warn
// line logged approval_id/kind/scope/title verbatim.

func TestApproveForeverNoForeverWarnBoundedFields(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, func(s *Settings) { s.AutoApprove = true })
	denyOnly := func(id, title, kind, scope string) Approval {
		return Approval{ID: id, Title: title, Kind: kind, Scope: scope, Options: []string{"deny"}}
	}
	// One fresh warn line per case: slice the log added by each
	// call and assert on that slice only (lengths, not buffers).
	warnSlice := func(before int, a Approval) string {
		_ = tb.bot.ApproveForever(context.Background(), []Approval{a})
		return tb.logBuf.String()[before:]
	}
	// 22.5k-char title: no title byte may reach the log.
	before := len(tb.logBuf.String())
	got := warnSlice(before, denyOnly("appr-l4d2-title", strings.Repeat("L4D2TITLE-", 2250), "", ""))
	if strings.Contains(got, "L4D2TITLE") {
		t.Error("warn line contains title bytes from a 22.5k-char title")
	}
	if len(got) > 400 {
		t.Errorf("warn line is %d bytes for a 22.5k-char title; want length-bounded", len(got))
	}
	if !strings.Contains(got, "title_length=22500") {
		t.Errorf("warn line lacks title_length=22500 (slice length %d)", len(got))
	}
	// Token-bearing title: the token must not reach the log.
	before = len(tb.logBuf.String())
	got = warnSlice(before, denyOnly("appr-l4d2-token", "L4D2TOKEN "+fakeToken+" tail", "", ""))
	if strings.Contains(got, fakeToken) {
		t.Error("warn line contains the fixture token from a token-bearing title")
	}
	if strings.Contains(got, "L4D2TOKEN") {
		t.Error("warn line contains title bytes from a token-bearing title")
	}
	if !strings.Contains(got, "title_length=") {
		t.Error("warn line lacks a title_length field")
	}
	if len(got) > 400 {
		t.Errorf("warn line is %d bytes for a token-bearing title; want length-bounded", len(got))
	}
	// Long kind/scope: no kind/scope byte may reach the log.
	before = len(tb.logBuf.String())
	got = warnSlice(before, denyOnly("appr-l4d2-long", "T", strings.Repeat("L4D2KIND-", 1500), strings.Repeat("L4D2SCOPE-", 1500)))
	if strings.Contains(got, "L4D2KIND") || strings.Contains(got, "L4D2SCOPE") {
		t.Error("warn line contains kind/scope bytes from long kind/scope fields")
	}
	if len(got) > 400 {
		t.Errorf("warn line is %d bytes for long kind/scope; want length-bounded", len(got))
	}
	if !strings.Contains(got, "kind_length=13500") || !strings.Contains(got, "scope_length=15000") {
		t.Errorf("warn line lacks kind_length=13500/scope_length=15000 (slice length %d)", len(got))
	}
	if !strings.Contains(got, "appr-l4d2-long") {
		t.Error("warn line lacks the gated approval_id for a well-formed id")
	}
	// Unbounded / ill-formed approval_id: gated to [omitted].
	before = len(tb.logBuf.String())
	got = warnSlice(before, denyOnly(strings.Repeat("x", 100)+":"+fakeToken, "T", "", ""))
	if strings.Contains(got, fakeToken) {
		t.Error("warn line contains the fixture token from an ill-formed approval_id")
	}
	if strings.Contains(got, strings.Repeat("x", 65)) {
		t.Error("warn line contains an unbounded approval_id run")
	}
	if !strings.Contains(got, "[omitted]") {
		t.Errorf("warn line lacks [omitted] for an ill-formed approval_id (slice length %d)", len(got))
	}
	if len(got) > 400 {
		t.Errorf("warn line is %d bytes for an ill-formed approval_id; want length-bounded", len(got))
	}
}

func TestLogApprovalIDGate(t *testing.T) {
	t.Parallel()
	srv := newFakeTelegramServer(t)
	tb := newTestBot(t, srv, nil)
	cases := []struct {
		in   string
		want string
	}{
		{"appr-1", "appr-1"},
		{"A1_b-2", "A1_b-2"},
		{"", "[omitted]"},
		{strings.Repeat("x", 65), "[omitted]"},
		{strings.Repeat("x", 64), strings.Repeat("x", 64)},
		{"a:b", "[omitted]"},
		{"a b", "[omitted]"},
		{"a/b", "[omitted]"},
		{fakeToken, "[omitted]"},
		{"123456:FAKE", "[omitted]"},
	}
	for _, tc := range cases {
		if got := tb.bot.logApprovalID(tc.in); got != tc.want {
			t.Errorf("logApprovalID(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}
