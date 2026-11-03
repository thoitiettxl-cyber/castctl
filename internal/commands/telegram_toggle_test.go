// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// Runtime-toggle measurement for /autoapprove once, through the
// full `telegram run` path: fake Bot API server + scripted fake
// gateway, no live network, no token, no cookies. This is the
// adapter/toggle half of the toggle measurement; it does NOT
// prove the real Telegram app UI (button taps in the app still
// need a human). Assertions are on observable behavior — the
// bot's replies, the gateway Decider calls, and the approval
// buttons — never on state-file bytes alone.
//
// Covered, in order, in one bot process and then across a
// restart into a second bot process over the same config home:
//   - `/autoapprove once on` alone does NOT auto-decide: the
//     main toggle stays off, and a once-only approval surfaces
//     as buttons with no decide call.
//   - `/autoapprove on` with once on DOES auto-decide a
//     once-only approval with allow_once, through the Decider.
//   - The once toggle is NOT consumed by one decision: a
//     status report after the decision still says on, and a
//     second once-only approval is decided again.
//   - Both toggles survive a full `telegram run` restart over
//     the same config home: the restarted bot reports them on
//     and decides a further once-only approval with no
//     re-toggle.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// runTelegramBotInHome is a test-only, home-reuse variant of
// runTelegramBotWithConfig: the same Run wiring, but the config
// home is caller-owned so a second Run can load the state file
// the first Run wrote. No production code is involved: the
// production telegram run already loads its state from the
// config home; this helper only keeps that home across Runs.
func runTelegramBotInHome(t *testing.T, gw *telegramTurnFakeGateway, home, configFile string, batches []string) (*telegramBotHarness, context.CancelFunc, chan int) {
	t.Helper()
	fake := &cmdFakeTelegram{batches: batches}
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
	env := &Env{Stdout: &strings.Builder{}, Stderr: &strings.Builder{}, Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	muse := conn.New(func(context.Context, conn.Config) (conn.Gateway, error) { return gw, nil })
	env.BuildRuntime = func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, env *Env) (*Runtime, error) {
		// The status report needs a VM id without the
		// FetchSessionInfo fallback (no cookies in tests).
		prof.VMID = "vm-test"
		return &Runtime{Profile: prof, Muse: muse, httpClientOverride: fakeClient}, nil
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	codeCh := make(chan int, 1)
	done := make(chan struct{})
	go func() {
		codeCh <- Run(ctx, []string{"telegram", "run"}, env)
		close(done)
	}()
	h := &telegramBotHarness{fake: fake, gw: gw, homeDir: home}
	cancel := func() {
		cancelFn()
		<-done
		drainTurns(fake)
	}
	return h, cancel, codeCh
}

// onceOnlyScript is one turn whose only approval offers
// allow_once: the exact shape the auto_allow_once fallback
// exists for. The reply text is the turn's completed reply.
func onceOnlyScript(t *testing.T, reply, title, id string) turnSubScript {
	t.Helper()
	approvalJSON, err := json.Marshal(approvalFixture(id, title, "allow_once"))
	if err != nil {
		t.Fatal(err)
	}
	return turnSubScript{
		replyText:       reply,
		deltas:          []string{"..."},
		approvalRecords: []string{fmt.Sprintf(`{"event":"approvals.snapshot","payload":{"pending_approvals":[%s]}}`, approvalJSON)},
	}
}

// waitForNewSend waits until a send at or after from (a send
// count captured before staging the update) contains want.
// The from index matters: status reports repeat, so waiting
// on any earlier send would prove nothing about the update
// staged after the count was taken.
func waitForNewSend(t *testing.T, h *telegramBotHarness, from int, want, what string) {
	t.Helper()
	waitFor(t, what, func() bool {
		for _, s := range sendsOf(h)[from:] {
			if strings.Contains(s, want) {
				return true
			}
		}
		return false
	})
}

// waitForEditFrom waits until an edit at or after from
// contains want.
func waitForEditFrom(t *testing.T, h *telegramBotHarness, from int, want, what string) {
	t.Helper()
	waitFor(t, what, func() bool {
		edits := h.fake.editTexts()
		for _, e := range edits[from:] {
			if strings.Contains(e, want) {
				return true
			}
		}
		return false
	})
}

// editMarkupsFrom returns a copy of the edit reply_markup JSON
// values at or after from, parallel to the edits.
func editMarkupsFrom(h *telegramBotHarness, from int) []string {
	h.fake.mu.Lock()
	defer h.fake.mu.Unlock()
	return append([]string(nil), h.fake.editMarkupJSON[from:]...)
}

// toggleWatermark returns the persisted main-chat watermark,
// or 0 when no state file exists yet.
func toggleWatermark(h *telegramBotHarness) int64 {
	_, wm, ok := h.readState()
	if !ok {
		return 0
	}
	return wm
}

// assertDecides fails unless the gateway saw exactly the
// wanted decide calls, in order, and no others.
func assertDecides(t *testing.T, gw *telegramTurnFakeGateway, want []decideRecord) {
	t.Helper()
	got := gw.decideHistory()
	if len(got) != len(want) {
		t.Fatalf("decide calls = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("decide calls = %+v, want %+v", got, want)
		}
	}
}

func TestTelegramRuntimeOnceTogglePersistsAcrossRestart(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.subScripts = []turnSubScript{
		onceOnlyScript(t, "Waiting 1", "Run shell probe 1", "A1"),
		onceOnlyScript(t, "Done 2", "Run shell probe 2", "A2"),
		onceOnlyScript(t, "Done 3", "Run shell probe 3", "A3"),
		onceOnlyScript(t, "Done 4", "Run shell probe 4", "A4"),
	}
	// NoAuto config: both toggles start off, as in the live
	// baseline. Every on in this test comes from a runtime
	// /autoapprove command through the fake server.
	home, configFile := testHome(t, telegramTestConfigNoAuto())

	// --- Run 1: runtime toggles, decided and not consumed. ---
	h, cancel, codeCh := runTelegramBotInHome(t, gw, home, configFile, []string{})

	// Once status: off/off at baseline.
	from := len(sendsOf(h))
	h.fake.setBatches([]string{telegramUpdate(1, 111, "/autoapprove once status")})
	waitForNewSend(t, h, from, "Auto-allow-once is <b>off</b>", "once-off status report")
	waitForNewSend(t, h, from, "Auto-approve is <b>off</b>", "main-off status report")

	// Once on alone: the report says once on, main still off.
	from = len(sendsOf(h))
	h.fake.setBatches([]string{telegramUpdate(2, 111, "/autoapprove once on")})
	waitForNewSend(t, h, from, "Auto-allow-once is <b>on</b>", "once-on report")
	waitForNewSend(t, h, from, "Auto-approve is <b>off</b>", "main still off after once-on")

	// A once-only approval with only once on must surface as
	// buttons and must NOT be decided.
	prev := toggleWatermark(h)
	editsBefore := len(h.fake.editTexts())
	markupsBefore := len(editMarkupsFrom(h, 0))
	h.fake.setBatches([]string{telegramUpdate(3, 111, "run shell probe 1")})
	waitForEditFrom(t, h, editsBefore, "Approval: Run shell probe 1", "approval note edit")
	waitForTurnEnd(t, h, prev)
	assertDecides(t, gw, nil)
	sawOnce, sawAlways := false, false
	for _, m := range editMarkupsFrom(h, markupsBefore) {
		if strings.Contains(m, "Allow once") {
			sawOnce = true
		}
		if strings.Contains(m, "Always allow") {
			sawAlways = true
		}
	}
	if !sawOnce {
		t.Error("approval buttons never carried Allow once")
	}
	if sawAlways {
		t.Error("approval buttons carried Always allow for a once-only approval")
	}

	// Main on: the report says on, with the once fallback.
	from = len(sendsOf(h))
	h.fake.setBatches([]string{telegramUpdate(4, 111, "/autoapprove on")})
	waitForNewSend(t, h, from, "Auto-approve is <b>on</b>", "main-on report")
	waitForNewSend(t, h, from, "fall back to allow_once", "once fallback in main-on report")

	// A once-only approval now IS decided, with allow_once,
	// and the delivered reply notes it.
	prev = toggleWatermark(h)
	editsBefore = len(h.fake.editTexts())
	h.fake.setBatches([]string{telegramUpdate(5, 111, "run shell probe 2")})
	waitForEditFrom(t, h, editsBefore, "auto-approved (once)", "auto-approved note edit")
	waitForEditFrom(t, h, editsBefore, "Run shell probe 2", "auto-approved title edit")
	waitForTurnEnd(t, h, prev)
	assertDecides(t, gw, []decideRecord{{approvalID: "A2", decision: "allow_once"}})

	// The once toggle is not consumed by that decision: a
	// status report still says on, with no further decide.
	from = len(sendsOf(h))
	h.fake.setBatches([]string{telegramUpdate(6, 111, "/autoapprove once status")})
	waitForNewSend(t, h, from, "Auto-allow-once is <b>on</b>", "once still on after one decision")
	assertDecides(t, gw, []decideRecord{{approvalID: "A2", decision: "allow_once"}})

	// A second once-only approval is decided the same way.
	prev = toggleWatermark(h)
	editsBefore = len(h.fake.editTexts())
	h.fake.setBatches([]string{telegramUpdate(7, 111, "run shell probe 3")})
	waitForEditFrom(t, h, editsBefore, "auto-approved (once)", "second auto-approved note edit")
	waitForEditFrom(t, h, editsBefore, "Run shell probe 3", "second auto-approved title edit")
	waitForTurnEnd(t, h, prev)
	assertDecides(t, gw, []decideRecord{
		{approvalID: "A2", decision: "allow_once"},
		{approvalID: "A3", decision: "allow_once"},
	})

	cancel()
	if code := <-codeCh; code != 130 {
		t.Errorf("run 1 code = %d, want 130 (interrupted)", code)
	}

	// --- Run 2: same config home, no re-toggle. ---
	h2, cancel2, codeCh2 := runTelegramBotInHome(t, gw, home, configFile, []string{})
	defer cancel2()

	// The restarted bot reports both toggles on: persistence
	// is observed in its reply, not by reading the file.
	from = len(sendsOf(h2))
	h2.fake.setBatches([]string{telegramUpdate(10, 111, "/autoapprove once status")})
	waitForNewSend(t, h2, from, "Auto-allow-once is <b>on</b>", "once on after restart")
	waitForNewSend(t, h2, from, "Auto-approve is <b>on</b>", "main on after restart")

	// And the toggles still decide: a further once-only
	// approval is auto-decided with allow_once.
	prev = toggleWatermark(h2)
	editsBefore = len(h2.fake.editTexts())
	h2.fake.setBatches([]string{telegramUpdate(11, 111, "run shell probe 4")})
	waitForEditFrom(t, h2, editsBefore, "auto-approved (once)", "auto-approved note edit after restart")
	waitForEditFrom(t, h2, editsBefore, "Run shell probe 4", "auto-approved title edit after restart")
	waitForTurnEnd(t, h2, prev)
	assertDecides(t, gw, []decideRecord{
		{approvalID: "A2", decision: "allow_once"},
		{approvalID: "A3", decision: "allow_once"},
		{approvalID: "A4", decision: "allow_once"},
	})

	// Toggling both off again still reports off.
	from = len(sendsOf(h2))
	h2.fake.setBatches([]string{telegramUpdate(12, 111, "/autoapprove off")})
	waitForNewSend(t, h2, from, "Auto-approve is <b>off</b>", "main-off report after restart")
	from = len(sendsOf(h2))
	h2.fake.setBatches([]string{telegramUpdate(13, 111, "/autoapprove once off")})
	waitForNewSend(t, h2, from, "Auto-allow-once is <b>off</b>", "once-off report after restart")
	waitForNewSend(t, h2, from, "Auto-approve is <b>off</b>", "main still off after once-off")

	cancel2()
	if code := <-codeCh2; code != 130 {
		t.Errorf("run 2 code = %d, want 130 (interrupted)", code)
	}
	assertDecides(t, gw, []decideRecord{
		{approvalID: "A2", decision: "allow_once"},
		{approvalID: "A3", decision: "allow_once"},
		{approvalID: "A4", decision: "allow_once"},
	})
}
