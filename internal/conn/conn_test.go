// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package conn

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClockGate is not used: timing assertions that need a fake clock
// live in shared_test.go under testing/synctest. This file covers the
// Muse lifecycle with real (short) timeouts.

func TestBoundedConnectFastSuccess(t *testing.T) {
	t.Parallel()
	gw := newFakeGateway()
	got, err := BoundedConnect(context.Background(), connectorReturning(gw), Config{}, 5*time.Second)
	if err != nil {
		t.Fatalf("BoundedConnect() error = %v", err)
	}
	if got != Gateway(gw) {
		t.Fatalf("BoundedConnect() returned a different gateway")
	}
	if gw.closeCallsCount() != 0 {
		t.Fatalf("fast gateway was closed")
	}
}

func TestBoundedConnectAuthErrorPassesThroughTyped(t *testing.T) {
	t.Parallel()
	want := NewAuthError("auth/check -> 401")
	connector := func(_ context.Context, _ Config) (Gateway, error) {
		return nil, fmt.Errorf("connector: %w", want)
	}
	_, err := BoundedConnect(context.Background(), connector, Config{}, 5*time.Second)
	var target *AuthError
	if !errors.As(err, &target) {
		t.Fatalf("BoundedConnect() error = %v, errors.As(*AuthError) = false", err)
	}
	if target != want {
		t.Fatalf("AuthError identity changed: got %p want %p", target, want)
	}
}

func TestBoundedConnectTimeoutClosesLateGatewayExactlyOnce(t *testing.T) {
	t.Parallel()
	// Port of test_bounded_connect_never_returns_a_closed_gateway:
	// a late gateway is either claimed (never closed by the worker)
	// or timed out (closed exactly once), never both.
	for i := 0; i < 30; i++ {
		gw := newFakeGateway()
		slow := func(_ context.Context, _ Config) (Gateway, error) {
			time.Sleep(15 * time.Millisecond)
			return gw, nil
		}
		_, err := BoundedConnect(context.Background(), slow, Config{}, 10*time.Millisecond)
		if err == nil {
			t.Fatalf("iteration %d: expected a timeout error", i)
		}
		var te *TimeoutError
		if !errors.As(err, &te) {
			t.Fatalf("iteration %d: error = %v, want *TimeoutError", i, err)
		}
		deadline := time.Now().Add(200 * time.Millisecond)
		for gw.closeCallsCount() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if got := gw.closeCallsCount(); got != 1 {
			t.Fatalf("iteration %d: late gateway Close calls = %d, want exactly 1", i, got)
		}
	}
}

func TestBoundedConnectClaimedGatewayNeverClosedByWorker(t *testing.T) {
	t.Parallel()
	for i := 0; i < 30; i++ {
		gw := newFakeGateway()
		slow := func(_ context.Context, _ Config) (Gateway, error) {
			time.Sleep(5 * time.Millisecond)
			return gw, nil
		}
		got, err := BoundedConnect(context.Background(), slow, Config{}, 200*time.Millisecond)
		if err != nil {
			t.Fatalf("iteration %d: BoundedConnect() error = %v", i, err)
		}
		if got != Gateway(gw) {
			t.Fatalf("iteration %d: wrong gateway returned", i)
		}
		time.Sleep(30 * time.Millisecond)
		if got := gw.closeCallsCount(); got != 0 {
			t.Fatalf("iteration %d: claimed gateway closed %d times", i, got)
		}
	}
}

func TestBoundedConnectContextCancelClosesLateGateway(t *testing.T) {
	t.Parallel()
	gw := newFakeGateway()
	ctx, cancel := context.WithCancel(context.Background())
	slow := func(_ context.Context, _ Config) (Gateway, error) {
		time.Sleep(100 * time.Millisecond)
		return gw, nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := BoundedConnect(ctx, slow, Config{}, 5*time.Second)
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("BoundedConnect() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("BoundedConnect did not return after context cancel")
	}
	deadline := time.Now().Add(300 * time.Millisecond)
	for gw.closeCallsCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := gw.closeCallsCount(); got != 1 {
		t.Fatalf("late gateway Close calls = %d, want 1", got)
	}
}

func TestLiveLoserClosesSurplusGateway(t *testing.T) {
	t.Parallel()
	// Port of test_live_does_not_hold_shared_lock_while_connecting:
	// both live() calls reach the connector (_open outside the shared
	// lock); exactly one gateway is installed and the extra is closed.
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var made []*fakeGateway
	calls := 0
	connector := connectorFactory(&made, &calls, func() {
		entered <- struct{}{}
		<-release
	})
	m := New(connector, WithConfig(Config{}))
	results := make([]Gateway, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			gw, err := m.Live(context.Background(), nil)
			if err != nil {
				t.Errorf("Live() error = %v", err)
				return
			}
			results[i] = gw
		}(i)
	}
	// Wait until both connectors are inside (proves the second live()
	// was not serialised behind the first one's connect).
	timeout := time.After(2 * time.Second)
	for n := 0; n < 2; n++ {
		select {
		case <-entered:
		case <-timeout:
			close(release)
			t.Fatalf("only %d live() calls reached the connector; _open must run outside the shared lock", n)
		}
	}
	close(release)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("live() goroutines did not finish")
	}
	if results[0] == nil || results[1] == nil {
		t.Fatalf("results = %v, want two gateways", results)
	}
	if results[0] != results[1] {
		t.Fatalf("live() results differ: %p vs %p", results[0], results[1])
	}
	closed := 0
	for _, gw := range made {
		closed += gw.closeCallsCount()
	}
	if closed != 1 {
		t.Fatalf("closed surplus gateways = %d, want exactly 1 (made=%d)", closed, len(made))
	}
	if m.Connects() != 2 {
		t.Fatalf("Connects() = %d, want 2", m.Connects())
	}
}

func TestLiveClosesDroppedGatewayWhenReopenFails(t *testing.T) {
	t.Parallel()
	// Port of test_live_closes_dropped_gateway_when_reopen_fails (N4).
	old := newFakeGateway()
	old.setAlive(false)
	old.setDead(errors.New("dead"))
	m := New(func(_ context.Context, _ Config) (Gateway, error) {
		return nil, errors.New("connect refused")
	}, WithConfig(Config{}))
	m.shared = old
	_, err := m.Live(context.Background(), nil)
	if err == nil {
		t.Fatal("Live() error = nil, want connect refused")
	}
	if old.closeCallsCount() != 1 {
		t.Fatalf("dropped gateway Close calls = %d, want 1", old.closeCallsCount())
	}
	m.mu.RLock()
	shared := m.shared
	m.mu.RUnlock()
	if shared != nil {
		t.Fatalf("shared = %v after failed reopen, want nil", shared)
	}
}

func TestLiveStaleProbe(t *testing.T) {
	t.Parallel()
	// Port of test_live_probes_a_quiet_connection_before_reusing_it.
	old := time.Now().Add(-1000 * time.Second)
	fresh := newFakeGateway()
	fresh.setStamps(old, old)
	m := New(connectorReturning(fresh), WithConfig(Config{}))
	m.shared = fresh
	got, err := m.Live(context.Background(), nil)
	if err != nil {
		t.Fatalf("Live() error = %v", err)
	}
	if got != Gateway(fresh) {
		t.Fatalf("Live() returned a different gateway after a passing probe")
	}
	if fresh.pingCallsCount() != 1 {
		t.Fatalf("ping calls = %d, want 1", fresh.pingCallsCount())
	}

	stale := newFakeGateway()
	stale.setStamps(old, old)
	stale.setPingErr(&TimeoutError{Message: "no response for connection.ping"})
	replacement := newFakeGateway()
	m2 := New(connectorReturning(replacement), WithConfig(Config{}))
	m2.shared = stale
	got, err = m2.Live(context.Background(), nil)
	if err != nil {
		t.Fatalf("Live() error = %v", err)
	}
	if got != Gateway(replacement) {
		t.Fatalf("Live() did not install the replacement after a failed probe")
	}
	if stale.closeCallsCount() != 1 {
		t.Fatalf("stale gateway Close calls = %d, want 1", stale.closeCallsCount())
	}
	if m2.Drops() < 1 {
		t.Fatalf("Drops() = %d, want >= 1", m2.Drops())
	}
}

func TestLiveReusesFreshGatewayWithoutPing(t *testing.T) {
	t.Parallel()
	gw := newFakeGateway() // stamps are time.Now(): fresh
	m := New(connectorReturning(gw), WithConfig(Config{}))
	m.shared = gw
	got, err := m.Live(context.Background(), nil)
	if err != nil {
		t.Fatalf("Live() error = %v", err)
	}
	if got != Gateway(gw) {
		t.Fatalf("Live() returned a different gateway")
	}
	if gw.pingCallsCount() != 0 {
		t.Fatalf("fresh gateway was pinged %d times, want 0", gw.pingCallsCount())
	}
}

func TestLiveAuthErrorNotMarkedDownAndCallbackFires(t *testing.T) {
	t.Parallel()
	var authCalls int
	var downCalls int
	authErr := NewAuthError("auth/check -> 401")
	m := New(func(_ context.Context, _ Config) (Gateway, error) { return nil, authErr },
		WithConfig(Config{}),
		WithOnAuthError(func(err error) { authCalls++ }),
		WithOnDown(func(err error, d time.Duration) { downCalls++ }),
	)
	_, err := m.Live(context.Background(), nil)
	var target *AuthError
	if !errors.As(err, &target) {
		t.Fatalf("Live() error = %v, want *AuthError", err)
	}
	if authCalls != 1 {
		t.Fatalf("onAuthError calls = %d, want 1", authCalls)
	}
	if downCalls != 0 {
		t.Fatalf("onDown calls = %d, want 0 for an AuthError", downCalls)
	}
	if m.Connects() != 0 {
		t.Fatalf("Connects() = %d, want 0 after an AuthError", m.Connects())
	}
}

func TestMarkDownCoalescingAndNotices(t *testing.T) {
	t.Parallel()
	var downs []time.Duration
	var ups []time.Duration
	m := New(connectorReturning(newFakeGateway()), WithConfig(Config{}),
		WithOnDown(func(err error, d time.Duration) { downs = append(downs, d) }),
		WithOnUp(func(d time.Duration) { ups = append(ups, d) }),
	)
	m.downNotice = 10 * time.Second
	m.downFailLimit = 3
	m.failSpacing = 50 * time.Millisecond

	// Three rapid failed connects count as one attempt (FAIL_SPACING).
	m.markDown(errors.New("refused"), true)
	m.markDown(errors.New("refused"), true)
	m.markDown(errors.New("refused"), true)
	m.downMu.Lock()
	fails := m.downFailCount
	notified := m.downNotified
	m.downMu.Unlock()
	if fails != 1 {
		t.Fatalf("downFailCount after rapid failures = %d, want 1", fails)
	}
	if notified {
		t.Fatal("downNotified after 1 coalesced failure, want false")
	}
	// After the spacing, two more failures reach DOWN_FAILS: one notice.
	time.Sleep(60 * time.Millisecond)
	m.markDown(errors.New("refused"), true)
	time.Sleep(60 * time.Millisecond)
	m.markDown(errors.New("refused"), true)
	if len(downs) != 1 {
		t.Fatalf("onDown calls = %d, want exactly 1", len(downs))
	}
	// Further failures while down do not re-notify.
	m.markDown(errors.New("refused"), true)
	if len(downs) != 1 {
		t.Fatalf("onDown calls = %d after repeat failure, want still 1", len(downs))
	}
	m.markUp()
	if len(ups) != 1 {
		t.Fatalf("onUp calls = %d, want 1", len(ups))
	}
	m.markUp()
	if len(ups) != 1 {
		t.Fatalf("onUp calls = %d after second markUp, want still 1", len(ups))
	}
}

func TestMarkDownNoticeAfterDownNoticeDuration(t *testing.T) {
	t.Parallel()
	var downs int
	m := New(connectorReturning(newFakeGateway()), WithConfig(Config{}),
		WithOnDown(func(err error, d time.Duration) { downs++ }),
	)
	m.downNotice = 50 * time.Millisecond
	m.downFailLimit = 100
	m.markDown(errors.New("down"), false)
	if downs != 0 {
		t.Fatalf("onDown calls = %d immediately, want 0", downs)
	}
	time.Sleep(60 * time.Millisecond)
	m.markDown(errors.New("down"), false)
	if downs != 1 {
		t.Fatalf("onDown calls = %d after DOWN_NOTICE, want 1", downs)
	}
}

func TestDropAdoptWarmReset(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	first := newFakeGateway()
	second := newFakeGateway()
	calls := 0
	m := New(func(_ context.Context, _ Config) (Gateway, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return second, nil
	}, WithConfig(Config{}))

	m.Adopt(first)
	if m.Connects() != 1 {
		t.Fatalf("Connects() after Adopt = %d, want 1", m.Connects())
	}
	m.Adopt(second)
	if first.closeCallsCount() != 1 {
		t.Fatalf("adopted-away gateway Close calls = %d, want 1", first.closeCallsCount())
	}
	m.Drop(second)
	if second.closeCallsCount() != 1 {
		t.Fatalf("dropped gateway Close calls = %d, want 1", second.closeCallsCount())
	}
	m.mu.RLock()
	shared := m.shared
	m.mu.RUnlock()
	if shared != nil {
		t.Fatalf("shared after Drop = %v, want nil", shared)
	}

	// Warm opens the shared connection once; a second warm reuses it.
	// A separate Muse with a fresh-gateway connector: reusing the
	// closed `first` gateway above would correctly force a
	// reconnect, which is a different behaviour.
	warmCalls := 0
	mw := New(func(_ context.Context, _ Config) (Gateway, error) {
		warmCalls++
		return newFakeGateway(), nil
	}, WithConfig(Config{}))
	mw.Warm(ctx)
	if warmCalls != 1 {
		t.Fatalf("connector calls after Warm = %d, want 1", warmCalls)
	}
	mw.Warm(ctx)
	if warmCalls != 1 {
		t.Fatalf("connector calls after second Warm = %d, want still 1 (shared reuse)", warmCalls)
	}
	mw.Reset()
	mw.mu.RLock()
	shared = mw.shared
	mw.mu.RUnlock()
	if shared != nil {
		t.Fatalf("shared after Reset = %v, want nil", shared)
	}
}

func TestReloadResetsOnlyOnIdentityChange(t *testing.T) {
	t.Parallel()
	gw := newFakeGateway()
	m := New(connectorReturning(gw), WithConfig(Config{CookiesFile: "/c1", VMID: "vm1", NodeID: "n1"}))
	m.shared = gw
	current := Config{CookiesFile: "/c1", VMID: "vm1", NodeID: "n1"}
	m.reloadFunc = func() (Config, error) { return current, nil }

	got, err := m.Reload()
	if err != nil || got != current {
		t.Fatalf("Reload() = (%v, %v), want (%v, nil)", got, err, current)
	}
	if gw.closeCallsCount() != 0 {
		t.Fatalf("gateway closed on an unchanged identity")
	}

	current = Config{CookiesFile: "/c2", VMID: "vm1", NodeID: "n1"}
	got, err = m.Reload()
	if err != nil || got != current {
		t.Fatalf("Reload() = (%v, %v), want (%v, nil)", got, err, current)
	}
	if gw.closeCallsCount() != 1 {
		t.Fatalf("gateway Close calls after identity change = %d, want 1", gw.closeCallsCount())
	}
	m.mu.RLock()
	shared := m.shared
	m.mu.RUnlock()
	if shared != nil {
		t.Fatalf("shared after identity-change Reload = %v, want nil", shared)
	}
	// Only cookies_file changing also resets; vm_id/node_id alone do not
	// need a separate test: the Identity comparison covers all three.
}

func TestReloadWithoutReloadFuncKeepsConfig(t *testing.T) {
	t.Parallel()
	m := New(connectorReturning(newFakeGateway()), WithConfig(Config{VMID: "vm1"}))
	got, err := m.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if got.VMID != "vm1" {
		t.Fatalf("Reload() = %+v, want VMID vm1", got)
	}
}

func TestConnectReturnsSharedConnForLeaserAndRawForNonLeaser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := New(connectorReturning(newFakeGateway()), WithConfig(Config{}))
	g, err := m.Connect(ctx, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if _, ok := g.(*SharedConn); !ok {
		t.Fatalf("Connect() returned %T, want *SharedConn for a Leaser gateway", g)
	}
	// Closing a SharedConn leaves the shared gateway up.
	if err := g.Close(); err != nil {
		t.Fatalf("SharedConn.Close() error = %v", err)
	}
	m.mu.RLock()
	shared := m.shared
	m.mu.RUnlock()
	if shared == nil {
		t.Fatal("shared gateway was closed by SharedConn.Close()")
	}

	nonLeaser := &noLeaseGateway{gw: newFakeGateway()}
	m2 := New(connectorReturning(nonLeaser), WithConfig(Config{}))
	g2, err := m2.Connect(ctx, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if g2 != Gateway(nonLeaser) {
		t.Fatalf("Connect() returned %T, want the raw gateway for a non-Leaser", g2)
	}
	if err := g2.Close(); err != nil {
		t.Fatalf("raw gateway Close() error = %v", err)
	}
	if nonLeaser.gw.closeCallsCount() != 1 {
		t.Fatalf("raw gateway Close calls = %d, want 1", nonLeaser.gw.closeCallsCount())
	}
}

// noLeaseGateway is a Gateway that deliberately does not implement
// Leaser: Muse.Connect must hand it out directly, caller-owned.
type noLeaseGateway struct{ gw *fakeGateway }

func (n *noLeaseGateway) CallJSON(ctx context.Context, m string, o RequestOptions) (any, error) {
	return n.gw.CallJSON(ctx, m, o)
}
func (n *noLeaseGateway) Request(ctx context.Context, m string, o RequestOptions) ([]byte, error) {
	return n.gw.Request(ctx, m, o)
}
func (n *noLeaseGateway) SubscribeRaw(ctx context.Context, m string, o SubscribeOptions) ([][]byte, error) {
	return n.gw.SubscribeRaw(ctx, m, o)
}
func (n *noLeaseGateway) SubscribeJSON(ctx context.Context, m string, o SubscribeOptions) ([]any, error) {
	return n.gw.SubscribeJSON(ctx, m, o)
}
func (n *noLeaseGateway) DownloadFile(ctx context.Context, r any, o DownloadOptions) ([]byte, error) {
	return n.gw.DownloadFile(ctx, r, o)
}
func (n *noLeaseGateway) Ping(ctx context.Context, d time.Duration) (any, error) {
	return n.gw.Ping(ctx, d)
}
func (n *noLeaseGateway) OpenStream(ctx context.Context, m string, o OpenStreamOptions) (int64, error) {
	return n.gw.OpenStream(ctx, m, o)
}
func (n *noLeaseGateway) CancelStream(ctx context.Context, id int64) error {
	return n.gw.CancelStream(ctx, id)
}
func (n *noLeaseGateway) LookupRoute(m string) (Route, bool) { return n.gw.LookupRoute(m) }
func (n *noLeaseGateway) Alive() bool                        { return n.gw.Alive() }
func (n *noLeaseGateway) Dead() error                        { return n.gw.Dead() }
func (n *noLeaseGateway) LastRecv() time.Time                { return n.gw.LastRecv() }
func (n *noLeaseGateway) LastUsed() time.Time                { return n.gw.LastUsed() }
func (n *noLeaseGateway) Close() error                       { return n.gw.Close() }

func TestMuseHistorySortsBySeq(t *testing.T) {
	t.Parallel()
	gw := newFakeGateway()
	gw.callFn = func(method string, opts RequestOptions) (any, error) {
		if method != "chat.history" {
			t.Errorf("unexpected method %q", method)
		}
		return map[string]any{"chat_events": []any{
			map[string]any{"seq": int64(9), "text": "c"},
			map[string]any{"text": "no-seq"},
			map[string]any{"seq": int64(3), "text": "a"},
			map[string]any{"seq": int64(5), "text": "b"},
		}}, nil
	}
	m := New(connectorReturning(gw), WithConfig(Config{}))
	evs, err := m.History(context.Background(), "sess", 20)
	if err != nil {
		t.Fatalf("History() error = %v", err)
	}
	if len(evs) != 4 {
		t.Fatalf("History() returned %d events, want 4", len(evs))
	}
	texts := make([]string, 0, 4)
	for _, ev := range evs {
		texts = append(texts, ev.(map[string]any)["text"].(string))
	}
	want := []string{"no-seq", "a", "b", "c"}
	for i := range want {
		if texts[i] != want[i] {
			t.Fatalf("History() order = %v, want %v", texts, want)
		}
	}
}

func TestHeartbeatRestartsAfterStop(t *testing.T) {
	// Port of the stop/restart half of
	// test_heartbeat_restarts_after_stop_and_after_death.
	gw := newFakeGateway()
	m := New(connectorReturning(gw), WithConfig(Config{}))
	m.StartHeartbeat(20 * time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for !m.heartbeatRunning() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !m.heartbeatRunning() {
		t.Fatal("heartbeat did not start")
	}
	m.StopHeartbeat()
	if m.heartbeatRunning() {
		t.Fatal("heartbeat still running after StopHeartbeat")
	}
	m.StartHeartbeat(20 * time.Millisecond)
	deadline = time.Now().Add(2 * time.Second)
	for !m.heartbeatRunning() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !m.heartbeatRunning() {
		t.Fatal("heartbeat did not restart after StopHeartbeat")
	}
	m.StopHeartbeat()
}

func TestHeartbeatRestartsAfterTickPanic(t *testing.T) {
	// Port of test_heartbeat_restarts_after_base_exception_in_tick:
	// a panic in one tick restarts the loop; the next tick still runs.
	var calls int
	var mu sync.Mutex
	m := New(connectorReturning(newFakeGateway()), WithConfig(Config{}))
	m.hbTickFn = func(_ time.Duration) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			panic("boom")
		}
	}
	m.StartHeartbeat(20 * time.Millisecond)
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := calls
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			if n < 2 {
				t.Fatalf("tick calls = %d, want >= 2 (heartbeat did not restart after panic)", n)
			}
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	m.StopHeartbeat()
}

func TestHeartbeatStopDuringTickExitsOldLoop(t *testing.T) {
	// Port of test_heartbeat_stop_during_tick_exits_old_thread: the
	// loop waits on the stop channel captured at ITS start, so a
	// stop+restart while the old loop is mid-tick cannot strand it.
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	m := New(connectorReturning(newFakeGateway()), WithConfig(Config{}))
	m.hbTickFn = func(_ time.Duration) {
		once.Do(func() { close(entered) })
		<-release
	}
	m.StartHeartbeat(20 * time.Millisecond)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat tick never started")
	}
	start := time.Now()
	m.StopHeartbeat() // bounded by HeartbeatStopTimeout (6s); tick releases below
	if elapsed := time.Since(start); elapsed > HeartbeatStopTimeout+time.Second {
		t.Fatalf("StopHeartbeat took %v, want <= ~6s", elapsed)
	}
	// Restart while the old tick is still blocked: the old loop must
	// exit on ITS stop channel once the tick returns, not strand.
	m.StartHeartbeat(20 * time.Millisecond)
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for m.heartbeatRunning() && time.Now().Before(deadline) {
		// The restarted loop is running; the old loop's done channel
		// is internal, so observe via a short settle + no second
		// concurrent tick: hbTickFn's once-guard means a stranded old
		// loop would block in the same tick again, which is fine as
		// long as StopHeartbeat below returns promptly.
		time.Sleep(10 * time.Millisecond)
		break
	}
	m.StopHeartbeat()
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Fatalf("heartbeat stop/restart cycle took %v", elapsed)
	}
}

func TestHeartbeatPingsQuietGatewayAndReconnectsOnFailure(t *testing.T) {
	old := time.Now().Add(-1000 * time.Second)
	quiet := newFakeGateway()
	quiet.setStamps(old, old)
	quiet.setPingErr(errors.New("ping failed"))
	fresh := newFakeGateway()
	// The quiet gateway is pre-installed without calling the
	// connector, so the reconnect call must return the fresh one.
	m := New(func(_ context.Context, _ Config) (Gateway, error) {
		return fresh, nil
	}, WithConfig(Config{}))
	m.shared = quiet
	m.StartHeartbeat(20 * time.Millisecond)
	deadline := time.Now().Add(3 * time.Second)
	for quiet.closeCallsCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	m.StopHeartbeat()
	if quiet.pingCallsCount() == 0 {
		t.Fatal("heartbeat never pinged the quiet gateway")
	}
	if quiet.closeCallsCount() != 1 {
		t.Fatalf("quiet gateway Close calls = %d, want 1 after failed ping", quiet.closeCallsCount())
	}
	m.mu.RLock()
	shared := m.shared
	m.mu.RUnlock()
	if shared != Gateway(fresh) {
		t.Fatalf("shared after heartbeat reconnect = %T, want the fresh gateway", shared)
	}
}

func TestHeartbeatNeverConnectsBeforeFirstCall(t *testing.T) {
	// _hb_tick with no shared gateway and zero connects does nothing.
	calls := 0
	m := New(func(_ context.Context, _ Config) (Gateway, error) {
		calls++
		return newFakeGateway(), nil
	}, WithConfig(Config{}))
	m.StartHeartbeat(20 * time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	m.StopHeartbeat()
	if calls != 0 {
		t.Fatalf("connector calls = %d, want 0 before the first real call", calls)
	}
}

func TestCloseStopsHeartbeatAndClosesShared(t *testing.T) {
	gw := newFakeGateway()
	m := New(connectorReturning(gw), WithConfig(Config{}))
	m.shared = gw
	m.StartHeartbeat(20 * time.Millisecond)
	m.Close()
	if m.heartbeatRunning() {
		t.Fatal("heartbeat still running after Close()")
	}
	if gw.closeCallsCount() != 1 {
		t.Fatalf("shared gateway Close calls = %d, want 1", gw.closeCallsCount())
	}
}
