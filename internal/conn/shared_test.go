package conn

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"
)

func TestSafeToRepeatTable(t *testing.T) {
	t.Parallel()
	// Port of test_safe_to_repeat_is_an_explicit_safe_set (F11).
	routes := fakeRoutes()
	cases := []struct {
		name   string
		method string
		route  *Route
		want   bool
	}{
		{"get history", "chat.history", routePtr(routes["chat.history"]), true},
		{"get sessions", "sessions.list", routePtr(routes["sessions.list"]), true},
		{"get approvals", "egress.approvals", routePtr(routes["egress.approvals"]), true},
		{"post read fs.read", "fs.read", routePtr(routes["fs.read"]), true},
		{"post read fs.list", "fs.list", routePtr(routes["fs.list"]), true},
		{"post read fs.stat", "fs.stat", routePtr(routes["fs.stat"]), true},
		{"post read memory.get", "memory.get", routePtr(routes["memory.get"]), true},
		{"post read connection.ping", "connection.ping", routePtr(routes["connection.ping"]), true},
		{"post read fs.reads", "fs.reads", routePtr(routes["fs.reads"]), true},
		{"post read fs.stats", "fs.stats", routePtr(routes["fs.stats"]), true},
		{"post read node.list", "node.list", routePtr(routes["node.list"]), true},
		{"post read custom_connectors.list", "custom_connectors.list", routePtr(routes["custom_connectors.list"]), true},
		{"decide never safe", "egress.approval.decide", routePtr(routes["egress.approval.decide"]), false},
		{"subscribe never safe", "chat.subscribe", routePtr(routes["chat.subscribe"]), false},
		{"mark_seen never safe", "chat.mark_seen", routePtr(routes["chat.mark_seen"]), false},
		{"shopping never safe", "shopping.events", routePtr(routes["shopping.events"]), false},
		{"identity subscribe never safe", "identity.subscribe", routePtr(routes["identity.subscribe"]), false},
		{"unlock read-word write", "messenger-read.unlock", routePtr(routes["messenger-read.unlock"]), false},
		{"patch state update", "shared_agents.state.update", routePtr(routes["shared_agents.state.update"]), false},
		{"widgets patch", "widgets.state.patch", routePtr(routes["widgets.state.patch"]), false},
		{"widgets set", "widgets.state.set", routePtr(routes["widgets.state.set"]), false},
		{"unknown method no route", "unknown.get_status", nil, false},
		{"unknown method empty route", "unknown.get_status", &Route{}, false},
		{"read set without route still safe", "fs.read", nil, true},
		{"get without route is conservative", "chat.history", nil, false},
		{"get lowercase http", "chat.history", &Route{Method: "chat.history", HTTP: "get"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := safeToRepeat(tc.method, tc.route); got != tc.want {
				t.Fatalf("safeToRepeat(%q, %+v) = %v, want %v", tc.method, tc.route, got, tc.want)
			}
		})
	}
}

func routePtr(r Route) *Route { return &r }

func TestRetryRespectsCallerDeadline(t *testing.T) {
	t.Parallel()
	// Port of test_retry_respects_the_callers_remaining_deadline.
	// A fake clock (synctest) makes the pause ladder deterministic.
	synctest.Test(t, func(t *testing.T) {
		gw := newFakeGateway()
		gw.routes = fakeRoutes()
		calls := 0
		gw.callFn = func(method string, opts RequestOptions) (any, error) {
			calls++
			if calls <= 2 {
				return nil, NewConnectionDown(errors.New("down"))
			}
			return map[string]any{"ok": true}, nil
		}
		m := New(connectorReturning(gw), WithConfig(Config{}))
		sc := &SharedConn{muse: m}
		past := time.Now().Add(-time.Second)
		_, err := sc.CallJSON(context.Background(), "fs.read",
			RequestOptions{Deadline: past, Route: &Route{Method: "fs.read", HTTP: "POST"}})
		var down *ConnectionDown
		if !errors.As(err, &down) {
			t.Fatalf("CallJSON() error = %v, want *ConnectionDown", err)
		}
		if calls != 1 {
			t.Fatalf("calls with a past deadline = %d, want 1 (no retry)", calls)
		}
		calls = 0
		got, err := sc.CallJSON(context.Background(), "fs.read",
			RequestOptions{Deadline: time.Now().Add(30 * time.Second), Route: &Route{Method: "fs.read", HTTP: "POST"}})
		if err != nil {
			t.Fatalf("CallJSON() error = %v", err)
		}
		if got.(map[string]any)["ok"] != true {
			t.Fatalf("CallJSON() = %v, want ok", got)
		}
		if calls != 3 {
			t.Fatalf("calls = %d, want 3", calls)
		}
	})
}

func TestRetryPauseLadderUnderFakeClock(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		gw := newFakeGateway()
		gw.routes = fakeRoutes()
		attempts := 0
		gw.callFn = func(method string, opts RequestOptions) (any, error) {
			attempts++
			if attempts <= 2 {
				return nil, NewConnectionDown(nil)
			}
			return map[string]any{"ok": true}, nil
		}
		m := New(connectorReturning(gw), WithConfig(Config{}))
		m.retryFor = 30 * time.Second
		sc := &SharedConn{muse: m}
		start := time.Now()
		_, err := sc.CallJSON(context.Background(), "fs.read", RequestOptions{Route: &Route{Method: "fs.read", HTTP: "POST"}})
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("CallJSON() error = %v", err)
		}
		// Pauses 0.25s + 0.5s before the third attempt.
		if elapsed < 700*time.Millisecond || elapsed > 850*time.Millisecond {
			t.Fatalf("retry elapsed = %v, want ~750ms (0.25s + 0.5s pauses)", elapsed)
		}
		if attempts != 3 {
			t.Fatalf("attempts = %d, want 3", attempts)
		}
	})
}

func TestRetryBudgetCapsAtRetryFor(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		gw := newFakeGateway()
		gw.routes = fakeRoutes()
		attempts := 0
		gw.callFn = func(method string, opts RequestOptions) (any, error) {
			attempts++
			return nil, NewConnectionDown(nil)
		}
		m := New(connectorReturning(gw), WithConfig(Config{}))
		m.retryFor = time.Second
		sc := &SharedConn{muse: m}
		start := time.Now()
		_, err := sc.CallJSON(context.Background(), "fs.read", RequestOptions{Route: &Route{Method: "fs.read", HTTP: "POST"}})
		elapsed := time.Since(start)
		var down *ConnectionDown
		if !errors.As(err, &down) {
			t.Fatalf("CallJSON() error = %v, want *ConnectionDown", err)
		}
		// Budget 1s: pauses 0.25 + 0.5 fit, the next 1s pause does not.
		if attempts != 3 {
			t.Fatalf("attempts = %d, want 3 within a 1s budget", attempts)
		}
		if elapsed > 900*time.Millisecond {
			t.Fatalf("retry elapsed = %v, want <= ~750ms within a 1s budget", elapsed)
		}
	})
}

func TestRetryAuthErrorNeverRetried(t *testing.T) {
	t.Parallel()
	gw := newFakeGateway()
	gw.routes = fakeRoutes()
	gw.callFn = func(method string, opts RequestOptions) (any, error) {
		return nil, fmt.Errorf("auth: %w", NewAuthError("cookies expired"))
	}
	m := New(connectorReturning(gw), WithConfig(Config{}))
	sc := &SharedConn{muse: m}
	_, err := sc.CallJSON(context.Background(), "fs.read", RequestOptions{Route: &Route{Method: "fs.read", HTTP: "POST"}})
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("CallJSON() error = %v, want *AuthError", err)
	}
	if got := gw.countOf("fs.read"); got != 1 {
		t.Fatalf("AuthError call count = %d, want 1 (never retried)", got)
	}
}

func TestRetrySafeVsUnsafeConnectionError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		method string
		route  Route
		want   int // CallJSON attempts
	}{
		{"safe read retries connection error", "fs.read", Route{Method: "fs.read", HTTP: "POST"}, 3},
		{"unsafe decide never retries connection error", "egress.approval.decide", Route{Method: "egress.approval.decide", HTTP: "POST"}, 1},
		{"unsafe subscribe never retries connection error", "chat.subscribe", Route{Method: "chat.subscribe", HTTP: "POST"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				gw := newFakeGateway()
				gw.routes = fakeRoutes()
				gw.callFn = func(method string, opts RequestOptions) (any, error) {
					return nil, &ConnectionError{Err: errors.New("lost mid-stream")}
				}
				m := New(connectorReturning(gw), WithConfig(Config{}))
				m.retryFor = time.Second
				sc := &SharedConn{muse: m}
				_, err := sc.CallJSON(context.Background(), tc.method, RequestOptions{Route: &tc.route})
				var ce *ConnectionError
				if !errors.As(err, &ce) {
					t.Fatalf("CallJSON() error = %v, want *ConnectionError", err)
				}
				if got := gw.countOf(tc.method); got != tc.want {
					t.Fatalf("attempts = %d, want %d", got, tc.want)
				}
			})
		})
	}
}

func TestRetryConnectionDownRetriedEvenWhenUnsafe(t *testing.T) {
	t.Parallel()
	// ConnectionDown means nothing was sent, so even an unsafe method
	// is repeated on a new connection (Python _retry: ConnectionDown
	// OR safe). The "never retry decide" rule covers errors raised
	// after a send (ConnectionError/GatewayError), not ConnectionDown.
	synctest.Test(t, func(t *testing.T) {
		gw := newFakeGateway()
		gw.routes = fakeRoutes()
		attempts := 0
		gw.callFn = func(method string, opts RequestOptions) (any, error) {
			attempts++
			if attempts == 1 {
				return nil, NewConnectionDown(nil)
			}
			return map[string]any{"ok": true}, nil
		}
		m := New(connectorReturning(gw), WithConfig(Config{}))
		sc := &SharedConn{muse: m}
		_, err := sc.CallJSON(context.Background(), "egress.approval.decide",
			RequestOptions{Route: &Route{Method: "egress.approval.decide", HTTP: "POST"}})
		if err != nil {
			t.Fatalf("CallJSON() error = %v", err)
		}
		if attempts != 2 {
			t.Fatalf("attempts = %d, want 2", attempts)
		}
	})
}

func TestRetryGatewayErrorNeverRetriedEvenWhenSafe(t *testing.T) {
	t.Parallel()
	gw := newFakeGateway()
	gw.routes = fakeRoutes()
	gw.callFn = func(method string, opts RequestOptions) (any, error) {
		return nil, &GatewayError{Status: 500, Payload: "boom"}
	}
	m := New(connectorReturning(gw), WithConfig(Config{}))
	sc := &SharedConn{muse: m}
	_, err := sc.CallJSON(context.Background(), "fs.read", RequestOptions{Route: &Route{Method: "fs.read", HTTP: "POST"}})
	var ge *GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("CallJSON() error = %v, want *GatewayError", err)
	}
	if got := gw.countOf("fs.read"); got != 1 {
		t.Fatalf("GatewayError call count = %d, want 1", got)
	}
}

func TestRetryReconnectFailureKeepsTryingWithinBudget(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		attempts := 0
		connector := func(_ context.Context, _ Config) (Gateway, error) {
			attempts++
			if attempts <= 2 {
				return nil, errors.New("connect refused")
			}
			gw := newFakeGateway()
			gw.routes = fakeRoutes()
			return gw, nil
		}
		m := New(connector, WithConfig(Config{}))
		m.retryFor = 5 * time.Second
		sc := &SharedConn{muse: m}
		got, err := sc.CallJSON(context.Background(), "fs.read", RequestOptions{Route: &Route{Method: "fs.read", HTTP: "POST"}})
		if err != nil {
			t.Fatalf("CallJSON() error = %v", err)
		}
		if got.(map[string]any)["ok"] != true {
			t.Fatalf("CallJSON() = %v", got)
		}
		if attempts != 3 {
			t.Fatalf("connector attempts = %d, want 3", attempts)
		}
	})
}

func TestSubscribeRawRetryCap(t *testing.T) {
	t.Parallel()
	// Only ConnectionDown before the stream opens is retried, max 3
	// attempts total (attempts 0, 1, 2 in Python).
	gw := newFakeGateway()
	attempts := 0
	gw.subscribeFn = func(method string, opts SubscribeOptions) ([][]byte, error) {
		attempts++
		return nil, NewConnectionDown(nil)
	}
	m := New(connectorReturning(gw), WithConfig(Config{}))
	sc := &SharedConn{muse: m}
	_, err := sc.SubscribeRaw(context.Background(), "chat.subscribe", SubscribeOptions{})
	var down *ConnectionDown
	if !errors.As(err, &down) {
		t.Fatalf("SubscribeRaw() error = %v, want *ConnectionDown", err)
	}
	if attempts != 3 {
		t.Fatalf("subscribe attempts = %d, want 3", attempts)
	}
}

func TestSubscribeRawSucceedsOnSecondAttempt(t *testing.T) {
	t.Parallel()
	gw := newFakeGateway()
	attempts := 0
	gw.subscribeFn = func(method string, opts SubscribeOptions) ([][]byte, error) {
		attempts++
		if attempts == 1 {
			return nil, NewConnectionDown(nil)
		}
		return [][]byte{[]byte(`{"seq":1}`)}, nil
	}
	m := New(connectorReturning(gw), WithConfig(Config{}))
	sc := &SharedConn{muse: m}
	records, err := sc.SubscribeRaw(context.Background(), "chat.subscribe", SubscribeOptions{})
	if err != nil {
		t.Fatalf("SubscribeRaw() error = %v", err)
	}
	if len(records) != 1 || attempts != 2 {
		t.Fatalf("records = %v, attempts = %d, want 1 record after 2 attempts", records, attempts)
	}
}

func TestSubscribeRawOtherErrorsNotRetried(t *testing.T) {
	t.Parallel()
	gw := newFakeGateway()
	attempts := 0
	gw.subscribeFn = func(method string, opts SubscribeOptions) ([][]byte, error) {
		attempts++
		return nil, &GatewayError{Status: 500, Payload: "boom"}
	}
	m := New(connectorReturning(gw), WithConfig(Config{}))
	sc := &SharedConn{muse: m}
	_, err := sc.SubscribeRaw(context.Background(), "chat.subscribe", SubscribeOptions{})
	var ge *GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("SubscribeRaw() error = %v, want *GatewayError", err)
	}
	if attempts != 1 {
		t.Fatalf("subscribe attempts = %d, want 1", attempts)
	}
}

func TestSharedConnLeaseAndCloseNoop(t *testing.T) {
	t.Parallel()
	gw := newFakeGateway()
	m := New(connectorReturning(gw), WithConfig(Config{}))
	sc := &SharedConn{muse: m}
	if sc.Lease() != Gateway(sc) {
		t.Fatal("SharedConn.Lease() did not return itself")
	}
	if err := sc.Close(); err != nil {
		t.Fatalf("SharedConn.Close() error = %v", err)
	}
	if gw.closeCallsCount() != 0 {
		t.Fatalf("SharedConn.Close() closed the shared gateway")
	}
	if sc.Alive() {
		t.Fatal("SharedConn.Alive() = true with no shared gateway, want false")
	}
	m.shared = gw
	if !sc.Alive() {
		t.Fatal("SharedConn.Alive() = false with a live shared gateway, want true")
	}
}

func TestSharedConnOpenStreamRetriesOnlyConnectionDown(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		gw := newFakeGateway()
		attempts := 0
		gw.openFn = func(method string, opts OpenStreamOptions) (int64, error) {
			attempts++
			if attempts == 1 {
				return 0, NewConnectionDown(nil)
			}
			return 7, nil
		}
		m := New(connectorReturning(gw), WithConfig(Config{}))
		sc := &SharedConn{muse: m}
		sid, err := sc.OpenStream(context.Background(), "chat.stream", OpenStreamOptions{Track: false})
		if err != nil {
			t.Fatalf("OpenStream() error = %v", err)
		}
		if sid != 7 || attempts != 2 {
			t.Fatalf("OpenStream() = (%d, attempts %d), want (7, 2)", sid, attempts)
		}
	})
}

func TestDownloadFileRetriesConnectionError(t *testing.T) {
	t.Parallel()
	// Python: download_file uses _retry(..., safe=True).
	synctest.Test(t, func(t *testing.T) {
		gw := newFakeGateway()
		attempts := 0
		gw.downloadFn = func(ref any, opts DownloadOptions) ([]byte, error) {
			attempts++
			if attempts == 1 {
				return nil, &ConnectionError{Err: errors.New("lost")}
			}
			return []byte("bytes"), nil
		}
		m := New(connectorReturning(gw), WithConfig(Config{}))
		sc := &SharedConn{muse: m}
		got, err := sc.DownloadFile(context.Background(), "sandbox://x", DownloadOptions{})
		if err != nil {
			t.Fatalf("DownloadFile() error = %v", err)
		}
		if string(got) != "bytes" || attempts != 2 {
			t.Fatalf("DownloadFile() = (%q, attempts %d), want (bytes, 2)", got, attempts)
		}
	})
}
