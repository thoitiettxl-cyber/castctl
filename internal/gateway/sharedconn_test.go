// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

// countingGateway is a minimal conn.Gateway for SharedConn retry
// tests: every method is scripted and counted.
type countingGateway struct {
	mu         sync.Mutex
	alive      bool
	callCounts map[string]int
	callFn     func(method string, opts conn.RequestOptions) (any, error)
	requestFn  func(method string, opts conn.RequestOptions) ([]byte, error)
	routes     map[string]conn.Route
}

func newCountingGateway() *countingGateway {
	return &countingGateway{
		alive:      true,
		callCounts: map[string]int{},
		routes: map[string]conn.Route{
			"egress.approval.decide": {Method: "egress.approval.decide", HTTP: "POST", Path: "/approvals/{approval_id}/decide", Service: "sentinel"},
			"chat.history":           {Method: "chat.history", HTTP: "GET", Path: "/chat/history"},
		},
	}
}

func (f *countingGateway) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callCounts[method]
}

func (f *countingGateway) CallJSON(_ context.Context, method string, opts conn.RequestOptions) (any, error) {
	f.mu.Lock()
	f.callCounts[method]++
	fn := f.callFn
	f.mu.Unlock()
	if fn != nil {
		return fn(method, opts)
	}
	return nil, nil
}

func (f *countingGateway) Request(_ context.Context, method string, opts conn.RequestOptions) ([]byte, error) {
	f.mu.Lock()
	f.callCounts[method]++
	fn := f.requestFn
	f.mu.Unlock()
	if fn != nil {
		return fn(method, opts)
	}
	return []byte(`{}`), nil
}

func (f *countingGateway) SubscribeRaw(_ context.Context, _ string, _ conn.SubscribeOptions) ([][]byte, error) {
	return nil, nil
}

func (f *countingGateway) SubscribeJSON(_ context.Context, _ string, _ conn.SubscribeOptions) ([]any, error) {
	return nil, nil
}

func (f *countingGateway) DownloadFile(_ context.Context, _ any, _ conn.DownloadOptions) ([]byte, error) {
	return nil, nil
}

func (f *countingGateway) Ping(_ context.Context, _ time.Duration) (any, error) { return nil, nil }

func (f *countingGateway) OpenStream(_ context.Context, _ string, _ conn.OpenStreamOptions) (int64, error) {
	return 0, nil
}

func (f *countingGateway) CancelStream(_ context.Context, _ int64) error { return nil }

func (f *countingGateway) LookupRoute(method string) (conn.Route, bool) {
	r, ok := f.routes[method]
	return r, ok
}

func (f *countingGateway) Alive() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alive
}

func (f *countingGateway) Dead() error { return nil }

func (f *countingGateway) LastRecv() time.Time { return time.Now() }

func (f *countingGateway) LastUsed() time.Time { return time.Now() }

func (f *countingGateway) Close() error { return nil }

func (f *countingGateway) Lease() conn.Gateway { return f }

// TestSharedConnNeverRetriesApprovalDecide: egress.approval.decide
// is NOT safe to repeat. A ConnectionError after the send must be
// returned immediately, with exactly one attempt — deciding twice
// could double-apply. (Python: decide is not in _READ_METHODS and
// is never retried on ConnectionError.)
func TestSharedConnNeverRetriesApprovalDecide(t *testing.T) {
	fake := newCountingGateway()
	downErr := &conn.ConnectionError{Err: errors.New("reply lost")}
	fake.callFn = func(method string, opts conn.RequestOptions) (any, error) {
		return nil, downErr
	}
	var connectorCalls int
	var mu sync.Mutex
	muse := conn.New(func(ctx context.Context, cfg conn.Config) (conn.Gateway, error) {
		mu.Lock()
		connectorCalls++
		mu.Unlock()
		return fake, nil
	}, conn.WithConfig(conn.Config{CookiesFile: "cookies.txt", VMID: "vm-1", NodeID: "node-1"}))
	shared, err := muse.Connect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	_, err = shared.CallJSON(context.Background(), "egress.approval.decide", conn.RequestOptions{})
	if err == nil {
		t.Fatal("nil error")
	}
	var ce *conn.ConnectionError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %T (%v), want ConnectionError", err, err)
	}
	if got := fake.count("egress.approval.decide"); got != 1 {
		t.Fatalf("decide attempts = %d, want exactly 1", got)
	}
}

// TestSharedConnReconnectsAfterDrop: a ConnectionDown (nothing
// sent) on a safe GET is retried on a fresh connection from a
// second Connector call, and succeeds.
func TestSharedConnReconnectsAfterDrop(t *testing.T) {
	first := newCountingGateway()
	second := newCountingGateway()
	second.requestFn = func(method string, opts conn.RequestOptions) ([]byte, error) {
		return []byte(`{"ok":true}`), nil
	}
	first.requestFn = func(method string, opts conn.RequestOptions) ([]byte, error) {
		// Mark this gateway dead so the retry reopens through
		// the Connector instead of reusing the shared slot.
		first.mu.Lock()
		first.alive = false
		first.mu.Unlock()
		return nil, conn.NewConnectionDown(errors.New("dropped before send"))
	}
	var calls int
	var mu sync.Mutex
	muse := conn.New(func(ctx context.Context, cfg conn.Config) (conn.Gateway, error) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		// The first gateway is reported dead by its own
		// requestFn (see above) so Live() reopens on retry.
		if n == 1 {
			return first, nil
		}
		return second, nil
	}, conn.WithConfig(conn.Config{CookiesFile: "cookies.txt", VMID: "vm-1", NodeID: "node-1"}))
	shared, err := muse.Connect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	// Flip the first gateway to not-alive so the retry reopens.
	// (Done inside first.requestFn on its first attempt.)
	got, err := shared.Request(context.Background(), "chat.history", conn.RequestOptions{})
	if err != nil {
		t.Fatalf("Request after drop: %v", err)
	}
	if string(got) != `{"ok":true}` {
		t.Errorf("got %q", got)
	}
	if c := first.count("chat.history"); c != 1 {
		t.Errorf("first gateway attempts = %d, want 1", c)
	}
	if c := second.count("chat.history"); c != 1 {
		t.Errorf("second gateway attempts = %d, want 1", c)
	}
	mu.Lock()
	total := calls
	mu.Unlock()
	if total < 2 {
		t.Errorf("connector calls = %d, want >= 2", total)
	}
}

// TestSharedConnAuthErrorNeverRetried: an AuthError from the
// gateway propagates immediately with one attempt.
func TestSharedConnAuthErrorNeverRetried(t *testing.T) {
	fake := newCountingGateway()
	fake.callFn = func(method string, opts conn.RequestOptions) (any, error) {
		return nil, conn.NewAuthError("cookies expired")
	}
	muse := conn.New(func(ctx context.Context, cfg conn.Config) (conn.Gateway, error) {
		return fake, nil
	}, conn.WithConfig(conn.Config{CookiesFile: "cookies.txt", VMID: "vm-1", NodeID: "node-1"}))
	shared, err := muse.Connect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	_, err = shared.CallJSON(context.Background(), "chat.history", conn.RequestOptions{})
	var ae *conn.AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %T (%v), want AuthError", err, err)
	}
	if got := fake.count("chat.history"); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

// TestErrorTaxonomyMapping asserts errors.As finds each taxonomy
// type through the gateway's own error values, as SharedConn's
// retry classification requires.
func TestErrorTaxonomyMapping(t *testing.T) {
	var ae *conn.AuthError
	if !errors.As(conn.NewAuthError("x"), &ae) {
		t.Error("AuthError not found by errors.As")
	}
	var ge *conn.GatewayError
	if !errors.As(&conn.GatewayError{Status: -1, Payload: "x"}, &ge) {
		t.Error("GatewayError not found by errors.As")
	}
	var down *conn.ConnectionDown
	if !errors.As(conn.NewConnectionDown(nil), &down) {
		t.Error("ConnectionDown not found by errors.As")
	}
	var ce *conn.ConnectionError
	if !errors.As(&conn.ConnectionError{Err: errors.New("x")}, &ce) {
		t.Error("ConnectionError not found by errors.As")
	}
	var te *conn.TimeoutError
	if !errors.As(&conn.TimeoutError{Message: "x"}, &te) {
		t.Error("TimeoutError not found by errors.As")
	}
	if !errors.Is(&conn.TimeoutError{Message: "x"}, context.DeadlineExceeded) {
		t.Error("TimeoutError does not unwrap to DeadlineExceeded")
	}
}
