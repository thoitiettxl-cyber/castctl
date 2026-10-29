package conn

import (
	"context"
	"sync"
	"time"
)

// fakeGateway is an in-memory Gateway for tests. No network, no loopback
// socket: every method is scripted through the Fn fields, and every call
// is counted under mu so tests can assert retry behaviour exactly.
type fakeGateway struct {
	mu          sync.Mutex
	alive       bool
	deadErr     error
	recv        time.Time
	used        time.Time
	pingErr     error
	pingCalls   int
	closeCalls  int
	closed      bool
	callFn      func(method string, opts RequestOptions) (any, error)
	requestFn   func(method string, opts RequestOptions) ([]byte, error)
	subscribeFn func(method string, opts SubscribeOptions) ([][]byte, error)
	downloadFn  func(ref any, opts DownloadOptions) ([]byte, error)
	openFn      func(method string, opts OpenStreamOptions) (int64, error)
	cancelCalls int
	routes      map[string]Route
	callCounts  map[string]int
}

func newFakeGateway() *fakeGateway {
	return &fakeGateway{
		alive:      true,
		recv:       time.Now(),
		used:       time.Now(),
		routes:     map[string]Route{},
		callCounts: map[string]int{},
	}
}

func (f *fakeGateway) setAlive(alive bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alive = alive
}

func (f *fakeGateway) setStamps(recv, used time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recv, f.used = recv, used
}

func (f *fakeGateway) setDead(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deadErr = err
}

func (f *fakeGateway) setPingErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pingErr = err
}

func (f *fakeGateway) pingCallsCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pingCalls
}

func (f *fakeGateway) closeCallsCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeCalls
}

func (f *fakeGateway) countOf(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callCounts[method]
}

func (f *fakeGateway) CallJSON(_ context.Context, method string, opts RequestOptions) (any, error) {
	f.mu.Lock()
	f.callCounts[method]++
	fn := f.callFn
	f.mu.Unlock()
	if fn != nil {
		return fn(method, opts)
	}
	return map[string]any{"ok": true}, nil
}

func (f *fakeGateway) Request(_ context.Context, method string, opts RequestOptions) ([]byte, error) {
	if f.requestFn != nil {
		return f.requestFn(method, opts)
	}
	return []byte(`{}`), nil
}

func (f *fakeGateway) SubscribeRaw(_ context.Context, method string, opts SubscribeOptions) ([][]byte, error) {
	if f.subscribeFn != nil {
		return f.subscribeFn(method, opts)
	}
	return nil, nil
}

func (f *fakeGateway) SubscribeJSON(ctx context.Context, method string, opts SubscribeOptions) ([]any, error) {
	raw, err := f.SubscribeRaw(ctx, method, opts)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(raw))
	for _, r := range raw {
		out = append(out, string(r))
	}
	return out, nil
}

func (f *fakeGateway) DownloadFile(_ context.Context, ref any, opts DownloadOptions) ([]byte, error) {
	if f.downloadFn != nil {
		return f.downloadFn(ref, opts)
	}
	return []byte("file-bytes"), nil
}

func (f *fakeGateway) Ping(_ context.Context, _ time.Duration) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pingCalls++
	if f.pingErr != nil {
		return nil, f.pingErr
	}
	return map[string]any{"ok": true}, nil
}

func (f *fakeGateway) OpenStream(_ context.Context, _ string, opts OpenStreamOptions) (int64, error) {
	if f.openFn != nil {
		return f.openFn("", opts)
	}
	return 1, nil
}

func (f *fakeGateway) CancelStream(_ context.Context, _ int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelCalls++
	return nil
}

func (f *fakeGateway) LookupRoute(method string) (Route, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.routes[method]
	return r, ok
}

func (f *fakeGateway) Alive() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alive && !f.closed
}

func (f *fakeGateway) Dead() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deadErr
}

func (f *fakeGateway) LastRecv() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.recv
}

func (f *fakeGateway) LastUsed() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.used
}

func (f *fakeGateway) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalls++
	f.closed = true
	return nil
}

func (f *fakeGateway) Lease() Gateway { return &fakeLease{gw: f} }

// fakeLease is the no-op-close view of a fakeGateway, mirroring the
// Python Lease proxy.
type fakeLease struct{ gw *fakeGateway }

func (l *fakeLease) CallJSON(ctx context.Context, method string, opts RequestOptions) (any, error) {
	return l.gw.CallJSON(ctx, method, opts)
}

func (l *fakeLease) Request(ctx context.Context, method string, opts RequestOptions) ([]byte, error) {
	return l.gw.Request(ctx, method, opts)
}

func (l *fakeLease) SubscribeRaw(ctx context.Context, method string, opts SubscribeOptions) ([][]byte, error) {
	return l.gw.SubscribeRaw(ctx, method, opts)
}

func (l *fakeLease) SubscribeJSON(ctx context.Context, method string, opts SubscribeOptions) ([]any, error) {
	return l.gw.SubscribeJSON(ctx, method, opts)
}

func (l *fakeLease) DownloadFile(ctx context.Context, ref any, opts DownloadOptions) ([]byte, error) {
	return l.gw.DownloadFile(ctx, ref, opts)
}

func (l *fakeLease) Ping(ctx context.Context, timeout time.Duration) (any, error) {
	return l.gw.Ping(ctx, timeout)
}

func (l *fakeLease) OpenStream(ctx context.Context, method string, opts OpenStreamOptions) (int64, error) {
	return l.gw.OpenStream(ctx, method, opts)
}

func (l *fakeLease) CancelStream(ctx context.Context, streamID int64) error {
	return l.gw.CancelStream(ctx, streamID)
}

func (l *fakeLease) LookupRoute(method string) (Route, bool) { return l.gw.LookupRoute(method) }
func (l *fakeLease) Alive() bool                             { return l.gw.Alive() }
func (l *fakeLease) Dead() error                             { return l.gw.Dead() }
func (l *fakeLease) LastRecv() time.Time                     { return l.gw.LastRecv() }
func (l *fakeLease) LastUsed() time.Time                     { return l.gw.LastUsed() }
func (l *fakeLease) Close() error                            { return nil }
func (l *fakeLease) Lease() Gateway                          { return l }

// fakeRoutes mirrors the routes.json verbs for the methods the
// safe-to-repeat table exercises: GET reads plus the POST reads.
func fakeRoutes() map[string]Route {
	return map[string]Route{
		"chat.history":               {Method: "chat.history", HTTP: "GET", Path: "/chat/history", Service: "daemon"},
		"sessions.list":              {Method: "sessions.list", HTTP: "GET", Path: "/api/session/list", Service: "daemon"},
		"egress.approvals":           {Method: "egress.approvals", HTTP: "GET", Path: "/approvals", Service: "daemon"},
		"connection.ping":            {Method: "connection.ping", HTTP: "POST", Path: "/api/ping", Service: "daemon"},
		"custom_connectors.list":     {Method: "custom_connectors.list", HTTP: "POST", Path: "/v1/custom-connectors/list", Service: "daemon"},
		"fs.list":                    {Method: "fs.list", HTTP: "POST", Path: "/fs/list", Service: "daemon"},
		"fs.read":                    {Method: "fs.read", HTTP: "POST", Path: "/fs/read", Service: "daemon"},
		"fs.reads":                   {Method: "fs.reads", HTTP: "POST", Path: "/fs/reads", Service: "daemon"},
		"fs.stat":                    {Method: "fs.stat", HTTP: "POST", Path: "/fs/stat", Service: "daemon"},
		"fs.stats":                   {Method: "fs.stats", HTTP: "POST", Path: "/fs/stats", Service: "daemon"},
		"memory.get":                 {Method: "memory.get", HTTP: "POST", Path: "/memory/get", Service: "daemon"},
		"node.list":                  {Method: "node.list", HTTP: "POST", Path: "/api/nodes/list", Service: "daemon"},
		"egress.approval.decide":     {Method: "egress.approval.decide", HTTP: "POST", Path: "/approvals/{approval_id}/decide", Service: "daemon"},
		"chat.subscribe":             {Method: "chat.subscribe", HTTP: "POST", Path: "/chat/subscribe", Service: "daemon"},
		"chat.mark_seen":             {Method: "chat.mark_seen", HTTP: "POST", Path: "/api/chat/{thread_id}/seen", Service: "daemon"},
		"shopping.events":            {Method: "shopping.events", HTTP: "POST", Path: "/api/shopping/events", Service: "daemon"},
		"identity.subscribe":         {Method: "identity.subscribe", HTTP: "POST", Path: "/identity/subscribe", Service: "daemon"},
		"messenger-read.unlock":      {Method: "messenger-read.unlock", HTTP: "POST", Path: "/api/messenger-read/unlock", Service: "daemon"},
		"shared_agents.state.update": {Method: "shared_agents.state.update", HTTP: "PATCH", Path: "/shared-agents/{shared_agent_id}/state", Service: "daemon"},
		"widgets.state.patch":        {Method: "widgets.state.patch", HTTP: "POST", Path: "/widgets/state/patch", Service: "daemon"},
		"widgets.state.set":          {Method: "widgets.state.set", HTTP: "POST", Path: "/widgets/state", Service: "daemon"},
	}
}

// connectorReturning returns a Connector that hands out gw on every call.
func connectorReturning(gw Gateway) Connector {
	return func(_ context.Context, _ Config) (Gateway, error) { return gw, nil }
}

// connectorFactory returns a Connector that builds one fresh fakeGateway
// per call and records them, for loser-closes-surplus tests. The
// recording is mutex-guarded: calls arrive concurrently. block runs
// outside the mutex: it is the barrier that holds the connector open.
func connectorFactory(made *[]*fakeGateway, calls *int, block func()) Connector {
	var mu sync.Mutex
	return func(_ context.Context, _ Config) (Gateway, error) {
		mu.Lock()
		gw := newFakeGateway()
		*made = append(*made, gw)
		*calls++
		mu.Unlock()
		if block != nil {
			block()
		}
		return gw, nil
	}
}
