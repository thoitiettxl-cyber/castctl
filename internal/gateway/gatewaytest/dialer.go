package gatewaytest

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/option"
)

// FakeDialer implements gateway.OutboundDialer against a fake
// gateway Server (loopback, plain TCP — TLS is deliberately not
// involved: the dialer ignores the requested host/port/security
// and dials the Server's listener) and an in-memory HTTP handler
// for muse.ai HTTPS calls. It is the "FAKE outbound" behind
// end-to-end gateway tests: auth chain, handshake, ServiceRequest
// round-trips, subscriptions, downloads, heartbeat and reconnect
// behaviour are all exercised without a live VM.
//
// The zero value is unusable; build one with NewFakeDialer.
type FakeDialer struct {
	serverAddr  string
	httpHandler http.Handler
	dials       atomic.Int64
}

// NewFakeDialer builds a FakeDialer for server. httpHandler serves
// every HTTPS request the gateway's auth/RSC/invite clients make
// (it sees the real muse.ai URLs); it may be nil, in which case
// HTTPS calls fail closed with 500.
func NewFakeDialer(server *Server, httpHandler http.Handler) *FakeDialer {
	if httpHandler == nil {
		httpHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "no fake http handler", http.StatusInternalServerError)
		})
	}
	return &FakeDialer{serverAddr: server.Addr(), httpHandler: httpHandler}
}

// WebSocketDial dials the fake server's listener, ignoring host,
// port and secure: the fake outbound always returns a plain
// loopback conn to the fake gateway.
func (d *FakeDialer) WebSocketDial(ctx context.Context, network, host string, port uint16, secure bool, _ option.OutboundTLSOptions) (net.Conn, error) {
	d.dials.Add(1)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, "tcp", d.serverAddr)
}

// HTTPClient returns a client whose transport serves requests
// through the fake HTTP handler in memory.
func (d *FakeDialer) HTTPClient() *http.Client {
	return &http.Client{Transport: HandlerRoundTripper(d.httpHandler)}
}

// Dials returns how many WebSocket dials have been made.
func (d *FakeDialer) Dials() int64 { return d.dials.Load() }

// CannedAuth is an http.Handler serving the 3-step auth chain
// with canned values. Counts record how many times each step ran.
// Failure injection: set a status to non-zero to force that step
// to fail with that status; set SessionNoVMID to return a session
// body without vm_id (the "VM unavailable" case).
type CannedAuth struct {
	VMID        string
	AccessToken string
	HatchToken  string

	SessionStatus   int
	SessionNoVMID   bool
	AuthCheckStatus int
	HatchStatus     int

	SessionCalls   atomic.Int64
	AuthCheckCalls atomic.Int64
	HatchCalls     atomic.Int64

	// SeenCookies records the Cookie header values received, in
	// call order. Values are the fake cookie only in tests.
	SeenCookies []string
	mu          sync.Mutex
}

// ServeHTTP implements http.Handler.
func (c *CannedAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.SeenCookies = append(c.SeenCookies, r.Header.Get("Cookie"))
	c.mu.Unlock()
	switch r.URL.Path {
	case "/api/session":
		c.SessionCalls.Add(1)
		if c.SessionStatus != 0 {
			WriteJSON(w, c.SessionStatus, `{"error":"canned"}`)
			return
		}
		if c.SessionNoVMID {
			WriteJSON(w, 200, `{"status":"unavailable","vm_resolution_issue":{"kind":"retryable"}}`)
			return
		}
		WriteJSON(w, 200, fmt.Sprintf(`{"vm_id":%q}`, c.VMID))
	case "/api/auth/check":
		c.AuthCheckCalls.Add(1)
		if c.AuthCheckStatus != 0 {
			WriteJSON(w, c.AuthCheckStatus, `{"error":"canned"}`)
			return
		}
		WriteJSON(w, 200, fmt.Sprintf(`{"access_token":%q}`, c.AccessToken))
	case "/api/hatch/token":
		c.HatchCalls.Add(1)
		if c.HatchStatus != 0 {
			WriteJSON(w, c.HatchStatus, `{"error":"canned"}`)
			return
		}
		WriteJSON(w, 200, fmt.Sprintf(`{"token":%q}`, c.HatchToken))
	default:
		http.NotFound(w, r)
	}
}
