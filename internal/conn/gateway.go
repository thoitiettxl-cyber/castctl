// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package conn

import (
	"context"
	"time"
)

// Timing constants, ported verbatim from conn.py (seconds in Python,
// durations here; the Go names follow MixedCaps convention — the
// values are identical).
const (
	// ConnectTimeout bounds one whole connect (token fetches, WebSocket
	// and Noise handshake) in BoundedConnect.
	ConnectTimeout = 60 * time.Second
	// Heartbeat is the quiet interval after which a shared connection
	// is pinged by the stale probe and the heartbeat goroutine.
	Heartbeat = 25 * time.Second
	// DownNotice is the time without a working connection before
	// OnDown fires once.
	DownNotice = 60 * time.Second
	// DownFails is the number of coalesced failed reconnects before
	// OnDown fires once.
	DownFails = 5
	// RetryFor bounds how long SharedConn keeps retrying one request
	// across reconnects.
	RetryFor = 30 * time.Second
	// FailSpacing coalesces failed reconnects closer than this into
	// one counted failure.
	FailSpacing = 2 * time.Second
	// StalePingTimeout bounds the liveness ping in the stale probe
	// (Python: ping(timeout=5)).
	StalePingTimeout = 5 * time.Second
	// HeartbeatPingTimeout bounds the heartbeat goroutine's ping
	// (Python: ping() with its 10s default).
	HeartbeatPingTimeout = 10 * time.Second
	// HeartbeatStopTimeout bounds StopHeartbeat's wait for the
	// heartbeat goroutine (Python: join(timeout=6)).
	HeartbeatStopTimeout = 6 * time.Second
	// MaxSubscribeAttempts is the total number of attempts
	// SharedConn.SubscribeRaw makes when the connection is down
	// before the stream opens (Python: attempts 0, 1, 2).
	MaxSubscribeAttempts = 3
	// RetryPauseInitial is the first pause between SharedConn retries;
	// RetryPauseMax caps the doubling ladder (Python: 0.25 doubling
	// to 4s).
	RetryPauseInitial = 250 * time.Millisecond
	RetryPauseMax     = 4 * time.Second
	// SubscribeRetryPause is the fixed pause between SubscribeRaw
	// attempts (Python: time.sleep(0.25)).
	SubscribeRetryPause = 250 * time.Millisecond
)

// Identity is the part of a profile that identifies a connection:
// when any field changes, the warm connection belongs to another
// profile or VM and must be dropped (see Muse.Reload). It mirrors the
// (cookies_file, vm_id, node_id) triple in Python's Muse.reload.
type Identity struct {
	CookiesFile string
	VMID        string
	NodeID      string
}

// Config is what a Connector receives: the identity of the profile to
// connect for. It carries no dialer, no HTTP client and no secret:
// the concrete Connector closure (built by internal/gateway wiring)
// captures the outbound Dialer and resolves cookies itself from
// CookiesFile. Wiring code maps a profile.Profile onto Config by
// copying CookiesFile, VMID and NodeID.
type Config struct {
	CookiesFile string
	VMID        string
	NodeID      string
}

// Identity returns the connection identity of this Config.
func (c Config) Identity() Identity {
	return Identity{CookiesFile: c.CookiesFile, VMID: c.VMID, NodeID: c.NodeID}
}

// Connector opens one gateway connection for cfg. It is the Go form of
// Python's `connector(cfg)` / cli.connect: the implementation (in
// internal/gateway wiring, NOT in this package) fetches tokens over
// HTTPS, dials through internal/outbound's Dialer, and returns a
// Gateway. The gateway NEVER dials itself, and this package never
// dials: BoundedConnect only bounds the Connector in time.
//
// Auth failures MUST be returned as *AuthError so they pass through
// unwrapped-typed. The Connector MUST honour ctx cancellation.
type Connector func(ctx context.Context, cfg Config) (Gateway, error)

// ReloadFunc reloads the current profile's Config, mirroring
// cli.load_config in Python's Muse.reload. It is injected because
// this package must not depend on internal/profile or on the
// filesystem: wiring code supplies a func that loads the active
// profile and maps it onto Config. A nil ReloadFunc means Reload
// returns the Config Muse was built with and never resets.
type ReloadFunc func() (Config, error)

// Route describes one gateway route: the HTTP verb, path template and
// service of a method, as listed in routes.json. Only HTTP is needed
// by this package (safe-to-repeat); Path and Service are carried so
// callers need not look them up twice. Route ownership stays with
// internal/gateway (routes.json); this package only consumes Routes
// through LookupRoute.
type Route struct {
	Method  string
	HTTP    string
	Path    string
	Service string
}

// RequestOptions carries the arguments of one unary gateway call.
// It mirrors Python's Gateway.request/call_json keyword arguments
// (path_params, body, query, timeout, route), adapted to Go: ctx is
// a separate first parameter on every method, and the options travel
// in one struct instead of **kw.
//
// Body is the request body before JSON encoding: nil (no body), a
// []byte or string (sent verbatim), or a value the gateway marshals
// to JSON (maps must use string keys; numbers must be int64 or
// json.Number, never float64 — see the plan's JSON invariant).
// A GET with a non-nil Body and a nil Query behaves as Python does:
// the gateway moves the body into the query string and sends no body.
// Query values are URL-encoded; nil values are dropped.
//
// Timeout bounds one call on the gateway (Python default 30s); zero
// means the gateway default. Deadline is an absolute monotonic
// deadline consumed ONLY by SharedConn's retry budget (Python's
// _deadline kwarg, popped before the gateway sees it); a direct
// Gateway call ignores it. Route, when non-nil, overrides the
// gateway's route-table lookup for this call.
type RequestOptions struct {
	PathParams map[string]string
	Body       any
	Query      map[string]string
	Timeout    time.Duration
	Route      *Route
	Deadline   time.Time
}

// DownloadOptions carries the arguments of DownloadFile. Timeout
// bounds the download (Python default 300s); zero means the gateway
// default. Deadline is consumed only by SharedConn's retry budget.
// Route, when non-nil, overrides the gateway's synthetic media.raw
// route for this call.
type DownloadOptions struct {
	Timeout  time.Duration
	Route    *Route
	Deadline time.Time
}

// SubscribeOptions carries the arguments of one subscription. It
// mirrors Python's subscribe_raw keyword arguments.
//
// MaxRecords caps the returned records (Python default 100); zero or
// negative means the gateway default. IdleTimeout ends the
// subscription after this long with no frame (Python default 10s);
// OverallTimeout bounds the whole subscription (Python default 120s);
// zero means the gateway default in both cases.
//
// OnRecord is called with each record the moment it arrives; a true
// return stops the subscription right there. ShouldStop is polled
// about every 0.5s even while no records arrive; a true return ends
// the subscription. OnOpen is called once the subscription request is
// on the wire. All three callbacks run on the calling goroutine;
// they must not call back into the same Gateway (the reader goroutine
// owns frame delivery) and must not block: a slow callback stalls
// the stream. Route, when non-nil, overrides the gateway's
// route-table lookup for this call.
type SubscribeOptions struct {
	PathParams     map[string]string
	Body           any
	Query          map[string]string
	MaxRecords     int
	IdleTimeout    time.Duration
	OverallTimeout time.Duration
	OnRecord       func(record []byte) bool
	ShouldStop     func() bool
	OnOpen         func()
	Route          *Route
}

// OpenStreamOptions carries the arguments of OpenStream (Python's
// Gateway._open). Track controls frame delivery: when Track is true,
// the gateway queues frames for this stream; when false, nobody reads
// its frames and the gateway MUST drop them (the reader still reads
// them off the wire, so the connection stays healthy). Either way
// the request is sent and a stream ID is returned; end the stream
// with CancelStream.
type OpenStreamOptions struct {
	PathParams map[string]string
	Body       any
	Query      map[string]string
	Route      *Route
	Track      bool
}

// Gateway is the CONSUMER-side contract W-gateway must implement.
// Method names match Python's Gateway exactly (CallJSON, Request,
// SubscribeRaw, SubscribeJSON, DownloadFile, Ping, Close, Alive,
// Lease, OpenStream for _open); signatures are adapted to Go (ctx
// first, option structs, explicit error returns, Alive as a method
// instead of a property). Renames and additions are recorded here:
//
//   - Alive is a method, not a property (Go has no properties).
//   - _open becomes the exported OpenStream; its private helpers
//     _forget/_cancel are NOT in the contract. CancelStream is the
//     one justified addition: it sends the CANCELLED reset and
//     forgets the stream, which callers of OpenStream need and
//     Python's private _cancel provided inside the gateway.
//   - LookupRoute is required: SharedConn's safe-to-repeat decision
//     needs the HTTP verb of a method. It MUST be backed by
//     routes.json (method/http/path/service). Without it, GET-only
//     methods are conservatively treated as unsafe.
//   - Dead and LastRecv/LastUsed expose what Python reads as
//     attributes (gw.dead, last_recv_mono, last_used_mono). The
//     timestamps MUST be monotonic (captured with time.Now); a zero
//     time.Time means "just now" (age 0).
//
// Error contract (binding on implementations):
//
//   - Auth failures: *AuthError. Never retried, never marked down.
//   - Server failures: *GatewayError (status, truncated payload).
//     Never retried.
//   - Nothing sent yet (gateway already down, checked before
//     sending): *ConnectionDown. Retried by SharedConn for every
//     method. OpenStream MUST return *ConnectionDown before
//     building or sending anything when the gateway is dead or
//     closed (Python N5).
//   - Sent, reply possibly lost: *ConnectionError. Retried only
//     when safe to repeat.
//   - No response before the deadline: *TimeoutError (unwraps to
//     context.DeadlineExceeded). Never retried.
//   - Bare net errors, bare io errors, and panics MUST NOT escape a
//     Gateway method: map them to the types above. A panic in the
//     reader goroutine must be recorded via Dead, never crash the
//     process.
//   - SubscribeRaw MUST return *ConnectionDown only when the stream
//     never opened. Once OnOpen has fired or a frame has arrived,
//     connection loss surfaces as *ConnectionError (or the records
//     gathered so far plus an error the caller can distinguish),
//     never as *ConnectionDown, or SharedConn would resubscribe a
//     stream that already delivered records.
//   - Record slices returned by SubscribeRaw MUST be freshly
//     allocated: the caller may retain them after the call returns.
//   - Close is idempotent and safe to call concurrently with a
//     blocked Ping/CallJSON: it must unblock the reader promptly
//     (Python: reader join 1s, I/O lock wait 2s, then close anyway).
//     Close on a lease (see Leaser) is a no-op.
//
// Concurrency contract: a Gateway is safe for concurrent use by any
// number of goroutines (multiplexed streams), exactly as Python's
// Gateway is shared across threads. Exactly ONE reader goroutine
// per gateway demultiplexes frames; that goroutine lives in
// internal/gateway, never in internal/conn.
type Gateway interface {
	// CallJSON performs one unary call and returns the decoded JSON
	// result: the "result" field of a {"ok":true} envelope, or the
	// whole decoded value otherwise (Python call_json). Numbers are
	// decoded as int64/json.Number, never float64.
	CallJSON(ctx context.Context, method string, opts RequestOptions) (any, error)
	// Request performs one unary call and returns the raw response
	// payload bytes (Python request).
	Request(ctx context.Context, method string, opts RequestOptions) ([]byte, error)
	// SubscribeRaw opens a subscription and returns the raw NDJSON
	// record bytes (Python subscribe_raw). See SubscribeOptions and
	// the ConnectionDown-only-before-open rule above.
	SubscribeRaw(ctx context.Context, method string, opts SubscribeOptions) ([][]byte, error)
	// SubscribeJSON is SubscribeRaw with bad JSON lines dropped
	// (Python subscribe_json).
	SubscribeJSON(ctx context.Context, method string, opts SubscribeOptions) ([]any, error)
	// DownloadFile returns the bytes of a sandbox file. Ref is a
	// sandbox:// path, a media URL, a bare /media/raw/... path, or
	// a resource dict (map with "path" and/or "variants.original"),
	// exactly as Python's media_path accepts (Python download_file).
	DownloadFile(ctx context.Context, ref any, opts DownloadOptions) ([]byte, error)
	// Ping is the web app's heartbeat: connection.ping with
	// {"presence":"away"}, bounded by timeout even when ctx has no
	// deadline (Python ping(timeout=10)).
	Ping(ctx context.Context, timeout time.Duration) (any, error)
	// OpenStream starts a stream and returns its stream ID (Python
	// _open). See OpenStreamOptions for Track semantics.
	OpenStream(ctx context.Context, method string, opts OpenStreamOptions) (int64, error)
	// CancelStream ends a stream opened by OpenStream: it forgets
	// the stream and sends the CANCELLED reset when the gateway is
	// alive (Python _cancel). It is a no-op for an unknown stream
	// ID. It never returns *ConnectionDown.
	CancelStream(ctx context.Context, streamID int64) error
	// LookupRoute returns the route for a method from routes.json,
	// or false when the method is unknown.
	LookupRoute(method string) (Route, bool)
	// Alive reports whether the connection is up: not closed and
	// no fatal reader error (Python alive property).
	Alive() bool
	// Dead returns the fatal error that killed the reader goroutine,
	// or nil when the gateway is healthy or was closed cleanly
	// (Python dead attribute).
	Dead() error
	// LastRecv returns the monotonic time of the last frame received
	// from the server (Python last_recv_mono). Zero means just now.
	LastRecv() time.Time
	// LastUsed returns the monotonic time of the last send on this
	// gateway (Python last_used_mono). Zero means just now.
	LastUsed() time.Time
	// Close closes the connection. See the idempotency rule above.
	Close() error
}

// Leaser is the shareability half of the contract, kept separate from
// Gateway so a connector whose gateways cannot be shared can return a
// Gateway that does not implement it (Python: hasattr(gw, "lease")).
// Every real gateway MUST implement Leaser: Lease returns a view of
// the same connection whose Close is a no-op, so code that calls
// Close when done leaves a shared warm connection up (Python
// Gateway.lease / Lease). Muse.Connect returns a SharedConn for a
// Leaser gateway and the raw gateway itself otherwise.
type Leaser interface {
	// Lease returns the no-op-close view of this gateway.
	Lease() Gateway
}
