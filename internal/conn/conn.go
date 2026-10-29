// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package conn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Muse is the shared warm gateway connection for one profile, ported
// from Python's conn.Muse. All calls share one multiplexed gateway
// connection, kept alive by the heartbeat goroutine and reopened
// transparently when it drops. A dropped connection is invisible to
// callers except through OnDown/OnUp: only a connection that stays
// down past DownNotice or DownFails failed reconnects is reported,
// once.
//
// A Muse is safe for concurrent use. Construct it with New; the zero
// value is not usable (no Connector, no logger).
type Muse struct {
	connector   Connector
	logger      *slog.Logger
	onAuthError func(error)
	onAuthOK    func()
	onDown      func(error, time.Duration)
	onUp        func(time.Duration)
	reloadFunc  ReloadFunc

	connectTimeout    time.Duration
	heartbeatInterval time.Duration
	downNotice        time.Duration
	downFailLimit     int
	retryFor          time.Duration
	failSpacing       time.Duration

	cfgMu  sync.RWMutex
	cfg    Config
	cfgSet bool

	// mu guards only the shared slot. It is never held across a
	// connect, a ping, or a Close: _open runs outside it, probes run
	// outside it, and Close calls happen after unlocking.
	mu     sync.RWMutex
	shared Gateway

	connects atomic.Int64
	drops    atomic.Int64

	// downMu guards the down state. downSince/lastFail are monotonic:
	// they measure durations, and a wall-clock jump must neither
	// hide an outage nor invent one (Python comment, ported).
	downMu        sync.Mutex
	downSince     time.Time
	downSet       bool
	lastFail      time.Time
	downFailCount int
	downNotified  bool

	// Heartbeat state. hbMu guards the loop bookkeeping only; the
	// loop itself never holds hbMu while ticking. hbStop is the stop
	// channel captured at the loop's start: a stop+restart while the
	// old loop is mid-tick cannot strand it on the new run's channel
	// (Python Fix 8, ported). hbGen invalidates stale loops after a
	// panic-restart or a stop so a late exit cannot clear a new
	// loop's running flag.
	hbMu       sync.Mutex
	hbStop     chan struct{}
	hbDone     chan struct{}
	hbRunning  bool
	hbGen      int
	hbTickFn   func(time.Duration) // test seam: replaces hbTick when set
	hbPingMu   sync.Mutex
	hbLastPing time.Time
}

// Option configures a Muse.
type Option func(*Muse)

// WithConfig sets the Config used until Reload supplies a new one.
func WithConfig(cfg Config) Option {
	return func(m *Muse) {
		m.cfg = cfg
		m.cfgSet = true
	}
}

// WithConnectTimeout sets the per-connect bound (Python
// connect_timeout; the wait path uses 30s, everything else the
// ConnectTimeout default). Zero or negative means the default.
func WithConnectTimeout(d time.Duration) Option {
	return func(m *Muse) { m.connectTimeout = d }
}

// WithLogger sets the logger. The default is slog.Default(). Log
// lines never include a Config, a cookie, or a token.
func WithLogger(logger *slog.Logger) Option {
	return func(m *Muse) {
		if logger != nil {
			m.logger = logger
		}
	}
}

// WithOnAuthError sets the callback fired (once per AuthError from
// _open) when a connect fails authentication.
func WithOnAuthError(fn func(error)) Option {
	return func(m *Muse) { m.onAuthError = fn }
}

// WithOnAuthOK sets the callback fired after each successful connect.
func WithOnAuthOK(fn func()) Option {
	return func(m *Muse) { m.onAuthOK = fn }
}

// WithOnDown sets the callback fired once when the gateway stays
// down (see markDown). It receives the down cause and the time
// since the outage began. A panicking callback is recovered and
// logged: a notice hook must never break the caller.
func WithOnDown(fn func(error, time.Duration)) Option {
	return func(m *Muse) { m.onDown = fn }
}

// WithOnUp sets the callback fired after recovery from a notified
// outage. It receives the total down duration.
func WithOnUp(fn func(time.Duration)) Option {
	return func(m *Muse) { m.onUp = fn }
}

// WithReloadFunc sets the function Reload uses to re-read the
// profile Config. Wiring code supplies it; see ReloadFunc.
func WithReloadFunc(fn ReloadFunc) Option {
	return func(m *Muse) { m.reloadFunc = fn }
}

// New builds a Muse. connector may be nil only when the Muse is used
// for nothing but Reload/Config inspection; Live and Connect then
// fail with errNoConnector.
func New(connector Connector, opts ...Option) *Muse {
	m := &Muse{
		connector:         connector,
		logger:            slog.Default(),
		heartbeatInterval: Heartbeat,
		downNotice:        DownNotice,
		downFailLimit:     DownFails,
		retryFor:          RetryFor,
		failSpacing:       FailSpacing,
	}
	for _, opt := range opts {
		opt(m)
	}
	if m.logger == nil {
		m.logger = slog.Default()
	}
	return m
}

// Connects returns the number of real connections opened, for tests
// and logs (Python connects attribute).
func (m *Muse) Connects() int64 { return m.connects.Load() }

// Drops returns the number of connections lost, for tests and logs
// (Python drops attribute).
func (m *Muse) Drops() int64 { return m.drops.Load() }

// Reload re-reads the profile Config and resets the shared
// connection when the identity (cookies_file, vm_id, node_id)
// changed (Python reload). With no ReloadFunc it returns the Config
// Muse was built with. A reload error returns the previous Config
// and the error, and never resets.
func (m *Muse) Reload() (Config, error) {
	if m.reloadFunc == nil {
		m.cfgMu.RLock()
		defer m.cfgMu.RUnlock()
		return m.cfg, nil
	}
	next, err := m.reloadFunc()
	if err != nil {
		m.cfgMu.RLock()
		defer m.cfgMu.RUnlock()
		return m.cfg, err
	}
	m.cfgMu.Lock()
	old, oldSet := m.cfg, m.cfgSet
	m.cfg, m.cfgSet = next, true
	m.cfgMu.Unlock()
	if oldSet && old.Identity() != next.Identity() {
		m.Reset()
	}
	return next, nil
}

// Config returns the current Config, reloading it first when none
// was ever set (Python config()).
func (m *Muse) Config() (Config, error) {
	m.cfgMu.RLock()
	if m.cfgSet {
		cfg := m.cfg
		m.cfgMu.RUnlock()
		return cfg, nil
	}
	m.cfgMu.RUnlock()
	return m.Reload()
}

// markDown records that the gateway is down. failedConnect counts
// toward DownFails, coalesced by FailSpacing: several goroutines
// failing at the same moment count as one attempt. OnDown fires at
// most once per outage, after DownNotice or DownFails. Callbacks run
// outside downMu.
func (m *Muse) markDown(err error, failedConnect bool) {
	if err == nil {
		err = errHeartbeatFailed
	}
	now := time.Now()
	m.downMu.Lock()
	if !m.downSet {
		m.downSince, m.downSet = now, true
	}
	if failedConnect && now.Sub(m.lastFail) >= m.failSpacing {
		m.downFailCount++
		m.lastFail = now
	}
	notify := !m.downNotified &&
		(now.Sub(m.downSince) >= m.downNotice || m.downFailCount >= m.downFailLimit)
	if notify {
		m.downNotified = true
	}
	since := m.downSince
	fails := m.downFailCount
	m.downMu.Unlock()
	if !notify {
		return
	}
	downFor := time.Since(since)
	m.logger.Warn("gateway down", "seconds", int64(downFor/time.Second), "failed_reconnects", fails, "err", err)
	if m.onDown != nil {
		callNotice(func() { m.onDown(err, downFor) }, m.logger, "down notice")
	}
}

// markUp records recovery. OnUp fires only when the outage was
// notified (Python: `if was`). Callbacks run outside downMu.
func (m *Muse) markUp() {
	m.downMu.Lock()
	if !m.downSet {
		m.downMu.Unlock()
		return
	}
	was, since := m.downNotified, m.downSince
	m.downSince, m.downSet, m.downFailCount, m.downNotified = time.Time{}, false, 0, false
	m.lastFail = time.Time{}
	m.downMu.Unlock()
	if was && m.onUp != nil {
		callNotice(func() { m.onUp(time.Since(since)) }, m.logger, "up notice")
	}
}

// callNotice invokes a notice callback, recovering a panic so a
// buggy hook cannot break the connection path (Python catches
// Exception around on_down/on_up).
func callNotice(fn func(), logger *slog.Logger, what string) {
	defer func() {
		if r := recover(); r != nil {
			logger.Warn(what+" panicked", "panic", r)
		}
	}()
	fn()
}

// BoundedConnect runs connector(cfg) with an upper bound on time. A
// connect that hangs raises *TimeoutError; if it completes later,
// that gateway is closed by the worker instead of leaking. A late
// gateway the caller claimed in the same instant is never closed by
// the worker: ownership is decided under one mutex, and the worker
// closes outside the lock. Connector errors (including *AuthError,
// possibly wrapped) are returned as-is, never wrapped, so errors.As
// finds them. A cancelled ctx returns ctx.Err() and likewise closes
// a late gateway.
func BoundedConnect(ctx context.Context, connector Connector, cfg Config, timeout time.Duration) (Gateway, error) {
	if connector == nil {
		return nil, errNoConnector
	}
	if timeout <= 0 {
		timeout = ConnectTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	type result struct {
		gw  Gateway
		err error
	}
	var mu sync.Mutex
	var res result
	finished := false
	abandoned := false
	claimed := false
	done := make(chan struct{})
	go func() {
		gw, err := connector(ctx, cfg)
		mu.Lock()
		res = result{gw: gw, err: err}
		finished = true
		// Ownership under the lock, close outside it: a late gateway
		// is closed by the worker only if the caller did not claim
		// it in the same instant.
		late := abandoned && err == nil && gw != nil && !claimed
		if late {
			res.gw = nil
		}
		mu.Unlock()
		if late {
			_ = gw.Close()
		}
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		mu.Lock()
		defer mu.Unlock()
		if res.err != nil {
			return nil, res.err
		}
		return res.gw, nil
	case <-ctx.Done():
		mu.Lock()
		abandoned = true
		if finished && res.gw != nil {
			claimed = true
			gw := res.gw
			mu.Unlock()
			return gw, nil
		}
		mu.Unlock()
		return nil, ctx.Err()
	case <-timer.C:
		mu.Lock()
		abandoned = true
		if finished && res.gw != nil {
			claimed = true
			gw := res.gw
			mu.Unlock()
			return gw, nil
		}
		mu.Unlock()
		return nil, &TimeoutError{Message: fmt.Sprintf("gateway connect timed out after %s", timeout)}
	}
}

// open connects once, bounded in time. An AuthError fires
// OnAuthError and passes through unwrapped-typed without marking
// the gateway down; any other error marks it down as a failed
// connect. On success it counts the connection and fires OnAuthOK.
func (m *Muse) open(ctx context.Context, cfg Config) (Gateway, error) {
	timeout := m.connectTimeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}
	gw, err := BoundedConnect(ctx, m.connector, cfg, timeout)
	if err != nil {
		var ae *AuthError
		if errors.As(err, &ae) {
			if m.onAuthError != nil {
				callNotice(func() { m.onAuthError(err) }, m.logger, "auth error notice")
			}
			return nil, err
		}
		m.markDown(err, true)
		return nil, err
	}
	m.connects.Add(1)
	if m.onAuthOK != nil {
		callNotice(m.onAuthOK, m.logger, "auth ok notice")
	}
	return gw, nil
}

// ageOf returns the age of a monotonic timestamp, or 0 for a zero
// (missing) stamp: a missing stamp means "just now" (Python _gw_age).
func ageOf(t time.Time) time.Duration {
	if t.IsZero() {
		return 0
	}
	return time.Since(t)
}

// probeStale pings a shared connection that claims to be alive but
// has neither sent nor received anything for a heartbeat interval:
// Alive alone cannot prove a silently dead socket. It returns false
// when the probe fails; the caller drops and reopens. It never
// drops itself, and it performs no I/O under any conn lock.
func (m *Muse) probeStale(ctx context.Context, g Gateway) bool {
	if ageOf(g.LastRecv()) <= m.heartbeatInterval {
		return true
	}
	if ageOf(g.LastUsed()) <= m.heartbeatInterval {
		return true
	}
	m.hbPingMu.Lock()
	m.hbLastPing = time.Now()
	m.hbPingMu.Unlock()
	pingCtx, cancel := context.WithTimeout(ctx, StalePingTimeout)
	defer cancel()
	if _, err := g.Ping(pingCtx, StalePingTimeout); err != nil {
		m.logger.Info("gateway liveness probe failed; reconnecting", "err", err)
		return false
	}
	return true
}

// Live returns the shared connection, (re)opened if it is missing or
// dead. A connection that only claims to be alive is probed first
// when it has been quiet for a heartbeat interval (see probeStale).
// _open runs OUTSIDE the shared lock: holding the lock across a
// connect (up to the connect timeout) would serialise every
// goroutine's Live behind one slow handshake. The lock guards only
// the shared slot: goroutines that connect at once install the
// first finisher and close the extra gateway. The stale probe is
// deliberately NOT repeated under the lock (a difference from
// Python's in-lock probe, required by this port's "no network I/O
// under locks" invariant): the first, outside-lock probe already
// settled this instance, and a different instance installed
// meanwhile is returned unprobed — the next Live call probes it.
func (m *Muse) Live(ctx context.Context, cfg *Config) (Gateway, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	effective, err := m.effectiveConfig(cfg)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	g := m.shared
	m.mu.RUnlock()
	if g != nil && g.Alive() {
		if m.probeStale(ctx, g) {
			return g, nil
		}
		m.Drop(g)
	}
	var old Gateway
	m.mu.Lock()
	g = m.shared
	if g != nil {
		if g.Alive() {
			// Installed meanwhile by another goroutine, or the
			// instance the outside probe already passed: reuse
			// it without probing under the lock.
			installed := g
			m.mu.Unlock()
			return installed, nil
		}
		old = g
		m.shared = nil
		m.drops.Add(1)
		dead := g.Dead()
		if dead == nil {
			dead = errGatewayClosed
		}
		m.mu.Unlock()
		m.markDown(dead, false)
		m.logger.Info("gateway connection dropped; reconnecting", "err", dead)
	} else {
		m.mu.Unlock()
	}
	t0 := time.Now()
	gw, err := m.open(ctx, effective)
	if err != nil {
		if old != nil {
			_ = old.Close() // N4: do not leak the dropped gateway
		}
		return nil, err
	}
	m.mu.Lock()
	installed := m.shared
	if installed == nil {
		// Only a shareable gateway is installed as the shared
		// one (Python: hasattr(gw, "lease")). A non-shareable
		// gateway is returned to the caller, who owns it, and
		// the slot stays empty so the next call opens fresh.
		if _, ok := gw.(Leaser); ok {
			m.shared = gw
		}
	}
	m.mu.Unlock()
	m.logger.Info("gateway connected", "seconds", time.Since(t0).Seconds())
	m.markUp()
	if installed != nil {
		_ = gw.Close() // another goroutine installed meanwhile: use theirs
		if old != nil {
			_ = old.Close()
		}
		return installed, nil
	}
	if old != nil {
		_ = old.Close()
	}
	return gw, nil
}

// effectiveConfig resolves the Config for one Live/Connect call: an
// explicit cfg wins, otherwise the Muse's current Config.
func (m *Muse) effectiveConfig(cfg *Config) (Config, error) {
	if cfg != nil {
		return *cfg, nil
	}
	return m.Config()
}

// Connect returns a gateway to use and close: a SharedConn on the
// shared connection (whose Close leaves it up), or a fresh
// connection when the gateway cannot be shared (whose Close closes
// it).
func (m *Muse) Connect(ctx context.Context, cfg *Config) (Gateway, error) {
	g, err := m.Live(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if _, ok := g.(Leaser); !ok {
		return g, nil
	}
	return &SharedConn{muse: m, cfg: cfg}, nil
}

// Drop forgets a connection that failed its heartbeat; the next call
// reconnects. The gateway is closed outside the shared lock.
func (m *Muse) Drop(g Gateway) {
	m.mu.Lock()
	if m.shared == g {
		m.shared = nil
		m.drops.Add(1)
	}
	m.mu.Unlock()
	m.markDown(errHeartbeatFailed, false)
	_ = g.Close()
}

// Adopt uses an already-open connection as the shared one, closing
// the previous shared connection (outside the lock) when it differs.
func (m *Muse) Adopt(gw Gateway) {
	m.mu.Lock()
	old := m.shared
	m.shared = gw
	m.mu.Unlock()
	m.connects.Add(1)
	if old != nil && old != gw {
		_ = old.Close()
	}
}

// Warm opens the shared connection now so the first message does not
// pay for it. Failures are logged, never returned (Python warm).
func (m *Muse) Warm(ctx context.Context) {
	g, err := m.Connect(ctx, nil)
	if err != nil {
		m.logger.Warn("gateway warm-up failed", "err", err)
		return
	}
	_ = g.Close()
}

// Reset drops the shared connection (new cookies/profile). The old
// gateway is closed outside the lock.
func (m *Muse) Reset() {
	m.mu.Lock()
	old := m.shared
	m.shared = nil
	m.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}

// Close stops the heartbeat and closes the connection: a CLI command
// is done.
func (m *Muse) Close() {
	m.StopHeartbeat()
	m.Reset()
}

// Call performs one unary call_json on a leased connection (Python
// Muse.call). The returned value is the decoded JSON result.
func (m *Muse) Call(ctx context.Context, method string, opts RequestOptions) (any, error) {
	g, err := m.Connect(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = g.Close() }()
	return g.CallJSON(ctx, method, opts)
}

// Download returns the bytes of a sandbox file via a leased
// connection (Python Muse.download).
func (m *Muse) Download(ctx context.Context, ref any, opts DownloadOptions) ([]byte, error) {
	g, err := m.Connect(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = g.Close() }()
	return g.DownloadFile(ctx, ref, opts)
}

// History returns chat_events sorted by seq (missing seq sorts as
// 0), via chat.history (Python Muse.history). limit <= 0 means 20.
func (m *Muse) History(ctx context.Context, sessionID string, limit int) ([]any, error) {
	if limit <= 0 {
		limit = 20
	}
	body := map[string]any{"limit": limit}
	if sessionID != "" {
		body["session_id"] = sessionID
	}
	result, err := m.Call(ctx, "chat.history", RequestOptions{Body: body})
	if err != nil {
		return nil, err
	}
	obj, ok := result.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("conn: chat.history result is not an object: %T", result)
	}
	raw, _ := obj["chat_events"].([]any)
	evs := make([]any, len(raw))
	copy(evs, raw)
	// Stable sort by seq: Python sorted(evs, key=seq or 0).
	sortEventsBySeq(evs)
	return evs, nil
}

func sortEventsBySeq(evs []any) {
	// Insertion sort keeps the implementation dependency-free and
	// stable; history windows are small (<= 1000).
	for i := 1; i < len(evs); i++ {
		for j := i; j > 0 && eventSeq(evs[j]) < eventSeq(evs[j-1]); j-- {
			evs[j], evs[j-1] = evs[j-1], evs[j]
		}
	}
}

func eventSeq(ev any) int64 {
	obj, ok := ev.(map[string]any)
	if !ok {
		return 0
	}
	switch v := obj["seq"].(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case int32:
		return int64(v)
	case float64:
		return int64(v)
	case uint64:
		return int64(v)
	default:
		return 0
	}
}

// WithGateway runs fn with a leased gateway and closes the lease
// afterwards. It is the Go form of Python's Muse.fs/gw helpers:
// fsclient builds its FS inside fn, because this package cannot
// import internal/fsclient (that package consumes the Gateway
// interface defined here; importing it back would be a cycle).
// fn must not retain the gateway after it returns.
func (m *Muse) WithGateway(ctx context.Context, fn func(Gateway) error) error {
	g, err := m.Connect(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = g.Close() }()
	return fn(g)
}

// sharedSnapshot returns the current shared gateway, or nil. It
// never opens a connection.
func (m *Muse) sharedSnapshot() Gateway {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.shared
}

// hasDown reports whether an outage is currently recorded.
func (m *Muse) hasDown() bool {
	m.downMu.Lock()
	defer m.downMu.Unlock()
	return m.downSet
}

// heartbeatRunning reports whether the heartbeat loop is running.
// Test seam (white-box tests); production code does not need it.
func (m *Muse) heartbeatRunning() bool {
	m.hbMu.Lock()
	defer m.hbMu.Unlock()
	return m.hbRunning
}

// StartHeartbeat starts the heartbeat goroutine, restarting it when
// it died and after a stop: a goroutine reference alone never proves
// it is alive, and a stop from an earlier run must not kill the new
// loop. The loop waits on the stop channel captured at ITS start.
// Starting an already-running heartbeat is a no-op. interval <= 0
// means the Muse's heartbeat interval (default Heartbeat).
func (m *Muse) StartHeartbeat(interval time.Duration) {
	if interval <= 0 {
		interval = m.heartbeatInterval
		if interval <= 0 {
			interval = Heartbeat
		}
	}
	m.hbMu.Lock()
	if m.hbRunning {
		m.hbMu.Unlock()
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	m.hbGen++
	gen := m.hbGen
	m.hbStop, m.hbDone, m.hbRunning = stop, done, true
	m.hbMu.Unlock()
	go m.heartbeatLoop(gen, interval, stop, done)
}

// heartbeatLoop ticks every min(5s, interval) until stop closes. A
// panic in a tick (the Go equivalent of Python's BaseException in a
// tick) is fatal to THIS loop only: the loop restarts from a fresh
// goroutine unless a stop was asked, and never restarts in place
// (restarting in place would deadlock on the running check against
// this dying loop). Ordinary tick errors are logged by hbTick and
// never reach here.
func (m *Muse) heartbeatLoop(gen int, interval time.Duration, stop, done chan struct{}) {
	defer close(done)
	defer func() {
		m.hbMu.Lock()
		if m.hbGen == gen {
			m.hbRunning = false
		}
		m.hbMu.Unlock()
	}()
	wait := interval
	if wait > 5*time.Second {
		wait = 5 * time.Second
	}
	for {
		timer := time.NewTimer(wait)
		select {
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
		}
		if m.runTick(gen, interval, stop) {
			return // restarted from a fresh goroutine
		}
	}
}

// runTick runs one heartbeat tick, recovering a panic into a
// restart. It reports whether a restart was spawned (the caller
// must then exit).
func (m *Muse) runTick(gen int, interval time.Duration, stop chan struct{}) (restarted bool) {
	defer func() {
		if r := recover(); r != nil {
			m.logger.Warn("heartbeat tick panicked; restarting", "panic", r)
			m.hbMu.Lock()
			current := m.hbGen == gen && m.hbRunning
			if current {
				m.hbRunning = false
			}
			// A stop (or a fresh start) increments the generation:
			// if it changed, someone else owns the heartbeat now
			// and this loop must not spawn a duplicate.
			genUnchanged := m.hbGen == gen
			m.hbMu.Unlock()
			select {
			case <-stop:
				// A stop was asked: do not restart.
			default:
				if genUnchanged {
					m.StartHeartbeat(interval)
				}
			}
			restarted = true
		}
	}()
	if m.hbTickFn != nil {
		m.hbTickFn(interval)
	} else {
		m.hbTick(interval)
	}
	return false
}

// hbTick is one heartbeat tick (Python _hb_tick). It never returns
// an error: reconnect and ping failures are logged and the loop
// keeps trying quietly; only markDown decides when to notify.
func (m *Muse) hbTick(interval time.Duration) {
	g := m.sharedSnapshot()
	if g == nil || !g.Alive() {
		if g == nil && !m.hasDown() && m.Connects() == 0 {
			return // never connected yet: the first call opens it
		}
		if _, err := m.Live(context.Background(), nil); err != nil {
			m.logger.Info("gateway reconnect failed", "err", err)
		}
		return
	}
	quiet := ageOf(g.LastRecv())
	used := ageOf(g.LastUsed())
	if used < interval && quiet < interval {
		return // in use and the server is talking: alive
	}
	// Idle, or nothing has arrived for a while (a connection can
	// die silently: no close, no error): a ping settles it.
	m.hbPingMu.Lock()
	m.hbLastPing = time.Now()
	m.hbPingMu.Unlock()
	pingCtx, cancel := context.WithTimeout(context.Background(), HeartbeatPingTimeout)
	defer cancel()
	if _, err := g.Ping(pingCtx, HeartbeatPingTimeout); err != nil {
		m.logger.Info("gateway heartbeat failed; reconnecting", "err", err)
		m.Drop(g)
		if _, err := m.Live(context.Background(), nil); err != nil {
			m.logger.Info("gateway reconnect failed", "err", err)
		}
	}
}

// StopHeartbeat stops the heartbeat goroutine, waiting at most
// HeartbeatStopTimeout (6s). A loop stuck mid-tick (a slow
// reconnect) is left running rather than blocking the caller
// indefinitely; it exits when its tick returns and sees the stop
// channel closed, and its late exit cannot clear a newer loop's
// running flag (generation check). StopHeartbeat is idempotent and
// safe to call before StartHeartbeat. It must not be called from the
// heartbeat goroutine itself; if it is, it returns after the 6s
// bound and the loop exits on its next tick boundary.
func (m *Muse) StopHeartbeat() {
	m.hbMu.Lock()
	stop := m.hbStop
	done := m.hbDone
	m.hbStop, m.hbDone, m.hbRunning = nil, nil, false
	m.hbGen++
	m.hbMu.Unlock()
	if stop == nil {
		return
	}
	close(stop)
	if done == nil {
		return
	}
	timer := time.NewTimer(HeartbeatStopTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}
