// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sagernet/sing-box/option"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// OutboundDialer is the minimal dial surface the Connector needs
// from internal/outbound's Dialer: WebSocketDial returns a net.Conn
// ready for a WebSocket handshake (plain, or TLS-wrapped when
// secure), and HTTPClient returns an *http.Client whose transport
// dials through the outbound. *outbound.Dialer satisfies this
// interface; tests inject fakes. The gateway never dials any other
// way, and never reads proxy environment variables.
type OutboundDialer interface {
	WebSocketDial(ctx context.Context, network, host string, port uint16, secure bool, tlsOptions option.OutboundTLSOptions) (net.Conn, error)
	HTTPClient() *http.Client
}

// ConnectorOption configures NewConnector.
type ConnectorOption func(*connectorConfig)

type connectorConfig struct {
	secure       bool
	host         string
	wsURL        func(vmID, hatchToken string) string
	clock        Clock
	wsTimeout    time.Duration
	noiseTimeout time.Duration
}

// WithWebSocketSecure sets whether the WebSocket dial is TLS
// (default true). Tests set false for a plain loopback fake
// gateway.
func WithWebSocketSecure(secure bool) ConnectorOption {
	return func(c *connectorConfig) { c.secure = secure }
}

// WithGatewayHost overrides the gateway host in the WebSocket URL
// (default hatch.metaaivm.com). It does not change dialing: the
// outbound dialer resolves the host it is given by the URL.
func WithGatewayHost(host string) ConnectorOption {
	return func(c *connectorConfig) { c.host = host }
}

// WithWSURL overrides WebSocket URL construction entirely
// (tests). The function receives the vm id and hatch token and
// must return the full ws(s) URL, including the auth_token query
// parameter, exactly as defaultWSURL does.
func WithWSURL(fn func(vmID, hatchToken string) string) ConnectorOption {
	return func(c *connectorConfig) { c.wsURL = fn }
}

// WithClock sets the Clock the built gateways use for their
// bounded waits and keep-alive tickers (S10). The default is the
// real clock; tests inject a fake clock.
func WithClock(c Clock) ConnectorOption {
	return func(cfg *connectorConfig) { cfg.clock = c }
}

// WithWSUpgradeTimeout bounds the WebSocket upgrade separately
// from the Noise handshake (item (b); default WSUpgradeTimeout).
func WithWSUpgradeTimeout(d time.Duration) ConnectorOption {
	return func(cfg *connectorConfig) { cfg.wsTimeout = d }
}

// WithNoiseHandshakeTimeout bounds the Noise handshake
// separately from the WebSocket upgrade (item (b); default
// HandshakeTimeout).
func WithNoiseHandshakeTimeout(d time.Duration) ConnectorOption {
	return func(cfg *connectorConfig) { cfg.noiseTimeout = d }
}

// defaultWSURL builds wss://<host>/v1/noise?vm_id=..&auth_token=..
// with the token URL-quoted (safe=""), as in gateway.py.
func defaultWSURL(secure bool, host string) func(vmID, hatchToken string) string {
	scheme := "wss"
	if !secure {
		scheme = "ws"
	}
	return func(vmID, hatchToken string) string {
		return fmt.Sprintf("%s://%s/v1/noise?vm_id=%s&auth_token=%s",
			scheme, host, quotePython(vmID, ""), quotePython(hatchToken, ""))
	}
}

// NewConnector builds a conn.Connector that opens one Gateway per
// call: it loads cookies, runs the 3-step HTTPS auth chain over
// the outbound HTTP client (session -> access token -> hatch
// token), dials the WebSocket through the outbound Dialer, and
// runs the Noise handshake. Auth failures are *conn.AuthError and
// pass through BoundedConnect unwrapped-typed; a missing vm_id is
// a retryable *conn.GatewayError, not an AuthError. The Connector
// honours ctx cancellation during dialing and the auth chain;
// after a Gateway is returned, its lifetime is independent of
// ctx. No hatch token is retained after the handshake.
func NewConnector(dialer OutboundDialer, opts ...ConnectorOption) conn.Connector {
	cfg := &connectorConfig{secure: true, host: GatewayHost, clock: realClock{}, wsTimeout: WSUpgradeTimeout, noiseTimeout: HandshakeTimeout}
	for _, o := range opts {
		o(cfg)
	}
	if cfg.clock == nil {
		cfg.clock = realClock{}
	}
	if cfg.wsTimeout <= 0 {
		cfg.wsTimeout = WSUpgradeTimeout
	}
	if cfg.noiseTimeout <= 0 {
		cfg.noiseTimeout = HandshakeTimeout
	}
	if cfg.wsURL == nil {
		cfg.wsURL = defaultWSURL(cfg.secure, cfg.host)
	}
	return func(ctx context.Context, c conn.Config) (conn.Gateway, error) {
		cookies, err := LoadCookies(c.CookiesFile)
		if err != nil {
			return nil, err
		}
		httpClient := dialer.HTTPClient()
		vmID := c.VMID
		if vmID == "" {
			info, err := FetchSessionInfo(ctx, httpClient, cookies)
			if err != nil {
				return nil, err
			}
			vmID = info.VMID
		}
		accessToken, err := FetchAccessToken(ctx, httpClient, cookies)
		if err != nil {
			return nil, err
		}
		hatchToken, err := FetchHatchToken(ctx, httpClient, cookies, accessToken, vmID)
		if err != nil {
			return nil, err
		}
		if hatchToken == "" {
			return nil, conn.NewAuthError("hatch/token response missing token")
		}
		return dialGateway(ctx, dialer, cfg.wsURL(vmID, hatchToken), cfg.secure, cfg)
	}
}

// dialGateway dials one WebSocket connection through the outbound
// dialer, runs the Noise handshake, and returns a live Gateway.
// On any failure the socket is closed and the error returned. It
// records per-phase connect timings (item (b)) on the gateway:
// the dialer exposes no DNS/TLS sub-phase timings, so those stay
// -1. The gateway never dials itself and never reads proxy
// environment variables; on any dialer failure it returns an
// error, never a direct dial (fail-closed).
func dialGateway(ctx context.Context, dialer OutboundDialer, wsURL string, secure bool, cfg *connectorConfig) (conn.Gateway, error) {
	routes, err := DefaultRoutes()
	if err != nil {
		return nil, err
	}
	ws, dialMS, wsMS, err := dialWebSocket(ctx, dialer, wsURL, secure, cfg.wsTimeout)
	if err != nil {
		return nil, err
	}
	noiseStart := time.Now()
	sendCS, recvCS, err := noiseHandshake(ws, cfg.noiseTimeout)
	if err != nil {
		_ = ws.Close()
		return nil, err
	}
	noiseMS := time.Since(noiseStart).Milliseconds()
	gw := newGateway(ws, sendCS, recvCS, routes, cfg.clock)
	gw.mu.Lock()
	gw.timings = HandshakeTimings{DialMS: dialMS, WSMS: wsMS, NoiseMS: noiseMS, DNSMS: -1, TLSMS: -1}
	gw.mu.Unlock()
	return gw, nil
}

// dialWebSocket dials through the outbound Dialer (which returns a
// conn whose TLS handshake is already done when secure) and
// performs the WebSocket upgrade on it with a gorilla Dialer whose
// NetDialTLSContext returns that conn. gorilla's
// websocket.NewClient must NEVER be used here: on a pre-TLS conn
// it attempts a second TLS handshake and fails (probe evidence:
// "tls: first record does not look like a TLS handshake"). No
// ALPN is pinned here; TLS details belong to the outbound Dialer.
// The upgrade is bounded separately by wsTimeout (item (b)). It
// returns the connection plus the dial and upgrade durations in
// milliseconds. Dial errors are redacted for safe logging (item
// (c)) while keeping the original error chain.
func dialWebSocket(ctx context.Context, dialer OutboundDialer, wsURL string, secure bool, wsTimeout time.Duration) (wsConn, int64, int64, error) {
	host, port, err := splitWSURL(wsURL)
	if err != nil {
		return nil, 0, 0, err
	}
	dialStart := time.Now()
	raw, err := dialer.WebSocketDial(ctx, "tcp", host, port, secure, option.OutboundTLSOptions{})
	dialMS := time.Since(dialStart).Milliseconds()
	if err != nil {
		if ctx.Err() != nil {
			return nil, dialMS, 0, ctx.Err()
		}
		return nil, dialMS, 0, &conn.ConnectionError{Err: fmt.Errorf("gateway: websocket dial: %w", redactErr(err))}
	}
	var used atomic.Bool
	take := func(_ context.Context, _, _ string) (net.Conn, error) {
		if !used.CompareAndSwap(false, true) {
			return nil, errors.New("gateway: websocket dialer called twice for one connection")
		}
		return raw, nil
	}
	d := &websocket.Dialer{
		NetDialContext:    take,
		NetDialTLSContext: take,
		HandshakeTimeout:  wsTimeout,
	}
	header := http.Header{}
	header.Set("User-Agent", UserAgent)
	header.Set("Origin", "https://muse.ai")
	upgradeStart := time.Now()
	ws, _, err := d.DialContext(ctx, wsURL, header)
	wsMS := time.Since(upgradeStart).Milliseconds()
	if err != nil {
		_ = raw.Close()
		if ctx.Err() != nil {
			return nil, dialMS, wsMS, ctx.Err()
		}
		return nil, dialMS, wsMS, &conn.ConnectionError{Err: fmt.Errorf("gateway: websocket handshake: %w", redactErr(err))}
	}
	return ws, dialMS, wsMS, nil
}

// splitWSURL extracts the host and port from a ws(s) URL, applying
// the scheme defaults (443 for wss, 80 for ws).
func splitWSURL(wsURL string) (string, uint16, error) {
	u, err := parseURL(wsURL)
	if err != nil {
		return "", 0, err
	}
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		if u.Scheme == "wss" {
			portStr = "443"
		} else {
			portStr = "80"
		}
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("gateway: invalid port in websocket URL %q", redactURL(wsURL))
	}
	return host, uint16(port), nil
}
