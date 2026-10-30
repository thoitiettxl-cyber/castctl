// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package dns builds a profile DNS client on sing-box dns.Router +
// dns.TransportManager from option.DNSOptions, and is the only place
// (besides outbound.BootstrapLookup) where hostname resolution is
// configured.
//
// Fail-closed invariant: DNS failure is an error. There is NO
// system-resolver fallback: no servers configured is an error at
// construction, a failing transport is an error at lookup, and
// "localhost" is resolved only if the configured DNS server answers
// for it. The sole bootstrap exception is the DNS server's own
// hostname, resolved once at construction through an injected
// BootstrapFunc (default: outbound.BootstrapLookup) and substituted
// into the server options; bootstrap is never used for any other
// hostname. DNS queries travel through the outbound/detour the
// transport is configured with, via sing-box's own transport dialer.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
)

// BootstrapFunc resolves a DNS server's own hostname. It is injected
// so tests can substitute a fake; production passes
// outbound.BootstrapLookup, the single system-resolver call site.
type BootstrapFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// ClientOption configures a Client.
type ClientOption func(*clientOptions)

type clientOptions struct {
	logFactory log.Factory
	bootstrap  BootstrapFunc
}

// WithLogFactory sets the log factory (default: a NOP factory).
func WithLogFactory(factory log.Factory) ClientOption {
	return func(o *clientOptions) { o.logFactory = factory }
}

// WithBootstrap sets the bootstrap function used for DNS server
// hostnames (default: outbound.BootstrapLookup).
func WithBootstrap(fn BootstrapFunc) ClientOption {
	return func(o *clientOptions) { o.bootstrap = fn }
}

// Client is a started/stopped DNS client. It is safe for concurrent
// Lookup calls after Start; Start/Close are serialized, double Start
// is an error, Close is idempotent, and Lookup after Close is an
// error.
type Client struct {
	router *dns.Router
	tm     *dns.TransportManager
	scope  *adapter.Scope
	logger log.ContextLogger

	mu      sync.Mutex
	started bool
	closed  bool
}

// New builds a Client from opts. ctx must be a registry context (see
// outbound.NewContext / Manager.Context): option parsing and
// transport construction read the registries and the outbound manager
// from it. outboundMgr is the sing-box outbound manager the
// transports dial through (for detours).
//
// Bootstrap substitution happens here, before any transport is
// created: a server whose address is a domain is resolved once via
// the bootstrap func and the first IPv4 address (else the first
// address) is substituted, preserving the original hostname as the
// TLS ServerName when TLS options have an empty ServerName.
// Bootstrap failure is a construction error.
func New(ctx context.Context, opts option.DNSOptions, outboundMgr adapter.OutboundManager, options ...ClientOption) (*Client, error) {
	cfg := clientOptions{
		logFactory: log.NewNOPFactory(),
		bootstrap:  outbound.BootstrapLookup,
	}
	for _, opt := range options {
		opt(&cfg)
	}
	if len(opts.Servers) == 0 {
		return nil, errors.New("dns: no DNS servers configured: refusing to fall back to the system resolver")
	}
	if outboundMgr == nil {
		return nil, errors.New("dns: outbound manager is required")
	}
	if cfg.bootstrap == nil {
		return nil, errors.New("dns: bootstrap function must not be nil")
	}

	registry := service.FromContext[adapter.DNSTransportRegistry](ctx)
	if registry == nil {
		return nil, errors.New("dns: context carries no DNS transport registry: pass a context from outbound.NewContext")
	}
	tm := dns.NewTransportManager(registry, outboundMgr, opts.Final)
	tm.Initialize(func() (adapter.DNSTransport, error) {
		return nil, errors.New("dns: no DNS transport configured: refusing to create an implicit fallback transport")
	})

	// Register the transport manager (and keep the outbound manager)
	// in a derived context so transport constructors and the DNS
	// router read the same services the outbound constructors see.
	derived := service.ContextWith[adapter.DNSTransportManager](ctx, tm)
	derived = service.ContextWith[adapter.OutboundManager](derived, outboundMgr)

	logger := cfg.logFactory.NewLogger("dns")
	bootstrapCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	servers, err := substituteBootstrap(bootstrapCtx, opts.Servers, cfg.bootstrap)
	if err != nil {
		return nil, err
	}

	for i, server := range servers {
		tag := server.Tag
		if tag == "" {
			tag = fmt.Sprintf("%d", i)
		}
		if err := tm.Create(derived, logger, tag, server.Type, server.Options); err != nil {
			return nil, fmt.Errorf("dns: create transport %s[%s]: %w", server.Type, tag, err)
		}
	}

	router, err := dns.NewRouter(derived, cfg.logFactory, opts)
	if err != nil {
		return nil, fmt.Errorf("dns: create router: %w", err)
	}
	if err := router.Initialize(opts.Rules); err != nil {
		return nil, fmt.Errorf("dns: initialize router: %w", err)
	}
	derived = service.ContextWith[adapter.DNSRouter](derived, router)

	return &Client{
		router: router,
		tm:     tm,
		scope:  adapter.NewScope(derived, logger),
		logger: logger,
	}, nil
}

// Start runs the sing-box lifecycle stages over the transport manager
// and the DNS router. A second Start is an error.
func (c *Client) Start() error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return errors.New("dns: Start called twice")
	}
	if c.closed {
		c.mu.Unlock()
		return errors.New("dns: Start called after Close")
	}
	c.started = true
	scope := c.scope
	c.mu.Unlock()

	for _, stage := range adapter.ListStartStages {
		if err := scope.Start("dns-transport", c.tm, stage); err != nil {
			return fmt.Errorf("dns: start transport manager (%s): %w", stage, err)
		}
		if err := scope.Start("dns-router", c.router, stage); err != nil {
			return fmt.Errorf("dns: start router (%s): %w", stage, err)
		}
	}
	return nil
}

// Close closes the lifecycle scope. Idempotent; safe without Start.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	scope := c.scope
	c.mu.Unlock()
	return scope.Close()
}

// Lookup resolves domain through the configured DNS. DNS failure is
// returned as an error; there is no system-resolver fallback. Lookup
// before Start returns an error from the router; Lookup after Close
// returns an error from this method.
func (c *Client) Lookup(ctx context.Context, domain string) ([]netip.Addr, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, errors.New("dns: Lookup called after Close")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.router.Lookup(ctx, domain, adapter.DNSQueryOptions{})
}

// Router returns the underlying DNS router, for registration with an
// outbound Manager (see outbound.Manager.RegisterDNS).
func (c *Client) Router() adapter.DNSRouter { return c.router }

// TransportManager returns the underlying transport manager, for
// registration with an outbound Manager.
func (c *Client) TransportManager() adapter.DNSTransportManager { return c.tm }

// Transport returns the transport with tag, if one was created.
func (c *Client) Transport(tag string) (adapter.DNSTransport, bool) {
	return c.tm.Transport(tag)
}
