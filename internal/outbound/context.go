// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package outbound builds and owns sing-box outbounds and endpoints
// for one muse-cli profile, and exposes the single Dialer through which
// all of that profile's network traffic flows.
//
// Fail-closed invariant: every network call of a profile goes through
// that profile's outbound.Dialer. No http.DefaultClient, no net.Dial,
// no system-resolver lookup anywhere else in the Go port. The sole
// exception is BootstrapLookup (bootstrap.go), the one system-resolver
// call site, used only to resolve a DNS server's own hostname before
// that server can be used.
//
// Env-proxy mapping: the VM egress proxy is modelled as an EXPLICIT
// sing-box "http" outbound in config, never as an implicit env shim.
// Proxy server/port from the environment map to the http outbound
// fields server/server_port. When the proxy is TLS-intercepting, the
// TLS options of that outbound carry the interception: tls.enabled,
// tls.server_name, tls.certificate (PEM bytes) or
// tls.certificate_path (path to the CA bundle), and tls.insecure only
// when the profile explicitly opts out of verification. CA bytes/path
// come from config, never from env vars, and no proxy credential is
// ever logged. Product code never reads HTTPS_PROXY, HTTP_PROXY,
// ALL_PROXY, or NO_PROXY (any case) to build dialers implicitly;
// "direct" stays truly direct. --outbound-from-env is a PR3 profile
// command and is not implemented here.
//
// F3 nil-router guard (see Manager.CreateOutbound): a domain-server
// outbound created with no DNS router registered panics inside
// sing-box on its first domain dial (nil DNS router dereference),
// so CreateOutbound refuses it fail-closed — except for detour
// chains PROVEN to forward the domain server address verbatim to
// a remote proxy (http/socks5/selector/urltest chains terminating
// in an IP-server forwarder, created detour-first). Wiring rules,
// both inviolable: RegisterDNS/RegisterDNSRouter BEFORE
// CreateOutbound for every other domain-server outbound, and the
// detour chain BEFORE the outer outbound. The guard comment in
// manager.go records the probe evidence and the limits (other
// protocols, socks 4a, endpoint detours and the ListenPacket path
// stay refused, [UNVERIFIED]).
package outbound

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing/service"
)

// registryOnce guards the single process-global include.Context() call.
// include.Context() is NOT safe to call concurrently: under the
// !with_quic build it assigns the package-global
// naive.ConfigureHTTP3ListenerFunc (include/quic_stub.go:48), which
// -race flags when two goroutines build registry contexts in parallel
// (measured by W-PROFILE, 2026-10-28). With with_quic the same global
// is assigned at package init instead, but the once rule is kept for
// every tag set: one call per process, always.
//
// RegistryContext is the ONLY include.Context call site in the Go
// port: internal/profile parses option.Outbound/Endpoint/DNSOptions
// through it (see profile singContext, NB9 unification), so both
// packages derive from the same underlying global registry instead
// of each building its own.
var (
	registryOnce sync.Once
	registryCtx  context.Context
)

// RegistryContext returns the process-global sing-box registry
// context, built exactly once. Callers must treat the registry as
// read-only (NewContext clones it per caller before registering
// services); the returned context itself is uncancelled.
func RegistryContext() context.Context {
	registryOnce.Do(func() {
		registryCtx = include.Context(context.Background())
	})
	return registryCtx
}

// NewContext returns a context carrying a CLONE of the process-global
// service registry, so concurrent callers never race inside
// include.Context() and never clobber each other's registered
// services. Each caller registers its own managers (outbound,
// endpoint, DNS, stub Router/NetworkManager) into its own clone.
//
// If ctx already carries a service registry, it is returned unchanged:
// calling include.Context() again would rebuild (and reassign) the
// global registries. The returned context is derived from the caller's
// ctx (so cancellation still propagates); the registry itself is
// process-global and uncancelled.
func NewContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if service.RegistryFromContext(ctx) != nil {
		return ctx
	}
	global := service.RegistryFromContext(RegistryContext())
	return service.ContextWithRegistry(ctx, global.Clone())
}

// services registers the per-Manager services into ctx: the stub
// Router and stub NetworkManager that sing-box constructors read from
// the service registry, plus the outbound, endpoint, and DNS
// transport managers.
func services(ctx context.Context, outboundManager adapter.OutboundManager, endpointManager adapter.EndpointManager, transports adapter.DNSTransportManager) context.Context {
	ctx = service.ContextWith[adapter.Router](ctx, stubRouter{})
	ctx = service.ContextWith[adapter.NetworkManager](ctx, stubNetworkManager{})
	ctx = service.ContextWith[adapter.OutboundManager](ctx, outboundManager)
	ctx = service.ContextWith[adapter.EndpointManager](ctx, endpointManager)
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, transports)
	return ctx
}
