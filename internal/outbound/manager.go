// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	endpointManager "github.com/sagernet/sing-box/adapter/endpoint"
	outboundManager "github.com/sagernet/sing-box/adapter/outbound"
	dnsTransportManager "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

// Manager owns the sing-box outbound and endpoint managers for one
// profile, plus the lifecycle scope that starts and closes them. It is
// built on registry-only managers + the stub Router/NetworkManager
// (see context.go and router_stub.go); no box.Box is involved.
//
// A Manager is safe for concurrent use after Start: Dialer lookups and
// outbound lookups take no locks that block on the network, and no
// network I/O happens under a lock. Start/Close are serialized by an
// internal mutex; double Start is an error, Close is idempotent, and
// Close without Start is a no-op.
type Manager struct {
	ctx    context.Context
	logger log.ContextLogger
	router adapter.Router

	endpoints *endpointManager.Manager
	outbounds *outboundManager.Manager

	scope *adapter.Scope

	mu      sync.Mutex
	started bool
	closed  bool

	// created records the detour-chain metadata of every outbound
	// created through CreateOutbound, keyed by tag. The F3 detour
	// exception reads it to decide whether a domain-server
	// outbound's detour chain self-resolves; it is guarded by mu
	// and only ever written on a successful creation, so a tag
	// recorded here always names a live outbound.
	created map[string]chainInfo
}

// NewManager builds the managers on a fresh registry context (see
// NewContext) and registers the stub Router/NetworkManager services
// that sing-box constructors read from the context. No outbound or
// endpoint is created here; use CreateOutbound/CreateEndpoint, then
// Start.
func NewManager(ctx context.Context, logger log.ContextLogger) (*Manager, error) {
	if logger == nil {
		return nil, errors.New("outbound: NewManager requires a logger")
	}
	ctx = NewContext(ctx)
	endpoints := endpointManager.NewManager(service.FromContext[adapter.EndpointRegistry](ctx))
	outbounds := outboundManager.NewManager(service.FromContext[adapter.OutboundRegistry](ctx), endpoints, "")
	outbounds.Initialize(func() (adapter.Outbound, error) {
		return nil, errors.New("outbound: no outbound configured: refusing to create an implicit direct fallback")
	})
	// Placeholder DNS transport manager: sing-box dialer
	// construction (dialer.NewDNSQueryOptions) dereferences the
	// DNSTransportManager unconditionally for RemoteIsDomain
	// outbounds, so the context must always carry one — even before
	// any DNS client exists. It holds no transports; domain dials
	// still fail closed via the Dialer's ErrNoResolver guard. The
	// DNS package replaces it via RegisterDNS before outbounds that
	// use a domain_resolver are created.
	transports := dnsTransportManager.NewTransportManager(service.FromContext[adapter.DNSTransportRegistry](ctx), outbounds, "")
	ctx = services(ctx, outbounds, endpoints, transports)
	m := &Manager{
		ctx:       ctx,
		logger:    logger,
		router:    service.FromContext[adapter.Router](ctx),
		endpoints: endpoints,
		outbounds: outbounds,
		scope:     adapter.NewScope(ctx, logger),
		created:   make(map[string]chainInfo),
	}
	return m, nil
}

// registryContext returns the Manager's current registry context.
// RegisterDNSRouter replaces it, so every read goes through the mutex.
func (m *Manager) registryContext() context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ctx
}

// (option.Outbound / option.DNSOptions) must use this context so the
// sing-box registries resolve.
func (m *Manager) Context() context.Context { return m.registryContext() }

// OutboundManager exposes the underlying sing-box outbound manager for
// the DNS package, which needs it to build its transport manager.
// The DNS package must not mutate it.
func (m *Manager) OutboundManager() adapter.OutboundManager { return m.outbounds }

// RegisterDNS registers a DNS router and its transport manager in
// the Manager's context so outbound constructors with a
// domain_resolver (or a RemoteIsDomain dialer) can resolve through
// them. It replaces the placeholder transport manager created by
// NewManager. It MUST be called before creating outbounds that use a
// domain_resolver, and before Start: sing-box constructors capture
// these services from the context at construction time.
//
// The DNS package calls this after building its Client; callers that
// use outbound without DNS simply never call it.
func (m *Manager) RegisterDNS(router adapter.DNSRouter, transports adapter.DNSTransportManager) {
	if router == nil || transports == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ctx = service.ContextWith[adapter.DNSRouter](m.ctx, router)
	m.ctx = service.ContextWith[adapter.DNSTransportManager](m.ctx, transports)
}

// RegisterDNSRouter registers only a DNS router, keeping the
// placeholder transport manager. Prefer RegisterDNS: without the real
// transport manager, domain_resolver lookups fail at construction.
func (m *Manager) RegisterDNSRouter(router adapter.DNSRouter) {
	if router == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ctx = service.ContextWith[adapter.DNSRouter](m.ctx, router)
}

// CreateOutbound creates one outbound from its registry type and
// options. options must be the *Options type the registry constructor
// for outboundType expects (as produced by parsing option.Outbound
// JSON through Manager.Context()).
//
// WireGuard as an outbound is rejected before the registry is
// consulted: {"type":"wireguard"} is a stub error in sing-box 1.14
// ("use WireGuard endpoint instead"), so the error here names the
// endpoint form directly.
//
// Nil-router guard (F3, fail-closed): sing-box's resolve dialer
// captures the DNS router from the registry context at outbound
// construction time (common/dialer.NewResolveDialer, resolve.go:46-63)
// and dereferences it on the first domain dial (resolve.go:103,
// d.router.Lookup; the same dereference is at resolve.go:123,
// :151 and :174 for the packet/parallel paths). With no DNS router
// registered that dial PANICS with a nil dereference — and
// registering a router after CreateOutbound cannot repair the
// already-captured nil. CreateOutbound therefore refuses, with a
// clean error, any outbound whose Server is a domain (not an IP
// literal) when no DNS router is registered in the context at
// creation time — EXCEPT the proven self-resolving detour chains
// below.
//
// WIRING RULE (inviolable, Phase-2 wiring must not miss it):
// call RegisterDNS/RegisterDNSRouter BEFORE CreateOutbound for
// every domain-server outbound that does not qualify for the
// detour exception. IP-server outbounds never touch the resolve
// dialer and are unaffected.
//
// Detour exception — DECISION (probed 2026-10-29 against the real
// sing-box constructors, loopback fakes only, no network; evidence
// pinned by the detour tests in manager_dns_guard_test.go):
// sing-box wraps the resolve dialer only when there is no detour,
// or when a domain_resolver is set (common/dialer/dialer.go:65).
// A domain-server outbound WITH a detour and WITHOUT a
// domain_resolver therefore dials its server by delegating the
// domain destination to the detour outbound, which may forward it
// verbatim to a remote proxy that resolves it — no local DNS
// router is ever dereferenced. That is PROVEN end-to-end (dial
// succeeds, reply "ok", no panic, no DNS router) for: http and
// socks5 outbounds whose detour chain terminates in a socks5 or
// http outbound with an IP-literal server, including a two-hop
// chain and a selector whose every member is such a chain.
// It is DISPROVEN (nil-dereference panic, recovered in the probe)
// for: a non-empty direct detour (the direct outbound's own
// resolve dialer, resolve.go:103 via protocol/direct/outbound.go),
// a socks version-4 detour (protocol/socks/outbound.go:87,
// h.dnsRouter.Lookup), and the reverse chain (an IP-server
// outbound whose detour is itself a domain-server outbound, which
// panics at resolve.go:103 when dialled). A detour plus a
// domain_resolver fails cleanly at construction instead ("domain
// resolver not found"), and a missing detour fails cleanly at
// Start ("dependency not found"); neither panics. Urltest was not
// probed end-to-end; it shares the selector group logic in the
// walk below, so it is allowed on the same all-members rule, but
// that allowance is logic-only, not probe evidence.
//
// The exception is therefore deliberately narrow — an allow-list,
// not a general "has a detour" rule. A domain-server outbound
// without a registered DNS router is allowed ONLY when every
// link of its detour chain, as recorded at creation time, is:
//   - an http or socks (version 5, or empty which defaults to 5)
//     outbound with no domain_resolver, whose detour (if any) is
//     itself allowed, terminating in an http/socks outbound with
//     an IP-literal server and no detour; or
//   - a selector/urltest outbound whose EVERY member (Outbounds
//     plus selector Default) is allowed — selection is dynamic,
//     so one unproven member is enough to refuse.
//
// Anything else — direct, socks4/4a, any other protocol, an
// endpoint tag, a detour not yet created, a cycle, a
// domain_resolver on any link — is refused. The detour chain
// must therefore be created BEFORE the outer outbound (a second
// ordering rule, alongside RegisterDNS-before-CreateOutbound):
// a detour created after the outer outbound cannot repair the
// refusal, exactly as a late router cannot repair a refused
// creation.
//
// LIMITS, recorded honestly: only http/socks5/selector chains
// were probed end-to-end. Other proxy protocols as detours
// (trojan, vmess, vless, shadowsocks, hysteria, naive, ...),
// socks version 4a, endpoint detours, urltest end-to-end, and
// the ListenPacket path through a detour chain are [UNVERIFIED]
// and stay refused — refusing a chain that would have worked
// costs a DNS configuration; allowing a chain that panics
// costs the process. TLS options on a chain link do not add a
// lookup (the TLS dialer wraps the detour dialer), but a TLS
// handshake through a detour chain was not probed end-to-end
// either.
//
// Enum validation: `enum:` struct tags are NOT validated at parse
// time (W-PROFILE finding). Invalid enum values are therefore
// rejected (or not) by the registry constructors themselves; the
// measured per-protocol results live in protocols_test.go
// (TestEnumValidationAtConstruction). No enum validation is invented
// here beyond what the constructors enforce.
func (m *Manager) CreateOutbound(ctx context.Context, tag, outboundType string, options any) error {
	// Construction is local, so it runs on the manager's registry
	// context; the caller's context is honoured only for cancellation.
	if err := ctx.Err(); err != nil {
		return err
	}
	if tag == "" {
		return errors.New("outbound: outbound tag must not be empty")
	}
	if strings.EqualFold(outboundType, "wireguard") {
		return fmt.Errorf("outbound: %q is not an outbound type in sing-box 1.14: declare a wireguard endpoint and reference its tag instead", outboundType)
	}
	if info := describeOutbound(outboundType, options); info.serverIsDomain {
		if service.FromContext[adapter.DNSRouter](m.registryContext()) == nil && !m.allowsDomainServerWithoutRouter(info) {
			return fmt.Errorf("outbound: create %s[%s]: domain server %q requires a DNS router: call RegisterDNS/RegisterDNSRouter before CreateOutbound (sing-box captures the DNS router at construction; registering later does not repair it), or create a self-resolving detour chain first (socks5/http/selector/urltest only, detour before the outer outbound)", outboundType, tag, info.server)
		}
	}
	if err := m.outbounds.Create(m.registryContext(), m.router, m.logger, tag, outboundType, options); err != nil {
		return logging.WrapErr(fmt.Errorf("outbound: create %s[%s]: %w", outboundType, tag, err))
	}
	m.mu.Lock()
	m.created[tag] = describeOutbound(outboundType, options)
	m.mu.Unlock()
	return nil
}

// serverString reports the outbound's Server address string
// ("" when the options carry none). domainServer reports the
// same address and whether it is a domain (needs resolution)
// rather than an IP literal. The sing-box outbound option structs
// all carry the remote address in a top-level Server string
// field; types without one (direct, selector, urltest, ...)
// report no server. An empty server is not a domain:
// construction/dial errors for it stay sing-box's. A bracketed
// IPv6 literal ("[::1]") parses as an IP, not a domain.
func serverString(options any) string {
	v := reflect.ValueOf(options)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return ""
	}
	f := findField(v, "Server")
	if !f.IsValid() || f.Kind() != reflect.String {
		return ""
	}
	return f.String()
}

func domainServer(options any) (string, bool) {
	server := serverString(options)
	if server == "" {
		return "", false
	}
	if _, err := netip.ParseAddr(strings.Trim(server, "[]")); err == nil {
		return "", false
	}
	return server, true
}

// chainInfo is the detour-relevant summary of one outbound's
// options, recorded at creation time for the F3 detour exception.
// Only scalars are kept: the options value itself is never retained,
// so later mutation of a caller's options value cannot change a
// recorded chain.
type chainInfo struct {
	typ            string // outbound type as passed to CreateOutbound, lowercased
	server         string
	serverIsDomain bool
	detour         string
	domainResolver string // DomainResolver.Server, "" when no domain_resolver
	version        string // socks Version, "" when absent (defaults to 5)
	members        []string
	deflt          string // selector Default
}

// describeOutbound extracts a chainInfo from an outbound's options
// value by reflection: the sing-box option structs carry Server,
// Detour, DomainResolver, Version and Outbounds in embedded structs
// (DialerOptions/ServerOptions), so the fields are found by name
// through promotion. Unknown option shapes yield a zero-valued
// info, which the detour exception treats as "not self-resolving".
func describeOutbound(outboundType string, options any) chainInfo {
	info := chainInfo{typ: strings.ToLower(outboundType)}
	info.server = serverString(options)
	_, info.serverIsDomain = domainServer(options)
	v := reflect.ValueOf(options)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return info
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return info
	}
	if f := findField(v, "Detour"); f.IsValid() && f.Kind() == reflect.String {
		info.detour = f.String()
	}
	if f := findField(v, "Version"); f.IsValid() && f.Kind() == reflect.String {
		info.version = f.String()
	}
	if f := findField(v, "DomainResolver"); f.IsValid() {
		for f.Kind() == reflect.Pointer {
			if f.IsNil() {
				break
			}
			f = f.Elem()
		}
		if f.Kind() == reflect.Struct {
			if sf := f.FieldByName("Server"); sf.IsValid() && sf.Kind() == reflect.String {
				info.domainResolver = sf.String()
			}
		}
	}
	if f := findField(v, "Outbounds"); f.IsValid() && f.Kind() == reflect.Slice {
		for i := 0; i < f.Len(); i++ {
			if e := f.Index(i); e.Kind() == reflect.String {
				info.members = append(info.members, e.String())
			}
		}
	}
	if f := findField(v, "Default"); f.IsValid() && f.Kind() == reflect.String {
		info.deflt = f.String()
	}
	return info
}

// findField returns the struct field named name, following
// promotion through anonymous embedded structs. FieldByName
// already promotes, so the recursion is only a backstop for
// doubly-embedded fields; it never descends into named fields.
func findField(v reflect.Value, name string) reflect.Value {
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return reflect.Value{}
	}
	if f := v.FieldByName(name); f.IsValid() {
		return f
	}
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		if !t.Field(i).Anonymous {
			continue
		}
		f := v.Field(i)
		for f.Kind() == reflect.Pointer {
			if f.IsNil() {
				break
			}
			f = f.Elem()
		}
		if f.Kind() == reflect.Struct {
			if r := findField(f, name); r.IsValid() {
				return r
			}
		}
	}
	return reflect.Value{}
}

// allowsDomainServerWithoutRouter is the F3 detour exception: it
// reports whether a domain-server outbound (described by info, not
// yet created) may be created with no DNS router because its
// detour chain provably forwards the domain server address
// verbatim to a remote proxy. The outer outbound must itself be
// an http or socks5 forwarder with no domain_resolver; the chain
// walk (chainSelfResolvesLocked) then decides the rest. Anything
// unproven returns false: refusal is the safe direction.
func (m *Manager) allowsDomainServerWithoutRouter(info chainInfo) bool {
	if info.domainResolver != "" || info.detour == "" {
		return false
	}
	switch info.typ {
	case "http":
	case "socks":
		if info.version != "" && info.version != "5" {
			return false
		}
	default:
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.chainSelfResolvesLocked(info.detour, map[string]bool{})
}

// chainSelfResolvesLocked reports whether dialling a domain
// destination through the already-created outbound with tag can
// never dereference a nil DNS router. The caller must hold m.mu.
// path is the set of tags on the current walk (cycle guard); a
// tag already on the path, a missing tag, a domain_resolver on
// any link, or a type outside the proven allow-list all return
// false. Selector/urltest members are all required to qualify,
// because group selection is dynamic.
func (m *Manager) chainSelfResolvesLocked(tag string, path map[string]bool) bool {
	info, ok := m.created[tag]
	if !ok || path[tag] || info.domainResolver != "" {
		return false
	}
	path[tag] = true
	defer delete(path, tag)
	switch info.typ {
	case "socks":
		if info.version != "" && info.version != "5" {
			return false
		}
	case "http":
	case "selector", "urltest":
		seen := 0
		for _, member := range append(append([]string{}, info.members...), info.deflt) {
			if member == "" {
				continue
			}
			seen++
			if !m.chainSelfResolvesLocked(member, path) {
				return false
			}
		}
		return seen > 0
	default:
		return false
	}
	if info.detour == "" {
		return info.server != "" && !info.serverIsDomain
	}
	return m.chainSelfResolvesLocked(info.detour, path)
}

// CreateEndpoint creates one endpoint from its registry type and
// options. WireGuard endpoints are userspace only (Gate 2 Q4): an
// option with System: true is rejected here, before the registry, so
// the error is the same with and without the with_wireguard tag.
func (m *Manager) CreateEndpoint(ctx context.Context, tag, endpointType string, options any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tag == "" {
		return errors.New("outbound: endpoint tag must not be empty")
	}
	if strings.EqualFold(endpointType, "wireguard") {
		if system, ok := wireGuardSystemFlag(options); ok && system {
			return errors.New("outbound: wireguard endpoint with system:true is rejected: userspace WireGuard only")
		}
	}
	if err := m.endpoints.Create(m.registryContext(), m.router, m.logger, tag, endpointType, options); err != nil {
		return logging.WrapErr(fmt.Errorf("outbound: create endpoint %s[%s]: %w", endpointType, tag, err))
	}
	return nil
}

// wireGuardSystemFlag extracts the System flag from a WireGuard
// endpoint options value in either pointer or value form. It reports
// false when the options are not WireGuard options at all.
func wireGuardSystemFlag(options any) (bool, bool) {
	switch opts := options.(type) {
	case *option.WireGuardEndpointOptions:
		if opts == nil {
			return false, false
		}
		return opts.System, true
	case option.WireGuardEndpointOptions:
		return opts.System, true
	default:
		return false, false
	}
}

// Outbound returns the outbound with tag, if one was created.
func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.outbounds.Outbound(tag)
}

// Endpoint returns the endpoint with tag, if one was created.
func (m *Manager) Endpoint(tag string) (adapter.Endpoint, bool) {
	return m.endpoints.Get(tag)
}

// Default returns the default outbound (the first created), or nil if
// none was created.
func (m *Manager) Default() adapter.Outbound {
	return m.outbounds.Default()
}

// Start runs the sing-box lifecycle stages Initialize, Start,
// PostStart, and Started over the endpoint and outbound managers, in
// the same order box.Box uses. A second Start is an error. Start after
// Close fails because the scope is closed.
//
// The started flag is set only after every stage succeeds, under the
// mutex that guards it, and Start holds that mutex for the whole stage
// loop: a concurrent Close cannot cancel the scope mid-start and leave
// the manager observable as started with unstarted outbounds, and a
// failed Start leaves started false (the caller should Close to
// release any partially started stage).
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return errors.New("outbound: Start called twice")
	}
	if m.closed {
		return errors.New("outbound: Start called after Close")
	}
	for _, stage := range adapter.ListStartStages {
		if err := m.scope.Start("endpoint", m.endpoints, stage); err != nil {
			// Sing-box start errors may embed config material
			// (e.g. the WireGuard IpcSet error); wrap at the
			// boundary so the printed text is redacted.
			return logging.WrapErr(fmt.Errorf("outbound: start endpoint manager (%s): %w", stage, err))
		}
		if err := m.scope.Start("outbound", m.outbounds, stage); err != nil {
			return logging.WrapErr(fmt.Errorf("outbound: start outbound manager (%s): %w", stage, err))
		}
	}
	m.started = true
	return nil
}

// Close closes the lifecycle scope, which closes every started
// outbound/endpoint in reverse order. Close is idempotent and safe
// without Start.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	scope := m.scope
	m.mu.Unlock()
	return scope.Close()
}

// Dialer returns a Dialer bound to the outbound with tag, wired to
// the DNS router registered via RegisterDNSRouter (nil when none was
// registered: domain dials then fail closed with ErrNoResolver).
// tlsOptions are the profile's default TLS options for DialTLS calls
// that pass none.
func (m *Manager) Dialer(tag string) (*Dialer, error) {
	outbound, ok := m.outbounds.Outbound(tag)
	if !ok {
		return nil, fmt.Errorf("outbound: no outbound with tag %q", tag)
	}
	var resolver HostResolver
	if router := service.FromContext[adapter.DNSRouter](m.registryContext()); router != nil {
		resolver = router
	}
	return NewDialerWithLogger(outbound, resolver, option.OutboundTLSOptions{}, m.logger), nil
}
