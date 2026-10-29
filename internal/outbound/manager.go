package outbound

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	endpointManager "github.com/sagernet/sing-box/adapter/endpoint"
	outboundManager "github.com/sagernet/sing-box/adapter/outbound"
	dnsTransportManager "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
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
	if err := m.outbounds.Create(m.registryContext(), m.router, m.logger, tag, outboundType, options); err != nil {
		return fmt.Errorf("outbound: create %s[%s]: %w", outboundType, tag, err)
	}
	return nil
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
		return fmt.Errorf("outbound: create endpoint %s[%s]: %w", endpointType, tag, err)
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
			return fmt.Errorf("outbound: start endpoint manager (%s): %w", stage, err)
		}
		if err := m.scope.Start("outbound", m.outbounds, stage); err != nil {
			return fmt.Errorf("outbound: start outbound manager (%s): %w", stage, err)
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
	return NewDialer(outbound, resolver, option.OutboundTLSOptions{}), nil
}
