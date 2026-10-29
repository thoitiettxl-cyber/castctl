package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// ErrNoResolver is returned when a domain destination is dialled (or
// resolved) without a registered DNS resolver. It is the fail-closed
// signal: dialling must never fall back to the system resolver.
var ErrNoResolver = errors.New("outbound: no DNS resolver registered: refusing to resolve a domain without configured DNS")

// HostResolver is the resolver seam the Dialer calls for hostname
// resolution. adapter.DNSRouter satisfies it (its Lookup method has
// this exact signature), and tests inject a fake. The Dialer never
// calls net.DefaultResolver.
type HostResolver interface {
	Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error)
}

// Dialer wraps one adapter.Outbound and is the ONLY dial path for a
// profile. All traffic — plain, TLS, HTTP, WebSocket — goes through
// the wrapped outbound. Domain destinations are resolved by
// sing-box's own resolve dialer inside the outbound (which uses the
// configured DNS router/transport), preserving parallel dial and
// remote-DNS proxy behaviour; Dialer only guards that a resolver
// exists before delegating, so a missing resolver fails closed
// instead of panicking inside sing-box code.
type Dialer struct {
	outbound   adapter.Outbound
	resolver   HostResolver
	tlsOptions option.OutboundTLSOptions
	logger     log.ContextLogger
}

// NewDialer builds a Dialer around outbound. resolver may be nil; in
// that case domain dials and Resolve fail with ErrNoResolver while IP
// dials still work.
func NewDialer(outbound adapter.Outbound, resolver HostResolver, tlsOptions option.OutboundTLSOptions) *Dialer {
	return &Dialer{
		outbound:   outbound,
		resolver:   resolver,
		tlsOptions: tlsOptions,
		logger:     log.NewNOPFactory().NewLogger("outbound"),
	}
}

// DialContext dials network ("tcp" or "udp") to host:port through the
// outbound. A domain host with no registered resolver returns
// ErrNoResolver before the outbound is touched. The caller's context
// deadline bounds the dial; no additional timeout is imposed here.
func (d *Dialer) DialContext(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
	dest := Socksaddr(host, port)
	if dest.IsDomain() && d.resolver == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoResolver, host)
	}
	conn, err := d.outbound.DialContext(ctx, network, dest)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Resolve resolves domain through the injected resolver seam under a
// monotonic 5s timeout. It never touches the system resolver.
func (d *Dialer) Resolve(ctx context.Context, domain string) ([]netip.Addr, error) {
	if d.resolver == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoResolver, domain)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return d.resolver.Lookup(ctx, domain, adapter.DNSQueryOptions{})
}

// DialTLS dials plain through the outbound, then handshakes TLS with
// the effective options (the passed options, or the Dialer's defaults
// when the passed options are disabled; TLS is forced on because
// DialTLS means TLS was requested). The uTLS chrome default from
// GatewayTLSOptions applies. On handshake failure the raw connection
// is closed and the error returned.
func (d *Dialer) DialTLS(ctx context.Context, network, host string, port uint16, tlsOptions option.OutboundTLSOptions) (net.Conn, error) {
	effective := tlsOptions
	if !effective.Enabled {
		effective = d.tlsOptions
	}
	effective.Enabled = true
	config, _, err := BuildTLSConfig(ctx, d.logger, host, effective)
	if err != nil {
		return nil, err
	}
	raw, err := d.DialContext(ctx, network, host, port)
	if err != nil {
		return nil, err
	}
	tlsConn, err := HandshakeTLS(ctx, raw, config)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tlsConn, nil
}

// HTTPClient returns an *http.Client whose transport dials through
// the outbound. Proxy is explicitly nil: http.Transport must never
// consult proxy environment variables. DialTLSContext uses the
// Dialer's default TLS options.
func (d *Dialer) HTTPClient() *http.Client {
	dialer := d
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := splitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, host, port)
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := splitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return dialer.DialTLS(ctx, network, host, port, dialer.tlsOptions)
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// WebSocketDial returns a net.Conn ready for a WebSocket handshake:
// dialled through the outbound, TLS-wrapped when secure is true. PR1
// does NOT pick a WebSocket library and does NOT implement WS
// framing; PR2 chooses the library and performs the handshake on
// this conn.
//
// Lesson recorded for PR2 (PR0 probe, gorilla/websocket): gorilla's
// websocket.NewClient double-handshakes a pre-TLS conn, so PR2 must
// NOT use NewClient on a pre-TLS conn. Use a Dialer+NetDialTLSContext
// style construction (or an equivalent that accepts a pre-dialled
// conn without re-handshaking), verified against the chosen
// library's docs before use.
//
// Noise lesson recorded for PR2 (PR0 probe): the gateway's Noise
// handshake msg2 payload is 36 bytes, and Python accepts any payload
// length. The PR2 gateway must accept any msg2 payload length and
// never assert it is 0.
func (d *Dialer) WebSocketDial(ctx context.Context, network, host string, port uint16, secure bool, tlsOptions option.OutboundTLSOptions) (net.Conn, error) {
	if !secure {
		return d.DialContext(ctx, network, host, port)
	}
	return d.DialTLS(ctx, network, host, port, tlsOptions)
}

// splitHostPort splits a net dial address ("host:port") into host and
// numeric port. It is used only for http.Transport dial callbacks,
// whose addr is already a host:port pair.
func splitHostPort(addr string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("outbound: invalid dial address %q: %w", addr, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return "", 0, fmt.Errorf("outbound: invalid port in dial address %q: %w", addr, err)
	}
	if port < 0 || port > 65535 {
		return "", 0, fmt.Errorf("outbound: port out of range in dial address %q", addr)
	}
	return host, uint16(port), nil
}
