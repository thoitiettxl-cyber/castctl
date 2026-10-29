package dns

import (
	"context"
	"fmt"

	"github.com/sagernet/sing-box/option"
)

// substituteBootstrap resolves the DNS server's own hostname once
// per server, before any transport is created. It is the ONLY place
// bootstrap resolution happens: never for dial targets, never for
// other hostnames, never as a fallback after a DNS failure.
//
// For each remote server whose address IsDomain(), the hostname is
// resolved via bootstrap and the first IPv4 address (else the first
// address) replaces the hostname in the server options. The original
// hostname is preserved as the TLS ServerName when TLS options exist
// with an empty ServerName, so certificate verification still uses
// the hostname. Server types without an address field (local, hosts,
// fakeip) are returned unchanged.
func substituteBootstrap(ctx context.Context, servers []option.DNSServerOptions, bootstrap BootstrapFunc) ([]option.DNSServerOptions, error) {
	out := make([]option.DNSServerOptions, len(servers))
	for i, server := range servers {
		options, err := substituteServerAddress(ctx, server.Options, bootstrap)
		if err != nil {
			return nil, fmt.Errorf("dns: bootstrap for server %q: %w", server.Tag, err)
		}
		server.Options = options
		out[i] = server
	}
	return out, nil
}

func substituteServerAddress(ctx context.Context, options any, bootstrap BootstrapFunc) (any, error) {
	switch opts := options.(type) {
	case *option.RemoteDNSServerOptions:
		return opts, substituteAddress(ctx, &opts.DNSServerAddressOptions, nil, bootstrap)
	case option.RemoteDNSServerOptions:
		if err := substituteAddress(ctx, &opts.DNSServerAddressOptions, nil, bootstrap); err != nil {
			return nil, err
		}
		return opts, nil
	case *option.RemoteTLSDNSServerOptions:
		return opts, substituteAddress(ctx, &opts.DNSServerAddressOptions, tlsServerNameOf(&opts.OutboundTLSOptionsContainer), bootstrap)
	case option.RemoteTLSDNSServerOptions:
		if err := substituteAddress(ctx, &opts.DNSServerAddressOptions, tlsServerNameOf(&opts.OutboundTLSOptionsContainer), bootstrap); err != nil {
			return nil, err
		}
		return opts, nil
	case *option.RemoteHTTPSDNSServerOptions:
		return opts, substituteAddress(ctx, &opts.DNSServerAddressOptions, tlsServerNameOf(&opts.OutboundTLSOptionsContainer), bootstrap)
	case option.RemoteHTTPSDNSServerOptions:
		if err := substituteAddress(ctx, &opts.DNSServerAddressOptions, tlsServerNameOf(&opts.OutboundTLSOptionsContainer), bootstrap); err != nil {
			return nil, err
		}
		return opts, nil
	default:
		return options, nil
	}
}

// tlsServerNameOf returns a setter for the TLS ServerName, or nil
// when the container carries no TLS options.
func tlsServerNameOf(container *option.OutboundTLSOptionsContainer) *string {
	if container == nil || container.TLS == nil {
		return nil
	}
	return &container.TLS.ServerName
}

func substituteAddress(ctx context.Context, addr *option.DNSServerAddressOptions, serverName *string, bootstrap BootstrapFunc) error {
	if !addr.ServerIsDomain() {
		return nil
	}
	original := addr.Server
	addrs, err := bootstrap(ctx, original)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return fmt.Errorf("bootstrap for %s returned no addresses", original)
	}
	chosen := addrs[0]
	for _, a := range addrs {
		if a.Is4() {
			chosen = a
			break
		}
	}
	addr.Server = chosen.String()
	if serverName != nil && *serverName == "" {
		*serverName = original
	}
	return nil
}
