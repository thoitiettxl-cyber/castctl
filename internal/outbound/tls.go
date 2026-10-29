package outbound

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// GatewayTLSOptions returns the effective TLS options for gateway
// traffic: uTLS with the "chrome" fingerprint is the DEFAULT. If the
// profile supplies no UTLS block, or an enabled UTLS block with an
// empty fingerprint, the default is filled in. An explicitly disabled
// UTLS block is left disabled (reality then fails inside sing-box,
// which requires uTLS). The caller's options are never mutated.
//
// ALPN is deliberately NOT pinned here: it passes through from the
// profile's TLS options / sing-box defaults. The h2-vs-http/1.1
// question is OPEN (sing-box uTLS appends "http/1.1" after a lone
// "h2"; see UTLSClientConfig.SetNextProtos in sing-box common/tls).
// Whether the real gateway negotiates h2 or http/1.1 under the chrome
// fingerprint is decided by the operator's direct (non-proxied) TLS
// probe, not by assumption in this code.
func GatewayTLSOptions(opts option.OutboundTLSOptions) option.OutboundTLSOptions {
	effective := opts
	switch {
	case effective.UTLS == nil:
		effective.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
	case effective.UTLS.Enabled && effective.UTLS.Fingerprint == "":
		utls := *effective.UTLS
		utls.Fingerprint = "chrome"
		effective.UTLS = &utls
	}
	return effective
}

// BuildTLSConfig builds a sing-box TLS client config for serverAddress
// from opts. When opts.Enabled is false it returns (nil, opts, nil):
// no TLS was requested. Only the verified methods of the sing-box
// tls.Config interface are called (verified with `go doc
// github.com/sagernet/sing/common/tls.Config`: ServerName,
// SetServerName, NextProtos, SetNextProtos, HandshakeTimeout,
// SetHandshakeTimeout, STDConfig, Client, Clone). Reality options pass
// through sing-box TLS untouched; no reality logic lives here.
func BuildTLSConfig(ctx context.Context, logger log.ContextLogger, serverAddress string, opts option.OutboundTLSOptions) (tls.Config, option.OutboundTLSOptions, error) {
	if !opts.Enabled {
		return nil, opts, nil
	}
	effective := GatewayTLSOptions(opts)
	if effective.ServerName == "" {
		effective.ServerName = serverAddress
	}
	config, err := tls.NewClientWithOptions(tls.ClientOptions{
		Context:       ctx,
		Logger:        logger,
		ServerAddress: serverAddress,
		Options:       effective,
	})
	if err != nil {
		return nil, effective, err
	}
	return config, effective, nil
}

// HandshakeTLS performs the TLS client handshake over conn using
// config. On error the caller owns conn; HandshakeTLS does not close
// it (DialTLS closes the raw conn on handshake failure instead).
func HandshakeTLS(ctx context.Context, conn net.Conn, config tls.Config) (tls.Conn, error) {
	return tls.ClientHandshake(ctx, conn, config)
}
