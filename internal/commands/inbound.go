// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"log/slog"

	"github.com/thoitiettxl-cyber/castctl/internal/keeper"
	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// The S2 inbound adapter: a keeper.InboundBuilder backed by
// one profile runtime's outbound Dialer. BuildInbound starts
// the loopback proxy (internal/outbound) and returns its URL
// plus a cleanup that closes it. The proxy is created per
// browser launch, never shared across profiles: the Dialer
// it closes over belongs to exactly one profile's runtime.
//
// The adapter is constructed by the command layer, which owns
// runtimes; the keeper package never sees a Dialer, and the
// outbound package never sees a profile.
type profileInboundBuilder struct {
	dialer *outbound.Dialer
	opts   outbound.ProxyOptions
}

// proxyOptionsForEntry is the SINGLE place production S2
// proxy options are built: from a keeper entry's Effective*
// accessors (nil-safe: a nil entry means the documented
// defaults) plus the refusal logger. The proxy never runs
// on hidden defaults. The refusal callback logs the refused
// host ONLY (no URL, query, port, or headers) through the
// runtime logger; it is the one place a guard refusal is
// logged.
func proxyOptionsForEntry(entry *profile.KeeperEntry, logger *slog.Logger) outbound.ProxyOptions {
	opts := outbound.ProxyOptions{
		DialTimeout:    entry.EffectiveProxyDialTimeout(),
		MaxHeaderBytes: entry.EffectiveProxyMaxHeaderBytes(),
		MaxBodyBytes:   entry.EffectiveProxyMaxBodyBytes(),
		AllowedHosts:   entry.EffectiveProxyAllowedHosts(),
	}
	if logger != nil {
		opts.OnRefused = func(host string) {
			logger.Warn("s2 proxy refused target", "host", host)
		}
	}
	return opts
}

// newProfileInboundBuilder returns the S2 inbound builder
// for a runtime and keeper entry, or nil when the runtime
// has no dialer (fail closed: the launch path refuses
// without an inbound).
func newProfileInboundBuilder(rt *Runtime, entry *profile.KeeperEntry) keeper.InboundBuilder {
	if rt == nil || rt.Dialer == nil {
		return nil
	}
	return profileInboundBuilder{dialer: rt.Dialer, opts: proxyOptionsForEntry(entry, rt.Logger("castctl"))}
}

func (b profileInboundBuilder) BuildInbound(_ context.Context, _ *profile.Profile) (string, func(), error) {
	proxy, proxyURL, err := outbound.NewLoopbackProxy(b.dialer, b.opts)
	if err != nil {
		return "", nil, err
	}
	return proxyURL, func() { _ = proxy.Close() }, nil
}
