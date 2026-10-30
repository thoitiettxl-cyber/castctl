// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// BootstrapLookup is the SINGLE system-resolver call site in the Go
// port. It resolves a DNS server's own hostname exactly once, before
// that server can be used as a transport — sing-box has no bootstrap
// concept of its own (verified by grep over the sing-box 1.14.4
// source: no "bootstrap" in dns/, common/dialer/, or adapter/).
//
// This is the ONLY exception to the fail-closed invariant, and it is
// never a fallback for other hostnames: BootstrapLookup is called
// only from the DNS package's bootstrap substitution, only for the
// configured DNS server's hostname, and a bootstrap failure is an
// error, never a silent fallback. The lookup is debug-logged with the
// hostname and the address count only — never the resolved values —
// and no secret is ever involved.
//
// Fail-closed boundary, precisely: bootstrap applies only to the DNS
// server's own hostname, resolved once before that server can be
// used. Every other lookup goes through the configured DNS server
// and the outbound/detour that server is configured with; DNS
// failure is an error, and there is no system-resolver fallback for
// any other host. RECOMMENDATION: configure DNS servers by IP
// address. An IP-address server needs no bootstrap lookup at all
// (the DNS package leaves non-domain server addresses untouched),
// so the system resolver is never consulted.
func BootstrapLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return BootstrapLookupWithLogger(ctx, host, slog.Default())
}

// BootstrapLookupWithLogger is BootstrapLookup with the slog
// logger supplied by the caller: the DNS client passes the
// factory-routed bridge logger so the lookup line obeys the
// resolved log level. A nil logger falls back to slog.Default().
// The logged fields are the host and the address COUNT only —
// never the resolved addresses themselves.
func BootstrapLookupWithLogger(ctx context.Context, host string, logger *slog.Logger) ([]netip.Addr, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if host == "" {
		return nil, errors.New("outbound: bootstrap lookup with empty host")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resolver := net.DefaultResolver
	hosts, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("outbound: bootstrap lookup for %s: %w", host, err)
	}
	addrs := make([]netip.Addr, 0, len(hosts))
	for _, h := range hosts {
		addr, err := netip.ParseAddr(h)
		if err != nil {
			continue
		}
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("outbound: bootstrap lookup for %s returned no addresses", host)
	}
	logger.Debug("outbound bootstrap lookup", "host", host, "addresses", len(addrs))
	return addrs, nil
}
