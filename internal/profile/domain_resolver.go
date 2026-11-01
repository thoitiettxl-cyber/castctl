// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"reflect"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// LocalBootstrapServerTag is the literal tag of the dedicated
// "local" DNS server synthesised by ResolveProfileDNS as the
// default domain_resolver target for outbound server addresses
// (see dns.go). The tag is literal and shared: sing-box DNS
// servers are addressed per TransportManager, so one tag per
// profile invocation is enough, and a user-defined server with
// this tag is reconciled by ResolveProfileDNS (reused when it is
// a clean local server, fail-closed otherwise).
const LocalBootstrapServerTag = "local"

// ApplyDomainResolverDefault is the runtime-only default for
// outbound server-address resolution (Seam B of the DNS-bootstrap
// fix). It returns ob with DomainResolver set to
// {Server: localTag} exactly when ALL of these hold:
//
//   - localTag is non-empty (the effective DNS options carry the
//     synthesised or user-defined "local" server),
//   - the outbound is not "direct" (a direct outbound's
//     domain_resolver governs request domains, never a server
//     address, and must never be defaulted here),
//   - the options carry a dialer + server address and that
//     address is a domain (ServerIsDomain; IP literals and
//     groups without a server address are untouched),
//   - DomainResolver is unset, or set with an empty server
//     (the empty string form is treated as unset; an explicit
//     string or object value is honoured exactly as sing-box
//     parsed it, never overwritten).
//
// The input outbound is never mutated: the options value is
// shallow-copied before ReplaceDialerOptions, so a parsed
// config value passed in keeps its authored shape (identity
// hashes and saved output are unaffected). The returned
// outbound is runtime-only: callers must never write it back
// to a config file.
//
// This is a deliberate castctl fail-closed choice, NOT a
// sing-box default: sing-box leaves domain_resolver unset
// unless authored. The default exists because a hostname
// outbound with no detour and no domain_resolver is resolved
// through the profile's only DNS transport, which loops when
// that transport itself detours through the outbound
// (sing-box rejects it with "DNS query loopback"). Resolving
// the server address through the system resolver ("local"
// transport) breaks the loop. The leak is documented in
// docs/config.md: the system resolver sees outbound server
// hostnames. SNI and TLS verification are untouched: no
// substitution happens, the resolved address only feeds the
// dialer.
func ApplyDomainResolverDefault(ob option.Outbound, localTag string) option.Outbound {
	if localTag == "" || strings.EqualFold(ob.Type, "direct") {
		return ob
	}
	cloned, ok := addressableOptionsCopy(ob.Options)
	if !ok {
		return ob
	}
	dialer, ok := cloned.(option.DialerOptionsWrapper)
	if !ok {
		return ob
	}
	server, ok := cloned.(option.ServerOptionsWrapper)
	if !ok {
		return ob
	}
	if !server.TakeServerOptions().ServerIsDomain() {
		return ob
	}
	dialerOpts := dialer.TakeDialerOptions()
	if dialerOpts.DomainResolver != nil && dialerOpts.DomainResolver.Server != "" {
		return ob
	}
	dialerOpts.DomainResolver = &option.DomainResolveOptions{Server: localTag}
	dialer.ReplaceDialerOptions(dialerOpts)
	out := ob
	out.Options = cloned
	return out
}

// addressableOptionsCopy returns a pointer to a shallow copy of
// the options value, so wrapper Replace methods (pointer
// receivers on the embedded DialerOptions) can run without
// mutating the caller's value. Pointer options are copied to a
// fresh pointer; struct-value options are copied to a fresh
// addressable value. Anything else reports false.
func addressableOptionsCopy(options any) (any, bool) {
	v := reflect.ValueOf(options)
	if !v.IsValid() {
		return nil, false
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || v.Elem().Kind() != reflect.Struct {
			return nil, false
		}
		cp := reflect.New(v.Elem().Type())
		cp.Elem().Set(v.Elem())
		return cp.Interface(), true
	case reflect.Struct:
		cp := reflect.New(v.Type())
		cp.Elem().Set(v)
		return cp.Interface(), true
	default:
		return nil, false
	}
}
