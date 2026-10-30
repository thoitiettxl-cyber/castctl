// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"context"

	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"

	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
)

// OutboundKind classifies how a profile selects its outbound.
type OutboundKind string

const (
	// OutboundDirect means no outbound key: direct, still through one
	// direct adapter so fail-closed applies uniformly (delta).
	OutboundDirect OutboundKind = "direct"
	// OutboundTag means the profile references a tag in outbounds/endpoints.
	OutboundTag OutboundKind = "tag"
	// OutboundInline means the profile carries a full option.Outbound object.
	OutboundInline OutboundKind = "inline"
)

// OutboundRef is a profile's resolved outbound selection. For Kind tag,
// Type is the referenced outbound/endpoint type and From names which
// section it came from ("outbound" or "endpoint"). For Kind inline, Raw
// holds the original object JSON and Tag is the object's tag (auto-tagged
// "profile:<name>" when absent).
type OutboundRef struct {
	Kind OutboundKind
	Tag  string
	Type string
	From string
	Raw  []byte

	parsed *option.Outbound
}

// IsDirect reports whether the profile uses the direct outbound.
func (r OutboundRef) IsDirect() bool { return r.Kind == OutboundDirect }

// RawJSON returns a defensive copy of the inline object JSON, or nil for
// non-inline refs.
func (r OutboundRef) RawJSON() []byte {
	if len(r.Raw) == 0 {
		return nil
	}
	out := make([]byte, len(r.Raw))
	copy(out, r.Raw)
	return out
}

// InlineOutbound returns the parsed option.Outbound for inline refs, or
// (nil, nil) for tag/direct refs. It re-parses the stored raw JSON so
// callers cannot mutate shared parsed state.
func (r OutboundRef) InlineOutbound() (*option.Outbound, error) {
	if r.Kind != OutboundInline {
		return nil, nil
	}
	if len(r.Raw) == 0 && r.parsed != nil {
		cp := *r.parsed
		return &cp, nil
	}
	ob, err := parseOutbound(r.Raw)
	if err != nil {
		return nil, err
	}
	return &ob, nil
}

// singContext returns a context carrying sing-box's own registries, so
// option.Outbound/Endpoint/DNSOptions parse through the registry instead
// of any hand-written schema copy.
//
// NB9 unification: this delegates to outbound.RegistryContext, the
// single process-global include.Context construction. include.Context
// is NOT safe to call concurrently (its QUIC stub registration
// assigns the package-global naive.ConfigureHTTP3ListenerFunc), and
// -race flags concurrent builds, so there must be exactly one call
// site; the registries themselves are safe for concurrent reads
// (CreateOptions takes the registry lock). This package must not
// build its own include.Context, and internal/outbound must not
// import this package (no cycle).
func singContext() context.Context {
	return outbound.RegistryContext()
}

// parseOutbound parses one outbound object with sing-box's own
// option.Outbound type via the include.Context registry. Unknown outbound
// types and unknown fields are rejected by badjson (see
// TestOutboundUnknownFieldRejected, which records the measured outcome).
func parseOutbound(raw []byte) (option.Outbound, error) {
	var ob option.Outbound
	if err := ob.UnmarshalJSONContext(singContext(), raw); err != nil {
		return ob, newConfigErrorf("parse outbound: %v", err)
	}
	if ob.Type == "wireguard" {
		return ob, newConfigError("outbound type \"wireguard\" is not an outbound; declare it in \"endpoints\" and reference its tag")
	}
	return ob, nil
}

// parseEndpoint parses one endpoint object with sing-box's own
// option.Endpoint type via the include.Context registry.
func parseEndpoint(raw []byte) (option.Endpoint, error) {
	var ep option.Endpoint
	if err := ep.UnmarshalJSONContext(singContext(), raw); err != nil {
		return ep, newConfigErrorf("parse endpoint: %v", err)
	}
	return ep, nil
}

// parseDNS parses the dns section with sing-box's own option.DNSOptions
// type via the include.Context registry.
func parseDNS(raw []byte) (*option.DNSOptions, error) {
	var dns option.DNSOptions
	if err := dns.UnmarshalJSONContext(singContext(), raw); err != nil {
		return nil, newConfigErrorf("parse dns: %v", err)
	}
	return &dns, nil
}

// marshalSing renders a sing-box option value through its
// MarshalJSONContext implementation (used only when no raw JSON was
// preserved for a value, e.g. a hand-built SingleConfig).
func marshalSing(v any) ([]byte, error) {
	raw, err := singjson.MarshalContext(singContext(), v)
	if err != nil {
		return nil, newConfigErrorf("marshal sing-box options: %v", err)
	}
	return raw, nil
}

// detourOf extracts the detour tag from parsed options that carry
// DialerOptions, or "" when the options type has no detour.
func detourOf(options any) string {
	if w, ok := options.(option.DialerOptionsWrapper); ok {
		return w.TakeDialerOptions().Detour
	}
	return ""
}

// groupMembers returns outbound tags referenced inside parsed
// options that are not detours: selector/urltest member lists and
// the selector default. Other option types reference no members.
func groupMembers(options any) []string {
	switch opts := options.(type) {
	case *option.SelectorOutboundOptions:
		out := append([]string{}, opts.Outbounds...)
		if opts.Default != "" {
			out = append(out, opts.Default)
		}
		return out
	case *option.URLTestOutboundOptions:
		return append([]string{}, opts.Outbounds...)
	default:
		return nil
	}
}

// referencedTags returns outbound tags referenced inside parsed options
// that are not detours: selector/urltest member lists and defaults.
func referencedTags(ob option.Outbound) []string {
	return groupMembers(ob.Options)
}
