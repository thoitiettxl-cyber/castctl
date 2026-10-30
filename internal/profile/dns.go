// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// Per-profile DNS resolution (gated model, implemented in this PR).
//
// Precedence, in order, for the active profile:
//  1. The profile's own "dns" block (DNSSourceProfile).
//  2. The WireGuard endpoint's DNS servers, reached through
//     that tunnel (DNSSourceWireGuard). The servers come from
//     SingleConfig.WireGuardDNS, keyed by endpoint tag: that map
//     is hand-written/preserved castctl-side state. The parser
//     outbound.ParseWireGuardConfWithDNS can capture wg-quick
//     DNS= lines, but no production caller wires that capture
//     into wireguard_dns yet — import-path wiring is a
//     follow-up, so branch (ii) must not be described as
//     "imported from the wg-quick DNS= line" as a present-tense
//     fact. When branch (ii) fires while a top-level dns section
//     is present, the section is shadowed, and ResolveProfileDNS
//     sets Warning (same stderr channel as the compat warning)
//     so the shadowing is observable.
//  3. The top-level "dns" section, compat fallback for one cycle
//     only (DNSSourceGlobalCompat), with a warning telling the
//     operator to distribute it into profile entries with
//     `config migrate --write` (which distributes for single
//     configs since G4). It applies ONLY when no
//     per-profile dns
//     exists; coexistence of a profile block and a top-level
//     section is a parse-time error (G1), and the warning cycle
//     ends in a hard error in a later PR (documented, not yet
//     implemented). Compat sits before the default deliberately:
//     a config migrated by the removal PR carries an authored
//     global section that must keep working for one cycle, and
//     the brief requires the compat-warning behaviour to be
//     observable — if the synthesised default always won, the
//     compat branch could never fire. (This differs from the
//     pre-gate design doc §3.3, which ordered synthesis before
//     the global fallback; that order would make compat dead
//     code. The ordering is stated here and in docs/config.md
//     so the PR review can rule on it explicitly.)
//  4. The synthesised default: DoH to 1.1.1.1 (https, IP-literal,
//     no bootstrap), with detour = the profile's outbound
//     (DNSSourceDefault). It applies only when the file carries
//     no resolver at all (e.g. Step A output). For a direct
//     profile there is no config tag to detour to, so the detour
//     is the runtime-only per-profile direct outbound named by
//     SynthesizedDirectTag; createOutbounds creates it (see
//     internal/commands/runtime.go and the gate-2 note below).
//
// "local" is NEVER synthesised here: it is explicit-only. A
// hand-written "local" server keeps sing-box's default
// prefer_go=false; on systemd-resolved hosts its queries may
// bypass the detour via D-Bus (see docs/config.md). The synthesised
// default is DoH, not local.
//
// Gate-2 note (measured, internal/dns/gate2_test.go): sing-box
// rejects a detour to an EMPTY direct outbound at transport Start
// ("detour to an empty direct outbound makes no sense",
// common/dialer/detour.go:69-76, sing-box v1.14.4), and its
// DisableEmptyDirectCheck switch is json:"-" and never set on
// any DNS transport dialer path, so castctl cannot flip it through
// dns.New. The clearance used here does NOT weaken that guard:
// the synthesised detour target is a direct outbound made
// non-empty by construction (see SynthesizedDirectOutbound in
// internal/commands/runtime.go), created only inside the active
// profile's own manager and used only as a DNS detour. The plain
// "direct" outbound stays empty, and a detour naming it still
// fails exactly as before.

// DNSSource names which precedence branch produced a resolution.
type DNSSource string

const (
	// DNSSourceProfile is the profile's own "dns" block.
	DNSSourceProfile DNSSource = "profile"
	// DNSSourceWireGuard is WireGuard DNS servers (from
	// wireguard_dns state).
	DNSSourceWireGuard DNSSource = "wireguard"
	// DNSSourceDefault is the synthesised DoH default.
	DNSSourceDefault DNSSource = "default"
	// DNSSourceGlobalCompat is the top-level section fallback.
	DNSSourceGlobalCompat DNSSource = "global-compat"
	// DNSSourceNone means no resolver (no single config file).
	DNSSourceNone DNSSource = "none"
)

// ResolvedDNS is one profile's effective resolver.
type ResolvedDNS struct {
	Options *option.DNSOptions
	Source  DNSSource
	// Warning is set for the global-compat branch and for the
	// WireGuard branch when it shadows a present top-level dns
	// section; the caller prints it once on stderr.
	Warning string
	// SynthesizedDirectTag is the runtime-only direct outbound
	// tag the detour names, or "" when the resolution detours
	// to an existing config tag. The runtime must create this
	// tag (non-empty direct) before dnsClient.Start().
	SynthesizedDirectTag string
}

// defaultDNSServerTag is the tag of the single server in the
// synthesised default and WireGuard resolvers.
const defaultDNSServerTag = "castctl-doh"

// SynthesizedDirectTagPrefix is reserved: no config outbound,
// endpoint, or inline outbound tag may carry it (enforced by
// validateTagGraph). The reservation is what keeps the
// synthesised tag collision-free: a config tag equal to a
// profile's synthesised tag would otherwise capture the
// default DoH detour, and createOutbounds would silently skip
// creating the synthesised outbound.
const SynthesizedDirectTagPrefix = "castctl-direct:"

// IsReservedSynthesizedTag reports whether a config tag carries
// the reserved synthesised-direct prefix.
func IsReservedSynthesizedTag(tag string) bool {
	return strings.HasPrefix(tag, SynthesizedDirectTagPrefix)
}

// SynthesizedDirectTag returns the runtime-only tag of the
// per-profile direct outbound synthesised for a direct profile's
// default DNS detour. It is deterministic from the profile name
// (profile names admit only [A-Za-z0-9._-]), never collides with
// a config tag namespace entry (config tags carrying the
// reserved prefix are rejected at parse time, and validation
// treats it as reachable only for its own profile), and is never
// written into the config file.
func SynthesizedDirectTag(profileName string) string {
	return SynthesizedDirectTagPrefix + profileName
}

// ResolveProfileDNS resolves the active profile's effective DNS
// options. It is pure: it reads only prof and single, never the
// filesystem, and never mutates either. A nil single (no single
// config file) yields DNSSourceNone with nil options, preserving
// the historical fail-closed path for config-less profiles.
func ResolveProfileDNS(prof *Profile, single *SingleConfig) (*ResolvedDNS, error) {
	if prof == nil {
		return nil, newConfigError("cannot resolve dns for nil profile")
	}
	if single == nil {
		return &ResolvedDNS{Source: DNSSourceNone}, nil
	}
	// (1) Own block.
	if prof.dnsPresent {
		if single.DNS != nil {
			return nil, newConfigErrorf("profile %q has both a per-profile dns block and a top-level dns section: remove the top-level dns section (distribute it into profile entries by hand first, see docs/config.md)", prof.Name)
		}
		opts, err := prof.ParsedDNS()
		if err != nil {
			return nil, err
		}
		synth := ""
		for _, srv := range opts.Servers {
			if d := detourOf(srv.Options); d == SynthesizedDirectTag(prof.Name) {
				synth = d
			}
		}
		return &ResolvedDNS{Options: opts, Source: DNSSourceProfile, SynthesizedDirectTag: synth}, nil
	}
	// (2) WireGuard DNS through the profile's tunnel. When a
	// top-level dns section is also present, this branch
	// shadows it: set the warning so the shadowing is
	// observable on stderr (same channel as the compat
	// warning), never silently.
	if tag, servers, ok := wireGuardDNSForProfile(prof, single); ok {
		opts, err := buildWireGuardDNSOptions(tag, servers)
		if err != nil {
			return nil, err
		}
		warning := ""
		if single.DNS != nil {
			warning = fmt.Sprintf("castctl: top-level dns section is ignored for profile %q: WireGuard DNS takes precedence; run \"config migrate --write\" to distribute the top-level section into profile entries (see docs/config.md)", prof.Name)
		}
		return &ResolvedDNS{Options: opts, Source: DNSSourceWireGuard, Warning: warning}, nil
	}
	// (3) Global-compat fallback, before the default (see the
	// package header for why compat precedes synthesis: a
	// migrated config's authored global section must keep
	// working for one cycle, and the compat warning must be
	// observable).
	if single.DNS != nil {
		opts, err := single.ParsedDNS()
		if err != nil {
			return nil, err
		}
		return &ResolvedDNS{
			Options: opts,
			Source:  DNSSourceGlobalCompat,
			Warning: "castctl: top-level dns section is deprecated and will become an error in a later release: run \"config migrate --write\" to distribute it into profile entries (see docs/config.md)",
		}, nil
	}
	// (4) Synthesised DoH default.
	detour, synth := defaultDetourForProfile(prof, single)
	opts, err := buildDefaultDNSOptions(detour)
	if err != nil {
		return nil, err
	}
	return &ResolvedDNS{Options: opts, Source: DNSSourceDefault, SynthesizedDirectTag: synth}, nil
}

// defaultDetourForProfile returns the detour tag the synthesised
// default DoH uses for this profile, plus the synthesised direct
// tag to create ("" unless the profile is direct).
func defaultDetourForProfile(prof *Profile, single *SingleConfig) (detour, synth string) {
	switch prof.Outbound.Kind {
	case OutboundTag:
		return prof.Outbound.Tag, ""
	case OutboundInline:
		return prof.Outbound.Tag, ""
	default: // OutboundDirect (and any unknown kind: fail-closed
		// to the synthesised direct, whose creation is explicit).
		tag := SynthesizedDirectTag(prof.Name)
		return tag, tag
	}
}

// buildDefaultDNSOptions builds the synthesised DoH resolver:
// one https server, IP-literal 1.1.1.1, path /dns-query, detour
// as given. It parses through parseDNS (sing-box's own schema)
// rather than hand-building option structs, so the shape stays
// identical to the migrate-time interim authoring.
func buildDefaultDNSOptions(detour string) (*option.DNSOptions, error) {
	detourJSON, err := json.Marshal(detour)
	if err != nil {
		return nil, newConfigErrorf("dns default: cannot encode detour tag: %v", err)
	}
	raw := []byte(fmt.Sprintf(`{"servers":[{"tag":%q,"type":"https","server":"1.1.1.1","server_port":443,"path":"/dns-query","detour":%s}],"final":%q}`,
		defaultDNSServerTag, detourJSON, defaultDNSServerTag))
	return parseDNS(raw)
}

// buildWireGuardDNSOptions builds one udp server per listed DNS
// address, all detouring through the WireGuard endpoint tag. Port
// 53 is sing-box's default for udp servers; the addresses are
// validated at config parse (see validateWireGuardDNS), so no
// re-validation happens here beyond parseDNS itself.
func buildWireGuardDNSOptions(endpointTag string, servers []string) (*option.DNSOptions, error) {
	detourJSON, err := json.Marshal(endpointTag)
	if err != nil {
		return nil, newConfigErrorf("dns wireguard: cannot encode detour tag: %v", err)
	}
	var b strings.Builder
	b.WriteString(`{"servers":[`)
	for i, srv := range servers {
		if i > 0 {
			b.WriteString(",")
		}
		srvJSON, err := json.Marshal(srv)
		if err != nil {
			return nil, newConfigErrorf("dns wireguard: cannot encode server: %v", err)
		}
		fmt.Fprintf(&b, `{"tag":%q,"type":"udp","server":%s,"server_port":53,"detour":%s}`,
			fmt.Sprintf("%s-%d", defaultDNSServerTag, i+1), srvJSON, detourJSON)
	}
	fmt.Fprintf(&b, `],"final":%q}`, fmt.Sprintf("%s-1", defaultDNSServerTag))
	return parseDNS([]byte(b.String()))
}

// wireGuardDNSForProfile returns the WireGuard endpoint tag and
// DNS servers for the profile's tunnel, when the profile's
// outbound resolves (directly, or one detour hop through an
// outbound) to a WireGuard endpoint that carries DNS servers in
// single.WireGuardDNS.
func wireGuardDNSForProfile(prof *Profile, single *SingleConfig) (string, []string, bool) {
	if single == nil || len(single.WireGuardDNS) == 0 {
		return "", nil, false
	}
	endpointsByTag := make(map[string]option.Endpoint, len(single.Endpoints))
	for _, ep := range single.Endpoints {
		endpointsByTag[ep.Tag] = ep
	}
	outboundsByTag := make(map[string]option.Outbound, len(single.Outbounds))
	for _, ob := range single.Outbounds {
		outboundsByTag[ob.Tag] = ob
	}
	var seeds []string
	switch prof.Outbound.Kind {
	case OutboundTag:
		seeds = append(seeds, prof.Outbound.Tag)
	case OutboundInline:
		if ob, err := prof.Outbound.InlineOutbound(); err == nil && ob != nil {
			seeds = append(seeds, outboundNextTags(*ob)...)
		}
	}
	// Walk detour chains (cycle-guarded) to the endpoint tag.
	visited := make(map[string]bool)
	queue := append([]string{}, seeds...)
	for len(queue) > 0 {
		tag := queue[0]
		queue = queue[1:]
		if visited[tag] {
			continue
		}
		visited[tag] = true
		if ep, ok := endpointsByTag[tag]; ok {
			if ep.Type == "wireguard" {
				if servers, ok := single.WireGuardDNS[tag]; ok && len(servers) > 0 {
					return tag, servers, true
				}
			}
			queue = append(queue, nextTags(ep.Options)...)
			continue
		}
		if ob, ok := outboundsByTag[tag]; ok {
			queue = append(queue, outboundNextTags(ob)...)
		}
	}
	return "", nil, false
}

// reachableTagsForProfile returns the tag set a profile's own dns
// detours may name: the profile's outbound tag (or inline tag),
// every tag reachable from it through detour chains and
// selector/urltest member lists, plus — for direct profiles
// only — the profile's synthesised direct tag. Tags of other
// profiles' inline outbounds are NOT reachable (they are never
// walked from this profile's seed), which is what makes the
// check per-profile rather than global.
func reachableTagsForProfile(cfg *SingleConfig, p *Profile) map[string]bool {
	outboundsByTag := make(map[string]option.Outbound, len(cfg.Outbounds))
	for _, ob := range cfg.Outbounds {
		outboundsByTag[ob.Tag] = ob
	}
	endpointsByTag := make(map[string]option.Endpoint, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		endpointsByTag[ep.Tag] = ep
	}
	reachable := make(map[string]bool)
	var queue []string
	switch p.Outbound.Kind {
	case OutboundTag:
		queue = append(queue, p.Outbound.Tag)
	case OutboundInline:
		queue = append(queue, p.Outbound.Tag)
		if ob, err := p.Outbound.InlineOutbound(); err == nil && ob != nil {
			queue = append(queue, outboundNextTags(*ob)...)
		}
	case OutboundDirect:
		reachable[SynthesizedDirectTag(p.Name)] = true
	}
	for len(queue) > 0 {
		tag := queue[0]
		queue = queue[1:]
		if reachable[tag] {
			continue
		}
		reachable[tag] = true
		if ob, ok := outboundsByTag[tag]; ok {
			queue = append(queue, outboundNextTags(ob)...)
			continue
		}
		if ep, ok := endpointsByTag[tag]; ok {
			queue = append(queue, nextTags(ep.Options)...)
		}
	}
	return reachable
}

// validateProfileDNS checks every profile's own dns block: each
// server's detour must be non-empty (G2) and in the owning
// profile's reachable set, server tags are unique within the
// block, and final (when set) matches a server tag in the same
// block. It runs inside validateTagGraph's caller chain, after
// the global checks, so per-profile errors name the profile.
func validateProfileDNS(cfg *SingleConfig) error {
	for _, name := range cfg.ProfileNames() {
		p := cfg.Profiles[name]
		if p == nil || !p.dnsPresent || p.DNS == nil {
			continue
		}
		reachable := reachableTagsForProfile(cfg, p)
		serverTags := make(map[string]bool)
		for _, srv := range p.DNS.Servers {
			if serverTags[srv.Tag] {
				return newConfigErrorf("profile %q: duplicate dns server tag %q", name, srv.Tag)
			}
			serverTags[srv.Tag] = true
			d := detourOf(srv.Options)
			if d == "" {
				return newConfigErrorf("profile %q: dns server %q has no detour: DNS must travel through the profile's outbound", name, srv.Tag)
			}
			if !reachable[d] {
				return newConfigErrorf("profile %q: dns server %q: dangling reference: detour %q is not reachable from this profile's outbound", name, srv.Tag, d)
			}
		}
		if p.DNS.Final != "" && !serverTags[p.DNS.Final] {
			return newConfigErrorf("profile %q: dns final %q does not match any dns server tag in this profile's dns block", name, p.DNS.Final)
		}
	}
	return nil
}

// validateWireGuardDNS checks the castctl-side wireguard_dns map:
// each key must name a WireGuard endpoint in the same file, and
// each value must be a non-empty server address (IP literal or
// hostname; sing-box resolves domain servers via bootstrap at
// construction, exactly as for hand-written dns servers).
func validateWireGuardDNS(cfg *SingleConfig) error {
	if len(cfg.WireGuardDNS) == 0 {
		return nil
	}
	for _, ep := range cfg.Endpoints {
		_ = ep
	}
	endpointsByTag := make(map[string]option.Endpoint, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		endpointsByTag[ep.Tag] = ep
	}
	for tag, servers := range cfg.WireGuardDNS {
		ep, ok := endpointsByTag[tag]
		if !ok {
			return newConfigErrorf("wireguard_dns: endpoint tag %q does not exist", tag)
		}
		if ep.Type != "wireguard" {
			return newConfigErrorf("wireguard_dns: endpoint %q is type %q, not wireguard", tag, ep.Type)
		}
		if len(servers) == 0 {
			return newConfigErrorf("wireguard_dns: endpoint %q has no dns servers", tag)
		}
		for _, srv := range servers {
			if strings.TrimSpace(srv) == "" {
				return newConfigErrorf("wireguard_dns: endpoint %q has an empty dns server", tag)
			}
		}
	}
	return nil
}

// parseWireGuardDNSMap parses the top-level "wireguard_dns"
// value: an object mapping endpoint tag -> array of server
// address strings. It validates shape only; tag existence and
// endpoint type are checked by validateWireGuardDNS, which runs
// after endpoints are parsed.
func parseWireGuardDNSMap(v any) (map[string][]string, error) {
	obj, ok := v.(*orderedObject)
	if !ok {
		return nil, newConfigError("\"wireguard_dns\" must be an object")
	}
	out := make(map[string][]string, len(obj.keys))
	for _, tag := range obj.keys {
		arr, ok := obj.values[tag].([]any)
		if !ok {
			return nil, newConfigErrorf("wireguard_dns: endpoint %q must map to an array of server addresses", tag)
		}
		servers := make([]string, 0, len(arr))
		for _, elem := range arr {
			s, ok := elem.(string)
			if !ok {
				return nil, newConfigErrorf("wireguard_dns: endpoint %q has a non-string dns server", tag)
			}
			servers = append(servers, s)
		}
		out[tag] = servers
	}
	return out, nil
}

// profileDNSWireGuardEndpoints returns the WireGuard endpoint tags
// reachable from one profile's own dns detour chains.
func profileDNSWireGuardEndpoints(p *Profile, endpointsByTag map[string]option.Endpoint, outboundsByTag map[string]option.Outbound) []string {
	if p == nil || p.DNS == nil {
		return nil
	}
	var seeds []string
	for _, srv := range p.DNS.Servers {
		if d := detourOf(srv.Options); d != "" {
			seeds = append(seeds, d)
		}
	}
	return walkWireGuardEndpoints(seeds, endpointsByTag, outboundsByTag)
}
