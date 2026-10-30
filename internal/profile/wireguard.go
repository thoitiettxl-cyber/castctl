// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"encoding/base64"
	"sort"

	"github.com/sagernet/sing-box/option"
)

// validateWireGuardPrivateKeys enforces Boss hard invariant bullet 4:
// two profiles may NOT share a WireGuard endpoint config with the same
// private key.
//
// The check runs over profile-resolved endpoints: for each profile, the
// WireGuard endpoints reachable from its outbound selection — a direct
// endpoint tag, an outbound detour chain, a selector/urltest member
// list, or an inline outbound's detour. Endpoint private keys are
// compared by VALUE, never by tag, so two profiles referencing the
// same endpoint tag fail exactly like two profiles referencing two
// different endpoint entries that carry the same key.
//
// The global dns section is checked too: every profile also
// resolves DNS through the dns servers' detour chains, so a
// profile whose outbound key equals a dns-detour key is the same
// sharing violation, reported naming the profile and "dns". The
// dns detour is global (shared by all profiles), so it is compared
// against each profile directly, not merged into the profile's own
// set — merging would make the two endpoints look like one
// profile's own config, which the cross-profile check skips. A
// profile whose outbound endpoint IS the dns detour endpoint
// (same tag) is not an error: that is one endpoint config, not
// two configs carrying the same key.
//
// Per-profile dns sections are checked the same way, scoped per
// profile: a profile's own dns detour key compared against that
// profile's outbound key (different tags, same key = error naming
// the profile and "dns"; same tag = one config, not an error),
// and the profile's dns endpoints merged into its cross-profile
// set, so a dns detour in one profile sharing a key with another
// profile's outbound is still a cross-profile violation.
//
// Key comparison is canonical: two different base64 strings can
// decode to the same 32-byte key (padding-bit variants), so keys
// that both base64-decode (StdEncoding, as sing-box does) compare
// by decoded bytes; keys that do not decode compare by exact
// string. See canonicalWireGuardKey.
//
// Scope, decided from the bullet wording ("two profiles whose endpoint
// configs carry the same key"):
//
//   - Endpoints NOT referenced by any profile are out of scope: a
//     dormant duplicate gives no profile a shared key, and it fails
//     the moment a second profile resolves to it.
//   - Two same-key endpoints resolved by ONE profile are out of scope:
//     the bullet is cross-profile. (Within one profile the key is
//     still a single profile's own config.)
//   - An endpoint with an empty private key is skipped: there is no
//     key value to share, and an absent key is sing-box's own
//     runtime concern, not a sharing violation.
//
// The error names both profiles and both endpoint tags and NEVER
// contains the key value. Callers must keep it that way: no logging,
// wrapping, or redaction step may append key material to it.
func validateWireGuardPrivateKeys(cfg *SingleConfig) error {
	if cfg == nil {
		return nil
	}
	endpointsByTag := make(map[string]option.Endpoint, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		endpointsByTag[ep.Tag] = ep
	}
	outboundsByTag := make(map[string]option.Outbound, len(cfg.Outbounds))
	for _, ob := range cfg.Outbounds {
		outboundsByTag[ob.Tag] = ob
	}

	// WireGuard endpoints reachable from the global dns servers'
	// detour chains, keyed by canonical key: the first dns tag
	// seen per key. Dns-only duplicates (no profile involved)
	// are out of scope, as unreferenced duplicates are.
	dnsTagByKey := make(map[string]string)
	for _, tag := range dnsWireGuardEndpoints(cfg, endpointsByTag, outboundsByTag) {
		ep := endpointsByTag[tag]
		key, ok := wireGuardPrivateKey(ep)
		if !ok || key == "" {
			continue
		}
		canonical := canonicalWireGuardKey(key)
		if _, seen := dnsTagByKey[canonical]; !seen {
			dnsTagByKey[canonical] = tag
		}
	}

	type seenKey struct {
		profile string
		tag     string
	}
	seen := make(map[string]seenKey)
	for _, name := range cfg.ProfileNames() {
		p := cfg.Profiles[name]
		if p == nil {
			continue
		}
		ownTags := wireGuardEndpointsForProfile(p, endpointsByTag, outboundsByTag)
		dnsTags := profileDNSWireGuardEndpoints(p, endpointsByTag, outboundsByTag)
		// Own dns detour vs own outbound: same key through two
		// different tags is the sharing violation; the same tag
		// is one config and is not an error.
		ownByKey := make(map[string]string)
		for _, tag := range ownTags {
			ep := endpointsByTag[tag]
			key, ok := wireGuardPrivateKey(ep)
			if !ok || key == "" {
				continue
			}
			ownByKey[canonicalWireGuardKey(key)] = tag
		}
		for _, tag := range dnsTags {
			ep := endpointsByTag[tag]
			key, ok := wireGuardPrivateKey(ep)
			if !ok || key == "" {
				continue
			}
			canonical := canonicalWireGuardKey(key)
			if ownTag, dup := ownByKey[canonical]; dup && ownTag != tag {
				return newConfigErrorf("wireguard private key shared by profile %q and the dns detour (endpoints %q and %q); each profile must use a distinct wireguard private key", name, ownTag, tag)
			}
		}
		// Cross-profile check over the union of the profile's
		// outbound and own-dns endpoints; the global-dns check
		// runs against the union too, so a global detour key
		// shared with a per-profile dns detour is still caught.
		for _, tag := range append(append([]string{}, ownTags...), dnsTags...) {
			ep := endpointsByTag[tag]
			key, ok := wireGuardPrivateKey(ep)
			if !ok || key == "" {
				continue
			}
			canonical := canonicalWireGuardKey(key)
			if dnsTag, dup := dnsTagByKey[canonical]; dup && dnsTag != tag {
				return newConfigErrorf("wireguard private key shared by profile %q and the dns detour (endpoints %q and %q); each profile must use a distinct wireguard private key", name, tag, dnsTag)
			}
			if prev, dup := seen[canonical]; dup {
				if prev.profile == name {
					continue
				}
				return newConfigErrorf("wireguard private key shared by profiles %q and %q (endpoints %q and %q); each profile must use a distinct wireguard private key", prev.profile, name, prev.tag, tag)
			}
			seen[canonical] = seenKey{profile: name, tag: tag}
		}
	}
	return nil
}

// canonicalWireGuardKey returns the comparison form of a private
// key: when the key base64-decodes (StdEncoding, as sing-box
// decodes it), the decoded bytes; otherwise the exact string.
// Two strings that decode to the same bytes — e.g. padding-bit
// variants such as "...A=" and "...B=" for 32 zero bytes —
// compare equal; two undecodable strings compare exactly.
// The "b:"/"s:" prefix keeps the two families apart: a raw
// string can never equal a decoded byte string.
func canonicalWireGuardKey(key string) string {
	if decoded, err := base64.StdEncoding.DecodeString(key); err == nil {
		return "b:" + string(decoded)
	}
	return "s:" + key
}

// wireGuardEndpointsForProfile returns the sorted tags of the
// WireGuard endpoints reachable from p's outbound selection, following
// detour chains and selector/urltest member lists. Cycles terminate
// via the visited set. Tags that do not exist in either section are
// ignored here: validateTagGraph already rejects dangling references
// before this runs.
func wireGuardEndpointsForProfile(p *Profile, endpointsByTag map[string]option.Endpoint, outboundsByTag map[string]option.Outbound) []string {
	var seeds []string
	switch p.Outbound.Kind {
	case OutboundTag:
		seeds = append(seeds, p.Outbound.Tag)
	case OutboundInline:
		if ob, err := p.Outbound.InlineOutbound(); err == nil && ob != nil {
			// An inline outbound can never itself be wireguard
			// (parseOutbound rejects type "wireguard"), but its
			// detour or member list may resolve to one.
			seeds = append(seeds, outboundNextTags(*ob)...)
		}
	}
	return walkWireGuardEndpoints(seeds, endpointsByTag, outboundsByTag)
}

// dnsWireGuardEndpoints returns the sorted tags of the WireGuard
// endpoints reachable from the global dns section: each dns
// server's detour, followed through detour chains and
// selector/urltest member lists, exactly as for a profile's
// outbound selection. The dns section is global, so the result
// applies to every profile.
func dnsWireGuardEndpoints(cfg *SingleConfig, endpointsByTag map[string]option.Endpoint, outboundsByTag map[string]option.Outbound) []string {
	if cfg == nil || cfg.DNS == nil {
		return nil
	}
	var seeds []string
	for _, srv := range cfg.DNS.Servers {
		if d := detourOf(srv.Options); d != "" {
			seeds = append(seeds, d)
		}
	}
	return walkWireGuardEndpoints(seeds, endpointsByTag, outboundsByTag)
}

// walkWireGuardEndpoints returns the sorted tags of the WireGuard
// endpoints reachable from seeds, following detour chains and
// selector/urltest member lists. Cycles terminate via the visited
// set.
func walkWireGuardEndpoints(seeds []string, endpointsByTag map[string]option.Endpoint, outboundsByTag map[string]option.Outbound) []string {
	visited := make(map[string]bool, len(seeds))
	found := make(map[string]bool)
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
				if _, isWG := ep.Options.(*option.WireGuardEndpointOptions); isWG {
					found[tag] = true
				}
			}
			queue = append(queue, nextTags(ep.Options)...)
			continue
		}
		if ob, ok := outboundsByTag[tag]; ok {
			queue = append(queue, outboundNextTags(ob)...)
		}
	}
	tags := make([]string, 0, len(found))
	for tag := range found {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

// outboundNextTags returns the tags an outbound forwards to: its
// detour plus, for selector/urltest, its member list.
func outboundNextTags(ob option.Outbound) []string {
	next := referencedTags(ob)
	if d := detourOf(ob.Options); d != "" {
		next = append(next, d)
	}
	return next
}

// nextTags returns the detour tag of endpoint options, if any.
func nextTags(options any) []string {
	if d := detourOf(options); d != "" {
		return []string{d}
	}
	return nil
}

// wireGuardPrivateKey extracts the private key from a parsed endpoint.
// It reports false when the endpoint is not a parsed WireGuard endpoint
// (nil or foreign options, e.g. a hand-built SingleConfig), so callers
// never mistake an unparsed object for a keyless one.
func wireGuardPrivateKey(ep option.Endpoint) (string, bool) {
	wg, ok := ep.Options.(*option.WireGuardEndpointOptions)
	if !ok || wg == nil {
		return "", false
	}
	return wg.PrivateKey, true
}
