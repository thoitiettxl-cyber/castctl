// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"fmt"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// distributeTopLevelDNS copies the candidate's top-level dns
// section verbatim into every profile's own dns block and removes
// the top-level key, in memory only: the caller decides whether
// to write the candidate (see MigrateFrom). It returns
// distributed=false with no error when the candidate carries no
// top-level section. Any refusal is all-or-nothing: the candidate
// is left unmutated and the refusal names the profile and the
// field/tag that failed (path/field names only, never values
// from the dns block).
//
// Detour mapping per profile (D2), for each dialer-carrying
// server (hosts/fakeip servers carry no detour field and are
// copied untouched):
//
//   - empty/missing detour -> filled with the profile's own
//     detour tag (defaultDetourForProfile: outbound/inline tag,
//     or the synthesised castctl-direct:<profile> tag for a
//     direct profile). A detour is always emitted; sing-box
//     treats an omitted detour as direct dial, never as "the
//     profile's outbound".
//   - detour equal to the profile's own tag -> kept verbatim.
//   - detour reachable from the profile's outbound (the
//     validateProfileDNS reachable set) but different from the
//     own tag -> kept verbatim; rewriting it would silently
//     reroute DNS onto a different tunnel.
//   - detour failing the per-profile fit checks -> the whole
//     run refuses. An unreachable detour is never silently
//     rewritten to the own tag.
//
// The copy is made at the raw-JSON level (the preserved top-level
// bytes, re-decoded per profile) so every field — servers,
// rules, final, reverse_mapping, and all client options —
// survives field-for-field with no field enumeration, and
// intra-block references (final, rule server refs) stay valid
// without renaming: server tags are scoped per block. After
// building the candidate it is validated exactly as a
// hand-written file would be (tag graph, per-profile DNS,
// WireGuard DNS, WireGuard key sharing, plus a full re-parse
// of the canonical encoding), and any failure refuses the run.
// A profile that already carries its own dns block, or that
// resolves WireGuard DNS through its tunnel (branch 2, which
// an own block would shadow), also refuses: distributing onto
// either would change behaviour silently. When no non-nil
// profile would receive a block (zero profiles, or every
// profile entry nil), the run refuses instead of deleting the
// top-level section without distributing it.
func distributeTopLevelDNS(candidate *SingleConfig, baseDir string) (distributed bool, refusal string, err error) {
	if candidate == nil || candidate.DNS == nil {
		return false, "", nil
	}
	// No-recipient guard (F1): distribution that would delete
	// the top-level section while no profile receives a copy
	// is a silent deletion, not a distribution. Refuse
	// all-or-nothing, before the empty-section guard below
	// (which names a profile and therefore needs a recipient
	// to exist) and before any mutation or validation: with
	// only nil entries, validation itself cannot run safely.
	hasRecipient := false
	for _, name := range candidate.ProfileNames() {
		if candidate.Profiles[name] != nil {
			hasRecipient = true
			break
		}
	}
	if !hasRecipient {
		refusal = "dns distribution refused: top-level dns section is present but no profile would receive a distributed dns block (no non-nil profile entries); refusing to delete the section without distributing it (see docs/config.md)"
		return false, refusal, newConfigError(refusal)
	}
	if len(candidate.DNS.Servers) == 0 && len(candidate.Profiles) > 0 {
		refusal = fmt.Sprintf("dns distribution refused: profile %q: top-level dns section has no servers; refusing to distribute an empty dns section (see docs/config.md)", candidate.ProfileNames()[0])
		return false, refusal, newConfigError(refusal)
	}

	// Guards that read state before any mutation. Presence
	// follows the existing dnsPresent/rawDNS parse semantics:
	// a present-but-empty {} counts as a block.
	for _, name := range candidate.ProfileNames() {
		p := candidate.Profiles[name]
		if p != nil && p.dnsPresent {
			refusal = fmt.Sprintf("dns distribution refused: profile %q already has a per-profile dns block; distribution would overwrite it (see docs/config.md)", name)
			return false, refusal, newConfigError(refusal)
		}
	}
	for _, name := range candidate.ProfileNames() {
		p := candidate.Profiles[name]
		if p == nil {
			continue
		}
		if tag, _, ok := wireGuardDNSForProfile(p, candidate); ok {
			refusal = fmt.Sprintf("dns distribution refused: profile %q resolves WireGuard DNS through endpoint %q; distributing the top-level dns section would shadow it with a per-profile dns block (see docs/config.md)", name, tag)
			return false, refusal, newConfigError(refusal)
		}
	}

	globalRaw := candidate.RawDNS()
	if len(globalRaw) == 0 {
		raw, merr := marshalSing(candidate.DNS)
		if merr != nil {
			return false, "", merr
		}
		globalRaw = raw
	}

	// Phase 1: compute every per-profile block without
	// mutating the candidate, so a refusal in any profile
	// leaves the whole candidate untouched.
	type pendingBlock struct {
		raw    []byte
		parsed *option.DNSOptions
	}
	pending := make(map[string]pendingBlock, len(candidate.Profiles))
	for _, name := range candidate.ProfileNames() {
		p := candidate.Profiles[name]
		if p == nil {
			continue
		}
		ownDetour, _ := defaultDetourForProfile(p, candidate)
		reachable := reachableTagsForProfile(candidate, p)
		decoded, derr := decodeOrderedJSON(globalRaw)
		if derr != nil {
			return false, "", derr
		}
		obj, ok := decoded.(*orderedObject)
		if !ok {
			refusal = fmt.Sprintf("dns distribution refused: profile %q: top-level dns section is not a JSON object", name)
			return false, refusal, newConfigError(refusal)
		}
		if serversVal, present := obj.get("servers"); present {
			servers, ok := serversVal.([]any)
			if !ok || len(servers) != len(candidate.DNS.Servers) {
				refusal = fmt.Sprintf("dns distribution refused: profile %q: top-level dns servers do not match the parsed dns section", name)
				return false, refusal, newConfigError(refusal)
			}
			for i, elem := range servers {
				srvObj, ok := elem.(*orderedObject)
				if !ok {
					refusal = fmt.Sprintf("dns distribution refused: profile %q: dns server %d is not a JSON object", name, i)
					return false, refusal, newConfigError(refusal)
				}
				parsedSrv := candidate.DNS.Servers[i]
				if !carriesDetour(parsedSrv.Options) {
					// hosts/fakeip: no detour field exists;
					// copy untouched (per-profile validation
					// below refuses the candidate, since a
					// detour-less server cannot satisfy G2).
					continue
				}
				current := detourOf(parsedSrv.Options)
				switch {
				case current == "":
					srvObj.set("detour", ownDetour)
				case current == ownDetour:
					// Keep verbatim: no edit.
				case reachable[current]:
					// Keep verbatim: rewriting a reachable
					// detour would silently reroute DNS.
				default:
					refusal = fmt.Sprintf("dns distribution refused: profile %q: dns server %q detour %q is not reachable from this profile's outbound (see docs/config.md)", name, parsedSrv.Tag, current)
					return false, refusal, newConfigError(refusal)
				}
			}
		}
		raw, rerr := rawOf(obj)
		if rerr != nil {
			return false, "", rerr
		}
		parsed, perr := parseDNS(raw)
		if perr != nil {
			refusal = fmt.Sprintf("dns distribution refused: profile %q: distributed dns block does not parse: %s", name, stripErrorPrefix(perr))
			return false, refusal, newConfigError(refusal)
		}
		pending[name] = pendingBlock{raw: raw, parsed: parsed}
	}

	// Phase 2: apply, then validate the whole candidate
	// exactly as a hand-written file is validated. On any
	// failure restore the pre-distribution state.
	savedDNS := candidate.DNS
	savedRawDNS := candidate.rawDNS
	savedProfiles := make(map[string]*pendingBlock, len(candidate.Profiles))
	for _, name := range candidate.ProfileNames() {
		p := candidate.Profiles[name]
		if p != nil {
			savedProfiles[name] = &pendingBlock{raw: p.rawDNS, parsed: p.DNS}
		}
	}
	restore := func() {
		candidate.DNS = savedDNS
		candidate.rawDNS = savedRawDNS
		for name, saved := range savedProfiles {
			if p := candidate.Profiles[name]; p != nil {
				p.DNS = saved.parsed
				p.rawDNS = saved.raw
				// The guards above refused any profile with
				// dnsPresent set, so every profile entered
				// with dnsPresent=false; restore exactly that.
				p.dnsPresent = false
			}
		}
	}
	for _, name := range candidate.ProfileNames() {
		p := candidate.Profiles[name]
		if p == nil {
			continue
		}
		block := pending[name]
		p.DNS = block.parsed
		p.rawDNS = block.raw
		p.dnsPresent = true
	}
	candidate.DNS = nil
	candidate.rawDNS = nil

	validate := func() error {
		if err := validateTagGraph(candidate); err != nil {
			return err
		}
		if err := validateProfileDNS(candidate); err != nil {
			return err
		}
		if err := validateWireGuardDNS(candidate); err != nil {
			return err
		}
		if err := validateWireGuardPrivateKeys(candidate); err != nil {
			return err
		}
		// Full re-parse of the canonical encoding: the
		// distributed file must load exactly as written.
		encoded, err := canonicalSingleBytes(candidate)
		if err != nil {
			return err
		}
		if _, err := ParseSingleConfig(encoded, baseDir); err != nil {
			return err
		}
		return nil
	}
	if err := validate(); err != nil {
		restore()
		refusal = fmt.Sprintf("dns distribution refused: %s", stripErrorPrefix(err))
		return false, refusal, newConfigError(refusal)
	}
	return true, "", nil
}

// stripErrorPrefix removes the standard "profile: " error prefix
// from an embedded validation or parse error, so a distribution
// refusal quoting it does not read "profile: profile ...".
// Only one leading prefix is removed, and only when present;
// errors without the prefix pass through unchanged. Local to
// this file's refusal rendering: shared error formatting is
// untouched.
func stripErrorPrefix(err error) string {
	return strings.TrimPrefix(err.Error(), "profile: ")
}

// carriesDetour reports whether parsed DNS server options carry
// a DialerOptions detour field. hosts and fakeip servers do
// not (sing-box option/dns.go: HostsDNSServerOptions and
// FakeIPDNSServerOptions embed no DialerOptions).
func carriesDetour(options any) bool {
	_, ok := options.(option.DialerOptionsWrapper)
	return ok
}
