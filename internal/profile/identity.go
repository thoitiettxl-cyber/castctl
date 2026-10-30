// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"encoding/json"
	"fmt"

	"github.com/sagernet/sing-box/option"
)

// Outbound identity for the S7 reconnect key (CLIProxyAPI notes §6
// item S7): a shared connection is reused only when the outbound
// identity matches, so changing a profile's outbound in config.json
// forces a reconnect. The identity is (tag, sha256-hex of the
// canonical outbound JSON).
//
// Canonical byte format: compact JSON (no whitespace), keys in the
// order stored, number literals preserved. It is produced by
// re-encoding the stored Raw JSON through the ordered decoder, which
// normalises whitespace only; a value with no stored Raw (hand-built
// config) is serialised through sing-box's own marshaller instead.
// Direct profiles hash the fixed bytes
// {"type":"direct","tag":"direct"}.
//
// The Profile-only form (OutboundIdentity) cannot see the object a
// tag reference points to, so for tag references it hashes the
// fixed-shape JSON {"kind":"tag","tag":<tag>,"type":<type>} (struct
// field order, encoding/json escaping). That identity is stable
// when the tag/type are unchanged but BLIND to edits of the
// referenced object: it must NOT be used as the reconnect key for
// tag-referencing profiles. Use OutboundIdentityForConfig, which
// resolves the tag to the actual stored object and hashes that, for
// the reconnect key.
func OutboundIdentity(p *Profile) (string, string, error) {
	if p == nil {
		return "", "", newConfigError("cannot compute outbound identity of nil profile")
	}
	switch p.Outbound.Kind {
	case OutboundDirect:
		return "direct", sha256Hex([]byte(`{"type":"direct","tag":"direct"}`)), nil
	case OutboundInline:
		if p.Outbound.Tag == "" {
			return "", "", newConfigErrorf("profile %q: inline outbound has no tag", p.Name)
		}
		raw, err := canonicalOutboundBytes(p.Outbound.RawJSON(), p.Outbound.parsed)
		if err != nil {
			return "", "", err
		}
		return p.Outbound.Tag, sha256Hex(raw), nil
	case OutboundTag:
		if p.Outbound.Tag == "" {
			return "", "", newConfigErrorf("profile %q: outbound tag reference is empty", p.Name)
		}
		shape := struct {
			Kind string `json:"kind"`
			Tag  string `json:"tag"`
			Type string `json:"type"`
		}{Kind: "tag", Tag: p.Outbound.Tag, Type: p.Outbound.Type}
		raw, err := json.Marshal(shape)
		if err != nil {
			return "", "", newConfigErrorf("outbound identity: %v", err)
		}
		return p.Outbound.Tag, sha256Hex(raw), nil
	default:
		return "", "", newConfigErrorf("profile %q: unknown outbound kind %q", p.Name, p.Outbound.Kind)
	}
}

// OutboundIdentityForConfig returns the S7 reconnect identity for
// the named profile in cfg: for tag references it resolves the tag
// to the stored outbound/endpoint object (raw JSON when the config
// was parsed from a file, sing-box marshalling otherwise) and hashes
// that, so editing the referenced object changes the identity and
// forces a reconnect. Direct and inline profiles delegate to
// OutboundIdentity.
func OutboundIdentityForConfig(cfg *SingleConfig, name string) (string, string, error) {
	if cfg == nil {
		return "", "", newConfigError("cannot compute outbound identity of nil config")
	}
	p, ok := cfg.Profiles[name]
	if !ok {
		return "", "", newConfigErrorf("profile %q does not exist in the single config file", name)
	}
	if p.Outbound.Kind != OutboundTag {
		return OutboundIdentity(p)
	}
	tag := p.Outbound.Tag
	if tag == "" {
		return "", "", newConfigErrorf("profile %q: outbound tag reference is empty", name)
	}
	// Prefer the section the reference resolved from, then search
	// both: the tag namespace is unique, so at most one matches.
	sections := []string{"outbound", "endpoint"}
	if p.Outbound.From == "endpoint" {
		sections = []string{"endpoint", "outbound"}
	}
	for _, section := range sections {
		if section == "outbound" {
			for i := range cfg.Outbounds {
				if cfg.Outbounds[i].Tag == tag {
					raw, err := rawOrMarshal(cfg.rawOutbounds, i, &cfg.Outbounds[i])
					if err != nil {
						return "", "", err
					}
					return tag, sha256Hex(raw), nil
				}
			}
		} else {
			for i := range cfg.Endpoints {
				if cfg.Endpoints[i].Tag == tag {
					raw, err := rawOrMarshal(cfg.rawEndpoints, i, &cfg.Endpoints[i])
					if err != nil {
						return "", "", err
					}
					return tag, sha256Hex(raw), nil
				}
			}
		}
	}
	return "", "", newConfigErrorf("profile %q: outbound tag %q does not exist", name, tag)
}

// canonicalOutboundBytes returns the canonical bytes for an inline
// outbound: the stored raw JSON re-encoded compactly, or the
// sing-box marshalling of the parsed value when no raw JSON is
// stored. At least one must be present.
func canonicalOutboundBytes(raw []byte, parsed *option.Outbound) ([]byte, error) {
	if len(raw) > 0 {
		v, err := decodeOrderedJSON(raw)
		if err != nil {
			return nil, err
		}
		return encodeOrderedJSON(v)
	}
	if parsed != nil {
		return marshalSing(parsed)
	}
	return nil, fmt.Errorf("inline outbound has neither raw json nor a parsed value")
}

// rawOrMarshal returns the canonical bytes for list entry i: the
// stored raw JSON at the same index when present, else the sing-box
// marshalling of the parsed value.
func rawOrMarshal(raws [][]byte, i int, v any) ([]byte, error) {
	if i < len(raws) && len(raws[i]) > 0 {
		vv, err := decodeOrderedJSON(raws[i])
		if err != nil {
			return nil, err
		}
		return encodeOrderedJSON(vv)
	}
	return marshalSing(v)
}
