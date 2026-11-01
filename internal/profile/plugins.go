// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"regexp"
	"strings"
)

// The top-level `plugins` config block.
//
// Schema (sing-box inline shape, Boss decision 2026-11-01, Q1 as
// amended): an ARRAY of entry objects, each carrying `tag` and
// `type` plus the plugin's own fields INLINE next to them — no
// `enabled` field at any level, no nested `config` wrapper:
//
//	{"tag": "muse", "type": "muse", ...plugin fields...}
//
// Presence of an entry means the plugin is active; disable it by
// removing the entry. An `enabled` key inside an entry, if a
// plugin ever carries one, is plugin-opaque data: core never
// reads it and never treats it as a toggle.
//
// Core parses `tag`/`type` strictly (both required, both
// non-empty strings, tag matching the plugin-ID rule below) and
// hands the REMAINING object verbatim to the plugin as its
// fragment: core never interprets, validates, or normalises
// plugin-specific keys. The fragment is preserved verbatim on
// save (raw-first, like every other block) and redacted
// wholesale on display (RedactConfig shows tag/type only, the
// fragment as a single `<redacted>` marker — see redact.go).
// Plugin tags live in their own namespace: they do not
// participate in validateTagGraph's outbound/endpoint tag
// namespace, and validatePlugins only enforces uniqueness and
// (defence in depth) tag/type presence.
//
// The shape mirrors sing-box's own inline objects: option/outbound.go
// (_Outbound: Type, Tag, Options merged into ONE flat object by
// badjson) and option/endpoint.go (_Endpoint, identical shape) at
// sing-box v1.14.4, documented in
// docs/configuration/outbound/index.md (`{"outbounds": [{"type":
// "", "tag": ""}]}` with per-type fields inline). There is no
// `enabled` field in either sing-box type. Castctl's `plugins`
// array follows the same pattern with the top-level key
// literally `plugins`.
//
// A nil *PluginsConfig on SingleConfig means the block was
// absent from the file and no plugin is configured. An absent
// block is preserved on save (defaults stay runtime-only, the
// same presence precedent as the `log` block).

// pluginIDPattern is the plugin tag rule, mirroring upstream
// CLIProxyAPI's plugin ID regex
// (internal/pluginhost/platform.go:35 at pin 250d5981:
// `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`). Tags are exact: no
// surrounding whitespace (the regex rejects it), no path
// separators beyond the allowed set, never "." or "..".
var pluginIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// PluginEntry is one parsed `plugins` array entry.
type PluginEntry struct {
	Tag  string
	Type string
	// fragment is the entry object minus tag/type, verbatim
	// compact JSON, or nil when the entry carries no other keys.
	fragment []byte
	// raw is the full entry object JSON as parsed.
	raw []byte
}

// FragmentJSON returns a defensive copy of the plugin's config
// fragment (the entry object minus tag/type), or nil when the
// entry carries no plugin-specific keys.
func (e *PluginEntry) FragmentJSON() []byte {
	if e == nil || len(e.fragment) == 0 {
		return nil
	}
	out := make([]byte, len(e.fragment))
	copy(out, e.fragment)
	return out
}

// RawJSON returns a defensive copy of the full entry JSON.
func (e *PluginEntry) RawJSON() []byte {
	if e == nil || len(e.raw) == 0 {
		return nil
	}
	out := make([]byte, len(e.raw))
	copy(out, e.raw)
	return out
}

// PluginsConfig is one parsed top-level `plugins` block: the
// entries in file order. A nil *PluginsConfig means the block
// was absent.
type PluginsConfig struct {
	Entries []*PluginEntry

	raw []byte
}

// RawPlugins returns a defensive copy of the raw `plugins` JSON
// when the block was parsed from a file, or nil. It mirrors the
// raw-preservation accessors used by other blocks.
func (c *SingleConfig) RawPlugins() []byte {
	if c == nil || len(c.rawPlugins) == 0 {
		return nil
	}
	cp := make([]byte, len(c.rawPlugins))
	copy(cp, c.rawPlugins)
	return cp
}

// validatePluginTag enforces the plugin-ID rule on a tag value.
func validatePluginTag(tag string) error {
	if !pluginIDPattern.MatchString(tag) {
		return newConfigErrorf("invalid plugin tag %q", tag)
	}
	return nil
}

// parsePluginsBlock parses one decoded `plugins` value (an array
// of entry objects) into a PluginsConfig. Wrong shapes, wrong
// types, missing tag/type, duplicate tags, and invalid tags are
// all config errors (exit 2). Plugin-specific keys are never
// inspected: they are captured verbatim into the fragment.
func parsePluginsBlock(v any) (*PluginsConfig, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, newConfigError(`"plugins" must be an array of entries`)
	}
	cfg := &PluginsConfig{}
	seenTags := make(map[string]bool)
	for i, elem := range arr {
		obj, ok := elem.(*orderedObject)
		if !ok {
			return nil, newConfigErrorf(`"plugins" entry %d must be an object`, i)
		}
		raw, err := rawOf(elem)
		if err != nil {
			return nil, err
		}
		entry := &PluginEntry{raw: raw}
		for _, k := range obj.keys {
			val := obj.values[k]
			switch k {
			case "tag":
				s, ok := val.(string)
				if !ok || strings.TrimSpace(s) == "" {
					return nil, newConfigErrorf(`"plugins" entry %d: "tag" must be a non-empty string`, i)
				}
				if err := validatePluginTag(s); err != nil {
					return nil, newConfigErrorf(`"plugins" entry %d: invalid "tag": %v`, i, err)
				}
				entry.Tag = s
			case "type":
				s, ok := val.(string)
				if !ok || strings.TrimSpace(s) == "" || s != strings.TrimSpace(s) {
					return nil, newConfigErrorf(`"plugins" entry %d: "type" must be a non-empty string`, i)
				}
				entry.Type = s
			}
		}
		if entry.Tag == "" {
			return nil, newConfigErrorf(`"plugins" entry %d: "tag" must be a non-empty string`, i)
		}
		if entry.Type == "" {
			return nil, newConfigErrorf(`"plugins" entry %d: "type" must be a non-empty string`, i)
		}
		if seenTags[entry.Tag] {
			return nil, newConfigErrorf("duplicate plugin tag %q", entry.Tag)
		}
		seenTags[entry.Tag] = true
		// Fragment: the entry object minus tag/type, verbatim.
		fragObj := newOrderedObject()
		for _, k := range obj.keys {
			if k == "tag" || k == "type" {
				continue
			}
			fragObj.set(k, obj.values[k])
		}
		if len(fragObj.keys) > 0 {
			frag, err := rawOf(fragObj)
			if err != nil {
				return nil, err
			}
			entry.fragment = frag
		}
		cfg.Entries = append(cfg.Entries, entry)
	}
	return cfg, nil
}

// validatePlugins enforces the block's cross-entry rule: plugin
// tags are unique. Parse already enforces tag/type presence and
// uniqueness; this re-check runs in the ParseSingleConfig tail
// (after validateTagGraph) so hand-built SingleConfigs get the
// same refusal. A nil block is valid (no plugins configured).
func validatePlugins(cfg *SingleConfig) error {
	if cfg == nil || cfg.Plugins == nil {
		return nil
	}
	seen := make(map[string]bool)
	for _, e := range cfg.Plugins.Entries {
		if e == nil {
			continue
		}
		if e.Tag == "" || e.Type == "" {
			return newConfigError("plugin entry must have a non-empty tag and type")
		}
		if seen[e.Tag] {
			return newConfigErrorf("duplicate plugin tag %q", e.Tag)
		}
		seen[e.Tag] = true
	}
	return nil
}

// encodePluginsBlock renders a PluginsConfig for save when no
// raw JSON was captured: entries in order, tag/type first, then
// the fragment keys in their stored order. The returned values
// are *orderedObject so the save encoder preserves key order.
func encodePluginsBlock(cfg *PluginsConfig) ([]any, error) {
	arr := make([]any, 0, len(cfg.Entries))
	for _, e := range cfg.Entries {
		entry := newOrderedObject()
		entry.set("tag", e.Tag)
		entry.set("type", e.Type)
		if len(e.fragment) > 0 {
			v, err := decodeOrderedJSON(e.fragment)
			if err != nil {
				return nil, err
			}
			if fragObj, ok := v.(*orderedObject); ok {
				for _, k := range fragObj.keys {
					entry.set(k, fragObj.values[k])
				}
			}
		}
		arr = append(arr, entry)
	}
	return arr, nil
}
