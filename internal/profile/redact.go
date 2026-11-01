// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"github.com/thoitiettxl-cyber/castctl/internal/redact"
)

// RedactJSON redacts every secret field in serialised JSON, operating
// on the decoded ordered value so field order is preserved, and
// re-encodes with indent 2. Secret values are replaced wholesale,
// whatever their JSON type (string, object, or array), by
// redact.Value; every other string value keeps everything except
// embedded URL userinfo. It never echoes secret values into errors.
func RedactJSON(data []byte) ([]byte, error) {
	v, err := decodeOrderedJSON(data)
	if err != nil {
		return nil, err
	}
	return encodeOrderedJSONIndent(redact.Value(v), 2)
}

// RedactOutboundJSON redacts one serialised outbound/endpoint object.
// The input must be a JSON object.
func RedactOutboundJSON(data []byte) ([]byte, error) {
	v, err := decodeOrderedJSON(data)
	if err != nil {
		return nil, err
	}
	if _, ok := v.(*orderedObject); !ok {
		return nil, newConfigError("outbound json must be an object")
	}
	return encodeOrderedJSONIndent(redact.Value(v), 2)
}

// RedactProfile renders a profile as redacted JSON (indent 2) for
// display: identity fields and paths are kept, the inline outbound is
// redacted, a tag reference is kept as a bare tag string, and a direct
// profile omits the outbound key. vm_id, node_id, and
// subscription_action_id are redacted by redact.Value (they are in
// its secret-key set): display output must never print them.
func RedactProfile(p *Profile) ([]byte, error) {
	if p == nil {
		return nil, newConfigError("cannot redact nil profile")
	}
	entry, err := buildProfileEntry(p)
	if err != nil {
		return nil, err
	}
	// Prepend the profile name for display; buildProfileEntry renders
	// the entry body only.
	out := newOrderedObject()
	if p.Name != "" {
		out.set("name", p.Name)
	}
	for _, k := range entry.keys {
		out.set(k, entry.values[k])
	}
	// Display always shows the recorded identity settings with
	// their effective values, even when the key is absent from the
	// file (buildProfileEntry omits absent keys so a save never
	// writes a default back). Neither value is a secret.
	// RedactConfig stays file-faithful and does not inject.
	if _, ok := out.get("fingerprint"); !ok {
		fp := p.Fingerprint
		if fp == "" {
			fp = DefaultFingerprint
		}
		out.set("fingerprint", fp)
	}
	if _, ok := out.get("tls_engine"); !ok {
		te := p.TLSEngine
		if te == "" {
			te = DefaultTLSEngine
		}
		out.set("tls_engine", te)
	}
	return encodeOrderedJSONIndent(redact.Value(out), 2)
}

// RedactConfig renders a whole SingleConfig as redacted JSON (indent 2).
// Plugin fragments are redacted wholesale by redactPluginsBlock
// (tag/type only, fragment as one <redacted> marker) before the
// generic key-based redaction runs.
func RedactConfig(cfg *SingleConfig) ([]byte, error) {
	if cfg == nil {
		return nil, newConfigError("cannot redact nil config")
	}
	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]*Profile)
	}
	root, err := buildSingleFileOrdered(cfg)
	if err != nil {
		return nil, err
	}
	redactPluginsBlock(root)
	return encodeOrderedJSONIndent(redact.Value(root), 2)
}

// redactPluginsBlock replaces every plugins entry's fragment with a
// single <redacted> marker: display shows tag/type only, plus a
// "config" key carrying the marker when the entry has any
// plugin-specific keys. Key-based redaction alone cannot do this:
// a fragment key that is not in redact's secret-key set could
// still carry a secret value under an unknown name, and the
// fragment's key names themselves are plugin-opaque. This
// operates on the built (copy) tree, never on the stored config.
func redactPluginsBlock(root *orderedObject) {
	if root == nil {
		return
	}
	v, ok := root.get("plugins")
	if !ok {
		return
	}
	arr, ok := v.([]any)
	if !ok {
		return
	}
	out := make([]any, 0, len(arr))
	for _, elem := range arr {
		entry, ok := elem.(*orderedObject)
		if !ok {
			out = append(out, elem)
			continue
		}
		shown := newOrderedObject()
		if tag, ok := entry.get("tag"); ok {
			shown.set("tag", tag)
		}
		if typ, ok := entry.get("type"); ok {
			shown.set("type", typ)
		}
		hasFragment := false
		for _, k := range entry.keys {
			if k != "tag" && k != "type" {
				hasFragment = true
				break
			}
		}
		if hasFragment {
			shown.set("config", redact.Marker)
		}
		out = append(out, shown)
	}
	root.set("plugins", out)
}

// The OrderedMap methods below let redact.Value redact
// *orderedObject values (including ones nested inside slices)
// without redact importing this package, which would be an import
// cycle: this package imports redact. They are pure accessors over
// the ordered object's keys and values; they change no other
// behaviour of the type. redact.Value builds its result into a
// fresh *orderedObject via NewOrderedMap, so redaction never
// mutates the decoded input.

// OrderedKeys returns the object's keys in insertion order.
func (o *orderedObject) OrderedKeys() []string {
	if o == nil {
		return nil
	}
	keys := make([]string, len(o.keys))
	copy(keys, o.keys)
	return keys
}

// OrderedGet returns the value stored under key.
func (o *orderedObject) OrderedGet(key string) (any, bool) {
	if o == nil {
		return nil, false
	}
	return o.get(key)
}

// OrderedSet stores value under key, appending the key to the order
// on first set.
func (o *orderedObject) OrderedSet(key string, value any) {
	if o == nil {
		return
	}
	o.set(key, value)
}

// NewOrderedMap returns an empty *orderedObject as a
// redact.OrderedMap.
func (o *orderedObject) NewOrderedMap() redact.OrderedMap {
	return newOrderedObject()
}
