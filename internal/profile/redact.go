// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/redact"
)

// secretKeys are JSON field names whose values are replaced with
// "<redacted>" by RedactJSON/RedactProfile/RedactOutboundJSON. The list
// is the delta's show-serialisation list (password, private_key,
// public_key, pre_shared_key, uuid, short_id, token, certificate, key,
// obfs, users[].password — the last via the generic walk), plus
// "secret" and "cookie": sing-box option objects carry those names for
// genuinely secret material (OpenConnect token secret, OpenConnect
// session cookie), and redacting them can only hide auth material,
// never config structure. The profile identifiers vm_id, node_id, and
// subscription_action_id are ALSO redacted here: display output must
// never print them (review finding B1). The remaining names cover
// secret fields in the sing-box 1.14.4 schema that the delta list
// missed: snell "psk", ssh "private_key_passphrase", hysteria
// "auth"/"auth_str", tailscale "auth_key", openvpn "auth".
var secretKeys = map[string]bool{
	"password":               true,
	"private_key":            true,
	"public_key":             true,
	"pre_shared_key":         true,
	"uuid":                   true,
	"short_id":               true,
	"token":                  true,
	"certificate":            true,
	"key":                    true,
	"obfs":                   true,
	"secret":                 true,
	"cookie":                 true,
	"vm_id":                  true,
	"node_id":                true,
	"subscription_action_id": true,
	"psk":                    true,
	"private_key_passphrase": true,
	"auth":                   true,
	"auth_str":               true,
	"auth_key":               true,
}

const redactedMarker = "<redacted>"

// RedactJSON redacts every secret field in serialised JSON, operating
// on the decoded ordered value so field order is preserved, and
// re-encodes with indent 2. Secret values are replaced wholesale,
// whatever their JSON type (string, object, or array). It never echoes
// secret values into errors.
func RedactJSON(data []byte) ([]byte, error) {
	v, err := decodeOrderedJSON(data)
	if err != nil {
		return nil, err
	}
	return encodeOrderedJSONIndent(redactValue(v), 2)
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
	return encodeOrderedJSONIndent(redactValue(v), 2)
}

func redactValue(v any) any {
	switch t := v.(type) {
	case *orderedObject:
		out := newOrderedObject()
		for _, k := range t.keys {
			if secretKeys[k] {
				out.set(k, redactedMarker)
				continue
			}
			out.set(k, redactValue(t.values[k]))
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, elem := range t {
			out[i] = redactValue(elem)
		}
		return out
	case string:
		// Any string value, whatever its key, has URL userinfo
		// redacted by the shared string-level redactor. Key-based
		// redaction above is untouched: a secret-key value is
		// replaced wholesale before reaching here, and a
		// non-secret string keeps everything except its URL
		// userinfo.
		return redact.RedactURLUserinfo(t)
	default:
		return v
	}
}

// RedactProfile renders a profile as redacted JSON (indent 2) for
// display: identity fields and paths are kept, the inline outbound is
// redacted, a tag reference is kept as a bare tag string, and a direct
// profile omits the outbound key. vm_id, node_id, and
// subscription_action_id are redacted (they are in secretKeys):
// display output must never print them.
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
	return encodeOrderedJSONIndent(redactValue(out), 2)
}

// RedactConfig renders a whole SingleConfig as redacted JSON (indent 2).
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
	return encodeOrderedJSONIndent(redactValue(root), 2)
}
