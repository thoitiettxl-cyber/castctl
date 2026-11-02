// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
	"github.com/thoitiettxl-cyber/castctl/internal/redact"
)

// StrippedOutboundHash returns the sha256 hex of the canonical
// JSON of the outbound object with every secret field replaced
// wholesale by redact.Value (the same key set RedactConfig
// uses). Two outbound objects differing ONLY in secret values
// therefore hash identically: the plugin-facing identity is
// blind to secret rotation and carries no secret value. This
// deliberately differs from
// profile.OutboundIdentityForConfig, which hashes the RAW
// outbound JSON (and may therefore change when a secret
// rotates, and must never be handed to a plugin). The canonical
// form is encoding/json's map encoding (keys sorted), so key
// order in the input does not affect the hash.
// NewPluginIdentity builds the ONLY identity a plugin may
// receive: the outbound tag plus the secret-stripped hash.
// Changing a secret value in the outbound object does not
// change the hash (see TestPluginIdentitySecretBlind); the
// identity carries no secret value and is stable across
// secret rotation. Wiring must call this helper for every
// plugin-facing identity path; the raw hash helpers in
// internal/profile are not for plugin use.
func NewPluginIdentity(outboundTag string, outboundRawJSON []byte) (*pluginabi.Identity, error) {
	if outboundTag == "" {
		return nil, fmt.Errorf("plugin identity requires an outbound tag")
	}
	hash, err := StrippedOutboundHash(outboundRawJSON)
	if err != nil {
		return nil, err
	}
	return &pluginabi.Identity{OutboundTag: outboundTag, OutboundHash: hash}, nil
}

func StrippedOutboundHash(raw []byte) (string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("stripped outbound hash: invalid json: %w", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return "", fmt.Errorf("stripped outbound hash: outbound json must be an object")
	}
	canonical, err := json.Marshal(redact.Value(obj))
	if err != nil {
		return "", fmt.Errorf("stripped outbound hash: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
