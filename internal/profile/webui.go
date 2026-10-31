// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

// The top-level `webui` config block and its resolution.
//
// Schema (exactly two keys; unknown keys are rejected, like every
// other strict section in this file):
//
//	{"listen": string, "token": string}
//
// The block is optional. A nil *WebUIConfig on SingleConfig means
// the block was absent from the file, and the web UI is off: `webui
// serve` fails closed (exit 2). An absent block is preserved on
// save (defaults stay runtime-only, the same presence precedent
// as the `log` block).
//
//   - `listen` (optional): a host:port the server binds. It must be
//     a loopback address — a loopback IP (127.0.0.0/8 or ::1) or
//     `localhost` — with an explicit port 1-65535. Any other host
//     (0.0.0.0, ::, a non-loopback IP, a hostname), a missing port,
//     port 0, a URL, or userinfo is a config error (exit 2) that
//     never echoes the supplied value. Absent means
//     DefaultWebUIListen ("127.0.0.1:8317", the prior design
//     default, stated here and in docs/config.md — not a hidden
//     default). The server binds the resolved loopback address;
//     there is no non-loopback listen in this build.
//   - `token` (optional): the Bearer token for /api/v1. The token
//     itself is a secret: parse errors name the key only, and
//     RedactConfig redacts the "token" key wholesale
//     (internal/redact already carries "token" in its secret-key
//     set). A present-but-empty token is a config error: an empty
//     token must never mean "no auth". The runtime token source
//     precedence is CASTCTL_WEBUI_KEY (environment) over the block
//     token; when neither is set, `webui serve` fails closed and
//     never starts unauthenticated (that precedence lives in the
//     command layer, which owns environment reads; see
//     internal/commands/webui.go).
//
// Resolution is pure (ResolveLogSettings / ResolveProfileDNS are
// the pattern): it reads only its input, never the filesystem,
// never mutates. The block references no other block, so there is
// no cross-reference validation beyond the listen rule.

import (
	"net"
	"strconv"
	"strings"
)

// DefaultWebUIListen is the listen address when a `webui` block
// is present without a `listen` key: loopback only, port 8317
// (the prior design default, docs/config.md).
const DefaultWebUIListen = "127.0.0.1:8317"

// WebUIConfig is one parsed `webui` block. A nil *WebUIConfig on
// SingleConfig means the block was absent.
type WebUIConfig struct {
	Listen string
	Token  string
}

// RawWebUI returns a copy of the raw JSON captured for the `webui`
// block at parse time, or nil when no raw JSON was captured.
func (c *SingleConfig) RawWebUI() []byte {
	if c == nil || len(c.rawWebUI) == 0 {
		return nil
	}
	cp := make([]byte, len(c.rawWebUI))
	copy(cp, c.rawWebUI)
	return cp
}

// parseWebUIBlock parses one decoded `webui` value into a
// WebUIConfig. Wrong shapes, wrong types, unknown keys, an empty
// token, and a non-loopback listen address are all config errors
// (exit 2). A supplied value is never echoed in an error: the
// token in particular must never appear in any error string, and
// the listen value is named only by its rule, never verbatim.
func parseWebUIBlock(v any) (*WebUIConfig, error) {
	obj, ok := v.(*orderedObject)
	if !ok {
		return nil, newConfigError(`"webui" must be an object`)
	}
	cfg := &WebUIConfig{}
	for _, k := range obj.keys {
		val := obj.values[k]
		switch k {
		case "listen":
			s, ok := val.(string)
			if !ok {
				return nil, newConfigError(`"webui.listen" must be a string`)
			}
			if strings.TrimSpace(s) == "" {
				return nil, newConfigError(`"webui.listen" must not be empty`)
			}
			if err := validateWebUIListen(s); err != nil {
				return nil, newConfigErrorf(`"webui.listen" %v`, err)
			}
			cfg.Listen = strings.TrimSpace(s)
		case "token":
			s, ok := val.(string)
			if !ok {
				return nil, newConfigError(`"webui.token" must be a string`)
			}
			if strings.TrimSpace(s) == "" {
				return nil, newConfigError(`"webui.token" must not be empty`)
			}
			cfg.Token = s
		default:
			return nil, newConfigErrorf("unknown webui config key %q", k)
		}
	}
	return cfg, nil
}

// validateWebUIListen enforces the loopback-only listen rule. It
// names the rule violated, never the supplied value (the value
// sits next to a secret in the same block). The value must be a
// bare host:port — not a URL, carrying no userinfo, query, or
// fragment — with a loopback host and an explicit port 1-65535.
func validateWebUIListen(raw string) error {
	s := strings.TrimSpace(raw)
	if strings.Contains(s, "://") {
		return &webUIListenError{"must be a host:port, not a URL"}
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return &webUIListenError{"must be a host:port with an explicit port"}
	}
	if strings.ContainsAny(host, "@/?#") {
		return &webUIListenError{"must not carry userinfo, a path, a query, or a fragment"}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return &webUIListenError{"port out of range"}
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return &webUIListenError{"host must be loopback"}
		}
		return nil
	}
	if !strings.EqualFold(host, "localhost") {
		return &webUIListenError{"host must be loopback"}
	}
	return nil
}

// webUIListenError is a fixed-rule error: its text names only the
// rule, never the supplied listen value.
type webUIListenError struct{ rule string }

func (e *webUIListenError) Error() string { return e.rule }

// EffectiveListen returns the listen address a present `webui`
// block resolves to: the block's `listen` when set, otherwise
// DefaultWebUIListen. A nil config means the block was absent
// (feature off); callers must check presence before listening.
func EffectiveListen(cfg *WebUIConfig) string {
	if cfg != nil && strings.TrimSpace(cfg.Listen) != "" {
		return strings.TrimSpace(cfg.Listen)
	}
	return DefaultWebUIListen
}

// ResolveWebUI returns the parsed `webui` block, or nil when the
// block is absent (feature off) or there is no single config. It
// never reads the filesystem and never mutates its input. The
// listen rule is re-checked here so callers that receive a
// hand-built SingleConfig get the same refusal parse gives.
func ResolveWebUI(single *SingleConfig) (*WebUIConfig, error) {
	if single == nil || single.WebUI == nil {
		return nil, nil
	}
	if strings.TrimSpace(single.WebUI.Listen) != "" {
		if err := validateWebUIListen(single.WebUI.Listen); err != nil {
			return nil, newConfigErrorf(`"webui.listen" %v`, err)
		}
	}
	if single.WebUI.Token != "" && strings.TrimSpace(single.WebUI.Token) == "" {
		return nil, newConfigError(`"webui.token" must not be empty`)
	}
	return single.WebUI, nil
}

// encodeWebUIBlock renders a WebUIConfig for save when no raw JSON
// was captured: canonical key order, only the keys that were set.
// The returned value is an *orderedObject so the save encoder
// preserves key order. The token is written verbatim (the file is
// 0600 and the block is write-only at the API layer, never at
// the file layer: a save must round-trip the stored token).
func encodeWebUIBlock(cfg *WebUIConfig) (*orderedObject, error) {
	entry := newOrderedObject()
	if strings.TrimSpace(cfg.Listen) != "" {
		entry.set("listen", strings.TrimSpace(cfg.Listen))
	}
	if cfg.Token != "" {
		entry.set("token", cfg.Token)
	}
	return entry, nil
}
