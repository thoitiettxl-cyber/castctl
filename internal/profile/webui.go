// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

// The top-level `webui` config block and its resolution.
//
// Schema (exactly three keys; unknown keys are rejected, like every
// other strict section in this file):
//
//	{"listen": string, "token": string, "ui_dir": string}
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
//   - `ui_dir` (optional): a directory of static frontend files
//     served WITHOUT auth by `webui serve` instead of the embedded
//     frontend (see docs/config.md). A relative value resolves
//     against the config directory. It is NOT a secret: the
//     directory is public static content, and the value is never
//     redacted. It must never overlap the config directory (or
//     contain a cookies file): the static shell is unauthenticated,
//     so an overlapping `ui_dir` would serve config.json and
//     cookies to anyone on loopback with no token. The overlap
//     rule is enforced lexically at parse time (see
//     parseWebUIBlock), canonically at serve time (the command
//     layer resolves symlinks before serving), and again at API
//     save time (internal/webui saveGuarded, which also checks
//     cookies files). A present-but-broken `ui_dir` (missing,
//     not a directory, no regular index.html) fails `webui
//     serve` closed (exit 2) at the command layer; only an
//     absent key falls back to the embedded frontend.
//
// Resolution is pure (ResolveLogSettings / ResolveProfileDNS are
// the pattern): it reads only its input, never the filesystem,
// never mutates. The block references no other block, so there is
// no cross-reference validation beyond the listen rule and the
// lexical `ui_dir` overlap rule (which needs no filesystem
// access: symlink escapes are caught where the path is
// canonicalised, at serve time).

import (
	"net"
	"path/filepath"
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
	UIDir  string
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
// token, a non-loopback listen address, and a `ui_dir` overlapping
// the config directory are all config errors (exit 2). A supplied
// value is never echoed in an error: the token in particular must
// never appear in any error string, and the listen and `ui_dir`
// values are named only by their rule, never verbatim. The
// overlap check here is lexical only (both sides absolutized
// against the working directory, then Clean + Join, no
// filesystem access to the compared paths, keeping resolution
// pure): a `ui_dir` that reaches the config tree only through
// a symlink is caught at serve time, where the path is
// canonicalised before any file is served.
func parseWebUIBlock(v any, baseDir string) (*WebUIConfig, error) {
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
		case "ui_dir":
			s, ok := val.(string)
			if !ok {
				return nil, newConfigError(`"webui.ui_dir" must be a string`)
			}
			if strings.TrimSpace(s) == "" {
				return nil, newConfigError(`"webui.ui_dir" must not be empty`)
			}
			cfg.UIDir = strings.TrimSpace(s)
		default:
			return nil, newConfigErrorf("unknown webui config key %q", k)
		}
	}
	if cfg.UIDir != "" && baseDir != "" {
		resolved := cfg.UIDir
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(baseDir, resolved)
		}
		if DirOverlaps(baseDir, resolved) {
			return nil, newConfigError(`"webui.ui_dir" must not overlap the config directory`)
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

// ValidateWebUIListen is the exported form of
// validateWebUIListen for the command layer, which re-validates
// --listen/--port overrides before serving. The parse-time rule
// in validateWebUIListen is the authority; this wrapper only
// exposes it.
func ValidateWebUIListen(raw string) error { return validateWebUIListen(raw) }

// webUIListenError is a fixed-rule error: its text names only the
// rule, never the supplied listen value.
type webUIListenError struct{ rule string }

func (e *webUIListenError) Error() string { return e.rule }

// DirOverlaps reports whether candidate is equal to, inside, or
// an ancestor of dir. Both paths are absolutized against the
// working directory first — a relative config directory, as
// produced by a relative --config path, must compare correctly
// with an absolute candidate: filepath.Rel cannot mix a
// relative base with an absolute target and errors, which
// would fail closed for every absolute ui_dir. Absolutizing
// is lexical apart from reading the working directory; no
// filesystem access to the compared paths happens, so
// symlink-resolved forms must be compared by callers that
// canonicalise first (the command layer's resolveWebUIUIDir
// does). A sibling subtree of an ancestor (e.g. dir=/a/b,
// candidate=/a/c) does NOT overlap: dir is not inside
// candidate. An unresolvable Rel or absolutization fails
// closed (overlap).
func DirOverlaps(dir, candidate string) bool {
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return true
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return true
	}
	rel, err := filepath.Rel(dirAbs, candidateAbs)
	if err != nil {
		return true
	}
	if rel == "." {
		return true
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if parts[0] != ".." {
		return true
	}
	for _, part := range parts {
		if part != ".." {
			return false
		}
	}
	return true
}

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
// hand-built SingleConfig get the same refusal parse gives. The
// `ui_dir` overlap rule is NOT re-checked here: it needs the
// config directory, which this signature does not carry. Parse
// (ParseSingleConfig) enforces it lexically, and the command
// layer enforces it canonically (resolveWebUIUIDir) before any
// file is served, so no serve path bypasses it.
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
	if strings.TrimSpace(cfg.UIDir) != "" {
		entry.set("ui_dir", strings.TrimSpace(cfg.UIDir))
	}
	return entry, nil
}
