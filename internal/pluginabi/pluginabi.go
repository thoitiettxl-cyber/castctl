// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package pluginabi defines the castctl plugin contract: the C ABI
// version, the JSON envelope exchanged across it, and the
// registration a plugin returns from plugin.register.
//
// The shape mirrors CLIProxyAPI's plugin ABI at pin 250d5981
// (sdk/pluginabi/types.go:7 ABIVersion=1, :36 SchemaVersion=10,
// Envelope/Error types, method-name constants, and
// internal/pluginhost/rpc_client.go:111-118 schema ceiling with
// missing-to-1), renamed into the castctl namespace and cut down
// to the v1 subset: castctl SchemaVersion starts at 1, the method
// list is the lifecycle subset plus the two v1 capability
// methods, and the host callback set is host.log only. Upstream's
// SchemaVersion 10, its ~30 capabilities, and its host.auth.* /
// host.http.* callbacks are deliberately NOT copied; see
// docs/plugins.md References for the per-file citation list and
// for what was not taken.
package pluginabi

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// ABIVersion tracks the native C ABI shape (native plugin
	// exports). It must match exactly: a plugin reporting any
	// other value is rejected, never adapted.
	ABIVersion uint32 = 1
	// SchemaVersion tracks the RPC JSON contract exchanged at
	// plugin.register. Castctl starts at 1; it is also the
	// ceiling: a plugin reporting a higher version is rejected.
	SchemaVersion uint32 = 1
)

// EntrySymbol is the single C entry symbol a plugin must export.
// It is the castctl rename of upstream's cliproxy_plugin_init
// (internal/pluginhost/loader_unix.go:130 at pin 250d5981).
const EntrySymbol = "castctl_plugin_init"

const (
	// MethodPluginRegister asks the plugin to register itself
	// with the host schema version and its config fragment.
	MethodPluginRegister = "plugin.register"
	// MethodPluginReconfigure re-registers an already-loaded
	// plugin with a new config fragment, same image.
	MethodPluginReconfigure = "plugin.reconfigure"
	// MethodPluginQuiesce asks the plugin to stop accepting new
	// work before it is replaced. A quiesce failure is logged,
	// never fatal.
	MethodPluginQuiesce = "plugin.quiesce"
	// MethodPluginShutdown asks the plugin to release its state.
	// The image is never unloaded.
	MethodPluginShutdown = "plugin.shutdown"
	// MethodProviderCall is the v1 Provider capability: one
	// opaque JSON request in, one opaque JSON result out.
	MethodProviderCall = "provider.call"
	// MethodCommandRegister asks a CommandProvider plugin to
	// list the commands it registers (via the registration
	// response; there is no separate init for commands).
	MethodCommandRegister = "command.register"
	// MethodCommandExecute runs one registered command.
	// Registration-only in this PR: commands are declared
	// in the registration response, but no castctl code
	// dispatches command.execute (no CLI command, no
	// scheduler calls it). Host.Call could invoke it
	// generically, but nothing in the repo does.
	MethodCommandExecute = "command.execute"
	// MethodHostLog is the ONLY reverse callback a plugin may
	// call into the host. Every other host.* method is rejected.
	MethodHostLog = "host.log"
)

// Envelope is the JSON value exchanged across the C ABI in both
// directions. It mirrors upstream's Envelope{OK, Result, Error}
// (sdk/pluginabi/types.go at pin 250d5981).
type Envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Error is the failure half of an Envelope. It carries a stable
// code and a redacted message only: a plugin never picks an exit
// code and must never return a raw server body. The host
// redacts/caps plugin-chosen error text before it reaches any
// output path; the plugin must not rely on the host to make a
// secret it embedded in a message safe.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Retryable is advisory only; the host decides retries.
	Retryable bool `json:"retryable,omitempty"`
}

// NewErrorEnvelope builds a failure envelope with the given code
// and message.
func NewErrorEnvelope(code, message string) Envelope {
	return Envelope{OK: false, Error: &Error{Code: code, Message: message}}
}

// Metadata identifies a plugin. Name, Version, and Author are
// required (mirroring upstream's validPlugin rule in
// internal/pluginhost/host.go:1241 at pin 250d5981); a plugin
// with an empty name, version, or author is rejected at
// registration.
type Metadata struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	Author           string `json:"author"`
	GitHubRepository string `json:"github_repository,omitempty"`
}

// Capabilities declares the optional integration points a plugin
// implements. V1 has exactly two; nil/absent means the plugin
// implements neither, which is rejected (a plugin must do
// something). This is the deliberate cut-down of upstream's
// ~30-bool rpcCapabilities
// (internal/pluginhost/rpc_schema.go:21-58 at pin 250d5981).
type Capabilities struct {
	// Provider is the opaque JSON-envelope capability.
	Provider bool `json:"provider,omitempty"`
	// CommandProvider registers commands via the contract.
	CommandProvider bool `json:"command_provider,omitempty"`
}

// Any reports whether at least one capability is declared.
func (c Capabilities) Any() bool { return c.Provider || c.CommandProvider }

// Command is one command a CommandProvider plugin registers.
type Command struct {
	Name  string `json:"name"`
	Usage string `json:"usage,omitempty"`
}

// Registration is the result of plugin.register /
// plugin.reconfigure.
type Registration struct {
	SchemaVersion uint32       `json:"schema_version"`
	Metadata      Metadata     `json:"metadata"`
	Capabilities  Capabilities `json:"capabilities"`
	Commands      []Command    `json:"commands,omitempty"`
	// CookieHosts declares the hosts the plugin needs the
	// egress proxy to inject the session cookie for (schema 1,
	// additive: absent means no hosts, hence no injection).
	// Core injects the cookie ONLY for these hosts; a plugin
	// that declares none never receives the cookie through
	// the proxy. Hosts are bare hostnames, no scheme, port,
	// path, or wildcard.
	CookieHosts []string `json:"cookie_hosts,omitempty"`
}

// Identity is the opaque, secret-stripped identity core hands a
// plugin: the profile outbound's tag plus the sha256 of its
// secret-stripped canonical JSON (see pluginhost.StrippedOutboundHash).
// It carries no secret value, no cookie, no key, and no path.
// Construct it only through pluginhost.NewPluginIdentity, which
// strips secrets internally; never hand a plugin the raw hash
// from profile.OutboundIdentityForConfig.
type Identity struct {
	OutboundTag  string `json:"outbound_tag"`
	OutboundHash string `json:"outbound_hash"`
}

// Egress describes the core-owned per-session loopback proxy a
// plugin must use for network traffic. The username/password are
// ephemeral, random, loopback-only credentials minted per
// session by core; they are never real proxy credentials and
// are useless outside the session.
type Egress struct {
	ProxyURL string `json:"proxy_url"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// RegisterRequest is the request core sends to plugin.register
// and plugin.reconfigure. ConfigJSON is the plugin's config
// fragment VERBATIM (the entry object minus tag/type): core
// never scrubs it, never adds secrets to it, and hands it as
// written in config.json. The fragment must never contain a
// secret: core's only protection for it is wholesale redaction
// on DISPLAY (tag/type only, fragment shown as <redacted>),
// never scrubbing on handoff. Identity and Egress are present
// only when the caller supplies them; a plugin must work when
// they are absent.
type RegisterRequest struct {
	ConfigJSON    json.RawMessage `json:"config_json"`
	SchemaVersion uint32          `json:"schema_version"`
	Tag           string          `json:"tag"`
	Type          string          `json:"type"`
	Identity      *Identity       `json:"identity,omitempty"`
	Egress        *Egress         `json:"egress,omitempty"`
}

// ValidateRegistration applies the schema gate and the metadata
// / capability rules to a registration response. A missing
// schema_version (0) is treated as the original contract, 1.
// A higher version is rejected with a clear error, never
// adapted. It returns the negotiated schema version.
//
// Rules enforced here (fail-closed): metadata name/version/
// author are required and must contain no control characters
// (they reach host output); at least one capability is
// required; commands are allowed only with the
// command_provider capability, and command names must be
// non-empty and control-free; cookie_hosts entries must be
// bare hostnames. Upstream's validPlugin additionally
// requires a non-empty GitHubRepository; castctl deliberately
// drops that requirement (first-party plugins need no
// repository URL) — the deviation is stated here and in
// docs/plugins.md.
func ValidateRegistration(reg Registration) (uint32, error) {
	if reg.SchemaVersion > SchemaVersion {
		return 0, fmt.Errorf("plugin schema version %d is not supported", reg.SchemaVersion)
	}
	schema := reg.SchemaVersion
	if schema == 0 {
		schema = 1
	}
	if reg.Metadata.Name == "" {
		return 0, fmt.Errorf("plugin metadata name is required")
	}
	if reg.Metadata.Version == "" {
		return 0, fmt.Errorf("plugin metadata version is required")
	}
	if reg.Metadata.Author == "" {
		return 0, fmt.Errorf("plugin metadata author is required")
	}
	for _, field := range []string{reg.Metadata.Name, reg.Metadata.Version, reg.Metadata.Author} {
		if strings.ContainsFunc(field, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return 0, fmt.Errorf("plugin metadata must not contain control characters")
		}
	}
	if !reg.Capabilities.Any() {
		return 0, fmt.Errorf("plugin declares no capabilities: at least one capability is required")
	}
	if len(reg.Commands) > 0 && !reg.Capabilities.CommandProvider {
		return 0, fmt.Errorf("plugin declares commands without the command_provider capability")
	}
	for _, cmd := range reg.Commands {
		if cmd.Name == "" {
			return 0, fmt.Errorf("plugin command name is required")
		}
		if strings.ContainsFunc(cmd.Name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return 0, fmt.Errorf("plugin command name must not contain control characters")
		}
	}
	for _, host := range reg.CookieHosts {
		if !ValidCookieHost(host) {
			return 0, fmt.Errorf("plugin cookie_hosts entry %q is not a bare hostname", host)
		}
	}
	return schema, nil
}

// ValidCookieHost reports whether host is a bare hostname
// usable in cookie_hosts: lowercase letters, digits, dots,
// and hyphens only, starting and ending with a letter or
// digit, at most 253 characters. No scheme, port, path,
// wildcard, or userinfo is allowed.
//
// Per-label rules (tightened): every dot-separated label is
// 1-63 characters and must not start or end with a hyphen,
// so `a..b` (empty label) and `a-.b` (label ending in a
// hyphen) are refused. Scope comparison is string-exact
// against the lowercased request hostname (see
// EgressProxy.cookieAllowed), so a refused shape can never
// widen injection: tightening only rejects declarations
// that could never have matched a real host.
func ValidCookieHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			default:
				return false
			}
		}
	}
	return true
}
