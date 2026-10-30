// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// SingleConfig is the parsed single-file config.json. Profiles are keyed
// by name; Outbounds/Endpoints/DNS hold sing-box's own parsed option
// types, with the original JSON preserved in raw* for faithful
// re-encoding on save.
type SingleConfig struct {
	DefaultProfile string
	Profiles       map[string]*Profile
	Outbounds      []option.Outbound
	Endpoints      []option.Endpoint
	DNS            *option.DNSOptions
	// WireGuardDNS is castctl-side (not sing-box) state: endpoint
	// tag -> DNS servers read by precedence branch (ii) in
	// ResolveProfileDNS. It is hand-written/preserved state,
	// stored under the top-level "wireguard_dns" key and
	// preserved verbatim on save like the other raw sections;
	// no production caller yet wires the
	// outbound.ParseWireGuardConfWithDNS capture into it
	// (import-path wiring is a follow-up).
	WireGuardDNS map[string][]string

	// Log is the top-level "log" block (nil when absent; see
	// internal/profile/log.go). Absence is preserved on save:
	// defaults are runtime-only and never written back.
	Log *LogConfig

	rawOutbounds    [][]byte
	rawEndpoints    [][]byte
	rawDNS          []byte
	rawWireGuardDNS []byte
	rawLog          []byte
	rawProfiles     map[string][]byte
}

// ProfileNames returns the profile names in sorted order.
func (c *SingleConfig) ProfileNames() []string {
	names := make([]string, 0, len(c.Profiles))
	for name := range c.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ParsedOutbounds re-parses the stored outbound JSON and returns fresh
// option.Outbound values.
func (c *SingleConfig) ParsedOutbounds() ([]option.Outbound, error) {
	out := make([]option.Outbound, 0, len(c.rawOutbounds))
	for _, raw := range c.rawOutbounds {
		ob, err := parseOutbound(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, ob)
	}
	if len(c.rawOutbounds) == 0 && len(c.Outbounds) > 0 {
		return append([]option.Outbound{}, c.Outbounds...), nil
	}
	return out, nil
}

// ParsedEndpoints re-parses the stored endpoint JSON and returns fresh
// option.Endpoint values.
func (c *SingleConfig) ParsedEndpoints() ([]option.Endpoint, error) {
	out := make([]option.Endpoint, 0, len(c.rawEndpoints))
	for _, raw := range c.rawEndpoints {
		ep, err := parseEndpoint(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	if len(c.rawEndpoints) == 0 && len(c.Endpoints) > 0 {
		return append([]option.Endpoint{}, c.Endpoints...), nil
	}
	return out, nil
}

// ParsedDNS re-parses the stored dns JSON, or returns nil when the file
// has no dns section.
func (c *SingleConfig) ParsedDNS() (*option.DNSOptions, error) {
	if len(c.rawDNS) == 0 {
		return c.DNS, nil
	}
	return parseDNS(c.rawDNS)
}

// RawOutbounds returns defensive copies of the stored outbound JSON.
func (c *SingleConfig) RawOutbounds() [][]byte { return copyRawList(c.rawOutbounds) }

// RawEndpoints returns defensive copies of the stored endpoint JSON.
func (c *SingleConfig) RawEndpoints() [][]byte { return copyRawList(c.rawEndpoints) }

// RawDNS returns a defensive copy of the stored dns JSON, or nil.
func (c *SingleConfig) RawDNS() []byte {
	if len(c.rawDNS) == 0 {
		return nil
	}
	out := make([]byte, len(c.rawDNS))
	copy(out, c.rawDNS)
	return out
}

// RawWireGuardDNS returns a defensive copy of the stored
// wireguard_dns JSON, or nil.
func (c *SingleConfig) RawWireGuardDNS() []byte {
	if len(c.rawWireGuardDNS) == 0 {
		return nil
	}
	out := make([]byte, len(c.rawWireGuardDNS))
	copy(out, c.rawWireGuardDNS)
	return out
}

func copyRawList(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, raw := range in {
		cp := make([]byte, len(raw))
		copy(cp, raw)
		out[i] = cp
	}
	return out
}

var singleTopLevelKeys = map[string]bool{
	"default_profile": true,
	"profiles":        true,
	"outbounds":       true,
	"endpoints":       true,
	"dns":             true,
	"wireguard_dns":   true,
	"log":             true,
}

var profileKeys = map[string]bool{
	"cookies_file":           true,
	"vm_id":                  true,
	"node_id":                true,
	"auto_approve":           true,
	"auto_allow_once":        true,
	"subscription_action_id": true,
	"fingerprint":            true,
	"tls_engine":             true,
	"outbound":               true,
	"dns":                    true,
}

// HasProfilesMarker reports whether data is a JSON object containing a
// "profiles" key (any value). A present-but-invalid "profiles" value
// still counts as the marker so callers surface a parse error instead
// of silently falling back. A file without the marker is a legacy
// flat config: LoadProfile refuses it (ErrLegacyLayout) and only
// Migrate reads it, deliberately, through the migrate-only parser.
func HasProfilesMarker(data []byte) (bool, error) {
	obj, err := decodeOrderedObject(data)
	if err != nil {
		return false, err
	}
	return obj.has("profiles"), nil
}

// ParseSingleConfig parses a single-file config.json. baseDir is used
// only to resolve relative cookies_file paths and to fill profile paths;
// no files are read. Cookies inline are rejected: a "cookies"/"cookie"
// key at the top level or directly in a profile entry is an error. (A
// "cookie" field inside a sing-box options object, e.g. OpenConnect
// endpoints, is legitimate and is NOT rejected; badjson strictness
// rejects any other unknown field inside option objects.)
func ParseSingleConfig(data []byte, baseDir string) (*SingleConfig, error) {
	obj, err := decodeOrderedObject(data)
	if err != nil {
		return nil, err
	}
	for _, k := range obj.keys {
		if k == "cookies" || k == "cookie" {
			return nil, newConfigError("cookies must stay in a separate cookies file, never inline in config.json")
		}
		if !singleTopLevelKeys[k] {
			return nil, newConfigErrorf("unknown top-level config key %q", k)
		}
	}
	cfg := &SingleConfig{
		Profiles:    make(map[string]*Profile),
		rawProfiles: make(map[string][]byte),
	}
	if v, ok := obj.get("default_profile"); ok {
		name, ok := v.(string)
		if !ok {
			return nil, newConfigError("default_profile must be a string")
		}
		if _, err := ValidateProfileName(name); err != nil {
			return nil, err
		}
		cfg.DefaultProfile = name
	}
	profilesVal, ok := obj.get("profiles")
	if !ok {
		return nil, newConfigError("single config requires a \"profiles\" object")
	}
	profilesObj, ok := profilesVal.(*orderedObject)
	if !ok {
		return nil, newConfigError("\"profiles\" must be an object")
	}

	// Outbounds and endpoints first: profiles may reference their tags.
	if v, ok := obj.get("outbounds"); ok {
		arr, ok := v.([]any)
		if !ok {
			return nil, newConfigError("\"outbounds\" must be an array")
		}
		for _, elem := range arr {
			raw, err := rawOf(elem)
			if err != nil {
				return nil, err
			}
			ob, err := parseOutbound(raw)
			if err != nil {
				return nil, err
			}
			if ob.Tag == "" {
				return nil, newConfigError("outbound in \"outbounds\" must have a tag")
			}
			cfg.Outbounds = append(cfg.Outbounds, ob)
			cfg.rawOutbounds = append(cfg.rawOutbounds, raw)
		}
	}
	if v, ok := obj.get("endpoints"); ok {
		arr, ok := v.([]any)
		if !ok {
			return nil, newConfigError("\"endpoints\" must be an array")
		}
		for _, elem := range arr {
			raw, err := rawOf(elem)
			if err != nil {
				return nil, err
			}
			ep, err := parseEndpoint(raw)
			if err != nil {
				return nil, err
			}
			if ep.Tag == "" {
				return nil, newConfigError("endpoint in \"endpoints\" must have a tag")
			}
			if wg, ok := ep.Options.(*option.WireGuardEndpointOptions); ok && wg.System {
				return nil, newConfigError("wireguard endpoint \"system\": true is not supported; use userspace wireguard only")
			}
			cfg.Endpoints = append(cfg.Endpoints, ep)
			cfg.rawEndpoints = append(cfg.rawEndpoints, raw)
		}
	}
	if v, ok := obj.get("dns"); ok {
		raw, err := rawOf(v)
		if err != nil {
			return nil, err
		}
		dns, err := parseDNS(raw)
		if err != nil {
			return nil, err
		}
		cfg.DNS = dns
		cfg.rawDNS = raw
	}
	if v, ok := obj.get("wireguard_dns"); ok {
		raw, err := rawOf(v)
		if err != nil {
			return nil, err
		}
		wgDNS, err := parseWireGuardDNSMap(v)
		if err != nil {
			return nil, err
		}
		cfg.WireGuardDNS = wgDNS
		cfg.rawWireGuardDNS = raw
	}
	if v, ok := obj.get("log"); ok {
		raw, err := rawOf(v)
		if err != nil {
			return nil, err
		}
		logCfg, err := parseLogBlock(v)
		if err != nil {
			return nil, err
		}
		cfg.Log = logCfg
		cfg.rawLog = raw
	}

	for _, name := range profilesObj.keys {
		if _, err := ValidateProfileName(name); err != nil {
			return nil, err
		}
		entryVal := profilesObj.values[name]
		entryObj, ok := entryVal.(*orderedObject)
		if !ok {
			return nil, newConfigErrorf("profile %q must be an object", name)
		}
		raw, err := rawOf(entryVal)
		if err != nil {
			return nil, err
		}
		p, err := parseProfileEntry(name, entryObj, baseDir)
		if err != nil {
			return nil, err
		}
		cfg.Profiles[name] = p
		cfg.rawProfiles[name] = raw
	}

	if err := validateTagGraph(cfg); err != nil {
		return nil, err
	}
	// G1 coexistence: a profile dns block and a top-level dns
	// section together are an error, never a silent shadowing.
	if cfg.DNS != nil {
		for _, name := range cfg.ProfileNames() {
			if p := cfg.Profiles[name]; p != nil && p.dnsPresent {
				return nil, newConfigErrorf("profile %q has a per-profile dns block and the file has a top-level dns section: remove the top-level dns section (distribute it into profile entries by hand first, see docs/config.md)", name)
			}
		}
	}
	if err := validateProfileDNS(cfg); err != nil {
		return nil, err
	}
	if err := validateWireGuardDNS(cfg); err != nil {
		return nil, err
	}
	if err := validateWireGuardPrivateKeys(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseProfileEntry parses one profile entry object. The outbound object,
// when present, is parsed through sing-box and auto-tagged
// "profile:<name>" when its tag is absent.
func parseProfileEntry(name string, obj *orderedObject, baseDir string) (*Profile, error) {
	for _, k := range obj.keys {
		if k == "cookies" || k == "cookie" {
			return nil, newConfigErrorf("profile %q: cookies must stay in a separate cookies file, never inline in config.json", name)
		}
		if !profileKeys[k] {
			return nil, newConfigErrorf("profile %q: unknown key %q", name, k)
		}
	}
	paths, err := ProfilePaths(baseDir, name)
	if err != nil {
		return nil, err
	}
	p := &Profile{
		Name:        name,
		Dir:         paths.Dir,
		ConfigFile:  filepath.Join(baseDir, "config.json"),
		CookiesFile: paths.Cookies,
		ChatFile:    paths.Chat,
		AutoApprove: "off",
		Fingerprint: DefaultFingerprint,
		TLSEngine:   DefaultTLSEngine,
		Source:      SourceSingle,
		ConfigFound: true,
		Outbound:    OutboundRef{Kind: OutboundDirect, Type: "direct"},
	}
	if v, ok := obj.get("cookies_file"); ok {
		s, ok := v.(string)
		if !ok {
			return nil, newConfigErrorf("profile %q: cookies_file must be a string", name)
		}
		p.CookiesFile = resolveCookiesFile(baseDir, paths, s, name != DefaultProfileName)
	}
	if v, ok := obj.get("vm_id"); ok {
		s, ok := v.(string)
		if !ok {
			return nil, newConfigErrorf("profile %q: vm_id must be a string", name)
		}
		p.VMID = s
		p.vmIDPresent = true
	}
	if v, ok := obj.get("node_id"); ok {
		s, ok := v.(string)
		if !ok {
			return nil, newConfigErrorf("profile %q: node_id must be a string", name)
		}
		p.NodeID = s
		p.nodeIDPresent = true
	}
	if v, ok := obj.get("auto_approve"); ok {
		s, ok := v.(string)
		if !ok {
			return nil, newConfigErrorf("profile %q: auto_approve must be a string", name)
		}
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "always":
			p.AutoApprove = "always"
		case "off":
			p.AutoApprove = "off"
		default:
			return nil, newConfigErrorf("profile %q: auto_approve must be \"always\" or \"off\"", name)
		}
	}
	if v, ok := obj.get("auto_allow_once"); ok {
		b, err := parseAutoAllowOnceValue(v)
		if err != nil {
			return nil, newConfigErrorf("profile %q: %v", name, err)
		}
		p.AutoAllowOnce = b
	}
	if v, ok := obj.get("subscription_action_id"); ok {
		s, ok := v.(string)
		if !ok {
			return nil, newConfigErrorf("profile %q: subscription_action_id must be a string", name)
		}
		p.SubscriptionActionID = s
	}
	if v, ok := obj.get("fingerprint"); ok {
		s, ok := v.(string)
		if !ok {
			return nil, newConfigErrorf("profile %q: fingerprint must be a string", name)
		}
		if err := validateFingerprintValue(s); err != nil {
			return nil, newConfigErrorf("profile %q: %v", name, err)
		}
		p.Fingerprint = s
		p.fingerprintPresent = true
	}
	if v, ok := obj.get("tls_engine"); ok {
		s, ok := v.(string)
		if !ok {
			return nil, newConfigErrorf("profile %q: tls_engine must be a string", name)
		}
		if err := validateTLSEngineValue(s); err != nil {
			return nil, newConfigErrorf("profile %q: %v", name, err)
		}
		p.TLSEngine = s
		p.tlsEnginePresent = true
	}
	if v, ok := obj.get("dns"); ok {
		raw, err := rawOf(v)
		if err != nil {
			return nil, err
		}
		dns, err := parseDNS(raw)
		if err != nil {
			return nil, newConfigErrorf("profile %q: %v", name, err)
		}
		p.DNS = dns
		p.rawDNS = raw
		p.dnsPresent = true
	}
	if v, ok := obj.get("outbound"); ok {
		switch t := v.(type) {
		case string:
			if strings.TrimSpace(t) == "" {
				return nil, newConfigErrorf("profile %q: outbound tag must not be empty", name)
			}
			// "direct" is the explicit direct form (CLIProxyAPI
			// idea 3): it is always direct, never a tag reference,
			// even if an outbound is tagged "direct". Any other
			// string is a tag reference resolved by
			// validateTagGraph; an invalid value is an error here,
			// never inherited from env or any other source.
			if t == "direct" {
				p.Outbound = OutboundRef{Kind: OutboundDirect, Type: "direct"}
			} else {
				p.Outbound = OutboundRef{Kind: OutboundTag, Tag: t}
			}
		case *orderedObject:
			// Auto-tag before parsing so the parsed object and the
			// stored raw JSON agree.
			tagged, tag, err := ensureInlineTag(t, "profile:"+name)
			if err != nil {
				return nil, err
			}
			raw := tagged
			ob, err := parseOutbound(raw)
			if err != nil {
				return nil, err
			}
			p.Outbound = OutboundRef{Kind: OutboundInline, Tag: ob.Tag, Type: ob.Type, Raw: raw, parsed: &ob}
			_ = tag
		default:
			return nil, newConfigErrorf("profile %q: outbound must be a tag string or an object", name)
		}
	}
	return p, nil
}

// ensureInlineTag returns the outbound object JSON with a tag set,
// inserting "tag" right after "type" when it was absent.
func ensureInlineTag(obj *orderedObject, autoTag string) ([]byte, string, error) {
	if v, ok := obj.get("tag"); ok {
		s, ok := v.(string)
		if !ok {
			return nil, "", newConfigError("outbound tag must be a string")
		}
		if strings.TrimSpace(s) == "" {
			return nil, "", newConfigError("outbound tag must not be empty")
		}
		raw, err := rawOf(obj)
		return raw, s, err
	}
	out := newOrderedObject()
	inserted := false
	for _, k := range obj.keys {
		out.set(k, obj.values[k])
		if k == "type" && !inserted {
			out.set("tag", autoTag)
			inserted = true
		}
	}
	if !inserted {
		// No "type" key (parse will reject it); put the tag first.
		withTag := newOrderedObject()
		withTag.set("tag", autoTag)
		for _, k := range obj.keys {
			withTag.set(k, obj.values[k])
		}
		out = withTag
	}
	raw, err := rawOf(out)
	return raw, autoTag, err
}

// parseAutoAllowOnceValue accepts a bool or an on/off word, mirroring
// Python's auto_allow_once_setting config handling.
func parseAutoAllowOnceValue(v any) (bool, error) {
	if b, ok := v.(bool); ok {
		return b, nil
	}
	if s, ok := v.(string); ok {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "on", "1", "true", "yes", "always":
			return true, nil
		case "off", "0", "false", "no", "never", "":
			return false, nil
		}
		return false, fmt.Errorf("auto_allow_once must be a boolean or an on/off word")
	}
	return false, fmt.Errorf("auto_allow_once must be a boolean or an on/off word")
}

// validateTagGraph enforces one tag namespace across outbounds,
// endpoints, and inline profile outbounds; resolves tag references and
// detour/selector references; and rejects dangling references.
// It also enforces the synthesised-direct reservation: any config
// tag carrying the castctl-direct: prefix is rejected here, so the
// reservation holds on every path that validates (parse and the
// profile-mutation commands), not just on the parse path.
func validateTagGraph(cfg *SingleConfig) error {
	reserve := func(tag, kind string) error {
		if IsReservedSynthesizedTag(tag) {
			return newConfigErrorf("tag %q (%s) is reserved for castctl's synthesised direct outbounds (castctl-direct:<profile>); rename the tag", tag, kind)
		}
		return nil
	}
	for _, ob := range cfg.Outbounds {
		if err := reserve(ob.Tag, "outbound"); err != nil {
			return err
		}
	}
	for _, ep := range cfg.Endpoints {
		if err := reserve(ep.Tag, "endpoint"); err != nil {
			return err
		}
	}
	for name, p := range cfg.Profiles {
		if p.Outbound.Kind == OutboundInline {
			if err := reserve(p.Outbound.Tag, "inline outbound for profile "+name); err != nil {
				return err
			}
		}
	}
	tags := make(map[string]string) // tag -> "outbound" | "endpoint" | "inline"
	for _, ob := range cfg.Outbounds {
		if prev, dup := tags[ob.Tag]; dup {
			return newConfigErrorf("duplicate outbound tag %q (already %s)", ob.Tag, prev)
		}
		tags[ob.Tag] = "outbound"
	}
	for _, ep := range cfg.Endpoints {
		if prev, dup := tags[ep.Tag]; dup {
			return newConfigErrorf("duplicate tag %q (already %s)", ep.Tag, prev)
		}
		tags[ep.Tag] = "endpoint"
	}
	for name, p := range cfg.Profiles {
		if p.Outbound.Kind == OutboundInline {
			if prev, dup := tags[p.Outbound.Tag]; dup {
				return newConfigErrorf("duplicate tag %q for profile %q (already %s)", p.Outbound.Tag, name, prev)
			}
			tags[p.Outbound.Tag] = "inline"
		}
	}
	require := func(tag, what string) error {
		if _, ok := tags[tag]; !ok {
			return newConfigErrorf("dangling reference: %s %q does not exist", what, tag)
		}
		return nil
	}
	for name, p := range cfg.Profiles {
		if p.Outbound.Kind == OutboundTag {
			from, ok := tags[p.Outbound.Tag]
			if !ok {
				return newConfigErrorf("profile %q: outbound tag %q does not exist", name, p.Outbound.Tag)
			}
			p.Outbound.From = from
			// Resolve the referenced type.
			for _, ob := range cfg.Outbounds {
				if ob.Tag == p.Outbound.Tag {
					p.Outbound.Type = ob.Type
				}
			}
			for _, ep := range cfg.Endpoints {
				if ep.Tag == p.Outbound.Tag {
					p.Outbound.Type = ep.Type
				}
			}
		}
	}
	for _, ob := range cfg.Outbounds {
		if d := detourOf(ob.Options); d != "" {
			if err := require(d, "detour"); err != nil {
				return newConfigErrorf("outbound %q: %v", ob.Tag, err)
			}
		}
		for _, ref := range referencedTags(ob) {
			if err := require(ref, "outbound"); err != nil {
				return newConfigErrorf("outbound %q: %v", ob.Tag, err)
			}
		}
	}
	for _, ep := range cfg.Endpoints {
		if d := detourOf(ep.Options); d != "" {
			if err := require(d, "detour"); err != nil {
				return newConfigErrorf("endpoint %q: %v", ep.Tag, err)
			}
		}
	}
	if cfg.DNS != nil {
		serverTags := make(map[string]bool)
		for _, srv := range cfg.DNS.Servers {
			serverTags[srv.Tag] = true
			if d := detourOf(srv.Options); d != "" {
				if err := require(d, "detour"); err != nil {
					return newConfigErrorf("dns server %q: %v", srv.Tag, err)
				}
			}
		}
		if cfg.DNS.Final != "" && !serverTags[cfg.DNS.Final] {
			return newConfigErrorf("dns final %q does not match any dns server tag", cfg.DNS.Final)
		}
	}
	return nil
}

// resolveCookiesFile resolves a cookies_file value: relative paths
// resolve under baseDir (delta rule); a named profile whose value points
// inside the base dir but at another profile's file is coerced to its
// own cookies file (cli.py:151-188). An empty value means the default.
func resolveCookiesFile(baseDir string, paths Paths, value string, named bool) string {
	if strings.TrimSpace(value) == "" {
		return paths.Cookies
	}
	resolved := value
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(baseDir, resolved)
	}
	resolved = filepath.Clean(resolved)
	if named && resolved != paths.Cookies && isInsideDir(resolved, baseDir) {
		return paths.Cookies
	}
	return resolved
}

func isInsideDir(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// readRegularFile reads path only after os.Stat confirms it is a
// regular file (following symlinks, like os.ReadFile): a FIFO,
// socket, or device at the path is an error naming the path without
// ever opening it, so a read can never block on a FIFO, and a
// directory is refused the same way. Callers keep their existing
// error wrapping (including the IsNotExist branches).
func readRegularFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		if st.IsDir() {
			return nil, fmt.Errorf("config path %q is a directory, not a file", path)
		}
		return nil, fmt.Errorf("config path %q is not a regular file", path)
	}
	return os.ReadFile(path)
}

// LoadSingleConfig loads the single-file config if baseDir/config.json
// exists and carries the "profiles" marker. It returns found=false when
// the file is absent or is a legacy flat config. A legacy-flat file is
// not an error here: LoadProfile refuses it (ErrLegacyLayout) and
// Migrate reads it deliberately. Callers must not treat found=false
// as "no config yet" without going through LoadProfile, or they
// would silently synthesise defaults over an unmigrated layout.
// An unparseable single file is an error, never a silent fallback.
func LoadSingleConfig(baseDir string) (*SingleConfig, bool, error) {
	path := filepath.Join(baseDir, "config.json")
	data, err := readRegularFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, newConfigErrorf("read config: %v", err)
	}
	marker, err := HasProfilesMarker(data)
	if err != nil {
		return nil, false, err
	}
	if !marker {
		return nil, false, nil
	}
	cfg, err := ParseSingleConfig(data, baseDir)
	if err != nil {
		return nil, false, err
	}
	return cfg, true, nil
}

// legacySettings is the flat per-profile config shape from cli.py.
// MIGRATE-ONLY: this type and parseLegacyConfig are input parsing
// for `config migrate` only. LoadProfile must never call them; it
// refuses a legacy file instead (ErrLegacyLayout).
// fingerprint/tls_engine are validated strictly in BOTH strict and
// non-strict modes (unlike the other settings, whose wrong-typed
// values are coerced when strict is false): an invalid recorded
// identity value is never silently reinterpreted.
type legacySettings struct {
	cookiesFile          string
	cookiesFilePresent   bool
	vmID                 string
	vmIDPresent          bool
	nodeID               string
	nodeIDPresent        bool
	autoApprove          string
	autoAllowOnce        bool
	subscriptionActionID string
	fingerprint          string
	fingerprintPresent   bool
	tlsEngine            string
	tlsEnginePresent     bool
}

// parseLegacyConfig parses a flat legacy config.json. MIGRATE-ONLY:
// the only caller is migrateLegacyProfile (via Migrate). When strict is
// true, wrong-typed settings are errors (used by Migrate, which must
// not silently reinterpret a corrupt file); when false, values are
// coerced the way Python's load_config effectively treats them.
func parseLegacyConfig(data []byte, strict bool) (*legacySettings, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, newConfigErrorf("parse legacy config: %v", err)
	}
	if _, ok := raw["profiles"]; ok {
		return nil, newConfigError("\"profiles\" key does not belong in a legacy per-profile config")
	}
	s := &legacySettings{autoApprove: "off"}
	getString := func(key string) (string, bool, error) {
		v, ok := raw[key]
		if !ok {
			return "", false, nil
		}
		var str string
		if err := json.Unmarshal(v, &str); err != nil {
			if strict {
				return "", false, newConfigErrorf("%s must be a string", key)
			}
			return "", false, nil
		}
		return str, true, nil
	}
	var err error
	if s.cookiesFile, s.cookiesFilePresent, err = getString("cookies_file"); err != nil {
		return nil, err
	}
	if s.vmID, s.vmIDPresent, err = getString("vm_id"); err != nil {
		return nil, err
	}
	if s.nodeID, s.nodeIDPresent, err = getString("node_id"); err != nil {
		return nil, err
	}
	if s.subscriptionActionID, _, err = getString("subscription_action_id"); err != nil {
		return nil, err
	}
	if v, ok := raw["fingerprint"]; ok {
		var str string
		if err := json.Unmarshal(v, &str); err != nil {
			return nil, newConfigError("fingerprint must be a string")
		}
		if err := validateFingerprintValue(str); err != nil {
			return nil, newConfigError(err.Error())
		}
		s.fingerprint, s.fingerprintPresent = str, true
	}
	if v, ok := raw["tls_engine"]; ok {
		var str string
		if err := json.Unmarshal(v, &str); err != nil {
			return nil, newConfigError("tls_engine must be a string")
		}
		if err := validateTLSEngineValue(str); err != nil {
			return nil, newConfigError(err.Error())
		}
		s.tlsEngine, s.tlsEnginePresent = str, true
	}
	if v, ok := raw["auto_approve"]; ok {
		var str string
		if err := json.Unmarshal(v, &str); err == nil {
			switch strings.ToLower(strings.TrimSpace(str)) {
			case "always":
				s.autoApprove = "always"
			default:
				s.autoApprove = "off"
			}
		} else if strict {
			return nil, newConfigError("auto_approve must be a string")
		} else {
			// Python: str(value) compared to "always"; a non-string
			// never equals it.
			s.autoApprove = "off"
		}
	}
	if v, ok := raw["auto_allow_once"]; ok {
		var b bool
		if err := json.Unmarshal(v, &b); err == nil {
			s.autoAllowOnce = b
		} else {
			var str string
			if err := json.Unmarshal(v, &str); err == nil {
				parsed, perr := parseAutoAllowOnceValue(str)
				if perr != nil {
					if strict {
						return nil, newConfigError("auto_allow_once must be a boolean or an on/off word")
					}
					s.autoAllowOnce = false
				} else {
					s.autoAllowOnce = parsed
				}
			} else if strict {
				return nil, newConfigError("auto_allow_once must be a boolean or an on/off word")
			}
		}
	}
	return s, nil
}

// applyLegacy builds a Profile from legacy settings for the given paths.
// MIGRATE-ONLY: the only caller is migrateLegacyProfile (via Migrate).
// LoadProfile never builds a profile from legacy settings.
func applyLegacy(name string, paths Paths, s *legacySettings, baseDir string) *Profile {
	p := &Profile{
		Name:                 name,
		Dir:                  paths.Dir,
		ConfigFile:           paths.Config,
		CookiesFile:          paths.Cookies,
		ChatFile:             paths.Chat,
		AutoApprove:          s.autoApprove,
		AutoAllowOnce:        s.autoAllowOnce,
		SubscriptionActionID: s.subscriptionActionID,
		Fingerprint:          DefaultFingerprint,
		TLSEngine:            DefaultTLSEngine,
		Source:               SourceLegacy,
		ConfigFound:          true,
		Outbound:             OutboundRef{Kind: OutboundDirect, Type: "direct"},
	}
	if s.cookiesFilePresent {
		p.CookiesFile = resolveCookiesFile(baseDir, paths, s.cookiesFile, name != DefaultProfileName)
	}
	if s.vmIDPresent {
		p.VMID = s.vmID
		p.vmIDPresent = true
	}
	if s.nodeIDPresent {
		p.NodeID = s.nodeID
		p.nodeIDPresent = true
	}
	if s.fingerprintPresent {
		p.Fingerprint = s.fingerprint
		p.fingerprintPresent = true
	}
	if s.tlsEnginePresent {
		p.TLSEngine = s.tlsEngine
		p.tlsEnginePresent = true
	}
	return p
}

// applyEnvFill fills vm_id/node_id from the environment only when the
// key was absent from the config file (cli.py:151-188). It never
// overrides a present key, and never writes anything.
func applyEnvFill(p *Profile, getenv func(string) (string, bool)) {
	if getenv == nil {
		return
	}
	if !p.vmIDPresent {
		if v, ok := getenv("MUSE_VM_ID"); ok && v != "" {
			p.VMID = v
		}
	}
	if !p.nodeIDPresent {
		if v, ok := getenv("MUSE_NODE_ID"); ok && v != "" {
			p.NodeID = v
		}
	}
}

// configPathExists reports whether path exists and is not a
// directory. It uses os.Stat deliberately: Stat follows symlinks
// (like the os.ReadFile it replaces for existence checks) but never
// opens the file, so a FIFO at the path cannot hang the check, and
// only existence and type are observed — never contents.
func configPathExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// strayDefaultLegacyPath is profiles/default/config.json: the
// default profile's stray legacy file. The default profile's own
// config path is the base config.json, so this file is never the
// default profile's own file — it is a legacy file for every
// purpose (refusal scan, LoadProfile default check, migrate
// discovery) and must never be skipped as "the default entry".
// DiscoverProfileNames skips a directory named "default" under
// profiles/, so this path is invisible to directory discovery and
// is checked explicitly wherever legacy files are scanned.
func strayDefaultLegacyPath(baseDir string) string {
	return filepath.Join(baseDir, "profiles", DefaultProfileName, "config.json")
}

// scanLegacyConfigFile returns the first legacy config file in
// baseDir: the flat base config.json (only when includeBase — the
// base file IS the single file when one was found, and must not
// count then), then profiles/default/config.json, then any
// profiles/<name>/config.json in sorted profile-name order,
// skipping exclude (the caller has already checked that name's own
// file). It uses os.Stat only: no file is opened, so a FIFO cannot
// hang the scan, and a bare directory (no config file) never
// counts. It reports ("", false, nil) when no legacy config file
// exists.
func scanLegacyConfigFile(baseDir, exclude string, includeBase bool) (string, bool, error) {
	if includeBase {
		basePath := filepath.Join(baseDir, "config.json")
		if configPathExists(basePath) {
			return basePath, true, nil
		}
	}
	if stray := strayDefaultLegacyPath(baseDir); configPathExists(stray) {
		return stray, true, nil
	}
	names, err := DiscoverProfileNames(baseDir)
	if err != nil {
		return "", false, err
	}
	for _, name := range names {
		if name == DefaultProfileName || name == exclude {
			continue
		}
		paths, err := ProfilePaths(baseDir, name)
		if err != nil {
			continue
		}
		if configPathExists(paths.Config) {
			return paths.Config, true, nil
		}
	}
	return "", false, nil
}

// findLegacyConfigFile returns the first legacy config file in
// baseDir, including the flat base config.json. See
// scanLegacyConfigFile.
func findLegacyConfigFile(baseDir, exclude string) (string, bool, error) {
	return scanLegacyConfigFile(baseDir, exclude, true)
}

// LoadProfile loads one profile's settings. It is strictly read-only:
// it creates no files and never generates a node_id (see the package
// doc). Precedence: a single-file entry wins wholly (never per-key
// merge). A name with no single-file entry is REFUSED with
// ErrLegacyLayout naming `castctl config migrate --write` and the
// legacy file path when ANY legacy config file exists anywhere in
// the layout: the name's own file, another profile's file, the flat
// base file (when no single file exists), or
// profiles/default/config.json. The refusal is layout-wide: it
// fires for ghost names with no file of their own, and it fires
// even when a single file exists (the base file is the single file
// then, so it does not itself count — named files and the stray
// default file still do). LoadProfile itself refuses; the CLI
// existence/identity guards (profileExists, refuseUnmigrated) only
// add write-path and explicit-name checks on top. A name with no
// entry anywhere, in a layout with no legacy file at all,
// synthesises defaults (SourceNone). An unparseable single file is
// an error with no silent fallback. Migrate is the only path that
// reads legacy files.
func LoadProfile(baseDir, name string, getenv func(string) (string, bool)) (*Profile, error) {
	paths, err := ProfilePaths(baseDir, name)
	if err != nil {
		return nil, err
	}
	single, found, err := LoadSingleConfig(baseDir)
	if err != nil {
		return nil, err
	}
	var p *Profile
	if found {
		if entry, ok := single.Profiles[name]; ok {
			p = entry.clone()
		}
	}
	if p == nil {
		// The base config.json is the single file when one was found;
		// the default profile has no separate legacy file in that
		// case, so the own-file check is skipped for it — but the
		// layout-wide scan below still runs, so leftover named
		// legacy files refuse even the default name.
		// Otherwise, an existing per-profile config file is an
		// unmigrated legacy file: refuse it (ErrLegacyLayout) instead
		// of reading it. The file's contents are never parsed here;
		// only its existence is checked, and only its path is named.
		// Existence is checked with os.Stat, not os.ReadFile: opening
		// a FIFO to read it would hang. A directory at the path is
		// a config error, not a legacy layout.
		if !(found && name == DefaultProfileName) {
			if st, serr := os.Stat(paths.Config); serr == nil {
				if st.IsDir() {
					return nil, newConfigErrorf("config path %q is a directory, not a file", paths.Config)
				}
				return nil, newLegacyLayoutError(paths.Config)
			} else if !os.IsNotExist(serr) {
				return nil, newConfigErrorf("read config: %v", serr)
			}
		}
		// Layout-wide refusal: when the name has no single-file
		// entry, ANY legacy config file anywhere in the layout
		// refuses the name — including a ghost name with no file
		// of its own, and including when a single file exists
		// (the base file is excluded from the scan then, since it
		// IS the single file; named files and
		// profiles/default/config.json still count). Only a layout
		// with no legacy file at all synthesises SourceNone
		// defaults below.
		legacyPath, ok, ferr := scanLegacyConfigFile(baseDir, name, !found)
		if ferr != nil {
			return nil, ferr
		}
		if ok {
			return nil, newLegacyLayoutError(legacyPath)
		}
	}
	if p == nil {
		p = &Profile{
			Name:        name,
			Dir:         paths.Dir,
			ConfigFile:  paths.Config,
			CookiesFile: paths.Cookies,
			ChatFile:    paths.Chat,
			AutoApprove: "off",
			Fingerprint: DefaultFingerprint,
			TLSEngine:   DefaultTLSEngine,
			Source:      SourceNone,
			Outbound:    OutboundRef{Kind: OutboundDirect, Type: "direct"},
		}
	}
	if st, serr := os.Stat(paths.Dir); serr == nil && st.IsDir() {
		p.Exists = true
	}
	applyEnvFill(p, getenv)
	return p, nil
}

// LoadProfileWithEnv is LoadProfile using the process environment.
func LoadProfileWithEnv(baseDir, name string) (*Profile, error) {
	return LoadProfile(baseDir, name, os.LookupEnv)
}

// ResolveActiveProfile resolves the active profile: --profile flag >
// CASTCTL_PROFILE > default_profile (single file) > "default". A
// default_profile naming a profile that exists nowhere is an error; an
// explicit flag or env name bypasses default_profile entirely.
func ResolveActiveProfile(baseDir string, flag *string, getenv func(string) (string, bool)) (*Profile, error) {
	if flag != nil {
		name, err := ResolveProfileName(flag, getenv)
		if err != nil {
			return nil, err
		}
		return LoadProfile(baseDir, name, getenv)
	}
	if getenv != nil {
		if env, ok := getenv(ProfileEnv); ok && strings.TrimSpace(env) != "" {
			name, err := ValidateProfileName(strings.TrimSpace(env))
			if err != nil {
				return nil, err
			}
			return LoadProfile(baseDir, name, getenv)
		}
	}
	single, found, err := LoadSingleConfig(baseDir)
	if err != nil {
		return nil, err
	}
	if found && single.DefaultProfile != "" {
		name := single.DefaultProfile
		if !profileExists(baseDir, name, single) {
			return nil, newConfigErrorf("default_profile %q does not exist", name)
		}
		return LoadProfile(baseDir, name, getenv)
	}
	return LoadProfile(baseDir, DefaultProfileName, getenv)
}

// profileExists reports whether name exists as a single-file entry,
// a per-profile config file, or a profile directory. A bare
// directory with no config file counts as existence (kept
// deliberately: the directory is the profile's home for cookies,
// chat, and telegram files, and LoadProfile synthesises SourceNone
// defaults for it). A legacy config file counts too — but only as
// existence: LoadProfile still refuses to read it.
func profileExists(baseDir, name string, single *SingleConfig) bool {
	if single != nil {
		if _, ok := single.Profiles[name]; ok {
			return true
		}
	}
	paths, err := ProfilePaths(baseDir, name)
	if err != nil {
		return false
	}
	if _, err := os.Stat(paths.Config); err == nil {
		return true
	}
	if st, err := os.Stat(paths.Dir); err == nil && st.IsDir() {
		return true
	}
	return false
}

// buildSingleFileOrdered renders a SingleConfig as an ordered JSON
// value with keys in the delta order: default_profile, profiles
// (sorted), outbounds, endpoints, dns.
func buildSingleFileOrdered(cfg *SingleConfig) (*orderedObject, error) {
	root := newOrderedObject()
	if cfg.DefaultProfile != "" {
		root.set("default_profile", cfg.DefaultProfile)
	}
	profilesObj := newOrderedObject()
	for _, name := range cfg.ProfileNames() {
		p := cfg.Profiles[name]
		entry, err := buildProfileEntry(p)
		if err != nil {
			return nil, err
		}
		profilesObj.set(name, entry)
	}
	root.set("profiles", profilesObj)
	if len(cfg.rawOutbounds) > 0 {
		arr, err := decodeRawList(cfg.rawOutbounds)
		if err != nil {
			return nil, err
		}
		root.set("outbounds", arr)
	} else if len(cfg.Outbounds) > 0 {
		arr := make([]any, 0, len(cfg.Outbounds))
		for i := range cfg.Outbounds {
			raw, err := marshalSing(&cfg.Outbounds[i])
			if err != nil {
				return nil, err
			}
			v, err := decodeOrderedJSON(raw)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		root.set("outbounds", arr)
	}
	if len(cfg.rawEndpoints) > 0 {
		arr, err := decodeRawList(cfg.rawEndpoints)
		if err != nil {
			return nil, err
		}
		root.set("endpoints", arr)
	} else if len(cfg.Endpoints) > 0 {
		arr := make([]any, 0, len(cfg.Endpoints))
		for i := range cfg.Endpoints {
			raw, err := marshalSing(&cfg.Endpoints[i])
			if err != nil {
				return nil, err
			}
			v, err := decodeOrderedJSON(raw)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		root.set("endpoints", arr)
	}
	if len(cfg.rawDNS) > 0 {
		v, err := decodeOrderedJSON(cfg.rawDNS)
		if err != nil {
			return nil, err
		}
		root.set("dns", v)
	} else if cfg.DNS != nil {
		raw, err := marshalSing(cfg.DNS)
		if err != nil {
			return nil, err
		}
		v, err := decodeOrderedJSON(raw)
		if err != nil {
			return nil, err
		}
		root.set("dns", v)
	}
	if len(cfg.rawWireGuardDNS) > 0 {
		v, err := decodeOrderedJSON(cfg.rawWireGuardDNS)
		if err != nil {
			return nil, err
		}
		root.set("wireguard_dns", v)
	} else if len(cfg.WireGuardDNS) > 0 {
		raw, err := json.Marshal(cfg.WireGuardDNS)
		if err != nil {
			return nil, err
		}
		v, err := decodeOrderedJSON(raw)
		if err != nil {
			return nil, err
		}
		root.set("wireguard_dns", v)
	}
	if len(cfg.rawLog) > 0 {
		v, err := decodeOrderedJSON(cfg.rawLog)
		if err != nil {
			return nil, err
		}
		root.set("log", v)
	} else if cfg.Log != nil {
		entry := newOrderedObject()
		entry.set("disabled", cfg.Log.Disabled)
		entry.set("level", cfg.Log.Level)
		entry.set("output", cfg.Log.Output)
		entry.set("timestamp", cfg.Log.Timestamp)
		root.set("log", entry)
	}
	return root, nil
}

func decodeRawList(raws [][]byte) ([]any, error) {
	arr := make([]any, 0, len(raws))
	for _, raw := range raws {
		v, err := decodeOrderedJSON(raw)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
	}
	return arr, nil
}

// buildProfileEntry renders one profile entry: cookies_file is always
// written (resolved), auto_approve/auto_allow_once always written,
// optional identifiers only when non-empty, outbound as an inline
// object, a tag string, or omitted for direct. fingerprint and
// tls_engine are written only when the key was present in the file
// the profile was loaded from, or when the loaded value differs
// from the default: an absent key stays absent (its effective value
// is the default) so a save never writes a default back into a file
// that did not carry the key. RedactProfile injects the effective
// values for display; see redact.go.
func buildProfileEntry(p *Profile) (*orderedObject, error) {
	entry := newOrderedObject()
	entry.set("cookies_file", p.CookiesFile)
	if p.VMID != "" {
		entry.set("vm_id", p.VMID)
	}
	if p.NodeID != "" {
		entry.set("node_id", p.NodeID)
	}
	autoApprove := "off"
	if strings.ToLower(strings.TrimSpace(p.AutoApprove)) == "always" {
		autoApprove = "always"
	}
	entry.set("auto_approve", autoApprove)
	entry.set("auto_allow_once", p.AutoAllowOnce)
	if p.SubscriptionActionID != "" {
		entry.set("subscription_action_id", p.SubscriptionActionID)
	}
	fp := p.Fingerprint
	if fp == "" {
		fp = DefaultFingerprint
	}
	if p.fingerprintPresent || fp != DefaultFingerprint {
		entry.set("fingerprint", fp)
	}
	te := p.TLSEngine
	if te == "" {
		te = DefaultTLSEngine
	}
	if p.tlsEnginePresent || te != DefaultTLSEngine {
		entry.set("tls_engine", te)
	}
	// Per-profile dns, presence-gated like fingerprint/tls_engine:
	// an absent key stays absent (the runtime synthesises the
	// default instead of writing it back), and a present key is
	// preserved verbatim from its raw JSON.
	if p.dnsPresent {
		if len(p.rawDNS) > 0 {
			v, err := decodeOrderedJSON(p.rawDNS)
			if err != nil {
				return nil, err
			}
			entry.set("dns", v)
		} else if p.DNS != nil {
			raw, err := marshalSing(p.DNS)
			if err != nil {
				return nil, err
			}
			v, err := decodeOrderedJSON(raw)
			if err != nil {
				return nil, err
			}
			entry.set("dns", v)
		}
	}
	switch p.Outbound.Kind {
	case OutboundTag:
		if p.Outbound.Tag != "" {
			entry.set("outbound", p.Outbound.Tag)
		}
	case OutboundInline:
		raw := p.Outbound.RawJSON()
		if len(raw) == 0 && p.Outbound.parsed != nil {
			var err error
			raw, err = marshalSing(p.Outbound.parsed)
			if err != nil {
				return nil, err
			}
		}
		if len(raw) > 0 {
			v, err := decodeOrderedJSON(raw)
			if err != nil {
				return nil, err
			}
			entry.set("outbound", v)
		}
	case OutboundDirect:
		// No outbound key means direct; omit.
	}
	return entry, nil
}

// SaveSingleConfig writes cfg to baseDir/config.json atomically
// (temp file in the same directory + rename), mode 0600, JSON indent 2.
// It creates the base directory if needed. It takes the config lock
// (see guard.go) but does NOT check the file's hash: callers that
// loaded the config first must use ConfigState.Save or
// UpdateSingleConfig instead, so a concurrent change is refused
// rather than overwritten.
func SaveSingleConfig(baseDir string, cfg *SingleConfig) error {
	if cfg == nil {
		return newConfigError("cannot save nil config")
	}
	release, err := lockConfigDir(baseDir)
	if err != nil {
		return err
	}
	defer release()
	_, err = writeSingleConfigLocked(baseDir, cfg)
	return err
}

// writeTempFile writes data to a new temp file in dir (mode perm, set
// before writing) and syncs it. The caller owns the returned name and
// must remove or rename it.
func writeTempFile(dir string, data []byte, perm os.FileMode) (string, error) {
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	fail := func(err error) (string, error) {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Chmod(perm); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	return tmpName, nil
}

// writeFileAtomic writes data to a temp file in the same directory
// (mode perm, set before writing) and renames it over path.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmpName, err := writeTempFile(dir, data, perm)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmpName) }()
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}
