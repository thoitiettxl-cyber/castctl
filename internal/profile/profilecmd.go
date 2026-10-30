// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"os"
	"path/filepath"

	"github.com/sagernet/sing-box/option"
)

// Profile-command library API for Phase 2 (parsing/validation in
// this package, per the plan). The command layer (internal/commands)
// only parses flags/stdin and prints results; every write below goes
// through the flock+sha256 guard (see guard.go), so concurrent
// profile commands serialise and a stale read is refused rather
// than overwritten. None of these functions reads proxy environment
// variables, creates a cookies file, or touches telegram/update
// files. A legacy layout is never written back to: these functions
// only ever rewrite baseDir/config.json as a single file.

// AddProfileOptions are the options for AddProfile.
type AddProfileOptions struct {
	// CookiesFile overrides the default cookies file. "" means the
	// default (baseDir/cookies.txt for "default",
	// baseDir/profiles/<name>/cookies.txt otherwise). Relative
	// paths resolve under baseDir; the named-profile coercion from
	// ParseSingleConfig applies. No cookies file is created.
	CookiesFile string
	// OutboundTag selects the outbound: "" or "direct" means
	// direct; any other value must be a tag in the single file's
	// outbounds/endpoints, else AddProfile errors and writes
	// nothing. An outbound object from a file is applied with a
	// separate SetOutbound call after AddProfile.
	OutboundTag string
	// SetDefault makes the new profile the default_profile.
	SetDefault bool
	// Fingerprint records the client fingerprint preset name
	// (storage only; see fingerprint.go). "" means the default
	// ("chrome") with no key written. A non-empty value is
	// validated (exact match against SupportedFingerprints);
	// invalid → error, nothing written.
	Fingerprint string
	// TLSEngine records the TLS engine name (storage only; see
	// fingerprint.go). "" means the default ("utls") with no key
	// written. A non-empty value is validated (exact match
	// against SupportedTLSEngines); invalid → error, nothing
	// written.
	TLSEngine string
}

// AddProfile creates one entry in the single file: auto_approve off,
// auto_allow_once false, a fresh crypto/rand node_id, and the
// default cookies file. It creates NO cookies file and no profile
// directory, and performs no network access. It refuses (exit 2)
// when the name already exists in the single file, when a legacy
// profile with the same name exists (the single file would shadow
// it), and with a "run config migrate first" error when the old
// layout exists unmigrated and no single file exists yet. The
// returned profile is the created entry.
func AddProfile(baseDir, name string, opts AddProfileOptions) (*Profile, error) {
	if _, err := ValidateProfileName(name); err != nil {
		return nil, err
	}
	paths, err := ProfilePaths(baseDir, name)
	if err != nil {
		return nil, err
	}
	// Validate the recorded-identity parameters before touching
	// the filesystem: invalid values fail fast and write nothing.
	if opts.Fingerprint != "" {
		if err := validateFingerprintValue(opts.Fingerprint); err != nil {
			return nil, newConfigError(err.Error())
		}
	}
	if opts.TLSEngine != "" {
		if err := validateTLSEngineValue(opts.TLSEngine); err != nil {
			return nil, newConfigError(err.Error())
		}
	}
	if err := refuseUnmigrated(baseDir); err != nil {
		return nil, err
	}
	var created *Profile
	err = UpdateSingleConfig(baseDir, func(cfg *SingleConfig) error {
		if _, dup := cfg.Profiles[name]; dup {
			return newConfigErrorf("profile %q already exists", name)
		}
		if name != DefaultProfileName && legacyProfileExists(paths) {
			return newConfigErrorf("profile %q already exists in the old layout; run config migrate first", name)
		}
		nodeID, err := generateNodeID()
		if err != nil {
			return err
		}
		p := &Profile{
			Name:          name,
			Dir:           paths.Dir,
			ConfigFile:    filepath.Join(baseDir, "config.json"),
			CookiesFile:   resolveCookiesFile(baseDir, paths, opts.CookiesFile, name != DefaultProfileName),
			ChatFile:      paths.Chat,
			NodeID:        nodeID,
			AutoApprove:   "off",
			AutoAllowOnce: false,
			Fingerprint:   DefaultFingerprint,
			TLSEngine:     DefaultTLSEngine,
			Source:        SourceSingle,
			ConfigFound:   true,
			Outbound:      OutboundRef{Kind: OutboundDirect, Type: "direct"},
		}
		p.nodeIDPresent = true
		if opts.Fingerprint != "" {
			p.Fingerprint = opts.Fingerprint
			p.fingerprintPresent = true
		}
		if opts.TLSEngine != "" {
			p.TLSEngine = opts.TLSEngine
			p.tlsEnginePresent = true
		}
		if st, serr := os.Stat(paths.Dir); serr == nil && st.IsDir() {
			p.Exists = true
		}
		if opts.OutboundTag != "" && opts.OutboundTag != "direct" {
			p.Outbound = OutboundRef{Kind: OutboundTag, Tag: opts.OutboundTag}
		}
		if cfg.Profiles == nil {
			cfg.Profiles = make(map[string]*Profile)
		}
		cfg.Profiles[name] = p
		if opts.SetDefault {
			cfg.DefaultProfile = name
		}
		// Validates the tag reference (dangling tag errors) and
		// resolves the referenced type; aborts the write on error.
		if err := validateTagGraph(cfg); err != nil {
			return err
		}
		// Same position pattern as SetOutbound: refuse a
		// shared WireGuard private key here, at write time,
		// instead of persisting a file every later load
		// would reject.
		if err := validateWireGuardPrivateKeys(cfg); err != nil {
			return err
		}
		created = p.clone()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// refuseUnmigrated returns a "run config migrate first" error when
// no single file exists and the old layout is present. When a single
// file exists the old files are mere fallbacks and adding is fine.
func refuseUnmigrated(baseDir string) error {
	state, err := LoadConfigState(baseDir)
	if err != nil {
		return err
	}
	if state.Found {
		return nil
	}
	if !state.Exists {
		// No base config at all: also refuse when named legacy
		// profiles exist (their base config was never the single
		// file, so Exists above says nothing about them).
		names, err := DiscoverProfileNames(baseDir)
		if err != nil {
			return err
		}
		if len(names) > 1 {
			return newConfigError("the old layout exists unmigrated; run config migrate first")
		}
		return nil
	}
	// A file exists but is not a single file: it is the legacy-flat
	// default config.
	return newConfigError("the old layout exists unmigrated; run config migrate first")
}

// legacyProfileExists reports whether a legacy config file or
// directory exists for paths (a named profile's own files). The
// default profile's config path is the base config.json itself, so
// callers must not use this for "default" when a single file exists.
func legacyProfileExists(paths Paths) bool {
	if _, err := os.Stat(paths.Config); err == nil {
		return true
	}
	if st, err := os.Stat(paths.Dir); err == nil && st.IsDir() {
		return true
	}
	return false
}

// RemoveProfileResult is the outcome of RemoveProfile.
type RemoveProfileResult struct {
	// Name is the removed profile.
	Name string
	// Warning is non-empty when removing the default_profile forced
	// a fallback; the caller prints it. Empty otherwise.
	Warning string
	// DefaultProfile is the default_profile after removal ("" means
	// none: null in JSON).
	DefaultProfile string
}

// RemoveProfile removes ONLY the single-file entry for name: it
// never deletes cookies, chat, telegram, or old-layout files, and
// never touches the profile directory. Removing the default_profile
// falls back to "default" when a profile of that name remains, else
// to none (""); either way Warning carries the fallback text for
// the caller to print. An unknown name, or no single file, is an
// error and writes nothing. Removing a profile whose inline outbound
// tag is referenced by another profile is refused (it would strand
// that profile with a dangling reference).
func RemoveProfile(baseDir, name string) (*RemoveProfileResult, error) {
	if _, err := ValidateProfileName(name); err != nil {
		return nil, err
	}
	state, err := LoadConfigState(baseDir)
	if err != nil {
		return nil, err
	}
	if !state.Found {
		if state.Exists {
			return nil, newConfigError("profile rm only removes single-file entries; the old layout exists unmigrated (run config migrate first)")
		}
		return nil, newConfigError("profile rm only removes single-file entries; no single config file exists")
	}
	if _, ok := state.Config.Profiles[name]; !ok {
		return nil, newConfigErrorf("profile %q does not exist in the single config file", name)
	}
	result := &RemoveProfileResult{Name: name}
	err = UpdateSingleConfig(baseDir, func(cfg *SingleConfig) error {
		if _, ok := cfg.Profiles[name]; !ok {
			return newConfigErrorf("profile %q does not exist in the single config file", name)
		}
		delete(cfg.Profiles, name)
		if cfg.DefaultProfile == name {
			if _, ok := cfg.Profiles[DefaultProfileName]; ok {
				cfg.DefaultProfile = DefaultProfileName
				result.Warning = `default_profile fell back to "default"`
			} else {
				cfg.DefaultProfile = ""
				result.Warning = `default_profile cleared: no "default" profile remains`
			}
		}
		result.DefaultProfile = cfg.DefaultProfile
		// Refuses when the removal would strand another profile's
		// tag reference; aborts the write on error.
		return validateTagGraph(cfg)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// SetOutbound sets one profile's outbound from ONE JSON object: an
// option.Outbound object, or an option.Endpoint object for WireGuard
// (type "wireguard"). Parsing uses sing-box's UnmarshalJSONContext
// with the registry, the same path ParseSingleConfig uses; a parse
// error is an error and nothing is written. The
// {"outbound": {...}} wrapper is rejected. Tagged objects go to the
// outbounds/endpoints list and the profile references the tag;
// untagged objects go inline (auto-tagged "profile:<name>"), except
// untagged WireGuard objects, which are auto-tagged and stored in
// endpoints with the profile referencing the tag. A tagged object
// overwrites an existing entry with the same tag only when no other
// profile uses that tag with a different type. The profile must
// already exist in the single file.
func SetOutbound(baseDir, name string, data []byte) (*Profile, error) {
	if _, err := ValidateProfileName(name); err != nil {
		return nil, err
	}
	state, err := LoadConfigState(baseDir)
	if err != nil {
		return nil, err
	}
	if !state.Found {
		return nil, newConfigError("profile set-outbound only modifies single-file entries; no single config file exists (run config migrate first)")
	}
	if _, ok := state.Config.Profiles[name]; !ok {
		return nil, newConfigErrorf("profile %q does not exist in the single config file", name)
	}
	var updated *Profile
	err = UpdateSingleConfig(baseDir, func(cfg *SingleConfig) error {
		p, ok := cfg.Profiles[name]
		if !ok {
			return newConfigErrorf("profile %q does not exist in the single config file", name)
		}
		if err := applySetOutbound(cfg, p, data); err != nil {
			return err
		}
		if err := validateTagGraph(cfg); err != nil {
			return err
		}
		// SetOutbound is the one in-package mutation path that can
		// introduce endpoints: refuse a shared WireGuard private
		// key here, at write time, instead of persisting a file
		// every later load would reject.
		if err := validateWireGuardPrivateKeys(cfg); err != nil {
			return err
		}
		updated = p.clone()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// SetFingerprint sets a profile's recorded fingerprint preset name
// (storage only; see fingerprint.go) through the same
// flock+sha256 guarded writer as the other profile commands. The
// value is validated before anything is written: invalid → error,
// file unchanged. An empty value resets the profile to the default
// ("chrome") and clears the stored key, so a later save omits it.
// The profile must already exist in the single file.
func SetFingerprint(baseDir, name, fingerprint string) (*Profile, error) {
	if _, err := ValidateProfileName(name); err != nil {
		return nil, err
	}
	if fingerprint != "" {
		if err := validateFingerprintValue(fingerprint); err != nil {
			return nil, newConfigError(err.Error())
		}
	}
	state, err := LoadConfigState(baseDir)
	if err != nil {
		return nil, err
	}
	if !state.Found {
		return nil, newConfigError("profile set-fingerprint only modifies single-file entries; no single config file exists (run config migrate first)")
	}
	if _, ok := state.Config.Profiles[name]; !ok {
		return nil, newConfigErrorf("profile %q does not exist in the single config file", name)
	}
	var updated *Profile
	err = UpdateSingleConfig(baseDir, func(cfg *SingleConfig) error {
		p, ok := cfg.Profiles[name]
		if !ok {
			return newConfigErrorf("profile %q does not exist in the single config file", name)
		}
		if fingerprint == "" {
			p.Fingerprint = DefaultFingerprint
			p.fingerprintPresent = false
		} else {
			p.Fingerprint = fingerprint
			p.fingerprintPresent = true
		}
		updated = p.clone()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// SetTlsEngine sets a profile's recorded TLS engine name (storage
// only; see fingerprint.go) through the same flock+sha256 guarded
// writer as the other profile commands. The value is validated
// before anything is written: invalid → error, file unchanged. An
// empty value resets the profile to the default ("utls") and clears
// the stored key, so a later save omits it. The profile must
// already exist in the single file.
func SetTlsEngine(baseDir, name, tlsEngine string) (*Profile, error) {
	if _, err := ValidateProfileName(name); err != nil {
		return nil, err
	}
	if tlsEngine != "" {
		if err := validateTLSEngineValue(tlsEngine); err != nil {
			return nil, newConfigError(err.Error())
		}
	}
	state, err := LoadConfigState(baseDir)
	if err != nil {
		return nil, err
	}
	if !state.Found {
		return nil, newConfigError("profile set-tls-engine only modifies single-file entries; no single config file exists (run config migrate first)")
	}
	if _, ok := state.Config.Profiles[name]; !ok {
		return nil, newConfigErrorf("profile %q does not exist in the single config file", name)
	}
	var updated *Profile
	err = UpdateSingleConfig(baseDir, func(cfg *SingleConfig) error {
		p, ok := cfg.Profiles[name]
		if !ok {
			return newConfigErrorf("profile %q does not exist in the single config file", name)
		}
		if tlsEngine == "" {
			p.TLSEngine = DefaultTLSEngine
			p.tlsEnginePresent = false
		} else {
			p.TLSEngine = tlsEngine
			p.tlsEnginePresent = true
		}
		updated = p.clone()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// applySetOutbound parses data and mutates cfg/p. It writes nothing
// itself; the caller validates and writes.
func applySetOutbound(cfg *SingleConfig, p *Profile, data []byte) error {
	obj, err := decodeOrderedObject(data)
	if err != nil {
		return err
	}
	if obj.has("outbound") {
		return newConfigError("set-outbound takes one outbound/endpoint object, not a {\"outbound\": {...}} wrapper")
	}
	typeVal, ok := obj.get("type")
	if !ok {
		return newConfigError("outbound object must have a \"type\"")
	}
	typeStr, ok := typeVal.(string)
	if !ok {
		return newConfigError("outbound \"type\" must be a string")
	}
	if typeStr == "wireguard" {
		return applySetEndpoint(cfg, p, obj)
	}
	return applySetOutboundObject(cfg, p, obj)
}

func applySetEndpoint(cfg *SingleConfig, p *Profile, obj *orderedObject) error {
	raw, tag, err := ensureInlineTag(obj, "profile:"+p.Name)
	if err != nil {
		return err
	}
	ep, err := parseEndpoint(raw)
	if err != nil {
		return err
	}
	if wg, ok := ep.Options.(*option.WireGuardEndpointOptions); ok && wg.System {
		return newConfigError("wireguard endpoint \"system\": true is not supported; use userspace wireguard only")
	}
	if err := checkSameTagOverwrite(cfg, p.Name, tag, ep.Type, "endpoint"); err != nil {
		return err
	}
	setEndpointInList(cfg, ep, raw)
	p.Outbound = OutboundRef{Kind: OutboundTag, Tag: tag}
	return nil
}

func applySetOutboundObject(cfg *SingleConfig, p *Profile, obj *orderedObject) error {
	raw, err := rawOf(obj)
	if err != nil {
		return err
	}
	ob, err := parseOutbound(raw)
	if err != nil {
		return err
	}
	if ob.Tag != "" {
		if err := checkSameTagOverwrite(cfg, p.Name, ob.Tag, ob.Type, "outbound"); err != nil {
			return err
		}
		setOutboundInList(cfg, ob, raw)
		p.Outbound = OutboundRef{Kind: OutboundTag, Tag: ob.Tag}
		return nil
	}
	// Untagged: inline, auto-tagged "profile:<name>".
	tagged, _, err := ensureInlineTag(obj, "profile:"+p.Name)
	if err != nil {
		return err
	}
	inline, err := parseOutbound(tagged)
	if err != nil {
		return err
	}
	p.Outbound = OutboundRef{Kind: OutboundInline, Tag: inline.Tag, Type: inline.Type, Raw: tagged, parsed: &inline}
	return nil
}

// checkSameTagOverwrite enforces the same-tag rule: overwriting an
// entry tagged tag with newType is refused when another profile
// references the tag with a different type, or when the tag is
// already used in the other section or as another profile's inline
// tag.
func checkSameTagOverwrite(cfg *SingleConfig, profile, tag, newType, section string) error {
	for _, ob := range cfg.Outbounds {
		if ob.Tag == tag && section != "outbound" {
			return newConfigErrorf("duplicate tag %q (already an outbound)", tag)
		}
	}
	for _, ep := range cfg.Endpoints {
		if ep.Tag == tag && section != "endpoint" {
			return newConfigErrorf("duplicate tag %q (already an endpoint)", tag)
		}
	}
	for otherName, other := range cfg.Profiles {
		if otherName == profile {
			continue
		}
		if other.Outbound.Kind == OutboundInline && other.Outbound.Tag == tag {
			return newConfigErrorf("duplicate tag %q (already the inline outbound of profile %q)", tag, otherName)
		}
		if other.Outbound.Kind == OutboundTag && other.Outbound.Tag == tag && other.Outbound.Type != "" && other.Outbound.Type != newType {
			return newConfigErrorf("tag %q is used by profile %q with type %q; refusing to overwrite with type %q", tag, otherName, other.Outbound.Type, newType)
		}
	}
	return nil
}

// setOutboundInList replaces the outbound with the same tag, or
// appends it, keeping cfg.Outbounds and cfg.rawOutbounds in sync.
func setOutboundInList(cfg *SingleConfig, ob option.Outbound, raw []byte) {
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i].Tag == ob.Tag {
			cfg.Outbounds[i] = ob
			cfg.rawOutbounds[i] = raw
			return
		}
	}
	cfg.Outbounds = append(cfg.Outbounds, ob)
	cfg.rawOutbounds = append(cfg.rawOutbounds, raw)
}

// SetAutoApprove sets a profile's auto_approve value ("always" or
// "off") through the same flock+sha256 guarded writer as the other
// profile commands. The profile must already exist in the single
// file; a legacy layout is never written back to. This is the
// persistent writer behind `auto-approve on|off`.
func SetAutoApprove(baseDir, name, value string) (*Profile, error) {
	if _, err := ValidateProfileName(name); err != nil {
		return nil, err
	}
	if value != "always" && value != "off" {
		return nil, newConfigErrorf("auto_approve must be \"always\" or \"off\", not %q", value)
	}
	state, err := LoadConfigState(baseDir)
	if err != nil {
		return nil, err
	}
	if !state.Found {
		return nil, newConfigError("auto-approve only modifies single-file entries; no single config file exists (run config migrate first)")
	}
	if _, ok := state.Config.Profiles[name]; !ok {
		return nil, newConfigErrorf("profile %q does not exist in the single config file", name)
	}
	var updated *Profile
	err = UpdateSingleConfig(baseDir, func(cfg *SingleConfig) error {
		p, ok := cfg.Profiles[name]
		if !ok {
			return newConfigErrorf("profile %q does not exist in the single config file", name)
		}
		p.AutoApprove = value
		updated = p.clone()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// SetAutoAllowOnce sets a profile's auto_allow_once fallback toggle
// through the same flock+sha256 guarded writer as the other profile
// commands. The profile must already exist in the single file; a
// legacy layout is never written back to. This is the persistent
// writer behind `auto-approve once on|off`.
func SetAutoAllowOnce(baseDir, name string, value bool) (*Profile, error) {
	if _, err := ValidateProfileName(name); err != nil {
		return nil, err
	}
	state, err := LoadConfigState(baseDir)
	if err != nil {
		return nil, err
	}
	if !state.Found {
		return nil, newConfigError("auto-approve only modifies single-file entries; no single config file exists (run config migrate first)")
	}
	if _, ok := state.Config.Profiles[name]; !ok {
		return nil, newConfigErrorf("profile %q does not exist in the single config file", name)
	}
	var updated *Profile
	err = UpdateSingleConfig(baseDir, func(cfg *SingleConfig) error {
		p, ok := cfg.Profiles[name]
		if !ok {
			return newConfigErrorf("profile %q does not exist in the single config file", name)
		}
		p.AutoAllowOnce = value
		updated = p.clone()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// setEndpointInList replaces the endpoint with the same tag, or
// appends it, keeping cfg.Endpoints and cfg.rawEndpoints in sync.
func setEndpointInList(cfg *SingleConfig, ep option.Endpoint, raw []byte) {
	for i := range cfg.Endpoints {
		if cfg.Endpoints[i].Tag == ep.Tag {
			cfg.Endpoints[i] = ep
			cfg.rawEndpoints[i] = raw
			return
		}
	}
	cfg.Endpoints = append(cfg.Endpoints, ep)
	cfg.rawEndpoints = append(cfg.rawEndpoints, raw)
}
