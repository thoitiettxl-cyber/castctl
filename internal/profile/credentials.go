// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"strings"
)

// The top-level `credentials` config block: stored login credentials
// for keeper auto re-login (Boss decisions G1/G2, 2026-11-02).
//
// Schema: an optional LIST of entries, sing-box style, referenced
// by tag. Each entry has exactly these keys; unknown keys are
// rejected, like every other strict section:
//
//	{"tag": string, "profile": string, "username": string, "password": string}
//
//   - `tag` (required): unique name, same exactness rule as keeper
//     tags (ValidateKeeperTag): no surrounding whitespace, no
//     path separators or control characters, never "." or "..".
//   - `profile` (required): the name of a key of
//     SingleConfig.Profiles. One entry per profile: two entries
//     naming the same profile is a config error (one login
//     identity per profile; ambiguity would risk submitting the
//     wrong credentials). A name that is not a profile key is a
//     dangling reference, exit 2.
//   - `username`, `password` (required, non-empty): the login
//     credentials for the profile's provider login form. They are
//     SECRET MATERIAL: stored reversibly (hashing is impossible —
//     the form submission needs the plaintext), write-only in
//     every display path, never logged, never exposed to plugins,
//     never echoed into errors. Both keys are in redact.secretKeys.
//     The config file itself must be mode 0600 (enforced by the
//     guarded config save; a world-readable file is refused at
//     load by the config loader's mode check where it exists).
//   - No `.bak` or backup copy of config.json is ever written for
//     credentials: the guarded atomic save is the only write path.
//
// A nil *CredentialsConfig on SingleConfig means the block was
// absent: no stored credentials, no auto re-login; the keeper
// falls back to alerting. An absent block is preserved on save.
// A present block is preserved verbatim on save when its raw JSON
// was captured, exactly like `keeper` and `telegram`.
//
// Access discipline: the username/password fields are unexported.
// The only accessor is CredentialForProfile, which returns a
// value struct to the keeper's headless re-login driver (built in
// the command layer) — never through an exported struct field
// any plugin API could serialise, never through RedactConfig
// (which renders the raw block through redact.Value, so both
// values come out as "<redacted>").

// CredentialEntry is one parsed `credentials` list entry. The
// credential values are unexported: see CredentialForProfile.
type CredentialEntry struct {
	Tag     string
	Profile string

	username string
	password string

	raw []byte
}

// CredentialsConfig is one parsed top-level `credentials` block:
// the list of entries in file order. A nil *CredentialsConfig
// means the block was absent.
type CredentialsConfig struct {
	Entries []*CredentialEntry

	raw []byte
}

// RawCredentials returns a defensive copy of the raw
// `credentials` JSON when the block was parsed from a file, or
// nil. It mirrors the raw-preservation accessors of other blocks.
func (c *SingleConfig) RawCredentials() []byte {
	if c == nil || len(c.rawCredentials) == 0 {
		return nil
	}
	cp := make([]byte, len(c.rawCredentials))
	copy(cp, c.rawCredentials)
	return cp
}

var credentialEntryKeys = map[string]bool{
	"tag": true, "profile": true, "username": true, "password": true,
}

// parseCredentialsBlock parses one decoded `credentials` value
// (an array of entry objects) into a CredentialsConfig. Wrong
// shapes, wrong types, unknown keys, missing required keys,
// duplicate tags, and empty credential values are all config
// errors (exit 2). Cross-references (profile existence, one
// entry per profile) are checked by validateCredentials, not
// here, so a hand-built SingleConfig gets the same refusal
// from ResolveCredentials. Error messages name keys and tags
// only, never credential values.
func parseCredentialsBlock(v any) (*CredentialsConfig, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, newConfigError(`"credentials" must be an array of entries`)
	}
	cfg := &CredentialsConfig{}
	seenTags := make(map[string]bool)
	for i, elem := range arr {
		obj, ok := elem.(*orderedObject)
		if !ok {
			return nil, newConfigErrorf(`"credentials" entry %d must be an object`, i)
		}
		raw, err := rawOf(elem)
		if err != nil {
			return nil, err
		}
		entry := &CredentialEntry{raw: raw}
		for _, k := range obj.keys {
			val := obj.values[k]
			switch k {
			case "tag":
				s, ok := val.(string)
				if !ok {
					return nil, newConfigErrorf(`"credentials" entry %d: "tag" must be a non-empty string`, i)
				}
				if err := ValidateKeeperTag(s); err != nil {
					return nil, newConfigErrorf(`"credentials" entry %d: invalid "tag": %v`, i, err)
				}
				entry.Tag = s
			case "profile":
				s, ok := val.(string)
				if !ok || strings.TrimSpace(s) == "" {
					return nil, newConfigErrorf(`"credentials" entry %d: "profile" must be a non-empty string`, i)
				}
				if _, err := ValidateProfileName(s); err != nil {
					return nil, newConfigErrorf(`"credentials" entry %d: invalid profile name %q`, i, s)
				}
				entry.Profile = s
			case "username":
				s, ok := val.(string)
				if !ok || s == "" {
					return nil, newConfigErrorf(`"credentials" entry %d: "username" must be a non-empty string`, i)
				}
				entry.username = s
			case "password":
				s, ok := val.(string)
				if !ok || s == "" {
					return nil, newConfigErrorf(`"credentials" entry %d: "password" must be a non-empty string`, i)
				}
				entry.password = s
			default:
				return nil, newConfigErrorf(`unknown credentials config key %q`, k)
			}
		}
		if entry.Tag == "" {
			return nil, newConfigErrorf(`"credentials" entry %d requires a "tag" key`, i)
		}
		if entry.Profile == "" {
			return nil, newConfigErrorf(`"credentials" entry %d requires a "profile" key`, i)
		}
		if entry.username == "" {
			return nil, newConfigErrorf(`"credentials" entry %d requires a "username" key`, i)
		}
		if entry.password == "" {
			return nil, newConfigErrorf(`"credentials" entry %d requires a "password" key`, i)
		}
		if seenTags[entry.Tag] {
			return nil, newConfigErrorf(`"credentials" has duplicate tag %q`, entry.Tag)
		}
		seenTags[entry.Tag] = true
		cfg.Entries = append(cfg.Entries, entry)
	}
	return cfg, nil
}

// validateCredentials enforces the block's cross-references:
// every entry's profile must name a key of SingleConfig.Profiles,
// and no two entries may name the same profile. It names
// profiles/tags only, never values. Called from the
// ParseSingleConfig tail after validateKeeper; a nil block is
// valid (feature off).
func validateCredentials(cfg *SingleConfig) error {
	c := cfg.Credentials
	if c == nil {
		return nil
	}
	seenProfiles := make(map[string]string)
	for _, e := range c.Entries {
		if _, ok := cfg.Profiles[e.Profile]; !ok {
			return newConfigErrorf("credentials: entry %q names profile %q, which does not exist", e.Tag, e.Profile)
		}
		if prev, ok := seenProfiles[e.Profile]; ok {
			return newConfigErrorf("credentials: entries %q and %q both name profile %q", prev, e.Tag, e.Profile)
		}
		seenProfiles[e.Profile] = e.Tag
	}
	return nil
}

// ResolveCredentials returns the parsed `credentials` block, or
// nil when the block is absent (feature off) or there is no
// single config. It never reads the filesystem and never
// mutates its input. The cross-reference checks are re-run here
// so callers that receive a hand-built SingleConfig get the
// same dangling-reference refusal parse gives.
func ResolveCredentials(single *SingleConfig) (*CredentialsConfig, error) {
	if single == nil || single.Credentials == nil {
		return nil, nil
	}
	if err := validateCredentials(single); err != nil {
		return nil, err
	}
	return single.Credentials, nil
}

// LoginCredential is the narrow value the keeper's headless
// re-login driver receives. It exists only in memory, only
// inside the keeper/login core: it is never marshalled, never
// logged, and never handed to any exported accessor. The
// driver must zero it after use where it can (it cannot be
// forced: the driver holds the only copy by construction).
type LoginCredential struct {
	Username string
	Password string
}

// CredentialForProfile returns the stored login credential for
// a profile name, or (zero, false) when no credentials entry
// names it. This is the ONLY read path for credential values
// outside this package's parse/encode: the keeper command
// layer calls it once per re-login attempt and hands the
// result to the driver; no exported struct field, no config
// serialisation, and no display path ever sees a value.
func (c *CredentialsConfig) CredentialForProfile(profileName string) (LoginCredential, bool) {
	if c == nil {
		return LoginCredential{}, false
	}
	for _, e := range c.Entries {
		if e.Profile == profileName {
			return LoginCredential{Username: e.username, Password: e.password}, true
		}
	}
	return LoginCredential{}, false
}

// CredentialEntryForTag returns the entry with the given tag,
// or nil. Callers use it to resolve a keeper entry's
// `credentials` reference; they must not read values from it
// except through CredentialForProfile.
func (c *CredentialsConfig) CredentialEntryForTag(tag string) *CredentialEntry {
	if c == nil {
		return nil
	}
	for _, e := range c.Entries {
		if e.Tag == tag {
			return e
		}
	}
	return nil
}

// encodeCredentialsBlock renders a CredentialsConfig for save
// when no raw JSON was captured: entries in order, canonical
// key order tag/profile/username/password. The values are
// written verbatim — this is the config save path, whose file
// is mode 0600; redaction applies only to display paths
// (RedactConfig), never to the save encoder.
func encodeCredentialsBlock(cfg *CredentialsConfig) ([]any, error) {
	arr := make([]any, 0, len(cfg.Entries))
	for _, e := range cfg.Entries {
		entry := newOrderedObject()
		entry.set("tag", e.Tag)
		entry.set("profile", e.Profile)
		entry.set("username", e.username)
		entry.set("password", e.password)
		arr = append(arr, entry)
	}
	return arr, nil
}

// validateCredentialRefs checks a keeper entry's `credentials`
// reference against the parsed credentials block: the tag must
// exist, and the referenced entry must name the keeper entry's
// own profile (a credential for another profile must never be
// submitted for this one). Called from the ParseSingleConfig
// tail (and from ResolveKeeper) so the refusal is a config
// error, exit 2. A nil credentials block with a reference
// present is a dangling reference. Messages name tags/profiles only.
func validateCredentialRefs(cfg *SingleConfig) error {
	k := cfg.Keeper
	if k == nil {
		return nil
	}
	for _, e := range k.Entries {
		if e.Credentials == "" {
			continue
		}
		if cfg.Credentials == nil {
			return newConfigErrorf("keeper: entry %q references credentials %q, but no \"credentials\" block exists", e.Tag, e.Credentials)
		}
		cred := cfg.Credentials.CredentialEntryForTag(e.Credentials)
		if cred == nil {
			return newConfigErrorf("keeper: entry %q references credentials %q, which does not exist", e.Tag, e.Credentials)
		}
		if cred.Profile != e.Profile {
			return newConfigErrorf("keeper: entry %q references credentials %q for profile %q, not %q", e.Tag, e.Credentials, cred.Profile, e.Profile)
		}
	}
	return nil
}
