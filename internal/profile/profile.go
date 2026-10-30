// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// DefaultProfileName is the name of the original layout profile.
const DefaultProfileName = "default"

// ProfileEnv is the environment variable naming the active profile.
const ProfileEnv = "CASTCTL_PROFILE"

// ValidateProfileName returns name if it matches the Python regex
// ^(?!\.)[A-Za-z0-9._-]{1,64}(?<!\.)$ (cli.py:37), else an
// ErrInvalidProfile error. Go's regexp package has no lookahead, so the
// leading/trailing-dot rules are checked explicitly; the result is
// identical to the Python regex.
func ValidateProfileName(name string) (string, error) {
	runes := []rune(name)
	if len(runes) < 1 || len(runes) > 64 {
		return "", newInvalidProfileError(name)
	}
	if runes[0] == '.' || runes[len(runes)-1] == '.' {
		return "", newInvalidProfileError(name)
	}
	for _, r := range runes {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' ||
			r == '.' || r == '_' || r == '-') {
			return "", newInvalidProfileError(name)
		}
	}
	return name, nil
}

// ResolveProfileName implements flag > env > "default" (cli.py:44-53).
// flag, when non-nil, is validated even when empty. An env value that is
// empty or whitespace-only is ignored. getenv is injected for tests;
// pass os.LookupEnv in production via ResolveProfile.
func ResolveProfileName(flag *string, getenv func(string) (string, bool)) (string, error) {
	if flag != nil {
		return ValidateProfileName(*flag)
	}
	if getenv != nil {
		if env, ok := getenv(ProfileEnv); ok && strings.TrimSpace(env) != "" {
			return ValidateProfileName(strings.TrimSpace(env))
		}
	}
	return DefaultProfileName, nil
}

// ResolveProfile resolves the profile name from a flag and the process
// environment.
func ResolveProfile(flag *string) (string, error) {
	return ResolveProfileName(flag, os.LookupEnv)
}

// BaseDir returns the $HOME-based default config directory
// (Join(home, ".config", "castctl")) for the given home directory.
// It is the fallback constructor used only when a relative
// XDG_CONFIG_HOME is caught by ResolveConfigLocation; the primary
// default comes from userConfigDir (os.UserConfigDir semantics).
func BaseDir(home string) string {
	return filepath.Join(home, ".config", "castctl")
}

// Paths holds the filesystem locations for one profile.
type Paths struct {
	Dir     string
	Config  string
	Cookies string
	Chat    string
}

// ProfilePaths returns the directory and file paths for a profile:
// default = base dir; named = base/profiles/NAME/ (cli.py:55-81).
func ProfilePaths(baseDir, name string) (Paths, error) {
	if _, err := ValidateProfileName(name); err != nil {
		return Paths{}, err
	}
	if name == DefaultProfileName {
		return Paths{
			Dir:     baseDir,
			Config:  filepath.Join(baseDir, "config.json"),
			Cookies: filepath.Join(baseDir, "cookies.txt"),
			Chat:    filepath.Join(baseDir, "chat.json"),
		}, nil
	}
	dir := filepath.Join(baseDir, "profiles", name)
	return Paths{
		Dir:     dir,
		Config:  filepath.Join(dir, "config.json"),
		Cookies: filepath.Join(dir, "cookies.txt"),
		Chat:    filepath.Join(dir, "chat.json"),
	}, nil
}

// EnsureProfileDir creates the profile directory. Named profiles get mode
// 0700 for both profiles/ and the profile dir (and the profile dir is
// chmodded to 0700 unconditionally, as in cli.py ensure_config_dir);
// the default directory is created with default permissions. It returns
// the profile's paths.
func EnsureProfileDir(baseDir, name string) (Paths, error) {
	paths, err := ProfilePaths(baseDir, name)
	if err != nil {
		return Paths{}, err
	}
	if name == DefaultProfileName {
		if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
			return Paths{}, err
		}
		return paths, nil
	}
	if err := os.MkdirAll(filepath.Dir(paths.Dir), 0o700); err != nil {
		return Paths{}, err
	}
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		return Paths{}, err
	}
	if err := os.Chmod(paths.Dir, 0o700); err != nil {
		return Paths{}, err
	}
	return paths, nil
}

// DiscoverProfileNames returns "default" first, then the sorted names of
// valid-slug directories under base/profiles, mirroring list_profiles
// (cli.py). Invalid names, files, and a missing profiles directory are
// skipped. A symlinked profile directory IS followed: DirEntry.IsDir
// is false for a symlink to a directory, so a bare IsDir check would
// silently drop every symlinked legacy profile from migration and
// from the legacy-layout scan. An unresolvable symlink holds no
// config and is skipped here; migrate itself fails loudly on it
// (see MigrateFrom), so it never vanishes silently from a
// migration. The active profile is not appended here; callers that need
// the Python behaviour (list the active profile even if not on disk)
// add it themselves. Directory discovery only: it reads no config
// file. Migrate uses it to enumerate the profiles a legacy layout
// may hold; LoadProfile never reads a legacy file it names.
func DiscoverProfileNames(baseDir string) ([]string, error) {
	names := []string{DefaultProfileName}
	profilesDir := filepath.Join(baseDir, "profiles")
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return names, nil
		}
		return nil, newConfigErrorf("list profiles: %v", err)
	}
	for _, e := range entries {
		isDir := e.IsDir()
		if !isDir && e.Type()&os.ModeSymlink != 0 {
			if st, serr := os.Stat(filepath.Join(profilesDir, e.Name())); serr == nil && st.IsDir() {
				isDir = true
			}
		}
		if !isDir {
			continue
		}
		if _, err := ValidateProfileName(e.Name()); err != nil {
			continue
		}
		if e.Name() == DefaultProfileName {
			continue
		}
		names = append(names, e.Name())
	}
	// ReadDir returns entries sorted by filename; names[1:] is sorted.
	return names, nil
}

// Source records where a profile's settings came from.
type Source string

const (
	// SourceSingle means settings came from the single-file config.json.
	SourceSingle Source = "single"
	// SourceLegacy means the profile was built from a legacy
	// per-profile config file by Migrate (migrate-only). LoadProfile
	// never returns it: a legacy file on disk is refused instead.
	SourceLegacy Source = "legacy"
	// SourceNone means no config file was found; defaults apply.
	SourceNone Source = "none"
)

// Profile is the resolved settings for one profile. CookiesFile is the
// resolved absolute path after defaulting and coercion. AutoApprove is
// normalised to "always" or "off". Outbound is direct when no outbound
// key is present.
//
// Fingerprint and TLSEngine are RECORDED in PR3 (storage + data
// validation + display only). Their EFFECT takes place only after
// the fingerprint-engine evaluation decision (pending); today all
// traffic uses uTLS chrome regardless of these values. Do NOT adopt
// "random"/"randomized" presets. Fingerprint defaults to "chrome"
// and TLSEngine to "utls" when the key is absent; the presence flags
// record whether the key was written in the file, so a save never
// writes a default back into a file that did not carry the key.
type Profile struct {
	Name                 string
	Dir                  string
	ConfigFile           string
	CookiesFile          string
	ChatFile             string
	VMID                 string
	NodeID               string
	AutoApprove          string
	AutoAllowOnce        bool
	SubscriptionActionID string
	Fingerprint          string
	TLSEngine            string
	// DNS is the profile's own parsed dns block, or nil when the
	// entry carries no "dns" key. Like Fingerprint/TLSEngine it
	// is storage + validation + display only: the runtime picks
	// the effective resolver via ResolveProfileDNS, which also
	// covers the WireGuard-imported and synthesised defaults.
	DNS      *option.DNSOptions
	Outbound OutboundRef
	Source   Source
	// Exists reports whether the profile directory exists on disk.
	Exists bool
	// ConfigFound reports whether settings came from a config file
	// (a single-file entry; a legacy file is refused, never a source).
	ConfigFound bool

	vmIDPresent        bool
	nodeIDPresent      bool
	fingerprintPresent bool
	tlsEnginePresent   bool
	// rawDNS preserves the profile entry's "dns" JSON verbatim
	// for faithful re-encoding on save; dnsPresent records that
	// the key was written in the file, so a save never invents
	// a dns block for a profile that did not carry one.
	rawDNS     []byte
	dnsPresent bool
}

// clone returns a shallow copy; the Outbound Raw slice is shared but
// RawJSON returns a defensive copy and InlineOutbound re-parses.
// The dns raw JSON is copied defensively (like SingleConfig's
// rawDNS in cloneSingleConfig) so mutating a clone's saved form
// never affects the original; the parsed DNS value is shared
// read-only, as for the global section.
func (p *Profile) clone() *Profile {
	if p == nil {
		return nil
	}
	cp := *p
	if len(p.rawDNS) > 0 {
		cp.rawDNS = append([]byte{}, p.rawDNS...)
	}
	return &cp
}

// ParsedDNS re-parses the stored per-profile dns JSON, or returns
// nil when the entry has no dns block. It mirrors
// SingleConfig.ParsedDNS.
func (p *Profile) ParsedDNS() (*option.DNSOptions, error) {
	if p == nil {
		return nil, nil
	}
	if len(p.rawDNS) == 0 {
		return p.DNS, nil
	}
	return parseDNS(p.rawDNS)
}

// RawDNS returns a defensive copy of the stored per-profile dns
// JSON, or nil.
func (p *Profile) RawDNS() []byte {
	if p == nil || len(p.rawDNS) == 0 {
		return nil
	}
	out := make([]byte, len(p.rawDNS))
	copy(out, p.rawDNS)
	return out
}

// HasDNS reports whether the profile entry carried a "dns" key.
func (p *Profile) HasDNS() bool {
	return p != nil && p.dnsPresent
}
