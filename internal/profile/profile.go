// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultProfileName is the name of the original layout profile.
const DefaultProfileName = "default"

// ProfileEnv is the environment variable naming the active profile.
const ProfileEnv = "MUSE_CLI_PROFILE"

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

// BaseDir returns ~/.config/muse-cli for the given home directory.
func BaseDir(home string) string {
	return filepath.Join(home, ".config", "muse-cli")
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
// skipped. The active profile is not appended here; callers that need
// the Python behaviour (list the active profile even if not on disk)
// add it themselves.
func DiscoverProfileNames(baseDir string) ([]string, error) {
	names := []string{DefaultProfileName}
	entries, err := os.ReadDir(filepath.Join(baseDir, "profiles"))
	if err != nil {
		if os.IsNotExist(err) {
			return names, nil
		}
		return nil, newConfigErrorf("list profiles: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
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
	// SourceLegacy means settings came from the profile's own legacy config.json.
	SourceLegacy Source = "legacy"
	// SourceNone means no config file was found; defaults apply.
	SourceNone Source = "none"
)

// Profile is the resolved settings for one profile. CookiesFile is the
// resolved absolute path after defaulting and coercion. AutoApprove is
// normalised to "always" or "off". Outbound is direct when no outbound
// key is present.
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
	Outbound             OutboundRef
	Source               Source
	// Exists reports whether the profile directory exists on disk.
	Exists bool
	// ConfigFound reports whether settings came from a config file
	// (single-file entry or legacy file).
	ConfigFound bool

	vmIDPresent   bool
	nodeIDPresent bool
}

// clone returns a shallow copy; the Outbound Raw slice is shared but
// RawJSON returns a defensive copy and InlineOutbound re-parses.
func (p *Profile) clone() *Profile {
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}
