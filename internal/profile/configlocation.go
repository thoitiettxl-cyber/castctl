// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config location (Requirement A, Boss order, PR3; portable
// resolution per the PLATFORMS clarification).
//
// Precedence, highest first: an explicit config FILE path (the
// --config flag value, else MUSE_CLI_CONFIG) > the
// os.UserConfigDir()-derived home (Join(userConfigDir, "muse-cli")).
// The default home follows os.UserConfigDir semantics exactly:
// XDG_CONFIG_HOME on Linux/Unix, %APPDATA% on Windows, and
// ~/Library/Application Support on macOS; see userConfigDir. A
// relative XDG_CONFIG_HOME is an error in os.UserConfigDir on Unix:
// the resolver catches that one case, warns visibly, and falls back
// to the computed $HOME-based default (Join(home, ".config",
// "muse-cli") from the HOME env). Any other user-config-dir error
// with no usable home is a clear error (exit 2 at the CLI), never a
// silent fallback to a hardcoded path.
//
// The resolved config file's directory becomes CONFIG_DIR for the
// whole invocation: every derived path (single-file config.json,
// the config.json.lock, legacy fallback files, profiles/<name>/,
// cookies_file defaults, chat.json, and — for consumers in other
// packages — telegram.json, telegram-state.json and update.json)
// comes from it. This package has no derivation that hardcodes a
// home directory; BaseDir is only the $HOME-based fallback
// constructor used for the relative-XDG case above.
//
// Symlinks are NOT resolved for display paths: CONFIG_DIR is the
// directory of the path as given, and opening follows the symlink
// with standard open semantics. Relative explicit paths resolve
// relative to the process working directory; no tilde expansion is
// performed (a leading "~" is a literal directory name).
//
// The per-key path-resolution table lives in the package doc
// (errors.go). In short: cookies_file is the only config key this
// package resolves, relative to the resolved CONFIG_DIR; path-like
// fields inside sing-box option objects pass through verbatim.
//
// Browser-optional principle: nothing in this package assumes a
// browser exists. Config resolution, profile storage, and the
// fingerprint/tls_engine fields are plain data on disk; no browser,
// display, or GUI capability is consulted or required.

// ConfigLocation is the resolved location of the config file for one
// invocation. Phase 2 resolves it once at startup (from the --config
// flag value, falling back to the environment) and passes ConfigDir
// as baseDir to every function in this package.
type ConfigLocation struct {
	// ConfigFile is the resolved config file path, as given for an
	// explicit path (cleaned lexically, symlinks unresolved) or
	// absolute for UserConfigDir-derived locations.
	ConfigFile string
	// ConfigDir is the directory of ConfigFile: the CONFIG_DIR for
	// the whole invocation.
	ConfigDir string
	// Explicit reports whether the location came from an explicit
	// path: the flag parameter or MUSE_CLI_CONFIG. False for
	// UserConfigDir-derived locations.
	Explicit bool
	// Warnings lists non-fatal observations for the CLI layer to
	// print on stderr, e.g. a relative XDG_CONFIG_HOME that was
	// ignored. Empty when there is nothing to warn about.
	Warnings []string
}

// ResolveConfigLocation resolves the config file location.
// explicitPath is the --config flag value as passed by the caller
// (Phase 2 resolves flag-vs-env before calling when it has a flag
// value; an empty value means "no flag value"). getenv has the same
// shape as LoadProfile's: func(key) (value, present); nil means
// os.LookupEnv. Rules, in precedence order:
//
//   - explicitPath non-empty (after trimming surrounding
//     whitespace, which only guards against blank values) wins and
//     is used as given, cleaned lexically. An empty explicitPath
//     means the caller passed nothing: it is NOT an error here —
//     the CLI layer rejects an empty --config flag value with
//     exit 2 before calling this function.
//   - else MUSE_CLI_CONFIG, when set and non-empty (empty means
//     unset, ignored silently), used the same way as explicitPath.
//   - else the UserConfigDir-derived home: Join(userConfigDir,
//     "muse-cli"), where userConfigDir follows os.UserConfigDir
//     semantics through getenv (see userConfigDir). A relative
//     XDG_CONFIG_HOME (Unix) is ignored with a warning, falling
//     back to the computed $HOME-based default; any other
//     user-config-dir error is returned as-is (exit 2 at the CLI).
//
// An explicit path naming a directory is an error. An explicit path
// that does not exist is NOT an error from this function: the
// caller decides via RequirePresent (every command except
// `config migrate --write` must call it; see RequirePresent).
func ResolveConfigLocation(explicitPath string, getenv func(string) (string, bool)) (*ConfigLocation, error) {
	if strings.TrimSpace(explicitPath) != "" {
		return resolveExplicitPath(explicitPath)
	}
	if v, ok := configLookupEnv(getenv, "MUSE_CLI_CONFIG"); ok && strings.TrimSpace(v) != "" {
		return resolveExplicitPath(v)
	}
	var warnings []string
	dir, err := userConfigDir(getenv)
	if err != nil {
		var relErr *relativeXDGError
		if errors.As(err, &relErr) {
			home, herr := configHomeDir(getenv)
			if herr != nil {
				return nil, newConfigErrorf("cannot determine config directory: XDG_CONFIG_HOME is relative and no home directory is available: %v", herr)
			}
			warnings = append(warnings, fmt.Sprintf("XDG_CONFIG_HOME %q is relative; using the default config location", relErr.value))
			// BaseDir already includes the trailing "muse-cli";
			// dir here is the user config dir, so take its parent.
			dir = filepath.Dir(BaseDir(home))
		} else {
			return nil, newConfigErrorf("cannot determine config directory: %v", err)
		}
	}
	configDir := filepath.Join(dir, "muse-cli")
	return &ConfigLocation{
		ConfigFile: filepath.Join(configDir, "config.json"),
		ConfigDir:  configDir,
		Warnings:   warnings,
	}, nil
}

// ResolveConfigLocationWithEnv is ResolveConfigLocation reading the
// process environment.
func ResolveConfigLocationWithEnv(explicitPath string) (*ConfigLocation, error) {
	return ResolveConfigLocation(explicitPath, os.LookupEnv)
}

// RequirePresent enforces the missing-explicit rule: when the
// location came from an explicit path, the config file must exist
// (and not be a directory), else an error (exit 2 at the CLI).
// Non-explicit locations always pass: a missing default/UserConfigDir
// file simply means "no config yet". Phase 2 MUST call this for every
// command except `config migrate --write`, which is the one path
// allowed to create a missing explicit file: for migrate --write,
// call Migrate(loc.ConfigDir, true) directly with no RequirePresent
// gate — Migrate treats a missing file as an empty layout and
// writes the single file at the resolved location. (Migrate dry-run
// does NOT bypass the gate: only --write creates.)
func (loc *ConfigLocation) RequirePresent() error {
	if loc == nil {
		return newConfigError("cannot check a nil config location")
	}
	if !loc.Explicit {
		return nil
	}
	info, err := os.Stat(loc.ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return newConfigErrorf("config file %q does not exist", loc.ConfigFile)
		}
		return newConfigErrorf("cannot stat config file %q: %v", loc.ConfigFile, err)
	}
	if info.IsDir() {
		return newConfigErrorf("config path %q is a directory, not a file", loc.ConfigFile)
	}
	return nil
}

// resolveExplicitPath resolves one explicit config file path: the
// path as given, cleaned lexically (no symlink resolution, no tilde
// expansion, no CWD absolutisation). A directory is an error; a
// missing file is recorded as a location and left for
// RequirePresent to judge.
func resolveExplicitPath(path string) (*ConfigLocation, error) {
	clean := filepath.Clean(path)
	info, err := os.Stat(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return &ConfigLocation{ConfigFile: clean, ConfigDir: filepath.Dir(clean), Explicit: true}, nil
		}
		return nil, newConfigErrorf("cannot stat config file %q: %v", clean, err)
	}
	if info.IsDir() {
		return nil, newConfigErrorf("config path %q is a directory, not a file", clean)
	}
	return &ConfigLocation{ConfigFile: clean, ConfigDir: filepath.Dir(clean), Explicit: true}, nil
}

// relativeXDGError reports a relative XDG_CONFIG_HOME value on the
// Unix branch of userConfigDir. ResolveConfigLocation catches it
// (via errors.As) to warn and fall back; every other
// user-config-dir error is fatal.
type relativeXDGError struct{ value string }

func (e *relativeXDGError) Error() string { return "path in $XDG_CONFIG_HOME is relative" }

// userConfigDir mirrors os.UserConfigDir (Go 1.27, os/file.go)
// through getenv instead of the process environment, so library
// callers and tests can inject the environment. The per-OS rules
// are Go's, verbatim:
//
//   - windows: %APPDATA%; empty → error.
//   - darwin/ios: $HOME + "/Library/Application Support" (XDG is
//     ignored, exactly as in Go); empty $HOME → error.
//   - plan9: $home + "/lib"; empty → error.
//   - Unix (default, incl. Linux and Android): XDG_CONFIG_HOME
//     when non-empty, which must be absolute (relative →
//     *relativeXDGError); empty → $HOME + "/.config"; empty $HOME
//     → error.
//
// No trimming is performed, matching Go: a whitespace-only value is
// a (relative, on Unix) value, not an unset one. This is plain
// portable code — a runtime.GOOS switch, no build constraints, no
// platform syscalls — so it compiles on every target.
func userConfigDir(getenv func(string) (string, bool)) (string, error) {
	get := func(key string) string {
		if v, ok := configLookupEnv(getenv, key); ok {
			return v
		}
		return ""
	}
	switch runtime.GOOS {
	case "windows":
		dir := get("AppData")
		if dir == "" {
			return "", errors.New("%AppData% is not defined")
		}
		return dir, nil
	case "darwin", "ios":
		dir := get("HOME")
		if dir == "" {
			return "", errors.New("$HOME is not defined")
		}
		return filepath.Join(dir, "Library", "Application Support"), nil
	case "plan9":
		dir := get("home")
		if dir == "" {
			return "", errors.New("$home is not defined")
		}
		return filepath.Join(dir, "lib"), nil
	default: // Unix
		dir := get("XDG_CONFIG_HOME")
		if dir == "" {
			dir = get("HOME")
			if dir == "" {
				return "", errors.New("neither $XDG_CONFIG_HOME nor $HOME are defined")
			}
			return filepath.Join(dir, ".config"), nil
		}
		if !filepath.IsAbs(dir) {
			return "", &relativeXDGError{value: dir}
		}
		return dir, nil
	}
}

// configLookupEnv reads one variable through getenv, or the process
// environment when getenv is nil.
func configLookupEnv(getenv func(string) (string, bool), key string) (string, bool) {
	if getenv != nil {
		return getenv(key)
	}
	return os.LookupEnv(key)
}

// configHomeDir returns $HOME through getenv, falling back to
// os.UserHomeDir when it is unset or blank there. It is used only
// for the relative-XDG fallback, which only the Unix branch of
// userConfigDir can produce.
func configHomeDir(getenv func(string) (string, bool)) (string, error) {
	if v, ok := configLookupEnv(getenv, "HOME"); ok && strings.TrimSpace(v) != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", newConfigErrorf("cannot determine home directory: %v", err)
	}
	return home, nil
}
