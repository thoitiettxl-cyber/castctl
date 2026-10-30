// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// No t.Parallel in this file: tests use t.Setenv and t.Chdir, and
// must never touch the real user config home.

// mustUserConfigDir returns os.UserConfigDir under the test's
// t.Setenv-controlled process environment, or fails the test.
func mustUserConfigDir(t *testing.T) string {
	t.Helper()
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("os.UserConfigDir: %v", err)
	}
	return dir
}

func mustStatConfig(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(`{"profiles":{"default":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolveConfigLocationPrecedence(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	envPath := filepath.Join(t.TempDir(), "env", "config.json")
	paramPath := filepath.Join(t.TempDir(), "param", "config.json")

	// Injected-environment precedence only: every case here is
	// decided by the explicit parameter or MUSE_CLI_CONFIG, or by
	// an absolute XDG_CONFIG_HOME. Default-home and relative-XDG
	// cases live in the process-environment tests below, where
	// expectations come from os.UserConfigDir() itself.
	cases := []struct {
		name     string
		explicit string
		env      map[string]string
		wantFile string
		wantDir  string
		wantExpl bool
		wantWarn bool
		wantErr  bool
	}{
		{
			name:     "XDG alone",
			env:      map[string]string{"HOME": home, "XDG_CONFIG_HOME": xdg},
			wantFile: filepath.Join(xdg, "muse-cli", "config.json"),
			wantDir:  filepath.Join(xdg, "muse-cli"),
		},
		{
			name:     "env alone",
			env:      map[string]string{"HOME": home, "MUSE_CLI_CONFIG": envPath},
			wantFile: envPath, wantDir: filepath.Dir(envPath), wantExpl: true,
		},
		{
			name:     "explicit alone",
			explicit: paramPath,
			env:      map[string]string{"HOME": home},
			wantFile: paramPath, wantDir: filepath.Dir(paramPath), wantExpl: true,
		},
		{
			name:     "explicit beats env",
			explicit: paramPath,
			env:      map[string]string{"HOME": home, "MUSE_CLI_CONFIG": envPath},
			wantFile: paramPath, wantDir: filepath.Dir(paramPath), wantExpl: true,
		},
		{
			name:     "explicit beats XDG",
			explicit: paramPath,
			env:      map[string]string{"HOME": home, "XDG_CONFIG_HOME": xdg},
			wantFile: paramPath, wantDir: filepath.Dir(paramPath), wantExpl: true,
		},
		{
			name:     "env beats XDG",
			env:      map[string]string{"HOME": home, "MUSE_CLI_CONFIG": envPath, "XDG_CONFIG_HOME": xdg},
			wantFile: envPath, wantDir: filepath.Dir(envPath), wantExpl: true,
		},
		{
			name:     "empty explicit falls through to env",
			explicit: "",
			env:      map[string]string{"HOME": home, "MUSE_CLI_CONFIG": envPath},
			wantFile: envPath, wantDir: filepath.Dir(envPath), wantExpl: true,
		},
		{
			name:     "explicit is a directory",
			explicit: home,
			env:      map[string]string{"HOME": home},
			wantErr:  true,
		},
		{
			name:    "env is a directory",
			env:     map[string]string{"HOME": home, "MUSE_CLI_CONFIG": home},
			wantErr: true,
		},
		{
			name:     "empty env falls through to XDG",
			env:      map[string]string{"HOME": home, "MUSE_CLI_CONFIG": "", "XDG_CONFIG_HOME": xdg},
			wantFile: filepath.Join(xdg, "muse-cli", "config.json"),
			wantDir:  filepath.Join(xdg, "muse-cli"),
		},
		{
			name:     "tilde is not expanded",
			explicit: "~/cfg.json",
			env:      map[string]string{"HOME": home},
			wantFile: "~/cfg.json", wantDir: "~", wantExpl: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loc, err := ResolveConfigLocation(tc.explicit, lookupEnv(tc.env))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ResolveConfigLocation = %+v, want error", loc)
				}
				if ExitCode(err) != 2 {
					t.Fatalf("ExitCode = %d, want 2", ExitCode(err))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if loc.ConfigFile != tc.wantFile {
				t.Errorf("ConfigFile = %q, want %q", loc.ConfigFile, tc.wantFile)
			}
			if loc.ConfigDir != tc.wantDir {
				t.Errorf("ConfigDir = %q, want %q", loc.ConfigDir, tc.wantDir)
			}
			if loc.Explicit != tc.wantExpl {
				t.Errorf("Explicit = %v, want %v", loc.Explicit, tc.wantExpl)
			}
			if tc.wantWarn {
				if len(loc.Warnings) != 1 || !strings.Contains(loc.Warnings[0], "relative") || !strings.Contains(loc.Warnings[0], "rel/xdg") {
					t.Errorf("Warnings = %v, want one relative-XDG warning naming the value", loc.Warnings)
				}
			} else if len(loc.Warnings) != 0 {
				t.Errorf("Warnings = %v, want none", loc.Warnings)
			}
		})
	}
}

func TestResolveConfigLocationFromProcessEnv(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	envPath := filepath.Join(t.TempDir(), "env", "config.json")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("MUSE_CLI_CONFIG", envPath)

	// Env beats XDG through the real process environment.
	loc, err := ResolveConfigLocationWithEnv("")
	if err != nil {
		t.Fatal(err)
	}
	if loc.ConfigFile != envPath || !loc.Explicit {
		t.Fatalf("ConfigFile = %q Explicit = %v, want %q true", loc.ConfigFile, loc.Explicit, envPath)
	}
	// An explicit parameter beats the env var.
	param := filepath.Join(t.TempDir(), "param", "config.json")
	loc, err = ResolveConfigLocationWithEnv(param)
	if err != nil {
		t.Fatal(err)
	}
	if loc.ConfigFile != param {
		t.Fatalf("ConfigFile = %q, want %q", loc.ConfigFile, param)
	}
}

func TestResolveConfigLocationDefaultRegression(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("MUSE_CLI_CONFIG", "")
	loc, err := ResolveConfigLocationWithEnv("")
	if err != nil {
		t.Fatal(err)
	}
	// The default is Join(os.UserConfigDir(), "muse-cli") under the
	// controlled environment — computed from the platform API, never
	// from a hardcoded home path.
	wantDir := filepath.Join(mustUserConfigDir(t), "muse-cli")
	if loc.ConfigDir != wantDir {
		t.Fatalf("ConfigDir = %q, want %q (os.UserConfigDir-derived)", loc.ConfigDir, wantDir)
	}
	if loc.ConfigFile != filepath.Join(wantDir, "config.json") {
		t.Fatalf("ConfigFile = %q, want %q", loc.ConfigFile, filepath.Join(wantDir, "config.json"))
	}
	if loc.Explicit {
		t.Fatal("Explicit = true, want false for the default location")
	}
	if len(loc.Warnings) != 0 {
		t.Fatalf("Warnings = %v, want none", loc.Warnings)
	}
}

func TestResolveConfigLocationXDGFromProcessEnv(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("MUSE_CLI_CONFIG", "")
	loc, err := ResolveConfigLocationWithEnv("")
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(mustUserConfigDir(t), "muse-cli")
	if loc.ConfigDir != wantDir || wantDir != filepath.Join(xdg, "muse-cli") {
		t.Fatalf("ConfigDir = %q, want os.UserConfigDir-derived %q", loc.ConfigDir, wantDir)
	}
	if loc.Explicit {
		t.Fatal("Explicit = true, want false for an XDG location")
	}
}

func TestResolveConfigLocationXDGEmptyFromProcessEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("MUSE_CLI_CONFIG", "")
	loc, err := ResolveConfigLocationWithEnv("")
	if err != nil {
		t.Fatal(err)
	}
	if loc.ConfigDir != filepath.Join(mustUserConfigDir(t), "muse-cli") {
		t.Fatalf("ConfigDir = %q, want the os.UserConfigDir-derived default", loc.ConfigDir)
	}
}

func TestResolveConfigLocationXDGRelativeFromProcessEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "rel/xdg")
	t.Setenv("MUSE_CLI_CONFIG", "")
	loc, err := ResolveConfigLocationWithEnv("")
	if err != nil {
		t.Fatal(err)
	}
	// Relative XDG is ignored with a visible warning; the fallback
	// is the computed $HOME-based default.
	if len(loc.Warnings) != 1 || !strings.Contains(loc.Warnings[0], "relative") || !strings.Contains(loc.Warnings[0], "rel/xdg") {
		t.Fatalf("Warnings = %v, want one relative-XDG warning naming the value", loc.Warnings)
	}
	if loc.ConfigDir != BaseDir(home) {
		t.Fatalf("ConfigDir = %q, want the $HOME-based fallback %q", loc.ConfigDir, BaseDir(home))
	}
	if loc.Explicit {
		t.Fatal("Explicit = true, want false for the fallback location")
	}
}

func TestResolveConfigLocationXDGRootFromProcessEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "/")
	t.Setenv("MUSE_CLI_CONFIG", "")
	loc, err := ResolveConfigLocationWithEnv("")
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(mustUserConfigDir(t), "muse-cli")
	if loc.ConfigDir != wantDir {
		t.Fatalf("ConfigDir = %q, want %q (XDG root treated literally)", loc.ConfigDir, wantDir)
	}
}

func TestResolveConfigLocationNoUsableHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("MUSE_CLI_CONFIG", "")
	_, err := ResolveConfigLocationWithEnv("")
	if err == nil {
		t.Fatal("ResolveConfigLocation = nil error, want an error with no usable home")
	}
	if ExitCode(err) != 2 {
		t.Fatalf("ExitCode = %d, want 2", ExitCode(err))
	}
	if !strings.Contains(err.Error(), "cannot determine config directory") {
		t.Fatalf("error = %q, want a clear config-directory error", err)
	}
}

func TestResolveConfigLocationRelativeXDGNoHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "rel/xdg")
	t.Setenv("MUSE_CLI_CONFIG", "")
	_, err := ResolveConfigLocationWithEnv("")
	if err == nil {
		t.Fatal("ResolveConfigLocation = nil error, want an error (relative XDG, no home for the fallback)")
	}
	if ExitCode(err) != 2 {
		t.Fatalf("ExitCode = %d, want 2", ExitCode(err))
	}
}

func TestResolveConfigLocationRelativeExplicit(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.MkdirAll("sub", 0o755); err != nil {
		t.Fatal(err)
	}
	mustStatConfig(t, "sub/config.json")
	loc, err := ResolveConfigLocation("sub/config.json", lookupEnv(map[string]string{"HOME": root}))
	if err != nil {
		t.Fatal(err)
	}
	if loc.ConfigFile != "sub/config.json" || loc.ConfigDir != "sub" {
		t.Fatalf("ConfigFile = %q ConfigDir = %q, want sub/config.json and sub (CWD-relative)", loc.ConfigFile, loc.ConfigDir)
	}
	if err := loc.RequirePresent(); err != nil {
		t.Fatalf("RequirePresent = %v, want nil", err)
	}
}

func TestResolveConfigLocationSymlink(t *testing.T) {
	realDir := filepath.Join(t.TempDir(), "real")
	linkDir := filepath.Join(t.TempDir(), "link")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustStatConfig(t, filepath.Join(realDir, "config.json"))
	linkPath := filepath.Join(linkDir, "config.json")
	if err := os.Symlink(filepath.Join(realDir, "config.json"), linkPath); err != nil {
		t.Fatal(err)
	}
	loc, err := ResolveConfigLocation(linkPath, lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	// CONFIG_DIR is the as-given directory: symlinks are not resolved
	// for display paths.
	if loc.ConfigDir != linkDir || loc.ConfigFile != linkPath {
		t.Fatalf("ConfigDir = %q ConfigFile = %q, want as-given %q %q", loc.ConfigDir, loc.ConfigFile, linkDir, linkPath)
	}
	// Opening follows the symlink with standard open semantics.
	if _, found, err := LoadSingleConfig(loc.ConfigDir); err != nil || !found {
		t.Fatalf("LoadSingleConfig = found=%v err=%v, want the symlinked file parsed", found, err)
	}
}

func TestRequirePresentMissingExplicit(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing", "config.json")
	loc, err := ResolveConfigLocation(missing, lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := loc.RequirePresent(); err == nil {
		t.Fatal("RequirePresent = nil, want an error for a missing explicit file")
	} else if ExitCode(err) != 2 {
		t.Fatalf("ExitCode = %d, want 2", ExitCode(err))
	}
	// A missing non-explicit location is fine: no config yet.
	def, err := ResolveConfigLocation("", lookupEnv(map[string]string{"HOME": t.TempDir()}))
	if err != nil {
		t.Fatal(err)
	}
	if err := def.RequirePresent(); err != nil {
		t.Fatalf("RequirePresent (default) = %v, want nil", err)
	}
}

func TestMigrateWriteCreatesMissingExplicit(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing", "config.json")
	loc, err := ResolveConfigLocation(missing, lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := loc.RequirePresent(); err == nil {
		t.Fatal("RequirePresent = nil before migrate, want an error")
	}
	// The migrate --write path bypasses RequirePresent and writes
	// the single file at the resolved location.
	res, err := Migrate(loc.ConfigDir, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Migrated {
		t.Fatalf("Migrate = %+v, want Migrated=true", res)
	}
	if _, err := os.Stat(loc.ConfigFile); err != nil {
		t.Fatalf("config file at resolved location: %v", err)
	}
	if err := loc.RequirePresent(); err != nil {
		t.Fatalf("RequirePresent after migrate = %v, want nil", err)
	}
	// A second migrate is already-migrated at the resolved location.
	res, err = Migrate(loc.ConfigDir, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Migrated || res.Reason != "already-migrated" {
		t.Fatalf("second Migrate = %+v, want already-migrated", res)
	}
}

func TestRelativeCookiesFileUnderCustomConfigDir(t *testing.T) {
	base := t.TempDir()
	seedSingleFile(t, base, `{"profiles":{"default":{"cookies_file":"relcookies.txt"},"work":{"cookies_file":"relcookies.txt"}}}`)
	// Default profile: relative resolves under the resolved dir.
	def, err := LoadProfile(base, "default", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "relcookies.txt")
	if def.CookiesFile != want {
		t.Fatalf("CookiesFile = %q, want %q", def.CookiesFile, want)
	}
	fake := `{"cookies":{"hatch_sess":"FAKESESS","datr":"FAKEDATR"}}`
	if err := os.WriteFile(want, []byte(fake), 0o600); err != nil {
		t.Fatal(err)
	}
	// The resolved file must hold the fake cookies that were
	// written there; parsing the header is gateway.LoadCookies'
	// job (tested there), not this package's.
	rawCookies, err := os.ReadFile(def.CookiesFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawCookies), "FAKESESS") || !strings.Contains(string(rawCookies), "FAKEDATR") {
		t.Fatalf("cookies file = %q, want the fake cookies", rawCookies)
	}
	// Named profile: the coercion still applies within the
	// resolved dir — a value inside the dir cannot borrow the
	// default profile's login.
	work, err := LoadProfile(base, "work", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	wantWork := filepath.Join(base, "profiles", "work", "cookies.txt")
	if work.CookiesFile != wantWork {
		t.Fatalf("CookiesFile (work) = %q, want coerced %q", work.CookiesFile, wantWork)
	}
}

func TestAbsoluteCookiesFileHonoured(t *testing.T) {
	base := t.TempDir()
	abs := filepath.Join(t.TempDir(), "elsewhere", "cookies.txt")
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(`{"cookies":{"hatch_sess":"ABSSESS"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	seedSingleFile(t, base, `{"profiles":{"default":{"cookies_file":`+strconv.Quote(abs)+`}}}`)
	p, err := LoadProfile(base, "default", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if p.CookiesFile != abs {
		t.Fatalf("CookiesFile = %q, want absolute %q honoured as-is", p.CookiesFile, abs)
	}
	rawCookies, err := os.ReadFile(p.CookiesFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawCookies), "ABSSESS") {
		t.Fatalf("cookies file = %q, want the fake cookies", rawCookies)
	}
}

func TestProfileResolutionUnchangedInCustomHome(t *testing.T) {
	base := t.TempDir()
	seedSingleFile(t, base, `{"default_profile":"work","profiles":{"default":{},"work":{}}}`)
	// default_profile wins when neither flag nor env names a profile.
	p, err := ResolveActiveProfile(base, nil, lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "work" {
		t.Fatalf("active = %q, want work via default_profile", p.Name)
	}
	// MUSE_CLI_PROFILE wins over default_profile.
	p, err = ResolveActiveProfile(base, nil, lookupEnv(map[string]string{"MUSE_CLI_PROFILE": "default"}))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "default" {
		t.Fatalf("active = %q, want default via MUSE_CLI_PROFILE", p.Name)
	}
	// --profile flag wins over both.
	flag := "work"
	p, err = ResolveActiveProfile(base, &flag, lookupEnv(map[string]string{"MUSE_CLI_PROFILE": "default"}))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "work" {
		t.Fatalf("active = %q, want work via flag", p.Name)
	}
	// Derived paths still flow from the custom dir.
	if p.Dir != filepath.Join(base, "profiles", "work") {
		t.Fatalf("Dir = %q, want the custom-dir profile dir", p.Dir)
	}
}
