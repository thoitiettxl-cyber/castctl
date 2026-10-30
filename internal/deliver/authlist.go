// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package deliver

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// ProfileRow is one row of the `auth list` output, ported from
// list_profiles (cli.py:111-136). Field order is the Python dict
// order: name, active, dir, exists, cookies, cookies_file,
// auto_approve.
type ProfileRow struct {
	Name        string `json:"name"`
	Active      bool   `json:"active"`
	Dir         string `json:"dir"`
	Exists      bool   `json:"exists"`
	Cookies     bool   `json:"cookies"`
	CookiesFile string `json:"cookies_file"`
	AutoApprove string `json:"auto_approve"`
}

// AuthList is the `--json` form of `auth list`: {"active": ...,
// "profiles": [...]}, ported from cmd_auth_list (cli.py:139-143).
// Field order is the Python dict order.
type AuthList struct {
	Active   string       `json:"active"`
	Profiles []ProfileRow `json:"profiles"`
}

// ListProfiles lists every profile, offline: no network, no
// writes. It mirrors list_profiles exactly: "default" first, then
// the sorted valid profile directories, then the active profile
// appended at the end when it is not already listed (for example
// an active profile whose directory does not exist yet).
//
// Rows come from the profile package: DiscoverProfileNames for
// discovery and LoadProfile for each profile's directory,
// cookies-file path, existence, and auto-approve value. The
// cookies flag is cookies-file existence with a non-zero size, as
// in Python (os.path.getsize > 0; any read error means no
// cookies). LoadProfile is called with a nil environment lookup,
// so no environment fill applies: list_profiles reads config
// values only. A LoadProfile error (for example an unparseable
// single config file) is returned with context; Python's
// list_profiles would instead show defaults for that profile,
// because it reads each config file leniently — the Go profile
// package fails closed on a corrupt config, and this function
// does not second-guess it.
//
// baseDir is the config base directory (the directory holding
// config.json and profiles/); active is the active profile name.
// Both come from the caller, which resolves them through the
// profile package.
func ListProfiles(baseDir, active string) (AuthList, error) {
	names, err := profile.DiscoverProfileNames(baseDir)
	if err != nil {
		return AuthList{}, fmt.Errorf("deliver: list profiles: %w", err)
	}
	found := false
	for _, n := range names {
		if n == active {
			found = true
			break
		}
	}
	if !found {
		names = append(names, active)
	}
	rows := make([]ProfileRow, 0, len(names))
	for _, name := range names {
		p, err := profile.LoadProfile(baseDir, name, nil)
		if err != nil {
			return AuthList{}, fmt.Errorf("deliver: load profile %q: %w", name, err)
		}
		rows = append(rows, ProfileRow{
			Name:        name,
			Active:      name == active,
			Dir:         p.Dir,
			Exists:      p.Exists,
			Cookies:     hasCookies(p.CookiesFile),
			CookiesFile: p.CookiesFile,
			AutoApprove: autoApproveValue(p.AutoApprove),
		})
	}
	return AuthList{Active: active, Profiles: rows}, nil
}

// hasCookies reports whether the cookies file exists and is
// non-empty. Any error (missing file, unreadable file) means no
// cookies, exactly as Python's try/except OSError around
// os.path.getsize.
func hasCookies(cookiesFile string) bool {
	info, err := os.Stat(cookiesFile)
	if err != nil {
		return false
	}
	return info.Size() > 0
}

// autoApproveValue renders the stored auto-approve value the way
// Python does: str(cfg.get("auto_approve") or "off").lower(). The
// profile package stores only "always" or "off"; lowercasing here
// keeps the rendering correct even for an empty value.
func autoApproveValue(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "off"
	}
	return v
}

// FormatAuthList renders the text form of `auth list`, ported
// verbatim from cmd_auth_list (cli.py:144-148): one line per row,
// "* name  state  dir", the name column padded to the widest
// name, the state column padded to width 11, "*" for the active
// profile and " " otherwise. State is "cookies" when the profile
// has a non-empty cookies file, "no cookies" when its directory
// exists without one, and "not created" otherwise. Each line ends
// with a newline, as print does. An empty list renders empty;
// ListProfiles never returns one.
func FormatAuthList(list AuthList) string {
	width := 0
	for _, r := range list.Profiles {
		if n := utf8.RuneCountInString(r.Name); n > width {
			width = n
		}
	}
	var b strings.Builder
	for _, r := range list.Profiles {
		mark := " "
		if r.Active {
			mark = "*"
		}
		state := "not created"
		if r.Cookies {
			state = "cookies"
		} else if r.Exists {
			state = "no cookies"
		}
		fmt.Fprintf(&b, "%s %-*s  %-11s  %s\n", mark, width, r.Name, state, r.Dir)
	}
	return b.String()
}
