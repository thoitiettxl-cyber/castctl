// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package update

import (
	"errors"
	"strings"
)

// Hand-written semver 2.0.0 parser (stdlib only). golang.org/x/mod/semver
// is an external module and must not become a direct dependency; go/version
// compares Go toolchain versions, not release tags. The parser is strict:
// it returns an error for every invalid input instead of adopting
// x/mod/semver's "invalid < valid" ordering, so a hostile tag_name can
// never silently order as older (or equal) to a real version.
//
// Rules pinned here (failure-report §4/§11): one optional leading 'v'
// is stripped; the core is exactly three dot-separated numeric
// components with no leading zeros; prerelease identifiers are
// [0-9A-Za-z-] with no leading zeros on numeric identifiers; build
// metadata is validated but ignored for precedence; no whitespace
// trimming, no lowercasing, no shorthand, no length-unbounded input.

// maxVersionLen bounds a tag before any parsing or allocation: real
// castctl tags are under 30 characters.
const maxVersionLen = 128

// Version is a parsed semantic version.
type Version struct {
	major string
	minor string
	patch string
	pre   []string // nil when absent
	build string   // "" when absent; an empty build is invalid, never stored
}

// ParseVersion parses s as a semantic version, stripping one leading 'v'.
func ParseVersion(s string) (Version, error) {
	if len(s) == 0 || len(s) > maxVersionLen {
		return Version{}, errors.New("update: invalid version")
	}
	rest := strings.TrimPrefix(s, "v")
	// Split build metadata at the FIRST '+': a second '+' lands in the
	// build part and fails the identifier charset check below.
	var build string
	if i := strings.IndexByte(rest, '+'); i >= 0 {
		build = rest[i+1:]
		rest = rest[:i]
		if build == "" {
			return Version{}, errors.New("update: invalid version")
		}
		if err := checkDotIdents(build, false); err != nil {
			return Version{}, err
		}
	}
	// Split prerelease at the FIRST '-' after the core: "alpha-1" is
	// one identifier, not two.
	var pre []string
	if i := strings.IndexByte(rest, '-'); i >= 0 {
		prePart := rest[i+1:]
		rest = rest[:i]
		if prePart == "" {
			return Version{}, errors.New("update: invalid version")
		}
		if err := checkDotIdents(prePart, true); err != nil {
			return Version{}, err
		}
		pre = strings.Split(prePart, ".")
	}
	core := strings.Split(rest, ".")
	if len(core) != 3 {
		return Version{}, errors.New("update: invalid version")
	}
	for _, c := range core {
		if !isNumericIdent(c) {
			return Version{}, errors.New("update: invalid version")
		}
	}
	return Version{major: core[0], minor: core[1], patch: core[2], pre: pre, build: build}, nil
}

func checkDotIdents(s string, prerelease bool) error {
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return errors.New("update: invalid version")
		}
		for i := 0; i < len(id); i++ {
			c := id[i]
			if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '-') {
				return errors.New("update: invalid version")
			}
		}
		if prerelease && isAllDigits(id) && !isNumericIdent(id) {
			return errors.New("update: invalid version")
		}
	}
	return nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isNumericIdent reports whether s is a valid numeric component:
// digits only, no leading zeros except the single digit "0".
func isNumericIdent(s string) bool {
	if !isAllDigits(s) {
		return false
	}
	return len(s) == 1 || s[0] != '0'
}

// compareNumeric compares two validated numeric strings without
// converting to int, so arbitrarily long components cannot overflow.
func compareNumeric(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// CompareVersions returns -1, 0, or 1 by semver precedence. Build
// metadata is ignored.
func CompareVersions(a, b Version) int {
	if c := compareNumeric(a.major, b.major); c != 0 {
		return c
	}
	if c := compareNumeric(a.minor, b.minor); c != 0 {
		return c
	}
	if c := compareNumeric(a.patch, b.patch); c != 0 {
		return c
	}
	switch {
	case a.pre == nil && b.pre == nil:
		return 0
	case a.pre == nil:
		return 1 // release > prerelease
	case b.pre == nil:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		if x == y {
			continue
		}
		xNum, yNum := isAllDigits(x), isAllDigits(y)
		switch {
		case xNum && yNum:
			return compareNumeric(x, y)
		case xNum:
			return -1 // numeric < alphanumeric
		case yNum:
			return 1
		default:
			return strings.Compare(x, y)
		}
	}
	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	default:
		return 0
	}
}

// String renders the canonical form: core, prerelease, and build
// metadata when present; never a leading 'v'.
func (v Version) String() string {
	s := v.major + "." + v.minor + "." + v.patch
	if v.pre != nil {
		s += "-" + strings.Join(v.pre, ".")
	}
	if v.build != "" {
		s += "+" + v.build
	}
	return s
}

// Core returns "major.minor.patch".
func (v Version) Core() string { return v.major + "." + v.minor + "." + v.patch }

// Prerelease returns the prerelease part without the '-', or "".
func (v Version) Prerelease() string {
	if v.pre == nil {
		return ""
	}
	return strings.Join(v.pre, ".")
}

// HasBuild reports whether build metadata was present.
func (v Version) HasBuild() bool { return v.build != "" }

// AssetVersion returns the version as it appears in release asset
// names: core plus prerelease, without build metadata (the release
// workflow's tag regex rejects '+', so no published asset name
// carries build metadata).
func (v Version) AssetVersion() string {
	s := v.Core()
	if v.pre != nil {
		s += "-" + strings.Join(v.pre, ".")
	}
	return s
}
