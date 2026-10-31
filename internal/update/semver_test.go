// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package update

import (
	"strings"
	"testing"
)

// Slice 1 RED: semver parser + comparison (failure-report §4, D-01..D-10).
// ParseVersion/Compare do not exist yet: this test must fail to compile.

func mustParse(t *testing.T, s string) Version {
	t.Helper()
	v, err := ParseVersion(s)
	if err != nil {
		t.Fatalf("ParseVersion(%q): unexpected error: %v", s, err)
	}
	return v
}

func TestParseVersionValid(t *testing.T) {
	valid := []string{
		"0.6.1", "v1.2.3", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-0",
		"1.0.0+build", "1.0.0-alpha+001", "1.0.0+21AF26D3----117B344092BD",
		"1.0.0-alpha-beta", "1.0.0-0.3.7", "1.0.0-x-y-z.-",
		// Huge numeric components must parse without overflow (D-09).
		"99999999999999999999999999.0.0",
		"1.99999999999999999999999999.0",
	}
	for _, s := range valid {
		if _, err := ParseVersion(s); err != nil {
			t.Errorf("ParseVersion(%q): want valid, got %v", s, err)
		}
	}
	// One leading v is stripped; the canonical form has no v.
	if got := mustParse(t, "v1.2.3").String(); got != "1.2.3" {
		t.Errorf("ParseVersion(v1.2.3).String() = %q, want 1.2.3", got)
	}
	if got := mustParse(t, "1.0.0-alpha+001").String(); got != "1.0.0-alpha+001" {
		t.Errorf("String() = %q, want 1.0.0-alpha+001", got)
	}
}

func TestParseVersionInvalid(t *testing.T) {
	invalid := []string{
		"", "v", ".", "...", "1", "1.0", "v1", "v1.0", "v1.0.0.0",
		"v1.0.0-", "v1.0.0+", "v1.0.0++x", "v1.0.0+é",
		"01.2.3", "v01.2.3", "1.02.3", "1.0.03",
		"1.0.0-01", "1.0.0-alpha.01", "1.0.0-00",
		"V1.0.0", "vv1.0.0", "v 1.0.0", "v1.0.0 ", " v1.0.0",
		"v1.0.0\nInjected", "v1.0.0\r\nx", "v1.0.0\x00x", "v1.0.0\tx",
		"v1..0", "v1.0.0-alpha..1", "v1.0.0-alpha.", "v1.0.0-.alpha",
		"v1.0.0-..", "--help", "-v", "v1.0.0; rm -rf /", "$(id)",
		"1.0.0-", "1.0.0-a_b", "1.0.0-a b", "1.0.0+a_b",
		strings.Repeat("9", 200),              // length cap (D-03)
		"v1.0.0-" + strings.Repeat("a", 1000), // length cap (D-03)
		"v1.0.0-alpha.1 ", "1.0.0-alpha..", "1.0.0+.",
	}
	for _, s := range invalid {
		if v, err := ParseVersion(s); err == nil {
			t.Errorf("ParseVersion(%q): want error, got %v", s, v)
		}
	}
	// Missing tag_name (empty) must never parse as version 0 (D-10).
	if _, err := ParseVersion(""); err == nil {
		t.Error("empty version must be invalid")
	}
}

func TestCompareVersionOrdering(t *testing.T) {
	// The semver 2.0.0 precedence chain (D-07).
	chain := []string{
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
	}
	for i := 0; i < len(chain); i++ {
		for j := 0; j < len(chain); j++ {
			a, b := mustParse(t, chain[i]), mustParse(t, chain[j])
			got := CompareVersions(a, b)
			var want int
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if (got < 0) != (want < 0) || (got > 0) != (want > 0) {
				t.Errorf("Compare(%s, %s) = %d, want sign %d", chain[i], chain[j], got, want)
			}
		}
	}
	pairs := []struct {
		a, b string
		want int // sign of Compare(a,b)
	}{
		{"1.10.0", "1.9.0", 1}, // numeric, not lexical (D-06)
		{"1.9.0", "1.10.0", -1},
		{"1.0.0+build1", "1.0.0+build2", 0}, // build ignored (D-08)
		{"1.0.0+build", "1.0.0", 0},
		{"1.0.0-alpha+001", "1.0.0", -1},
		{"1.0.0-1", "1.0.0-alpha", -1}, // numeric < alphanumeric
		{"1.0.0-alpha.10", "1.0.0-alpha.2", 1},
		{"1.0.0-alpha.1", "1.0.0-alpha.2", -1},
		{"2.0.0", "1.99999999999999999999999999.0", 1}, // huge numerics (D-09)
		{"v1.0.0", "1.0.0", 0},                         // v-strip both sides
		{"0.6.4", "0.6.3", 1},
		{"0.6.3", "0.6.3", 0},
		{"0.6.2", "0.6.3", -1},
	}
	for _, p := range pairs {
		got := CompareVersions(mustParse(t, p.a), mustParse(t, p.b))
		if (got < 0) != (p.want < 0) || (got > 0) != (p.want > 0) {
			t.Errorf("Compare(%s, %s) = %d, want sign %d", p.a, p.b, got, p.want)
		}
	}
}

func TestVersionCoreAndPrerelease(t *testing.T) {
	v := mustParse(t, "1.2.3-rc.1+build.5")
	if v.Core() != "1.2.3" {
		t.Errorf("Core() = %q, want 1.2.3", v.Core())
	}
	if v.Prerelease() != "rc.1" {
		t.Errorf("Prerelease() = %q, want rc.1", v.Prerelease())
	}
	if !v.HasBuild() {
		t.Error("HasBuild() = false, want true")
	}
	plain := mustParse(t, "1.2.3")
	if plain.Prerelease() != "" || plain.HasBuild() {
		t.Errorf("plain version: prerelease=%q build=%v", plain.Prerelease(), plain.HasBuild())
	}
	if plain.AssetVersion() != "1.2.3" {
		t.Errorf("AssetVersion() = %q, want 1.2.3", plain.AssetVersion())
	}
	if v.AssetVersion() != "1.2.3-rc.1" {
		t.Errorf("AssetVersion() = %q, want 1.2.3-rc.1", v.AssetVersion())
	}
}
