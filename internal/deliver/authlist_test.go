// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package deliver_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/deliver"
)

func writeTestFile(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
}

func TestListProfiles(t *testing.T) {
	base := t.TempDir()
	// Default profile: directory exists, non-empty cookies file,
	// config sets auto_approve always.
	writeTestFile(t, filepath.Join(base, "cookies.txt"), "hatch_sess=FAKE; datr=FAKE", 0o600)
	writeTestFile(t, filepath.Join(base, "config.json"), `{"auto_approve": "always"}`, 0o600)
	// Named profile "work": directory exists, empty cookies file.
	writeTestFile(t, filepath.Join(base, "profiles", "work", "cookies.txt"), "", 0o600)
	// Invalid entries under profiles/ are skipped by discovery:
	// a file (not a directory) and a dot-leading directory.
	writeTestFile(t, filepath.Join(base, "profiles", "notadir"), "x", 0o600)
	if err := os.MkdirAll(filepath.Join(base, "profiles", ".hidden"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Active profile "ghost" has no directory: it is appended last.
	list, err := deliver.ListProfiles(base, "ghost")
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if list.Active != "ghost" {
		t.Fatalf("Active = %q, want %q", list.Active, "ghost")
	}
	if got, want := len(list.Profiles), 3; got != want {
		t.Fatalf("len(Profiles) = %d, want %d: %+v", got, want, list.Profiles)
	}
	want := []deliver.ProfileRow{
		{Name: "default", Active: false, Dir: base, Exists: true, Cookies: true, CookiesFile: filepath.Join(base, "cookies.txt"), AutoApprove: "always"},
		{Name: "work", Active: false, Dir: filepath.Join(base, "profiles", "work"), Exists: true, Cookies: false, CookiesFile: filepath.Join(base, "profiles", "work", "cookies.txt"), AutoApprove: "off"},
		{Name: "ghost", Active: true, Dir: filepath.Join(base, "profiles", "ghost"), Exists: false, Cookies: false, CookiesFile: filepath.Join(base, "profiles", "ghost", "cookies.txt"), AutoApprove: "off"},
	}
	for i, w := range want {
		if list.Profiles[i] != w {
			t.Errorf("Profiles[%d] = %+v, want %+v", i, list.Profiles[i], w)
		}
	}
}

func TestListProfilesJSONOrder(t *testing.T) {
	base := t.TempDir()
	list, err := deliver.ListProfiles(base, "default")
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	raw, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"active":"default","profiles":[{"name":"default","active":true,"dir":` + quoteJSON(base) + `,"exists":true,"cookies":false,"cookies_file":` + quoteJSON(filepath.Join(base, "cookies.txt")) + `,"auto_approve":"off"}]}`
	if string(raw) != want {
		t.Errorf("JSON = %s, want %s", raw, want)
	}
}

func quoteJSON(s string) string {
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func TestListProfilesInvalidActive(t *testing.T) {
	if _, err := deliver.ListProfiles(t.TempDir(), ".bad"); err == nil {
		t.Error("ListProfiles with invalid active name: got nil error, want an error")
	}
}

func TestFormatAuthList(t *testing.T) {
	list := deliver.AuthList{
		Active: "default",
		Profiles: []deliver.ProfileRow{
			{Name: "default", Active: true, Dir: "/cfg", Exists: true, Cookies: true},
			{Name: "work", Active: false, Dir: "/cfg/profiles/work", Exists: true},
			{Name: "ghost", Active: false, Dir: "/cfg/profiles/ghost"},
		},
	}
	// Width is the widest name ("default", 7). State is padded to 11.
	want := "* default  cookies      /cfg\n" +
		"  work     no cookies   /cfg/profiles/work\n" +
		"  ghost    not created  /cfg/profiles/ghost\n"
	if got := deliver.FormatAuthList(list); got != want {
		t.Errorf("FormatAuthList =\n%q\nwant\n%q", got, want)
	}
}

func TestFormatAuthListEmpty(t *testing.T) {
	if got := deliver.FormatAuthList(deliver.AuthList{}); got != "" {
		t.Errorf("FormatAuthList(empty) = %q, want empty", got)
	}
}
