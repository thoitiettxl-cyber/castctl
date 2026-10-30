// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func readJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("file %s is not JSON: %v", path, err)
	}
	return m
}

func snapshotDir(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[rel] = data
		return nil
	})
	return out
}

// assertSameSnapshot fails unless two directory snapshots hold
// exactly the same files with exactly the same bytes.
func assertSameSnapshot(t *testing.T, before, after map[string][]byte) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("snapshot file sets differ: before %v, after %v", keysOf(before), keysOf(after))
	}
	for rel, data := range before {
		got, ok := after[rel]
		if !ok {
			t.Fatalf("snapshot lost file %q", rel)
		}
		if string(got) != string(data) {
			t.Fatalf("snapshot file %q changed bytes", rel)
		}
	}
}

func keysOf(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestMigrateFromCrossDir (--from): migration reads legacy profiles
// ONLY from the source dir and writes the single config ONLY to the
// destination dir. The source is never written (byte-for-byte
// identical, including after --write); the destination write is
// atomic mode 0600; refuse-overwrite applies at the destination;
// a dry-run writes nothing anywhere; a missing source dir is an
// exit-2 error; source == destination behaves exactly like Migrate.
func TestMigrateFromCrossDir(t *testing.T) {
	t.Parallel()
	seedSource := func(t *testing.T, home string) string {
		t.Helper()
		src := filepath.Join(home, "muse-cli")
		writeFile(t, filepath.Join(src, "config.json"), `{"auto_approve":"always","node_id":"MAIN-NODE","vm_id":"FAKE-VM"}`, 0o600)
		writeFile(t, filepath.Join(src, "cookies.txt"), "hatch_sess=FAKE-SESS\n", 0o600)
		writeFile(t, filepath.Join(src, "profiles", "muse01", "config.json"), `{"auto_approve":"off","node_id":"MUSE01-NODE"}`, 0o600)
		writeFile(t, filepath.Join(src, "profiles", "muse01", "cookies.txt"), "hatch_sess=FAKE-MUSE01\n", 0o600)
		return src
	}
	namesOf := func(result *MigrateResult) []string {
		names := make([]string, 0, len(result.Profiles))
		for _, p := range result.Profiles {
			names = append(names, p.Name)
		}
		return names
	}

	t.Run("cross-dir dry-run then write", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		src := seedSource(t, home)
		dest := filepath.Join(home, "castctl")
		before := snapshotDir(t, src)

		// Dry-run: plan for both profiles, nothing written anywhere.
		dry, err := MigrateFrom(src, dest, false)
		if err != nil {
			t.Fatal(err)
		}
		if !dry.WouldWrite || dry.Migrated {
			t.Errorf("dry-run = %+v; want would_write, not migrated", dry)
		}
		if got := namesOf(dry); len(got) != 2 || got[0] != "default" || got[1] != "muse01" {
			t.Errorf("dry-run profiles = %v; want [default muse01]", got)
		}
		for _, p := range dry.Profiles {
			if p.Source != "legacy" {
				t.Errorf("dry-run profile %q source = %q; want legacy", p.Name, p.Source)
			}
		}
		if _, err := os.Stat(dest); !os.IsNotExist(err) {
			t.Errorf("dry-run created the destination dir: stat err = %v", err)
		}
		assertSameSnapshot(t, before, snapshotDir(t, src))

		// --write: single config lands in the destination, mode 0600.
		written, err := MigrateFrom(src, dest, true)
		if err != nil {
			t.Fatal(err)
		}
		if !written.Migrated {
			t.Errorf("write = %+v; want migrated", written)
		}
		destFile := filepath.Join(dest, "config.json")
		if mode := fileMode(t, destFile); mode != 0o600 {
			t.Errorf("destination config mode = %o; want 600", mode)
		}
		cfg, found, err := LoadSingleConfig(dest)
		if err != nil || !found {
			t.Fatalf("LoadSingleConfig(dest) = found=%v err=%v", found, err)
		}
		if len(cfg.Profiles) != 2 {
			t.Fatalf("destination profiles = %v; want default + muse01", cfg.ProfileNames())
		}
		// Cookies stay in the source dir; the migrated entries
		// point at them by absolute path.
		if cfg.Profiles["default"].CookiesFile != filepath.Join(src, "cookies.txt") {
			t.Errorf("default cookies_file = %q; want the source cookies file", cfg.Profiles["default"].CookiesFile)
		}
		if cfg.Profiles["muse01"].CookiesFile != filepath.Join(src, "profiles", "muse01", "cookies.txt") {
			t.Errorf("muse01 cookies_file = %q; want the source cookies file", cfg.Profiles["muse01"].CookiesFile)
		}
		// The source is untouched byte-for-byte, including --write.
		assertSameSnapshot(t, before, snapshotDir(t, src))

		// A second write is already-migrated and rewrites nothing.
		st1, _ := os.Stat(destFile)
		again, err := MigrateFrom(src, dest, true)
		if err != nil {
			t.Fatal(err)
		}
		if again.Migrated || again.Reason != "already-migrated" {
			t.Errorf("second run = %+v; want already-migrated", again)
		}
		st2, _ := os.Stat(destFile)
		if !st1.ModTime().Equal(st2.ModTime()) {
			t.Error("second run rewrote the destination file; want no write")
		}
	})

	t.Run("refuse-overwrite at destination", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		src := seedSource(t, home)
		dest := filepath.Join(home, "castctl")
		destFile := filepath.Join(dest, "config.json")
		writeFile(t, destFile, `{"default_profile":"other","profiles":{"other":{"node_id":"OTHER-NODE"}}}`, 0o600)
		beforeDest, _ := os.ReadFile(destFile)
		beforeSrc := snapshotDir(t, src)
		_, err := MigrateFrom(src, dest, true)
		if err == nil {
			t.Fatal("MigrateFrom over a differing destination single config = nil error; want refuse-overwrite")
		}
		if !errors.Is(err, ErrRefuseOverwrite) {
			t.Errorf("MigrateFrom error = %v; want errors.Is ErrRefuseOverwrite", err)
		}
		if ExitCode(err) != 2 {
			t.Errorf("MigrateFrom ExitCode = %d; want 2", ExitCode(err))
		}
		afterDest, _ := os.ReadFile(destFile)
		if string(afterDest) != string(beforeDest) {
			t.Error("refused MigrateFrom modified the destination file")
		}
		assertSameSnapshot(t, beforeSrc, snapshotDir(t, src))
	})

	t.Run("existing destination single refuses additions", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		src := seedSource(t, home)
		dest := filepath.Join(home, "castctl")
		destFile := filepath.Join(dest, "config.json")
		writeFile(t, destFile,
			`{"profiles":{"existing":{"node_id":"EXISTING-NODE"}},"outbounds":[`+validOutbounds["socks"]+`]}`, 0o600)
		beforeDest, _ := os.ReadFile(destFile)
		beforeSrc := snapshotDir(t, src)
		// The one-shot contract applies at the destination too:
		// a differing existing single file refuses, even though
		// the source holds profiles the destination lacks. The
		// operator adds them via profile-add, not migrate.
		_, err := MigrateFrom(src, dest, true)
		if err == nil {
			t.Fatal("MigrateFrom over a differing destination single config = nil error; want refuse-overwrite")
		}
		if !errors.Is(err, ErrRefuseOverwrite) {
			t.Errorf("MigrateFrom error = %v; want errors.Is ErrRefuseOverwrite", err)
		}
		afterDest, _ := os.ReadFile(destFile)
		if string(afterDest) != string(beforeDest) {
			t.Error("refused MigrateFrom modified the destination file")
		}
		assertSameSnapshot(t, beforeSrc, snapshotDir(t, src))
	})

	t.Run("missing source dir", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		dest := filepath.Join(home, "castctl")
		for _, write := range []bool{false, true} {
			_, err := MigrateFrom(filepath.Join(home, "no-such-dir"), dest, write)
			if err == nil {
				t.Fatalf("MigrateFrom(missing source, write=%v) = nil error; want exit 2", write)
			}
			if ExitCode(err) != 2 {
				t.Errorf("MigrateFrom(missing source, write=%v) ExitCode = %d; want 2", write, ExitCode(err))
			}
		}
		if _, err := os.Stat(dest); !os.IsNotExist(err) {
			t.Errorf("missing-source run created the destination: stat err = %v", err)
		}
	})

	t.Run("source is a file", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		fileSrc := filepath.Join(home, "not-a-dir")
		writeFile(t, fileSrc, `{}`, 0o600)
		if _, err := MigrateFrom(fileSrc, filepath.Join(home, "castctl"), false); err == nil {
			t.Fatal("MigrateFrom(file source) = nil error; want exit 2")
		} else if ExitCode(err) != 2 {
			t.Errorf("MigrateFrom(file source) ExitCode = %d; want 2", ExitCode(err))
		}
	})

	t.Run("source equals destination behaves as today", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		base := seedSource(t, home)
		dry, err := MigrateFrom(base, base, false)
		if err != nil || !dry.WouldWrite {
			t.Fatalf("same-dir dry-run = %+v, %v; want would_write", dry, err)
		}
		written, err := MigrateFrom(base, base, true)
		if err != nil || !written.Migrated {
			t.Fatalf("same-dir write = %+v, %v; want migrated", written, err)
		}
		again, err := MigrateFrom(base, base, false)
		if err != nil || again.Reason != "already-migrated" {
			t.Fatalf("same-dir re-run = %+v, %v; want already-migrated", again, err)
		}
	})
}

func TestMigrateDryRun(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	writeFile(t, filepath.Join(base, "config.json"), `{"auto_approve":"always","node_id":"MAIN-NODE","vm_id":"FAKE-VM"}`, 0o600)
	writeFile(t, filepath.Join(base, "cookies.txt"), "hatch_sess=FAKE-SESS; datr=FAKE-DATR\n", 0o600)
	writeFile(t, filepath.Join(base, "profiles", "work", "config.json"), `{"auto_approve":"off","node_id":"WORK-NODE"}`, 0o600)
	writeFile(t, filepath.Join(base, "profiles", "work", "cookies.txt"), "hatch_sess=FAKE-WORK\n", 0o600)
	before := snapshotDir(t, base)

	result, err := Migrate(base, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExistingSingleConfig {
		t.Error("ExistingSingleConfig = true; want false")
	}
	if !result.WouldWrite {
		t.Error("WouldWrite = false; want true for dry-run with legacy profiles")
	}
	if result.Migrated {
		t.Error("Migrated = true on dry-run; want false")
	}
	if result.DefaultProfile != "default" {
		t.Errorf("DefaultProfile = %q; want default", result.DefaultProfile)
	}
	if len(result.Errors) != 0 {
		t.Errorf("Errors = %v; want none", result.Errors)
	}
	if len(result.Profiles) != 2 {
		t.Fatalf("Profiles = %v; want 2", result.Profiles)
	}
	byName := map[string]MigrateProfile{}
	for _, p := range result.Profiles {
		byName[p.Name] = p
	}
	def := byName["default"]
	if def.Source != "legacy" || def.CookiesFile != filepath.Join(base, "cookies.txt") {
		t.Errorf("default migrate entry = %+v", def)
	}
	if def.Outbound != nil {
		t.Errorf("default outbound = %+v; want null for migrated profiles", def.Outbound)
	}
	work := byName["work"]
	if work.Source != "legacy" || work.CookiesFile != filepath.Join(base, "profiles", "work", "cookies.txt") {
		t.Errorf("work migrate entry = %+v", work)
	}
	// Dry-run writes nothing and touches no old file.
	after := snapshotDir(t, base)
	if len(before) != len(after) {
		t.Errorf("dry-run changed file set: before %v after %v", keys(before), keys(after))
	}
	for k, v := range before {
		if string(after[k]) != string(v) {
			t.Errorf("dry-run modified %s", k)
		}
	}
	// Result is JSON-marshalable with the delta shape.
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"would_write", "default_profile", "profiles", "existing_single_config", "errors"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("migrate JSON missing key %q: %s", k, raw)
		}
	}
	profiles, _ := doc["profiles"].([]any)
	if len(profiles) != 2 || profiles[0].(map[string]any)["outbound"] != nil {
		t.Errorf("migrate JSON profiles outbound not null: %s", raw)
	}
}

func keys(m map[string][]byte) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestMigrateWriteAndIdempotent(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	writeFile(t, filepath.Join(base, "config.json"), `{"auto_approve":"always","node_id":"MAIN-NODE"}`, 0o600)
	writeFile(t, filepath.Join(base, "profiles", "work", "config.json"), `{"auto_approve":"off"}`, 0o600)
	before := snapshotDir(t, base)

	result, err := Migrate(base, true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Migrated {
		t.Errorf("Migrated = false; want true: %+v", result)
	}
	if len(result.Generated) != 1 || result.Generated[0] != "work" {
		t.Errorf("Generated = %v; want [work] (work had no node_id)", result.Generated)
	}
	path := filepath.Join(base, "config.json")
	if mode := fileMode(t, path); mode != 0o600 {
		t.Errorf("migrated config mode = %o; want 600", mode)
	}
	doc := readJSONFile(t, path)
	profiles, _ := doc["profiles"].(map[string]any)
	if profiles == nil {
		t.Fatalf("migrated config has no profiles: %v", doc)
	}
	work, _ := profiles["work"].(map[string]any)
	nodeID, _ := work["node_id"].(string)
	if len(nodeID) != 16 || !isHex(nodeID) {
		t.Errorf("generated node_id = %q; want 16 hex chars", nodeID)
	}
	if work["auto_approve"] != "off" {
		t.Errorf("work auto_approve = %v; want off", work["auto_approve"])
	}
	if profiles["default"].(map[string]any)["node_id"] != "MAIN-NODE" {
		t.Errorf("default node_id not preserved: %v", profiles["default"])
	}
	// Old files untouched (never deleted/modified, no node_id written back).
	after := snapshotDir(t, base)
	legacyWork, _ := os.ReadFile(filepath.Join(base, "profiles", "work", "config.json"))
	if strings.Contains(string(legacyWork), "node_id") {
		t.Errorf("legacy work config gained node_id: %s", legacyWork)
	}
	for k, v := range before {
		if k == "config.json" {
			continue // the base config.json IS the single file destination
		}
		if string(after[k]) != string(v) {
			t.Errorf("migrate modified old file %s", k)
		}
	}

	// Second run: already-migrated, no error, no rewrite.
	st1, _ := os.Stat(path)
	result2, err := Migrate(base, true)
	if err != nil {
		t.Fatalf("second migrate error: %v", err)
	}
	if result2.Migrated || result2.Reason != "already-migrated" {
		t.Errorf("second migrate = %+v; want migrated=false reason=already-migrated", result2)
	}
	if !result2.ExistingSingleConfig {
		t.Error("second migrate ExistingSingleConfig = false; want true")
	}
	st2, _ := os.Stat(path)
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Error("second migrate rewrote the file; want no write")
	}

	// Dry-run after migration: would_write false, already-migrated.
	result3, err := Migrate(base, false)
	if err != nil {
		t.Fatal(err)
	}
	if result3.WouldWrite || result3.Reason != "already-migrated" {
		t.Errorf("dry-run after migrate = %+v; want would_write=false already-migrated", result3)
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return len(s) > 0
}

func TestMigrateRefusesDifferentSingleFile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	writeFile(t, filepath.Join(base, "config.json"),
		`{"default_profile":"muse01","profiles":{"muse01":{"auto_approve":"off","node_id":"N1","outbound":{"type":"direct","tag":"direct"}}},"outbounds":[{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1080}]}`, 0o600)
	writeFile(t, filepath.Join(base, "profiles", "work", "config.json"), `{"auto_approve":"off","node_id":"W1"}`, 0o600)
	before, _ := os.ReadFile(filepath.Join(base, "config.json"))

	result, err := Migrate(base, true)
	if err == nil {
		t.Fatal("migrate over different single file = nil error; want refuse-overwrite")
	}
	if !result.ExistingSingleConfig {
		t.Error("ExistingSingleConfig = false; want true")
	}
	after, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if string(before) != string(after) {
		t.Error("refused migrate modified the single file")
	}
	// Dry-run also refuses (nothing would be written).
	if _, err := Migrate(base, false); err == nil {
		t.Error("dry-run over different single file = nil error; want refuse-overwrite")
	}
}

func TestMigrateProfileErrorKeepsGoodProfiles(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	writeFile(t, filepath.Join(base, "config.json"), `{"auto_approve":"always","node_id":"MAIN-NODE"}`, 0o600)
	writeFile(t, filepath.Join(base, "profiles", "bad", "config.json"), `{"auto_approve":42}`, 0o600)
	writeFile(t, filepath.Join(base, "profiles", "good", "config.json"), `{"auto_approve":"off","node_id":"GOOD-NODE"}`, 0o600)

	result, err := Migrate(base, false)
	if err == nil {
		t.Fatal("migrate with bad profile = nil error; want overall error")
	}
	if len(result.Profiles) != 2 {
		t.Fatalf("Profiles = %v; want good + default despite bad profile", result.Profiles)
	}
	names := []string{}
	for _, p := range result.Profiles {
		names = append(names, p.Name)
	}
	if !contains(names, "default") || !contains(names, "good") {
		t.Errorf("Profiles names = %v; want default and good", names)
	}
	if len(result.Errors) == 0 {
		t.Error("Errors empty; want the bad profile error listed")
	}
	for _, e := range result.Errors {
		if strings.Contains(e, "42") {
			// Error text may name the field; must not echo raw file content beyond the value.
		}
	}

	// Write mode with a profile error writes nothing.
	result2, err := Migrate(base, true)
	if err == nil {
		t.Fatal("write migrate with bad profile = nil error; want error")
	}
	if result2.Migrated {
		t.Error("write migrate with error reported Migrated=true")
	}
	if _, err := os.Stat(filepath.Join(base, "profiles")); err != nil {
		t.Fatal(err)
	}
	// Base config.json must still be the legacy flat file (not overwritten).
	doc := readJSONFile(t, filepath.Join(base, "config.json"))
	if _, ok := doc["profiles"]; ok {
		t.Error("write migrate with profile error overwrote the config with a single file")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestMigrateMissingNodeIDListedAsGeneratedOnlyOnWrite(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	writeFile(t, filepath.Join(base, "config.json"), `{"auto_approve":"off"}`, 0o600)

	dry, err := Migrate(base, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(dry.Generated) != 0 {
		t.Errorf("dry-run Generated = %v; dry-run must not invent node_id", dry.Generated)
	}
	def := dry.Profiles[0]
	if def.NodeIDGenerated {
		t.Error("dry-run profile marked node_id generated; want false")
	}

	written, err := Migrate(base, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(written.Generated) != 1 || written.Generated[0] != "default" {
		t.Errorf("write Generated = %v; want [default]", written.Generated)
	}
	doc := readJSONFile(t, filepath.Join(base, "config.json"))
	profiles, _ := doc["profiles"].(map[string]any)
	nodeID, _ := profiles["default"].(map[string]any)["node_id"].(string)
	if len(nodeID) != 16 || !isHex(nodeID) {
		t.Errorf("written node_id = %q; want 16 hex chars", nodeID)
	}
}

func TestMigrateEmptyBase(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	// No files at all: migrate still produces the default profile entry.
	result, err := Migrate(base, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Profiles) != 1 || result.Profiles[0].Name != "default" {
		t.Errorf("Profiles = %+v; want just default", result.Profiles)
	}
	if !result.Profiles[0].NodeIDGenerated {
		t.Error("default node_id not generated on write with no prior config")
	}
	doc := readJSONFile(t, filepath.Join(base, "config.json"))
	if _, ok := doc["profiles"]; !ok {
		t.Errorf("migrated config missing profiles: %v", doc)
	}
}

// TestMigrateSingleFileOnlyIdempotent (NB4) pins migrate idempotency
// when profiles exist ONLY in the single file, with no legacy layout
// on disk: no profiles/ directory, no flat legacy config. A dry-run
// and a write must both report already-migrated, twice in a row, with
// no error and no rewrite. The single files below are in the canonical
// form Migrate itself writes (explicit cookies_file, node_id,
// auto_approve, auto_allow_once), so parsed-equal must mean
// byte-equal after canonicalisation.
func TestMigrateSingleFileOnlyIdempotent(t *testing.T) {
	t.Parallel()
	cookies := func(base, name string) string {
		if name == DefaultProfileName {
			return filepath.Join(base, "cookies.txt")
		}
		return filepath.Join(base, "profiles", name, "cookies.txt")
	}
	cases := []struct {
		name string
		file func(base string) string
	}{
		{
			name: "non-default profile only",
			file: func(base string) string {
				return `{"default_profile":"muse01","profiles":{"muse01":{"cookies_file":` + quoteJSON(cookies(base, "muse01")) + `,"node_id":"MUSE01-NODE","auto_approve":"off","auto_allow_once":false}}}`
			},
		},
		{
			name: "default profile plus outbounds and endpoints",
			file: func(base string) string {
				return `{"profiles":{"default":{"cookies_file":` + quoteJSON(cookies(base, "default")) + `,"node_id":"MAIN-NODE","auto_approve":"always","auto_allow_once":false}},"outbounds":[` + validOutbounds["socks"] + `],"endpoints":[` + validOutbounds["wireguard-ep"] + `]}`
			},
		},
		{
			name: "two single-only profiles, one tagged one direct",
			file: func(base string) string {
				return `{"default_profile":"p1","profiles":{"p1":{"cookies_file":` + quoteJSON(cookies(base, "p1")) + `,"node_id":"N1","auto_approve":"off","auto_allow_once":false,"outbound":"proxy-sg"},"p2":{"cookies_file":` + quoteJSON(cookies(base, "p2")) + `,"node_id":"N2","auto_approve":"off","auto_allow_once":true}},"outbounds":[` + validOutbounds["socks"] + `]}`
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			base := BaseDir(home)
			path := filepath.Join(base, "config.json")
			writeFile(t, path, tc.file(base), 0o600)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			st1, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, write := range []bool{false, true, false, true} {
				result, err := Migrate(base, write)
				if err != nil {
					t.Fatalf("Migrate(write=%v) error: %v (result %+v)", write, err, result)
				}
				if result.Migrated {
					t.Errorf("Migrate(write=%v) Migrated=true; want false (already-migrated)", write)
				}
				if result.Reason != "already-migrated" {
					t.Errorf("Migrate(write=%v) Reason=%q; want already-migrated", write, result.Reason)
				}
				if result.WouldWrite {
					t.Errorf("Migrate(write=%v) WouldWrite=true; want false", write)
				}
				if !result.ExistingSingleConfig {
					t.Errorf("Migrate(write=%v) ExistingSingleConfig=false; want true", write)
				}
				if len(result.Generated) != 0 {
					t.Errorf("Migrate(write=%v) Generated=%v; want none (dry-run and write never invent node_id for an already-migrated file)", write, result.Generated)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Errorf("migrate rewrote the single file:\nbefore: %s\nafter: %s", before, after)
			}
			st2, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !st1.ModTime().Equal(st2.ModTime()) {
				t.Error("migrate rewrote the file; want no write (mtime changed)")
			}
		})
	}
}

func TestMigrateConcurrentWritesExactlyOneWins(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	writeFile(t, filepath.Join(base, "config.json"), `{"auto_approve":"always","node_id":"MAIN-NODE"}`, 0o600)
	writeFile(t, filepath.Join(base, "profiles", "work", "config.json"), `{"auto_approve":"off"}`, 0o600)

	// RT-2: before the lock-across-decide+write fix, several
	// of these runs both exited 0 with different generated
	// node_ids (measured 4 wins out of 8 in the probe).
	const n = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]*MigrateResult, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = Migrate(base, true)
		}(i)
	}
	close(start)
	wg.Wait()
	wins := 0
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("migrate %d: %v", i, errs[i])
		}
		if results[i] == nil {
			t.Errorf("migrate %d: nil result", i)
			continue
		}
		if results[i].Migrated {
			wins++
			if len(results[i].Generated) != 1 || results[i].Generated[0] != "work" {
				t.Errorf("migrate %d: Generated = %v; want [work]", i, results[i].Generated)
			}
		} else if results[i].Reason != "already-migrated" {
			t.Errorf("migrate %d: migrated=false reason=%q; want already-migrated", i, results[i].Reason)
		}
	}
	if wins != 1 {
		t.Errorf("migrate wins = %d; want exactly 1", wins)
	}
	// The winner's generated id is the one persisted: a
	// further migrate reports already-migrated and the file
	// is byte-stable.
	cfg, _, err := LoadSingleConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := cfg.Profiles["work"].NodeID
	if len(nodeID) != 16 || !isHex(nodeID) {
		t.Errorf("final work node_id = %q; want 16 hex chars", nodeID)
	}
	before, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := Migrate(base, true)
	if err != nil {
		t.Fatalf("follow-up migrate: %v", err)
	}
	if again.Migrated || again.Reason != "already-migrated" {
		t.Errorf("follow-up migrate = %+v; want already-migrated", again)
	}
	after, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("follow-up migrate rewrote the file; the winner's ids must already be persisted")
	}
}

// TestMigrateConcurrentWithAddProfile pins the other half of
// RT-2: a `profile add` racing the FIRST `migrate --write` on
// an empty base must survive, whichever order the lock
// serialises them in. Before the fix, migrate's stale-candidate
// SaveSingleConfig could overwrite the add's write, losing the
// added profile while both commands reported success. (A
// legacy-only profile pending beside an existing single file is
// refuse-overwrite by the pre-existing one-shot design, so the
// race that can clobber an add is the first-write race on an
// empty base, where AddProfile is allowed.)
func TestMigrateConcurrentWithAddProfile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	// Empty base: no files at all.

	start := make(chan struct{})
	var wg sync.WaitGroup
	var migrateErr, addErr error
	var migrateResult *MigrateResult
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		migrateResult, migrateErr = Migrate(base, true)
	}()
	go func() {
		defer wg.Done()
		<-start
		_, addErr = AddProfile(base, "work", AddProfileOptions{})
	}()
	close(start)
	wg.Wait()
	if migrateErr != nil {
		t.Fatalf("Migrate: %v", migrateErr)
	}
	if migrateResult == nil {
		t.Fatal("Migrate: nil result")
	}
	if addErr != nil {
		t.Fatalf("AddProfile: %v", addErr)
	}
	cfg, _, err := LoadSingleConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	work, ok := cfg.Profiles["work"]
	if !ok {
		t.Fatalf("final config missing profile %q (clobbered by migrate): %v", "work", cfg.ProfileNames())
	}
	if len(work.NodeID) != 16 || !isHex(work.NodeID) {
		t.Errorf("work node_id = %q; want 16 hex chars", work.NodeID)
	}
}

func quoteJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestMigrateAuthorsDNSWhenSingleDetourServesAllProfiles pins the
// `config migrate` dns extension (INTERIM global section only): when
// the candidate config has no dns section and every profile shares
// one outbound tag, migrate authors the gated default DoH section
// (https to 1.1.1.1, IP-literal, detour = the shared tag). The
// extension fires only on a run that would otherwise be
// already-migrated, so it never rewrites a differing single file
// and never invents a section for a fresh legacy migration.
func TestMigrateAuthorsDNSWhenSingleDetourServesAllProfiles(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	cookies := func(name string) string {
		if name == DefaultProfileName {
			return filepath.Join(base, "cookies.txt")
		}
		return filepath.Join(base, "profiles", name, "cookies.txt")
	}
	entry := func(name string) string {
		return `{"cookies_file":` + quoteJSON(cookies(name)) + `,"node_id":"N1","auto_approve":"off","auto_allow_once":false,"outbound":"proxy-sg"}`
	}
	path := filepath.Join(base, "config.json")
	writeFile(t, path, `{"profiles":{"p1":`+entry("p1")+`,"p2":`+entry("p2")+`},"outbounds":[`+validOutbounds["socks"]+`]}`, 0o600)
	before, _ := os.ReadFile(path)
	st1, _ := os.Stat(path)

	// Dry-run authors nothing but reports that it would.
	dry, err := Migrate(base, false)
	if err != nil {
		t.Fatal(err)
	}
	if !dry.WouldWrite || !dry.DNSAuthored || dry.DNSRefusal != "" {
		t.Errorf("dry-run = %+v; want would_write + dns_authored, no refusal", dry)
	}
	if dry.Reason == "already-migrated" {
		t.Error("dry-run Reason = already-migrated; want none (a dns section would be written)")
	}
	afterDry, _ := os.ReadFile(path)
	if string(before) != string(afterDry) {
		t.Error("dry-run modified the file")
	}

	// --write authors the section atomically, mode 0600.
	written, err := Migrate(base, true)
	if err != nil {
		t.Fatal(err)
	}
	if !written.Migrated || written.Reason != "dns-authored" || !written.DNSAuthored {
		t.Errorf("write = %+v; want migrated + dns-authored", written)
	}
	if mode := fileMode(t, path); mode != 0o600 {
		t.Errorf("migrated config mode = %o; want 600", mode)
	}
	assertAuthoredDNS(t, base)

	// A further run is already-migrated: the authored section is
	// carried verbatim, never re-authored, and the file is untouched.
	st2, _ := os.Stat(path)
	again, err := Migrate(base, true)
	if err != nil {
		t.Fatal(err)
	}
	if again.Migrated || again.Reason != "already-migrated" || again.DNSAuthored {
		t.Errorf("second run = %+v; want already-migrated, no re-authoring", again)
	}
	st3, _ := os.Stat(path)
	if !st2.ModTime().Equal(st3.ModTime()) {
		t.Error("second run rewrote the file; want no write")
	}
	_ = st1
}

// assertAuthoredDNS checks the authored section field by field
// against independent literals: exactly the gated default shape,
// nothing invented beyond it.
func assertAuthoredDNS(t *testing.T, base string) {
	t.Helper()
	cfg, found, err := LoadSingleConfig(base)
	if err != nil || !found {
		t.Fatalf("LoadSingleConfig = found=%v err=%v; want the authored file to load", found, err)
	}
	dnsOpts, err := cfg.ParsedDNS()
	if err != nil {
		t.Fatal(err)
	}
	if dnsOpts == nil || len(dnsOpts.Servers) != 1 {
		t.Fatalf("authored dns servers = %+v; want exactly 1", dnsOpts)
	}
	srv := dnsOpts.Servers[0]
	if srv.Tag != "castctl-doh" || srv.Type != "https" {
		t.Errorf("authored server = tag %q type %q; want castctl-doh/https", srv.Tag, srv.Type)
	}
	// The raw JSON is the shape that lands on disk: verify the
	// literal fields through a re-parse of the file bytes.
	data, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	dnsDoc, _ := doc["dns"].(map[string]any)
	servers, _ := dnsDoc["servers"].([]any)
	if len(servers) != 1 {
		t.Fatalf("dns section in file = %v; want 1 server", dnsDoc)
	}
	server, _ := servers[0].(map[string]any)
	if server["server"] != "1.1.1.1" || server["server_port"] != float64(443) ||
		server["detour"] != "proxy-sg" || server["path"] != "/dns-query" {
		t.Errorf("authored server JSON = %v; want https 1.1.1.1:443 detour proxy-sg path /dns-query", server)
	}
	if dnsDoc["final"] != "castctl-doh" {
		t.Errorf("authored final = %v; want castctl-doh", dnsDoc["final"])
	}
}

func TestMigrateDNSRefusalDirectOnly(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	writeFile(t, filepath.Join(base, "config.json"), `{"auto_approve":"always","node_id":"MAIN-NODE"}`, 0o600)
	writeFile(t, filepath.Join(base, "profiles", "work", "config.json"), `{"auto_approve":"off"}`, 0o600)

	// A fresh legacy migration has no outbound tag to detour
	// through: migrate succeeds and writes NO dns section, but
	// records the refusal naming the first direct-only profile.
	dry, err := Migrate(base, false)
	if err != nil {
		t.Fatal(err)
	}
	if !dry.WouldWrite || dry.DNSAuthored || !strings.Contains(dry.DNSRefusal, `"default"`) {
		t.Errorf("dry-run = %+v; want would_write, no authoring, refusal naming \"default\"", dry)
	}
	written, err := Migrate(base, true)
	if err != nil {
		t.Fatal(err)
	}
	if !written.Migrated || written.DNSAuthored || !strings.Contains(written.DNSRefusal, `"default"`) {
		t.Errorf("write = %+v; want migrated, no authoring, refusal naming \"default\"", written)
	}
	doc := readJSONFile(t, filepath.Join(base, "config.json"))
	if _, ok := doc["dns"]; ok {
		t.Errorf("migrated config gained a dns section: %v", doc)
	}
	// The refusal persists on the already-migrated re-run: the
	// config is still direct-only with no detour to author for.
	again, err := Migrate(base, false)
	if err != nil {
		t.Fatal(err)
	}
	if again.Reason != "already-migrated" || !strings.Contains(again.DNSRefusal, `"default"`) {
		t.Errorf("re-run = %+v; want already-migrated + refusal naming \"default\"", again)
	}
}

func TestMigrateDNSRefusalMultiDetour(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	otherSocks := `{"type":"socks","tag":"proxy-other","server":"127.0.0.1","server_port":1081,"version":"5"}`
	entry := func(name, tag string) string {
		cookies := filepath.Join(base, "profiles", name, "cookies.txt")
		return `{"cookies_file":` + quoteJSON(cookies) + `,"node_id":"N1","auto_approve":"off","auto_allow_once":false,"outbound":"` + tag + `"}`
	}
	path := filepath.Join(base, "config.json")
	writeFile(t, path, `{"profiles":{"p1":`+entry("p1", "proxy-sg")+`,"p2":`+entry("p2", "proxy-other")+`},"outbounds":[`+validOutbounds["socks"]+`,`+otherSocks+`]}`, 0o600)
	before, _ := os.ReadFile(path)
	st1, _ := os.Stat(path)

	// Two different detours: no invented multi-detour section.
	// The run stays already-migrated and the file is untouched.
	for _, write := range []bool{false, true} {
		result, err := Migrate(base, write)
		if err != nil {
			t.Fatal(err)
		}
		if result.Migrated || result.Reason != "already-migrated" || result.DNSAuthored {
			t.Errorf("Migrate(write=%v) = %+v; want already-migrated, no authoring", write, result)
		}
		if !strings.Contains(result.DNSRefusal, `"p2"`) {
			t.Errorf("Migrate(write=%v) DNSRefusal = %q; want it to name \"p2\"", write, result.DNSRefusal)
		}
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("multi-detour migrate rewrote the file")
	}
	st2, _ := os.Stat(path)
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Error("multi-detour migrate rewrote the file; want no write (mtime changed)")
	}
}

// TestMigrateDNSRefusalDirectTaggedDetour (F2): a detour tag that
// resolves to a direct outbound must not be authored into a dns
// section — sing-box rejects a detour to an empty direct outbound
// at runtime, so authoring it writes a config the same binary then
// refuses. Tag references are resolved through outbounds, endpoints,
// and inline profile outbounds; a tag resolving to a non-direct
// outbound still authors (control).
func TestMigrateDNSRefusalDirectTaggedDetour(t *testing.T) {
	t.Parallel()
	directOutbound := `{"type":"direct","tag":"proxy-direct"}`
	writeSingle := func(base, doc string) string {
		path := filepath.Join(base, "config.json")
		writeFile(t, path, doc, 0o600)
		before, _ := os.ReadFile(path)
		return string(before)
	}
	assertNoAuthoring := func(t *testing.T, base, before, refusing string) {
		t.Helper()
		for _, write := range []bool{false, true} {
			result, err := Migrate(base, write)
			if err != nil {
				t.Fatal(err)
			}
			if result.Migrated || result.DNSAuthored || result.Reason != "already-migrated" {
				t.Errorf("Migrate(write=%v) = %+v; want already-migrated, no authoring", write, result)
			}
			if !strings.Contains(result.DNSRefusal, `"`+refusing+`"`) {
				t.Errorf("Migrate(write=%v) DNSRefusal = %q; want it to name %q", write, result.DNSRefusal, refusing)
			}
		}
		after, _ := os.ReadFile(filepath.Join(base, "config.json"))
		if string(after) != before {
			t.Errorf("migrate rewrote the file:\nbefore: %s\nafter: %s", before, after)
		}
		if doc := readJSONFile(t, filepath.Join(base, "config.json")); func() bool { _, ok := doc["dns"]; return ok }() {
			t.Errorf("migrated config gained a dns section: %v", doc)
		}
	}

	t.Run("tag to direct outbound", func(t *testing.T) {
		t.Parallel()
		base := BaseDir(t.TempDir())
		before := writeSingle(base, `{"profiles":{"p1":{"node_id":"N1","auto_approve":"off","auto_allow_once":false,"outbound":"proxy-direct"}},"outbounds":[`+directOutbound+`]}`)
		assertNoAuthoring(t, base, before, "p1")
	})

	t.Run("tag to inline direct outbound", func(t *testing.T) {
		t.Parallel()
		base := BaseDir(t.TempDir())
		before := writeSingle(base, `{"profiles":{"p1":{"node_id":"N1","auto_approve":"off","auto_allow_once":false,"outbound":"profile:p2"},"p2":{"node_id":"N2","auto_approve":"off","auto_allow_once":false,"outbound":{"type":"direct"}}}}`)
		assertNoAuthoring(t, base, before, "p1")
	})

	t.Run("tag to socks outbound still authors", func(t *testing.T) {
		t.Parallel()
		base := BaseDir(t.TempDir())
		path := filepath.Join(base, "config.json")
		writeFile(t, path, `{"profiles":{"p1":{"node_id":"N1","auto_approve":"off","auto_allow_once":false,"outbound":"proxy-sg"}},"outbounds":[`+validOutbounds["socks"]+`]}`, 0o600)
		result, err := Migrate(base, true)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Migrated || !result.DNSAuthored {
			t.Fatalf("socks-detour migrate = %+v; want migrated + dns authored", result)
		}
		assertAuthoredDNS(t, base)
	})
}

// TestDetourTagForProfileResolvesDirectTags pins the resolution
// rule directly: tag references to direct outbounds (list, endpoint,
// or inline) yield no detour; tag references to non-direct targets
// and inline non-direct outbounds yield their tag.
func TestDetourTagForProfileResolvesDirectTags(t *testing.T) {
	t.Parallel()
	doc := `{"profiles":{
		"tagged-direct":{"node_id":"N1","outbound":"proxy-direct"},
		"tagged-socks":{"node_id":"N1","outbound":"proxy-sg"},
		"tagged-inline-direct":{"node_id":"N1","outbound":"profile:inline-direct"},
		"inline-direct":{"node_id":"N1","outbound":{"type":"direct"}},
		"inline-socks":{"node_id":"N1","outbound":{"type":"socks","server":"127.0.0.1","server_port":1080,"version":"5"}},
		"direct-kind":{"node_id":"N1","outbound":"direct"}
	},"outbounds":[{"type":"direct","tag":"proxy-direct"},` + validOutbounds["socks"] + `]}`
	cfg, err := ParseSingleConfig([]byte(doc), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"tagged-direct":        "",
		"tagged-socks":         "proxy-sg",
		"tagged-inline-direct": "",
		"inline-direct":        "",
		"inline-socks":         "profile:inline-socks",
		"direct-kind":          "",
	}
	for name, wantTag := range want {
		if got := detourTagForProfile(cfg, cfg.Profiles[name]); got != wantTag {
			t.Errorf("detourTagForProfile(%q) = %q; want %q", name, got, wantTag)
		}
	}
}

func TestMigrateCarriesExistingDNSVerbatim(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	cookies := filepath.Join(base, "profiles", "p1", "cookies.txt")
	entry := `{"cookies_file":` + quoteJSON(cookies) + `,"node_id":"N1","auto_approve":"off","auto_allow_once":false,"outbound":"proxy-sg"}`
	dnsJSON := `{"servers":[{"type":"https","tag":"dns-remote","server":"1.1.1.1","server_port":443,"path":"/dns-query","detour":"proxy-sg"}],"final":"dns-remote"}`
	path := filepath.Join(base, "config.json")
	writeFile(t, path, `{"profiles":{"p1":`+entry+`},"outbounds":[`+validOutbounds["socks"]+`],"dns":`+dnsJSON+`}`, 0o600)
	before, _ := os.ReadFile(path)

	result, err := Migrate(base, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Migrated || result.Reason != "already-migrated" || result.DNSAuthored || result.DNSRefusal != "" {
		t.Errorf("migrate over existing dns = %+v; want already-migrated, verbatim carryover", result)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Errorf("migrate rewrote the file with an existing dns section:\nbefore: %s\nafter: %s", before, after)
	}
}

func TestMigrateAuthorsDNSInlineAndEndpointDetours(t *testing.T) {
	t.Parallel()
	t.Run("inline outbound detour", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		base := BaseDir(home)
		cookies := filepath.Join(base, "profiles", "p1", "cookies.txt")
		inline := `{"type":"socks","server":"127.0.0.1","server_port":1080,"version":"5"}`
		entry := `{"cookies_file":` + quoteJSON(cookies) + `,"node_id":"N1","auto_approve":"off","auto_allow_once":false,"outbound":` + inline + `}`
		writeFile(t, filepath.Join(base, "config.json"), `{"profiles":{"p1":`+entry+`}}`, 0o600)
		result, err := Migrate(base, true)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Migrated || !result.DNSAuthored {
			t.Fatalf("inline-detour migrate = %+v; want migrated + dns authored", result)
		}
		cfg, _, err := LoadSingleConfig(base)
		if err != nil {
			t.Fatal(err)
		}
		dnsOpts, err := cfg.ParsedDNS()
		if err != nil {
			t.Fatal(err)
		}
		if len(dnsOpts.Servers) != 1 {
			t.Fatalf("authored servers = %+v; want 1", dnsOpts.Servers)
		}
		if got := detourOf(dnsOpts.Servers[0].Options); got != "profile:p1" {
			t.Errorf("authored detour = %q; want profile:p1 (the inline auto-tag)", got)
		}
	})
	t.Run("endpoint detour", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		base := BaseDir(home)
		cookies := filepath.Join(base, "profiles", "p1", "cookies.txt")
		entry := `{"cookies_file":` + quoteJSON(cookies) + `,"node_id":"N1","auto_approve":"off","auto_allow_once":false,"outbound":"wg-home"}`
		writeFile(t, filepath.Join(base, "config.json"), `{"profiles":{"p1":`+entry+`},"endpoints":[`+validOutbounds["wireguard-ep"]+`]}`, 0o600)
		result, err := Migrate(base, true)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Migrated || !result.DNSAuthored {
			t.Fatalf("endpoint-detour migrate = %+v; want migrated + dns authored", result)
		}
		cfg, _, err := LoadSingleConfig(base)
		if err != nil {
			t.Fatal(err)
		}
		dnsOpts, err := cfg.ParsedDNS()
		if err != nil {
			t.Fatal(err)
		}
		if len(dnsOpts.Servers) != 1 {
			t.Fatalf("authored servers = %+v; want 1", dnsOpts.Servers)
		}
		if got := detourOf(dnsOpts.Servers[0].Options); got != "wg-home" {
			t.Errorf("authored detour = %q; want wg-home (the endpoint tag)", got)
		}
	})
}
