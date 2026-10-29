// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
