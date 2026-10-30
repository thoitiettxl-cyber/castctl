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
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
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
// TestMigrateRefusesNonRegularFiles (R3): migrateLegacyProfile and
// readExistingSingle must Stat/type-guard before opening a
// config.json path. A FIFO at a named profile path must make a
// migrate dry-run fail promptly with a profile error naming the
// profile (never hang); a FIFO or symlink-to-FIFO at the base
// path must make it fail promptly with an exit-2 error naming the
// path. A directory at a named path keeps its exit-2 error.
func TestMigrateRefusesNonRegularFiles(t *testing.T) {
	t.Parallel()

	runMigratePrompt := func(t *testing.T, base string) (*MigrateResult, error) {
		t.Helper()
		type outcome struct {
			result *MigrateResult
			err    error
		}
		done := make(chan outcome, 1)
		go func() {
			result, err := Migrate(base, false)
			done <- outcome{result, err}
		}()
		select {
		case o := <-done:
			return o.result, o.err
		case <-time.After(5 * time.Second):
			t.Fatal("Migrate hung; want a prompt exit-2 error")
			return nil, nil
		}
	}

	// FIFO at a named profile path: profile error, promptly.
	fifoBase := BaseDir(t.TempDir())
	fifoPath := filepath.Join(fifoBase, "profiles", "work", "config.json")
	if err := os.MkdirAll(filepath.Dir(fifoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := runMigratePrompt(t, fifoBase)
	if err == nil {
		t.Fatalf("Migrate over a named FIFO = nil error; want a profile error")
	}
	if ExitCode(err) != 2 {
		t.Errorf("Migrate over a named FIFO ExitCode = %d; want 2", ExitCode(err))
	}
	if result == nil || len(result.Errors) == 0 || !strings.Contains(strings.Join(result.Errors, " "), "work") {
		t.Errorf("Migrate over a named FIFO errors = %v; want a profile error naming \"work\"", result.Errors)
	}

	// Symlink to a FIFO at a named profile path: same, promptly.
	linkBase := BaseDir(t.TempDir())
	realFIFO := filepath.Join(t.TempDir(), "real-fifo")
	if err := syscall.Mkfifo(realFIFO, 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(linkBase, "profiles", "work", "config.json")
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realFIFO, linkPath); err != nil {
		t.Fatal(err)
	}
	result, err = runMigratePrompt(t, linkBase)
	if err == nil {
		t.Fatalf("Migrate over a symlink-to-FIFO named path = nil error; want a profile error")
	}
	if ExitCode(err) != 2 {
		t.Errorf("Migrate over a symlink-to-FIFO named path ExitCode = %d; want 2", ExitCode(err))
	}
	if result == nil || len(result.Errors) == 0 || !strings.Contains(strings.Join(result.Errors, " "), "work") {
		t.Errorf("Migrate over a symlink-to-FIFO named path errors = %v; want a profile error naming \"work\"", result.Errors)
	}

	// FIFO at the base path: exit-2 error naming the path, promptly.
	baseFIFO := BaseDir(t.TempDir())
	baseFIFOPath := filepath.Join(baseFIFO, "config.json")
	if err := os.MkdirAll(baseFIFO, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(baseFIFOPath, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = runMigratePrompt(t, baseFIFO)
	if err == nil {
		t.Fatal("Migrate over a base FIFO = nil error; want exit 2")
	}
	if ExitCode(err) != 2 {
		t.Errorf("Migrate over a base FIFO ExitCode = %d; want 2", ExitCode(err))
	}
	if !strings.Contains(err.Error(), baseFIFOPath) {
		t.Errorf("Migrate over a base FIFO error = %q; want it to name %q", err.Error(), baseFIFOPath)
	}

	// Symlink to a FIFO at the base path: same, promptly.
	baseLink := BaseDir(t.TempDir())
	realBaseFIFO := filepath.Join(t.TempDir(), "real-base-fifo")
	if err := syscall.Mkfifo(realBaseFIFO, 0o600); err != nil {
		t.Fatal(err)
	}
	baseLinkPath := filepath.Join(baseLink, "config.json")
	if err := os.MkdirAll(baseLink, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realBaseFIFO, baseLinkPath); err != nil {
		t.Fatal(err)
	}
	_, err = runMigratePrompt(t, baseLink)
	if err == nil {
		t.Fatal("Migrate over a symlink-to-FIFO base path = nil error; want exit 2")
	}
	if ExitCode(err) != 2 {
		t.Errorf("Migrate over a symlink-to-FIFO base path ExitCode = %d; want 2", ExitCode(err))
	}
	if !strings.Contains(err.Error(), baseLinkPath) {
		t.Errorf("Migrate over a symlink-to-FIFO base path error = %q; want it to name %q", err.Error(), baseLinkPath)
	}

	// Directory at a named path: exit-2 error, preserved.
	dirBase := BaseDir(t.TempDir())
	dirPath := filepath.Join(dirBase, "profiles", "work", "config.json")
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = runMigratePrompt(t, dirBase)
	if err == nil {
		t.Fatal("Migrate over a directory named path = nil error; want exit 2")
	}
	if ExitCode(err) != 2 {
		t.Errorf("Migrate over a directory named path ExitCode = %d; want 2", ExitCode(err))
	}
}

// TestMigrateStrayDefaultLegacyFile (R4): profiles/default/config.json
// migrates like any named legacy file: its settings become the
// default profile entry. On collision with a base-file default
// entry it refuses naming the collision instead of silently
// dropping either file.
func TestMigrateStrayDefaultLegacyFile(t *testing.T) {
	t.Parallel()

	strayJSON := `{"auto_approve":"always","node_id":"STRAY-NODE","vm_id":"STRAY-VM","fingerprint":"firefox","tls_engine":"stdlib"}`

	// Stray file only: --write carries its settings into the
	// default entry; the stray file stays on disk untouched.
	t.Run("stray only migrates as default", func(t *testing.T) {
		t.Parallel()
		base := BaseDir(t.TempDir())
		stray := filepath.Join(base, "profiles", "default", "config.json")
		writeFile(t, stray, strayJSON, 0o600)
		before, _ := os.ReadFile(stray)
		result, err := Migrate(base, true)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Migrated {
			t.Fatalf("Migrate over stray-only layout = %+v; want migrated", result)
		}
		cfg, found, err := LoadSingleConfig(base)
		if err != nil || !found {
			t.Fatalf("LoadSingleConfig = found=%v err=%v", found, err)
		}
		def := cfg.Profiles["default"]
		if def == nil {
			t.Fatal("migrated config has no default entry; want the stray file's settings")
		}
		if def.VMID != "STRAY-VM" || def.NodeID != "STRAY-NODE" || def.AutoApprove != "always" ||
			def.Fingerprint != "firefox" || def.TLSEngine != "stdlib" {
			t.Errorf("migrated default = %+v; want the stray file's settings", def)
		}
		after, _ := os.ReadFile(stray)
		if string(before) != string(after) {
			t.Error("migrate modified the stray legacy file; want it untouched")
		}
	})

	// Stray file + legacy-flat base file: both claim the default
	// profile. Refuse naming both paths; write nothing.
	t.Run("stray plus base legacy collides", func(t *testing.T) {
		t.Parallel()
		base := BaseDir(t.TempDir())
		basePath := filepath.Join(base, "config.json")
		writeFile(t, basePath, `{"auto_approve":"off","node_id":"BASE-NODE"}`, 0o600)
		stray := filepath.Join(base, "profiles", "default", "config.json")
		writeFile(t, stray, strayJSON, 0o600)
		before, _ := os.ReadFile(basePath)
		result, err := Migrate(base, true)
		if err == nil {
			t.Fatal("Migrate over stray+base legacy = nil error; want a collision refusal")
		}
		if ExitCode(err) != 2 {
			t.Errorf("collision ExitCode = %d; want 2", ExitCode(err))
		}
		if result == nil || len(result.Errors) == 0 ||
			!strings.Contains(strings.Join(result.Errors, " "), basePath) ||
			!strings.Contains(strings.Join(result.Errors, " "), stray) {
			t.Errorf("collision errors = %v; want one naming both legacy files", result.Errors)
		}
		if result != nil && result.Migrated {
			t.Error("collision run migrated; want nothing written")
		}
		after, _ := os.ReadFile(basePath)
		if string(before) != string(after) {
			t.Error("refused migrate modified the base file")
		}
	})

	// Stray file + existing single file without a default entry:
	// the stray settings join the candidate, so the candidate
	// differs from the existing file and migrate refuses to
	// overwrite (the one-shot rule) instead of silently dropping
	// the stray file. The destination is untouched and the result
	// lists the stray profile as a legacy source.
	t.Run("stray against existing single refuses overwrite", func(t *testing.T) {
		t.Parallel()
		base := BaseDir(t.TempDir())
		destPath := filepath.Join(base, "config.json")
		writeFile(t, destPath, `{"profiles":{"work":{"node_id":"W1"}}}`, 0o600)
		before, _ := os.ReadFile(destPath)
		stray := filepath.Join(base, "profiles", "default", "config.json")
		writeFile(t, stray, strayJSON, 0o600)
		result, err := Migrate(base, true)
		if err == nil {
			t.Fatal("Migrate over stray + existing single = nil error; want refuse-overwrite")
		}
		if ExitCode(err) != 2 {
			t.Errorf("refuse-overwrite ExitCode = %d; want 2", ExitCode(err))
		}
		if result == nil || result.Migrated {
			t.Error("refused migrate reported Migrated; want nothing written")
		}
		found := false
		for _, p := range result.Profiles {
			if p.Name == "default" && p.Source == "legacy" {
				found = true
			}
		}
		if !found {
			t.Errorf("migrate result profiles = %+v; want the stray default listed as legacy", result.Profiles)
		}
		after, _ := os.ReadFile(destPath)
		if string(before) != string(after) {
			t.Error("refused migrate modified the destination file")
		}
	})

	// Cross-dir: stray file against a destination single file
	// with a DIFFERING default entry refuses, naming the
	// collision (source stray path + destination config path).
	t.Run("cross-dir stray differing from destination entry collides", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		src := filepath.Join(home, "muse-cli")
		stray := filepath.Join(src, "profiles", "default", "config.json")
		writeFile(t, stray, strayJSON, 0o600)
		dest := filepath.Join(home, "castctl")
		destPath := filepath.Join(dest, "config.json")
		writeFile(t, destPath, `{"profiles":{"default":{"node_id":"OTHER-NODE","auto_approve":"off","auto_allow_once":false}}}`, 0o600)
		before, _ := os.ReadFile(destPath)
		result, err := MigrateFrom(src, dest, true)
		if err == nil {
			t.Fatal("cross-dir migrate over differing stray = nil error; want a collision refusal")
		}
		if ExitCode(err) != 2 {
			t.Errorf("collision ExitCode = %d; want 2", ExitCode(err))
		}
		if result == nil || len(result.Errors) == 0 ||
			!strings.Contains(strings.Join(result.Errors, " "), stray) ||
			!strings.Contains(strings.Join(result.Errors, " "), destPath) {
			t.Errorf("collision errors = %v; want one naming the stray file and the destination config", result.Errors)
		}
		if result != nil && result.Migrated {
			t.Error("collision run migrated; want nothing written")
		}
		after, _ := os.ReadFile(destPath)
		if string(before) != string(after) {
			t.Error("refused migrate modified the destination file")
		}
	})

	// Cross-dir: stray file identical in settings to the
	// destination default entry stands as already-migrated.
	t.Run("cross-dir stray identical to destination entry is already-migrated", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		src := filepath.Join(home, "muse-cli")
		strayCookies := filepath.Join(src, "profiles", "default", "cookies.txt")
		stray := filepath.Join(src, "profiles", "default", "config.json")
		writeFile(t, stray, `{"cookies_file":`+quoteJSON(strayCookies)+`,"auto_approve":"always","node_id":"STRAY-NODE","vm_id":"STRAY-VM","fingerprint":"firefox","tls_engine":"stdlib"}`, 0o600)
		dest := filepath.Join(home, "castctl")
		destPath := filepath.Join(dest, "config.json")
		writeFile(t, destPath, `{"profiles":{"default":{"cookies_file":`+quoteJSON(strayCookies)+`,"auto_approve":"always","node_id":"STRAY-NODE","vm_id":"STRAY-VM","auto_allow_once":false,"fingerprint":"firefox","tls_engine":"stdlib"}}}`, 0o600)
		result, err := MigrateFrom(src, dest, true)
		if err != nil {
			t.Fatal(err)
		}
		if result.Migrated || result.Reason != "already-migrated" {
			t.Errorf("identical stray collision = %+v; want already-migrated", result)
		}
	})
}

// TestDetourTagForProfileWalksDetourChains (R2): detourTagForProfile
// must walk detour chains (with a cycle guard) through detour
// fields and selector/urltest member lists, and refuse authoring
// ("") when EVERY resolution path terminates in an empty direct
// outbound, an empty group, or an unusable urltest detour.
// Authoring is kept when at least one path terminates in a usable
// non-direct outbound.
func TestDetourTagForProfileWalksDetourChains(t *testing.T) {
	t.Parallel()
	socks := func(tag, detour string) string {
		d := ""
		if detour != "" {
			d = `,"detour":` + quoteJSON(detour)
		}
		return `{"type":"socks","tag":` + quoteJSON(tag) + `,"server":"127.0.0.1","server_port":1080,"version":"5"` + d + `}`
	}
	direct := func(tag, detour string) string {
		d := ""
		if detour != "" {
			d = `,"detour":` + quoteJSON(detour)
		}
		return `{"type":"direct","tag":` + quoteJSON(tag) + d + `}`
	}
	selector := func(tag string, members ...string) string {
		parts := make([]string, 0, len(members))
		for _, m := range members {
			parts = append(parts, quoteJSON(m))
		}
		return `{"type":"selector","tag":` + quoteJSON(tag) + `,"outbounds":[` + strings.Join(parts, ",") + `]}`
	}
	urltest := func(tag string, members ...string) string {
		parts := make([]string, 0, len(members))
		for _, m := range members {
			parts = append(parts, quoteJSON(m))
		}
		return `{"type":"urltest","tag":` + quoteJSON(tag) + `,"outbounds":[` + strings.Join(parts, ",") + `],"url":"http://127.0.0.1/","interval":"60s"}`
	}
	doc := `{"profiles":{
		"chain-empty":{"node_id":"N1","outbound":"outer"},
		"chain-live":{"node_id":"N1","outbound":"outer-live"},
		"chain-inner":{"node_id":"N1","outbound":"inner-live"},
		"inline-chain":{"node_id":"N1","outbound":{"type":"socks","server":"127.0.0.1","server_port":1080,"version":"5","detour":"proxy-direct"}},
		"empty-selector":{"node_id":"N1","outbound":"sel-empty"},
		"selector-direct-only":{"node_id":"N1","outbound":"sel-direct"},
		"selector-mixed":{"node_id":"N1","outbound":"sel-mixed"},
		"selector-urltest-only":{"node_id":"N1","outbound":"sel-ut"},
		"selector-urltest-mixed":{"node_id":"N1","outbound":"sel-ut-mix"},
		"urltest-direct":{"node_id":"N1","outbound":"ut-direct"},
		"urltest-socks":{"node_id":"N1","outbound":"ut-socks"},
		"cycle":{"node_id":"N1","outbound":"cyc-a"},
		"chain-via-selector":{"node_id":"N1","outbound":"outer-sel"},
		"bound-direct":{"node_id":"N1","outbound":"bound"},
		"wg-chain":{"node_id":"N1","outbound":"wg-chain"}
	},"outbounds":[
		` + socks("outer", "inner") + `,` + direct("inner", "proxy-direct") + `,` + direct("proxy-direct", "") + `,
		` + socks("outer-live", "inner-live") + `,` + direct("inner-live", "proxy-sg") + `,
		` + selector("sel-empty") + `,
		` + selector("sel-direct", "proxy-direct") + `,
		` + selector("sel-mixed", "proxy-direct", "proxy-sg") + `,
		` + selector("sel-ut", "ut-socks") + `,
		` + selector("sel-ut-mix", "ut-socks", "proxy-sg") + `,
		` + urltest("ut-direct", "proxy-direct") + `,
		` + urltest("ut-socks", "proxy-sg") + `,
		` + socks("cyc-a", "cyc-b") + `,` + socks("cyc-b", "cyc-a") + `,
		` + socks("outer-sel", "sel-direct") + `,
		` + `{"type":"direct","tag":"bound","bind_interface":"eth0"}` + `,
		` + validOutbounds["socks"] + `
	],"endpoints":[` + strings.Replace(validOutbounds["wireguard-ep"], `"tag":"wg-home"`, `"tag":"wg-chain","detour":"proxy-direct"`, 1) + `]}`
	cfg, err := ParseSingleConfig([]byte(doc), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		// (i) chain outer -> inner(direct) -> empty direct: refuse.
		"chain-empty": "",
		// Chain through a non-empty direct (detour to socks): keep.
		"chain-live":  "outer-live",
		"chain-inner": "inner-live",
		// (ii) inline socks detouring to an empty direct: refuse.
		"inline-chain": "",
		// (iii) empty selector: refuse.
		"empty-selector": "",
		// Selector over direct-only / mixed members: keep (dial ok).
		"selector-direct-only": "sel-direct",
		"selector-mixed":       "sel-mixed",
		// Selector over urltest-only members: refuse (urltest
		// unusable in this Manager); with a usable member: keep.
		"selector-urltest-only":  "",
		"selector-urltest-mixed": "sel-ut-mix",
		// (iv) urltest detours: refuse regardless of members.
		"urltest-direct": "",
		"urltest-socks":  "",
		// Detour cycle: refuse, never loop.
		"cycle": "",
		// Chain through a selector with a direct member: keep.
		"chain-via-selector": "outer-sel",
		// Direct with a non-detour dialer option is non-empty: keep.
		"bound-direct": "bound",
		// WireGuard endpoint detouring to an empty direct: refuse
		// (chain-walking only; WG dial validity is [UNVERIFIED]).
		"wg-chain": "",
	}
	for name, wantTag := range want {
		if got := detourTagForProfile(cfg, cfg.Profiles[name]); got != wantTag {
			t.Errorf("detourTagForProfile(%q) = %q; want %q", name, got, wantTag)
		}
	}
}

// TestDetourTagForProfileDanglingTags (R2): a starting tag that
// resolves to nothing is returned as-is and left for
// validateTagGraph to reject as dangling. A dangling member inside
// a selector is not a usable path: a selector whose only member
// dangles refuses authoring. (Hand-built configs: the parser
// rejects dangling references, so these shapes cannot be built
// through ParseSingleConfig.)
func TestDetourTagForProfileDanglingTags(t *testing.T) {
	t.Parallel()

	dangling := &SingleConfig{
		Profiles: map[string]*Profile{
			"p": {Name: "p", Outbound: OutboundRef{Kind: OutboundTag, Tag: "ghost"}},
		},
	}
	if got := detourTagForProfile(dangling, dangling.Profiles["p"]); got != "ghost" {
		t.Errorf("dangling start tag = %q; want %q (left for validateTagGraph)", got, "ghost")
	}

	selDangle := &SingleConfig{
		Profiles: map[string]*Profile{
			"p": {Name: "p", Outbound: OutboundRef{Kind: OutboundTag, Tag: "sel-dangle"}},
		},
		Outbounds: []option.Outbound{
			{Type: "selector", Tag: "sel-dangle", Options: &option.SelectorOutboundOptions{Outbounds: []string{"ghost"}}},
		},
	}
	if got := detourTagForProfile(selDangle, selDangle.Profiles["p"]); got != "" {
		t.Errorf("selector with only a dangling member = %q; want \"\"", got)
	}
}

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

// TestMigrateDNSRefusalDetourChains (R2): detour chains that
// terminate in an empty direct outbound, an empty selector, or a
// urltest must not be authored into a dns section — migrate
// records the refusal naming the profile and writes no section.
// A chain through a non-empty direct still authors (control).
func TestMigrateDNSRefusalDetourChains(t *testing.T) {
	t.Parallel()
	assertNoAuthoring := func(t *testing.T, base, refusing string) {
		t.Helper()
		before, _ := os.ReadFile(filepath.Join(base, "config.json"))
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
		if string(after) != string(before) {
			t.Error("migrate rewrote the file; want no write")
		}
		if doc := readJSONFile(t, filepath.Join(base, "config.json")); func() bool { _, ok := doc["dns"]; return ok }() {
			t.Errorf("migrated config gained a dns section: %v", doc)
		}
	}
	socks := func(tag, detour string) string {
		return `{"type":"socks","tag":"` + tag + `","server":"127.0.0.1","server_port":1080,"version":"5","detour":"` + detour + `"}`
	}
	direct := func(tag, detour string) string {
		d := ""
		if detour != "" {
			d = `,"detour":"` + detour + `"`
		}
		return `{"type":"direct","tag":"` + tag + `"` + d + `}`
	}

	t.Run("chain to empty direct", func(t *testing.T) {
		t.Parallel()
		base := BaseDir(t.TempDir())
		writeFile(t, filepath.Join(base, "config.json"),
			`{"profiles":{"p1":{"node_id":"N1","auto_approve":"off","auto_allow_once":false,"outbound":"outer"}},"outbounds":[`+socks("outer", "inner")+`,`+direct("inner", "proxy-direct")+`,`+direct("proxy-direct", "")+`]}`, 0o600)
		assertNoAuthoring(t, base, "p1")
	})
	t.Run("empty selector", func(t *testing.T) {
		t.Parallel()
		base := BaseDir(t.TempDir())
		writeFile(t, filepath.Join(base, "config.json"),
			`{"profiles":{"p1":{"node_id":"N1","auto_approve":"off","auto_allow_once":false,"outbound":"sel"}},"outbounds":[{"type":"selector","tag":"sel","outbounds":[]}]}`, 0o600)
		assertNoAuthoring(t, base, "p1")
	})
	t.Run("urltest over socks", func(t *testing.T) {
		t.Parallel()
		base := BaseDir(t.TempDir())
		writeFile(t, filepath.Join(base, "config.json"),
			`{"profiles":{"p1":{"node_id":"N1","auto_approve":"off","auto_allow_once":false,"outbound":"ut"}},"outbounds":[{"type":"urltest","tag":"ut","outbounds":["proxy-sg"],"url":"http://127.0.0.1/","interval":"60s"},`+validOutbounds["socks"]+`]}`, 0o600)
		assertNoAuthoring(t, base, "p1")
	})
	t.Run("chain through non-empty direct still authors", func(t *testing.T) {
		t.Parallel()
		base := BaseDir(t.TempDir())
		writeFile(t, filepath.Join(base, "config.json"),
			`{"profiles":{"p1":{"node_id":"N1","auto_approve":"off","auto_allow_once":false,"outbound":"outer"}},"outbounds":[`+socks("outer", "inner")+`,`+direct("inner", "proxy-sg")+`,`+validOutbounds["socks"]+`]}`, 0o600)
		result, err := Migrate(base, true)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Migrated || !result.DNSAuthored {
			t.Fatalf("chain-through-direct migrate = %+v; want migrated + dns authored", result)
		}
		cfg, found, err := LoadSingleConfig(base)
		if err != nil || !found {
			t.Fatalf("LoadSingleConfig = found=%v err=%v", found, err)
		}
		dnsOpts, err := cfg.ParsedDNS()
		if err != nil {
			t.Fatal(err)
		}
		if len(dnsOpts.Servers) != 1 || detourOf(dnsOpts.Servers[0].Options) != "outer" {
			t.Errorf("authored detour = %q; want \"outer\" (the profile's outbound tag, chain and all)", detourOf(dnsOpts.Servers[0].Options))
		}
	})
}

// TestMigrateFromCrossDirCollision (R5): with --from naming a
// DIFFERENT directory, a source legacy profile whose settings
// differ from the destination single-file entry of the same name
// must REFUSE (naming the profile and both locations), never
// silently report already-migrated. A byte-identical source entry
// stands as already-migrated. A bare source directory with no
// config file for the name stays silent (nothing to compare).
// Same-dir behaviour is unchanged (NB4 skip) — see
// TestMigrateStrayDefaultLegacyFile and the NB4 tests.
func TestMigrateFromCrossDirCollision(t *testing.T) {
	t.Parallel()
	entry := func(node, vm, approve string) string {
		return `{"node_id":` + quoteJSON(node) + `,"vm_id":` + quoteJSON(vm) + `,"auto_approve":` + quoteJSON(approve) + `,"auto_allow_once":false}`
	}
	single := func(entries string) string {
		return `{"profiles":{` + entries + `}}`
	}
	assertRefusal := func(t *testing.T, src, dest string, name string, srcFile, destFile string) {
		t.Helper()
		srcBefore := snapshotDir(t, src)
		destBefore, _ := os.ReadFile(filepath.Join(dest, "config.json"))
		for _, write := range []bool{false, true} {
			result, err := MigrateFrom(src, dest, write)
			if err == nil {
				t.Fatalf("MigrateFrom(write=%v) err = nil; want a profile error for %q", write, name)
			}
			joined := strings.Join(result.Errors, "\n")
			for _, want := range []string{`"` + name + `"`, srcFile, destFile} {
				if !strings.Contains(joined, want) {
					t.Errorf("MigrateFrom(write=%v) errors = %q; want it to name %q", write, joined, want)
				}
			}
		}
		assertSameSnapshot(t, srcBefore, snapshotDir(t, src))
		destAfter, _ := os.ReadFile(filepath.Join(dest, "config.json"))
		if string(destAfter) != string(destBefore) {
			t.Error("refused migrate rewrote the destination config")
		}
	}
	assertAlreadyMigrated := func(t *testing.T, src, dest string) {
		t.Helper()
		destBefore, _ := os.ReadFile(filepath.Join(dest, "config.json"))
		for _, write := range []bool{false, true} {
			result, err := MigrateFrom(src, dest, write)
			if err != nil {
				t.Fatalf("MigrateFrom(write=%v) err = %v; want already-migrated", write, err)
			}
			if result.Reason != "already-migrated" || result.Migrated {
				t.Errorf("MigrateFrom(write=%v) = %+v; want already-migrated, not migrated", write, result)
			}
		}
		destAfter, _ := os.ReadFile(filepath.Join(dest, "config.json"))
		if string(destAfter) != string(destBefore) {
			t.Error("already-migrated migrate rewrote the destination config")
		}
	}
	// Every fixture below seeds a source base file whose settings
	// match the destination default entry, so the default profile
	// never varies: only the colliding named profile (or the
	// default entry itself, in the default subtests) decides.
	seedMatchingBase := func(t *testing.T, src, dest string) {
		t.Helper()
		writeFile(t, filepath.Join(src, "config.json"), `{"auto_approve":"off","node_id":"BASE-NODE","vm_id":"BASE-VM"}`, 0o600)
		writeFile(t, filepath.Join(dest, "config.json"), single(`"default":`+entry("BASE-NODE", "BASE-VM", "off")), 0o600)
	}

	t.Run("default differing", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		src := filepath.Join(home, "muse-cli")
		dest := filepath.Join(home, "castctl")
		writeFile(t, filepath.Join(src, "config.json"), `{"auto_approve":"always","node_id":"SRC-NODE","vm_id":"SRC-VM"}`, 0o600)
		writeFile(t, filepath.Join(dest, "config.json"), single(`"default":`+entry("DEST-NODE", "DEST-VM", "off")), 0o600)
		assertRefusal(t, src, dest, "default", filepath.Join(src, "config.json"), filepath.Join(dest, "config.json"))
	})
	t.Run("named differing", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		src := filepath.Join(home, "muse-cli")
		dest := filepath.Join(home, "castctl")
		seedMatchingBase(t, src, dest)
		writeFile(t, filepath.Join(src, "profiles", "work", "config.json"), `{"auto_approve":"always","node_id":"SRC-NODE","vm_id":"SRC-VM"}`, 0o600)
		// Replace the destination single with default + work entries.
		writeFile(t, filepath.Join(dest, "config.json"), single(`"default":`+entry("BASE-NODE", "BASE-VM", "off")+`,"work":`+entry("DEST-NODE", "DEST-VM", "off")), 0o600)
		assertRefusal(t, src, dest, "work", filepath.Join(src, "profiles", "work", "config.json"), filepath.Join(dest, "config.json"))
	})
	t.Run("named identical", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		src := filepath.Join(home, "muse-cli")
		dest := filepath.Join(home, "castctl")
		seedMatchingBase(t, src, dest)
		writeFile(t, filepath.Join(src, "profiles", "work", "config.json"), `{"auto_approve":"off","node_id":"SAME-NODE","vm_id":"SAME-VM"}`, 0o600)
		writeFile(t, filepath.Join(dest, "config.json"), single(`"default":`+entry("BASE-NODE", "BASE-VM", "off")+`,"work":`+entry("SAME-NODE", "SAME-VM", "off")), 0o600)
		assertAlreadyMigrated(t, src, dest)
	})
	t.Run("default identical", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		src := filepath.Join(home, "muse-cli")
		dest := filepath.Join(home, "castctl")
		writeFile(t, filepath.Join(src, "config.json"), `{"auto_approve":"off","node_id":"SAME-NODE","vm_id":"SAME-VM"}`, 0o600)
		writeFile(t, filepath.Join(dest, "config.json"), single(`"default":`+entry("SAME-NODE", "SAME-VM", "off")), 0o600)
		assertAlreadyMigrated(t, src, dest)
	})
	t.Run("single-format source colliding", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		src := filepath.Join(home, "muse-cli")
		dest := filepath.Join(home, "castctl")
		seedMatchingBase(t, src, dest)
		// A single-format file in the source is not copied: the
		// strict legacy parser refuses it. Before the R5 fix
		// this colliding position skipped the file silently
		// (never parsed); now it errors and writes nothing.
		// (The parse error names the problem, not both
		// locations — that is the pre-existing parse-error
		// shape, distinct from the differing-settings refusal.)
		writeFile(t, filepath.Join(src, "profiles", "work", "config.json"), `{"profiles":{"work":{"node_id":"X"}}}`, 0o600)
		writeFile(t, filepath.Join(dest, "config.json"), single(`"default":`+entry("BASE-NODE", "BASE-VM", "off")+`,"work":`+entry("DEST-NODE", "DEST-VM", "off")), 0o600)
		srcBefore := snapshotDir(t, src)
		destBefore, _ := os.ReadFile(filepath.Join(dest, "config.json"))
		for _, write := range []bool{false, true} {
			result, err := MigrateFrom(src, dest, write)
			if err == nil {
				t.Fatalf("MigrateFrom(write=%v) err = nil; want a profile error for the single-format source", write)
			}
			if !strings.Contains(strings.Join(result.Errors, "\n"), `"profiles" key does not belong`) {
				t.Errorf("MigrateFrom(write=%v) errors = %q; want the strict-parser refusal", write, strings.Join(result.Errors, "\n"))
			}
		}
		assertSameSnapshot(t, srcBefore, snapshotDir(t, src))
		destAfter, _ := os.ReadFile(filepath.Join(dest, "config.json"))
		if string(destAfter) != string(destBefore) {
			t.Error("refused migrate rewrote the destination config")
		}
	})
	t.Run("bare source dir silent", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		src := filepath.Join(home, "muse-cli")
		dest := filepath.Join(home, "castctl")
		seedMatchingBase(t, src, dest)
		if err := os.MkdirAll(filepath.Join(src, "profiles", "work"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dest, "config.json"), single(`"default":`+entry("BASE-NODE", "BASE-VM", "off")+`,"work":`+entry("DEST-NODE", "DEST-VM", "off")), 0o600)
		assertAlreadyMigrated(t, src, dest)
	})
}

// TestSameDirResolvesSymlinks (R6): sameDir compares directories
// after resolving symlinks, so an alias of a directory counts as
// the same directory. A path that cannot be resolved (dangling
// symlink, missing directory) is treated as different — fail-open
// to cross-dir logic, never a crash, never a false same.
func TestSameDirResolvesSymlinks(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	real := filepath.Join(home, "castctl")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(home, "link")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(home, "other")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(home, "dangling")
	if err := os.Symlink(filepath.Join(home, "no-such-dir"), dangling); err != nil {
		t.Fatal(err)
	}
	if !sameDir(alias, real) || !sameDir(real, alias) {
		t.Error("symlink alias of a directory must compare same")
	}
	if !sameDir(real, real) {
		t.Error("a directory must compare same with itself")
	}
	if sameDir(real, other) {
		t.Error("two different directories must not compare same")
	}
	if sameDir(dangling, real) || sameDir(real, dangling) {
		t.Error("a dangling symlink must compare different (fail-open)")
	}
	if sameDir(filepath.Join(home, "missing-a"), filepath.Join(home, "missing-b")) {
		t.Error("two different missing paths must not compare same")
	}
}

// TestMigrateFromSymlinkAlias (R6): --from naming the destination
// through a symlink takes same-dir behaviour: the default skip
// applies (a present single file is already-migrated, not a
// legacy source to parse), and a write lands in the real
// directory with destination-spelled paths.
func TestMigrateFromSymlinkAlias(t *testing.T) {
	t.Parallel()

	t.Run("single present is already-migrated", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		dest := filepath.Join(home, "castctl")
		writeFile(t, filepath.Join(dest, "config.json"), `{"profiles":{"default":{"node_id":"N1","vm_id":"V1","auto_approve":"off","auto_allow_once":false}}}`, 0o600)
		alias := filepath.Join(home, "link")
		if err := os.Symlink(dest, alias); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(filepath.Join(dest, "config.json"))
		for _, write := range []bool{false, true} {
			result, err := MigrateFrom(alias, dest, write)
			if err != nil {
				t.Fatalf("MigrateFrom(alias, write=%v) err = %v; want already-migrated", write, err)
			}
			if result.Reason != "already-migrated" || result.Migrated {
				t.Errorf("MigrateFrom(alias, write=%v) = %+v; want already-migrated", write, result)
			}
		}
		after, _ := os.ReadFile(filepath.Join(dest, "config.json"))
		if string(after) != string(before) {
			t.Error("alias migrate rewrote the destination config")
		}
	})

	t.Run("legacy write uses destination spelling", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		dest := filepath.Join(home, "castctl")
		writeFile(t, filepath.Join(dest, "config.json"), `{"auto_approve":"always","node_id":"MAIN-NODE","vm_id":"FAKE-VM"}`, 0o600)
		alias := filepath.Join(home, "link")
		if err := os.Symlink(dest, alias); err != nil {
			t.Fatal(err)
		}
		result, err := MigrateFrom(alias, dest, true)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Migrated {
			t.Fatalf("MigrateFrom(alias) = %+v; want migrated", result)
		}
		doc := readJSONFile(t, filepath.Join(dest, "config.json"))
		profiles, _ := doc["profiles"].(map[string]any)
		def, _ := profiles["default"].(map[string]any)
		if got, _ := def["cookies_file"].(string); got != filepath.Join(dest, "cookies.txt") {
			t.Errorf("written cookies_file = %q; want destination spelling %q", got, filepath.Join(dest, "cookies.txt"))
		}
	})
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
