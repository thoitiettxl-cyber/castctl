// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fingerprint/tls_engine are recorded data only (FINGERPRINT-HOLD):
// these tests pin storage, validation, migrate preservation, the
// guarded library commands, and display. Nothing here dials or
// wires TLS behaviour.

func TestSupportedFingerprintSets(t *testing.T) {
	t.Parallel()
	fps := SupportedFingerprints()
	if len(fps) != 4 || fps[0] != "chrome" || fps[1] != "firefox" || fps[2] != "ios" || fps[3] != "safari" {
		t.Fatalf("SupportedFingerprints = %v, want [chrome firefox ios safari]", fps)
	}
	engines := SupportedTLSEngines()
	if len(engines) != 3 || engines[0] != "cronet" || engines[1] != "stdlib" || engines[2] != "utls" {
		t.Fatalf("SupportedTLSEngines = %v, want [cronet stdlib utls]", engines)
	}
	// Callers must not be able to mutate the accepted sets.
	fps[0] = "bogus"
	if SupportedFingerprints()[0] != "chrome" {
		t.Fatal("SupportedFingerprints result is mutable")
	}
}

func TestFingerprintParseDefaultsAndValid(t *testing.T) {
	t.Parallel()
	for _, fp := range SupportedFingerprints() {
		for _, te := range SupportedTLSEngines() {
			json := `{"profiles":{"default":{"fingerprint":` + qstr(fp) + `,"tls_engine":` + qstr(te) + `}}}`
			cfg, err := ParseSingleConfig([]byte(json), t.TempDir())
			if err != nil {
				t.Fatalf("ParseSingleConfig %s/%s: %v", fp, te, err)
			}
			p := cfg.Profiles["default"]
			if p.Fingerprint != fp || p.TLSEngine != te {
				t.Fatalf("parsed %s/%s, got %s/%s", fp, te, p.Fingerprint, p.TLSEngine)
			}
		}
	}
	// Absent keys default, and a save omits them: reads never
	// write defaults back.
	base := t.TempDir()
	cfg, err := ParseSingleConfig([]byte(`{"profiles":{"default":{}}}`), base)
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Profiles["default"]
	if p.Fingerprint != DefaultFingerprint || p.TLSEngine != DefaultTLSEngine {
		t.Fatalf("defaults = %s/%s, want chrome/utls", p.Fingerprint, p.TLSEngine)
	}
	if err := SaveSingleConfig(base, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "fingerprint") || strings.Contains(string(data), "tls_engine") {
		t.Fatalf("saved file carries default keys: %s", data)
	}
	// Present values round-trip verbatim through a save.
	base2 := t.TempDir()
	cfg2, err := ParseSingleConfig([]byte(`{"profiles":{"default":{"fingerprint":"safari","tls_engine":"cronet"}}}`), base2)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSingleConfig(base2, cfg2); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(base2, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"fingerprint": "safari"`) || !strings.Contains(string(data), `"tls_engine": "cronet"`) {
		t.Fatalf("saved file lost present values: %s", data)
	}
}

func qstr(s string) string { return `"` + s + `"` }

func TestFingerprintParseInvalid(t *testing.T) {
	t.Parallel()
	cases := []struct{ key, raw, want string }{
		{"fingerprint", `"random"`, "chrome"},
		{"fingerprint", `"randomized"`, "safari"},
		{"fingerprint", `"Chrome"`, "chrome"},
		{"fingerprint", `"CHROME"`, "chrome"},
		{"fingerprint", `""`, "chrome"},
		{"fingerprint", `" chrome"`, "chrome"},
		// Wrong-typed values fail as type errors, not enum errors.
		{"fingerprint", `42`, "must be a string"},
		{"fingerprint", `true`, "must be a string"},
		{"fingerprint", `null`, "must be a string"},
		{"tls_engine", `"random"`, "cronet"},
		{"tls_engine", `"chrome"`, "utls"},
		{"tls_engine", `"UTLS"`, "utls"},
		{"tls_engine", `""`, "stdlib"},
		{"tls_engine", `42`, "must be a string"},
	}
	for _, tc := range cases {
		json := `{"profiles":{"default":{` + qstr(tc.key) + `:` + tc.raw + `}}}`
		_, err := ParseSingleConfig([]byte(json), t.TempDir())
		if err == nil {
			t.Fatalf("ParseSingleConfig %s=%s: want error", tc.key, tc.raw)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseSingleConfig %s=%s: error %q does not name a supported value %q", tc.key, tc.raw, err, tc.want)
		}
		if ExitCode(err) != 2 {
			t.Errorf("ParseSingleConfig %s=%s: ExitCode = %d, want 2", tc.key, tc.raw, ExitCode(err))
		}
	}
}

func TestFingerprintLegacy(t *testing.T) {
	t.Parallel()
	// Present values in a legacy flat config load verbatim.
	home := t.TempDir()
	legacy := BaseDir(home)
	writeFile(t, filepath.Join(legacy, "config.json"), `{"fingerprint":"ios","tls_engine":"stdlib"}`, 0o600)
	p, err := LoadProfile(legacy, "default", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if p.Fingerprint != "ios" || p.TLSEngine != "stdlib" {
		t.Fatalf("legacy = %s/%s, want ios/stdlib", p.Fingerprint, p.TLSEngine)
	}
	// Absent keys default.
	home2 := t.TempDir()
	legacy2 := BaseDir(home2)
	writeFile(t, filepath.Join(legacy2, "config.json"), `{"auto_approve":"off"}`, 0o600)
	p, err = LoadProfile(legacy2, "default", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if p.Fingerprint != "chrome" || p.TLSEngine != "utls" {
		t.Fatalf("legacy defaults = %s/%s, want chrome/utls", p.Fingerprint, p.TLSEngine)
	}
	// Invalid values error even on the non-strict (LoadProfile)
	// path, and wrong types too: recorded identity is never
	// silently reinterpreted.
	for _, raw := range []string{`{"fingerprint":"random"}`, `{"tls_engine":"bogus"}`, `{"fingerprint":42}`, `{"tls_engine":true}`} {
		home3 := t.TempDir()
		legacy3 := BaseDir(home3)
		writeFile(t, filepath.Join(legacy3, "config.json"), raw, 0o600)
		if _, err := LoadProfile(legacy3, "default", lookupEnv(map[string]string{})); err == nil {
			t.Fatalf("LoadProfile %s: want error", raw)
		} else if ExitCode(err) != 2 {
			t.Fatalf("LoadProfile %s: ExitCode = %d, want 2", raw, ExitCode(err))
		}
	}
}

func TestFingerprintMigratePreserves(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	base := BaseDir(home)
	writeFile(t, filepath.Join(base, "config.json"), `{"auto_approve":"off"}`, 0o600)
	writeFile(t, filepath.Join(base, "profiles", "work", "config.json"), `{"fingerprint":"ios","tls_engine":"stdlib"}`, 0o600)
	res, err := Migrate(base, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Migrated {
		t.Fatalf("Migrate = %+v, want Migrated=true", res)
	}
	data, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"fingerprint": "ios"`) || !strings.Contains(string(data), `"tls_engine": "stdlib"`) {
		t.Fatalf("migrated file lost present values: %s", data)
	}
	if n := strings.Count(string(data), "fingerprint"); n != 1 {
		t.Fatalf("fingerprint appears %d times, want 1 (absent default entry stays absent)", n)
	}
	if n := strings.Count(string(data), "tls_engine"); n != 1 {
		t.Fatalf("tls_engine appears %d times, want 1", n)
	}
	// The default entry loads with defaults; a second migrate is
	// already-migrated.
	def, err := LoadProfile(base, "default", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if def.Fingerprint != "chrome" || def.TLSEngine != "utls" {
		t.Fatalf("migrated default = %s/%s, want chrome/utls", def.Fingerprint, def.TLSEngine)
	}
	res, err = Migrate(base, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Migrated || res.Reason != "already-migrated" {
		t.Fatalf("second Migrate = %+v, want already-migrated", res)
	}
	// A single file already carrying the values is
	// already-migrated on the first run too.
	base2 := t.TempDir()
	seedSingleFile(t, base2, `{"profiles":{"default":{"fingerprint":"firefox","tls_engine":"cronet"}}}`)
	res, err = Migrate(base2, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Migrated || res.Reason != "already-migrated" {
		t.Fatalf("single-file Migrate = %+v, want already-migrated", res)
	}
}

func TestAddSetFingerprintRoundTrip(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	seedSingleFile(t, base, `{"profiles":{"default":{}}}`)
	before, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	// AddProfile with both parameters writes them.
	p, err := AddProfile(base, "work", AddProfileOptions{Fingerprint: "firefox", TLSEngine: "cronet"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Fingerprint != "firefox" || p.TLSEngine != "cronet" {
		t.Fatalf("AddProfile = %s/%s, want firefox/cronet", p.Fingerprint, p.TLSEngine)
	}
	loaded, err := LoadProfile(base, "work", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fingerprint != "firefox" || loaded.TLSEngine != "cronet" {
		t.Fatalf("reloaded = %s/%s", loaded.Fingerprint, loaded.TLSEngine)
	}
	// Invalid AddProfile writes nothing.
	if _, err := AddProfile(base, "bad", AddProfileOptions{Fingerprint: "random"}); err == nil {
		t.Fatal("AddProfile random: want error")
	}
	if _, err := AddProfile(base, "bad2", AddProfileOptions{TLSEngine: "bogus"}); err == nil {
		t.Fatal("AddProfile bogus engine: want error")
	}
	after, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), `"bad"`) || strings.Contains(string(after), `"bad2"`) {
		t.Fatalf("invalid AddProfile wrote profiles: %s", after)
	}
	// Invalid AddProfile on a fresh dir creates no file.
	fresh := t.TempDir()
	if _, err := AddProfile(fresh, "x", AddProfileOptions{Fingerprint: "randomized"}); err == nil {
		t.Fatal("AddProfile on fresh dir: want error")
	}
	if _, err := os.Stat(filepath.Join(fresh, "config.json")); !os.IsNotExist(err) {
		t.Fatalf("fresh dir config stat = %v, want not-exist", err)
	}
	// SetFingerprint / SetTlsEngine round-trip through the guard.
	if _, err := SetFingerprint(base, "work", "safari"); err != nil {
		t.Fatal(err)
	}
	if _, err := SetTlsEngine(base, "work", "stdlib"); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadProfile(base, "work", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fingerprint != "safari" || loaded.TLSEngine != "stdlib" {
		t.Fatalf("after set = %s/%s, want safari/stdlib", loaded.Fingerprint, loaded.TLSEngine)
	}
	// Invalid set writes nothing.
	beforeSet, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SetFingerprint(base, "work", "random"); err == nil {
		t.Fatal("SetFingerprint random: want error")
	}
	if _, err := SetTlsEngine(base, "work", "bogus"); err == nil {
		t.Fatal("SetTlsEngine bogus: want error")
	}
	afterSet, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(beforeSet) != string(afterSet) {
		t.Fatal("invalid Set* changed the file")
	}
	// Empty set resets to the default and clears the stored key.
	if _, err := SetFingerprint(base, "work", ""); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadProfile(base, "work", lookupEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fingerprint != "chrome" {
		t.Fatalf("after reset fingerprint = %q, want chrome", loaded.Fingerprint)
	}
	data, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "fingerprint") {
		t.Fatalf("reset did not clear the stored key: %s", data)
	}
	// Unknown profile and missing single file error.
	if _, err := SetFingerprint(base, "nope", "safari"); err == nil {
		t.Fatal("SetFingerprint unknown profile: want error")
	}
	if _, err := SetTlsEngine(t.TempDir(), "default", "utls"); err == nil {
		t.Fatal("SetTlsEngine without a single file: want error")
	}
	_ = before
}

func TestFingerprintDisplay(t *testing.T) {
	t.Parallel()
	// Stored values show in profile and whole-config display.
	cfg, err := ParseSingleConfig([]byte(`{"profiles":{"default":{"fingerprint":"ios","tls_engine":"stdlib"}}}`), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out, err := RedactProfile(cfg.Profiles["default"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"fingerprint": "ios"`) || !strings.Contains(string(out), `"tls_engine": "stdlib"`) {
		t.Fatalf("RedactProfile = %s, want both stored values", out)
	}
	out, err = RedactConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"fingerprint": "ios"`) || !strings.Contains(string(out), `"tls_engine": "stdlib"`) {
		t.Fatalf("RedactConfig = %s, want both stored values", out)
	}
	// Absent keys: profile show displays the effective defaults;
	// the whole-config rendering stays file-faithful (no injection).
	cfg2, err := ParseSingleConfig([]byte(`{"profiles":{"default":{}}}`), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out, err = RedactProfile(cfg2.Profiles["default"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"fingerprint": "chrome"`) || !strings.Contains(string(out), `"tls_engine": "utls"`) {
		t.Fatalf("RedactProfile (defaults) = %s, want effective chrome/utls", out)
	}
	out, err = RedactConfig(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "fingerprint") || strings.Contains(string(out), "tls_engine") {
		t.Fatalf("RedactConfig injected defaults: %s", out)
	}
}
