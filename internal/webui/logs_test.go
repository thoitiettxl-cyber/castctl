// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// Log fixture lines are RECONSTRUCTED from the sing-box console
// format (sing-box v1.14.4 log/format.go + the castctl factory's
// "-0700 2006-01-02 15:04:05" timestamp layout): they are not
// captured output. Marker values are FAKE and must never appear
// in any response.

func newLogTestServer(t *testing.T, config string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	config = strings.ReplaceAll(config, "COOKIESFILE", filepath.Join(dir, "cookies.txt"))
	config = strings.ReplaceAll(config, "LOGFILE", filepath.Join(dir, "castctl.log"))
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Deps{
		ConfigDir:    dir,
		Version:      "t",
		ListenAddr:   "127.0.0.1:8317",
		TokenHash:    testTokenHash(t),
		HasToken:     true,
		DistFS:       fstest.MapFS{"index.html": {Data: []byte("shell")}},
		BundleSHA256: "h",
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, dir
}

func logDo(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

const logBlockConfig = `{
  "default_profile": "muse01",
  "profiles": {"muse01": {"cookies_file": "COOKIESFILE"}},
  "log": {"output": "LOGFILE", "timestamp": true}
}`

func TestLogsDisabledWithoutBlock(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	rec := ts.do(t, "GET", "/api/v1/logs", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("logs: %d: %s", rec.Code, rec.Body.String())
	}
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	if data["disabled"] != true || data["reason"] != "logging_disabled" {
		t.Fatalf("disabled response = %v", data)
	}
}

func TestLogsDisabledForStderrOutput(t *testing.T) {
	config := strings.Replace(fixtureConfig, `"dns":`, `"log": {"output": "stderr"}, "dns":`, 1)
	ts := newTestServer(t, config, nil)
	rec := ts.do(t, "GET", "/api/v1/logs", "", true)
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	if data["disabled"] != true || data["reason"] != "log_output_not_file" {
		t.Fatalf("disabled response = %v", data)
	}
}

func TestLogsRefusedIdentity(t *testing.T) {
	// A log output that IS the config file is refused (A7):
	// the endpoint reports disabled and never opens the config
	// as if it were a log.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	config := strings.ReplaceAll(logBlockConfig, "COOKIESFILE", filepath.Join(dir, "cookies.txt"))
	config = strings.ReplaceAll(config, "LOGFILE", configPath)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Deps{
		ConfigDir:    dir,
		Version:      "t",
		ListenAddr:   "127.0.0.1:8317",
		TokenHash:    testTokenHash(t),
		HasToken:     true,
		DistFS:       fstest.MapFS{"index.html": {Data: []byte("shell")}},
		BundleSHA256: "h",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := logDo(t, srv, "/api/v1/logs")
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	if data["disabled"] != true || data["reason"] != "log_output_refused" {
		t.Fatalf("refused response = %v", data)
	}
}

func TestLogsTailRedactionAndCursor(t *testing.T) {
	srv, dir := newLogTestServer(t, logBlockConfig)
	logPath := filepath.Join(dir, "castctl.log")
	lines := strings.Join([]string{
		"+0700 2026-10-31 13:00:01 INFO gateway: session ok status=200",
		"+0700 2026-10-31 13:00:02 WARN gateway: retry class=timeout",
		"+0700 2026-10-31 13:00:03 ERROR gateway: token: MARKER-SECRET-TOKEN",
		"+0700 2026-10-31 13:00:04 INFO gateway: {\"password\": \"MARKER-SECRET-PW\"}",
		"unparseable line here",
		"",
	}, "\n")
	if err := os.WriteFile(logPath, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := logDo(t, srv, "/api/v1/logs")
	if rec.Code != http.StatusOK {
		t.Fatalf("logs: %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, marker := range []string{"MARKER-SECRET-TOKEN", "MARKER-SECRET-PW"} {
		if strings.Contains(body, marker) {
			t.Fatalf("marker %s leaked into log response:\n%s", marker, body)
		}
	}
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	data := env["data"].(map[string]any)
	entries, _ := data["entries"].([]any)
	if len(entries) != 5 {
		t.Fatalf("entries = %d, want 5: %v", len(entries), entries)
	}
	first := entries[0].(map[string]any)
	if first["level"] != "info" || first["kind"] != "gateway" || first["ts"] != "+0700 2026-10-31 13:00:01" {
		t.Fatalf("first entry = %v", first)
	}
	last := entries[4].(map[string]any)
	if last["level"] != "" || last["message"] != "unparseable line here" {
		t.Fatalf("unparseable entry = %v", last)
	}
	cursor, _ := data["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("next_cursor missing")
	}
	// Append one line; a cursor read returns only the new line.
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("+0700 2026-10-31 13:00:05 INFO gateway: appended\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	rec = logDo(t, srv, "/api/v1/logs?cursor="+cursor)
	var env2 map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env2); err != nil {
		t.Fatal(err)
	}
	entries2, _ := env2["data"].(map[string]any)["entries"].([]any)
	if len(entries2) != 1 {
		t.Fatalf("cursor entries = %d, want 1: %v", len(entries2), entries2)
	}
	if entries2[0].(map[string]any)["message"] != "appended" {
		t.Fatalf("cursor entry = %v", entries2[0])
	}
	// Level filter: exact match on the parsed level.
	rec = logDo(t, srv, "/api/v1/logs?level=error")
	var env3 map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env3); err != nil {
		t.Fatal(err)
	}
	entries3, _ := env3["data"].(map[string]any)["entries"].([]any)
	if len(entries3) != 1 {
		t.Fatalf("error-filtered entries = %d, want 1: %v", len(entries3), entries3)
	}
}

func TestParseLogLine(t *testing.T) {
	cases := []struct {
		line  string
		level string
		kind  string
		msg   string
	}{
		{"+0700 2026-10-31 13:00:01 INFO gateway: hello", "info", "gateway", "hello"},
		{"WARN something happened", "warn", "", "something happened"},
		{"ERROR[0042] outbound: dial failed", "error", "outbound", "dial failed"},
		{"WARNING plain", "warn", "", "plain"},
		{"just text", "", "", "just text"},
	}
	for _, tc := range cases {
		e := parseLogLine(tc.line)
		if e.Level != tc.level || e.Kind != tc.kind || e.Message != tc.msg {
			t.Errorf("parse %q: got %+v", tc.line, e)
		}
	}
}

// Log-gate refusal tests (loop-2 F1, Boss ruling 2026-10-31):
// the gate must refuse the cookies file, its .bak sibling, the
// legacy cookies file and its .bak, and every file resolving
// under profiles/ — symlink-resolved per request. FAKE markers
// only; a refused output must never reach a response.

func logServerFromConfig(t *testing.T, dir, config string) *Server {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Deps{
		ConfigDir:    dir,
		Version:      "t",
		ListenAddr:   "127.0.0.1:8317",
		TokenHash:    testTokenHash(t),
		HasToken:     true,
		DistFS:       fstest.MapFS{"index.html": {Data: []byte("shell")}},
		BundleSHA256: "h",
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func logConfigWithOutput(t *testing.T, dir, cookiesPath, logPath string) string {
	t.Helper()
	_ = t
	return `{
  "default_profile": "muse01",
  "profiles": {"muse01": {"cookies_file": "` + cookiesPath + `"}},
  "log": {"output": "` + logPath + `", "timestamp": true}
}`
}

func assertLogsRefused(t *testing.T, srv *Server, markers ...string) {
	t.Helper()
	rec := logDo(t, srv, "/api/v1/logs")
	if rec.Code != http.StatusOK {
		t.Fatalf("logs: %d: %s", rec.Code, rec.Body.String())
	}
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	if data["disabled"] != true || data["reason"] != "log_output_refused" {
		t.Fatalf("refused response = %v", data)
	}
	for _, marker := range markers {
		if strings.Contains(rec.Body.String(), marker) {
			t.Fatalf("marker %s leaked into log response:\n%s", marker, rec.Body.String())
		}
	}
}

func TestLogsRefusedCookiesBak(t *testing.T) {
	dir := t.TempDir()
	cookiesPath := filepath.Join(dir, "cookies.txt")
	bakPath := cookiesPath + ".bak"
	jar := ".example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tFAKE-COOKIE-HATCH-12345\n" +
		".example.com\tTRUE\t/\tFALSE\t0\tdatr\tFAKE-COOKIE-DATR-67890\n"
	if err := os.WriteFile(bakPath, []byte(jar), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, bakPath))
	assertLogsRefused(t, srv, "FAKE-COOKIE-HATCH-12345", "FAKE-COOKIE-DATR-67890")
}

func TestLogsRefusedLegacyBak(t *testing.T) {
	dir := t.TempDir()
	legacyDir := filepath.Join(dir, "profiles", "legacy1")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "config.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyBak := filepath.Join(legacyDir, "cookies.txt.bak")
	jar := ".example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tFAKE-LEGACY-HATCH-111\n"
	if err := os.WriteFile(legacyBak, []byte(jar), 0o600); err != nil {
		t.Fatal(err)
	}
	cookiesPath := filepath.Join(dir, "cookies.txt")
	config := logConfigWithOutput(t, dir, cookiesPath, legacyBak)
	srv := logServerFromConfig(t, dir, config)
	assertLogsRefused(t, srv, "FAKE-LEGACY-HATCH-111")
}

func TestLogsRefusedProfilesSubtree(t *testing.T) {
	dir := t.TempDir()
	notesPath := filepath.Join(dir, "profiles", "muse01", "notes.txt")
	if err := os.MkdirAll(filepath.Dir(notesPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notesPath, []byte("INFO gateway: FAKE-PROFILES-NOTE-222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cookiesPath := filepath.Join(dir, "profiles", "muse01", "cookies.txt")
	config := logConfigWithOutput(t, dir, cookiesPath, notesPath)
	srv := logServerFromConfig(t, dir, config)
	assertLogsRefused(t, srv, "FAKE-PROFILES-NOTE-222")
}

func TestLogsRefusedSymlinkToBak(t *testing.T) {
	dir := t.TempDir()
	cookiesPath := filepath.Join(dir, "cookies.txt")
	bakPath := cookiesPath + ".bak"
	jar := ".example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tFAKE-SYMLINK-HATCH-333\n"
	if err := os.WriteFile(bakPath, []byte(jar), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "link.log")
	if err := os.Symlink(bakPath, linkPath); err != nil {
		t.Fatal(err)
	}
	config := logConfigWithOutput(t, dir, cookiesPath, linkPath)
	srv := logServerFromConfig(t, dir, config)
	assertLogsRefused(t, srv, "FAKE-SYMLINK-HATCH-333")
}

func TestLogsRefusedDotDotSymlinkBak(t *testing.T) {
	// The .bak does not exist yet: the gate must refuse the
	// symlink-resolved target even before the backup exists.
	// The output path reaches the (absent) .bak through a
	// symlinked directory plus a ".." component, so a purely
	// lexical check cannot see the target.
	dir := t.TempDir()
	aliasPath := filepath.Join(dir, "alias")
	if err := os.Symlink(dir, aliasPath); err != nil {
		t.Fatal(err)
	}
	cookiesPath := filepath.Join(dir, "cookies.txt")
	// Lexically: dir/alias/profiles/../cookies.txt.bak collapses
	// to dir/alias/cookies.txt.bak; resolved: dir/cookies.txt.bak.
	logPath := filepath.Join(dir, "alias", "profiles", "..", "cookies.txt.bak")
	config := logConfigWithOutput(t, dir, cookiesPath, logPath)
	srv := logServerFromConfig(t, dir, config)
	assertLogsRefused(t, srv)
}

func TestLogsLegitimateFileOutsideProfilesTails(t *testing.T) {
	// No-over-refusal guard: a plain log file outside profiles/
	// still tails normally. (Green on both old and new code.)
	srv, dir := newLogTestServer(t, logBlockConfig)
	logPath := filepath.Join(dir, "castctl.log")
	lines := "+0700 2026-10-31 13:00:01 INFO gateway: hello\n" +
		"+0700 2026-10-31 13:00:02 INFO gateway: world\n"
	if err := os.WriteFile(logPath, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := logDo(t, srv, "/api/v1/logs")
	if rec.Code != http.StatusOK {
		t.Fatalf("logs: %d: %s", rec.Code, rec.Body.String())
	}
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	if data["disabled"] != false {
		t.Fatalf("legitimate log refused: %v", data)
	}
	entries, _ := data["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2: %v", len(entries), entries)
	}
}

// writeLegacyProfile creates profiles/<name>/config.json with the
// given content and returns the profile directory.
func writeLegacyProfile(t *testing.T, dir, name, config string) string {
	t.Helper()
	legacyDir := filepath.Join(dir, "profiles", name)
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return legacyDir
}

// Log-gate refusal tests (loop-3 R10): a legacy profile's OWN
// cookies_file override — absolute, .bak, or relative — must be
// refused exactly like the default legacy cookies path. The
// override lives in profiles/<name>/config.json, which the
// loop-2 guard never read.

func TestLogsRefusedLegacyOverrideCookiesFile(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	jarPath := filepath.Join(outside, "override-cookies.txt")
	jar := ".example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tFAKE-LEGACY-OVERRIDE-HATCH-555\n"
	if err := os.WriteFile(jarPath, []byte(jar), 0o600); err != nil {
		t.Fatal(err)
	}
	writeLegacyProfile(t, dir, "legacy1", `{"cookies_file": "`+jarPath+`"}`)
	cookiesPath := filepath.Join(dir, "cookies.txt")
	srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, jarPath))
	assertLogsRefused(t, srv, "FAKE-LEGACY-OVERRIDE-HATCH-555")
}

func TestLogsRefusedLegacyOverrideCookiesBak(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	jarPath := filepath.Join(outside, "override-cookies.txt")
	bakPath := jarPath + ".bak"
	jar := ".example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tFAKE-LEGACY-OVERRIDEBAK-HATCH-666\n"
	if err := os.WriteFile(bakPath, []byte(jar), 0o600); err != nil {
		t.Fatal(err)
	}
	writeLegacyProfile(t, dir, "legacy1", `{"cookies_file": "`+jarPath+`"}`)
	cookiesPath := filepath.Join(dir, "cookies.txt")
	srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, bakPath))
	assertLogsRefused(t, srv, "FAKE-LEGACY-OVERRIDEBAK-HATCH-666")
}

func TestLogsRefusedLegacyOverrideRelative(t *testing.T) {
	// Relative override: the value joins the config dir, so
	// the file at the config root holds the jar rows. The
	// parser would coerce this spelling to the profile's own
	// path, but the raw spelling is the one an operator's
	// log.output can name, so the guard must refuse it too.
	dir := t.TempDir()
	relPath := filepath.Join(dir, "legacy-rel-cookies.txt")
	jar := ".example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tFAKE-LEGACYREL-HATCH-777\n"
	if err := os.WriteFile(relPath, []byte(jar), 0o600); err != nil {
		t.Fatal(err)
	}
	writeLegacyProfile(t, dir, "legacy1", `{"cookies_file": "legacy-rel-cookies.txt"}`)
	cookiesPath := filepath.Join(dir, "cookies.txt")
	srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, relPath))
	assertLogsRefused(t, srv, "FAKE-LEGACYREL-HATCH-777")
}

func TestLogsRefusedLegacyConfigUnparseable(t *testing.T) {
	// Fail closed: when a legacy config cannot be decoded,
	// the guard cannot enumerate that profile's cookies
	// files, so it refuses the whole gate instead of serving
	// a file it cannot rule out. A null cookies_file counts
	// as absent (the parser treats it that way), so the
	// legitimate log still tails.
	cases := []struct {
		name          string
		legacy        string
		expectRefused bool
	}{
		{"invalidJSON", `{invalid json`, true},
		{"nonStringCookiesFile", `{"cookies_file": 42}`, true},
		{"nullCookiesFile", `{"cookies_file": null}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeLegacyProfile(t, dir, "legacy1", tc.legacy)
			logPath := filepath.Join(dir, "castctl.log")
			if err := os.WriteFile(logPath, []byte("+0700 2026-10-31 13:00:01 INFO gateway: hello\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cookiesPath := filepath.Join(dir, "cookies.txt")
			srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, logPath))
			rec := logDo(t, srv, "/api/v1/logs")
			if rec.Code != http.StatusOK {
				t.Fatalf("logs: %d: %s", rec.Code, rec.Body.String())
			}
			data := decodeEnvelope(t, rec)["data"].(map[string]any)
			if tc.expectRefused {
				if data["disabled"] != true || data["reason"] != "log_output_refused" {
					t.Fatalf("unparseable legacy config: refused response = %v", data)
				}
			} else if data["disabled"] != false {
				t.Fatalf("null cookies_file: legitimate log refused: %v", data)
			}
		})
	}
}

// Log-gate refusal tests (final fix, M1): a legacy profile
// reached through a SYMLINKED profiles/<name> directory must
// be enumerated exactly like a regular directory, so its
// default cookies path and its cookies_file override (plus
// .bak) are refused. The symlinked directory must pre-exist
// on the filesystem; neither the CLI nor the web UI creates
// symlinked profile dirs. The jar lives inside the symlink
// target and the legacy config names it by absolute target
// path, so both the target spelling and the spelling through
// the symlink name the same cookies file.

func TestLogsRefusedSymlinkedLegacyDirOverride(t *testing.T) {
	cases := []struct {
		name     string
		spelling func(dir, target string) string
		bak      bool
	}{
		{"targetSpelling", func(_, target string) string {
			return filepath.Join(target, "jar-cookies.txt")
		}, false},
		{"symlinkSpelling", func(dir, _ string) string {
			return filepath.Join(dir, "profiles", "linkprof", "jar-cookies.txt")
		}, false},
		{"symlinkSpellingBak", func(dir, _ string) string {
			return filepath.Join(dir, "profiles", "linkprof", "jar-cookies.txt.bak")
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := t.TempDir()
			jarPath := filepath.Join(target, "jar-cookies.txt")
			jar := ".example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tFAKE-SYMDIR-OVERRIDE-HATCH-111\n"
			writePath := jarPath
			if tc.bak {
				writePath = jarPath + ".bak"
			}
			if err := os.WriteFile(writePath, []byte(jar), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, "config.json"), []byte(`{"cookies_file": "`+jarPath+`"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "profiles"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "profiles", "linkprof")); err != nil {
				t.Fatal(err)
			}
			cookiesPath := filepath.Join(dir, "cookies.txt")
			srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, tc.spelling(dir, target)))
			assertLogsRefused(t, srv, "FAKE-SYMDIR-OVERRIDE-HATCH-111")
		})
	}
}

func TestLogsRefusedSymlinkedLegacyDirDefault(t *testing.T) {
	// The legacy config carries no override, so the default
	// path (profiles/linkprof/cookies.txt, through the
	// symlink) is the cookies file. Both spellings of it,
	// plus both .bak spellings, must be refused.
	cases := []struct {
		name     string
		spelling func(dir, target string) string
		bak      bool
	}{
		{"symlinkSpelling", func(dir, _ string) string {
			return filepath.Join(dir, "profiles", "linkprof", "cookies.txt")
		}, false},
		{"targetSpelling", func(_, target string) string {
			return filepath.Join(target, "cookies.txt")
		}, false},
		{"symlinkSpellingBak", func(dir, _ string) string {
			return filepath.Join(dir, "profiles", "linkprof", "cookies.txt.bak")
		}, true},
		{"targetSpellingBak", func(_, target string) string {
			return filepath.Join(target, "cookies.txt.bak")
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := t.TempDir()
			jar := ".example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tFAKE-SYMDIR-DEF-HATCH-222\n"
			writePath := filepath.Join(target, "cookies.txt")
			if tc.bak {
				writePath += ".bak"
			}
			if err := os.WriteFile(writePath, []byte(jar), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, "config.json"), []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "profiles"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "profiles", "linkprof")); err != nil {
				t.Fatal(err)
			}
			cookiesPath := filepath.Join(dir, "cookies.txt")
			srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, tc.spelling(dir, target)))
			assertLogsRefused(t, srv, "FAKE-SYMDIR-DEF-HATCH-222")
		})
	}
}

func TestLogsRefusedWhenLegacyEnumerationFails(t *testing.T) {
	// Fail closed: when the profiles/ enumeration itself
	// fails, the refused set cannot be enumerated, so the
	// whole gate refuses — like the unreadable-config case.
	// A missing profiles/ directory is NOT a failure (no
	// legacy profile can exist), so the legitimate log
	// still tails. Both failure shapes are deterministic
	// filesystem conditions, not permission tricks (which
	// root would bypass): profiles/ as a regular file
	// fails the listing, and a self-symlinked config.json
	// fails the entry stat with ELOOP.
	legitLog := func(t *testing.T, dir string) string {
		t.Helper()
		logPath := filepath.Join(dir, "castctl.log")
		if err := os.WriteFile(logPath, []byte("+0700 2026-10-31 13:00:01 INFO gateway: hello\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return logPath
	}
	t.Run("profilesIsFile", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "profiles"), []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		cookiesPath := filepath.Join(dir, "cookies.txt")
		srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, legitLog(t, dir)))
		assertLogsRefused(t, srv)
	})
	t.Run("configSymlinkLoop", func(t *testing.T) {
		dir := t.TempDir()
		legacyDir := filepath.Join(dir, "profiles", "legacy1")
		if err := os.MkdirAll(legacyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("config.json", filepath.Join(legacyDir, "config.json")); err != nil {
			t.Fatal(err)
		}
		cookiesPath := filepath.Join(dir, "cookies.txt")
		srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, legitLog(t, dir)))
		assertLogsRefused(t, srv)
	})
	t.Run("noProfilesDir", func(t *testing.T) {
		dir := t.TempDir()
		cookiesPath := filepath.Join(dir, "cookies.txt")
		srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, legitLog(t, dir)))
		rec := logDo(t, srv, "/api/v1/logs")
		if rec.Code != http.StatusOK {
			t.Fatalf("logs: %d: %s", rec.Code, rec.Body.String())
		}
		data := decodeEnvelope(t, rec)["data"].(map[string]any)
		if data["disabled"] != false {
			t.Fatalf("no profiles dir: legitimate log refused: %v", data)
		}
		entries, _ := data["entries"].([]any)
		if len(entries) != 1 {
			t.Fatalf("entries = %d, want 1: %v", len(entries), entries)
		}
	})
}

func TestLogsRefusedWhenLegacySymlinkUnresolvable(t *testing.T) {
	// Fail closed: a symlink entry whose target cannot be
	// stat'ed (loop or dangling) is an enumeration failure,
	// not a skip — the entry's config is unreachable, so a
	// jar named directly as log.output would otherwise be
	// served by no rule. There is deliberately no IsNotExist
	// carve-out: a dangling symlink's ENOENT means the
	// target does not resolve. The refusal is a normal gate
	// response, so the handler returns (no hang, no panic);
	// os.Stat on a loop returns ELOOP immediately.
	cases := []struct {
		name   string
		entry  string
		target func(dir string) string
		bak    bool
	}{
		{"symlinkLoop", "loopprof", func(string) string { return "loopprof" }, false},
		{"danglingSymlink", "ghostprof", func(dir string) string { return filepath.Join(dir, "no-such-target") }, false},
		{"danglingSymlinkBak", "ghostprof", func(dir string) string { return filepath.Join(dir, "no-such-target") }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			jarDir := t.TempDir()
			jarPath := filepath.Join(jarDir, "jar-cookies.txt")
			writePath := jarPath
			if tc.bak {
				writePath = jarPath + ".bak"
			}
			jar := ".example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tFAKE-NARROW-LOOP-HATCH-333\n"
			if err := os.WriteFile(writePath, []byte(jar), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "profiles"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(tc.target(dir), filepath.Join(dir, "profiles", tc.entry)); err != nil {
				t.Fatal(err)
			}
			cookiesPath := filepath.Join(dir, "cookies.txt")
			srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, writePath))
			assertLogsRefused(t, srv, "FAKE-NARROW-LOOP-HATCH-333")
		})
	}
}

func TestLogsRefusedInvalidNameLegacyDir(t *testing.T) {
	// Fail closed (code fix, not rewording): an invalid-name
	// directory carrying a config.json is listed by the
	// guard scan, but its refused set cannot be computed
	// (ProfilePaths rejects the name), so the whole gate
	// refuses — its override and default jars are never
	// served. An invalid-name directory WITHOUT a
	// config.json is still skipped (no legacy profile
	// there), so the legitimate log tails; the
	// default-via-profiles-spelling case is likewise a
	// guard (the subtree rule refused it on the old code
	// too). Both guards pass on both heads, by design.
	legitLog := func(t *testing.T, dir string) string {
		t.Helper()
		logPath := filepath.Join(dir, "castctl.log")
		if err := os.WriteFile(logPath, []byte("+0700 2026-10-31 13:00:01 INFO gateway: hello\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return logPath
	}
	marker := "FAKE-NARROW-BADNAME-HATCH-444"
	jar := ".example.com\tTRUE\t/\tFALSE\t0\thatch_sess\t" + marker + "\n"
	t.Run("absoluteOverride", func(t *testing.T) {
		dir := t.TempDir()
		jarDir := t.TempDir()
		jarPath := filepath.Join(jarDir, "jar-cookies.txt")
		if err := os.WriteFile(jarPath, []byte(jar), 0o600); err != nil {
			t.Fatal(err)
		}
		legacyDir := filepath.Join(dir, "profiles", "bad name")
		if err := os.MkdirAll(legacyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(legacyDir, "config.json"), []byte(`{"cookies_file": "`+jarPath+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		cookiesPath := filepath.Join(dir, "cookies.txt")
		srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, jarPath))
		assertLogsRefused(t, srv, marker)
	})
	t.Run("overrideBak", func(t *testing.T) {
		dir := t.TempDir()
		jarDir := t.TempDir()
		jarPath := filepath.Join(jarDir, "jar-cookies.txt")
		if err := os.WriteFile(jarPath+".bak", []byte(jar), 0o600); err != nil {
			t.Fatal(err)
		}
		legacyDir := filepath.Join(dir, "profiles", "bad name")
		if err := os.MkdirAll(legacyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(legacyDir, "config.json"), []byte(`{"cookies_file": "`+jarPath+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		cookiesPath := filepath.Join(dir, "cookies.txt")
		srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, jarPath+".bak"))
		assertLogsRefused(t, srv, marker)
	})
	t.Run("defaultViaProfilesSpelling", func(t *testing.T) {
		dir := t.TempDir()
		legacyDir := filepath.Join(dir, "profiles", "bad name")
		if err := os.MkdirAll(legacyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(legacyDir, "config.json"), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		jarPath := filepath.Join(legacyDir, "cookies.txt")
		if err := os.WriteFile(jarPath, []byte(jar), 0o600); err != nil {
			t.Fatal(err)
		}
		cookiesPath := filepath.Join(dir, "cookies.txt")
		srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, jarPath))
		assertLogsRefused(t, srv, marker)
	})
	t.Run("symlinkedDefaultTargetSpelling", func(t *testing.T) {
		dir := t.TempDir()
		target := t.TempDir()
		if err := os.WriteFile(filepath.Join(target, "config.json"), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		jarPath := filepath.Join(target, "cookies.txt")
		if err := os.WriteFile(jarPath, []byte(jar), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "profiles"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "profiles", "bad name")); err != nil {
			t.Fatal(err)
		}
		cookiesPath := filepath.Join(dir, "cookies.txt")
		srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, jarPath))
		assertLogsRefused(t, srv, marker)
	})
	t.Run("symlinkedDefaultTargetBak", func(t *testing.T) {
		dir := t.TempDir()
		target := t.TempDir()
		if err := os.WriteFile(filepath.Join(target, "config.json"), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		jarPath := filepath.Join(target, "cookies.txt")
		if err := os.WriteFile(jarPath+".bak", []byte(jar), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "profiles"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "profiles", "bad name")); err != nil {
			t.Fatal(err)
		}
		cookiesPath := filepath.Join(dir, "cookies.txt")
		srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, jarPath+".bak"))
		assertLogsRefused(t, srv, marker)
	})
	t.Run("noConfigSkipped", func(t *testing.T) {
		dir := t.TempDir()
		legacyDir := filepath.Join(dir, "profiles", "bad name")
		if err := os.MkdirAll(legacyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		cookiesPath := filepath.Join(dir, "cookies.txt")
		srv := logServerFromConfig(t, dir, logConfigWithOutput(t, dir, cookiesPath, legitLog(t, dir)))
		rec := logDo(t, srv, "/api/v1/logs")
		if rec.Code != http.StatusOK {
			t.Fatalf("logs: %d: %s", rec.Code, rec.Body.String())
		}
		data := decodeEnvelope(t, rec)["data"].(map[string]any)
		if data["disabled"] != false {
			t.Fatalf("no-config invalid-name dir: legitimate log refused: %v", data)
		}
		entries, _ := data["entries"].([]any)
		if len(entries) != 1 {
			t.Fatalf("entries = %d, want 1: %v", len(entries), entries)
		}
	})
}

func TestDisplayCallersDegradeOnGuardEnumerationError(t *testing.T) {
	// Guard (green on both old and new code, by design):
	// display-only callers (config source, profile
	// summaries) degrade gracefully when the guard
	// enumeration fails — 200, no crash, no marker served.
	// Fixtures: an invalid-name legacy dir with a config
	// (whose refused set cannot be computed) and a
	// dangling-symlink legacy dir (whose target cannot be
	// stat'ed). The gate itself still fails closed for
	// these fixtures; that is proven by the gate tests
	// above, not here.
	ts := newTestServer(t, fixtureConfig, nil)
	legacyDir := filepath.Join(ts.dir, "profiles", "bad name")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	jarDir := t.TempDir()
	jarPath := filepath.Join(jarDir, "jar-cookies.txt")
	marker := "FAKE-NARROW-DISPLAY-HATCH-555"
	if err := os.WriteFile(jarPath, []byte(".example.com\tTRUE\t/\tFALSE\t0\thatch_sess\t"+marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "config.json"), []byte(`{"cookies_file": "`+jarPath+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(ts.dir, "no-such-target"), filepath.Join(ts.dir, "profiles", "ghostprof")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/profiles", "/api/v1/config"} {
		rec := ts.do(t, "GET", path, "", true)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d: %s", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), marker) {
			t.Fatalf("%s: marker leaked:\n%s", path, rec.Body.String())
		}
	}
}

func TestLogsRefusedRawCoercedCookiesFile(t *testing.T) {
	// Guard (green on both old and new code): a raw
	// single-file cookies_file value the parser coerces to
	// the profile's own path — the raw spelling itself must
	// still be refused when named as the log output.
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "cookies.txt")
	jar := ".example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tFAKE-RAW-COERCED-HATCH-888\n"
	if err := os.WriteFile(rawPath, []byte(jar), 0o600); err != nil {
		t.Fatal(err)
	}
	config := `{
  "default_profile": "muse01",
  "profiles": {"muse01": {"cookies_file": "cookies.txt"}},
  "log": {"output": "` + rawPath + `", "timestamp": true}
}`
	srv := logServerFromConfig(t, dir, config)
	assertLogsRefused(t, srv, "FAKE-RAW-COERCED-HATCH-888")
}

func TestLogsInvalidLimitRejected(t *testing.T) {
	// N-T11: an invalid limit is a 400 like an invalid
	// cursor, not a silent fallback to the default. The
	// frontend always sends a valid limit (PAGE_LIMIT) or
	// omits the parameter, so no legitimate caller depends
	// on the fallback.
	srv, dir := newLogTestServer(t, logBlockConfig)
	logPath := filepath.Join(dir, "castctl.log")
	lines := "+0700 2026-10-31 13:00:01 INFO gateway: one\n" +
		"+0700 2026-10-31 13:00:02 INFO gateway: two\n"
	if err := os.WriteFile(logPath, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"0", "-1", "501", "abc"} {
		rec := logDo(t, srv, "/api/v1/logs?limit="+q)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "validation_failed") {
			t.Fatalf("limit=%q: got %d: %s", q, rec.Code, rec.Body.String())
		}
	}
	rec := logDo(t, srv, "/api/v1/logs?limit=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("limit=1: %d: %s", rec.Code, rec.Body.String())
	}
	entries, _ := decodeEnvelope(t, rec)["data"].(map[string]any)["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("limit=1: entries = %d, want 1", len(entries))
	}
}

func collectLogMessages(t *testing.T, srv *Server, path string) ([]string, map[string]any) {
	t.Helper()
	rec := logDo(t, srv, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("logs %s: %d: %s", path, rec.Code, rec.Body.String())
	}
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	data := env["data"].(map[string]any)
	entries, _ := data["entries"].([]any)
	msgs := []string{}
	for _, e := range entries {
		msgs = append(msgs, e.(map[string]any)["message"].(string))
	}
	return msgs, data
}

func TestLogsCursorPaginationNoLoss(t *testing.T) {
	srv, dir := newLogTestServer(t, logBlockConfig)
	logPath := filepath.Join(dir, "castctl.log")
	var b strings.Builder
	want := []string{}
	for i := 0; i < 12; i++ {
		msg := "line-" + itoa(i)
		want = append(want, msg)
		b.WriteString("+0700 2026-10-31 13:00:01 INFO gateway: " + msg + "\n")
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []string
	cursor := "0"
	for page := 0; page < 10; page++ {
		msgs, data := collectLogMessages(t, srv, "/api/v1/logs?cursor="+cursor+"&limit=5")
		got = append(got, msgs...)
		more, _ := data["more"].(bool)
		next, _ := data["next_cursor"].(string)
		if !more {
			if len(msgs) == 0 && page == 0 {
				t.Fatal("first page empty with more=false")
			}
			break
		}
		if next == "" || next == cursor {
			t.Fatalf("page %d: more=true but next_cursor %q did not advance from %q", page, next, cursor)
		}
		cursor = next
		if page == 9 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(got) != len(want) {
		t.Fatalf("paginated messages = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("message %d = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}

func TestLogsLevelFilterBeforeTruncate(t *testing.T) {
	srv, dir := newLogTestServer(t, logBlockConfig)
	logPath := filepath.Join(dir, "castctl.log")
	var b strings.Builder
	for i := 0; i < 8; i++ {
		level := "INFO"
		if i%2 == 1 {
			level = "ERROR"
		}
		b.WriteString("+0700 2026-10-31 13:00:01 " + level + " gateway: line-" + itoa(i) + "\n")
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []string
	cursor := "0"
	for page := 0; page < 10; page++ {
		msgs, data := collectLogMessages(t, srv, "/api/v1/logs?cursor="+cursor+"&limit=2&level=error")
		got = append(got, msgs...)
		more, _ := data["more"].(bool)
		next, _ := data["next_cursor"].(string)
		if !more {
			break
		}
		if next == "" || next == cursor {
			t.Fatalf("page %d: more=true but next_cursor %q did not advance", page, next)
		}
		cursor = next
		if page == 9 {
			t.Fatal("pagination did not terminate")
		}
	}
	want := []string{"line-1", "line-3", "line-5", "line-7"}
	if len(got) != len(want) {
		t.Fatalf("filtered messages = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("filtered message %d = %q, want %q", i, got[i], want[i])
		}
	}
}
