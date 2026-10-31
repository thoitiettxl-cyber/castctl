// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"crypto/sha256"
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
	sum := sha256.Sum256([]byte(testToken))
	srv, err := New(Deps{
		ConfigDir:    dir,
		Version:      "t",
		ListenAddr:   "127.0.0.1:8317",
		TokenHash:    sum,
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
	sum := sha256.Sum256([]byte(testToken))
	srv, err := New(Deps{
		ConfigDir:    dir,
		Version:      "t",
		ListenAddr:   "127.0.0.1:8317",
		TokenHash:    sum,
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
