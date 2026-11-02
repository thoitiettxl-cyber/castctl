// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/redact"
)

// topLevelKeys returns a JSON document's top-level keys in
// stored order, via a token stream (a map decode would lose
// order). Used to prove a section save does not reorder keys.
func topLevelKeys(t *testing.T, data []byte) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(data)))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("top-level token = %v, %v", tok, err)
	}
	var keys []string
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			t.Fatalf("key token: %v", err)
		}
		keys = append(keys, keyTok.(string))
		var skip any
		if err := dec.Decode(&skip); err != nil {
			t.Fatalf("skip value: %v", err)
		}
	}
	return keys
}

func readTestConfig(t *testing.T, ts *testServer) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	return data
}

func getSettingsSHA(t *testing.T, ts *testServer, path string) (map[string]any, string) {
	t.Helper()
	rec := ts.do(t, "GET", path, "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: got %d: %s", path, rec.Code, rec.Body.String())
	}
	env := decodeEnvelope(t, rec)
	data, _ := env["data"].(map[string]any)
	sha, _ := data["sha256"].(string)
	return data, sha
}

const keeperFixtureConfig = `{
  "default_profile": "muse01",
  "profiles": {
    "muse01": {
      "cookies_file": "COOKIESFILE",
      "vm_id": "FAKE-SECRET-VMID",
      "node_id": "FAKE-SECRET-NODEID",
      "outbound": "proxy-eu",
      "fingerprint": "chrome"
    },
    "muse02": {
      "cookies_file": "COOKIESFILE2",
      "vm_id": "FAKE-SECRET-VMID2",
      "node_id": "FAKE-SECRET-NODEID2",
      "outbound": "proxy-eu",
      "fingerprint": "chrome"
    }
  },
  "outbounds": [
    {"type": "trojan", "tag": "proxy-eu", "server": "203.0.113.10", "server_port": 443, "password": "FAKE-SECRET-TROJAN"}
  ],
  "keeper": [
    {"tag": "k1", "profile": "muse01", "browser": "http://127.0.0.1:9226", "interval": "24h"}
  ]
}`

func TestKeeperSettingsGetPutRoundTrip(t *testing.T) {
	ts := newTestServer(t, keeperFixtureConfig, nil)
	before := readTestConfig(t, ts)
	beforeKeys := topLevelKeys(t, before)

	data, sha := getSettingsSHA(t, ts, "/api/v1/settings/keeper")
	entries, _ := data["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries = %v, want 1", entries)
	}
	entry, _ := entries[0].(map[string]any)
	if entry["tag"] != "k1" || entry["interval"] != "24h0m0s" || entry["interval_seconds"] != float64(86400) {
		t.Fatalf("entry = %v", entry)
	}

	// PUT a second entry + a changed interval, with the fresh
	// base hash: the save succeeds, the file re-parses, and
	// the top-level key order is unchanged. (One entry per
	// profile: the second entry names muse02.)
	body := `{"entries":[
	  {"tag":"k1","profile":"muse01","browser":"http://127.0.0.1:9226","interval":"12h"},
	  {"tag":"k2","profile":"muse02","browser":"http://127.0.0.1:9227"}
	],"base_sha256":"` + sha + `"}`
	rec := ts.do(t, "PUT", "/api/v1/settings/keeper", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT keeper: got %d: %s", rec.Code, rec.Body.String())
	}
	after := readTestConfig(t, ts)
	if got := topLevelKeys(t, after); strings.Join(got, ",") != strings.Join(beforeKeys, ",") {
		t.Fatalf("top-level key order changed: %v -> %v", beforeKeys, got)
	}
	cfg, err := profile.ParseSingleConfig(after, ts.dir)
	if err != nil {
		t.Fatalf("saved config does not parse: %v", err)
	}
	if cfg.Keeper == nil || len(cfg.Keeper.Entries) != 2 {
		t.Fatalf("keeper entries after save = %+v", cfg.Keeper)
	}
	// Re-GET shows the saved values and a new hash.
	data2, sha2 := getSettingsSHA(t, ts, "/api/v1/settings/keeper")
	if sha2 == sha {
		t.Fatal("sha256 did not change after PUT")
	}
	entries2, _ := data2["entries"].([]any)
	if len(entries2) != 2 {
		t.Fatalf("entries after save = %v", entries2)
	}
	// A stale base hash is a 409 with no write.
	stale := `{"entries":[],"base_sha256":"` + sha + `"}`
	rec = ts.do(t, "PUT", "/api/v1/settings/keeper", stale, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale PUT: got %d, want 409", rec.Code)
	}
	if got := readTestConfig(t, ts); string(got) != string(after) {
		t.Fatal("stale PUT modified the file")
	}
	// An invalid entry (dangling profile) is a 400 with no write.
	bad := `{"entries":[{"tag":"k9","profile":"nope","browser":"http://127.0.0.1:9226"}],"base_sha256":"` + sha2 + `"}`
	rec = ts.do(t, "PUT", "/api/v1/settings/keeper", bad, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("dangling profile PUT: got %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got := readTestConfig(t, ts); string(got) != string(after) {
		t.Fatal("invalid PUT modified the file")
	}
	// Unknown entry key, missing entries, and missing base
	// hash are all 400s with no write.
	for _, badBody := range []string{
		`{"entries":[{"tag":"k1","profile":"muse01","browser":"http://127.0.0.1:9226","bogus":1}],"base_sha256":"` + sha2 + `"}`,
		`{"base_sha256":"` + sha2 + `"}`,
		`{"entries":[],"base_sha256":""}`,
	} {
		rec = ts.do(t, "PUT", "/api/v1/settings/keeper", badBody, true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s: got %d, want 400", badBody, rec.Code)
		}
	}
	if got := readTestConfig(t, ts); string(got) != string(after) {
		t.Fatal("rejected PUT modified the file")
	}
	// null deletes the block.
	rec = ts.do(t, "PUT", "/api/v1/settings/keeper", `{"entries":null,"base_sha256":"`+sha2+`"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete PUT: got %d: %s", rec.Code, rec.Body.String())
	}
	data3, _ := getSettingsSHA(t, ts, "/api/v1/settings/keeper")
	if entries3, _ := data3["entries"].([]any); len(entries3) != 0 {
		t.Fatalf("entries after delete = %v", entries3)
	}
}

// webuiSettingsFixture appends a `webui` block (in canonical
// last position) to the fixture config. The stored token is a
// bcrypt hash of the test token — as production leaves it
// after hashWebUITokenOnStart — so API saves that re-adopt the
// stored hash keep authenticating the test token. A plaintext
// marker token here would be hash-on-saved by the first PUT
// and legitimately replace the live comparator.
func webuiSettingsFixture(t *testing.T) string {
	t.Helper()
	hash := testTokenHash(t)
	return strings.TrimSuffix(fixtureConfig, "}") + `,"webui":{"token":"` + hash + `","listen":"127.0.0.1:8317"}}`
}

func TestWebUISettingsGetDefaults(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	data, _ := getSettingsSHA(t, ts, "/api/v1/settings/webui")
	settings, _ := data["settings"].(map[string]any)
	if settings["token_set"] != false || settings["masked"] != "" {
		t.Fatalf("settings without a webui block: %v", settings)
	}
	if settings["session_idle_timeout_seconds"] != float64(43200) {
		t.Fatalf("default idle seconds = %v, want 43200", settings["session_idle_timeout_seconds"])
	}
	limit, _ := settings["login_rate_limit"].(map[string]any)
	if limit["attempts"] != float64(5) || limit["window_seconds"] != float64(300) {
		t.Fatalf("default rate limit = %v", limit)
	}
}

func TestWebUISettingsPutRoundTrip(t *testing.T) {
	ts := newTestServer(t, webuiSettingsFixture(t), nil)
	before := readTestConfig(t, ts)
	beforeKeys := topLevelKeys(t, before)

	data, sha := getSettingsSHA(t, ts, "/api/v1/settings/webui")
	settings, _ := data["settings"].(map[string]any)
	if settings["token_set"] != true || settings["masked"] != "***" {
		t.Fatalf("settings view: %v", settings)
	}
	if settings["listen"] != "127.0.0.1:8317" {
		t.Fatalf("listen = %v", settings["listen"])
	}

	// Set the idle timeout + rate limit. The stored file must
	// re-parse, keep key order, and keep the stored token a
	// bcrypt hash (the hashed fixture token passes through
	// hash-on-save untouched).
	body := `{"session_idle_timeout":"6h","login_rate_limit":{"attempts":3,"window":"10m"},"base_sha256":"` + sha + `"}`
	rec := ts.do(t, "PUT", "/api/v1/settings/webui", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT webui settings: got %d: %s", rec.Code, rec.Body.String())
	}
	after := readTestConfig(t, ts)
	if got := topLevelKeys(t, after); strings.Join(got, ",") != strings.Join(beforeKeys, ",") {
		t.Fatalf("top-level key order changed: %v -> %v", beforeKeys, got)
	}
	parsed, err := profile.ParseSingleConfig(after, ts.dir)
	if err != nil {
		t.Fatalf("saved config does not parse: %v", err)
	}
	if !parsed.WebUI.SessionIdleTimeoutSet || parsed.WebUI.SessionIdleTimeout != 6*time.Hour {
		t.Fatalf("idle timeout = %+v", parsed.WebUI)
	}
	if parsed.WebUI.LoginRateLimit == nil || parsed.WebUI.LoginRateLimit.Attempts != 3 {
		t.Fatalf("rate limit = %+v", parsed.WebUI.LoginRateLimit)
	}
	if !profile.LooksLikeBcryptHash(parsed.WebUI.Token) {
		t.Fatalf("stored token is not a bcrypt hash after save: %q", parsed.WebUI.Token)
	}
	data2, sha2 := getSettingsSHA(t, ts, "/api/v1/settings/webui")
	settings2, _ := data2["settings"].(map[string]any)
	if settings2["session_idle_timeout_seconds"] != float64(21600) {
		t.Fatalf("idle seconds after save = %v", settings2["session_idle_timeout_seconds"])
	}
	limit2, _ := settings2["login_rate_limit"].(map[string]any)
	if limit2["attempts"] != float64(3) || limit2["window_seconds"] != float64(600) {
		t.Fatalf("rate limit after save = %v", limit2)
	}
	// Stale base -> 409, no write. Invalid duration -> 400,
	// no write. Unknown key -> 400.
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"session_idle_timeout":"6h","base_sha256":"` + sha + `"}`, http.StatusConflict},
		{`{"session_idle_timeout":"soon","base_sha256":"` + sha2 + `"}`, http.StatusBadRequest},
		{`{"session_idle_timeout":"0s","base_sha256":"` + sha2 + `"}`, http.StatusBadRequest},
		{`{"bogus":1,"base_sha256":"` + sha2 + `"}`, http.StatusBadRequest},
		{`{"login_rate_limit":{"attempts":0},"base_sha256":"` + sha2 + `"}`, http.StatusBadRequest},
		{`{"login_rate_limit":{"window":""},"base_sha256":"` + sha2 + `"}`, http.StatusBadRequest},
	} {
		rec = ts.do(t, "PUT", "/api/v1/settings/webui", tc.body, true)
		if rec.Code != tc.want {
			t.Fatalf("body %s: got %d, want %d: %s", tc.body, rec.Code, tc.want, rec.Body.String())
		}
	}
	if got := readTestConfig(t, ts); string(got) != string(after) {
		t.Fatal("rejected PUT modified the file")
	}
	// Deleting the rate-limit key restores defaults.
	rec = ts.do(t, "PUT", "/api/v1/settings/webui", `{"login_rate_limit":null,"base_sha256":"`+sha2+`"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete limit: got %d: %s", rec.Code, rec.Body.String())
	}
	data3, _ := getSettingsSHA(t, ts, "/api/v1/settings/webui")
	limit3, _ := data3["settings"].(map[string]any)["login_rate_limit"].(map[string]any)
	if limit3["attempts"] != float64(5) {
		t.Fatalf("rate limit after delete = %v, want defaults", limit3)
	}
}

func TestWebUISettingsTokenRotation(t *testing.T) {
	ts := newTestServer(t, webuiSettingsFixture(t), nil)
	_, sha := getSettingsSHA(t, ts, "/api/v1/settings/webui")

	// A placeholder token is rejected, with no write.
	before := readTestConfig(t, ts)
	for _, ph := range []string{"***", redact.Marker} {
		rec := ts.do(t, "PUT", "/api/v1/settings/webui", `{"token":"`+ph+`","base_sha256":"`+sha+`"}`, true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("placeholder %q: got %d, want 400", ph, rec.Code)
		}
	}
	if got := readTestConfig(t, ts); string(got) != string(before) {
		t.Fatal("placeholder PUT modified the file")
	}
	// An empty token leaves the stored token unchanged: the
	// old Bearer still authenticates afterwards.
	rec := ts.do(t, "PUT", "/api/v1/settings/webui", `{"token":"","session_idle_timeout":"6h","base_sha256":"`+sha+`"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty-token PUT: got %d: %s", rec.Code, rec.Body.String())
	}
	_, sha2 := getSettingsSHA(t, ts, "/api/v1/settings/webui")
	if rec := ts.do(t, "GET", "/api/v1/status", "", true); rec.Code != http.StatusOK {
		t.Fatalf("old token after empty-token PUT: got %d, want 200", rec.Code)
	}
	// Rotate: the new token authenticates, the old one 401s,
	// the stored value is a bcrypt hash, and the plaintext
	// never appears in any response or on disk.
	const newToken = "MARKER-ROTATED-TOKEN-12345"
	rec = ts.do(t, "PUT", "/api/v1/settings/webui", `{"token":"`+newToken+`","base_sha256":"`+sha2+`"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate PUT: got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), newToken) {
		t.Fatalf("rotate response echoes the token: %s", rec.Body.String())
	}
	if rec := ts.do(t, "GET", "/api/v1/status", "", true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old token after rotation: got %d, want 401", rec.Code)
	}
	if rec := ts.doToken(t, "GET", "/api/v1/status", "", newToken); rec.Code != http.StatusOK {
		t.Fatalf("new token after rotation: got %d, want 200", rec.Code)
	}
	after := readTestConfig(t, ts)
	if strings.Contains(string(after), newToken) {
		t.Fatal("plaintext token persisted on disk")
	}
	parsed, err := profile.ParseSingleConfig(after, ts.dir)
	if err != nil {
		t.Fatalf("saved config does not parse: %v", err)
	}
	if !profile.LooksLikeBcryptHash(parsed.WebUI.Token) {
		t.Fatalf("stored token after rotation is not a bcrypt hash: %q", parsed.WebUI.Token)
	}
}
