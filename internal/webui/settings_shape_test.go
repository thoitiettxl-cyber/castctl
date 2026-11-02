// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Settings GET shape contract (D-WEBUI-GET, fix loop 3).
//
// The frontend consumes every settings GET through the `data`
// envelope and reads the fields its TS types declare. The
// server once wrapped GET /settings/webui under a nested
// "settings" key while the dev mock returned the flat shape,
// so the frontend tests passed and the real editor failed to
// load. This test pins the wire shape of EVERY settings GET
// against the TS types, so a future drift fails here instead
// of silently in the browser.
//
// Shared field list (asserted here server-side and by the
// dev-mock shape check in webui/tests/mockServer.test.ts):
//
//	GET /dns              -> {dns: object, sha256}
//	                         (inline type, webui/src/services/api/index.ts:129)
//	GET /settings/telegram -> TelegramSettings
//	                         (webui/src/types/api.ts:121)
//	GET /settings/keeper   -> KeeperSettings + KeeperSettingsEntry
//	                         (webui/src/types/api.ts:257, :265)
//	GET /settings/webui    -> WebUISettings
//	                         (webui/src/types/api.ts:273)
//
// Additive Go-only fields NOT declared in the TS types are
// sanctioned explicitly and nowhere else: webui
// session_idle_timeout_seconds + login_rate_limit.window_seconds
// (view struct, sections.go) and keeper entry interval_seconds
// (keeperSettingsEntry, sections.go). Any other extra key fails
// this test: add it to the TS type first, then here.

var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// settingsShapeFixture exercises all four settings GETs at
// once: keeper + telegram blocks (keeperFixtureConfig) plus a
// dns section and a listen-only webui block. Placeholder
// fixture values only; auth uses the harness test token, not
// the config's webui token.
func settingsShapeFixture() string {
	return strings.TrimSuffix(keeperFixtureConfig, "}") +
		`,"dns": {"servers": [{"tag": "dns1", "type": "tcp", "server": "127.0.0.1", "server_port": 5353}], "final": "dns1"}` +
		`,"webui": {"listen": "127.0.0.1:8317"}}`
}

func getSettingsData(t *testing.T, ts *testServer, path string) map[string]any {
	t.Helper()
	rec := ts.do(t, "GET", path, "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: got %d: %s", path, rec.Code, rec.Body.String())
	}
	data, _ := decodeEnvelope(t, rec)["data"].(map[string]any)
	if data == nil {
		t.Fatalf("GET %s: envelope data is not an object: %s", path, rec.Body.String())
	}
	return data
}

func exactKeys(t *testing.T, what string, got map[string]any, want ...string) {
	t.Helper()
	var keys []string
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sort.Strings(want)
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("%s keys = %v, want %v", what, keys, want)
	}
}

func asString(t *testing.T, what string, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key].(string)
	if !ok {
		t.Fatalf("%s: %q = %v (%T), want string", what, key, m[key], m[key])
	}
	return v
}

func asBool(t *testing.T, what string, m map[string]any, key string) bool {
	t.Helper()
	v, ok := m[key].(bool)
	if !ok {
		t.Fatalf("%s: %q = %v (%T), want bool", what, key, m[key], m[key])
	}
	return v
}

func asNumber(t *testing.T, what string, m map[string]any, key string) float64 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("%s: %q = %v (%T), want number", what, key, m[key], m[key])
	}
	return v
}

func asObject(t *testing.T, what string, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("%s: %q = %v (%T), want object", what, key, m[key], m[key])
	}
	return v
}

func asArray(t *testing.T, what string, m map[string]any, key string) []any {
	t.Helper()
	v, ok := m[key].([]any)
	if !ok {
		t.Fatalf("%s: %q = %v (%T), want array", what, key, m[key], m[key])
	}
	return v
}

func checkSHA256(t *testing.T, what string, m map[string]any) {
	t.Helper()
	sha := asString(t, what, m, "sha256")
	if !sha256HexPattern.MatchString(sha) {
		t.Fatalf("%s: sha256 = %q, want 64 lowercase hex", what, sha)
	}
}

func TestSettingsGETShapesMatchFrontend(t *testing.T) {
	ts := newTestServer(t, settingsShapeFixture(), nil)

	t.Run("dns", func(t *testing.T) {
		// Inline type {dns: Record<string, unknown>; sha256: string}
		// (webui/src/services/api/index.ts:129), consumed as
		// result.dns / result.sha256 in SettingsPage loadDns.
		data := getSettingsData(t, ts, "/api/v1/dns")
		exactKeys(t, "GET /dns", data, "dns", "sha256")
		checkSHA256(t, "GET /dns", data)
		dns := asObject(t, "GET /dns", data, "dns")
		servers := asArray(t, "GET /dns dns", dns, "servers")
		if len(servers) != 1 {
			t.Fatalf("dns servers = %v, want 1", servers)
		}
		if asString(t, "GET /dns dns", dns, "final") != "dns1" {
			t.Fatalf("dns final = %v, want dns1", dns["final"])
		}
	})

	t.Run("telegram", func(t *testing.T) {
		// TelegramSettings (webui/src/types/api.ts:121).
		data := getSettingsData(t, ts, "/api/v1/settings/telegram")
		exactKeys(t, "GET /settings/telegram", data,
			"configured", "masked", "profile", "allowed_user_ids", "auto_approve", "auto_allow_once")
		if !asBool(t, "GET /settings/telegram", data, "configured") {
			t.Fatalf("configured = false, want true (fixture has a telegram block)")
		}
		if asString(t, "GET /settings/telegram", data, "masked") != "***" {
			t.Fatalf("masked = %q, want ***", data["masked"])
		}
		if asString(t, "GET /settings/telegram", data, "profile") != "muse01" {
			t.Fatalf("profile = %q, want muse01", data["profile"])
		}
		ids := asArray(t, "GET /settings/telegram", data, "allowed_user_ids")
		if len(ids) != 1 || ids[0] != float64(12345) {
			t.Fatalf("allowed_user_ids = %v, want [12345]", ids)
		}
		if asBool(t, "GET /settings/telegram", data, "auto_approve") {
			t.Fatalf("auto_approve = true, want false")
		}
		if asBool(t, "GET /settings/telegram", data, "auto_allow_once") {
			t.Fatalf("auto_allow_once = true, want false")
		}
	})

	t.Run("keeper", func(t *testing.T) {
		// KeeperSettings + KeeperSettingsEntry
		// (webui/src/types/api.ts:257, :265). interval_seconds
		// is the sanctioned additive field.
		data := getSettingsData(t, ts, "/api/v1/settings/keeper")
		exactKeys(t, "GET /settings/keeper", data, "entries", "sha256")
		checkSHA256(t, "GET /settings/keeper", data)
		entries := asArray(t, "GET /settings/keeper", data, "entries")
		if len(entries) != 1 {
			t.Fatalf("entries = %v, want 1", entries)
		}
		entry, _ := entries[0].(map[string]any)
		if entry == nil {
			t.Fatalf("entry is not an object: %v", entries[0])
		}
		exactKeys(t, "GET /settings/keeper entry", entry,
			"tag", "profile", "browser", "interval", "interval_seconds", "notify")
		if asString(t, "GET /settings/keeper entry", entry, "tag") != "k1" ||
			asString(t, "GET /settings/keeper entry", entry, "profile") != "muse01" ||
			asString(t, "GET /settings/keeper entry", entry, "browser") != "http://127.0.0.1:9226" {
			t.Fatalf("entry identity = %v", entry)
		}
		if asString(t, "GET /settings/keeper entry", entry, "interval") != "24h0m0s" {
			t.Fatalf("interval = %q, want 24h0m0s", entry["interval"])
		}
		if asNumber(t, "GET /settings/keeper entry", entry, "interval_seconds") != 86400 {
			t.Fatalf("interval_seconds = %v, want 86400", entry["interval_seconds"])
		}
	})

	t.Run("webui", func(t *testing.T) {
		// WebUISettings (webui/src/types/api.ts:273).
		// session_idle_timeout_seconds + window_seconds are
		// the sanctioned additive fields. A nested "settings"
		// key fails exactKeys: that was D-WEBUI-GET.
		data := getSettingsData(t, ts, "/api/v1/settings/webui")
		exactKeys(t, "GET /settings/webui", data,
			"listen", "ui_dir", "token_set", "masked",
			"session_idle_timeout", "session_idle_timeout_seconds",
			"login_rate_limit", "sha256")
		checkSHA256(t, "GET /settings/webui", data)
		if asString(t, "GET /settings/webui", data, "listen") != "127.0.0.1:8317" {
			t.Fatalf("listen = %q, want 127.0.0.1:8317", data["listen"])
		}
		asString(t, "GET /settings/webui", data, "ui_dir")
		if asBool(t, "GET /settings/webui", data, "token_set") {
			t.Fatalf("token_set = true, want false (fixture webui block has no token)")
		}
		if asString(t, "GET /settings/webui", data, "masked") != "" {
			t.Fatalf("masked = %q, want empty (no token stored)", data["masked"])
		}
		if asString(t, "GET /settings/webui", data, "session_idle_timeout") != "12h0m0s" {
			t.Fatalf("session_idle_timeout = %q, want 12h0m0s (default)", data["session_idle_timeout"])
		}
		if asNumber(t, "GET /settings/webui", data, "session_idle_timeout_seconds") != 43200 {
			t.Fatalf("session_idle_timeout_seconds = %v, want 43200", data["session_idle_timeout_seconds"])
		}
		limit := asObject(t, "GET /settings/webui", data, "login_rate_limit")
		exactKeys(t, "GET /settings/webui login_rate_limit", limit,
			"attempts", "window", "window_seconds")
		if asNumber(t, "GET /settings/webui login_rate_limit", limit, "attempts") != 5 {
			t.Fatalf("attempts = %v, want 5 (default)", limit["attempts"])
		}
		if asString(t, "GET /settings/webui login_rate_limit", limit, "window") != "5m0s" {
			t.Fatalf("window = %q, want 5m0s (default)", limit["window"])
		}
		if asNumber(t, "GET /settings/webui login_rate_limit", limit, "window_seconds") != 300 {
			t.Fatalf("window_seconds = %v, want 300", limit["window_seconds"])
		}
	})
}
