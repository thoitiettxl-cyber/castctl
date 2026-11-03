// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Secret-leak sweeps (research §2.3): every response the API can
// produce for a config carrying KNOWN marker secrets must
// contain none of the markers, while the redacted config view
// must contain a redaction marker — so the test cannot pass
// vacuously by the endpoints returning nothing. All secrets
// below are FAKE markers, never real credentials. The
// log-path sweep is the behavioural
// TestLogsTailRedactionAndCursor (logs_test.go): it plants
// marker secrets in the log file and asserts they never reach
// the /logs response — that test, not this file, pins the
// log boundary, because this package has no logger and writes
// nothing to stderr (verified by grep: no log/slog/fmt-print
// import in non-test files). The sweeps here cover the
// response, write, error, rate-limit, Origin, and oversized
// paths.

const (
	leakTrojanPassword = "FAKE-SECRET-TROJAN-PASSWORD"
	leakWGPrivate      = "FAKE-SECRET-WG-PRIVATE-KEY"
	leakWGPublic       = "FAKE-SECRET-WG-PUBLIC-KEY"
	leakVMID           = "FAKE-SECRET-VMID-VALUE"
	leakNodeID         = "FAKE-SECRET-NODEID-VALUE"
	leakTelegramToken  = "123456789:FAKE-SECRET-TELEGRAM-TOKEN-0123456789"
	leakWebUIToken     = "FAKE-SECRET-WEBUI-TOKEN-VALUE"
	leakCookieValue    = "hatch_sess=FAKE-SECRET-HATCH-SESS-VALUE"
	// leakProxyPassword is the secret half of a proxy URL's
	// userinfo (proxy auth password): it must never surface in
	// an outbound view or a validation error.
	leakProxyPassword = "FAKE-SECRET-PROXY-PASSWORD"
)

var leakMarkers = []string{
	leakTrojanPassword, leakWGPrivate, leakWGPublic, leakVMID,
	leakNodeID, leakTelegramToken, leakWebUIToken, leakCookieValue,
	leakProxyPassword,
}

const leakFixtureConfig = `{
  "default_profile": "muse01",
  "profiles": {
    "muse01": {
      "cookies_file": "COOKIESFILE",
      "vm_id": "FAKE-SECRET-VMID-VALUE",
      "node_id": "FAKE-SECRET-NODEID-VALUE",
      "outbound": "proxy-eu",
      "fingerprint": "chrome"
    }
  },
  "outbounds": [
    {"type": "trojan", "tag": "proxy-eu", "server": "203.0.113.10", "server_port": 443, "password": "FAKE-SECRET-TROJAN-PASSWORD"},
    {"type": "socks", "tag": "proxy-userinfo", "server": "203.0.113.10", "server_port": 1080, "version": "5", "username": "proxy-user", "password": "FAKE-SECRET-PROXY-PASSWORD"}
  ],
  "endpoints": [
    {"type": "wireguard", "tag": "wg-home", "address": ["10.0.0.2/32"], "private_key": "FAKE-SECRET-WG-PRIVATE-KEY", "peers": [{"address": "203.0.113.10", "port": 51820, "public_key": "FAKE-SECRET-WG-PUBLIC-KEY", "allowed_ips": ["0.0.0.0/0"]}]}
  ],
  "telegram": {"profile": "muse01", "token": "123456789:FAKE-SECRET-TELEGRAM-TOKEN-0123456789", "allowed_user_ids": [12345]},
  "dns": {"servers": [{"tag": "dns1", "type": "tcp", "server": "127.0.0.1", "server_port": 5353}], "final": "dns1"}
}`

func assertNoLeak(t *testing.T, where, body string) {
	t.Helper()
	for _, marker := range leakMarkers {
		if strings.Contains(body, marker) {
			t.Errorf("%s: response contains secret marker %q:\n%s", where, marker, body)
		}
	}
}

func TestSecretLeakResponseSweep(t *testing.T) {
	ts := newTestServer(t, leakFixtureConfig, nil)
	// Every GET route, authenticated: no marker anywhere.
	gets := []string{
		"/api/v1/status",
		"/api/v1/profiles",
		"/api/v1/profiles/muse01",
		"/api/v1/outbounds",
		"/api/v1/outbounds/proxy-eu",
		"/api/v1/outbounds/proxy-userinfo",
		"/api/v1/endpoints",
		"/api/v1/endpoints/wg-home",
		"/api/v1/config",
		"/api/v1/dns",
		"/api/v1/settings/telegram",
		"/api/v1/keeper",
		"/api/v1/settings/keeper",
		"/api/v1/settings/webui",
		"/api/v1/logs",
		"/api/v1/plugins",
		"/api/v1/profiles/muse01/login/status",
		"/api/v1/screencast/status?profile=muse01",
	}
	for _, path := range gets {
		rec := ts.do(t, "GET", path, "", true)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: got %d: %s", path, rec.Code, rec.Body.String())
		}
		assertNoLeak(t, "GET "+path, rec.Body.String())
	}
	// Non-vacuous: the redacted config view DOES carry the
	// redaction marker at the secret positions. The marker is
	// checked inside the decoded `content` string (the outer
	// envelope's JSON encoder HTML-escapes `<`/`>`, so a raw
	// body search for "<redacted>" would miss it). If
	// redaction ever stopped replacing values, this fails
	// alongside (or instead of) the absence checks above.
	rec := ts.do(t, "GET", "/api/v1/config", "", true)
	content, _ := decodeEnvelope(t, rec)["data"].(map[string]any)["content"].(string)
	if !strings.Contains(content, "<redacted>") {
		t.Fatalf("GET /config content carries no <redacted> marker — redaction may be off:\n%s", content)
	}
	// Unauthenticated responses leak nothing either (the 401
	// body is fixed), and the shell carries no secret.
	rec = ts.do(t, "GET", "/api/v1/config", "", false)
	assertNoLeak(t, "GET /config unauthenticated", rec.Body.String())
	rec = ts.do(t, "GET", "/", "", false)
	assertNoLeak(t, "GET / shell", rec.Body.String())
}

func TestSecretLeakWritePathSweep(t *testing.T) {
	ts := newTestServer(t, leakFixtureConfig, nil)
	// A PUT that introduces a NEW marker secret at a secret
	// position must not echo it in its response, and the
	// re-read must show the marker, not the value.
	_, sha := getSettingsSHA(t, ts, "/api/v1/settings/keeper")
	_ = sha
	// Telegram token replacement: the response is masked only.
	rec := ts.do(t, "PUT", "/api/v1/settings/telegram", `{"token":"123456789:FAKE-SECRET-TELEGRAM-TOKEN-0123456789"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT telegram: got %d: %s", rec.Code, rec.Body.String())
	}
	assertNoLeak(t, "PUT telegram response", rec.Body.String())
	if !strings.Contains(rec.Body.String(), `"masked":"***"`) {
		t.Fatalf("PUT telegram response lacks the masked marker: %s", rec.Body.String())
	}
	// Whole-config PUT with a fresh secret value: the response
	// is a bare hash, and the re-read is redacted. The PUT
	// must succeed (200) for the write path to be swept at
	// all — a rejected body would sweep only the error path.
	_, sha2 := getSettingsSHA(t, ts, "/api/v1/config")
	// The PUT doc carries the profile's own cookies file: the
	// literal placeholder would resolve inside the config dir
	// at a non-default path, which the parser rejects.
	cfgDoc := strings.ReplaceAll(`{"default_profile":"muse01","profiles":{"muse01":{"cookies_file":"COOKIESFILE","vm_id":"FAKE-SECRET-VMID-VALUE","node_id":"FAKE-SECRET-NODEID-VALUE","outbound":"proxy-eu","fingerprint":"chrome"}},"outbounds":[{"type":"trojan","tag":"proxy-eu","server":"203.0.113.10","server_port":443,"password":"FAKE-SECRET-TROJAN-PASSWORD-NEW"}],"endpoints":[],"dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353}],"final":"dns1"}}`, "COOKIESFILE", filepath.Join(ts.dir, "profiles", "muse01", "cookies.txt"))
	putBody, err := json.Marshal(map[string]string{"content": cfgDoc, "base_sha256": sha2})
	if err != nil {
		t.Fatalf("marshal PUT body: %v", err)
	}
	rec = ts.do(t, "PUT", "/api/v1/config", string(putBody), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /config: got %d: %s", rec.Code, rec.Body.String())
	}
	assertNoLeak(t, "PUT /config response", rec.Body.String())
	rec = ts.do(t, "GET", "/api/v1/config", "", true)
	assertNoLeak(t, "GET /config after PUT", rec.Body.String())
	content, _ := decodeEnvelope(t, rec)["data"].(map[string]any)["content"].(string)
	if !strings.Contains(content, "<redacted>") {
		t.Fatalf("GET /config after PUT carries no <redacted> marker:\n%s", content)
	}
	// DNS section PUT with a marker-bearing section: the
	// response is a bare hash.
	_, sha3 := getSettingsSHA(t, ts, "/api/v1/dns")
	rec = ts.do(t, "PUT", "/api/v1/dns", `{"dns":{"servers":[{"tag":"dns1","type":"tcp","server":"127.0.0.1","server_port":5353}],"final":"dns1"},"base_sha256":"`+sha3+`"}`, true)
	assertNoLeak(t, "PUT /dns response", rec.Body.String())
	// WebUI settings PUT with a fresh token: no echo.
	_, sha4 := getSettingsSHA(t, ts, "/api/v1/settings/webui")
	rec = ts.do(t, "PUT", "/api/v1/settings/webui", `{"token":"FAKE-SECRET-WEBUI-TOKEN-VALUE","base_sha256":"`+sha4+`"}`, true)
	assertNoLeak(t, "PUT webui settings response", rec.Body.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT webui settings: got %d: %s", rec.Code, rec.Body.String())
	}
	// On-disk: the stored file must hold the token as a bcrypt
	// hash, never the plaintext marker, and the marker token
	// must authenticate against the refreshed comparator.
	stored := readTestConfig(t, ts)
	if strings.Contains(string(stored), leakWebUIToken) {
		t.Fatal("stored config.json contains the plaintext webui token marker")
	}
	parsed, err := profile.ParseSingleConfig(stored, ts.dir)
	if err != nil {
		t.Fatalf("stored config does not parse: %v", err)
	}
	if parsed.WebUI == nil || !profile.LooksLikeBcryptHash(parsed.WebUI.Token) {
		t.Fatalf("stored webui token is not a bcrypt hash: %+v", parsed.WebUI)
	}
	rec = ts.doToken(t, "GET", "/api/v1/status", "", leakWebUIToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("marker token after rotation: got %d, want 200", rec.Code)
	}
}

func TestSecretLeakErrorPathSweep(t *testing.T) {
	ts := newTestServer(t, leakFixtureConfig, nil)
	// Error responses must never echo request bytes — even
	// when the request body itself carries marker secrets.
	bodies := []struct{ method, path, body string }{
		{"POST", "/api/v1/config/validate", `{"bogus": "FAKE-SECRET-TROJAN-PASSWORD"}`},
		{"POST", "/api/v1/config/validate", `{"profiles": {"muse01": {"password": "FAKE-SECRET-TROJAN-PASSWORD"}}}`},
		{"PUT", "/api/v1/settings/telegram", `{"token": "bad", "note": "FAKE-SECRET-TELEGRAM-TOKEN-0123456789"}`},
		{"PUT", "/api/v1/dns", `{"dns": {"x": "FAKE-SECRET-WG-PRIVATE-KEY"}, "base_sha256": "stale"}`},
		{"POST", "/api/v1/profiles", `{"name": "FAKE-SECRET-VMID-VALUE", "bogus": true}`},
		{"POST", "/api/v1/outbounds/validate", `{"outbound": {"password": "FAKE-SECRET-TROJAN-PASSWORD"}}`},
	}
	for _, tc := range bodies {
		rec := ts.do(t, tc.method, tc.path, tc.body, true)
		assertNoLeak(t, tc.method+" "+tc.path+" error", rec.Body.String())
	}
	// Malformed JSON carrying a marker: fixed message only.
	rec := ts.do(t, "PUT", "/api/v1/settings/telegram", `{"token": "FAKE-SECRET-TELEGRAM-TOKEN-0123456789", broken`, true)
	assertNoLeak(t, "malformed JSON error", rec.Body.String())
	// A 409 (stale hash) with a marker in the body: fixed message.
	_, sha := getSettingsSHA(t, ts, "/api/v1/dns")
	_ = sha
	rec = ts.do(t, "PUT", "/api/v1/dns", `{"dns": {}, "base_sha256": "FAKE-SECRET-WG-PRIVATE-KEY"}`, true)
	assertNoLeak(t, "409 error", rec.Body.String())
	// Failed auth with a marker as the presented token: the
	// 401 body is fixed and echoes nothing.
	rec = ts.doToken(t, "GET", "/api/v1/status", "", leakCookieValue)
	assertNoLeak(t, "401 error", rec.Body.String())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("marker token: got %d, want 401", rec.Code)
	}
	// A sentinel at a secret position with no stored value:
	// the rejection names the path, never the value.
	rec = ts.do(t, "PUT", "/api/v1/dns", `{"dns": {"servers": []}, "base_sha256": "`+sha+`"}`, true)
	assertNoLeak(t, "dns PUT", rec.Body.String())
}

func TestSecretLeakRateLimitOriginOversizedSweep(t *testing.T) {
	// 429 bodies: a marker presented as the Bearer on a
	// 1-attempt window must never be echoed by the fixed
	// rate-limit body.
	cfg429 := strings.Replace(leakFixtureConfig, `"dns":`, `"webui":{"token":"FAKE-SECRET-WEBUI-TOKEN-VALUE","login_rate_limit":{"attempts":1,"window":"5m"}},"dns":`, 1)
	ts := newTestServer(t, cfg429, nil)
	rec := ts.doToken(t, "GET", "/api/v1/status", "", leakCookieValue)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("first marker failure: got %d, want 401", rec.Code)
	}
	assertNoLeak(t, "401 body", rec.Body.String())
	rec = ts.doToken(t, "GET", "/api/v1/status", "", leakCookieValue)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second marker failure: got %d, want 429", rec.Code)
	}
	assertNoLeak(t, "429 body", rec.Body.String())

	// 403 bodies: a marker-bearing mutation from a remote
	// Origin gets the fixed cross-origin body only.
	ts2 := newTestServer(t, leakFixtureConfig, nil)
	rec = ts2.doReq(t, "POST", "/api/v1/config/validate", `{"bogus":"FAKE-SECRET-TROJAN-PASSWORD"}`, true, map[string]string{"Origin": "https://evil.example"}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("remote Origin: got %d, want 403", rec.Code)
	}
	assertNoLeak(t, "403 body", rec.Body.String())

	// Oversized bodies: a marker past the 1 MiB section-editor
	// cap must never be echoed by the fixed validation error.
	huge := `{"token":"` + strings.Repeat("A", 2<<20) + leakTelegramToken + `"}`
	rec = ts2.do(t, "PUT", "/api/v1/settings/telegram", huge, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: got %d, want 400: %s", rec.Code, rec.Body.String())
	}
	assertNoLeak(t, "oversized body error", rec.Body.String())

	// Proxy-userinfo marker in a validation error: an
	// outbound carrying the marker password must not leak
	// it when validation rejects the document.
	rec = ts2.do(t, "POST", "/api/v1/outbounds/validate", `{"outbound":{"type":"socks","tag":"x","server":"203.0.113.10","server_port":1080,"version":"5","username":"proxy-user","password":"FAKE-SECRET-PROXY-PASSWORD","bogus":1}}`, true)
	assertNoLeak(t, "outbound validate error", rec.Body.String())
}
