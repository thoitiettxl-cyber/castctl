// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// Fixture values are FAKE markers only. The fixture config is a
// RECONSTRUCTED sample assembled from the shapes in
// docs/config.md and the profile/keeper test fixtures at base:
// it is not captured traffic and not a real config.

const testToken = "MARKER-TEST-TOKEN"

const fixtureConfig = `{
  "default_profile": "muse01",
  "profiles": {
    "muse01": {
      "cookies_file": "COOKIESFILE",
      "vm_id": "FAKE-SECRET-VMID",
      "node_id": "FAKE-SECRET-NODEID",
      "outbound": "proxy-eu",
      "fingerprint": "chrome"
    }
  },
  "outbounds": [
    {"type": "trojan", "tag": "proxy-eu", "server": "203.0.113.10", "server_port": 443, "password": "FAKE-SECRET-TROJAN"}
  ],
  "endpoints": [
    {"type": "wireguard", "tag": "wg-home", "address": ["10.0.0.2/32"], "private_key": "FAKE-SECRET-WG-PRIV", "peers": [{"address": "203.0.113.10", "port": 51820, "public_key": "FAKE-SECRET-WG-PUB", "allowed_ips": ["0.0.0.0/0"]}]}
  ],
  "dns": {"servers": [{"tag": "dns1", "type": "tcp", "server": "127.0.0.1", "server_port": 5353}], "final": "dns1"}
}`

type testServer struct {
	srv     *Server
	dir     string
	handler http.Handler
}

func newTestServer(t *testing.T, config string, extra func(*Deps)) *testServer {
	t.Helper()
	dir := t.TempDir()
	cookiesFile := filepath.Join(dir, "profiles", "muse01", "cookies.txt")
	config = strings.ReplaceAll(config, "COOKIESFILE", cookiesFile)
	if config != "" {
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}
	sum := sha256.Sum256([]byte(testToken))
	deps := Deps{
		ConfigDir:    dir,
		Version:      "0.6.1-test",
		ListenAddr:   "127.0.0.1:8317",
		TokenHash:    sum,
		HasToken:     true,
		DistFS:       fstest.MapFS{"index.html": {Data: []byte("<html>castctl shell</html>")}},
		BundleSHA256: "test-bundle-hash",
	}
	if extra != nil {
		extra(&deps)
	}
	srv, err := New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &testServer{srv: srv, dir: dir, handler: srv.Handler()}
}

func (ts *testServer) do(t *testing.T, method, path, body string, authed bool) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if authed {
		req.Header.Set("Authorization", "Bearer "+testToken)
	}
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)
	return rec
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope %q: %v", rec.Body.String(), err)
	}
	return env
}

func TestAuthGate(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	// No token: fixed 401, same body for every route.
	for _, path := range []string{"/api/v1/status", "/api/v1/profiles", "/api/v1/config", "/api/v1/screencast/status"} {
		rec := ts.do(t, "GET", path, "", false)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s without token: %d, want 401", path, rec.Code)
		}
		env := decodeEnvelope(t, rec)
		errObj, _ := env["error"].(map[string]any)
		if errObj["type"] != "unauthorized" || errObj["message"] != "invalid or missing token" {
			t.Fatalf("GET %s: error envelope = %v", path, env)
		}
	}
	// Wrong token: identical fixed 401 (no leak about whether
	// the token exists or which route was hit).
	rec := ts.do(t, "GET", "/api/v1/status", "", false)
	rec.Header().Set("Authorization", "Bearer wrong")
	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer wrong-token-value")
	rec2 := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnauthorized || rec2.Body.String() != rec.Body.String() {
		t.Fatalf("wrong-token body differs from missing-token body: %q vs %q", rec2.Body.String(), rec.Body.String())
	}
	// Right token works; the token value never appears in a
	// response body.
	rec = ts.do(t, "GET", "/api/v1/status", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("authed status: %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), testToken) {
		t.Fatal("token value leaked into a response body")
	}
	// Static shell needs no token and carries no secrets.
	rec = ts.do(t, "GET", "/", "", false)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "castctl shell") {
		t.Fatalf("shell: %d: %s", rec.Code, rec.Body.String())
	}
	// Unknown API path under auth: 404, still authed-first.
	rec = ts.do(t, "GET", "/api/v1/nope", "", false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown API path without token: %d, want 401", rec.Code)
	}
}

func TestNewFailsClosedWithoutToken(t *testing.T) {
	sum := sha256.Sum256([]byte(testToken))
	_, err := New(Deps{
		ConfigDir:    t.TempDir(),
		TokenHash:    sum,
		HasToken:     false,
		DistFS:       fstest.MapFS{"index.html": {Data: []byte("x")}},
		BundleSHA256: "h",
	})
	if err == nil {
		t.Fatal("New without HasToken succeeded, want failure")
	}
}

func TestStatusShape(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	rec := ts.do(t, "GET", "/api/v1/status", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d: %s", rec.Code, rec.Body.String())
	}
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	if data["version"] != "0.6.1-test" {
		t.Fatalf("version = %v", data["version"])
	}
	if data["remote_exposure"] != false {
		t.Fatalf("remote_exposure = %v, want false (loopback-only)", data["remote_exposure"])
	}
	if data["listen_addr"] != "127.0.0.1:8317" {
		t.Fatalf("listen_addr = %v", data["listen_addr"])
	}
	if data["config_source"] != "single-file" {
		t.Fatalf("config_source = %v", data["config_source"])
	}
	if data["profile_count"] != float64(1) || data["outbound_count"] != float64(1) || data["endpoint_count"] != float64(1) {
		t.Fatalf("counts = %v", data)
	}
	if data["bundle_sha256"] != "test-bundle-hash" {
		t.Fatalf("bundle_sha256 = %v", data["bundle_sha256"])
	}
	if data["go_version"] == "" || data["singbox_version"] == "" {
		t.Fatalf("versions missing: %v", data)
	}
}

func TestConfigRedactionAndSave(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	rec := ts.do(t, "GET", "/api/v1/config", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET config: %d: %s", rec.Code, rec.Body.String())
	}
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	content, _ := data["content"].(string)
	for _, marker := range []string{"FAKE-SECRET-VMID", "FAKE-SECRET-NODEID", "FAKE-SECRET-TROJAN", "FAKE-SECRET-WG-PRIV", "FAKE-SECRET-WG-PUB"} {
		if strings.Contains(content, marker) {
			t.Fatalf("marker %s leaked into GET /config", marker)
		}
	}
	if !strings.Contains(content, "<redacted>") {
		t.Fatalf("no sentinel in redacted view:\n%s", content)
	}
	baseSHA, _ := data["sha256"].(string)
	if baseSHA == "" {
		t.Fatal("sha256 missing")
	}
	// File hash on disk must equal the reported hash.
	raw, _ := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if got := sha256Hex(raw); got != baseSHA {
		t.Fatalf("reported sha %s != file sha %s", baseSHA, got)
	}
	// Save the redacted view with one non-secret edit: secrets
	// stay, the edit lands, mode stays 0600.
	edited := strings.Replace(content, `"fingerprint": "chrome"`, `"fingerprint": "firefox"`, 1)
	if edited == content {
		t.Fatal("fixture edit did not apply (fingerprint spelling?)")
	}
	body, _ := json.Marshal(map[string]any{"content": edited, "base_sha256": baseSHA})
	rec = ts.do(t, "PUT", "/api/v1/config", string(body), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT config: %d: %s", rec.Code, rec.Body.String())
	}
	after, _ := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if !strings.Contains(string(after), "FAKE-SECRET-TROJAN") {
		t.Fatal("stored secret lost on sentinel save")
	}
	if !strings.Contains(string(after), `"fingerprint": "firefox"`) {
		t.Fatalf("edit did not land:\n%s", after)
	}
	st, _ := os.Stat(filepath.Join(ts.dir, "config.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %04o, want 0600", st.Mode().Perm())
	}
	// Stale hash: 409, file untouched.
	before := append([]byte(nil), after...)
	body, _ = json.Marshal(map[string]any{"content": edited, "base_sha256": baseSHA})
	rec = ts.do(t, "PUT", "/api/v1/config", string(body), true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale PUT: %d, want 409", rec.Code)
	}
	after2, _ := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if !bytes.Equal(before, after2) {
		t.Fatal("stale save modified the file")
	}
	// Invalid merged doc: 400, file byte-identical.
	bad := strings.Replace(content, `"final": "dns1"`, `"final": "no-such-dns"`, 1)
	newHash := decodeEnvelope(t, ts.do(t, "GET", "/api/v1/config", "", true))["data"].(map[string]any)["sha256"].(string)
	body, _ = json.Marshal(map[string]any{"content": bad, "base_sha256": newHash})
	rec = ts.do(t, "PUT", "/api/v1/config", string(body), true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid PUT: %d, want 400: %s", rec.Code, rec.Body.String())
	}
	after3, _ := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if !bytes.Equal(before, after3) {
		t.Fatal("invalid save modified the file")
	}
	// A marker value smuggled into an invalid doc must not
	// appear in the error body.
	if strings.Contains(rec.Body.String(), "FAKE-SECRET") {
		t.Fatalf("marker leaked into error body: %s", rec.Body.String())
	}
}

func TestConfigValidateEndpoint(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	body, _ := json.Marshal(map[string]any{"content": `{"profiles":{},"webui":{"listen":"0.0.0.0:8317"}}`})
	rec := ts.do(t, "POST", "/api/v1/config/validate", string(body), true)
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	if data["valid"] != false {
		t.Fatalf("non-loopback listen validated: %v", data)
	}
	errs, _ := data["errors"].([]any)
	if len(errs) == 0 || strings.Contains(errs[0].(string), "0.0.0.0") {
		t.Fatalf("validation error echoes value: %v", errs)
	}
}

func TestProfilesCRUD(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	// List.
	rec := ts.do(t, "GET", "/api/v1/profiles", "", true)
	data := decodeEnvelope(t, rec)["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("profiles = %v", data)
	}
	// Detail: entry redacted, warnings present shape.
	rec = ts.do(t, "GET", "/api/v1/profiles/muse01", "", true)
	detail := decodeEnvelope(t, rec)["data"].(map[string]any)
	entry := detail["entry"].(map[string]any)
	if entry["vm_id"] != "<redacted>" || entry["node_id"] != "<redacted>" {
		t.Fatalf("entry not redacted: %v", entry)
	}
	// Patch toggles: auto_approve true -> "always".
	rec = ts.do(t, "PATCH", "/api/v1/profiles/muse01", `{"auto_approve":true,"auto_allow_once":true}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH: %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if !strings.Contains(string(raw), `"auto_approve": "always"`) || !strings.Contains(string(raw), `"auto_allow_once": true`) {
		t.Fatalf("patch did not land:\n%s", raw)
	}
	// Create + rename + set-default + delete.
	rec = ts.do(t, "POST", "/api/v1/profiles", `{"name":"work","outbound":"proxy-eu"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d: %s", rec.Code, rec.Body.String())
	}
	rec = ts.do(t, "POST", "/api/v1/profiles/work/rename", `{"to":"work2"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename: %d: %s", rec.Code, rec.Body.String())
	}
	rec = ts.do(t, "POST", "/api/v1/profiles/work2/set-default", ``, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("set-default: %d: %s", rec.Code, rec.Body.String())
	}
	rec = ts.do(t, "GET", "/api/v1/status", "", true)
	if decodeEnvelope(t, rec)["data"].(map[string]any)["default_profile"] != "work2" {
		t.Fatalf("default not moved: %s", rec.Body.String())
	}
	// Delete without confirmation: 400, profile survives.
	rec = ts.do(t, "DELETE", "/api/v1/profiles/work2", `{"confirm":false,"name":"work2"}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed delete: %d, want 400", rec.Code)
	}
	rec = ts.do(t, "DELETE", "/api/v1/profiles/work2", `{"confirm":true,"name":"work2"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d: %s", rec.Code, rec.Body.String())
	}
	rec = ts.do(t, "GET", "/api/v1/profiles/work2", "", true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("deleted profile GET: %d, want 404", rec.Code)
	}
	// Unknown profile: 404.
	rec = ts.do(t, "GET", "/api/v1/profiles/nope", "", true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown profile: %d, want 404", rec.Code)
	}
}

func TestOutboundsCRUDAndValidate(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	rec := ts.do(t, "GET", "/api/v1/outbounds", "", true)
	list := decodeEnvelope(t, rec)["data"].([]any)
	if len(list) != 1 {
		t.Fatalf("outbounds = %v", list)
	}
	summary := list[0].(map[string]any)
	if summary["summary"] != "trojan 203.0.113.10:443" {
		t.Fatalf("summary = %v", summary)
	}
	usedBy, _ := summary["used_by"].([]any)
	if len(usedBy) != 1 || usedBy[0] != "muse01" {
		t.Fatalf("used_by = %v", usedBy)
	}
	// Detail redacted.
	rec = ts.do(t, "GET", "/api/v1/outbounds/proxy-eu", "", true)
	detail := decodeEnvelope(t, rec)["data"].(map[string]any)
	if detail["password"] != "<redacted>" {
		t.Fatalf("detail not redacted: %v", detail)
	}
	// Patch with sentinel keeps the stored password.
	patched, _ := json.Marshal(detail)
	patchedStr := strings.Replace(string(patched), `"server":"203.0.113.10"`, `"server":"203.0.113.11"`, 1)
	rec = ts.do(t, "PATCH", "/api/v1/outbounds/proxy-eu", `{"outbound":`+patchedStr+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH outbound: %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if !strings.Contains(string(raw), "FAKE-SECRET-TROJAN") || !strings.Contains(string(raw), "203.0.113.11") {
		t.Fatalf("patch lost secret or edit:\n%s", raw)
	}
	// Create with a sentinel password rejects (no stored value).
	rec = ts.do(t, "POST", "/api/v1/outbounds", `{"outbound":{"type":"trojan","tag":"new","server":"203.0.113.12","server_port":443,"password":"<redacted>"}}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("sentinel create: %d, want 400: %s", rec.Code, rec.Body.String())
	}
	// Validate endpoint: valid + invalid, no write either way.
	before, _ := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	rec = ts.do(t, "POST", "/api/v1/outbounds/validate", `{"outbound":{"type":"socks","tag":"v1","server":"127.0.0.1","server_port":1080,"version":"5"}}`, true)
	if decodeEnvelope(t, rec)["data"].(map[string]any)["valid"] != true {
		t.Fatalf("validate valid: %s", rec.Body.String())
	}
	// Unknown keys are rejected by strict parsing (a missing
	// server alone is parse-valid: sing-box fills defaults and
	// the runtime fails later, so it must validate true above).
	rec = ts.do(t, "POST", "/api/v1/outbounds/validate", `{"outbound":{"type":"socks","tag":"v1","server":"127.0.0.1","server_port":1080,"bogus_key":1}}`, true)
	if decodeEnvelope(t, rec)["data"].(map[string]any)["valid"] != false {
		t.Fatalf("validate invalid: %s", rec.Body.String())
	}
	after, _ := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("validate wrote to the file")
	}
	// Delete while referenced: validation refuses (dangling tag).
	rec = ts.do(t, "DELETE", "/api/v1/outbounds/proxy-eu", ``, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete referenced outbound: %d, want 400: %s", rec.Code, rec.Body.String())
	}
	// Test endpoints are explicitly unavailable.
	rec = ts.do(t, "POST", "/api/v1/profiles/muse01/test", `{}`, true)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("profile test: %d, want 501", rec.Code)
	}
	rec = ts.do(t, "POST", "/api/v1/outbounds/proxy-eu/test", `{}`, true)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("outbound test: %d, want 501", rec.Code)
	}
}

func TestDNSGetPut(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	rec := ts.do(t, "GET", "/api/v1/dns", "", true)
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	dns, _ := data["dns"].(map[string]any)
	if dns["final"] != "dns1" {
		t.Fatalf("dns = %v", dns)
	}
	baseSHA, _ := data["sha256"].(string)
	// PUT with stale hash: 409.
	body, _ := json.Marshal(map[string]any{"dns": dns, "base_sha256": "deadbeef"})
	rec = ts.do(t, "PUT", "/api/v1/dns", string(body), true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale DNS PUT: %d, want 409", rec.Code)
	}
	// PUT replacing the section (null deletes it, then restore).
	body, _ = json.Marshal(map[string]any{"dns": nil, "base_sha256": baseSHA})
	rec = ts.do(t, "PUT", "/api/v1/dns", string(body), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("DNS delete: %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if strings.Contains(string(raw), `"dns"`) {
		t.Fatalf("dns section survived delete:\n%s", raw)
	}
}

func TestTelegramWriteOnly(t *testing.T) {
	config := strings.Replace(fixtureConfig, `"dns":`, `"telegram": {"profile": "muse01", "token": "123456:FAKE-SECRET-TG-TOKEN-0123456789", "allowed_user_ids": [111], "auto_approve": false, "auto_allow_once": false}, "dns":`, 1)
	ts := newTestServer(t, config, nil)
	rec := ts.do(t, "GET", "/api/v1/settings/telegram", "", true)
	view := decodeEnvelope(t, rec)["data"].(map[string]any)
	if view["configured"] != true || view["masked"] != "***" {
		t.Fatalf("telegram view = %v", view)
	}
	if strings.Contains(rec.Body.String(), "FAKE-SECRET-TG") {
		t.Fatal("telegram token leaked into GET response")
	}
	// Empty token = unchanged; allowlist edit lands.
	rec = ts.do(t, "PUT", "/api/v1/settings/telegram", `{"token":"","allowed_user_ids":[111,222]}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT telegram: %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if !strings.Contains(string(raw), "FAKE-SECRET-TG-TOKEN") {
		t.Fatal("empty-token save clobbered the stored token")
	}
	if !strings.Contains(string(raw), "222") {
		t.Fatalf("allowlist edit did not land:\n%s", raw)
	}
	// Malformed replacement token: 400, stored token untouched.
	rec = ts.do(t, "PUT", "/api/v1/settings/telegram", `{"token":"not-a-token"}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad token PUT: %d, want 400: %s", rec.Code, rec.Body.String())
	}
	raw2, _ := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if !bytes.Equal(raw, raw2) {
		t.Fatal("bad token save modified the file")
	}
	// Create path: no block, defaults profile to default_profile.
	ts2 := newTestServer(t, fixtureConfig, nil)
	rec = ts2.do(t, "PUT", "/api/v1/settings/telegram", `{"token":"123456:FAKE-SECRET-TG2-TOKEN-0123456789","allowed_user_ids":[333]}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("telegram create: %d: %s", rec.Code, rec.Body.String())
	}
	raw3, _ := os.ReadFile(filepath.Join(ts2.dir, "config.json"))
	if !strings.Contains(string(raw3), `"profile": "muse01"`) {
		t.Fatalf("created block did not default profile:\n%s", raw3)
	}
}

func TestLoginStatusAndImportRestore(t *testing.T) {
	var importedContent string
	var importedProfile string
	ts := newTestServer(t, fixtureConfig, func(d *Deps) {
		d.ImportCookies = func(ctx context.Context, profileName, content string) (bool, error) {
			importedProfile, importedContent = profileName, content
			return false, nil
		}
		d.RestoreCookies = func(ctx context.Context, profileName string) (bool, error) {
			return false, ErrNoBackup
		}
	})
	// No cookies file yet: not logged in, format null.
	rec := ts.do(t, "GET", "/api/v1/profiles/muse01/login/status", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status: %d: %s", rec.Code, rec.Body.String())
	}
	status := decodeEnvelope(t, rec)["data"].(map[string]any)
	if status["logged_in"] != false || status["cookies_present"] != false {
		t.Fatalf("status without cookies = %v", status)
	}
	if status["vm_id_prefix"] != nil {
		t.Fatalf("vm_id_prefix = %v, want null (never value-derived)", status["vm_id_prefix"])
	}
	// Write a FAKE jar: logged in, format netscape, no values
	// in the response.
	cookiesFile := filepath.Join(ts.dir, "profiles", "muse01", "cookies.txt")
	if err := os.MkdirAll(filepath.Dir(cookiesFile), 0o700); err != nil {
		t.Fatal(err)
	}
	jar := "# Netscape HTTP Cookie File\n.muse.ai\tTRUE\t/\tTRUE\t1893456000\thatch_sess\tFAKE-SECRET-COOKIE\n"
	if err := os.WriteFile(cookiesFile, []byte(jar), 0o600); err != nil {
		t.Fatal(err)
	}
	rec = ts.do(t, "GET", "/api/v1/profiles/muse01/login/status", "", true)
	status = decodeEnvelope(t, rec)["data"].(map[string]any)
	if status["logged_in"] != true || status["cookies_format"] != "netscape" {
		t.Fatalf("status with jar = %v", status)
	}
	if strings.Contains(rec.Body.String(), "FAKE-SECRET-COOKIE") {
		t.Fatal("cookie value leaked into login status")
	}
	// Import goes through the seam with the exact content.
	rec = ts.do(t, "POST", "/api/v1/profiles/muse01/login/import", `{"format":"text","content":"hatch_sess=FAKE-SECRET-NEW; datr=x"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d: %s", rec.Code, rec.Body.String())
	}
	if importedProfile != "muse01" || importedContent != "hatch_sess=FAKE-SECRET-NEW; datr=x" {
		t.Fatalf("seam got profile=%q content=%q", importedProfile, importedContent)
	}
	result := decodeEnvelope(t, rec)["data"].(map[string]any)
	if result["saved"] != true || result["verified"] != false {
		t.Fatalf("import result = %v (verified must be false: no live check)", result)
	}
	// Restore with no .bak: explicit 404.
	rec = ts.do(t, "POST", "/api/v1/profiles/muse01/login/restore", `{}`, true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("restore without .bak: %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

func TestKeeperStatusAndScreencastUnavailable(t *testing.T) {
	config := strings.Replace(fixtureConfig, `"dns":`, `"keeper": [{"tag": "k1", "profile": "muse01", "browser": "http://127.0.0.1:9226"}], "dns":`, 1)
	ts := newTestServer(t, config, nil)
	rec := ts.do(t, "GET", "/api/v1/keeper", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("keeper: %d: %s", rec.Code, rec.Body.String())
	}
	entries := decodeEnvelope(t, rec)["data"].([]any)
	if len(entries) != 1 {
		t.Fatalf("keeper entries = %v", entries)
	}
	entry := entries[0].(map[string]any)
	if entry["tag"] != "k1" || entry["profile"] != "muse01" || entry["browser"] != "http://127.0.0.1:9226" {
		t.Fatalf("keeper entry = %v", entry)
	}
	status, _ := entry["status"].(map[string]any)
	if status["tag"] != "k1" {
		t.Fatalf("keeper status = %v", status)
	}
	// Screencast without seams: page AND API say unavailable.
	rec = ts.do(t, "GET", "/api/v1/screencast/status?profile=muse01", "", true)
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	if data["available"] != false {
		t.Fatalf("screencast status = %v, want unavailable", data)
	}
	if reason, _ := data["reason"].(string); !strings.Contains(reason, "with_chromedp") {
		t.Fatalf("reason = %q, want the rebuild hint", reason)
	}
	rec = ts.do(t, "POST", "/api/v1/screencast/muse01/start", ``, true)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("screencast start: %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if decodeEnvelope(t, rec)["error"].(map[string]any)["type"] != "screencast_unavailable" {
		t.Fatalf("start error type wrong: %s", rec.Body.String())
	}
	// WebSocket without a session token: 401 before upgrade.
	rec = ts.do(t, "GET", "/api/v1/screencast/ws", "", true)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("WS without session: %d, want 401", rec.Code)
	}
}

func TestLogsDeleteRefused(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	rec := ts.do(t, "DELETE", "/api/v1/logs", ``, true)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE /logs: %d, want 405", rec.Code)
	}
}

func TestRecoverer(t *testing.T) {
	h := recoverer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("MARKER-PANIC-VALUE")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic: %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "MARKER-PANIC-VALUE") {
		t.Fatal("panic value leaked into response")
	}
}

func TestConfigAbsentAndLegacy(t *testing.T) {
	ts := newTestServer(t, "", nil)
	rec := ts.do(t, "GET", "/api/v1/config", "", true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("absent config GET: %d, want 404", rec.Code)
	}
	rec = ts.do(t, "GET", "/api/v1/status", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status without config: %d", rec.Code)
	}
	if decodeEnvelope(t, rec)["data"].(map[string]any)["config_source"] != "none" {
		t.Fatalf("source = %s", rec.Body.String())
	}
}

// Web UI cookies_file containment (loop-2 F2, Boss ruling
// 2026-10-31): web UI seams reject absolute paths and anything
// resolving outside the config dir (including via symlinks and
// ".."). CLI resolveCookiesFile is unchanged; general CLI
// containment is a backlog follow-up.

func postJSONBody(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCreateProfileRejectsOutsideCookiesFile(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	before, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	target := filepath.Join(outside, "cookies.txt")
	if err := os.WriteFile(target, []byte("ORIGINAL-CONTENT"), 0o600); err != nil {
		t.Fatal(err)
	}
	escapeLink := filepath.Join(ts.dir, "escape-link")
	if err := os.Symlink(outside, escapeLink); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(ts.dir, target)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"absolute": target,
		"dotdot":   rel,
		"symlink":  filepath.Join("escape-link", "cookies.txt"),
	}
	for name, cookiesFile := range cases {
		t.Run(name, func(t *testing.T) {
			rec := ts.do(t, http.MethodPost, "/api/v1/profiles", postJSONBody(t, map[string]any{
				"name": "evil", "cookies_file": cookiesFile, "outbound": "direct",
			}), true)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("POST /profiles = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), target) || strings.Contains(rec.Body.String(), outside) {
				t.Fatalf("rejection echoed the path: %s", rec.Body.String())
			}
			if got := ts.do(t, http.MethodGet, "/api/v1/profiles/evil", "", true); got.Code != http.StatusNotFound {
				t.Fatalf("GET /profiles/evil = %d, want 404: %s", got.Code, got.Body.String())
			}
			after, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("config file changed:\n%s", after)
			}
			content, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(content) != "ORIGINAL-CONTENT" {
				t.Fatalf("target changed: %q", content)
			}
			if _, err := os.Stat(target + ".bak"); !os.IsNotExist(err) {
				t.Fatalf("backup created for rejected target: err=%v", err)
			}
		})
	}
}

func TestCreateProfileAcceptsInDirCookiesFile(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	rec := ts.do(t, http.MethodPost, "/api/v1/profiles", postJSONBody(t, map[string]any{
		"name": "inside", "cookies_file": "profiles/inside/cookies.txt", "outbound": "direct",
	}), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /profiles = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	rec = ts.do(t, http.MethodPost, "/api/v1/profiles", postJSONBody(t, map[string]any{
		"name": "plain", "outbound": "direct",
	}), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /profiles (default cookies) = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func importConfigWithCookiesFile(cookiesFile string) string {
	b, _ := json.Marshal(map[string]any{
		"default_profile": "evil",
		"profiles":        map[string]any{"evil": map[string]any{"cookies_file": cookiesFile}},
	})
	return string(b)
}

func TestLoginImportRefusesOutsideCookiesFile(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "cookies.txt")
	if err := os.WriteFile(target, []byte("ORIGINAL-CONTENT"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	ts := newTestServer(t, importConfigWithCookiesFile(target), func(deps *Deps) {
		deps.ImportCookies = func(ctx context.Context, profileName, content string) (bool, error) {
			calls++
			return false, nil
		}
	})
	rec := ts.do(t, http.MethodPost, "/api/v1/profiles/evil/login/import", postJSONBody(t, map[string]any{
		"format": "text", "content": "example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tFAKE-VALUE-1\n",
	}), true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST import = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("import seam called %d times, want 0", calls)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "ORIGINAL-CONTENT" {
		t.Fatalf("target changed: %q", content)
	}
	if _, err := os.Stat(target + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("backup created for rejected import: err=%v", err)
	}
}

func TestLoginImportWorksInDir(t *testing.T) {
	calls := 0
	ts := newTestServer(t, importConfigWithCookiesFile("cookies-evil.txt"), func(deps *Deps) {
		deps.ImportCookies = func(ctx context.Context, profileName, content string) (bool, error) {
			calls++
			if profileName != "evil" {
				t.Errorf("profile = %q, want evil", profileName)
			}
			return false, nil
		}
	})
	rec := ts.do(t, http.MethodPost, "/api/v1/profiles/evil/login/import", postJSONBody(t, map[string]any{
		"format": "text", "content": "example.com\tTRUE\t/\tFALSE\t0\thatch_sess\tFAKE-VALUE-1\n",
	}), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST import = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if calls != 1 {
		t.Fatalf("import seam called %d times, want 1", calls)
	}
}

func TestPutConfigRejectsNewOutsideCookiesFile(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	before, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	rec := ts.do(t, http.MethodGet, "/api/v1/config", "", true)
	env := decodeEnvelope(t, rec)
	data := env["data"].(map[string]any)
	content, _ := data["content"].(string)
	baseSHA, _ := data["sha256"].(string)
	doc := map[string]any{}
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		t.Fatal(err)
	}
	doc["profiles"].(map[string]any)["muse01"].(map[string]any)["cookies_file"] = filepath.Join(t.TempDir(), "cookies.txt")
	body, _ := json.Marshal(doc)
	rec = ts.do(t, http.MethodPut, "/api/v1/config", postJSONBody(t, map[string]any{
		"base_sha256": baseSHA,
		"content":     string(body),
	}), true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT /config = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	after, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("config file changed:\n%s", after)
	}
}

func TestPutConfigKeepsUnchangedAbsoluteCookiesFile(t *testing.T) {
	// Interpretation guard: the fixture's stored absolute
	// in-dir cookies_file is unchanged by the save, so it must
	// not block an otherwise valid edit.
	ts := newTestServer(t, fixtureConfig, nil)
	rec := ts.do(t, http.MethodGet, "/api/v1/config", "", true)
	data := decodeEnvelope(t, rec)["data"].(map[string]any)
	content, _ := data["content"].(string)
	baseSHA, _ := data["sha256"].(string)
	edited := strings.Replace(content, `"fingerprint": "chrome"`, `"fingerprint": "firefox"`, 1)
	if edited == content {
		t.Fatal("fixture edit did not apply (fingerprint spelling?)")
	}
	body, _ := json.Marshal(map[string]any{"content": edited, "base_sha256": baseSHA})
	rec = ts.do(t, http.MethodPut, "/api/v1/config", string(body), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /config = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestRenameDeleteKeeperReferencedProfileRefused(t *testing.T) {
	config := `{
  "default_profile": "muse01",
  "profiles": {"muse01": {}},
  "keeper": [{"tag": "keep1", "profile": "muse01", "browser": "http://127.0.0.1:9226/"}]
}`
	ts := newTestServer(t, config, nil)
	before, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	rec := ts.do(t, http.MethodPost, "/api/v1/profiles/muse01/rename", postJSONBody(t, map[string]any{"to": "renamed"}), true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("rename = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	rec = ts.do(t, http.MethodDelete, "/api/v1/profiles/muse01", postJSONBody(t, map[string]any{"confirm": true, "name": "muse01"}), true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	after, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("config file changed:\n%s", after)
	}
}

func TestPutTelegramRejectsPlaceholderToken(t *testing.T) {
	ts := newTestServer(t, fixtureConfig, nil)
	rec := ts.do(t, http.MethodPut, "/api/v1/settings/telegram", postJSONBody(t, map[string]any{
		"profile": "muse01", "token": "123456789:FAKE-TELEGRAM-TOKEN-ABCDEF123456", "allowed_user_ids": []int{123},
	}), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT telegram = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	for _, bad := range []string{"***", "<redacted>"} {
		rec = ts.do(t, http.MethodPut, "/api/v1/settings/telegram", postJSONBody(t, map[string]any{"profile": "muse01", "token": bad}), true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("PUT telegram token %q = %d, want 400: %s", bad, rec.Code, rec.Body.String())
		}
	}
	raw, err := os.ReadFile(filepath.Join(ts.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "123456789:FAKE-TELEGRAM-TOKEN-ABCDEF123456") {
		t.Fatalf("stored token replaced:\n%s", raw)
	}
	if strings.Contains(string(raw), `"token":"***"`) || strings.Contains(string(raw), `"token":"<redacted>"`) {
		t.Fatalf("placeholder token stored:\n%s", raw)
	}
}
