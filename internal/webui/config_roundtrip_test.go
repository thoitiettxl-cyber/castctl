// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// TestConfigRoundTripCredentials (R-4/T5) pins the full
// HTTP round-trip: GET /api/v1/config returns the redacted
// view, PUTting that view back with the base hash succeeds,
// a second GET matches the first, no response carries a
// sentinel value, and the values on disk are preserved.
// Fake sentinel values only.
func TestConfigRoundTripCredentials(t *testing.T) {
	const sentinelUser = "SENTINEL-USER-9f3a7c"
	const sentinelPass = "SENTINEL-PASS-9f3a7c"
	cfg := `{"default_profile":"muse01","profiles":{"muse01":{}},` +
		`"credentials":[{"tag":"c1","profile":"muse01","username":"` + sentinelUser + `","password":"` + sentinelPass + `"}]}`
	srv, dir := newLogTestServer(t, cfg)

	do := func(method, path string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		var req *http.Request
		if body == nil {
			req = httptest.NewRequest(method, path, nil)
		} else {
			req = httptest.NewRequest(method, path, bytes.NewReader(body))
		}
		req.Header.Set("Authorization", "Bearer "+testToken)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	get := func() (content, hash string) {
		t.Helper()
		rec := do("GET", "/api/v1/config", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET config: code=%d body=%q", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), sentinelUser) || strings.Contains(rec.Body.String(), sentinelPass) {
			t.Fatal("sentinel leaked into GET /api/v1/config response")
		}
		data := decodeEnvelope(t, rec)["data"].(map[string]any)
		content, _ = data["content"].(string)
		hash, _ = data["sha256"].(string)
		if content == "" || hash == "" {
			t.Fatalf("GET config envelope = %v; want content+sha256", data)
		}
		return content, hash
	}

	content1, hash1 := get()
	if !strings.Contains(content1, "<redacted>") {
		t.Fatalf("redacted view has no sentinel marker: %q", content1)
	}
	putBody, _ := json.Marshal(map[string]string{"content": content1, "base_sha256": hash1})
	rec := do("PUT", "/api/v1/config", putBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT round-trip: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), sentinelUser) || strings.Contains(rec.Body.String(), sentinelPass) {
		t.Fatal("sentinel leaked into PUT /api/v1/config response")
	}
	content2, _ := get()
	// The save path normalises the document through a parse
	// (profile defaults are filled in), so the views need
	// not be byte-identical — but the credentials block
	// must survive the round-trip unchanged.
	if canonicalJSON(t, credentialsOf(t, content1)) != canonicalJSON(t, credentialsOf(t, content2)) {
		t.Fatalf("credentials block changed across round-trip:\n%s\n---\n%s", content1, content2)
	}
	// Values on disk preserved, no marker persisted.
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "<redacted>") {
		t.Fatalf("sentinel marker persisted to disk: %q", raw)
	}
	single, found, err := profile.LoadSingleConfig(dir)
	if err != nil || !found {
		t.Fatalf("load saved config: found=%v err=%v", found, err)
	}
	creds, err := profile.ResolveCredentials(single)
	if err != nil || creds == nil {
		t.Fatalf("resolve credentials: %v", err)
	}
	cred, ok := creds.CredentialForProfile("muse01")
	if !ok || cred.Username != sentinelUser || cred.Password != sentinelPass {
		t.Fatalf("saved credential = ok=%v; want the original sentinels", ok)
	}
	cred.Clear()
}

func canonicalJSON(t *testing.T, s string) string {
	t.Helper()
	v, err := decodeGeneric([]byte(s))
	if err != nil {
		t.Fatalf("decodeGeneric: %v", err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// credentialsOf extracts the credentials block of a config
// document as a JSON string for comparison.
func credentialsOf(t *testing.T, s string) string {
	t.Helper()
	v, err := decodeGeneric([]byte(s))
	if err != nil {
		t.Fatalf("decodeGeneric: %v", err)
	}
	doc, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("config is not an object: %T", v)
	}
	raw, err := json.Marshal(doc["credentials"])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}
