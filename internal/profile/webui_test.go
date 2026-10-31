// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"strings"
	"testing"
)

func parseWebUITestConfig(t *testing.T, doc string) *SingleConfig {
	t.Helper()
	cfg, err := ParseSingleConfig([]byte(doc), t.TempDir())
	if err != nil {
		t.Fatalf("ParseSingleConfig: %v", err)
	}
	return cfg
}

func TestWebUIBlockAbsent(t *testing.T) {
	cfg := parseWebUITestConfig(t, `{"profiles":{}}`)
	if cfg.WebUI != nil {
		t.Fatalf("WebUI = %+v, want nil (absent block)", cfg.WebUI)
	}
	resolved, err := ResolveWebUI(cfg)
	if err != nil || resolved != nil {
		t.Fatalf("ResolveWebUI = %v, %v; want nil, nil", resolved, err)
	}
	if got := EffectiveListen(nil); got != DefaultWebUIListen {
		t.Fatalf("EffectiveListen(nil) = %q, want %q", got, DefaultWebUIListen)
	}
}

func TestWebUIBlockPresent(t *testing.T) {
	cfg := parseWebUITestConfig(t, `{"profiles":{},"webui":{"listen":"127.0.0.1:8317","token":"MARKER-WEBUI-TOKEN"}}`)
	if cfg.WebUI == nil {
		t.Fatal("WebUI is nil, want parsed block")
	}
	if cfg.WebUI.Listen != "127.0.0.1:8317" {
		t.Fatalf("Listen = %q", cfg.WebUI.Listen)
	}
	if cfg.WebUI.Token != "MARKER-WEBUI-TOKEN" {
		t.Fatal("Token was not preserved verbatim")
	}
	if got := EffectiveListen(cfg.WebUI); got != "127.0.0.1:8317" {
		t.Fatalf("EffectiveListen = %q", got)
	}
	// Default listen when the key is absent from a present block.
	cfg2 := parseWebUITestConfig(t, `{"profiles":{},"webui":{"token":"MARKER-WEBUI-TOKEN"}}`)
	if got := EffectiveListen(cfg2.WebUI); got != DefaultWebUIListen {
		t.Fatalf("EffectiveListen = %q, want %q", got, DefaultWebUIListen)
	}
}

func TestWebUIListenValidation(t *testing.T) {
	cases := []struct {
		listen string
		valid  bool
	}{
		{"127.0.0.1:8317", true},
		{"127.0.0.2:1", true},
		{"127.255.255.255:65535", true},
		{"localhost:8317", true},
		{"LOCALHOST:8317", true},
		{"[::1]:8317", true},
		{"0.0.0.0:8317", false},
		{"[::]:8317", false},
		{"192.168.1.1:8317", false},
		{"example.com:8317", false},
		{"127.0.0.1", false},          // missing port
		{"127.0.0.1:0", false},        // port 0
		{"127.0.0.1:65536", false},   // port out of range
		{"127.0.0.1:abc", false},     // non-numeric port
		{"http://127.0.0.1:8317", false}, // URL, not host:port
		{"user@127.0.0.1:8317", false},   // userinfo
		{"127.0.0.1:8317/path", false},   // path
		{"127.0.0.1:8317?x=1", false},    // query
		{"", false},
		{"   ", false},
	}
	for _, tc := range cases {
		doc := `{"profiles":{},"webui":{"listen":` + quoteWebUIJSON(tc.listen) + `}}`
		_, err := ParseSingleConfig([]byte(doc), t.TempDir())
		if tc.valid && err != nil {
			t.Errorf("listen %q: unexpected error: %v", tc.listen, err)
		}
		if !tc.valid {
			if err == nil {
				t.Errorf("listen %q: accepted, want rejection", tc.listen)
			} else if strings.Contains(err.Error(), tc.listen) && tc.listen != "" {
				t.Errorf("listen %q: error echoes the value: %v", tc.listen, err)
			}
		}
	}
}

func quoteWebUIJSON(s string) string {
	// Minimal JSON string quoting for the table above (no control
	// characters in the test values).
	out := `"`
	for _, r := range s {
		switch r {
		case '"':
			out += `\"`
		case '\\':
			out += `\\`
		default:
			out += string(r)
		}
	}
	return out + `"`
}

func TestWebUIBlockRejects(t *testing.T) {
	cases := []string{
		`{"profiles":{},"webui":[]}`,
		`{"profiles":{},"webui":{"listen":8317}}`,
		`{"profiles":{},"webui":{"token":""}}`,
		`{"profiles":{},"webui":{"token":123}}`,
		`{"profiles":{},"webui":{"listen":""}}`,
		`{"profiles":{},"webui":{"unknown":true}}`,
		`{"profiles":{},"webui":{"listen":"0.0.0.0:8317"}}`,
	}
	for _, doc := range cases {
		if _, err := ParseSingleConfig([]byte(doc), t.TempDir()); err == nil {
			t.Errorf("doc %s: accepted, want rejection", doc)
		}
	}
	// The token value must never be echoed in an error.
	_, err := ParseSingleConfig([]byte(`{"profiles":{},"webui":{"token":""}}`), t.TempDir())
	if err == nil || strings.Contains(err.Error(), "MARKER") {
		t.Fatalf("empty-token error = %v", err)
	}
}

func TestWebUIBlockRoundTrip(t *testing.T) {
	// A hand-built config (no raw capture) renders the block and
	// re-parses identically, token verbatim.
	cfg := &SingleConfig{
		Profiles: map[string]*Profile{},
		WebUI:    &WebUIConfig{Listen: "127.0.0.1:9000", Token: "MARKER-WEBUI-TOKEN"},
	}
	encoded, err := encodeSingleConfig(cfg)
	if err != nil {
		t.Fatalf("encodeSingleConfig: %v", err)
	}
	back, err := ParseSingleConfig(encoded, t.TempDir())
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if back.WebUI == nil || back.WebUI.Listen != "127.0.0.1:9000" || back.WebUI.Token != "MARKER-WEBUI-TOKEN" {
		t.Fatalf("round-trip WebUI = %+v", back.WebUI)
	}
	// Raw preservation: a parsed block re-renders verbatim.
	cfg2 := parseWebUITestConfig(t, "{\n  \"profiles\": {},\n  \"webui\": {\"token\": \"MARKER-WEBUI-TOKEN\", \"listen\": \"127.0.0.1:8317\"}\n}")
	encoded2, err := encodeSingleConfig(cfg2)
	if err != nil {
		t.Fatalf("encodeSingleConfig: %v", err)
	}
	if !strings.Contains(string(encoded2), `"token": "MARKER-WEBUI-TOKEN"`) {
		t.Fatalf("raw webui block not preserved verbatim:\n%s", encoded2)
	}
}
