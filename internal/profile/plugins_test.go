// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const pluginsBaseConfig = `{"profiles":{"default":{}}}`

func parsePluginsConfig(t *testing.T, pluginsJSON string) *SingleConfig {
	t.Helper()
	data := `{"profiles":{"default":{}},"plugins":` + pluginsJSON + `}`
	cfg, err := ParseSingleConfig([]byte(data), t.TempDir())
	if err != nil {
		t.Fatalf("ParseSingleConfig = %v", err)
	}
	return cfg
}

func TestParsePluginsArrayInline(t *testing.T) {
	cfg := parsePluginsConfig(t, `[{"tag":"echo","type":"echo","greeting":"hi","nested":{"n":3},"list":[1,2]}]`)
	if cfg.Plugins == nil {
		t.Fatal("Plugins is nil, want non-nil")
	}
	if got := len(cfg.Plugins.Entries); got != 1 {
		t.Fatalf("entries = %d, want 1", got)
	}
	e := cfg.Plugins.Entries[0]
	if e.Tag != "echo" || e.Type != "echo" {
		t.Fatalf("entry = %+v, want tag/type echo", e)
	}
	wantFragment := `{"greeting":"hi","nested":{"n":3},"list":[1,2]}`
	if got := string(e.FragmentJSON()); got != wantFragment {
		t.Fatalf("fragment = %s, want %s", got, wantFragment)
	}
	if raw := cfg.RawPlugins(); len(raw) == 0 {
		t.Fatal("RawPlugins empty, want captured raw")
	}
}

func TestParsePluginsEnabledKeyIsOpaqueData(t *testing.T) {
	cfg := parsePluginsConfig(t, `[{"tag":"echo","type":"echo","enabled":false}]`)
	if len(cfg.Plugins.Entries) != 1 {
		t.Fatalf("entries = %d, want 1: presence means active, enabled:false must not disable", len(cfg.Plugins.Entries))
	}
	if got := string(cfg.Plugins.Entries[0].FragmentJSON()); got != `{"enabled":false}` {
		t.Fatalf("fragment = %s, want %s", got, `{"enabled":false}`)
	}
}

func TestParsePluginsAbsentMeansNil(t *testing.T) {
	cfg, err := ParseSingleConfig([]byte(pluginsBaseConfig), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Plugins != nil {
		t.Fatalf("Plugins = %+v, want nil when block absent", cfg.Plugins)
	}
}

func TestParsePluginsShapeErrors(t *testing.T) {
	cases := []struct {
		name    string
		plugins string
		want    string
	}{
		{"object not array", `{"enabled":true}`, `"plugins" must be an array`},
		{"entry not object", `[42]`, `"plugins" entry 0 must be an object`},
		{"missing tag", `[{"type":"echo"}]`, `"tag" must be a non-empty string`},
		{"missing type", `[{"tag":"echo"}]`, `"type" must be a non-empty string`},
		{"empty tag", `[{"tag":"","type":"echo"}]`, `"tag" must be a non-empty string`},
		{"tag not string", `[{"tag":1,"type":"echo"}]`, `"tag" must be a non-empty string`},
		{"type not string", `[{"tag":"echo","type":1}]`, `"type" must be a non-empty string`},
		{"duplicate tags", `[{"tag":"echo","type":"echo"},{"tag":"echo","type":"echo"}]`, `duplicate plugin tag "echo"`},
		{"tag with slash", `[{"tag":"a/b","type":"echo"}]`, `invalid "tag"`},
		{"tag with space padding", `[{"tag":" echo ","type":"echo"}]`, `invalid "tag"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := `{"profiles":{"default":{}},"plugins":` + tc.plugins + `}`
			_, err := ParseSingleConfig([]byte(data), t.TempDir())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseSingleConfig err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestPluginsSaveRoundTripPreservesFragment(t *testing.T) {
	dir := t.TempDir()
	data := `{"profiles":{"default":{}},"webui":{"listen":"127.0.0.1:8317"},"plugins":[{"tag":"echo","type":"echo","zeta":1,"alpha":"x"}]}`
	cfg, err := ParseSingleConfig([]byte(data), dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSingleConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), `"zeta": 1`) || !strings.Contains(string(saved), `"alpha": "x"`) {
		t.Fatalf("saved config lost fragment keys/order: %s", saved)
	}
	// Plugins block comes after webui in save order.
	if strings.Index(string(saved), `"webui"`) > strings.Index(string(saved), `"plugins"`) {
		t.Fatalf("plugins block must follow webui in save order: %s", saved)
	}
	cfg2, err := ParseSingleConfig(saved, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(cfg2.Plugins.Entries[0].FragmentJSON()); got != `{"zeta":1,"alpha":"x"}` {
		t.Fatalf("re-parsed fragment = %s", got)
	}
}

func TestRedactConfigPluginsFragmentWholesale(t *testing.T) {
	cfg := parsePluginsConfig(t, `[{"tag":"echo","type":"echo","api_key":"SECRET-VALUE-xyz","endpoint":"https://example.invalid/x"}]`)
	out, err := RedactConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "SECRET-VALUE-xyz") {
		t.Fatalf("RedactConfig leaked fragment value: %s", out)
	}
	if strings.Contains(string(out), "example.invalid") {
		t.Fatalf("RedactConfig leaked fragment value: %s", out)
	}
	if !strings.Contains(string(out), `"tag": "echo"`) || !strings.Contains(string(out), `"type": "echo"`) {
		t.Fatalf("RedactConfig lost tag/type: %s", out)
	}
	if !strings.Contains(string(out), `"<redacted>"`) {
		t.Fatalf("RedactConfig missing <redacted> marker: %s", out)
	}
	if strings.Contains(string(out), `"api_key"`) {
		t.Fatalf("RedactConfig leaked fragment key name: %s", out)
	}
	if !strings.Contains(string(out), `"fragment": "<redacted>"`) {
		t.Fatalf("RedactConfig marker key must be \"fragment\": %s", out)
	}
}

func TestParsePluginsTypeValidation(t *testing.T) {
	for _, typ := range []string{"../evil", "a/b", "", "echo x", "echo\nx", strings.Repeat("e", 129)} {
		data := `{"profiles":{"default":{}},"plugins":[{"tag":"echo","type":` + strconv.Quote(typ) + `}]}`
		if _, err := ParseSingleConfig([]byte(data), t.TempDir()); err == nil {
			t.Fatalf("type %q: want config error", typ)
		}
	}
	for _, typ := range []string{"echo", "echo-1", "echo.v2", "e"} {
		data := `{"profiles":{"default":{}},"plugins":[{"tag":"echo","type":` + strconv.Quote(typ) + `}]}`
		if _, err := ParseSingleConfig([]byte(data), t.TempDir()); err != nil {
			t.Fatalf("type %q: want valid, got %v", typ, err)
		}
	}
}

func TestRedactRawConfigMatchesRedactJSONWithoutPlugins(t *testing.T) {
	raw := []byte(`{"profiles":{"default":{"outbound":{"type":"direct","tag":"direct"}}},"log":{"level":"info"}}`)
	a, err := RedactJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RedactRawConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("RedactRawConfig differs without plugins:\n%s\nvs\n%s", a, b)
	}
}

func TestRedactRawConfigPluginsFragmentWholesale(t *testing.T) {
	raw := []byte(`{"profiles":{"default":{}},"plugins":[{"tag":"echo","type":"echo","api_key":"SECRET-VALUE-xyz","weird_name":"hidden-value"}]}`)
	out, err := RedactRawConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "SECRET-VALUE-xyz") || strings.Contains(string(out), "hidden-value") || strings.Contains(string(out), "weird_name") {
		t.Fatalf("RedactRawConfig leaked fragment: %s", out)
	}
	if !strings.Contains(string(out), `"fragment": "<redacted>"`) {
		t.Fatalf("RedactRawConfig missing fragment marker: %s", out)
	}
}

// Malformed plugins shapes must redact wholesale: a fragment value
// must never survive display just because the shape is not the
// well-formed array-of-objects the parser accepts.
func TestRedactRawConfigMalformedPluginsShapes(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"object", `{"profiles":{"default":{}},"plugins":{"tag":"echo","type":"echo","api_key":"SECRET-VALUE-xyz"}}`},
		{"string", `{"profiles":{"default":{}},"plugins":"SECRET-VALUE-xyz"}`},
		{"number", `{"profiles":{"default":{}},"plugins":42}`},
		{"array-string", `{"profiles":{"default":{}},"plugins":["SECRET-VALUE-xyz"]}`},
		{"array-number", `{"profiles":{"default":{}},"plugins":[42]}`},
		{"array-null", `{"profiles":{"default":{}},"plugins":[null]}`},
		{"array-mixed", `{"profiles":{"default":{}},"plugins":[{"tag":"echo","type":"echo"},"SECRET-VALUE-xyz",42]}`},
		{"non-string-tag", `{"profiles":{"default":{}},"plugins":[{"tag":123,"type":"echo","api_key":"SECRET-VALUE-xyz"}]}`},
		{"non-string-type", `{"profiles":{"default":{}},"plugins":[{"tag":"echo","type":["echo"],"api_key":"SECRET-VALUE-xyz"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := RedactRawConfig([]byte(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(out), "SECRET-VALUE-xyz") {
				t.Fatalf("RedactRawConfig leaked fragment for %s shape: %s", tc.name, out)
			}
			if !strings.Contains(string(out), "<redacted>") {
				t.Fatalf("RedactRawConfig missing marker for %s shape: %s", tc.name, out)
			}
		})
	}
}

func TestPluginsFragmentDefensiveCopy(t *testing.T) {
	cfg := parsePluginsConfig(t, `[{"tag":"echo","type":"echo","n":1}]`)
	frag := cfg.Plugins.Entries[0].FragmentJSON()
	frag[0] = 'X'
	if got := string(cfg.Plugins.Entries[0].FragmentJSON()); got != `{"n":1}` {
		t.Fatalf("fragment mutated via copy: %s", got)
	}
}

// TestInvalidPluginTagErrorBounded: an over-long invalid tag
// or type must not bloat the config error with its full
// value; the echo is truncated with a marker.
func TestInvalidPluginTagErrorBounded(t *testing.T) {
	long := strings.Repeat("x", 5000) + "!"
	for _, field := range []string{"tag", "type"} {
		var data string
		if field == "tag" {
			data = `{"profiles":{"default":{}},"plugins":[{"tag":` + strconv.Quote(long) + `,"type":"echo"}]}`
		} else {
			data = `{"profiles":{"default":{}},"plugins":[{"tag":"echo","type":` + strconv.Quote(long) + `}]}`
		}
		_, err := ParseSingleConfig([]byte(data), t.TempDir())
		if err == nil {
			t.Fatalf("%s: want config error", field)
		}
		if len(err.Error()) > 300 {
			t.Fatalf("%s error len = %d, want bounded: %.100q...", field, len(err.Error()), err.Error())
		}
		if !strings.Contains(err.Error(), "…") {
			t.Fatalf("%s error missing truncation marker: %.100q...", field, err.Error())
		}
	}
}
