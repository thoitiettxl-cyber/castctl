// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginabi_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
)

func TestVersionsAndSymbol(t *testing.T) {
	if got := pluginabi.ABIVersion; got != 1 {
		t.Fatalf("ABIVersion = %d, want 1", got)
	}
	if got := pluginabi.SchemaVersion; got != 1 {
		t.Fatalf("SchemaVersion = %d, want 1", got)
	}
	if got := pluginabi.EntrySymbol; got != "castctl_plugin_init" {
		t.Fatalf("EntrySymbol = %q, want %q", got, "castctl_plugin_init")
	}
	if got := pluginabi.MethodPluginRegister; got != "plugin.register" {
		t.Fatalf("MethodPluginRegister = %q, want %q", got, "plugin.register")
	}
	if got := pluginabi.MethodHostLog; got != "host.log" {
		t.Fatalf("MethodHostLog = %q, want %q", got, "host.log")
	}
}

func validRegistration() pluginabi.Registration {
	return pluginabi.Registration{
		SchemaVersion: 1,
		Metadata: pluginabi.Metadata{
			Name:             "echo",
			Version:          "0.1.0",
			Author:           "castctl",
			GitHubRepository: "https://github.com/thoitiettxl-cyber/castctl",
		},
		Capabilities: pluginabi.Capabilities{Provider: true},
	}
}

func TestValidateRegistration(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		schema, err := pluginabi.ValidateRegistration(validRegistration())
		if err != nil {
			t.Fatalf("ValidateRegistration = %v, want nil", err)
		}
		if schema != 1 {
			t.Fatalf("schema = %d, want 1", schema)
		}
	})
	t.Run("missing schema becomes 1", func(t *testing.T) {
		reg := validRegistration()
		reg.SchemaVersion = 0
		schema, err := pluginabi.ValidateRegistration(reg)
		if err != nil {
			t.Fatalf("ValidateRegistration = %v, want nil", err)
		}
		if schema != 1 {
			t.Fatalf("schema = %d, want 1", schema)
		}
	})
	t.Run("higher schema rejected", func(t *testing.T) {
		reg := validRegistration()
		reg.SchemaVersion = 2
		if _, err := pluginabi.ValidateRegistration(reg); err == nil || !strings.Contains(err.Error(), "plugin schema version 2 is not supported") {
			t.Fatalf("ValidateRegistration err = %v, want error containing %q", err, "plugin schema version 2 is not supported")
		}
	})
	t.Run("empty name rejected", func(t *testing.T) {
		reg := validRegistration()
		reg.Metadata.Name = ""
		if _, err := pluginabi.ValidateRegistration(reg); err == nil || !strings.Contains(err.Error(), "plugin metadata name is required") {
			t.Fatalf("ValidateRegistration err = %v, want name error", err)
		}
	})
	t.Run("empty version rejected", func(t *testing.T) {
		reg := validRegistration()
		reg.Metadata.Version = ""
		if _, err := pluginabi.ValidateRegistration(reg); err == nil {
			t.Fatal("ValidateRegistration = nil, want error")
		}
	})
	t.Run("empty author rejected", func(t *testing.T) {
		reg := validRegistration()
		reg.Metadata.Author = ""
		if _, err := pluginabi.ValidateRegistration(reg); err == nil {
			t.Fatal("ValidateRegistration = nil, want error")
		}
	})
	t.Run("no capabilities rejected", func(t *testing.T) {
		reg := validRegistration()
		reg.Capabilities = pluginabi.Capabilities{}
		if _, err := pluginabi.ValidateRegistration(reg); err == nil || !strings.Contains(err.Error(), "at least one capability") {
			t.Fatalf("ValidateRegistration err = %v, want capability error", err)
		}
	})
	t.Run("commands without command_provider rejected", func(t *testing.T) {
		reg := validRegistration()
		reg.Commands = []pluginabi.Command{{Name: "x"}}
		if _, err := pluginabi.ValidateRegistration(reg); err == nil || !strings.Contains(err.Error(), "command_provider") {
			t.Fatalf("ValidateRegistration err = %v, want command_provider error", err)
		}
	})
	t.Run("commands with command_provider accepted", func(t *testing.T) {
		reg := validRegistration()
		reg.Capabilities = pluginabi.Capabilities{CommandProvider: true}
		reg.Commands = []pluginabi.Command{{Name: "x", Usage: "run x"}}
		if _, err := pluginabi.ValidateRegistration(reg); err != nil {
			t.Fatalf("ValidateRegistration = %v, want nil", err)
		}
	})
	t.Run("empty command name rejected", func(t *testing.T) {
		reg := validRegistration()
		reg.Capabilities = pluginabi.Capabilities{CommandProvider: true}
		reg.Commands = []pluginabi.Command{{Name: ""}}
		if _, err := pluginabi.ValidateRegistration(reg); err == nil || !strings.Contains(err.Error(), "command name is required") {
			t.Fatalf("ValidateRegistration err = %v, want command name error", err)
		}
	})
	t.Run("metadata newline rejected", func(t *testing.T) {
		reg := validRegistration()
		reg.Metadata.Name = "echo\nFORGED-LINE"
		if _, err := pluginabi.ValidateRegistration(reg); err == nil || !strings.Contains(err.Error(), "control characters") {
			t.Fatalf("ValidateRegistration err = %v, want control-character error", err)
		}
	})
	t.Run("cookie_hosts valid", func(t *testing.T) {
		reg := validRegistration()
		reg.CookieHosts = []string{"api.example.invalid", "example.invalid"}
		if _, err := pluginabi.ValidateRegistration(reg); err != nil {
			t.Fatalf("ValidateRegistration = %v, want nil", err)
		}
	})
	t.Run("cookie_hosts rejected", func(t *testing.T) {
		for _, host := range []string{"*.example.invalid", "example.invalid:443", "https://example.invalid", "exa mple.invalid", "", "EXAMPLE.INVALID", "/etc/passwd"} {
			reg := validRegistration()
			reg.CookieHosts = []string{host}
			if _, err := pluginabi.ValidateRegistration(reg); err == nil {
				t.Fatalf("ValidateRegistration cookie_hosts %q = nil, want error", host)
			}
		}
	})
}

func TestEnvelopeJSON(t *testing.T) {
	env := pluginabi.Envelope{OK: true, Result: json.RawMessage(`{"payload":"echo-ok"}`)}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); got != `{"ok":true,"result":{"payload":"echo-ok"}}` {
		t.Fatalf("envelope = %s, want %s", got, `{"ok":true,"result":{"payload":"echo-ok"}}`)
	}
	var back pluginabi.Envelope
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !back.OK || string(back.Result) != `{"payload":"echo-ok"}` {
		t.Fatalf("decoded envelope = %+v", back)
	}
	errEnv := pluginabi.NewErrorEnvelope("plugin_error", "boom")
	raw, err = json.Marshal(errEnv)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); got != `{"ok":false,"error":{"code":"plugin_error","message":"boom"}}` {
		t.Fatalf("error envelope = %s", got)
	}
}

func TestRegisterRequestJSONKeys(t *testing.T) {
	req := pluginabi.RegisterRequest{
		ConfigJSON:    json.RawMessage(`{"greeting":"hi"}`),
		SchemaVersion: 1,
		Tag:           "echo",
		Type:          "echo",
		Identity:      &pluginabi.Identity{OutboundTag: "direct", OutboundHash: "abc"},
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"config_json", "schema_version", "tag", "type", "identity"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("register request missing key %q: %s", key, raw)
		}
	}
	if _, ok := decoded["cookies"]; ok {
		t.Fatalf("register request must never carry cookies: %s", raw)
	}
	if _, ok := decoded["cookie_file"]; ok {
		t.Fatalf("register request must never carry cookie_file: %s", raw)
	}
}

// TestValidCookieHostLabels: per-label rules refuse empty
// labels and hyphen-edged labels; string-exact scope means
// no refused shape could have widened injection.
func TestValidCookieHostLabels(t *testing.T) {
	valid := []string{"example.invalid", "a", "a-b.c-d", "a1.b2", strings.Repeat("a", 63) + ".invalid", "x." + strings.Repeat("a", 63)}
	for _, h := range valid {
		if !pluginabi.ValidCookieHost(h) {
			t.Fatalf("ValidCookieHost(%q) = false, want true", h)
		}
	}
	invalid := []string{
		"", "a..b", "a-.b", "a.-b", "-a.b", "a.b-", ".a.b", "a.b.",
		"a_b", "a/b", "a:b", "a b", "A.B", "*.invalid", "a.*",
		strings.Repeat("a", 64) + ".invalid", strings.Repeat("a", 254),
		"http://example.invalid", "example.invalid:443",
	}
	for _, h := range invalid {
		if pluginabi.ValidCookieHost(h) {
			t.Fatalf("ValidCookieHost(%q) = true, want false", h)
		}
	}
}
