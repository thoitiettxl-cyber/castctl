// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func noEnv(string) (string, bool) { return "", false }

func runMain(t *testing.T, home string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, noEnv, &out, &errb, home)
	return code, out.String(), errb.String()
}

func TestVersionAndHelp(t *testing.T) {
	home := t.TempDir()
	if code, out, _ := runMain(t, home, "--version"); code != 0 || strings.TrimSpace(out) != "muse-cli 0.6.1" {
		t.Fatalf("--version: code=%d out=%q", code, out)
	}
	if code, out, _ := runMain(t, home, "--help"); code != 0 || !strings.Contains(out, "Usage: muse-cli") {
		t.Fatalf("--help: code=%d out=%q", code, out)
	}
	if code, out, _ := runMain(t, home, "-h"); code != 0 || !strings.Contains(out, "Usage: muse-cli") {
		t.Fatalf("-h: code=%d out=%q", code, out)
	}
}

func TestArgparseShapeRejections(t *testing.T) {
	home := t.TempDir()
	for _, args := range [][]string{{"--version=true"}, {"-version"}, {"--profile"}, {"--bogus"}, {"-x"}} {
		if code, _, _ := runMain(t, home, args...); code != 2 {
			t.Fatalf("%v: code=%d, want 2", args, code)
		}
	}
}

func TestUnknownFlagAndPositionalExit2(t *testing.T) {
	home := t.TempDir()
	if code, _, _ := runMain(t, home, "--bogus"); code != 2 {
		t.Fatalf("unknown flag: code=%d, want 2", code)
	}
	if code, _, _ := runMain(t, home, "send"); code != 2 {
		t.Fatalf("positional arg: code=%d, want 2", code)
	}
}

func TestConfigLoadNoConfigDefaults(t *testing.T) {
	home := t.TempDir()
	code, out, _ := runMain(t, home)
	if code != 0 {
		t.Fatalf("code=%d, want 0", code)
	}
	var s summary
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatalf("unmarshal: %v (out=%q)", err, out)
	}
	if s.Profile != "default" || s.Source != "none" || s.ConfigFound {
		t.Fatalf("summary=%+v, want default/none/not-found", s)
	}
	if strings.Contains(out, "vm_id") || strings.Contains(out, "node_id") || strings.Contains(out, "subscription_action_id") {
		t.Fatalf("output must never contain secret/id fields: %q", out)
	}
	// Read-only: no files created under the fake home.
	var names []string
	_ = filepath.Walk(home, func(p string, _ os.FileInfo, _ error) error { names = append(names, p); return nil })
	if len(names) != 1 {
		t.Fatalf("load wrote files: %v", names)
	}
}

func TestConfigLoadSingleFile(t *testing.T) {
	home := t.TempDir()
	base := filepath.Join(home, ".config", "muse-cli")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `{"default_profile":"default","profiles":{"default":{"auto_approve":"always","auto_allow_once":true,"outbound":"proxy"}},"outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080,"version":"5"}]}`
	if err := os.WriteFile(filepath.Join(base, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runMain(t, home)
	if code != 0 {
		t.Fatalf("code=%d, want 0", code)
	}
	var s summary
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Profile != "default" || s.Source != "single" || !s.ConfigFound || s.AutoApprove != "always" || !s.AutoAllowOnce {
		t.Fatalf("summary=%+v", s)
	}
	if s.OutboundKind != "tag" || s.OutboundTag != "proxy" || s.OutboundType != "socks" {
		t.Fatalf("outbound=%+v, want tag/proxy/socks", s)
	}
}

func TestConfigLoadUnparseableExits2(t *testing.T) {
	home := t.TempDir()
	base := filepath.Join(home, ".config", "muse-cli")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "config.json"), []byte(`{"profiles":{},"bogus":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runMain(t, home); code != 2 {
		t.Fatalf("code=%d, want 2", code)
	}
}
