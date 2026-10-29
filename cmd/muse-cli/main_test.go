// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/commands"
)

// runMain drives the real dispatch with a hermetic HOME: the config
// location resolves under t.TempDir via the process environment
// (t.Setenv), never the real ~/.config.
func runMain(t *testing.T, home string, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("MUSE_CLI_CONFIG", "")
	t.Setenv("MUSE_CLI_PROFILE", "")
	var out, errb bytes.Buffer
	code := commands.Run(context.Background(), args, &commands.Env{Stdout: &out, Stderr: &errb, Stdin: strings.NewReader("")})
	return code, out.String(), errb.String()
}

func TestVersionAndHelp(t *testing.T) {
	home := t.TempDir()
	if code, out, _ := runMain(t, home, "--version"); code != 0 || strings.TrimSpace(out) != "muse-cli 0.6.1" {
		t.Fatalf("--version: code=%d out=%q", code, out)
	}
	if code, out, _ := runMain(t, home, "--help"); code != 0 || !strings.Contains(out, "muse-cli") {
		t.Fatalf("--help: code=%d out=%q", code, out)
	}
	if code, out, _ := runMain(t, home, "-h"); code != 0 || !strings.Contains(out, "muse-cli") {
		t.Fatalf("-h: code=%d out=%q", code, out)
	}
	// Help mentions the config-location contract.
	if _, out, _ := runMain(t, home, "--help"); !strings.Contains(out, "--config") || !strings.Contains(out, "MUSE_CLI_CONFIG") || !strings.Contains(out, "XDG") {
		t.Fatalf("--help must mention --config, MUSE_CLI_CONFIG and XDG: %q", out)
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

func TestUnknownAndDeferredCommandsExit2(t *testing.T) {
	home := t.TempDir()
	if code, _, errb := runMain(t, home, "--bogus"); code != 2 {
		t.Fatalf("unknown flag: code=%d, want 2", code)
	} else if errb == "" {
		t.Fatalf("unknown flag: empty stderr")
	}
	// Deferred commands name their PR; unknown commands do not.
	// "send" is wired (PR4): bare "send" fails on the missing TEXT
	// positional with exit 2, with no deferred note.
	if code, _, errb := runMain(t, home, "send"); code != 2 || strings.Contains(errb, "is not implemented in the Go port yet") {
		t.Fatalf("send: code=%d err=%q, want 2 without a deferred message", code, errb)
	}
	if code, _, errb := runMain(t, home, "telegram"); code != 2 || !strings.Contains(errb, "PR5") {
		t.Fatalf("telegram: code=%d err=%q, want 2 + PR5", code, errb)
	}
	if code, _, errb := runMain(t, home, "frobnicate"); code != 2 || strings.Contains(errb, "is not implemented in the Go port yet") {
		t.Fatalf("unknown command: code=%d err=%q, want 2 without a deferred message", code, errb)
	}
}

func TestBareInvocationRunsChat(t *testing.T) {
	home := t.TempDir()
	code, out, errb := runMain(t, home)
	if code != 2 || !strings.Contains(out, "Can't sign in") || !strings.Contains(out, "cookie export is not available") || !strings.Contains(errb, "cookies_missing") {
		t.Fatalf("bare: code=%d out=%q err=%q, want chat sign-in failure", code, out, errb)
	}
	// Nothing is read or written under the fake home: the REPL
	// fails at connect, before any state file or config write.
	var names []string
	_ = filepath.Walk(home, func(p string, _ os.FileInfo, _ error) error { names = append(names, p); return nil })
	if len(names) != 1 {
		t.Fatalf("bare invocation touched the home dir: %v", names)
	}
}

func TestProfileListLoadsSingleFile(t *testing.T) {
	home := t.TempDir()
	base := filepath.Join(home, ".config", "muse-cli")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `{"default_profile":"default","profiles":{"default":{"auto_approve":"always","auto_allow_once":true,"outbound":"proxy"}},"outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080,"version":"5"}]}`
	if err := os.WriteFile(filepath.Join(base, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runMain(t, home, "profile", "list")
	if code != 0 {
		t.Fatalf("code=%d, want 0 (out=%q)", code, out)
	}
	var list struct {
		Active string `json:"active"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatalf("unmarshal: %v (out=%q)", err, out)
	}
	if list.Active != "default" || list.Source != "single" {
		t.Fatalf("list=%+v, want default/single", list)
	}
	if strings.Contains(out, "vm_id") || strings.Contains(out, "node_id") || strings.Contains(out, "subscription_action_id") {
		t.Fatalf("output must never contain secret/id fields: %q", out)
	}
}

func TestProfileListUnparseableExits2(t *testing.T) {
	home := t.TempDir()
	base := filepath.Join(home, ".config", "muse-cli")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "config.json"), []byte(`{"profiles":{},"bogus":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runMain(t, home, "profile", "list"); code != 2 {
		t.Fatalf("code=%d, want 2", code)
	}
}
