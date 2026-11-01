// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && (linux || darwin || freebsd)

package commands

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/plugintest"
)

func runPluginCheck(t *testing.T, path string) (string, string, error) {
	t.Helper()
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Getenv: mapGetenv(nil)}
	err := cmdPluginCheck(context.Background(), env, []string{path})
	return out.String(), errb.String(), err
}

func TestPluginCheckProviderPasses(t *testing.T) {
	dir := t.TempDir()
	so := plugintest.BuildFakePlugin(t, dir, plugintest.FakePluginOptions{})
	out, errb, err := runPluginCheck(t, so)
	if err != nil {
		t.Fatalf("check err = %v stderr=%s", err, errb)
	}
	for _, line := range []string{"dlopen: ok", "init: ok", "register: ok", "provider.call: ok", "shutdown: ok"} {
		if !strings.Contains(out, line) {
			t.Fatalf("output missing %q:\n%s", line, out)
		}
	}
}

func TestPluginCheckCommandOnlySkipsProviderCall(t *testing.T) {
	dir := t.TempDir()
	so := plugintest.BuildFakePlugin(t, dir, plugintest.FakePluginOptions{Caps: "command"})
	out, errb, err := runPluginCheck(t, so)
	if err != nil {
		t.Fatalf("command-only check err = %v stderr=%s", err, errb)
	}
	if !strings.Contains(out, "provider.call: skipped (command-only plugin)") {
		t.Fatalf("output missing skip line:\n%s", out)
	}
	if strings.Contains(out, "provider.call: ok") {
		t.Fatalf("command-only plugin must not run provider.call:\n%s", out)
	}
}

func TestPluginCheckCorruptNoShadowPathLeak(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.so")
	if err := os.WriteFile(bad, []byte("not an elf"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, errb, err := runPluginCheck(t, bad)
	if err == nil {
		t.Fatal("corrupt plugin: want error")
	}
	if !strings.Contains(errb, "FAIL") {
		t.Fatalf("stderr missing FAIL: %s", errb)
	}
	if strings.Contains(errb, "castctl-plugins") || strings.Contains(errb, "pid-") {
		t.Fatalf("check output leaks shadow path/pid: %s", errb)
	}
}

func TestPluginCheckHelpersRedactAndCap(t *testing.T) {
	if got := shortPluginCheckError(errors.New(`boom hatch_sess=SECRETVALUE tail`)); strings.Contains(got, "SECRETVALUE") {
		t.Fatalf("shortPluginCheckError leaked: %q", got)
	}
	long := strings.Repeat("x", 5000)
	if got := shortPluginCheckError(errors.New(long)); len(got) > 210 {
		t.Fatalf("shortPluginCheckError len = %d, want <= 210", len(got))
	}
	if got := compactJSON([]byte(`{"a": 1}`)); got != `{"a":1}` {
		t.Fatalf("compactJSON = %q", got)
	}
	if got := compactJSON([]byte(strings.Repeat("y", 5000))); len(got) > 4100 {
		t.Fatalf("compactJSON len = %d, want capped", len(got))
	}
	if got := compactJSON([]byte(`{"api_key":"abc123"}`)); strings.Contains(got, "abc123") {
		t.Fatalf("compactJSON leaked: %q", got)
	}
	if got := checkField("a\nb\x1bc"); strings.ContainsAny(got, "\n\x1b") {
		t.Fatalf("checkField kept controls: %q", got)
	}
}
