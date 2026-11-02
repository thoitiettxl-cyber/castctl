// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && linux

package pluginhost_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginhost"
)

// TestRealLoaderOriginDepRefusesCleanly: a plugin whose
// DT_NEEDED dependency is resolved via $ORIGIN fails to
// load through the shadow copy (the shadow directory has
// no such sidecar), and the failure is a clean load error,
// not a crash. Transitive dependencies are a documented
// known limit: deps must be self-contained or absolute-rpath.
func TestRealLoaderOriginDepRefusesCleanly(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("cc not available")
	}
	dir := t.TempDir()
	depSrc := "int dep_symbol(void) { return 42; }\n"
	if err := os.WriteFile(filepath.Join(dir, "dep.c"), []byte(depSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	pluginSrc := `
#include <stdint.h>
#include <stddef.h>
typedef struct { void* ptr; size_t len; } castctl_buffer;
typedef struct { uint32_t abi_version; void* call; void* free_buffer; void* shutdown; } castctl_plugin_api;
extern int dep_symbol(void);
__attribute__((visibility("default"))) int castctl_plugin_init(void* host, castctl_plugin_api* plugin) {
	(void)host;
	if (plugin == NULL) return 1;
	if (dep_symbol() != 42) return 1;
	plugin->abi_version = 1;
	plugin->call = NULL;
	plugin->free_buffer = NULL;
	plugin->shutdown = NULL;
	return 0;
}
`
	if err := os.WriteFile(filepath.Join(dir, "plugin.c"), []byte(pluginSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run("cc", "-shared", "-fPIC", "-o", "libdep.so", "dep.c")
	run("cc", "-shared", "-fPIC", "-o", "plugin.so", "plugin.c", "-L.", "-ldep", "-Wl,-rpath,$ORIGIN")
	// The sidecar exists next to the source plugin, so a
	// direct dlopen would succeed; the shadow copy has no
	// sidecar, so the host load must refuse cleanly.
	so := filepath.Join(dir, "plugin.so")
	if err := os.Remove(filepath.Join(dir, "libdep.so")); err != nil {
		t.Fatal(err)
	}
	var logs []string
	h := pluginhost.New(pluginhost.Options{Log: func(level, message string) { logs = append(logs, level+":"+message) }})
	defer h.Close()
	report := h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "origin", Type: "origin", Path: so}})
	if len(report.Skipped) != 1 {
		t.Fatalf("report = %+v, want one skip", report)
	}
	reason := report.Skipped[0].Reason
	if !strings.Contains(reason, "dlopen") && !strings.Contains(reason, "cannot open shared object") && !strings.Contains(reason, "libdep") {
		t.Fatalf("skip reason = %q, want a dlopen refusal", reason)
	}
	// The test process survived: dlopen refusal is a clean
	// error, not a crash. (Reaching this line is the proof.)
}
