// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build cgo && (linux || darwin || freebsd)

package pluginhost_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
	"github.com/thoitiettxl-cyber/castctl/internal/pluginhost"
	"github.com/thoitiettxl-cyber/castctl/internal/plugintest"
)

func newRealHost(t *testing.T, logs *[]string) *pluginhost.Host {
	t.Helper()
	return pluginhost.New(pluginhost.Options{
		Log: func(level, message string) {
			*logs = append(*logs, level+":"+message)
		},
	})
}

func applyOne(t *testing.T, h *pluginhost.Host, path string, opts ...func(*pluginhost.Desired)) pluginhost.ApplyReport {
	t.Helper()
	d := pluginhost.Desired{Tag: "echo", Type: "echo", Path: path, Fragment: []byte(`{"greeting":"hi"}`)}
	for _, o := range opts {
		o(&d)
	}
	return h.ApplyConfig(context.Background(), []pluginhost.Desired{d})
}

func TestRealLoaderLoadCallAndHostCallbacks(t *testing.T) {
	dir := t.TempDir()
	so := plugintest.BuildFakePlugin(t, dir, plugintest.FakePluginOptions{})
	var logs []string
	h := newRealHost(t, &logs)
	defer h.Close()
	report := applyOne(t, h, so)
	if len(report.Skipped) != 0 {
		t.Fatalf("skipped = %+v", report.Skipped)
	}
	loaded, ok := h.Loaded("echo")
	if !ok || loaded.Metadata.Name != "fake" || loaded.SchemaVersion != 1 {
		t.Fatalf("loaded = %+v ok=%v", loaded, ok)
	}
	out, err := h.Call(context.Background(), "echo", pluginabi.MethodProviderCall, []byte(`{"input":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(out, &payload); err != nil || payload.Payload != "echo:ping" {
		t.Fatalf("provider call = %s err=%v", out, err)
	}
	// host.log: the fixture calls back and expects an OK envelope.
	out, err = h.Call(context.Background(), "echo", "fake.log", nil)
	if err != nil {
		t.Fatalf("fake.log err = %v", err)
	}
	if !strings.Contains(string(out), `"logged":true`) {
		t.Fatalf("fake.log = %s", out)
	}
	found := false
	for _, l := range logs {
		if strings.Contains(l, "hello from fake") {
			found = true
		}
	}
	if !found {
		t.Fatalf("logs = %v, want hello from fake", logs)
	}
	// host.auth.*: the fixture calls back and expects rejection.
	_, err = h.Call(context.Background(), "echo", "fake.auth", nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported host callback") || !strings.Contains(err.Error(), "host_auth_rejected") {
		t.Fatalf("fake.auth err = %v, want host_auth_rejected wrapping unsupported host callback rejection", err)
	}
}

func TestRealLoaderMissingSymbol(t *testing.T) {
	dir := t.TempDir()
	so := plugintest.BuildNoSymbolPlugin(t, dir)
	var logs []string
	h := newRealHost(t, &logs)
	defer h.Close()
	report := applyOne(t, h, so)
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "missing castctl_plugin_init") {
		t.Fatalf("skipped = %+v, want missing-symbol refusal", report.Skipped)
	}
}

func TestRealLoaderABIMismatch(t *testing.T) {
	dir := t.TempDir()
	so := plugintest.BuildFakePlugin(t, dir, plugintest.FakePluginOptions{ABI: "2"})
	var logs []string
	h := newRealHost(t, &logs)
	defer h.Close()
	report := applyOne(t, h, so)
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "ABI version 2 is not supported") {
		t.Fatalf("skipped = %+v, want ABI refusal", report.Skipped)
	}
}

func TestRealLoaderBadMetadataAndSchema(t *testing.T) {
	cases := []struct {
		name string
		opts plugintest.FakePluginOptions
		want string
		load bool
	}{
		{"schema 2 rejected", plugintest.FakePluginOptions{Schema: "2"}, "not supported", false},
		{"schema 0 becomes 1", plugintest.FakePluginOptions{Schema: "0"}, "", true},
		{"no capabilities", plugintest.FakePluginOptions{Caps: "none"}, "at least one capability", false},
		{"empty name", plugintest.FakePluginOptions{EmptyName: true}, "name is required", false},
		{"fail register", plugintest.FakePluginOptions{FailRegister: true}, "register_failed", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			so := plugintest.BuildFakePlugin(t, dir, tc.opts)
			var logs []string
			h := newRealHost(t, &logs)
			defer h.Close()
			report := applyOne(t, h, so)
			if tc.load {
				if len(report.Skipped) != 0 {
					t.Fatalf("skipped = %+v, want load", report.Skipped)
				}
				loaded, ok := h.Loaded("echo")
				if !ok || loaded.SchemaVersion != 1 {
					t.Fatalf("loaded = %+v", loaded)
				}
				return
			}
			if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, tc.want) {
				t.Fatalf("skipped = %+v, want %q", report.Skipped, tc.want)
			}
		})
	}
}

func TestRealLoaderCorruptSO(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.so")
	if err := os.WriteFile(bad, []byte("this is not a shared library at all, just text"), 0o644); err != nil {
		t.Fatal(err)
	}
	var logs []string
	h := newRealHost(t, &logs)
	defer h.Close()
	report := applyOne(t, h, bad)
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "dlopen") {
		t.Fatalf("skipped = %+v, want dlopen refusal", report.Skipped)
	}
}

var glibcVersionRe = regexp.MustCompile(`GLIBC_2\.[0-9.]+`)

// patchGLIBCRequirement rewrites every GLIBC_2.x requirement
// in the .dynstr of src to a 2.99x requirement of identical
// byte length, keeping all ELF offsets valid. The patched
// copy must be refused by the compat gate before dlopen.
func patchGLIBCRequirement(t *testing.T, src, dst string) {
	t.Helper()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	patched := glibcVersionRe.ReplaceAllFunc(raw, func(m []byte) []byte {
		// m is like "GLIBC_2.34" or "GLIBC_2.2.5": keep the
		// "GLIBC_2." prefix and fill the rest with 9s.
		out := make([]byte, len(m))
		copy(out, m[:len("GLIBC_2.")])
		for i := len("GLIBC_2."); i < len(out); i++ {
			out[i] = '9'
		}
		return out
	})
	if string(patched) == string(raw) {
		t.Fatal("no GLIBC_ requirement found to patch")
	}
	if err := os.WriteFile(dst, patched, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRealLoaderGLIBCCompatGate(t *testing.T) {
	dir := t.TempDir()
	so := plugintest.BuildFakePlugin(t, dir, plugintest.FakePluginOptions{})
	// The unpatched 2.17-era fixture loads (its requirements
	// are satisfied by the running libc).
	max, err := pluginhost.MaxRequiredGLIBC(so)
	if err != nil {
		t.Fatalf("MaxRequiredGLIBC = %v", err)
	}
	t.Logf("fixture max required GLIBC = %q", max)
	if err := pluginhost.CheckPluginCompat(so); err != nil {
		t.Fatalf("CheckPluginCompat(unpatched) = %v", err)
	}
	patched := filepath.Join(dir, "patched.so")
	patchGLIBCRequirement(t, so, patched)
	maxPatched, err := pluginhost.MaxRequiredGLIBC(patched)
	if err != nil {
		t.Fatalf("MaxRequiredGLIBC(patched) = %v", err)
	}
	t.Logf("patched max required GLIBC = %q", maxPatched)
	if err := pluginhost.CheckPluginCompat(patched); err == nil || !strings.Contains(err.Error(), "requires GLIBC_") {
		t.Fatalf("CheckPluginCompat(patched) = %v, want GLIBC refusal", err)
	}
	// The loader refuses the patched file BEFORE dlopen: the
	// skip reason is the compat error, never a dlopen error.
	var logs []string
	h := newRealHost(t, &logs)
	defer h.Close()
	report := applyOne(t, h, patched)
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "requires GLIBC_") {
		t.Fatalf("skipped = %+v, want compat refusal before dlopen", report.Skipped)
	}
	// And the unpatched original still loads through the
	// same host.
	report = applyOne(t, h, so)
	if len(report.Skipped) != 0 {
		t.Fatalf("skipped = %+v, want unpatched load", report.Skipped)
	}
}

func TestRealLoaderDiscoveryAndChecksum(t *testing.T) {
	dir := t.TempDir()
	so := plugintest.BuildFakePlugin(t, dir, plugintest.FakePluginOptions{})
	root := filepath.Join(dir, "plugins")
	archDir := filepath.Join(root, "linux", "amd64")
	if err := os.MkdirAll(archDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A stray file with an invalid name is skipped; the
	// arch-dir candidate wins over the root candidate.
	if err := copyFile(t, so, filepath.Join(archDir, "echo-v1.2.3.so")); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(t, so, filepath.Join(root, "echo-v9.9.9.so")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archDir, "not-a-plugin.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := pluginhost.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	var found pluginhost.File
	for _, f := range files {
		if f.ID == "echo" {
			found = f
		}
	}
	if found.Version != "9.9.9" || !strings.Contains(found.Path, "echo-v9.9.9.so") {
		t.Fatalf("discovered = %+v, want root 9.9.9 (highest version wins)", files)
	}
	if _, err := pluginhost.Discover(filepath.Join(dir, "no-such-root")); err == nil {
		t.Fatal("missing root: want error")
	}
	// Manifest verification at load: correct checksum loads,
	// wrong checksum refuses before dlopen.
	manifest := filepath.Join(dir, "checksums.txt")
	sum := sha256File(t, so)
	if err := os.WriteFile(manifest, []byte(sum+"  "+filepath.Base(so)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pluginhost.VerifyFileChecksum(so, manifest); err != nil {
		t.Fatalf("VerifyFileChecksum(correct) = %v", err)
	}
	if err := os.WriteFile(manifest, []byte(strings.Repeat("0", 64)+"  "+filepath.Base(so)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pluginhost.VerifyFileChecksum(so, manifest); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("VerifyFileChecksum(wrong) = %v, want checksum mismatch", err)
	}
	var logs []string
	h := newRealHost(t, &logs)
	defer h.Close()
	report := applyOne(t, h, so, func(d *pluginhost.Desired) { d.ManifestPath = manifest })
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "checksum mismatch") {
		t.Fatalf("skipped = %+v, want checksum refusal", report.Skipped)
	}
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func copyFile(t *testing.T, src, dst string) error {
	t.Helper()
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, raw, 0o644)
}
