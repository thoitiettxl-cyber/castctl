// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestShadowCopy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "echo.so")
	content := []byte("fake-plugin-bytes-1")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}
	file := File{ID: "echo", Path: src}
	shadow1, err := ShadowCopy(file)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(shadow1)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("shadow content = %q, want %q", got, content)
	}
	base := filepath.Base(shadow1)
	sum := sha256.Sum256(content)
	wantPrefix := "castctl-plugin-echo-" + hex.EncodeToString(sum[:])[:32]
	if !strings.HasPrefix(base, wantPrefix) || !strings.HasSuffix(base, ".so") {
		t.Fatalf("shadow name = %q, want prefix %q + .so", base, wantPrefix)
	}
	if !strings.Contains(shadow1, "castctl-pluginhost"+string(filepath.Separator)+"pid-") {
		t.Fatalf("shadow path = %q, want castctl-pluginhost/pid-<pid> dir", shadow1)
	}
	// Same content again -> same shadow path.
	shadow2, err := ShadowCopy(file)
	if err != nil {
		t.Fatal(err)
	}
	if shadow2 != shadow1 {
		t.Fatalf("second shadow = %q, want %q", shadow2, shadow1)
	}
	// Different content -> different shadow path; source untouched.
	if err := os.WriteFile(src, []byte("fake-plugin-bytes-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	shadow3, err := ShadowCopy(file)
	if err != nil {
		t.Fatal(err)
	}
	if shadow3 == shadow1 {
		t.Fatal("different content must map to a different shadow path")
	}
	// A symlink source is refused (castctl hardening; upstream
	// has no such check — see docs/plugins.md).
	link := filepath.Join(dir, "link.so")
	if err := os.Symlink(src, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ShadowCopy(File{ID: "echo", Path: link}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink source err = %v, want symlink refusal", err)
	}
	// A directory source is refused.
	if _, err := ShadowCopy(File{ID: "echo", Path: dir}); err == nil {
		t.Fatal("directory source: want error")
	}
}

func TestDiscover(t *testing.T) {
	root := t.TempDir()
	ext := PluginExtension(runtime.GOOS)
	write := func(rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archDir := filepath.Join(runtime.GOOS, runtime.GOARCH)
	write(filepath.Join(archDir, "echo-v1.2.3"+ext))
	write(filepath.Join(archDir, "echo"+ext)) // arch dir wins over root for echo
	write("echo-v9.9.9" + ext)
	write("other" + ext)
	write("bad name!" + ext) // invalid id: skipped
	write("notaplugin.txt")
	files, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("discovered = %+v, want 2 files", files)
	}
	byID := map[string]File{}
	for _, f := range files {
		byID[f.ID] = f
	}
	echo, ok := byID["echo"]
	if !ok {
		t.Fatalf("echo not discovered: %+v", files)
	}
	if echo.Version != "1.2.3" {
		t.Fatalf("echo version = %q, want 1.2.3 (arch-dir file wins)", echo.Version)
	}
	if byID["other"].Version != "" {
		t.Fatalf("other version = %q, want empty", byID["other"].Version)
	}
	if _, err := Discover(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing root: want error")
	}
}

func TestPluginExtension(t *testing.T) {
	if got := PluginExtension("darwin"); got != ".dylib" {
		t.Fatalf("darwin ext = %q", got)
	}
	if got := PluginExtension("windows"); got != ".dll" {
		t.Fatalf("windows ext = %q", got)
	}
	if got := PluginExtension("linux"); got != ".so" {
		t.Fatalf("linux ext = %q", got)
	}
}

func TestStrippedOutboundHash(t *testing.T) {
	a := []byte(`{"type":"http","tag":"p","password":"first-secret"}`)
	b := []byte(`{"type":"http","tag":"p","password":"second-secret"}`)
	c := []byte(`{"type":"socks","tag":"p","password":"first-secret"}`)
	ha, err := StrippedOutboundHash(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := StrippedOutboundHash(b)
	if err != nil {
		t.Fatal(err)
	}
	hc, err := StrippedOutboundHash(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(ha) != 64 {
		t.Fatalf("hash = %q, want 64 hex chars", ha)
	}
	if ha != hb {
		t.Fatalf("hash differs across secret values: %s vs %s (identity must be secret-blind)", ha, hb)
	}
	if ha == hc {
		t.Fatal("hash equal across different outbound types: want different")
	}
	raw := sha256.Sum256(a)
	if ha == hex.EncodeToString(raw[:]) {
		t.Fatal("stripped hash equals raw hash: secrets were not stripped")
	}
	if _, err := StrippedOutboundHash([]byte(`{bad json`)); err == nil {
		t.Fatal("invalid json: want error")
	}
	if _, err := StrippedOutboundHash([]byte(`[1,2]`)); err == nil {
		t.Fatal("non-object json: want error")
	}
}

func TestChecksums(t *testing.T) {
	dir := t.TempDir()
	data := []byte("plugin-bytes")
	sum := sha256.Sum256(data)
	sumHex := hex.EncodeToString(sum[:])
	pluginPath := filepath.Join(dir, "echo.so")
	if err := os.WriteFile(pluginPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	text := "# comment\n\n" + sumHex + "  echo.so\n"
	sums, err := ParseChecksums([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChecksum("echo.so", data, sums); err != nil {
		t.Fatal(err)
	}
	if err := VerifyChecksum("echo.so", []byte("other"), sums); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("mismatch err = %v", err)
	}
	if err := VerifyChecksum("missing.so", data, sums); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing entry err = %v", err)
	}
	if err := VerifyFileChecksum(pluginPath, filepath.Join(dir, "checksums.txt")); err == nil {
		t.Fatal("missing checksums file: want error")
	}
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFileChecksum(pluginPath, filepath.Join(dir, "checksums.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseChecksums([]byte("short\n")); err == nil {
		t.Fatal("bad checksum line: want error")
	}
	if _, err := ParseChecksums([]byte("zz" + strings.Repeat("0", 62) + "  echo.so\n")); err == nil {
		t.Fatal("non-hex checksum: want error")
	}
}
