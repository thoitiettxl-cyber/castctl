// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeManifest(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	manifest := filepath.Join(dir, "checksums.txt")
	if err := os.WriteFile(manifest, []byte(hex.EncodeToString(sum[:])+"  "+name+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestParseChecksumsRejectsDuplicatesAndTraversal(t *testing.T) {
	sum := strings.Repeat("a", 64)
	for _, manifest := range []string{
		sum + "  echo.so\n" + sum + "  echo.so\n",
		sum + "  ../evil.so\n",
		sum + "  /abs/evil.so\n",
		sum + "  sub/echo.so\n",
	} {
		if _, err := ParseChecksums([]byte(manifest)); err == nil {
			t.Fatalf("manifest %q: want error", manifest)
		}
	}
	if _, err := ParseChecksums([]byte(sum + "  echo.so\n")); err != nil {
		t.Fatalf("valid manifest: %v", err)
	}
}

func TestVerifyShadowFileChecksumTamperAndSymlink(t *testing.T) {
	dir := t.TempDir()
	data := []byte("shadow-bytes-v1")
	shadow := filepath.Join(dir, "castctl-plugin-echo-abc.so")
	if err := os.WriteFile(shadow, data, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := writeManifest(t, dir, "echo.so", data)
	if err := VerifyShadowFileChecksum(shadow, manifest, "echo.so"); err != nil {
		t.Fatalf("untampered shadow: %v", err)
	}
	// Tamper after the manifest was written: verification
	// of the shadow bytes must fail.
	if err := os.WriteFile(shadow, []byte("shadow-bytes-v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyShadowFileChecksum(shadow, manifest, "echo.so"); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("tampered shadow err = %v, want mismatch", err)
	}
	// A symlinked shadow path is refused.
	real := filepath.Join(dir, "real.so")
	if err := os.WriteFile(real, data, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.so")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := VerifyShadowFileChecksum(link, manifest, "echo.so"); err == nil {
		t.Fatal("symlinked shadow path: want error")
	}
}

func TestVerifyFileChecksumRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	data := []byte("plugin-bytes")
	real := filepath.Join(dir, "echo.so")
	if err := os.WriteFile(real, data, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := writeManifest(t, dir, "echo.so", data)
	if err := VerifyFileChecksum(real, manifest); err != nil {
		t.Fatalf("regular file: %v", err)
	}
	link := filepath.Join(dir, "via.so")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// The manifest entry is keyed by base name "via.so",
	// which is absent — but the symlink refusal must fire
	// first and be the reported reason.
	if err := VerifyFileChecksum(link, manifest); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked plugin err = %v, want symlink refusal", err)
	}
}

// TestVerifyShadowFileChecksumNoShadowPathLeak: errors from
// the checksum/compat gates must never embed the shadow
// path (which carries the pid directory layout).
func TestVerifyShadowFileChecksumNoShadowPathLeak(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "echo.so", []byte("shadow-bytes"))
	shadow := filepath.Join(dir, "castctl-pluginhost", "pid-424242", "castctl-plugin-echo-abc.so")
	// Missing shadow file: the open error must not carry
	// the shadow path.
	err := VerifyShadowFileChecksum(shadow, manifest, "echo.so")
	if err == nil {
		t.Fatal("missing shadow file: want error")
	}
	if strings.Contains(err.Error(), "pid-424242") || strings.Contains(err.Error(), "castctl-pluginhost") {
		t.Fatalf("checksum error leaked shadow path: %v", err)
	}
	// Non-regular shadow file (a directory): same rule.
	shadowDir := filepath.Join(dir, "castctl-pluginhost", "pid-424243", "castctl-plugin-echo-def.so")
	if err := os.MkdirAll(shadowDir, 0o700); err != nil {
		t.Fatal(err)
	}
	err = VerifyShadowFileChecksum(shadowDir, manifest, "echo.so")
	if err == nil {
		t.Fatal("directory shadow file: want error")
	}
	if strings.Contains(err.Error(), "pid-424243") || strings.Contains(err.Error(), "castctl-pluginhost") {
		t.Fatalf("checksum error leaked shadow path: %v", err)
	}
}
