// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Manifest + checksums verification for local-directory plugins
// (BQ4). The pattern mirrors CLIProxyAPI
// internal/pluginstore/checksum.go:10 (ParseChecksums) and :34
// (VerifyChecksum) and install.go:116-133 (download checksums.txt,
// parse, verify BEFORE extract) — with the download/registry/
// signing parts deliberately NOT taken: there is no store, no
// registry, and no default remote. Verification happens at
// place/load time for files already in a local plugin directory:
// a directory carrying a checksums.txt manifest must have every
// plugin file it lists verify, and a plugin file listed in the
// manifest must match before it is loaded. A directory with no
// checksums.txt is unverified but loadable (local, first-party
// files); that absence is stated in docs/plugins.md, never
// hidden behind a verification claim.

// ParseChecksums parses a checksums.txt body: one
// "<sha256-hex>  <name>" per line, blank lines and #-comments
// skipped, a leading "*" on the name stripped (sha256sum -b
// form). It mirrors upstream's ParseChecksums.
func ParseChecksums(data []byte) (map[string]string, error) {
	out := map[string]string{}
	for lineNumber, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("line %d: invalid checksum entry", lineNumber+1)
		}
		hash := strings.ToLower(strings.TrimSpace(fields[0]))
		if len(hash) != sha256.Size*2 {
			return nil, fmt.Errorf("line %d: invalid sha256 length", lineNumber+1)
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return nil, fmt.Errorf("line %d: invalid sha256: %w", lineNumber+1, err)
		}
		name := strings.TrimPrefix(strings.TrimSpace(fields[1]), "*")
		out[name] = hash
	}
	return out, nil
}

// VerifyChecksum checks data against the manifest entry for
// name. A missing entry and a mismatch are both errors naming
// the file only, never a hash value beyond the expected form
// already present in the manifest.
func VerifyChecksum(name string, data []byte, checksums map[string]string) error {
	expected := strings.ToLower(strings.TrimSpace(checksums[name]))
	if expected == "" {
		return fmt.Errorf("checksum for %s not found", name)
	}
	actualBytes := sha256.Sum256(data)
	if hex.EncodeToString(actualBytes[:]) != expected {
		return fmt.Errorf("checksum mismatch for %s", name)
	}
	return nil
}

// VerifyFileChecksum verifies the plugin file at pluginPath
// against the checksums.txt manifest at manifestPath. The
// manifest entry is looked up by the plugin file's base name.
func VerifyFileChecksum(pluginPath, manifestPath string) error {
	data, err := os.ReadFile(pluginPath)
	if err != nil {
		return err
	}
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read plugin checksums manifest: %w", err)
	}
	checksums, err := ParseChecksums(manifest)
	if err != nil {
		return err
	}
	return VerifyChecksum(filepath.Base(pluginPath), data, checksums)
}
