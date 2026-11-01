// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// Manifest + checksums verification for local-directory plugins
// (BQ4). The pattern mirrors CLIProxyAPI
// internal/pluginstore/checksum.go:10 (ParseChecksums) and :34
// (VerifyChecksum) and install.go:125-133 (download checksums.txt,
// parse, verify BEFORE extract) — with the download/registry/
// signing parts deliberately NOT taken: there is no store, no
// registry, and no default remote. Verification happens at load
// time, on the SHADOW-COPY bytes about to be dlopened, when the
// caller supplies a manifest path (Desired.ManifestPath): the
// loader hashes the shadow file through a single open
// (O_NOFOLLOW on unix; plain open plus the Lstat refusal
// elsewhere — see open_unix.go / open_windows.go) and
// compares it against the manifest. Verifying the
// source file instead would leave a swap window between the
// verify read and the shadow copy; the shadow bytes are the
// bytes the loader maps. A directory with no checksums.txt is
// unverified but loadable (local, first-party files); that
// absence is stated in docs/plugins.md, never hidden behind a
// verification claim. No caller in this PR supplies a
// ManifestPath except tests: wiring the manifest from a plugin
// directory's checksums.txt is future work for the wiring PR
// (see docs/plugins.md "Known limits").

// ParseChecksums parses a checksums.txt body: one
// "<sha256-hex>  <name>" per line, blank lines and #-comments
// skipped, a leading "*" on the name stripped (sha256sum -b
// form). It mirrors upstream's ParseChecksums. Duplicate
// names, absolute names, and names containing a path
// separator or ".." are rejected: a manifest entry names
// exactly one base name in the plugin directory, and a
// duplicate must never silently last-win.
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
		if err := validateManifestName(name); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("line %d: duplicate checksum entry for %q", lineNumber+1, name)
		}
		out[name] = hash
	}
	return out, nil
}

func validateManifestName(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("invalid checksum name %q", name)
	}
	if filepath.IsAbs(name) || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return fmt.Errorf("invalid checksum name %q", name)
	}
	if filepath.Base(name) != name {
		return fmt.Errorf("invalid checksum name %q", name)
	}
	return nil
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
// Both files are opened refusing symlinks (final component
// and every path component): a manifest or plugin reached
// through a symlink is refused rather than verified through
// the link. This helper verifies the bytes at pluginPath;
// the loader path verifies the shadow copy instead (see
// VerifyShadowFileChecksum).
func VerifyFileChecksum(pluginPath, manifestPath string) error {
	if err := refuseSymlinkedComponents(pluginPath); err != nil {
		return err
	}
	if err := refuseSymlinkedComponents(manifestPath); err != nil {
		return err
	}
	data, err := readRegularFile(pluginPath)
	if err != nil {
		return err
	}
	manifest, err := readRegularFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read plugin checksums manifest: %w", err)
	}
	checksums, err := ParseChecksums(manifest)
	if err != nil {
		return err
	}
	return VerifyChecksum(filepath.Base(pluginPath), data, checksums)
}

// VerifyShadowFileChecksum verifies the shadow-copy bytes at
// shadowPath against the checksums.txt manifest at
// manifestPath, looking the entry up by entryName (the base
// name of the original plugin file — the shadow file's own
// name is content-derived and never appears in a manifest).
// The shadow file is hashed through a single open
// (O_NOFOLLOW on unix; plain open plus the Lstat refusal
// elsewhere) with a regular-file re-check, so the hashed
// bytes are the bytes on the shadow path at verify time. A residual window
// remains between this verification and dlopen (no fd pin);
// see docs/plugins.md "Known limits" (U1).
func VerifyShadowFileChecksum(shadowPath, manifestPath, entryName string) error {
	if err := validateManifestName(entryName); err != nil {
		return err
	}
	if err := refuseSymlinkedComponents(manifestPath); err != nil {
		return err
	}
	manifest, err := readRegularFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read plugin checksums manifest: %w", err)
	}
	checksums, err := ParseChecksums(manifest)
	if err != nil {
		return err
	}
	expected := strings.ToLower(strings.TrimSpace(checksums[entryName]))
	if expected == "" {
		return fmt.Errorf("checksum for %s not found", entryName)
	}
	f, err := openPluginSource(shadowPath)
	if err != nil {
		return openErrorWithoutPath("open plugin shadow file", err)
	}
	defer func() { _ = f.Close() }()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("plugin shadow file is not a regular file")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return fmt.Errorf("hash plugin shadow file: %w", err)
	}
	if hex.EncodeToString(hasher.Sum(nil)) != expected {
		return fmt.Errorf("checksum mismatch for %s", entryName)
	}
	return nil
}

// readRegularFile reads a whole file through an open with
// a regular-file re-check (O_NOFOLLOW on unix), refusing
// symlinks.
func readRegularFile(path string) ([]byte, error) {
	f, err := openPluginSource(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("file %q is not a regular file", path)
	}
	return io.ReadAll(f)
}
