// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Shadow copies (mirroring CLIProxyAPI internal/pluginhost/shadow.go
// at pin 250d5981: shadowCopyPlugin :33, shadowCopyPluginToDir :73,
// shadowPluginPath :154, digest length 32 at :28, pid dir at :128
// with MkdirAll 0700, temp prefix at :29, predictable
// sha256[:32] name — NOT random, NOT memfd).
//
// A loaded Go plugin image must stay mapped for the lifetime of
// the host process (its runtime cannot be unloaded), so loading
// from a shadow copy keeps the original artifact replaceable
// and gives every distinct plugin build its own path, which the
// dynamic loader maps as a fresh image.
//
// Castctl hardening, NOT upstream (upstream has no Lstat /
// hardlink / O_NOFOLLOW check — verified absent by grep at pin
// 250d5981; never cite upstream for it): the source is refused
// when it is a symlink, and must be a regular file. This is a
// load-time check on the artifact path, not a sandbox: it does
// not make an untrusted plugin safe.

const (
	shadowPrefix     = "castctl-plugin-"
	shadowTempPrefix = ".castctl-plugin-"
	shadowDigestLen  = 32
)

var shadowCleanupOnce sync.Once

// ShadowCopy copies the plugin file into the per-process shadow
// directory and returns the shadow path. Identical content maps
// to the same path; different content maps to a different path.
// The source file is never modified.
func ShadowCopy(file File) (string, error) {
	dir, err := shadowDir()
	if err != nil {
		return "", err
	}
	shadowCleanupOnce.Do(func() { removeStaleShadowPlugins(dir) })
	return shadowCopyToDir(file, dir)
}

func shadowDir() (string, error) {
	dir := filepath.Join(os.TempDir(), "castctl-pluginhost", fmt.Sprintf("pid-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func removeStaleShadowPlugins(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry == nil || entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, shadowPrefix) || strings.HasPrefix(name, shadowTempPrefix) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

func shadowCopyToDir(file File, dir string) (string, error) {
	source := filepath.Clean(file.Path)
	if info, err := os.Lstat(source); err != nil {
		return "", err
	} else if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("plugin file %q must not be a symlink", source)
	} else if !info.Mode().IsRegular() {
		return "", fmt.Errorf("plugin file %q is not a regular file", source)
	}
	tmp, err := os.CreateTemp(dir, shadowTempPrefix+file.ID+"-*"+filepath.Ext(source))
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpName)
		}
	}()
	in, err := openPluginSource(source)
	if err != nil {
		_ = tmp.Close()
		return "", err
	}
	defer func() { _ = in.Close() }()
	if info, err := in.Stat(); err != nil || !info.Mode().IsRegular() {
		_ = tmp.Close()
		return "", fmt.Errorf("plugin file %q is not a regular file", source)
	}
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, hasher), in)
	if err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	target := shadowPath(dir, file.ID, digest, filepath.Ext(source))
	if shadowMatches(target, size, digest) {
		return target, nil
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		if shadowMatches(target, size, digest) {
			return target, nil
		}
		_ = os.Remove(target)
		return "", fmt.Errorf("remove stale shadow plugin: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		if shadowMatches(target, size, digest) {
			return target, nil
		}
		return "", fmt.Errorf("move shadow plugin: %w", err)
	}
	removeTemp = false
	return target, nil
}

func shadowPath(dir, id, digest, ext string) string {
	if len(digest) > shadowDigestLen {
		digest = digest[:shadowDigestLen]
	}
	return filepath.Join(dir, shadowPrefix+id+"-"+digest+ext)
}

func shadowMatches(path string, size int64, digest string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !info.Mode().IsRegular() || info.Size() != size {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return false
	}
	got := hex.EncodeToString(hasher.Sum(nil))
	if len(got) > shadowDigestLen {
		got = got[:shadowDigestLen]
	}
	if len(digest) > shadowDigestLen {
		digest = digest[:shadowDigestLen]
	}
	return got == digest
}
