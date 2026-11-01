// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// Discovery (mirroring CLIProxyAPI
// internal/pluginhost/platform.go at pin 250d5981: candidateDirs
// :308, DiscoverPluginFiles :291, PluginExtension :99,
// pluginFileFromPath :62, ID regex :17, version rule :39-40,
// comparePluginVersions :218, pluginFilePreferred :204).
//
// A plugin binary is named <id>[-v<version>]<ext> and is looked
// up in <root>/<goos>/<goarch> first, then in <root>. Selection
// is by VERSION, mirroring upstream pluginFilePreferred: the
// highest version wins across both directories (numeric
// segments, a missing segment counting as 0, non-numeric
// segments falling back to lexical order); a versioned file
// beats a versionless one; on an exact version tie the
// platform directory wins. A downgrade is therefore never
// silent: dropping an older file into the root cannot beat a
// newer platform file. Files whose names do not parse —
// including a "-v" suffix whose version part is malformed
// (e.g. echo-vv1.0.so) — are skipped, not given a silent
// odd id. Symlink entries are skipped at discovery (the
// load-time refusal in ShadowCopy is the backstop). The root
// itself must exist and must not traverse a symlinked
// component; a missing root is an error so a misconfigured
// plugins directory fails closed instead of silently
// loading nothing.

var pluginIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var pluginVersionPattern = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]*$`)

// File is one discovered plugin binary.
type File struct {
	ID      string
	Path    string
	Version string
	// ManifestPath, when set, names a checksums.txt manifest
	// the shadow-copy bytes must verify against before the
	// file is loaded. It is set by the host from Desired,
	// never by discovery.
	ManifestPath string
}

// ValidatePluginID reports whether id can be used as a plugin
// file ID / config tag.
func ValidatePluginID(id string) bool { return pluginIDPattern.MatchString(id) }

// PluginExtension returns the dynamic library extension for
// goos: .dylib on darwin, .dll on windows, .so elsewhere.
func PluginExtension(goos string) string {
	switch goos {
	case "darwin":
		return ".dylib"
	case "windows":
		return ".dll"
	default:
		return ".so"
	}
}

func fileFromPath(path, requiredExt string) (File, bool) {
	base := filepath.Base(path)
	lowerBase := strings.ToLower(base)
	ext := strings.TrimSpace(requiredExt)
	if ext != "" {
		if !strings.HasSuffix(lowerBase, strings.ToLower(ext)) {
			return File{}, false
		}
	} else {
		for _, candidate := range []string{".so", ".dylib", ".dll"} {
			if strings.HasSuffix(lowerBase, candidate) {
				ext = candidate
				break
			}
		}
		if ext == "" {
			return File{}, false
		}
	}
	name := base[:len(base)-len(ext)]
	id := name
	version := ""
	if idx := strings.LastIndex(name, "-v"); idx > 0 {
		candidateID := name[:idx]
		candidateVersion := name[idx+2:]
		if validPluginID(candidateID) {
			if !validPluginVersion(candidateVersion) {
				// A "-v" suffix with a malformed
				// version is not a different id: the
				// file is skipped, never silently
				// discovered under an odd id.
				return File{}, false
			}
			id = candidateID
			version = candidateVersion
		}
	}
	if !validPluginID(id) {
		return File{}, false
	}
	return File{ID: id, Path: path, Version: version}, true
}

// comparePluginVersions mirrors upstream
// comparePluginVersions (platform.go:218): numeric
// dot-separated segments, a missing segment counting as 0.
// It returns (comparison, comparable): comparable is false
// when any segment is non-numeric (e.g. a pre-release tag),
// in which case callers fall back to lexical order.
func comparePluginVersions(a, b string) (int, bool) {
	segmentsA := strings.Split(a, ".")
	segmentsB := strings.Split(b, ".")
	length := len(segmentsA)
	if len(segmentsB) > length {
		length = len(segmentsB)
	}
	for index := 0; index < length; index++ {
		numberA, okA := pluginVersionSegment(segmentsA, index)
		numberB, okB := pluginVersionSegment(segmentsB, index)
		if !okA || !okB {
			return 0, false
		}
		if numberA != numberB {
			if numberA < numberB {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func pluginVersionSegment(segments []string, index int) (int64, bool) {
	if index >= len(segments) {
		return 0, true
	}
	number, err := strconv.ParseInt(segments[index], 10, 64)
	if err != nil || number < 0 {
		return 0, false
	}
	return number, true
}

// pluginFilePreferred mirrors upstream pluginFilePreferred
// (platform.go:204): a versioned candidate beats a
// versionless current, a versionless candidate never
// replaces, and otherwise the higher version wins (lexical
// fallback when segments are not comparable). Equal
// versions keep the current file, so the platform
// directory — scanned first — wins ties.
func pluginFilePreferred(candidate, current File) bool {
	if candidate.Version == "" {
		return false
	}
	if current.Version == "" {
		return true
	}
	comparison, comparable := comparePluginVersions(candidate.Version, current.Version)
	if !comparable {
		return candidate.Version > current.Version
	}
	return comparison > 0
}

func validPluginID(id string) bool { return pluginIDPattern.MatchString(id) }

func validPluginVersion(version string) bool {
	return version != "" && !strings.HasPrefix(version, "v") && pluginVersionPattern.MatchString(version)
}

func candidateDirs(root, goos, goarch string) []string {
	return []string{filepath.Join(root, goos, goarch), root}
}

// Discover returns the plugin binaries selected by the host
// discovery rules under root, sorted by ID.
func Discover(root string) ([]File, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("plugin discovery root must not be empty")
	}
	if info, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("plugin discovery root %q: %w", root, err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("plugin discovery root %q is not a directory", root)
	}
	if err := refuseSymlinkedComponents(root); err != nil {
		return nil, err
	}
	ext := PluginExtension(runtime.GOOS)
	selected := make(map[string]File)
	for _, dir := range candidateDirs(root, runtime.GOOS, runtime.GOARCH) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, entry := range entries {
			if entry == nil || entry.IsDir() {
				continue
			}
			if info, err := entry.Info(); err != nil || info.Mode()&os.ModeSymlink != 0 {
				// Symlink entries are refused at
				// discovery; load-time refusal is
				// the backstop. An Info error
				// skips the entry rather than
				// failing the directory.
				continue
			}
			file, ok := fileFromPath(filepath.Join(dir, entry.Name()), ext)
			if !ok {
				continue
			}
			if current, taken := selected[file.ID]; !taken {
				selected[file.ID] = file
			} else if pluginFilePreferred(file, current) {
				selected[file.ID] = file
			}
		}
	}
	out := make([]File, 0, len(selected))
	for _, f := range selected {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
