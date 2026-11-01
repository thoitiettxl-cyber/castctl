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
	"strings"
)

// Discovery (mirroring CLIProxyAPI
// internal/pluginhost/platform.go at pin 250d5981: candidateDirs
// :308, DiscoverPluginFiles :292, PluginExtension :99,
// pluginFileFromPath :62, ID regex :35, version rule :38-41).
//
// A plugin binary is named <id>[-v<version>]<ext> and is looked
// up in <root>/<goos>/<goarch> first, then in <root>. The
// platform directory wins for an ID present in both. Files
// whose names do not parse are skipped silently: discovery
// never fails a whole directory over one stray file. The root
// itself must exist; a missing root is an error so a
// misconfigured plugins directory fails closed instead of
// silently loading nothing.

var pluginIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var pluginVersionPattern = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]*$`)

// File is one discovered plugin binary.
type File struct {
	ID      string
	Path    string
	Version string
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
		if validPluginID(candidateID) && validPluginVersion(candidateVersion) {
			id = candidateID
			version = candidateVersion
		}
	}
	if !validPluginID(id) {
		return File{}, false
	}
	return File{ID: id, Path: path, Version: version}, true
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
			file, ok := fileFromPath(filepath.Join(dir, entry.Name()), ext)
			if !ok {
				continue
			}
			if _, taken := selected[file.ID]; !taken {
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
