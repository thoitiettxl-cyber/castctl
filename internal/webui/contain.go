// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"os"
	"path/filepath"
	"strings"
)

// Symlink-aware path containment for the web UI seams.
//
// A lexical check alone is not containment: a path can escape
// the config dir through a symlinked component followed by
// "..", or reach a refused file through a symlink, while its
// cleaned lexical form stays inside. resolveAgainst therefore
// walks components one at a time, resolving each existing
// prefix with EvalSymlinks and letting ".." pop the RESOLVED
// prefix (kernel semantics). resolvePathBestEffort resolves
// as much of a possibly-nonexistent path as exists. Both are
// re-run per request: no verdict is cached across renames.

// resolvePathBestEffort resolves symlinks in path as far as
// possible: EvalSymlinks on the full path, else on the nearest
// existing ancestor, rejoining the remainder. It never fails;
// the lexical Clean fallback keeps comparisons working for
// paths that do not exist yet (a .bak the next write has not
// created).
func resolvePathBestEffort(path string) string {
	clean := filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		return resolved
	}
	var tail []string
	cur := clean
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return clean
		}
		if resolved, err := filepath.EvalSymlinks(parent); err == nil {
			return filepath.Join(append([]string{resolved, filepath.Base(cur)}, tail...)...)
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		cur = parent
	}
}

func splitPathComponents(p string) []string {
	p = strings.TrimPrefix(p, string(filepath.Separator))
	if p == "" {
		return nil
	}
	return strings.Split(p, string(filepath.Separator))
}

func joinPathComponents(parts []string) string {
	if len(parts) == 0 {
		return string(filepath.Separator)
	}
	return string(filepath.Separator) + filepath.Join(parts...)
}

// resolveAgainst resolves candidate against baseDir,
// component by component, resolving each existing prefix and
// letting ".." pop the resolved prefix. Absolute candidates
// ignore baseDir. The result is absolute and symlink-resolved
// as far as the filesystem allows.
func resolveAgainst(baseDir, candidate string) string {
	var parts []string
	if !filepath.IsAbs(candidate) {
		parts = splitPathComponents(resolvePathBestEffort(baseDir))
	}
	for _, comp := range strings.Split(filepath.ToSlash(candidate), "/") {
		switch comp {
		case "", ".":
		case "..":
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
		default:
			parts = append(parts, comp)
			if resolved, err := filepath.EvalSymlinks(joinPathComponents(parts)); err == nil {
				parts = splitPathComponents(resolved)
			}
		}
	}
	return joinPathComponents(parts)
}

// pathWithin reports whether resolved is equal to or under
// dir. Both arguments must already be resolved (see
// resolveAgainst / resolvePathBestEffort).
func pathWithin(resolved, dir string) bool {
	rel, err := filepath.Rel(dir, resolved)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// containedInDir reports whether candidate, resolved against
// baseDir with symlink evaluation, stays inside baseDir.
func containedInDir(baseDir, candidate string) bool {
	return pathWithin(resolveAgainst(baseDir, candidate), resolvePathBestEffort(baseDir))
}

// rejectNewCookiesFile enforces the web UI containment rule
// for a cookies_file value the web UI is about to introduce
// (profile-create, PUT /config): absolute values are rejected
// outright, and relative values must resolve inside the config
// dir. Values already stored unchanged are not re-checked
// here: saveGuarded compares against the stored document and
// only checks new or changed values, so a CLI-created absolute
// in-dir path keeps round-tripping and can only be replaced by
// an in-dir relative value. CLI resolveCookiesFile is
// untouched; general CLI containment is a backlog follow-up,
// not this change. The error message never echoes the value.
func rejectNewCookiesFile(configDir, value string) error {
	if filepath.IsAbs(value) {
		return errValidation("cookies_file must be a relative path inside the config directory")
	}
	if !containedInDir(configDir, value) {
		return errValidation("cookies_file must stay inside the config directory")
	}
	return nil
}

// webUIUIDirValue extracts the `webui.ui_dir` string from a
// decoded config document. A missing block, a missing key, or a
// non-string value is absent from the result (the config parser
// rejects non-string values separately).
func webUIUIDirValue(doc any) (string, bool) {
	root, ok := doc.(map[string]any)
	if !ok {
		return "", false
	}
	block, ok := root["webui"].(map[string]any)
	if !ok {
		return "", false
	}
	v, ok := block["ui_dir"].(string)
	if !ok {
		return "", false
	}
	return v, true
}

// rejectNewUIDir enforces the B-1 containment rule for a
// `ui_dir` value the web UI is about to introduce: the
// symlink-resolved root must not overlap the config directory
// in either direction, and must not contain any cookies file
// named in the document. A symlinked index.html inside the
// root is refused too (any symlink, even one whose target
// stays inside the root: the shell path must only ever serve
// the file startup validated). A missing index.html is not
// refused here — the startup checks reject a root without
// one. The error messages name the rule only, never the value.
func rejectNewUIDir(configDir, value string, cookiesFiles map[string]string) error {
	root := resolveAgainst(configDir, value)
	base := resolvePathBestEffort(configDir)
	if pathWithin(root, base) || pathWithin(base, root) {
		return errValidation("webui.ui_dir must not overlap the config directory")
	}
	for _, cookiesFile := range cookiesFiles {
		if pathWithin(resolveAgainst(configDir, cookiesFile), root) {
			return errValidation("webui.ui_dir must not contain a cookies file")
		}
	}
	if lst, err := os.Lstat(filepath.Join(root, "index.html")); err == nil && lst.Mode()&os.ModeSymlink != 0 {
		return errValidation("webui.ui_dir index.html must not be a symlink")
	}
	return nil
}

// profileCookiesFiles extracts each profile's cookies_file
// string from a decoded config document. Non-string or missing
// values are absent from the result (the config parser rejects
// them separately).
func profileCookiesFiles(doc any) map[string]string {
	out := map[string]string{}
	root, ok := doc.(map[string]any)
	if !ok {
		return out
	}
	profiles, ok := root["profiles"].(map[string]any)
	if !ok {
		return out
	}
	for name, raw := range profiles {
		p, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if v, ok := p["cookies_file"].(string); ok {
			out[name] = v
		}
	}
	return out
}
