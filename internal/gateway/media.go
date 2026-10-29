// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"fmt"
	"net/url"
	"strings"
)

// quotePython percent-encodes s exactly like Python's
// urllib.parse.quote(s, safe=safe): UTF-8 bytes, unreserved
// A-Za-z0-9_.-~ plus the safe characters stay literal, everything
// else becomes %XX with uppercase hex. url.PathEscape/QueryEscape
// differ (they leave "$&+,/:;=?@" and friends alone), so the
// encoder is written by hand here.
func quotePython(s, safe string) string {
	safeSet := make(map[byte]bool, len(safe))
	for i := 0; i < len(safe); i++ {
		safeSet[safe[i]] = true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '.' || c == '-' || c == '~' || safeSet[c] {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// MediaPath maps a sandbox path, media URL, or resource dict to a
// /media/raw/... path, ported verbatim from gateway.py media_path:
// variants.original is preferred over path/url; a leading
// media/raw/ is stripped once; the remainder is unquoted, ".."
// segments and empty paths are rejected, and the result is
// re-quoted with "/" safe. Bad input returns *ValidationError
// (Python ValueError).
func MediaPath(ref any) (string, error) {
	s, ok := mediaRefString(ref)
	if !ok {
		return "", &ValidationError{Message: "resource has no path or variants.original"}
	}
	rel := s
	if strings.HasPrefix(rel, "sandbox://") {
		rel = rel[len("sandbox://"):]
	} else if strings.HasPrefix(rel, "https://") || strings.HasPrefix(rel, "http://") {
		u, err := url.Parse(rel)
		if err != nil {
			return "", &ValidationError{Message: fmt.Sprintf("bad sandbox path: %q", s)}
		}
		rel = u.EscapedPath()
	}
	rel = strings.TrimLeft(rel, "/")
	rel = strings.TrimPrefix(rel, "media/raw/")
	if unq, err := url.PathUnescape(rel); err == nil {
		rel = unq
	}
	if rel == "" {
		return "", &ValidationError{Message: fmt.Sprintf("bad sandbox path: %q", s)}
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == ".." {
			return "", &ValidationError{Message: fmt.Sprintf("bad sandbox path: %q", s)}
		}
	}
	return "/media/raw/" + quotePython(rel, "/"), nil
}

// mediaRefString extracts the path string from a ref: a string
// itself, or a resource dict (map) whose variants.original wins
// over path, then url.
func mediaRefString(ref any) (string, bool) {
	switch r := ref.(type) {
	case string:
		return r, true
	case map[string]any:
		if v := dictString(r, "variants", "original"); v != "" {
			return v, true
		}
		if v := mapString(r, "path"); v != "" {
			return v, true
		}
		if v := mapString(r, "url"); v != "" {
			return v, true
		}
		return "", false
	case map[string]string:
		if v := r["path"]; v != "" {
			return v, true
		}
		if v := r["url"]; v != "" {
			return v, true
		}
		return "", false
	default:
		return "", false
	}
}

// dictString reads m[outer][inner] as a string when both levels are
// maps with a string value.
func dictString(m map[string]any, outer, inner string) string {
	v, ok := m[outer]
	if !ok {
		return ""
	}
	innerMap, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	return mapString(innerMap, inner)
}

func mapString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
