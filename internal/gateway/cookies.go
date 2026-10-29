// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// LoadCookies reads a cookies file and returns the Cookie header
// value, ported from gateway.py load_cookies. Three forms are
// accepted: a JSON object ({"cookies": {...}} or a flat dict), a
// one-line 'a=b; c=d' form containing hatch_sess= or datr=, or a
// Netscape cookie jar (tab-separated, name/value in columns 6/7).
// An unparseable file returns *conn.AuthError; a missing file
// returns the I/O error unwrapped (Python raises FileNotFoundError
// there, not AuthError). The returned value is secret material: it
// must only ever go into a Cookie header, never into an error or a
// log line.
func LoadCookies(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("gateway: read cookies file: %w", err)
	}
	return ParseCookies(string(raw), path)
}

// ParseCookies parses already-read cookies file contents. It is
// exported so tests and wiring code can parse without a file.
func ParseCookies(raw, path string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "{") {
		dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
		dec.UseNumber()
		var d map[string]any
		if err := dec.Decode(&d); err == nil {
			if cookies, ok := d["cookies"]; ok {
				if cm, ok := cookies.(map[string]any); ok {
					return joinCookiePairs(cm), nil
				}
			}
			return joinCookiePairs(d), nil
		}
		// A "{" file that is not JSON falls through to the
		// line-based forms below, as in Python (JSONDecodeError
		// is caught there). A JSON value that decoded to a
		// non-object cannot happen here: Decode into a map fails
		// for arrays/scalars, so it falls through too, and the
		// jar parse below reports AuthError. (Python raises
		// AttributeError in that corner; see doc.go.)
	}
	if strings.Contains(raw, "hatch_sess=") || strings.Contains(raw, "datr=") {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && strings.Contains(line, "=") && strings.Contains(line, ";") {
				return line, nil
			}
		}
		return strings.Join(strings.Fields(raw), " "), nil
	}
	var parts []string
	for _, line := range strings.Split(raw, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) >= 7 {
			parts = append(parts, cols[5]+"="+cols[6])
		}
	}
	if len(parts) == 0 {
		return "", conn.NewAuthError(fmt.Sprintf("could not parse cookies file %s", path))
	}
	return strings.Join(parts, "; "), nil
}

func joinCookiePairs(m map[string]any) string {
	// Python iterates dict order (insertion order); Go map
	// iteration is random. Cookie order is not semantically
	// significant to the server, and JSON object key order is not
	// preserved by encoding/json either. Keep the join simple.
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+cookieValueString(v))
	}
	return strings.Join(parts, "; ")
}

func cookieValueString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}
