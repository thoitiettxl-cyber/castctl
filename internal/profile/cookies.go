// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"encoding/json"
	"os"
	"strings"
)

// ParseCookies parses a cookies file in the three forms accepted by
// Python's load_cookies (gateway.py:170-198), in the same order:
//
//  1. JSON: {"cookies": {...}} or a flat dict; entries joined as
//     "k=v" in file order.
//  2. A single-line "a=b; c=d" form: any line containing "hatch_sess="
//     or "datr=" is scanned for the first non-comment line containing
//     both "=" and ";"; if none, the whitespace-joined whole file is
//     returned.
//  3. Netscape cookie-jar format: tab-separated lines, columns 6/7 are
//     name/value.
//
// Anything else is an AuthError-class error. A JSON object that fails
// to decode falls through to forms 2 and 3, exactly as in Python
// (only json.JSONDecodeError is caught there).
func ParseCookies(data []byte) (string, error) {
	raw := strings.TrimSpace(string(data))
	if strings.HasPrefix(raw, "{") {
		if v, err := decodeOrderedJSON([]byte(raw)); err == nil {
			if obj, ok := v.(*orderedObject); ok {
				if cookiesVal, ok := obj.get("cookies"); ok {
					if cookiesObj, ok := cookiesVal.(*orderedObject); ok {
						return joinCookieEntries(cookiesObj), nil
					}
				}
				return joinCookieEntries(obj), nil
			}
		}
		// Decode failed or top level was not an object: fall through.
	}
	if strings.Contains(raw, "hatch_sess=") || strings.Contains(raw, "datr=") {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") &&
				strings.Contains(line, "=") && strings.Contains(line, ";") {
				return line, nil
			}
		}
		return strings.Join(strings.Fields(raw), " "), nil
	}
	var parts []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) >= 7 {
			parts = append(parts, cols[5]+"="+cols[6])
		}
	}
	if len(parts) == 0 {
		return "", newAuthError("could not parse cookies file")
	}
	return strings.Join(parts, "; "), nil
}

func joinCookieEntries(obj *orderedObject) string {
	parts := make([]string, 0, len(obj.keys))
	for _, k := range obj.keys {
		parts = append(parts, k+"="+cookieValueString(obj.values[k]))
	}
	return strings.Join(parts, "; ")
}

// cookieValueString renders a JSON value the way Python's f"{k}={v}"
// does for the scalar cases that occur in cookie files. Non-scalar
// values render as compact JSON.
func cookieValueString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "True"
		}
		return "False"
	case nil:
		return "None"
	default:
		raw, err := encodeOrderedJSON(v)
		if err != nil {
			return ""
		}
		return string(raw)
	}
}

// LoadCookiesFile reads and parses the cookies file at path.
func LoadCookiesFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", newAuthError("cannot read cookies file: " + err.Error())
	}
	cookies, err := ParseCookies(data)
	if err != nil {
		return "", err
	}
	return cookies, nil
}
