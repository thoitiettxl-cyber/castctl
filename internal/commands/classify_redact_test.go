// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// classifyError redaction tests: an unredacted server-shaped
// payload reaching the CLI error path must be stripped by the
// strong (SafeString) boundary in classifyError, not merely by
// redact.String — through the plain-error path, the typed
// auth-error JSON path, and the conn.AuthError JSON path. The
// 12 shapes, names, and forms match
// TestSafeStringTwelveServerShapes; shapes 10-12 are the
// derived already-stripped ones named explicitly there. The
// publicKey shape keeps the first-8-chars prefix rule.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

func TestClassifyErrorTwelveShapes(t *testing.T) {
	t.Parallel()
	const (
		colonVal  = "LOGFIX-CLICOLON-2c6e88"
		singleVal = "LOGFIX-CLISINGLE-51bc07"
		basicVal  = "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
		pctVal    = "LOGFIX-CLIPCT-83af10"
		fragVal   = "LOGFIX-CLIFRAG-9d2e41"
		authVal   = "LOGFIX-CLIAUTH-77d4e9"
		secretVal = "LOGFIX-CLISECRET-22d9f0"
		privVal   = "LOGFIX-CLIPRIV-6e19d0"
		pubVal    = "LOGFIX-CLIPUB-4b77c2"
		tokenVal  = "LOGFIX-CLIAT-83af10"
		bearerVal = "LOGFIX-CLIBEARER-1a8f33"
	)
	shapes := []struct {
		name       string
		input      string
		forbidden  []string
		wantPrefix string
	}{
		{"camelCase-privateKey-JSON", `{"privateKey": "` + privVal + `"}`, []string{privVal}, ""},
		{"camelCase-publicKey-JSON", `{"publicKey": "` + pubVal + `"}`, []string{pubVal}, pubVal[:8]},
		{"colon-form", "private_key: " + colonVal, []string{colonVal}, ""},
		{"single-quote-JSON", `{'token': '` + singleVal + `'}`, []string{singleVal}, ""},
		{"authorization-basic", "Authorization: Basic " + basicVal, []string{basicVal}, ""},
		{"percent-encoded-equals-query", "https://example.invalid/cb?auth_token%3D" + pctVal, []string{pctVal}, ""},
		{"bare-fragment", "https://example.invalid/reset#" + fragVal, []string{fragVal}, ""},
		{"bare-auth-equals", "auth=" + authVal, []string{authVal}, ""},
		{"bare-secret-equals", "secret=" + secretVal, []string{secretVal}, ""},
		{"double-quote-JSON-token (derived)", `{"token": "` + tokenVal + `"}`, []string{tokenVal}, ""},
		// Loop 4 (b): the remaining quote combinations, incl.
		// the loop-3 survivor (double key, single value).
		{"json-double-single", `{"token": '` + tokenVal + `'}`, []string{tokenVal}, ""},
		{"json-single-double", `{'token': "` + tokenVal + `"}`, []string{tokenVal}, ""},
		// Loop 4 (c): observation shapes through all 3 paths.
		{"json-unicode-escaped-key", `{"tok\u0065n": "` + tokenVal + `"}`, []string{tokenVal}, ""},
		{"json-numeric-value", `{"token": 987654321}`, []string{"987654321"}, ""},
		{"pct-encoded-key", "%61uth_token=" + tokenVal, []string{tokenVal}, ""},
		{"pct-encoded-key-equals", "%61uth_token%3D" + tokenVal, []string{tokenVal}, ""},
		{"digitless-fragment", "see #LOGFIXCLIFRAG-abcdef", []string{"LOGFIXCLIFRAG-abcdef"}, ""},
		{"bare-keyvalue-token (derived)", "token=" + tokenVal, []string{tokenVal}, ""},
		{"bearer (derived)", "Authorization: Bearer " + bearerVal, []string{bearerVal}, ""},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			// wantPrefix applies to the plain and typed
			// paths only: the AuthError path renders the
			// loop-5 allowlist summary (class + length),
			// which carries no value bytes at all — not
			// even the public-key prefix.
			check := func(label, text string, wantJSON bool, wantPrefix string) {
				t.Helper()
				for _, v := range sh.forbidden {
					if strings.Contains(text, v) {
						t.Errorf("%s classifyError text %q contains fixture value %q", label, text, v)
					}
				}
				if wantPrefix != "" && !strings.Contains(text, wantPrefix) {
					t.Errorf("%s classifyError text %q, want the 8-char public-key prefix %q present", label, text, wantPrefix)
				}
				if wantJSON {
					var decoded map[string]string
					if err := json.Unmarshal([]byte(text), &decoded); err != nil {
						t.Errorf("%s classifyError text %q is not typed JSON: %v", label, text, err)
					}
				}
			}
			// Plain error: exit 1, "castctl: <message>".
			code, text := classifyError(errors.New(sh.input))
			if code != 1 {
				t.Errorf("plain classifyError code = %d, want 1", code)
			}
			check("plain", text, false, sh.wantPrefix)
			// Typed auth error: one JSON line.
			code, text = classifyError(&typedAuthError{Code: 2, Type: "auth_failed", Err: errors.New(sh.input)})
			if code != 2 {
				t.Errorf("typed classifyError code = %d, want 2", code)
			}
			check("typed", text, true, sh.wantPrefix)
			// conn.AuthError: one JSON line, exit 2.
			code, text = classifyError(conn.NewAuthError(sh.input))
			if code != 2 {
				t.Errorf("auth classifyError code = %d, want 2", code)
			}
			check("auth", text, true, "")
		})
	}
}
