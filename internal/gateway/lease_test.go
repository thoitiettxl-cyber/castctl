// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"strings"
	"testing"
)

func TestRedactURL(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		// forbidden substrings that must not survive redaction
		forbidden []string
		// required substrings: the safe shape that must survive
		required []string
	}{
		{
			name:      "userinfo with password is replaced, rest intact",
			raw:       "wss://alice:FAKE-PASSWORD@hatch.metaaivm.com/v1/noise?vm_id=vm-1&auth_token=FAKE-TOKEN",
			forbidden: []string{"alice", "FAKE-PASSWORD", "FAKE-TOKEN"},
			required:  []string{"hatch.metaaivm.com", "/v1/noise", "vm_id="},
		},
		{
			name:      "userinfo without password is replaced",
			raw:       "wss://bob@hatch.metaaivm.com/v1/noise?vm_id=vm-1",
			forbidden: []string{"bob@"},
			required:  []string{"hatch.metaaivm.com", "/v1/noise"},
		},
		{
			name:      "no userinfo keeps query redaction",
			raw:       "wss://hatch.metaaivm.com/v1/noise?vm_id=vm-1&auth_token=FAKE-TOKEN",
			forbidden: []string{"FAKE-TOKEN", "vm-1"},
			required:  []string{"hatch.metaaivm.com", "/v1/noise", "auth_token="},
		},
		{
			name:      "unparseable url",
			raw:       "://bad url",
			forbidden: []string{"bad"},
			required:  []string{"[unparseable url]"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactURL(tc.raw)
			for _, f := range tc.forbidden {
				if strings.Contains(got, f) {
					t.Errorf("redactURL(%q) = %q, contains forbidden %q", tc.raw, got, f)
				}
			}
			for _, r := range tc.required {
				if !strings.Contains(got, r) {
					t.Errorf("redactURL(%q) = %q, missing required %q", tc.raw, got, r)
				}
			}
		})
	}
}
