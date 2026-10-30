// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"testing"
)

// TestDecodeRecord is the single test of the NDJSON trailing-data
// rule: decodeRecord is the one decoder for the package, and the
// rule (exactly one JSON object, nothing after it) is pinned
// here, not duplicated in FeedRecord/Runner tests.
func TestDecodeRecord(t *testing.T) {
	ev := decodeRecord([]byte(`{"event":"task.status","seq":120,"payload":{"status":"running"}}`))
	if ev == nil || ev["event"] != "task.status" {
		t.Fatalf("valid record = %v", ev)
	}
	if n, ok := ev["seq"].(interface{ String() string }); !ok || n.String() != "120" {
		t.Errorf("seq must decode as json.Number 120, got %T %v", ev["seq"], ev["seq"])
	}
	cases := []struct {
		name string
		rec  string
	}{
		{"empty", ""},
		{"whitespace", "  \n "},
		{"invalid json", `{"status": "completed"`},
		{"non-object", `42`},
		{"trailing data", `{"event":"task.status"} {"x":1}`},
		{"trailing garbage", `{"event":"task.status"} junk`},
		{"array", `[1,2]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decodeRecord([]byte(tc.rec)); got != nil {
				t.Errorf("decodeRecord(%q) = %v, want nil", tc.rec, got)
			}
		})
	}
	// Leading/trailing whitespace around one object is fine.
	if ev := decodeRecord([]byte("  {\"event\":\"x\"}  \n")); ev == nil || ev["event"] != "x" {
		t.Errorf("padded record = %v", ev)
	}
}
