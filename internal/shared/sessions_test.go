// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// ict returns a +07:00 zone for tests: Asia/Ho_Chi_Minh when the
// system zoneinfo has it, else an equivalent fixed zone (Vietnam
// has no DST, so the wall clock is identical either way).
func ict(t *testing.T) *time.Location {
	t.Helper()
	if loc, err := time.LoadLocation("Asia/Ho_Chi_Minh"); err == nil {
		return loc
	}
	return time.FixedZone("ICT", 7*3600)
}

func TestSessionRows(t *testing.T) {
	t.Parallel()
	loc := ict(t)
	d := map[string]any{"sessions": []any{
		map[string]any{"session_id": "s1", "title": "Main", "is_thread": false,
			"pinned": true, "archived": false, "updated_at_ms": int64(1792821457000)},
		map[string]any{"session_id": "s2", "title": "Old", "is_thread": true,
			"pinned": false, "archived": true, "updated_at_ms": int64(0)},
		map[string]any{"session_id": "s3", "title": "No stamp", "is_thread": false,
			"pinned": false, "archived": false},
	}}
	rows := SessionRows(d, false, loc)
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2 (archived dropped)", len(rows))
	}
	want0 := SessionRow{SessionID: strPtr("s1"), Title: strPtr("Main"),
		Thread: boolPtr(false), Pinned: boolPtr(true), Archived: boolPtr(false),
		Updated: "2026-10-24 12:57"}
	if !reflect.DeepEqual(rows[0], want0) {
		t.Errorf("rows[0] = %+v, want %+v", rows[0], want0)
	}
	if rows[1].Updated != epochIn(loc) {
		t.Errorf("rows[1].Updated = %q, want the local epoch (missing stamp -> 0)", rows[1].Updated)
	}
	all := SessionRows(d, true, loc)
	if len(all) != 3 {
		t.Fatalf("len(all) = %d, want 3 with archived", len(all))
	}
	if all[1].Updated != epochIn(loc) {
		t.Errorf("archived row updated = %q, want the local epoch", all[1].Updated)
	}
}

// epochIn renders the epoch in loc. It is computed, not hardcoded:
// Asia/Ho_Chi_Minh was +08:00 at the epoch (pre-1975 offset), so a
// hardcoded "1970-01-01 07:00" would be wrong under the real
// zoneinfo while a fixed +07 zone would render 07:00. The pin that
// matters is missing-stamp -> epoch, not the historical offset.
func epochIn(loc *time.Location) string {
	return time.UnixMilli(0).In(loc).Format("2006-01-02 15:04")
}

func boolPtr(b bool) *bool { return &b }

func TestSessionRowsNumberForms(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("UTC", 0)
	d := map[string]any{"sessions": []any{
		map[string]any{"session_id": "s1", "updated_at_ms": json.Number("1792821457000")},
	}}
	rows := SessionRows(d, false, loc)
	if len(rows) != 1 || rows[0].Updated != "2026-10-24 05:57" {
		t.Errorf("rows = %+v, want updated 2026-10-24 05:57 UTC", rows)
	}
	if got := SessionRows(map[string]any{}, false, loc); len(got) != 0 {
		t.Errorf("SessionRows(empty) = %+v, want empty", got)
	}
}
