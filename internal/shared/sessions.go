// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

import "time"

// SessionRow is one row of the `threads` command output, ported
// from cli.py:739-748 (session_rows). Field order is the Python
// dict order: session_id, title, thread, pinned, archived, updated.
type SessionRow struct {
	// SessionID is the session's id, or nil when absent.
	SessionID *string `json:"session_id"`
	// Title is the session's title, or nil when absent.
	Title *string `json:"title"`
	// Thread reports the session's is_thread flag, or nil when absent.
	Thread *bool `json:"thread"`
	// Pinned reports the session's pinned flag, or nil when absent.
	Pinned *bool `json:"pinned"`
	// Archived reports the session's archived flag, or nil when absent.
	Archived *bool `json:"archived"`
	// Updated is the session's updated_at_ms rendered as
	// "%Y-%m-%d %H:%M" in loc (Python: time.strftime with
	// time.localtime). A missing updated_at_ms renders the local
	// epoch, exactly as Python's .get("updated_at_ms", 0) does.
	Updated string `json:"updated"`
}

// SessionRows converts a sessions.list result into the rows
// `threads` prints, ported verbatim from cli.py:739-748
// (session_rows). Archived rows are dropped unless
// includeArchived is true. loc is the timezone for the updated
// rendering; nil means time.Local.
func SessionRows(d map[string]any, includeArchived bool, loc *time.Location) []SessionRow {
	if loc == nil {
		loc = time.Local
	}
	sessions, _ := asList(d["sessions"])
	rows := make([]SessionRow, 0, len(sessions))
	for _, s := range sessions {
		m, ok := asMap(s)
		if !ok {
			continue
		}
		row := SessionRow{
			SessionID: stringPtrField(m, "session_id"),
			Title:     stringPtrField(m, "title"),
			Thread:    boolPtrField(m, "is_thread"),
			Pinned:    boolPtrField(m, "pinned"),
			Archived:  boolPtrField(m, "archived"),
			Updated:   formatUpdatedAt(intField(m, "updated_at_ms", 0), loc),
		}
		if !includeArchived && row.Archived != nil && *row.Archived {
			continue
		}
		rows = append(rows, row)
	}
	return rows
}

// formatUpdatedAt renders epoch milliseconds as "%Y-%m-%d %H:%M"
// in loc, mirroring time.strftime("%Y-%m-%d %H:%M",
// time.localtime(ms/1000)).
func formatUpdatedAt(ms int64, loc *time.Location) string {
	return time.UnixMilli(ms).In(loc).Format("2006-01-02 15:04")
}
