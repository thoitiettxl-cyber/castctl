// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

// FeedRow is one row of the `feed` command output, ported from
// cli.py:1950-1958 (feed_rows): a unit's id and title, its day's
// local date, and its edition's kind.
type FeedRow struct {
	ID      *string `json:"id"`
	Title   *string `json:"title"`
	Date    *string `json:"date"`
	Edition *string `json:"edition"`
}

// FeedRows flattens a feed.list result (days -> editions -> units)
// into rows, ported from cli.py:1950-1958 (feed_rows).
// limit follows Python's `rows[:limit] if limit else rows`
// exactly: 0 (falsy) means no cap; a positive limit keeps the
// first N rows; a NEGATIVE limit is truthy in Python, so the
// slice applies and drops that many trailing rows (rows[:-1]
// drops the last row; a negative limit at least as large as the
// row count yields no rows). The `feed` command sends the same
// limit value as the feed.list query whenever it is non-zero
// (limit != 0), so the query and the local slice agree on
// negative limits too.
func FeedRows(d map[string]any, limit int) []FeedRow {
	var rows []FeedRow
	days, _ := asList(d["days"])
	for _, day := range days {
		dayMap, ok := asMap(day)
		if !ok {
			continue
		}
		editions, _ := asList(dayMap["editions"])
		for _, ed := range editions {
			edMap, ok := asMap(ed)
			if !ok {
				continue
			}
			units, _ := asList(edMap["units"])
			for _, u := range units {
				unit, ok := asMap(u)
				if !ok {
					continue
				}
				rows = append(rows, FeedRow{
					ID:      stringPtrField(unit, "unit_id"),
					Title:   stringPtrField(unit, "title"),
					Date:    stringPtrField(dayMap, "local_date"),
					Edition: stringPtrField(edMap, "kind"),
				})
			}
		}
	}
	if limit == 0 {
		return rows
	}
	if limit > 0 {
		if len(rows) > limit {
			rows = rows[:limit]
		}
		return rows
	}
	// Negative limit: Python slice semantics (rows[:limit]).
	if keep := len(rows) + limit; keep <= 0 {
		return rows[:0]
	} else {
		return rows[:keep]
	}
}

// GoalRow is one row of the `goals` command output, ported from
// cli.py:1961-1964 (goal_rows).
type GoalRow struct {
	ID       *string `json:"id"`
	Title    *string `json:"title"`
	Status   *string `json:"status"`
	Subtitle *string `json:"subtitle"`
}

// GoalRows converts a goals.list result into rows, ported verbatim
// from cli.py:1961-1964 (goal_rows). A goal's id falls back to
// goal_id, with Python's `or` semantics: an empty id falls through
// to goal_id.
func GoalRows(d map[string]any) []GoalRow {
	goals, _ := asList(d["goals"])
	rows := make([]GoalRow, 0, len(goals))
	for _, g := range goals {
		m, ok := asMap(g)
		if !ok {
			continue
		}
		rows = append(rows, GoalRow{
			ID:       firstStringPtr(m["id"], m["goal_id"]),
			Title:    stringPtrField(m, "title"),
			Status:   stringPtrField(m, "status"),
			Subtitle: stringPtrField(m, "subtitle"),
		})
	}
	return rows
}

// IdeaRow is one row of the `ideas` command output, ported from
// cli.py:1967-1973 (idea_rows): a card's id and title plus the
// title of the section that holds it.
type IdeaRow struct {
	ID      *string `json:"id"`
	Title   *string `json:"title"`
	Section *string `json:"section"`
}

// IdeaRows converts an idea-cards list result (sections -> cards)
// into rows, ported verbatim from cli.py:1967-1973 (idea_rows). A
// section's cards fall back to its "ideas" list, and a card's id
// falls back to ideaCardId, both with Python's `or` semantics.
func IdeaRows(d map[string]any) []IdeaRow {
	var rows []IdeaRow
	sections, _ := asList(d["sections"])
	for _, s := range sections {
		section, ok := asMap(s)
		if !ok {
			continue
		}
		cards, ok := asList(section["cards"])
		if !ok {
			cards, _ = asList(section["ideas"])
		}
		for _, c := range cards {
			card, ok := asMap(c)
			if !ok {
				continue
			}
			rows = append(rows, IdeaRow{
				ID:      firstStringPtr(card["id"], card["ideaCardId"]),
				Title:   stringPtrField(card, "title"),
				Section: stringPtrField(section, "title"),
			})
		}
	}
	return rows
}
