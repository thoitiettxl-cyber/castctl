// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

import (
	"reflect"
	"testing"
)

func TestFeedRows(t *testing.T) {
	t.Parallel()
	d := map[string]any{"days": []any{
		map[string]any{"local_date": "2026-10-29", "editions": []any{
			map[string]any{"kind": "morning", "units": []any{
				map[string]any{"unit_id": "u1", "title": "First"},
				map[string]any{"unit_id": "u2", "title": "Second"},
			}},
			map[string]any{"kind": "evening", "units": []any{
				map[string]any{"unit_id": "u3", "title": "Third"},
			}},
		}},
		map[string]any{"local_date": "2026-10-28", "editions": []any{
			map[string]any{"kind": "morning", "units": []any{
				map[string]any{"unit_id": "u4", "title": "Fourth"},
			}},
		}},
	}}
	want := []FeedRow{
		{ID: strPtr("u1"), Title: strPtr("First"), Date: strPtr("2026-10-29"), Edition: strPtr("morning")},
		{ID: strPtr("u2"), Title: strPtr("Second"), Date: strPtr("2026-10-29"), Edition: strPtr("morning")},
		{ID: strPtr("u3"), Title: strPtr("Third"), Date: strPtr("2026-10-29"), Edition: strPtr("evening")},
		{ID: strPtr("u4"), Title: strPtr("Fourth"), Date: strPtr("2026-10-28"), Edition: strPtr("morning")},
	}
	if got := FeedRows(d, 0); !reflect.DeepEqual(got, want) {
		t.Errorf("FeedRows(limit 0) = %+v, want %+v", got, want)
	}
	if got := FeedRows(d, -1); !reflect.DeepEqual(got, want[:len(want)-1]) {
		t.Errorf("FeedRows(limit -1) = %+v, want all but the last row (Python rows[:-1])", got)
	}
	if got := FeedRows(d, -99); len(got) != 0 {
		t.Errorf("FeedRows(limit -99) = %+v, want empty (Python rows[:-99])", got)
	}
	if got := FeedRows(d, 2); !reflect.DeepEqual(got, want[:2]) {
		t.Errorf("FeedRows(limit 2) = %+v, want first 2", got)
	}
	if got := FeedRows(d, 99); !reflect.DeepEqual(got, want) {
		t.Errorf("FeedRows(limit 99) = %+v, want all rows", got)
	}
	if got := FeedRows(map[string]any{}, 0); len(got) != 0 {
		t.Errorf("FeedRows(empty) = %+v, want empty", got)
	}
}

func TestGoalRows(t *testing.T) {
	t.Parallel()
	d := map[string]any{"goals": []any{
		map[string]any{"id": "g1", "title": "Run", "status": "active", "subtitle": "daily"},
		map[string]any{"goal_id": "g2", "title": "Read", "status": "done"},
		map[string]any{"id": "", "goal_id": "g3", "title": "Empty id falls through"},
	}}
	want := []GoalRow{
		{ID: strPtr("g1"), Title: strPtr("Run"), Status: strPtr("active"), Subtitle: strPtr("daily")},
		{ID: strPtr("g2"), Title: strPtr("Read"), Status: strPtr("done")},
		{ID: strPtr("g3"), Title: strPtr("Empty id falls through")},
	}
	if got := GoalRows(d); !reflect.DeepEqual(got, want) {
		t.Errorf("GoalRows = %+v, want %+v", got, want)
	}
}

func TestIdeaRows(t *testing.T) {
	t.Parallel()
	d := map[string]any{"sections": []any{
		map[string]any{"title": "Build", "cards": []any{
			map[string]any{"id": "c1", "title": "App"},
			map[string]any{"ideaCardId": "c2", "title": "Tool"},
		}},
		map[string]any{"title": "Learn", "ideas": []any{
			map[string]any{"id": "c3", "title": "Go"},
		}},
	}}
	want := []IdeaRow{
		{ID: strPtr("c1"), Title: strPtr("App"), Section: strPtr("Build")},
		{ID: strPtr("c2"), Title: strPtr("Tool"), Section: strPtr("Build")},
		{ID: strPtr("c3"), Title: strPtr("Go"), Section: strPtr("Learn")},
	}
	if got := IdeaRows(d); !reflect.DeepEqual(got, want) {
		t.Errorf("IdeaRows = %+v, want %+v", got, want)
	}
}

func TestSummarizeStatus(t *testing.T) {
	t.Parallel()
	s := SummarizeStatus("vm-1",
		map[string]any{"sessions": []any{map[string]any{}, map[string]any{}}},
		int64(3), map[string]any{"name": "Boss"})
	if s.VMID != "vm-1" || s.Sessions != 2 {
		t.Errorf("SummarizeStatus = %+v, want vm-1 / 2 sessions", s)
	}
	if s.Unread != int64(3) {
		t.Errorf("unread = %v, want passthrough 3", s.Unread)
	}
	empty := SummarizeStatus("vm-1", map[string]any{}, nil, nil)
	if empty.Sessions != 0 || empty.Unread != nil || empty.Identity != nil {
		t.Errorf("SummarizeStatus(empty) = %+v", empty)
	}
}
