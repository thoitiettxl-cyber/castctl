// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The `feed`, `goals` and `ideas` command rows.
//!
//! Source: `internal/shared/feed.go` (`FeedRow`/`FeedRows`,
//! `GoalRow`/`GoalRows`, `IdeaRow`/`IdeaRows`, ported from
//! `cli.py:1950-1973`).

use crate::resources::escape_json_string;
use crate::value::{JsonValue, as_list, as_map, first_string_ptr, get_or_null, string_ptr_field};

/// One row of the `feed` command output.
/// Source: `internal/shared/feed.go:10` (`FeedRow`).
/// Field order: id, title, date, edition.
#[derive(Debug, Clone, PartialEq)]
pub struct FeedRow {
    /// A unit's id.
    pub id: Option<String>,
    /// A unit's title.
    pub title: Option<String>,
    /// Its day's local date.
    pub date: Option<String>,
    /// Its edition's kind.
    pub edition: Option<String>,
}

/// One row of the `goals` command output.
/// Source: `internal/shared/feed.go:76` (`GoalRow`).
/// Field order: id, title, status, subtitle.
#[derive(Debug, Clone, PartialEq)]
pub struct GoalRow {
    /// A goal's id.
    pub id: Option<String>,
    /// A goal's title.
    pub title: Option<String>,
    /// A goal's status.
    pub status: Option<String>,
    /// A goal's subtitle.
    pub subtitle: Option<String>,
}

/// One row of the `ideas` command output.
/// Source: `internal/shared/feed.go:108` (`IdeaRow`).
/// Field order: id, title, section.
#[derive(Debug, Clone, PartialEq)]
pub struct IdeaRow {
    /// A card's id.
    pub id: Option<String>,
    /// A card's title.
    pub title: Option<String>,
    /// The title of the section that holds it.
    pub section: Option<String>,
}

/// Flatten a `feed.list` result (days -> editions -> units)
/// into rows. `limit` follows Python's `rows[:limit] if limit
/// else rows` exactly: 0 (falsy) means no cap; a positive
/// limit keeps the first N rows; a NEGATIVE limit is truthy
/// in Python, so the slice applies and drops that many
/// trailing rows.
/// Source: `internal/shared/feed.go:28` (`FeedRows`).
pub fn feed_rows(d: &JsonValue, limit: i64) -> Vec<FeedRow> {
    let mut rows: Vec<FeedRow> = Vec::new();
    let empty: Vec<JsonValue> = Vec::new();
    let days = as_map(d)
        .and_then(|m| m.get("days"))
        .and_then(as_list)
        .unwrap_or(&empty);
    for day in days {
        let Some(day_map) = as_map(day) else {
            continue;
        };
        let editions = day_map.get("editions").and_then(as_list).unwrap_or(&empty);
        for ed in editions {
            let Some(ed_map) = as_map(ed) else {
                continue;
            };
            let units = ed_map.get("units").and_then(as_list).unwrap_or(&empty);
            for u in units {
                let Some(unit) = as_map(u) else {
                    continue;
                };
                rows.push(FeedRow {
                    id: string_ptr_field(unit, "unit_id"),
                    title: string_ptr_field(unit, "title"),
                    date: string_ptr_field(day_map, "local_date"),
                    edition: string_ptr_field(ed_map, "kind"),
                });
            }
        }
    }
    if limit == 0 {
        return rows;
    }
    if limit > 0 {
        rows.truncate(limit as usize);
        return rows;
    }
    // Negative limit: Python rows[:limit].
    let keep = rows.len() as i64 + limit;
    if keep <= 0 {
        rows.clear();
    } else {
        rows.truncate(keep as usize);
    }
    rows
}

/// Convert a `goals.list` result into rows. A goal's id falls
/// back to `goal_id`, with Python's `or` semantics: an empty
/// id falls through to `goal_id`.
/// Source: `internal/shared/feed.go:87` (`GoalRows`).
pub fn goal_rows(d: &JsonValue) -> Vec<GoalRow> {
    let empty: Vec<JsonValue> = Vec::new();
    let goals = as_map(d)
        .and_then(|m| m.get("goals"))
        .and_then(as_list)
        .unwrap_or(&empty);
    let mut rows = Vec::with_capacity(goals.len());
    for g in goals {
        let Some(m) = as_map(g) else {
            continue;
        };
        rows.push(GoalRow {
            id: first_string_ptr(&[get_or_null(m, "id"), get_or_null(m, "goal_id")]),
            title: string_ptr_field(m, "title"),
            status: string_ptr_field(m, "status"),
            subtitle: string_ptr_field(m, "subtitle"),
        });
    }
    rows
}

/// Convert an idea-cards list result (sections -> cards) into
/// rows. A section's cards fall back to its `"ideas"` list,
/// and a card's id falls back to `ideaCardId`, both with
/// Python's `or` semantics.
/// Source: `internal/shared/feed.go:118` (`IdeaRows`).
pub fn idea_rows(d: &JsonValue) -> Vec<IdeaRow> {
    let mut rows: Vec<IdeaRow> = Vec::new();
    let empty: Vec<JsonValue> = Vec::new();
    let sections = as_map(d)
        .and_then(|m| m.get("sections"))
        .and_then(as_list)
        .unwrap_or(&empty);
    for s in sections {
        let Some(section) = as_map(s) else {
            continue;
        };
        // Fall back to "ideas" only when "cards" is not a
        // list at all (Go: `cards, ok := asList(...); if !ok`).
        let cards = match section.get("cards").and_then(as_list) {
            Some(c) => c,
            None => section.get("ideas").and_then(as_list).unwrap_or(&empty),
        };
        for c in cards {
            let Some(card) = as_map(c) else {
                continue;
            };
            rows.push(IdeaRow {
                id: first_string_ptr(&[get_or_null(card, "id"), get_or_null(card, "ideaCardId")]),
                title: string_ptr_field(card, "title"),
                section: string_ptr_field(section, "title"),
            });
        }
    }
    rows
}

fn opt_str_to_json(v: &Option<String>, out: &mut String) {
    match v {
        Some(s) => escape_json_string(s, out, false),
        None => out.push_str("null"),
    }
}

/// Serialize a `FeedRow` exactly as Go's `encoding/json`
/// would with `writeJSON` (indent 2, HTML unescaped):
/// field order `id`, `title`, `date`, `edition`; all fields
/// always emitted (`null` when `None`).
/// Source: `internal/shared/feed.go:10` (struct tags).
pub fn feed_row_to_json(row: &FeedRow) -> String {
    let mut out = String::from("{");
    out.push_str("\"id\":");
    opt_str_to_json(&row.id, &mut out);
    out.push_str(",\"title\":");
    opt_str_to_json(&row.title, &mut out);
    out.push_str(",\"date\":");
    opt_str_to_json(&row.date, &mut out);
    out.push_str(",\"edition\":");
    opt_str_to_json(&row.edition, &mut out);
    out.push('}');
    out
}

/// Serialize a `GoalRow` exactly as Go's `encoding/json`
/// would with `writeJSON` (indent 2, HTML unescaped):
/// field order `id`, `title`, `status`, `subtitle`; all
/// fields always emitted (`null` when `None`).
/// Source: `internal/shared/feed.go:76` (struct tags).
pub fn goal_row_to_json(row: &GoalRow) -> String {
    let mut out = String::from("{");
    out.push_str("\"id\":");
    opt_str_to_json(&row.id, &mut out);
    out.push_str(",\"title\":");
    opt_str_to_json(&row.title, &mut out);
    out.push_str(",\"status\":");
    opt_str_to_json(&row.status, &mut out);
    out.push_str(",\"subtitle\":");
    opt_str_to_json(&row.subtitle, &mut out);
    out.push('}');
    out
}

/// Serialize an `IdeaRow` exactly as Go's `encoding/json`
/// would with `writeJSON` (indent 2, HTML unescaped):
/// field order `id`, `title`, `section`; all fields always
/// emitted (`null` when `None`).
/// Source: `internal/shared/feed.go:108` (struct tags).
pub fn idea_row_to_json(row: &IdeaRow) -> String {
    let mut out = String::from("{");
    out.push_str("\"id\":");
    opt_str_to_json(&row.id, &mut out);
    out.push_str(",\"title\":");
    opt_str_to_json(&row.title, &mut out);
    out.push_str(",\"section\":");
    opt_str_to_json(&row.section, &mut out);
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::JsonValue;
    use std::collections::BTreeMap;

    fn s(v: &str) -> JsonValue {
        JsonValue::Str(v.to_string())
    }

    fn obj(pairs: &[(&str, JsonValue)]) -> JsonValue {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), v.clone());
        }
        JsonValue::Object(m)
    }

    fn arr(items: &[JsonValue]) -> JsonValue {
        JsonValue::Array(items.to_vec())
    }

    fn feed_fixture() -> JsonValue {
        obj(&[(
            "days",
            arr(&[
                obj(&[
                    ("local_date", s("2026-10-29")),
                    (
                        "editions",
                        arr(&[
                            obj(&[
                                ("kind", s("morning")),
                                (
                                    "units",
                                    arr(&[
                                        obj(&[("unit_id", s("u1")), ("title", s("First"))]),
                                        obj(&[("unit_id", s("u2")), ("title", s("Second"))]),
                                    ]),
                                ),
                            ]),
                            obj(&[
                                ("kind", s("evening")),
                                (
                                    "units",
                                    arr(&[obj(&[("unit_id", s("u3")), ("title", s("Third"))])]),
                                ),
                            ]),
                        ]),
                    ),
                ]),
                obj(&[
                    ("local_date", s("2026-10-28")),
                    (
                        "editions",
                        arr(&[obj(&[
                            ("kind", s("morning")),
                            (
                                "units",
                                arr(&[obj(&[("unit_id", s("u4")), ("title", s("Fourth"))])]),
                            ),
                        ])]),
                    ),
                ]),
            ]),
        )])
    }

    // Ported from internal/shared/feed_test.go TestFeedRows.
    #[test]
    fn feed_rows_limit_follows_python_slice() {
        let want = vec![
            FeedRow {
                id: Some("u1".to_string()),
                title: Some("First".to_string()),
                date: Some("2026-10-29".to_string()),
                edition: Some("morning".to_string()),
            },
            FeedRow {
                id: Some("u2".to_string()),
                title: Some("Second".to_string()),
                date: Some("2026-10-29".to_string()),
                edition: Some("morning".to_string()),
            },
            FeedRow {
                id: Some("u3".to_string()),
                title: Some("Third".to_string()),
                date: Some("2026-10-29".to_string()),
                edition: Some("evening".to_string()),
            },
            FeedRow {
                id: Some("u4".to_string()),
                title: Some("Fourth".to_string()),
                date: Some("2026-10-28".to_string()),
                edition: Some("morning".to_string()),
            },
        ];
        assert_eq!(feed_rows(&feed_fixture(), 0), want);
        assert_eq!(feed_rows(&feed_fixture(), -1), want[..3].to_vec());
        assert_eq!(feed_rows(&feed_fixture(), -99).len(), 0);
        assert_eq!(feed_rows(&feed_fixture(), 2), want[..2].to_vec());
        assert_eq!(feed_rows(&feed_fixture(), 99), want);
        assert_eq!(feed_rows(&obj(&[]), 0).len(), 0);
    }

    // Ported from internal/shared/feed_test.go TestGoalRows.
    #[test]
    fn goal_rows_id_falls_back_to_goal_id() {
        let d = obj(&[(
            "goals",
            arr(&[
                obj(&[
                    ("id", s("g1")),
                    ("title", s("Run")),
                    ("status", s("active")),
                    ("subtitle", s("daily")),
                ]),
                obj(&[
                    ("goal_id", s("g2")),
                    ("title", s("Read")),
                    ("status", s("done")),
                ]),
                obj(&[
                    ("id", s("")),
                    ("goal_id", s("g3")),
                    ("title", s("Empty id falls through")),
                ]),
            ]),
        )]);
        assert_eq!(
            goal_rows(&d),
            vec![
                GoalRow {
                    id: Some("g1".to_string()),
                    title: Some("Run".to_string()),
                    status: Some("active".to_string()),
                    subtitle: Some("daily".to_string()),
                },
                GoalRow {
                    id: Some("g2".to_string()),
                    title: Some("Read".to_string()),
                    status: Some("done".to_string()),
                    subtitle: None,
                },
                GoalRow {
                    id: Some("g3".to_string()),
                    title: Some("Empty id falls through".to_string()),
                    status: None,
                    subtitle: None,
                },
            ]
        );
    }

    // Ported from internal/shared/feed_test.go TestIdeaRows.
    #[test]
    fn idea_rows_cards_fall_back_to_ideas() {
        let d = obj(&[(
            "sections",
            arr(&[
                obj(&[
                    ("title", s("Build")),
                    (
                        "cards",
                        arr(&[
                            obj(&[("id", s("c1")), ("title", s("App"))]),
                            obj(&[("ideaCardId", s("c2")), ("title", s("Tool"))]),
                        ]),
                    ),
                ]),
                obj(&[
                    ("title", s("Learn")),
                    ("ideas", arr(&[obj(&[("id", s("c3")), ("title", s("Go"))])])),
                ]),
            ]),
        )]);
        assert_eq!(
            idea_rows(&d),
            vec![
                IdeaRow {
                    id: Some("c1".to_string()),
                    title: Some("App".to_string()),
                    section: Some("Build".to_string()),
                },
                IdeaRow {
                    id: Some("c2".to_string()),
                    title: Some("Tool".to_string()),
                    section: Some("Build".to_string()),
                },
                IdeaRow {
                    id: Some("c3".to_string()),
                    title: Some("Go".to_string()),
                    section: Some("Learn".to_string()),
                },
            ]
        );
    }

    #[test]
    fn row_json_orders_match_go() {
        assert_eq!(
            feed_row_to_json(&FeedRow {
                id: Some("u1".to_string()),
                title: Some("First".to_string()),
                date: Some("2026-10-29".to_string()),
                edition: Some("morning".to_string()),
            }),
            r#"{"id":"u1","title":"First","date":"2026-10-29","edition":"morning"}"#
        );
        assert_eq!(
            goal_row_to_json(&GoalRow {
                id: Some("g1".to_string()),
                title: Some("Run".to_string()),
                status: Some("active".to_string()),
                subtitle: Some("daily".to_string()),
            }),
            r#"{"id":"g1","title":"Run","status":"active","subtitle":"daily"}"#
        );
        assert_eq!(
            idea_row_to_json(&IdeaRow {
                id: Some("c1".to_string()),
                title: Some("App".to_string()),
                section: Some("Build".to_string()),
            }),
            r#"{"id":"c1","title":"App","section":"Build"}"#
        );
    }
}
