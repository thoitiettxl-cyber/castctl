// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! History-event resource shaping, ported from Go
//! `internal/shared/resources.go` and `values.go` (M1, pure logic),
//! plus the read-command shapes (M4b): `status`, `usage`,
//! `sessions` (`threads`), `event` (`history`), `feed`
//! (`feed`/`goals`/`ideas`).

pub mod bridge;
pub mod event;
pub mod feed;
pub mod lenient_json;
pub mod resources;
pub mod sessions;
pub mod status;
pub mod timefmt;
pub mod usage;
pub mod value;

pub use bridge::from_serde;
pub use event::{EventRow, clean_text, event_row_to_json, fmt_event};
pub use feed::{
    FeedRow, GoalRow, IdeaRow, feed_row_to_json, feed_rows, goal_row_to_json, goal_rows,
    idea_row_to_json, idea_rows,
};
pub use lenient_json::{
    FirstError, Kind, LenientError, Parsed, apply_bool_field, apply_i64_field, apply_raw_field,
    apply_str_field, go_fold_name,
};
pub use resources::{FileRow, Resource, event_resources, file_row_to_json, file_rows, local_name};
pub use sessions::{SessionRow, session_row_to_json, session_rows};
pub use status::{StatusSummary, status_summary_to_json, summarize_status};
pub use timefmt::{format_resets_at, format_updated_at_ms, local_abbr_now};
pub use usage::{
    BonusTokens, UsageSummary, bonus_tokens_to_json, human_tokens, parse_tokens_left,
    summarize_usage, usage_lines, usage_summary_to_json,
};
pub use value::JsonValue;
