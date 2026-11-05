// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Keeper status reads (`internal/keeper/run.go`
//! `ReadStatus` + `Status`, `internal/keeper/state.go`
//! `LoadState` / `SessionState`).
//!
//! `ReadStatus` reads one entry's status from its
//! profile's state file (`session-state.json`). A missing
//! state file is a never-ticked entry, not an error. A
//! corrupt or unknown-version state file is reported
//! distinctly (`StateCorrupt` + `state_corrupt` reason),
//! not an error: the remedy is to delete the state file.
//! It performs no network I/O.
//!
//! Times are stored as UTC RFC3339Nano (Go `time.Time`
//! JSON). The keeper always writes UTC; a stored offset
//! is normalised to UTC on read — the only observable
//! difference is the rendered zone suffix, and no keeper
//! writer emits a non-UTC offset.

use crate::chats::rfc3339_nano;
use crate::validate::KeeperEntry;
use castctl_config::jsonvalue::{JsonValue, OrderedObject, decode_ordered_json};
use chrono::{DateTime, Utc};
use std::path::Path;

/// State file name within a profile directory
/// (`StateFileName`).
pub const STATE_FILE_NAME: &str = "session-state.json";

/// `StateVersion` (v1).
pub const STATE_VERSION: i64 = 1;

/// `StoppedStateCorrupt` reason string.
pub const STOPPED_STATE_CORRUPT: &str = "state_corrupt";

/// `OutcomeNever`: the last-tick outcome of a fresh state.
pub const OUTCOME_NEVER: &str = "never";

/// `keeper.Status`, in Go struct order. Optional fields
/// are omitted when empty (`omitempty`); `last_tick_outcome`
/// has no `omitempty` and always renders.
#[derive(Debug, Clone, Default)]
pub struct KeeperStatus {
    pub tag: String,
    pub profile: String,
    pub logged_out: bool,
    pub keeper_stopped: bool,
    pub keeper_stopped_reason: String,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub last_tick_outcome: String,
    pub earliest_expiry: Option<DateTime<Utc>>,
    pub driving_cookie: String,
    pub driving_expiry: Option<DateTime<Utc>>,
    pub warn_pending: bool,
    pub warn_sent: bool,
    pub next_check_at: Option<DateTime<Utc>>,
    pub state_corrupt: bool,
}

impl KeeperStatus {
    /// Render as Go's `Status` JSON (struct order,
    /// `omitempty` where Go has it).
    pub fn to_json(&self) -> JsonValue {
        let mut obj = OrderedObject::new();
        obj.set("tag", JsonValue::Str(self.tag.clone()));
        obj.set("profile", JsonValue::Str(self.profile.clone()));
        obj.set("logged_out", JsonValue::Bool(self.logged_out));
        obj.set("keeper_stopped", JsonValue::Bool(self.keeper_stopped));
        if !self.keeper_stopped_reason.is_empty() {
            obj.set(
                "keeper_stopped_reason",
                JsonValue::Str(self.keeper_stopped_reason.clone()),
            );
        }
        if let Some(t) = &self.last_checked_at {
            obj.set("last_checked_at", JsonValue::Str(rfc3339_nano(*t)));
        }
        obj.set(
            "last_tick_outcome",
            JsonValue::Str(self.last_tick_outcome.clone()),
        );
        if let Some(t) = &self.earliest_expiry {
            obj.set("earliest_expiry", JsonValue::Str(rfc3339_nano(*t)));
        }
        if !self.driving_cookie.is_empty() {
            obj.set("driving_cookie", JsonValue::Str(self.driving_cookie.clone()));
        }
        if let Some(t) = &self.driving_expiry {
            obj.set("driving_expiry", JsonValue::Str(rfc3339_nano(*t)));
        }
        if self.warn_pending {
            obj.set("warn_pending", JsonValue::Bool(true));
        }
        if self.warn_sent {
            obj.set("warn_sent", JsonValue::Bool(true));
        }
        if let Some(t) = &self.next_check_at {
            obj.set("next_check_at", JsonValue::Str(rfc3339_nano(*t)));
        }
        if self.state_corrupt {
            obj.set("state_corrupt", JsonValue::Bool(true));
        }
        JsonValue::Object(obj)
    }
}

fn parse_time(value: &JsonValue) -> Option<Option<DateTime<Utc>>> {
    match value {
        JsonValue::Null => Some(None),
        JsonValue::Str(s) => {
            let dt = DateTime::parse_from_rfc3339(s).ok()?;
            Some(Some(dt.with_timezone(&Utc)))
        }
        _ => None,
    }
}

fn get_str(obj: &OrderedObject, key: &str) -> Option<String> {
    match obj.get(key) {
        Some(JsonValue::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

fn get_bool(obj: &OrderedObject, key: &str) -> bool {
    matches!(obj.get(key), Some(JsonValue::Bool(true)))
}

fn get_time(obj: &OrderedObject, key: &str) -> Result<Option<DateTime<Utc>>, ()> {
    match obj.get(key) {
        None => Ok(None),
        Some(v) => parse_time(v).ok_or(()),
    }
}

/// `LoadState` outcome: a fresh state, a parsed state, or
/// a corrupt file. I/O errors other than "not found" are
/// hard errors.
enum LoadState {
    Fresh,
    Parsed(KeeperStatusFields),
    Corrupt,
}

#[derive(Debug, Default)]
struct KeeperStatusFields {
    logged_out: bool,
    keeper_stopped: bool,
    keeper_stopped_reason: String,
    last_checked_at: Option<DateTime<Utc>>,
    last_tick_outcome: String,
    earliest_expiry: Option<DateTime<Utc>>,
    driving_cookie: String,
    driving_expiry: Option<DateTime<Utc>>,
    warn_pending: bool,
    warn_sent: bool,
    next_check_at: Option<DateTime<Utc>>,
}

fn load_state(profile_dir: &Path) -> Result<LoadState, String> {
    let path = profile_dir.join(STATE_FILE_NAME);
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(LoadState::Fresh),
        Err(e) => return Err(e.to_string()),
    };
    if data.is_empty() {
        return Ok(LoadState::Fresh);
    }
    let text = String::from_utf8_lossy(&data).into_owned();
    let value = match decode_ordered_json(&text) {
        Ok(v) => v,
        Err(_) => return Ok(LoadState::Corrupt),
    };
    let JsonValue::Object(obj) = &value else {
        return Ok(LoadState::Corrupt);
    };
    let version = match obj.get("version") {
        Some(JsonValue::Number(n)) => n.parse::<i64>().unwrap_or(-1),
        _ => return Ok(LoadState::Corrupt),
    };
    if version != STATE_VERSION {
        return Ok(LoadState::Corrupt);
    }
    let mut fields = KeeperStatusFields {
        logged_out: get_bool(obj, "logged_out"),
        keeper_stopped: get_bool(obj, "keeper_stopped"),
        keeper_stopped_reason: get_str(obj, "keeper_stopped_reason").unwrap_or_default(),
        last_tick_outcome: get_str(obj, "last_tick_outcome").unwrap_or_default(),
        driving_cookie: get_str(obj, "driving_cookie").unwrap_or_default(),
        warn_pending: get_bool(obj, "warn_pending"),
        warn_sent: get_bool(obj, "warn_sent"),
        ..Default::default()
    };
    // A time field present but unparseable is corrupt JSON
    // for Go's `json.Unmarshal` into `time.Time`: fail the
    // whole load, not just the field.
    for (key, slot) in [
        ("last_checked_at", &mut fields.last_checked_at),
        ("earliest_expiry", &mut fields.earliest_expiry),
        ("driving_expiry", &mut fields.driving_expiry),
        ("next_check_at", &mut fields.next_check_at),
    ] {
        match get_time(obj, key) {
            Ok(v) => *slot = v,
            Err(()) => return Ok(LoadState::Corrupt),
        }
    }
    if fields.last_tick_outcome.is_empty() {
        fields.last_tick_outcome = OUTCOME_NEVER.to_string();
    }
    Ok(LoadState::Parsed(fields))
}

/// `keeper.ReadStatus`: read one entry's status. A
/// corrupt state file yields a `state_corrupt` status, not
/// an error; other failures (bad profile name, unreadable
/// directory) are errors.
pub fn read_status(config_dir: &Path, entry: &KeeperEntry) -> Result<KeeperStatus, String> {
    let paths = castctl_config::profile_paths(&config_dir.to_string_lossy(), &entry.profile)
        .map_err(|e| e.message().to_string())?;
    match load_state(Path::new(&paths.dir))? {
        LoadState::Fresh => Ok(KeeperStatus {
            tag: entry.tag.clone(),
            profile: entry.profile.clone(),
            last_tick_outcome: OUTCOME_NEVER.to_string(),
            ..Default::default()
        }),
        LoadState::Corrupt => Ok(KeeperStatus {
            tag: entry.tag.clone(),
            profile: entry.profile.clone(),
            keeper_stopped_reason: STOPPED_STATE_CORRUPT.to_string(),
            state_corrupt: true,
            ..Default::default()
        }),
        LoadState::Parsed(f) => Ok(KeeperStatus {
            tag: entry.tag.clone(),
            profile: entry.profile.clone(),
            logged_out: f.logged_out,
            keeper_stopped: f.keeper_stopped,
            keeper_stopped_reason: f.keeper_stopped_reason,
            last_checked_at: f.last_checked_at,
            last_tick_outcome: f.last_tick_outcome,
            earliest_expiry: f.earliest_expiry,
            driving_cookie: f.driving_cookie,
            driving_expiry: f.driving_expiry,
            warn_pending: f.warn_pending,
            warn_sent: f.warn_sent,
            next_check_at: f.next_check_at,
            state_corrupt: false,
        }),
    }
}

/// Go `time.RFC3339` (seconds precision) for the login
/// status view: `earliest_expiry` / `last_checked_at`
/// render without fractional seconds.
pub fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn entry(tag: &str, profile: &str) -> KeeperEntry {
        KeeperEntry {
            tag: tag.to_string(),
            profile: profile.to_string(),
            browser: String::new(),
            interval_ns: 0,
            interval_set: false,
            notify: String::new(),
            credentials: String::new(),
        }
    }

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("m6b-keeper-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn missing_state_is_never_ticked() {
        let d = dir("missing");
        let st = read_status(&d, &entry("k1", "muse01")).unwrap();
        assert_eq!(st.last_tick_outcome, "never");
        assert!(!st.logged_out);
        let JsonValue::Object(o) = st.to_json() else { panic!("object") };
        assert_eq!(o.get("last_tick_outcome"), Some(&JsonValue::Str("never".to_string())));
        // omitempty: no reason, no timestamps, no corrupt flag.
        assert!(o.get("keeper_stopped_reason").is_none());
        assert!(o.get("state_corrupt").is_none());
    }

    #[test]
    fn corrupt_state_reports_state_corrupt() {
        let d = dir("corrupt");
        let prof = d.join("profiles").join("muse01");
        fs::create_dir_all(&prof).unwrap();
        fs::write(prof.join(STATE_FILE_NAME), b"{not json").unwrap();
        let st = read_status(&d, &entry("k1", "muse01")).unwrap();
        assert!(st.state_corrupt);
        assert_eq!(st.keeper_stopped_reason, "state_corrupt");
        assert_eq!(st.last_tick_outcome, "");
    }

    #[test]
    fn wrong_version_is_corrupt() {
        let d = dir("version");
        let prof = d.join("profiles").join("muse01");
        fs::create_dir_all(&prof).unwrap();
        fs::write(prof.join(STATE_FILE_NAME), b"{\"version\": 99}").unwrap();
        let st = read_status(&d, &entry("k1", "muse01")).unwrap();
        assert!(st.state_corrupt);
    }

    #[test]
    fn parsed_state_round_trips() {
        let d = dir("parsed");
        let prof = d.join("profiles").join("muse01");
        fs::create_dir_all(&prof).unwrap();
        fs::write(
            prof.join(STATE_FILE_NAME),
            br#"{"version":1,"logged_out":true,"last_tick_outcome":"ok","earliest_expiry":"2026-12-05T00:00:00Z"}"#,
        )
        .unwrap();
        let st = read_status(&d, &entry("k1", "muse01")).unwrap();
        assert!(st.logged_out);
        assert_eq!(st.last_tick_outcome, "ok");
        assert!(st.earliest_expiry.is_some());
        let JsonValue::Object(o) = st.to_json() else { panic!("object") };
        assert_eq!(
            o.get("earliest_expiry"),
            Some(&JsonValue::Str("2026-12-05T00:00:00Z".to_string()))
        );
    }
}
