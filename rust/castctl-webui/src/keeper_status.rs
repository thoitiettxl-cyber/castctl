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
//! Times are Go `time.Time` JSON (RFC3339Nano): the
//! keeper writes local-origin times (`last/next_check_at`)
//! with the machine-local offset (`+07:00`) and expiry
//! times (`earliest/driving_expiry`) as UTC (`Z`). A
//! stored offset is preserved on read — it is NEVER
//! normalised to UTC (M7g: the old `parse_time` did
//! exactly that, the second offset-drop site; fix loop 1,
//! B6: the expiry fields keep their stored offset too,
//! instead of converting to UTC after parsing).

use crate::validate::KeeperEntry;
use castctl_config::jsonvalue::{JsonValue, OrderedObject, decode_ordered_json};
use castctl_shared::timefmt::{format_go_rfc3339_nano, format_go_rfc3339_secs};
use chrono::{DateTime, FixedOffset};
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
    pub last_checked_at: Option<DateTime<FixedOffset>>,
    pub last_tick_outcome: String,
    pub earliest_expiry: Option<DateTime<FixedOffset>>,
    pub driving_cookie: String,
    pub driving_expiry: Option<DateTime<FixedOffset>>,
    pub warn_pending: bool,
    pub warn_sent: bool,
    pub next_check_at: Option<DateTime<FixedOffset>>,
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
            obj.set("last_checked_at", JsonValue::Str(rfc3339_nano_offset(*t)));
        }
        obj.set(
            "last_tick_outcome",
            JsonValue::Str(self.last_tick_outcome.clone()),
        );
        if let Some(t) = &self.earliest_expiry {
            obj.set("earliest_expiry", JsonValue::Str(format_go_rfc3339_nano(t)));
        }
        if !self.driving_cookie.is_empty() {
            obj.set(
                "driving_cookie",
                JsonValue::Str(self.driving_cookie.clone()),
            );
        }
        if let Some(t) = &self.driving_expiry {
            obj.set("driving_expiry", JsonValue::Str(format_go_rfc3339_nano(t)));
        }
        if self.warn_pending {
            obj.set("warn_pending", JsonValue::Bool(true));
        }
        if self.warn_sent {
            obj.set("warn_sent", JsonValue::Bool(true));
        }
        if let Some(t) = &self.next_check_at {
            obj.set("next_check_at", JsonValue::Str(rfc3339_nano_offset(*t)));
        }
        if self.state_corrupt {
            obj.set("state_corrupt", JsonValue::Bool(true));
        }
        JsonValue::Object(obj)
    }
}

/// Parse one RFC 3339 timestamp with Go's `time.Time`
/// accept-set, keeping the stored offset. This mirrors
/// `castctl-keeper/src/state.rs::rfc3339_offset::parse`
/// (the webui has no keeper dependency, so the two tiny
/// helpers live here too) — keep the two in sync: Go
/// carries out-of-range offset minutes (`+07:60` ->
/// `+08:00`, wall clock preserved) and rejects lowercase
/// `t`/`z`, space separator, leap second `:60`, and a
/// non-ASCII minus, all of which chrono accepts.
/// Mirror of `castctl-keeper/src/state.rs::rfc3339_offset::normalize_offset_minutes`
/// — keep the two in sync. Only an offset minutes of
/// exactly 60 carries (`+07:60` -> `+08:00`); 61–99 are
/// rejected by Go and left for the parser to reject (fix
/// loop 1, B2).
fn normalize_offset_minutes(s: &str) -> String {
    let Some(t) = s.find('T') else {
        return s.to_string();
    };
    let rest = &s[t + 1..];
    let Some(sign_pos) = rest.rfind(['+', '-']) else {
        return s.to_string();
    };
    let off = &rest[sign_pos..];
    let b = off.as_bytes();
    if b.len() != 6
        || b[3] != b':'
        || !b[1].is_ascii_digit()
        || !b[2].is_ascii_digit()
        || !b[4].is_ascii_digit()
        || !b[5].is_ascii_digit()
    {
        return s.to_string();
    }
    let hh = (b[1] - b'0') as u32 * 10 + (b[2] - b'0') as u32;
    let mm = (b[4] - b'0') as u32 * 10 + (b[5] - b'0') as u32;
    if mm != 60 {
        return s.to_string();
    }
    let total = hh * 60 + mm;
    format!(
        "{}{:02}:{:02}",
        &s[..t + 1 + sign_pos + 1],
        total / 60,
        total % 60
    )
}

/// Mirror of `castctl-keeper/src/state.rs::rfc3339_offset::check_go_strict`
/// — keep the two in sync. The offset must be exactly
/// `Z` or `±HH:MM` and then end-of-input (fix loop 1,
/// B3+B4): `+0700` (no colon), trailing text after the
/// offset, and surrounding whitespace are all rejected,
/// like Go.
fn check_go_strict(s: &str) -> Result<(), String> {
    // Go rejects surrounding whitespace; chrono
    // tolerates it.
    if s.starts_with(|c: char| c.is_ascii_whitespace())
        || s.ends_with(|c: char| c.is_ascii_whitespace())
    {
        return Err("timestamp has surrounding whitespace".to_string());
    }
    let b = s.as_bytes();
    if b.len() < 20 {
        return Err("timestamp too short for RFC3339".to_string());
    }
    if b[10] != b'T' {
        return Err("date/time separator must be 'T'".to_string());
    }
    if b[17] == b'6' && b[18] == b'0' {
        return Err("leap second ':60' is not valid RFC3339 for Go".to_string());
    }
    let mut i = 19;
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return Err("'.' must be followed by fractional digits".to_string());
        }
    }
    match b.get(i) {
        Some(b'Z') => {
            // `Z` must be the last byte.
            if i + 1 == b.len() {
                Ok(())
            } else {
                Err("unexpected text after 'Z'".to_string())
            }
        }
        Some(b'+') | Some(b'-') => {
            // `±HH:MM` (two digits, colon, two digits)
            // and then end-of-input.
            let rest = &b[i..];
            if rest.len() != 6
                || rest[3] != b':'
                || !rest[1].is_ascii_digit()
                || !rest[2].is_ascii_digit()
                || !rest[4].is_ascii_digit()
                || !rest[5].is_ascii_digit()
            {
                return Err("offset must be ±HH:MM".to_string());
            }
            Ok(())
        }
        _ => Err("missing or invalid RFC3339 offset".to_string()),
    }
}

fn parse_offset_time(s: &str) -> Option<DateTime<FixedOffset>> {
    check_go_strict(s).ok()?;
    let s = normalize_offset_minutes(s);
    s.parse::<DateTime<FixedOffset>>().ok()
}

fn parse_time(value: &JsonValue) -> Option<Option<DateTime<FixedOffset>>> {
    match value {
        JsonValue::Null => Some(None),
        JsonValue::Str(s) => Some(Some(parse_offset_time(s)?)),
        _ => None,
    }
}

/// Expiry fields are UTC by construction (Go
/// `time.Unix(...).UTC()`), so a Go-written expiry renders
/// `Z` — but the stored offset is still preserved on read
/// (fix loop 1, B6): parse offset-preserving and keep it,
/// exactly like the LOCAL fields.
fn get_str(obj: &OrderedObject, key: &str) -> Option<String> {
    match obj.get(key) {
        Some(JsonValue::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

fn get_bool(obj: &OrderedObject, key: &str) -> bool {
    matches!(obj.get(key), Some(JsonValue::Bool(true)))
}

fn get_time(obj: &OrderedObject, key: &str) -> Result<Option<DateTime<FixedOffset>>, ()> {
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
    last_checked_at: Option<DateTime<FixedOffset>>,
    last_tick_outcome: String,
    earliest_expiry: Option<DateTime<FixedOffset>>,
    driving_cookie: String,
    driving_expiry: Option<DateTime<FixedOffset>>,
    warn_pending: bool,
    warn_sent: bool,
    next_check_at: Option<DateTime<FixedOffset>>,
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
    let value = match decode_ordered_json(text.as_bytes()) {
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
    // whole load, not just the field. Every time field
    // keeps its stored offset (fix loop 1, B6: expiry
    // fields no longer convert to UTC after parsing).
    for (key, slot) in [
        ("last_checked_at", &mut fields.last_checked_at),
        ("next_check_at", &mut fields.next_check_at),
    ] {
        match get_time(obj, key) {
            Ok(v) => *slot = v,
            Err(()) => return Ok(LoadState::Corrupt),
        }
    }
    for (key, slot) in [
        ("earliest_expiry", &mut fields.earliest_expiry),
        ("driving_expiry", &mut fields.driving_expiry),
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
    let paths =
        castctl_config::profile::profile_paths(&config_dir.to_string_lossy(), &entry.profile)
            .map_err(|e| e.message)?;
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

/// Go's `time.Time` JSON (RFC3339Nano) for a
/// `FixedOffset` time: fractional seconds with trailing
/// zeros trimmed, the stored offset kept, `Z` for a zero
/// offset. One shared implementation lives in
/// `castctl-shared/src/timefmt.rs` (fix loop 1, B1); this
/// is only the webui's local name for it. (The `Utc` twin
/// is `chats::rfc3339_nano` and must stay `Utc`: chat
/// times are Go `nowUTC`.)
pub fn rfc3339_nano_offset(dt: DateTime<FixedOffset>) -> String {
    format_go_rfc3339_nano(&dt)
}

/// Go `time.RFC3339` (seconds precision) for the login
/// status view: a time renders without fractional seconds,
/// with the stored offset kept (`+07:00`; `Z` for a zero
/// offset) — Go `handlers.go:688,691`
/// `Format(time.RFC3339)`. Used for both the expiry and
/// the LOCAL field (fix loop 1, B6: the expiry twin no
/// longer forces `Z`). Renders via the shared
/// `format_go_rfc3339_secs` (fix loop 2, technical N1):
/// chrono's `to_rfc3339_opts(Secs, true)` rounds
/// seconds-offsets; Go truncates them.
pub fn rfc3339_offset(dt: DateTime<FixedOffset>) -> String {
    format_go_rfc3339_secs(&dt)
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
        let JsonValue::Object(o) = st.to_json() else {
            panic!("object")
        };
        assert_eq!(
            o.get("last_tick_outcome"),
            Some(&JsonValue::Str("never".to_string()))
        );
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
        let JsonValue::Object(o) = st.to_json() else {
            panic!("object")
        };
        assert_eq!(
            o.get("earliest_expiry"),
            Some(&JsonValue::Str("2026-12-05T00:00:00Z".to_string()))
        );
    }

    #[test]
    fn parsed_state_keeps_local_offset() {
        // M7g: Go's `LoadState` keeps the stored offset, so
        // a Go-written state with `last_checked_at` at
        // `+07:00` must render `+07:00` here too — the
        // `parse_time` normalisation to UTC was the second
        // offset-drop site. The expiry field in the same
        // file stays `Z`.
        let d = dir("parsed-local");
        let prof = d.join("profiles").join("muse01");
        fs::create_dir_all(&prof).unwrap();
        fs::write(
            prof.join(STATE_FILE_NAME),
            br#"{"version":1,"last_tick_outcome":"ok","last_checked_at":"2026-11-07T18:33:11.890775586+07:00","next_check_at":"2026-11-07T18:33:11.890775586+07:00","earliest_expiry":"2026-12-05T00:00:00Z"}"#,
        )
        .unwrap();
        let st = read_status(&d, &entry("k1", "muse01")).unwrap();
        let JsonValue::Object(o) = st.to_json() else {
            panic!("object")
        };
        assert_eq!(
            o.get("last_checked_at"),
            Some(&JsonValue::Str(
                "2026-11-07T18:33:11.890775586+07:00".to_string()
            ))
        );
        assert_eq!(
            o.get("next_check_at"),
            Some(&JsonValue::Str(
                "2026-11-07T18:33:11.890775586+07:00".to_string()
            ))
        );
        assert_eq!(
            o.get("earliest_expiry"),
            Some(&JsonValue::Str("2026-12-05T00:00:00Z".to_string()))
        );
    }

    #[test]
    fn parsed_state_plus_zero_zero_collapses_to_z() {
        // Go normalises a stored `+00:00` to `Z` (R1 probe
        // P2); the webui read path must do the same.
        let d = dir("parsed-zero");
        let prof = d.join("profiles").join("muse01");
        fs::create_dir_all(&prof).unwrap();
        fs::write(
            prof.join(STATE_FILE_NAME),
            br#"{"version":1,"last_tick_outcome":"ok","last_checked_at":"2026-11-07T11:33:11+00:00"}"#,
        )
        .unwrap();
        let st = read_status(&d, &entry("k1", "muse01")).unwrap();
        let JsonValue::Object(o) = st.to_json() else {
            panic!("object")
        };
        assert_eq!(
            o.get("last_checked_at"),
            Some(&JsonValue::Str("2026-11-07T11:33:11Z".to_string()))
        );
    }

    #[test]
    fn rfc3339_offset_seconds_only_keeps_offset() {
        // M7g: the login-status view renders
        // `last_checked_at` seconds-only with the stored
        // offset (Go `handlers.go:691`
        // `Format(time.RFC3339)`), `Z` for a zero offset.
        use chrono::TimeZone;
        let plus7 = FixedOffset::east_opt(7 * 3600)
            .unwrap()
            .with_ymd_and_hms(2026, 11, 7, 18, 33, 11)
            .unwrap();
        assert_eq!(rfc3339_offset(plus7), "2026-11-07T18:33:11+07:00");
        let zero = FixedOffset::east_opt(0)
            .unwrap()
            .with_ymd_and_hms(2026, 11, 7, 11, 33, 11)
            .unwrap();
        assert_eq!(rfc3339_offset(zero), "2026-11-07T11:33:11Z");
        assert_eq!(rfc3339_nano_offset(plus7), "2026-11-07T18:33:11+07:00");
    }

    #[test]
    fn rfc3339_offset_truncates_seconds_offsets_like_go() {
        // Fix loop 2, technical N1 (same defect as the
        // nano helper): chrono's `to_rfc3339_opts(Secs,
        // true)` rounds a seconds-offset (+07:06:30 ->
        // +07:07); Go truncates it (+07:06:30 -> +07:06).
        // Expected values are the literal Go 1.27.3 probe
        // outputs (FixedZone marshal). Latent only (the
        // parser rejects seconds-offsets) — fixed anyway.
        use chrono::TimeZone;
        for (secs, expected) in [
            (7 * 3600 + 6 * 60 + 30, "2026-11-07T18:33:11+07:06"),
            (-(7 * 3600 + 6 * 60 + 30), "2026-11-07T18:33:11-07:06"),
        ] {
            let off = FixedOffset::east_opt(secs)
                .unwrap()
                .with_ymd_and_hms(2026, 11, 7, 18, 33, 11)
                .unwrap();
            assert_eq!(rfc3339_offset(off), expected, "offset_secs={secs}");
        }
    }

    #[test]
    fn rfc3339_nano_offset_trims_trailing_zeros_like_go() {
        // Fix loop 1, B1 (webui mirror): Go RFC3339Nano
        // trims ALL trailing zeros; the `AutoSi` render
        // printed `.500` / `.120` / `.123456780`. Expected
        // values are the literal Go 1.27.3 probe outputs.
        use chrono::{TimeZone, Timelike};
        let plus7 = FixedOffset::east_opt(7 * 3600).unwrap();
        for (nanos, expected) in [
            (500_000_000u32, "2026-11-07T18:33:11.5+07:00"),
            (100_000_000, "2026-11-07T18:33:11.1+07:00"),
            (120_000_000, "2026-11-07T18:33:11.12+07:00"),
            (123_400_000, "2026-11-07T18:33:11.1234+07:00"),
            (123_456_780, "2026-11-07T18:33:11.12345678+07:00"),
            (10, "2026-11-07T18:33:11.00000001+07:00"),
            (0, "2026-11-07T18:33:11+07:00"),
        ] {
            let dt = plus7
                .with_ymd_and_hms(2026, 11, 7, 18, 33, 11)
                .unwrap()
                .with_nanosecond(nanos)
                .unwrap();
            assert_eq!(rfc3339_nano_offset(dt), expected, "nanos={nanos}");
        }
    }

    #[test]
    fn offset_minutes_61_to_99_is_corrupt() {
        // Fix loop 1, B2 (webui mirror): Go rejects offset
        // minutes 61–99; only mm==60 carries.
        for bad in ["2026-11-07T18:33:11+07:61", "2026-11-07T18:33:11+07:99"] {
            let d = dir("offset-61");
            let prof = d.join("profiles").join("muse01");
            fs::create_dir_all(&prof).unwrap();
            fs::write(
                prof.join(STATE_FILE_NAME),
                format!(
                    "{{\"version\":1,\"last_tick_outcome\":\"ok\",\"next_check_at\":\"{bad}\"}}"
                ),
            )
            .unwrap();
            let st = read_status(&d, &entry("k1", "muse01")).unwrap();
            assert!(st.state_corrupt, "{bad} must be state_corrupt");
        }
    }

    #[test]
    fn go_strict_offset_shape_is_corrupt() {
        // Fix loop 1, B3+B4 (webui mirror): the offset
        // must be exactly `Z` or `±HH:MM` and then
        // end-of-input; Go rejects `+0700`, trailing text,
        // and surrounding whitespace.
        for bad in [
            "2026-11-07T18:33:11+0700",
            "2026-11-07T18:33:11+07:00 ",
            " 2026-11-07T18:33:11+07:00",
            "2026-11-07T18:33:11+07:00:30",
        ] {
            let d = dir("strict-shape");
            let prof = d.join("profiles").join("muse01");
            fs::create_dir_all(&prof).unwrap();
            fs::write(
                prof.join(STATE_FILE_NAME),
                format!(
                    "{{\"version\":1,\"last_tick_outcome\":\"ok\",\"next_check_at\":\"{bad}\"}}"
                ),
            )
            .unwrap();
            let st = read_status(&d, &entry("k1", "muse01")).unwrap();
            assert!(st.state_corrupt, "{bad:?} must be state_corrupt");
        }
    }

    #[test]
    fn expiry_fields_preserve_stored_offset_like_go() {
        // Fix loop 1, B6 (webui mirror): a hand-edited
        // `+07:00` expiry re-prints `+07:00` in Go; the
        // webui path normalised it to `Z`.
        let d = dir("expiry-offset");
        let prof = d.join("profiles").join("muse01");
        fs::create_dir_all(&prof).unwrap();
        fs::write(
            prof.join(STATE_FILE_NAME),
            br#"{"version":1,"last_tick_outcome":"ok","earliest_expiry":"2026-12-05T07:00:00+07:00","driving_expiry":"2026-12-05T07:00:00+07:00"}"#,
        )
        .unwrap();
        let st = read_status(&d, &entry("k1", "muse01")).unwrap();
        assert!(!st.state_corrupt);
        let JsonValue::Object(o) = st.to_json() else {
            panic!("object")
        };
        assert_eq!(
            o.get("earliest_expiry"),
            Some(&JsonValue::Str("2026-12-05T07:00:00+07:00".to_string()))
        );
        assert_eq!(
            o.get("driving_expiry"),
            Some(&JsonValue::Str("2026-12-05T07:00:00+07:00".to_string()))
        );
    }

    #[test]
    fn expiry_strict_spellings_match_go() {
        // Fix loop 1, B6 (webui mirror): lowercase `z`
        // expiry is corrupt in Go (the webui path already
        // rejected it, the keeper path accepted it);
        // `+07:60` expiry is accepted by Go and carries to
        // `+08:00`; a `.5` expiry renders `.5Z`, not `.500Z`.
        let d = dir("expiry-lower-z");
        let prof = d.join("profiles").join("muse01");
        fs::create_dir_all(&prof).unwrap();
        fs::write(
            prof.join(STATE_FILE_NAME),
            br#"{"version":1,"last_tick_outcome":"ok","earliest_expiry":"2026-12-05T00:00:00z"}"#,
        )
        .unwrap();
        assert!(
            read_status(&d, &entry("k1", "muse01"))
                .unwrap()
                .state_corrupt
        );
        let d = dir("expiry-60");
        let prof = d.join("profiles").join("muse01");
        fs::create_dir_all(&prof).unwrap();
        fs::write(
            prof.join(STATE_FILE_NAME),
            br#"{"version":1,"last_tick_outcome":"ok","earliest_expiry":"2026-12-05T00:00:00+07:60"}"#,
        )
        .unwrap();
        let st = read_status(&d, &entry("k1", "muse01")).unwrap();
        assert!(!st.state_corrupt);
        let JsonValue::Object(o) = st.to_json() else {
            panic!("object")
        };
        assert_eq!(
            o.get("earliest_expiry"),
            Some(&JsonValue::Str("2026-12-05T00:00:00+08:00".to_string()))
        );
        let d = dir("expiry-frac");
        let prof = d.join("profiles").join("muse01");
        fs::create_dir_all(&prof).unwrap();
        fs::write(
            prof.join(STATE_FILE_NAME),
            br#"{"version":1,"last_tick_outcome":"ok","earliest_expiry":"2026-12-05T00:00:00.5Z"}"#,
        )
        .unwrap();
        let st = read_status(&d, &entry("k1", "muse01")).unwrap();
        let JsonValue::Object(o) = st.to_json() else {
            panic!("object")
        };
        assert_eq!(
            o.get("earliest_expiry"),
            Some(&JsonValue::Str("2026-12-05T00:00:00.5Z".to_string()))
        );
    }
}
