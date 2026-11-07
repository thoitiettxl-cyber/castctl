// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Per-profile session state — port of
//! `internal/keeper/state.go`.
//!
//! `session-state.json`, mode 0600, NEXT TO (never inside)
//! `config.json`, one file per profile. Schema v1, frozen.
//! The state file is OBSERVED state, not configuration.
//!
//! Values NEVER appear here: the `cookies` map carries
//! names, expiry dates, and session flags only. The file
//! hash of the cookies file is recorded for change
//! detection; the hash itself is never logged.
//!
//! Unknown JSON fields are ignored on load (forward
//! tolerance); an unknown `version` refuses the tick rather
//! than guessing.
//!
//! [DEVIATION] Go's `json.MarshalIndent` escapes `<`, `>`
//! and `&` in strings (`\u003c` etc.); `serde_json` does
//! not. `setcookie.rs` `is_token_char` INCLUDES `b'&'`,
//! and `jar.rs` does not limit name charset, so a state
//! file CAN differ byte-for-byte from Go's; the difference
//! is byte-only (both parsers read the same values), so
//! the state is semantically identical when loaded. The
//! deviation is recorded, not worked around.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::error::KeeperError;
use crate::jar::{StoredCookie, driving_cookie, earliest_expiry, epoch_to_datetime};
use crate::notify::NoticeKind;

/// Frozen schema version (`state.go:38`).
pub const STATE_VERSION: i32 = 1;
/// State file name within a profile dir (`state.go:40`).
pub const STATE_FILE_NAME: &str = "session-state.json";
/// Bounds a login pause: a flag older than this is
/// recovered by the next tick (`state.go:43`).
pub const LOGIN_FLAG_STALE_AFTER: Duration = Duration::from_secs(70 * 60);
/// Bounds one cookies-file lock hold attempt (`state.go:46`).
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Stopped reasons: the closed enum for
/// `keeper_stopped_reason` (`state.go:54-58`).
pub const STOPPED_AUTH_ERROR: &str = "auth_error";
/// Stopped because the cookies file is missing.
pub const STOPPED_COOKIES_MISSING: &str = "cookies_missing";
/// Stopped because the state file is corrupt.
pub const STOPPED_STATE_CORRUPT: &str = "state_corrupt";

/// Tick outcomes: the closed enum for `last_tick_outcome`
/// (`state.go:66-76`). `outcome_error` is tick-result-only
/// and is never written to the state file.
pub const OUTCOME_NEVER: &str = "never";
/// Tick outcome: ok.
pub const OUTCOME_OK: &str = "ok";
/// Tick outcome: auth error.
pub const OUTCOME_AUTH_ERROR: &str = "auth_error";
/// Tick outcome: transient error.
pub const OUTCOME_TRANSIENT_ERROR: &str = "transient_error";
/// Tick outcome: export failed.
pub const OUTCOME_EXPORT_FAILED: &str = "export_failed";
/// Tick outcome: skipped.
pub const OUTCOME_SKIPPED: &str = "skipped";
/// Tick outcome: hard error (result-only, never persisted).
pub const OUTCOME_ERROR: &str = "error";

/// `skip_serializing_if` helper for `omitempty` bools.
fn is_false(b: &bool) -> bool {
    !*b
}

/// `serde(default)` only fills a MISSING field; an
/// explicit `null` still fails. Go decodes `null` into a
/// nil map, which reads as empty (S-6).
fn null_as_empty_map<'de, D, K, V>(de: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: serde::Deserialize<'de> + Ord,
    V: serde::Deserialize<'de>,
{
    let opt = Option::<BTreeMap<K, V>>::deserialize(de)?;
    Ok(opt.unwrap_or_default())
}

/// RFC 3339 serde for `DateTime<FixedOffset>` /
/// `Option<DateTime<FixedOffset>>` — Go `time.Time` JSON
/// semantics for every keeper time, LOCAL-origin or expiry
/// (`last/next_check_at`, `login_*`, `warned_at`,
/// `last_seen`, audit `started_at`, and the expiry fields
/// `expires_at` / `earliest_expiry` / `driving_expiry` —
/// fix loop 1, B6: expiry fields use this module too, so
/// a stored non-`Z` offset is preserved on re-print like
/// Go; values constructed from UTC instants still render
/// `Z`).
///
/// The stored offset is preserved: parse keeps it
/// (`DateTime<FixedOffset>`), serialize re-emits it via
/// the shared `castctl_shared::timefmt::format_go_rfc3339_nano`
/// (Go RFC3339Nano: trailing-zero nanos trimmed, `Z` for
/// a zero offset). Go normalises an input `+00:00` to `Z`
/// on output, and so does this module (the zero offset has
/// no other spelling in chrono). A timestamp with no offset,
/// or an offset hour out of range, fails to parse — like Go,
/// the state file is then corrupt.
///
/// Two Go behaviours need explicit code because chrono's
/// `parse_rfc3339` differs (verified against chrono
/// 0.4.45 source + Go 1.27.3 probes, 2026-11-07):
/// - Go accepts an out-of-range offset MINUTES of exactly
///   60 and carries it (`+07:60` -> `+08:00`, wall clock
///   preserved; `-07:60` -> `-08:00`); 61–99 are rejected
///   ("offset minute out of range"). Chrono rejects all
///   of them. `normalize_offset_minutes` rewrites only
///   `:60` first (fix loop 1, B2).
/// - Go rejects spellings chrono accepts (lowercase
///   `t`/`z`, space separator, leap second `:60`,
///   non-ASCII minus U+2212, `+0700` with no colon,
///   trailing text after the offset, surrounding
///   whitespace); `check_go_strict` rejects those before
///   chrono sees them (fix loop 1, B3+B4).
pub mod rfc3339_offset {
    use chrono::{DateTime, FixedOffset};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Re-write a trailing RFC 3339 offset whose minutes
    /// are out of range the way Go's `time.Parse` does:
    /// the minutes carry into the hour, the wall clock is
    /// preserved (`+07:60` -> `+08:00`). ONLY `mm == 60`
    /// carries — Go rejects 61–99 ("time zone offset
    /// minute out of range"), so those are left for the
    /// parser to reject (fix loop 1, B2). Inputs that need
    /// no rewrite are returned unchanged. A rewrite that
    /// lands on `±24:00` is left for the parser to reject:
    /// chrono cannot represent a 24h offset, and Go —
    /// while it accepts such a value on unmarshal — cannot
    /// marshal it back (`timezone hour outside of range
    /// [0,23]`), so no round-trip is lost (see PORTING.md
    /// §M7g).
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

    /// Reject the spellings Go's `time.Parse` (RFC3339
    /// layout) rejects but chrono's `parse_rfc3339`
    /// accepts. Everything else is left to chrono, whose
    /// remaining checks (digits, ranges, offset within
    /// ±23:59) match Go's probed behaviour. The offset
    /// must be exactly `Z` or `±HH:MM` and then
    /// end-of-input (fix loop 1, B3+B4): `+0700` (no
    /// colon), trailing text after the offset (`:30`),
    /// and leading/trailing whitespace are all rejected,
    /// like Go.
    fn check_go_strict(s: &str) -> Result<(), String> {
        // Go rejects surrounding whitespace (`extra text`
        // / `cannot parse … as "2006"`); chrono tolerates
        // it.
        if s.starts_with(|c: char| c.is_ascii_whitespace())
            || s.ends_with(|c: char| c.is_ascii_whitespace())
        {
            return Err("timestamp has surrounding whitespace".to_string());
        }
        let b = s.as_bytes();
        // Go's RFC3339 layout needs at least
        // `2006-01-02T15:04:05Z` (20 bytes).
        if b.len() < 20 {
            return Err("timestamp too short for RFC3339".to_string());
        }
        // Separator must be an uppercase `T` (chrono also
        // accepts `t` and ` `; Go rejects both).
        if b[10] != b'T' {
            return Err("date/time separator must be 'T'".to_string());
        }
        // No leap second: chrono maps `:60` to `:59` + 1s,
        // Go rejects it.
        if b[17] == b'6' && b[18] == b'0' {
            return Err("leap second ':60' is not valid RFC3339 for Go".to_string());
        }
        // Offset introducer must be `Z` (uppercase), `+`
        // or `-` (ASCII): chrono also accepts `z` and the
        // non-ASCII minus U+2212; Go rejects both.
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

    /// Parse one RFC 3339 timestamp with Go's `time.Time`
    /// accept-set. The `String` error is surfaced verbatim
    /// by the serde error (and by the webui mirror in
    /// `castctl-webui/src/keeper_status.rs`, which must
    /// stay in sync with this function).
    fn parse(s: &str) -> Result<DateTime<FixedOffset>, String> {
        check_go_strict(s)?;
        let s = normalize_offset_minutes(s);
        s.parse::<DateTime<FixedOffset>>()
            .map_err(|e| e.to_string())
    }

    pub fn serialize<S>(v: &DateTime<FixedOffset>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&castctl_shared::timefmt::format_go_rfc3339_nano(v))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<DateTime<FixedOffset>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        parse(&s).map_err(serde::de::Error::custom)
    }

    pub mod opt {
        use chrono::{DateTime, FixedOffset};
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(v: &Option<DateTime<FixedOffset>>, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match v {
                Some(v) => s.serialize_some(&castctl_shared::timefmt::format_go_rfc3339_nano(v)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(d: D) -> Result<Option<DateTime<FixedOffset>>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt = Option::<String>::deserialize(d)?;
            match opt {
                Some(s) => super::parse(&s).map(Some).map_err(serde::de::Error::custom),
                None => Ok(None),
            }
        }
    }
}

/// Per-cookie observed record: name is the map key; values
/// never appear (`state.go:78-88`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieState {
    /// Expiry; `None` for a session cookie.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_offset::opt"
    )]
    pub expires_at: Option<DateTime<FixedOffset>>,
    /// Session cookie (no expiry).
    pub session: bool,
    /// Last time this cookie was seen (LOCAL: Go
    /// `state.go:342` `LastSeen: now`, `clock.Now()`).
    #[serde(with = "rfc3339_offset")]
    pub last_seen: DateTime<FixedOffset>,
}

/// One per-kind dedup record (`state.go:167-171`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarnedKind {
    /// Whether the notice for this kind was sent during the
    /// current episode.
    pub sent: bool,
    /// When it was sent (LOCAL: Go `state.go:193`
    /// `MarkWarnSent`, `clock.Now()`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_offset::opt"
    )]
    pub at: Option<DateTime<FixedOffset>>,
}

/// The v1 state file body (`state.go:91-165`). Field order
/// matches the Go struct (serde preserves declaration
/// order); `omitempty` fields are skipped when empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    /// Schema version (always 1).
    pub version: i32,
    /// The keeper proved the session dead.
    #[serde(default)]
    pub logged_out: bool,
    /// The entry is sticky-stopped.
    #[serde(default)]
    pub keeper_stopped: bool,
    /// Why the entry stopped (closed enum).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keeper_stopped_reason: String,
    /// Last tick time (LOCAL: Go tick paths,
    /// `clock.Now()`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_offset::opt"
    )]
    pub last_checked_at: Option<DateTime<FixedOffset>>,
    /// Last tick outcome (closed enum; never `"error"`).
    #[serde(default)]
    pub last_tick_outcome: String,
    /// Tick stage of the last outcome: `""`, `"session"`,
    /// `"auth_check"`, `"export"`, or `"save"`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_tick_stage: String,
    /// Per-cookie observed records, keyed by name.
    #[serde(
        default,
        deserialize_with = "null_as_empty_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub cookies: BTreeMap<String, CookieState>,
    /// Earliest expiry in the set.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_offset::opt"
    )]
    pub earliest_expiry: Option<DateTime<FixedOffset>>,
    /// Name of the driving cookie.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub driving_cookie: String,
    /// Expiry of the driving cookie.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_offset::opt"
    )]
    pub driving_expiry: Option<DateTime<FixedOffset>>,
    /// SHA-256 of the cookies file (change detection; never
    /// logged).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cookies_sha256: String,
    /// Next scheduled check (LOCAL: Go tick paths,
    /// `clock.Now().Add(...)`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_offset::opt"
    )]
    pub next_check_at: Option<DateTime<FixedOffset>>,
    /// A screencast login is in progress for this profile.
    #[serde(default, skip_serializing_if = "is_false")]
    pub login_active: bool,
    /// The login session's opaque id (not a secret).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub login_session_id: String,
    /// When the login started (bounds the pause)
    /// (LOCAL: Go `login.go:401` `LoginStartedAt = &now`,
    /// `clock.Now()`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_offset::opt"
    )]
    pub login_started_at: Option<DateTime<FixedOffset>>,
    /// Login provenance, written ONLY by the login flow.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub login_user_agent: String,
    /// Login provenance (browser product string).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub login_chromium_version: String,
    /// When the login saved cookies (LOCAL: Go
    /// `login.go:343-344` `LoginAt = &loginAt`,
    /// `clock.Now()`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_offset::opt"
    )]
    pub login_at: Option<DateTime<FixedOffset>>,
    /// Legacy warn-once fields (kept in sync with
    /// `warned_kinds` for existing readers).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub warn_kind: String,
    /// A notice is pending for the current episode.
    #[serde(default, skip_serializing_if = "is_false")]
    pub warn_pending: bool,
    /// A notice was sent for the current episode.
    #[serde(default, skip_serializing_if = "is_false")]
    pub warn_sent: bool,
    /// When the last notice was sent (LOCAL: Go
    /// `state.go:194` `MarkWarnSent`, `clock.Now()`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_offset::opt"
    )]
    pub warned_at: Option<DateTime<FixedOffset>>,
    /// Per-(incident, kind) dedup record: the
    /// episode-scoped authority.
    #[serde(
        default,
        deserialize_with = "null_as_empty_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub warned_kinds: BTreeMap<String, WarnedKind>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionState {
    /// A fresh v1 state (`state.go:232-234`).
    pub fn new() -> Self {
        Self {
            version: STATE_VERSION,
            logged_out: false,
            keeper_stopped: false,
            keeper_stopped_reason: String::new(),
            last_checked_at: None,
            last_tick_outcome: OUTCOME_NEVER.to_string(),
            last_tick_stage: String::new(),
            cookies: BTreeMap::new(),
            earliest_expiry: None,
            driving_cookie: String::new(),
            driving_expiry: None,
            cookies_sha256: String::new(),
            next_check_at: None,
            login_active: false,
            login_session_id: String::new(),
            login_started_at: None,
            login_user_agent: String::new(),
            login_chromium_version: String::new(),
            login_at: None,
            warn_kind: String::new(),
            warn_pending: false,
            warn_sent: false,
            warned_at: None,
            warned_kinds: BTreeMap::new(),
        }
    }

    /// Whether `kind` was already alerted in the current
    /// episode (`state.go:175-183`).
    pub fn warned_kind_sent(&self, kind: NoticeKind) -> bool {
        self.warned_kinds
            .get(kind.as_str())
            .map(|m| m.sent)
            .unwrap_or(false)
    }

    /// Record a pending notice for `kind` in the current
    /// episode, unless the kind was already sent in this
    /// episode. Reports whether the notice is newly pending
    /// (`false` = already alerted, caller must not
    /// re-notify). The legacy `warn_*` fields are kept in
    /// sync (`state.go:185-203`).
    pub fn mark_warn_pending(&mut self, kind: NoticeKind, _now: DateTime<FixedOffset>) -> bool {
        if self.warned_kind_sent(kind) {
            return false;
        }
        self.warned_kinds.insert(
            kind.as_str().to_string(),
            WarnedKind {
                sent: false,
                at: None,
            },
        );
        self.warn_kind = kind.as_str().to_string();
        self.warn_pending = true;
        self.warn_sent = false;
        true
    }

    /// Record that `kind`'s notice was sent: the episode
    /// dedup entry flips to `sent` and the legacy fields
    /// sync. Other kinds' entries are untouched
    /// (`state.go:205-217`).
    pub fn mark_warn_sent(&mut self, kind: NoticeKind, now: DateTime<FixedOffset>) {
        self.mark_warn_sent_raw(kind.as_str(), now);
    }

    /// `mark_warn_sent` for a RAW kind string from state:
    /// Go `NotifyStopped` (`tick.go`) passes
    /// `NoticeKind(ls.state.WarnKind)` — the raw string —
    /// into the dedup bookkeeping, and `NoticeKind` is a
    /// string type there, so an unknown kind stays
    /// unknown in state. Rust's `NoticeKind` is a closed
    /// enum and cannot carry it, so the notifier is still
    /// called with the parsed kind (unknown kinds map to
    /// `LoggedOut`, whose notice text Go renders for any
    /// unknown kind via its `NoticeText` default branch),
    /// but the stored `warn_kind` is NOT rewritten to
    /// `"logged_out"` (S-8).
    pub fn mark_warn_sent_raw(&mut self, raw: &str, now: DateTime<FixedOffset>) {
        self.warned_kinds.insert(
            raw.to_string(),
            WarnedKind {
                sent: true,
                at: Some(now),
            },
        );
        self.warn_pending = false;
        self.warn_sent = true;
        self.warn_kind = raw.to_string();
        self.warned_at = Some(now);
    }

    /// Clear the whole episode dedup record and the legacy
    /// warn fields: called when the entry recovers, so a
    /// later incident alerts afresh (`state.go:219-229`).
    pub fn clear_warn_episode(&mut self) {
        self.warned_kinds.clear();
        self.warn_kind = String::new();
        self.warn_pending = false;
        self.warn_sent = false;
        self.warned_at = None;
    }

    /// Rebuild the per-cookie records from the merged set:
    /// names and expiry dates only, `last_seen = now` for
    /// every cookie present. Cookies absent from the set are
    /// dropped (`state.go:337-353`).
    pub fn refresh_cookie_records(&mut self, cookies: &[StoredCookie], now: DateTime<FixedOffset>) {
        let mut map: BTreeMap<String, CookieState> = BTreeMap::new();
        for c in cookies {
            let rec = CookieState {
                expires_at: if c.is_session() {
                    None
                } else {
                    Some(epoch_to_datetime(c.expires))
                },
                session: c.is_session(),
                last_seen: now,
            };
            map.insert(c.name.clone(), rec);
        }
        self.cookies = map;
        self.earliest_expiry = earliest_expiry(cookies);
        let (name, exp) = driving_cookie(cookies);
        self.driving_cookie = name;
        self.driving_expiry = exp;
    }
}

/// The state file path for a profile directory
/// (`state.go:237-239`).
pub fn state_path(profile_dir: &str) -> PathBuf {
    Path::new(profile_dir).join(STATE_FILE_NAME)
}

/// Read the state file (`state.go:241-275`). A missing file
/// is a fresh state, not an error. A present file with an
/// unknown version, or unparseable JSON, is a
/// [`KeeperError::StateCorrupt`]: callers that can recover
/// substitute a fresh state and record the corruption.
/// Unknown fields are ignored.
pub fn load_state(profile_dir: &str) -> Result<SessionState, KeeperError> {
    let path = state_path(profile_dir);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SessionState::new()),
        Err(e) => return Err(KeeperError::Io(e)),
    };
    if data.is_empty() {
        return Ok(SessionState::new());
    }
    let mut st: SessionState = serde_json::from_slice(&data)
        .map_err(|e| KeeperError::StateCorrupt(format!("{}: {}", path.display(), e)))?;
    if st.version != STATE_VERSION {
        return Err(KeeperError::StateCorrupt(format!(
            "{}: version {} is not supported (want {})",
            path.display(),
            st.version,
            STATE_VERSION
        )));
    }
    if st.last_tick_outcome.is_empty() {
        st.last_tick_outcome = OUTCOME_NEVER.to_string();
    }
    Ok(st)
}

/// Write the state atomically (temp file + rename in the
/// same directory), mode 0600 (`state.go:311-344`). The
/// write is byte-stable for equal content: keys are written
/// in struct order and the cookies map is sorted.
pub fn save_state(profile_dir: &str, st: &SessionState) -> Result<(), KeeperError> {
    let mut st = st.clone();
    st.version = STATE_VERSION;
    let mut data = serde_json::to_string_pretty(&st)
        .map_err(|e| KeeperError::Other(format!("cannot encode session state: {e}")))?;
    data.push('\n');
    let path = state_path(profile_dir);
    let dir = Path::new(profile_dir);
    // Temp file in the same directory (unique name; Go uses
    // os.CreateTemp with ".session-state-*.tmp"). Mode 0600
    // from the moment of creation (S-1); the name carries
    // pid + counter + nanos (S-5).
    let tmp_name = format!(".session-state-{}.tmp", crate::lockfile::temp_suffix());
    let tmp_path = dir.join(tmp_name);
    {
        let mut tmp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        tmp.write_all(data.as_bytes())?;
        tmp.sync_all()?;
        // `File::sync_all` + close before rename (Go syncs
        // before rename so a crash cannot leave a torn file).
    }
    if let Err(e) = std::fs::rename(&tmp_path, &path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(KeeperError::Io(e));
    }
    Ok(())
}

/// Hex SHA-256 of data, for the `cookies_sha256` state
/// field (`state.go:325-328`). A change-detection
/// fingerprint of secret material: record it, never log it.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let sum = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in sum {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::os::unix::fs::PermissionsExt;

    fn tmpdir() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "castctl-keeper-state-test-{}-{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn save_load_round_trip_and_mode() {
        let dir = tmpdir();
        let mut st = SessionState::new();
        st.last_tick_outcome = OUTCOME_OK.to_string();
        st.keeper_stopped = true;
        st.keeper_stopped_reason = STOPPED_AUTH_ERROR.to_string();
        let now = FixedOffset::east_opt(7 * 3600)
            .unwrap()
            .with_ymd_and_hms(2026, 11, 5, 0, 0, 0)
            .unwrap();
        st.mark_warn_pending(NoticeKind::LoggedOut, now);
        save_state(dir.to_str().unwrap(), &st).expect("saves");
        let mode = std::fs::metadata(state_path(dir.to_str().unwrap()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let back = load_state(dir.to_str().unwrap()).expect("loads");
        assert_eq!(back.last_tick_outcome, OUTCOME_OK);
        assert!(back.keeper_stopped);
        assert_eq!(back.keeper_stopped_reason, STOPPED_AUTH_ERROR);
        assert!(back.warn_pending);
        assert_eq!(back.warn_kind, "logged_out");
        assert_eq!(back.version, STATE_VERSION);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_and_empty_is_fresh() {
        let dir = tmpdir();
        let st = load_state(dir.to_str().unwrap()).expect("missing is fresh");
        assert_eq!(st.last_tick_outcome, OUTCOME_NEVER);
        std::fs::write(state_path(dir.to_str().unwrap()), b"").unwrap();
        let st2 = load_state(dir.to_str().unwrap()).expect("empty is fresh");
        assert_eq!(st2.last_tick_outcome, OUTCOME_NEVER);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_corrupt_and_bad_version() {
        let dir = tmpdir();
        std::fs::write(state_path(dir.to_str().unwrap()), b"{not json").unwrap();
        assert!(matches!(
            load_state(dir.to_str().unwrap()),
            Err(KeeperError::StateCorrupt(_))
        ));
        std::fs::write(
            state_path(dir.to_str().unwrap()),
            b"{\"version\": 2, \"last_tick_outcome\": \"never\"}",
        )
        .unwrap();
        let err = load_state(dir.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("version 2 is not supported"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_null_maps_are_empty() {
        // S-6: Go decodes `"cookies": null` into a nil
        // map, which reads as empty; serde `default`
        // alone fails on an explicit null.
        let dir = tmpdir();
        std::fs::write(
            state_path(dir.to_str().unwrap()),
            b"{\"version\": 1, \"cookies\": null, \"warned_kinds\": null}",
        )
        .unwrap();
        let st = load_state(dir.to_str().unwrap()).expect("null maps load as empty");
        assert!(st.cookies.is_empty());
        assert!(st.warned_kinds.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mark_warn_sent_raw_keeps_unknown_kind() {
        // S-8: a hand-edited state with an unknown kind
        // keeps the raw kind in bookkeeping instead of
        // being rewritten to "logged_out".
        let now = FixedOffset::east_opt(0)
            .unwrap()
            .with_ymd_and_hms(2026, 11, 5, 0, 0, 0)
            .unwrap();
        let mut st = SessionState::new();
        st.mark_warn_sent_raw("bogus_kind", now);
        assert_eq!(st.warn_kind, "bogus_kind");
        assert!(st.warn_sent);
        assert!(!st.warn_pending);
        assert!(st.warned_kinds.contains_key("bogus_kind"));
    }

    #[test]
    fn warn_dedup_episode() {
        let now = FixedOffset::east_opt(0)
            .unwrap()
            .with_ymd_and_hms(2026, 11, 5, 0, 0, 0)
            .unwrap();
        let mut st = SessionState::new();
        assert!(st.mark_warn_pending(NoticeKind::Captcha, now));
        // Go `state.go:168-180`: a repeat pending for the same
        // kind still returns true; only an already-SENT kind
        // returns false.
        assert!(st.mark_warn_pending(NoticeKind::Captcha, now));
        assert!(st.mark_warn_pending(NoticeKind::Locked, now));
        assert!(!st.warned_kind_sent(NoticeKind::Captcha));
        st.mark_warn_sent(NoticeKind::Captcha, now);
        assert!(st.warned_kind_sent(NoticeKind::Captcha));
        assert!(!st.mark_warn_pending(NoticeKind::Captcha, now));
        st.clear_warn_episode();
        assert!(!st.warned_kind_sent(NoticeKind::Captcha));
        assert!(st.mark_warn_pending(NoticeKind::Captcha, now));
    }

    #[test]
    fn sha256_hex_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn write_raw_state(dir: &Path, json: &str) {
        std::fs::write(state_path(dir.to_str().unwrap()), json.as_bytes()).unwrap();
    }

    fn saved_state_text(dir: &Path) -> String {
        std::fs::read_to_string(state_path(dir.to_str().unwrap())).unwrap()
    }

    #[test]
    fn local_offset_round_trip_preserves_stored_offset() {
        // M7g: Go `time.Time` JSON keeps the stored offset
        // (R1 probe P1, re-verified by the writer 2026-11-07
        // with sandbox go1.27.3): `+07:00`, `Z` and `-03:00`
        // re-print byte-identical. Expected values are the
        // literal Go-probe outputs, never recomputed.
        for input in [
            "2026-11-07T18:33:11.890775586+07:00",
            "2026-11-07T11:33:15.063157834Z",
            "2026-11-07T08:33:15.063157834-03:00",
        ] {
            let dir = tmpdir();
            write_raw_state(
                &dir,
                &format!(
                    "{{\"version\":1,\"last_checked_at\":\"{input}\",\"next_check_at\":\"{input}\"}}"
                ),
            );
            let st = load_state(dir.to_str().unwrap()).expect("loads");
            save_state(dir.to_str().unwrap(), &st).expect("saves");
            let text = saved_state_text(&dir);
            assert!(
                text.contains(input),
                "re-print of {input} should contain {input} verbatim, got:\n{text}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn plus_zero_zero_collapses_to_z_like_go() {
        // Go normalises input `+00:00` to `Z` on output
        // (R1 probe P2, re-verified by the writer).
        let dir = tmpdir();
        write_raw_state(
            &dir,
            "{\"version\":1,\"next_check_at\":\"2026-11-07T11:33:11+00:00\"}",
        );
        let st = load_state(dir.to_str().unwrap()).expect("loads");
        save_state(dir.to_str().unwrap(), &st).expect("saves");
        assert!(
            saved_state_text(&dir).contains("2026-11-07T11:33:11Z"),
            "got:\n{}",
            saved_state_text(&dir)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offset_minutes_carry_like_go() {
        // Go accepts `+07:60` and normalises it to `+08:00`
        // with the wall clock preserved (writer re-probe
        // 2026-11-07, sandbox go1.27.3, run twice:
        // `2026-11-07T18:33:11+07:60` ->
        // `"2026-11-07T18:33:11+08:00"`; R1's recorded
        // `08:33:11` is a transcription error).
        let dir = tmpdir();
        write_raw_state(
            &dir,
            "{\"version\":1,\"next_check_at\":\"2026-11-07T18:33:11+07:60\"}",
        );
        let st = load_state(dir.to_str().unwrap()).expect("loads");
        save_state(dir.to_str().unwrap(), &st).expect("saves");
        assert!(
            saved_state_text(&dir).contains("2026-11-07T18:33:11+08:00"),
            "got:\n{}",
            saved_state_text(&dir)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn time_without_offset_is_corrupt() {
        // Go rejects a timestamp with no offset outright
        // (R1 probe P5).
        let dir = tmpdir();
        write_raw_state(
            &dir,
            "{\"version\":1,\"next_check_at\":\"2026-11-07T18:33:11\"}",
        );
        assert!(matches!(
            load_state(dir.to_str().unwrap()),
            Err(KeeperError::StateCorrupt(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offset_hour_out_of_range_is_corrupt() {
        // Go rejects `+99:00` (R1 probe P4).
        let dir = tmpdir();
        write_raw_state(
            &dir,
            "{\"version\":1,\"next_check_at\":\"2026-11-07T18:33:11.5+99:00\"}",
        );
        assert!(matches!(
            load_state(dir.to_str().unwrap()),
            Err(KeeperError::StateCorrupt(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_write_carries_local_offset() {
        // M7g: a state written from a `+07:00` clock
        // carries the local offset on disk (Go `time.Now()`
        // marshal), not `+00:00`/`Z`. The instant is the
        // fixed Go-probe value
        // `2026-11-07T18:33:11.890775586+07:00`.
        use crate::clock::{Clock, FakeClock};
        use chrono::Timelike;
        let dir = tmpdir();
        let clock = FakeClock::new(
            FixedOffset::east_opt(7 * 3600)
                .unwrap()
                .with_ymd_and_hms(2026, 11, 7, 18, 33, 11)
                .unwrap()
                .with_nanosecond(890_775_586)
                .unwrap(),
        );
        let now = clock.now();
        let mut st = SessionState::new();
        st.last_checked_at = Some(now);
        st.next_check_at = Some(now);
        save_state(dir.to_str().unwrap(), &st).expect("saves");
        let text = saved_state_text(&dir);
        assert!(
            text.contains("2026-11-07T18:33:11.890775586+07:00"),
            "state write must carry +07:00, got:\n{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn go_strict_spellings_are_corrupt() {
        // M7g: chrono accepts spellings Go's `time.Parse`
        // rejects — lowercase `t`/`z`, space separator,
        // leap second `:60`, non-ASCII minus U+2212. Each
        // must fail the load like Go (probed with Go
        // 1.27.3, 2026-11-07).
        for bad in [
            "2026-11-07t18:33:11+07:00",
            "2026-11-07T18:33:11z",
            "2026-11-07 18:33:11+07:00",
            "2026-11-07T18:33:60+07:00",
            "2026-11-07T18:33:11\u{2212}07:00",
        ] {
            let dir = tmpdir();
            write_raw_state(
                &dir,
                &format!("{{\"version\":1,\"next_check_at\":\"{bad}\"}}"),
            );
            assert!(
                matches!(
                    load_state(dir.to_str().unwrap()),
                    Err(KeeperError::StateCorrupt(_))
                ),
                "{bad} must be corrupt"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn offset_24h_is_corrupt() {
        // M7g: `+23:60` / `+24:00` normalise to a 24h
        // offset, which chrono cannot represent — and Go
        // cannot marshal back (`timezone hour outside of
        // range [0,23]`), so rejecting at load loses no
        // round-trip (see PORTING.md §M7g).
        for bad in ["2026-11-07T18:33:11+23:60", "2026-11-07T18:33:11+24:00"] {
            let dir = tmpdir();
            write_raw_state(
                &dir,
                &format!("{{\"version\":1,\"next_check_at\":\"{bad}\"}}"),
            );
            assert!(
                matches!(
                    load_state(dir.to_str().unwrap()),
                    Err(KeeperError::StateCorrupt(_))
                ),
                "{bad} must be corrupt"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn expiry_fields_stay_utc() {
        // Go writes `expires_at` / `earliest_expiry` /
        // `driving_expiry` from `time.Unix(...).UTC()` —
        // always `Z` (R1 §2a) — while a LOCAL field in the
        // same file keeps its offset.
        let dir = tmpdir();
        write_raw_state(
            &dir,
            "{\"version\":1,\"earliest_expiry\":\"2026-12-05T00:00:00Z\",\"driving_expiry\":\"2026-12-05T00:00:00Z\",\"cookies\":{\"hatch_sess\":{\"expires_at\":\"2026-12-05T00:00:00Z\",\"session\":false,\"last_seen\":\"2026-11-07T18:33:11+07:00\"}}}",
        );
        let st = load_state(dir.to_str().unwrap()).expect("loads");
        save_state(dir.to_str().unwrap(), &st).expect("saves");
        let text = saved_state_text(&dir);
        assert!(
            text.contains("2026-12-05T00:00:00Z"),
            "expiry fields must stay Z, got:\n{text}"
        );
        assert!(
            !text.contains("+00:00"),
            "no expiry field may render +00:00, got:\n{text}"
        );
        assert!(
            text.contains("2026-11-07T18:33:11+07:00"),
            "last_seen must keep its local offset, got:\n{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn go_rfc3339_nano_trims_trailing_zeros_like_go() {
        // Fix loop 1, B1: Go RFC3339Nano trims ALL
        // trailing zeros (`.5`, `.12`, `.1234`,
        // `.12345678`); chrono `AutoSi` prints 3/6/9
        // digits only (`.500`, `.120`, `.123400`,
        // `.123456780`). Expected values are the literal
        // Go 1.27.3 probe outputs (review1-technical
        // §Probes), never recomputed with the code under
        // test.
        for (input, expected) in [
            (
                "2026-11-07T18:33:11.500000000+07:00",
                "2026-11-07T18:33:11.5+07:00",
            ),
            (
                "2026-11-07T18:33:11.100000000+07:00",
                "2026-11-07T18:33:11.1+07:00",
            ),
            (
                "2026-11-07T18:33:11.120000000+07:00",
                "2026-11-07T18:33:11.12+07:00",
            ),
            (
                "2026-11-07T18:33:11.123400000+07:00",
                "2026-11-07T18:33:11.1234+07:00",
            ),
            (
                "2026-11-07T18:33:11.123456780+07:00",
                "2026-11-07T18:33:11.12345678+07:00",
            ),
            (
                "2026-11-07T18:33:11.000000010+07:00",
                "2026-11-07T18:33:11.00000001+07:00",
            ),
            (
                "2026-11-07T18:33:11.123000000+07:00",
                "2026-11-07T18:33:11.123+07:00",
            ),
            (
                "2026-11-07T18:33:11.123456000+07:00",
                "2026-11-07T18:33:11.123456+07:00",
            ),
            (
                "2026-11-07T18:33:11.000000001Z",
                "2026-11-07T18:33:11.000000001Z",
            ),
            ("2026-11-07T18:33:11.500000000Z", "2026-11-07T18:33:11.5Z"),
        ] {
            let dir = tmpdir();
            write_raw_state(
                &dir,
                &format!("{{\"version\":1,\"next_check_at\":\"{input}\"}}"),
            );
            let st = load_state(dir.to_str().unwrap()).expect("loads");
            save_state(dir.to_str().unwrap(), &st).expect("saves");
            let text = saved_state_text(&dir);
            assert!(
                text.contains(expected),
                "re-print of {input} should contain {expected}, got:\n{text}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn state_write_trims_trailing_zeros_like_go() {
        // Fix loop 1, B1 (write side): a fake clock at
        // nanos 120000000 writes `.12`, not `.120`
        // (Go re-marshal of the same instant).
        use crate::clock::{Clock, FakeClock};
        use chrono::Timelike;
        let dir = tmpdir();
        let clock = FakeClock::new(
            FixedOffset::east_opt(7 * 3600)
                .unwrap()
                .with_ymd_and_hms(2026, 11, 7, 18, 33, 11)
                .unwrap()
                .with_nanosecond(120_000_000)
                .unwrap(),
        );
        let mut st = SessionState::new();
        st.last_checked_at = Some(clock.now());
        st.next_check_at = Some(clock.now());
        save_state(dir.to_str().unwrap(), &st).expect("saves");
        let text = saved_state_text(&dir);
        assert!(
            text.contains("2026-11-07T18:33:11.12+07:00"),
            "state write must render .12 like Go, got:\n{text}"
        );
        assert!(
            !text.contains(".120+07:00"),
            "state write must not render .120, got:\n{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offset_minutes_61_to_99_are_corrupt() {
        // Fix loop 1, B2: Go rejects offset minutes 61–99
        // ("time zone offset minute out of range"); only
        // mm==60 carries (`+07:60` -> `+08:00`).
        for bad in [
            "2026-11-07T18:33:11+07:61",
            "2026-11-07T18:33:11+07:75",
            "2026-11-07T18:33:11+07:99",
            "2026-11-07T18:33:11-07:61",
        ] {
            let dir = tmpdir();
            write_raw_state(
                &dir,
                &format!("{{\"version\":1,\"next_check_at\":\"{bad}\"}}"),
            );
            assert!(
                matches!(
                    load_state(dir.to_str().unwrap()),
                    Err(KeeperError::StateCorrupt(_))
                ),
                "{bad} must be corrupt"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn go_strict_offset_shape_and_end_of_input_are_corrupt() {
        // Fix loop 1, B3+B4: the offset must be exactly `Z`
        // or `±HH:MM` and then end-of-input. Go rejects
        // `+0700` (no colon), trailing text after the
        // offset, and surrounding whitespace — all of which
        // chrono's parser tolerates.
        for bad in [
            "2026-11-07T18:33:11+0700",
            "2026-11-07T18:33:11+07:00 ",
            " 2026-11-07T18:33:11+07:00",
            "2026-11-07T18:33:11+07:00:30",
            "2026-11-07T18:33:11Z ",
            // `\n` / `\t` arrive as JSON escapes and decode
            // to real whitespace before the time parser.
            "2026-11-07T18:33:11+07:00\\n",
            "2026-11-07T18:33:11+07:00\\t",
        ] {
            let dir = tmpdir();
            write_raw_state(
                &dir,
                &format!("{{\"version\":1,\"next_check_at\":\"{bad}\"}}"),
            );
            assert!(
                matches!(
                    load_state(dir.to_str().unwrap()),
                    Err(KeeperError::StateCorrupt(_))
                ),
                "{bad:?} must be corrupt"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn expiry_fields_preserve_stored_offset_like_go() {
        // Fix loop 1, B6: Go's `time.Time` keeps the
        // stored offset on unmarshal for expiry fields
        // too — a hand-edited `+07:00` expiry re-prints
        // `+07:00` in Go, not `Z`.
        let dir = tmpdir();
        write_raw_state(
            &dir,
            "{\"version\":1,\"earliest_expiry\":\"2026-12-05T07:00:00+07:00\",\"driving_expiry\":\"2026-12-05T07:00:00+07:00\",\"cookies\":{\"hatch_sess\":{\"expires_at\":\"2026-12-05T07:00:00+07:00\",\"session\":false,\"last_seen\":\"2026-11-07T18:33:11+07:00\"}}}",
        );
        let st = load_state(dir.to_str().unwrap()).expect("loads");
        save_state(dir.to_str().unwrap(), &st).expect("saves");
        let text = saved_state_text(&dir);
        assert!(
            text.contains("2026-12-05T07:00:00+07:00"),
            "expiry fields must keep the stored +07:00, got:\n{text}"
        );
        assert!(
            !text.contains("2026-12-05T00:00:00Z"),
            "the same instant must not be re-printed as Z, got:\n{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expiry_strict_spellings_match_go() {
        // Fix loop 1, B6: the legacy Utc module's
        // accept-set differs from Go's for expiry fields —
        // lowercase `z` is accepted (Go rejects),
        // `+07:60` is rejected (Go accepts -> `+08:00`),
        // and `.5` renders `.500Z` (Go renders `.5Z`).
        let dir = tmpdir();
        write_raw_state(
            &dir,
            "{\"version\":1,\"earliest_expiry\":\"2026-12-05T00:00:00z\"}",
        );
        assert!(
            matches!(
                load_state(dir.to_str().unwrap()),
                Err(KeeperError::StateCorrupt(_))
            ),
            "lowercase z expiry must be corrupt"
        );
        let dir = tmpdir();
        write_raw_state(
            &dir,
            "{\"version\":1,\"earliest_expiry\":\"2026-12-05T00:00:00+07:60\"}",
        );
        let st = load_state(dir.to_str().unwrap()).expect("loads +07:60 expiry");
        save_state(dir.to_str().unwrap(), &st).expect("saves");
        assert!(
            saved_state_text(&dir).contains("2026-12-05T00:00:00+08:00"),
            "+07:60 expiry must carry to +08:00, got:\n{}",
            saved_state_text(&dir)
        );
        let _ = std::fs::remove_dir_all(&dir);
        let dir = tmpdir();
        write_raw_state(
            &dir,
            "{\"version\":1,\"earliest_expiry\":\"2026-12-05T00:00:00.5Z\"}",
        );
        let st = load_state(dir.to_str().unwrap()).expect("loads .5 expiry");
        save_state(dir.to_str().unwrap(), &st).expect("saves");
        assert!(
            saved_state_text(&dir).contains("2026-12-05T00:00:00.5Z"),
            ".5 expiry must render .5Z, got:\n{}",
            saved_state_text(&dir)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
