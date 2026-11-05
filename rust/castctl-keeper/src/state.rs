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
//! not. Profile and cookie names are charset-validated at
//! parse time and cannot contain them, so no byte differs
//! in practice; the deviation is recorded, not worked
//! around.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::error::KeeperError;
use crate::jar::{StoredCookie, driving_cookie, earliest_expiry};
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

/// RFC 3339 serde for `DateTime<Utc>` / `Option<DateTime<Utc>>`
/// (chrono has no `serde` feature enabled in this workspace,
/// so the impl is hand-written; the wire form is Go
/// `time.Time` JSON: RFC 3339 with nanoseconds).
pub mod rfc3339 {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(v: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&v.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        s.parse::<DateTime<Utc>>().map_err(serde::de::Error::custom)
    }

    pub mod opt {
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(v: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match v {
                Some(v) => {
                    s.serialize_some(&v.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
                }
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(d: D) -> Result<Option<DateTime<Utc>>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt = Option::<String>::deserialize(d)?;
            match opt {
                Some(s) => s
                    .parse::<DateTime<Utc>>()
                    .map(Some)
                    .map_err(serde::de::Error::custom),
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
        with = "rfc3339::opt"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    /// Session cookie (no expiry).
    pub session: bool,
    /// Last time this cookie was seen.
    #[serde(with = "rfc3339")]
    pub last_seen: DateTime<Utc>,
}

/// One per-kind dedup record (`state.go:167-171`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarnedKind {
    /// Whether the notice for this kind was sent during the
    /// current episode.
    pub sent: bool,
    /// When it was sent.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::opt"
    )]
    pub at: Option<DateTime<Utc>>,
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
    /// Last tick time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::opt"
    )]
    pub last_checked_at: Option<DateTime<Utc>>,
    /// Last tick outcome (closed enum; never `"error"`).
    #[serde(default)]
    pub last_tick_outcome: String,
    /// Tick stage of the last outcome: `""`, `"session"`,
    /// `"auth_check"`, `"export"`, or `"save"`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_tick_stage: String,
    /// Per-cookie observed records, keyed by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cookies: BTreeMap<String, CookieState>,
    /// Earliest expiry in the set.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::opt"
    )]
    pub earliest_expiry: Option<DateTime<Utc>>,
    /// Name of the driving cookie.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub driving_cookie: String,
    /// Expiry of the driving cookie.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::opt"
    )]
    pub driving_expiry: Option<DateTime<Utc>>,
    /// SHA-256 of the cookies file (change detection; never
    /// logged).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cookies_sha256: String,
    /// Next scheduled check.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::opt"
    )]
    pub next_check_at: Option<DateTime<Utc>>,
    /// A screencast login is in progress for this profile.
    #[serde(default, skip_serializing_if = "is_false")]
    pub login_active: bool,
    /// The login session's opaque id (not a secret).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub login_session_id: String,
    /// When the login started (bounds the pause).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::opt"
    )]
    pub login_started_at: Option<DateTime<Utc>>,
    /// Login provenance, written ONLY by the login flow.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub login_user_agent: String,
    /// Login provenance (browser product string).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub login_chromium_version: String,
    /// When the login saved cookies.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::opt"
    )]
    pub login_at: Option<DateTime<Utc>>,
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
    /// When the last notice was sent.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::opt"
    )]
    pub warned_at: Option<DateTime<Utc>>,
    /// Per-(incident, kind) dedup record: the
    /// episode-scoped authority.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
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
    pub fn mark_warn_pending(&mut self, kind: NoticeKind, _now: DateTime<Utc>) -> bool {
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
    pub fn mark_warn_sent(&mut self, kind: NoticeKind, now: DateTime<Utc>) {
        self.warned_kinds.insert(
            kind.as_str().to_string(),
            WarnedKind {
                sent: true,
                at: Some(now),
            },
        );
        self.warn_pending = false;
        self.warn_sent = true;
        self.warn_kind = kind.as_str().to_string();
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
    pub fn refresh_cookie_records(&mut self, cookies: &[StoredCookie], now: DateTime<Utc>) {
        let mut map: BTreeMap<String, CookieState> = BTreeMap::new();
        for c in cookies {
            let rec = CookieState {
                expires_at: if c.is_session() {
                    None
                } else {
                    Some(
                        chrono::TimeZone::timestamp_opt(&Utc, c.expires, 0)
                            .single()
                            .expect("valid epoch"),
                    )
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
    // os.CreateTemp with ".session-state-*.tmp").
    let tmp_name = format!(
        ".session-state-{}.tmp",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let tmp_path = dir.join(tmp_name);
    {
        let mut tmp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        tmp.write_all(data.as_bytes())?;
        tmp.sync_all()?;
        tmp.set_permissions(std::fs::Permissions::from_mode(0o600))?;
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

    fn tmpdir() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir()
            .join(format!("castctl-keeper-state-test-{}-{}", std::process::id(), n));
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
        st.mark_warn_pending(NoticeKind::LoggedOut, Utc::now());
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
    fn warn_dedup_episode() {
        let now = Utc.with_ymd_and_hms(2026, 11, 5, 0, 0, 0).unwrap();
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
}
