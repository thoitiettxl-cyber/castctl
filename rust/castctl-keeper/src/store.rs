// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Locked cookies + state store — port of
//! `internal/keeper/store.go` (`Store`, `LockedStore`).
//!
//! The store owns the cookies file's lock and the session
//! state on disk. The lock is held only for a short
//! read-modify-write window (`DefaultLockTimeout = 5s`):
//! a lock acquisition that exceeds it is a hard error, not
//! a wait. The state-only lock (`lock_state_only`) omits
//! the cookies-file lock, so a corrupted or missing cookies
//! file can never block a recovery write.

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::KeeperError;
use crate::jar::{StoredCookie, parse_cookies_lenient, parse_jar, serialize_jar};
use crate::lockfile::{LockGuard, ensure_profile_dir, lock_cookies_file, write_cookies_file};
use crate::state::{SessionState, load_state, save_state, sha256_hex, state_path};

/// The store for one keeper entry: its profile paths and
/// lock timeout (`store.go:30-41`). The profile and entry
/// data is resolved at construction; the lock is taken per
/// operation.
pub struct Store {
    /// Base dir for the default profile (profile dir for
    /// named profiles).
    pub base_dir: String,
    /// Profile name (`"default"` for the default profile).
    pub profile_name: String,
    /// Profile directory (holds the state file).
    pub profile_dir: String,
    /// Absolute cookies-file path.
    pub cookies_path: String,
    /// Timeout for one cookies-file lock hold attempt.
    pub lock_timeout: Duration,
}

impl Store {
    /// Create a store for one profile (`store.go:43-86`).
    /// `cookies_path` is the profile's resolved cookies
    /// file, or empty for the profile default. `lock_timeout`
    /// is bounded to `DefaultLockTimeout` (5s) when zero or
    /// negative.
    pub fn new(
        base_dir: &str,
        profile_name: &str,
        cookies_path: &str,
        lock_timeout: Duration,
    ) -> Result<Self, KeeperError> {
        let paths = castctl_config::profile::profile_paths(base_dir, profile_name)?;
        let cookies = if cookies_path.is_empty() {
            paths.cookies
        } else {
            cookies_path.to_string()
        };
        let lock_timeout = if lock_timeout.is_zero() {
            crate::state::DEFAULT_LOCK_TIMEOUT
        } else {
            lock_timeout
        };
        Ok(Self {
            base_dir: base_dir.to_string(),
            profile_name: profile_name.to_string(),
            profile_dir: paths.dir,
            cookies_path: cookies,
            lock_timeout,
        })
    }

    /// Lock the cookies file, then read state and cookies
    /// under the lock (`store.go:88-150`). The locked
    /// store's `state` is a live copy: `save_jar` persists
    /// it together with the cookies bytes.
    pub fn lock(&self) -> Result<LockedStore<'_>, KeeperError> {
        let guard = lock_cookies_file(
            &self.base_dir,
            &self.profile_name,
            &self.cookies_path,
            self.lock_timeout,
        )?;
        let (state, cookies, jar_form, is_jar, file_missing, raw, state_corrupt) =
            self.read_locked(false)?;
        Ok(LockedStore {
            store: self,
            _guard: Some(guard),
            state,
            cookies,
            jar_form,
            is_jar,
            file_missing,
            raw,
            state_corrupt,
        })
    }

    /// Lock the state only (`store.go:152-205`): no
    /// cookies-file lock, so a corrupted or missing cookies
    /// file can never block a recovery write. A missing or
    /// corrupt state file yields a fresh state with
    /// `state_corrupt = true`.
    pub fn lock_state_only(&self) -> Result<LockedStore<'_>, KeeperError> {
        let (state, cookies, jar_form, is_jar, file_missing, raw, state_corrupt) =
            self.read_locked(true)?;
        Ok(LockedStore {
            store: self,
            _guard: None,
            state,
            cookies,
            jar_form,
            is_jar,
            file_missing,
            raw,
            state_corrupt,
        })
    }

    /// Read state + cookies; `state_only` skips the cookies
    /// file entirely (still verifies the state dir exists).
    /// A missing cookies file yields an empty jar and
    /// `file_missing = true` (`store.go:88-205`).
    fn read_locked(
        &self,
        state_only: bool,
    ) -> Result<
        (
            SessionState,
            Vec<StoredCookie>,
            Vec<u8>,
            bool,
            bool,
            Vec<u8>,
            bool,
        ),
        KeeperError,
    > {
        // The state dir must exist before any read/write.
        ensure_profile_dir(&self.base_dir, &self.profile_name)
            .map_err(|e| KeeperError::StateDir(e.to_string()))?;
        let (state, state_corrupt) = match load_state(&self.profile_dir) {
            Ok(st) => (st, false),
            Err(KeeperError::StateCorrupt(_)) => (SessionState::new(), true),
            Err(e) => return Err(e),
        };
        if state_only {
            return Ok((
                state,
                Vec::new(),
                Vec::new(),
                true,
                false,
                Vec::new(),
                state_corrupt,
            ));
        }
        let raw = match read_regular_file(&self.cookies_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((
                    state,
                    Vec::new(),
                    Vec::new(),
                    true,
                    true,
                    Vec::new(),
                    state_corrupt,
                ));
            }
            Err(e) => return Err(KeeperError::Io(e)),
        };
        // A file that LOOKS like a jar (any tab, or the
        // Netscape header) is parsed strictly; a file with
        // no tabs is tried as the one-line/JSON forms; anything
        // else is corrupt: fail closed (`tick.go:456-493`).
        // An empty file is an empty jar.
        let (cookies, is_jar) = classify_cookies_file(&raw, &self.cookies_path)?;
        let jar_form = serialize_jar(&cookies);
        Ok((state, cookies, jar_form?, is_jar, false, raw, state_corrupt))
    }
}

/// Decide the stored file's form (`tick.go:456-493`). A file
/// that looks like a jar (any tab, or the Netscape header)
/// is parsed strictly: a malformed row fails closed with
/// its line number. A file with no tabs is tried as the
/// one-line/JSON forms; success means non-jar form
/// (`is_jar = false`). Anything else is corrupt: fail
/// closed. An empty file is an empty jar. Non-jar cookies
/// carry placeholder domain `muse.ai` / path `/`; on a
/// rotation write the file is converted to jar form (G5).
pub fn classify_cookies_file(
    raw: &[u8],
    path: &str,
) -> Result<(Vec<StoredCookie>, bool), KeeperError> {
    let text = String::from_utf8_lossy(raw);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok((Vec::new(), true));
    }
    if trimmed.contains('\t') || trimmed.starts_with("# Netscape") {
        let cookies = parse_jar(raw).map_err(|e| KeeperError::JarParse(e.to_string()))?;
        return Ok((cookies, true));
    }
    parse_cookies_lenient(trimmed)
        .map(|cookies| (cookies, false))
        .map_err(|e| {
            KeeperError::JarParse(format!(
                "cookies file {path} is neither a jar nor a readable one-line/JSON form: {e}"
            ))
        })
}

/// Read a regular file only after `stat` confirms it is
/// regular (following symlinks): a FIFO, socket, or device
/// at the path is refused without ever opening it
/// (`config.go:read_regular_file`).
fn read_regular_file(path: &str) -> std::io::Result<Vec<u8>> {
    let st = std::fs::metadata(path)?;
    if !st.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{path}: not a regular file"),
        ));
    }
    std::fs::read(path)
}

/// The locked store: a live copy of the state plus the
/// parsed cookies (`store.go:207-222`). The caller mutates
/// `state`/`cookies` in place, then calls `save_jar` to
/// persist.
pub struct LockedStore<'a> {
    store: &'a Store,
    _guard: Option<LockGuard>,
    /// Live copy of the session state.
    pub state: SessionState,
    /// Parsed cookies (empty when the file is missing).
    pub cookies: Vec<StoredCookie>,
    /// Canonical re-serialisation of `cookies`
    /// (serialisation is lossy: the file's original
    /// formatting is NOT preserved).
    pub jar_form: Vec<u8>,
    /// Whether the file was a jar (from
    /// `classify_cookies_file`): a non-jar file is
    /// converted to jar form only when the cheap chain
    /// rotates a cookie (G5).
    pub is_jar: bool,
    /// The cookies file did not exist when locked.
    pub file_missing: bool,
    /// The cookies file's raw bytes at lock time.
    pub raw: Vec<u8>,
    /// The state file was corrupt at lock time and was
    /// replaced by a fresh state in memory.
    pub state_corrupt: bool,
}

impl<'a> LockedStore<'a> {
    /// Whether this store holds the cookies-file lock
    /// (`state_only` stores do not).
    pub fn has_lock(&self) -> bool {
        self._guard.is_some()
    }

    /// Persist the current cookies and the current state
    /// (`store.go:224-273`). The cookies file is rewritten
    /// ONLY when the serialised jar differs from the bytes
    /// read at lock time (`raw`): a byte-identical jar is
    /// never rewritten (the stop path preserves the jar
    /// byte-identically, K-LIVE-2). The state file is
    /// ALWAYS rewritten when `save_jar` runs — callers
    /// that only read must not call it.
    pub fn save_jar(&mut self) -> Result<(), KeeperError> {
        let jar = serialize_jar(&self.cookies)?;
        if jar != self.raw {
            let _ = write_cookies_file(
                &self.store.base_dir,
                &self.store.profile_name,
                &self.store.cookies_path,
                &jar,
            )?;
            self.raw = jar.clone();
            self.jar_form = jar;
        }
        self.state.cookies_sha256 = sha256_hex(&self.raw);
        self.save_state()
    }

    /// Persist the state file only (no cookies write).
    pub fn save_state(&mut self) -> Result<(), KeeperError> {
        save_state(&self.store.profile_dir, &self.state)
    }

    /// The state file path (for diagnostics).
    pub fn state_file_path(&self) -> String {
        state_path(&self.store.profile_dir).display().to_string()
    }

    /// The cookies file path.
    pub fn cookies_file_path(&self) -> &str {
        &self.store.cookies_path
    }
}

/// Current time helper for callers that need `now` without
/// a clock trait.
pub fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jar::StoredCookie;

    fn tmpbase() -> String {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir()
            .join(format!("castctl-keeper-store-test-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&p).unwrap();
        p.to_str().unwrap().to_string()
    }

    #[test]
    fn lock_missing_file_then_save_creates() {
        let base = tmpbase();
        let store = Store::new(&base, "default", "", Duration::from_secs(5)).unwrap();
        let mut ls = store.lock().expect("lock");
        assert!(ls.file_missing);
        assert!(ls.cookies.is_empty());
        ls.cookies.push(StoredCookie {
            domain: ".muse.ai".to_string(),
            path: "/".to_string(),
            secure: true,
            http_only: false,
            expires: 1_800_000_000,
            name: "hatch_sess".to_string(),
            value: "v".to_string(),
        });
        ls.state.last_tick_outcome = crate::state::OUTCOME_OK.to_string();
        ls.save_jar().expect("save");
        let raw = std::fs::read(store.cookies_path.clone()).unwrap();
        assert!(String::from_utf8(raw).unwrap().contains("hatch_sess"));
        drop(ls);
        let back = store.lock().expect("re-lock");
        assert!(!back.file_missing);
        assert_eq!(back.cookies.len(), 1);
        assert_eq!(back.state.last_tick_outcome, crate::state::OUTCOME_OK);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn save_jar_no_write_when_unchanged() {
        let base = tmpbase();
        let store = Store::new(&base, "default", "", Duration::from_secs(5)).unwrap();
        let mut ls = store.lock().expect("lock");
        ls.cookies.push(StoredCookie {
            domain: ".muse.ai".to_string(),
            path: "/".to_string(),
            secure: true,
            http_only: false,
            expires: 1_800_000_000,
            name: "hatch_sess".to_string(),
            value: "v".to_string(),
        });
        ls.save_jar().expect("save");
        let mtime1 = std::fs::metadata(store.cookies_path.clone())
            .unwrap()
            .modified()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        drop(ls);
        let mut ls2 = store.lock().expect("re-lock");
        ls2.save_jar().expect("save again (no cookie change)");
        let mtime2 = std::fs::metadata(store.cookies_path.clone())
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(mtime1, mtime2, "byte-identical jar is never rewritten");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn non_jar_file_is_hard_error() {
        let base = tmpbase();
        let store = Store::new(&base, "default", "", Duration::from_secs(5)).unwrap();
        std::fs::create_dir_all(&store.profile_dir).unwrap();
        std::fs::write(store.cookies_path.clone(), b"not a jar\n").unwrap();
        assert!(matches!(store.lock(), Err(KeeperError::JarParse(_))));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn lock_state_only_recovers_from_corrupt_cookies() {
        let base = tmpbase();
        let store = Store::new(&base, "default", "", Duration::from_secs(5)).unwrap();
        std::fs::create_dir_all(&store.profile_dir).unwrap();
        std::fs::write(store.cookies_path.clone(), b"not a jar\n").unwrap();
        let mut ls = store.lock_state_only().expect("state-only lock");
        assert!(!ls.has_lock());
        ls.state.last_tick_outcome = crate::state::OUTCOME_SKIPPED.to_string();
        ls.save_state().expect("state save works without cookies");
        let _ = std::fs::remove_dir_all(&base);
    }
}
