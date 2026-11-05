// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Guarded config writes (`internal/profile/guard.go`:
//! `LoadConfigState`, `ConfigState.Save`,
//! `UpdateSingleConfig`, `lockConfigDir`,
//! `writeSingleConfigLocked`).
//!
//! Every guarded write holds, for the whole
//! read-modify-write:
//! - `configWriteMu`, the in-process mutex (Go uses ONE
//!   global mutex for all directories — this module does
//!   the same, so the serialisation matches), and
//! - an inter-process flock (LOCK_EX, blocking) on
//!   `baseDir/config.json.lock`, created mode 0600. The lock
//!   file is never deleted: deleting it would let a later
//!   opener lock a different inode while an earlier holder
//!   still holds the old one.
//!
//! Checked writes record the sha256 of the bytes read and
//! re-read under the lock before writing: if the file
//! changed since the load (created, deleted, or different
//! bytes), the write is refused with a concurrent-change
//! (409 at the API layer) and the file is left untouched.
//! The write itself is a temp file + rename, mode 0600.
//!
//! Reads take no lock: a read racing a write sees either
//! the old or the new atomic rename, never a torn file.

use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// In-process write mutex, mirroring Go's global
/// `configWriteMu`. One mutex for all directories.
static CONFIG_WRITE_MU: Mutex<()> = Mutex::new(());

/// Lowercase hex sha256 of `data` (`sha256Hex`).
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sum = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in sum {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `readRegularFile`: stat the path; a missing file is
/// `None`; a directory or non-regular file is an error
/// (a FIFO swapped in for the file must not hang the read).
pub fn read_regular_file(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::metadata(path) {
        Ok(md) => {
            if !md.is_file() {
                if md.is_dir() {
                    return Err(format!(
                        "profile: config path {path:?} is a directory, not a file"
                    ));
                }
                return Err(format!(
                    "profile: config path {path:?} is not a regular file"
                ));
            }
            std::fs::read(path)
                .map(Some)
                .map_err(|e| format!("profile: read config: {e}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("profile: read config: {e}")),
    }
}

/// One load-time snapshot of `baseDir/config.json` for a
/// checked write (`ConfigState`).
#[derive(Debug, Clone)]
pub struct ConfigState {
    /// A parseable single file existed at load.
    pub found: bool,
    /// `config.json` existed at load in any form (single
    /// file or legacy-flat). Found implies exists.
    pub exists: bool,
    /// Lowercase hex sha256 of the raw bytes read at load,
    /// or "" when the file was absent.
    pub sha256: String,
    /// Raw bytes read at load (empty when absent).
    pub raw: Vec<u8>,
    /// Base directory this state was loaded from.
    pub base_dir: PathBuf,
}

impl ConfigState {
    /// `LoadConfigState`: read once, record the sha256.
    /// Found=false when the file is absent or is a
    /// legacy-flat config; an error when a single file is
    /// present but unparseable (never a silent fallback).
    /// Marker/parse errors carry the `profile: ` prefix
    /// already; callers wrap them as
    /// `stored config is invalid: ...`.
    pub fn load(base_dir: &Path) -> Result<ConfigState, String> {
        let path = base_dir.join("config.json");
        let data = match read_regular_file(&path)? {
            Some(data) => data,
            None => {
                return Ok(ConfigState {
                    found: false,
                    exists: false,
                    sha256: String::new(),
                    raw: Vec::new(),
                    base_dir: base_dir.to_path_buf(),
                });
            }
        };
        let sha = sha256_hex(&data);
        let marker = castctl_config::config::has_profiles_marker(&data).map_err(|e| e.message)?;
        if !marker {
            return Ok(ConfigState {
                found: false,
                exists: true,
                sha256: sha,
                raw: data,
                base_dir: base_dir.to_path_buf(),
            });
        }
        // Marker present: the file must parse.
        let _cfg = castctl_config::config::parse_single_config(&data, &base_dir.to_string_lossy())
            .map_err(|e| e.message)?;
        Ok(ConfigState {
            found: true,
            exists: true,
            sha256: sha,
            raw: data,
            base_dir: base_dir.to_path_buf(),
        })
    }

    /// `ConfigState.Save`: write `data` (already encoded)
    /// under the lock, refusing when the file changed since
    /// the load. Returns the new sha256 on success and
    /// refreshes this state to the just-written bytes, so
    /// the same state can be Saved again. A concurrent
    /// change maps to 409 at the API layer.
    pub fn save(&mut self, data: &[u8]) -> Result<String, SaveError> {
        let _guard = CONFIG_WRITE_MU.lock().map_err(|_| SaveError::Internal)?;
        let _lock = acquire_flock(&self.base_dir)?;
        let current = ConfigState::load(&self.base_dir).map_err(|_| SaveError::Internal)?;
        if current.exists != self.exists
            || current.found != self.found
            || current.sha256 != self.sha256
        {
            return Err(SaveError::ConcurrentChange);
        }
        let hash = write_file_atomic(&self.base_dir.join("config.json"), data)
            .map_err(|_| SaveError::Internal)?;
        self.exists = true;
        self.found = true;
        self.sha256 = hash.clone();
        self.raw = data.to_vec();
        Ok(hash)
    }
}

/// Save failure classes: a concurrent change (409) or an
/// internal error (500). Lock/IO failures are internal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveError {
    ConcurrentChange,
    Internal,
}

/// Acquire the inter-process flock on
/// `baseDir/config.json.lock` (created mode 0600 when
/// missing). Returns the open file; closing it releases
/// the flock. The caller must already hold the in-process
/// mutex. Fails closed on any error (Go fails closed on
/// non-unix targets too).
pub fn acquire_flock(base_dir: &Path) -> Result<std::fs::File, SaveError> {
    std::fs::create_dir_all(base_dir).map_err(|_| SaveError::Internal)?;
    let lock_path = base_dir.join("config.json.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&lock_path)
        .map_err(|_| SaveError::Internal)?;
    #[cfg(unix)]
    {
        // Go's OpenFile passes 0600 on creation; enforce it
        // here too (the umask would otherwise leave 0644).
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(SaveError::Internal);
        }
    }
    #[cfg(not(unix))]
    {
        return Err(SaveError::Internal);
    }
    Ok(file)
}

/// `writeFileAtomic`: temp file in the same directory
/// (mode 0600) + fsync + rename. The temp name carries the
/// process id so concurrent writers never collide.
pub fn write_file_atomic(path: &Path, data: &[u8]) -> Result<String, String> {
    let dir = path
        .parent()
        .ok_or_else(|| "no parent directory".to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp_name = format!(".config.json.tmp.{}", std::process::id());
    let tmp_path = dir.join(tmp_name);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        f.write_all(data).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        e.to_string()
    })?;
    Ok(sha256_hex(data))
}

/// `UpdateSingleConfig`-style guarded read-modify-write:
/// under one lock hold, load the current document bytes,
/// run `update` (which returns `Some(new_bytes)` to write,
/// or `None` to write nothing), re-read the bytes to
/// confirm nothing changed under the lock, and write.
/// Returns the new sha256 when written. Used by the
/// hash-on-start path.
pub fn guarded_update<F>(base_dir: &Path, update: F) -> Result<Option<String>, SaveError>
where
    F: FnOnce(&[u8]) -> Result<Option<Vec<u8>>, String>,
{
    let _guard = CONFIG_WRITE_MU.lock().map_err(|_| SaveError::Internal)?;
    let _lock = acquire_flock(base_dir)?;
    let state = ConfigState::load(base_dir).map_err(|_| SaveError::Internal)?;
    let new_bytes = update(&state.raw).map_err(|_| SaveError::Internal)?;
    let Some(bytes) = new_bytes else {
        return Ok(None);
    };
    let current = match read_regular_file(&base_dir.join("config.json")) {
        Ok(Some(data)) => data,
        Ok(None) => Vec::new(),
        Err(_) => return Err(SaveError::Internal),
    };
    if sha256_hex(&current) != sha256_hex(&state.raw) {
        return Err(SaveError::ConcurrentChange);
    }
    let hash = write_file_atomic(&base_dir.join("config.json"), &bytes)
        .map_err(|_| SaveError::Internal)?;
    Ok(Some(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn atomic_write_is_0600_and_renames() {
        let dir = tmpdir("castctl-webui-guarded-test");
        let path = dir.join("config.json");
        let hash = write_file_atomic(&path, b"{\"a\": 1}\n").unwrap();
        assert_eq!(hash, sha256_hex(b"{\"a\": 1}\n"));
        assert_eq!(fs::read(&path).unwrap(), b"{\"a\": 1}\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // No temp file left behind.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_refuses_concurrent_change() {
        let dir = tmpdir("castctl-webui-guarded-cc");
        let path = dir.join("config.json");
        fs::write(&path, b"{\"profiles\":{}}\n").unwrap();
        let mut state = ConfigState::load(&dir).unwrap();
        assert!(state.found);
        // Another writer changes the file under us.
        fs::write(&path, b"{\"profiles\":{},\"default_profile\":\"x\"}\n").unwrap();
        let err = state.save(b"{\"profiles\":{}}\n").unwrap_err();
        assert_eq!(err, SaveError::ConcurrentChange);
        // The file is untouched by the refused save.
        assert_eq!(
            fs::read(&path).unwrap(),
            b"{\"profiles\":{},\"default_profile\":\"x\"}\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_succeeds_and_refreshes_state() {
        let dir = tmpdir("castctl-webui-guarded-ok");
        let path = dir.join("config.json");
        fs::write(&path, b"{\"profiles\":{}}\n").unwrap();
        let mut state = ConfigState::load(&dir).unwrap();
        let hash = state
            .save(b"{\"profiles\":{},\"default_profile\":\"p\"}\n")
            .unwrap();
        assert_eq!(hash, state.sha256);
        assert_eq!(
            fs::read(&path).unwrap(),
            b"{\"profiles\":{},\"default_profile\":\"p\"}\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fail_before_flock() {
        // If the flock were dropped, two writers could
        // interleave read-modify-write and the second save
        // would silently clobber the first. The
        // concurrent-change check above is the observable
        // guard; this test pins the lock file's existence
        // and mode after a save.
        let dir = tmpdir("castctl-webui-guarded-lock");
        let path = dir.join("config.json");
        fs::write(&path, b"{\"profiles\":{}}\n").unwrap();
        let mut state = ConfigState::load(&dir).unwrap();
        let _ = state.save(b"{\"profiles\":{}}\n").unwrap();
        let lock = dir.join("config.json.lock");
        assert!(lock.exists(), "lock file must exist after a save");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
