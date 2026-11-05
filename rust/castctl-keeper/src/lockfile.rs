// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Cookies-file lock + atomic write — port of
//! `internal/profile/cookielock.go` and
//! `internal/profile/cookies.go` (the two keeper-adjacent
//! helpers; the keeper itself only calls them).
//!
//! Rules (Go):
//! - The lock file is `cookiesPath + ".lock"`, created mode
//!   0600, NEVER deleted (deleting it would let a later
//!   opener lock a different inode while an earlier holder
//!   still holds the old one). The lock is an inter-process
//!   flock on the lock file; every acquisition opens the
//!   file separately (flock locks are per open file
//!   description), so it serialises within a process too.
//!   Non-blocking flock is retried every 25ms until the
//!   timeout, then `ErrCookiesLockTimeout`. A non-positive
//!   timeout means "try once". The lock is held only for a
//!   short read-modify-write window.
//! - The atomic write: durable temp file (0600) first, then
//!   copy the existing destination to `.bak`, then rename
//!   the temp file over the destination. The destination is
//!   never absent. Both the cookies file and `.bak` end at
//!   mode 0600, except when the previous file was a symlink:
//!   then `.bak` remains that symlink (no copy, no chmod)
//!   and only the new cookies file ends at 0600. No previous
//!   file means no `.bak` and `backup == false`. No lock is
//!   taken here — the keeper always holds the lock outside.
//! - Parent-directory rules: the default path goes through
//!   `EnsureProfileDir` (0700); any other path inside
//!   `baseDir` gets its parent created at 0700; a path
//!   outside `baseDir` is written only when its parent
//!   already exists (fail closed).
//!
//! [DEVIATION] flock is unix-only here (`#[cfg(unix)]`);
//! on a non-unix target lock acquisition fails closed with
//! `KeeperError::Other`. Go has the same fail-closed rule
//! (`flock_other.go`).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::KeeperError;

/// The lock retry cadence (`cookielock.go:124-130`).
pub const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(25);

/// An acquired cookies-file (or short-file) lock. Dropping
/// it closes the file, which releases the flock — exactly
/// like Go's release closure (`cookielock.go`).
#[derive(Debug)]
pub struct LockGuard {
    _file: File,
}

impl LockGuard {
    /// Release the lock explicitly (dropping does the same).
    pub fn release(self) {
        drop(self);
    }
}

/// Create the profile directory with Go's `EnsureProfileDir`
/// semantics (`profile.go:113-137`): the `profiles/` parent
/// is created at 0700 when missing and NEVER chmodded
/// afterwards (S-4); the profile dir itself is created at
/// 0700 and chmodded 0700 unconditionally (Go does both).
/// Returns the profile dir path.
pub fn ensure_profile_dir(base_dir: &str, profile_name: &str) -> Result<String, KeeperError> {
    let paths = castctl_config::profile::profile_paths(base_dir, profile_name)?;
    let dir = Path::new(&paths.dir);
    if profile_name != castctl_config::profile::DEFAULT_PROFILE_NAME
        && let Some(parent) = dir.parent()
    {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(parent)
            .map_err(|e| KeeperError::StateDir(format!("{}: {}", parent.display(), e)))?;
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| KeeperError::StateDir(format!("{}: {}", dir.display(), e)))?;
    set_mode_0700(dir)?;
    Ok(paths.dir)
}

/// Temp-file name suffix: pid + a process-wide atomic
/// counter + wall-clock nanos (S-5). Nanos alone can
/// collide across processes (and across fast successive
/// calls in one process on a coarse clock); the pid and
/// counter close both windows. Go uses `os.CreateTemp`
/// (random suffix); this is the same shape without a
/// randomness dependency.
pub fn temp_suffix() -> String {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}-{}", std::process::id(), n, nanos)
}

/// Write `data` to `path` (create or truncate) with mode
/// 0600 from the moment of creation (S-1): Go uses
/// `os.CreateTemp` (0600 at creation) / `os.WriteFile`
/// with 0600. The mode applies at creation; a pre-existing
/// file keeps its mode (callers here only write files they
/// created 0600, or files under the short flock).
pub fn write_file_0600(path: &str, data: &[u8]) -> Result<(), KeeperError> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(KeeperError::Io)?;
    f.write_all(data).map_err(KeeperError::Io)?;
    f.sync_all().map_err(KeeperError::Io)?;
    Ok(())
}

fn set_mode_0700(p: &Path) -> Result<(), KeeperError> {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).map_err(KeeperError::Io)
}

/// `filepath.Rel`-style inside check (`config.go:813`):
/// `rel != "." && rel != ".." && !rel.starts_with("../")`.
fn is_inside_dir(path: &str, dir: &str) -> bool {
    let path = Path::new(path);
    let dir = Path::new(dir);
    let Ok(rel) = path.strip_prefix(dir) else {
        return false;
    };
    let rel = rel.to_string_lossy();
    !rel.is_empty() && rel != "." && rel != ".." && !rel.starts_with("../")
}

fn clean_abs(path: &str) -> String {
    // Lexical clean of an absolute path (no symlink
    // resolution, like Go's filepath.Clean).
    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            p => out.push(p),
        }
    }
    format!("/{}", out.join("/"))
}

/// Apply the parent-directory rules shared by
/// `LockCookiesFile` and `WriteCookiesFile`
/// (`cookielock.go:55-87`, `cookies.go:49-110`). Returns the
/// profile's default cookies path for the caller's
/// comparison.
fn ensure_cookies_parent(
    base_dir: &str,
    profile_name: &str,
    cookies_path: &str,
) -> Result<String, KeeperError> {
    let paths = castctl_config::profile::profile_paths(base_dir, profile_name)?;
    if cookies_path == paths.cookies {
        ensure_profile_dir(base_dir, profile_name).map_err(|e| match e {
            KeeperError::StateDir(m) => {
                KeeperError::Other(format!("cannot create profile directory: {m}"))
            }
            other => other,
        })?;
    } else if is_inside_dir(cookies_path, base_dir) {
        let parent = Path::new(cookies_path)
            .parent()
            .ok_or_else(|| KeeperError::Other("cookies path has no parent".to_string()))?;
        // Go `os.MkdirAll(..., 0o700)`: 0700 at creation
        // only, never chmod an existing parent (S-4).
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(parent)
            .map_err(KeeperError::Io)?;
    } else {
        let parent = Path::new(cookies_path)
            .parent()
            .ok_or_else(|| KeeperError::Other("cookies path has no parent".to_string()))?;
        let st = std::fs::metadata(parent).map_err(|e| {
            KeeperError::Other(format!(
                "cookies parent directory {:?}: {}",
                parent.display(),
                e
            ))
        })?;
        if !st.is_dir() {
            return Err(KeeperError::Other(format!(
                "cookies parent {:?} is not a directory",
                parent.display()
            )));
        }
    }
    Ok(paths.cookies)
}

/// Acquire the cookies-file lock for `cookies_path`
/// (already-resolved absolute path). Returns a guard the
/// caller must drop exactly once (`cookielock.go:89-131`).
pub fn lock_cookies_file(
    base_dir: &str,
    profile_name: &str,
    cookies_path: &str,
    timeout: Duration,
) -> Result<LockGuard, KeeperError> {
    if !Path::new(cookies_path).is_absolute() {
        return Err(KeeperError::Other(format!(
            "cookies path {cookies_path:?} is not absolute"
        )));
    }
    let cookies_path = clean_abs(cookies_path);
    ensure_cookies_parent(base_dir, profile_name, &cookies_path)?;
    let lock_path = format!("{cookies_path}.lock");
    // The lock file is only ever flocked, never read or
    // written: create it if missing, never truncate it.
    let f = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)?;
    acquire_flock(&f, timeout)
}

/// Acquire a short-lived exclusive flock on an arbitrary
/// file (created mode 0600 when missing)
/// (`cookielock.go:150-172`). The keeper single-flight
/// owner file's lock; it takes no lock-file suffix and never
/// deletes the file.
pub fn lock_short_file(path: &str, timeout: Duration) -> Result<LockGuard, KeeperError> {
    // As above: the file is a flock identity only, never
    // truncated.
    let f = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    acquire_flock(&f, timeout)
}

fn acquire_flock(f: &File, timeout: Duration) -> Result<LockGuard, KeeperError> {
    let deadline = Instant::now() + timeout;
    loop {
        if flock_try_exclusive(f)? {
            return Ok(LockGuard {
                _file: dup_file(f)?,
            });
        }
        if timeout.is_zero() || Instant::now() > deadline {
            return Err(KeeperError::LockTimeout);
        }
        std::thread::sleep(LOCK_RETRY_INTERVAL);
    }
}

#[cfg(unix)]
fn dup_file(f: &File) -> Result<File, KeeperError> {
    use std::os::unix::io::AsRawFd;
    let fd = unsafe { libc::dup(f.as_raw_fd()) };
    if fd < 0 {
        return Err(KeeperError::Io(std::io::Error::last_os_error()));
    }
    use std::os::unix::io::FromRawFd;
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(not(unix))]
fn dup_file(f: &File) -> Result<File, KeeperError> {
    f.try_clone().map_err(KeeperError::Io)
}

#[cfg(unix)]
fn flock_try_exclusive(f: &File) -> Result<bool, KeeperError> {
    use std::os::unix::io::AsRawFd;
    loop {
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(true);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Ok(false);
        }
        return Err(KeeperError::Io(err));
    }
}

#[cfg(not(unix))]
fn flock_try_exclusive(_f: &File) -> Result<bool, KeeperError> {
    Err(KeeperError::Other(
        "flock unavailable on this platform".to_string(),
    ))
}

/// Replace the cookies file at `cookies_path` with `data`,
/// preserving the previous file (if any) as `cookiesPath +
/// ".bak"` (`cookies.go:49-110`). Returns `true` when a
/// previous file was backed up. No lock is taken here.
pub fn write_cookies_file(
    base_dir: &str,
    profile_name: &str,
    cookies_path: &str,
    data: &[u8],
) -> Result<bool, KeeperError> {
    if !Path::new(cookies_path).is_absolute() {
        return Err(KeeperError::Other(format!(
            "cookies path {cookies_path:?} is not absolute"
        )));
    }
    let cookies_path = clean_abs(cookies_path);
    let _default_cookies = ensure_cookies_parent(base_dir, profile_name, &cookies_path)?;
    let dir = Path::new(&cookies_path)
        .parent()
        .ok_or_else(|| KeeperError::Other("cookies path has no parent".to_string()))?;
    let tmp_path = write_temp_file(dir, data)?;
    let mut backup = false;
    if let Ok(st) = std::fs::metadata(&cookies_path) {
        if st.is_dir() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(KeeperError::Other(format!(
                "cookies path {cookies_path:?} is a directory"
            )));
        }
        let bak = format!("{cookies_path}.bak");
        if let Err(e) = backup_cookies_file(&cookies_path, &bak) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
        backup = true;
    } else if let Err(e) = std::fs::metadata(&cookies_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(KeeperError::Io(e));
    }
    if let Err(e) = std::fs::rename(&tmp_path, &cookies_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(KeeperError::Io(e));
    }
    Ok(backup)
}

/// Write `data` to a temp file in `dir` (0600, fsynced) and
/// return its path. The caller renames or removes it.
fn write_temp_file(dir: &Path, data: &[u8]) -> Result<PathBuf, KeeperError> {
    let name = format!(".cookies-{}.tmp", temp_suffix());
    let path = dir.join(name);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    Ok(path)
}

fn sync_dir(dir: &Path) {
    if let Ok(f) = File::open(dir) {
        let _ = f.sync_all();
    }
}

/// Copy the previous cookies file to `bak` BEFORE the new
/// file is renamed over the destination (`cookies.go:120-194`).
fn backup_cookies_file(cookies_path: &str, bak: &str) -> Result<(), KeeperError> {
    if let Ok(st) = std::fs::metadata(bak)
        && st.is_dir()
    {
        return Err(KeeperError::Other(format!(
            "backup path {bak:?} is a directory"
        )));
    }
    let lst = std::fs::symlink_metadata(cookies_path)?;
    let dir = Path::new(bak)
        .parent()
        .ok_or_else(|| KeeperError::Other("backup path has no parent".to_string()))?;
    if lst.file_type().is_symlink() {
        let target = std::fs::read_link(cookies_path)?;
        let tmp = write_temp_file(dir, b"")?;
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(&target, &tmp).map_err(KeeperError::Io)?;
        if let Err(e) = std::fs::rename(&tmp, bak) {
            let _ = std::fs::remove_file(&tmp);
            return Err(KeeperError::Io(e));
        }
        sync_dir(dir);
        return Ok(());
    }
    let data = std::fs::read(cookies_path)?;
    let tmp = write_temp_file(dir, &data)?;
    if let Err(e) = std::fs::rename(&tmp, bak) {
        let _ = std::fs::remove_file(&tmp);
        return Err(KeeperError::Io(e));
    }
    sync_dir(dir);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpbase() -> PathBuf {
        // Unique per call: tests in one process run in parallel and
        // share the pid, so a pid-only dir races (one test deletes
        // another's files). The counter makes each dir private.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "castctl-keeper-lock-test-{}-{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn lock_timeout_when_held() {
        let base = tmpbase();
        let cookies = base.join("cookies.txt");
        let cpath = cookies.to_str().unwrap();
        let g1 = lock_cookies_file(
            base.to_str().unwrap(),
            "default",
            cpath,
            Duration::from_secs(1),
        )
        .expect("first lock");
        // Second acquisition with a short timeout fails.
        let err = lock_cookies_file(
            base.to_str().unwrap(),
            "default",
            cpath,
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(matches!(err, KeeperError::LockTimeout));
        // Try-once (zero timeout) also fails while held.
        assert!(matches!(
            lock_cookies_file(base.to_str().unwrap(), "default", cpath, Duration::ZERO),
            Err(KeeperError::LockTimeout)
        ));
        drop(g1);
        // After release it succeeds again.
        let _g2 = lock_cookies_file(
            base.to_str().unwrap(),
            "default",
            cpath,
            Duration::from_secs(1),
        )
        .expect("re-lock after release");
        // The lock file is never deleted.
        assert!(Path::new(&format!("{cpath}.lock")).exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn concurrent_write_serialised_no_loss() {
        // 8 threads x 25 writes through the lock: every
        // write is a full read-modify-write (append one
        // line), so a lost update would show as a missing
        // line. This is the `TestTickConcurrentSerialised`
        // analogue at the lock layer.
        let base = tmpbase();
        let cookies = base.join("cookies.txt");
        let cpath = cookies.to_str().unwrap().to_string();
        let base_s = base.to_str().unwrap().to_string();
        std::fs::write(&cookies, b"# Netscape HTTP Cookie File\n").unwrap();
        let mut handles = Vec::new();
        for t in 0..8 {
            let cpath = cpath.clone();
            let base_s = base_s.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..25 {
                    let _g = lock_cookies_file(&base_s, "default", &cpath, Duration::from_secs(5))
                        .expect("lock");
                    let cur = std::fs::read_to_string(&cpath).unwrap();
                    let next = format!("{cur}t{t}-i{i}\n");
                    write_cookies_file(&base_s, "default", &cpath, next.as_bytes()).expect("write");
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let final_text = std::fs::read_to_string(&cookies).unwrap();
        let lines: Vec<&str> = final_text.lines().collect();
        assert_eq!(lines.len(), 1 + 8 * 25);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn write_cookies_file_backup_and_mode() {
        let base = tmpbase();
        let cookies = base.join("cookies.txt");
        let cpath = cookies.to_str().unwrap();
        let base_s = base.to_str().unwrap();
        // First write: no previous file, no .bak.
        assert!(!write_cookies_file(base_s, "default", cpath, b"v1").unwrap());
        assert!(!Path::new(&format!("{cpath}.bak")).exists());
        // Second write: previous bytes preserved in .bak.
        assert!(write_cookies_file(base_s, "default", cpath, b"v2").unwrap());
        assert_eq!(
            std::fs::read_to_string(format!("{cpath}.bak")).unwrap(),
            "v1"
        );
        assert_eq!(std::fs::read_to_string(cpath).unwrap(), "v2");
        let mode = std::fs::metadata(cpath).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let bak_mode = std::fs::metadata(format!("{cpath}.bak"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(bak_mode, 0o600);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn short_file_lock_is_independent() {
        let base = tmpbase();
        let p = base.join("owner.json");
        let ps = p.to_str().unwrap();
        let g = lock_short_file(ps, Duration::from_secs(1)).expect("lock");
        assert!(matches!(
            lock_short_file(ps, Duration::from_millis(50)),
            Err(KeeperError::LockTimeout)
        ));
        drop(g);
        assert!(lock_short_file(ps, Duration::from_secs(1)).is_ok());
        let _ = std::fs::remove_dir_all(&base);
    }
}
