// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Non-blocking advisory file lock for updates.
//!
//! Go source: `acquireUpdateLock` (`internal/update/lock_unix.go`,
//! unix build). The lock file is `<dir>/.castctl-update.lock`.
//! It is never deleted (deleting it would race a concurrent
//! opener). Closing the file releases the flock, including on
//! SIGKILL. A lock path that is a symlink, or whose identity
//! changes between Lstat and open, refuses (G-75). The
//! identity re-check narrows but does not close the
//! check-to-flock window (`lock_unix.go:21-27`) — that
//! residual is kept, not "fixed", per the decision rules.
//!
//! Flock choice (R3 §3.3): `libc::flock` directly, not
//! `fslock` 0.2.1 or `nix` 0.31.3. Reason: the Go code needs
//! (a) the raw fd for the EINTR-retry loop and the
//! EWOULDBLOCK → held distinction, (b) the Lstat-vs-fstat
//! identity re-check on the same fd, and (c) close-to-
//! release semantics — all three are one `libc::flock` call
//! plus std metadata, with no wrapper API to verify.
//! `libc` 0.2.191 is already in `Cargo.lock` (via `nix`).

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::error::UpdateError;

/// Lock file name in the target directory.
/// Source: `lockFileName` (`internal/update/replace.go:27`).
pub const LOCK_FILE_NAME: &str = ".castctl-update.lock";

/// A held update lock. Dropping it closes the file, which
/// releases the flock. The file is never deleted.
/// Source: `acquireUpdateLock` (`internal/update/lock_unix.go:36-60`).
pub struct UpdateLock {
    _file: File,
    /// The lock path, for diagnostics (never rendered to the user).
    path: PathBuf,
}

impl UpdateLock {
    /// The lock file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Outcome of [`acquire_update_lock`].
pub enum LockOutcome {
    /// The lock is held by this caller.
    Held(UpdateLock),
    /// Another update holds the lock: fail fast, do not wait.
    AlreadyHeld,
}

/// Take a non-blocking advisory flock on
/// `<dir>/.castctl-update.lock`.
///
/// Source: `acquireUpdateLock` (`internal/update/lock_unix.go:29-60`).
/// Errors: symlink → `"update lock file is a symlink"`;
/// identity change → `"update lock file changed during open"`.
pub fn acquire_update_lock(dir: &Path) -> Result<LockOutcome, UpdateError> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join(LOCK_FILE_NAME);
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if meta.file_type().is_symlink() {
            return Err(UpdateError::failure("update lock file is a symlink"));
        }
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| {
            UpdateError::failure(format!("update: cannot lock the update directory: {e}"))
        })?;
    // Identity re-check: the opened file must be the path's file.
    let after = std::fs::symlink_metadata(&path).map_err(|e| {
        UpdateError::failure(format!("update: cannot lock the update directory: {e}"))
    })?;
    let opened = file.metadata().map_err(|e| {
        UpdateError::failure(format!("update: cannot lock the update directory: {e}"))
    })?;
    if after.dev() != opened.dev() || after.ino() != opened.ino() {
        return Err(UpdateError::failure(
            "update lock file changed during open",
        ));
    }
    use std::os::unix::io::AsRawFd;
    loop {
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(LockOutcome::Held(UpdateLock {
                _file: file,
                path,
            }));
        }
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(0);
        if errno == libc::EINTR {
            continue;
        }
        if errno == libc::EWOULDBLOCK {
            return Ok(LockOutcome::AlreadyHeld);
        }
        return Err(UpdateError::failure(format!(
            "update: cannot lock the update directory: {errno}"
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Port of `TestLockHeldFailsFast` (fs half)
    /// (`internal/update/edge_test.go:615-635`): a held lock
    /// makes a second acquire fail fast with `AlreadyHeld`.
    #[test]
    fn lock_held_fails_fast() {
        let dir = tempfile::tempdir().unwrap();
        let first = acquire_update_lock(dir.path()).unwrap();
        assert!(matches!(first, LockOutcome::Held(_)));
        let second = acquire_update_lock(dir.path()).unwrap();
        assert!(matches!(second, LockOutcome::AlreadyHeld));
        drop(first);
        // After release, the lock is acquirable again.
        assert!(matches!(
            acquire_update_lock(dir.path()).unwrap(),
            LockOutcome::Held(_)
        ));
    }

    /// Port of `TestLockSymlinkRefuses`
    /// (`edge_test.go:636-654`): a symlinked lock file refuses.
    #[test]
    fn lock_symlink_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"x").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join(LOCK_FILE_NAME)).unwrap();
        assert_eq!(
            acquire_update_lock(dir.path()).unwrap_err().to_string(),
            "update lock file is a symlink"
        );
    }

    /// The lock file is created 0600 and never deleted.
    #[test]
    fn lock_file_created_0600_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let held = acquire_update_lock(dir.path()).unwrap();
        let path = dir.path().join(LOCK_FILE_NAME);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(held);
        // Still there after release: never deleted.
        assert!(path.exists());
    }
}
