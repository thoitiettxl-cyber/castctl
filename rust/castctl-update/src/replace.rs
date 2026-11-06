// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Safe-replace helpers: ETXTBSY retry, directory sync, exec check.
//!
//! Go sources: `openForSync` / `syncDir` / `isDirSyncTolerable` /
//! `runExecCheck` / `checkVersionOutput`
//! (`internal/update/replace.go:38-72, 298-406`).

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::error::UpdateError;
use crate::semver::{Version, compare_versions, parse_version};

/// ETXTBSY retry budget for `open_for_sync`.
/// Source: `reopenRetryBudget = 200ms` (`internal/update/replace.go:42`).
pub const REOPEN_RETRY_BUDGET: Duration = Duration::from_millis(200);
/// First retry delay; doubles each time to a 20ms cap.
/// Source: `replace.go:42-72` (5ms start, doubling, 20ms max).
pub const REOPEN_RETRY_START_DELAY: Duration = Duration::from_millis(5);
/// Maximum retry delay. Source: `replace.go:42-72`.
pub const REOPEN_RETRY_MAX_DELAY: Duration = Duration::from_millis(20);

/// Linux `ETXTBSY` (text file busy), the only errno retried.
/// Source: `replace.go:38-72` (only `syscall.ETXTBSY` retries).
pub const ETXTBSY: i32 = 26;

/// Open `path` O_RDWR for the pre-rename fsync, retrying only
/// ETXTBSY until the budget expires. Any other error returns
/// immediately; exhaustion returns the last error, so callers
/// can still recognise ETXTBSY.
/// Source: `openForSync` (`internal/update/replace.go:38-72`).
///
/// The `opener` seam is the Rust equivalent of Go's `reopenOpen`
/// package variable (`replace.go:34`): tests inject failures
/// through it, production passes the real opener. The seam is
/// why the three `replace_test.go` inject tests stay portable
/// (R1 §5).
pub fn open_for_sync_with<F>(path: &Path, mut opener: F) -> std::io::Result<File>
where
    F: FnMut(&Path) -> std::io::Result<File>,
{
    let deadline = Instant::now() + REOPEN_RETRY_BUDGET;
    let mut delay = REOPEN_RETRY_START_DELAY;
    loop {
        match opener(path) {
            Ok(f) => return Ok(f),
            Err(e) => {
                if e.raw_os_error() != Some(ETXTBSY) {
                    return Err(e);
                }
                if Instant::now() + delay > deadline {
                    return Err(e);
                }
                std::thread::sleep(delay);
                delay = (delay * 2).min(REOPEN_RETRY_MAX_DELAY);
            }
        }
    }
}

/// Production `open_for_sync`: open O_RDWR.
/// Source: `reopenOpen` default (`internal/update/replace.go:34`).
pub fn open_for_sync(path: &Path) -> std::io::Result<File> {
    open_for_sync_with(path, |p| {
        std::fs::OpenOptions::new().read(true).write(true).open(p)
    })
}

/// Fsync a directory so a just-completed rename is durable.
/// Source: `syncDir` (`internal/update/replace.go:298-308`).
pub fn sync_dir(dir: &Path) -> std::io::Result<()> {
    let d = File::open(dir)?;
    d.sync_all()
}

/// Whether a directory-sync error may be tolerated, succeeding
/// silently: filesystems that return ENOTSUP/EINVAL for
/// directory fsync still hold the rename.
/// Source: `isDirSyncTolerable` (`internal/update/replace.go:310-315`).
/// On Linux `ENOTSUP` and `EOPNOTSUPP` share errno 95, so the
/// match lists `ENOTSUP` once and still covers both spellings.
/// (R1 Q5: `std::io::ErrorKind::Unsupported` does not
/// distinguish them, so raw errno is used.)
pub fn is_dir_sync_tolerable(e: &std::io::Error) -> bool {
    // On Linux `EOPNOTSUPP == ENOTSUP == 95`, so only one
    // arm is reachable; the other name is listed in the
    // doc comment above, not here, to keep the match exact.
    matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOTSUP))
}

/// Maximum `--version` output bytes.
/// Source: `maxExecOutputBytes = 64 KiB` (`internal/update/update.go:38`).
pub const MAX_EXEC_OUTPUT_BYTES: usize = 64 * 1024;

/// Exec-check timeout.
/// Source: `execCheckTimeout = 10s` (`internal/update/update.go:43`).
pub const EXEC_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Run the extracted binary with `--version` in a clean minimal
/// environment (empty env: no `LD_PRELOAD` or other injection
/// variables are inherited), closed stdin, discarded stderr,
/// capped stdout. The output must be exactly one line,
/// `castctl <version>`, equal to the target version.
/// Source: `runExecCheck` (`internal/update/replace.go:329-372`).
///
/// This executes bytes that already passed checksum
/// verification; it proves the binary runs on this machine
/// and reports the claimed version. It does NOT prove
/// provenance (see the no-signature limitation in the docs).
pub fn run_exec_check(path: &Path, want: &Version, timeout: Duration) -> Result<(), UpdateError> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(path)
        .arg("--version")
        .env_clear()
        .current_dir(path.parent().unwrap_or(Path::new(".")))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| UpdateError::failure("update: cannot execute the downloaded binary"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| UpdateError::failure("update: cannot check the downloaded binary"))?;
    // Read up to cap+1 bytes in a thread so a flooding child
    // cannot block the wait; the deadline is enforced by
    // polling `try_wait` (Go uses `CommandContext` + a pipe
    // read). The child handle is shared with the reader
    // thread: the moment the reader observes more than
    // `MAX_EXEC_OUTPUT_BYTES`, it kills the child at once
    // (Go's `cancel()` on `len(out) > maxExecOutputBytes`,
    // `replace.go:344-346`) and records `too_large`, so a
    // flood+hang child returns `too large` promptly instead
    // of waiting out the whole timeout and reporting
    // `did not answer in time` (red-team B2, fix loop 1).
    // A child detached by the candidate binary survives
    // the timeout kill (Go `replace.go:322-323`): that
    // residual is shared with Go, not fixed here.
    let child = std::sync::Arc::new(std::sync::Mutex::new(child));
    let too_large = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::channel();
    let reader_child = std::sync::Arc::clone(&child);
    let reader_too_large = std::sync::Arc::clone(&too_large);
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut read_failed = false;
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() > MAX_EXEC_OUTPUT_BYTES {
                        // Kill promptly, like Go's cancel():
                        // do not wait for the child to exit
                        // on its own (it may hang forever).
                        reader_too_large.store(true, std::sync::atomic::Ordering::SeqCst);
                        if let Ok(mut child) = reader_child.lock() {
                            let _ = child.kill();
                        }
                        break;
                    }
                }
                Err(_) => {
                    read_failed = true;
                    break;
                }
            }
        }
        let _ = tx.send((buf, read_failed));
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        let waited = child
            .lock()
            .map(|mut c| c.try_wait())
            .unwrap_or(Err(std::io::Error::other("lock poisoned")));
        match waited {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    if let Ok(mut c) = child.lock() {
                        let _ = c.kill();
                        let _ = c.wait();
                    }
                    break None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break None,
        }
    };
    // Drain the reader thread's output (it ends when the
    // pipe closes, i.e. after the child exits or is killed).
    let (out, read_failed) = rx.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
    // Go's order (`replace.go:347-372`): a cap overflow
    // cancels the context, so `ctx.Err()` is `Canceled`,
    // not `DeadlineExceeded` — `too large` wins over the
    // timeout message whenever the reader saw the flood.
    if too_large.load(std::sync::atomic::Ordering::SeqCst) || out.len() > MAX_EXEC_OUTPUT_BYTES {
        return Err(UpdateError::failure(
            "update: the downloaded binary --version output is too large",
        ));
    }
    let Some(status) = status else {
        return Err(UpdateError::failure(
            "update: the downloaded binary did not answer --version in time",
        ));
    };
    if read_failed {
        return Err(UpdateError::failure(
            "update: cannot read the downloaded binary --version output",
        ));
    }
    if !status.success() {
        return Err(UpdateError::failure(
            "update: the downloaded binary --version check failed",
        ));
    }
    check_version_output(&out, want)
}

/// Require exactly one line, `castctl <version>` optionally
/// followed by ` (<commit> <date>)`, where `<version>` parses
/// and compares equal to the target version. The parenthetical
/// is shape-only: only its surrounding parentheses are
/// checked, its content is never parsed.
/// Source: `checkVersionOutput` (`internal/update/replace.go:373-406`).
///
/// Note (coordinator decision, R1 Q4): `castctl v0.6.4` is
/// ACCEPTED, because `ParseVersion` strips the `v`.
///
/// The checks run on BYTES, not on a `str`: Go converts
/// with `string(out)` without validating UTF-8, so an
/// invalid-UTF-8 byte in the shape-only parenthetical is
/// ACCEPTED (Go's control-byte scan only refuses
/// `< 0x20` except `\n`, and `0x7f`). Only the version
/// part is converted to `str` — and there invalid UTF-8
/// refuses, matching Go, because `ParseVersion` fails on
/// it. Do NOT use `from_utf8_lossy` on the whole string:
/// it changes the length at the 256-byte boundary (Go
/// measures byte length).
pub fn check_version_output(out: &[u8], want: &Version) -> Result<(), UpdateError> {
    let fail =
        || UpdateError::failure("update: the downloaded binary does not report the target version");
    for &b in out {
        if (b < 0x20 && b != b'\n') || b == 0x7f {
            return Err(fail());
        }
    }
    // Strip one trailing '\n', then require a single
    // line of at most 256 BYTES.
    let s = out.strip_suffix(b"\n").unwrap_or(out);
    if s.contains(&b'\n') || s.is_empty() || s.len() > 256 {
        return Err(fail());
    }
    let Some(rest) = s.strip_prefix(b"castctl ") else {
        return Err(fail());
    };
    let mut ver_bytes = rest;
    if let Some(i) = rest.iter().position(|&b| b == b' ') {
        ver_bytes = &rest[..i];
        let tail = &rest[i..];
        if !tail.starts_with(b" (") || !tail.ends_with(b")") {
            return Err(fail());
        }
    }
    // Only the version part becomes a `str`: invalid
    // UTF-8 here refuses, like Go's `ParseVersion`.
    let ver_str = std::str::from_utf8(ver_bytes).map_err(|_| fail())?;
    let got = parse_version(ver_str).map_err(|_| fail())?;
    if compare_versions(&got, want) != 0 {
        return Err(fail());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    fn want() -> Version {
        parse_version("0.6.4").unwrap()
    }

    /// Port of `TestOpenForSyncNonBusyErrorReturnsImmediately`
    /// (`internal/update/replace_test.go:47-63`): EACCES → 1
    /// attempt, no retry.
    #[test]
    fn open_for_sync_non_busy_error_returns_immediately() {
        let mut attempts = 0;
        let err = open_for_sync_with(Path::new("/nonexistent"), |_| {
            attempts += 1;
            Err(std::io::Error::from_raw_os_error(libc::EACCES))
        })
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert_eq!(err.raw_os_error(), Some(libc::EACCES));
    }

    /// Port of `TestOpenForSyncExhaustionReturnsBusy`
    /// (`replace_test.go:65-81`): always ETXTBSY → retries
    /// more than once, then returns ETXTBSY.
    #[test]
    fn open_for_sync_exhaustion_returns_busy() {
        let mut attempts = 0;
        let err = open_for_sync_with(Path::new("/nonexistent"), |_| {
            attempts += 1;
            Err(std::io::Error::from_raw_os_error(ETXTBSY))
        })
        .unwrap_err();
        assert!(attempts > 1, "attempts={attempts}");
        assert_eq!(err.raw_os_error(), Some(ETXTBSY));
    }

    /// Port of `TestOpenForSyncRetriesBusyThenSucceeds`
    /// (`replace_test.go:20-45`): 3× ETXTBSY then success →
    /// exactly 4 attempts.
    #[test]
    fn open_for_sync_retries_busy_then_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let mut attempts = 0;
        let f = open_for_sync_with(&path, |p| {
            attempts += 1;
            if attempts <= 3 {
                return Err(std::io::Error::from_raw_os_error(ETXTBSY));
            }
            std::fs::OpenOptions::new().read(true).write(true).open(p)
        })
        .unwrap();
        drop(f);
        assert_eq!(attempts, 4);
    }

    /// Port of `TestCheckVersionOutput`
    /// (`internal/update/edge_test.go:766-802`, want `0.6.4`):
    /// 17 cases + the coordinator-decided `v`-prefix accept.
    #[test]
    fn check_version_output_table() {
        let cases: &[(&[u8], bool)] = &[
            (b"castctl 0.6.4\n", true),
            (b"castctl 0.6.4 (deadbeef 2026-01-01T00:00:00Z)\n", true),
            (b"castctl 0.6.4", true),
            (b"castctl 0.6.3\n", false),
            (b"castctl 9.9.9 (x y)\n", false),
            (b"castctl 0.6.4-rc.1\n", false),
            (b"castctl 0.6.4\ninjected\n", false),
            (b"hello\ncastctl 0.6.4\n", false),
            (b"castctl 0.6.4\x1b[31m\n", false),
            (b"castctl 0.6.4\x00\n", false),
            (b"", false),
            (b"0.6.4\n", false),
            (b"castctl 0.6.4-evil\n", false),
            (b"castctl 0.6.4 \n", false),
            (b"castctl 0.6.4 (unclosed\n", false),
            (b"castctl 0.6.4+build\n", true),
            // Q4 (coordinator decision): `v`-prefix accepts.
            (b"castctl v0.6.4\n", true),
            // Red-team B1 (fix loop 1): Go accepts invalid
            // UTF-8 in the shape-only parenthetical
            // (`string(out)` never validates UTF-8) but
            // refuses it in the version part (`ParseVersion`
            // fails). Both probed against Go verbatim.
            (b"castctl 0.6.4 (\xff)\n", true),
            (b"castctl 0.6.4 (caf\xe9)\n", true),
            (b"castctl 0.6.4\xff\n", false),
            (b"castctl 0.6.4 (\xff", false),
        ];
        for (out, want_ok) in cases {
            let got = check_version_output(out, &want()).is_ok();
            assert_eq!(got, *want_ok, "output {out:?}");
        }
        // > 256 bytes refuses.
        let mut long = b"castctl ".to_vec();
        long.extend(std::iter::repeat_n(b'x', 300));
        long.push(b'\n');
        assert!(check_version_output(&long, &want()).is_err());
        // The 256-byte boundary is measured in BYTES,
        // even with invalid UTF-8 in the parenthetical:
        // exactly 256 accepts, 257 refuses on length
        // alone (the extra byte stays inside the parens,
        // so shape still passes).
        let mut edge = b"castctl 0.6.4 (".to_vec();
        edge.extend(std::iter::repeat_n(0xff, 256 - edge.len() - 1));
        edge.push(b')');
        assert_eq!(edge.len(), 256);
        assert!(check_version_output(&edge, &want()).is_ok());
        edge.insert(edge.len() - 1, 0xff);
        assert_eq!(edge.len(), 257);
        assert!(check_version_output(&edge, &want()).is_err());
        // Every failure carries the same fixed message.
        let err = check_version_output(b"hello\n", &want()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "update: the downloaded binary does not report the target version"
        );
    }

    #[test]
    fn dir_sync_tolerable_errno_mapping() {
        // EINVAL / ENOTSUP / EOPNOTSUPP are tolerable (Go
        // `isDirSyncTolerable`); other errnos are not.
        for errno in [libc::EINVAL, libc::ENOTSUP, libc::EOPNOTSUPP] {
            assert!(is_dir_sync_tolerable(&std::io::Error::from_raw_os_error(
                errno
            )));
        }
        assert!(!is_dir_sync_tolerable(&std::io::Error::from(
            ErrorKind::NotFound,
        )));
    }

    #[test]
    fn sync_dir_succeeds_on_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(sync_dir(dir.path()).is_ok());
    }
}
