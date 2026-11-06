// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! OS error text rendering matching Go's `%v` on `*PathError` /
//! `*LinkError`: `<op> <path>: <strerror>`. Only the message text is
//! reproduced; no error values cross the boundary.
//!
//! `IsNotExist` is decided by raw errno `ENOENT` (2) only, matching
//! Go's `os.IsNotExist` (which does NOT treat `ENOTDIR` as
//! not-exist, unlike Rust's `ErrorKind::NotFound` mapping).

/// Whether an I/O error is Go `os.IsNotExist` (raw errno `ENOENT`).
pub fn is_not_exist(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(2)
}

/// `strerror` text for common errnos, as Go's `syscall.Errno.Error()`
/// renders them on Linux. Unlisted codes fall back to
/// `os error <n>` (documented approximation; see PORTING.md).
pub fn strerror(errno: i32) -> String {
    let text = match errno {
        1 => "operation not permitted",
        2 => "no such file or directory",
        3 => "no such process",
        4 => "interrupted system call",
        5 => "input/output error",
        11 => "resource temporarily unavailable",
        13 => "permission denied",
        17 => "file exists",
        18 => "invalid cross-device link",
        20 => "not a directory",
        21 => "is a directory",
        22 => "invalid argument",
        24 => "too many open files in system",
        26 => "text file busy",
        27 => "file too large",
        28 => "no space left on device",
        30 => "read-only file system",
        31 => "too many links",
        32 => "broken pipe",
        36 => "file name too long",
        39 => "directory not empty",
        40 => "too many levels of symbolic links",
        _ => return format!("os error {errno}"),
    };
    text.to_string()
}

/// The OS message for an I/O error: `strerror` for OS errors, the
/// Rust display otherwise (e.g. invalid UTF-8 paths, which Go
/// renders differently — unreached in practice).
pub fn os_message(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => strerror(code),
        None => format!("{e}"),
    }
}

/// Go `*PathError` text: `stat <path>: <strerror>`.
pub fn stat_error_text(path: &str, e: &std::io::Error) -> String {
    format!("stat {path}: {}", os_message(e))
}

/// Go `*PathError` text for reads: `open <path>: <strerror>`.
pub fn open_error_text(path: &str, e: &std::io::Error) -> String {
    format!("open {path}: {}", os_message(e))
}

/// Go `*PathError` text for writes: `write <path>: <strerror>`.
pub fn write_error_text(path: &str, e: &std::io::Error) -> String {
    format!("write {path}: {}", os_message(e))
}

/// Go `*PathError` text for syncs: `sync <path>: <strerror>`.
pub fn sync_error_text(path: &str, e: &std::io::Error) -> String {
    format!("sync {path}: {}", os_message(e))
}

/// Go `*LinkError` text for renames: `rename <old> <new>: <strerror>`.
/// Go's `os.Rename` Lstats the destination first: when it is a
/// directory it returns EEXIST ("file exists") without issuing the
/// syscall, while the raw kernel rename returns EISDIR ("is a
/// directory") — red-team round-2 R2-B1. The mapping fires only
/// when the destination Lstats as a directory (a symlink to a
/// directory does not: Go's Lstat does not follow it).
pub fn rename_error_text(old: &str, new: &str, e: &std::io::Error) -> String {
    if e.raw_os_error() == Some(21) && std::fs::symlink_metadata(new).is_ok_and(|m| m.is_dir()) {
        return format!("rename {old} {new}: {}", strerror(17));
    }
    format!("rename {old} {new}: {}", os_message(e))
}

/// Go `os.MkdirAll` (`os/path.go:19`), ported exactly:
/// Stat fast path (succeeds + dir → Ok; succeeds + not a
/// dir → `mkdir <path>: not a directory`), else recurse
/// into the parent and `Mkdir` the path, with an `Lstat`
/// re-check on failure (a directory appearing meanwhile →
/// Ok). The error text is the Go `*PathError` shape
/// `mkdir <component>: <strerror>` where `<component>` is
/// the FAILING component, not the full path: a dangling
/// symlink or a symlink loop yields `file exists` (EEXIST)
/// on the loop/dangling component, because `Mkdir` on an
/// existing symlink returns EEXIST — red-team round-3 R3-B2
/// (E10/E11/E12/E13). Returns `Ok(())` when the directory
/// exists or was created, `Err(text)` otherwise.
pub fn mkdir_all(path: &str) -> Result<(), String> {
    match std::fs::metadata(path) {
        Ok(m) => {
            if m.is_dir() {
                return Ok(());
            }
            return Err(format!("mkdir {path}: {}", strerror(20)));
        }
        Err(_) => {}
    }
    let parent = mkdir_all_parent(path);
    if !parent.is_empty() {
        mkdir_all(parent)?;
    }
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Go double-checks that the directory doesn't
            // exist (handles "foo/." and races): an Lstat
            // success + dir swallows the Mkdir error.
            if let Ok(m) = std::fs::symlink_metadata(path)
                && m.is_dir()
            {
                return Ok(());
            }
            Err(format!("mkdir {path}: {}", os_message(&e)))
        }
    }
}

/// Go `MkdirAll`'s parent extraction (`os/path.go:36-44`):
/// strip trailing separators, then cut at the last
/// separator; no separator → "" (the slow path then skips
/// the recursion, as Go's `len(parent) > len(VolumeName)`
/// check does on Unix).
fn mkdir_all_parent(path: &str) -> &str {
    let bytes = path.as_bytes();
    let mut i = bytes.len() as isize - 1;
    while i >= 0 && bytes[i as usize] == b'/' {
        i -= 1;
    }
    while i >= 0 && bytes[i as usize] != b'/' {
        i -= 1;
    }
    if i < 0 {
        i = 0;
    }
    &path[..i as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strerror_common() {
        assert_eq!(strerror(2), "no such file or directory");
        assert_eq!(strerror(13), "permission denied");
        assert_eq!(strerror(21), "is a directory");
        assert_eq!(strerror(20), "not a directory");
        assert_eq!(strerror(27), "file too large");
        assert_eq!(strerror(39), "directory not empty");
    }

    #[test]
    fn test_is_not_exist_raw_code_only() {
        let enoent = std::io::Error::from_raw_os_error(2);
        assert!(is_not_exist(&enoent));
        let enotdir = std::io::Error::from_raw_os_error(20);
        assert!(!is_not_exist(&enotdir));
    }

    #[test]
    fn rename_error_text_maps_dir_dest_to_file_exists() {
        // Go `os.Rename` Lstats the destination first: a
        // directory destination is EEXIST ("file exists"),
        // not the kernel's EISDIR ("is a directory") —
        // red-team round-2 R2-B1. Both empty and non-empty
        // directories map; a symlink to a directory does
        // NOT (Go's Lstat does not follow it).
        let dir = std::env::temp_dir().join(format!("castctl-oserr-rename-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("pic.jpg");
        std::fs::create_dir_all(&dest).unwrap();
        let e = std::io::Error::from_raw_os_error(21); // EISDIR
        let dest_s = dest.to_str().unwrap();
        assert_eq!(
            rename_error_text("/tmp/x.part", dest_s, &e),
            format!("rename /tmp/x.part {dest_s}: file exists")
        );
        std::fs::write(dest.join("inner.txt"), b"x").unwrap();
        assert_eq!(
            rename_error_text("/tmp/x.part", dest_s, &e),
            format!("rename /tmp/x.part {dest_s}: file exists")
        );
        let file = dir.join("f.jpg");
        std::fs::write(&file, b"x").unwrap();
        let file_s = file.to_str().unwrap();
        assert_eq!(
            rename_error_text("/tmp/x.part", file_s, &e),
            format!("rename /tmp/x.part {file_s}: is a directory")
        );
        let missing = dir.join("nope.jpg");
        let missing_s = missing.to_str().unwrap();
        assert_eq!(
            rename_error_text("/tmp/x.part", missing_s, &e),
            format!("rename /tmp/x.part {missing_s}: is a directory")
        );
        let link = dir.join("link.jpg");
        std::os::unix::fs::symlink(&dest, &link).unwrap();
        let link_s = link.to_str().unwrap();
        assert_eq!(
            rename_error_text("/tmp/x.part", link_s, &e),
            format!("rename /tmp/x.part {link_s}: is a directory")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mkdir_write_sync_error_text_shapes() {
        // Go `*PathError` shapes for the toggle writer
        // (red-team round-2 R2-B2): open/write/sync/rename
        // carry the op + path. (The mkdir shapes moved to
        // `mkdir_all_matches_go_mkdir_all`: `mkdir_error_text`
        // was deleted in fix loop 3 — it mapped ALL EEXIST
        // to ENOTDIR, which is wrong for dangling symlinks
        // and loops, R3-B2.)
        let e = std::io::Error::from_raw_os_error(1); // EPERM
        assert_eq!(
            open_error_text("/tmp/x.tmp", &e),
            "open /tmp/x.tmp: operation not permitted"
        );
        assert_eq!(
            write_error_text("/tmp/x.tmp", &e),
            "write /tmp/x.tmp: operation not permitted"
        );
        assert_eq!(
            sync_error_text("/tmp/x.tmp", &e),
            "sync /tmp/x.tmp: operation not permitted"
        );
        assert_eq!(
            rename_error_text("/tmp/x.tmp", "/tmp/cfg", &e),
            "rename /tmp/x.tmp /tmp/cfg: operation not permitted"
        );
    }

    #[test]
    fn mkdir_all_matches_go_mkdir_all() {
        // R3-B2 regression: Go `os.MkdirAll` (`os/path.go:19`)
        // returns ENOTDIR only when `Stat(path)` succeeds and
        // the path is not a directory; in every other EEXIST
        // case it returns EEXIST, and it reports the FAILING
        // COMPONENT, not the full path. Expected strings are
        // the verbatim outputs of the standalone Go probe on
        // cue (`/tmp/m7b-r3redteam-mkdir.go`, same ext4 fs).
        // Order matters: the dangling/loop shapes must be
        // checked BEFORE the missing dir is created (the
        // dangling symlink points at it).
        let base = std::env::temp_dir()
            .join(format!("castctl-oserr-mkdirall-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let b = |p: &str| base.join(p);
        std::fs::write(b("afile"), b"x").unwrap();
        std::os::unix::fs::symlink(b("afile"), b("linkfile")).unwrap();
        std::fs::create_dir_all(b("realdir")).unwrap();
        std::os::unix::fs::symlink(b("realdir"), b("linkdir")).unwrap();
        std::os::unix::fs::symlink(b("missing"), b("dangling")).unwrap();
        std::os::unix::fs::symlink(b("loop"), b("loop")).unwrap();
        let s = |p: &std::path::Path| p.to_str().unwrap().to_string();
        let base_s = s(&base);
        // File, symlink-to-file: ENOTDIR on the path itself.
        assert_eq!(
            mkdir_all(&s(&b("afile"))),
            Err(format!("mkdir {base_s}/afile: not a directory"))
        );
        assert_eq!(
            mkdir_all(&s(&b("linkfile"))),
            Err(format!("mkdir {base_s}/linkfile: not a directory"))
        );
        // Symlink-to-dir: success, nothing created.
        assert_eq!(mkdir_all(&s(&b("linkdir"))), Ok(()));
        // Dangling symlink, loop: EEXIST on the path itself.
        assert_eq!(
            mkdir_all(&s(&b("dangling"))),
            Err(format!("mkdir {base_s}/dangling: file exists"))
        );
        assert_eq!(
            mkdir_all(&s(&b("loop"))),
            Err(format!("mkdir {base_s}/loop: file exists"))
        );
        // Under a loop: EEXIST on the LOOP component.
        assert_eq!(
            mkdir_all(&s(&b("loop/sub"))),
            Err(format!("mkdir {base_s}/loop: file exists"))
        );
        // Under a file: ENOTDIR on the FILE component.
        assert_eq!(
            mkdir_all(&s(&b("afile/sub"))),
            Err(format!("mkdir {base_s}/afile: not a directory"))
        );
        // Missing: success, created (and under it too).
        assert_eq!(mkdir_all(&s(&b("missing"))), Ok(()));
        assert_eq!(mkdir_all(&s(&b("missing/sub"))), Ok(()));
        assert!(b("missing/sub").is_dir());
        let _ = std::fs::remove_dir_all(&base);
    }
}
