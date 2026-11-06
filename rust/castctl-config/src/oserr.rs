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

/// Go `MkdirAll`-style error text: `mkdir <path>: <strerror>`.
/// Rust's `create_dir_all` reports EEXIST when a path component
/// is a regular file, while Go's `MkdirAll` reports ENOTDIR
/// (`mkdir <path>: not a directory` — red-team probe E1).
pub fn mkdir_error_text(path: &str, e: &std::io::Error) -> String {
    if e.raw_os_error() == Some(17) {
        format!("mkdir {path}: {}", strerror(20))
    } else {
        format!("mkdir {path}: {}", os_message(e))
    }
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
        // carry the op + path; mkdir maps EEXIST-on-a-file
        // to ENOTDIR, as Go's `MkdirAll` does (probe E1).
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
        let eexist = std::io::Error::from_raw_os_error(17); // EEXIST
        assert_eq!(
            mkdir_error_text("/tmp/notadir", &eexist),
            "mkdir /tmp/notadir: not a directory"
        );
        assert_eq!(
            mkdir_error_text("/tmp/notadir", &e),
            "mkdir /tmp/notadir: operation not permitted"
        );
    }
}
