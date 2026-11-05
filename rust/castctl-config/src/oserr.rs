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
}
