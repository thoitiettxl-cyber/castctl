// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Path containment (`internal/webui/contain.go`).
//!
//! `resolveAgainst` walks path components, resolving each
//! existing prefix with `EvalSymlinks`; `..` pops the
//! RESOLVED prefix, so a symlink inside the path cannot
//! smuggle `..` past the boundary. Absolute candidates
//! ignore the base dir. `resolvePathBestEffort` never fails:
//! EvalSymlinks on the full path, else the nearest existing
//! ancestor plus the remainder, always absolute.
//! `pathWithin` is `filepath.Rel == "."` or not starting
//! with `".."`.

use std::path::{Component, Path, PathBuf};

/// Resolve `candidate` against `base_dir` the way Go's
/// `resolveAgainst` does: each existing prefix is resolved
/// with `canonicalize` (symlinks), `..` pops the resolved
/// prefix, `.` is dropped, and a leading `/` makes the
/// candidate absolute (base ignored).
pub fn resolve_against(base_dir: &Path, candidate: &str) -> PathBuf {
    let cand = Path::new(candidate);
    let mut resolved: PathBuf = if cand.is_absolute() {
        PathBuf::from("/")
    } else {
        base_dir.to_path_buf()
    };
    for comp in cand.components() {
        match comp {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) => {
                resolved.push(name);
                if let Ok(real) = std::fs::canonicalize(&resolved) {
                    resolved = real;
                }
            }
            Component::Prefix(_) => {}
        }
    }
    resolved
}

/// Best-effort absolute resolution (`resolvePathBestEffort`):
/// full `canonicalize` when possible, else the nearest
/// existing ancestor plus the remainder. Never fails.
pub fn resolve_path_best_effort(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => path.to_path_buf(),
        }
    };
    if let Ok(real) = std::fs::canonicalize(&abs) {
        return real;
    }
    // Walk up to the nearest existing ancestor, then re-append.
    let mut ancestor = abs.as_path();
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(real) = std::fs::canonicalize(ancestor) {
            let mut out = real;
            for part in suffix.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match ancestor.parent() {
            Some(parent) if parent != ancestor => {
                if let Some(name) = ancestor.file_name() {
                    suffix.push(name.to_os_string());
                }
                ancestor = parent;
            }
            _ => return abs,
        }
    }
}

/// `pathWithin`: `path` is inside (or equal to) `dir`
/// after both are resolved. (`filepath.Rel` is `"."` or
/// does not start with `".."`. Go's `filepath.Rel` also
/// returns an error for different volumes on Windows; on
/// Unix that case cannot occur.)
pub fn path_within(path: &Path, dir: &Path) -> bool {
    match path.strip_prefix(dir) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// `containedInDir(candidate, baseDir)`: resolve the
/// candidate against the base, resolve the base
/// best-effort, then check containment.
pub fn contained_in_dir(candidate: &str, base_dir: &Path) -> bool {
    let resolved = resolve_against(base_dir, candidate);
    let base = resolve_path_best_effort(base_dir);
    path_within(&resolved, &base)
}

/// `dirOverlaps(a, b)`: two directories overlap when one
/// contains the other or they are equal, after absolute
/// resolution (Go's `internal/profile/webui.go`
/// `DirOverlaps`; unresolvable `Rel` fails closed = overlap).
pub fn dir_overlaps(a: &Path, b: &Path) -> bool {
    let ra = resolve_path_best_effort(a);
    let rb = resolve_path_best_effort(b);
    path_within(&ra, &rb) || path_within(&rb, &ra)
}

/// Lexical path cleaning, Go `filepath.Clean` semantics:
/// drop `.`, resolve `..` lexically (never above root),
/// collapse duplicate separators. No filesystem access.
pub fn clean_path(p: &Path) -> PathBuf {
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    let mut rooted = false;
    for comp in p.components() {
        match comp {
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::ParentDir => {
                if out.pop().is_none() && !rooted {
                    out.push(std::ffi::OsString::from(".."));
                }
            }
            Component::Normal(name) => out.push(name.to_os_string()),
            Component::Prefix(_) => {}
        }
    }
    let mut buf = PathBuf::new();
    if rooted {
        buf.push("/");
    }
    for part in out {
        buf.push(part);
    }
    if buf.as_os_str().is_empty() {
        buf.push(".");
    }
    buf
}

/// Lexical overlap check used at webui-block parse time
/// (`DirOverlaps` with absolutized paths; unresolvable
/// relative path fails closed = overlap). Unlike
/// [`dir_overlaps`], this does not touch the filesystem
/// beyond absolutizing against the current directory.
pub fn dir_overlaps_lexical(a: &Path, b: &Path) -> bool {
    let ra = clean_path(&absolutize(a));
    let rb = clean_path(&absolutize(b));
    ra == rb || ra.starts_with(&rb) || rb.starts_with(&ra)
}

fn absolutize(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(p),
            Err(_) => p.to_path_buf(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn dotdot_cannot_escape_base() {
        let dir = std::env::temp_dir().join("castctl-webui-contain-test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sub")).unwrap();
        let base = dir.join("sub");
        assert!(contained_in_dir("../sub", &base));
        assert!(!contained_in_dir("../../etc", &base));
        assert!(!contained_in_dir("/etc/passwd", &base));
        assert!(contained_in_dir("file.txt", &base));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlink_inside_path_is_resolved() {
        // A symlink `sub/link -> /etc` inside the base must
        // NOT let "link/passwd" count as contained.
        let dir = std::env::temp_dir().join("castctl-webui-contain-symlink");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sub")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc", dir.join("sub").join("link")).unwrap();
        let base = dir.join("sub");
        assert!(!contained_in_dir("link/passwd", &base));
        assert!(contained_in_dir("plain.txt", &base));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fail_before_dotdot_escape() {
        // Removing the resolve-against walk (plain join)
        // would let "../.." escape; this pins the walk.
        let base = Path::new("/cfg/profiles");
        let resolved = resolve_against(base, "../../etc/passwd");
        assert_eq!(resolved, PathBuf::from("/etc/passwd"));
        assert!(!path_within(&resolved, base));
    }
}
