// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Lexical `filepath` operations on Unix paths, mirroring Go's
//! `path/filepath` (which, on Linux, is the slash-separated lexical
//! algorithm with no symlink resolution and no tilde expansion).
//!
//! Source: Go stdlib `path/filepath` (`Clean`, `Join`, `Dir`, `Base`,
//! `Rel`, `IsAbs`) as used by `internal/profile/config.go`,
//! `configlocation.go`, and `profile.go` at base `dev-rust` `85a8d5e`.

/// Go `filepath.Clean`: lexical cleanup. Empty becomes `"."`; repeated
/// slashes collapse; `.` elements vanish; `..` pops lexically (and is
/// dropped at the root); a trailing slash is dropped except at root.
///
/// Source: Go stdlib `path/filepath.Clean`.
pub fn go_clean(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let rooted = path.as_bytes()[0] == b'/';
    let mut out: Vec<&str> = Vec::new();
    for elem in path.split('/') {
        match elem {
            "" | "." => {}
            ".." => {
                if let Some(last) = out.last() {
                    if *last != ".." {
                        out.pop();
                        continue;
                    }
                }
                if !rooted {
                    out.push("..");
                }
            }
            _ => out.push(elem),
        }
    }
    let mut result = String::new();
    if rooted {
        result.push('/');
    }
    result.push_str(&out.join("/"));
    if result.is_empty() {
        return ".".to_string();
    }
    result
}

/// Go `filepath.Join`: join with `/`, ignoring empty elements, then
/// `Clean`; all-empty input joins to `""`.
///
/// Source: Go stdlib `path/filepath.Join`.
pub fn go_join(elems: &[&str]) -> String {
    let parts: Vec<&str> = elems.iter().copied().filter(|e| !e.is_empty()).collect();
    if parts.is_empty() {
        return String::new();
    }
    go_clean(&parts.join("/"))
}

/// Go `filepath.Dir`: all but the last element, cleaned.
///
/// Source: Go stdlib `path/filepath.Dir`.
pub fn go_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(idx) => go_clean(&path[..idx + 1]),
        None => ".".to_string(),
    }
}

/// Go `filepath.Base`: the last element after trailing slashes are
/// removed; `""` becomes `"."`, all-slash paths become `"/"`.
///
/// Source: Go stdlib `path/filepath.Base`.
pub fn go_base(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_string();
    }
    match trimmed.rfind('/') {
        Some(idx) => trimmed[idx + 1..].to_string(),
        None => trimmed.to_string(),
    }
}

/// Go `filepath.IsAbs`: a leading `/`.
///
/// Source: Go stdlib `path/filepath.IsAbs`.
pub fn go_is_abs(path: &str) -> bool {
    path.starts_with('/')
}

/// Go `filepath.Rel`: the lexical relative path from `base` to
/// `target`. Both paths are cleaned first; mixing absolute and
/// relative paths is an error, reported as `None` (Go's error
/// value is never surfaced by the callers).
///
/// Source: Go stdlib `path/filepath.Rel`.
pub fn go_rel(base: &str, target: &str) -> Option<String> {
    let base = go_clean(base);
    let target = go_clean(target);
    if go_is_abs(&base) != go_is_abs(&target) {
        return None;
    }
    let base_parts: Vec<&str> = base.split('/').filter(|e| !e.is_empty()).collect();
    let target_parts: Vec<&str> = target.split('/').filter(|e| !e.is_empty()).collect();
    let mut common = 0;
    while common < base_parts.len()
        && common < target_parts.len()
        && base_parts[common] == target_parts[common]
    {
        common += 1;
    }
    let mut out: Vec<&str> = Vec::new();
    out.extend(std::iter::repeat_n("..", base_parts.len() - common));
    out.extend_from_slice(&target_parts[common..]);
    if out.is_empty() {
        return Some(".".to_string());
    }
    Some(out.join("/"))
}

/// `isInsideDir` (`internal/profile/config.go:813`): the relative path
/// from `dir` to `path` is neither `.`, `..`, nor `../...`.
pub fn is_inside_dir(path: &str, dir: &str) -> bool {
    match go_rel(dir, path) {
        Some(rel) => rel != "." && rel != ".." && !rel.starts_with("../"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_clean_probe_corpus() {
        assert_eq!(go_clean(""), ".");
        assert_eq!(go_clean("a//b"), "a/b");
        assert_eq!(go_clean("a/../b"), "b");
        assert_eq!(go_clean("~/cfg.json"), "~/cfg.json");
        assert_eq!(go_clean("a/b/"), "a/b");
        assert_eq!(go_clean("/"), "/");
        assert_eq!(go_clean("//"), "/");
        assert_eq!(go_clean("/../a"), "/a");
        assert_eq!(go_clean("a/../../b"), "../b");
        assert_eq!(go_clean("./a"), "a");
        assert_eq!(go_clean("../"), "..");
        assert_eq!(go_clean("a/b/.."), "a");
        assert_eq!(go_clean("."), ".");
    }

    #[test]
    fn test_go_join_probe_corpus() {
        assert_eq!(go_join(&["/base", ""]), "/base");
        assert_eq!(go_join(&["/base", "../x"]), "/x");
        assert_eq!(go_join(&["", "x"]), "x");
        assert_eq!(go_join(&["", ""]), "");
        assert_eq!(go_join(&[]), "");
        assert_eq!(go_join(&["a", "b", "c"]), "a/b/c");
        assert_eq!(go_join(&["/a", "/b"]), "/a/b");
    }

    #[test]
    fn test_go_dir_base_probe_corpus() {
        assert_eq!(go_base("/nonexistent"), "nonexistent");
        assert_eq!(go_dir("~/cfg.json"), "~");
        assert_eq!(go_dir("/a"), "/");
        assert_eq!(go_dir("a"), ".");
        assert_eq!(go_dir(""), ".");
        assert_eq!(go_base(""), ".");
        assert_eq!(go_base("/"), "/");
        assert_eq!(go_base("a/"), "a");
        assert_eq!(go_dir("/"), "/");
    }

    #[test]
    fn test_go_rel_probe_corpus() {
        assert_eq!(
            go_rel("/base", "/base/profiles/p/cookies.txt"),
            Some("profiles/p/cookies.txt".to_string())
        );
        assert_eq!(go_rel("/base", "/other/x"), Some("../other/x".to_string()));
        assert_eq!(go_rel("/base", "/base"), Some(".".to_string()));
        assert_eq!(go_rel("a", "a/b"), Some("b".to_string()));
        assert_eq!(go_rel("/a", "b"), None);
        assert_eq!(go_rel("a", "/b"), None);
    }

    #[test]
    fn test_is_inside_dir() {
        assert!(is_inside_dir("/cfg/other.txt", "/cfg"));
        assert!(!is_inside_dir("/cfg", "/cfg"));
        assert!(!is_inside_dir("/other/x", "/cfg"));
        assert!(!is_inside_dir("/cfg/../other", "/cfg"));
    }
}
