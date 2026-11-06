// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Plugin discovery: `<id>[-v<version>]<ext>` under
//! `<root>/<goos>/<goarch>` first, then `<root>`.
//!
//! Go source: `internal/pluginhost/discovery.go` (all of it).
//!
//! Selection is by VERSION: the highest version wins
//! across both directories (numeric segments, a missing
//! segment counting as 0, non-numeric segments falling
//! back to lexical order); a versioned file beats a
//! versionless one; on an exact version tie the platform
//! directory wins (scanned first). Files whose names do
//! not parse — including a `-v` suffix whose version part
//! is malformed — are skipped, not given a silent odd id.
//! Symlink entries are skipped at discovery (the
//! load-time refusal in the shadow copy is the backstop).
//! The root itself must exist and must not traverse a
//! symlinked component; a missing root is an error so a
//! misconfigured plugins directory fails closed instead
//! of silently loading nothing.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::PluginHostError;
use crate::paths::refuse_symlinked_components;

/// One discovered plugin binary.
/// Source: `File` (`discovery.go:44-53`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginFile {
    /// Plugin id (also the config tag).
    pub id: String,
    /// Full path to the binary.
    pub path: PathBuf,
    /// Version (`""` when versionless).
    pub version: String,
    /// Manifest path, when set: names a checksums.txt
    /// manifest the shadow-copy bytes must verify against
    /// before the file is loaded. Set by the host from
    /// `Desired`, never by discovery.
    pub manifest_path: PathBuf,
}

/// Whether `id` can be used as a plugin file ID /
/// config tag: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`.
/// Source: `ValidatePluginID` (`discovery.go:55-56`).
#[must_use]
pub fn validate_plugin_id(id: &str) -> bool {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    if id.len() > 128 {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// The dynamic library extension for `goos`: `.dylib` on
/// darwin, `.dll` on windows, `.so` elsewhere.
/// Source: `PluginExtension` (`discovery.go:59-68`).
#[must_use]
pub fn plugin_extension(goos: &str) -> &'static str {
    match goos {
        "darwin" => ".dylib",
        "windows" => ".dll",
        _ => ".so",
    }
}

/// Map `std::env::consts::OS` to the Go GOOS value used
/// in discovery paths and extensions.
#[must_use]
pub fn goos_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

/// Map `std::env::consts::ARCH` to the Go GOARCH value.
/// Rust's names differ from Go's on 32-bit x86 (`x86`
/// → Go `386`) and 64-bit PowerPC (`powerpc64` → Go
/// `ppc64`); the old code passed both through unchanged
/// (red-team note, fix loop 1).
#[must_use]
pub fn goarch_name() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "powerpc64" => "ppc64",
        other => other,
    }
}

fn valid_plugin_version(version: &str) -> bool {
    if version.is_empty() || version.starts_with('v') {
        return false;
    }
    let mut chars = version.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_digit() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '+' || c == '-')
}

/// Parse one file name into a [`PluginFile`].
/// Source: `fileFromPath` (`discovery.go:70-108`).
fn file_from_path(path: &Path, required_ext: &str) -> Option<PluginFile> {
    let base = path.file_name()?.to_string_lossy().into_owned();
    let lower_base = base.to_ascii_lowercase();
    let ext = required_ext.trim();
    let ext = if !ext.is_empty() {
        if !lower_base.ends_with(&ext.to_ascii_lowercase()) {
            return None;
        }
        ext.to_string()
    } else {
        let mut found = String::new();
        for candidate in [".so", ".dylib", ".dll"] {
            if lower_base.ends_with(candidate) {
                found = candidate.to_string();
                break;
            }
        }
        if found.is_empty() {
            return None;
        }
        found
    };
    let name = &base[..base.len() - ext.len()];
    let mut id = name.to_string();
    let mut version = String::new();
    if let Some(idx) = name.rfind("-v")
        && idx > 0
    {
        let candidate_id = &name[..idx];
        let candidate_version = &name[idx + 2..];
        if validate_plugin_id(candidate_id) {
            if !valid_plugin_version(candidate_version) {
                // A "-v" suffix with a malformed
                // version is not a different id: the
                // file is skipped, never silently
                // discovered under an odd id.
                return None;
            }
            id = candidate_id.to_string();
            version = candidate_version.to_string();
        }
    }
    if !validate_plugin_id(&id) {
        return None;
    }
    Some(PluginFile {
        id,
        path: path.to_path_buf(),
        version,
        manifest_path: PathBuf::new(),
    })
}

/// Compare two plugin versions: numeric dot-separated
/// segments, a missing segment counting as 0. Returns
/// `(comparison, comparable)`: comparable is false when
/// any segment is non-numeric (e.g. a pre-release tag),
/// in which case callers fall back to lexical order.
/// Source: `comparePluginVersions` (`discovery.go:114-139`).
fn compare_plugin_versions(a: &str, b: &str) -> (i32, bool) {
    let segs_a: Vec<&str> = a.split('.').collect();
    let segs_b: Vec<&str> = b.split('.').collect();
    let length = segs_a.len().max(segs_b.len());
    for index in 0..length {
        let (number_a, ok_a) = version_segment(&segs_a, index);
        let (number_b, ok_b) = version_segment(&segs_b, index);
        if !ok_a || !ok_b {
            return (0, false);
        }
        if number_a != number_b {
            return (if number_a < number_b { -1 } else { 1 }, true);
        }
    }
    (0, true)
}

fn version_segment(segments: &[&str], index: usize) -> (i64, bool) {
    if index >= segments.len() {
        return (0, true);
    }
    match segments[index].parse::<i64>() {
        Ok(n) if n >= 0 => (n, true),
        _ => (0, false),
    }
}

/// Whether `candidate` should replace `current`:
/// a versioned candidate beats a versionless current, a
/// versionless candidate never replaces, and otherwise
/// the higher version wins (lexical fallback when
/// segments are not comparable). Equal versions keep the
/// current file, so the platform directory — scanned
/// first — wins ties.
/// Source: `pluginFilePreferred` (`discovery.go:148-163`).
fn plugin_file_preferred(candidate: &PluginFile, current: &PluginFile) -> bool {
    if candidate.version.is_empty() {
        return false;
    }
    if current.version.is_empty() {
        return true;
    }
    let (comparison, comparable) = compare_plugin_versions(&candidate.version, &current.version);
    if !comparable {
        return candidate.version > current.version;
    }
    comparison > 0
}

/// Discover the plugin binaries selected by the host
/// discovery rules under `root`, sorted by ID.
/// Source: `Discover` (`discovery.go:173-243`).
pub fn discover(root: &Path) -> Result<Vec<PluginFile>, PluginHostError> {
    let root_str = root.display().to_string();
    let root_trimmed = root_str.trim();
    if root_trimmed.is_empty() {
        return Err(PluginHostError::invalid(
            "plugin discovery root must not be empty",
        ));
    }
    let root = Path::new(root_trimmed);
    let meta = std::fs::metadata(root)
        .map_err(|e| PluginHostError::failed(format!("plugin discovery root {root:?}: {e}")))?;
    if !meta.is_dir() {
        return Err(PluginHostError::invalid(format!(
            "plugin discovery root {root:?} is not a directory"
        )));
    }
    refuse_symlinked_components(root)?;
    let ext = plugin_extension(goos_name());
    let goos = goos_name();
    let goarch = goarch_name();
    let dirs = [root.join(goos).join(goarch), root.to_path_buf()];
    let mut selected: HashMap<String, PluginFile> = HashMap::new();
    for dir in &dirs {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(PluginHostError::failed(format!(
                    "plugin discovery failed: {e}"
                )));
            }
        };
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                continue;
            }
            // Symlink entries are refused at discovery;
            // load-time refusal is the backstop. An Info
            // error skips the entry rather than failing
            // the directory.
            let meta = match std::fs::symlink_metadata(entry.path()) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            let Some(file) = file_from_path(&entry.path(), ext) else {
                continue;
            };
            match selected.get(&file.id) {
                None => {
                    selected.insert(file.id.clone(), file);
                }
                Some(current) => {
                    if plugin_file_preferred(&file, current) {
                        selected.insert(file.id.clone(), file);
                    }
                }
            }
        }
    }
    let mut out: Vec<PluginFile> = selected.into_values().collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"x").unwrap();
    }

    /// Technical F-k (fix loop 1): `plugin_extension`
    /// is a 3-line match (`.so` / `.dylib` / `.dll` by
    /// GOOS, `discovery.go:44-68`) with no test pin.
    #[test]
    fn plugin_extension_table() {
        assert_eq!(plugin_extension("linux"), ".so");
        assert_eq!(plugin_extension("darwin"), ".dylib");
        assert_eq!(plugin_extension("windows"), ".dll");
        assert_eq!(plugin_extension("freebsd"), ".so");
    }

    #[test]
    fn validate_plugin_id_table() {
        for good in ["a", "a1", "a-b_c.d", &"a".repeat(128)] {
            assert!(validate_plugin_id(good), "{good}");
        }
        for bad in ["", "-a", ".a", "_a", "a b", "a/b", "a:b", &"a".repeat(129)] {
            assert!(!validate_plugin_id(bad), "{bad}");
        }
    }

    #[test]
    fn compare_plugin_versions_table() {
        // `1.0` == `1.0.0` (missing segment counts as 0).
        assert_eq!(compare_plugin_versions("1.0", "1.0.0"), (0, true));
        assert_eq!(compare_plugin_versions("2.0", "10.0"), (-1, true));
        assert_eq!(compare_plugin_versions("10.0", "2.0"), (1, true));
        assert_eq!(compare_plugin_versions("1.2.3", "1.2.3"), (0, true));
        assert_eq!(compare_plugin_versions("1.2", "1.10"), (-1, true));
        // Non-numeric segments are incomparable.
        assert_eq!(compare_plugin_versions("1.0-rc.1", "1.0"), (0, false));
        assert_eq!(compare_plugin_versions("1.0", "1.0-alpha"), (0, false));
    }

    #[test]
    fn discover_zero_one_many() {
        let tmp = tempfile::tempdir().unwrap();
        // Zero plugins.
        assert!(discover(tmp.path()).unwrap().is_empty());
        // One plugin.
        touch(tmp.path(), "echo.so");
        let found = discover(tmp.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "echo");
        assert_eq!(found[0].version, "");
        // Many: versioned beats versionless, higher wins.
        touch(tmp.path(), "echo-v1.0.so");
        touch(tmp.path(), "echo-v2.0.so");
        touch(tmp.path(), "other-v0.1.so");
        let found = discover(tmp.path()).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].id, "echo");
        assert_eq!(found[0].version, "2.0");
        assert_eq!(found[1].id, "other");
        assert_eq!(found[1].version, "0.1");
        // Sorted by ID.
        assert!(found[0].id < found[1].id);
    }

    #[test]
    fn discover_broken_plugin_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        // Malformed "-v" suffix: skipped, never discovered
        // under an odd id.
        touch(tmp.path(), "echo-vv1.0.so");
        // Invalid id characters.
        touch(tmp.path(), "bad id.so");
        // Wrong extension.
        touch(tmp.path(), "echo.txt");
        // Version starting with "v" after the dash is
        // malformed too ("-vv..." covered above); a bare
        // "v" prefix in the version part refuses.
        touch(tmp.path(), "echo-vv2.so");
        // A good plugin still discovers.
        touch(tmp.path(), "good-v1.0.so");
        let found = discover(tmp.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "good");
    }

    #[test]
    fn discover_platform_dir_wins_tie() {
        let tmp = tempfile::tempdir().unwrap();
        let plat = tmp.path().join(goos_name()).join(goarch_name());
        std::fs::create_dir_all(&plat).unwrap();
        touch(tmp.path(), "echo-v1.0.so");
        touch(&plat, "echo-v1.0.so");
        let found = discover(tmp.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, plat.join("echo-v1.0.so"));
        // Higher version in root beats platform.
        touch(tmp.path(), "echo-v2.0.so");
        let found = discover(tmp.path()).unwrap();
        assert_eq!(found[0].version, "2.0");
        assert_eq!(found[0].path, tmp.path().join("echo-v2.0.so"));
    }

    #[test]
    fn discover_symlink_entry_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "real.so");
        std::os::unix::fs::symlink(tmp.path().join("real.so"), tmp.path().join("link.so")).unwrap();
        let found = discover(tmp.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "real");
    }

    #[test]
    fn discover_root_errors() {
        let tmp = tempfile::tempdir().unwrap();
        // Missing root fails closed.
        assert!(discover(&tmp.path().join("no-such")).is_err());
        // A file is not a directory.
        let f = tmp.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        assert!(discover(&f).is_err());
        // A root through a symlinked component refuses.
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(discover(&link).is_err());
        // Empty root refuses.
        assert!(discover(Path::new("")).is_err());
    }
}
