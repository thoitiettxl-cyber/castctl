// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Shadow copies: content-addressed copies under
//! `<tmp>/castctl-pluginhost/pid-<pid>/`.
//!
//! Go source: `internal/pluginhost/shadow.go` (all of it).
//!
//! A loaded plugin image must stay mapped for the lifetime
//! of the host process, so loading from a shadow copy keeps
//! the original artifact replaceable and gives every
//! distinct plugin build its own path. The name is
//! predictable by content (`sha256[:32]`), NOT random and
//! NOT memfd: identical content maps to the same path.
//!
//! Hardening (castctl, NOT upstream): the source is
//! refused when it is a symlink, when any path component
//! is a symlink, when it is a hard link (`Nlink > 1`),
//! and must be a regular file.
//!
//! Error messages never embed the shadow path (which
//! carries the pid directory layout); source-path errors
//! name the operator's source path, like Go.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Once;

use sha2::{Digest, Sha256};

use crate::discovery::{PluginFile, validate_plugin_id};
use crate::error::PluginHostError;
use crate::paths::{
    check_hardlink, check_shadow_dir_ownership, open_plugin_source, pid_alive,
    refuse_symlinked_components,
};

/// Shadow file name prefix.
/// Source: `shadowPrefix` (`shadow.go:39`).
pub const SHADOW_PREFIX: &str = "castctl-plugin-";
/// Temp file prefix inside the shadow dir.
/// Source: `shadowTempPrefix` (`shadow.go:40`).
pub const SHADOW_TEMP_PREFIX: &str = ".castctl-plugin-";
/// Digest characters kept in the shadow name.
/// Source: `shadowDigestLen` (`shadow.go:41`).
pub const SHADOW_DIGEST_LEN: usize = 32;

/// The stale sweep runs once per process.
/// Source: `shadowCleanupOnce` (`shadow.go:43`).
static SWEEP_ONCE: Once = Once::new();

/// The shadow root: `<tmp>/castctl-pluginhost`.
/// Source: `shadowRoot` (`shadow.go:57-59`).
#[must_use]
pub fn shadow_root() -> PathBuf {
    std::env::temp_dir().join("castctl-pluginhost")
}

/// The per-process shadow directory, `0700`, refusing
/// another uid's pre-existing directory.
/// Source: `shadowDir` (`shadow.go:61-76`).
pub fn shadow_dir() -> Result<PathBuf, PluginHostError> {
    let dir = shadow_root().join(format!("pid-{}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .map_err(|e| PluginHostError::failed(format!("cannot create shadow directory: {e}")))?;
    // `create_dir_all` does not harden a pre-existing
    // directory: force 0700 and refuse another uid's.
    if let Ok(info) = std::fs::metadata(&dir) {
        check_shadow_dir_ownership(&info)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

/// Remove the process's own shadow directory
/// (best-effort, never an error). `Host.Close` calls it;
/// a crash-killed process leaves its directory for the
/// next process's stale sweep.
/// Source: `CleanupShadowDir` (`shadow.go:83-87`).
pub fn cleanup_shadow_dir() {
    let dir = shadow_root().join(format!("pid-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Remove `pid-*` directories under the shadow root
/// whose pid is not alive. ONLY dead-pid directories are
/// removed, and only under the shadow root: files in the
/// live process's own directory are NEVER deleted here.
/// Every error is ignored: the sweep must never fail a load.
/// Source: `sweepStaleShadowDirs` (`shadow.go:103-130`).
pub fn sweep_stale_shadow_dirs() {
    let root = shadow_root();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if !ft.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(pid_str) = name.strip_prefix("pid-") else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<i32>() else {
            continue;
        };
        // Exact `pid-%d` format check (rejects `pid-01`,
        // `pid-1x`, ...).
        if pid <= 0 || format!("pid-{pid}") != name {
            continue;
        }
        if pid as u32 == std::process::id() || pid_alive(pid) {
            continue;
        }
        let _ = std::fs::remove_dir_all(root.join(&name));
    }
}

/// Copy the plugin file into the per-process shadow
/// directory and return the shadow path. Identical
/// content maps to the same path; different content maps
/// to a different path. The source file is never
/// modified. The file ID is validated before it is
/// embedded in a filename.
/// Source: `ShadowCopy` (`shadow.go:50-56`).
pub fn shadow_copy(file: &PluginFile) -> Result<PathBuf, PluginHostError> {
    if !validate_plugin_id(&file.id) {
        return Err(PluginHostError::invalid(format!(
            "invalid plugin id {:?}",
            file.id
        )));
    }
    let dir = shadow_dir()?;
    SWEEP_ONCE.call_once(sweep_stale_shadow_dirs);
    shadow_copy_to_dir(file, &dir)
}

/// The copy proper, into an explicit directory (the seam
/// tests use to isolate the shadow root).
/// Source: `shadowCopyToDir` (`shadow.go:132-207`).
pub fn shadow_copy_to_dir(file: &PluginFile, dir: &Path) -> Result<PathBuf, PluginHostError> {
    // Checked BEFORE Clean: `refuse_symlinked_components`
    // refuses ".." components, and Clean would resolve
    // them away lexically before the check could see them.
    refuse_symlinked_components(&file.path)?;
    let source = lexical_clean(&file.path);
    let info = std::fs::symlink_metadata(&source)
        .map_err(|e| PluginHostError::failed(format!("plugin file {source:?}: {e}")))?;
    if info.file_type().is_symlink() {
        return Err(PluginHostError::invalid(format!(
            "plugin file {source:?} must not be a symlink"
        )));
    }
    if !info.is_file() {
        return Err(PluginHostError::invalid(format!(
            "plugin file {source:?} is not a regular file"
        )));
    }
    check_hardlink(&info)?;
    let ext = source
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let mut tmp = tempfile::Builder::new()
        .prefix(&format!("{SHADOW_TEMP_PREFIX}{}-", file.id))
        .suffix(&ext)
        .tempfile_in(dir)
        .map_err(|e| PluginHostError::failed(format!("cannot create shadow temp file: {e}")))?;
    let tmp_path = tmp.path().to_path_buf();
    let copy_result = (|| -> Result<(u64, String), PluginHostError> {
        let mut input = open_plugin_source(&source)
            .map_err(|e| PluginHostError::failed(format!("cannot open plugin file: {e}")))?;
        let info = input.metadata().map_err(|_| {
            PluginHostError::invalid(format!("plugin file {source:?} is not a regular file"))
        })?;
        if !info.is_file() {
            return Err(PluginHostError::invalid(format!(
                "plugin file {source:?} is not a regular file"
            )));
        }
        check_hardlink(&info)?;
        let mut hasher = Sha256::new();
        let mut size: u64 = 0;
        let mut chunk = [0u8; 32 << 10];
        loop {
            use std::io::Read;
            match input.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    size += n as u64;
                    hasher.update(&chunk[..n]);
                    tmp.write_all(&chunk[..n]).map_err(|e| {
                        PluginHostError::failed(format!("cannot write shadow temp file: {e}"))
                    })?;
                }
                Err(e) => {
                    return Err(PluginHostError::failed(format!(
                        "cannot read plugin file: {e}"
                    )));
                }
            }
        }
        tmp.flush()
            .map_err(|e| PluginHostError::failed(format!("cannot write shadow temp file: {e}")))?;
        Ok((size, hex::encode(hasher.finalize())))
    })();
    let (size, digest) = match copy_result {
        Ok(t) => t,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
    };
    // NB: do NOT drop `tmp` here: dropping a
    // `NamedTempFile` DELETES the file, and the rename
    // below needs it. `tmp` stays alive until the
    // rename completes; its Drop afterwards is a no-op
    // (the temp path no longer exists).
    let target = shadow_path(dir, &file.id, &digest, &ext);
    if shadow_matches(&target, size, &digest) {
        let _ = std::fs::remove_file(&tmp_path);
        return Ok(target);
    }
    if let Err(e) = std::fs::remove_file(&target)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        if shadow_matches(&target, size, &digest) {
            let _ = std::fs::remove_file(&tmp_path);
            return Ok(target);
        }
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(&tmp_path);
        // No shadow path in the message (Go wraps the
        // os error, which carries it; this port drops
        // the path-bearing cause).
        return Err(PluginHostError::failed("remove stale shadow plugin"));
    }
    if let Err(e) = std::fs::rename(&tmp_path, &target) {
        if e.kind() != std::io::ErrorKind::AlreadyExists && !shadow_matches(&target, size, &digest)
        {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(PluginHostError::failed("move shadow plugin"));
        }
        // Lost the rename race to an identical file: the
        // target now matches.
        if shadow_matches(&target, size, &digest) {
            let _ = std::fs::remove_file(&tmp_path);
            return Ok(target);
        }
        let _ = std::fs::remove_file(&tmp_path);
        return Err(PluginHostError::failed("move shadow plugin"));
    }
    Ok(target)
}

/// The shadow path for content `digest`.
/// Source: `shadowPath` (`shadow.go:209-214`).
#[must_use]
pub fn shadow_path(dir: &Path, id: &str, digest: &str, ext: &str) -> PathBuf {
    let short = if digest.len() > SHADOW_DIGEST_LEN {
        &digest[..SHADOW_DIGEST_LEN]
    } else {
        digest
    };
    dir.join(format!("{SHADOW_PREFIX}{id}-{short}{ext}"))
}

/// Remove one shadow file (best-effort).
/// Source: `removeShadowFile` (`shadow.go:220-222`).
pub fn remove_shadow_file(path: &Path) -> std::io::Result<()> {
    std::fs::remove_file(path)
}

/// Whether the shadow file at `path` already holds
/// exactly `size` bytes with SHA-256 `digest`.
/// Source: `shadowMatches` (`shadow.go:224-245`).
#[must_use]
pub fn shadow_matches(path: &Path, size: u64, digest: &str) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() || meta.len() != size {
        return false;
    }
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut hasher = Sha256::new();
    let mut chunk = [0u8; 32 << 10];
    loop {
        use std::io::Read;
        match f.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => hasher.update(&chunk[..n]),
            Err(_) => return false,
        }
    }
    let got = hex::encode(hasher.finalize());
    let got_short = if got.len() > SHADOW_DIGEST_LEN {
        &got[..SHADOW_DIGEST_LEN]
    } else {
        &got[..]
    };
    let want_short = if digest.len() > SHADOW_DIGEST_LEN {
        &digest[..SHADOW_DIGEST_LEN]
    } else {
        digest
    };
    got_short == want_short
}

/// Lexical Clean: drop `.` components and duplicate
/// separators (no `..` handling — callers refuse `..` first).
fn lexical_clean(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        use std::path::Component;
        match comp {
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::Normal(n) => out.push(n),
            Component::ParentDir => {
                out.pop();
            }
            Component::Prefix(_) => {}
        }
    }
    out
}

/// Test-only lock serialising every test in this
/// process that touches the per-process shadow
/// directory (`<root>/pid-<pid>`): `shadow_dir()`,
/// `shadow_copy()`, and `cleanup_shadow_dir()` (via
/// `Host::close`) all share that one directory, so
/// a test that creates it can recreate it inside
/// another test's cleanup-then-assert window.
/// Observed on cue, 2026-11-06 (M6c-b final
/// gates): `shadow_dir_is_0700` failed its
/// `!dir.exists()` assert because a concurrent
/// `shadow_copy` recreated the dir after
/// `cleanup_shadow_dir()` and before the assert.
/// M6c added this lock for the sweep test only;
/// M6c-b extends it to every in-process toucher.
/// Production code never takes this lock.
#[cfg(test)]
pub(crate) static SHADOW_DIR_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin_file(dir: &Path, id: &str, bytes: &[u8]) -> PluginFile {
        let path = dir.join(format!("{id}.so"));
        std::fs::write(&path, bytes).unwrap();
        PluginFile {
            id: id.to_string(),
            path,
            version: String::new(),
            manifest_path: PathBuf::new(),
        }
    }

    #[test]
    fn shadow_copy_content_and_perms() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("shadow");
        std::fs::create_dir(&dir).unwrap();
        let file = plugin_file(tmp.path(), "echo", b"plugin-bytes-v1");
        let target = shadow_copy_to_dir(&file, &dir).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"plugin-bytes-v1");
        // Same content -> same path.
        let again = shadow_copy_to_dir(&file, &dir).unwrap();
        assert_eq!(target, again);
        // Name shape: castctl-plugin-<id>-<sha256[:32]>.so
        let name = target.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("castctl-plugin-echo-"));
        assert!(name.ends_with(".so"));
        assert_eq!(name.len(), "castctl-plugin-echo-".len() + 32 + 3);
        // Different content -> different path.
        let file2 = plugin_file(tmp.path(), "echo", b"plugin-bytes-v2");
        let target2 = shadow_copy_to_dir(&file2, &dir).unwrap();
        assert_ne!(target, target2);
        // Temp litter: only the two shadow files.
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn shadow_copy_refuses_symlink_and_hardlink_and_traversal() {
        // Calls `shadow_copy` (creates the own pid
        // dir): take the shared shadow-dir lock.
        let _guard = SHADOW_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("shadow");
        std::fs::create_dir(&dir).unwrap();
        // Symlink source refuses.
        let real = plugin_file(tmp.path(), "real", b"x");
        let link_path = tmp.path().join("link.so");
        std::os::unix::fs::symlink(&real.path, &link_path).unwrap();
        let link = PluginFile {
            id: "link".to_string(),
            path: link_path,
            version: String::new(),
            manifest_path: PathBuf::new(),
        };
        let err = shadow_copy_to_dir(&link, &dir).unwrap_err();
        // Go's hardening test asserts only that the
        // error mentions "symlink"
        // (`shadow_hardening_test.go:47`): the refusal
        // fires in `refuse_symlinked_components`
        // ("traverses a symlink at ..."), before the
        // Lstat "must not be a symlink" layer.
        assert!(err.to_string().contains("symlink"));
        // Hardlink source refuses.
        let hard = plugin_file(tmp.path(), "hard", b"x");
        std::fs::hard_link(&hard.path, tmp.path().join("hard2.so")).unwrap();
        let err = shadow_copy_to_dir(&hard, &dir).unwrap_err();
        assert!(err.to_string().contains("must not be a hard link"));
        // Traversal id refuses before any file access.
        let bad = PluginFile {
            id: "../evil".to_string(),
            path: tmp.path().join("x.so"),
            version: String::new(),
            manifest_path: PathBuf::new(),
        };
        assert!(shadow_copy(&bad).is_err());
        // Non-regular source refuses.
        let sub = tmp.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();
        let dir_file = PluginFile {
            id: "dir".to_string(),
            path: sub,
            version: String::new(),
            manifest_path: PathBuf::new(),
        };
        assert!(shadow_copy_to_dir(&dir_file, &dir).is_err());
    }

    #[test]
    fn sweep_removes_only_dead_pid_dirs() {
        // Creates + removes the own pid dir: take the
        // shared shadow-dir lock (see
        // `SHADOW_DIR_TEST_LOCK`).
        let _guard = SHADOW_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = shadow_root();
        std::fs::create_dir_all(&root).unwrap();
        // Dead pid dir (a pid that cannot exist).
        let dead = root.join("pid-1000000000");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join("x.so"), b"x").unwrap();
        // Own pid dir must survive.
        let own = root.join(format!("pid-{}", std::process::id()));
        std::fs::create_dir_all(&own).unwrap();
        std::fs::write(own.join("keep.so"), b"x").unwrap();
        // A stray temp file inside the own dir must
        // survive too: the sweep removes whole
        // dead-pid dirs, never files inside a live
        // one (technical F-i, fix loop 1).
        std::fs::write(own.join(".castctl-plugin-stray"), b"x").unwrap();
        // Non-pid dir must survive.
        let other = root.join("not-a-pid-dir");
        std::fs::create_dir_all(&other).unwrap();
        sweep_stale_shadow_dirs();
        assert!(!dead.exists(), "dead pid dir must be swept");
        assert!(own.join("keep.so").exists(), "own dir must survive");
        assert!(
            own.join(".castctl-plugin-stray").exists(),
            "stray temp in own dir must survive"
        );
        assert!(other.exists(), "non-pid dir must survive");
        let _ = std::fs::remove_dir_all(&own);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn shadow_dir_is_0700() {
        // Creates, checks, then removes the own pid
        // dir and asserts it is gone: take the shared
        // shadow-dir lock for the whole body, or a
        // concurrent `shadow_copy` recreates the dir
        // inside the cleanup-then-assert window.
        let _guard = SHADOW_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = shadow_dir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        cleanup_shadow_dir();
        assert!(!dir.exists());
    }
}
