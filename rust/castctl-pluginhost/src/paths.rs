// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Path hardening: symlinked-component refusal, hardlink
//! refusal, shadow-dir ownership, pid liveness, O_NOFOLLOW open.
//!
//! Go sources: `internal/pluginhost/paths.go`
//! (`refuseSymlinkedComponents`), `hardlink_unix.go`
//! (`checkHardlink`, `checkShadowDirOwnership`, `pidAlive`),
//! `open_unix.go` (`openPluginSource`).

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::error::PluginHostError;

/// Refuse a path whose final component or any path
/// component is a symlink. Lstat / O_NOFOLLOW checks on
/// the final component alone do not catch a symlinked
/// directory component, so every component of the
/// absolute path is Lstat-checked.
///
/// `".."` components are refused outright, BEFORE Clean:
/// Clean resolves `".."` lexically (in the link's
/// parent), while the kernel resolves it in the link
/// target's parent, so checking the cleaned path would
/// validate a different file than the kernel opens.
/// Source: `refuseSymlinkedComponents` (`paths.go:36-78`).
pub fn refuse_symlinked_components(path: &Path) -> Result<(), PluginHostError> {
    let raw: String = if path.is_absolute() {
        path.display().to_string()
    } else {
        let cwd = std::env::current_dir().map_err(|e| {
            PluginHostError::failed(format!("cannot determine working directory: {e}"))
        })?;
        // Concatenation, not Join: Join Cleans ".." away
        // before the check below can see it.
        format!("{}/{}", cwd.display(), path.display())
    };
    for comp in raw.split('/') {
        if comp == ".." {
            return Err(PluginHostError::invalid(format!(
                "plugin path {path:?} must not contain \"..\"; pass a resolved path"
            )));
        }
    }
    // Lexical Abs + Clean (Go `filepath.Abs` + `Clean`);
    // ".." is already refused above, so only "." and
    // duplicate separators remain to normalise.
    let abs = lexical_abs(path);
    let mut cur = PathBuf::from("/");
    for comp in abs.components() {
        use std::path::Component;
        let name = match comp {
            Component::Normal(n) => n.to_string_lossy().into_owned(),
            _ => continue,
        };
        cur.push(&name);
        let meta = std::fs::symlink_metadata(&cur).map_err(|e| {
            PluginHostError::failed(format!("plugin path {}: {}", cur.display(), e))
        })?;
        if meta.file_type().is_symlink() {
            return Err(PluginHostError::invalid(format!(
                "plugin path {path:?} traverses a symlink at {cur:?}"
            )));
        }
    }
    Ok(())
}

/// Lexical absolute path: join the cwd when relative,
/// drop `.` components and duplicate separators.
/// (No `..` handling: callers refuse `..` first.)
fn lexical_abs(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    };
    let mut out = PathBuf::new();
    for comp in joined.components() {
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

/// Refuse a plugin file with more than one hard link
/// (`Nlink > 1`): a hardlinked artifact shares its inode
/// with another path, so replacing or removing the other
/// path changes the bytes a load would map.
/// Source: `checkHardlink` (`hardlink_unix.go:24-36`).
pub fn check_hardlink(meta: &std::fs::Metadata) -> Result<(), PluginHostError> {
    if meta.nlink() > 1 {
        return Err(PluginHostError::invalid(format!(
            "plugin file must not be a hard link (nlink={})",
            meta.nlink()
        )));
    }
    Ok(())
}

/// Refuse a pre-existing shadow directory owned by
/// another uid. Source: `checkShadowDirOwnership`
/// (`hardlink_unix.go:44-55`).
pub fn check_shadow_dir_ownership(meta: &std::fs::Metadata) -> Result<(), PluginHostError> {
    if meta.uid() != unsafe { libc::getuid() } {
        return Err(PluginHostError::invalid(
            "shadow directory is owned by another user",
        ));
    }
    Ok(())
}

/// Whether `pid` names a live process: `kill(pid, 0)`
/// succeeds or is refused for permission (alive, other
/// uid); ESRCH means no such process.
/// Source: `pidAlive` (`hardlink_unix.go:59-65`).
#[must_use]
pub fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Open a plugin artifact refusing symlinks at open time
/// (`O_NOFOLLOW`), as defence in depth over the Lstat
/// check in the shadow copy.
/// Source: `openPluginSource` (`open_unix.go:17-19`).
pub fn open_plugin_source(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuse_symlinked_components_table() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // Direct symlinked component refuses.
        assert!(refuse_symlinked_components(&link).is_err());
        // A path through the symlinked directory refuses.
        assert!(refuse_symlinked_components(&link.join("x.so")).is_err());
        // A real directory passes.
        assert!(refuse_symlinked_components(&real).is_ok());
        // ".." refuses before Clean.
        let dotdot = tmp.path().join("real").join("..").join("real");
        assert!(refuse_symlinked_components(&dotdot).is_err());
        // Missing component errors (Lstat fails).
        assert!(refuse_symlinked_components(&tmp.path().join("no-such")).is_err());
    }

    #[test]
    fn hardlink_refuses_nlink_gt_1() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a.so");
        std::fs::write(&a, b"x").unwrap();
        let meta = std::fs::metadata(&a).unwrap();
        assert!(check_hardlink(&meta).is_ok());
        std::fs::hard_link(&a, tmp.path().join("b.so")).unwrap();
        let meta = std::fs::metadata(&a).unwrap();
        assert_eq!(
            check_hardlink(&meta).unwrap_err().to_string(),
            "plugin file must not be a hard link (nlink=2)"
        );
    }

    #[test]
    fn pid_alive_self_and_dead() {
        assert!(pid_alive(std::process::id() as i32));
        assert!(!pid_alive(0));
        assert!(!pid_alive(-1));
        // A pid that cannot exist (far beyond any real pid).
        assert!(!pid_alive(1_000_000_000));
    }

    #[test]
    fn open_plugin_source_refuses_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real.so");
        std::fs::write(&real, b"x").unwrap();
        let link = tmp.path().join("link.so");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(open_plugin_source(&real).is_ok());
        assert!(open_plugin_source(&link).is_err());
    }
}
