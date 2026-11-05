// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Config location resolution: explicit path > `CASTCTL_CONFIG` >
//! user-config-dir home, with the legacy `muse-cli` fallback.
//!
//! Source: `internal/profile/configlocation.go` at base `dev-rust`
//! `85a8d5e` (`ResolveConfigLocation`, `RequirePresent`,
//! `resolveExplicitPath`, `userConfigDir`, `configHomeDir`,
//! `isMissingDir`, `isExistingDir`, `configLookupEnv`).

use crate::config_errorf;
use crate::errors::{ConfigError, config_error};
use crate::gopath::{go_clean, go_dir, go_is_abs, go_join};
use crate::gostr::{go_quote, go_trim_space};
use crate::oserr::{is_not_exist, stat_error_text};
use crate::profile::base_dir;

/// The resolved config file location for one invocation
/// (`configlocation.go`, `ConfigLocation`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigLocation {
    /// Resolved config file path.
    pub config_file: String,
    /// Directory of the config file (CONFIG_DIR).
    pub config_dir: String,
    /// Whether the location came from an explicit path.
    pub explicit: bool,
    /// Non-fatal observations for the CLI layer to print on stderr.
    pub warnings: Vec<String>,
}

/// Environment lookup: `Some(value)` when set, `None` when unset.
/// Pass `None` as the whole getter to read the process environment
/// (Go `nil` getenv = `os.LookupEnv` in `configLookupEnv`).
///
/// CONVENTION (fix-loop N-b): `None` ALWAYS means the process
/// environment, everywhere in this crate — `resolve_profile_name`,
/// `resolve_active_profile`, and `apply_env_fill` all consult the
/// process environment when passed `None`, and consult only the
/// supplied getter when passed `Some`. This matches Go production
/// behaviour (callers pass `os.LookupEnv`); the Go nil-getenv
/// guards (skip env entirely) do not apply to this API. Tests
/// that need isolation must pass `Some` with a stub getter.
pub type Getenv<'a> = Option<&'a dyn Fn(&str) -> Option<String>>;

/// Read one variable through `getenv`, or the process environment
/// when `getenv` is `None` (Go `configLookupEnv`). See the
/// `Getenv` convention above.
pub(crate) fn config_lookup_env(getenv: Getenv<'_>, key: &str) -> Option<String> {
    match getenv {
        Some(getenv) => getenv(key),
        None => std::env::var_os(key).map(|v| v.to_string_lossy().into_owned()),
    }
}

/// A `userConfigDir` failure: either the relative-XDG case (caught
/// by the caller for warn-and-fallback) or a plain fatal message.
enum UserConfigDirError {
    /// Relative `$XDG_CONFIG_HOME` value (Go `*relativeXDGError`).
    RelativeXdg(String),
    /// Any other failure (Go `errors.New` text, no `profile: ` prefix).
    Plain(String),
}

/// `userConfigDir` (`configlocation.go`): mirrors `os.UserConfigDir`
/// through `getenv`. No trimming is performed. The OS branches are
/// Go's, verbatim, except plan9 (no Rust target; the Unix branch
/// applies there — documented in PORTING.md).
fn user_config_dir(getenv: Getenv<'_>) -> Result<String, UserConfigDirError> {
    let get = |key: &str| -> String { config_lookup_env(getenv, key).unwrap_or_default() };
    if cfg!(target_os = "windows") {
        let dir = get("AppData");
        if dir.is_empty() {
            return Err(UserConfigDirError::Plain(
                "%AppData% is not defined".to_string(),
            ));
        }
        return Ok(dir);
    }
    if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
        let dir = get("HOME");
        if dir.is_empty() {
            return Err(UserConfigDirError::Plain(
                "$HOME is not defined".to_string(),
            ));
        }
        return Ok(go_join(&[&dir, "Library", "Application Support"]));
    }
    // Unix (default, incl. Linux and Android).
    let dir = get("XDG_CONFIG_HOME");
    if dir.is_empty() {
        let dir = get("HOME");
        if dir.is_empty() {
            return Err(UserConfigDirError::Plain(
                "neither $XDG_CONFIG_HOME nor $HOME are defined".to_string(),
            ));
        }
        return Ok(go_join(&[&dir, ".config"]));
    }
    if !go_is_abs(&dir) {
        return Err(UserConfigDirError::RelativeXdg(dir));
    }
    Ok(dir)
}

/// `configHomeDir` (`configlocation.go`): `$HOME` through `getenv`
/// when non-blank there, else the process home directory. The error
/// carries the `profile: ` prefix (Go `newConfigErrorf`).
fn config_home_dir(getenv: Getenv<'_>) -> Result<String, ConfigError> {
    if let Some(v) = config_lookup_env(getenv, "HOME") {
        if !go_trim_space(&v).is_empty() {
            return Ok(v);
        }
    }
    match std::env::var_os("HOME") {
        Some(home) => {
            let home = home.to_string_lossy().into_owned();
            if home.is_empty() {
                Err(config_error(
                    "cannot determine home directory: $HOME is not defined",
                ))
            } else {
                Ok(home)
            }
        }
        None => Err(config_error(
            "cannot determine home directory: $HOME is not defined",
        )),
    }
}

/// `isMissingDir` (`configlocation.go`): stat reports not-exist. Any
/// other stat error counts as "not missing".
fn is_missing_dir(path: &str) -> bool {
    match std::fs::metadata(path) {
        Ok(_) => false,
        Err(e) => is_not_exist(&e),
    }
}

/// `isExistingDir` (`configlocation.go`): stat succeeds and is a
/// directory.
fn is_existing_dir(path: &str) -> bool {
    std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

/// `resolveExplicitPath` (`configlocation.go`): the path as given,
/// cleaned lexically. A directory is an error; a missing file is
/// recorded for `RequirePresent` to judge.
fn resolve_explicit_path(path: &str) -> Result<ConfigLocation, ConfigError> {
    let clean = go_clean(path);
    match std::fs::metadata(&clean) {
        Ok(meta) => {
            if meta.is_dir() {
                return Err(config_errorf!(
                    "config path {} is a directory, not a file",
                    go_quote(&clean)
                ));
            }
        }
        Err(e) => {
            if !is_not_exist(&e) {
                return Err(config_errorf!(
                    "cannot stat config file {}: {}",
                    go_quote(&clean),
                    stat_error_text(&clean, &e)
                ));
            }
        }
    }
    Ok(ConfigLocation {
        config_file: clean.clone(),
        config_dir: go_dir(&clean),
        explicit: true,
        warnings: Vec::new(),
    })
}

/// `ResolveConfigLocation` (`configlocation.go`).
pub fn resolve_config_location(
    explicit_path: &str,
    getenv: Getenv<'_>,
) -> Result<ConfigLocation, ConfigError> {
    if !go_trim_space(explicit_path).is_empty() {
        return resolve_explicit_path(explicit_path);
    }
    if let Some(v) = config_lookup_env(getenv, "CASTCTL_CONFIG") {
        if !go_trim_space(&v).is_empty() {
            return resolve_explicit_path(&v);
        }
    }
    let mut warnings: Vec<String> = Vec::new();
    let dir = match user_config_dir(getenv) {
        Ok(dir) => dir,
        Err(UserConfigDirError::RelativeXdg(value)) => {
            let home = config_home_dir(getenv).map_err(|herr| {
                config_errorf!(
                    "cannot determine config directory: XDG_CONFIG_HOME is relative and no home directory is available: {}",
                    herr.message
                )
            })?;
            warnings.push(format!(
                "XDG_CONFIG_HOME {} is relative; using the default config location",
                go_quote(&value)
            ));
            // BaseDir includes "castctl"; dir is the user config
            // dir, so take its parent.
            go_dir(&base_dir(&home))
        }
        Err(UserConfigDirError::Plain(msg)) => {
            return Err(config_errorf!("cannot determine config directory: {}", msg));
        }
    };
    let mut config_dir = go_join(&[&dir, "castctl"]);
    if is_missing_dir(&config_dir) {
        let legacy_dir = go_join(&[&dir, "muse-cli"]);
        if is_existing_dir(&legacy_dir) {
            warnings.push(format!(
                "legacy config directory {} found; reading config from there. Move it to {} to use the new location",
                go_quote(&legacy_dir),
                go_quote(&config_dir)
            ));
            config_dir = legacy_dir;
        }
    }
    Ok(ConfigLocation {
        config_file: go_join(&[&config_dir, "config.json"]),
        config_dir,
        explicit: false,
        warnings,
    })
}

impl ConfigLocation {
    /// `RequirePresent` (`configlocation.go`): an explicit location's
    /// file must exist and not be a directory. Non-explicit
    /// locations always pass.
    pub fn require_present(&self) -> Result<(), ConfigError> {
        if !self.explicit {
            return Ok(());
        }
        match std::fs::metadata(&self.config_file) {
            Ok(meta) => {
                if meta.is_dir() {
                    return Err(config_errorf!(
                        "config path {} is a directory, not a file",
                        go_quote(&self.config_file)
                    ));
                }
                Ok(())
            }
            Err(e) => {
                if is_not_exist(&e) {
                    Err(config_errorf!(
                        "config file {} does not exist",
                        go_quote(&self.config_file)
                    ))
                } else {
                    Err(config_errorf!(
                        "cannot stat config file {}: {}",
                        go_quote(&self.config_file),
                        stat_error_text(&self.config_file, &e)
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn getenv_map(map: HashMap<String, String>) -> impl Fn(&str) -> Option<String> {
        move |k: &str| map.get(k).cloned()
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("castctl-config-loc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_none_getenv_reads_process_environment() {
        // The Getenv convention: None means the process
        // environment, not "skip env". PATH is always set in a
        // test process, so no env mutation is needed to pin it.
        let expected = std::env::var("PATH").ok();
        assert_eq!(config_lookup_env(None, "PATH"), expected);
        let stub = getenv_map(HashMap::new());
        assert_eq!(config_lookup_env(Some(&stub), "PATH"), None);
    }

    #[test]
    fn test_explicit_path_cleaned_and_dir_refused() {
        let dir = temp_dir("explicit");
        let path = dir.join("sub/../config.json");
        let loc = resolve_config_location(path.to_str().unwrap(), None).unwrap();
        assert!(loc.explicit);
        assert_eq!(loc.config_file, dir.join("config.json").to_str().unwrap());
        let err = loc.require_present().unwrap_err();
        assert!(err.message.contains("does not exist"));
        let loc = resolve_config_location(dir.to_str().unwrap(), None).unwrap_err();
        assert!(loc.message.contains("is a directory, not a file"));
    }

    #[test]
    fn test_env_config_wins_over_default() {
        let dir = temp_dir("env");
        let file = dir.join("my.json");
        std::fs::write(&file, "{}").unwrap();
        let mut map = HashMap::new();
        map.insert(
            "CASTCTL_CONFIG".to_string(),
            file.to_str().unwrap().to_string(),
        );
        let g = getenv_map(map);
        let loc = resolve_config_location("", Some(&g)).unwrap();
        assert!(loc.explicit);
        assert_eq!(loc.config_file, file.to_str().unwrap());
        assert!(loc.require_present().is_ok());
    }

    #[test]
    fn test_default_location_and_legacy_fallback() {
        let root = temp_dir("default");
        let home = root.join("home");
        let xdg = home.join(".config");
        std::fs::create_dir_all(&xdg).unwrap();
        let mut map = HashMap::new();
        map.insert("HOME".to_string(), home.to_str().unwrap().to_string());
        map.insert(
            "XDG_CONFIG_HOME".to_string(),
            xdg.to_str().unwrap().to_string(),
        );
        let g = getenv_map(map);
        let loc = resolve_config_location("", Some(&g)).unwrap();
        assert!(!loc.explicit);
        assert_eq!(loc.config_dir, xdg.join("castctl").to_str().unwrap());
        assert!(loc.warnings.is_empty());
        assert!(loc.require_present().is_ok());

        // Legacy fallback: castctl dir missing, muse-cli dir exists.
        let legacy = xdg.join("muse-cli");
        std::fs::create_dir_all(&legacy).unwrap();
        let loc = resolve_config_location("", Some(&g)).unwrap();
        assert_eq!(loc.config_dir, legacy.to_str().unwrap());
        assert_eq!(loc.warnings.len(), 1);
        assert!(loc.warnings[0].contains("legacy config directory"));
    }

    #[test]
    fn test_relative_xdg_warns_and_falls_back() {
        let root = temp_dir("xdg");
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let mut map = HashMap::new();
        map.insert("HOME".to_string(), home.to_str().unwrap().to_string());
        map.insert("XDG_CONFIG_HOME".to_string(), "rel/path".to_string());
        let g = getenv_map(map);
        let loc = resolve_config_location("", Some(&g)).unwrap();
        assert_eq!(
            loc.config_dir,
            home.join(".config/castctl").to_str().unwrap()
        );
        assert_eq!(loc.warnings.len(), 1);
        assert!(loc.warnings[0].contains("XDG_CONFIG_HOME \"rel/path\" is relative"));
    }

    #[test]
    fn test_missing_home_is_fatal() {
        let mut map = HashMap::new();
        map.insert("XDG_CONFIG_HOME".to_string(), String::new());
        map.insert("HOME".to_string(), String::new());
        let g = getenv_map(map);
        let err = resolve_config_location("", Some(&g)).unwrap_err();
        assert_eq!(
            err.message,
            "profile: cannot determine config directory: neither $XDG_CONFIG_HOME nor $HOME are defined"
        );
    }

    #[test]
    fn test_no_home_no_xdg_env_injected() {
        // Both unset in the injected env: the Unix branch errors
        // before touching the process environment.
        let map: HashMap<String, String> = HashMap::new();
        let g = getenv_map(map);
        let err = resolve_config_location("", Some(&g)).unwrap_err();
        assert!(err.message.contains("neither $XDG_CONFIG_HOME nor $HOME"));
    }

    #[test]
    fn test_explicit_blank_falls_through() {
        let root = temp_dir("blank");
        let home = root.join("home");
        let mut map = HashMap::new();
        map.insert("HOME".to_string(), home.to_str().unwrap().to_string());
        let g = getenv_map(map);
        let loc = resolve_config_location("   ", Some(&g)).unwrap();
        assert!(!loc.explicit);
    }
}
