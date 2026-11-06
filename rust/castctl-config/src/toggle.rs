// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Targeted single-file toggle edits: `SetAutoApprove` /
//! `SetAutoAllowOnce`.
//!
//! Go sources: `internal/profile/profilecmd.go:552,590`
//! (`SetAutoApprove`, `SetAutoAllowOnce`) and
//! `internal/profile/guard.go:183`
//! (`UpdateSingleConfig`, the flock + sha256 guarded
//! writer).
//!
//! DEVIATION (safer direction, recorded in PORTING.md
//! §M7b): Go re-encodes through `buildSingleFileOrdered`,
//! which emits keys in canonical struct order and
//! re-marshals numbers through typed values. This writer
//! edits the ordered JSON document in place (decode to
//! ordered `JsonValue`, mutate one field, re-encode with
//! the same 2-space indent + trailing newline), so the
//! file's key order and number literals survive
//! byte-for-byte. (Unknown keys are rejected by the
//! parse pre-check on both sides, so there is nothing
//! extra to preserve there.) The flock + sha256 re-read
//! guard and the atomic temp+rename write (mode 0600)
//! match Go exactly.

use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::config::load_single_config;
use crate::config_errorf;
use crate::errors::{ConfigError, ErrorKind, config_error};
use crate::gopath::go_join;
use crate::gostr::go_quote;
use crate::jsonvalue::{JsonValue, decode_ordered_json, encode_ordered_json_indent};
use crate::profile::validate_profile_name;

/// Set a profile's `auto_approve` value (`"always"` or
/// `"off"`) in the single file, guarded by the flock +
/// sha256 writer. The profile must already exist; a
/// legacy layout is never written back to.
/// Source: `internal/profile/profilecmd.go:552`.
pub fn set_auto_approve(base_dir: &str, name: &str, value: &str) -> Result<(), ConfigError> {
    validate_profile_name(name)?;
    if value != "always" && value != "off" {
        return Err(config_errorf!(
            "auto_approve must be \"always\" or \"off\", not {}",
            go_quote(value)
        ));
    }
    update_single_profile_field(
        base_dir,
        name,
        "auto_approve",
        JsonValue::Str(value.to_string()),
    )
}

/// Set a profile's `auto_allow_once` fallback toggle in
/// the single file, guarded the same way.
/// Source: `internal/profile/profilecmd.go:590`.
pub fn set_auto_allow_once(base_dir: &str, name: &str, value: bool) -> Result<(), ConfigError> {
    validate_profile_name(name)?;
    update_single_profile_field(base_dir, name, "auto_allow_once", JsonValue::Bool(value))
}

/// The guarded read-modify-write shared by the two
/// setters: load state, refuse when there is no single
/// file or no such profile, then take the flock, re-read
/// the bytes under the lock, edit the ordered document in
/// place, re-read to confirm nothing changed under the
/// lock, and write atomically (temp + rename, mode
/// 0600). Mirrors `UpdateSingleConfig` (`guard.go:183`).
fn update_single_profile_field(
    base_dir: &str,
    name: &str,
    key: &str,
    value: JsonValue,
) -> Result<(), ConfigError> {
    let (state, found) = load_single_config(base_dir)?;
    if !found {
        return Err(config_error(
            "auto-approve only modifies single-file entries; no single config file exists (run config migrate first)",
        ));
    }
    let Some(cfg) = state else {
        return Err(config_error(
            "auto-approve only modifies single-file entries; no single config file exists (run config migrate first)",
        ));
    };
    if !cfg.profiles.contains_key(name) {
        return Err(config_errorf!(
            "profile {} does not exist in the single config file",
            go_quote(name)
        ));
    }
    // lockConfigDir (guard.go:226): mkdir the base dir,
    // open the lock file (0600), flock exclusive.
    std::fs::create_dir_all(base_dir)
        .map_err(|e| config_errorf!("lock config: {}", io_error_text(&e)))?;
    let lock_path = go_join(&[base_dir, "config.json.lock"]);
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| config_errorf!("lock config: {}", io_error_text(&e)))?;
    // SAFETY: `flock` on a valid open file descriptor;
    // LOCK_EX blocks until the lock is held. This is the
    // crate's only `unsafe` call (the inter-process lock
    // has no safe std equivalent).
    let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(config_errorf!(
            "lock config: {}",
            io_error_text(&std::io::Error::last_os_error())
        ));
    }
    let result = update_locked(base_dir, name, key, value);
    // Closing the file releases the flock (deferred
    // release in Go); the result is returned unchanged.
    drop(lock_file);
    result
}

/// The body of the guarded update, run while the flock is
/// held. `data` is the file bytes read under the lock.
fn update_locked(
    base_dir: &str,
    name: &str,
    key: &str,
    value: JsonValue,
) -> Result<(), ConfigError> {
    let path = go_join(&[base_dir, "config.json"]);
    let data = read_config_bytes(&path)?;
    if data.is_empty() {
        // Deleted between the load and the lock: Go would
        // see Found=false here and the update would fail
        // on the missing profile.
        return Err(config_errorf!(
            "profile {} does not exist in the single config file",
            go_quote(name)
        ));
    }
    let mut doc = decode_ordered_json(&data)?;
    let JsonValue::Object(root) = &mut doc else {
        return Err(config_error("read config: config.json is not an object"));
    };
    // OrderedObject has no get_mut: clone the two levels,
    // set the field, and write the clones back. `set`
    // keeps an existing key's position, so key order is
    // preserved; a missing key appends at the end.
    let Some(JsonValue::Object(profiles)) = root.get("profiles") else {
        return Err(config_errorf!(
            "profile {} does not exist in the single config file",
            go_quote(name)
        ));
    };
    let Some(JsonValue::Object(profile)) = profiles.get(name) else {
        return Err(config_errorf!(
            "profile {} does not exist in the single config file",
            go_quote(name)
        ));
    };
    let mut profile = profile.clone();
    profile.set(key.to_string(), value);
    let mut profiles = profiles.clone();
    profiles.set(name.to_string(), JsonValue::Object(profile));
    root.set("profiles".to_string(), JsonValue::Object(profiles));
    let mut out = encode_ordered_json_indent(&doc, 2)?;
    out.push('\n');
    // Re-read under the lock: the only way the bytes
    // changed since the load is a writer that bypassed
    // the lock. Refuse rather than overwrite its change.
    let current = read_config_bytes(&path)?;
    if sha256_hex(&current) != sha256_hex(&data) {
        return Err(ConfigError {
            code: 2,
            kind: ErrorKind::ConcurrentChange,
            message: format!("profile: config changed concurrently, retry: {path}"),
        });
    }
    write_file_atomic(&path, out.as_bytes())
}

/// Read `config.json` bytes, tolerating absence (Go
/// `readRegularFile` returns nil bytes on `IsNotExist`).
/// A directory in its place, or any other read error, is
/// a `read config: …` error.
fn read_config_bytes(path: &str) -> Result<Vec<u8>, ConfigError> {
    match std::fs::read(path) {
        Ok(data) => Ok(data),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => {
            if Path::new(path).is_dir() {
                Err(config_errorf!("read config: {} is a directory", path))
            } else {
                Err(config_errorf!("read config: {}", io_error_text(&e)))
            }
        }
    }
}

/// Atomic write: temp file in the same directory (mode
/// 0600) + rename, mirroring Go `writeFileAtomic`.
fn write_file_atomic(path: &str, data: &[u8]) -> Result<(), ConfigError> {
    let dir = Path::new(path)
        .parent()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    let tmp = dir.join(format!(".config.json.tmp.{}", std::process::id()));
    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(config_errorf!("write config: {}", io_error_text(&e)));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(config_errorf!("write config: {}", io_error_text(&e)));
    }
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let sum = h.finalize();
    let mut s = String::with_capacity(64);
    for b in sum {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Go `%v` of an `os` error prints the lowercase
/// message (`permission denied`, `no such file or
/// directory`); Rust's `Display` appends ` (os error N)`.
/// Strip that suffix so config error text matches Go.
fn io_error_text(e: &std::io::Error) -> String {
    let text = e.to_string();
    match text.rfind(" (os error ") {
        Some(idx) if text.ends_with(')') => text[..idx].to_string(),
        _ => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "castctl-config-toggle-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_config(dir: &std::path::Path, text: &str) {
        std::fs::write(dir.join("config.json"), text).unwrap();
    }

    fn read_config(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join("config.json")).unwrap()
    }

    #[test]
    fn set_auto_approve_round_trip_preserves_key_order() {
        let dir = temp_dir("approve");
        // Non-canonical key order must survive: Go's
        // buildSingleFileOrdered re-emits canonical struct
        // order; this writer preserves the file's order
        // (recorded deviation, safer direction).
        write_config(
            &dir,
            "{\n  \"profiles\": {\n    \"no.0\": {\n      \"auto_approve\": \"off\",\n      \"auto_allow_once\": false\n    }\n  },\n  \"default_profile\": \"no.0\"\n}\n",
        );
        set_auto_approve(dir.to_str().unwrap(), "no.0", "always").unwrap();
        let out = read_config(&dir);
        assert!(out.contains("\"auto_approve\": \"always\""));
        assert!(out.ends_with('\n'));
        assert!(
            out.find("\"profiles\"").unwrap() < out.find("\"default_profile\"").unwrap(),
            "key order preserved, got:\n{out}"
        );
        // And back.
        set_auto_approve(dir.to_str().unwrap(), "no.0", "off").unwrap();
        assert!(read_config(&dir).contains("\"auto_approve\": \"off\""));
        // Once toggle, bool round-trip.
        set_auto_allow_once(dir.to_str().unwrap(), "no.0", true).unwrap();
        assert!(read_config(&dir).contains("\"auto_allow_once\": true"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_auto_approve_errors() {
        let dir = temp_dir("errors");
        // No single file at all.
        let e = set_auto_approve(dir.to_str().unwrap(), "no.0", "always").unwrap_err();
        assert_eq!(
            e.message,
            "profile: auto-approve only modifies single-file entries; no single config file exists (run config migrate first)"
        );
        write_config(
            &dir,
            "{\n  \"default_profile\": \"no.0\",\n  \"profiles\": {\n    \"no.0\": {\"auto_approve\": \"off\"}\n  }\n}\n",
        );
        // Bad value.
        let e = set_auto_approve(dir.to_str().unwrap(), "no.0", "sometimes").unwrap_err();
        assert_eq!(
            e.message,
            "profile: auto_approve must be \"always\" or \"off\", not \"sometimes\""
        );
        // Missing profile.
        let e = set_auto_approve(dir.to_str().unwrap(), "ghost", "always").unwrap_err();
        assert_eq!(
            e.message,
            "profile: profile \"ghost\" does not exist in the single config file"
        );
        // Bad name.
        let e = set_auto_approve(dir.to_str().unwrap(), ".bad.", "always").unwrap_err();
        assert_eq!(e.kind, ErrorKind::InvalidProfile);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn io_error_text_strips_os_error_suffix() {
        let e = std::io::Error::from_raw_os_error(13);
        assert_eq!(io_error_text(&e), "Permission denied");
        let e = std::io::Error::other("custom boom");
        assert_eq!(io_error_text(&e), "custom boom");
    }
}
