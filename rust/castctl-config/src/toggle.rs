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

use crate::config::{
    SingleConfig, encode_single_config, has_profiles_marker, load_single_config,
    parse_single_config, scan_legacy_config_file,
};
use crate::config_errorf;
use crate::errors::{ConfigError, ErrorKind, config_error, raw_io_error};
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
/// Nested calls deadlock: the flock is held for the whole
/// update and `flock(LOCK_EX)` on an already-held lock
/// blocks — Go documents the same for
/// `UpdateSingleConfig` (`guard.go:183`: "update must not
/// call SaveSingleConfig, ConfigState.Save, or
/// UpdateSingleConfig itself (the lock is already held;
/// nested calls deadlock)"). Rust relies on the flock
/// alone (Go also takes the in-process `configWriteMu`);
/// the flock serializes across threads and processes.
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
    // lockConfigDir (guard.go:226): mkdir the base dir
    // (Go `os.MkdirAll`, ported as `oserr::mkdir_all` —
    // same failing-component rule as the download mkdir
    // arm, R3-B2), open the lock file (0600), flock
    // exclusive. The mkdir/open arms return their errors
    // RAW in Go (exit 1, `mkdir`/`open <path>: ...`); only
    // the flock arm is wrapped (`newConfigErrorf("lock
    // config: %v")` — exit 2, `profile: lock config:
    // ...`). The Rust code mirrors that split (R2-B2 audit).
    // The guard releases the flock (by closing the file)
    // when it drops; the mkdir/open/flock error split is
    // documented on `lock_config_dir` below.
    let _guard = lock_config_dir(base_dir)?;
    update_locked(base_dir, name, key, value)
}

/// A load-time snapshot of `base_dir/config.json` for one
/// checked write (`guard.go`, `ConfigState`).
/// `found` reports whether a parseable single file existed
/// at load; `exists` reports whether config.json existed
/// at load in any form (single file or legacy-flat —
/// `found` implies `exists`, `exists` without `found` is
/// exactly the unmigrated legacy-flat state); `sha256` is
/// the lowercase hex sha256 of the raw bytes read at load,
/// or `""` when the file was absent; `config` is the parsed
/// single file when `found`, `None` otherwise.
#[derive(Debug, Clone)]
pub struct ConfigState {
    pub found: bool,
    pub exists: bool,
    pub sha256: String,
    pub config: Option<SingleConfig>,
}

/// `LoadConfigState` (`guard.go`): read
/// `base_dir/config.json` once and record its sha256. It
/// takes no lock. Returns `found=false` when the file is
/// absent or is a legacy-flat config, and an error when a
/// single file is present but unparseable (never a silent
/// fallback).
pub fn load_config_state(base_dir: &str) -> Result<ConfigState, ConfigError> {
    let (state, _) = read_config_state(base_dir)?;
    Ok(state)
}

/// `readConfigState` (`guard.go`): the file plus the raw
/// bytes (empty when absent). An unparseable single file is
/// an error.
fn read_config_state(base_dir: &str) -> Result<(ConfigState, Vec<u8>), ConfigError> {
    let path = go_join(&[base_dir, "config.json"]);
    let mut state = ConfigState {
        found: false,
        exists: false,
        sha256: String::new(),
        config: None,
    };
    match std::fs::metadata(&path) {
        Err(e) if crate::oserr::is_not_exist(&e) => return Ok((state, Vec::new())),
        Err(e) => {
            return Err(config_errorf!(
                "read config: {}",
                crate::oserr::stat_error_text(&path, &e)
            ));
        }
        Ok(_) => {}
    }
    state.exists = true;
    let data = read_config_bytes(&path)?;
    state.sha256 = sha256_hex(&data);
    if !has_profiles_marker(&data)? {
        return Ok((state, data));
    }
    let cfg = parse_single_config(&data, base_dir)?;
    // Go `readConfigState` parses with `ParseSingleConfig`,
    // which runs the FULL validation chain (tag graph → G1
    // → profile DNS → WireGuard DNS → WireGuard keys →
    // telegram → keeper → credentials → credential refs →
    // plugins). A config with a dangling tag or a bad DNS
    // block therefore fails BEFORE any mutation closure
    // runs — including AddProfile/RemoveProfile/SetOutbound
    // — exactly as in Go. The closure's own re-validation
    // (tag graph + WireGuard keys) still runs afterwards,
    // mirroring Go's double validation.
    state.found = true;
    state.config = Some(cfg);
    Ok((state, data))
}

/// The held config lock: closing the file releases the
/// flock (Go's deferred release in `lockConfigDir`).
/// Dropping the guard releases it.
pub struct ConfigLock {
    _file: std::fs::File,
}

/// `lockConfigDir` (`guard.go:226`): create the base
/// directory if needed, open `config.json.lock` (0600),
/// flock exclusive (blocking). The mkdir/open arms return
/// their errors RAW (exit 1, `mkdir`/`open <path>: ...`);
/// only the flock arm is wrapped (`lock config: %v`,
/// exit 2). Go also takes an in-process mutex; Rust relies
/// on the flock alone — it serialises across threads and
/// processes (same note as `update_single_profile_field`).
/// Nested guarded calls deadlock: the flock is held for
/// the whole update and `flock(LOCK_EX)` on an
/// already-held lock blocks.
pub fn lock_config_dir(base_dir: &str) -> Result<ConfigLock, ConfigError> {
    crate::oserr::mkdir_all(base_dir).map_err(raw_io_error)?;
    let lock_path = go_join(&[base_dir, "config.json.lock"]);
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| raw_io_error(crate::oserr::open_error_text(&lock_path, &e)))?;
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
    Ok(ConfigLock { _file: lock_file })
}

/// `UpdateSingleConfig` (`guard.go`): one guarded
/// read-modify-write — under a single lock hold it loads
/// the current single file (or a fresh empty config when
/// no single file exists), calls `update` to mutate it in
/// place, re-reads the file bytes to confirm nothing
/// changed under the lock, and writes. `update` returning
/// an error writes nothing. A legacy-flat file is NOT
/// loaded into the fresh config: callers that must refuse
/// on an unmigrated old layout check for it themselves
/// (see `refuse_unmigrated`), inside `update`, before
/// mutating. `update` must not call
/// `update_single_config` itself (the lock is already
/// held; nested calls deadlock), and must not read proxy
/// environment variables.
pub fn update_single_config<F>(base_dir: &str, update: F) -> Result<(), ConfigError>
where
    F: FnOnce(&mut SingleConfig) -> Result<(), ConfigError>,
{
    let _guard = lock_config_dir(base_dir)?;
    let (state, data) = read_config_state(base_dir)?;
    let mut cfg = state.config.unwrap_or_default();
    update(&mut cfg)?;
    // Re-read under the lock: the only way the bytes
    // changed since the load is a writer that bypassed
    // the lock. Refuse rather than overwrite its change.
    let path = go_join(&[base_dir, "config.json"]);
    let current = read_config_bytes(&path)?;
    if sha256_hex(&current) != sha256_hex(&data) {
        return Err(ConfigError {
            code: 2,
            kind: ErrorKind::ConcurrentChange,
            message: format!("profile: config changed concurrently, retry: {path}"),
        });
    }
    write_single_config_locked(base_dir, &cfg)?;
    Ok(())
}

/// `writeSingleConfigLocked` (`guard.go`):
/// encode `cfg` and write it atomically (temp file +
/// rename, mode 0600) to `base_dir/config.json`. The
/// caller must hold the config lock. Returns the hex
/// sha256 of the bytes written.
pub fn write_single_config_locked(
    base_dir: &str,
    cfg: &SingleConfig,
) -> Result<String, ConfigError> {
    let text = encode_single_config(cfg)?;
    crate::oserr::mkdir_all(base_dir).map_err(raw_io_error)?;
    let path = go_join(&[base_dir, "config.json"]);
    write_file_atomic(&path, text.as_bytes())?;
    Ok(sha256_hex(text.as_bytes()))
}

/// `refuseUnmigrated` (`internal/profile/profilecmd.go:177`):
/// refuse when the old layout exists unmigrated — no
/// single file and a legacy config file anywhere in the
/// layout, or a base file that exists but is not a single
/// file (the legacy-flat default config). A bare profile
/// directory with no config file is not a legacy layout
/// and does not block.
pub fn refuse_unmigrated(base_dir: &str) -> Result<(), ConfigError> {
    let state = load_config_state(base_dir)?;
    if state.found {
        return Ok(());
    }
    if !state.exists {
        let legacy = scan_legacy_config_file(base_dir, "", true)?;
        if legacy.is_some() {
            return Err(config_error(
                "the old layout exists unmigrated; run config migrate first",
            ));
        }
        return Ok(());
    }
    Err(config_error(
        "the old layout exists unmigrated; run config migrate first",
    ))
}

/// `generateNodeID` (`internal/profile/migrate.go:903`):
/// 16 lowercase hex chars from 8 crypto-random bytes.
/// The RNG failure arm returns a config error (Go:
/// `generate node_id: %v`); in practice the OS RNG does
/// not fail, and `rand` would panic on it if called
/// through `rand::random` — the `try_fill_bytes` form
/// keeps the failure an error instead.
pub fn generate_node_id() -> Result<String, ConfigError> {
    use rand::TryRng;
    let mut b = [0u8; 8];
    rand::rng()
        .try_fill_bytes(&mut b)
        .map_err(|e| config_errorf!("generate node_id: {e}"))?;
    let mut s = String::with_capacity(16);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    Ok(s)
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
/// The file is stat-guarded before opening
/// (`config.go:827`): a FIFO, socket, or device at the
/// path is refused without ever opening it, so a read can
/// never block on a FIFO; a directory is refused the same
/// way. A stat/read error is a `read config: …` error.
fn read_config_bytes(path: &str) -> Result<Vec<u8>, ConfigError> {
    match std::fs::metadata(path) {
        Ok(md) => {
            if !md.is_file() {
                if md.is_dir() {
                    return Err(config_errorf!(
                        "read config: config path {} is a directory, not a file",
                        go_quote(path)
                    ));
                }
                return Err(config_errorf!(
                    "read config: config path {} is not a regular file",
                    go_quote(path)
                ));
            }
        }
        Err(e) if crate::oserr::is_not_exist(&e) => return Ok(Vec::new()),
        Err(e) => {
            return Err(config_errorf!(
                "read config: {}",
                crate::oserr::stat_error_text(path, &e)
            ));
        }
    }
    match std::fs::read(path) {
        Ok(data) => Ok(data),
        Err(e) if crate::oserr::is_not_exist(&e) => Ok(Vec::new()),
        Err(e) => Err(config_errorf!(
            "read config: {}",
            crate::oserr::open_error_text(path, &e)
        )),
    }
}

/// A per-process-unique temp suffix (pid + nanosecond
/// clock + a counter): two writers in the same directory
/// never share a temp name, and `create_new` (O_EXCL)
/// refuses to truncate a pre-existing file. Mirrors Go
/// `os.CreateTemp(dir, ".tmp-*")` (`config.go:1634`).
fn temp_suffix() -> String {
    static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{}-{}-{}", std::process::id(), nanos, n)
}

/// Remove temp files older than an hour left by crashed
/// writers. Best-effort: every failure is ignored, and
/// only the `.config.json.tmp.` prefix is touched. The
/// age gate keeps a concurrent live writer's temp —
/// always fresh — from ever being removed (Go removes
/// only its own temp name, via a deferred `os.Remove`).
fn remove_stale_temp_files(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(".config.json.tmp.") {
            continue;
        }
        let Ok(md) = entry.metadata() else {
            continue;
        };
        let Ok(mtime) = md.modified() else {
            continue;
        };
        let Ok(age) = mtime.elapsed() else {
            continue;
        };
        if age.as_secs() > 3600 {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Atomic write: temp file in the same directory (mode
/// 0600) + rename, mirroring Go `writeFileAtomic`
/// (`config.go:1634`). Errors are RAW `*PathError` /
/// `*LinkError` (exit 1, no `profile: ` prefix, no
/// `write config: ` wrap): Go returns them unwrapped
/// from `writeTempFile` (`open`/`write`/`sync`) and
/// `os.Rename` (`rename <tmp> <path>:`) — red-team
/// round-2 R2-B2.
fn write_file_atomic(path: &str, data: &[u8]) -> Result<(), ConfigError> {
    let dir = Path::new(path)
        .parent()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    remove_stale_temp_files(&dir);
    let (tmp, mut f) = loop {
        let candidate = dir.join(format!(".config.json.tmp.{}", temp_suffix()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(f) => break (candidate, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(raw_io_error(crate::oserr::open_error_text(
                    &candidate.to_string_lossy(),
                    &e,
                )));
            }
        }
    };
    let tmp_s = tmp.to_string_lossy();
    {
        use std::io::Write;
        if let Err(e) = f.write_all(data) {
            let _ = std::fs::remove_file(&tmp);
            return Err(raw_io_error(crate::oserr::write_error_text(&tmp_s, &e)));
        }
        if let Err(e) = f.sync_all() {
            let _ = std::fs::remove_file(&tmp);
            return Err(raw_io_error(crate::oserr::sync_error_text(&tmp_s, &e)));
        }
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(raw_io_error(crate::oserr::rename_error_text(
            &tmp_s, path, &e,
        )));
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
/// `syscall.Errno` text (`permission denied`, `no such
/// file or directory`); Rust's `Display` capitalizes it
/// and appends ` (os error N)`. Reuse the shared `oserr`
/// table, which renders Go's lowercase text.
fn io_error_text(e: &std::io::Error) -> String {
    crate::oserr::os_message(e)
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
    fn write_file_atomic_errors_are_raw_exit_1() {
        // R2-B2: Go's `writeFileAtomic` (`config.go:1634`)
        // returns raw `*PathError` / `*LinkError` — exit 1,
        // no `profile: ` prefix, no `write config: ` wrap.
        let dir = temp_dir("writefail");
        // (a) Rename arm: the target path is a directory.
        // Go's `os.Rename` pre-check reports EEXIST
        // ("file exists") for a directory destination.
        let target = dir.join("config.json");
        std::fs::create_dir_all(&target).unwrap();
        let e = write_file_atomic(target.to_str().unwrap(), b"{}\n").unwrap_err();
        assert_eq!(e.code, 1, "message: {}", e.message);
        assert!(e.message.starts_with("rename "), "message: {}", e.message);
        assert!(
            e.message.ends_with(": file exists"),
            "message: {}",
            e.message
        );
        assert!(!e.message.contains("profile:"), "message: {}", e.message);
        assert!(
            !e.message.contains("write config:"),
            "message: {}",
            e.message
        );
        // (b) Temp-create arm: the parent directory does
        // not exist.
        let missing = dir.join("nope").join("config.json");
        let e = write_file_atomic(missing.to_str().unwrap(), b"{}\n").unwrap_err();
        assert_eq!(e.code, 1, "message: {}", e.message);
        assert!(e.message.starts_with("open "), "message: {}", e.message);
        assert!(
            e.message.ends_with(": no such file or directory"),
            "message: {}",
            e.message
        );
        assert!(!e.message.contains("profile:"), "message: {}", e.message);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_open_error_is_raw_exit_1() {
        // R2-B2 audit: Go's `lockConfigDir` returns the
        // lock-file open error raw (`guard.go:226`), like
        // the write arms — exit 1, `open <lock>: ...`,
        // no `lock config: ` wrap. (The flock arm stays
        // wrapped: Go wraps it with `newConfigErrorf(
        // "lock config: %v")`.)
        let dir = temp_dir("lockfail");
        write_config(
            &dir,
            "{\n  \"default_profile\": \"no.0\",\n  \"profiles\": {\n    \"no.0\": {\"auto_approve\": \"off\"}\n  }\n}\n",
        );
        std::fs::create_dir_all(dir.join("config.json.lock")).unwrap();
        let e = set_auto_approve(dir.to_str().unwrap(), "no.0", "always").unwrap_err();
        assert_eq!(e.code, 1, "message: {}", e.message);
        assert!(e.message.starts_with("open "), "message: {}", e.message);
        assert!(
            e.message.ends_with(": is a directory"),
            "message: {}",
            e.message
        );
        assert!(!e.message.contains("profile:"), "message: {}", e.message);
        assert!(
            !e.message.contains("lock config:"),
            "message: {}",
            e.message
        );
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
    fn io_error_text_is_lowercase_strerror() {
        let e = std::io::Error::from_raw_os_error(13);
        assert_eq!(io_error_text(&e), "permission denied");
        let e = std::io::Error::from_raw_os_error(2);
        assert_eq!(io_error_text(&e), "no such file or directory");
        let e = std::io::Error::other("custom boom");
        assert_eq!(io_error_text(&e), "custom boom");
    }

    #[test]
    fn read_config_bytes_refuses_fifo_without_blocking() {
        // S-N4: a FIFO at the config path is refused by
        // the stat guard before any open, so the read can
        // never block waiting for a writer.
        let dir = temp_dir("fifo");
        let fifo = dir.join("config.json");
        let cpath = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        let rc = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed");
        let e = read_config_bytes(fifo.to_str().unwrap()).unwrap_err();
        assert!(e.message.contains("is not a regular file"), "{}", e.message);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_config_state_shapes() {
        let dir = temp_dir("state");
        // Absent.
        let st = load_config_state(dir.to_str().unwrap()).unwrap();
        assert!(!st.found && !st.exists && st.sha256.is_empty() && st.config.is_none());
        // Legacy-flat base file: exists, not found.
        write_config(&dir, "{\"auto_approve\": \"off\"}\n");
        let st = load_config_state(dir.to_str().unwrap()).unwrap();
        assert!(!st.found && st.exists && !st.sha256.is_empty() && st.config.is_none());
        // Single file: found, sha matches the bytes.
        write_config(&dir, "{\n  \"profiles\": {\n    \"no.0\": {}\n  }\n}\n");
        let raw = std::fs::read(dir.join("config.json")).unwrap();
        let st = load_config_state(dir.to_str().unwrap()).unwrap();
        assert!(st.found && st.exists);
        assert_eq!(st.sha256, sha256_hex(&raw));
        assert!(st.config.unwrap().profiles.contains_key("no.0"));
        // Unparseable single file: error, never a fallback.
        write_config(&dir, "{\n  \"profiles\": {\n");
        let e = load_config_state(dir.to_str().unwrap()).unwrap_err();
        assert_eq!(e.code, 2, "message: {}", e.message);
        assert!(e.message.contains("invalid json"), "message: {}", e.message);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_single_config_round_trip() {
        let dir = temp_dir("update");
        write_config(
            &dir,
            "{\n  \"default_profile\": \"no.0\",\n  \"profiles\": {\n    \"no.0\": {\n      \"auto_approve\": \"off\"\n    }\n  }\n}\n",
        );
        update_single_config(dir.to_str().unwrap(), |cfg| {
            let p = cfg.profiles.get_mut("no.0").unwrap();
            p.auto_approve = "always".to_string();
            Ok(())
        })
        .unwrap();
        let out = read_config(&dir);
        assert!(out.contains("\"auto_approve\": \"always\""), "got:\n{out}");
        assert!(out.ends_with('\n'));
        // Canonical top-level order (buildSingleFileOrdered):
        // default_profile first.
        assert!(
            out.find("\"default_profile\"").unwrap() < out.find("\"profiles\"").unwrap(),
            "got:\n{out}"
        );
        // Mode 0600, lock file present (never deleted).
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("config.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "mode {mode:o}");
        assert!(dir.join("config.json.lock").exists());
        // A closure error writes nothing.
        update_single_config(dir.to_str().unwrap(), |_| Err(config_error("boom"))).unwrap_err();
        assert!(read_config(&dir).contains("\"auto_approve\": \"always\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_single_config_creates_fresh_file() {
        let dir = temp_dir("create");
        update_single_config(dir.to_str().unwrap(), |cfg| {
            cfg.default_profile = "no.0".to_string();
            Ok(())
        })
        .unwrap();
        let out = read_config(&dir);
        assert!(out.contains("\"default_profile\": \"no.0\""), "got:\n{out}");
        assert!(out.contains("\"profiles\": {}"), "got:\n{out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_single_config_locked_returns_sha() {
        let dir = temp_dir("locked");
        let cfg = SingleConfig {
            default_profile: "no.0".to_string(),
            ..Default::default()
        };
        let hash = write_single_config_locked(dir.to_str().unwrap(), &cfg).unwrap();
        let raw = std::fs::read(dir.join("config.json")).unwrap();
        assert_eq!(hash, sha256_hex(&raw));
        assert_eq!(hash.len(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuse_unmigrated_shapes() {
        // Bare dir: no legacy anywhere, OK.
        let dir = temp_dir("refuse-bare");
        refuse_unmigrated(dir.to_str().unwrap()).unwrap();
        // Legacy-flat base file: refuse.
        write_config(&dir, "{\"auto_approve\": \"off\"}\n");
        let e = refuse_unmigrated(dir.to_str().unwrap()).unwrap_err();
        assert_eq!(e.code, 2);
        assert_eq!(
            e.message,
            "profile: the old layout exists unmigrated; run config migrate first"
        );
        // Single file: OK.
        write_config(&dir, "{\n  \"profiles\": {}\n}\n");
        refuse_unmigrated(dir.to_str().unwrap()).unwrap();
        // Legacy per-profile file under profiles/: refuse.
        let dir2 = temp_dir("refuse-prof");
        let pdir = dir2.join("profiles").join("old");
        std::fs::create_dir_all(&pdir).unwrap();
        std::fs::write(pdir.join("config.json"), "{}\n").unwrap();
        let e = refuse_unmigrated(dir2.to_str().unwrap()).unwrap_err();
        assert_eq!(e.code, 2, "message: {}", e.message);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn generate_node_id_shape() {
        let a = generate_node_id().unwrap();
        let b = generate_node_id().unwrap();
        assert_eq!(a.len(), 16, "id: {a}");
        assert!(
            a.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(a, b);
    }
}
