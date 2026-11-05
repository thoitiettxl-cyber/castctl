// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Config store (`internal/webui/store.go`): `loadConfig`,
//! `parseLoaded`, `saveGuarded` / `saveMerged` /
//! `saveDirect` / `saveSubmitted`, `configSource`,
//! `legacyProfileNames`, `summarizeObject`.
//!
//! The save funnel, in order (see `saveGuarded` in Go):
//! legacy check → 409 on base_sha256 mismatch → decode
//! stored doc → snapshot stored cookies/ui_dir/token →
//! mutate → containment on NEW values only → whitespace
//! keys → ordered marshal → FULL re-parse (parse +
//! tag/keeper/credential/webui validation) → R8 sentinel
//! assertion → hash-on-save (plaintext webui.token →
//! bcrypt cost 10) → flock + atomic temp+rename 0600 →
//! token comparator refresh (by the caller).
//!
//! The file is written from the RE-PARSED struct
//! (`encode_single_config`), never from the merged generic
//! bytes directly — Go's `Save(parsed)` re-encodes from
//! the parsed struct, so this port does the same.

use crate::auth::{REDACTED_MARKER, hash_token, looks_like_bcrypt_hash};
use crate::contain::{
    contained_in_dir, path_within, resolve_against, resolve_path_best_effort,
};
use crate::error::{
    ApiError, err_config_changed, err_internal, err_not_found, err_validation, safe_message,
};
use crate::guarded::{ConfigState, SaveError, sha256_hex};
use crate::merge::{check_whitespace_keys, find_sentinel_at_secret_position, merge_config};
use crate::ordered::marshal_ordered;
use crate::validate::{KeeperEntry, parse_and_validate_config};
use castctl_config::jsonvalue::{
    JsonValue, OrderedObject, decode_ordered_json, encode_ordered_json,
};
use castctl_config::{SingleConfig, encode_single_config, profile_paths};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// One loaded config: raw bytes + hash + load state
/// (`configLoad` in Go).
#[derive(Debug, Clone)]
pub struct ConfigLoad {
    /// Raw file bytes (empty when absent).
    pub raw: Vec<u8>,
    /// Lowercase hex sha256 of the raw bytes ("" when absent).
    pub hash: String,
    /// Load state (exists/found for the legacy/absent checks).
    pub state: ConfigState,
}

/// `loadConfig`: load the state; an unparseable single
/// file is 400 `stored config is invalid: ...`. When the
/// file exists, re-read it with a plain read (a race with
/// a delete is 409; any other read error is 500).
pub fn load_config(config_dir: &Path) -> Result<ConfigLoad, ApiError> {
    let state = ConfigState::load(config_dir).map_err(|e| {
        err_validation(format!("stored config is invalid: {}", safe_message_str(&e)))
    })?;
    let mut raw: Vec<u8> = Vec::new();
    if state.exists {
        match std::fs::read(config_dir.join("config.json")) {
            Ok(data) => raw = data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(err_config_changed());
            }
            Err(_) => return Err(err_internal()),
        }
    }
    Ok(ConfigLoad { raw, hash: state.sha256.clone(), state })
}

fn safe_message_str(msg: &str) -> String {
    castctl_log_redact::safe_string(msg)
}

/// `parseLoaded`: refuse legacy-only (400) and absent
/// (404) layouts; parse + fully validate the stored
/// document (400 `stored config is invalid: ...`).
pub fn parse_loaded(
    load: &ConfigLoad,
    config_dir: &Path,
) -> Result<(SingleConfig, Vec<KeeperEntry>), ApiError> {
    if load.state.exists && !load.state.found {
        return Err(err_validation(
            "legacy layout: run castctl config migrate in the CLI; the web UI does not migrate",
        ));
    }
    if !load.state.found {
        return Err(err_not_found("no config file"));
    }
    parse_and_validate_config(&load.raw, config_dir).map_err(|e| {
        err_validation(format!("stored config is invalid: {}", safe_message_str(&e)))
    })
}

/// Outcome of a successful guarded save: the new file
/// sha256, the saved webui token (if the saved document
/// carries one — already hashed when it was plaintext),
/// and whether the STORED document carried a token (for
/// the comparator refresh).
#[derive(Debug, Clone)]
pub struct SaveOutcome {
    pub sha256: String,
    pub webui_token: Option<String>,
    pub stored_had_token: bool,
}

/// `saveGuarded`: the single save funnel. `expected_sha`
/// is checked only when `check_expected` is true
/// (`saveMerged`); `saveDirect` passes the freshly loaded
/// hash with `check_expected=false` (the under-lock
/// re-read still refuses a concurrent change).
pub fn save_guarded<F>(
    load: &ConfigLoad,
    config_dir: &Path,
    expected_sha: &str,
    check_expected: bool,
    mutate: F,
) -> Result<SaveOutcome, ApiError>
where
    F: FnOnce(&mut JsonValue) -> Result<(), ApiError>,
{
    if load.state.exists && !load.state.found {
        return Err(err_validation(
            "legacy layout: run castctl config migrate in the CLI; the web UI does not migrate",
        ));
    }
    if check_expected && load.hash != expected_sha {
        return Err(err_config_changed());
    }
    let mut stored = JsonValue::Object(OrderedObject::new());
    if !load.raw.is_empty() {
        // Go decodes the stored document with
        // `decodeGeneric`: the first JSON value only,
        // trailing data ignored, invalid UTF-8 coerced to
        // U+FFFD by encoding/json — never a UTF-8 error.
        let text = String::from_utf8_lossy(&load.raw).into_owned();
        stored = crate::go_decode::decode_first_value(text.as_bytes()).map_err(|e| {
            err_validation(format!(
                "stored config is invalid: {}",
                safe_message_str(&e.message())
            ))
        })?;
    }
    let JsonValue::Object(_) = &stored else {
        return Err(err_validation("config document must be a JSON object"));
    };
    let stored_cookies = profile_cookies_files(&stored);
    let (stored_ui_dir, stored_ui_dir_has) = webui_ui_dir_value(&stored);
    let stored_had_token = stored_webui_token(&stored);

    let mut doc = stored.clone();
    mutate(&mut doc)?;

    // Containment on NEW cookies_file values only.
    let stored_values: HashSet<&str> =
        stored_cookies.values().map(|v| v.as_str()).collect();
    for (name, value) in profile_cookies_files(&doc) {
        if !stored_values.contains(value.as_str())
            && !is_own_cookies_file(config_dir, &name, &value)
        {
            reject_new_cookies_file(config_dir, &value)?;
        }
    }
    // B-1: a new or changed ui_dir is re-checked.
    if let (Some(merged_ui_dir), _) = webui_ui_dir_value(&doc) {
        if !merged_ui_dir.is_empty()
            && (!stored_ui_dir_has || stored_ui_dir.as_deref() != Some(merged_ui_dir.as_str()))
        {
            reject_new_ui_dir(config_dir, &merged_ui_dir, &profile_cookies_files(&doc))?;
        }
    }
    if let Err(rej) = check_whitespace_keys(&doc, "") {
        return Err(err_validation(format!("invalid key at {}", rej.path)));
    }
    let merged = marshal_ordered(&load.raw, &doc).map_err(|_| err_internal())?;
    let (mut parsed, _) = parse_and_validate_config(&merged, config_dir).map_err(|e| {
        err_validation(format!("merged config is invalid: {}", safe_message_str(&e)))
    })?;
    // R8 assertion on the merged document as written.
    let merged_text = String::from_utf8(merged.clone()).map_err(|_| err_internal())?;
    let merged_doc = decode_ordered_json(&merged_text).map_err(|_| err_internal())?;
    if let Some(path) = find_sentinel_at_secret_position(&merged_doc, false, "") {
        return Err(err_validation(format!(
            "redacted value at {path} has no stored value to keep"
        )));
    }
    // Hash-on-save: a plaintext webui.token is hashed with
    // bcrypt before persisting. The sentinel can never
    // reach here (R1 restores it, R8 rejects it), so a
    // Marker here is an internal error.
    let mut webui_token: Option<String> = None;
    if let Some(JsonValue::Object(webui)) = parsed.webui_raw.as_ref() {
        if let Some(JsonValue::Str(token)) = webui.get("token") {
            if !token.is_empty() {
                if !looks_like_bcrypt_hash(token) {
                    if token == REDACTED_MARKER {
                        return Err(err_internal());
                    }
                    let hash = hash_token(token).map_err(|e| {
                        err_validation(format!(
                            "webui token is invalid: {}",
                            safe_message_str(&e)
                        ))
                    })?;
                    if let Some(JsonValue::Object(webui_mut)) = parsed.webui_raw.as_mut() {
                        webui_mut.set("token".to_string(), JsonValue::Str(hash.clone()));
                    }
                    webui_token = Some(hash);
                } else {
                    webui_token = Some(token.clone());
                }
            }
        }
    }
    let encoded = encode_single_config(&parsed).map_err(|_| err_internal())?;
    let mut state = load.state.clone();
    let new_sha = state.save(encoded.as_bytes()).map_err(|e| match e {
        SaveError::ConcurrentChange => err_config_changed(),
        SaveError::Internal => err_internal(),
    })?;
    Ok(SaveOutcome { sha256: new_sha, webui_token, stored_had_token })
}

/// `saveMerged`: save with a client-supplied base_sha256
/// (409 on mismatch, no write, no merge).
pub fn save_merged<F>(
    load: &ConfigLoad,
    config_dir: &Path,
    base_sha: &str,
    mutate: F,
) -> Result<SaveOutcome, ApiError>
where
    F: FnOnce(&mut JsonValue) -> Result<(), ApiError>,
{
    save_guarded(load, config_dir, base_sha, true, mutate)
}

/// `saveDirect`: save with no client hash (the expected
/// hash is the freshly loaded one).
pub fn save_direct<F>(
    load: &ConfigLoad,
    config_dir: &Path,
    mutate: F,
) -> Result<SaveOutcome, ApiError>
where
    F: FnOnce(&mut JsonValue) -> Result<(), ApiError>,
{
    let expected = load.hash.clone();
    save_guarded(load, config_dir, &expected, false, mutate)
}

/// `saveSubmitted`: PUT /config's path — merge a full
/// submitted document against the stored one with the
/// sentinel merge, then save through the guarded funnel.
pub fn save_submitted(
    load: &ConfigLoad,
    config_dir: &Path,
    base_sha: &str,
    submitted: &JsonValue,
) -> Result<SaveOutcome, ApiError> {
    let JsonValue::Object(_) = submitted else {
        return Err(err_validation("config document must be a JSON object"));
    };
    if let Err(rej) = check_whitespace_keys(submitted, "") {
        return Err(err_validation(format!("invalid key at {}", rej.path)));
    }
    let mut stored = JsonValue::Object(OrderedObject::new());
    if !load.raw.is_empty() {
        // `decodeGeneric` semantics: first value only,
        // invalid UTF-8 coerced (see save_merged above).
        let text = String::from_utf8_lossy(&load.raw).into_owned();
        stored = crate::go_decode::decode_first_value(text.as_bytes()).map_err(|e| {
            err_validation(format!(
                "stored config is invalid: {}",
                safe_message_str(&e.message())
            ))
        })?;
    }
    let merged = merge_config(&stored, submitted).map_err(|rej| {
        err_validation(format!(
            "redacted value at {} has no stored value to keep",
            rej.path
        ))
    })?;
    let JsonValue::Object(_) = &merged else {
        return Err(err_validation("config document must be a JSON object"));
    };
    let merged_owned = merged.clone();
    save_merged(load, config_dir, base_sha, move |doc| {
        *doc = merged_owned;
        Ok(())
    })
}

/// `profileCookiesFiles`: each profile's `cookies_file`
/// string, by profile name. Non-string or missing values
/// are absent (the config parser rejects them separately).
pub fn profile_cookies_files(doc: &JsonValue) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let JsonValue::Object(root) = doc else {
        return out;
    };
    let Some(JsonValue::Object(profiles)) = root.get("profiles") else {
        return out;
    };
    for (name, entry) in profiles.iter() {
        if let JsonValue::Object(entry_obj) = entry {
            if let Some(JsonValue::Str(cookies)) = entry_obj.get("cookies_file") {
                out.insert(name.clone(), cookies.clone());
            }
        }
    }
    out
}

/// `webUIUIDirValue`: the `webui.ui_dir` string and
/// whether the key is present. A missing block, missing
/// key or non-string value is absent.
pub fn webui_ui_dir_value(doc: &JsonValue) -> (Option<String>, bool) {
    let JsonValue::Object(root) = doc else {
        return (None, false);
    };
    let Some(JsonValue::Object(block)) = root.get("webui") else {
        return (None, false);
    };
    match block.get("ui_dir") {
        Some(JsonValue::Str(s)) => (Some(s.clone()), true),
        _ => (None, false),
    }
}

/// `storedWebUIToken`: whether the document carries a
/// non-empty `webui.token`.
pub fn stored_webui_token(doc: &JsonValue) -> bool {
    let JsonValue::Object(root) = doc else {
        return false;
    };
    let Some(JsonValue::Object(block)) = root.get("webui") else {
        return false;
    };
    matches!(block.get("token"), Some(JsonValue::Str(t)) if !t.is_empty())
}

/// `isOwnCookiesFile`: whether `value` names the
/// profile's own cookies file, in either spelling
/// (absolute or relative to the config dir).
pub fn is_own_cookies_file(config_dir: &Path, name: &str, value: &str) -> bool {
    let Ok(paths) = profile_paths(&config_dir.to_string_lossy(), name) else {
        return false;
    };
    let resolved = if Path::new(value).is_absolute() {
        value.to_string()
    } else {
        config_dir.join(value).to_string_lossy().into_owned()
    };
    let cleaned = crate::contain::clean_path(Path::new(&resolved));
    cleaned.to_string_lossy() == paths.cookies
}

/// `rejectNewCookiesFile`: absolute values are refused
/// with one message, relative values escaping the config
/// dir with another (the two messages differ by one word —
/// do not unify them).
pub fn reject_new_cookies_file(config_dir: &Path, value: &str) -> Result<(), ApiError> {
    if Path::new(value).is_absolute() {
        return Err(err_validation(
            "cookies_file must be a relative path inside the config directory",
        ));
    }
    if !contained_in_dir(value, config_dir) {
        return Err(err_validation(
            "cookies_file must stay inside the config directory",
        ));
    }
    Ok(())
}

/// `rejectNewUIDir`: a ui_dir the save introduces must
/// not overlap the config directory in either direction,
/// must not contain any cookies file named in the
/// document, and its `index.html` (when present) must not
/// be a symlink. A missing index.html is NOT refused here.
pub fn reject_new_ui_dir(
    config_dir: &Path,
    value: &str,
    cookies_files: &HashMap<String, String>,
) -> Result<(), ApiError> {
    let root = resolve_against(config_dir, value);
    let base = resolve_path_best_effort(config_dir);
    if path_within(&root, &base) || path_within(&base, &root) {
        return Err(err_validation(
            "webui.ui_dir must not overlap the config directory",
        ));
    }
    for cookies_file in cookies_files.values() {
        if path_within(&resolve_against(config_dir, cookies_file), &root) {
            return Err(err_validation(
                "webui.ui_dir must not contain a cookies file",
            ));
        }
    }
    if let Ok(md) = std::fs::symlink_metadata(root.join("index.html")) {
        if md.file_type().is_symlink() {
            return Err(err_validation(
                "webui.ui_dir index.html must not be a symlink",
            ));
        }
    }
    Ok(())
}

/// `configSource`: "single-file" / "legacy" / "mixed" /
/// "none". An enumeration error degrades to no legacy
/// profiles shown (only the log gate fails closed on it).
pub fn config_source(load: &ConfigLoad, config_dir: &Path, cfg: &SingleConfig) -> String {
    let legacy_names = legacy_profile_names_in(config_dir, cfg).unwrap_or_default();
    if !load.state.found {
        if !legacy_names.is_empty() {
            return "legacy".to_string();
        }
        return "none".to_string();
    }
    if !legacy_names.is_empty() {
        return "mixed".to_string();
    }
    "single-file".to_string()
}

/// `legacyProfileNames`: names of legacy profile
/// directories under `profiles/` that are not keys of the
/// single-file document — a directory carrying a
/// `config.json`. A symlink to a directory IS followed.
/// An error is returned when the profiles directory cannot
/// be listed (other than not existing), when a symlink
/// entry's target cannot be stat'ed, or when a candidate
/// entry's `config.json` cannot be stat'ed (other than not
/// existing). Invalid-name directories are still listed.
pub fn legacy_profile_names_in(
    config_dir: &Path,
    cfg: &SingleConfig,
) -> Result<Vec<String>, String> {
    let profiles_dir = config_dir.join("profiles");
    let entries = match std::fs::read_dir(&profiles_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if cfg.profiles.contains_key(&name) {
            continue;
        }
        let path = entry.path();
        let md = match std::fs::metadata(&path) {
            Ok(md) => md,
            Err(e) => return Err(e.to_string()),
        };
        if !md.is_dir() {
            continue;
        }
        match std::fs::metadata(path.join("config.json")) {
            Ok(_) => names.push(name),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    names.sort();
    Ok(names)
}

/// `summarizeObject` (`store.go`): `"<type> <host>:<port>"`
/// (host = first non-empty of `server` / `address` / `host`
/// as strings, else the first element of an `address`
/// array; port = first of `server_port` / `port`, the
/// `json.Number` literal), else `"<type> <host>"`, else
/// `"<type>"`, else `""`.
pub fn summarize_object(obj: &OrderedObject) -> String {
    let typ = match obj.get("type") {
        Some(JsonValue::Str(t)) => t.clone(),
        _ => String::new(),
    };
    let mut host = String::new();
    for key in ["server", "address", "host"] {
        if let Some(JsonValue::Str(s)) = obj.get(key) {
            if !s.is_empty() {
                host = s.clone();
                break;
            }
        }
    }
    if host.is_empty() {
        if let Some(JsonValue::Array(items)) = obj.get("address") {
            if let Some(JsonValue::Str(s)) = items.first() {
                host = s.clone();
            }
        }
    }
    let mut port = String::new();
    for key in ["server_port", "port"] {
        if let Some(JsonValue::Number(n)) = obj.get(key) {
            port = n.clone();
            break;
        }
    }
    if !typ.is_empty() && !host.is_empty() && !port.is_empty() {
        return format!("{typ} {host}:{port}");
    }
    if !typ.is_empty() && !host.is_empty() {
        return format!("{typ} {host}");
    }
    if !typ.is_empty() {
        return typ;
    }
    String::new()
}

/// `usedByOutbound`: profile names whose outbound tag
/// (tag reference or inline auto-tag) equals `tag`, sorted.
/// Direct profiles never match (their tag is empty).
pub fn used_by_outbound(cfg: &SingleConfig, tag: &str) -> Vec<String> {
    let mut names: Vec<String> = cfg
        .profiles
        .iter()
        .filter(|(_, p)| {
            p.outbound.tag == tag
                && !matches!(
                    p.outbound.kind,
                    castctl_config::profile::OutboundKind::Direct
                )
        })
        .map(|(name, _)| name.clone())
        .collect();
    names.sort();
    names
}

/// `usedByEndpoint`: names referencing an endpoint tag —
/// profiles whose outbound tag equals it, and outbounds
/// whose `detour` / `endpoint` field names it. Deduped,
/// sorted.
pub fn used_by_endpoint(cfg: &SingleConfig, tag: &str) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut names: Vec<String> = Vec::new();
    let mut add = |name: &str, seen: &mut HashSet<String>, names: &mut Vec<String>| {
        if !name.is_empty() && seen.insert(name.to_string()) {
            names.push(name.to_string());
        }
    };
    for (name, p) in cfg.profiles.iter() {
        if p.outbound.tag == tag {
            add(name, &mut seen, &mut names);
        }
    }
    if let Some(JsonValue::Array(obs)) = &cfg.outbounds_raw {
        for ob in obs {
            if let JsonValue::Object(o) = ob {
                for key in ["detour", "endpoint"] {
                    if let Some(JsonValue::Str(s)) = o.get(key) {
                        if s == tag {
                            if let Some(JsonValue::Str(t)) = o.get("tag") {
                                add(t, &mut seen, &mut names);
                            }
                        }
                    }
                }
            }
        }
    }
    names.sort();
    names
}

/// Encode a [`JsonValue`] as compact JSON with Go's
/// ordered encoder (no HTML escaping) — the display
/// encoding for redacted config text.
pub fn encode_ordered(value: &JsonValue) -> String {
    encode_ordered_json(value)
}
