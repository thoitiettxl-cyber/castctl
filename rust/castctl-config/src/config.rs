// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The parsed single-file config: parse, render, load, and
//! active-profile resolution.
//!
//! Sources at base `dev-rust` `85a8d5e`: `internal/profile/config.go`
//! (`SingleConfig`, `ParseSingleConfig`, `buildSingleFileOrdered`,
//! `buildProfileEntry`, `LoadSingleConfig`, `LoadProfile`,
//! `ResolveActiveProfile`, `HasProfilesMarker`,
//! `scanLegacyConfigFile`, `applyEnvFill`, `profileExists`).

use crate::blocks::{
    CredentialsBlock, PluginsBlock, check_endpoint_wireguard_system, check_keeper_shape,
    check_webui_shape, parse_credentials_block, parse_plugins_block, parse_wireguard_dns_map,
    validate_credentials, validate_plugins,
};
use crate::config_errorf;
use crate::configlocation::Getenv;
use crate::errors::{ConfigError, config_error, legacy_layout_error};
use crate::gopath::go_join;
use crate::gostr::{go_lower, go_quote, go_trim_space};
use crate::jsonvalue::{
    JsonValue, OrderedObject, decode_ordered_json, decode_ordered_object, encode_ordered_json,
    encode_ordered_json_indent, raw_of,
};
use crate::log::{LogConfig, parse_log_block, render_log_block};
use crate::oserr::{is_not_exist, open_error_text, stat_error_text};
use crate::profile::{
    DEFAULT_PROFILE_NAME, PROFILE_ENV, Profile, Source, discover_profile_names,
    parse_profile_entry, profile_paths, resolve_profile_name, validate_profile_name,
};
use crate::telegram::{TelegramConfig, parse_telegram_block, validate_telegram};
use std::collections::BTreeMap;

/// The parsed single-file config.json (`config.go:17`,
/// `SingleConfig`). Profiles are keyed by name; iteration is in
/// sorted-name order (`ProfileNames`). Raw block values are preserved
/// for faithful re-encoding; parsed sing-box option values are
/// deferred (D-M2-1) and represented by their raw JSON only.
///
/// `Debug` is hand-written (M1 F5 precedent): raw block values
/// render as presence/count markers only — they may carry secrets
/// (credentials, WireGuard keys) — never their content. The
/// parsed `telegram` field is redacted by its own `Debug` impl.
#[derive(Clone, Default)]
pub struct SingleConfig {
    /// `default_profile` (empty when absent).
    pub default_profile: String,
    /// Profiles by name.
    pub profiles: BTreeMap<String, Profile>,
    /// Raw `outbounds` elements (deferred sing-box parse).
    pub outbounds_raw: Vec<JsonValue>,
    /// Raw `endpoints` elements (deferred sing-box parse).
    pub endpoints_raw: Vec<JsonValue>,
    /// Raw top-level `dns` value (deferred sing-box parse).
    pub dns_raw: Option<JsonValue>,
    /// Parsed `wireguard_dns` shape (tag -> servers, file order).
    pub wireguard_dns: Vec<(String, Vec<String>)>,
    /// Raw `wireguard_dns` value.
    pub wireguard_dns_raw: Option<JsonValue>,
    /// Parsed `log` block.
    pub log: Option<LogConfig>,
    /// Raw `log` value.
    pub log_raw: Option<JsonValue>,
    /// Parsed `telegram` block.
    pub telegram: Option<TelegramConfig>,
    /// Raw `telegram` value.
    pub telegram_raw: Option<JsonValue>,
    /// Raw `keeper` value (shape-checked only).
    pub keeper_raw: Option<JsonValue>,
    /// Raw `webui` value (shape-checked only).
    pub webui_raw: Option<JsonValue>,
    /// Parsed `plugins` block (tag/type only).
    pub plugins: Option<PluginsBlock>,
    /// Raw `plugins` value.
    pub plugins_raw: Option<JsonValue>,
    /// Parsed `credentials` block (tag/profile only).
    pub credentials: Option<CredentialsBlock>,
    /// Raw `credentials` value.
    pub credentials_raw: Option<JsonValue>,
}

impl std::fmt::Debug for SingleConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleConfig")
            .field("default_profile", &self.default_profile)
            .field("profiles", &self.profiles)
            .field(
                "outbounds_raw",
                &crate::jsonvalue::raw_list_debug_marker(&self.outbounds_raw),
            )
            .field(
                "endpoints_raw",
                &crate::jsonvalue::raw_list_debug_marker(&self.endpoints_raw),
            )
            .field(
                "dns_raw",
                &crate::jsonvalue::raw_debug_marker(&self.dns_raw),
            )
            .field("wireguard_dns", &self.wireguard_dns)
            .field(
                "wireguard_dns_raw",
                &crate::jsonvalue::raw_debug_marker(&self.wireguard_dns_raw),
            )
            .field("log", &self.log)
            .field(
                "log_raw",
                &crate::jsonvalue::raw_debug_marker(&self.log_raw),
            )
            .field("telegram", &self.telegram)
            .field(
                "telegram_raw",
                &crate::jsonvalue::raw_debug_marker(&self.telegram_raw),
            )
            .field(
                "keeper_raw",
                &crate::jsonvalue::raw_debug_marker(&self.keeper_raw),
            )
            .field(
                "webui_raw",
                &crate::jsonvalue::raw_debug_marker(&self.webui_raw),
            )
            .field("plugins", &self.plugins)
            .field(
                "plugins_raw",
                &crate::jsonvalue::raw_debug_marker(&self.plugins_raw),
            )
            .field("credentials", &self.credentials)
            .field(
                "credentials_raw",
                &crate::jsonvalue::raw_debug_marker(&self.credentials_raw),
            )
            .finish()
    }
}

impl SingleConfig {
    /// Profile names in sorted order (Go `ProfileNames`,
    /// `config.go:83`).
    pub fn profile_names(&self) -> Vec<String> {
        self.profiles.keys().cloned().collect()
    }

    /// Defensive copies of the stored outbound JSON (Go
    /// `RawOutbounds`).
    pub fn raw_outbounds(&self) -> Vec<JsonValue> {
        self.outbounds_raw.clone()
    }

    /// Defensive copies of the stored endpoint JSON (Go
    /// `RawEndpoints`).
    pub fn raw_endpoints(&self) -> Vec<JsonValue> {
        self.endpoints_raw.clone()
    }
}

const SINGLE_TOP_LEVEL_KEYS: [&str; 12] = [
    "default_profile",
    "profiles",
    "outbounds",
    "endpoints",
    "dns",
    "wireguard_dns",
    "log",
    "telegram",
    "keeper",
    "webui",
    "plugins",
    "credentials",
];

/// `HasProfilesMarker` (`config.go:200`): the data is a JSON object
/// containing a `profiles` key (any value, even a wrong-typed one).
/// Decode errors propagate.
pub fn has_profiles_marker(data: &[u8]) -> Result<bool, ConfigError> {
    let obj = decode_ordered_object(data)?;
    Ok(obj.has("profiles"))
}

/// `ParseSingleConfig` (`config.go:221`): checks run in fixed order —
/// top-level key scan (file order) → `default_profile` → `profiles`
/// presence/shape → blocks in fixed order → profiles in file order →
/// tail validation (G1, telegram, credentials, plugins; the
/// sing-box tail checks are deferred, D-M2-1).
pub fn parse_single_config(data: &[u8], base_dir: &str) -> Result<SingleConfig, ConfigError> {
    let obj = decode_ordered_object(data)?;
    for k in obj.keys() {
        if k == "cookies" || k == "cookie" {
            return Err(config_error(
                "cookies must stay in a separate cookies file, never inline in config.json",
            ));
        }
        if !SINGLE_TOP_LEVEL_KEYS.contains(&k.as_str()) {
            return Err(config_errorf!(
                "unknown top-level config key {}",
                go_quote(k)
            ));
        }
    }
    let mut cfg = SingleConfig::default();
    if let Some(v) = obj.get("default_profile") {
        let name = match v {
            JsonValue::Str(s) => s,
            _ => return Err(config_error("default_profile must be a string")),
        };
        validate_profile_name(name)?;
        cfg.default_profile = name.clone();
    }
    let profiles_val = match obj.get("profiles") {
        Some(v) => v,
        None => {
            return Err(config_error("single config requires a \"profiles\" object"));
        }
    };
    let profiles_obj = match profiles_val {
        JsonValue::Object(obj) => obj,
        _ => return Err(config_error("\"profiles\" must be an object")),
    };

    // Outbounds and endpoints first: profiles may reference tags.
    if let Some(v) = obj.get("outbounds") {
        let arr = match v {
            JsonValue::Array(arr) => arr,
            _ => return Err(config_error("\"outbounds\" must be an array")),
        };
        // Deferred: sing-box parseOutbound + tag-presence check.
        // Elements are stored raw, verbatim.
        for elem in arr {
            let _ = raw_of(elem)?;
            cfg.outbounds_raw.push(elem.clone());
        }
    }
    if let Some(v) = obj.get("endpoints") {
        let arr = match v {
            JsonValue::Array(arr) => arr,
            _ => return Err(config_error("\"endpoints\" must be an array")),
        };
        for elem in arr {
            let _ = raw_of(elem)?;
            // Raw-field approximation of the wireguard-system check.
            check_endpoint_wireguard_system(elem)?;
            cfg.endpoints_raw.push(elem.clone());
        }
    }
    if let Some(v) = obj.get("dns") {
        let _ = raw_of(v)?;
        // Deferred: sing-box parseDNS.
        cfg.dns_raw = Some(v.clone());
    }
    if let Some(v) = obj.get("wireguard_dns") {
        let _ = raw_of(v)?;
        cfg.wireguard_dns = parse_wireguard_dns_map(v)?;
        cfg.wireguard_dns_raw = Some(v.clone());
    }
    if let Some(v) = obj.get("log") {
        let _ = raw_of(v)?;
        cfg.log = Some(parse_log_block(v)?);
        cfg.log_raw = Some(v.clone());
    }
    if let Some(v) = obj.get("telegram") {
        let _ = raw_of(v)?;
        cfg.telegram = Some(parse_telegram_block(v)?);
        cfg.telegram_raw = Some(v.clone());
    }
    if let Some(v) = obj.get("keeper") {
        let _ = raw_of(v)?;
        check_keeper_shape(v)?;
        cfg.keeper_raw = Some(v.clone());
    }
    if let Some(v) = obj.get("webui") {
        let _ = raw_of(v)?;
        check_webui_shape(v)?;
        cfg.webui_raw = Some(v.clone());
    }
    if let Some(v) = obj.get("plugins") {
        let _ = raw_of(v)?;
        cfg.plugins = Some(parse_plugins_block(v)?);
        cfg.plugins_raw = Some(v.clone());
    }
    if let Some(v) = obj.get("credentials") {
        let _ = raw_of(v)?;
        cfg.credentials = Some(parse_credentials_block(v)?);
        cfg.credentials_raw = Some(v.clone());
    }

    for (name, entry_val) in profiles_obj.iter() {
        validate_profile_name(name)?;
        let entry_obj = match entry_val {
            JsonValue::Object(obj) => obj,
            _ => {
                return Err(config_errorf!(
                    "profile {} must be an object",
                    go_quote(name)
                ));
            }
        };
        let _ = raw_of(entry_val)?;
        let p = parse_profile_entry(name, entry_obj, base_dir)?;
        cfg.profiles.insert(name.clone(), p);
    }

    // Tail validation, in Go order. validateTagGraph,
    // validateProfileDNS, validateWireGuardDNS, and
    // validateWireGuardPrivateKeys are deferred (D-M2-1).
    if cfg.dns_raw.is_some() {
        for name in cfg.profile_names() {
            let p = &cfg.profiles[&name];
            if p.dns_present {
                return Err(config_errorf!(
                    "profile {} has a per-profile dns block and the file has a top-level dns section: remove the top-level dns section (distribute it into profile entries by hand first, see docs/config.md)",
                    go_quote(&name)
                ));
            }
        }
    }
    if let Some(tg) = &cfg.telegram {
        let tg = tg.clone();
        validate_telegram(&tg, |name| cfg.profiles.contains_key(name))?;
    }
    // validateKeeper: deferred (keeper entries are raw-only).
    if let Some(creds) = &cfg.credentials {
        let creds = creds.clone();
        validate_credentials(&creds, |name| cfg.profiles.contains_key(name))?;
    }
    // validateCredentialRefs: deferred (keeper entries are raw-only).
    if let Some(plugins) = &cfg.plugins {
        let plugins = plugins.clone();
        validate_plugins(&plugins)?;
    }
    Ok(cfg)
}

/// `buildSingleFileOrdered` (`config.go:1292`): fixed top-level
/// order, raw-first rendering; synthesized branches only where a
/// parsed struct exists (log, telegram, wireguard_dns shape,
/// profile entries). Keeper/webui/plugins/credentials synthesis is
/// deferred: without raw JSON those blocks are omitted (unreachable
/// from the parse path, which always captures raw).
pub fn build_single_file_ordered(cfg: &SingleConfig) -> Result<OrderedObject, ConfigError> {
    let mut root = OrderedObject::new();
    if !cfg.default_profile.is_empty() {
        root.set(
            "default_profile".to_string(),
            JsonValue::Str(cfg.default_profile.clone()),
        );
    }
    let mut profiles_obj = OrderedObject::new();
    for name in cfg.profile_names() {
        let entry = build_profile_entry(&cfg.profiles[&name])?;
        profiles_obj.set(name, JsonValue::Object(entry));
    }
    root.set("profiles".to_string(), JsonValue::Object(profiles_obj));
    if !cfg.outbounds_raw.is_empty() {
        root.set(
            "outbounds".to_string(),
            JsonValue::Array(cfg.outbounds_raw.clone()),
        );
    }
    if !cfg.endpoints_raw.is_empty() {
        root.set(
            "endpoints".to_string(),
            JsonValue::Array(cfg.endpoints_raw.clone()),
        );
    }
    if let Some(dns) = &cfg.dns_raw {
        root.set("dns".to_string(), dns.clone());
    }
    if let Some(raw) = &cfg.wireguard_dns_raw {
        root.set("wireguard_dns".to_string(), raw.clone());
    } else if !cfg.wireguard_dns.is_empty() {
        let mut obj = OrderedObject::new();
        for (tag, servers) in &cfg.wireguard_dns {
            let arr = servers.iter().map(|s| JsonValue::Str(s.clone())).collect();
            obj.set(tag.clone(), JsonValue::Array(arr));
        }
        root.set("wireguard_dns".to_string(), JsonValue::Object(obj));
    }
    if let Some(raw) = &cfg.log_raw {
        root.set("log".to_string(), raw.clone());
    } else if let Some(log) = &cfg.log {
        root.set("log".to_string(), JsonValue::Object(render_log_block(log)));
    }
    if let Some(raw) = &cfg.telegram_raw {
        root.set("telegram".to_string(), raw.clone());
    } else if let Some(tg) = &cfg.telegram {
        root.set(
            "telegram".to_string(),
            JsonValue::Object(render_telegram_block(tg)),
        );
    }
    if let Some(raw) = &cfg.keeper_raw {
        root.set("keeper".to_string(), raw.clone());
    }
    if let Some(raw) = &cfg.webui_raw {
        root.set("webui".to_string(), raw.clone());
    }
    if let Some(raw) = &cfg.plugins_raw {
        root.set("plugins".to_string(), raw.clone());
    }
    if let Some(raw) = &cfg.credentials_raw {
        root.set("credentials".to_string(), raw.clone());
    }
    Ok(root)
}

/// The synthesized telegram render branch of
/// `buildSingleFileOrdered`: five keys in fixed order. D-M2-2 /
/// D19: `owner_id` is DROPPED here, reproducing the Go bug exactly;
/// the raw path above preserves it.
pub fn render_telegram_block(tg: &TelegramConfig) -> OrderedObject {
    let mut entry = OrderedObject::new();
    entry.set("profile".to_string(), JsonValue::Str(tg.profile.clone()));
    entry.set("token".to_string(), JsonValue::Str(tg.token.clone()));
    let ids: Vec<JsonValue> = tg
        .allowed_user_ids
        .iter()
        .map(|id| JsonValue::Number(id.to_string()))
        .collect();
    entry.set("allowed_user_ids".to_string(), JsonValue::Array(ids));
    entry.set("auto_approve".to_string(), JsonValue::Bool(tg.auto_approve));
    entry.set(
        "auto_allow_once".to_string(),
        JsonValue::Bool(tg.auto_allow_once),
    );
    entry
}

/// `buildProfileEntry` (`config.go:1500`): `cookies_file` always;
/// optional identifiers only when non-empty; `auto_approve` /
/// `auto_allow_once` always; `fingerprint` / `tls_engine` only when
/// present in the file or differing from the default; `dns` only
/// when present; `outbound` as a tag string, an inline object, or
/// omitted for direct.
pub fn build_profile_entry(p: &Profile) -> Result<OrderedObject, ConfigError> {
    let mut entry = OrderedObject::new();
    entry.set(
        "cookies_file".to_string(),
        JsonValue::Str(p.cookies_file.clone()),
    );
    if !p.vm_id.is_empty() {
        entry.set("vm_id".to_string(), JsonValue::Str(p.vm_id.clone()));
    }
    if !p.node_id.is_empty() {
        entry.set("node_id".to_string(), JsonValue::Str(p.node_id.clone()));
    }
    let auto_approve = if go_lower(go_trim_space(&p.auto_approve)) == "always" {
        "always"
    } else {
        "off"
    };
    entry.set(
        "auto_approve".to_string(),
        JsonValue::Str(auto_approve.to_string()),
    );
    entry.set(
        "auto_allow_once".to_string(),
        JsonValue::Bool(p.auto_allow_once),
    );
    if !p.subscription_action_id.is_empty() {
        entry.set(
            "subscription_action_id".to_string(),
            JsonValue::Str(p.subscription_action_id.clone()),
        );
    }
    let fp = if p.fingerprint.is_empty() {
        crate::fingerprint::DEFAULT_FINGERPRINT
    } else {
        &p.fingerprint
    };
    if p.fingerprint_present || fp != crate::fingerprint::DEFAULT_FINGERPRINT {
        entry.set("fingerprint".to_string(), JsonValue::Str(fp.to_string()));
    }
    let te = if p.tls_engine.is_empty() {
        crate::fingerprint::DEFAULT_TLS_ENGINE
    } else {
        &p.tls_engine
    };
    if p.tls_engine_present || te != crate::fingerprint::DEFAULT_TLS_ENGINE {
        entry.set("tls_engine".to_string(), JsonValue::Str(te.to_string()));
    }
    if p.dns_present {
        if let Some(dns) = &p.dns {
            entry.set("dns".to_string(), dns.clone());
        }
    }
    match p.outbound.kind {
        crate::profile::OutboundKind::Tag => {
            if !p.outbound.tag.is_empty() {
                entry.set(
                    "outbound".to_string(),
                    JsonValue::Str(p.outbound.tag.clone()),
                );
            }
        }
        crate::profile::OutboundKind::Inline => {
            if let Some(raw) = &p.outbound.raw {
                entry.set("outbound".to_string(), raw.clone());
            }
        }
        crate::profile::OutboundKind::Direct => {}
    }
    Ok(entry)
}

/// `encodeSingleConfig` (`guard.go:283`): indent-2 rendering plus
/// exactly one trailing newline.
pub fn encode_single_config(cfg: &SingleConfig) -> Result<String, ConfigError> {
    let root = build_single_file_ordered(cfg)?;
    let mut out = encode_ordered_json_indent(&JsonValue::Object(root), 2)?;
    out.push('\n');
    Ok(out)
}

/// Outcome of `read_regular_file`: Go's `os.Stat` + `os.ReadFile`
/// split, so callers can apply their `IsNotExist` branches.
enum ReadOutcome {
    /// File bytes.
    Ok(Vec<u8>),
    /// Stat failed with ENOENT.
    NotExist,
    /// Stat failed otherwise (`stat <path>: <err>` text).
    StatError(String),
    /// Not a regular file: directory or other type (plain Go
    /// `fmt.Errorf` texts, no `profile: ` prefix).
    NotRegular(String),
    /// Open/read failed after a successful stat (`open <path>: <err>`).
    ReadError(String),
}

/// `readRegularFile` (`config.go:827`): stat first (following
/// symlinks); directories and non-regular files are refused without
/// ever opening the path, so a read can never block on a FIFO.
fn read_regular_file(path: &str) -> ReadOutcome {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            if is_not_exist(&e) {
                return ReadOutcome::NotExist;
            }
            return ReadOutcome::StatError(stat_error_text(path, &e));
        }
    };
    if !meta.is_file() {
        if meta.is_dir() {
            return ReadOutcome::NotRegular(format!(
                "config path {} is a directory, not a file",
                go_quote(path)
            ));
        }
        return ReadOutcome::NotRegular(format!(
            "config path {} is not a regular file",
            go_quote(path)
        ));
    }
    match std::fs::read(path) {
        Ok(data) => ReadOutcome::Ok(data),
        Err(e) => ReadOutcome::ReadError(open_error_text(path, &e)),
    }
}

/// `LoadSingleConfig` (`config.go:849`): `(config, found)`; `found`
/// is false when the file is absent or carries no `profiles` marker.
/// An unparseable single file is an error, never a silent fallback.
pub fn load_single_config(base_dir: &str) -> Result<(Option<SingleConfig>, bool), ConfigError> {
    let path = go_join(&[base_dir, "config.json"]);
    let data = match read_regular_file(&path) {
        ReadOutcome::Ok(data) => data,
        ReadOutcome::NotExist => return Ok((None, false)),
        ReadOutcome::StatError(text) | ReadOutcome::ReadError(text) => {
            return Err(config_errorf!("read config: {}", text));
        }
        ReadOutcome::NotRegular(text) => {
            return Err(config_errorf!("read config: {}", text));
        }
    };
    if !has_profiles_marker(&data)? {
        return Ok((None, false));
    }
    let cfg = parse_single_config(&data, base_dir)?;
    Ok((Some(cfg), true))
}

/// Whether `path` exists and is not a directory (`configPathExists`,
/// `config.go:1070`): stat only, never opened.
fn config_path_exists(path: &str) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => !meta.is_dir(),
        Err(_) => false,
    }
}

/// `scanLegacyConfigFile` (`config.go:1095`): the flat base file
/// (only when `include_base`), then `profiles/default/config.json`,
/// then `profiles/<name>/config.json` in sorted-name order, skipping
/// `exclude`. Stat only, never opened.
pub fn scan_legacy_config_file(
    base_dir: &str,
    exclude: &str,
    include_base: bool,
) -> Result<Option<String>, ConfigError> {
    if include_base {
        let base_path = go_join(&[base_dir, "config.json"]);
        if config_path_exists(&base_path) {
            return Ok(Some(base_path));
        }
    }
    let stray = go_join(&[base_dir, "profiles", DEFAULT_PROFILE_NAME, "config.json"]);
    if config_path_exists(&stray) {
        return Ok(Some(stray));
    }
    let names = discover_profile_names(base_dir)?;
    for name in names {
        if name == DEFAULT_PROFILE_NAME || name == exclude {
            continue;
        }
        let paths = match profile_paths(base_dir, &name) {
            Ok(paths) => paths,
            Err(_) => continue,
        };
        if config_path_exists(&paths.config) {
            return Ok(Some(paths.config));
        }
    }
    Ok(None)
}

/// `applyEnvFill` (`config.go:1046`): only when the key was absent:
/// non-empty `MUSE_VM_ID` / `MUSE_NODE_ID` fill `vm_id` / `node_id`.
/// `getenv`: `None` means the process environment (see the `Getenv`
/// convention in `configlocation.rs`).
pub fn apply_env_fill(p: &mut Profile, getenv: Getenv<'_>) {
    let lookup = |key: &str| crate::configlocation::config_lookup_env(getenv, key);
    if !p.vm_id_present {
        if let Some(v) = lookup("MUSE_VM_ID") {
            if !v.is_empty() {
                p.vm_id = v;
            }
        }
    }
    if !p.node_id_present {
        if let Some(v) = lookup("MUSE_NODE_ID") {
            if !v.is_empty() {
                p.node_id = v;
            }
        }
    }
}

/// `LoadProfile` (`config.go:1150`): read-only; a single-file entry
/// wins wholly; otherwise a legacy file anywhere in the layout is
/// refused; otherwise `SourceNone` defaults are synthesised. Never
/// creates files or generates a node id.
pub fn load_profile(
    base_dir: &str,
    name: &str,
    getenv: Getenv<'_>,
) -> Result<Profile, ConfigError> {
    let paths = profile_paths(base_dir, name)?;
    let (single, found) = load_single_config(base_dir)?;
    let mut p: Option<Profile> = None;
    if found {
        if let Some(single) = &single {
            if let Some(entry) = single.profiles.get(name) {
                p = Some(entry.clone());
            }
        }
    }
    if p.is_none() {
        if !(found && name == DEFAULT_PROFILE_NAME) {
            match std::fs::metadata(&paths.config) {
                Ok(meta) => {
                    if meta.is_dir() {
                        return Err(config_errorf!(
                            "config path {} is a directory, not a file",
                            go_quote(&paths.config)
                        ));
                    }
                    return Err(legacy_layout_error(&paths.config));
                }
                Err(e) => {
                    if !is_not_exist(&e) {
                        return Err(config_errorf!(
                            "read config: {}",
                            stat_error_text(&paths.config, &e)
                        ));
                    }
                }
            }
        }
        let legacy = scan_legacy_config_file(base_dir, name, !found)?;
        if let Some(legacy_path) = legacy {
            return Err(legacy_layout_error(&legacy_path));
        }
    }
    let mut p = match p {
        Some(p) => p,
        None => Profile {
            name: name.to_string(),
            dir: paths.dir.clone(),
            config_file: paths.config.clone(),
            cookies_file: paths.cookies.clone(),
            chat_file: paths.chat.clone(),
            auto_approve: "off".to_string(),
            fingerprint: crate::fingerprint::DEFAULT_FINGERPRINT.to_string(),
            tls_engine: crate::fingerprint::DEFAULT_TLS_ENGINE.to_string(),
            source: Source::None,
            outbound: crate::profile::OutboundRef {
                kind: crate::profile::OutboundKind::Direct,
                typ: "direct".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
    };
    if let Ok(meta) = std::fs::metadata(&paths.dir) {
        if meta.is_dir() {
            p.exists = true;
        }
    }
    apply_env_fill(&mut p, getenv);
    Ok(p)
}

/// `profileExists` (`config.go:1273`): a single-file entry, a
/// per-profile config file, or a bare profile directory (which
/// counts) — a legacy file counts as existence too, though
/// `LoadProfile` still refuses to read it.
pub fn profile_exists(base_dir: &str, name: &str, single: Option<&SingleConfig>) -> bool {
    if let Some(single) = single {
        if single.profiles.contains_key(name) {
            return true;
        }
    }
    let Ok(paths) = profile_paths(base_dir, name) else {
        return false;
    };
    if std::fs::metadata(&paths.config).is_ok() {
        return true;
    }
    if let Ok(meta) = std::fs::metadata(&paths.dir) {
        if meta.is_dir() {
            return true;
        }
    }
    false
}

/// `ResolveActiveProfile` (`config.go:1235`): flag > env >
/// `default_profile` (must exist) > `"default"`. `getenv`:
/// `None` means the process environment (see the `Getenv`
/// convention in `configlocation.rs`).
pub fn resolve_active_profile(
    base_dir: &str,
    flag: Option<&str>,
    getenv: Getenv<'_>,
) -> Result<Profile, ConfigError> {
    if flag.is_some() {
        let name = resolve_profile_name(flag, getenv)?;
        return load_profile(base_dir, &name, getenv);
    }
    if let Some(env) = crate::configlocation::config_lookup_env(getenv, PROFILE_ENV) {
        if !go_trim_space(&env).is_empty() {
            let name = validate_profile_name(go_trim_space(&env))?;
            return load_profile(base_dir, &name, getenv);
        }
    }
    let (single, found) = load_single_config(base_dir)?;
    if found {
        if let Some(single) = &single {
            if !single.default_profile.is_empty() {
                let name = single.default_profile.clone();
                if !profile_exists(base_dir, &name, Some(single)) {
                    return Err(config_errorf!(
                        "default_profile {} does not exist",
                        go_quote(&name)
                    ));
                }
                return load_profile(base_dir, &name, getenv);
            }
        }
    }
    load_profile(base_dir, DEFAULT_PROFILE_NAME, getenv)
}

/// Decode one value and render it compactly (test helper mirroring
/// Go's `rawOf` + `decodeOrderedJSON` round-trip through
/// `buildSingleFileOrdered`'s raw branches).
pub fn round_trip_compact(data: &[u8]) -> Result<String, ConfigError> {
    let v = decode_ordered_json(data)?;
    encode_ordered_json(&v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonvalue::decode_ordered_json as decode;

    /// Invented shape-only token (never a real credential).
    const FAKE_TOKEN: &str = "123456789:ABCDEFGHIJKLMNOPQRST";

    fn parse(input: &str) -> Result<SingleConfig, ConfigError> {
        parse_single_config(input.as_bytes(), "/cfg")
    }

    #[test]
    fn test_parse_minimal_round_trip() {
        let cfg = parse("{\"profiles\":{\"default\":{}}}").unwrap();
        assert_eq!(cfg.profile_names(), vec!["default".to_string()]);
        let rendered = encode_single_config(&cfg).unwrap();
        assert_eq!(
            rendered,
            "{\n  \"profiles\": {\n    \"default\": {\n      \"cookies_file\": \"/cfg/cookies.txt\",\n      \"auto_approve\": \"off\",\n      \"auto_allow_once\": false\n    }\n  }\n}\n"
        );
    }

    #[test]
    fn test_debug_never_prints_secrets() {
        // Fake secret-adjacent values (invented, never real
        // credentials): the hand-written Debug impls must not
        // print the token, the credential password, or the inline
        // outbound raw JSON.
        let cfg = parse(&format!(
            "{{\"profiles\":{{\"default\":{{\"outbound\":{{\"type\":\"wireguard\",\"private_key\":\"SECRET-PRIVATE-KEY\"}}}}}},\"credentials\":[{{\"tag\":\"c1\",\"profile\":\"default\",\"username\":\"alice\",\"password\":\"SECRET-PASSWORD\"}}],\"telegram\":{{\"profile\":\"default\",\"token\":\"{FAKE_TOKEN}\",\"allowed_user_ids\":[111]}}}}"
        ))
        .unwrap();
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("SECRET-PRIVATE-KEY"));
        assert!(!rendered.contains("SECRET-PASSWORD"));
        assert!(!rendered.contains(FAKE_TOKEN));
        assert!(rendered.contains("[redacted]"));
        // The parsed Profile's own Debug is redacted too.
        let rendered_profile = format!("{:?}", cfg.profiles["default"]);
        assert!(!rendered_profile.contains("SECRET-PRIVATE-KEY"));
    }

    #[test]
    fn test_parse_top_level_key_errors_in_file_order() {
        assert_eq!(
            parse("{\"bogus\":1,\"profiles\":{}}").unwrap_err().message,
            "profile: unknown top-level config key \"bogus\""
        );
        assert_eq!(
            parse("{\"cookies\":{},\"profiles\":{}}")
                .unwrap_err()
                .message,
            "profile: cookies must stay in a separate cookies file, never inline in config.json"
        );
        assert_eq!(parse("{\"profiles\":{}}").unwrap().profiles.len(), 0);
        assert_eq!(
            parse("{}").unwrap_err().message,
            "profile: single config requires a \"profiles\" object"
        );
        assert_eq!(
            parse("{\"profiles\":[]}").unwrap_err().message,
            "profile: \"profiles\" must be an object"
        );
        assert_eq!(
            parse("{\"profiles\":{},\"default_profile\":1}")
                .unwrap_err()
                .message,
            "profile: default_profile must be a string"
        );
    }

    #[test]
    fn test_parse_block_shape_errors() {
        assert_eq!(
            parse("{\"profiles\":{},\"outbounds\":{}}")
                .unwrap_err()
                .message,
            "profile: \"outbounds\" must be an array"
        );
        assert_eq!(
            parse("{\"profiles\":{},\"endpoints\":{}}")
                .unwrap_err()
                .message,
            "profile: \"endpoints\" must be an array"
        );
        assert_eq!(
            parse("{\"profiles\":{},\"log\":[]}").unwrap_err().message,
            "profile: \"log\" must be an object"
        );
        assert_eq!(
            parse("{\"profiles\":{},\"keeper\":{}}")
                .unwrap_err()
                .message,
            "profile: \"keeper\" must be an array of entries"
        );
        assert_eq!(
            parse("{\"profiles\":{},\"webui\":[]}").unwrap_err().message,
            "profile: \"webui\" must be an object"
        );
        assert_eq!(
            parse("{\"profiles\":{},\"plugins\":{}}")
                .unwrap_err()
                .message,
            "profile: \"plugins\" must be an array of entries"
        );
        assert_eq!(
            parse("{\"profiles\":{},\"credentials\":{}}")
                .unwrap_err()
                .message,
            "profile: \"credentials\" must be an array of entries"
        );
    }

    #[test]
    fn test_raw_preserve_reorders_nothing() {
        // Reversed key order + special chars survive a round trip.
        let input = "{\"telegram\":{\"allowed_user_ids\":[1],\"token\":\"123456789:ABCDEFGHIJKLMNOPQRST\",\"profile\":\"default\"},\"profiles\":{\"default\":{\"auto_allow_once\":true}}}";
        let cfg = parse(input).unwrap();
        let rendered = encode_single_config(&cfg).unwrap();
        // Top-level order is canonical (profiles first); the telegram
        // block keeps its input key order (raw-first).
        assert!(rendered.starts_with("{\n  \"profiles\": {"));
        assert!(rendered.contains("\"allowed_user_ids\": [\n      1\n    ]"));
        let reparsed = parse_single_config(rendered.trim_end().as_bytes(), "/cfg").unwrap();
        assert_eq!(encode_single_config(&reparsed).unwrap(), rendered);
    }

    #[test]
    fn test_telegram_d19_synthesized_render_drops_owner_id() {
        // D-M2-2 regression: a hand-built config (no raw) with
        // owner_id renders WITHOUT owner_id, reproducing the Go bug.
        let mut cfg = SingleConfig::default();
        cfg.profiles.insert(
            "default".to_string(),
            parse_profile_entry("default", &crate::jsonvalue::OrderedObject::new(), "/cfg")
                .unwrap(),
        );
        cfg.telegram = Some(TelegramConfig {
            profile: "default".to_string(),
            token: FAKE_TOKEN.to_string(),
            allowed_user_ids: vec![111],
            auto_approve: false,
            auto_allow_once: false,
            owner_id: 999,
            owner_id_set: true,
        });
        let rendered = encode_single_config(&cfg).unwrap();
        assert!(!rendered.contains("owner_id"));
        assert!(!rendered.contains("999"));
        // The parse path (raw present) preserves owner_id.
        let input = format!(
            "{{\"profiles\":{{\"default\":{{}}}},\"telegram\":{{\"profile\":\"default\",\"token\":\"{FAKE_TOKEN}\",\"allowed_user_ids\":[111],\"owner_id\":999}}}}"
        );
        let cfg2 = parse(&input).unwrap();
        let rendered2 = encode_single_config(&cfg2).unwrap();
        assert!(rendered2.contains("\"owner_id\": 999"));
    }

    #[test]
    fn test_telegram_validate_dangling_profile_in_tail() {
        let input = format!(
            "{{\"profiles\":{{\"default\":{{}}}},\"telegram\":{{\"profile\":\"ghost\",\"token\":\"{FAKE_TOKEN}\",\"allowed_user_ids\":[1]}}}}"
        );
        assert_eq!(
            parse(&input).unwrap_err().message,
            "profile: telegram: profile \"ghost\" does not exist"
        );
    }

    #[test]
    fn test_g1_coexistence() {
        let input = "{\"profiles\":{\"default\":{\"dns\":{\"servers\":[]}}},\"dns\":{}}";
        assert!(
            parse(input)
                .unwrap_err()
                .message
                .contains("has a per-profile dns block and the file has a top-level dns section")
        );
    }

    #[test]
    fn test_wireguard_system_endpoint_rejected() {
        let input = "{\"profiles\":{},\"endpoints\":[{\"type\":\"wireguard\",\"tag\":\"w\",\"system\":true}]}";
        assert_eq!(
            parse(input).unwrap_err().message,
            "profile: wireguard endpoint \"system\": true is not supported; use userspace wireguard only"
        );
    }

    #[test]
    fn test_has_profiles_marker() {
        assert!(has_profiles_marker(b"{\"profiles\":[]}").unwrap());
        assert!(!has_profiles_marker(b"{\"x\":1}").unwrap());
        assert!(has_profiles_marker(b"not json").is_err());
    }

    fn load_test_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("castctl-config-load-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_load_profile_single_entry_wins() {
        let dir = load_test_dir("single");
        std::fs::write(
            dir.join("config.json"),
            "{\"profiles\":{\"work\":{\"vm_id\":\"vm1\",\"auto_approve\":\"always\"}}}",
        )
        .unwrap();
        let p = load_profile(dir.to_str().unwrap(), "work", None).unwrap();
        assert_eq!(p.vm_id, "vm1");
        assert_eq!(p.auto_approve, "always");
        assert_eq!(p.source, Source::Single);
        assert_eq!(
            p.cookies_file,
            dir.join("profiles/work/cookies.txt").to_str().unwrap()
        );
    }

    #[test]
    fn test_load_profile_missing_file_synthesises_defaults() {
        // Base dir does not exist at all: nothing to find, and
        // Exists is false. (When the base dir DOES exist, the
        // default profile's Dir is the base dir itself, so Exists
        // is true in Go too.)
        let dir =
            std::env::temp_dir().join(format!("castctl-config-load-absent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = load_profile(dir.to_str().unwrap(), "default", None).unwrap();
        assert_eq!(p.source, Source::None);
        assert_eq!(p.auto_approve, "off");
        assert_eq!(p.fingerprint, "chrome");
        assert_eq!(p.tls_engine, "utls");
        assert!(!p.exists);
    }

    #[test]
    fn test_load_profile_legacy_own_file_refused() {
        // A per-profile config.json with no "profiles" marker is a
        // legacy layout: refused even though LoadSingleConfig
        // reports "not found" for it.
        let dir = load_test_dir("legacy");
        let prof_dir = dir.join("profiles/work");
        std::fs::create_dir_all(&prof_dir).unwrap();
        std::fs::write(prof_dir.join("config.json"), "{}").unwrap();
        let err = load_profile(dir.to_str().unwrap(), "work", None).unwrap_err();
        assert!(err.message.contains("legacy layout found"));
        assert!(err.message.contains("config migrate --write"));
    }

    #[test]
    fn test_load_profile_stray_default_file_refused() {
        // A stray profiles/default/config.json refuses loads for
        // OTHER names too (layout-wide scan), when a single file
        // exists.
        let dir = load_test_dir("stray");
        std::fs::write(dir.join("config.json"), "{\"profiles\":{}}").unwrap();
        let def_dir = dir.join("profiles/default");
        std::fs::create_dir_all(&def_dir).unwrap();
        std::fs::write(def_dir.join("config.json"), "{}").unwrap();
        let err = load_profile(dir.to_str().unwrap(), "work", None).unwrap_err();
        assert!(err.message.contains("legacy layout found"));
    }

    #[test]
    fn test_load_profile_own_path_is_dir() {
        let dir = load_test_dir("owndir");
        let prof_dir = dir.join("profiles/work");
        std::fs::create_dir_all(prof_dir.join("config.json")).unwrap();
        let err = load_profile(dir.to_str().unwrap(), "work", None).unwrap_err();
        assert!(err.message.contains("is a directory, not a file"));
    }

    #[test]
    fn test_resolve_active_profile_default_profile_rules() {
        let dir = load_test_dir("active");
        std::fs::write(
            dir.join("config.json"),
            "{\"default_profile\":\"ghost\",\"profiles\":{}}",
        )
        .unwrap();
        let err = resolve_active_profile(dir.to_str().unwrap(), None, None).unwrap_err();
        assert_eq!(
            err.message,
            "profile: default_profile \"ghost\" does not exist"
        );
        // A bare profile directory counts as existence.
        std::fs::create_dir_all(dir.join("profiles/ghost")).unwrap();
        let p = resolve_active_profile(dir.to_str().unwrap(), None, None).unwrap();
        assert_eq!(p.name, "ghost");
        assert!(p.exists);
        assert_eq!(p.source, Source::None);
    }

    #[test]
    fn test_load_profile_env_fill_only_when_absent() {
        let dir = load_test_dir("envfill");
        std::fs::write(
            dir.join("config.json"),
            "{\"profiles\":{\"work\":{\"vm_id\":\"from-file\"}}}",
        )
        .unwrap();
        let getenv = |k: &str| match k {
            "MUSE_VM_ID" => Some("from-env".to_string()),
            "MUSE_NODE_ID" => Some("node-env".to_string()),
            _ => None,
        };
        let p = load_profile(dir.to_str().unwrap(), "work", Some(&getenv)).unwrap();
        assert_eq!(p.vm_id, "from-file");
        assert_eq!(p.node_id, "node-env");
    }

    #[test]
    fn test_decode_helpers() {
        assert_eq!(round_trip_compact(b"{\"b\":1.50}").unwrap(), "{\"b\":1.50}");
        let _ = decode(b"{}");
    }
}
