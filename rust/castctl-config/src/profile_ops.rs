// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Profile write operations: `AddProfile`, `RemoveProfile`,
//! `SetOutbound`, `SetFingerprint`, `SetTlsEngine`,
//! `OutboundFromEnv`, `ResolveTelegram`.
//!
//! Go sources: `internal/profile/profilecmd.go`
//! (`AddProfile`, `RemoveProfile`, `SetOutbound`,
//! `SetFingerprint`, `SetTlsEngine`, `applySetOutbound`,
//! `applySetEndpoint`, `applySetOutboundObject`,
//! `checkSameTagOverwrite`, `setOutboundInList`,
//! `setEndpointInList`, `refuseUnmigrated`,
//! `legacyProfileExists`), `internal/profile/envproxy.go`
//! (`OutboundFromEnv`, `firstProxyEnv`, `noProxyBypass`,
//! `envProxyError`), `internal/profile/telegram.go`
//! (`ResolveTelegram`).
//!
//! Every write goes through the flock+sha256 guard
//! (`update_single_config`); none of these functions reads
//! proxy environment variables (except `OutboundFromEnv`,
//! the only place in product code that does), creates a
//! cookies file, or touches telegram/update files. A
//! legacy layout is never written back to.
//!
//! M7f: `SetOutbound` runs sing-box's `parseOutbound` /
//! `parseEndpoint` at write time, in Go's order
//! (`profilecmd.go:431-501`): wrapper rejection and `type`
//! presence/shape first, then the strict parse, then the
//! WireGuard `system` refusal and the same-tag overwrite
//! rules. The tag-graph and WireGuard-key checks run at
//! write time too, exactly as in Go.

use castctl_log_redact::redact_string;

use crate::config::SingleConfig;
use crate::configlocation::Getenv;
use crate::dnsvalidate::validate_wireguard_private_keys;
use crate::errors::{ConfigError, config_error};
use crate::fingerprint::{
    DEFAULT_FINGERPRINT, DEFAULT_TLS_ENGINE, validate_fingerprint_value, validate_tls_engine_value,
};
use crate::gopath::go_join;
use crate::gostr::{go_quote, go_trim_space};
use crate::jsonvalue::{JsonValue, OrderedObject, decode_ordered_object};
use crate::profile::{
    DEFAULT_PROFILE_NAME, OutboundKind, OutboundRef, Profile, Source, profile_paths,
    resolve_cookies_file, validate_profile_name,
};
use crate::taggraph::validate_tag_graph;
use crate::telegram::{TelegramConfig, validate_telegram};
use crate::toggle::{generate_node_id, load_config_state, refuse_unmigrated, update_single_config};

/// Options for `add_profile` (`profilecmd.go`,
/// `AddProfileOptions`).
#[derive(Debug, Clone, Default)]
pub struct AddProfileOptions {
    /// `cookies_file` override (`""` = default).
    pub cookies_file: String,
    /// Outbound tag (`""` or `"direct"` = direct).
    pub outbound_tag: String,
    /// Make the new profile the `default_profile`.
    pub set_default: bool,
    /// Fingerprint preset (`""` = default, no key written).
    pub fingerprint: String,
    /// TLS engine (`""` = default, no key written).
    pub tls_engine: String,
}

/// Whether `path` exists and is not a directory
/// (`configPathExists`, `config.go:1070`): stat only,
/// never opened.
fn config_path_exists(path: &str) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => !meta.is_dir(),
        Err(_) => false,
    }
}

/// `AddProfile` (`profilecmd.go:64`): create one entry in
/// the single file — `auto_approve` off, `auto_allow_once`
/// false, a fresh crypto/rand node_id, the default cookies
/// file. It creates NO cookies file and no profile
/// directory, and performs no network access. It refuses
/// when the name already exists in the single file, when a
/// legacy profile with the same name exists, and with a
/// "run config migrate first" error when the old layout
/// exists unmigrated and no single file exists yet. The
/// returned profile is the created entry.
pub fn add_profile(
    base_dir: &str,
    name: &str,
    opts: AddProfileOptions,
) -> Result<Profile, ConfigError> {
    validate_profile_name(name)?;
    let paths = profile_paths(base_dir, name)?;
    // Validate the recorded-identity parameters before
    // touching the filesystem: invalid values fail fast
    // and write nothing.
    if !opts.fingerprint.is_empty() {
        validate_fingerprint_value(&opts.fingerprint).map_err(config_error)?;
    }
    if !opts.tls_engine.is_empty() {
        validate_tls_engine_value(&opts.tls_engine).map_err(config_error)?;
    }
    refuse_unmigrated(base_dir)?;
    let mut created: Option<Profile> = None;
    update_single_config(base_dir, |cfg| {
        if cfg.profiles.contains_key(name) {
            return Err(crate::config_errorf!(
                "profile {} already exists",
                go_quote(name)
            ));
        }
        if name != DEFAULT_PROFILE_NAME && config_path_exists(&paths.config) {
            return Err(crate::config_errorf!(
                "profile {} already exists in the old layout; run config migrate first",
                go_quote(name)
            ));
        }
        if name == DEFAULT_PROFILE_NAME
            && config_path_exists(&go_join(&[base_dir, "profiles", "default", "config.json"]))
        {
            // profiles/default/config.json is the default
            // profile's legacy file (its own config path is
            // the base file, which is the single file here):
            // adding "default" would silently shadow it.
            return Err(crate::config_errorf!(
                "profile {} already exists in the old layout; run config migrate first",
                go_quote(name)
            ));
        }
        let node_id = generate_node_id()?;
        let cookies_file = resolve_cookies_file(base_dir, &paths, &opts.cookies_file, name)?;
        let mut p = Profile {
            name: name.to_string(),
            dir: paths.dir.clone(),
            config_file: go_join(&[base_dir, "config.json"]),
            cookies_file,
            chat_file: paths.chat.clone(),
            node_id,
            node_id_present: true,
            auto_approve: "off".to_string(),
            auto_allow_once: false,
            fingerprint: DEFAULT_FINGERPRINT.to_string(),
            tls_engine: DEFAULT_TLS_ENGINE.to_string(),
            source: Source::Single,
            config_found: true,
            outbound: OutboundRef {
                kind: OutboundKind::Direct,
                tag: String::new(),
                typ: "direct".to_string(),
                from: String::new(),
                raw: None,
            },
            ..Default::default()
        };
        if !opts.fingerprint.is_empty() {
            p.fingerprint = opts.fingerprint.clone();
            p.fingerprint_present = true;
        }
        if !opts.tls_engine.is_empty() {
            p.tls_engine = opts.tls_engine.clone();
            p.tls_engine_present = true;
        }
        if let Ok(md) = std::fs::metadata(&paths.dir)
            && md.is_dir()
        {
            p.exists = true;
        }
        if !opts.outbound_tag.is_empty() && opts.outbound_tag != "direct" {
            p.outbound = OutboundRef {
                kind: OutboundKind::Tag,
                tag: opts.outbound_tag.clone(),
                typ: String::new(),
                from: String::new(),
                raw: None,
            };
        }
        cfg.profiles.insert(name.to_string(), p.clone());
        if opts.set_default {
            cfg.default_profile = name.to_string();
        }
        // Validates the tag reference (dangling tag errors)
        // and resolves the referenced type; aborts the write
        // on error.
        validate_tag_graph(cfg)?;
        // Refuse a shared WireGuard private key here, at
        // write time, instead of persisting a file every
        // later load would reject.
        validate_wireguard_private_keys(cfg)?;
        // Re-read the entry: the tag graph resolved its
        // From/Type in place.
        if let Some(p) = cfg.profiles.get(name) {
            created = Some(p.clone());
        }
        Ok(())
    })?;
    created.ok_or_else(|| crate::config_errorf!("profile {} was not created", go_quote(name)))
}

/// The outcome of `remove_profile`
/// (`profilecmd.go`, `RemoveProfileResult`).
#[derive(Debug, Clone, Default)]
pub struct RemoveProfileResult {
    /// The removed profile.
    pub name: String,
    /// Non-empty when removing the `default_profile`
    /// forced a fallback; the caller prints it.
    pub warning: String,
    /// The `default_profile` after removal (`""` means
    /// none: null in JSON).
    pub default_profile: String,
}

/// `RemoveProfile` (`profilecmd.go:235`): remove ONLY the
/// single-file entry for `name` — never cookies, chat,
/// telegram, or old-layout files, never the profile
/// directory. Removing the `default_profile` falls back
/// to `"default"` when a profile of that name remains,
/// else to none (`""`); either way `warning` carries the
/// fallback text. An unknown name, or no single file, is
/// an error and writes nothing. Removing a profile whose
/// inline outbound tag is referenced by another profile
/// is refused (it would strand that profile with a
/// dangling reference).
pub fn remove_profile(base_dir: &str, name: &str) -> Result<RemoveProfileResult, ConfigError> {
    validate_profile_name(name)?;
    let state = load_config_state(base_dir)?;
    if !state.found {
        if state.exists {
            return Err(config_error(
                "profile rm only removes single-file entries; the old layout exists unmigrated (run config migrate first)",
            ));
        }
        return Err(config_error(
            "profile rm only removes single-file entries; no single config file exists",
        ));
    }
    if !state
        .config
        .as_ref()
        .is_some_and(|c| c.profiles.contains_key(name))
    {
        return Err(crate::config_errorf!(
            "profile {} does not exist in the single config file",
            go_quote(name)
        ));
    }
    let mut result = RemoveProfileResult {
        name: name.to_string(),
        ..Default::default()
    };
    update_single_config(base_dir, |cfg| {
        if !cfg.profiles.contains_key(name) {
            return Err(crate::config_errorf!(
                "profile {} does not exist in the single config file",
                go_quote(name)
            ));
        }
        cfg.profiles.remove(name);
        if cfg.default_profile == name {
            if cfg.profiles.contains_key(DEFAULT_PROFILE_NAME) {
                cfg.default_profile = DEFAULT_PROFILE_NAME.to_string();
                result.warning = "default_profile fell back to \"default\"".to_string();
            } else {
                cfg.default_profile = String::new();
                result.warning =
                    "default_profile cleared: no \"default\" profile remains".to_string();
            }
        }
        result.default_profile = cfg.default_profile.clone();
        // Refuses when the removal would strand another
        // profile's tag reference; aborts the write on
        // error.
        validate_tag_graph(cfg)
    })?;
    Ok(result)
}

/// `SetOutbound` (`profilecmd.go:291`): set one profile's
/// outbound from ONE JSON object — an outbound object, or
/// an endpoint object for WireGuard (type `"wireguard"`).
/// The `{"outbound": {...}}` wrapper is rejected. Tagged
/// objects go to the outbounds/endpoints list and the
/// profile references the tag; untagged objects go inline
/// (auto-tagged `"profile:<name>"`), except untagged
/// WireGuard objects, which are auto-tagged and stored in
/// endpoints with the profile referencing the tag. A
/// tagged object overwrites an existing entry with the
/// same tag only when no other profile uses that tag with
/// a different type. The profile must already exist in the
/// single file.
pub fn set_outbound(base_dir: &str, name: &str, data: &[u8]) -> Result<Profile, ConfigError> {
    validate_profile_name(name)?;
    let state = load_config_state(base_dir)?;
    if !state.found {
        return Err(config_error(
            "profile set-outbound only modifies single-file entries; no single config file exists (run config migrate first)",
        ));
    }
    if !state
        .config
        .as_ref()
        .is_some_and(|c| c.profiles.contains_key(name))
    {
        return Err(crate::config_errorf!(
            "profile {} does not exist in the single config file",
            go_quote(name)
        ));
    }
    let mut updated: Option<Profile> = None;
    update_single_config(base_dir, |cfg| {
        let Some(mut p) = cfg.profiles.get(name).cloned() else {
            return Err(crate::config_errorf!(
                "profile {} does not exist in the single config file",
                go_quote(name)
            ));
        };
        apply_set_outbound(cfg, &mut p, data)?;
        // Go mutates the map entry IN PLACE (`p` is a
        // pointer into `cfg.Profiles`), so the tag graph
        // below resolves From/Type on the NEW outbound.
        // Insert before validating — validating first and
        // inserting after leaves the returned profile with
        // typ/from "" (the pre-fix bug: tagged set-outbound
        // returned typ "" instead of "socks").
        cfg.profiles.insert(name.to_string(), p);
        validate_tag_graph(cfg)?;
        // SetOutbound is the one in-package mutation path
        // that can introduce endpoints: refuse a shared
        // WireGuard private key here, at write time.
        validate_wireguard_private_keys(cfg)?;
        // Re-read the entry: the tag graph resolved its
        // From/Type in place (same pattern as add_profile).
        if let Some(p) = cfg.profiles.get(name) {
            updated = Some(p.clone());
        }
        Ok(())
    })?;
    updated.ok_or_else(|| crate::config_errorf!("profile {} was not updated", go_quote(name)))
}

/// `applySetOutbound` (`profilecmd.go:431`): parse `data`
/// and mutate `cfg`/`p`. Writes nothing itself; the
/// caller validates and writes.
fn apply_set_outbound(
    cfg: &mut SingleConfig,
    p: &mut Profile,
    data: &[u8],
) -> Result<(), ConfigError> {
    let obj = decode_ordered_object(data)?;
    if obj.has("outbound") {
        return Err(config_error(
            "set-outbound takes one outbound/endpoint object, not a {\"outbound\": {...}} wrapper",
        ));
    }
    let Some(type_val) = obj.get("type") else {
        return Err(config_error("outbound object must have a \"type\""));
    };
    let JsonValue::Str(type_str) = type_val else {
        return Err(config_error("outbound \"type\" must be a string"));
    };
    if type_str == "wireguard" {
        return apply_set_endpoint(cfg, p, &obj);
    }
    apply_set_outbound_object(cfg, p, &obj)
}

fn apply_set_endpoint(
    cfg: &mut SingleConfig,
    p: &mut Profile,
    obj: &OrderedObject,
) -> Result<(), ConfigError> {
    let (tagged, tag) = crate::profile::ensure_inline_tag(obj, &format!("profile:{}", p.name))?;
    // Go `applySetEndpoint`: `parseEndpoint` runs before the
    // `system` refusal.
    crate::singbox::validate_endpoint_strict(&JsonValue::Object(tagged.clone()))?;
    if matches!(tagged.get("system"), Some(JsonValue::Bool(true))) {
        return Err(config_error(
            "wireguard endpoint \"system\": true is not supported; use userspace wireguard only",
        ));
    }
    check_same_tag_overwrite(cfg, &p.name, &tag, "wireguard", "endpoint")?;
    set_endpoint_in_list(cfg, JsonValue::Object(tagged));
    p.outbound = OutboundRef {
        kind: OutboundKind::Tag,
        tag,
        typ: String::new(),
        from: String::new(),
        raw: None,
    };
    Ok(())
}

fn apply_set_outbound_object(
    cfg: &mut SingleConfig,
    p: &mut Profile,
    obj: &OrderedObject,
) -> Result<(), ConfigError> {
    let type_str = match obj.get("type") {
        Some(JsonValue::Str(s)) => s.clone(),
        _ => String::new(),
    };
    // Go `applySetOutboundObject`: `parseOutbound` runs on the
    // raw object first, before the tag branch.
    crate::singbox::validate_outbound_strict(&JsonValue::Object(obj.clone()))?;
    if let Some(tag_val) = obj.get("tag") {
        match tag_val {
            JsonValue::Str(tag) if !tag.is_empty() => {
                check_same_tag_overwrite(cfg, &p.name, tag, &type_str, "outbound")?;
                set_outbound_in_list(cfg, JsonValue::Object(obj.clone()));
                p.outbound = OutboundRef {
                    kind: OutboundKind::Tag,
                    tag: tag.clone(),
                    typ: String::new(),
                    from: String::new(),
                    raw: None,
                };
                return Ok(());
            }
            JsonValue::Str(_) => {
                // Empty tag: Go's parse rejects an empty tag
                // only for list entries, not here — an empty
                // tag falls through to the inline path below
                // in Go (`ob.Tag == ""`). Keep the same
                // fall-through.
            }
            _ => {
                return Err(config_error("outbound \"tag\" must be a string"));
            }
        }
    }
    // Untagged: inline, auto-tagged "profile:<name>"; Go
    // re-parses the tagged object (`parseOutbound`).
    let (tagged, tag) = crate::profile::ensure_inline_tag(obj, &format!("profile:{}", p.name))?;
    crate::singbox::validate_outbound_strict(&JsonValue::Object(tagged.clone()))?;
    p.outbound = OutboundRef {
        kind: OutboundKind::Inline,
        tag,
        typ: type_str,
        from: String::new(),
        raw: Some(JsonValue::Object(tagged)),
    };
    Ok(())
}

/// `checkSameTagOverwrite` (`profilecmd.go:508`):
/// overwriting an entry tagged `tag` with `new_type` is
/// refused when another profile references the tag with a
/// different type, or when the tag is already used in the
/// other section or as another profile's inline tag.
fn check_same_tag_overwrite(
    cfg: &SingleConfig,
    profile: &str,
    tag: &str,
    new_type: &str,
    section: &str,
) -> Result<(), ConfigError> {
    for raw in &cfg.outbounds_raw {
        if let Some(JsonValue::Str(t)) = raw_obj_str(raw, "tag")
            && t == tag
            && section != "outbound"
        {
            return Err(crate::config_errorf!(
                "duplicate tag {} (already an outbound)",
                go_quote(tag)
            ));
        }
    }
    for raw in &cfg.endpoints_raw {
        if let Some(JsonValue::Str(t)) = raw_obj_str(raw, "tag")
            && t == tag
            && section != "endpoint"
        {
            return Err(crate::config_errorf!(
                "duplicate tag {} (already an endpoint)",
                go_quote(tag)
            ));
        }
    }
    for (other_name, other) in &cfg.profiles {
        if other_name == profile {
            continue;
        }
        if other.outbound.kind == OutboundKind::Inline && other.outbound.tag == tag {
            return Err(crate::config_errorf!(
                "duplicate tag {} (already the inline outbound of profile {})",
                go_quote(tag),
                go_quote(other_name)
            ));
        }
        if other.outbound.kind == OutboundKind::Tag
            && other.outbound.tag == tag
            && !other.outbound.typ.is_empty()
            && other.outbound.typ != new_type
        {
            return Err(crate::config_errorf!(
                "tag {} is used by profile {} with type {}; refusing to overwrite with type {}",
                go_quote(tag),
                go_quote(other_name),
                go_quote(&other.outbound.typ),
                go_quote(new_type)
            ));
        }
    }
    Ok(())
}

fn raw_obj_str<'a>(v: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    match v {
        JsonValue::Object(obj) => obj.get(key),
        _ => None,
    }
}

/// Replace the outbound with the same tag, or append it
/// (`setOutboundInList`, `profilecmd.go:531`).
fn set_outbound_in_list(cfg: &mut SingleConfig, raw: JsonValue) {
    let tag = match &raw {
        JsonValue::Object(obj) => match obj.get("tag") {
            Some(JsonValue::Str(t)) => t.clone(),
            _ => String::new(),
        },
        _ => String::new(),
    };
    for (i, existing) in cfg.outbounds_raw.iter().enumerate() {
        if let Some(JsonValue::Str(t)) = raw_obj_str(existing, "tag")
            && t == &tag
        {
            cfg.outbounds_raw[i] = raw;
            return;
        }
    }
    cfg.outbounds_raw.push(raw);
}

/// Replace the endpoint with the same tag, or append it
/// (`setEndpointInList`, `profilecmd.go:636`).
fn set_endpoint_in_list(cfg: &mut SingleConfig, raw: JsonValue) {
    let tag = match &raw {
        JsonValue::Object(obj) => match obj.get("tag") {
            Some(JsonValue::Str(t)) => t.clone(),
            _ => String::new(),
        },
        _ => String::new(),
    };
    for (i, existing) in cfg.endpoints_raw.iter().enumerate() {
        if let Some(JsonValue::Str(t)) = raw_obj_str(existing, "tag")
            && t == &tag
        {
            cfg.endpoints_raw[i] = raw;
            return;
        }
    }
    cfg.endpoints_raw.push(raw);
}

/// `SetFingerprint` (`profilecmd.go:343`): set a
/// profile's recorded fingerprint preset name (storage
/// only). The value is validated before anything is
/// written: invalid → error, file unchanged. An empty
/// value resets the profile to the default (`"chrome"`)
/// and clears the stored key, so a later save omits it.
/// The profile must already exist in the single file.
pub fn set_fingerprint(
    base_dir: &str,
    name: &str,
    fingerprint: &str,
) -> Result<Profile, ConfigError> {
    set_identity_field(base_dir, name, fingerprint, true)
}

/// `SetTlsEngine` (`profilecmd.go:386`): same shape for
/// the TLS engine name (default `"utls"`).
pub fn set_tls_engine(
    base_dir: &str,
    name: &str,
    tls_engine: &str,
) -> Result<Profile, ConfigError> {
    set_identity_field(base_dir, name, tls_engine, false)
}

fn set_identity_field(
    base_dir: &str,
    name: &str,
    value: &str,
    is_fingerprint: bool,
) -> Result<Profile, ConfigError> {
    validate_profile_name(name)?;
    if !value.is_empty() {
        if is_fingerprint {
            validate_fingerprint_value(value).map_err(config_error)?;
        } else {
            validate_tls_engine_value(value).map_err(config_error)?;
        }
    }
    let state = load_config_state(base_dir)?;
    if !state.found {
        let what = if is_fingerprint {
            "set-fingerprint"
        } else {
            "set-tls-engine"
        };
        return Err(config_error(format!(
            "profile {what} only modifies single-file entries; no single config file exists (run config migrate first)"
        )));
    }
    if !state
        .config
        .as_ref()
        .is_some_and(|c| c.profiles.contains_key(name))
    {
        return Err(crate::config_errorf!(
            "profile {} does not exist in the single config file",
            go_quote(name)
        ));
    }
    let mut updated: Option<Profile> = None;
    update_single_config(base_dir, |cfg| {
        let Some(p) = cfg.profiles.get_mut(name) else {
            return Err(crate::config_errorf!(
                "profile {} does not exist in the single config file",
                go_quote(name)
            ));
        };
        if is_fingerprint {
            if value.is_empty() {
                p.fingerprint = DEFAULT_FINGERPRINT.to_string();
                p.fingerprint_present = false;
            } else {
                p.fingerprint = value.to_string();
                p.fingerprint_present = true;
            }
        } else if value.is_empty() {
            p.tls_engine = DEFAULT_TLS_ENGINE.to_string();
            p.tls_engine_present = false;
        } else {
            p.tls_engine = value.to_string();
            p.tls_engine_present = true;
        }
        updated = Some(p.clone());
        Ok(())
    })?;
    updated.ok_or_else(|| crate::config_errorf!("profile {} was not updated", go_quote(name)))
}

// ---------------------------------------------------------------------
// OutboundFromEnv
// ---------------------------------------------------------------------

/// The tag of the outbound `outbound_from_env` builds
/// (`envproxy.go`, `EnvProxyOutboundTag`). Stable so the
/// S7 outbound identity is stable for a given proxy URL.
pub const ENV_PROXY_OUTBOUND_TAG: &str = "env-proxy";

/// One parsed proxy URL.
struct ProxyUrl {
    scheme: String,
    host: String,
    port: u16,
    username: String,
    /// `None` when the URL carries no userinfo password.
    password: Option<String>,
}

/// `OutboundFromEnv` (`envproxy.go:70`): build ONE
/// explicit sing-box `"http"` outbound from the proxy
/// environment variables. Returns `None` when no proxy
/// variable is set, when the chosen value is
/// `"direct"`/`"none"`, or when NO_PROXY is `"*"`. A
/// malformed URL is an error (exit 2 at command level).
///
/// Variable precedence: HTTPS_PROXY/https_proxy, then
/// HTTP_PROXY/http_proxy, then ALL_PROXY/all_proxy.
/// Within one family the uppercase spelling wins. The
/// first non-empty value wins.
///
/// The returned object is built in sing-box marshal
/// order (`type`, `tag`, `server`, `server_port`,
/// `username`, `password`, `tls`) so its bytes match Go's
/// `marshalSing` output for the same URL.
pub fn outbound_from_env(getenv: Getenv<'_>) -> Result<Option<JsonValue>, ConfigError> {
    let lookup = |key: &str| crate::configlocation::config_lookup_env(getenv, key);
    if no_proxy_bypass(&lookup) {
        return Ok(None);
    }
    let Some((raw, name)) = first_proxy_env(&lookup) else {
        return Ok(None);
    };
    let trimmed = go_trim_space(&raw).to_string();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if go_trim_space(&trimmed).to_lowercase() == "direct"
        || go_trim_space(&trimmed).to_lowercase() == "none"
    {
        return Ok(None);
    }
    let parsed = parse_proxy_url(&trimmed).map_err(|inner| {
        let msg = format!(
            "invalid proxy url in {} {}: {}",
            name,
            go_quote(&trimmed),
            inner
        );
        config_error(redact_string(&msg))
    })?;
    let mut obj = OrderedObject::new();
    obj.set("type".to_string(), JsonValue::Str("http".to_string()));
    obj.set(
        "tag".to_string(),
        JsonValue::Str(ENV_PROXY_OUTBOUND_TAG.to_string()),
    );
    obj.set("server".to_string(), JsonValue::Str(parsed.host));
    obj.set(
        "server_port".to_string(),
        JsonValue::Number(parsed.port.to_string()),
    );
    if !parsed.username.is_empty() {
        obj.set("username".to_string(), JsonValue::Str(parsed.username));
    }
    if let Some(pw) = parsed.password
        && !pw.is_empty()
    {
        obj.set("password".to_string(), JsonValue::Str(pw));
    }
    if parsed.scheme == "https" {
        let mut tls = OrderedObject::new();
        tls.set("enabled".to_string(), JsonValue::Bool(true));
        obj.set("tls".to_string(), JsonValue::Object(tls));
    }
    Ok(Some(JsonValue::Object(obj)))
}

fn no_proxy_bypass(lookup: &dyn Fn(&str) -> Option<String>) -> bool {
    for key in ["NO_PROXY", "no_proxy"] {
        if let Some(v) = lookup(key) {
            for entry in v.split(',') {
                if go_trim_space(entry) == "*" {
                    return true;
                }
            }
        }
    }
    false
}

fn first_proxy_env(lookup: &dyn Fn(&str) -> Option<String>) -> Option<(String, &'static str)> {
    for family in [
        ("HTTPS_PROXY", "https_proxy"),
        ("HTTP_PROXY", "http_proxy"),
        ("ALL_PROXY", "all_proxy"),
    ] {
        for name in [family.0, family.1] {
            if let Some(v) = lookup(name)
                && !go_trim_space(&v).is_empty()
            {
                return Some((v, name));
            }
        }
    }
    None
}

/// Parse a proxy URL the way Go's `url.Parse` + the
/// `OutboundFromEnv` checks do, returning the Go-style
/// inner error text on failure (the caller wraps it with
/// `invalid proxy url in <NAME> "<raw>": ...` and runs it
/// through `redact.String`).
///
/// Covered exactly: scheme check, missing host, port
/// digits/range, missing `]` in an IPv6 literal, invalid
/// `%` escapes, control characters. The remaining
/// `url.Parse` failure modes (e.g. a bad scheme spelling)
/// are approximated with Go's `first path segment in URL
/// cannot contain colon` text; a `%` escape error names
/// the offending 3-byte sequence, as Go does.
fn parse_proxy_url(raw: &str) -> Result<ProxyUrl, String> {
    // Control characters and bad `%` escapes fail the
    // whole parse in Go, before any component is read.
    for c in raw.chars() {
        if (c as u32) < 0x20 || (c as u32) == 0x7f {
            return Err(format!(
                "parse {}: net/url: invalid control character in URL",
                go_quote(raw)
            ));
        }
    }
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let ok = i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit();
            if !ok {
                let end = (i + 3).min(bytes.len());
                let esc = &raw[i..end];
                return Err(format!(
                    "parse {}: invalid URL escape {}",
                    go_quote(raw),
                    go_quote(esc)
                ));
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    let Some(sep) = raw.find("://") else {
        // No scheme delimiter: Go's url.Parse reads the
        // scheme (if any) before the first ':'.
        let scheme = match raw.find(':') {
            Some(colon) => {
                let cand = &raw[..colon];
                if !cand.is_empty()
                    && cand.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                    && cand
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
                {
                    cand.to_string()
                } else {
                    String::new()
                }
            }
            None => String::new(),
        };
        return Err(format!(
            "unsupported proxy scheme {}: want http or https",
            go_quote(&scheme)
        ));
    };
    let scheme_raw = &raw[..sep];
    if scheme_raw.is_empty() {
        return Err(format!("parse {}: missing protocol scheme", go_quote(raw)));
    }
    if !scheme_raw
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
        || !scheme_raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return Err(format!(
            "parse {}: first path segment in URL cannot contain colon {}",
            go_quote(raw),
            go_quote(scheme_raw)
        ));
    }
    let scheme = scheme_raw.to_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!(
            "unsupported proxy scheme {}: want http or https",
            go_quote(scheme_raw)
        ));
    }
    let rest = &raw[sep + 3..];
    let auth_end = rest
        .find(|c| ['/', '?', '#'].contains(&c))
        .unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    if authority.is_empty() {
        return Err("proxy url has no host".to_string());
    }
    // Userinfo splits at the LAST '@' (Go `url.Parse`).
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(at) => (&authority[..at], &authority[at + 1..]),
        None => ("", authority),
    };
    let (username, password) = if userinfo.is_empty() {
        (String::new(), None)
    } else {
        match userinfo.find(':') {
            Some(colon) => (
                percent_decode(&userinfo[..colon]),
                Some(percent_decode(&userinfo[colon + 1..])),
            ),
            None => (percent_decode(userinfo), None),
        }
    };
    // Host/port: bracketed IPv6 or bare host.
    let (host, port_str): (String, Option<String>) =
        if let Some(stripped) = hostport.strip_prefix('[') {
            let Some(close) = stripped.find(']') else {
                return Err(format!("parse {}: missing ']' in host", go_quote(raw)));
            };
            let host = stripped[..close].to_string();
            let after = &stripped[close + 1..];
            if after.is_empty() {
                (host, None)
            } else if let Some(p) = after.strip_prefix(':') {
                (host, Some(p.to_string()))
            } else {
                return Err(format!(
                    "parse {}: invalid port {} after host",
                    go_quote(raw),
                    go_quote(after)
                ));
            }
        } else {
            match hostport.find(':') {
                Some(colon) => (
                    hostport[..colon].to_string(),
                    Some(hostport[colon + 1..].to_string()),
                ),
                None => (hostport.to_string(), None),
            }
        };
    if host.is_empty() {
        return Err("proxy url has no host".to_string());
    }
    let default_port: u16 = if scheme == "https" { 443 } else { 80 };
    let port = match port_str.as_deref() {
        None | Some("") => default_port,
        Some(p) => {
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!(
                    "parse {}: invalid port {} after host",
                    go_quote(raw),
                    go_quote(&format!(":{p}"))
                ));
            }
            match p.parse::<u32>() {
                Ok(n) if (1..=65535).contains(&n) => n as u16,
                _ => {
                    return Err(format!("invalid proxy port {}", go_quote(p)));
                }
            }
        }
    };
    Ok(ProxyUrl {
        scheme,
        host,
        port,
        username,
        password,
    })
}

/// Percent-decode `%XX` sequences (Go's `url.Userinfo`
/// accessors return decoded values). The caller already
/// rejected malformed escapes; a stray `%` is left as-is.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hex = |b: u8| -> u8 {
                match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    _ => b - b'A' + 10,
                }
            };
            out.push(hex(bytes[i + 1]) * 16 + hex(bytes[i + 2]));
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `ResolveTelegram` (`internal/profile/telegram.go:263`):
/// the parsed `telegram` block, or `None` when the block
/// is absent. The block is re-validated, so a hand-built
/// config gets the same refusal parse gives.
pub fn resolve_telegram(single: &SingleConfig) -> Result<Option<&TelegramConfig>, ConfigError> {
    let Some(tg) = &single.telegram else {
        return Ok(None);
    };
    validate_telegram(tg, |name| single.profiles.contains_key(name))?;
    Ok(Some(tg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_single_config;
    use crate::jsonvalue::encode_ordered_json;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "castctl-config-profileops-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_config(dir: &std::path::Path, text: &str) {
        std::fs::write(dir.join("config.json"), text).unwrap();
    }

    fn read_config(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join("config.json")).unwrap()
    }

    fn base_config() -> &'static str {
        "{\n  \"default_profile\": \"no.0\",\n  \"profiles\": {\n    \"no.0\": {\n      \"cookies_file\": \"/tmp/cfg/cookies.txt\",\n      \"auto_approve\": \"off\",\n      \"auto_allow_once\": false\n    }\n  }\n}\n"
    }

    #[test]
    fn add_profile_round_trip() {
        let dir = temp_dir("add");
        write_config(&dir, base_config());
        let created = add_profile(
            dir.to_str().unwrap(),
            "eps",
            AddProfileOptions {
                set_default: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(created.name, "eps");
        assert_eq!(created.node_id.len(), 16);
        assert!(created.node_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(created.auto_approve, "off");
        assert_eq!(
            created.cookies_file,
            dir.join("profiles/eps/cookies.txt").to_string_lossy()
        );
        let out = read_config(&dir);
        assert!(out.contains("\"eps\""), "got:\n{out}");
        assert!(out.contains("\"default_profile\": \"eps\""), "got:\n{out}");
        assert!(out.contains("\"node_id\": "), "got:\n{out}");
        // No cookies file or profile dir created.
        assert!(
            !dir.join("profiles")
                .join("eps")
                .join("cookies.txt")
                .exists()
        );
        // Duplicate refused, file unchanged.
        let before = read_config(&dir);
        let e =
            add_profile(dir.to_str().unwrap(), "eps", AddProfileOptions::default()).unwrap_err();
        assert_eq!(e.message, "profile: profile \"eps\" already exists");
        assert_eq!(read_config(&dir), before);
        // Bad fingerprint: validated before touching the FS.
        let e = add_profile(
            dir.to_str().unwrap(),
            "new",
            AddProfileOptions {
                fingerprint: "opera".to_string(),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            e.message,
            "profile: fingerprint must be one of chrome, firefox, ios, safari"
        );
        assert_eq!(read_config(&dir), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_profile_tag_and_legacy_refusals() {
        let dir = temp_dir("addtag");
        write_config(
            &dir,
            "{\n  \"profiles\": {\n    \"no.0\": {}\n  },\n  \"outbounds\": [{\"type\": \"socks\", \"tag\": \"proxy-sg\", \"server\": \"127.0.0.1\", \"server_port\": 1080}]\n}\n",
        );
        let created = add_profile(
            dir.to_str().unwrap(),
            "eps",
            AddProfileOptions {
                outbound_tag: "proxy-sg".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(created.outbound.tag, "proxy-sg");
        assert_eq!(created.outbound.from, "outbound");
        assert_eq!(created.outbound.typ, "socks");
        // Dangling tag: the write aborts.
        let e = add_profile(
            dir.to_str().unwrap(),
            "ghost",
            AddProfileOptions {
                outbound_tag: "nosuchtag".to_string(),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            e.message,
            "profile: profile \"ghost\": outbound tag \"nosuchtag\" does not exist"
        );
        // Legacy per-profile file blocks adding the same name.
        let dir2 = temp_dir("addlegacy");
        let pdir = dir2.join("profiles").join("old");
        std::fs::create_dir_all(&pdir).unwrap();
        std::fs::write(pdir.join("config.json"), "{}\n").unwrap();
        let e =
            add_profile(dir2.to_str().unwrap(), "old", AddProfileOptions::default()).unwrap_err();
        assert_eq!(
            e.message,
            "profile: the old layout exists unmigrated; run config migrate first"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn remove_profile_fallbacks() {
        let dir = temp_dir("rm");
        write_config(
            &dir,
            "{\n  \"default_profile\": \"gamma\",\n  \"profiles\": {\n    \"gamma\": {},\n    \"default\": {}\n  }\n}\n",
        );
        let r = remove_profile(dir.to_str().unwrap(), "gamma").unwrap();
        assert_eq!(r.name, "gamma");
        assert_eq!(r.warning, "default_profile fell back to \"default\"");
        assert_eq!(r.default_profile, "default");
        assert!(read_config(&dir).contains("\"default_profile\": \"default\""));
        // Removing the last default clears the key.
        let r = remove_profile(dir.to_str().unwrap(), "default").unwrap();
        assert_eq!(
            r.warning,
            "default_profile cleared: no \"default\" profile remains"
        );
        assert_eq!(r.default_profile, "");
        assert!(
            !read_config(&dir).contains("default_profile"),
            "got:\n{}",
            read_config(&dir)
        );
        // Unknown name.
        let e = remove_profile(dir.to_str().unwrap(), "ghost").unwrap_err();
        assert_eq!(
            e.message,
            "profile: profile \"ghost\" does not exist in the single config file"
        );
        // No single file at all.
        let dir2 = temp_dir("rm-none");
        let e = remove_profile(dir2.to_str().unwrap(), "ghost").unwrap_err();
        assert_eq!(
            e.message,
            "profile: profile rm only removes single-file entries; no single config file exists"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn remove_profile_stranded_inline_refused() {
        // Removing b strands a's tag reference to b's inline
        // outbound: validateTagGraph refuses.
        let dir = temp_dir("rm-strand");
        write_config(
            &dir,
            "{\n  \"profiles\": {\n    \"a\": {\"outbound\": \"profile:b\"},\n    \"b\": {\"outbound\": {\"type\": \"socks\", \"tag\": \"profile:b\", \"server\": \"127.0.0.1\", \"server_port\": 1080}}\n  }\n}\n",
        );
        let e = remove_profile(dir.to_str().unwrap(), "b").unwrap_err();
        assert_eq!(
            e.message,
            "profile: profile \"a\": outbound tag \"profile:b\" does not exist"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_outbound_paths() {
        let dir = temp_dir("setob");
        write_config(&dir, base_config());
        // Inline (untagged): auto-tagged profile:<name>.
        let updated = set_outbound(
            dir.to_str().unwrap(),
            "no.0",
            br#"{"type":"socks","server":"127.0.0.1","server_port":1080,"username":"u","password":"p"}"#,
        )
        .unwrap();
        assert_eq!(updated.outbound.kind, OutboundKind::Inline);
        assert_eq!(updated.outbound.tag, "profile:no.0");
        assert_eq!(updated.outbound.typ, "socks");
        assert!(
            read_config(&dir).contains("\"profile:no.0\""),
            "got:\n{}",
            read_config(&dir)
        );
        // Tagged: goes to the list, profile references the tag.
        let updated = set_outbound(
            dir.to_str().unwrap(),
            "no.0",
            br#"{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1080}"#,
        )
        .unwrap();
        assert_eq!(updated.outbound.kind, OutboundKind::Tag);
        assert_eq!(updated.outbound.tag, "proxy-sg");
        // The tag graph resolves Type/From on the returned
        // profile (Go `validateTagGraph`, in-place on the
        // map entry — see `set_outbound`'s insert-before-
        // validate order).
        assert_eq!(updated.outbound.typ, "socks");
        assert_eq!(updated.outbound.from, "outbound");
        // WireGuard (untagged): auto-tagged into endpoints.
        // The endpoint shape is Go's `WireGuardEndpointOptions`:
        // `address` + `peers`, never `server`/`server_port`
        // (those are not endpoint fields — Go's `parseEndpoint`
        // rejects them as unknown fields).
        let updated = set_outbound(
            dir.to_str().unwrap(),
            "no.0",
            br#"{"type":"wireguard","private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","address":["10.0.0.2/32"],"peers":[{"address":"10.0.0.1","port":51820,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowed_ips":["0.0.0.0/0"]}]}"#,
        )
        .unwrap();
        assert_eq!(updated.outbound.kind, OutboundKind::Tag);
        assert_eq!(updated.outbound.tag, "profile:no.0");
        assert_eq!(updated.outbound.from, "endpoint");
        // Wrapper rejected.
        let e = set_outbound(
            dir.to_str().unwrap(),
            "no.0",
            br#"{"outbound":{"type":"socks"}}"#,
        )
        .unwrap_err();
        assert_eq!(
            e.message,
            "profile: set-outbound takes one outbound/endpoint object, not a {\"outbound\": {...}} wrapper"
        );
        // Missing type.
        let e =
            set_outbound(dir.to_str().unwrap(), "no.0", br#"{"server":"127.0.0.1"}"#).unwrap_err();
        assert_eq!(e.message, "profile: outbound object must have a \"type\"");
        // system:true refused.
        let e = set_outbound(
            dir.to_str().unwrap(),
            "no.0",
            br#"{"type":"wireguard","system":true}"#,
        )
        .unwrap_err();
        assert_eq!(
            e.message,
            "profile: wireguard endpoint \"system\": true is not supported; use userspace wireguard only"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_outbound_same_tag_rules() {
        let dir = temp_dir("setob-tag");
        write_config(
            &dir,
            "{\n  \"profiles\": {\n    \"a\": {\"outbound\": \"shared\"},\n    \"b\": {}\n  },\n  \"outbounds\": [{\"type\": \"socks\", \"tag\": \"shared\", \"server\": \"127.0.0.1\", \"server_port\": 1080}]\n}\n",
        );
        // Another profile uses the tag with a different type:
        // overwrite refused.
        let e = set_outbound(
            dir.to_str().unwrap(),
            "b",
            br#"{"type":"http","tag":"shared","server":"127.0.0.1","server_port":8080}"#,
        )
        .unwrap_err();
        assert_eq!(
            e.message,
            "profile: tag \"shared\" is used by profile \"a\" with type \"socks\"; refusing to overwrite with type \"http\""
        );
        // Same type: overwrite allowed.
        set_outbound(
            dir.to_str().unwrap(),
            "b",
            br#"{"type":"socks","tag":"shared","server":"127.0.0.2","server_port":1080}"#,
        )
        .unwrap();
        assert!(read_config(&dir).contains("127.0.0.2"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_fingerprint_and_tls_engine() {
        let dir = temp_dir("setid");
        write_config(&dir, base_config());
        let updated = set_fingerprint(dir.to_str().unwrap(), "no.0", "firefox").unwrap();
        assert_eq!(updated.fingerprint, "firefox");
        assert!(updated.fingerprint_present);
        assert!(read_config(&dir).contains("\"fingerprint\": \"firefox\""));
        // Empty resets to the default and removes the key.
        let updated = set_fingerprint(dir.to_str().unwrap(), "no.0", "").unwrap();
        assert_eq!(updated.fingerprint, "chrome");
        assert!(!updated.fingerprint_present);
        assert!(!read_config(&dir).contains("fingerprint"));
        let updated = set_tls_engine(dir.to_str().unwrap(), "no.0", "cronet").unwrap();
        assert_eq!(updated.tls_engine, "cronet");
        let e = set_tls_engine(dir.to_str().unwrap(), "no.0", "quic").unwrap_err();
        assert_eq!(
            e.message,
            "profile: tls_engine must be one of cronet, stdlib, utls"
        );
        let e = set_fingerprint(dir.to_str().unwrap(), "ghost", "firefox").unwrap_err();
        assert_eq!(
            e.message,
            "profile: profile \"ghost\" does not exist in the single config file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn getenv_map(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone())
    }

    #[test]
    fn outbound_from_env_shapes() {
        // No vars: None.
        let lookup = getenv_map(&[]);
        assert!(outbound_from_env(Some(&lookup)).unwrap().is_none());
        // HTTPS wins over HTTP; marshal order is sing-box's.
        let lookup = getenv_map(&[
            ("HTTPS_PROXY", "https://user:s3cret@proxy.invalid:8443"),
            ("HTTP_PROXY", "http://other.invalid:8080"),
        ]);
        let v = outbound_from_env(Some(&lookup)).unwrap().unwrap();
        assert_eq!(
            encode_ordered_json(&v).unwrap(),
            r#"{"type":"http","tag":"env-proxy","server":"proxy.invalid","server_port":8443,"username":"user","password":"s3cret","tls":{"enabled":true}}"#
        );
        // HTTP default port, no userinfo, no tls key.
        let lookup = getenv_map(&[("HTTP_PROXY", "http://proxy.invalid")]);
        let v = outbound_from_env(Some(&lookup)).unwrap().unwrap();
        assert_eq!(
            encode_ordered_json(&v).unwrap(),
            r#"{"type":"http","tag":"env-proxy","server":"proxy.invalid","server_port":80}"#
        );
        // direct / none / NO_PROXY=* mean no outbound.
        for (k, val) in [
            ("HTTPS_PROXY", "direct"),
            ("HTTPS_PROXY", "NONE"),
            ("ALL_PROXY", "http://proxy.invalid"),
        ] {
            let _ = (k, val);
        }
        let lookup = getenv_map(&[("HTTPS_PROXY", "direct")]);
        assert!(outbound_from_env(Some(&lookup)).unwrap().is_none());
        let lookup = getenv_map(&[("ALL_PROXY", "http://proxy.invalid"), ("NO_PROXY", "*")]);
        assert!(outbound_from_env(Some(&lookup)).unwrap().is_none());
        let lookup = getenv_map(&[("NO_PROXY", "example.com, *")]);
        assert!(outbound_from_env(Some(&lookup)).unwrap().is_none());
        // Unsupported scheme names the variable, never the URL
        // credentials: Go's `envProxyError`
        // (`envproxy.go:183`) formats the raw URL, then runs
        // the whole message through `redact.String`, which
        // replaces URL userinfo with `<redacted>`.
        let lookup = getenv_map(&[("HTTPS_PROXY", "socks5://user:pw@proxy.invalid:1080")]);
        let e = outbound_from_env(Some(&lookup)).unwrap_err();
        assert_eq!(
            e.message,
            "profile: invalid proxy url in HTTPS_PROXY \"socks5://<redacted>@proxy.invalid:1080\": unsupported proxy scheme \"socks5\": want http or https"
        );
        // No host.
        let lookup = getenv_map(&[("HTTPS_PROXY", "http:///path")]);
        let e = outbound_from_env(Some(&lookup)).unwrap_err();
        assert!(
            e.message.contains("proxy url has no host"),
            "message: {}",
            e.message
        );
        // Bad ports.
        for bad in ["http://h:0", "http://h:65536", "http://h:abc"] {
            let lookup = getenv_map(&[("HTTPS_PROXY", bad)]);
            let e = outbound_from_env(Some(&lookup)).unwrap_err();
            assert!(
                e.message.contains("invalid proxy port") || e.message.contains("invalid port"),
                "bad={bad} message: {}",
                e.message
            );
        }
        // IPv6 literal + percent-decoded userinfo.
        let lookup = getenv_map(&[("HTTPS_PROXY", "http://us%40er:p%3Ass@[2001:db8::1]:8080")]);
        let v = outbound_from_env(Some(&lookup)).unwrap().unwrap();
        assert_eq!(
            encode_ordered_json(&v).unwrap(),
            r#"{"type":"http","tag":"env-proxy","server":"2001:db8::1","server_port":8080,"username":"us@er","password":"p:ss"}"#
        );
    }

    #[test]
    fn resolve_telegram_shapes() {
        let cfg = parse_single_config(
            br#"{"profiles":{"a":{}},"telegram":{"profile":"a","token":"123456:AAAAAAAAAAAAAAAAAAAAA","allowed_user_ids":[111]}}"#,
            "/tmp",
        )
        .unwrap();
        assert!(resolve_telegram(&cfg).unwrap().is_some());
        let cfg = parse_single_config(br#"{"profiles":{"a":{}}}"#, "/tmp").unwrap();
        assert!(resolve_telegram(&cfg).unwrap().is_none());
        // A dangling telegram profile reference fails at
        // PARSE, not in ResolveTelegram: Go's
        // `ParseSingleConfig` calls `validateTelegram`
        // (`config.go:442`), which rejects it with
        // `telegram: profile "ghost" does not exist`
        // (`telegram.go:232`). ResolveTelegram re-runs the
        // same check for hand-built configs.
        let e = parse_single_config(
            br#"{"profiles":{"a":{}},"telegram":{"profile":"ghost","token":"123456:AAAAAAAAAAAAAAAAAAAAA","allowed_user_ids":[111]}}"#,
            "/tmp",
        )
        .unwrap_err();
        assert_eq!(
            e.message,
            "profile: telegram: profile \"ghost\" does not exist"
        );
    }
}
