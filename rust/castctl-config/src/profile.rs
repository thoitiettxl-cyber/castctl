// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Profile names, paths, entries, and outbound references.
//!
//! Sources at base `dev-rust` `85a8d5e`: `internal/profile/profile.go`
//! (`ValidateProfileName`, `ResolveProfileName`, `BaseDir`,
//! `ProfilePaths`, `DiscoverProfileNames`, `Profile`),
//! `internal/profile/outbound.go` (`OutboundRef`, kinds),
//! `internal/profile/dns.go:147-165` (synthesised-direct tag),
//! `internal/profile/config.go` (`parseProfileEntry`,
//! `ensureInlineTag`, `parseAutoAllowOnceValue`,
//! `resolveCookiesFile`).

use crate::configlocation::Getenv;
use crate::errors::{ConfigError, config_error, invalid_profile_error};
use crate::fingerprint::{
    DEFAULT_FINGERPRINT, DEFAULT_TLS_ENGINE, validate_fingerprint_value, validate_tls_engine_value,
};
use crate::gopath::{go_clean, go_is_abs, go_join, is_inside_dir};
use crate::gostr::{go_lower, go_quote, go_trim_space};
use crate::jsonvalue::{JsonValue, OrderedObject};

/// The default profile name (`profile.go`: `DefaultProfileName`).
pub const DEFAULT_PROFILE_NAME: &str = "default";

/// Environment variable naming the active profile (`ProfileEnv`).
pub const PROFILE_ENV: &str = "CASTCTL_PROFILE";

/// Where a profile's settings came from (`profile.go:186`,
/// `Source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Source {
    /// Settings came from the single-file config.json (`"single"`).
    Single,
    /// Built from a legacy file by Migrate, migrate-only (`"legacy"`).
    Legacy,
    /// No config file found; defaults apply (`"none"`).
    #[default]
    None,
}

impl Source {
    /// The Go `Source` string value.
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Single => "single",
            Source::Legacy => "legacy",
            Source::None => "none",
        }
    }
}

/// `ValidateProfileName` (`profile.go:26`): 1-64 runes, only
/// letters, digits, `.`, `_`, `-`, never starting or ending with
/// `.`. Mirrors the Python regex `^(?!\.)[A-Za-z0-9._-]{1,64}(?<!\.)$`.
pub fn validate_profile_name(name: &str) -> Result<String, ConfigError> {
    let runes: Vec<char> = name.chars().collect();
    if runes.is_empty() || runes.len() > 64 {
        return Err(invalid_profile_error(name));
    }
    if runes[0] == '.' || runes[runes.len() - 1] == '.' {
        return Err(invalid_profile_error(name));
    }
    for r in &runes {
        let ok = r.is_ascii_alphanumeric() || *r == '.' || *r == '_' || *r == '-';
        if !ok {
            return Err(invalid_profile_error(name));
        }
    }
    Ok(name.to_string())
}

/// `ResolveProfileName` (`profile.go:47`): flag (even empty) >
/// non-blank env value (trimmed) > `"default"`. `getenv` returns
/// `None` for an unset variable; pass `None` as the whole getter
/// to read the process environment (see the `Getenv` convention
/// in `configlocation.rs`).
pub fn resolve_profile_name(flag: Option<&str>, getenv: Getenv<'_>) -> Result<String, ConfigError> {
    if let Some(flag) = flag {
        return validate_profile_name(flag);
    }
    if let Some(env) = crate::configlocation::config_lookup_env(getenv, PROFILE_ENV)
        && !go_trim_space(&env).is_empty()
    {
        return validate_profile_name(go_trim_space(&env));
    }
    Ok(DEFAULT_PROFILE_NAME.to_string())
}

/// `BaseDir` (`profile.go:80`): `Join(home, ".config", "castctl")`,
/// the fallback constructor for the relative-XDG case only.
pub fn base_dir(home: &str) -> String {
    go_join(&[home, ".config", "castctl"])
}

/// Filesystem locations for one profile (`profile.go:84`, `Paths`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// Profile directory.
    pub dir: String,
    /// Profile config file.
    pub config: String,
    /// Profile cookies file.
    pub cookies: String,
    /// Profile chat file.
    pub chat: String,
}

/// `ProfilePaths` (`profile.go:84`): default = base dir; named =
/// `base/profiles/<name>/`.
pub fn profile_paths(base_dir: &str, name: &str) -> Result<Paths, ConfigError> {
    validate_profile_name(name)?;
    if name == DEFAULT_PROFILE_NAME {
        return Ok(Paths {
            dir: base_dir.to_string(),
            config: go_join(&[base_dir, "config.json"]),
            cookies: go_join(&[base_dir, "cookies.txt"]),
            chat: go_join(&[base_dir, "chat.json"]),
        });
    }
    let dir = go_join(&[base_dir, "profiles", name]);
    Ok(Paths {
        config: go_join(&[&dir, "config.json"]),
        cookies: go_join(&[&dir, "cookies.txt"]),
        chat: go_join(&[&dir, "chat.json"]),
        dir,
    })
}

/// `DiscoverProfileNames` (`profile.go:153`): `["default"]` plus
/// validly-named subdirectories of `profiles/`, in `ReadDir`
/// (filename-sorted) order. A missing `profiles/` dir yields just
/// `["default"]`; other read errors are config errors. Symlinks to
/// directories count (via `Stat` follow).
pub fn discover_profile_names(base_dir: &str) -> Result<Vec<String>, ConfigError> {
    let mut names = vec![DEFAULT_PROFILE_NAME.to_string()];
    let profiles_dir = go_join(&[base_dir, "profiles"]);
    let entries = match std::fs::read_dir(&profiles_dir) {
        Ok(entries) => entries,
        Err(e) if crate::oserr::is_not_exist(&e) => return Ok(names),
        Err(e) => {
            return Err(crate::config_errorf!(
                "list profiles: {}",
                crate::oserr::open_error_text(&profiles_dir, &e)
            ));
        }
    };
    let mut dirs: Vec<String> = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_dir = match entry.file_type() {
            Ok(ft) if ft.is_dir() => true,
            Ok(ft) if ft.is_symlink() => std::fs::metadata(entry.path())
                .map(|m| m.is_dir())
                .unwrap_or(false),
            _ => false,
        };
        if !is_dir {
            continue;
        }
        if validate_profile_name(&name).is_err() || name == DEFAULT_PROFILE_NAME {
            continue;
        }
        dirs.push(name);
    }
    dirs.sort();
    names.extend(dirs);
    Ok(names)
}

/// The synthesised-direct tag prefix (`dns.go:147`,
/// `SynthesizedDirectTagPrefix`): reserved, never a config tag.
pub const SYNTHESIZED_DIRECT_TAG_PREFIX: &str = "castctl-direct:";

/// `IsReservedSynthesizedTag` (`dns.go:151`).
pub fn is_reserved_synthesized_tag(tag: &str) -> bool {
    tag.starts_with(SYNTHESIZED_DIRECT_TAG_PREFIX)
}

/// `SynthesizedDirectTag` (`dns.go:163`): `castctl-direct:<profile>`.
pub fn synthesized_direct_tag(profile_name: &str) -> String {
    format!("{SYNTHESIZED_DIRECT_TAG_PREFIX}{profile_name}")
}

/// Outbound selection kinds (`outbound.go:19-27`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutboundKind {
    /// No outbound key: direct (`"direct"`).
    #[default]
    Direct,
    /// A tag reference into outbounds/endpoints (`"tag"`).
    Tag,
    /// A full inline outbound object (`"inline"`).
    Inline,
}

impl OutboundKind {
    /// The Go `OutboundKind` string value.
    pub fn as_str(self) -> &'static str {
        match self {
            OutboundKind::Direct => "direct",
            OutboundKind::Tag => "tag",
            OutboundKind::Inline => "inline",
        }
    }
}

/// A profile's resolved outbound selection (`outbound.go:34`,
/// `OutboundRef`). For `Tag`, `Type`/`From` are resolved by the
/// (deferred) tag graph and stay empty in M2. For `Inline`, `raw`
/// holds the auto-tagged object JSON.
///
/// `Debug` is hand-written (M1 F5 precedent): `raw` renders as a
/// presence/kind marker only — inline objects may carry
/// secret-adjacent fields — never its content.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct OutboundRef {
    /// Selection kind.
    pub kind: OutboundKind,
    /// Tag (reference target, or the inline object's tag).
    pub tag: String,
    /// Referenced outbound/endpoint type (deferred: tag graph).
    pub typ: String,
    /// Which section the tag came from (deferred: tag graph).
    pub from: String,
    /// Inline object JSON (auto-tagged), or empty.
    pub raw: Option<JsonValue>,
}

impl std::fmt::Debug for OutboundRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundRef")
            .field("kind", &self.kind)
            .field("tag", &self.tag)
            .field("typ", &self.typ)
            .field("from", &self.from)
            .field("raw", &crate::jsonvalue::raw_debug_marker(&self.raw))
            .finish()
    }
}

impl OutboundRef {
    /// `IsDirect` (`outbound.go:44`).
    pub fn is_direct(&self) -> bool {
        self.kind == OutboundKind::Direct
    }

    /// `RawJSON` (`outbound.go:49`): a defensive copy of the inline
    /// object JSON, or `None` for non-inline refs.
    pub fn raw_json(&self) -> Option<JsonValue> {
        self.raw.clone()
    }
}

/// A resolved profile's settings (`profile.go:213`, `Profile`).
///
/// `Debug` is hand-written (M1 F5 precedent): the raw `dns` value
/// and the outbound ref render as presence/kind markers only —
/// both may carry secret-adjacent fields — never their content.
/// The remaining fields are names, paths, and ids, which Go also
/// displays.
#[derive(Clone, PartialEq, Default)]
pub struct Profile {
    /// Profile name.
    pub name: String,
    /// Profile directory.
    pub dir: String,
    /// Config file path (`<baseDir>/config.json` for single-file entries).
    pub config_file: String,
    /// Resolved cookies file path.
    pub cookies_file: String,
    /// Chat file path.
    pub chat_file: String,
    /// `vm_id` value.
    pub vm_id: String,
    /// `node_id` value.
    pub node_id: String,
    /// Normalised `auto_approve` (`"always"` or `"off"`).
    pub auto_approve: String,
    /// `auto_allow_once`.
    pub auto_allow_once: bool,
    /// `subscription_action_id`.
    pub subscription_action_id: String,
    /// `fingerprint` (effective value; default `chrome`).
    pub fingerprint: String,
    /// `tls_engine` (effective value; default `utls`).
    pub tls_engine: String,
    /// The profile's own `dns` block, raw JSON (deferred parse).
    pub dns: Option<JsonValue>,
    /// Outbound selection.
    pub outbound: OutboundRef,
    /// Where the settings came from.
    pub source: Source,
    /// Whether the profile directory exists on disk.
    pub exists: bool,
    /// Whether settings came from a config file.
    pub config_found: bool,
    /// Whether `vm_id` was present in the file.
    pub vm_id_present: bool,
    /// Whether `node_id` was present in the file.
    pub node_id_present: bool,
    /// Whether `fingerprint` was present in the file.
    pub fingerprint_present: bool,
    /// Whether `tls_engine` was present in the file.
    pub tls_engine_present: bool,
    /// Whether `dns` was present in the file.
    pub dns_present: bool,
}

impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Profile")
            .field("name", &self.name)
            .field("dir", &self.dir)
            .field("config_file", &self.config_file)
            .field("cookies_file", &self.cookies_file)
            .field("chat_file", &self.chat_file)
            .field("vm_id", &self.vm_id)
            .field("node_id", &self.node_id)
            .field("auto_approve", &self.auto_approve)
            .field("auto_allow_once", &self.auto_allow_once)
            .field("subscription_action_id", &self.subscription_action_id)
            .field("fingerprint", &self.fingerprint)
            .field("tls_engine", &self.tls_engine)
            .field("dns", &crate::jsonvalue::raw_debug_marker(&self.dns))
            .field("outbound", &self.outbound)
            .field("source", &self.source)
            .field("exists", &self.exists)
            .field("config_found", &self.config_found)
            .field("vm_id_present", &self.vm_id_present)
            .field("node_id_present", &self.node_id_present)
            .field("fingerprint_present", &self.fingerprint_present)
            .field("tls_engine_present", &self.tls_engine_present)
            .field("dns_present", &self.dns_present)
            .finish()
    }
}

/// `parseAutoAllowOnceValue` (`config.go:655`): a bool, or an
/// on/off word (case-insensitive, trimmed). Returns the plain error
/// text; callers wrap with `profile %q: `.
pub fn parse_auto_allow_once_value(value: &JsonValue) -> Result<bool, String> {
    const ERR: &str = "auto_allow_once must be a boolean or an on/off word";
    match value {
        JsonValue::Bool(b) => Ok(*b),
        JsonValue::Str(s) => match go_lower(go_trim_space(s)).as_str() {
            "on" | "1" | "true" | "yes" | "always" => Ok(true),
            "off" | "0" | "false" | "no" | "never" | "" => Ok(false),
            _ => Err(ERR.to_string()),
        },
        _ => Err(ERR.to_string()),
    }
}

/// `ensureInlineTag` (`config.go:619`): return the outbound object
/// with a tag set, inserting `"tag"` right after `"type"` when it
/// was absent, or first when there is no `"type"` key. An existing
/// tag must be a non-empty string (after trim) and is kept as-is.
/// The tag is NOT prefixed with the profile name when present.
pub fn ensure_inline_tag(
    obj: &OrderedObject,
    auto_tag: &str,
) -> Result<(OrderedObject, String), ConfigError> {
    if let Some(tag_value) = obj.get("tag") {
        match tag_value {
            JsonValue::Str(s) => {
                if go_trim_space(s).is_empty() {
                    return Err(config_error("outbound tag must not be empty"));
                }
                return Ok((obj.clone(), s.clone()));
            }
            _ => return Err(config_error("outbound tag must be a string")),
        }
    }
    let mut out = OrderedObject::new();
    let mut inserted = false;
    for (k, v) in obj.iter() {
        out.set(k.clone(), v.clone());
        if k == "type" && !inserted {
            out.set("tag".to_string(), JsonValue::Str(auto_tag.to_string()));
            inserted = true;
        }
    }
    if !inserted {
        let mut with_tag = OrderedObject::new();
        with_tag.set("tag".to_string(), JsonValue::Str(auto_tag.to_string()));
        for (k, v) in obj.iter() {
            with_tag.set(k.clone(), v.clone());
        }
        out = with_tag;
    }
    Ok((out, auto_tag.to_string()))
}

/// `resolveCookiesFile` (`config.go:798`): blank values default;
/// relative values resolve under `base_dir` and are cleaned; a named
/// profile's inside-the-config-dir value at a non-default path is a
/// config error naming both paths.
pub fn resolve_cookies_file(
    base_dir: &str,
    paths: &Paths,
    value: &str,
    name: &str,
) -> Result<String, ConfigError> {
    if go_trim_space(value).is_empty() {
        return Ok(paths.cookies.clone());
    }
    let mut resolved = value.to_string();
    if !go_is_abs(&resolved) {
        resolved = go_join(&[base_dir, &resolved]);
    }
    resolved = go_clean(&resolved);
    if name != DEFAULT_PROFILE_NAME
        && resolved != paths.cookies
        && is_inside_dir(&resolved, base_dir)
    {
        return Err(crate::config_errorf!(
            "profile {}: cookies_file {} is inside the config directory but is not the profile cookies file {}; remove cookies_file to use the default, or point it outside the config directory",
            go_quote(name),
            go_quote(&resolved),
            go_quote(&paths.cookies)
        ));
    }
    Ok(resolved)
}

/// `parseProfileEntry` (`config.go:463`): unknown keys (including
/// inline `cookies`/`cookie`) are rejected in file order first; then
/// fields are checked in fixed code order. The per-profile `dns`
/// block and inline `outbound` objects are stored raw (sing-box
/// parsing deferred, D-M2-1); the outbound tag/type extraction for
/// inline objects reads only the `tag`/`type` string fields.
pub fn parse_profile_entry(
    name: &str,
    obj: &OrderedObject,
    base_dir: &str,
) -> Result<Profile, ConfigError> {
    const PROFILE_KEYS: [&str; 10] = [
        "cookies_file",
        "vm_id",
        "node_id",
        "auto_approve",
        "auto_allow_once",
        "subscription_action_id",
        "fingerprint",
        "tls_engine",
        "outbound",
        "dns",
    ];
    for k in obj.keys() {
        if k == "cookies" || k == "cookie" {
            return Err(crate::config_errorf!(
                "profile {}: cookies must stay in a separate cookies file, never inline in config.json",
                go_quote(name)
            ));
        }
        if !PROFILE_KEYS.contains(&k.as_str()) {
            return Err(crate::config_errorf!(
                "profile {}: unknown key {}",
                go_quote(name),
                go_quote(k)
            ));
        }
    }
    let paths = profile_paths(base_dir, name)?;
    let mut p = Profile {
        name: name.to_string(),
        dir: paths.dir.clone(),
        config_file: go_join(&[base_dir, "config.json"]),
        cookies_file: paths.cookies.clone(),
        chat_file: paths.chat.clone(),
        auto_approve: "off".to_string(),
        fingerprint: DEFAULT_FINGERPRINT.to_string(),
        tls_engine: DEFAULT_TLS_ENGINE.to_string(),
        source: Source::Single,
        config_found: true,
        outbound: OutboundRef {
            kind: OutboundKind::Direct,
            typ: "direct".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    if let Some(v) = obj.get("cookies_file") {
        let s = match v {
            JsonValue::Str(s) => s,
            _ => {
                return Err(crate::config_errorf!(
                    "profile {}: cookies_file must be a string",
                    go_quote(name)
                ));
            }
        };
        p.cookies_file = resolve_cookies_file(base_dir, &paths, s, name)?;
    }
    if let Some(v) = obj.get("vm_id") {
        match v {
            JsonValue::Str(s) => {
                p.vm_id = s.clone();
                p.vm_id_present = true;
            }
            _ => {
                return Err(crate::config_errorf!(
                    "profile {}: vm_id must be a string",
                    go_quote(name)
                ));
            }
        }
    }
    if let Some(v) = obj.get("node_id") {
        match v {
            JsonValue::Str(s) => {
                p.node_id = s.clone();
                p.node_id_present = true;
            }
            _ => {
                return Err(crate::config_errorf!(
                    "profile {}: node_id must be a string",
                    go_quote(name)
                ));
            }
        }
    }
    if let Some(v) = obj.get("auto_approve") {
        let s = match v {
            JsonValue::Str(s) => s,
            _ => {
                return Err(crate::config_errorf!(
                    "profile {}: auto_approve must be a string",
                    go_quote(name)
                ));
            }
        };
        match go_lower(go_trim_space(s)).as_str() {
            "always" => p.auto_approve = "always".to_string(),
            "off" => p.auto_approve = "off".to_string(),
            _ => {
                return Err(crate::config_errorf!(
                    "profile {}: auto_approve must be \"always\" or \"off\"",
                    go_quote(name)
                ));
            }
        }
    }
    if let Some(v) = obj.get("auto_allow_once") {
        match parse_auto_allow_once_value(v) {
            Ok(b) => p.auto_allow_once = b,
            Err(msg) => {
                return Err(crate::config_errorf!("profile {}: {}", go_quote(name), msg));
            }
        }
    }
    if let Some(v) = obj.get("subscription_action_id") {
        match v {
            JsonValue::Str(s) => p.subscription_action_id = s.clone(),
            _ => {
                return Err(crate::config_errorf!(
                    "profile {}: subscription_action_id must be a string",
                    go_quote(name)
                ));
            }
        }
    }
    if let Some(v) = obj.get("fingerprint") {
        let s = match v {
            JsonValue::Str(s) => s,
            _ => {
                return Err(crate::config_errorf!(
                    "profile {}: fingerprint must be a string",
                    go_quote(name)
                ));
            }
        };
        if let Err(msg) = validate_fingerprint_value(s) {
            return Err(crate::config_errorf!("profile {}: {}", go_quote(name), msg));
        }
        p.fingerprint = s.clone();
        p.fingerprint_present = true;
    }
    if let Some(v) = obj.get("tls_engine") {
        let s = match v {
            JsonValue::Str(s) => s,
            _ => {
                return Err(crate::config_errorf!(
                    "profile {}: tls_engine must be a string",
                    go_quote(name)
                ));
            }
        };
        if let Err(msg) = validate_tls_engine_value(s) {
            return Err(crate::config_errorf!("profile {}: {}", go_quote(name), msg));
        }
        p.tls_engine = s.clone();
        p.tls_engine_present = true;
    }
    if let Some(v) = obj.get("dns") {
        // Deferred: sing-box DNS parsing. The raw value is kept for
        // rendering; only presence is recorded.
        p.dns = Some(v.clone());
        p.dns_present = true;
    }
    if let Some(v) = obj.get("outbound") {
        match v {
            JsonValue::Str(t) => {
                if go_trim_space(t).is_empty() {
                    return Err(crate::config_errorf!(
                        "profile {}: outbound tag must not be empty",
                        go_quote(name)
                    ));
                }
                if t == "direct" {
                    p.outbound = OutboundRef {
                        kind: OutboundKind::Direct,
                        typ: "direct".to_string(),
                        ..Default::default()
                    };
                } else {
                    p.outbound = OutboundRef {
                        kind: OutboundKind::Tag,
                        tag: t.clone(),
                        ..Default::default()
                    };
                }
            }
            JsonValue::Object(obj) => {
                let (tagged, tag) = ensure_inline_tag(obj, &format!("profile:{name}"))?;
                // Type from the raw object, if a string; sing-box
                // parsing (which validates it) is deferred.
                let typ = match tagged.get("type") {
                    Some(JsonValue::Str(s)) => s.clone(),
                    _ => String::new(),
                };
                p.outbound = OutboundRef {
                    kind: OutboundKind::Inline,
                    tag,
                    typ,
                    raw: Some(JsonValue::Object(tagged)),
                    ..Default::default()
                };
            }
            _ => {
                return Err(crate::config_errorf!(
                    "profile {}: outbound must be a tag string or an object",
                    go_quote(name)
                ));
            }
        }
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonvalue::decode_ordered_json;

    fn entry_json(input: &str) -> OrderedObject {
        match decode_ordered_json(input.as_bytes()).unwrap() {
            JsonValue::Object(o) => o,
            _ => panic!("not object"),
        }
    }

    #[test]
    fn test_discover_profile_names_enotdir_is_error() {
        // `profiles/` as a regular file is ENOTDIR, not ENOENT:
        // Go's os.IsNotExist is false, so discovery must error
        // (`list profiles:`) instead of silently returning
        // ["default"].
        let dir =
            std::env::temp_dir().join(format!("castctl-discover-enotdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("profiles"), b"x").unwrap();
        let err = discover_profile_names(dir.to_str().unwrap()).unwrap_err();
        assert!(
            err.message.contains("list profiles:"),
            "unexpected message: {}",
            err.message
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_validate_profile_name() {
        assert!(validate_profile_name("default").is_ok());
        assert!(validate_profile_name("a.b-c_d9").is_ok());
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name(".a").is_err());
        assert!(validate_profile_name("a.").is_err());
        assert!(validate_profile_name("a/b").is_err());
        assert!(validate_profile_name("a b").is_err());
        assert!(validate_profile_name(&"a".repeat(65)).is_err());
        assert!(validate_profile_name(&"a".repeat(64)).is_ok());
        assert_eq!(
            validate_profile_name("").unwrap_err().message,
            "profile: invalid profile name \"\": use 1-64 letters, digits, '.', '-' or '_' (not starting or ending with '.')"
        );
    }

    #[test]
    fn test_resolve_profile_name_precedence() {
        assert_eq!(
            resolve_profile_name(Some(""), None).unwrap_err().message,
            "profile: invalid profile name \"\": use 1-64 letters, digits, '.', '-' or '_' (not starting or ending with '.')"
        );
        assert_eq!(
            resolve_profile_name(Some("x"), None).unwrap(),
            "x".to_string()
        );
        let getenv = |k: &str| -> Option<String> {
            if k == PROFILE_ENV {
                Some("  env-name ".to_string())
            } else {
                None
            }
        };
        assert_eq!(
            resolve_profile_name(None, Some(&getenv)).unwrap(),
            "env-name".to_string()
        );
        let blank = |k: &str| -> Option<String> {
            if k == PROFILE_ENV {
                Some("   ".to_string())
            } else {
                None
            }
        };
        assert_eq!(
            resolve_profile_name(None, Some(&blank)).unwrap(),
            "default".to_string()
        );
    }

    #[test]
    fn test_profile_paths() {
        let p = profile_paths("/cfg", "default").unwrap();
        assert_eq!(p.dir, "/cfg");
        assert_eq!(p.config, "/cfg/config.json");
        assert_eq!(p.cookies, "/cfg/cookies.txt");
        let p = profile_paths("/cfg", "work").unwrap();
        assert_eq!(p.dir, "/cfg/profiles/work");
        assert_eq!(p.cookies, "/cfg/profiles/work/cookies.txt");
    }

    #[test]
    fn test_parse_profile_entry_defaults_and_fields() {
        let p = parse_profile_entry("default", &entry_json("{}"), "/cfg").unwrap();
        assert_eq!(p.auto_approve, "off");
        assert_eq!(p.fingerprint, "chrome");
        assert_eq!(p.tls_engine, "utls");
        assert!(p.outbound.is_direct());
        assert!(p.config_found);
        assert_eq!(p.source, Source::Single);
        assert_eq!(p.cookies_file, "/cfg/cookies.txt");
        assert!(!p.fingerprint_present);
    }

    #[test]
    fn test_parse_profile_entry_errors() {
        let err =
            parse_profile_entry("default", &entry_json("{\"cookies\":{}}"), "/cfg").unwrap_err();
        assert_eq!(
            err.message,
            "profile: profile \"default\": cookies must stay in a separate cookies file, never inline in config.json"
        );
        let err = parse_profile_entry("default", &entry_json("{\"bogus\":1}"), "/cfg").unwrap_err();
        assert_eq!(
            err.message,
            "profile: profile \"default\": unknown key \"bogus\""
        );
        let err = parse_profile_entry("default", &entry_json("{\"fingerprint\":\"X\"}"), "/cfg")
            .unwrap_err();
        assert_eq!(
            err.message,
            "profile: profile \"default\": fingerprint must be one of chrome, firefox, ios, safari"
        );
        let err = parse_profile_entry(
            "default",
            &entry_json("{\"auto_allow_once\":\"maybe\"}"),
            "/cfg",
        )
        .unwrap_err();
        assert_eq!(
            err.message,
            "profile: profile \"default\": auto_allow_once must be a boolean or an on/off word"
        );
    }

    #[test]
    fn test_parse_profile_entry_outbound_forms() {
        let p = parse_profile_entry("default", &entry_json("{\"outbound\":\"direct\"}"), "/cfg")
            .unwrap();
        assert!(p.outbound.is_direct());
        let p =
            parse_profile_entry("default", &entry_json("{\"outbound\":\"wg1\"}"), "/cfg").unwrap();
        assert_eq!(p.outbound.kind, OutboundKind::Tag);
        assert_eq!(p.outbound.tag, "wg1");
        // " direct " (with spaces) is a tag reference, not direct:
        // Go compares the raw string to "direct" exactly.
        let p = parse_profile_entry(
            "default",
            &entry_json("{\"outbound\":\" direct \"}"),
            "/cfg",
        )
        .unwrap();
        assert_eq!(p.outbound.kind, OutboundKind::Tag);
        assert_eq!(p.outbound.tag, " direct ");
        // Inline object without a tag gets profile:<name> after "type".
        let p = parse_profile_entry(
            "work",
            &entry_json("{\"outbound\":{\"type\":\"socks\",\"server\":\"127.0.0.1\"}}"),
            "/cfg",
        )
        .unwrap();
        assert_eq!(p.outbound.kind, OutboundKind::Inline);
        assert_eq!(p.outbound.tag, "profile:work");
        let raw = p.outbound.raw_json().unwrap();
        assert_eq!(
            crate::jsonvalue::encode_ordered_json(&raw).unwrap(),
            "{\"type\":\"socks\",\"tag\":\"profile:work\",\"server\":\"127.0.0.1\"}"
        );
    }

    #[test]
    fn test_ensure_inline_tag_positions() {
        let obj = entry_json("{\"server\":\"x\"}");
        let (tagged, tag) = ensure_inline_tag(&obj, "profile:work").unwrap();
        assert_eq!(tag, "profile:work");
        assert_eq!(tagged.keys()[0], "tag");
        let obj = entry_json("{\"tag\":\"t1\",\"type\":\"socks\"}");
        let (tagged, tag) = ensure_inline_tag(&obj, "profile:work").unwrap();
        assert_eq!(tag, "t1");
        assert_eq!(tagged.keys(), &["tag".to_string(), "type".to_string()]);
    }

    #[test]
    fn test_resolve_cookies_file_rules() {
        let paths = profile_paths("/cfg", "work").unwrap();
        assert_eq!(
            resolve_cookies_file("/cfg", &paths, "", "work").unwrap(),
            "/cfg/profiles/work/cookies.txt"
        );
        assert_eq!(
            resolve_cookies_file("/cfg", &paths, "/other/ck.txt", "work").unwrap(),
            "/other/ck.txt"
        );
        // Inside-dir non-default path for a named profile: error.
        let err = resolve_cookies_file("/cfg", &paths, "rel/ck.txt", "work").unwrap_err();
        assert!(err.message.contains("is inside the config directory"));
        // The default profile honours any value.
        let dpaths = profile_paths("/cfg", "default").unwrap();
        assert_eq!(
            resolve_cookies_file("/cfg", &dpaths, "other.txt", "default").unwrap(),
            "/cfg/other.txt"
        );
    }

    #[test]
    fn test_synthesized_direct_tag() {
        assert_eq!(synthesized_direct_tag("work"), "castctl-direct:work");
        assert!(is_reserved_synthesized_tag("castctl-direct:work"));
        assert!(!is_reserved_synthesized_tag("direct"));
    }
}
